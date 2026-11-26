package identityreal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/testkit"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/repository/postgres"
	"github.com/hostryhq/svc-identity/service"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/directory/dirtest"
	"github.com/hostryhq/svc-sync/identityclient"
	"github.com/hostryhq/svc-sync/realdir"
	sp "github.com/hostryhq/svc-sync/syncproto"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const outletA = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61"

var tenant = testkit.TenantA.String()

// fixture is the real identity service layers behind HTTP, with one staff member holding a PIN, and one
// registered point-of-sale device whose pack lists that member.
type fixture struct {
	t        *testing.T
	d        *double.Double
	srv      *httptest.Server
	owner    string // a strong-session token for the owner, to revoke devices
	dev      *double.Device
	staff    string
	packV    int
	opened   time.Time
	proofKey []byte
	dir      *realdir.Directory
}

func newFixture(t *testing.T) *fixture { return newFixtureOn(t, double.Options{}) }

func newFixtureOn(t *testing.T, o double.Options) *fixture {
	t.Helper()
	f := &fixture{t: t, d: double.New(o)}
	f.srv = httptest.NewServer(f.d)
	t.Cleanup(f.srv.Close)
	ctx := context.Background()
	sd := f.d.Service.Seed()
	roleID, staff := string(ids.New()), string(ids.New())
	if err := sd.Role(ctx, tenant, roleID, "Cashier", []string{"member.read"}); err != nil {
		t.Fatal(err)
	}
	if err := sd.Member(ctx, tenant, service.SeedMember{ID: staff, Name: "Ravi", Assignments: []service.SeedAssignment{{ID: string(ids.New()), RoleID: roleID}}}); err != nil {
		t.Fatal(err)
	}
	salt, err := sd.PinFor(ctx, tenant, staff, "482916")
	if err != nil {
		t.Fatal(err)
	}
	f.staff = staff
	f.proofKey = double.PinSecrets(f.d.Service.Cfg.PinParams, "482916", salt).ProofKey
	f.owner = f.ownerSignIn("+919876543210")

	f.dev = double.NewDevice(string(ids.New()))
	var code struct {
		Code string `json:"code"`
	}
	f.call(201, "POST", "/v1/activation-codes", f.owner, map[string]any{"outlet_id": outletA, "kind": "pos"}, &code)
	var nonce struct {
		Nonce string `json:"nonce"`
	}
	f.call(201, "POST", "/v1/device-nonces", "", nil, &nonce)
	k := f.dev.JWK()
	var act struct {
		OfflinePack struct {
			PackV int `json:"pack_v"`
		} `json:"offline_pack"`
	}
	f.call(201, "POST", "/v1/device-activations", "", map[string]any{"activation_code": code.Code, "id": f.dev.ID, "name": "Counter 1",
		"public_key": map[string]string{"kty": k.Kty, "crv": k.Crv, "x": k.X, "y": k.Y}, "key_protection": "os-software",
		"nonce": nonce.Nonce, "nonce_signature": f.dev.SignNonce(nonce.Nonce)}, &act)
	f.packV, f.opened = act.OfflinePack.PackV, f.d.Clock.Now()

	cl, err := identityclient.New(f.srv.URL, f.d.Services.Signer("sync"), f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	cl.Sleep = func(context.Context, time.Duration) {}
	f.dir = &realdir.Directory{Identity: cl, Clock: f.d.Clock.Now}
	return f
}

var n int

var otpRE = regexp.MustCompile(`[0-9]{6}`)

// ownerSignIn signs the owner in over the real OTP flow (an invitation seeded for the number) and returns the
// strong-session access token: only a real member may revoke a device (grant limits).
func (f *fixture) ownerSignIn(mobile string) string {
	f.t.Helper()
	if _, _, err := f.d.Service.Seed().OwnerInvitation(context.Background(), tenant, mobile, "Asha"); err != nil {
		f.t.Fatal(err)
	}
	dev := double.NewDevice(string(ids.New()))
	k := dev.JWK()
	var ch struct {
		ID string `json:"id"`
	}
	f.call(202, "POST", "/v1/otp-challenges", "", map[string]any{"mobile_e164": mobile, "device_id": dev.ID,
		"device_public_key": map[string]string{"kty": k.Kty, "crv": k.Crv, "x": k.X, "y": k.Y}}, &ch)
	msg, ok := f.d.SMS.Last(mobile)
	if !ok {
		f.t.Fatal("no sign-in code was sent")
	}
	var sess struct {
		Tokens struct {
			AccessToken string `json:"access_token"`
		} `json:"tokens"`
	}
	f.call(201, "POST", "/v1/sessions", "", map[string]any{"grant_type": "otp", "challenge_id": ch.ID, "code": otpRE.FindString(msg.Text), "device_id": dev.ID,
		"device_assertion": dev.Assert(f.d.Clock.Now(), "owner-jti", service.AssertionClaims{Cid: ch.ID})}, &sess)
	return sess.Tokens.AccessToken
}

func (f *fixture) call(want int, method, path, token string, body, out any) {
	f.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, f.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method != "GET" {
		n++
		req.Header.Set("Idempotency-Key", fmt.Sprintf("real-test-%d", n))
	}
	res, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	var raw bytes.Buffer
	_, _ = raw.ReadFrom(res.Body)
	if res.StatusCode != want {
		f.t.Fatalf("%s %s: status %d, want %d: %s", method, path, res.StatusCode, want, raw.String())
	}
	if out != nil {
		if err := json.Unmarshal(raw.Bytes(), out); err != nil {
			f.t.Fatalf("decode %s: %v", path, err)
		}
	}
}

func (f *fixture) proof(sid string) string {
	return double.SessionProof(f.proofKey, sid, f.dev.ID, f.staff, f.packV, 1, f.opened)
}

// question is what the gateway asks about the proof of session sid (A3.1): every field the proof binds.
func (f *fixture) question(sid string) directory.ProofQuestion {
	return directory.ProofQuestion{Kind: directory.ProofKindSession, Device: f.dev.ID, Member: f.staff, SID: sid, PackV: f.packV, PinV: 1,
		OpenedAt: f.opened, Proof: f.proof(sid)}
}

// The security condition: stub and real identity answer `locked` alike, for every op kind. The same contract
// runs against the stub in svc-sync/identitystub.
func TestRealIdentityAnswersLockedLikeTheStub(t *testing.T) {
	f := newFixture(t)
	dirtest.Run(t, dirtest.Target{Dir: f.dir, Tenant: tenant,
		Valid: f.question, Wrong: func(i int) string { return fmt.Sprintf("wrong-%d", i) }})
}

// The same contract against identity assembled over Postgres (its real repository, row-level security and
// idempotency store) on the infra dev stack: SYNC_IDENTITY_PG_DSN is an admin DSN; a throwaway database is made
// and dropped.
func TestRealIdentityOverPostgresAnswersLocked(t *testing.T) {
	admin := os.Getenv("SYNC_IDENTITY_PG_DSN")
	if admin == "" {
		t.Skip("SYNC_IDENTITY_PG_DSN not set: no Postgres dev stack")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	name := "identityreal_" + regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(strings.ToLower(string(ids.New()))[19:], "")
	if _, err := db.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.WithoutCancel(ctx), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") //nolint:errcheck
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	st, err := postgres.Open(ctx, u.String(), "identity_app")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := postgres.Migrate(ctx, st.DB()); err != nil {
		t.Fatal(err)
	}
	f := newFixtureOn(t, double.Options{Store: st, AccessLog: &postgres.AccessLog{DB: st.DB(), Role: "identity_app"}, Idem: postgres.NewIdempotency(st)})
	dirtest.Run(t, dirtest.Target{Dir: f.dir, Tenant: tenant,
		Valid: f.question, Wrong: func(i int) string { return fmt.Sprintf("wrong-%d", i) }})
}

// Another tenant's service token never sees this tenant's members: the same proof is not valid there.
func TestRealIdentityProofIsTenantScoped(t *testing.T) {
	f := newFixture(t)
	other := testkit.TenantB.String()
	ask := func(tenant string, q directory.ProofQuestion) directory.ProofResult {
		q.Key = fmt.Sprintf("scoped-%d", n)
		n++
		return f.dir.VerifyProof(tenant, q)
	}
	if got := ask(other, f.question("s0")); got == directory.ProofValid || got == directory.ProofLocked {
		t.Fatalf("a proof for another tenant's member must not verify: %v", got)
	}
	if got := ask(tenant, f.question("s0")); got != directory.ProofValid {
		t.Fatalf("own tenant: %v", got)
	}
	q := f.question("s0")
	q.Proof = ""
	if got := ask(tenant, q); got != directory.ProofMissing {
		t.Fatalf("no proof: %v", got)
	}
}

// A question repeated under the same Idempotency-Key is a replay at identity: the failure is counted once (A3.1 item 2).
func TestRealIdentityReplayedQuestionCountsOnce(t *testing.T) {
	f := newFixture(t)
	q := f.question("s0")
	q.Proof, q.Key = "wrong", "sync:dev:outlet:1"
	for i := 0; i < 20; i++ {
		if got := f.dir.VerifyProof(tenant, q); got != directory.ProofInvalid {
			t.Fatalf("replay %d answered %v", i, got)
		}
	}
	// Four more distinct failures stay below the cap of five in fifteen minutes, so the right proof is still valid.
	for i := 0; i < 3; i++ {
		q.Proof, q.Key = fmt.Sprintf("wrong-%d", i), fmt.Sprintf("sync:dev:outlet:%d", i+2)
		f.dir.VerifyProof(tenant, q)
	}
	good := f.question("s9")
	good.Key = "sync:dev:outlet:99"
	if got := f.dir.VerifyProof(tenant, good); got != directory.ProofValid {
		t.Fatalf("20 replays of one failure counted more than once: %v", got)
	}
}

// The directory routes of ADR-0005 A3.2 against real identity: the credential in any state, the pack an issued
// version granted, the member's current grants, pack history without a version, the revocation feed with its reason
// and the drain report with the statement the device signed itself.
func TestRealIdentityDirectoryRoutesAndDrain(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cred, ok := f.dir.Credential(tenant, f.dev.ID)
	if !ok || cred.Cred.DeviceID != f.dev.ID || cred.Cred.OutletID != outletA || cred.Cred.Kid != f.dev.KID() || cred.Cred.Kind != sp.KindPOS {
		t.Fatalf("credential: %+v %v", cred, ok)
	}
	if pub, err := cred.Cred.PubKey(); err != nil || !pub.Equal(&f.dev.Priv.PublicKey) {
		t.Fatalf("the credential's key is the device's key: %v", err)
	}
	if _, ok := f.dir.Credential(testkit.TenantB.String(), f.dev.ID); ok {
		t.Fatal("another tenant's token must not read the credential")
	}
	if _, ok := f.dir.Credential(tenant, string(ids.New())); ok {
		t.Fatal("an unknown device has no credential")
	}
	pk, ok := f.dir.PackFor(tenant, f.dev.ID, f.packV)
	if !ok || pk.Version != f.packV || pk.Members[f.staff] == nil || pk.Expires.IsZero() {
		t.Fatalf("pack: %+v %v", pk, ok)
	}
	if _, ok := f.dir.PackFor(tenant, f.dev.ID, f.packV+100); ok {
		t.Fatal("a pack never issued is not found")
	}
	for perm := range pk.Members[f.staff] {
		if !f.dir.StillHolds(tenant, outletA, f.staff, perm) {
			t.Fatalf("the member still holds %s", perm)
		}
	}
	if f.dir.StillHolds(tenant, outletA, f.staff, "bill.void") || f.dir.StillHolds(tenant, outletA, string(ids.New()), "member.read") {
		t.Fatal("a permission the member never held, and a member that does not exist, hold nothing")
	}
	if !f.dir.InAnyPack(tenant, f.dev.ID, f.staff) || f.dir.InAnyPack(tenant, f.dev.ID, string(ids.New())) {
		t.Fatal("pack history: the staff member is in a pack the device held, a stranger is not")
	}
	if _, ok := f.dir.RecoveryFor(tenant, f.dev.ID); ok {
		t.Fatal("no recovery was made")
	}
	if _, lk := f.dir.StrongSession(tenant, string(ids.New())); lk != directory.NotFound {
		t.Fatalf("an unknown session: %v", lk)
	}
	if err := f.dir.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if revoked, _ := f.dir.Revoked(tenant, f.dev.ID); revoked {
		t.Fatal("not revoked yet")
	}
	f.call(200, "PUT", "/v1/devices/"+f.dev.ID+"/revocation", f.owner, map[string]any{"reason": "lost"}, nil)
	if err := f.dir.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if revoked, reason := f.dir.Revoked(tenant, f.dev.ID); !revoked || reason != "revoked" {
		t.Fatalf("the feed shows the revoked device with its reason: %v %q", revoked, reason)
	}
	if revoked, _ := f.dir.Revoked(testkit.TenantB.String(), f.dev.ID); revoked {
		t.Fatal("the feed entry belongs to its organisation only")
	}
	// The credential is answered in any state: a revoked device's key still verifies its drain statement.
	if _, ok := f.dir.Credential(tenant, f.dev.ID); !ok {
		t.Fatal("the credential of a revoked device is still answered")
	}
	// The drain report carries the statement the device signed itself; identity verifies it and the series set.
	key := &sp.KeyPair{Kid: f.dev.KID(), Priv: f.dev.Priv}
	st, err := sp.MakeDrainStatement(key, sp.DrainStatement{Origin: f.dev.ID, By: f.dev.ID, At: f.d.Clock.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Streams: []sp.DrainStream{{Stream: "outlet:" + outletA, Seq: 7, H: strings.Repeat("ab", 32)}}, Series: []sp.DrainSeriesLast{}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(st)
	rep := directory.DrainReport{Key: "drain-key-1", Through: map[string]int64{"outlet:" + outletA: 7}, Statement: raw}
	if err := f.dir.RecordDrained(ctx, tenant, f.dev.ID, rep); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if err := f.dir.RecordDrained(ctx, tenant, f.dev.ID, rep); err != nil {
		t.Fatalf("a second report of the same drain is the same answer: %v", err)
	}
	if err := f.dir.RecordDrained(ctx, tenant, string(ids.New()), rep); err == nil {
		t.Fatal("a device identity does not know cannot be drained")
	}
}
