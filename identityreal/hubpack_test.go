package identityreal

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// handlerRT calls a handler in process: the hub behind it needs no network, as on the restaurant LAN with the internet cut.
type handlerRT struct{ h http.Handler }

func (t handlerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// HP1 and HP2 of ADR-0002 A3.6: a hub is activated against the real identity service layers (the code is bound to kind hub, the
// answer carries a HubPackClaims), runs on that pack with no other source, and after a tablet is revoked in identity and the pack
// refreshed, the hub drops the tablet's LAN session and refuses its next hello. The pack holds no display name, PIN verifier or
// salt, series code or manual book, and carries the hub's own LAN credential, which a tablet then verifies offline.
func TestHP1_HubActivatesAgainstIdentityRunsOnItsPackAndRefusesARevokedTablet(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var code struct {
		Code string `json:"code"`
	}
	f.call(201, "POST", "/v1/activation-codes", f.owner, map[string]any{"outlet_id": outletA, "kind": "hub"}, &code)
	hubKey, err := sp.NewKeyPair("", nil)
	if err != nil {
		t.Fatal(err)
	}
	idc := &hub.IdentityClient{Base: f.srv.URL, HTTP: f.srv.Client(), Now: f.d.Clock.Now}
	act, err := idc.Activate(ctx, code.Code, "Hub", string(ids.New()), hubKey, "os-software", sp.StoreProtected)
	if err != nil {
		t.Fatal(err)
	}
	p := act.Pack
	if p.Cred.Kind != sp.KindHub || p.Cred.Store != sp.StoreProtected || p.CredJWS == "" || p.Cred.OutletID != outletA {
		t.Fatalf("the hub pack carries the hub's own LAN credential: %+v", p.Cred)
	}

	// HP2: nothing a PIN guess or a customer-facing screen could use.
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(p.Raw, ".")[1])
	for _, banned := range []string{"display_name", "pin_salt", "pin_verifier", "vbits", "pin_v", `"series"`, "manual_books", "entitlement", "idle_lock"} {
		if bytes.Contains(payload, []byte(banned)) {
			t.Errorf("a hub pack must not hold %s: %s", banned, payload)
		}
	}

	hubKey.Kid = p.Cred.Kid
	st, err := repository.Open("file:" + filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h, err := hub.New(ctx, hub.Config{Tenant: p.Tenant, Outlet: p.Outlet, Brand: p.Brand, Cred: sp.CredentialEnvelope{Cred: p.Cred}, CredJWS: p.CredJWS, Key: hubKey,
		IdentityPub: p.IdentityKeys[0], CloudKeys: map[string]*hub.PubKey{p.OpKid: p.OpKey}, Store: st, Now: f.d.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.ApplyPack(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got, err := hub.LoadStoredPack(ctx, st, p.Tenant, act.DeviceID); err != nil || got.PackV != p.PackV {
		t.Fatalf("the stored pack reloads with no internet: %v", err)
	}

	// The tablet's LAN credential is in its own pack; it opens a LAN session with the hub offline.
	tabKey := &sp.KeyPair{Kid: f.dev.KID(), Priv: f.dev.Priv}
	tabIdc := &hub.IdentityClient{Base: f.srv.URL, HTTP: f.srv.Client(), Now: f.d.Clock.Now}
	tok, err := tabIdc.Token(ctx, f.dev.ID, tabKey)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", f.srv.URL+"/v1/devices/"+f.dev.ID+"/offline-packs/latest", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var tabPack struct {
		Claims struct {
			Device struct {
				Credential string `json:"credential"`
			} `json:"device"`
		} `json:"claims"`
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if json.Unmarshal(b, &tabPack) != nil || tabPack.Claims.Device.Credential == "" {
		t.Fatalf("the tablet's pack carries its LAN credential: %s", b)
	}
	lan := &hub.LANClient{CredJWS: tabPack.Claims.Device.Credential, Key: tabKey, DeviceID: f.dev.ID, Tenant: p.Tenant, Outlet: p.Outlet, Now: f.d.Clock.Now,
		Identity: func() []*ecdsa.PublicKey { return p.IdentityKeys }, Next: handlerRT{h.Handler()}, SPKISeen: h.SPKI}
	cl := &http.Client{Transport: lan.RoundTripper()}
	resp, err := cl.Get("http://hub/sync/v1/snapshot")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("the tablet verifies the hub with identity's keys from its own pack and opens a session: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	if h.SessionCount() != 1 {
		t.Fatal("one session")
	}

	// The owner revokes the tablet; the hub's next pack refresh lists it.
	f.call(200, "PUT", "/v1/devices/"+f.dev.ID+"/revocation", f.owner, map[string]any{"reason": "lost"}, nil)
	np, err := idc.Pack(ctx, act.DeviceID, hubKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.ApplyPack(ctx, np); err != nil {
		t.Fatal(err)
	}
	if !h.IsRevoked(f.dev.ID) || h.SessionCount() != 0 {
		t.Fatalf("after the refresh the hub refuses the tablet: revoked=%v sessions=%d", h.IsRevoked(f.dev.ID), h.SessionCount())
	}
	lan.Forget()
	if resp, err := cl.Get("http://hub/sync/v1/snapshot"); err == nil && resp.StatusCode == 200 {
		t.Fatal("a revoked tablet opened a LAN session")
	}
}
