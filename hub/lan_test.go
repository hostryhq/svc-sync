package hub_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/identitystub"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

const (
	tenant = "018f0000-0000-7000-8000-0000000000a0"
	outlet = "018f0000-0000-7000-8000-0000000000a1"
	brand  = "018f0000-0000-7000-8000-0000000000b1"
)

type fixture struct {
	t     *testing.T
	id    *identitystub.Identity
	now   time.Time
	clock atomic.Pointer[time.Time]
	hubKP *sp.KeyPair
	hubJ  string
	dir   string
	hub   *hub.Hub
}

func (f *fixture) Now() time.Time { return *f.clock.Load() }

func (f *fixture) advance(d time.Duration) { n := f.Now().Add(d); f.clock.Store(&n) }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), now: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)}
	f.clock.Store(&f.now)
	var err error
	if f.id, err = identitystub.New(f.Now, nil); err != nil {
		t.Fatal(err)
	}
	f.hubKP, _ = sp.NewKeyPair("k-hub", nil)
	if _, err := f.id.Activate(tenant, outlet, brand, "hub-01", sp.KindHub, f.hubKP, ""); err != nil {
		t.Fatal(err)
	}
	f.hubJ, _ = f.id.LANCredential("hub-01")
	f.hub = f.startHub()
	return f
}

// startHub starts a hub on the fixture's store, as a service start does: a new TLS key and no sessions.
func (f *fixture) startHub() *hub.Hub {
	st, err := repository.Open("file:" + filepath.Join(f.dir, "hub.db"))
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = st.Close() })
	env, _ := f.id.Credential(tenant, "hub-01")
	h, err := hub.New(context.Background(), hub.Config{Tenant: tenant, Outlet: outlet, Brand: brand, Cred: env, CredJWS: f.hubJ, Key: f.hubKP,
		IdentityPub: f.id.IdentityPub(), Store: st, Now: f.Now})
	if err != nil {
		f.t.Fatal(err)
	}
	return h
}

func (f *fixture) device(id, kind, store string) *hub.LANClient {
	f.t.Helper()
	kp, _ := sp.NewKeyPair("k-"+id, nil)
	if _, err := f.id.ActivateStore(tenant, outlet, brand, id, kind, kp.Kid, kp.PublicB64(), "", store); err != nil {
		f.t.Fatal(err)
	}
	jws, _ := f.id.LANCredential(id)
	c := &hub.LANClient{CredJWS: jws, Key: kp, DeviceID: id, Tenant: tenant, Outlet: outlet, Now: f.Now,
		Identity: func() []*ecdsa.PublicKey { return []*ecdsa.PublicKey{f.id.IdentityPub()} }}
	c.Next = hub.NewLANTransport(c)
	return c
}

// serve runs h behind real TLS 1.3 on loopback, with the hub chosen per connection so a test can swap it (a restart).
func serve(t *testing.T, cur *atomic.Pointer[hub.Hub]) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return cur.Load().TLSConfig(), nil }}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { cur.Load().Handler().ServeHTTP(w, r) }), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String()
}

func get(c *http.Client, url string) (int, string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func problemCode(body string) string {
	var p struct{ Code string }
	_ = json.Unmarshal([]byte(body), &p)
	return p.Code
}

// The happy path over real TLS 1.3: the handshake, then a call under the session token.
func TestHandshakeOverTLSOpensASession(t *testing.T) {
	f := newFixture(t)
	var cur atomic.Pointer[hub.Hub]
	cur.Store(f.hub)
	base := serve(t, &cur)
	c := f.device("dev-pos", sp.KindPOS, sp.StoreProtected)
	cl := &http.Client{Transport: c.RoundTripper()}
	code, body, err := get(cl, base+"/sync/v1/snapshot")
	if err != nil || code != 200 {
		t.Fatalf("snapshot after the handshake: %d %s %v", code, body, err)
	}
	if f.hub.SessionCount() != 1 {
		t.Fatalf("one session expected, got %d", f.hub.SessionCount())
	}
}

// LT1: a relay that terminates TLS with its own certificate and forwards the hello. The device saw the relay's key hash, the hub
// signed its own: the device refuses the hub's proof, sends nothing but the hello, and no session exists.
func TestLT1_ARelayWithItsOwnCertificateGetsNoSession(t *testing.T) {
	f := newFixture(t)
	var cur atomic.Pointer[hub.Hub]
	cur.Store(f.hub)
	hubURL := serve(t, &cur)
	target, _ := url.Parse(hubURL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // the relay does not care
	var paths []string
	relay := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		proxy.ServeHTTP(w, r)
	}))
	relay.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	relay.StartTLS() // httptest's own certificate: a different key than the hub's
	defer relay.Close()

	c := f.device("dev-pos", sp.KindPOS, sp.StoreProtected)
	_, _, err := get(&http.Client{Transport: c.RoundTripper()}, relay.URL+"/sync/v1/snapshot")
	if err == nil || !errors.Is(err, hub.ErrHubProof) {
		t.Fatalf("the device must refuse a hub it cannot prove through the relay: %v", err)
	}
	if len(paths) != 1 || paths[0] != "/sync/v1/lan/hello" {
		t.Fatalf("nothing but hello may be sent before the hub is proven: %v", paths)
	}
	if f.hub.SessionCount() != 0 {
		t.Fatal("no session token may exist")
	}
}

// LT1b: a relay on the second connection only. The hello goes to the real hub, the connection that opens the session shows another
// certificate key: the device refuses it before it writes the proof, so no relay receives the proof or a token (P2R-L1).
func TestLT1b_AHubThatSwapsItsCertificateBetweenTheStepsIsRefused(t *testing.T) {
	f := newFixture(t)
	other := f.startHub() // a hub with its own TLS key: the second connection's certificate
	var conns atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		if conns.Add(1) == 1 {
			return f.hub.TLSConfig(), nil
		}
		return other.TLSConfig(), nil
	}}
	var paths []string
	var mu sync.Mutex
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		f.hub.Handler().ServeHTTP(w, r)
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := f.device("dev-pos", sp.KindPOS, sp.StoreProtected)
	_, _, err = get(&http.Client{Transport: c.RoundTripper()}, "https://"+ln.Addr().String()+"/sync/v1/snapshot")
	if err == nil || !errors.Is(err, hub.ErrHubProof) {
		t.Fatalf("the device must refuse a hub whose key changed between the steps: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 || paths[0] != "/sync/v1/lan/hello" {
		t.Fatalf("only the hello may reach the server; the proof must not be written on the swapped connection: %v", paths)
	}
	if f.hub.SessionCount() != 0 || other.SessionCount() != 0 {
		t.Fatal("no session token may exist")
	}
}

// The hub's half of LT1: a device proof over a different key hash than the certificate this hub presented is refused.
func TestLT1_TheHubRefusesADeviceProofOverAnotherKeyHash(t *testing.T) {
	f := newFixture(t)
	h := f.hub.Handler()
	kp, _ := sp.NewKeyPair("k-d", nil)
	if _, err := f.id.Activate(tenant, outlet, brand, "dev-x", sp.KindPOS, kp, ""); err != nil {
		t.Fatal(err)
	}
	jws, _ := f.id.LANCredential("dev-x")
	nd, _ := sp.NewNonce()
	post := func(path string, in any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(in)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", path, bytes.NewReader(b)))
		return rec
	}
	rec := post("/sync/v1/lan/hello", sp.LanHelloRequest{Credential: jws, NonceD: nd})
	var hello sp.LanHelloResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &hello)
	relaySPKI := strings.Repeat("a0", 32)
	proof, _ := kp.Sign(sp.LanProofMessage(sp.LanTagDevice, nd, hello.NonceH, "dev-x", "hub-01", relaySPKI))
	rec = post("/sync/v1/lan/session", sp.LanSessionRequest{NonceD: nd, NonceH: hello.NonceH, DeviceProof: proof})
	if rec.Code != 401 || problemCode(rec.Body.String()) != sp.CodeLanProofInvalid || f.hub.SessionCount() != 0 {
		t.Fatalf("a proof over another spki: %d %s", rec.Code, rec.Body.String())
	}
	// The nonce is single use: even the right proof cannot be sent after a refusal.
	right, _ := kp.Sign(sp.LanProofMessage(sp.LanTagDevice, nd, hello.NonceH, "dev-x", "hub-01", f.hub.SPKI()))
	rec = post("/sync/v1/lan/session", sp.LanSessionRequest{NonceD: nd, NonceH: hello.NonceH, DeviceProof: right})
	if rec.Code != 401 {
		t.Fatalf("a spent nonce opened a session: %d", rec.Code)
	}
}

// LT2: a device refuses a hub with a self-made credential, one of another outlet, an expired one, or a revoked hub id, with no
// internet involved.
func TestLT2_ADeviceRefusesAHubWhoseCredentialIsNotAcceptable(t *testing.T) {
	f := newFixture(t)
	rogue, _ := sp.NewKeyPair("k-rogue", nil)
	hubClaims := func(mod func(*sp.Credential)) sp.Credential {
		c := sp.Credential{DeviceID: "hub-01", TenantID: tenant, OutletID: outlet, BrandID: brand, Kind: sp.KindHub, Kid: f.hubKP.Kid,
			Pub: f.hubKP.PublicB64(), Store: sp.StoreProtected, NotAfter: f.Now().Add(time.Hour).Unix()}
		mod(&c)
		return c
	}
	idKP := f.id.Key
	cases := []struct {
		name    string
		jws     func() string
		revoked bool
	}{
		{"self-made credential", func() string { j, _ := sp.SignCredentialJWS(rogue, hubClaims(func(*sp.Credential) {})); return j }, false},
		{"another outlet", func() string {
			j, _ := sp.SignCredentialJWS(idKP, hubClaims(func(c *sp.Credential) { c.OutletID = "other-outlet" }))
			return j
		}, false},
		{"expired", func() string {
			j, _ := sp.SignCredentialJWS(idKP, hubClaims(func(c *sp.Credential) { c.NotAfter = f.Now().Add(-time.Minute).Unix() }))
			return j
		}, false},
		{"revoked hub id", func() string { j, _ := sp.SignCredentialJWS(idKP, hubClaims(func(*sp.Credential) {})); return j }, true},
		{"a device credential, not a hub", func() string {
			j, _ := sp.SignCredentialJWS(idKP, hubClaims(func(c *sp.Credential) { c.Kind = sp.KindPOS }))
			return j
		}, false},
	}
	for i, tc := range cases {
		devID := "dev-pos-" + string(rune('a'+i))
		t.Run(tc.name, func(t *testing.T) {
			jws := tc.jws()
			var spki string
			fake := httptest.NewUnstartedServer(nil)
			fake.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			fake.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req sp.LanHelloRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				nh, _ := sp.NewNonce()
				// A valid proof by the hub key over the right key hash: the credential is the only thing wrong.
				proof, _ := f.hubKP.Sign(sp.LanProofMessage(sp.LanTagHub, req.NonceD, nh, devID, "hub-01", spki))
				_ = json.NewEncoder(w).Encode(sp.LanHelloResponse{Credential: jws, NonceH: nh, HubProof: proof})
			})
			fake.StartTLS()
			defer fake.Close()
			spki = sp.SPKIOf(fake.Certificate())
			c := f.device(devID, sp.KindPOS, sp.StoreProtected)
			c.Revoked = func(id string) bool { return tc.revoked && id == "hub-01" }
			_, _, err := get(&http.Client{Transport: c.RoundTripper()}, fake.URL+"/sync/v1/snapshot")
			if !errors.Is(err, hub.ErrHubProof) {
				t.Fatalf("the hub must be refused: %v", err)
			}
		})
	}
}

// LT3 (release binary half): plain HTTP to the hub's listener gets no answer from the application. (The `devlan` binary's
// refusal to start outside dev, test and ci is tested in cmd/hub with the tag.)
func TestLT3_PlainHTTPToTheTLSListenerGetsNothing(t *testing.T) {
	f := newFixture(t)
	var cur atomic.Pointer[hub.Hub]
	cur.Store(f.hub)
	base := serve(t, &cur)
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: hub\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, _ := io.ReadAll(conn)
	if strings.Contains(string(b), `"status":"ok"`) || strings.Contains(string(b), "200 OK") {
		t.Fatalf("a plain request was answered by the application: %q", b)
	}
}

// LT4: the hub restarts mid-service (a new TLS key, no sessions). The device's next call fails closed, it runs the handshake
// again against the new key hash and the call goes through.
func TestLT4_AHubRestartIsRecoveredByANewHandshake(t *testing.T) {
	f := newFixture(t)
	var cur atomic.Pointer[hub.Hub]
	cur.Store(f.hub)
	base := serve(t, &cur)
	c := f.device("dev-pos", sp.KindPOS, sp.StoreProtected)
	cl := &http.Client{Transport: c.RoundTripper()}
	if code, body, err := get(cl, base+"/sync/v1/snapshot"); err != nil || code != 200 {
		t.Fatalf("before the restart: %d %s %v", code, body, err)
	}
	first := f.hub.SPKI()
	f.hub = f.startHub()
	cur.Store(f.hub)
	if f.hub.SPKI() == first {
		t.Fatal("a restarted hub must present a new key")
	}
	cl.CloseIdleConnections()
	c.Next.(*http.Transport).CloseIdleConnections()
	if code, body, err := get(cl, base+"/sync/v1/snapshot"); err != nil || code != 200 {
		t.Fatalf("after the restart the device must re-run hello and go on: %d %s %v", code, body, err)
	}
	// The session token lapses after 15 minutes: the next call gets 401 lan_session_expired inside the client and repeats.
	f.advance(16 * time.Minute)
	if code, body, err := get(cl, base+"/sync/v1/snapshot"); err != nil || code != 200 {
		t.Fatalf("after the token lapsed: %d %s %v", code, body, err)
	}
}

// LT5: a request that carries no valid token, whatever else it carries (a captured request of the old per-request assertion
// scheme, a token from before a restart, a lapsed token), is 401 lan_session_expired and changes no state.
func TestLT5_AReplayedRequestWithoutAValidTokenIs401(t *testing.T) {
	f := newFixture(t)
	h := f.hub.Handler()
	call := func(hdr map[string]string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/sync/v1/push", strings.NewReader(`{"items":[]}`))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		h.ServeHTTP(rec, req)
		return rec
	}
	tok, _ := sp.NewNonce()
	for name, hdr := range map[string]map[string]string{
		"no token":                {},
		"an old signed assertion": {"Hostry-Device-Assertion": "eyJjcmVkIjp7fX0"},
		"an unknown token":        {sp.HeaderLanSession: tok},
	} {
		rec := call(hdr)
		if rec.Code != 401 || problemCode(rec.Body.String()) != sp.CodeLanSessionExpired {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	// A real token: accepted. The same request replayed after the token's 15 minutes, or on a hub that restarted: 401, and the
	// hub's vector has not moved.
	token := openInProcess(t, f, f.hub, "dev-pos")
	ok := call(map[string]string{sp.HeaderLanSession: token})
	if ok.Code != 200 {
		t.Fatalf("a valid token: %d %s", ok.Code, ok.Body.String())
	}
	f.advance(16 * time.Minute)
	if rec := call(map[string]string{sp.HeaderLanSession: token}); rec.Code != 401 || problemCode(rec.Body.String()) != sp.CodeLanSessionExpired {
		t.Errorf("a lapsed token: %d %s", rec.Code, rec.Body.String())
	}
	restarted := f.startHub()
	h = restarted.Handler()
	if rec := call(map[string]string{sp.HeaderLanSession: token}); rec.Code != 401 {
		t.Errorf("a token from before a restart: %d", rec.Code)
	}
	if v, err := restarted.Engine().Vector(context.Background()); err != nil || len(v) != 0 {
		t.Errorf("a refused replay changed the hub's state: %v %v", v, err)
	}
}

// openInProcess runs both handshake steps against h's handler (no network) with a fresh device and returns the token.
func openInProcess(t *testing.T, f *fixture, h *hub.Hub, id string) string {
	t.Helper()
	kp, _ := sp.NewKeyPair("k-"+id, nil)
	if _, err := f.id.ActivateStore(tenant, outlet, brand, id, sp.KindPOS, kp.Kid, kp.PublicB64(), "", sp.StoreProtected); err != nil {
		t.Fatal(err)
	}
	jws, _ := f.id.LANCredential(id)
	hd := h.Handler()
	post := func(path string, in any) []byte {
		b, _ := json.Marshal(in)
		rec := httptest.NewRecorder()
		hd.ServeHTTP(rec, httptest.NewRequest("POST", path, bytes.NewReader(b)))
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		return rec.Body.Bytes()
	}
	nd, _ := sp.NewNonce()
	var hello sp.LanHelloResponse
	_ = json.Unmarshal(post("/sync/v1/lan/hello", sp.LanHelloRequest{Credential: jws, NonceD: nd}), &hello)
	proof, _ := kp.Sign(sp.LanProofMessage(sp.LanTagDevice, nd, hello.NonceH, id, "hub-01", h.SPKI()))
	var s sp.LanSession
	_ = json.Unmarshal(post("/sync/v1/lan/session", sp.LanSessionRequest{NonceD: nd, NonceH: hello.NonceH, DeviceProof: proof}), &s)
	return s.Token
}

// A revoked device loses its session at once, and cannot open another (A3.1 item 5).
func TestRevokedDeviceLosesItsSessions(t *testing.T) {
	f := newFixture(t)
	var cur atomic.Pointer[hub.Hub]
	cur.Store(f.hub)
	base := serve(t, &cur)
	c := f.device("dev-pos", sp.KindPOS, sp.StoreProtected)
	cl := &http.Client{Transport: c.RoundTripper()}
	if code, _, err := get(cl, base+"/sync/v1/snapshot"); err != nil || code != 200 {
		t.Fatal(code, err)
	}
	f.hub.Revoke("dev-pos")
	if f.hub.SessionCount() != 0 {
		t.Fatal("the revoked device's session must end with the pack refresh")
	}
	if _, _, err := get(cl, base+"/sync/v1/snapshot"); err == nil {
		t.Fatal("a revoked device opened a new session")
	}
}
