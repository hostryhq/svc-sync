package hub

import (
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-sync/api"
	"github.com/hostryhq/svc-sync/engine"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// LAN transport (ADR-0002 A3.1, sync/protocol-v1.md "LAN handshake"). The hub speaks TLS 1.3 with a certificate nobody checks.
// A device proves itself and the hub in two calls, each proof bound to the certificate's key hash (spki), and receives a session
// token held in the hub's memory for 15 minutes. Every other call carries the token. There is no timestamp window and nothing to
// replay: a captured request on a new connection has no valid token (LT5).

const (
	// pendingTTL is how long a handshake's hub nonce waits for step 2.
	pendingTTL = 30 * time.Second
	// maxPending and maxSessions bound hub memory against a flood of handshakes on the Wi-Fi.
	maxPending  = 1024
	maxSessions = 4096
)

type pendingHS struct {
	nonceD string
	cred   sp.Credential
	spki   string
	exp    time.Time
}

type session struct {
	cred sp.Credential
	exp  time.Time
}

func (h *Hub) identityKeys() []*ecdsa.PublicKey {
	return *h.idKeys.Load()
}

func lanRefused() error {
	return apperr.New(apperr.Unauthenticated, sp.CodeLanCredentialRefused, "the credential is not acceptable")
}

func lanProofInvalid() error {
	return apperr.New(apperr.Unauthenticated, sp.CodeLanProofInvalid, "the proof is not valid")
}

func badRequest() error {
	return apperr.New(apperr.Validation, "sync.bad_request", "request body is not valid for this endpoint")
}

func readJSON(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil || json.Unmarshal(b, v) != nil {
		return badRequest()
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// acceptable judges a device credential the way the hub must (A3.1 item 4): signature against the identity keys, same tenant and
// outlet, not past `not_after`, not revoked, and a store claim of a known value.
func (h *Hub) acceptable(jws string) (sp.Credential, bool) {
	c, err := sp.VerifyCredentialJWS(h.identityKeys(), jws)
	if err != nil || c.TenantID != h.cfg.Tenant || c.OutletID != h.cfg.Outlet || h.cfg.Now().Unix() > c.NotAfter || h.IsRevoked(c.DeviceID) {
		return sp.Credential{}, false
	}
	if c.Store != sp.StoreProtected && c.Store != sp.StoreUnprotected {
		return sp.Credential{}, false
	}
	return c, true
}

func (h *Hub) hubID() string { return h.cfg.Cred.Cred.DeviceID }

// handleHello is helloLan: step 1.
func (h *Hub) handleHello(w http.ResponseWriter, r *http.Request) {
	var req sp.LanHelloRequest
	if err := readJSON(r, &req); err != nil || !sp.ValidNonce(req.NonceD) {
		apperr.WriteProblem(w, r, badRequest())
		return
	}
	c, ok := h.acceptable(req.Credential)
	if !ok {
		apperr.WriteProblem(w, r, lanRefused())
		return
	}
	nonceH, err := sp.NewNonce()
	if err != nil {
		apperr.WriteProblem(w, r, err)
		return
	}
	spki := h.SPKI()
	proof, err := h.cfg.Key.Sign(sp.LanProofMessage(sp.LanTagHub, req.NonceD, nonceH, c.DeviceID, h.hubID(), spki))
	if err != nil {
		apperr.WriteProblem(w, r, err)
		return
	}
	now := h.cfg.Now()
	h.mu.Lock()
	for k, p := range h.pending {
		if now.After(p.exp) {
			delete(h.pending, k)
		}
	}
	if len(h.pending) >= maxPending {
		h.mu.Unlock()
		apperr.WriteProblem(w, r, apperr.New(apperr.RateLimited, "sync.lan_busy", "too many handshakes in progress"))
		return
	}
	h.pending[nonceH] = pendingHS{nonceD: req.NonceD, cred: c, spki: spki, exp: now.Add(pendingTTL)}
	h.mu.Unlock()
	writeJSON(w, sp.LanHelloResponse{Credential: *h.credJWS.Load(), NonceH: nonceH, HubProof: proof})
}

// handleSession is openLanSession: step 2.
func (h *Hub) handleSession(w http.ResponseWriter, r *http.Request) {
	var req sp.LanSessionRequest
	if err := readJSON(r, &req); err != nil || !sp.ValidNonce(req.NonceD) || !sp.ValidNonce(req.NonceH) {
		apperr.WriteProblem(w, r, badRequest())
		return
	}
	h.mu.Lock()
	p, ok := h.pending[req.NonceH]
	delete(h.pending, req.NonceH) // single use
	h.mu.Unlock()
	now := h.cfg.Now()
	if !ok || now.After(p.exp) || p.nonceD != req.NonceD {
		apperr.WriteProblem(w, r, lanProofInvalid())
		return
	}
	// The device must have signed the spki of the certificate this hub presented at step 1: a relay's differs.
	pub, err := p.cred.PubKey()
	if err != nil || !sp.VerifySig(pub, sp.LanProofMessage(sp.LanTagDevice, p.nonceD, req.NonceH, p.cred.DeviceID, h.hubID(), p.spki), req.DeviceProof) {
		apperr.WriteProblem(w, r, lanProofInvalid())
		return
	}
	if h.IsRevoked(p.cred.DeviceID) {
		apperr.WriteProblem(w, r, lanRefused())
		return
	}
	token, err := sp.NewNonce()
	if err != nil {
		apperr.WriteProblem(w, r, err)
		return
	}
	h.cache.AddLAN(p.cred)
	h.mu.Lock()
	for k, s := range h.sessions {
		if now.After(s.exp) {
			delete(h.sessions, k)
		}
	}
	if len(h.sessions) >= maxSessions {
		h.mu.Unlock()
		apperr.WriteProblem(w, r, apperr.New(apperr.RateLimited, "sync.lan_busy", "too many sessions"))
		return
	}
	h.sessions[token] = session{cred: p.cred, exp: now.Add(sp.LanSessionTTLSeconds * time.Second)}
	h.mu.Unlock()
	writeJSON(w, sp.LanSession{Token: token, ExpiresIn: sp.LanSessionTTLSeconds})
}

// dropSessions ends every session of a device (a pack refresh lists it revoked). Callers hold no lock.
func (h *Hub) dropSessions(device string) {
	h.mu.Lock()
	for k, s := range h.sessions {
		if s.cred.DeviceID == device {
			delete(h.sessions, k)
		}
	}
	h.mu.Unlock()
}

// SessionCount is the number of live LAN sessions (tests and the status line).
func (h *Hub) SessionCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sessions)
}

// LANAuth authenticates a call by its LAN session token (A3.1 item 5). The quarantine upload is not offered by the hub (KL3).
type LANAuth struct {
	H *Hub
}

// Authenticate implements api.Authenticator.
func (a LANAuth) Authenticate(r *http.Request, _ []byte, route api.Route) (api.Principal, error) {
	if route == api.RouteUpload {
		return api.Principal{}, apperr.New(apperr.NotFound, "sync.not_offered", "this node does not offer the endpoint")
	}
	h := a.H
	expired := apperr.New(apperr.Unauthenticated, sp.CodeLanSessionExpired, "the LAN session is missing or has lapsed: run the handshake again")
	tok := r.Header.Get(sp.HeaderLanSession)
	h.mu.Lock()
	s, ok := h.sessions[tok]
	if ok && h.cfg.Now().After(s.exp) {
		delete(h.sessions, tok)
		ok = false
	}
	revoked := ok && h.revoked[s.cred.DeviceID]
	h.mu.Unlock()
	if !ok || tok == "" || revoked || h.cfg.Now().Unix() > s.cred.NotAfter {
		return api.Principal{}, expired
	}
	c := s.cred
	return api.Principal{Tenant: h.cfg.Tenant, Caller: engine.Caller{ID: c.DeviceID, Kind: c.Kind, Store: c.Store, Outlet: c.OutletID, Brand: c.BrandID}}, nil
}
