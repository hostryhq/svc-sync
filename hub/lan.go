package hub

import (
	"crypto/ecdsa"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-sync/api"
	"github.com/hostryhq/svc-sync/engine"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// LANWindow is how far a request timestamp may differ from the hub's clock.
const LANWindow = 2 * time.Minute

// LANAuth authenticates devices on the LAN with the credentials from the offline pack (S10): the
// device presents its identity-signed credential and signs the request with its device key. No
// internet is needed. Discovery gains an attacker nothing: a fake hub or device without a
// credential signed by identity is refused.
type LANAuth struct {
	H *Hub
}

// Authenticate implements api.Authenticator. A drain token has no meaning on the LAN, and the
// quarantine upload is not offered by the hub (KL3).
func (a LANAuth) Authenticate(r *http.Request, raw []byte, route api.Route) (api.Principal, error) {
	deny := func() error {
		return apperr.New(apperr.Unauthenticated, "auth.invalid_assertion", "authentication required")
	}
	if route == api.RouteUpload {
		return api.Principal{}, apperr.New(apperr.NotFound, "sync.not_offered", "this node does not offer the endpoint")
	}
	as, err := sp.DecodeAssertion(r.Header.Get(sp.HeaderAssertion))
	if err != nil {
		return api.Principal{}, deny()
	}
	c := as.Cred.Cred
	h := a.H
	if !sp.VerifyCredential(h.cfg.IdentityPub, as.Cred) || c.TenantID != h.cfg.Tenant || c.OutletID != h.cfg.Outlet {
		return api.Principal{}, deny()
	}
	now := h.cfg.Now()
	if now.Unix() > c.NotAfter {
		return api.Principal{}, deny() // an expired pack is refused on the LAN until it refreshes online
	}
	if h.IsRevoked(c.DeviceID) {
		return api.Principal{}, deny()
	}
	pub, err := c.PubKey()
	if err != nil {
		return api.Principal{}, deny()
	}
	ts := time.Unix(as.TS, 0)
	if ts.Before(now.Add(-LANWindow)) || ts.After(now.Add(LANWindow)) {
		return api.Principal{}, deny()
	}
	if !sp.VerifySig(pub, sp.AssertionMessage(r.Method, r.URL.Path, as.TS, raw), as.Sig) {
		return api.Principal{}, deny()
	}
	_ = h.cache.Add(as.Cred) // a pack refresh may have added the device since provisioning
	return api.Principal{Tenant: h.cfg.Tenant, Caller: engine.Caller{ID: c.DeviceID, Kind: c.Kind, Outlet: c.OutletID, Brand: c.BrandID}}, nil
}

// Sign adds the hub's proof to a response, binding its identity to the request it answers.
func (h *Hub) Sign(hd http.Header, r *http.Request, body []byte) error {
	as, err := sp.DecodeAssertion(r.Header.Get(sp.HeaderAssertion))
	if err != nil {
		return nil
	}
	sig, err := h.cfg.Key.Sign(sp.HubProofMessage(as.Sig, body))
	if err != nil {
		return err
	}
	return encodeProof(hd, sp.HubProof{Cred: h.cfg.Cred, Sig: sig})
}

// LANClient signs requests with a device key and verifies the hub's proof.
type LANClient struct {
	Cred        sp.CredentialEnvelope
	Key         *sp.KeyPair
	IdentityPub *ecdsa.PublicKey
	Outlet      string
	Now         func() time.Time

	mu   sync.Mutex
	last string
}

// Authorize implements HTTPTransport.Authorize.
func (c *LANClient) Authorize(req *http.Request, body []byte) error {
	ts := c.Now().Unix()
	sig, err := c.Key.Sign(sp.AssertionMessage(req.Method, req.URL.Path, ts, body))
	if err != nil {
		return err
	}
	v, err := sp.Assertion{Cred: c.Cred, TS: ts, Sig: sig}.Encode()
	if err != nil {
		return err
	}
	req.Header.Set(sp.HeaderAssertion, v)
	return nil
}

// ErrHubProof is returned when the answering hub cannot prove it is the outlet's hub.
var ErrHubProof = errors.New("hub: response proof invalid")

// VerifyResponse implements HTTPTransport.VerifyResponse: only a credential of kind hub for this
// outlet, signed by identity, whose key signed this request and answer, is accepted.
func (c *LANClient) VerifyResponse(req *http.Request, resp *http.Response, body []byte) error {
	as, err := sp.DecodeAssertion(req.Header.Get(sp.HeaderAssertion))
	if err != nil {
		return ErrHubProof
	}
	hp, err := decodeProof(resp.Header)
	if err != nil || !sp.VerifyCredential(c.IdentityPub, hp.Cred) || hp.Cred.Cred.Kind != sp.KindHub || hp.Cred.Cred.OutletID != c.Outlet || hp.Cred.Cred.TenantID != c.Cred.Cred.TenantID {
		return ErrHubProof
	}
	pub, err := hp.Cred.Cred.PubKey()
	if err != nil || !sp.VerifySig(pub, sp.HubProofMessage(as.Sig, body), hp.Sig) {
		return ErrHubProof
	}
	return nil
}
