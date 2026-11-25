// Package devreg is the development-only registration and token surface of the gateway's stub directory
// (cmd/gateway with SYNC_DEV_STUB=1). Real devices activate against identity; until the identity directory
// answers the gateway's lookups (docs/phase2-notes.md), a local stack registers its devices here, receives the
// credential and a device token, and can mint more tokens. It exists so that no harness has to wrap the
// gateway to add these routes (soak finding F2).
//
// It is refused outside dev, test and ci (Guard, the same rule as identity's test SMS sender and dev aids),
// needs the explicit flag, and is never mounted otherwise. The keys it holds are generated per run and nothing
// here is a secret.
package devreg

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/identitystub"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Guard refuses the dev registration surface unless the environment is dev, test or ci and the explicit flag
// (SYNC_DEV_REGISTER=1) is set. A named environment such as staging or production is always refused.
func Guard(environment string, allow bool) error {
	switch environment {
	case "dev", "test", "ci":
	default:
		return fmt.Errorf("the dev registration routes need HOSTRY_ENV in dev, test or ci (got %q)", environment)
	}
	if !allow {
		return errors.New("the dev registration routes need SYNC_DEV_REGISTER=1")
	}
	return nil
}

// Registry registers devices, members, series and manual books in the stub identity and mints device tokens.
type Registry struct {
	ID     *identitystub.Identity
	Issuer *authtest.Issuer
	Now    func() time.Time
	// CloudURL is the gateway's own URL as a hub reaches it; it goes into the hub pack (empty: the hub syncs on its LAN only).
	CloudURL string

	mu      sync.Mutex
	hubKeys map[string]string // tenant|device -> PKCS#8 of a hub key this registry generated
}

// keep remembers the key of a hub the registry generated, so that GET /dev/v1/hub-packs/{device_id} can write the
// hub's pack again after devices and series were added.
func (r *Registry) keep(tenant, device, pkcs8 string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hubKeys == nil {
		r.hubKeys = map[string]string{}
	}
	r.hubKeys[tenant+"|"+device] = pkcs8
}

// hubPack builds the pack cmd/hub reads (hub.LoadPack): the hub's credential and key, the identity and gateway keys,
// the credentials of the outlet's other devices, the members its devices' packs list and the owner of every series.
func (r *Registry) hubPack(tenant, device string) (hub.Pack, bool) {
	r.mu.Lock()
	pkcs8, ok := r.hubKeys[tenant+"|"+device]
	r.mu.Unlock()
	cred, cok := r.ID.Credential(tenant, device)
	if !ok || !cok {
		return hub.Pack{}, false
	}
	p := hub.Pack{Tenant: tenant, Outlet: cred.Cred.OutletID, Brand: cred.Cred.BrandID, Cred: cred, PKCS8: pkcs8,
		IdentityPub: sp.EncodePub(r.ID.IdentityPub()), CloudKeys: map[string]string{r.ID.CloudKey.Kid: r.ID.CloudKey.PublicB64()},
		Members: r.ID.MembersOfOutlet(tenant, cred.Cred.OutletID), SeriesOwner: map[string]string{}, CloudURL: r.CloudURL}
	for _, c := range r.ID.Devices(tenant, cred.Cred.OutletID) {
		if c.Cred.DeviceID == device {
			continue
		}
		p.Peers = append(p.Peers, c)
		for _, s := range r.ID.SeriesOf(tenant, c.Cred.DeviceID) {
			p.SeriesOwner[s.Code] = c.Cred.DeviceID
		}
	}
	return p, true
}

func (r *Registry) hubPackRoute(w http.ResponseWriter, req *http.Request) {
	p, ok := r.hubPack(req.URL.Query().Get("tenant_id"), req.PathValue("device_id"))
	if !ok {
		problem(w, http.StatusNotFound, "no such hub, or its key was not generated here")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// maxBody bounds a request.
const maxBody = 64 << 10

// Mount adds the routes under /dev/v1. The caller has already passed Guard.
func (r *Registry) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /dev/v1/devices", r.registerDevice)
	mux.HandleFunc("POST /dev/v1/device-tokens", r.mintToken)
	mux.HandleFunc("POST /dev/v1/members", r.setMember)
	mux.HandleFunc("POST /dev/v1/manual-books", r.registerBook)
	mux.HandleFunc("GET /dev/v1/trust", r.trust)
	mux.HandleFunc("GET /dev/v1/hub-packs/{device_id}", r.hubPackRoute)
}

// SeriesSpec is a series issued to a device under a code the caller chose (the code tenancy issued).
type SeriesSpec struct {
	Code    string `json:"code"`
	DocType string `json:"doc_type"`
	Status  string `json:"status"` // active (default), dormant or closed
}

// MemberSpec is a member the device's pack lists. Without permissions the member holds every permission
// the intent registry names.
type MemberSpec struct {
	ID          string   `json:"id"`
	Permissions []string `json:"permissions"`
}

// RegisterRequest registers one device. The tenant, outlet and brand are the caller's: this is a dev stand-in
// for identity's activation, so it takes them from the body.
type RegisterRequest struct {
	TenantID string `json:"tenant_id"`
	OutletID string `json:"outlet_id"`
	BrandID  string `json:"brand_id"`
	DeviceID string `json:"device_id"`
	Kind     string `json:"kind"` // pos, waiter, kds or hub
	// Kid and Pub are the device's own public key (base64url, as client-core exports it). Without them the
	// registry generates a key pair and returns the private half (pkcs8), for harnesses that hold no key.
	Kid string `json:"kid"`
	Pub string `json:"pub"`
	// PackVersion is the version of the offline pack issued to the device, an integer of at least 1 (default 1).
	// It is the pack_v the device's client sends on every op (ADR-0005 A3.1).
	PackVersion int          `json:"pack_version"`
	Series      []SeriesSpec `json:"series"`
	Members     []MemberSpec `json:"members"`
	// TTLSeconds is the lifetime of the token returned (default 14 minutes, at most 24 hours).
	TTLSeconds int `json:"ttl_seconds"`
}

// RegisterResponse is what a device needs to start: its credential, the keys it verifies with and a token.
type RegisterResponse struct {
	DeviceID    string                  `json:"device_id"`
	Credential  sp.CredentialEnvelope   `json:"credential"`
	IdentityPub string                  `json:"identity_pub"`
	CloudKeys   map[string]string       `json:"cloud_keys"`
	Token       string                  `json:"token"`
	PKCS8       string                  `json:"pkcs8,omitempty"`
	Series      []map[string]string     `json:"series"`
	Peers       []sp.CredentialEnvelope `json:"peers,omitempty"`
	PackVersion int                     `json:"pack_version"`
	// HubPack is the file cmd/hub reads (SYNC_HUB_PACK), present for a hub registered with a generated key.
	HubPack *hub.Pack `json:"hub_pack,omitempty"`
}

func (r *Registry) registerDevice(w http.ResponseWriter, req *http.Request) {
	var in RegisterRequest
	if !decode(w, req, &in) {
		return
	}
	kind, ok := map[string]string{"pos": sp.KindPOS, "waiter": sp.KindWaiter, "kds": sp.KindKDS, "hub": sp.KindHub, "personal": sp.KindPersonal}[in.Kind]
	if in.TenantID == "" || in.OutletID == "" || in.DeviceID == "" || !ok {
		problem(w, http.StatusBadRequest, "tenant_id, outlet_id, device_id and a kind of pos, waiter, kds or hub are required")
		return
	}
	if _, exists := r.ID.Credential(in.TenantID, in.DeviceID); exists {
		problem(w, http.StatusConflict, "the device is already registered")
		return
	}
	kid, pub, pkcs8 := in.Kid, in.Pub, ""
	if pub == "" {
		if kid == "" {
			kid = "k-" + in.DeviceID
		}
		kp, err := sp.NewKeyPair(kid, nil)
		if err != nil {
			problem(w, http.StatusInternalServerError, "key generation failed")
			return
		}
		raw, err := x509.MarshalPKCS8PrivateKey(kp.Priv)
		if err != nil {
			problem(w, http.StatusInternalServerError, "key encoding failed")
			return
		}
		pub, pkcs8 = kp.PublicB64(), base64.RawURLEncoding.EncodeToString(raw)
	} else if kid == "" {
		problem(w, http.StatusBadRequest, "kid is required with pub")
		return
	} else if _, err := sp.DecodePub(pub); err != nil {
		problem(w, http.StatusBadRequest, "pub is not a public key")
		return
	}
	cred, err := r.ID.ActivatePub(in.TenantID, in.OutletID, in.BrandID, in.DeviceID, kind, kid, pub, "")
	if err != nil {
		problem(w, http.StatusConflict, err.Error())
		return
	}
	for _, s := range in.Series {
		state := s.Status
		if state == "" {
			state = directory.SeriesActive
		}
		if s.Code == "" || (state != directory.SeriesActive && state != directory.SeriesDormant && state != directory.SeriesClosed) {
			problem(w, http.StatusBadRequest, "a series needs a code and a status of active, dormant or closed")
			return
		}
		if err := r.ID.RegisterSeries(in.TenantID, s.Code, in.DeviceID, s.DocType, state); err != nil {
			problem(w, http.StatusConflict, err.Error())
			return
		}
	}
	r.members(in.TenantID, in.Members)
	pv := in.PackVersion
	if pv == 0 {
		pv = 1
	}
	if pv < 1 {
		problem(w, http.StatusBadRequest, "pack_version is an integer of at least 1")
		return
	}
	r.ID.IssuePack(in.TenantID, in.DeviceID, pv, 30*24*time.Hour)
	for _, s := range []string{"outlet:" + in.OutletID, "tenant:" + in.TenantID, "brand:" + in.BrandID} {
		if s != "brand:" {
			r.ID.DeclareStream(in.TenantID, s)
		}
	}
	if kind == sp.KindHub && pkcs8 != "" {
		r.keep(in.TenantID, in.DeviceID, pkcs8)
	}
	out := RegisterResponse{DeviceID: in.DeviceID, PackVersion: pv, Credential: cred, IdentityPub: sp.EncodePub(r.ID.IdentityPub()),
		CloudKeys: map[string]string{r.ID.CloudKey.Kid: r.ID.CloudKey.PublicB64()}, Token: r.token(in.TenantID, in.DeviceID, in.TTLSeconds), PKCS8: pkcs8,
		Series: []map[string]string{}, Peers: r.ID.Devices(in.TenantID, in.OutletID)}
	for _, s := range r.ID.SeriesOf(in.TenantID, in.DeviceID) {
		out.Series = append(out.Series, map[string]string{"code": s.Code, "docType": s.DocType, "state": s.State})
	}
	if kind == sp.KindHub {
		if p, ok := r.hubPack(in.TenantID, in.DeviceID); ok {
			out.HubPack = &p
		}
	}
	writeJSON(w, http.StatusCreated, out)
}

func (r *Registry) token(tenant, device string, ttlSeconds int) string {
	ttl := 14 * time.Minute
	if ttlSeconds > 0 && ttlSeconds <= 24*3600 {
		ttl = time.Duration(ttlSeconds) * time.Second
	}
	return r.Issuer.Mint(authtest.Spec{Type: auth.TypeDevice, Tenant: ids.ID(tenant), Device: device, TTL: ttl})
}

// members sets the members; with no permissions listed a member holds every permission of the intent registry.
func (r *Registry) members(tenant string, ms []MemberSpec) {
	for _, m := range ms {
		perms := m.Permissions
		if len(perms) == 0 {
			perms = allPermissions()
		}
		r.ID.SetMember(tenant, m.ID, perms...)
	}
}

func allPermissions() []string {
	set := map[string]bool{"kds.bump": true, "menu.availability.set": true}
	for _, in := range sp.Intents {
		if in.Permission != "" {
			set[in.Permission] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

type tokenRequest struct {
	TenantID   string `json:"tenant_id"`
	DeviceID   string `json:"device_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// mintToken mints a device token for a device registered in the tenant. A device of another tenant or one that
// does not exist is the same 404.
func (r *Registry) mintToken(w http.ResponseWriter, req *http.Request) {
	var in tokenRequest
	if !decode(w, req, &in) {
		return
	}
	if _, ok := r.ID.Credential(in.TenantID, in.DeviceID); !ok {
		problem(w, http.StatusNotFound, "no such device")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": r.token(in.TenantID, in.DeviceID, in.TTLSeconds)})
}

type memberRequest struct {
	TenantID string `json:"tenant_id"`
	MemberSpec
	// PackVersion re-issues the pack of every device of the tenant under this version so the member is listed.
	PackVersion int `json:"pack_version"`
}

func (r *Registry) setMember(w http.ResponseWriter, req *http.Request) {
	var in memberRequest
	if !decode(w, req, &in) {
		return
	}
	if in.TenantID == "" || in.ID == "" {
		problem(w, http.StatusBadRequest, "tenant_id and id are required")
		return
	}
	r.members(in.TenantID, []MemberSpec{in.MemberSpec})
	pv := in.PackVersion
	if pv == 0 {
		pv = 1
	}
	if pv < 1 {
		problem(w, http.StatusBadRequest, "pack_version is an integer of at least 1")
		return
	}
	for _, d := range r.ID.DevicesOf(in.TenantID) {
		r.ID.IssuePack(in.TenantID, d, pv, 30*24*time.Hour)
	}
	w.WriteHeader(http.StatusNoContent)
}

type bookRequest struct {
	TenantID  string   `json:"tenant_id"`
	Code      string   `json:"code"`
	OutletIDs []string `json:"outlet_ids"`
	Status    string   `json:"status"`
}

// registerBook registers a paper bill book as an entry-only manual_book series (what tenancy's
// registerManualBookSeries does in the real stack).
func (r *Registry) registerBook(w http.ResponseWriter, req *http.Request) {
	var in bookRequest
	if !decode(w, req, &in) {
		return
	}
	if in.TenantID == "" || in.Code == "" {
		problem(w, http.StatusBadRequest, "tenant_id and code are required")
		return
	}
	if err := r.ID.RegisterManualBook(in.TenantID, in.Code, in.Status, in.OutletIDs...); err != nil {
		problem(w, http.StatusConflict, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (r *Registry) trust(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"identity_pub": sp.EncodePub(r.ID.IdentityPub()),
		"cloud_keys": map[string]string{r.ID.CloudKey.Kid: r.ID.CloudKey.PublicB64()}})
}

func decode(w http.ResponseWriter, req *http.Request, into any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, req.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		problem(w, http.StatusBadRequest, "the body is not valid for this endpoint")
		return false
	}
	return true
}

func problem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:hostry:problem:sync.dev_registration", "title": "Dev registration refused", "status": status, "detail": detail})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
