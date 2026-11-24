// Package identitystub stands in for the identity and tenancy services in sync tests and the
// simulator (ADR-0002 PoC scope: "or a stub of it that enforces uniqueness per registration").
// It issues device credentials and offline packs, owns the document-series registry, verifies
// PIN-derived proofs with the shared failure counter of ADR-0005 A2.1, and keeps key-loss
// recovery records (A1.3). It is test support, not a service: nothing here is a secret.
package identitystub

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/hostryhq/svc-sync/directory"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

const (
	SeriesActive  = directory.SeriesActive
	SeriesDormant = directory.SeriesDormant
	SeriesClosed  = directory.SeriesClosed
)

const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no I, O, 0, 1 (S7)

// Types shared with the gateway.
type (
	Pack        = directory.Pack
	SeriesInfo  = directory.SeriesInfo
	ProofResult = directory.ProofResult
	RecoveryRec = directory.RecoveryRec
)

// Device is a registered device.
type Device struct {
	Env     sp.CredentialEnvelope
	Revoked bool
	Reason  string
	Packs   map[string]Pack
}

// Proof results.
const (
	ProofValid       = directory.ProofValid
	ProofMissing     = directory.ProofMissing
	ProofInvalid     = directory.ProofInvalid
	ProofLocked      = directory.ProofLocked
	ProofUnavailable = directory.ProofUnavailable
)

type member struct {
	removed bool
	perms   map[string]bool // current permissions
}

type pairKey struct{ tenant, member, device string }

type failures struct {
	sids   map[string]time.Time
	locked bool
}

// Identity is the in-memory stub.
type Identity struct {
	mu       sync.Mutex
	now      func() time.Time
	Key      *sp.KeyPair // identity signing key
	CloudKey *sp.KeyPair // gateway op-signing key, public half in every pack
	secret   []byte
	devices  map[string]*Device     // device id -> device (ids are globally unique UUIDs)
	series   map[string]*SeriesInfo // tenant|code
	nextCode map[string]int
	members  map[string]map[string]*member // tenant -> member -> state
	fail     map[pairKey]*failures
	recs     map[string]*RecoveryRec
	down     bool
	seq      int
}

// New builds a stub with fresh keys. r may be a seeded reader for reproducible keys.
func New(now func() time.Time, r interface{ Read([]byte) (int, error) }) (*Identity, error) {
	var rd = r
	k1, err := sp.NewKeyPair("identity-1", rd)
	if err != nil {
		return nil, err
	}
	k2, err := sp.NewKeyPair("gateway-op-1", rd)
	if err != nil {
		return nil, err
	}
	return &Identity{now: now, Key: k1, CloudKey: k2, secret: []byte("test-only-proof-secret"), devices: map[string]*Device{},
		series: map[string]*SeriesInfo{}, nextCode: map[string]int{}, members: map[string]map[string]*member{},
		fail: map[pairKey]*failures{}, recs: map[string]*RecoveryRec{}}, nil
}

// IdentityPub is the identity verification key.
func (i *Identity) IdentityPub() *ecdsa.PublicKey { return &i.Key.Priv.PublicKey }

// SetDown makes proof verification unavailable (identity outage).
func (i *Identity) SetDown(d bool) { i.mu.Lock(); i.down = d; i.mu.Unlock() }

// Activate registers a device and returns its credential. The caller keeps the private key.
func (i *Identity) Activate(tenant, outlet, brand, id, kind string, kp *sp.KeyPair, recovers string) (sp.CredentialEnvelope, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if _, ok := i.devices[id]; ok {
		return sp.CredentialEnvelope{}, errors.New("identitystub: device exists")
	}
	env, err := sp.SignCredential(i.Key, sp.Credential{DeviceID: id, TenantID: tenant, OutletID: outlet, BrandID: brand, Kind: kind,
		Kid: kp.Kid, Pub: kp.PublicB64(), Recovers: recovers, NotAfter: i.now().Add(24 * 365 * time.Hour).Unix()})
	if err != nil {
		return env, err
	}
	i.devices[id] = &Device{Env: env, Packs: map[string]Pack{}}
	return env, nil
}

// Credential returns a device's credential within the tenant.
func (i *Identity) Credential(tenant, device string) (sp.CredentialEnvelope, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	d, ok := i.devices[device]
	if !ok || d.Env.Cred.TenantID != tenant {
		return sp.CredentialEnvelope{}, false
	}
	return d.Env, true
}

// Devices lists the credentials of one outlet (the hub's pack lists its outlet's devices).
func (i *Identity) Devices(tenant, outlet string) []sp.CredentialEnvelope {
	i.mu.Lock()
	defer i.mu.Unlock()
	var out []sp.CredentialEnvelope
	for _, d := range i.devices {
		if d.Env.Cred.TenantID == tenant && d.Env.Cred.OutletID == outlet {
			out = append(out, d.Env)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Cred.DeviceID < out[b].Cred.DeviceID })
	return out
}

// Revoke revokes a device (ADR-0005 section 4).
func (i *Identity) Revoke(device, reason string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if d, ok := i.devices[device]; ok {
		d.Revoked, d.Reason = true, reason
	}
}

// Revoked reports revocation and its reason.
func (i *Identity) Revoked(tenant, device string) (bool, string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	d, ok := i.devices[device]
	if !ok || d.Env.Cred.TenantID != tenant {
		return false, ""
	}
	return d.Revoked, d.Reason
}

// IssueSeries issues the next series code under the tenant (one registration in the stub), unique
// across all its outlets and document types (S7).
func (i *Identity) IssueSeries(tenant, device, docType, state string) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	n := i.nextCode[tenant]
	i.nextCode[tenant]++
	code := string([]byte{codeAlphabet[(n/1024)%32], codeAlphabet[(n/32)%32], codeAlphabet[n%32]})
	i.series[tenant+"|"+code] = &SeriesInfo{Tenant: tenant, Code: code, Device: device, DocType: docType, State: state}
	return code
}

// SetSeriesState changes a series state (activation, closing).
func (i *Identity) SetSeriesState(tenant, code, state string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if s, ok := i.series[tenant+"|"+code]; ok {
		s.State = state
	}
}

// Series looks a code up within the tenant only. A code issued under another tenant is not found:
// the answer is the same as for a code that exists nowhere (A1.1, V2).
func (i *Identity) Series(tenant, code string) (SeriesInfo, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	s, ok := i.series[tenant+"|"+code]
	if !ok {
		return SeriesInfo{}, false
	}
	return *s, true
}

// SeriesOf lists the series issued to a device.
func (i *Identity) SeriesOf(tenant, device string) []SeriesInfo {
	i.mu.Lock()
	defer i.mu.Unlock()
	var out []SeriesInfo
	for _, s := range i.series {
		if s.Tenant == tenant && s.Device == device {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Code < out[b].Code })
	return out
}

// SetMember sets (or replaces) a member's current permissions.
func (i *Identity) SetMember(tenant, id string, perms ...string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.members[tenant] == nil {
		i.members[tenant] = map[string]*member{}
	}
	m := &member{perms: map[string]bool{}}
	for _, p := range perms {
		m.perms[p] = true
	}
	i.members[tenant][id] = m
}

// RemoveMember removes a member (staff left); packs already issued still list them.
func (i *Identity) RemoveMember(tenant, id string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if m := i.members[tenant][id]; m != nil {
		m.removed = true
	}
}

// WithdrawPermission removes one permission from a member.
func (i *Identity) WithdrawPermission(tenant, id, perm string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if m := i.members[tenant][id]; m != nil {
		delete(m.perms, perm)
	}
}

// IssuePack records a pack for a device: the members and permissions as they are now.
func (i *Identity) IssuePack(tenant, device, version string, ttl time.Duration) {
	i.mu.Lock()
	defer i.mu.Unlock()
	d := i.devices[device]
	if d == nil {
		return
	}
	p := Pack{Version: version, Members: map[string]map[string]bool{}, Expires: i.now().Add(ttl)}
	for id, m := range i.members[tenant] {
		if m.removed {
			continue
		}
		cp := map[string]bool{}
		for k := range m.perms {
			cp[k] = true
		}
		p.Members[id] = cp
	}
	d.Packs[version] = p
}

// PackFor returns the pack of a given version issued to the device.
func (i *Identity) PackFor(tenant, device, version string) (Pack, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	d := i.devices[device]
	if d == nil || d.Env.Cred.TenantID != tenant {
		return Pack{}, false
	}
	p, ok := d.Packs[version]
	return p, ok
}

// InAnyPack reports whether the member appeared in any pack issued to the device.
func (i *Identity) InAnyPack(tenant, device, actor string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	d := i.devices[device]
	if d == nil || d.Env.Cred.TenantID != tenant {
		return false
	}
	for _, p := range d.Packs {
		if _, ok := p.Members[actor]; ok {
			return true
		}
	}
	return false
}

// StillHolds reports whether the member exists now and still holds the permission.
func (i *Identity) StillHolds(tenant, actor, perm string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	m := i.members[tenant][actor]
	return m != nil && !m.removed && m.perms[perm]
}

// MintProof makes the proof a device holds for a member: valid proofs derive from a secret the
// stub shares with the test devices; an invalid proof is any other string.
func (i *Identity) MintProof(device, actor string) string {
	mac := hmac.New(sha256.New, i.secret)
	mac.Write([]byte(device + "|" + actor))
	return "p1:" + hex.EncodeToString(mac.Sum(nil))[:24]
}

const (
	failWindow = 15 * time.Minute
	failCap5   = 5
	failCapDay = 10
)

// CheckProof verifies a session or action proof and keeps the shared failure counter (A1.2 item 4).
// configClass is true for configuration ops, for which a locked pair is answered without a check.
// A failure counts once per sid.
func (i *Identity) CheckProof(tenant, device, actor, sid, proof string, configClass bool) ProofResult {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.down {
		return ProofUnavailable
	}
	pk := pairKey{tenant, actor, device}
	f := i.fail[pk]
	if f == nil {
		f = &failures{sids: map[string]time.Time{}}
		i.fail[pk] = f
	}
	i.refreshLock(f)
	if configClass && f.locked {
		return ProofLocked
	}
	if proof == "" {
		return ProofMissing
	}
	mac := hmac.New(sha256.New, i.secret)
	mac.Write([]byte(device + "|" + actor))
	if hmac.Equal([]byte(proof), []byte("p1:"+hex.EncodeToString(mac.Sum(nil))[:24])) {
		return ProofValid
	}
	if _, seen := f.sids[sid]; !seen {
		f.sids[sid] = i.now()
		i.refreshLock(f)
	}
	return ProofInvalid
}

func (i *Identity) refreshLock(f *failures) {
	now := i.now()
	inWindow, inDay := 0, 0
	for _, t := range f.sids {
		if now.Sub(t) <= failWindow {
			inWindow++
		}
		if now.Sub(t) <= 24*time.Hour {
			inDay++
		}
	}
	if inWindow >= failCap5 || inDay >= failCapDay {
		f.locked = true
	}
}

// ClearLock clears the proof lock of a member on a device (by someone who may administer them).
func (i *Identity) ClearLock(tenant, actor, device string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.fail, pairKey{tenant, actor, device})
}

// Failures returns the failures counted for a pair (tests: shared counter, RB5).
func (i *Identity) Failures(tenant, actor, device string) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	if f := i.fail[pairKey{tenant, actor, device}]; f != nil {
		return len(f.sids)
	}
	return 0
}

// CreateRecovery issues a recovery code for a key-lost device; only an owner may (A1.3 item 2).
func (i *Identity) CreateRecovery(tenant, old string, byOwner bool) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !byOwner {
		return "", errors.New("identitystub: only an owner may recover a device")
	}
	d := i.devices[old]
	if d == nil || d.Env.Cred.TenantID != tenant {
		return "", errors.New("identitystub: unknown device")
	}
	for _, r := range i.recs {
		if r.Old == old && r.Used {
			return "", errors.New("identitystub: device already recovered")
		}
	}
	i.seq++
	id := fmt.Sprintf("rec-%d", i.seq)
	code := fmt.Sprintf("RC%06d", i.seq)
	i.recs[code] = &RecoveryRec{ID: id, Tenant: tenant, Old: old, Code: code, Expires: i.now().Add(10 * time.Minute)}
	return code, nil
}

// ErrRecoveryCode is returned for a used, expired or unknown recovery code.
var ErrRecoveryCode = errors.New("identitystub: recovery code not valid")

// ActivateRecovery turns an installation into a new device (A1.3 item 3), in one step: the old
// device is revoked with reason key_lost, the new one registered with new series codes for the
// same document types, and a single-use record written.
func (i *Identity) ActivateRecovery(code, newID string, kp *sp.KeyPair) (sp.CredentialEnvelope, RecoveryRec, error) {
	i.mu.Lock()
	r := i.recs[code]
	if r == nil || r.Used || i.now().After(r.Expires) {
		i.mu.Unlock()
		return sp.CredentialEnvelope{}, RecoveryRec{}, ErrRecoveryCode
	}
	old := i.devices[r.Old]
	oc := old.Env.Cred
	r.Used, r.New = true, newID
	old.Revoked, old.Reason = true, "key_lost"
	i.mu.Unlock()
	env, err := i.Activate(oc.TenantID, oc.OutletID, oc.BrandID, newID, oc.Kind, kp, oc.DeviceID)
	if err != nil {
		return env, RecoveryRec{}, err
	}
	// New series codes for the same document types; the old series are closed (A1.3 item 5).
	for _, s := range i.SeriesOf(oc.TenantID, oc.DeviceID) {
		if s.State == SeriesClosed {
			continue
		}
		i.IssueSeries(oc.TenantID, newID, s.DocType, s.State)
		i.SetSeriesState(oc.TenantID, s.Code, SeriesClosed)
	}
	return env, *r, nil
}

// RecoveryFor returns the used recovery record for an old device within the tenant.
func (i *Identity) RecoveryFor(tenant, old string) (RecoveryRec, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, r := range i.recs {
		if r.Tenant == tenant && r.Old == old && r.Used {
			return *r, true
		}
	}
	return RecoveryRec{}, false
}

// Now is the stub's clock.
func (i *Identity) Now() time.Time { return i.now() }

// InAnyPackOf reports whether the member appears in a pack issued to any device of the outlet:
// what the hub's pack tells it about the outlet's staff (S8).
func (i *Identity) InAnyPackOf(tenant, outlet, actor string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, d := range i.devices {
		if d.Env.Cred.TenantID != tenant || d.Env.Cred.OutletID != outlet {
			continue
		}
		for _, p := range d.Packs {
			if _, ok := p.Members[actor]; ok {
				return true
			}
		}
	}
	return false
}

// PinTokenFailure counts a failed PIN check at the pin token request against the same counter the
// gateway uses (A1.2 item 4: failures at the token request and at the gateway share it).
func (i *Identity) PinTokenFailure(tenant, actor, device, sid string) {
	i.CheckProof(tenant, device, actor, sid, "bogus-at-token-request", false)
}

// RecoveryCodeDevice names the device a recovery code is bound to.
func (i *Identity) RecoveryCodeDevice(code string) (string, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	r := i.recs[code]
	if r == nil {
		return "", false
	}
	return r.Old, true
}
