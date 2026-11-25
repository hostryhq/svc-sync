// Package identitystub stands in for the identity and tenancy services in sync tests and the
// simulator (ADR-0002 PoC scope: "or a stub of it that enforces uniqueness per registration").
// It issues device credentials and offline packs, owns the document-series registry, verifies
// PIN-derived proofs with the shared failure counter of ADR-0005 A2.1, and keeps key-loss
// recovery records (A1.3). It is test support, not a service: nothing here is a secret.
package identitystub

import (
	"context"
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
	Pack          = directory.Pack
	SeriesInfo    = directory.SeriesInfo
	ProofResult   = directory.ProofResult
	ProofQuestion = directory.ProofQuestion
	RecoveryRec   = directory.RecoveryRec
)

// Device is a registered device.
type Device struct {
	Env     sp.CredentialEnvelope
	Revoked bool
	Reason  string
	Packs   map[int]Pack
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
	drained  map[string]map[string]int64
	reports  map[string]directory.DrainReport
	strong   map[string]*strongRow
	idem     map[string]ProofResult
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
	return i.ActivatePub(tenant, outlet, brand, id, kind, kp.Kid, kp.PublicB64(), recovers)
}

// ActivatePub registers a device by its public key (base64url) alone: the private key never reaches identity.
func (i *Identity) ActivatePub(tenant, outlet, brand, id, kind, kid, pub, recovers string) (sp.CredentialEnvelope, error) {
	return i.ActivateStore(tenant, outlet, brand, id, kind, kid, pub, recovers, sp.StoreProtected)
}

// ActivateStore is ActivatePub with the device store claim (ADR-0002 A3.5 item 1).
func (i *Identity) ActivateStore(tenant, outlet, brand, id, kind, kid, pub, recovers, store string) (sp.CredentialEnvelope, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if _, ok := i.devices[id]; ok {
		return sp.CredentialEnvelope{}, errors.New("identitystub: device exists")
	}
	env, err := sp.SignCredential(i.Key, sp.Credential{DeviceID: id, TenantID: tenant, OutletID: outlet, BrandID: brand, Kind: kind,
		Kid: kid, Pub: pub, Store: store, Recovers: recovers, NotAfter: i.now().Add(24 * 365 * time.Hour).Unix()})
	if err != nil {
		return env, err
	}
	i.devices[id] = &Device{Env: env, Packs: map[int]Pack{}}
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

// RecordDrained implements directory.DrainRecorder: the stub remembers the last report per device.
func (i *Identity) RecordDrained(_ context.Context, tenant, device string, rep directory.DrainReport) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	d, ok := i.devices[device]
	if !ok || d.Env.Cred.TenantID != tenant || !d.Revoked {
		return errors.New("identitystub: only a revoked device of the tenant can be drained")
	}
	if i.drained == nil {
		i.drained = map[string]map[string]int64{}
	}
	i.drained[device] = rep.Through
	if i.reports == nil {
		i.reports = map[string]directory.DrainReport{}
	}
	i.reports[device] = rep
	return nil
}

// DrainReportOf returns the full report RecordDrained last stored for a device (the statement and its series).
func (i *Identity) DrainReportOf(device string) (directory.DrainReport, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	r, ok := i.reports[device]
	return r, ok
}

// Drained returns what RecordDrained last stored for a device.
func (i *Identity) Drained(device string) (map[string]int64, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	m, ok := i.drained[device]
	return m, ok
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

// IssueManualBook registers a paper bill book as an entry-only series (kind manual_book) for the outlets
// given (none means every outlet), under the code the owner chose. It has no device and no document type.
func (i *Identity) IssueManualBook(tenant, code string, outlets ...string) {
	_ = i.RegisterManualBook(tenant, code, SeriesActive, outlets...)
}

// RegisterManualBook is IssueManualBook with a state (active or closed; empty means active) and the refusal
// tenancy gives: a code is unique across the device series and the books of a tenant.
func (i *Identity) RegisterManualBook(tenant, code, state string, outlets ...string) error {
	if state == "" {
		state = SeriesActive
	}
	if state != SeriesActive && state != SeriesClosed {
		return fmt.Errorf("identitystub: a manual book is active or closed, not %q", state)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if _, ok := i.series[tenant+"|"+code]; ok {
		return fmt.Errorf("identitystub: series code %s is in use", code)
	}
	i.series[tenant+"|"+code] = &SeriesInfo{Tenant: tenant, Code: code, State: state, Kind: directory.SeriesKindManualBook, Outlets: outlets}
	return nil
}

// RegisterSeries issues a series under a code the caller chose (the code tenancy issued) to a device.
func (i *Identity) RegisterSeries(tenant, code, device, docType, state string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if _, ok := i.series[tenant+"|"+code]; ok {
		return fmt.Errorf("identitystub: series code %s is in use", code)
	}
	i.series[tenant+"|"+code] = &SeriesInfo{Tenant: tenant, Code: code, Device: device, DocType: docType, State: state}
	return nil
}

// DevicesOf lists the ids of the tenant's devices.
func (i *Identity) DevicesOf(tenant string) []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	var out []string
	for id, d := range i.devices {
		if d.Env.Cred.TenantID == tenant {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
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

// SeriesFor implements directory.Directory. The stub can tell a series of another device from one that was
// never issued, so the gateway keeps its foreign_series / unknown_series marks apart.
func (i *Identity) SeriesFor(tenant, _, _, code string) (SeriesInfo, bool) {
	return i.Series(tenant, code)
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
func (i *Identity) IssuePack(tenant, device string, version int, ttl time.Duration) {
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
func (i *Identity) PackFor(tenant, device string, version int) (Pack, bool) {
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
func (i *Identity) StillHolds(tenant, _, actor, perm string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	m := i.members[tenant][actor]
	return m != nil && !m.removed && m.perms[perm]
}

// MintProof makes the proof a device holds for a question: valid proofs derive from a secret the stub shares with
// the test devices and are bound to every field identity binds (session: device, member, session id, pack_v,
// pin_v and the opening time; approval: those of the approval record). An invalid proof is any other string.
func (i *Identity) MintProof(q ProofQuestion) string {
	mac := hmac.New(sha256.New, i.secret)
	fmt.Fprintf(mac, "%s|%s|%s|%s|%d|%d|%s|%s|%s|%s|%s|%s|%s", q.Kind, q.Device, q.Member, q.SID, q.PackV, q.PinV, q.OpenedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		q.ApprovalID, q.Permission, q.Target, q.Requester, q.ActionHash, q.ApprovedAt.UTC().Format("2006-01-02T15:04:05.000Z"))
	return "p2:" + hex.EncodeToString(mac.Sum(nil))[:24]
}

const (
	failWindow = 15 * time.Minute
	failCap5   = 5
	failCapDay = 10
)

// VerifyProof verifies a session or approval proof and keeps the shared failure counter (A1.2 item 4). A locked
// pair is answered `locked` for every op kind. A failure counts once per proof (sid or approval id plus a digest
// of the wrong proof), and a question repeated under the same Key is a replay: the first answer, counted once.
func (i *Identity) VerifyProof(tenant string, q ProofQuestion) ProofResult {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.down {
		return ProofUnavailable
	}
	ik := tenant + "|" + q.Key
	if q.Key != "" {
		if r, ok := i.idem[ik]; ok {
			return r
		}
	}
	r := i.verify(tenant, q)
	if q.Key != "" {
		if i.idem == nil {
			i.idem = map[string]ProofResult{}
		}
		i.idem[ik] = r
	}
	return r
}

func (i *Identity) verify(tenant string, q ProofQuestion) ProofResult {
	pk := pairKey{tenant, q.Member, q.Device}
	f := i.fail[pk]
	if f == nil {
		f = &failures{sids: map[string]time.Time{}}
		i.fail[pk] = f
	}
	i.refreshLock(f)
	if f.locked {
		// Locked for every op kind, as real identity answers (security final verdict). Nothing is
		// checked or counted any more: the counter is capped at the lock (RB5).
		return ProofLocked
	}
	if q.Proof == "" {
		return ProofMissing
	}
	if hmac.Equal([]byte(q.Proof), []byte(i.MintProof(q))) {
		return ProofValid
	}
	// Each distinct wrong proof counts (key: sid plus proof digest); an identical retry does not.
	ph := sha256.Sum256([]byte(q.Proof))
	id := q.SID
	if q.Kind == directory.ProofKindApproval {
		id = q.ApprovalID
	}
	fk := id + "|" + hex.EncodeToString(ph[:12])
	if _, seen := f.sids[fk]; !seen {
		f.sids[fk] = i.now()
		i.refreshLock(f)
	}
	return ProofInvalid
}

// CheckProof is VerifyProof for a session proof asked without an idempotency key (a new question each time).
func (i *Identity) CheckProof(tenant, device, actor, sid, proof string, _ bool) ProofResult {
	return i.VerifyProof(tenant, ProofQuestion{Kind: directory.ProofKindSession, Device: device, Member: actor, SID: sid, Proof: proof})
}

type strongRow struct {
	facts directory.SessionFacts
}

// OpenStrong records a strong session (identity's own session, issued after an online sign-in).
func (i *Identity) OpenStrong(tenant, sid, member, device string, issued time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.strong == nil {
		i.strong = map[string]*strongRow{}
	}
	i.strong[tenant+"|"+sid] = &strongRow{facts: directory.SessionFacts{Member: member, Device: device, Issued: issued}}
}

// EndStrong ends a strong session at the given time (the revocation feed's `session` subject).
func (i *Identity) EndStrong(tenant, sid string, at time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if r := i.strong[tenant+"|"+sid]; r != nil {
		r.facts.Ended = at
	}
}

// StrongSession implements directory.Directory.
func (i *Identity) StrongSession(tenant, sid string) (directory.SessionFacts, directory.Lookup) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.down {
		return directory.SessionFacts{}, directory.Unreachable
	}
	r := i.strong[tenant+"|"+sid]
	if r == nil {
		return directory.SessionFacts{}, directory.NotFound
	}
	return r.facts, directory.Found
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
	if d.Revoked {
		// Only an active device can be recovered: a thief holding a revoked PC's disk must not be able to
		// get it re-admitted by phishing the owner (security review ruling 2 (a), ADR-0002 A1.3).
		return "", ErrRecoveryRevoked
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

// ErrRecoveryRevoked is returned when the device to recover is already revoked, for any reason.
var ErrRecoveryRevoked = errors.New("identitystub: a revoked device cannot be recovered")

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
	if old.Revoked {
		// Revoked after the code was issued (a stolen or retired device): the code is dead.
		i.mu.Unlock()
		return sp.CredentialEnvelope{}, RecoveryRec{}, ErrRecoveryRevoked
	}
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

// MembersOfOutlet lists, sorted, the members that appear in a pack issued to any device of the outlet: the staff a
// hub's pack lists (S8).
func (i *Identity) MembersOfOutlet(tenant, outlet string) []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	set := map[string]bool{}
	for _, d := range i.devices {
		if d.Env.Cred.TenantID != tenant || d.Env.Cred.OutletID != outlet {
			continue
		}
		for _, p := range d.Packs {
			for m := range p.Members {
				set[m] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}
