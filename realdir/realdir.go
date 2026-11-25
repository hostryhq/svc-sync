// Package realdir is the gateway's directory over the identity and tenancy services (ADR-0005 A3.2): device
// credentials, issued packs, current member grants, key-loss recovery records, strong sessions, the proof check, the
// revocation feed, pack history and drain from identity; the series of a device, the paper bill books of an outlet and
// the owner of a stream from tenancy. It caches what cannot change without expiry and everything else for 60 seconds.
//
// The failure rule of A3.2: an unanswered question is never "found", "held" or "valid". A lookup that could not be
// asked answers "not found" to the caller and counts a fault (Faults), so that the gateway makes a configuration op
// wait and stores a trading fact with the pending mark instead of judging it on a guess.
package realdir

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/identityclient"
	sp "github.com/hostryhq/svc-sync/syncproto"
	"github.com/hostryhq/svc-sync/tenancyclient"
)

// Cache times (A3.2).
const (
	shortTTL  = 60 * time.Second
	maxCached = 20000
)

// Directory implements directory.Directory, directory.DrainRecorder and directory.Faulty.
type Directory struct {
	Identity *identityclient.Client
	Tenancy  *tenancyclient.Client
	// Clock defaults to time.Now.
	Clock func() time.Time
	// StateFile, when set, persists the revocation cursor and set across restarts (A3.2 row 5).
	StateFile string

	faults atomic.Uint64
	polled atomic.Bool

	mu     sync.RWMutex
	loaded bool
	rev    revState

	creds   *cache[sp.CredentialEnvelope]
	packs   *cache[*directory.Pack]
	members *cache[identityclient.MemberGrants]
	history *cache[bool]
	series  *cache[[]tenancyclient.Series]
	books   *cache[[]tenancyclient.Book]
	owners  *cache[tenancyclient.StreamOwner]
	recov   *cache[directory.RecoveryRec]
	strong  *cache[directory.SessionFacts]
	once    sync.Once
}

var (
	_ directory.Directory     = (*Directory)(nil)
	_ directory.DrainRecorder = (*Directory)(nil)
	_ directory.Faulty        = (*Directory)(nil)
)

type revDevice struct {
	Reason     string    `json:"reason"`
	RecoveryID string    `json:"recovery_id,omitempty"`
	At         time.Time `json:"at"`
}

// revState is the persisted state of the revocation feed.
type revState struct {
	Cursor   string               `json:"cursor"`
	Devices  map[string]revDevice `json:"devices"`  // tenant|device
	Sessions map[string]time.Time `json:"sessions"` // tenant|sid
}

func (d *Directory) init() {
	d.once.Do(func() {
		d.creds = newCache[sp.CredentialEnvelope](maxCached)
		d.packs = newCache[*directory.Pack](maxCached)
		d.members = newCache[identityclient.MemberGrants](maxCached)
		d.history = newCache[bool](maxCached)
		d.series = newCache[[]tenancyclient.Series](maxCached)
		d.books = newCache[[]tenancyclient.Book](maxCached)
		d.owners = newCache[tenancyclient.StreamOwner](maxCached)
		d.recov = newCache[directory.RecoveryRec](maxCached)
		d.strong = newCache[directory.SessionFacts](maxCached)
		d.rev = revState{Devices: map[string]revDevice{}, Sessions: map[string]time.Time{}}
		if d.StateFile != "" {
			if raw, err := os.ReadFile(d.StateFile); err == nil {
				var st revState
				if json.Unmarshal(raw, &st) == nil {
					if st.Devices == nil {
						st.Devices = map[string]revDevice{}
					}
					if st.Sessions == nil {
						st.Sessions = map[string]time.Time{}
					}
					d.rev = st
					d.polled.Store(st.Cursor != "")
				}
			}
		}
	})
}

// Faults counts the lookups that could not be asked or answered since the start. The gateway compares it before
// and after judging an op.
func (d *Directory) Faults() uint64 { return d.faults.Load() }

// Gaps lists the directory questions the real directory cannot answer. Since A3.2 it is empty.
func (d *Directory) Gaps() []string { return nil }

func (d *Directory) now() time.Time {
	if d.Clock != nil {
		return d.Clock()
	}
	return time.Now()
}

// Now implements directory.Directory.
func (d *Directory) Now() time.Time { return d.now() }

func (d *Directory) ctx() context.Context { return context.Background() }

// fault records a lookup that failed for a reason other than "no such record".
func (d *Directory) fault(err error) {
	if err != nil && !errors.Is(err, identityclient.ErrNotFound) && !errors.Is(err, tenancyclient.ErrNotFound) {
		d.faults.Add(1)
	}
}

// Poll reads the revocation feed from the last cursor to its end. The gateway polls on start and every 60 seconds.
// A failed page leaves the cursor where it was.
func (d *Directory) Poll(ctx context.Context) error {
	d.init()
	for {
		d.mu.RLock()
		cur := d.rev.Cursor
		d.mu.RUnlock()
		items, next, err := d.Identity.Revocations(ctx, cur)
		if err != nil {
			return err
		}
		d.mu.Lock()
		for _, r := range items {
			if r.Device {
				reason := r.Reason
				if reason == "" {
					reason = "revoked"
				}
				d.rev.Devices[r.Tenant+"|"+r.Subject] = revDevice{Reason: reason, RecoveryID: r.RecoveryID, At: r.At}
			} else {
				d.rev.Sessions[r.Tenant+"|"+r.Subject] = r.At
				d.strong.drop(r.Tenant + "|" + r.Subject)
			}
		}
		if next != "" {
			d.rev.Cursor = next
		} else if len(items) > 0 {
			d.rev.Cursor = items[len(items)-1].ID
		}
		d.save()
		d.mu.Unlock()
		if next == "" {
			d.polled.Store(true)
			return nil
		}
	}
}

// Ready reports whether the revocation feed has been read once (or its persisted state loaded): until then the
// gateway cannot say that a device is revoked, so it is not ready.
func (d *Directory) Ready() error {
	d.init()
	if !d.polled.Load() {
		return errors.New("realdir: the revocation feed has not been read yet")
	}
	return nil
}

// save persists the revocation state (the caller holds the lock). A write failure is not fatal: the feed is read
// from the start again after a restart.
func (d *Directory) save() {
	if d.StateFile == "" {
		return
	}
	raw, err := json.Marshal(d.rev)
	if err != nil {
		return
	}
	tmp := d.StateFile + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) == nil {
		_ = os.Rename(tmp, d.StateFile)
	}
}

// Run polls until ctx ends.
func (d *Directory) Run(ctx context.Context, every time.Duration, onErr func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := d.Poll(ctx); err != nil && onErr != nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Revoked implements directory.Directory: the revocation feed is the only source (A3.2 row 5); no other answer ever
// says a device is revoked. The reason is revoked or key_lost.
func (d *Directory) Revoked(tenant, device string) (bool, string) {
	d.init()
	d.mu.RLock()
	defer d.mu.RUnlock()
	r, ok := d.rev.Devices[tenant+"|"+device]
	if !ok {
		return false, ""
	}
	return true, r.Reason
}

// Credential implements directory.Directory (A3.2 row 1): one key per device id for life, so no expiry; 404 is not
// cached. The credential is unsigned here: the gateway trusts the route, not a signature.
func (d *Directory) Credential(tenant, device string) (sp.CredentialEnvelope, bool) {
	d.init()
	k := tenant + "|" + device
	if c, ok := d.creds.get(k, d.now()); ok {
		return c, true
	}
	c, err := d.Identity.GetDeviceCredential(d.ctx(), tenant, device)
	if err != nil {
		d.fault(err)
		return sp.CredentialEnvelope{}, false
	}
	if c.TenantID != tenant {
		return sp.CredentialEnvelope{}, false
	}
	env := sp.CredentialEnvelope{Cred: sp.Credential{DeviceID: c.DeviceID, TenantID: c.TenantID, OutletID: c.OutletID, BrandID: c.BrandID, Kind: c.Kind, Kid: c.Kid, Pub: c.Pub, Recovers: c.Recovers}}
	d.creds.put(k, env, d.now(), 0)
	return env, true
}

// PackFor implements directory.Directory (A3.2 row 2): an issued pack is immutable, so no expiry; 404 pack_unknown
// is cached for 60 seconds.
func (d *Directory) PackFor(tenant, device string, version int) (directory.Pack, bool) {
	d.init()
	k := tenant + "|" + device + "|" + itoa(version)
	if p, ok := d.packs.get(k, d.now()); ok {
		if p == nil {
			return directory.Pack{}, false
		}
		return *p, true
	}
	g, err := d.Identity.GetPackGrants(d.ctx(), tenant, device, version)
	if err != nil {
		if errors.Is(err, identityclient.ErrNotFound) {
			d.packs.put(k, nil, d.now(), shortTTL)
		}
		d.fault(err)
		return directory.Pack{}, false
	}
	p := &directory.Pack{Version: version, Expires: g.OfflineValidUntil, Members: map[string]map[string]bool{}}
	for m, perms := range g.Members {
		set := map[string]bool{}
		for _, x := range perms {
			set[x] = true
		}
		p.Members[m] = set
	}
	d.packs.put(k, p, d.now(), 0)
	return *p, true
}

// InAnyPack implements directory.Directory with checkPackHistory without a pack version: "any pack issued to the
// device" (A3.2 row 7). true is cached without expiry, false for 60 seconds.
func (d *Directory) InAnyPack(tenant, device, actor string) bool {
	d.init()
	k := tenant + "|" + device + "|" + actor
	if v, ok := d.history.get(k, d.now()); ok {
		return v
	}
	h, err := d.Identity.CheckPackHistory(d.ctx(), tenant, device, 0, actor, "")
	if err != nil {
		d.fault(err)
		return false
	}
	if h.MemberInPack {
		d.history.put(k, true, d.now(), 0)
	} else {
		d.history.put(k, false, d.now(), shortTTL)
	}
	return h.MemberInPack
}

// StillHolds implements directory.Directory (A3.2 row 3, cached 60 seconds): the member is active now and holds the
// permission at the outlet.
func (d *Directory) StillHolds(tenant, outlet, actor, perm string) bool {
	d.init()
	k := tenant + "|" + outlet + "|" + actor
	g, ok := d.members.get(k, d.now())
	if !ok {
		var err error
		if g, err = d.Identity.GetMemberGrants(d.ctx(), tenant, actor, outlet); err != nil {
			d.fault(err)
			return false
		}
		d.members.put(k, g, d.now(), shortTTL)
	}
	if g.Status != "active" {
		return false
	}
	for _, p := range g.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

// VerifyProof implements directory.Directory. A question that identity rejects (422: the proof does not fit it) is
// an invalid proof; one it cannot answer is unavailable, never valid.
func (d *Directory) VerifyProof(tenant string, q directory.ProofQuestion) directory.ProofResult {
	if q.Proof == "" {
		return directory.ProofMissing
	}
	in := identityclient.ProofCheck{DeviceID: q.Device, MemberID: q.Member, SessionID: q.SID, PackV: q.PackV, PinV: q.PinV, OpenedAt: q.OpenedAt,
		Proof: q.Proof, Key: q.Key}
	if q.Kind == directory.ProofKindApproval {
		in.ApprovalID, in.ActionHash, in.Permission, in.Target, in.RequesterID, in.Reason, in.ApprovedAt =
			q.ApprovalID, q.ActionHash, q.Permission, q.Target, q.Requester, q.Reason, q.ApprovedAt
	}
	v, err := d.Identity.VerifyProof(d.ctx(), tenant, in)
	switch {
	case errors.Is(err, identityclient.ErrRejected):
		return directory.ProofInvalid
	case err != nil:
		d.fault(err)
		return directory.ProofUnavailable
	case v.Locked:
		return directory.ProofLocked
	case v.Valid:
		return directory.ProofValid
	}
	return directory.ProofInvalid
}

// StrongSession implements directory.Directory (A3.2 row 6): the facts never change, so no expiry; the end arrives
// on the revocation feed.
func (d *Directory) StrongSession(tenant, sid string) (directory.SessionFacts, directory.Lookup) {
	d.init()
	k := tenant + "|" + sid
	f, ok := d.strong.get(k, d.now())
	if !ok {
		s, err := d.Identity.GetSession(d.ctx(), tenant, sid)
		switch {
		case errors.Is(err, identityclient.ErrNotFound):
			return directory.SessionFacts{}, directory.NotFound
		case err != nil:
			d.fault(err)
			return directory.SessionFacts{}, directory.Unreachable
		}
		f = directory.SessionFacts{Member: s.MemberID, Device: s.DeviceID, Issued: s.IssuedAt, Ended: s.EndedAt}
		d.strong.put(k, f, d.now(), 0)
	}
	d.mu.RLock()
	if end, ended := d.rev.Sessions[k]; ended {
		f.Ended = end
	}
	d.mu.RUnlock()
	return f, directory.Found
}

// RecoveryFor implements directory.Directory (A3.2 row 4): found is cached without expiry (single use), 404 never.
// Identity never returns the code, so Code is empty.
func (d *Directory) RecoveryFor(tenant, old string) (directory.RecoveryRec, bool) {
	d.init()
	k := tenant + "|" + old
	if r, ok := d.recov.get(k, d.now()); ok {
		return r, true
	}
	r, err := d.Identity.GetDeviceRecovery(d.ctx(), tenant, old)
	if err != nil {
		d.fault(err)
		return directory.RecoveryRec{}, false
	}
	rec := directory.RecoveryRec{ID: r.ID, Tenant: tenant, Old: r.OldDeviceID, New: r.NewDeviceID, Used: true}
	d.recov.put(k, rec, d.now(), 0)
	return rec, true
}

func seriesState(s string) string {
	switch s {
	case "dormant":
		return directory.SeriesDormant
	case "closed", "closed_unreconciled":
		return directory.SeriesClosed
	}
	return directory.SeriesActive
}

// SeriesFor implements directory.Directory over tenancy (A3.2 row 8): the series issued to the device (by device,
// not by code), then the registered paper books of its outlet. A code of another device is not found, so the
// gateway holds it as foreign_series. Cached 60 seconds; DropSeries and DropBooks clear it on the events.
func (d *Directory) SeriesFor(tenant, device, outlet, code string) (directory.SeriesInfo, bool) {
	d.init()
	k := tenant + "|" + device
	ss, ok := d.series.get(k, d.now())
	if !ok {
		var err error
		if ss, err = d.Tenancy.DeviceSeries(d.ctx(), tenant, device); err != nil {
			d.fault(err)
		} else {
			d.series.put(k, ss, d.now(), shortTTL)
		}
	}
	for _, s := range ss {
		if s.Code == code {
			return directory.SeriesInfo{Tenant: tenant, Code: code, Device: device, DocType: s.DocType, State: seriesState(s.Status)}, true
		}
	}
	if outlet == "" {
		return directory.SeriesInfo{}, false
	}
	bk := tenant + "|" + outlet
	bs, ok := d.books.get(bk, d.now())
	if !ok {
		var err error
		if bs, err = d.Tenancy.OutletBooks(d.ctx(), tenant, outlet); err != nil {
			d.fault(err)
		} else {
			d.books.put(bk, bs, d.now(), shortTTL)
		}
	}
	for _, b := range bs {
		if b.Code == code {
			return directory.SeriesInfo{Tenant: tenant, Code: code, State: seriesState(b.Status), Kind: directory.SeriesKindManualBook, Outlets: b.OutletIDs}, true
		}
	}
	return directory.SeriesInfo{}, false
}

// DropSeries clears the cached series of a device (tenancy.series.issued, tenancy.series.closed).
func (d *Directory) DropSeries(tenant, device string) { d.init(); d.series.drop(tenant + "|" + device) }

// DropBooks clears the cached books of the outlets (tenancy.manual_book.registered).
func (d *Directory) DropBooks(tenant string, outlets ...string) {
	d.init()
	for _, o := range outlets {
		d.books.drop(tenant + "|" + o)
	}
}

// StreamInTenant implements service.StreamInTenant over getStreamOwner: an outlet or brand id belongs to the tenant.
// Found is cached without expiry; 404 and errors are not.
func (d *Directory) StreamInTenant(tenant, stream string) bool {
	d.init()
	kind, id, ok := strings.Cut(stream, ":")
	if !ok || id == "" || (kind != "outlet" && kind != "brand") {
		return false
	}
	k := tenant + "|" + id
	o, ok := d.owners.get(k, d.now())
	if !ok {
		var err error
		if o, err = d.Tenancy.StreamOwner(d.ctx(), tenant, id); err != nil {
			d.fault(err)
			return false
		}
		d.owners.put(k, o, d.now(), 0)
	}
	return o.OrganisationID == tenant && o.Kind == kind
}

// RecordDrained implements directory.DrainRecorder.
func (d *Directory) RecordDrained(ctx context.Context, tenant, device string, rep directory.DrainReport) error {
	r := identityclient.DrainReport{Key: rep.Key, Through: rep.Through, Statement: rep.Statement}
	for _, s := range rep.Series {
		r.Series = append(r.Series, identityclient.DrainSeries{SeriesID: s.SeriesID, FY: s.FY, LastNumber: s.LastNumber})
	}
	return d.Identity.RecordDrained(ctx, tenant, device, r)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
