package identityclient

import (
	"context"
	"sync"
	"time"

	"github.com/hostryhq/svc-sync/directory"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// ProofParams are what identity's verifyProof and checkPackHistory need and the op body does not carry
// yet: the pack and PIN versions the proof was made under and the opening time of the session. The op
// carries `pack_v` as text and has no `pin_v` or `opened_at` (see contract/README.md, open question 1); the
// hook that supplies them is the single place to change when the wire carries them.
type ProofParams struct {
	PackV, PinV int
	OpenedAt    time.Time
}

// Directory answers the gateway's directory questions from identity's internal routes.
//
// Answered by identity: the proof check (CheckProof, `locked` for every op kind), revocation (a polled feed),
// pack history (InAnyPack) and drain (RecordDrained). NOT answered, because the contract has no internal route
// for them: Credential (a device's public key, kind, outlet and brand), PackFor (the permissions a pack
// granted), StillHolds, RecoveryFor (identity's key-loss records) and Series (tenancy's registry). Those
// answer "not found", so the gateway refuses what it cannot check and nothing is ever granted on a guess.
// Gaps lists them; cmd/gateway refuses to start with gaps unless the operator accepts them (development).
type Directory struct {
	Client *Client
	// Proof supplies ProofParams for the session of an actor on a device. Without an answer the proof
	// check is "unavailable" (the op waits), never "valid".
	Proof func(tenant, device, actor, sid string) (ProofParams, bool)
	// Clock defaults to time.Now.
	Clock func() time.Time

	mu      sync.RWMutex
	revoked map[string]time.Time // tenant|device
	cursor  string
}

var (
	_ directory.Directory     = (*Directory)(nil)
	_ directory.DrainRecorder = (*Directory)(nil)
)

// Gaps lists the directory questions identity cannot answer today.
func (d *Directory) Gaps() []string {
	return []string{"Credential", "PackFor", "StillHolds", "RecoveryFor", "Series"}
}

func (d *Directory) now() time.Time {
	if d.Clock != nil {
		return d.Clock()
	}
	return time.Now()
}

// Poll reads the revocation feed from the last cursor to its end. The gateway polls on start and every 60
// seconds (the contract). A failed page leaves the cursor where it was.
func (d *Directory) Poll(ctx context.Context) error {
	for {
		d.mu.RLock()
		cur := d.cursor
		d.mu.RUnlock()
		items, next, err := d.Client.Revocations(ctx, cur)
		if err != nil {
			return err
		}
		d.mu.Lock()
		if d.revoked == nil {
			d.revoked = map[string]time.Time{}
		}
		for _, r := range items {
			if r.Device {
				d.revoked[r.Tenant+"|"+r.Subject] = r.At
			}
		}
		if next != "" {
			d.cursor = next
		} else if len(items) > 0 {
			d.cursor = items[len(items)-1].ID
		}
		d.mu.Unlock()
		if next == "" {
			return nil
		}
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

// Revoked implements directory.Directory. The feed names no reason, so the reason is empty: the key-loss
// recovery rules that read "key_lost" need identity's recovery records (see Gaps).
func (d *Directory) Revoked(tenant, device string) (bool, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.revoked[tenant+"|"+device]
	return ok, ""
}

// CheckProof implements directory.Directory. configClass is not sent: identity answers the same for every
// op kind, which is the security condition (a locked pair answers locked for sales and configuration alike).
func (d *Directory) CheckProof(tenant, device, actor, sid, proof string, _ bool) directory.ProofResult {
	if proof == "" {
		return directory.ProofMissing
	}
	if d.Proof == nil {
		return directory.ProofUnavailable
	}
	pp, ok := d.Proof(tenant, device, actor, sid)
	if !ok {
		return directory.ProofUnavailable
	}
	v, err := d.Client.VerifyProof(context.Background(), tenant, ProofCheck{DeviceID: device, MemberID: actor, SessionID: sid,
		PackV: pp.PackV, PinV: pp.PinV, OpenedAt: pp.OpenedAt, Proof: proof})
	switch {
	case err != nil:
		return directory.ProofUnavailable
	case v.Locked:
		return directory.ProofLocked
	case v.Valid:
		return directory.ProofValid
	}
	return directory.ProofInvalid
}

// InAnyPack implements directory.Directory with identity's pack-history check, judged against the pack the
// device held (not today). An unknown pack, an error or no ProofParams answers false.
func (d *Directory) InAnyPack(tenant, device, actor string) bool {
	if d.Proof == nil {
		return false
	}
	pp, ok := d.Proof(tenant, device, actor, "")
	if !ok {
		return false
	}
	h, err := d.Client.CheckPackHistory(context.Background(), tenant, device, pp.PackV, actor, "")
	return err == nil && h.PackKnown && h.MemberInPack
}

// RecordDrained implements directory.DrainRecorder.
func (d *Directory) RecordDrained(ctx context.Context, tenant, device string, through map[string]int64) error {
	return d.Client.RecordDrained(ctx, tenant, device, through)
}

// Credential implements directory.Directory: identity has no internal route for it (see Gaps).
func (d *Directory) Credential(string, string) (sp.CredentialEnvelope, bool) {
	return sp.CredentialEnvelope{}, false
}

// Series implements directory.Directory: the series registry is tenancy's (see Gaps).
func (d *Directory) Series(string, string) (directory.SeriesInfo, bool) {
	return directory.SeriesInfo{}, false
}

// PackFor implements directory.Directory: identity has no internal route for it (see Gaps).
func (d *Directory) PackFor(string, string, string) (directory.Pack, bool) {
	return directory.Pack{}, false
}

// StillHolds implements directory.Directory: identity has no internal route for it (see Gaps).
func (d *Directory) StillHolds(string, string, string) bool { return false }

// RecoveryFor implements directory.Directory: identity has no internal route for it (see Gaps).
func (d *Directory) RecoveryFor(string, string) (directory.RecoveryRec, bool) {
	return directory.RecoveryRec{}, false
}

// Now implements directory.Directory.
func (d *Directory) Now() time.Time { return d.now() }
