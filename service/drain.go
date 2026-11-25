package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// ErrNoDrainRecorder is returned when the configured directory cannot tell identity about a drain.
var ErrNoDrainRecorder = errors.New("service: the directory does not record drains")

// Drain (ADR-0005 A3.3). The device declares, signed, and the gateway only confirms. The one trigger of a report to
// identity is a drain statement that satisfies every check below; no timer, no admin action and no inference from
// silence calls recordDeviceDrained. A device that never signs stays revoked and goes to `lost` (section 4 item 7).

// drainOrigin names the origin a quarantine upload drains: the revoked device itself, or, for a recovery drain token,
// the old origin the adopting device holds the tail of.
func drainOrigin(c engine.Caller) string {
	if c.Recovers != "" {
		return c.Recovers
	}
	return c.ID
}

// statedHeads is the head a satisfied statement fixed per stream.
type statedHeads map[string]int64

// fixedHeads returns the stream heads the origin's accepted drain statement fixed, if it has one.
func fixedHeads(tx repository.Tx, origin string) (statedHeads, bool, error) {
	ds, err := tx.Drains(origin)
	if err != nil {
		return nil, false, err
	}
	for _, d := range ds {
		if d.State == repository.DrainSatisfied || d.State == repository.DrainReported {
			var st sp.DrainStatement
			if json.Unmarshal([]byte(d.Statement), &st) != nil {
				return nil, false, nil
			}
			out := statedHeads{}
			for _, s := range st.Streams {
				out[s.Stream] = s.Seq
			}
			return out, true, nil
		}
	}
	return nil, false, nil
}

// filterBeyondStatement drops the items an origin uploads above the heads of its accepted statement (or in a stream
// it did not state): the statement fixed what the device holds, so anything else is fork evidence, kept and alerted,
// never stored as an op (A3.3 item 4).
func (g *Gateway) filterBeyondStatement(ctx context.Context, tenant, origin string, items []sp.Item) ([]sp.Item, []sp.Refusal, error) {
	var keep []sp.Item
	var refused []sp.Refusal
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		heads, ok, err := fixedHeads(tx, origin)
		if err != nil {
			return err
		}
		if !ok {
			keep = items
			return nil
		}
		for _, it := range items {
			if it.Origin == origin {
				if h, found := heads[it.Stream]; !found || it.Seq > h {
					if err := tx.PutFork(it.Stream, it.Origin, it.Seq, it.H, it.Body, origin); err != nil {
						return err
					}
					if err := tx.AddAlert("vendor", "high", "drain_beyond_statement", fmt.Sprintf("%s/%s/%d", it.Origin, it.Stream, it.Seq)); err != nil {
						return err
					}
					refused = append(refused, sp.Refusal{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq, Reason: sp.ReasonFork})
					continue
				}
			}
			keep = append(keep, it)
		}
		return nil
	})
	return keep, refused, err
}

// acceptDrainStatement checks the device-signed statement of an upload and stores it. It returns whether the
// statement is accepted (the gateway holds exactly what it states). A statement that does not check out is stored as
// fork evidence with a vendor alert and reports nothing.
func (g *Gateway) acceptDrainStatement(ctx context.Context, tenant string, c engine.Caller, st *sp.DrainStatement) (bool, error) {
	origin := drainOrigin(c)
	hash, err := st.Hash()
	if err != nil {
		return false, nil
	}
	accepted := false
	err = g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		raw, _ := json.Marshal(st)
		rec := repository.DrainRec{Origin: origin, Hash: hash, Statement: string(raw)}
		refuse := func(detail string) error {
			rec.State, rec.Detail = repository.DrainRefused, detail
			if err := tx.PutDrain(rec); err != nil {
				return err
			}
			return tx.AddAlert("vendor", "high", "drain_statement_refused", origin+": "+detail)
		}
		prior, err := tx.Drains(origin)
		if err != nil {
			return err
		}
		for _, p := range prior {
			if p.State == repository.DrainSatisfied || p.State == repository.DrainReported {
				if p.Hash == hash {
					accepted = true // a replay of the accepted statement
					return nil
				}
				return refuse("a different statement is already accepted") // kept; it never replaces the first
			}
		}
		if reason := g.checkDrain(tx, tenant, c, origin, st); reason != "" {
			return refuse(reason)
		}
		rec.State = repository.DrainSatisfied
		if err := tx.PutDrain(rec); err != nil {
			return err
		}
		// A refused statement sent again once the missing ops arrived: the row exists, so move it.
		if err := tx.SetDrainState(origin, hash, repository.DrainSatisfied); err != nil {
			return err
		}
		accepted = true
		return nil
	})
	return accepted, err
}

// checkDrain runs the checks of A3.3 item 3 and returns the first that fails ("" when the statement is satisfied).
func (g *Gateway) checkDrain(tx repository.Tx, tenant string, c engine.Caller, origin string, st *sp.DrainStatement) string {
	dir := g.cfg.Dir
	if revoked, _ := dir.Revoked(tenant, origin); !revoked {
		return "the device is not revoked"
	}
	if st.Origin != origin || st.By != c.ID {
		return "the statement names another origin or signer"
	}
	cred, ok := dir.Credential(tenant, c.ID)
	if !ok || cred.Cred.Kid != st.Kid {
		return "the signing key is not the credential's"
	}
	pub, err := cred.Cred.PubKey()
	if err != nil || !st.Verify(pub) {
		return "the signature does not verify"
	}
	if c.Recovers != "" {
		rec, ok := dir.RecoveryFor(tenant, c.Recovers)
		if !ok || rec.New != c.ID || st.Rec != rec.ID {
			return "the recovery record does not match"
		}
		r, _, err := tx.GetRecovery(rec.ID)
		if err != nil {
			return "recovery record unreadable"
		}
		var fixed map[string]attested
		_ = json.Unmarshal([]byte(r.Attested), &fixed)
		if len(fixed) != len(st.Streams) {
			return "the streams do not equal the attestations"
		}
		for _, s := range st.Streams {
			a, ok := fixed[sp.VKey(origin, s.Stream)]
			if !ok || a.Seq != s.Seq || a.H != s.H {
				return "the streams do not equal the attestations"
			}
		}
	} else if st.Rec != "" {
		return "an ordinary drain names no recovery"
	}
	heads, err := tx.Heads()
	if err != nil {
		return "heads unreadable"
	}
	have := map[string]int64{}
	for _, h := range heads {
		if h.Origin == origin {
			have[h.Stream] = h.Seq
		}
	}
	seen := map[string]bool{}
	for _, s := range st.Streams {
		if seen[s.Stream] || s.Seq < 1 {
			return "a stream is stated twice or empty"
		}
		seen[s.Stream] = true
		if have[s.Stream] < s.Seq {
			return fmt.Sprintf("the gateway holds %s only through %d of the stated %d", s.Stream, have[s.Stream], s.Seq)
		}
		if have[s.Stream] > s.Seq {
			return "the gateway holds ops above the stated head of " + s.Stream
		}
		op, found, err := tx.GetOp(s.Stream, origin, s.Seq)
		if err != nil || !found || op.H != s.H {
			return "the hash at the head of " + s.Stream + " differs"
		}
	}
	for stream := range have {
		if !seen[stream] {
			return "the gateway holds ops of the origin in an unstated stream"
		}
	}
	// The register holds no number above a stated last number.
	reg, err := tx.Register()
	if err != nil {
		return "register unreadable"
	}
	last := map[string]int64{}
	for _, s := range st.Series {
		last[s.Code+"/"+s.FY] = s.LastNumber
	}
	for _, e := range reg {
		if e.Origin != origin || e.Mark == MarkForeign || e.Mark == MarkUnknownSeries {
			continue
		}
		if n, stated := last[e.Code+"/"+e.FY]; stated && e.Num > n {
			return fmt.Sprintf("the register holds %s/%s/%d above the stated last number %d", e.Code, e.FY, e.Num, n)
		}
	}
	return ""
}

// ReportPendingDrains tells identity about every accepted statement not yet reported (A3.3 item 4): one call per
// statement, with the statement hash as its Idempotency-Key, repeated until identity answers. It reports nothing else.
// It returns how many statements identity has recorded now.
func (g *Gateway) ReportPendingDrains(ctx context.Context, tenant string) (int, error) {
	rec, ok := g.cfg.Dir.(directory.DrainRecorder)
	if !ok {
		return 0, ErrNoDrainRecorder
	}
	var pending []repository.DrainRec
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		var err error
		pending, err = tx.DrainsByState(repository.DrainSatisfied)
		return err
	})
	if err != nil {
		return 0, err
	}
	done := 0
	for _, d := range pending {
		var st sp.DrainStatement
		if err := json.Unmarshal([]byte(d.Statement), &st); err != nil {
			continue
		}
		rep := directory.DrainReport{Key: d.Hash, Through: map[string]int64{}, Statement: json.RawMessage(d.Statement)}
		for _, s := range st.Streams {
			rep.Through[s.Stream] = s.Seq
		}
		for _, s := range st.Series {
			rep.Series = append(rep.Series, directory.DrainSeries{SeriesID: s.SeriesID, Code: s.Code, FY: s.FY, LastNumber: s.LastNumber})
		}
		if err := rec.RecordDrained(ctx, tenant, d.Origin, rep); err != nil {
			continue // identity unreachable or refusing: stays pending, tried again
		}
		if err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
			return tx.SetDrainState(d.Origin, d.Hash, repository.DrainReported)
		}); err != nil {
			return done, err
		}
		done++
	}
	return done, nil
}
