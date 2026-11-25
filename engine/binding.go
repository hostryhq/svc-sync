package engine

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// A2.8: a body taken over a placeholder is bound where it can be bound, marked unbound where it
// cannot, and a contradiction is a chain_conflict that is never silent.

// MarkUnbound is the audit mark of an op taken by hash with no seal and no neighbour that binds it
// (A2.8 item 1.3). A node never relays an unbound op, and shows it in its exceptions until the
// cloud's own hash clears it at a direct hello.
const MarkUnbound = "unbound"

// DirectCloudInterval is how often a node behind a hub reaches the cloud directly when it can
// (security review ruling 4 (7), ADR-0002 A2.8 item 1.3).
const DirectCloudInterval = 24 * time.Hour

const (
	metaUnbound   = "unbound"
	metaConflicts = "chain_conflicts"
	metaCloudAt   = "cloud_hello_at"
	metaStaleSeal = "stale_cloud_seals"
	srcRelay      = "relay"
	srcCloud      = "cloud"
)

type storedConflict struct {
	sp.Conflict
	Src      string `json:"src"`
	Reported bool   `json:"reported,omitempty"`
}

func hasMarkS(marks, m string) bool {
	for _, x := range strings.Split(marks, ",") {
		if x == m {
			return true
		}
	}
	return false
}

func withMark(marks, m string) string {
	if hasMarkS(marks, m) {
		return marks
	}
	return strings.Trim(marks+","+m, ",")
}

func withoutMark(marks, m string) string {
	var out []string
	for _, x := range strings.Split(marks, ",") {
		if x != "" && x != m {
			out = append(out, x)
		}
	}
	return strings.Join(out, ",")
}

func srcOf(fromCloud bool) string {
	if fromCloud {
		return srcCloud
	}
	return srcRelay
}

func getJSON(tx repository.Tx, key string, out any) error {
	v, ok, err := tx.GetMeta(key)
	if err != nil || !ok || v == "" {
		return err
	}
	return json.Unmarshal([]byte(v), out)
}

func putJSON(tx repository.Tx, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.SetMeta(key, string(b))
}

func conflictsOf(tx repository.Tx) ([]storedConflict, error) {
	var cs []storedConflict
	err := getJSON(tx, metaConflicts, &cs)
	return cs, err
}

// conflictGate reports whether this node already recorded a conflict on (origin, stream) from the
// kind of upstream the batch comes from: it takes nothing more of that origin from that upstream.
func conflictGate(tx repository.Tx, origin, stream string, fromCloud bool) (bool, error) {
	cs, err := conflictsOf(tx)
	if err != nil {
		return false, err
	}
	for _, c := range cs {
		if c.Origin == origin && c.Stream == stream && c.Src == srcOf(fromCloud) {
			return true, nil
		}
	}
	return false, nil
}

// noteConflict records a conflict once per (origin, stream, source); the first stays.
func noteConflict(tx repository.Tx, c sp.Conflict, src string) error {
	cs, err := conflictsOf(tx)
	if err != nil {
		return err
	}
	for _, x := range cs {
		if x.Origin == c.Origin && x.Stream == c.Stream && x.Src == src {
			return nil
		}
	}
	return putJSON(tx, metaConflicts, append(cs, storedConflict{Conflict: c, Src: src}))
}

func unboundRefs(tx repository.Tx) ([]sp.Ref, error) {
	var rs []sp.Ref
	err := getJSON(tx, metaUnbound, &rs)
	return rs, err
}

func addUnbound(tx repository.Tx, r sp.Ref) error {
	rs, err := unboundRefs(tx)
	if err != nil {
		return err
	}
	for _, x := range rs {
		if x == r {
			return nil
		}
	}
	return putJSON(tx, metaUnbound, append(rs, r))
}

func removeUnbound(tx repository.Tx, r sp.Ref) error {
	rs, err := unboundRefs(tx)
	if err != nil {
		return err
	}
	out := rs[:0:0]
	for _, x := range rs {
		if x != r {
			out = append(out, x)
		}
	}
	if len(out) == len(rs) {
		return nil
	}
	return putJSON(tx, metaUnbound, out)
}

// clearUnbound removes the unbound mark of a stored slot.
func clearUnbound(tx repository.Tx, rec repository.OpRec) error {
	if !hasMarkS(rec.Marks, MarkUnbound) {
		return nil
	}
	rec.Marks = withoutMark(rec.Marks, MarkUnbound)
	if err := tx.UpdateOp(rec); err != nil {
		return err
	}
	return removeUnbound(tx, sp.Ref{Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq})
}

type binding int

const (
	bindOK binding = iota
	unbound
	conflict
)

// bindSlot decides how a body that arrives over a held placeholder binds (A2.8 item 1.2). It checks,
// in order: the body's link to the slot below, a seal that names the slot, and the op held above.
// seen is the hash that contradicts the slot when the result is conflict.
func (e *Engine) bindSlot(tx repository.Tx, g *group, seals map[string]sp.Seal, rec repository.OpRec, hb string, b sp.Body) (res binding, seen string, err error) {
	// Below: the body must chain to what the node holds at seq-1.
	if rec.Seq == 1 {
		if b.PH != sp.GenesisHash(rec.Origin, rec.Stream) {
			return conflict, b.PH, nil
		}
	} else if lo, ok, err := tx.GetOp(rec.Stream, rec.Origin, rec.Seq-1); err != nil {
		return 0, "", err
	} else if ok && lo.H != "" && b.PH != lo.H {
		return conflict, b.PH, nil
	}
	// A seal that names exactly this slot.
	if _, _, sh, ok, err := tx.GetSeal(rec.Stream, rec.Origin, rec.Seq); err != nil {
		return 0, "", err
	} else if ok {
		if sh != hb {
			return conflict, sh, nil
		}
		return bindOK, "", nil
	}
	if s, ok := seals[rec.Origin+"/"+rec.Stream+"/"+strconv.FormatInt(rec.Seq, 10)]; ok {
		if pub, has := e.cfg.Trust.OriginKey(rec.Origin); has && e.sealOK(s, rec.Origin, pub) {
			if s.H != hb {
				return conflict, s.H, nil
			}
			return bindOK, "", nil
		}
	}
	// Above: the op held at seq+1 names this slot as its predecessor. An op that was itself taken
	// by hash with no binding proves nothing.
	if up, ok, err := tx.GetOp(rec.Stream, rec.Origin, rec.Seq+1); err != nil {
		return 0, "", err
	} else if ok && up.Body != "" && up.PH != "" && !hasMarkS(up.Marks, MarkUnbound) {
		if up.PH != hb {
			return conflict, up.PH, nil
		}
		return bindOK, "", nil
	}
	for _, it := range g.items {
		if it.Seq == rec.Seq+1 && !it.IsPlaceholder() && sp.Hash(it.Body) == it.H {
			if ub, derr := sp.DecodeBody(it.Body); derr == nil {
				if ub.PH != hb {
					return conflict, ub.PH, nil
				}
				return bindOK, "", nil
			}
		}
	}
	return unbound, "", nil
}

// UnboundSlots lists the slots this node took by hash with no binding yet.
func (e *Engine) UnboundSlots(ctx context.Context) ([]sp.Ref, error) {
	var out []sp.Ref
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		var err error
		out, err = unboundRefs(tx)
		return err
	})
	if len(out) > 500 {
		out = out[:500]
	}
	return out, err
}

// ResolveUnbound applies the cloud's answer to a hello that listed unbound slots: an equal hash
// clears the mark, a different one is a chain_conflict (A2.8 item 1.3, 1.4).
func (e *Engine) ResolveUnbound(ctx context.Context, answers []sp.SlotHash) error {
	if len(answers) == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		for _, a := range answers {
			rec, ok, err := tx.GetOp(a.Stream, a.Origin, a.Seq)
			if err != nil {
				return err
			}
			if !ok || !hasMarkS(rec.Marks, MarkUnbound) {
				continue
			}
			if rec.H == a.H {
				if err := clearUnbound(tx, rec); err != nil {
					return err
				}
				continue
			}
			if err := noteConflict(tx, sp.Conflict{Origin: a.Origin, Stream: a.Stream, Seq: a.Seq, Held: rec.H, Seen: a.H}, srcRelay); err != nil {
				return err
			}
		}
		return nil
	})
}

// Conflicts lists the chain conflicts this node recorded; unreportedOnly skips those already sent
// to the cloud.
func (e *Engine) Conflicts(ctx context.Context, unreportedOnly bool) ([]sp.Conflict, error) {
	var out []sp.Conflict
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		cs, err := conflictsOf(tx)
		for _, c := range cs {
			if !unreportedOnly || !c.Reported {
				out = append(out, c.Conflict)
			}
		}
		return err
	})
	return out, err
}

// markReported records that a direct cloud hello carried the conflicts.
func (e *Engine) markReported(ctx context.Context) error {
	return e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		cs, err := conflictsOf(tx)
		if err != nil || len(cs) == 0 {
			return err
		}
		for i := range cs {
			cs[i].Reported = true
		}
		return putJSON(tx, metaConflicts, cs)
	})
}

// NoteCloudHello stamps a successful direct cloud hello.
func (e *Engine) NoteCloudHello(ctx context.Context) error {
	return e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		if err := tx.SetMeta(metaCloudAt, e.cfg.Clock.Time().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
		return tx.DeleteMeta(metaStaleSeal)
	})
}

// DirectCloudDue reports that a node whose upstream is a hub should now reach the cloud directly:
// 24 hours since its last direct hello, an unbound slot or unreported conflict waiting, or a cloud
// seal it had to refuse under a dropped key (A2.8 items 1.3 and 2.2).
func (e *Engine) DirectCloudDue(ctx context.Context) bool {
	due := false
	_ = e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		at, ok, _ := tx.GetMeta(metaCloudAt)
		t, err := time.Parse(time.RFC3339, at)
		if !ok || err != nil || e.cfg.Clock.Time().Sub(t) >= DirectCloudInterval {
			due = true
			return nil
		}
		if v, ok, _ := tx.GetMeta(metaStaleSeal); ok && v != "" {
			due = true
			return nil
		}
		if rs, _ := unboundRefs(tx); len(rs) > 0 {
			due = true
			return nil
		}
		cs, _ := conflictsOf(tx)
		for _, c := range cs {
			if !c.Reported {
				due = true
			}
		}
		return nil
	})
	return due
}

// RefreshSeals replaces stored cloud-origin seals by the upstream's current ones after an
// op-signing key rotation (A2.8 item 2). A refreshed seal must verify under a key this node accepts
// and name the hash it already holds at the slot.
func (e *Engine) RefreshSeals(ctx context.Context, seals []sp.Seal) (int, error) {
	rt, ok := e.cfg.Trust.(RecoveryTrust)
	if !ok || len(seals) == 0 {
		return 0, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		n = 0
		for _, s := range seals {
			if !strings.HasPrefix(s.Origin, CloudOriginPrefix) {
				continue
			}
			k, ok := rt.OpKey(s.Kid)
			if !ok || !s.Verify(k) {
				continue
			}
			_, _, h, have, err := tx.GetSeal(s.Stream, s.Origin, s.Seq)
			if err != nil {
				return err
			}
			if !have || h != s.H {
				continue
			}
			if err := tx.ReplaceSeal(s.Stream, s.Origin, s.Seq, s.H, s.Kid, s.Sig); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// StaleSeals lists the stored cloud-origin seals under an op-signing key this node no longer
// accepts: the ones to ask the upstream to refresh.
func (e *Engine) StaleSeals(ctx context.Context, limit int) ([]sp.Ref, error) {
	rt, ok := e.cfg.Trust.(RecoveryTrust)
	if !ok {
		return nil, nil
	}
	var out []sp.Ref
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		seals, err := tx.SealsOfOrigins(CloudOriginPrefix)
		if err != nil {
			return err
		}
		for _, s := range seals {
			if _, ok := rt.OpKey(s.Kid); !ok && len(out) < limit {
				out = append(out, sp.Ref{Origin: s.Origin, Stream: s.Stream, Seq: s.Seq})
			}
		}
		return nil
	})
	return out, err
}

// conflict records a chain conflict on the slot and refuses the body as chain_conflict (A2.8 item 1.4).
func (e *Engine) conflict(tx repository.Tx, req IngestReq, res *IngestRes, rec repository.OpRec, seen string) error {
	res.Refused = append(res.Refused, sp.Refusal{Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq, Reason: sp.ReasonChainConflict})
	return noteConflict(tx, sp.Conflict{Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq, Held: rec.H, Seen: seen}, srcOf(req.FromCloud))
}

// sealedAtOrAbove reports whether a valid seal of the slot's origin covers the slot: one stored, or
// one in the batch that verifies (A2.8 item 1.1).
func (e *Engine) sealedAtOrAbove(tx repository.Tx, seals map[string]sp.Seal, rec repository.OpRec) bool {
	if m, err := tx.MaxSealSeq(rec.Stream, rec.Origin); err == nil && m >= rec.Seq {
		return true
	}
	pub, ok := e.cfg.Trust.OriginKey(rec.Origin)
	if !ok {
		return false
	}
	for _, s := range seals {
		if s.Origin == rec.Origin && s.Stream == rec.Stream && s.Seq >= rec.Seq && e.sealOK(s, rec.Origin, pub) {
			return true
		}
	}
	return false
}
