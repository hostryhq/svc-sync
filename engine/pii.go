package engine

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Meta keys of personal-data erasure (PROVISIONAL; see syncproto/piic.go and contract/README.md).
const (
	// MetaPIIErased marks an op whose pii was erased: pii that arrives later for it is discarded.
	MetaPIIErased = "pii-erased:"
	// MetaPIIAck marks an erasure this node applied and has not yet acknowledged to the cloud.
	MetaPIIAck = "pii-ack:"
)

func opKey(stream, origin string, seq int64) string {
	return stream + "|" + origin + "|" + strconv.FormatInt(seq, 10)
}

// openPII verifies the pii of an arriving item against the commitments of its sealed body and
// keeps only what verifies (values and salts), in this node's store. An op whose pii was erased
// keeps none. An unverifiable field is dropped, never stored or relayed.
func (e *Engine) openPII(tx repository.Tx, p *Parsed) error {
	it := p.Item
	if _, erased, err := tx.GetMeta(MetaPIIErased + opKey(it.Stream, it.Origin, it.Seq)); err != nil {
		return err
	} else if erased {
		p.Item.PII = nil
		return nil
	}
	if len(it.PII) > sp.MaxPIIBytes { // over the size limit: never stored or published
		p.PIIDropped, p.Item.PII = 1, nil
		return nil
	}
	var commits sp.PIICommit
	if !p.Opaque {
		commits = p.Body.PIIC
	}
	o, err := sp.OpenPII(it.PII, commits)
	if err != nil {
		p.PIIDropped, p.Item.PII = 1, nil
		return nil
	}
	p.PIIDropped, p.Item.PII = o.Dropped, o.Verified
	if len(o.Verified) > 0 {
		return storePII(tx, it.Stream, it.Origin, it.Seq, o.Verified)
	}
	return nil
}

// storePII keeps verified wire pii for an op, merged with what the node already holds for it.
func storePII(tx repository.Tx, stream, origin string, seq int64, verified json.RawMessage) error {
	old, ok, err := tx.GetPII(stream, origin, seq)
	if err != nil {
		return err
	}
	if ok {
		merged, err := sp.MergePII(json.RawMessage(old), verified)
		if err != nil {
			return err
		}
		if err := tx.ErasePII(stream, origin, seq); err != nil {
			return err
		}
		verified = merged
	}
	return tx.PutPII(stream, origin, seq, string(verified))
}

// servedPII is the pii this node holds for an op, as it serves it to a kind that receives it.
func servedPII(tx repository.Tx, r repository.OpRec) (json.RawMessage, error) {
	pii, ok, err := tx.GetPII(r.Stream, r.Origin, r.Seq)
	if err != nil || !ok {
		return nil, err
	}
	return json.RawMessage(pii), nil // verified values with their salts; erased ones are gone
}

// MetaPIINeed marks an op whose commitments have no value on this node yet (`pii_incomplete`, ADR-0014 A3.1 item 4).
const MetaPIINeed = "pii-need:"

// piiTo reports whether a pull by c may carry the pii of an op of origin (ADR-0002 A3.5 item 2).
func (e *Engine) piiTo(c Caller, origin string) bool {
	return sp.PIIPlacement(c.Kind, c.Store, c.ID, origin, e.cfg.PIIToUnprotected)
}

// wantsPII reports whether this node expects values for the commitments of the ops it stores.
func (e *Engine) wantsPII() bool { return e.cfg.Role != RoleCloud && sp.ServesPII(e.cfg.Kind) }

// notePIINeed records, for an op that carries commitments, whether a value is still missing: the row applies, the field
// is pending and the value is fetched at the next contact with any upstream. A kds expects none; an erased op needs none.
func (e *Engine) notePIINeed(tx repository.Tx, it sp.Item, p *Parsed) error {
	if !e.wantsPII() || p.Opaque || len(p.Body.PIIC) == 0 {
		return nil
	}
	key := opKey(it.Stream, it.Origin, it.Seq)
	if _, erased, err := tx.GetMeta(MetaPIIErased + key); err != nil || erased {
		return err
	}
	stored, _, err := tx.GetPII(it.Stream, it.Origin, it.Seq)
	if err != nil {
		return err
	}
	if sp.PIIMissing(p.Body.PIIC, json.RawMessage(stored)) == 0 {
		return tx.DeleteMeta(MetaPIINeed + key)
	}
	return tx.SetMeta(MetaPIINeed+key, "1")
}

// refillPII takes the pii an upstream or peer sends again for an op this node already holds: verified fields are merged
// in, so a field that was stripped on an earlier arrival is completed (PA4). An erased op takes nothing.
func (e *Engine) refillPII(tx repository.Tx, it sp.Item) error {
	rec, ok, err := tx.GetOp(it.Stream, it.Origin, it.Seq)
	if err != nil || !ok {
		return err
	}
	b, err := sp.DecodeBody(rec.Body)
	if err != nil {
		return nil
	}
	p := &Parsed{Item: it, Body: b}
	if err := e.openPII(tx, p); err != nil {
		return err
	}
	return e.notePIINeed(tx, it, p)
}

// IncompletePII lists, up to limit, the ops whose pii values this node still lacks; a client asks for them again.
func (e *Engine) IncompletePII(tx repository.Tx, limit int) ([]sp.Ref, error) {
	if !e.wantsPII() || limit <= 0 {
		return nil, nil
	}
	m, err := tx.MetaPrefix(MetaPIINeed)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []sp.Ref
	for _, k := range keys {
		parts := strings.Split(strings.TrimPrefix(k, MetaPIINeed), "|")
		if len(parts) != 3 {
			continue
		}
		seq, _ := strconv.ParseInt(parts[2], 10, 64)
		out = append(out, sp.Ref{Stream: parts[0], Origin: parts[1], Seq: seq})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// ApplyErasure applies a cloud-signed erasure op (intent sync.pii.erase, record pii_erase) to this
// node's store: the values and salts of the named op are removed and later arrivals of its pii are
// discarded. The commitments stay in the sealed body. The node acknowledges at its next direct
// cloud hello (PendingErasureAcks). It does nothing for any other op.
func ApplyErasure(tx repository.Tx, b *sp.Body) error {
	if b.Intent != sp.IntentPIIErase || !strings.HasPrefix(b.Origin, CloudOriginPrefix) {
		return nil
	}
	for _, m := range b.Muts {
		if m.E != sp.RecordPIIErase || m.K != sp.KInsert {
			continue
		}
		parts := strings.Split(m.ID, "|")
		if len(parts) != 3 {
			continue
		}
		seq, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil || seq < 1 {
			continue
		}
		if err := tx.ErasePII(parts[0], parts[1], seq); err != nil {
			return err
		}
		if err := tx.SetMeta(MetaPIIErased+m.ID, "1"); err != nil {
			return err
		}
		if err := tx.DeleteMeta(MetaPIINeed + m.ID); err != nil {
			return err
		}
		if err := tx.SetMeta(MetaPIIAck+m.ID, "1"); err != nil {
			return err
		}
	}
	return nil
}

// PendingErasureAcks lists the erasures this node applied and has not acknowledged.
func (e *Engine) PendingErasureAcks(ctx context.Context) ([]sp.Ref, error) {
	var out []sp.Ref
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		m, err := tx.MetaPrefix(MetaPIIAck)
		if err != nil {
			return err
		}
		for k := range m {
			parts := strings.Split(strings.TrimPrefix(k, MetaPIIAck), "|")
			if len(parts) != 3 {
				continue
			}
			seq, _ := strconv.ParseInt(parts[2], 10, 64)
			out = append(out, sp.Ref{Stream: parts[0], Origin: parts[1], Seq: seq})
		}
		return nil
	})
	return out, err
}

// ClearErasureAcks forgets acknowledgements the cloud has received.
func (e *Engine) ClearErasureAcks(ctx context.Context, refs []sp.Ref) error {
	return e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		for _, r := range refs {
			if err := tx.DeleteMeta(MetaPIIAck + opKey(r.Stream, r.Origin, r.Seq)); err != nil {
				return err
			}
		}
		return nil
	})
}

// EraseLocal removes the pii of one op from this node's store, as a cloud-signed erasure does. The
// gateway calls it for the op it erases; it acknowledges nothing (it is the cloud).
func EraseLocal(tx repository.Tx, ref sp.Ref, at time.Time) error {
	if err := tx.ErasePII(ref.Stream, ref.Origin, ref.Seq); err != nil {
		return err
	}
	if err := tx.DeleteMeta(MetaPIINeed + opKey(ref.Stream, ref.Origin, ref.Seq)); err != nil {
		return err
	}
	return tx.SetMeta(MetaPIIErased+opKey(ref.Stream, ref.Origin, ref.Seq), at.UTC().Format(time.RFC3339))
}
