package engine

import (
	"context"
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
		return tx.PutPII(it.Stream, it.Origin, it.Seq, string(o.Verified))
	}
	return nil
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
	return tx.SetMeta(MetaPIIErased+opKey(ref.Stream, ref.Origin, ref.Seq), at.UTC().Format(time.RFC3339))
}
