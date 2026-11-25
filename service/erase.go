package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// metaErasureAck is the meta key of a node's acknowledgement: pii-ack-recv:<node>:<stream|origin|seq>.
const metaErasureAck = "pii-ack-recv:"

// ErasePII erases the personal data of one op (PROVISIONAL, security ruling of the Phase 1
// re-review; syncproto/piic.go). In one transaction the gateway removes the stored values and salts
// of the op, records a cloud-signed erasure op (intent sync.pii.erase, record pii_erase, sealed with
// the op-signing key) that devices and hubs apply to their rows, op logs, caches and spool, and
// writes sync.pii.erased (ids only) so every owning service erases its side rows. The commitments
// stay in the sealed body of the original op. It returns the erasure op. Erasing twice is a no-op
// that returns the first erasure op's identity.
func (g *Gateway) ErasePII(ctx context.Context, tenant string, ref sp.Ref) (sp.Ref, error) {
	e := g.engineFor(tenant)
	var out sp.Ref
	err := e.InTxLocked(ctx, func(tx repository.Tx) error {
		if _, ok, err := tx.GetOp(ref.Stream, ref.Origin, ref.Seq); err != nil {
			return err
		} else if !ok {
			return ErrNotFound
		}
		if prev, ok, err := tx.GetMeta(engine.MetaPIIErased + sp.VoidID(ref)); err != nil {
			return err
		} else if ok && strings.Contains(prev, "|") {
			parts := strings.Split(prev, "|") // origin|seq of the erasure op
			seq, _ := strconv.ParseInt(parts[1], 10, 64)
			out = sp.Ref{Origin: parts[0], Stream: ref.Stream, Seq: seq}
			return nil
		}
		it, err := e.RecordAndSealTx(tx, engine.Input{Stream: ref.Stream, Intent: sp.IntentPIIErase, Muts: []sp.Mut{{
			E: sp.RecordPIIErase, ID: sp.VoidID(ref), K: sp.KInsert,
			F: map[string]any{"origin": ref.Origin, "stream": ref.Stream, "seq": ref.Seq},
		}}})
		if err != nil {
			return err
		}
		out = sp.Ref{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq}
		if err := tx.ErasePII(ref.Stream, ref.Origin, ref.Seq); err != nil {
			return err
		}
		if err := tx.SetMeta(engine.MetaPIIErased+sp.VoidID(ref), fmt.Sprintf("%s|%d", it.Origin, it.Seq)); err != nil {
			return err
		}
		rec, _, err := tx.GetOp(it.Stream, it.Origin, it.Seq)
		if err != nil {
			return err
		}
		if err := g.publish(tx, rec); err != nil {
			return err
		}
		return g.publishErased(tx, ref)
	})
	if err == nil {
		g.poker(tenant).bump()
	}
	return out, err
}

func (g *Gateway) publishErased(tx repository.Tx, ref sp.Ref) error {
	if !g.outboxOn() {
		return nil
	}
	data, _ := json.Marshal(map[string]any{"origin": ref.Origin, "stream": ref.Stream, "seq": ref.Seq})
	env := events.Envelope{ID: g.cfg.IDs.New(), Type: TypePIIErased, V: 1, Source: "sync", TenantID: ids.ID(tx.Tenant()),
		Key: ref.Stream + "|" + ref.Origin, KeySeq: ref.Seq, OccurredAt: g.cfg.Now(), Epoch: g.Epoch(), Data: data}
	if kind, sid, ok := splitStream(ref.Stream); ok && kind == "outlet" {
		env.OutletID = ids.ID(sid)
	}
	return g.putOutbox(tx, env)
}

// noteErasureAcks records the erasures a node reports as applied in its hello (pii_erased). Only
// streams the caller may read are accepted, so one device cannot acknowledge for another outlet.
func (g *Gateway) noteErasureAcks(ctx context.Context, tenant string, c engine.Caller, refs []sp.Ref) error {
	if len(refs) == 0 {
		return nil
	}
	return g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		for i, r := range refs {
			if i >= 500 || !streamAllowed(c, tenant, r.Stream) {
				continue
			}
			if _, ok, err := tx.GetMeta(engine.MetaPIIErased + sp.VoidID(r)); err != nil {
				return err
			} else if !ok {
				continue // not an erasure this gateway made
			}
			if err := tx.SetMeta(metaErasureAck+c.ID+":"+sp.VoidID(r), g.cfg.Now().UTC().Format("2006-01-02T15:04:05Z")); err != nil {
				return err
			}
		}
		return nil
	})
}

// ErasureAcked reports whether node acknowledged the erasure of ref.
func (g *Gateway) ErasureAcked(ctx context.Context, tenant, node string, ref sp.Ref) (bool, error) {
	var ok bool
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		var err error
		_, ok, err = tx.GetMeta(metaErasureAck + node + ":" + sp.VoidID(ref))
		return err
	})
	return ok, err
}
