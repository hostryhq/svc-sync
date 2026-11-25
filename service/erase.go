package service

import (
	"context"
	"encoding/json"
	"errors"
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
	out, _, err := g.erasePII(ctx, tenant, ref)
	return out, err
}

// Erase refusals (openapi/sync/v1 erasePii, 422).
const (
	EraseTargetUnknown = "erase.target_unknown"
	EraseBatchSize     = "erase.batch_size"
	// MaxEraseTargets is the most targets of one erasePii request.
	MaxEraseTargets = 200
)

// EraseError is a refusal of the erase operation; nothing was written for any target.
type EraseError struct{ Code string }

func (e *EraseError) Error() string { return "service: erase refused: " + e.Code }

// EraseResult is one target's erasure: the target, the cloud erasure op that carries it and whether an
// earlier request had already erased it.
type EraseResult struct {
	Target, Erase sp.Ref
	Replayed      bool
}

// ErasePIIBatch is the operation behind erasePii: one to 200 targets, all of the tenant. The batch is atomic
// in what it refuses: every target is checked first, and one the gateway does not hold refuses the whole
// request (EraseError erase.target_unknown) before anything is written. Each target is then erased in its own
// transaction; erasing twice answers the first erasure op with Replayed.
func (g *Gateway) ErasePIIBatch(ctx context.Context, tenant string, targets []sp.Ref) ([]EraseResult, error) {
	if len(targets) < 1 || len(targets) > MaxEraseTargets {
		return nil, &EraseError{Code: EraseBatchSize}
	}
	if err := g.guard.Check(ctx); err != nil {
		return nil, ErrEmitUnavailable
	}
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		for _, t := range targets {
			if _, ok, err := tx.GetOp(t.Stream, t.Origin, t.Seq); err != nil {
				return err
			} else if !ok {
				return &EraseError{Code: EraseTargetUnknown}
			}
		}
		return nil
	})
	if err != nil {
		var ee *EraseError
		if errors.As(err, &ee) {
			return nil, err
		}
		g.cfg.Log.Error("erase check failed", "err", err.Error())
		return nil, ErrEmitUnavailable
	}
	out := make([]EraseResult, 0, len(targets))
	for _, t := range targets {
		er, replayed, err := g.erasePII(ctx, tenant, t)
		if err != nil {
			g.cfg.Log.Error("erase failed", "err", err.Error())
			return nil, ErrEmitUnavailable // targets are idempotent: the caller retries the request
		}
		out = append(out, EraseResult{Target: t, Erase: er, Replayed: replayed})
	}
	return out, nil
}

func (g *Gateway) erasePII(ctx context.Context, tenant string, ref sp.Ref) (sp.Ref, bool, error) {
	e := g.engineFor(tenant)
	var out sp.Ref
	var replayed bool
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
			replayed = true
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
	return out, replayed, err
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
