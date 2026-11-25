package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hostryhq/go-common/logx"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Codes of the emit refusals (openapi/sync/v1 emitOps, 422). A refusal is a defect in the caller.
const (
	EmitIdempotencyMismatch = "idempotency.mismatch"
	EmitIntentUnknown       = "emit.intent_unknown"
	EmitIntentNotCloud      = "emit.intent_not_cloud"
	EmitCallerNotOwner      = "emit.caller_not_owner"
	EmitEntityNotAllowed    = "emit.entity_not_allowed"
	EmitStreamNotInTenant   = "emit.stream_not_in_tenant"
	EmitBatchSize           = "emit.batch_size"
	EmitOpTooLarge          = "op.too_large"
)

// EmitError is a refusal of the emit operation; nothing was stored.
type EmitError struct {
	Code   string
	Detail string
}

func (e *EmitError) Error() string { return "service: emit refused: " + e.Code }

// ErrEmitUnavailable means the gateway cannot accept an emit now (restore in progress or its store
// is unavailable). Nothing changed; the caller retries with the same keys (503 emit.unavailable).
var ErrEmitUnavailable = errors.New("service: emit unavailable")

// EmitOp is one cloud-origin op requested by a service. The gateway chooses origin, seq, ph and hlc.
type EmitOp struct {
	Key          string
	Stream       string
	Intent       string
	IntentV      int
	Muts         []sp.Mut
	PII          sp.PII
	Actor        string
	AuthorisedBy *string
	Approval     string
}

// EmitResult says where an op landed.
type EmitResult struct {
	Key      string
	Origin   string
	Stream   string
	Seq      int64
	Replayed bool
}

// content is the idempotency fingerprint of an op: everything the caller chose.
func (o EmitOp) content() (string, error) {
	raw, err := json.Marshal(struct {
		Stream       string   `json:"stream"`
		Intent       string   `json:"intent"`
		IntentV      int      `json:"intent_v"`
		Muts         []sp.Mut `json:"muts"`
		PII          sp.PII   `json:"pii"`
		Actor        string   `json:"actor"`
		AuthorisedBy *string  `json:"authorised_by"`
		Approval     string   `json:"approval"`
	}{o.Stream, o.Intent, o.IntentV, o.Muts, o.PII, o.Actor, o.AuthorisedBy, o.Approval})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// StreamInTenant is implemented by directories that can say whether a stream id belongs to a tenant
// (outlet and brand ids are tenancy's); without it only the tenant stream is accepted.
type StreamInTenant interface {
	StreamInTenant(tenant, stream string) bool
}

func (g *Gateway) streamInTenant(tenant, stream string) bool {
	kind, id, ok := strings.Cut(stream, ":")
	if !ok || id == "" {
		return false
	}
	if kind == "tenant" {
		return id == tenant
	}
	if kind != "outlet" && kind != "brand" {
		return false
	}
	if d, ok := g.cfg.Dir.(StreamInTenant); ok {
		return d.StreamInTenant(tenant, stream)
	}
	return false
}

// checkEmit validates one op against the registry; callerSvc is the verified service name.
func (g *Gateway) checkEmit(tenant, callerSvc string, o EmitOp) *EmitError {
	in, ok := sp.Intents[o.Intent]
	if !ok || o.IntentV != in.MaxV {
		return &EmitError{Code: EmitIntentUnknown}
	}
	if !in.CloudOrigin() {
		return &EmitError{Code: EmitIntentNotCloud}
	}
	if in.Owner != callerSvc {
		return &EmitError{Code: EmitCallerNotOwner}
	}
	if o.AuthorisedBy != nil {
		found := false
		for _, a := range in.AuthorisedBy {
			found = found || a == *o.AuthorisedBy
		}
		if !found {
			return &EmitError{Code: EmitCallerNotOwner, Detail: "authorised_by is not one of the intent's authorised_online_by"}
		}
	}
	for _, m := range o.Muts {
		if !in.AllowsEntity(m.E, m.K) {
			return &EmitError{Code: EmitEntityNotAllowed}
		}
	}
	skind, _, _ := strings.Cut(o.Stream, ":")
	streamOK := false
	for _, s := range in.Streams {
		streamOK = streamOK || s == skind
	}
	if !streamOK || !g.streamInTenant(tenant, o.Stream) {
		return &EmitError{Code: EmitStreamNotInTenant}
	}
	return nil
}

// Emit stores a batch of cloud-origin ops for one tenant on behalf of a service (ADR-0014 A2.2).
// callerSvc is the verified service name from the service token; the tenant is the one the token
// carries (the controller has already compared it with the request). The batch is atomic: any
// refusal stores nothing. Each op is idempotent on (tenant, caller, key): the same content answers
// the original identity with Replayed, other content is idempotency.mismatch. The gateway alone
// stamps origin cloud-<epoch>, seq, ph and hlc and seals each op with the op-signing key; every op
// is published whole on the bus in the transaction that stores it.
func (g *Gateway) Emit(ctx context.Context, tenant, callerSvc string, ops []EmitOp) ([]EmitResult, error) {
	if err := g.guard.Check(ctx); err != nil {
		return nil, ErrEmitUnavailable
	}
	if len(ops) < sp.MinEmitOps || len(ops) > sp.MaxEmitOps {
		return nil, &EmitError{Code: EmitBatchSize}
	}
	for _, o := range ops {
		if o.Key == "" || len(o.Key) > 128 || o.Actor == "" || len(o.Muts) == 0 {
			return nil, &EmitError{Code: EmitIntentUnknown, Detail: "key, actor and muts are required"}
		}
		if e := g.checkEmit(tenant, callerSvc, o); e != nil {
			return nil, e
		}
	}
	e := g.engineFor(tenant)
	var res []EmitResult
	err := e.InTxLocked(ctx, func(tx repository.Tx) error {
		res = res[:0]
		seen := map[string]EmitResult{}
		fp := map[string]string{}
		for _, o := range ops {
			content, err := o.content()
			if err != nil {
				return err
			}
			if prev, ok := seen[o.Key]; ok { // the same key twice in one batch
				if fp[o.Key] != content {
					return &EmitError{Code: EmitIdempotencyMismatch}
				}
				prev.Replayed = true
				res = append(res, prev)
				continue
			}
			if rec, ok, err := tx.GetEmit(callerSvc, o.Key); err != nil {
				return err
			} else if ok {
				if rec.Content != content {
					return &EmitError{Code: EmitIdempotencyMismatch}
				}
				r := EmitResult{Key: o.Key, Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq, Replayed: true}
				seen[o.Key], fp[o.Key] = r, content
				res = append(res, r)
				continue
			}
			in := engine.Input{Stream: o.Stream, Intent: o.Intent, IntentV: o.IntentV, Actor: o.Actor, Approval: o.Approval, Muts: o.Muts}
			if len(o.PII) > 0 {
				raw, err := json.Marshal(o.PII)
				if err != nil {
					return err
				}
				in.PII = raw
			}
			it, err := e.RecordAndSealTx(tx, in)
			if errors.Is(err, sp.ErrTooLarge) {
				return &EmitError{Code: EmitOpTooLarge}
			}
			if err != nil {
				return err
			}
			if err := tx.PutEmit(repository.EmitRec{Caller: callerSvc, Key: o.Key, Content: content, Origin: it.Origin, Stream: it.Stream, Seq: it.Seq}); err != nil {
				return err
			}
			rec, _, err := tx.GetOp(it.Stream, it.Origin, it.Seq)
			if err != nil {
				return err
			}
			if err := g.publish(tx, rec); err != nil {
				return err
			}
			by := ""
			if o.AuthorisedBy != nil {
				by = *o.AuthorisedBy
			}
			if err := tx.PutAudit(repository.AuditRec{ID: g.cfg.IDs.New().String(), At: g.cfg.Now(), Actor: callerSvc, ActorType: "service", Action: ActionEmit,
				Origin: it.Origin, Stream: it.Stream, Seq: it.Seq, Reason: fmt.Sprintf("actor=%s authorised_by=%s approval=%s", o.Actor, by, o.Approval),
				After: repository.StAccepted, RequestID: logx.RequestID(ctx)}); err != nil {
				return err
			}
			r := EmitResult{Key: o.Key, Origin: it.Origin, Stream: it.Stream, Seq: it.Seq}
			seen[o.Key], fp[o.Key] = r, content
			res = append(res, r)
		}
		return nil
	})
	var ee *EmitError
	switch {
	case err == nil:
		g.poker(tenant).bump()
		return res, nil
	case errors.As(err, &ee):
		return nil, err
	default:
		g.cfg.Log.Error("emit failed", "err", err.Error())
		return nil, ErrEmitUnavailable
	}
}
