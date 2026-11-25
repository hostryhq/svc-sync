package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/outbox"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Event types published by the gateway (api-specs events/sync, events/billing).
const (
	TypeOpPrefix         = "sync.op."
	TypePIIErased        = "sync.pii.erased"
	TypeSeriesReconciled = "billing.series.reconciled"
)

// Namespace is the text before the first dot of the intent name; a void (sync.void) is published
// under namespace sync.
func Namespace(intent string) string {
	ns, _, _ := strings.Cut(intent, ".")
	return ns
}

// opEnvelope builds the sync.op.<namespace> event of an op that became applicable (ADR-0014 A2.1):
// data holds the exact bytes the origin sent as the JSON string body, and the verified pii without
// its salts. Nothing of the op is repeated beside body. The bus message is the whole op, so the
// size limits of the protocol keep it under the bus max_payload.
func opEnvelope(id ids.ID, tenant string, now time.Time, epoch string, rec repository.OpRec, pii json.RawMessage) (events.Envelope, error) {
	b, err := sp.DecodeBody(rec.Body)
	if err != nil {
		return events.Envelope{}, fmt.Errorf("service: op %s/%s/%d has no publishable body", rec.Origin, rec.Stream, rec.Seq)
	}
	if err := sp.CheckSize(len(rec.Body), len(pii)); err != nil {
		return events.Envelope{}, err
	}
	marks := splitMarks(rec.Marks)
	if marks == nil {
		marks = []string{}
	}
	if len(pii) == 0 {
		pii = json.RawMessage(`{}`)
	}
	data, err := json.Marshal(struct {
		Origin  string          `json:"origin"`
		Stream  string          `json:"stream"`
		Seq     int64           `json:"seq"`
		H       string          `json:"h"`
		Intent  string          `json:"intent"`
		IntentV int             `json:"intent_v"`
		Status  string          `json:"status"`
		Marks   []string        `json:"marks"`
		Body    string          `json:"body"`
		PII     json.RawMessage `json:"pii"`
	}{rec.Origin, rec.Stream, rec.Seq, rec.H, b.Intent, b.IntentV, rec.Status, marks, rec.Body, pii})
	if err != nil {
		return events.Envelope{}, err
	}
	env := events.Envelope{
		ID: id, Type: TypeOpPrefix + Namespace(b.Intent), V: 1, Source: "sync", TenantID: ids.ID(tenant),
		Key: rec.Stream + "|" + rec.Origin, KeySeq: rec.Seq, OccurredAt: now, Actor: b.Actor, Epoch: epoch, Data: data,
	}
	if kind, sid, ok := strings.Cut(rec.Stream, ":"); ok && kind == "outlet" {
		env.OutletID = ids.ID(sid)
	}
	return env, nil
}

// BuildOpEvent builds the sync.op.<namespace> event for a stored op (the same builder publish uses), for
// tests of the contract with consumers: go-common sync.ParseOp must accept it.
func BuildOpEvent(id ids.ID, tenant string, now time.Time, epoch string, rec repository.OpRec, pii json.RawMessage) (events.Envelope, error) {
	return opEnvelope(id, tenant, now, epoch, rec, pii)
}

func (g *Gateway) outboxOn() bool { return g.cfg.Outbox && g.cfg.Store.Dialect() == "postgres" }

// publish writes the sync.op.<namespace> event of an accepted, flagged or released op to the
// outbox in the storing transaction (ADR-0011 B4). A quarantined op is never published.
func (g *Gateway) publish(tx repository.Tx, rec repository.OpRec) error {
	if !g.outboxOn() {
		return nil
	}
	var pii json.RawMessage
	if raw, ok, err := tx.GetPII(rec.Stream, rec.Origin, rec.Seq); err != nil {
		return err
	} else if ok {
		if pii, err = sp.StripSalts(json.RawMessage(raw)); err != nil {
			return err
		}
	}
	env, err := opEnvelope(g.cfg.IDs.New(), tx.Tenant(), g.cfg.Now(), g.Epoch(), rec, pii)
	if err != nil {
		return err
	}
	return g.putOutbox(tx, env)
}

func (g *Gateway) putOutbox(tx repository.Tx, env events.Envelope) error {
	if _, err := ids.Parse(string(env.TenantID)); err != nil {
		// Never drop an event silently (review L5): an op that cannot be published must not be stored.
		return fmt.Errorf("service: tenant id %q is not a UUID; refusing to store an op that cannot be published", env.TenantID)
	}
	return outbox.Publish(context.Background(), tx.SQLTx(), env)
}
