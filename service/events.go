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
	TypeOpFlagged        = "sync.op.flagged"
	TypeQuarantine       = "sync.quarantine.recorded"
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
		// Stored pii is the verified wire form: values with their ~s:<field> salts. The event carries both
		// (api-specs sync/protocol-v1.md, O2-12), so an owning service can verify the commitments itself.
		pii = json.RawMessage(raw)
	}
	env, err := opEnvelope(g.cfg.IDs.New(), tx.Tenant(), g.cfg.Now(), g.Epoch(), rec, pii)
	if err != nil {
		return err
	}
	return g.putOutbox(tx, env)
}

// flagCode is the coarse code of why an op was flagged: the first mark that names a flag. The text and
// the attribution stay behind the exceptions endpoint (api-specs events/sync/op.flagged.v1).
func flagCode(marks []string) string {
	for _, m := range marks {
		switch m {
		case MarkReleased, MarkPIIDropped, MarkVendorConfirmed, MarkFork, MarkRecoveredSealed, MarkProofPending, MarkConfigShared:
			continue
		}
		return m
	}
	return "flagged"
}

// publishFlagged writes sync.op.flagged for an op flagged at acceptance or at release (id and code only).
func (g *Gateway) publishFlagged(tx repository.Tx, rec repository.OpRec, marks []string) error {
	if !g.outboxOn() {
		return nil
	}
	return g.putIDEvent(tx, TypeOpFlagged, rec, map[string]any{"origin": rec.Origin, "stream": rec.Stream, "seq": rec.Seq, "code": flagCode(marks)})
}

// publishQuarantined writes sync.quarantine.recorded for a slot held in quarantine: coarse reason and, when the
// op carries a legal number, its series code, number and document type; never the content (id-only, A2.1 item 4).
// An op with several numbers (bill.rebill) names the first; billing reads the register for the rest.
func (g *Gateway) publishQuarantined(tx repository.Tx, rec repository.OpRec, reason string, b *sp.Body) error {
	if !g.outboxOn() {
		return nil
	}
	d := map[string]any{"origin": rec.Origin, "stream": rec.Stream, "seq": rec.Seq, "reason": reason}
	if b != nil {
		for _, doc := range b.Documents() {
			if code, _, _, ok := doc.ParseNumber(); ok {
				d["series_code"], d["number"], d["document_type"] = code, doc.Number, doc.Type
				break
			}
		}
	}
	return g.putIDEvent(tx, TypeQuarantine, rec, d)
}

func (g *Gateway) putIDEvent(tx repository.Tx, typ string, rec repository.OpRec, d map[string]any) error {
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	env := events.Envelope{ID: g.cfg.IDs.New(), Type: typ, V: 1, Source: "sync", TenantID: ids.ID(tx.Tenant()),
		Key: rec.Stream + "|" + rec.Origin, KeySeq: rec.Seq, OccurredAt: g.cfg.Now(), Epoch: g.Epoch(), Data: data}
	if kind, sid, ok := strings.Cut(rec.Stream, ":"); ok && kind == "outlet" {
		env.OutletID = ids.ID(sid)
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
