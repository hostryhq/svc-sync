package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// sessionMaxAge is how long after its opening a session may carry ops (ADR-0005 A3.1 item 3).
const sessionMaxAge = 16 * time.Hour

// proofKey is the Idempotency-Key of the question about one proof-bearing op: derived from (origin, stream, seq), so a
// retry or a re-offer of the op is a replay at identity and never counts a failed session twice (A2.1 item 5).
func proofKey(origin, stream string, seq int64) string {
	return fmt.Sprintf("sync:%s:%s:%d", origin, stream, seq)
}

// openedSession returns the type of the session the op opens (its `session` mutation for sid).
func openedSession(b sp.Body) (string, bool) {
	for _, m := range b.Muts {
		if m.E == "session" && m.ID == b.SID {
			t, _ := m.F["type"].(string)
			return t, true
		}
	}
	return "", false
}

func verdictOf(r directory.ProofResult) string {
	switch r {
	case directory.ProofValid:
		return repository.VerdictValid
	case directory.ProofLocked:
		return repository.VerdictLocked
	case directory.ProofUnavailable:
		return repository.VerdictPending
	}
	return repository.VerdictInvalid // missing and invalid are one verdict: the actor is unverified
}

func resultOf(verdict string) directory.ProofResult {
	switch verdict {
	case repository.VerdictValid:
		return directory.ProofValid
	case repository.VerdictLocked:
		return directory.ProofLocked
	case repository.VerdictInvalid:
		return directory.ProofInvalid
	}
	return directory.ProofUnavailable
}

func final(verdict string) bool {
	return verdict == repository.VerdictValid || verdict == repository.VerdictInvalid || verdict == repository.VerdictLocked
}

// proofOf gives the proof result of a member op (A3.1). A session.open of a pin session and an approval.grant carry
// a proof, and identity is asked once for each; every other op is judged from the stored session row. An op whose
// session.open has not arrived yet is pending, and so is any op while identity cannot answer.
func (g *Gateway) proofOf(tx repository.Tx, p *engine.Parsed) directory.ProofResult {
	b := p.Body
	switch b.Intent {
	case sp.IntentApprovalGrant, sp.IntentApprovalSelfConfirm:
		return g.approvalProof(tx, p)
	case sp.IntentSessionOpen:
		switch typ, _ := openedSession(b); typ {
		case sp.SessionPin:
			return g.openPin(tx, p)
		case sp.SessionStrong:
			return g.openStrong(tx, p)
		}
		return directory.ProofInvalid // a session of an unknown type proves nothing
	}
	if b.SID == "" {
		return directory.ProofMissing
	}
	row, ok, err := tx.GetSession(p.Item.Origin, b.SID)
	if err != nil || !ok || row.Verdict == "" {
		return directory.ProofUnavailable // the open has not arrived, or was held before it was judged
	}
	if row.Actor != b.Actor {
		return directory.ProofInvalid
	}
	at, aok := time.Parse(sp.TimeLayout, b.At)
	opened, ook := time.Parse(sp.TimeLayout, row.OpenedAt)
	if aok != nil || ook != nil || at.After(opened.Add(sessionMaxAge)) {
		return directory.ProofInvalid
	}
	if row.Type == sp.SessionStrong && row.Verdict == repository.VerdictValid {
		facts, lk := g.cfg.Dir.StrongSession(tx.Tenant(), row.SID)
		switch {
		case lk == directory.Unreachable:
			return directory.ProofUnavailable
		case lk == directory.Found && !facts.Ended.IsZero() && at.After(facts.Ended):
			return directory.ProofInvalid // the session was ended (revoked) before this op
		}
	}
	return resultOf(row.Verdict)
}

func (g *Gateway) openPin(tx repository.Tx, p *engine.Parsed) directory.ProofResult {
	b, origin := p.Body, p.Item.Origin
	if row, ok, err := tx.GetSession(origin, b.SID); err == nil && ok && final(row.Verdict) {
		return resultOf(row.Verdict) // identity is asked once per session
	}
	at, err := time.Parse(sp.TimeLayout, b.At)
	var res directory.ProofResult
	if err != nil || b.Proof == "" || b.PinV < 1 || b.PackV < 1 || b.Actor == "" {
		res = directory.ProofMissing
	} else {
		res = g.cfg.Dir.VerifyProof(tx.Tenant(), directory.ProofQuestion{Kind: directory.ProofKindSession, Device: origin, Member: b.Actor,
			SID: b.SID, PackV: b.PackV, PinV: b.PinV, OpenedAt: at, Proof: b.Proof, Key: proofKey(origin, p.Item.Stream, p.Item.Seq)})
	}
	_ = tx.PutSessionRow(repository.SessionRow{Origin: origin, SID: b.SID, Type: sp.SessionPin, Actor: b.Actor, PackV: b.PackV, PinV: b.PinV,
		OpenedAt: b.At, Verdict: verdictOf(res)})
	return res
}

func (g *Gateway) openStrong(tx repository.Tx, p *engine.Parsed) directory.ProofResult {
	b, origin := p.Body, p.Item.Origin
	if row, ok, err := tx.GetSession(origin, b.SID); err == nil && ok && final(row.Verdict) {
		return resultOf(row.Verdict)
	}
	facts, lk := g.cfg.Dir.StrongSession(tx.Tenant(), b.SID)
	res := directory.ProofUnavailable
	switch {
	case lk == directory.Found && facts.Member == b.Actor && facts.Device == origin:
		res = directory.ProofValid
	case lk == directory.Found, lk == directory.NotFound:
		res = directory.ProofInvalid
	}
	_ = tx.PutSessionRow(repository.SessionRow{Origin: origin, SID: b.SID, Type: sp.SessionStrong, Actor: b.Actor, PackV: b.PackV,
		OpenedAt: b.At, Verdict: verdictOf(res)})
	return res
}

// approvalProof asks identity about the action proof of an approval.grant, once per approval id. The fields identity
// binds are taken from the approval record the op carries (ADR-0005 section 8, A3.1 item 2).
func (g *Gateway) approvalProof(tx repository.Tx, p *engine.Parsed) directory.ProofResult {
	b, origin := p.Body, p.Item.Origin
	var rec *sp.Mut
	for i := range b.Muts {
		if b.Muts[i].E == "approval" {
			rec = &b.Muts[i]
			break
		}
	}
	if rec == nil || rec.ID == "" {
		return directory.ProofMissing
	}
	if v, ok, err := tx.GetApprovalVerdict(origin, rec.ID); err == nil && ok && final(v) {
		return resultOf(v)
	}
	str := func(k string) string { s, _ := rec.F[k].(string); return s }
	approver := str("approver")
	if approver == "" {
		approver = b.Actor
	}
	at, err := time.Parse(sp.TimeLayout, b.At)
	var res directory.ProofResult
	if err != nil || b.Proof == "" || b.PinV < 1 || b.PackV < 1 || approver == "" {
		res = directory.ProofMissing
	} else {
		res = g.cfg.Dir.VerifyProof(tx.Tenant(), directory.ProofQuestion{Kind: directory.ProofKindApproval, Device: origin, Member: approver,
			SID: b.SID, PackV: b.PackV, PinV: b.PinV, Proof: b.Proof, Key: proofKey(origin, p.Item.Stream, p.Item.Seq),
			ApprovalID: rec.ID, Permission: str("permission"), Target: str("target"), Requester: str("requester"), Reason: str("reason"),
			ActionHash: str("action_hash"), ApprovedAt: at})
	}
	_ = tx.PutApprovalVerdict(origin, rec.ID, verdictOf(res))
	_ = tx.PutApprovalRecord(repository.ApprovalRow{Origin: origin, ID: rec.ID, Kind: b.Intent, SID: b.SID, Intent: str("intent"), Permission: str("permission"),
		Target: str("target"), ActionHash: str("action_hash"), Requester: str("requester"), Approver: approver, Reason: str("reason"), ApprovedAt: b.At})
	return res
}

// ResolveSessions asks identity again about every session whose proof it could not answer, then re-judges the
// configuration ops that waited (ReverifyPending). When the verdict arrives, every stored op of the session that
// carries the pending mark is marked: a failure flags it and publishes sync.op.flagged (A3.1 item 4). It returns the
// number of sessions that reached a verdict.
func (g *Gateway) ResolveSessions(ctx context.Context, tenant string) (int, error) {
	resolved := 0
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		rows, err := tx.PendingSessions()
		if err != nil {
			return err
		}
		for _, row := range rows {
			open, ok, err := g.openOp(tx, row)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			var res directory.ProofResult
			switch row.Type {
			case sp.SessionStrong:
				res = g.openStrong(tx, open)
			default:
				res = g.openPin(tx, open)
			}
			if res == directory.ProofUnavailable {
				continue
			}
			resolved++
			if err := g.markSession(tx, row, res); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return resolved, err
	}
	n, err := g.ReverifyPending(ctx, tenant)
	if n > 0 {
		g.poker(tenant).bump()
	}
	return resolved, err
}

// openOp finds the session.open op of a session row among the origin's ops.
func (g *Gateway) openOp(tx repository.Tx, row repository.SessionRow) (*engine.Parsed, bool, error) {
	recs, err := tx.OpsByOrigin(row.Origin)
	if err != nil {
		return nil, false, err
	}
	for _, r := range recs {
		if r.Intent != sp.IntentSessionOpen || r.Body == "" {
			continue
		}
		b, err := sp.DecodeBody(r.Body)
		if err != nil || b.SID != row.SID {
			continue
		}
		return &engine.Parsed{Item: sp.Item{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq, H: r.H, Body: r.Body}, Body: b}, true, nil
	}
	return nil, false, nil
}

// markSession clears the pending mark of the session's stored ops; a failed verdict flags them.
func (g *Gateway) markSession(tx repository.Tx, row repository.SessionRow, res directory.ProofResult) error {
	recs, err := tx.OpsByOrigin(row.Origin)
	if err != nil {
		return err
	}
	for _, r := range recs {
		marks := splitMarks(r.Marks)
		if r.Body == "" || !hasMark(marks, MarkProofPending) {
			continue
		}
		b, err := sp.DecodeBody(r.Body)
		if err != nil || b.SID != row.SID {
			continue
		}
		var kept []string
		for _, m := range marks {
			if m != MarkProofPending {
				kept = append(kept, m)
			}
		}
		failed := res == directory.ProofInvalid || res == directory.ProofLocked || res == directory.ProofMissing
		if failed {
			kept = append(kept, MarkAttributionUnverified)
			if r.Status == repository.StAccepted {
				r.Status = repository.StFlagged
			}
		}
		r.Marks = strings.Join(kept, ",")
		if err := tx.UpdateOp(r); err != nil {
			return err
		}
		if failed {
			if err := g.alert(tx, "owner", "medium", "attribution_unverified", r); err != nil {
				return err
			}
			if err := g.publishFlagged(tx, r, kept); err != nil {
				return err
			}
		}
	}
	return nil
}
