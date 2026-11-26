package service

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Marks and reasons of an approval citation (ADR-0014 A3.3).
const (
	// MarkApprovalFlag is raised for a cited approval that fails a check; the mark MarkApprovalReason+reason follows it.
	MarkApprovalFlag = "approval_flag"
	// MarkApprovalPending is on an accepted op whose cited approval has not arrived or whose proof identity has not answered.
	MarkApprovalPending = "approval_pending"
	// MarkApprovalReason prefixes the reason of an approval_flag.
	MarkApprovalReason = "approval_reason:"
	// MarkApprovedBy prefixes the approver of an op an approval cleared ("approved by").
	MarkApprovedBy = "approved_by:"
	// ReasonApprovalFailed is the void reason of a configuration op whose cited approval failed.
	ReasonApprovalFailed = "approval_failed"
)

// approvalFlag reasons (api-specs Exception.reason).
const (
	ApprovalProofInvalid = "proof_invalid"
	ApprovalMismatch     = "mismatch"
	ApprovalReused       = "reused"
	ApprovalExpired      = "expired"
	ApprovalNotPermitted = "approver_not_permitted"
	ApprovalSelf         = "self"
	// ApprovalMissing: the cited approval never arrived. The citing op waited the A3.3 window plus ApprovalMissingGrace
	// (api-specs Exception.reason must list it).
	ApprovalMissing = "missing"
)

// ApprovalMaxAge is how long after the approval the citing op may be recorded.
const ApprovalMaxAge = 120 * time.Second

// ApprovalMissingGrace is how long, beyond ApprovalMaxAge, the gateway waits for an approval.grant it does not hold before it
// flags the citing op `missing` (P2-H1). A grant is recorded by the same origin on the same stream, before the op that cites it, so
// it reaches the gateway in the push that carries the op; the grace only covers a slow re-offer.
const ApprovalMissingGrace = 10 * time.Minute

const approvalWaitPrefix = "approval-wait:"

type approvalState int

const (
	approvalOK approvalState = iota
	approvalPending
	approvalFail
)

type approvalOutcome struct {
	State    approvalState
	Reason   string
	Approver string
}

func opRefKey(stream, origin string, seq int64) string {
	return stream + "|" + origin + "|" + strconv.FormatInt(seq, 10)
}

// checkApproval answers question 6 (permission) for an op of an `override: true` intent whose actor lacks the permission and
// cites an approval (ADR-0014 A3.3 item 2). The permission is satisfied by the approver when the approval verdict is valid;
// the approval is the same origin's and the same session's; its intent, permission, target and action hash are this op's;
// requester is the op's actor and differs from the approver; the approver held the permission in the op's pack; the op is 0 to
// 120 seconds after the approval; and no other op cites it (the lowest hlc keeps it). Not yet known is pending, never a flag.
func (g *Gateway) checkApproval(tx repository.Tx, b sp.Body, in sp.Intent, stream, origin, outlet string) approvalOutcome {
	fail := func(reason string) approvalOutcome { return approvalOutcome{State: approvalFail, Reason: reason} }
	row, ok, err := tx.GetApproval(origin, b.Approval)
	if err != nil || !ok || row.Kind == "" || !final(row.Verdict) {
		return approvalOutcome{State: approvalPending} // the approval.grant has not arrived, or identity could not answer
	}
	if row.Verdict != repository.VerdictValid {
		return fail(ApprovalProofInvalid)
	}
	// Single citer: the lowest hlc keeps it. A citer that was displaced is flagged `reused` after the fact.
	// The claim is written only after every other check passes (CR-L5): an op that fails another check must not displace a valid citer.
	me := opRefKey(stream, origin, b.Seq)
	displaces := false
	if row.Citer != "" && row.Citer != me {
		mine, e1 := sp.ParseHLC(b.HLC)
		held, e2 := sp.ParseHLC(row.CiterHLC)
		if e1 != nil || e2 != nil || !(mine < held) {
			return fail(ApprovalReused)
		}
		displaces = true
	}
	// requester = approver is allowed only in an approval.self_confirm, and that never makes an actor without the
	// permission pass (this path is only taken for such an actor).
	if row.Kind == sp.IntentApprovalSelfConfirm || row.Requester == row.Approver {
		return fail(ApprovalSelf)
	}
	values, bound := b.BoundValues(in.Binds)
	want, err := sp.ActionHash(b.Intent, in.Permission, b.Actor, b.ActionTarget(), b.Approval, row.Reason, values)
	if !bound || err != nil || row.SID != b.SID || row.Intent != b.Intent || row.Permission != in.Permission || row.Requester != b.Actor ||
		row.Target != b.ActionTarget() || row.ActionHash != want {
		return fail(ApprovalMismatch)
	}
	pack, havePack := g.cfg.Dir.PackFor(tx.Tenant(), origin, b.PackV)
	if !havePack || !pack.Members[row.Approver][in.Permission] || !g.cfg.Dir.StillHolds(tx.Tenant(), outlet, row.Approver, in.Permission) {
		return fail(ApprovalNotPermitted)
	}
	at, e1 := time.Parse(sp.TimeLayout, b.At)
	given, e2 := time.Parse(sp.TimeLayout, row.ApprovedAt)
	if d := at.Sub(given); e1 != nil || e2 != nil || d < 0 || d > ApprovalMaxAge {
		return fail(ApprovalExpired)
	}
	if displaces {
		if err := g.flagReused(tx, row.Citer); err != nil {
			return fail(ApprovalReused)
		}
	}
	if row.Citer != me {
		if err := tx.ClaimApproval(origin, b.Approval, me, b.HLC); err != nil {
			return approvalOutcome{State: approvalPending} // the claim is not stored: judged again, never accepted unclaimed
		}
	}
	return approvalOutcome{State: approvalOK, Approver: row.Approver}
}

// waitApproval records that an accepted op waits for the approval it cites.
func (g *Gateway) waitApproval(tx repository.Tx, stream, origin string, seq int64, approvalID string) error {
	return tx.SetMeta(approvalWaitPrefix+origin+"|"+approvalID+"|"+opRefKey(stream, origin, seq), g.cfg.Now().UTC().Format(time.RFC3339))
}

// expireApprovalWaits makes "not yet known" final once absence is provable (P2-H1): an op that cites an approval the gateway
// does not hold, ApprovalMaxAge plus ApprovalMissingGrace after the gateway stored it, becomes an approval_flag `missing`, with an
// owner alert. A citation whose approval is held but whose proof identity could not answer stays pending (identity's answer
// decides it), and shows on the exceptions list meanwhile.
func (g *Gateway) expireApprovalWaits(tx repository.Tx) (int, error) {
	waits, err := tx.MetaPrefix(approvalWaitPrefix)
	if err != nil {
		return 0, err
	}
	now := g.cfg.Now().UTC()
	n := 0
	for k, started := range waits {
		parts := strings.Split(strings.TrimPrefix(k, approvalWaitPrefix), "|")
		if len(parts) != 5 { // origin | approval id | stream | origin | seq
			continue
		}
		at, err := time.Parse(time.RFC3339, started)
		if err != nil { // a wait written before the time was kept: its clock starts now
			if err := tx.SetMeta(k, now.Format(time.RFC3339)); err != nil {
				return n, err
			}
			continue
		}
		if now.Sub(at) < ApprovalMaxAge+ApprovalMissingGrace {
			continue
		}
		if row, ok, err := tx.GetApproval(parts[0], parts[1]); err != nil {
			return n, err
		} else if ok && row.Kind != "" {
			continue // held: the proof verdict decides
		}
		seq, _ := strconv.ParseInt(parts[4], 10, 64)
		rec, ok, err := tx.GetOp(parts[2], parts[3], seq)
		if err != nil {
			return n, err
		}
		if err := tx.DeleteMeta(k); err != nil {
			return n, err
		}
		if !ok {
			continue
		}
		if err := g.markApprovalFailed(tx, rec, ApprovalMissing); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// pendingApprovalOps lists the accepted ops that still wait for the approval they cite.
func pendingApprovalOps(tx repository.Tx) ([]repository.OpRec, error) {
	waits, err := tx.MetaPrefix(approvalWaitPrefix)
	if err != nil {
		return nil, err
	}
	var out []repository.OpRec
	for k := range waits {
		parts := strings.Split(strings.TrimPrefix(k, approvalWaitPrefix), "|")
		if len(parts) != 5 {
			continue
		}
		seq, _ := strconv.ParseInt(parts[4], 10, 64)
		rec, ok, err := tx.GetOp(parts[2], parts[3], seq)
		if err != nil {
			return nil, err
		}
		if ok && rec.Status == repository.StAccepted && hasMark(splitMarks(rec.Marks), MarkApprovalPending) {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Origin != out[j].Origin {
			return out[i].Origin < out[j].Origin
		}
		return out[i].Seq < out[j].Seq
	})
	return out, nil
}

// flagReused marks the op that cited an approval first (by arrival) but not first by clock: another op with a lower hlc
// keeps the approval, so this one is an approval_flag `reused`.
func (g *Gateway) flagReused(tx repository.Tx, key string) error {
	parts := strings.Split(key, "|")
	if len(parts) != 3 {
		return nil
	}
	seq, _ := strconv.ParseInt(parts[2], 10, 64)
	rec, ok, err := tx.GetOp(parts[0], parts[1], seq)
	if err != nil || !ok {
		return err
	}
	return g.markApprovalFailed(tx, rec, ApprovalReused)
}

// markApprovalFailed flags an already stored op: approval_flag with the reason, accepted at high severity (a trading fact),
// the owner told and sync.op.flagged published.
func (g *Gateway) markApprovalFailed(tx repository.Tx, rec repository.OpRec, reason string) error {
	marks := dropMarks(splitMarks(rec.Marks), MarkApprovalPending, MarkApprovedBy)
	if hasMark(marks, MarkApprovalFlag) {
		return nil
	}
	marks = append(marks, MarkApprovalFlag, MarkApprovalReason+reason)
	rec.Marks = strings.Join(marks, ",")
	if rec.Status == repository.StAccepted {
		rec.Status = repository.StFlagged
	}
	if err := tx.UpdateOp(rec); err != nil {
		return err
	}
	if err := g.alert(tx, "owner", "high", "approval_flag", rec); err != nil {
		return err
	}
	return g.publishFlagged(tx, rec, marks)
}

// dropMarks removes the marks equal to, or starting with, any of the given names.
func dropMarks(marks []string, names ...string) []string {
	var out []string
	for _, m := range marks {
		drop := false
		for _, n := range names {
			if m == n || (strings.HasSuffix(n, ":") && strings.HasPrefix(m, n)) {
				drop = true
			}
		}
		if !drop {
			out = append(out, m)
		}
	}
	return out
}

// resolveApprovalWaiters judges again the accepted ops that cited this approval before it was known (ADR-0014 A3.3 item 4,
// test OV5): the pending mark goes, and a failure is flagged as for an op judged after the approval.
func (g *Gateway) resolveApprovalWaiters(tx repository.Tx, origin, approvalID string) error {
	waits, err := tx.MetaPrefix(approvalWaitPrefix + origin + "|" + approvalID + "|")
	if err != nil {
		return err
	}
	for k := range waits {
		parts := strings.Split(strings.TrimPrefix(k, approvalWaitPrefix), "|")
		if len(parts) != 5 { // origin | approval id | stream | origin | seq
			continue
		}
		seq, _ := strconv.ParseInt(parts[4], 10, 64)
		rec, ok, err := tx.GetOp(parts[2], parts[3], seq)
		if err != nil {
			return err
		}
		if !ok || rec.Body == "" {
			_ = tx.DeleteMeta(k)
			continue
		}
		b, err := sp.DecodeBody(rec.Body)
		if err != nil {
			_ = tx.DeleteMeta(k)
			continue
		}
		in := sp.Intents[b.Intent]
		cred, _ := g.cfg.Dir.Credential(tx.Tenant(), origin)
		out := g.checkApproval(tx, b, in, rec.Stream, origin, cred.Cred.OutletID)
		if out.State == approvalPending {
			continue
		}
		if err := tx.DeleteMeta(k); err != nil {
			return err
		}
		if out.State == approvalFail {
			if err := g.markApprovalFailed(tx, rec, out.Reason); err != nil {
				return err
			}
			continue
		}
		marks := dropMarks(splitMarks(rec.Marks), MarkApprovalPending)
		marks = append(marks, MarkApprovedBy+out.Approver)
		rec.Marks = strings.Join(marks, ",")
		if err := tx.UpdateOp(rec); err != nil {
			return err
		}
	}
	return nil
}

// ApprovalReason extracts the reason of an approval_flag from the marks of an op, and the marks without it.
func ApprovalReason(marks []string) (reason string, rest []string) {
	for _, m := range marks {
		if strings.HasPrefix(m, MarkApprovalReason) {
			reason = strings.TrimPrefix(m, MarkApprovalReason)
			continue
		}
		rest = append(rest, m)
	}
	return reason, rest
}

// resolveApproval asks identity again about an approval proof it could not answer. A verdict clears the pending mark of the
// approving op (a failure flags it, as for a session) and lets the ops that cite the approval be judged again.
func (g *Gateway) resolveApproval(tx repository.Tx, ap repository.ApprovalRow) (int, error) {
	recs, err := tx.OpsByOrigin(ap.Origin)
	if err != nil {
		return 0, err
	}
	for _, r := range recs {
		if (r.Intent != sp.IntentApprovalGrant && r.Intent != sp.IntentApprovalSelfConfirm) || r.Body == "" {
			continue
		}
		b, err := sp.DecodeBody(r.Body)
		if err != nil || !carriesApproval(b, ap.ID) {
			continue
		}
		res := g.approvalProof(tx, &engine.Parsed{Item: sp.Item{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq, H: r.H, Body: r.Body}, Body: b})
		if res == directory.ProofUnavailable {
			return 0, nil
		}
		marks := splitMarks(r.Marks)
		if hasMark(marks, MarkProofPending) {
			kept := dropMarks(marks, MarkProofPending)
			if res == directory.ProofInvalid || res == directory.ProofLocked || res == directory.ProofMissing {
				kept = append(kept, MarkAttributionUnverified)
				if r.Status == repository.StAccepted {
					r.Status = repository.StFlagged
				}
				if err := g.alert(tx, "owner", "medium", "attribution_unverified", r); err != nil {
					return 0, err
				}
				r.Marks = strings.Join(kept, ",")
				if err := tx.UpdateOp(r); err != nil {
					return 0, err
				}
				if err := g.publishFlagged(tx, r, kept); err != nil {
					return 0, err
				}
			} else {
				r.Marks = strings.Join(kept, ",")
				if err := tx.UpdateOp(r); err != nil {
					return 0, err
				}
			}
		}
		return 1, g.resolveApprovalWaiters(tx, ap.Origin, ap.ID)
	}
	return 0, nil
}

func carriesApproval(b sp.Body, id string) bool {
	for _, m := range b.Muts {
		if m.E == "approval" && m.ID == id {
			return true
		}
	}
	return false
}
