package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	"github.com/hostryhq/svc-sync/sim"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

const (
	limited = "m4" // holds neither bill.credit_note.create nor approval.grant
	perm    = "bill.credit_note.create"
	reason  = "guest left"
)

// approvalFix is one outlet with a limited member who asks and a manager who approves, on one device and one session.
type approvalFix struct {
	t    *testing.T
	w    *sim.World
	a    *sim.Device
	sid  string
	base time.Time
}

func newApprovalFix(t *testing.T, seed uint64) *approvalFix {
	w := world(t, seed)
	a := w.Devices[0]
	w.Identity.SetMember(w.Tenant, limited, "order.create", "session.open")
	w.Identity.IssuePack(w.Tenant, a.ID, 1, 30*24*time.Hour)
	sid, err := a.SessionWith(limited, "req", "")
	if err != nil {
		t.Fatal(err)
	}
	return &approvalFix{t: t, w: w, a: a, sid: sid, base: w.Clock.Now().Truncate(time.Millisecond)}
}

func (f *approvalFix) values(total int64) map[string]any {
	return map[string]any{"bill_id": "bill-1", "total_paise": total}
}

// grant records the approver's approval.grant (or approval.self_confirm) for a credit note of the given total.
func (f *approvalFix) grant(id, intent, cn, requester, approver string, total int64, at time.Time) sp.Item {
	target := "credit_note:" + cn
	hash, err := sp.ActionHash("creditnote.issue", perm, requester, target, id, reason, f.values(total))
	if err != nil {
		f.t.Fatal(err)
	}
	proof := f.w.Identity.MintProof(directory.ProofQuestion{Kind: directory.ProofKindApproval, Device: f.a.ID, Member: approver, SID: f.sid, PackV: 1, PinV: 1,
		ApprovalID: id, Permission: perm, Target: target, Requester: requester, ActionHash: hash, ApprovedAt: at})
	it, err := f.a.Eng.Record(context.Background(), engine.Input{Stream: "outlet:" + f.w.Outlet, Intent: intent, Actor: approver, SID: f.sid, PackV: 1, PinV: 1, Proof: proof, At: at,
		Muts: []sp.Mut{{E: "approval", ID: id, K: sp.KInsert, F: map[string]any{"permission": perm, "intent": "creditnote.issue", "target": target, "action_hash": hash,
			"requester": requester, "approver": approver, "reason": reason}}}})
	if err != nil {
		f.t.Fatal(err)
	}
	return it
}

// cite records the credit note that cites the approval.
func (f *approvalFix) cite(id, cn string, total int64, at time.Time) sp.Item {
	it, err := f.a.Eng.Record(context.Background(), engine.Input{Stream: "outlet:" + f.w.Outlet, Intent: "creditnote.issue", Actor: limited, SID: f.sid, PackV: 1, Approval: id,
		DocType: "credit_note", At: at, MutsFn: func(n string) []sp.Mut {
			return []sp.Mut{{E: "credit_note", ID: cn, K: sp.KInsert, F: map[string]any{"number": n, "bill_id": "bill-1", "total_paise": total}}}
		}})
	if err != nil {
		f.t.Fatal(err)
	}
	return it
}

func (f *approvalFix) sync() {
	f.t.Helper()
	if err := f.a.SyncCloud(context.Background()); err != nil {
		f.t.Fatal(err)
	}
}

func (f *approvalFix) rec(it sp.Item) repository.OpRec { return opRec(f.t, f.w, it) }

func (f *approvalFix) expectFlag(name string, it sp.Item, reason string) {
	f.t.Helper()
	r := f.rec(it)
	if r.Status != repository.StFlagged || !strings.Contains(r.Marks, service.MarkApprovalFlag) || !strings.Contains(r.Marks, service.MarkApprovalReason+reason) ||
		strings.Contains(r.Marks, service.MarkPermissionFlag) {
		f.t.Fatalf("%s: got %s marks %q, want flagged approval_flag %s and no permission_flag", name, r.Status, r.Marks, reason)
	}
}

// ADR-0014 A3.3 and tests OV1 to OV4 of the amendment: an approval that matches clears the cashier's action with no flag;
// another amount is a mismatch; a second citer is reused; no approval and no permission is a permission_flag.
func TestApprovalCitationClearsOrFlagsTheAction(t *testing.T) {
	f := newApprovalFix(t, 401)
	at := f.base.Add(time.Second)
	f.grant("ap-ok", sp.IntentApprovalGrant, "cn-ok", limited, manager, 50400, at)
	ok := f.cite("ap-ok", "cn-ok", 50400, at.Add(30*time.Second))
	f.grant("ap-amt", sp.IntentApprovalGrant, "cn-amt", limited, manager, 50400, at)
	amount := f.cite("ap-amt", "cn-amt", 60000, at.Add(40*time.Second)) // OV2: approved for 50400, records 60000
	reuse := f.cite("ap-ok", "cn-reuse", 50400, at.Add(50*time.Second)) // OV3: ap-ok is cited a second time
	f.grant("ap-late", sp.IntentApprovalGrant, "cn-late", limited, manager, 50400, at)
	late := f.cite("ap-late", "cn-late", 50400, at.Add(121*time.Second))
	none := must(f.a.Eng.Record(context.Background(), engine.Input{Stream: "outlet:" + f.w.Outlet, Intent: "creditnote.issue", Actor: limited, SID: f.sid, PackV: 1,
		DocType: "credit_note", At: at.Add(time.Minute), MutsFn: func(n string) []sp.Mut { // OV4: no approval cited
			return []sp.Mut{{E: "credit_note", ID: "cn-none", K: sp.KInsert, F: map[string]any{"number": n, "bill_id": "bill-1", "total_paise": int64(100)}}}
		}}))
	f.sync()

	if r := f.rec(ok); r.Status != repository.StAccepted || strings.Contains(r.Marks, "flag") || !strings.Contains(r.Marks, service.MarkApprovedBy+manager) {
		t.Fatalf("a matching approval: got %s marks %q, want accepted, no flag, approved by the manager", r.Status, r.Marks)
	}
	f.expectFlag("another amount", amount, service.ApprovalMismatch)
	f.expectFlag("a second citer", reuse, service.ApprovalReused)
	f.expectFlag("outside 120 seconds", late, service.ApprovalExpired)
	if r := f.rec(none); r.Status != repository.StFlagged || !strings.Contains(r.Marks, service.MarkPermissionFlag) || strings.Contains(r.Marks, service.MarkApprovalFlag) {
		t.Fatalf("no approval and no permission: got %s marks %q, want permission_flag only", r.Status, r.Marks)
	}
}

// The approver must differ from the requester in a two-person approval, and a self-confirmation never makes an actor
// without the permission pass; an approver who does not hold the permission clears nothing.
func TestApprovalSelfAndApproverWithoutPermission(t *testing.T) {
	f := newApprovalFix(t, 402)
	at := f.base.Add(time.Second)
	f.grant("ap-self", sp.IntentApprovalGrant, "cn-self", limited, limited, 100, at) // requester = approver in a grant
	self := f.cite("ap-self", "cn-self", 100, at.Add(time.Second))
	f.grant("ap-conf", sp.IntentApprovalSelfConfirm, "cn-conf", limited, limited, 100, at) // a self-confirmation by an actor without the permission
	conf := f.cite("ap-conf", "cn-conf", 100, at.Add(time.Second))
	f.w.Identity.SetMember(f.w.Tenant, "m5", "order.create") // an approver without the permission, in no pack
	f.w.Identity.IssuePack(f.w.Tenant, f.a.ID, 1, 30*24*time.Hour)
	f.grant("ap-weak", sp.IntentApprovalGrant, "cn-weak", limited, "m5", 100, at)
	weak := f.cite("ap-weak", "cn-weak", 100, at.Add(time.Second))
	f.sync()
	f.expectFlag("requester is the approver", self, service.ApprovalSelf)
	f.expectFlag("self-confirmation by an actor without the permission", conf, service.ApprovalSelf)
	f.expectFlag("approver without the permission", weak, service.ApprovalNotPermitted)
}

// OV5: the action is recorded while identity cannot answer the approval proof (or before the approval is known): the op is
// accepted as pending, never flagged for permission, and judged again when the verdict arrives.
func TestApprovalPendingUntilTheVerdictArrives(t *testing.T) {
	f := newApprovalFix(t, 403)
	at := f.base.Add(time.Second)
	f.grant("ap-p", sp.IntentApprovalGrant, "cn-p", limited, manager, 50400, at)
	pend := f.cite("ap-p", "cn-p", 50400, at.Add(10*time.Second))
	f.w.Identity.SetDown(true)
	f.sync()
	r := f.rec(pend)
	if strings.Contains(r.Marks, service.MarkPermissionFlag) || !strings.Contains(r.Marks, service.MarkApprovalPending) || r.Status == repository.StQuarantined && r.Reason != service.ReasonConfigPending {
		t.Fatalf("identity down: got %s/%s marks %q, want pending and no permission_flag", r.Status, r.Reason, r.Marks)
	}
	f.w.Identity.SetDown(false)
	if _, err := f.w.GW.ResolveSessions(context.Background(), f.w.Tenant); err != nil {
		t.Fatal(err)
	}
	if r := f.rec(pend); r.Status != repository.StAccepted || strings.Contains(r.Marks, service.MarkApprovalPending) || !strings.Contains(r.Marks, service.MarkApprovedBy+manager) {
		t.Fatalf("after the verdict: got %s marks %q, want accepted, approved by the manager", r.Status, r.Marks)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
