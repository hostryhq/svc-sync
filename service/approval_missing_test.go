package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
)

// OV6 (P2-H1): an op that cites an approval the gateway never receives is not accepted unflagged for ever. Until the window
// and the grace have passed it is pending and is listed on the exceptions screen; after them it is an approval_flag `missing`,
// with an owner alert.
func TestApprovalThatNeverArrivesIsFlaggedMissingAfterTheWindow(t *testing.T) {
	f := newApprovalFix(t, 404)
	cited := f.cite("ap-forged", "cn-forged", 90000, f.base.Add(time.Second))
	f.sync()
	if r := f.rec(cited); r.Status != repository.StAccepted || !strings.Contains(r.Marks, service.MarkApprovalPending) {
		t.Fatalf("before the window ends: got %s marks %q, want accepted and pending", r.Status, r.Marks)
	}
	listed := func() bool {
		ex, err := f.w.GW.Exceptions(context.Background(), f.w.Tenant)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range ex {
			if it.Ref.Seq == cited.Seq && it.Ref.Origin == cited.Origin {
				return true
			}
		}
		return false
	}
	if !listed() {
		t.Fatal("a pending approval citation must be on the exceptions list")
	}
	f.w.Advance(service.ApprovalMaxAge + service.ApprovalMissingGrace/2)
	if err := f.w.GW.MaintainOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := f.rec(cited); !strings.Contains(r.Marks, service.MarkApprovalPending) || strings.Contains(r.Marks, service.MarkApprovalFlag) {
		t.Fatalf("inside the grace: got %s marks %q, want still pending", r.Status, r.Marks)
	}
	f.w.Advance(service.ApprovalMaxAge + service.ApprovalMissingGrace)
	if err := f.w.GW.MaintainOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.expectFlag("an approval that never arrived", cited, service.ApprovalMissing)
	if r := f.rec(cited); strings.Contains(r.Marks, service.MarkApprovalPending) {
		t.Fatalf("the pending mark must go once the flag is final: %q", r.Marks)
	}
	if !listed() {
		t.Fatal("a missing-approval flag must be on the exceptions list")
	}
	var alerted bool
	al, err := f.w.GW.Alerts(context.Background(), f.w.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range al {
		alerted = alerted || (a.Audience == "owner" && a.Kind == "approval_flag")
	}
	if !alerted {
		t.Fatal("an owner approval_flag alert is expected")
	}
}
