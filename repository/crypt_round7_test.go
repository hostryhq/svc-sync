package repository_test

import (
	"context"
	"testing"

	"github.com/hostryhq/svc-sync/repository"
)

// Round 7: alerts.detail and approval_verdicts.reason can quote an operator's words, so the hub seals them like every other value
// column. They read back whole, an alert still resolves by its detail, and neither is in the file in the clear.
func TestHubStoreSealsAlertDetailAndApprovalReason(t *testing.T) {
	dir := t.TempDir()
	s := openEnc(t, dir, devProvider(t, dir, "key"))
	ctx := context.Background()
	const detail, reason = "series INV/2627:3 held by Ravi Menon's tablet", "customer Priya Nair asked for the discount in person"
	if err := s.InTx(ctx, tenant, func(tx repository.Tx) error {
		if err := tx.AddAlert("owner", "high", "series_tail_missing", detail); err != nil {
			return err
		}
		if err := tx.AddAlert("owner", "high", "series_tail_missing", "other detail"); err != nil {
			return err
		}
		if err := tx.PutApprovalVerdict("d1", "ap1", "pending"); err != nil {
			return err
		}
		return tx.PutApprovalRecord(repository.ApprovalRow{Origin: "d1", ID: "ap1", Kind: "approval.grant", Reason: reason, Approver: "m1"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InTx(ctx, tenant, func(tx repository.Tx) error {
		al, err := tx.Alerts()
		if err != nil || len(al) != 2 || al[0].Detail != detail {
			t.Fatalf("alerts read back whole: %+v %v", al, err)
		}
		ap, ok, err := tx.GetApproval("d1", "ap1")
		if err != nil || !ok || ap.Reason != reason {
			t.Fatalf("approval reason reads back whole: %+v %v %v", ap, ok, err)
		}
		pend, err := tx.PendingApprovals()
		if err != nil || len(pend) != 1 || pend[0].Reason != reason {
			t.Fatalf("pending approvals read back whole: %+v %v", pend, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InTx(ctx, tenant, func(tx repository.Tx) error { return tx.ResolveAlerts("series_tail_missing", detail) }); err != nil {
		t.Fatal(err)
	}
	if err := s.InTx(ctx, tenant, func(tx repository.Tx) error {
		al, err := tx.Alerts()
		if err != nil || len(al) != 1 || al[0].Detail != "other detail" {
			t.Fatalf("resolving by the sealed detail removes exactly that alert: %+v %v", al, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Checkpoint(ctx)
	if found := fileHas(t, dir, "Priya Nair", "Ravi Menon", "other detail"); len(found) > 0 {
		t.Fatalf("values in the clear in the store file: %v", found)
	}
}

// A sealed alert detail copied to another alert row fails as tampered, as every sealed column does.
func TestAlertDetailCopiedToAnotherRowFailsAsTampered(t *testing.T) {
	dir := t.TempDir()
	s := openEnc(t, dir, devProvider(t, dir, "key"))
	ctx := context.Background()
	if err := s.InTx(ctx, tenant, func(tx repository.Tx) error {
		if err := tx.AddAlert("owner", "high", "k", "first"); err != nil {
			return err
		}
		return tx.AddAlert("owner", "high", "k", "second")
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InTx(ctx, tenant, func(tx repository.Tx) error {
		return tx.Exec(`UPDATE alerts SET detail=(SELECT detail FROM alerts WHERE id=1) WHERE id=2`)
	}); err != nil {
		t.Fatal(err)
	}
	err := s.InTx(ctx, tenant, func(tx repository.Tx) error { _, err := tx.Alerts(); return err })
	if err != repository.ErrTampered {
		t.Fatalf("got %v, want ErrTampered", err)
	}
}
