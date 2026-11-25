package sim

import (
	"testing"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// numberedBill records a bill with a typed number (the allocator is bypassed, as a restored backup or a client bug would).
func numberedBill(t *testing.T, d *Device, id, number string) sp.Item {
	t.Helper()
	return must(d.Do(pCashier, engine.Input{Intent: "bill.finalize", Muts: []sp.Mut{
		{E: "bill", ID: id, K: sp.KInsert, F: map[string]any{"number": number, "doc_type": "tax_invoice", "total_paise": int64(10000)}}}}))
}

// CR-H5: the same legal number under two different bill ids is refused as duplicate_document, the first op keeps the number,
// the owner is told, and a replay of the same bill id (the same page typed twice) is not a duplicate.
func TestDuplicateDocumentIsRefusedAndTheFirstOpKeepsTheNumber(t *testing.T) {
	w, _ := newTestWorld(t, 31, WorldOptions{Pos: 1})
	d := w.Devices[0]
	first := w.billAs(t, d, d.SaleCode(), "tax_invoice")
	fb := must(sp.DecodeBody(first.Body))
	var number, firstID string
	for _, m := range fb.Muts {
		if m.E == "bill" {
			number, firstID = m.F["number"].(string), m.ID
		}
	}
	if number == "" {
		t.Fatal("test needs the first bill's number")
	}
	dup := numberedBill(t, d, "bill-other", number)
	same := numberedBill(t, d, firstID, number) // the same bill id again: one row, no duplicate
	w.toCloud(t, d)

	if r := w.rec(t, first); r.Status != repository.StAccepted {
		t.Fatalf("first op keeps the number: got %s/%s", r.Status, r.Reason)
	}
	if r := w.rec(t, dup); r.Status != repository.StQuarantined || r.Reason != service.ReasonDuplicateDocument {
		t.Fatalf("a different bill id on the same number: got %s/%s, want quarantined duplicate_document", r.Status, r.Reason)
	}
	if r := w.rec(t, same); r.Reason == service.ReasonDuplicateDocument {
		t.Fatalf("the same bill id is not a duplicate: got %s/%s", r.Status, r.Reason)
	}
	var owner bool
	for _, al := range must(w.GW.Alerts(bg, w.Tenant)) {
		owner = owner || (al.Audience == "owner" && al.Severity == "high" && al.Kind == "duplicate_document")
	}
	if !owner {
		t.Fatal("an owner high alert duplicate_document is expected")
	}
	cs, _, _ := w.CloudState(bg)
	for _, id := range cs.IDs("bill") {
		if id == "bill-other" {
			t.Fatal("the refused duplicate must not be projected")
		}
	}
}
