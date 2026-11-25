package sim

import (
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// A paper-book entry (bill.manual_entry, typed number) in a series the owner registered as a manual_book
// series is accepted and shown in the register, not held as foreign_series (ADR-0014 A1.6 item 4); a
// typed number in a code nobody registered is still held, and a manual_book code cannot be allocated from.
func TestManualBookEntryMapsToRegisteredSeries(t *testing.T) {
	w, _ := newTestWorld(t, 41, WorldOptions{Pos: 2})
	a := w.Devices[0]
	w.Identity.IssueManualBook(w.Tenant, "BKB", w.Outlet)
	w.Identity.SetMember(w.Tenant, pCashier, append([]string{"bill.manual_entry"}, cashierPerms...)...)
	w.Identity.IssuePack(w.Tenant, a.ID, "v1", 24*time.Hour)
	entry := func(code string) sp.Item {
		a.SetBadSeries(code)
		defer a.SetBadSeries("")
		return must(a.Do(pCashier, engine.Input{Intent: "bill.manual_entry", DocType: "tax_invoice", MutsFn: func(n string) []sp.Mut {
			return []sp.Mut{{E: "bill", ID: a.nextID("b"), K: sp.KInsert, F: map[string]any{"number": n, "total_paise": int64(10000), "source_kind": "manual_book"}}}
		}}))
	}
	book := entry("BKB")
	nobody := entry("BKX")
	alloc := w.billAs(t, a, "BKB", "tax_invoice") // allocation from an entry-only series is not allowed
	w.toCloud(t, a)
	if r := w.rec(t, book); r.Status != repository.StAccepted {
		t.Fatalf("a typed number in a registered manual_book series: got %s/%s, want accepted", r.Status, r.Reason)
	}
	if r := w.rec(t, nobody); r.Status != repository.StQuarantined || r.Reason != service.ReasonForeignSeries {
		t.Fatalf("a typed number in an unregistered code: got %s/%s", r.Status, r.Reason)
	}
	if r := w.rec(t, alloc); r.Status != repository.StQuarantined || r.Reason != service.ReasonForeignSeries {
		t.Fatalf("an allocated number in an entry-only series: got %s/%s", r.Status, r.Reason)
	}
	rep := must(w.GW.Register(bg, w.Tenant))
	for _, g := range rep.Gaps {
		if g.Code == "BKB" {
			t.Fatalf("a paper book is typed, never gapless; no gap alert expected: %+v", g)
		}
	}
	found := false
	for _, e := range rep.Entries {
		found = found || (e.Code == "BKB" && e.Mark == service.MarkManualBook)
	}
	if !found {
		t.Fatalf("the register must hold the book entry marked manual_book: %+v", rep.Entries)
	}
}

// A page of a closed book is accepted and flagged after_closure; a book listing other outlets is foreign.
func TestManualBookClosedAndOtherOutlet(t *testing.T) {
	w, _ := newTestWorld(t, 43, WorldOptions{Pos: 1})
	a := w.Devices[0]
	w.Identity.SetMember(w.Tenant, pCashier, append([]string{"bill.manual_entry"}, cashierPerms...)...)
	w.Identity.IssuePack(w.Tenant, a.ID, "v1", 24*time.Hour)
	w.Identity.IssueManualBook(w.Tenant, "BKC", w.Outlet)
	w.Identity.SetSeriesState(w.Tenant, "BKC", "closed")
	w.Identity.IssueManualBook(w.Tenant, "BKO", "some-other-outlet")
	entry := func(code string) sp.Item {
		a.SetBadSeries(code)
		defer a.SetBadSeries("")
		return must(a.Do(pCashier, engine.Input{Intent: "bill.manual_entry", DocType: "tax_invoice", MutsFn: func(n string) []sp.Mut {
			return []sp.Mut{{E: "bill", ID: a.nextID("b"), K: sp.KInsert, F: map[string]any{"number": n, "total_paise": int64(1)}}}
		}}))
	}
	closed, other := entry("BKC"), entry("BKO")
	w.toCloud(t, a)
	if r := w.rec(t, closed); r.Status != repository.StFlagged || !hasMark(r, service.MarkAfterClosure) {
		t.Fatalf("a page of a closed book: got %s marks %q, want flagged after_closure", r.Status, r.Marks)
	}
	if r := w.rec(t, other); r.Status != repository.StQuarantined || r.Reason != service.ReasonForeignSeries {
		t.Fatalf("a book of another outlet: got %s/%s", r.Status, r.Reason)
	}
}

// A device session (actor device:<own id>, no PIN, no pack member) may record the intents that list the device
// kind and the device session type, and only those: not a sale, not free text such as device-kds, not another
// device's id, and not a pin session that merely uses the name (sync/protocol-v1.md, device-session ops).
func TestDeviceActorOnlyForIntentsThatDeclareIt(t *testing.T) {
	w, _ := newTestWorld(t, 42, WorldOptions{Pos: 1, KDS: 1})
	var k, p *Device
	for _, d := range w.Devices {
		if d.Kind == sp.KindKDS {
			k = d
		} else {
			p = d
		}
	}
	open := func(d *Device, actor, typ string) string {
		sid := "s-" + typ + "-" + d.ID
		must(d.record(engine.Input{Stream: "outlet:" + w.Outlet, Intent: sp.IntentSessionOpen, Actor: actor, SID: sid, Proof: "none",
			Muts: []sp.Mut{{E: "session", ID: sid, K: sp.KInsert, F: map[string]any{"type": typ, "device": d.ID}}}}, true))
		return sid
	}
	bump := func(d *Device, actor, sid string) sp.Item {
		return must(d.record(engine.Input{Stream: "outlet:" + w.Outlet, Intent: "kds.status", Actor: actor, SID: sid, Proof: "none",
			Muts: []sp.Mut{{E: "kot_line", ID: "kl-1", K: sp.KRank, F: map[string]any{"status": "preparing"}}}}, true))
	}
	own := service.DeviceActorPrefix + k.ID
	sid := open(k, own, "device")
	ok := bump(k, own, sid)
	freeText := bump(k, "device-kds", sid)
	otherDevice := bump(k, service.DeviceActorPrefix+p.ID, sid)
	pinSid := open(k, own, "pin") // a pin session that claims the device actor's name
	pinClaim := bump(k, own, pinSid)
	k.SetBadSeries(p.SaleCode()) // the KDS has no series of its own; any code reaches the verdict
	sale := must(k.record(engine.Input{Stream: "outlet:" + w.Outlet, Intent: "bill.finalize", Actor: own, SID: sid, Proof: "none", DocType: "tax_invoice",
		MutsFn: func(n string) []sp.Mut {
			return []sp.Mut{{E: "bill", ID: k.nextID("b"), K: sp.KInsert, F: map[string]any{"number": n, "total_paise": int64(1)}}}
		}}, true))
	w.toCloud(t, k, p)
	if r := w.rec(t, ok); r.Status != repository.StAccepted {
		t.Fatalf("kds.status by the device actor: got %s/%s, want accepted", r.Status, r.Reason)
	}
	for name, it := range map[string]sp.Item{"free text": freeText, "another device's id": otherDevice, "a pin session": pinClaim} {
		if r := w.rec(t, it); r.Status != repository.StQuarantined || r.Reason != service.ReasonActorUnknown {
			t.Fatalf("%s: got %s/%s, want quarantined actor_unknown", name, r.Status, r.Reason)
		}
	}
	if r := w.rec(t, sale); r.Status != repository.StQuarantined {
		t.Fatalf("a device actor cannot sell: got %s/%s", r.Status, r.Reason)
	}
}
