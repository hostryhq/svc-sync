package sim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

var bg = context.Background()

func (w *World) rec(t *testing.T, it sp.Item) repository.OpRec {
	t.Helper()
	var r repository.OpRec
	var ok bool
	err := w.GWStore.InTx(bg, w.Tenant, func(tx repository.Tx) error {
		var err error
		r, ok, err = tx.GetOp(it.Stream, it.Origin, it.Seq)
		return err
	})
	if err != nil || !ok {
		t.Fatalf("cloud has no slot %s/%d: %v", it.Origin, it.Seq, err)
	}
	return r
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func must0(err error) {
	if err != nil {
		panic(err)
	}
}

func (w *World) toCloud(t *testing.T, ds ...*Device) {
	t.Helper()
	for _, d := range ds {
		if err := d.SyncCloud(bg); err != nil {
			t.Fatalf("%s sync to cloud: %v", d.ID, err)
		}
	}
}

func (w *World) billAs(t *testing.T, d *Device, code string, docType string) sp.Item {
	t.Helper()
	d.SetBadSeries(code)
	defer d.SetBadSeries("")
	return must(d.Do(pCashier, engine.Input{Intent: "bill.finalize", DocType: docType, MutsFn: func(n string) []sp.Mut {
		return []sp.Mut{{E: "bill", ID: d.nextID("b"), K: sp.KInsert, F: map[string]any{"number": n, "total_paise": int64(10000)}}}
	}}))
}

func hasMark(r repository.OpRec, m string) bool {
	for _, x := range strings.Split(r.Marks, ",") {
		if x == m {
			return true
		}
	}
	return false
}

func TestV1_NumberInAnotherDevicesSeriesIsHeldAndTheRegisterShowsIt(t *testing.T) {
	w, _ := newTestWorld(t, 11, WorldOptions{Pos: 2, Waiters: 0, KDS: 0})
	a, b := w.Devices[0], w.Devices[1]
	own := w.billAs(t, b, b.SaleCode(), "tax_invoice")
	foreign := w.billAs(t, a, b.SaleCode(), "tax_invoice") // D bills in E's series
	w.toCloud(t, a, b)
	r := w.rec(t, foreign)
	if r.Status != repository.StQuarantined || r.Reason != service.ReasonForeignSeries {
		t.Fatalf("got %s/%s", r.Status, r.Reason)
	}
	if w.rec(t, own).Status != repository.StAccepted {
		t.Fatal("E's own bill must be accepted")
	}
	rep := must(w.GW.Register(bg, w.Tenant))
	if len(rep.Foreign) != 1 || rep.Foreign[0].Origin != a.ID {
		t.Fatalf("register must show one foreign claim by %s: %+v", a.ID, rep.Foreign)
	}
	if len(rep.Gaps) != 0 {
		t.Fatalf("a foreign claim must not raise a gap alert on E's series: %+v", rep.Gaps)
	}
	alerts := must(w.GW.Alerts(bg, w.Tenant))
	var owner, vendor bool
	for _, al := range alerts {
		owner = owner || (al.Audience == "owner" && al.Severity == "high")
		vendor = vendor || (al.Audience == "vendor" && al.Kind == "foreign_series")
	}
	if !owner || !vendor {
		t.Fatalf("owner high alert and vendor alert expected, got %+v", alerts)
	}
	// Served to others as an empty placeholder; not projected.
	pr := must(w.GW.Pull(bg, w.Tenant, engine.Caller{ID: b.ID, Kind: sp.KindPOS, Outlet: w.Outlet, Brand: w.Brand}, sp.PullRequest{Vector: sp.Vector{}}))
	for _, it := range pr.Items {
		if it.Origin == a.ID && it.Seq == foreign.Seq && !it.IsPlaceholder() {
			t.Fatal("quarantined slot must be served as a placeholder")
		}
	}
	cs, _, _ := w.CloudState(bg)
	if len(cs.IDs("bill")) != 1 {
		t.Fatalf("only E's bill is projected, got %d", len(cs.IDs("bill")))
	}
	// D is not revoked: its next bill in its own series is accepted.
	next := w.billAs(t, a, a.SaleCode(), "tax_invoice")
	w.toCloud(t, a)
	if w.rec(t, next).Status != repository.StAccepted {
		t.Fatal("D's next bill in its own series must be accepted")
	}
}

func TestV2_OtherTenantAndNowhereCodesGiveTheSameAnswerAndTouchNoOtherRegister(t *testing.T) {
	w, _ := newTestWorld(t, 12, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	otherT := "018f0000-0000-7000-8000-0000000000ff"
	var theirs string
	for i := 0; i < 24; i++ {
		theirs = w.Identity.IssueSeries(otherT, "stranger", "tax_invoice", directory.SeriesActive)
	}
	if _, ok := w.Identity.Series(w.Tenant, theirs); ok {
		t.Fatalf("test needs a code that exists only in the other tenant")
	}
	ia := w.billAs(t, a, theirs, "tax_invoice")
	ib := w.billAs(t, b, "ZZ9", "tax_invoice")
	respOf := func(d *Device) string {
		req := must(d.Eng.Outbound(bg, sp.Vector{}, engine.OutboundOpts{}))
		resp, err := w.CloudTransport("dev-cloud:"+d.ID, d.ID).Push(bg, req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(resp)
		return strings.ReplaceAll(string(raw), d.ID, "DEV")
	}
	ra, rb := respOf(a), respOf(b)
	if ra != rb {
		t.Fatalf("responses differ:\n%s\n%s", ra, rb)
	}
	for _, it := range []sp.Item{ia, ib} {
		if r := w.rec(t, it); r.Status != repository.StQuarantined || r.Reason != service.ReasonForeignSeries || !hasMark(r, service.MarkUnknownSeries) {
			t.Fatalf("got %s/%s marks=%s", r.Status, r.Reason, r.Marks)
		}
	}
	rep := must(w.GW.Register(bg, w.Tenant))
	if len(rep.Unknown) != 2 {
		t.Fatalf("both numbers are listed under unknown series, got %d", len(rep.Unknown))
	}
	other := must(w.GW.Register(bg, otherT))
	if len(other.Entries) != 0 {
		t.Fatal("the other tenant's register must be unchanged")
	}
}

func TestV3toV5_FlaggedRowsKeepTheirNumbers(t *testing.T) {
	w, _ := newTestWorld(t, 13, WorldOptions{Pos: 1, Waiters: 1})
	a, wt := w.Devices[0], w.Devices[1]
	// V3: own series closed.
	w.Identity.SetSeriesState(w.Tenant, a.SaleCode(), directory.SeriesClosed)
	v3 := w.billAs(t, a, a.SaleCode(), "tax_invoice")
	w.toCloud(t, a)
	// V4a: dormant series, no activation op earlier in the stream.
	v4a := w.billAs(t, wt, wt.SaleCode(), "tax_invoice")
	// V5: a credit note numbered in the device's own sale series.
	w.Identity.SetSeriesState(w.Tenant, a.SaleCode(), directory.SeriesActive)
	v5 := w.billAs(t, a, a.SaleCode(), "credit_note")
	w.toCloud(t, a, wt)
	for name, c := range map[string]struct {
		it   sp.Item
		mark string
	}{"V3": {v3, service.MarkSeriesClosed}, "V4a": {v4a, service.MarkDormantSeries}, "V5": {v5, service.MarkDocTypeMismatch}} {
		r := w.rec(t, c.it)
		if r.Status != repository.StFlagged || !hasMark(r, c.mark) {
			t.Errorf("%s: got %s marks=%s", name, r.Status, r.Marks)
		}
	}
	cs, _, _ := w.CloudState(bg)
	if len(cs.IDs("bill")) < 3 {
		t.Error("flagged bills are accepted and projected")
	}
}

func TestV4b_DormantSeriesWithEarlierActivationIsAcceptedAndTheActivationFlagged(t *testing.T) {
	w, _ := newTestWorld(t, 14, WorldOptions{Pos: 1, Waiters: 1})
	wt := w.Devices[1]
	act := must(wt.ActivateSeriesOp())
	bill := w.billAs(t, wt, wt.SaleCode(), "tax_invoice")
	w.toCloud(t, wt)
	if r := w.rec(t, bill); r.Status != repository.StAccepted {
		t.Fatalf("bill after activation: %s marks=%s", r.Status, r.Marks)
	}
	if r := w.rec(t, act); r.Status != repository.StFlagged || !hasMark(r, service.MarkActivationFlag) {
		t.Fatalf("the activation is flagged for the owner: %s marks=%s", r.Status, r.Marks)
	}
}

func TestV6_ConfigOpCarryingANumberIsQuarantinedAsMalformed(t *testing.T) {
	w, _ := newTestWorld(t, 15, WorldOptions{Pos: 1})
	a := w.Devices[0]
	it := must(a.Do(pManager, engine.Input{Stream: "brand:" + w.Brand, Intent: "menu.price.set", DocType: "tax_invoice",
		Muts: []sp.Mut{{E: "menu_item", ID: "menu-1", K: sp.KSet, F: map[string]any{"price_paise": int64(100)}, Prev: map[string]string{"price_paise": engine.ZeroStamp}}}}))
	w.toCloud(t, a)
	if r := w.rec(t, it); r.Status != repository.StQuarantined || r.Reason != service.ReasonMalformed {
		t.Fatalf("got %s/%s", r.Status, r.Reason)
	}
}

func TestV7_ForeignSeriesCannotBeDiscardedAndNeedsVendorToRelease(t *testing.T) {
	w, _ := newTestWorld(t, 16, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	it := w.billAs(t, a, b.SaleCode(), "tax_invoice")
	w.toCloud(t, a)
	ref := sp.Ref{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq}
	if err := w.GW.Discard(bg, w.Tenant, ref); !errors.Is(err, service.ErrDiscardNumbered) {
		t.Fatalf("discard must be refused, got %v", err)
	}
	if _, err := w.GW.Release(bg, w.Tenant, ref, service.ReleaseOpts{}); !errors.Is(err, service.ErrNeedsVendor) {
		t.Fatalf("release without vendor confirmation must be refused, got %v", err)
	}
	// Over HTTP: only a support token in act mode counts as vendor confirmation.
	user := w.Issuer.Mint(authtest.Spec{Type: auth.TypeUser, Tenant: ids.ID(w.Tenant), Grants: authtest.OwnerGrants()})
	body, _ := json.Marshal(ref)
	call := func(tok string) int {
		req := httptest.NewRequest(http.MethodPost, "/sync/v1/quarantine/release", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		w.CloudH.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := call(user); c != http.StatusConflict {
		t.Fatalf("owner release of a foreign series: want 409, got %d", c)
	}
	support := w.Issuer.Mint(authtest.Spec{Type: auth.TypeSupport, Tenant: ids.ID(w.Tenant), Mode: auth.ModeAct, Grants: authtest.OwnerGrants()})
	if c := call(support); c != http.StatusOK {
		t.Fatalf("support act release: want 200, got %d", c)
	}
	if r := w.rec(t, it); r.Status == repository.StQuarantined {
		t.Fatal("released op must leave quarantine")
	}
}

func TestV8_HubDoesNotRelayAForeignSeriesOpAndTheCloudStillGetsIt(t *testing.T) {
	w, _ := newTestWorld(t, 17, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	it := w.billAs(t, a, b.SaleCode(), "tax_invoice")
	must0(a.SyncHub(bg))
	must0(b.SyncHub(bg))
	// B must not have received it from the hub.
	if rows := b.ids("bill"); len(rows) != 0 {
		t.Fatalf("hub relayed a bill numbered in a series its origin does not hold: %v", rows)
	}
	var hubStatus string
	_ = w.Hub.Engine().Config().Store.InTx(bg, w.Tenant, func(tx repository.Tx) error {
		r, _, _ := tx.GetOp(it.Stream, it.Origin, it.Seq)
		hubStatus = r.Status
		return nil
	})
	if hubStatus != repository.StHeldLocal {
		t.Fatalf("hub status %q, want held_local", hubStatus)
	}
	// The hub (or the origin) delivers it to the cloud, which decides: quarantined as in V1.
	_, _ = w.Hub.SyncUpstream(bg)
	if r := w.rec(t, it); r.Status != repository.StQuarantined || r.Reason != service.ReasonForeignSeries {
		t.Fatalf("cloud verdict %s/%s", r.Status, r.Reason)
	}
	_, _ = w.Hub.SyncUpstream(bg)
	must0(b.SyncHub(bg))
	if rows := b.ids("bill"); len(rows) != 0 {
		t.Fatal("still not relayed after the cloud held it")
	}
}
