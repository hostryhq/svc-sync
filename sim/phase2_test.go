package sim

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/svc-sync/contract/specs"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

func (w *World) fy() string { return engine.FY(w.Clock.Now()) }

func (w *World) register(t *testing.T) []repository.RegisterEntry {
	t.Helper()
	rep, err := w.GW.Register(bg, w.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	return rep.Entries
}

// ADR-0014 / protocol-v1 "Several document numbers in one op": a re-bill takes a credit note number and a
// new bill number in one transaction, and the register keeps both under the op's identity.
func TestRebillOpRegistersEveryNumberItCarries(t *testing.T) {
	w, _ := newTestWorld(t, 61, WorldOptions{Pos: 1})
	a := w.Devices[0]
	rebill := func(second string) sp.Item {
		return must(a.Do(pCashier, engine.Input{Intent: "bill.rebill", DocType: "credit_note", MutsFn: func(n string) []sp.Mut {
			return []sp.Mut{
				{E: "credit_note", ID: a.nextID("cn"), K: sp.KInsert, F: map[string]any{"number": n}},
				{E: "bill", ID: a.nextID("b"), K: sp.KInsert, F: map[string]any{"number": second, "doc_type": "tax_invoice"}},
			}
		}}))
	}
	it := rebill(engine.FormatNumber(a.SaleCode(), w.fy(), 1))
	w.toCloud(t, a)
	if r := w.rec(t, it); r.Status == repository.StQuarantined {
		t.Fatalf("a re-bill from the device's own series: %s/%s", r.Status, r.Reason)
	}
	var codes []string
	for _, e := range w.register(t) {
		if e.Seq == it.Seq && e.Origin == it.Origin {
			codes = append(codes, e.Code+":"+e.DocType)
		}
	}
	if len(codes) != 2 {
		t.Fatalf("the register must hold both numbers of the op, got %v", codes)
	}
	// Both numbers of one series in one op: an op never takes a series twice. Held, never accepted.
	bad := rebill(engine.FormatNumber(a.CNCode(), w.fy(), 77))
	w.toCloud(t, a)
	if r := w.rec(t, bad); r.Status != repository.StQuarantined || r.Reason != service.ReasonMalformed {
		t.Fatalf("two numbers of one series in an op: %s/%s", r.Status, r.Reason)
	}
}

// A closed series is confirmed by the device's own statement of its last number: the gateway waits until
// the register holds every number up to it (a gap is an alert), then records it as reconciled.
func TestSeriesCloseConfirmsTheTailWhenTheRegisterIsComplete(t *testing.T) {
	w, _ := newTestWorld(t, 62, WorldOptions{Pos: 1})
	a := w.Devices[0]
	code, fy := a.SaleCode(), w.fy()
	for i := 0; i < 3; i++ {
		w.billAs(t, a, "", "tax_invoice")
	}
	stmt := must(a.Do(pCashier, engine.Input{Intent: "series.close", Muts: []sp.Mut{
		{E: "series_close", ID: "series-1", K: sp.KInsert, F: map[string]any{"code": code, "fy": fy, "last_number": int64(5)}}}}))
	w.toCloud(t, a)
	state := func() (last int64, done, stated bool, alerts int) {
		err := w.GWStore.InTx(bg, w.Tenant, func(tx repository.Tx) error {
			var err error
			last, done, stated, err = w.GW.SeriesState(tx, code, fy)
			al, _ := tx.Alerts()
			for _, x := range al {
				if x.Kind == "series_tail_missing" {
					alerts++
				}
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if r := w.rec(t, stmt); r.Status == repository.StQuarantined {
		t.Fatalf("the statement is held: %s/%s", r.Status, r.Reason)
	}
	if last, done, stated, alerts := state(); !stated || last != 5 || done || alerts != 1 {
		t.Fatalf("two numbers are missing: last=%d reconciled=%v stated=%v alerts=%d", last, done, stated, alerts)
	}
	w.billAs(t, a, "", "tax_invoice")
	w.billAs(t, a, "", "tax_invoice")
	w.toCloud(t, a)
	if _, done, _, alerts := state(); !done || alerts != 0 {
		t.Fatalf("the register is complete: reconciled=%v open alerts=%d", done, alerts)
	}
	// A second statement with another last number is refused and alerted, never taking over.
	again := must(a.Do(pCashier, engine.Input{Intent: "series.close", Muts: []sp.Mut{
		{E: "series_close", ID: "series-1", K: sp.KInsert, F: map[string]any{"code": code, "fy": fy, "last_number": int64(9)}}}}))
	w.toCloud(t, a)
	_ = again
	if last, _, _, _ := state(); last != 5 {
		t.Fatalf("a later statement replaced the first: %d", last)
	}
}

func (w *World) gwPII(t *testing.T, it sp.Item) (string, bool) {
	t.Helper()
	var raw string
	var ok bool
	if err := w.GWStore.InTx(bg, w.Tenant, func(tx repository.Tx) error {
		var err error
		raw, ok, err = tx.GetPII(it.Stream, it.Origin, it.Seq)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return raw, ok
}

// Personal data: the sealed body carries salted commitments only; the gateway keeps what verifies, drops what
// does not, and a cloud-signed erasure removes values and salts everywhere and is acknowledged by the node.
func TestPIICommitmentsVerifyDropAndErase(t *testing.T) {
	w, _ := newTestWorld(t, 63, WorldOptions{Pos: 1, NoHub: true})
	a := w.Devices[0]
	pii := json.RawMessage(`{"check":{"c1":{"customer_phone":"+910000000000","customer_name":"Asha"}}}`)
	mk := func(p json.RawMessage) sp.Item {
		return must(a.Do(pCashier, engine.Input{Intent: "order.create", PII: p, Muts: []sp.Mut{{E: "order", ID: a.nextID("o"), K: sp.KInsert, F: map[string]any{"table": "t1"}}}}))
	}
	it := mk(pii)
	if strings.Contains(it.Body, "+910000000000") || !strings.Contains(it.Body, `"pii_c"`) {
		t.Fatalf("the sealed body must carry commitments and no value: %s", it.Body)
	}
	w.toCloud(t, a)
	raw, ok := w.gwPII(t, it)
	if !ok || !strings.Contains(raw, "+910000000000") {
		t.Fatalf("the gateway keeps the verified pii: %q %v", raw, ok)
	}
	if r := w.rec(t, it); hasMark(r, service.MarkPIIDropped) {
		t.Fatalf("clean pii was marked dropped: %s", r.Marks)
	}

	// Tampered in transit: values that do not match their commitment are dropped, the op is kept, marked.
	it2 := mk(pii)
	req, err := a.Eng.Outbound(bg, sp.Vector{sp.VKey(a.ID, it.Stream): it.Seq}, engine.OutboundOpts{})
	if err != nil || len(req.Items) != 1 {
		t.Fatalf("outbound: %v %d", err, len(req.Items))
	}
	req.Items[0].PII = json.RawMessage(strings.ReplaceAll(string(req.Items[0].PII), "+910000000000", "+911111111111"))
	if _, err := w.GW.Push(bg, w.Tenant, engine.Caller{ID: a.ID, Kind: sp.KindPOS, Outlet: w.Outlet, Brand: w.Brand}, req); err != nil {
		t.Fatal(err)
	}
	if raw, _ := w.gwPII(t, it2); strings.Contains(raw, "1111") || !strings.Contains(raw, "Asha") {
		t.Fatalf("the altered field must be dropped and the intact one kept: %q", raw)
	}
	if r := w.rec(t, it2); r.Status == repository.StQuarantined || !hasMark(r, service.MarkPIIDropped) {
		t.Fatalf("the op is kept and marked: %s %s", r.Status, r.Marks)
	}

	// Erasure.
	ref := sp.Ref{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq}
	er, err := w.GW.ErasePII(bg, w.Tenant, ref)
	if err != nil || !strings.HasPrefix(er.Origin, engine.CloudOriginPrefix) {
		t.Fatalf("erase: %+v %v", er, err)
	}
	if _, ok := w.gwPII(t, it); ok {
		t.Fatal("the gateway still holds the values and salts")
	}
	if again, err := w.GW.ErasePII(bg, w.Tenant, ref); err != nil || again != er {
		t.Fatalf("erasing twice must answer the first erasure op: %+v %v", again, err)
	}
	devHas := func() bool {
		var ok bool
		_ = a.Eng.Config().Store.InTx(bg, w.Tenant, func(tx repository.Tx) error {
			_, ok, _ = tx.GetPII(it.Stream, it.Origin, it.Seq)
			return nil
		})
		return ok
	}
	if !devHas() {
		t.Fatal("setup: the device holds its own pii")
	}
	w.toCloud(t, a) // pulls the erasure op, applies it
	if devHas() {
		t.Fatal("the device kept values after the cloud-signed erasure")
	}
	if acked, _ := w.GW.ErasureAcked(bg, w.Tenant, a.ID, ref); acked {
		t.Fatal("acknowledged before the next hello")
	}
	w.toCloud(t, a) // the next hello acknowledges
	if acked, err := w.GW.ErasureAcked(bg, w.Tenant, a.ID, ref); err != nil || !acked {
		t.Fatalf("the node's acknowledgement did not reach the gateway: %v %v", acked, err)
	}
	if raw, ok := w.gwPII(t, it); ok {
		t.Fatalf("resurrected: %q", raw)
	}
}

// An op over the size limit that still arrives is malformed (S11): kept in quarantine as an opaque body.
func TestOversizeDeviceOpIsQuarantinedAsOpaque(t *testing.T) {
	w, _ := newTestWorld(t, 64, WorldOptions{Pos: 1, NoHub: true})
	a := w.Devices[0]
	if _, err := a.Do(pCashier, engine.Input{Intent: "order.create", Muts: []sp.Mut{{E: "order", ID: "o1", K: sp.KInsert, F: map[string]any{"table": strings.Repeat("x", sp.MaxBodyBytes)}}}}); err == nil {
		t.Fatal("the client must refuse an op over the limit before recording or numbering anything")
	}
	// The same op built by a misbehaving node is held, never dropped, never published with its body.
	stream := "outlet:" + w.Outlet
	body := sp.Body{V: 1, Origin: a.ID, Stream: stream, Seq: 1, PH: sp.GenesisHash(a.ID, stream), HLC: sp.MakeHLC(w.Clock.Now().UnixMilli(), 0).String(), Clk: sp.ClkSync,
		TenantID: w.Tenant, Actor: pCashier, Intent: "order.create", IntentV: 1, At: w.Clock.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Muts: []sp.Mut{{E: "order", ID: "o1", K: sp.KInsert, F: map[string]any{"table": strings.Repeat("x", sp.MaxBodyBytes)}}}}
	it, err := sp.NewItem(body, nil)
	if err != nil {
		t.Fatal(err)
	}
	seal := must(sp.MakeSeal(a.Key, a.ID, stream, 1, it.H))
	res, err := w.GW.Push(bg, w.Tenant, engine.Caller{ID: a.ID, Kind: sp.KindPOS, Outlet: w.Outlet, Brand: w.Brand}, sp.PushRequest{Items: []sp.Item{it}, Seals: []sp.Seal{seal}})
	if err != nil || len(res.Held) != 1 {
		t.Fatalf("push: %+v %v", res, err)
	}
	if r := w.rec(t, it); r.Status != repository.StQuarantined || r.Reason != service.ReasonOpaque {
		t.Fatalf("oversize op: %s/%s", r.Status, r.Reason)
	}
}

// Admin answers have the shapes of openapi/sync/v1 (listQuarantine, listExceptions, getSeriesRegister, listSyncAlerts).
func TestAdminAnswersConformToTheContract(t *testing.T) {
	api, err := specs.LoadOpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	w, _ := newTestWorld(t, 65, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	w.billAs(t, a, "", "tax_invoice")
	foreign := w.billAs(t, a, b.SaleCode(), "tax_invoice")
	w.toCloud(t, a)
	owner := w.mint(authtest.Spec{Type: auth.TypeUser, Grants: authtest.OwnerGrants()})
	for _, path := range []string{"/sync/v1/quarantine", "/sync/v1/exceptions", "/sync/v1/series-register", "/sync/v1/alerts"} {
		code, body := w.adminCall("GET", path, owner, "", nil)
		if code != 200 {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		op, ok := api.Find("GET", path)
		if !ok {
			t.Fatalf("%s is not in the contract", path)
		}
		var v any
		_ = json.Unmarshal([]byte(body), &v)
		if err := api.Validate(api.ResponseSchema(op, 200), v); err != nil {
			t.Errorf("%s does not conform: %v: %s", path, err, body)
		}
	}
	if code, body := w.adminCall("GET", "/sync/v1/series-register", owner, "", nil); code != 200 || !strings.Contains(body, `"series_code"`) {
		t.Fatalf("register: %d %s", code, body)
	}
	_ = foreign
}

// Security conditions on manager decisions: no self-decision, a confirmation is bound to the hash of the held
// op and tells the owner, and money or bill-number holds need the approval a binding under caution needs.
func TestHoldDecisionConditions(t *testing.T) {
	w, _ := newTestWorld(t, 66, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	foreign := w.billAs(t, a, b.SaleCode(), "tax_invoice") // actor m1, foreign series: a bill-number hold
	w.toCloud(t, a)
	ref := refOf(foreign)
	self := w.mint(authtest.Spec{Type: auth.TypeUser, Subject: pCashier, Grants: authtest.OwnerGrants()})
	if code, body := w.adminCall("POST", "/sync/v1/quarantine/release", self, "", decision{ref, "mine", ""}); code != 403 || !strings.Contains(body, "sync.self_decision") {
		t.Fatalf("releasing a hold on your own op: %d %s", code, body)
	}
	if code, _ := w.adminCall("POST", "/sync/v1/quarantine/discard", self, "", decision{ref, "mine", ""}); code != 403 {
		t.Fatalf("discarding a hold on your own op: %d", code)
	}
	caution := w.mint(authtest.Spec{Type: auth.TypeUser, Subject: "owner-1", Grants: authtest.OwnerGrants(), CautionUntil: w.Clock.Now().Add(time.Hour)})
	if code, body := w.adminCall("POST", "/sync/v1/quarantine/release", caution, "", decision{ref, "checked", ""}); code != 403 || !strings.Contains(body, "approval_required") {
		t.Fatalf("a bill-number hold released from a device under caution: %d %s", code, body)
	}
	svc := w.serviceToken(t)
	act := w.mint(authtest.Spec{Type: auth.TypeSupport, Mode: auth.ModeAct, Grants: authtest.Grants(nil, pConfirm)})
	for _, h := range []string{"", strings.Repeat("0", 64)} {
		if code, body := w.adminCall("POST", "/sync/v1/quarantine/confirm", act, svc, decision{ref, "cause found", h}); code != 422 || !strings.Contains(body, "sync.confirm_hash_required") {
			t.Fatalf("confirmation with hash %q: %d %s", h, code, body)
		}
	}
	if code, body := w.adminCall("POST", "/sync/v1/quarantine/confirm", act, svc, decision{ref, "cause found", foreign.H}); code != 200 {
		t.Fatalf("confirmation bound to the held op's hash: %d %s", code, body)
	}
	alerts := must(w.GW.Alerts(bg, w.Tenant))
	told := false
	for _, al := range alerts {
		told = told || (al.Kind == "vendor_confirmed_hold" && al.Audience == "owner")
	}
	if !told {
		t.Fatalf("the owner must be told of the vendor confirmation: %+v", alerts)
	}
	owner := w.mint(authtest.Spec{Type: auth.TypeUser, Subject: "owner-2", Grants: authtest.OwnerGrants()})
	if code, body := w.adminCall("POST", "/sync/v1/quarantine/release", owner, "", decision{ref, "approved", ""}); code != 200 {
		t.Fatalf("release by another member: %d %s", code, body)
	}
	released := false
	for _, al := range must(w.GW.Alerts(bg, w.Tenant)) {
		released = released || (al.Kind == "hold_released" && al.Audience == "owner")
	}
	if !released {
		t.Fatal("the owner must be told of a release")
	}
}

// A revoked device that is drained is reported to identity with the highest sequence the gateway stores per
// stream of its own ops; a device that is not revoked is not reported; nothing reports on its own.
func TestReportDrainedSendsTheStoredSequencesOfARevokedDevice(t *testing.T) {
	w, _ := newTestWorld(t, 71, WorldOptions{Pos: 1, NoHub: true})
	a := w.Devices[0]
	it := must(a.OrderOp(NewRand(5)))
	w.toCloud(t, a)
	if err := w.GW.ReportDrained(bg, w.Tenant, a.ID); err != service.ErrNotFound {
		t.Fatalf("a device that is not revoked is not drained: %v", err)
	}
	w.Identity.Revoke(a.ID, "stolen")
	if _, ok := w.Identity.Drained(a.ID); ok {
		t.Fatal("the gateway must not report a drain on its own")
	}
	if err := w.GW.ReportDrained(bg, w.Tenant, a.ID); err != nil {
		t.Fatal(err)
	}
	got, ok := w.Identity.Drained(a.ID)
	vec := must(w.GW.EngineFor(w.Tenant).Vector(bg))
	if !ok || got[it.Stream] != vec[sp.VKey(a.ID, it.Stream)] || got[it.Stream] < it.Seq {
		t.Fatalf("reported %v, stored %v", got, vec)
	}
}
