package sim

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/identitystub"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// recordBills makes the device record n bills (with a few orders first) without syncing.
func recordBills(t *testing.T, d *Device, rng *Rand, n int) {
	t.Helper()
	for i := 0; i < 3; i++ {
		must(d.OrderOp(rng))
	}
	for i := 0; i < n; i++ {
		must(d.BillOp(rng))
	}
}

func (w *World) uploadAll(t *testing.T, d *Device, rc *Recovery) {
	t.Helper()
	for i := 0; i < 30; i++ {
		if done := must(w.UploadRecovery(bg, d, rc)); done {
			return
		}
	}
	t.Fatal("recovery upload did not drain")
}

func (w *World) heldByReason(t *testing.T, origin string) map[string]int {
	t.Helper()
	out := map[string]int{}
	cloud := must(readAll(bg, w.GWStore, w.Tenant))
	for _, r := range cloud {
		if r.Origin == origin && r.Status != repository.StAccepted {
			out[r.Status+"/"+r.Reason]++
		}
	}
	return out
}

func TestKL1_FortyUnsyncedBillsTwentyFiveSealedFifteenNotAreRecovered(t *testing.T) {
	w, rng := newTestWorld(t, 31, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	old, oldSale := a.ID, a.SaleCode()
	for i := 0; i < 3; i++ {
		must(a.OrderOp(rng))
	}
	for i := 0; i < 25; i++ {
		must(a.BillOp(rng))
	}
	must0(a.Eng.StoreSeals(bg)) // a seal made while the key existed
	for i := 0; i < 15; i++ {
		must(a.BillOp(rng))
	}
	a.LoseKey()
	if _, err := a.BillOp(rng); err == nil {
		t.Fatal("a key-lost device records nothing")
	}
	rc := must(w.RecoverDevice(a, true))
	if a.ID == old || a.SaleCode() == oldSale {
		t.Fatal("new device id and new series codes expected")
	}
	w.uploadAll(t, a, rc)
	got := w.heldByReason(t, old)
	if got["quarantined/revoked"] == 0 || got["quarantined/unsealed_tail"] == 0 {
		t.Fatalf("sealed ops must be held as revoked and the tail as unsealed: %v", got)
	}
	cs, _, _ := w.CloudState(bg)
	if len(cs.IDs("bill")) != 0 {
		t.Fatal("nothing is applied before release")
	}
	rep := must(w.GW.Register(bg, w.Tenant))
	n := 0
	var sealedBills, tailBills int
	for _, e := range rep.Entries {
		if e.Code == oldSale {
			n++
			if e.Mark == "recovered_unsealed" {
				tailBills++
			} else if e.Mark == "recovered_sealed" {
				sealedBills++
			}
		}
	}
	if n != 40 || sealedBills != 25 || tailBills != 15 {
		t.Fatalf("register: %d numbers, %d sealed, %d unsealed (want 40/25/15)", n, sealedBills, tailBills)
	}
	// Owner reviews: sealed ones as ADR-0005 says, the tail with device.recover.
	for _, q := range must(w.GW.Quarantine(bg, w.Tenant)) {
		if q.Reason == service.ReasonUnsealedTail {
			if _, err := w.GW.Release(bg, w.Tenant, q.Ref, service.ReleaseOpts{}); !errors.Is(err, service.ErrNeedsRecoverPerm) {
				t.Fatalf("tail release without device.recover must be refused: %v", err)
			}
		}
		must(w.GW.Release(bg, w.Tenant, q.Ref, service.ReleaseOpts{DeviceRecover: true}))
	}
	unsealedMarked := 0
	for _, r := range must(readAll(bg, w.GWStore, w.Tenant)) {
		if r.Origin == old && hasMark(r, service.MarkUnsealed) {
			unsealedMarked++
		}
	}
	if unsealedMarked == 0 {
		t.Fatal("released tail ops stay marked unsealed")
	}
	if rep := must(w.GW.Register(bg, w.Tenant)); len(rep.Gaps) != 0 {
		t.Fatalf("old series must be gapless: %+v", rep.Gaps)
	}
	if si, _ := w.Identity.Series(w.Tenant, oldSale); si.State != "closed" {
		t.Fatal("old series is closed")
	}
	it := must(a.BillOp(rng)) // billing reopened under the new origin at once
	if it.Seq != 1 && it.Stream != "outlet:"+w.Outlet {
		t.Fatal("new origin starts at seq 1")
	}
	_ = b
	if r := w.Quiesce(bg, 40); !r.Converged {
		t.Fatal("no quiescence")
	}
	for _, p := range w.CheckAll(bg, nil) {
		t.Error(p)
	}
}

func TestKL2toKL3_RecoveryUploadIsRefusedWithoutARecordAndNeverTakenByTheHub(t *testing.T) {
	w, rng := newTestWorld(t, 32, WorldOptions{Pos: 3})
	a, b, c := w.Devices[0], w.Devices[1], w.Devices[2]
	recordBills(t, a, rng, 5)
	old := a.ID
	a.LoseKey()
	// No recovery record at all.
	tok := b.DrainToken("recovers:" + old)
	_, err := w.CloudTransportToken("dev-cloud:"+b.ID, w.Token("drain", b.ID, "recovers:"+old)).QuarantineUpload(bg, sp.PushRequest{})
	_ = tok
	if !engine.IsStatus(err, 403) {
		t.Fatalf("no recovery record: want 403, got %v", err)
	}
	rc := must(w.RecoverDevice(a, true))
	// A record for another device: c holds a token for old but the record names a's new id.
	_, err = w.CloudTransportToken("dev-cloud:"+c.ID, c.DrainToken(old)).QuarantineUpload(bg, sp.PushRequest{})
	if !engine.IsStatus(err, 403) {
		t.Fatalf("record for another device: want 403, got %v", err)
	}
	// An ordinary access token through /push, carrying the old origin's ops, stores nothing.
	req := must(a.Eng.RecoveryUpload(bg, old, sp.Vector{}, 500, func(s string, q int64, h string) (sp.Attestation, error) {
		return sp.MakeAttestation(a.Key, sp.Attestation{Origin: old, Stream: s, Seq: q, H: h, By: a.ID, Rec: rc.RecID})
	}))
	resp := must(w.CloudTransport("dev-cloud:"+a.ID, a.ID).Push(bg, req))
	if len(resp.Refused) == 0 {
		t.Fatal("old-origin ops through /push must be refused")
	}
	if n := len(w.heldByReason(t, old)); n != 0 {
		t.Fatalf("nothing may be stored: %v", w.heldByReason(t, old))
	}
	// The recovery drain token is refused at every other endpoint.
	_, err = w.CloudTransportToken("dev-cloud:"+a.ID, a.DrainToken(old)).Hello(bg, sp.HelloRequest{Protocol: 1})
	if !engine.IsStatus(err, 401) {
		t.Fatalf("drain token at hello: want 401, got %v", err)
	}
	// KL3: the hub takes neither the upload nor an unsealed op.
	_, err = a.HubC.T.(*engine.HTTPTransport).QuarantineUpload(bg, req)
	if !engine.IsStatus(err, 404) {
		t.Fatalf("hub quarantine-upload: want 404, got %v", err)
	}
	hr := must(a.HubC.T.Push(bg, sp.PushRequest{Items: req.Items}))
	if len(hr.Refused) == 0 {
		t.Fatal("hub must refuse unsealed ops")
	}
	if v := must(w.Hub.Engine().Vector(bg)); v[sp.VKey(old, "outlet:"+w.Outlet)] != 0 {
		t.Fatal("hub stored an unsealed op")
	}
}

func TestKL4toKL6_ChainBreakForkAndSecondAttestation(t *testing.T) {
	w, rng := newTestWorld(t, 33, WorldOptions{Pos: 2})
	a := w.Devices[0]
	recordBills(t, a, rng, 6)
	old := a.ID
	stream := "outlet:" + w.Outlet
	// The cloud already holds the first 4 ops of a (sealed, normal sync).
	must0(a.Eng.StoreSeals(bg))
	req := must(a.Eng.Outbound(bg, sp.Vector{}, engine.OutboundOpts{Limit: 4}))
	must(w.CloudTransport("dev-cloud:"+old, old).Push(bg, req))
	for i := 0; i < 3; i++ {
		must(a.BillOp(rng))
	}
	a.LoseKey()
	rc := must(w.RecoverDevice(a, true))
	att := func(s string, q int64, h string) (sp.Attestation, error) {
		return sp.MakeAttestation(a.Key, sp.Attestation{Origin: old, Stream: s, Seq: q, H: h, By: a.ID, Rec: rc.RecID})
	}
	up := must(a.Eng.RecoveryUpload(bg, old, must(w.CloudTransport("dev-cloud:"+a.ID, a.ID).Hello(bg, sp.HelloRequest{Protocol: 1})).Vector, 500, att))
	if len(up.Items) < 2 {
		t.Fatal("need a tail")
	}
	// KL4a: the first op does not chain to the cloud's last op.
	bad := up
	bad.Items = append([]sp.Item(nil), up.Items...)
	b0 := must(sp.DecodeBody(bad.Items[0].Body))
	b0.PH = sp.Hash("not the head")
	bad.Items[0] = must(sp.NewItem(b0, nil))
	r := must(w.CloudTransportToken("dev-cloud:"+a.ID, a.DrainToken(old)).QuarantineUpload(bg, bad))
	_ = r // held slots count as held: the gateway reports drained once everything up to the attested seq is stored
	got := w.heldByReason(t, old)
	if got["quarantined/chain_broken"] == 0 || got["quarantined/unsealed_tail"] != 0 {
		t.Fatalf("chain break must be chain_broken, never unsealed_tail: %v", got)
	}
	var vendor bool
	for _, al := range must(w.GW.Alerts(bg, w.Tenant)) {
		vendor = vendor || (al.Audience == "vendor" && al.Kind == "chain_broken")
	}
	if !vendor {
		t.Fatal("vendor alert expected")
	}
	// KL4b: an op that differs from one the cloud holds is kept as fork evidence.
	fk := sp.PushRequest{Items: []sp.Item{must(sp.NewItem(sp.Body{Origin: old, Stream: stream, Seq: 2, PH: sp.Hash("x"), HLC: "0000000000000001", Clk: "sync", TenantID: w.Tenant, Intent: "stock.move", At: "2026-11-24T00:00:00.000Z"}, nil))}}
	fr := must(w.CloudTransportToken("dev-cloud:"+a.ID, a.DrainToken(old)).QuarantineUpload(bg, fk))
	if len(fr.Refused) == 0 || fr.Refused[0].Reason != sp.ReasonFork {
		t.Fatalf("fork expected: %+v", fr.Refused)
	}
	if len(must(w.heldForks())) == 0 {
		t.Fatal("fork evidence kept")
	}
	// KL6: second attestation with different content is refused; a second recovery too.
	other := must(sp.MakeAttestation(a.Key, sp.Attestation{Origin: old, Stream: stream, Seq: up.Attestations[0].Seq, H: sp.Hash("different"), By: a.ID, Rec: rc.RecID}))
	ok := must(w.CloudTransportToken("dev-cloud:"+a.ID, a.DrainToken(old)).QuarantineUpload(bg, sp.PushRequest{Attestations: []sp.Attestation{up.Attestations[0]}}))
	_ = ok
	r2 := must(w.CloudTransportToken("dev-cloud:"+a.ID, a.DrainToken(old)).QuarantineUpload(bg, sp.PushRequest{Attestations: []sp.Attestation{other}}))
	if len(r2.Refused) == 0 {
		t.Fatal("a second attestation with different content must be refused")
	}
	if _, err := w.Identity.CreateRecovery(w.Tenant, old, true); err == nil {
		t.Fatal("a device is recovered once")
	}
}

func (w *World) heldForks() ([]string, error) {
	var f []string
	err := w.GWStore.InTx(bg, w.Tenant, func(tx repository.Tx) error {
		var err error
		f, err = tx.Forks()
		return err
	})
	return f, err
}

func TestKL6_UsedExpiredAndForeignCodesAreRefused(t *testing.T) {
	w, _ := newTestWorld(t, 34, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	code := must(w.Identity.CreateRecovery(w.Tenant, a.ID, true))
	if _, err := w.ActivateRecovery(b, code); err == nil {
		t.Fatal("a code for another device must be refused")
	}
	if _, err := w.Identity.CreateRecovery(w.Tenant, b.ID, false); err == nil {
		t.Fatal("only an owner creates a recovery code")
	}
	w.Advance(11 * time.Minute)
	if _, err := w.ActivateRecovery(a, code); err == nil {
		t.Fatal("an expired code must be refused")
	}
	code2 := must(w.Identity.CreateRecovery(w.Tenant, a.ID, true))
	must(w.ActivateRecovery(a, code2))
	if _, _, err := w.Identity.ActivateRecovery(code2, "again", a.Key); err == nil {
		t.Fatal("a used code must be refused")
	}
}

func TestKL5_OldKeyHolderIsRefusedAndItsDrainBecomesAForkNeitherSideReleasable(t *testing.T) {
	w, rng := newTestWorld(t, 35, WorldOptions{Pos: 2})
	a := w.Devices[0]
	old, oldKey := a.ID, a.Key
	recordBills(t, a, rng, 4)
	a.LoseKey()
	rc := must(w.RecoverDevice(a, true))
	w.uploadAll(t, a, rc)
	// The old key holder: normal sync refused.
	_, err := w.CloudTransportToken("dev-cloud:"+old, w.Token("device", old, "")).Hello(bg, sp.HelloRequest{Protocol: 1})
	if !engine.IsStatus(err, 401) {
		t.Fatalf("revoked device sync: want 401, got %v", err)
	}
	// It drains different content for the same slots, signed with the old key.
	st := must(repository.Open("file:" + t.TempDir() + "/clone.db"))
	defer st.Close()
	clone := engine.New(engine.Config{Role: engine.RoleDevice, Tenant: w.Tenant, Outlet: w.Outlet, Origin: old, Key: oldKey, Store: st, Trust: a.Cache,
		Clock: sp.NewClock(w.Clock.Now), Series: seriesSrc{&Device{saleCode: "AAA"}}})
	for i := 0; i < 4; i++ {
		must(clone.Record(bg, engine.Input{Stream: "outlet:" + w.Outlet, Intent: "stock.move", Actor: pCashier, PackV: "v1",
			Muts: []sp.Mut{{E: "stock_level", ID: "forked", K: sp.KDelta, F: map[string]any{"qty_milli": int64(i + 1)}}}}))
	}
	req := must(clone.Outbound(bg, sp.Vector{}, engine.OutboundOpts{}))
	resp := must(w.UploadRevokedDrain(bg, a, old, oldKey, req))
	if len(resp.Refused) == 0 {
		t.Fatal("differing slots must be refused as fork")
	}
	if len(must(w.heldForks())) == 0 {
		t.Fatal("fork evidence must be kept")
	}
	for _, q := range must(w.GW.Quarantine(bg, w.Tenant)) {
		if q.Reason == service.ReasonFork {
			if _, err := w.GW.Release(bg, w.Tenant, q.Ref, service.ReleaseOpts{DeviceRecover: true}); !errors.Is(err, service.ErrNeedsVendor) {
				t.Fatalf("a fork cannot be released by the owner alone: %v", err)
			}
			return
		}
	}
	t.Fatal("no slot was marked fork")
}

func TestKL7_UploadCutMidRequestResumesExactlyOnce(t *testing.T) {
	w, rng := newTestWorld(t, 36, WorldOptions{Pos: 2})
	a := w.Devices[0]
	recordBills(t, a, rng, 30)
	old := a.ID
	a.LoseKey()
	rc := must(w.RecoverDevice(a, true))
	cloud := w.CloudTransport("dev-cloud:"+a.ID, a.ID)
	att := func(s string, q int64, h string) (sp.Attestation, error) {
		return sp.MakeAttestation(a.Key, sp.Attestation{Origin: old, Stream: s, Seq: q, H: h, By: a.ID, Rec: rc.RecID})
	}
	up := w.CloudTransportToken("dev-cloud:"+a.ID, a.DrainToken(old))
	drained := false
	for round := 0; round < 40 && !drained; round++ {
		hv := must(cloud.Hello(bg, sp.HelloRequest{Protocol: 1}))
		req := must(a.Eng.RecoveryUpload(bg, old, hv.Vector, 10, att))
		if round == 1 { // the server processes the batch, the client never hears, and the process is killed
			w.Net.Faults("dev-cloud:"+a.ID, 0, 1, 0, 0)
			if _, err := up.QuarantineUpload(bg, req); err == nil {
				t.Fatal("lost ack expected")
			}
			w.Net.Faults("dev-cloud:"+a.ID, 0, 0, 0, 0)
			must0(a.Crash())
			continue
		}
		resp := must(up.QuarantineUpload(bg, req))
		if resp.Drained {
			drained = true
		}
	}
	if !drained {
		t.Fatal("never drained")
	}
	cloudOps := must(readAll(bg, w.GWStore, w.Tenant))
	var n int64
	for _, r := range cloudOps {
		if r.Origin == old {
			n++
		}
	}
	hv := must(w.GW.EngineFor(w.Tenant).Vector(bg))
	var head int64
	for k, v := range hv {
		if o, _, _ := sp.SplitVKey(k); o == old {
			head += v
		}
	}
	if n != head {
		t.Fatalf("exactly once: %d slots, heads sum %d", n, head)
	}
}

func TestKL8_CloudRolledBackBeforeTheUploadTheAdoptingDeviceReoffersTheTail(t *testing.T) {
	w, rng := newTestWorld(t, 37, WorldOptions{Pos: 2})
	a := w.Devices[0]
	recordBills(t, a, rng, 12)
	old := a.ID
	a.LoseKey()
	rc := must(w.RecoverDevice(a, true))
	must0(w.SnapshotCloud("pre"))
	w.uploadAll(t, a, rc)
	before := w.heldByReason(t, old)
	must0(w.RestoreCloud("pre", "restore-1"))
	if len(w.heldByReason(t, old)) != 0 {
		t.Fatal("rollback must lose the upload")
	}
	must0(a.Sync(bg)) // device sync repeats the recovery upload
	after := w.heldByReason(t, old)
	if len(after) != len(before) {
		t.Fatalf("tail back in quarantine: before %v after %v", before, after)
	}
	if rev, why := w.Identity.Revoked(w.Tenant, old); !rev || why != "key_lost" {
		t.Fatal("old device stays revoked")
	}
	if rep := must(w.GW.Register(bg, w.Tenant)); len(rep.Gaps) != 0 {
		t.Fatalf("no register gap: %+v", rep.Gaps)
	}
}

func TestKL9_UnsealedOpsKeepTheirAttributionAndTheUnsealedMark(t *testing.T) {
	w, _ := newTestWorld(t, 38, WorldOptions{Pos: 2})
	a := w.Devices[0]
	old := a.ID
	good := stockOp(t, a, w.Identity.MintProof(a.ID, pCashier))
	bad := stockOp(t, a, "bogus-proof")
	a.LoseKey()
	rc := must(w.RecoverDevice(a, true))
	w.uploadAll(t, a, rc)
	for _, q := range must(w.GW.Quarantine(bg, w.Tenant)) {
		must(w.GW.Release(bg, w.Tenant, q.Ref, service.ReleaseOpts{DeviceRecover: true}))
	}
	g, b := w.rec(t, good), w.rec(t, bad)
	if g.Origin != old || g.Status != repository.StAccepted || b.Status != repository.StFlagged || !hasMark(b, service.MarkAttributionUnverified) {
		t.Fatalf("good %s/%s bad %s/%s", g.Status, g.Marks, b.Status, b.Marks)
	}
	if !hasMark(g, service.MarkUnsealed) || !hasMark(b, service.MarkUnsealed) {
		t.Fatal("both stay marked unsealed")
	}
}

func TestKL10_AnIsolatedDeviceLosesAtMostTheSealIntervalAndRecordsNothingAfterKeyLoss(t *testing.T) {
	w, rng := newTestWorld(t, 39, WorldOptions{Pos: 2})
	a := w.Devices[0]
	old := a.ID
	for i := 0; i < 24; i++ { // two hours, one op every five minutes, seal tick before each op
		w.Advance(5*time.Minute + time.Second)
		a.SealTick()
		must(a.StockOp(rng))
	}
	recorded := len(a.Recorded)
	a.LoseKey()
	for i := 0; i < 5; i++ {
		if _, err := a.StockOp(rng); err == nil {
			t.Fatal("nothing may be recorded in the key-lost state")
		}
	}
	if len(a.Recorded) != recorded {
		t.Fatal("recorded count changed")
	}
	rc := must(w.RecoverDevice(a, true))
	w.uploadAll(t, a, rc)
	if n := w.heldByReason(t, old)["quarantined/unsealed_tail"]; n > 2 {
		t.Fatalf("unsealed tail %d ops, want at most one seal interval's worth", n)
	}
}

func TestKL11_AConfigChangeInTheUnsealedTailIsVoidedOnTheAdoptingDeviceAndReachesNoOneElse(t *testing.T) {
	w, rng := newTestWorld(t, 40, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	oldSale := a.SaleCode()
	must(a.OrderOp(rng))
	must0(a.Eng.StoreSeals(bg))
	price := must(a.PriceOp(rng)) // after the last seal
	var item string
	for _, m := range must(sp.DecodeBody(price.Body)).Muts {
		item = m.ID
	}
	if _, ok := a.rowOf("menu_item", item); !ok {
		t.Fatal("the device applied its own price change locally")
	}
	a.LoseKey()
	rc := must(w.RecoverDevice(a, true))
	w.uploadAll(t, a, rc)
	if r := w.rec(t, price); r.Status != repository.StVoided {
		t.Fatalf("config in the unsealed tail must be voided: %s/%s", r.Status, r.Reason)
	}
	must0(a.SyncCloud(bg))
	if _, ok := a.rowOf("menu_item", item); ok {
		t.Fatal("voided on the adopting device")
	}
	must0(b.SyncCloud(bg))
	if _, ok := b.rowOf("menu_item", item); ok {
		t.Fatal("the change must reach no other node")
	}
	bill := must(a.BillOp(rng))
	body := must(sp.DecodeBody(bill.Body))
	if strings.HasPrefix(body.Doc.Number, oldSale+"/") {
		t.Fatal("the adopting device must never number in the old series")
	}
	w.toCloud(t, a)
	if r := w.rec(t, bill); r.Status != repository.StAccepted {
		t.Fatalf("new bill: %s/%s", r.Status, r.Reason)
	}
}

func TestRestore_NewEpochNoIdentityReuseAndLostWindowOpsComeBack(t *testing.T) {
	w, rng := newTestWorld(t, 41, WorldOptions{Pos: 2, Waiters: 1, KDS: 1})
	a := w.Devices[0]
	for i := 0; i < 5; i++ {
		must(a.OrderOp(rng))
	}
	must(a.BillOp(rng))
	w.Quiesce(bg, 20)
	must0(w.SnapshotCloud("t"))
	// After T: more ops, a cloud emit that devices pull, a device added (activation).
	for i := 0; i < 5; i++ {
		must(a.OrderOp(rng))
	}
	must(a.BillOp(rng))
	em := must(w.GW.Emit(bg, w.Tenant, "brand:"+w.Brand, "cloud.emit",
		[]sp.Mut{{E: "menu_item", ID: "menu-cloud", K: sp.KInsert, F: map[string]any{"name": "cloud item", "price_paise": int64(500)}}}))
	w.Quiesce(bg, 20)
	late := must(w.AddDevice("dev-late", sp.KindPOS))
	must(late.OrderOp(rng))
	w.Quiesce(bg, 20)
	must0(w.RestoreCloud("t", "restore-1"))
	if w.GW.Epoch() != "restore-1" {
		t.Fatal("epoch")
	}
	if rep := w.Quiesce(bg, 60); !rep.Converged {
		t.Fatal("no quiescence after restore")
	}
	if r := w.rec(t, em); r.Status != repository.StAccepted {
		t.Fatal("the cloud op from the lost window is back")
	}
	em2 := must(w.GW.Emit(bg, w.Tenant, "brand:"+w.Brand, "cloud.emit",
		[]sp.Mut{{E: "menu_item", ID: "menu-cloud2", K: sp.KInsert, F: map[string]any{"name": "after", "price_paise": int64(600)}}}))
	if em2.Origin != engine.CloudOriginPrefix+"restore-1" || em2.Seq != 1 {
		t.Fatalf("new cloud origin per epoch starting at 1, got %s/%d", em2.Origin, em2.Seq)
	}
	w.Quiesce(bg, 40)
	for _, p := range w.CheckAll(bg, nil) {
		t.Error(p)
	}
}

// A1.3 (security ruling 2 (a)): only an active device can be recovered. A device revoked for any
// reason cannot get a recovery code, and a code issued before a revocation is dead.
func TestKL_RevokedDeviceCannotBeRecovered(t *testing.T) {
	w, _ := newTestWorld(t, 44, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	w.Identity.Revoke(a.ID, "stolen")
	if _, err := w.Identity.CreateRecovery(w.Tenant, a.ID, true); !errors.Is(err, identitystub.ErrRecoveryRevoked) {
		t.Fatalf("a revoked device must not get a recovery code, got %v", err)
	}
	code := must(w.Identity.CreateRecovery(w.Tenant, b.ID, true))
	w.Identity.Revoke(b.ID, "stolen") // revoked after the code was issued
	kp := must(sp.NewKeyPair("k-new", nil))
	if _, _, err := w.Identity.ActivateRecovery(code, "dev-new", kp); !errors.Is(err, identitystub.ErrRecoveryRevoked) {
		t.Fatalf("a code for a since-revoked device must be refused, got %v", err)
	}
}
