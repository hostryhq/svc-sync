package sim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// stockOp records a trading op with an explicit proof, as a member of the cashier role.
func stockOp(t *testing.T, d *Device, proof string) sp.Item {
	t.Helper()
	sid := must(d.session(pCashier))
	return must(d.record(engine.Input{Stream: "outlet:" + d.W.Outlet, Intent: "stock.move", Actor: pCashier, SID: sid, Proof: proof,
		Muts: []sp.Mut{{E: "stock_level", ID: "item-1", K: sp.KDelta, F: map[string]any{"qty_milli": int64(1000)}}}}, true))
}

// pushAndPull does the two calls a device makes against the cloud and returns the raw JSON of
// both responses, with the device id masked.
func pushAndPull(t *testing.T, d *Device) (string, string) {
	t.Helper()
	tr := d.W.CloudTransport("dev-cloud:"+d.ID, d.ID)
	req := must(d.Eng.Outbound(bg, sp.Vector{}, engine.OutboundOpts{}))
	pr := must(tr.Push(bg, req))
	vec := must(d.Eng.Vector(bg))
	pl := must(tr.Pull(bg, sp.PullRequest{Vector: vec}))
	a, _ := json.Marshal(pr)
	b, _ := json.Marshal(pl)
	return strings.ReplaceAll(string(a), d.ID, "DEV"), strings.ReplaceAll(string(b), d.ID, "DEV")
}

func TestRB1_AValidAndAnInvalidProofGiveTheDeviceIdenticalAnswers(t *testing.T) {
	good, _ := newTestWorld(t, 21, WorldOptions{Pos: 1})
	badW, _ := newTestWorld(t, 21, WorldOptions{Pos: 1})
	stockOp(t, good.Devices[0], good.Identity.MintProof(good.Devices[0].ID, pCashier))
	stockOp(t, badW.Devices[0], "bogus-proof")
	gp, gl := pushAndPull(t, good.Devices[0])
	bp, bl := pushAndPull(t, badW.Devices[0])
	if gp != bp || gl != bl {
		t.Fatalf("answers differ:\npush  %s\n      %s\npull  %s\n      %s", gp, bp, gl, bl)
	}
	for _, s := range []string{"attribution", "flag", "unverified", "proof"} {
		if strings.Contains(gp+bp+gl+bl, s) {
			t.Fatalf("a response mentions %q", s)
		}
	}
	// The flag exists in the cloud and is readable only with a member token.
	ex := must(badW.GW.Exceptions(bg, badW.Tenant))
	if len(ex) != 1 || ex[0].Marks[0] != service.MarkAttributionUnverified {
		t.Fatalf("exceptions: %+v", ex)
	}
	get := func(w *World, tok string) int {
		req := httptest.NewRequest(http.MethodGet, "/sync/v1/exceptions", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		w.CloudH.ServeHTTP(rec, req)
		return rec.Code
	}
	dev := badW.Token(auth.TypeDevice, badW.Devices[0].ID, "")
	if c := get(badW, dev); c != http.StatusUnauthorized {
		t.Fatalf("a device token must not reach the exceptions report, got %d", c)
	}
	cashier := badW.Issuer.Mint(authtest.Spec{Type: auth.TypePin, Tenant: ids.ID(badW.Tenant), Device: badW.Devices[0].ID, Grants: authtest.Grants(nil, "order.create")})
	if c := get(badW, cashier); c != http.StatusUnauthorized {
		t.Fatalf("a cashier pin session must not reach the exceptions report, got %d", c)
	}
	owner := badW.Issuer.Mint(authtest.Spec{Type: auth.TypeUser, Tenant: ids.ID(badW.Tenant), Grants: authtest.OwnerGrants()})
	if c := get(badW, owner); c != http.StatusOK {
		t.Fatalf("owner must read the exceptions report, got %d", c)
	}
}

func TestRB2_HeldCodesReachTheOriginDirectlyAndThroughTheHub(t *testing.T) {
	w, _ := newTestWorld(t, 22, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	// Direct push: foreign series -> held_support.
	it := w.billAs(t, a, b.SaleCode(), "tax_invoice")
	req := must(a.Eng.Outbound(bg, sp.Vector{}, engine.OutboundOpts{}))
	resp := must(w.CloudTransport("dev-cloud:"+a.ID, a.ID).Push(bg, req))
	if len(resp.Held) != 1 || resp.Held[0].Code != sp.HoldSupport || resp.Held[0].Seq != it.Seq {
		t.Fatalf("direct push response: %+v", resp.Held)
	}
	// Relayed by the hub: a clock-review hold -> held_manager, learned at the next pull from the hub.
	b.Skew = 3 * time.Hour
	pi := must(b.PriceOp(NewRand(1)))
	b.Skew = 0
	must0(b.SyncHub(bg))
	_, _ = w.Hub.SyncUpstream(bg)
	must0(b.SyncHub(bg))
	var got []sp.HeldSlot
	for _, h := range b.HubC.OwnHeld {
		got = append(got, h)
	}
	if len(got) != 1 || got[0].Seq != pi.Seq || got[0].Code != sp.HoldManager {
		t.Fatalf("own_held through the hub: %+v", got)
	}
	for _, h := range got {
		if h.Code != sp.HoldPending && h.Code != sp.HoldManager && h.Code != sp.HoldSupport {
			t.Fatalf("code %q is not one of the three", h.Code)
		}
	}
}

func TestRB3_ReleaseClearsTheMarkAndAPeerHoldingThePlaceholderConverges(t *testing.T) {
	w, _ := newTestWorld(t, 23, WorldOptions{Pos: 3})
	a, b := w.Devices[0], w.Devices[1]
	w.Net.SetDown("dev-hub:"+b.ID, true) // b can reach only the cloud
	a.Skew = 3 * time.Hour
	it := must(a.PriceOp(NewRand(2)))
	a.Skew = 0
	must0(a.SyncHub(bg))
	_, _ = w.Hub.SyncUpstream(bg)
	w.toCloud(t, b) // b receives a placeholder for the held slot
	if b.Eng.StateHash() == a.Eng.StateHash() {
		t.Fatal("test needs b to lack the held op")
	}
	w.toCloud(t, a)
	if len(a.CloudC.OwnHeld) != 1 {
		t.Fatalf("a must see one slot needing attention, has %d", len(a.CloudC.OwnHeld))
	}
	ref := sp.Ref{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq}
	st := must(w.GW.Release(bg, w.Tenant, ref, service.ReleaseOpts{}))
	if st != repository.StAccepted && st != repository.StFlagged {
		t.Fatalf("released into %q", st)
	}
	w.toCloud(t, b) // b names the placeholder in its pull, receives the op, checks it against h
	w.toCloud(t, a)
	if len(a.CloudC.OwnHeld) != 0 {
		t.Fatal("a release must leave the origin's own_held")
	}
	if rep := w.Quiesce(bg, 30); !rep.Converged {
		t.Fatal("no quiescence")
	}
	for _, p := range w.CheckAll(bg, nil) {
		t.Error(p)
	}
}

func (d *Device) rowOf(entity, id string) (map[string]any, bool) {
	var r map[string]any
	var ok bool
	d.Eng.WithState(func(s *engine.State) { r, ok = s.Row(entity, id) })
	return r, ok
}

func TestRB4_ThreeKindsOfRefusedConfigurationLookTheSameToTheDevice(t *testing.T) {
	w, _ := newTestWorld(t, 24, WorldOptions{Pos: 1})
	a := w.Devices[0]
	price := func(actor, proof string) sp.Item {
		sid := must(a.session(actor))
		return must(a.record(engine.Input{Stream: "brand:" + w.Brand, Intent: "menu.price.set", Actor: actor, SID: sid, Proof: proof,
			Muts: []sp.Mut{{E: "menu_item", ID: "menu-1", K: sp.KSet, F: map[string]any{"price_paise": int64(500)}, Prev: map[string]string{"price_paise": engine.ZeroStamp}}}}, true))
	}
	failedProof := price(pManager, "bogus-proof")
	missingPerm := price(pCashier, w.Identity.MintProof(a.ID, pCashier)) // the cashier role has no menu.edit
	w.Identity.RemoveMember(w.Tenant, pManager)
	removed := price(pManager, w.Identity.MintProof(a.ID, pManager))
	w.toCloud(t, a)
	reasons := map[string]string{}
	for _, it := range []sp.Item{failedProof, missingPerm, removed} {
		if r := w.rec(t, it); r.Status != repository.StVoided {
			t.Fatalf("%d: want voided, got %s/%s", it.Seq, r.Status, r.Reason)
		}
	}
	// What the device sees: a sync.void op naming each refused op, with the single reason "refused".
	pr := must(w.GW.Pull(bg, w.Tenant, engine.Caller{ID: a.ID, Kind: sp.KindPOS, Outlet: w.Outlet, Brand: w.Brand}, sp.PullRequest{Vector: sp.Vector{}}))
	for _, item := range pr.Items {
		if strings.HasPrefix(item.Origin, engine.CloudOriginPrefix) && !item.IsPlaceholder() {
			b := must(sp.DecodeBody(item.Body))
			if b.Intent == sp.IntentVoid {
				for _, m := range b.Muts {
					reasons[fmt.Sprint(m.F["seq"])] = fmt.Sprint(m.F["reason"])
				}
			}
		}
	}
	if len(reasons) != 3 {
		t.Fatalf("want 3 voids, got %v", reasons)
	}
	for k, v := range reasons {
		if v != sp.VoidReasonCloud {
			t.Errorf("slot %s: reason %q, want only %q", k, v, sp.VoidReasonCloud)
		}
	}
}

// guessRun records 244 configuration ops in the manager's name, each with a candidate proof and
// its own session, one of them with the real PIN, and delivers them one by one or in one batch.
func guessRun(t *testing.T, batch bool) *World {
	w, _ := newTestWorld(t, 25, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	var items []sp.Item
	for i := 0; i < 244; i++ {
		proof := fmt.Sprintf("guess-%03d", i)
		if i == 100 {
			proof = w.Identity.MintProof(a.ID, pManager)
		}
		sid := fmt.Sprintf("guess-session-%d", i)
		it := must(a.record(engine.Input{Stream: "brand:" + w.Brand, Intent: "menu.price.set", Actor: pManager, SID: sid, Proof: proof,
			Muts: []sp.Mut{{E: "menu_item", ID: "menu-1", K: sp.KSet, F: map[string]any{"price_paise": int64(100 + i)}, Prev: map[string]string{"price_paise": engine.ZeroStamp}}}}, true))
		items = append(items, it)
		if !batch {
			w.toCloud(t, a)
		}
	}
	if batch {
		w.toCloud(t, a)
	}
	voided, checked := 0, 0
	for i, it := range items {
		r := w.rec(t, it)
		if r.Status == repository.StVoided {
			voided++
		}
		if i == 100 && r.Status != repository.StVoided {
			t.Fatalf("the real PIN comes after the lock and must be voided too, got %s", r.Status)
		}
		if r.Reason == service.ReasonProofFailed {
			checked++
		}
	}
	if voided != 244 {
		t.Fatalf("every op after the lock is voided, the real one included: %d of 244", voided)
	}
	if checked > 10 {
		t.Fatalf("at most 10 proofs may be checked, %d were", checked)
	}
	if f := w.Identity.Failures(w.Tenant, pManager, a.ID); f > 10 {
		t.Fatalf("the shared counter reads %d", f)
	}
	// The same member on another device is unaffected.
	sid := must(b.session(pManager))
	ok := must(b.record(engine.Input{Stream: "brand:" + w.Brand, Intent: "menu.price.set", Actor: pManager, SID: sid,
		Muts: []sp.Mut{{E: "menu_item", ID: "menu-2", K: sp.KSet, F: map[string]any{"price_paise": int64(900)}, Prev: map[string]string{"price_paise": engine.ZeroStamp}}}}, true))
	w.toCloud(t, b)
	if r := w.rec(t, ok); r.Status != repository.StAccepted {
		t.Fatalf("same member, other device: %s/%s", r.Status, r.Reason)
	}
	// Trading facts by that member on the locked device are still verified, and flagged if invalid.
	good := must(a.Do(pManager, engine.Input{Intent: "stock.move", Muts: []sp.Mut{{E: "stock_level", ID: "item-1", K: sp.KDelta, F: map[string]any{"qty_milli": int64(1)}}}}))
	invalid := must(a.record(engine.Input{Stream: "outlet:" + w.Outlet, Intent: "stock.move", Actor: pManager, SID: "other-sid", Proof: "bogus",
		Muts: []sp.Mut{{E: "stock_level", ID: "item-1", K: sp.KDelta, F: map[string]any{"qty_milli": int64(1)}}}}, true))
	w.toCloud(t, a)
	if r := w.rec(t, good); r.Status != repository.StAccepted {
		t.Fatalf("valid trading proof on a locked pair: %s", r.Status)
	}
	if r := w.rec(t, invalid); r.Status != repository.StFlagged {
		t.Fatalf("invalid trading proof on a locked pair: %s", r.Status)
	}
	return w
}

func TestRB5_244CandidateProofsAreCappedAndTheRealPINIsVoidedToo(t *testing.T) { guessRun(t, false) }

func TestRB6_TheSame244GuessesInOneBatchGiveTheSameResult(t *testing.T) { guessRun(t, true) }

func TestRB5_TokenRequestFailuresShareTheCounterAndRestoreDoesNotCount(t *testing.T) {
	w, _ := newTestWorld(t, 26, WorldOptions{Pos: 1})
	a := w.Devices[0]
	for i := 0; i < 4; i++ { // four failed PIN checks at the pin token request
		w.Identity.PinTokenFailure(w.Tenant, pManager, a.ID, fmt.Sprintf("tok-%d", i))
	}
	sid := must(a.session(pManager))
	bad := must(a.record(engine.Input{Stream: "brand:" + w.Brand, Intent: "menu.price.set", Actor: pManager, SID: sid, Proof: "bogus",
		Muts: []sp.Mut{{E: "menu_item", ID: "menu-1", K: sp.KSet, F: map[string]any{"price_paise": int64(1)}, Prev: map[string]string{"price_paise": engine.ZeroStamp}}}}, true))
	real := must(a.record(engine.Input{Stream: "brand:" + w.Brand, Intent: "menu.price.set", Actor: pManager, SID: sid,
		Muts: []sp.Mut{{E: "menu_item", ID: "menu-1", K: sp.KSet, F: map[string]any{"price_paise": int64(2)}, Prev: map[string]string{"price_paise": engine.ZeroStamp}}}}, true))
	w.toCloud(t, a)
	if r := w.rec(t, bad); r.Reason != service.ReasonProofFailed {
		t.Fatalf("the failure at the gateway is the 5th: %s/%s", r.Status, r.Reason)
	}
	if r := w.rec(t, real); r.Status != repository.StVoided || r.Reason != service.ReasonProofLocked {
		t.Fatalf("a correct PIN after 5 failures must get the same answer as a wrong one: %s/%s", r.Status, r.Reason)
	}
	// Identity unreachable (a restore): the configuration op waits and nothing is counted.
	w2, _ := newTestWorld(t, 27, WorldOptions{Pos: 1})
	b := w2.Devices[0]
	w2.Identity.SetDown(true)
	sid = must(b.session(pManager))
	pend := must(b.record(engine.Input{Stream: "brand:" + w2.Brand, Intent: "menu.price.set", Actor: pManager, SID: sid,
		Muts: []sp.Mut{{E: "menu_item", ID: "menu-1", K: sp.KSet, F: map[string]any{"price_paise": int64(3)}, Prev: map[string]string{"price_paise": engine.ZeroStamp}}}}, true))
	w2.toCloud(t, b)
	r := w2.rec(t, pend)
	if r.Status != repository.StQuarantined || r.Reason != service.ReasonConfigPending || engine.HoldCode(r.Reason) != sp.HoldPending {
		t.Fatalf("config op while identity is down: %s/%s", r.Status, r.Reason)
	}
	if n := w2.Identity.Failures(w2.Tenant, pManager, b.ID); n != 0 {
		t.Fatalf("an unverifiable proof must not count, counter=%d", n)
	}
	w2.Identity.SetDown(false)
	if n := must(w2.GW.ReverifyPending(bg, w2.Tenant)); n != 1 {
		t.Fatalf("reverified %d", n)
	}
	if r := w2.rec(t, pend); r.Status != repository.StAccepted {
		t.Fatalf("after identity returns: %s/%s", r.Status, r.Reason)
	}
}
