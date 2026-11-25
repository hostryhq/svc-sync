package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/devepoch"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/identitystub"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	"github.com/hostryhq/svc-sync/sim"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

const (
	cashier = "m1"
	manager = "m2"
)

func world(t *testing.T, seed uint64) *sim.World {
	t.Helper()
	w, err := sim.NewWorld(context.Background(), sim.NewRand(seed), sim.WorldOptions{Pos: 1, NoHub: true, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w
}

func opRec(t *testing.T, w *sim.World, it sp.Item) repository.OpRec {
	t.Helper()
	var r repository.OpRec
	var ok bool
	if err := w.GWStore.InTx(context.Background(), w.Tenant, func(tx repository.Tx) error {
		var err error
		r, ok, err = tx.GetOp(it.Stream, it.Origin, it.Seq)
		return err
	}); err != nil || !ok {
		t.Fatalf("op %s/%s/%d not stored: %v", it.Origin, it.Stream, it.Seq, err)
	}
	return r
}

func stock(d *sim.Device, actor, sid string, at time.Time) (sp.Item, error) {
	return d.Eng.Record(context.Background(), engine.Input{Stream: "outlet:" + d.W.Outlet, Intent: "stock.move", Actor: actor, SID: sid, PackV: 1, At: at,
		Muts: []sp.Mut{{E: "stock_level", ID: "item-1", K: sp.KDelta, F: map[string]any{"qty_milli": int64(1000)}}}})
}

// A3.1 item 3: identity is asked once per proof. A session opened with a wrong proof counts one failure, however many
// ops follow in it, and every op of the session is judged from that stored verdict (flagged, never rejected).
func TestSessionVerdictIsStoredOnceAndJudgesEveryLaterOp(t *testing.T) {
	w := world(t, 301)
	a := w.Devices[0]
	sid, err := a.BadSession(cashier)
	if err != nil {
		t.Fatal(err)
	}
	var last sp.Item
	for i := 0; i < 15; i++ {
		if last, err = stock(a, cashier, sid, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.SyncCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := w.Identity.Failures(w.Tenant, cashier, a.ID); n != 1 {
		t.Fatalf("one wrong proof, %d failures counted", n)
	}
	if r := opRec(t, w, last); r.Status != repository.StFlagged || !strings.Contains(r.Marks, service.MarkAttributionUnverified) {
		t.Fatalf("the last op of the bad session: %s %s", r.Status, r.Marks)
	}
	// The same actor in another session opened with the right PIN is valid: the verdict belongs to the session.
	good, _ := a.SessionWith(cashier, "good", "")
	it, err := stock(a, cashier, good, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	// An op that names another actor than the session's, and one more than 16 hours after the opening, are unverified too.
	other, _ := stock(a, manager, good, time.Time{})
	late, _ := stock(a, cashier, good, w.Clock.Now().Add(17*time.Hour))
	if err := a.SyncCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := opRec(t, w, it); r.Status != repository.StAccepted {
		t.Fatalf("right PIN: %s %s", r.Status, r.Marks)
	}
	for name, x := range map[string]sp.Item{"another actor": other, "17 hours later": late} {
		if r := opRec(t, w, x); r.Status != repository.StFlagged || !strings.Contains(r.Marks, service.MarkAttributionUnverified) {
			t.Errorf("%s: %s %s", name, r.Status, r.Marks)
		}
	}
}

// A3.1 item 3: the row is per origin, not per stream. A configuration change in the brand stream that reaches the
// gateway before the session.open in the outlet stream waits (pending), and is judged once the open has arrived and
// the gateway has asked identity (A3.1 item 4).
func TestAnOpBeforeItsSessionOpenWaitsAndIsJudgedWhenTheOpenArrives(t *testing.T) {
	w := world(t, 302)
	a := w.Devices[0]
	ctx := context.Background()
	sid, err := a.SessionWith(manager, "brand", "")
	if err != nil {
		t.Fatal(err)
	}
	price, err := a.Eng.Record(ctx, engine.Input{Stream: "brand:" + w.Brand, Intent: "menu.price.set", Actor: manager, SID: sid, PackV: 1,
		Muts: []sp.Mut{{E: "menu_item", ID: "menu-1", K: sp.KSet, F: map[string]any{"price_paise": int64(500)}, Prev: map[string]string{"price_paise": engine.ZeroStamp}}}})
	if err != nil {
		t.Fatal(err)
	}
	tr := w.CloudTransport("dev-cloud:"+a.ID, a.ID)
	push := func(stream string) {
		req, err := a.Eng.Outbound(ctx, sp.Vector{}, engine.OutboundOpts{Streams: []string{stream}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Push(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	push("brand:" + w.Brand)
	if r := opRec(t, w, price); r.Status != repository.StQuarantined || r.Reason != service.ReasonConfigPending {
		t.Fatalf("before its session.open: %s/%s", r.Status, r.Reason)
	}
	push("outlet:" + w.Outlet)
	if _, err := w.GW.ResolveSessions(ctx, w.Tenant); err != nil {
		t.Fatal(err)
	}
	if r := opRec(t, w, price); r.Status != repository.StAccepted {
		t.Fatalf("after the open arrived: %s/%s", r.Status, r.Reason)
	}
}

// A3.1 item 4: identity unreachable is pending, never valid. A sale made in the session is stored with the pending
// mark; when identity answers the mark goes, and a failure flags the op and publishes sync.op.flagged.
func TestPendingProofIsResolvedLaterAndAFailureFlagsTheStoredOps(t *testing.T) {
	w := world(t, 303)
	a := w.Devices[0]
	ctx := context.Background()
	w.Identity.SetDown(true)
	bad, _ := a.BadSession(cashier)
	good, _ := a.SessionWith(cashier, "ok", "")
	badOp, _ := stock(a, cashier, bad, time.Time{})
	goodOp, _ := stock(a, cashier, good, time.Time{})
	if err := a.SyncCloud(ctx); err != nil {
		t.Fatal(err)
	}
	for name, it := range map[string]sp.Item{"bad": badOp, "good": goodOp} {
		if r := opRec(t, w, it); r.Status != repository.StAccepted || !strings.Contains(r.Marks, service.MarkProofPending) {
			t.Fatalf("%s while identity is down: %s %s (a trading fact is kept with the pending mark, never judged valid)", name, r.Status, r.Marks)
		}
	}
	w.Identity.SetDown(false)
	if n, err := w.GW.ResolveSessions(ctx, w.Tenant); err != nil || n != 2 {
		t.Fatalf("resolved %d sessions: %v", n, err)
	}
	if r := opRec(t, w, goodOp); r.Status != repository.StAccepted || strings.Contains(r.Marks, service.MarkProofPending) || strings.Contains(r.Marks, service.MarkAttributionUnverified) {
		t.Fatalf("right PIN once identity answers: %s %s", r.Status, r.Marks)
	}
	if r := opRec(t, w, badOp); r.Status != repository.StFlagged || !strings.Contains(r.Marks, service.MarkAttributionUnverified) || strings.Contains(r.Marks, service.MarkProofPending) {
		t.Fatalf("wrong PIN once identity answers: %s %s", r.Status, r.Marks)
	}
}

// A3.1 item 5: a strong session carries no proof; identity's own session facts decide, and the end of the session on
// the revocation feed ends it for the gateway.
func TestStrongSessionIsJudgedFromIdentitysFacts(t *testing.T) {
	w := world(t, 304)
	a := w.Devices[0]
	ctx := context.Background()
	open := func(sid, actor string) sp.Item {
		it, err := a.Eng.Record(ctx, engine.Input{Stream: "outlet:" + w.Outlet, Intent: sp.IntentSessionOpen, Actor: actor, SID: sid, PackV: 1,
			Muts: []sp.Mut{{E: "session", ID: sid, K: sp.KInsert, F: map[string]any{"type": sp.SessionStrong, "device": a.ID}}}})
		if err != nil {
			t.Fatal(err)
		}
		return it
	}
	w.Identity.OpenStrong(w.Tenant, "strong-1", manager, a.ID, w.Clock.Now())
	openOK := open("strong-1", manager)
	openUnknown := open("strong-ghost", manager) // identity has no such session
	opOK, _ := stock(a, manager, "strong-1", time.Time{})
	w.Identity.EndStrong(w.Tenant, "strong-1", w.Clock.Now().Add(time.Second))
	afterEnd, _ := stock(a, manager, "strong-1", w.Clock.Now().Add(time.Minute))
	if err := a.SyncCloud(ctx); err != nil {
		t.Fatal(err)
	}
	if r := opRec(t, w, openOK); r.Status != repository.StAccepted {
		t.Fatalf("a strong session identity knows: %s %s", r.Status, r.Marks)
	}
	if r := opRec(t, w, opOK); r.Status != repository.StAccepted {
		t.Fatalf("an op of the live strong session: %s %s", r.Status, r.Marks)
	}
	if r := opRec(t, w, openUnknown); r.Status != repository.StFlagged {
		t.Fatalf("a strong session identity does not know: %s %s", r.Status, r.Marks)
	}
	if r := opRec(t, w, afterEnd); r.Status != repository.StFlagged {
		t.Fatalf("an op after the session ended: %s %s", r.Status, r.Marks)
	}
}

// A3.1 item 2: an approval.grant carries the action proof and the approver's pin_v; identity is asked once per
// approval id with the fields the approval record binds.
func TestApprovalGrantProofIsAskedOnceWithTheFieldsTheRecordBinds(t *testing.T) {
	w := world(t, 305)
	a := w.Devices[0]
	ctx := context.Background()
	sid, _ := a.SessionWith(cashier, "req", "")
	grant := func(id, proof string, tamper bool) sp.Item {
		at := w.Clock.Now().Truncate(time.Millisecond)
		f := map[string]any{"permission": "bill.void", "target": "bill-1", "requester": cashier, "approver": manager, "action_hash": "sha256:abc", "reason": "wrong item"}
		q := directory.ProofQuestion{Kind: directory.ProofKindApproval, Device: a.ID, Member: manager, SID: sid, PackV: 1, PinV: 1, ApprovalID: id,
			Permission: "bill.void", Target: "bill-1", Requester: cashier, ActionHash: "sha256:abc", Reason: "wrong item", ApprovedAt: at}
		if proof == "" {
			proof = w.Identity.MintProof(q)
		}
		if tamper {
			f["target"] = "bill-2" // the record the gateway reads differs from what the proof was made over
		}
		it, err := a.Eng.Record(ctx, engine.Input{Stream: "outlet:" + w.Outlet, Intent: sp.IntentApprovalGrant, Actor: manager, SID: sid, PackV: 1, PinV: 1, Proof: proof, At: at,
			Muts: []sp.Mut{{E: "approval", ID: id, K: sp.KInsert, F: f}}})
		if err != nil {
			t.Fatal(err)
		}
		return it
	}
	ok := grant("ap-1", "", false)
	forged := grant("ap-2", "forged", false)
	tampered := grant("ap-3", "", true)
	if err := a.SyncCloud(ctx); err != nil {
		t.Fatal(err)
	}
	if r := opRec(t, w, ok); r.Status != repository.StAccepted {
		t.Fatalf("a valid action proof: %s %s", r.Status, r.Marks)
	}
	for name, it := range map[string]sp.Item{"forged": forged, "record differs from what was signed": tampered} {
		if r := opRec(t, w, it); r.Status != repository.StFlagged || !strings.Contains(r.Marks, service.MarkAttributionUnverified) {
			t.Errorf("%s: %s %s", name, r.Status, r.Marks)
		}
	}
	// Re-judging the same approval (a release, a re-offer) does not ask identity again: the failures stay two.
	if n := w.Identity.Failures(w.Tenant, manager, a.ID); n != 2 {
		t.Fatalf("two wrong action proofs, %d failures", n)
	}
}

// faultyDir wraps the stub and reports every lookup after the cut-off as a fault, as the real directory does when
// identity or tenancy cannot be asked.
type faultyDir struct {
	*identitystub.Identity
	faults uint64
	broken bool
}

func (f *faultyDir) Faults() uint64 { return f.faults }
func (f *faultyDir) PackFor(tenant, device string, v int) (directory.Pack, bool) {
	if f.broken {
		f.faults++
		return directory.Pack{}, false
	}
	return f.Identity.PackFor(tenant, device, v)
}

// A3.2 failure rule: a lookup that could not be asked is never "held" or "valid". A configuration op whose pack could
// not be read waits; it is not voided as permission_absent.
func TestConfigurationOpWaitsWhenADirectoryLookupFails(t *testing.T) {
	w := world(t, 306)
	a := w.Devices[0]
	ctx := context.Background()
	fd := &faultyDir{Identity: w.Identity, broken: true}
	ep, err := devepoch.Reader(ctx, "file:fault-epoch-"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	gw, err := service.New(ctx, service.Config{Store: w.GWStore, Epoch: ep, Dir: fd, OpKey: w.Identity.CloudKey, Now: w.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := a.SessionWith(manager, "cfg", "")
	price, err := a.Eng.Record(ctx, engine.Input{Stream: "brand:" + w.Brand, Intent: "menu.price.set", Actor: manager, SID: sid, PackV: 1,
		Muts: []sp.Mut{{E: "menu_item", ID: "menu-1", K: sp.KSet, F: map[string]any{"price_paise": int64(500)}, Prev: map[string]string{"price_paise": engine.ZeroStamp}}}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := a.Eng.Outbound(ctx, sp.Vector{}, engine.OutboundOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Push(ctx, w.Tenant, engine.Caller{ID: a.ID, Kind: sp.KindPOS, Outlet: w.Outlet, Brand: w.Brand}, req); err != nil {
		t.Fatal(err)
	}
	if r := opRec(t, w, price); r.Status != repository.StQuarantined || r.Reason != service.ReasonConfigPending {
		t.Fatalf("a configuration op whose pack could not be read: %s/%s", r.Status, r.Reason)
	}
	fd.broken = false
	if n, err := gw.ReverifyPending(ctx, w.Tenant); err != nil || n != 1 {
		t.Fatalf("judged again: %d %v", n, err)
	}
	if r := opRec(t, w, price); r.Status != repository.StAccepted {
		t.Fatalf("once the directory answers: %s/%s", r.Status, r.Reason)
	}
}
