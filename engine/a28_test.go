package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Cases PH1 to PH3 and KR1 of ADR-0002 A2.8, and the tenant check of review M3.

const stream = "outlet:o1"

// chain records n ops on a device and returns the items (with bodies) in order.
func chain(t *testing.T, d *node, n int) []sp.Item {
	t.Helper()
	var out []sp.Item
	for i := 1; i <= n; i++ {
		it, err := d.e.Record(context.Background(), Input{Stream: stream, Intent: "order.create", Muts: order(fmt.Sprintf("o%d", i))})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, it)
	}
	return out
}

func slot(it sp.Item) sp.Item {
	return sp.Item{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq, H: it.H}
}

func seal(t *testing.T, d *node, it sp.Item) sp.Seal {
	t.Helper()
	s, err := sp.MakeSeal(d.key, it.Origin, it.Stream, it.Seq, it.H)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func refusedWith(res IngestRes, seq int64, reason string) bool {
	for _, r := range res.Refused {
		if r.Seq == seq && r.Reason == reason {
			return true
		}
	}
	return false
}

func statusAt(t *testing.T, n *node, origin string, seq int64) (repository.OpRec, bool) {
	t.Helper()
	var rec repository.OpRec
	var ok bool
	if err := n.e.Config().Store.InTx(context.Background(), n.e.Config().Tenant, func(tx repository.Tx) error {
		var err error
		rec, ok, err = tx.GetOp(stream, origin, seq)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return rec, ok
}

// PH1: a placeholder above the origin's highest seal is refused from any upstream but the cloud.
func TestPH1_PlaceholderAboveSealedHeadIsRefusedFromARelay(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	a := v.node(RoleDevice, "dev-a", sp.KindWaiter)
	its := chain(t, a, 3)
	batch := func() IngestReq {
		return IngestReq{Items: []sp.Item{its[0], slot(its[1])}, Seals: []sp.Seal{seal(t, a, its[0])}, FromUpstream: true, Caller: Caller{ID: "upstream"}}
	}
	for _, tc := range []struct {
		name      string
		fromCloud bool
		stored    bool
	}{{"hub", false, false}, {"cloud", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			n := v.node(RoleDevice, "dev-"+tc.name, sp.KindKDS)
			_ = n.c.Add(a.cred)
			req := batch()
			req.FromCloud = tc.fromCloud
			res, err := n.e.Ingest(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			_, held := statusAt(t, n, "dev-a", 2)
			if held != tc.stored {
				t.Fatalf("slot 2 stored=%v want %v (refused %+v)", held, tc.stored, res.Refused)
			}
			if !tc.stored && !refusedWith(res, 2, sp.ReasonUnsealed) {
				t.Fatalf("slot 2 must be refused as %s: %+v", sp.ReasonUnsealed, res.Refused)
			}
			if _, ok := statusAt(t, n, "dev-a", 1); !ok {
				t.Fatal("the sealed op below must still be taken")
			}
		})
	}
}

// A hub never serves a placeholder above a sealed head either.
func TestPH1_RelayServesNoTrailingPlaceholder(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	a := v.node(RoleDevice, "dev-a", sp.KindWaiter)
	hub := v.node(RoleHub, "hub-1", sp.KindHub)
	_ = hub.c.Add(a.cred)
	its := chain(t, a, 2)
	if _, err := hub.e.Ingest(ctx, IngestReq{Items: []sp.Item{its[0], slot(its[1])}, Seals: []sp.Seal{seal(t, a, its[0])}, FromUpstream: true, FromCloud: true, Caller: Caller{ID: "upstream"}}); err != nil {
		t.Fatal(err)
	}
	resp, err := hub.e.Serve(ctx, sp.PullRequest{Vector: sp.Vector{}}, ServeOpts{Caller: Caller{ID: "dev-x"}}, func(string) (sp.CredentialEnvelope, bool) { return sp.CredentialEnvelope{}, false })
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range resp.Items {
		if it.Seq == 2 {
			t.Fatalf("a hub served the trailing placeholder: %+v", resp.Items)
		}
	}
}

// PH2: a released body that contradicts the hash held for its slot is refused as chain_conflict, the
// node takes nothing more of that origin from that upstream, and the conflict is reported to the cloud.
func TestPH2_ContradictingBodyIsAChainConflictAndNeverSilent(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	a := v.node(RoleDevice, "dev-a", sp.KindWaiter)
	its := chain(t, a, 4)
	n := v.node(RoleDevice, "dev-n", sp.KindKDS)
	_ = n.c.Add(a.cred)
	// Slot 2 is held as a placeholder inside a sealed range (from the cloud).
	if _, err := n.e.Ingest(ctx, IngestReq{Items: []sp.Item{its[0], slot(its[1]), its[2]}, Seals: []sp.Seal{seal(t, a, its[2])}, FromUpstream: true, FromCloud: true, Caller: Caller{ID: "upstream"}}); err != nil {
		t.Fatal(err)
	}
	// A hub serves a different body for slot 2.
	lie := its[1]
	lie.Body = lie.Body[:len(lie.Body)-1] + `,"zz":1}`
	lie.H = sp.Hash(lie.Body)
	res, err := n.e.Ingest(ctx, IngestReq{Items: []sp.Item{lie}, FromUpstream: true, Caller: Caller{ID: "upstream"}})
	if err != nil {
		t.Fatal(err)
	}
	if !refusedWith(res, 2, sp.ReasonChainConflict) || len(res.New) != 0 {
		t.Fatalf("want chain_conflict and nothing stored: %+v", res)
	}
	if rec, _ := statusAt(t, n, "dev-a", 2); rec.Status != repository.StPlaceholder {
		t.Fatalf("slot 2 must stay a placeholder, is %s", rec.Status)
	}
	// Nothing more of that origin from that upstream, even the honest next op.
	res, _ = n.e.Ingest(ctx, IngestReq{Items: []sp.Item{its[3]}, Seals: []sp.Seal{seal(t, a, its[3])}, FromUpstream: true, Caller: Caller{ID: "upstream"}})
	if !refusedWith(res, 4, sp.ReasonChainConflict) {
		t.Fatalf("the conflicted origin must be refused from that upstream: %+v", res.Refused)
	}
	// It is reported at the next direct cloud hello, once.
	var got sp.HelloRequest
	cl := &Client{E: n.e, UpstreamIsCloud: true, Cache: n.c, T: helloSpy{got: &got, vec: sp.Vector{}}}
	if _, err := cl.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(got.Conflicts) != 1 || got.Conflicts[0].Origin != "dev-a" || got.Conflicts[0].Seq != 2 {
		t.Fatalf("hello must carry the conflict: %+v", got.Conflicts)
	}
	got = sp.HelloRequest{}
	if _, err := cl.SyncOnce(ctx); err != nil || len(got.Conflicts) != 0 {
		t.Fatalf("a reported conflict is not sent again: %v %+v", err, got.Conflicts)
	}
	// The same body arriving from the cloud itself is not gated by the relay conflict.
	res, _ = n.e.Ingest(ctx, IngestReq{Items: []sp.Item{its[3]}, Seals: []sp.Seal{seal(t, a, its[3])}, FromUpstream: true, FromCloud: true, Caller: Caller{ID: "upstream"}})
	if refusedWith(res, 4, sp.ReasonChainConflict) {
		t.Fatal("a relay conflict must not gate the cloud")
	}
}

type helloSpy struct {
	got *sp.HelloRequest
	vec sp.Vector
}

func (h helloSpy) Hello(_ context.Context, r sp.HelloRequest) (sp.HelloResponse, error) {
	*h.got = r
	return sp.HelloResponse{Vector: h.vec}, nil
}
func (helloSpy) Push(context.Context, sp.PushRequest) (sp.PushResponse, error) {
	return sp.PushResponse{}, nil
}
func (helloSpy) Pull(context.Context, sp.PullRequest) (sp.PullResponse, error) {
	return sp.PullResponse{}, nil
}

// PH3: the lower slot of a run of two placeholders cannot be bound. A lying hub's body is taken and
// marked unbound, never relayed onward, and contradicted at the next direct cloud hello; an honest
// body clears the mark.
func TestPH3_UnboundLowerSlotOfARunIsMarkedNotRelayedAndCrossChecked(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	a := v.node(RoleDevice, "dev-a", sp.KindWaiter)
	its := chain(t, a, 4)

	lie := its[1]
	lie.Body = lie.Body[:len(lie.Body)-1] + `,"zz":1}`
	lie.H = sp.Hash(lie.Body)

	run := func(name string, lower sp.Item, honest bool) {
		t.Run(name, func(t *testing.T) {
			hub := v.node(RoleHub, "hub-"+name, sp.KindHub)
			_ = hub.c.Add(a.cred)
			// Slots 2 and 3 arrive as placeholders in a run; slot 2 carries the hub's hash.
			if _, err := hub.e.Ingest(ctx, IngestReq{Items: []sp.Item{its[0], slot(lower), slot(its[2]), its[3]}, Seals: []sp.Seal{seal(t, a, its[3])},
				FromUpstream: true, FromCloud: true, Caller: Caller{ID: "upstream"}}); err != nil {
				t.Fatal(err)
			}
			// The body for slot 2 arrives from a relay: nothing seals it, the slot above has no body.
			res, err := hub.e.Ingest(ctx, IngestReq{Items: []sp.Item{lower}, FromUpstream: true, Caller: Caller{ID: "upstream"}})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.New) != 1 || len(res.Refused) != 0 {
				t.Fatalf("taken by hash: %+v", res)
			}
			rec, _ := statusAt(t, hub, "dev-a", 2)
			if !hasMarkS(rec.Marks, MarkUnbound) {
				t.Fatalf("slot 2 must be marked %s, marks %q", MarkUnbound, rec.Marks)
			}
			// A hub never relays an unbound op onward.
			resp, _ := hub.e.Serve(ctx, sp.PullRequest{Vector: sp.Vector{}}, ServeOpts{Caller: Caller{ID: "dev-x"}}, func(string) (sp.CredentialEnvelope, bool) { return sp.CredentialEnvelope{}, false })
			for _, it := range resp.Items {
				if it.Origin == "dev-a" && it.Seq >= 2 {
					t.Fatalf("an unbound slot or what follows it was served: %+v", it)
				}
			}
			out, _ := hub.e.Outbound(ctx, sp.Vector{}, OutboundOpts{Others: true})
			for _, it := range out.Items {
				if it.Origin == "dev-a" && it.Seq >= 2 {
					t.Fatalf("an unbound op was offered upstream: %+v", it)
				}
			}
			if !hub.e.DirectCloudDue(ctx) {
				t.Fatal("an unbound slot must make a direct cloud check due")
			}
			// The cloud answers with its own hash.
			if err := hub.e.ResolveUnbound(ctx, []sp.SlotHash{{Origin: "dev-a", Stream: stream, Seq: 2, H: its[1].H}}); err != nil {
				t.Fatal(err)
			}
			cs, _ := hub.e.Conflicts(ctx, true)
			un, _ := hub.e.UnboundSlots(ctx)
			if honest && (len(cs) != 0 || len(un) != 0) {
				t.Fatalf("an honest run clears the mark: conflicts %+v unbound %+v", cs, un)
			}
			if !honest && (len(cs) != 1 || cs[0].Seq != 2 || cs[0].Seen != its[1].H) {
				t.Fatalf("a lying hub is a chain_conflict at the direct hello: %+v", cs)
			}
		})
	}
	run("honest", its[1], true)
	run("lying", lie, false)
}

// When the op above arrives later and links, the unbound mark clears without the cloud.
func TestPH3_LaterOpAboveBindsTheSlot(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	a := v.node(RoleDevice, "dev-a", sp.KindWaiter)
	its := chain(t, a, 3)
	n := v.node(RoleDevice, "dev-n", sp.KindKDS)
	_ = n.c.Add(a.cred)
	// Slot 2 is a placeholder, slot 3 is not held yet; the body of slot 2 comes first.
	if _, err := n.e.Ingest(ctx, IngestReq{Items: []sp.Item{its[0], slot(its[1])}, Seals: []sp.Seal{seal(t, a, its[0])}, FromUpstream: true, FromCloud: true, Caller: Caller{ID: "upstream"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := n.e.Ingest(ctx, IngestReq{Items: []sp.Item{its[1]}, FromUpstream: true, FromCloud: true, Caller: Caller{ID: "upstream"}}); err != nil {
		t.Fatal(err)
	}
	if un, _ := n.e.UnboundSlots(ctx); len(un) != 1 {
		t.Fatalf("slot 2 should be unbound: %+v", un)
	}
	if _, err := n.e.Ingest(ctx, IngestReq{Items: []sp.Item{its[2]}, Seals: []sp.Seal{seal(t, a, its[2])}, FromUpstream: true, FromCloud: true, Caller: Caller{ID: "upstream"}}); err != nil {
		t.Fatal(err)
	}
	if un, _ := n.e.UnboundSlots(ctx); len(un) != 0 {
		t.Fatalf("the op above must bind slot 2: %+v", un)
	}
}

// KR1: after an op-key rotation a device with only the new key syncs through a hub that has
// refreshed its stored cloud seals, and converges including the ops of a retired cloud origin.
func TestKR1_HubRefreshesStoredCloudSealsAfterRotation(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	cl := v.node(RoleCloud, "cloud-A", sp.KindHub)
	hub := v.node(RoleHub, "hub-1", sp.KindHub)
	dev := v.node(RoleDevice, "dev-b", sp.KindKDS)
	oldKey := cl.key
	for _, n := range []*node{hub} {
		n.c.AddCloudKey(oldKey.Kid, &oldKey.Priv.PublicKey)
	}
	for i := 1; i <= 3; i++ {
		if _, err := cl.e.Record(ctx, Input{Stream: stream, Intent: "order.create", Muts: order(fmt.Sprintf("c%d", i))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := cl.e.StoreSeals(ctx); err != nil {
		t.Fatal(err)
	}
	hubC := &Client{E: hub.e, T: loop{up: cl.e, caller: Caller{ID: "hub-1"}}, Cache: hub.c, IsHub: true, UpstreamIsCloud: true}
	if _, err := hubC.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if hub.e.State().RowCount() != 3 {
		t.Fatalf("the hub must hold the cloud ops, has %d rows", hub.e.State().RowCount())
	}
	// Emergency rotation: the cloud re-signs its seals; the new pack drops the old key.
	next, _ := sp.NewKeyPair("k-cloud-new", nil)
	if err := cl.e.Config().Store.InTx(ctx, v.tenant, func(tx repository.Tx) error {
		seals, err := tx.SealsOfOrigins(CloudOriginPrefix)
		for _, s := range seals {
			n, merr := sp.MakeSeal(next, s.Origin, s.Stream, s.Seq, s.H)
			if merr != nil {
				return merr
			}
			if err := tx.ReplaceSeal(s.Stream, s.Origin, s.Seq, s.H, n.Kid, n.Sig); err != nil {
				return err
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	hub.c.AddCloudKey(next.Kid, &next.Priv.PublicKey)
	hub.c.RevokeCloudKey(oldKey.Kid)
	dev.c.AddCloudKey(next.Kid, &next.Priv.PublicKey) // the device was activated after the rotation: only the new key
	devC := &Client{E: dev.e, T: loop{up: hub.e, caller: Caller{ID: "dev-b"}}, Cache: dev.c}

	// Before the hub refreshes, the device cannot take the retired origin's ops and says so.
	if _, err := devC.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if dev.e.State().RowCount() != 0 {
		t.Fatal("ops under a dropped key must not be taken")
	}
	if !dev.e.DirectCloudDue(ctx) {
		t.Fatal("a refused cloud seal must not stall silently: the cloud must be due for a direct read")
	}
	// The hub refreshes at its next round with the cloud; then the device converges from the hub alone.
	if _, err := hubC.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if stale, _ := hub.e.StaleSeals(ctx, 10); len(stale) != 0 {
		t.Fatalf("the hub still holds stale seals: %+v", stale)
	}
	if _, err := devC.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if dev.e.State().RowCount() != 3 || dev.e.StateHash() != hub.e.StateHash() {
		t.Fatalf("the device must converge from the hub alone: %d rows", dev.e.State().RowCount())
	}
}

// M3: a body that names another tenant is refused at ingest, by device, hub and cloud alike.
func TestIngestRefusesABodyNamingAnotherTenant(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	a := v.node(RoleDevice, "dev-a", sp.KindWaiter)
	hub := v.node(RoleHub, "hub-1", sp.KindHub)
	_ = hub.c.Add(a.cred)
	// dev-a's engine believes it is in tenant t2; its credential and the hub are in t1.
	cfg := a.e.Config()
	cfg.Tenant = "t2"
	st, err := repository.Open(fmt.Sprintf("file:%s-foreign?mode=memory&cache=shared", t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg.Store = st
	foreign := New(cfg)
	if err := foreign.Open(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.Record(ctx, Input{Stream: stream, Intent: "order.create", Muts: order("x")}); err != nil {
		t.Fatal(err)
	}
	req, err := foreign.Outbound(ctx, sp.Vector{}, OutboundOpts{})
	if err != nil || len(req.Items) != 1 {
		t.Fatalf("outbound: %v %d", err, len(req.Items))
	}
	res, _ := hub.e.Ingest(ctx, IngestReq{Items: req.Items, Seals: req.Seals, Caller: Caller{ID: "dev-a"}})
	if len(res.New) != 0 || !refusedWith(res, 1, sp.ReasonFramed) {
		t.Fatalf("a foreign tenant_id in the body must be refused as framing: %+v", res)
	}
}

// L8: a cloud-origin seal verifies under the key its kid names, whichever keys the cache holds, and
// a dropped kid is refused.
func TestCloudSealVerifiesUnderTheNamedKidOnly(t *testing.T) {
	v := newEnv(t)
	n := v.node(RoleDevice, "dev-n", sp.KindKDS)
	k1, _ := sp.NewKeyPair("k1", nil)
	k2, _ := sp.NewKeyPair("k2", nil)
	n.c.AddCloudKey("k1", &k1.Priv.PublicKey)
	n.c.AddCloudKey("k2", &k2.Priv.PublicKey)
	s1, _ := sp.MakeSeal(k1, "cloud-A", stream, 1, "h")
	s2, _ := sp.MakeSeal(k2, "cloud-A", stream, 1, "h")
	for i := 0; i < 20; i++ { // map order is random: the result must not depend on it
		if !n.e.sealOK(s1, "cloud-A", nil) || !n.e.sealOK(s2, "cloud-A", nil) {
			t.Fatal("a seal under a held kid must verify")
		}
	}
	s1.Kid = "k2" // right signature, wrong kid
	if n.e.sealOK(s1, "cloud-A", nil) {
		t.Fatal("a seal must verify under the kid it names, not under another held key")
	}
	n.c.RevokeCloudKey("k1")
	s1.Kid = "k1"
	if n.e.sealOK(s1, "cloud-A", nil) {
		t.Fatal("a revoked kid must be refused")
	}
}
