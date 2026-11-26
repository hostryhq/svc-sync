package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

type env struct {
	t        *testing.T
	now      time.Time
	identity *sp.KeyPair
	tenant   string
	outlet   string
}

func newEnv(t *testing.T) *env {
	id, err := sp.NewKeyPair("identity-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, now: time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC), identity: id, tenant: "t1", outlet: "o1"}
}

type node struct {
	e    *Engine
	key  *sp.KeyPair
	cred sp.CredentialEnvelope
	c    *CredCache
}

func (v *env) node(role Role, id, kind string) *node {
	v.t.Helper()
	st, err := repository.Open(fmt.Sprintf("file:%s-%s?mode=memory&cache=shared", v.t.Name(), id))
	if err != nil {
		v.t.Fatal(err)
	}
	v.t.Cleanup(func() { _ = st.Close() })
	kp, _ := sp.NewKeyPair("k-"+id, nil)
	cred, _ := sp.SignCredential(v.identity, sp.Credential{DeviceID: id, TenantID: v.tenant, OutletID: v.outlet, Kind: kind, Kid: kp.Kid, Pub: kp.PublicB64(), Store: sp.StoreProtected, NotAfter: v.now.Add(time.Hour).Unix()})
	cache := NewCredCache(&v.identity.Priv.PublicKey, v.tenant, v.outlet, func() time.Time { return v.now })
	cfg := Config{Role: role, Kind: kind, Tenant: v.tenant, Outlet: v.outlet, Origin: id, Key: kp, Store: st, Trust: cache,
		Clock: sp.NewClock(func() time.Time { return v.now }), Series: fixedSeries{"A07"}}
	e := New(cfg)
	if err := e.Open(context.Background()); err != nil {
		v.t.Fatal(err)
	}
	n := &node{e: e, key: kp, cred: cred, c: cache}
	_ = cache.Add(cred)
	return n
}

type fixedSeries struct{ code string }

func (f fixedSeries) Code(string) (string, bool) { return f.code, true }

// loop is an in-process upstream: a hub engine without hooks.
type loop struct {
	up     *Engine
	caller Caller
}

func (l loop) Hello(ctx context.Context, r sp.HelloRequest) (sp.HelloResponse, error) {
	v, err := l.up.Vector(ctx)
	return sp.HelloResponse{Vector: v}, err
}
func (l loop) Push(ctx context.Context, r sp.PushRequest) (sp.PushResponse, error) {
	res, err := l.up.Ingest(ctx, IngestReq{Items: r.Items, Seals: r.Seals, Caller: l.caller})
	return sp.PushResponse{Vector: res.Vector, Refused: res.Refused}, err
}
func (l loop) Pull(ctx context.Context, r sp.PullRequest) (sp.PullResponse, error) {
	return l.up.Serve(ctx, r, ServeOpts{Caller: l.caller}, func(string) (sp.CredentialEnvelope, bool) { return sp.CredentialEnvelope{}, false })
}

func order(id string) []sp.Mut {
	return []sp.Mut{{E: "order", ID: id, K: sp.KInsert, F: map[string]any{"table": "T1"}}}
}

func TestRecordGivesGaplessSeqChainAndNumber(t *testing.T) {
	v := newEnv(t)
	d := v.node(RoleDevice, "dev-a", sp.KindPOS)
	ctx := context.Background()
	var prev sp.Item
	for i := 1; i <= 3; i++ {
		it, err := d.e.Record(ctx, Input{Stream: "outlet:o1", Intent: "bill.finalize", DocType: "tax_invoice",
			MutsFn: func(n string) []sp.Mut {
				return []sp.Mut{{E: "bill", ID: fmt.Sprintf("b%d", i), K: sp.KInsert, F: map[string]any{"number": n, "total_paise": int64(100 * i)}}}
			}})
		if err != nil {
			t.Fatal(err)
		}
		b, err := sp.VerifyItem(it)
		if err != nil || b.Seq != int64(i) {
			t.Fatalf("item %d: %v seq=%d", i, err, b.Seq)
		}
		if i > 1 {
			if b.PH != prev.H {
				t.Fatalf("chain broken at %d", i)
			}
		} else if b.PH != sp.GenesisHash("dev-a", "outlet:o1") {
			t.Fatal("first op must chain to genesis")
		}
		if want := fmt.Sprintf("A07/2627/%06d", i); b.Doc.Number != want || len(want) > 16 {
			t.Fatalf("number %q want %q", b.Doc.Number, want)
		}
		prev = it
	}
}

func TestPushThroughHubReachesOtherDeviceAndStatesConverge(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	a, b, hub := v.node(RoleDevice, "dev-a", sp.KindWaiter), v.node(RoleDevice, "dev-b", sp.KindKDS), v.node(RoleHub, "hub-1", sp.KindHub)
	for _, d := range []*node{a, b} {
		_ = hub.c.Add(d.cred)
		_ = a.c.Add(d.cred)
		_ = b.c.Add(d.cred)
	}
	for i := 0; i < 5; i++ {
		if _, err := a.e.Record(ctx, Input{Stream: "outlet:o1", Intent: "order.create", Muts: order(fmt.Sprintf("o%d", i))}); err != nil {
			t.Fatal(err)
		}
	}
	ca := &Client{E: a.e, T: loop{up: hub.e, caller: Caller{ID: "dev-a"}}, Cache: a.c}
	cb := &Client{E: b.e, T: loop{up: hub.e, caller: Caller{ID: "dev-b"}}, Cache: b.c}
	for _, c := range []*Client{ca, cb, ca} {
		if _, err := c.SyncOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if a.e.StateHash() != b.e.StateHash() || a.e.State().RowCount() != 5 {
		t.Fatalf("no convergence: %d vs %d rows", a.e.State().RowCount(), b.e.State().RowCount())
	}
	// Replaying the whole exchange is a no-op (idempotent apply).
	before := b.e.StateHash()
	for i := 0; i < 2; i++ {
		_, _ = cb.SyncOnce(ctx)
	}
	if b.e.StateHash() != before {
		t.Fatal("replay changed state")
	}
}

func TestIngestRefusesTamperedAndGappedOps(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	a, hub := v.node(RoleDevice, "dev-a", sp.KindWaiter), v.node(RoleHub, "hub-1", sp.KindHub)
	_ = hub.c.Add(a.cred)
	for i := 0; i < 3; i++ {
		_, _ = a.e.Record(ctx, Input{Stream: "outlet:o1", Intent: "order.create", Muts: order(fmt.Sprintf("o%d", i))})
	}
	req, err := a.e.Outbound(ctx, sp.Vector{}, OutboundOpts{})
	if err != nil || len(req.Items) != 3 {
		t.Fatalf("outbound: %v %d", err, len(req.Items))
	}
	// Drop the middle op: gap/chain.
	drop := req
	drop.Items = []sp.Item{req.Items[0], req.Items[2]}
	res, _ := hub.e.Ingest(ctx, IngestReq{Items: drop.Items, Seals: drop.Seals, Caller: Caller{ID: "dev-a"}})
	if len(res.New) != 0 || len(res.Refused) == 0 {
		t.Fatalf("dropping an op from the middle leaves nothing under the seal: new=%d refused=%d", len(res.New), len(res.Refused))
	}
	// Alter an op body: hash no longer matches.
	alt := req
	alt.Items = append([]sp.Item(nil), req.Items...)
	alt.Items[1].Body = alt.Items[1].Body[:len(alt.Items[1].Body)-2] + `,"x":1}`
	res, _ = hub.e.Ingest(ctx, IngestReq{Items: alt.Items, Seals: alt.Seals, Caller: Caller{ID: "dev-a"}})
	if len(res.Refused) == 0 {
		t.Fatal("altered op must be refused")
	}
	// A seal from another key does not cover the batch.
	other, _ := sp.NewKeyPair("k-x", nil)
	bad := req
	bad.Seals = []sp.Seal{func() sp.Seal { s, _ := sp.MakeSeal(other, "dev-a", "outlet:o1", 3, req.Items[2].H); return s }()}
	h2 := v.node(RoleHub, "hub-2", sp.KindHub)
	_ = h2.c.Add(a.cred)
	res, _ = h2.e.Ingest(ctx, IngestReq{Items: bad.Items, Seals: bad.Seals, Caller: Caller{ID: "dev-a"}})
	if len(res.New) != 0 {
		t.Fatalf("batch under a foreign seal must not be stored (stored %d)", len(res.New))
	}
}
