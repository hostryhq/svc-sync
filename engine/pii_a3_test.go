package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// ADR-0014 A3.1 and A3.2 (tests PA1, PA3, PA4, PA5 at the engine): a check with customer details is served to pos, waiter,
// personal and hub pullers with the values and never to a kds; every node's state hash covers the commitments, so it is
// equal with or without the values and does not change when a field is erased.

func checkWithPII(t *testing.T, d *node) sp.Item {
	t.Helper()
	it, err := d.e.Record(context.Background(), Input{Stream: stream, Intent: "check.create",
		PII:  json.RawMessage(`{"check":{"c1":{"customer_name":"Meera","customer_phone":"+919876543210"}}}`),
		Muts: []sp.Mut{{E: "check", ID: "c1", K: sp.KInsert, F: map[string]any{"label": "Guest 1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func storedPII(t *testing.T, n *node, it sp.Item) (string, bool) {
	t.Helper()
	var raw string
	var ok bool
	if err := n.e.Config().Store.InTx(context.Background(), n.e.Config().Tenant, func(tx repository.Tx) error {
		var err error
		raw, ok, err = tx.GetPII(it.Stream, it.Origin, it.Seq)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return raw, ok
}

func fromCloud(items []sp.Item, seals ...sp.Seal) IngestReq {
	return IngestReq{Items: items, Seals: seals, FromUpstream: true, FromCloud: true, Caller: Caller{ID: "upstream"}}
}

func TestPA1_PIIIsServedToStaffDevicesAndHubAndNeverToAKDS(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	a := v.node(RoleDevice, "dev-a", sp.KindPOS)
	hub := v.node(RoleHub, "hub-1", sp.KindHub)
	_ = hub.c.Add(a.cred)
	it := checkWithPII(t, a)
	if _, err := hub.e.Ingest(ctx, fromCloud([]sp.Item{it}, seal(t, a, it))); err != nil {
		t.Fatal(err)
	}
	if _, ok := storedPII(t, hub, it); !ok {
		t.Fatal("setup: the hub holds the values it was sent")
	}
	for _, tc := range []struct {
		kind   string
		served bool
	}{{sp.KindPOS, true}, {sp.KindWaiter, true}, {sp.KindPersonal, true}, {sp.KindHub, true}, {sp.KindKDS, false}} {
		resp, err := hub.e.Serve(ctx, sp.PullRequest{Vector: sp.Vector{}}, ServeOpts{Caller: Caller{ID: "x", Kind: tc.kind, Store: sp.StoreProtected}}, func(string) (sp.CredentialEnvelope, bool) { return sp.CredentialEnvelope{}, false })
		if err != nil || len(resp.Items) != 1 {
			t.Fatalf("%s pull: %v %+v", tc.kind, err, resp)
		}
		if got := len(resp.Items[0].PII) > 0; got != tc.served {
			t.Fatalf("%s: pii served=%v, want %v", tc.kind, got, tc.served)
		}
		if tc.served && !strings.Contains(string(resp.Items[0].PII), "Meera") {
			t.Fatalf("%s: the values must travel with their salts: %s", tc.kind, resp.Items[0].PII)
		}
		if !strings.Contains(resp.Items[0].Body, `"pii_c"`) || strings.Contains(resp.Items[0].Body, "Meera") {
			t.Fatalf("%s: the commitments are in the body for every kind and the values never are", tc.kind)
		}
	}
}

func TestPA3_StateHashCoversCommitmentsNotValuesAndSurvivesErasure(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	a := v.node(RoleDevice, "dev-a", sp.KindPOS)
	it := checkWithPII(t, a)
	pos := v.node(RoleDevice, "dev-pos", sp.KindPOS)
	kds := v.node(RoleDevice, "dev-kds", sp.KindKDS)
	for _, n := range []*node{pos, kds} {
		_ = n.c.Add(a.cred)
		sent := it
		if n == kds {
			sent.PII = nil // a kds is never sent the values
		}
		if _, err := n.e.Ingest(ctx, fromCloud([]sp.Item{sent}, seal(t, a, it))); err != nil {
			t.Fatal(err)
		}
	}
	want := a.e.StateHash()
	if pos.e.StateHash() != want || kds.e.StateHash() != want {
		t.Fatalf("state hash differs: origin %s pos %s kds %s", want, pos.e.StateHash(), kds.e.StateHash())
	}
	row, ok := a.e.State().Row("check", "c1")
	if !ok || row["~c:customer_name"] == nil || row["~c:customer_phone"] == nil || row["customer_name"] != nil {
		t.Fatalf("the row holds a commitment per pii field and no value: %v", row)
	}
	if err := pos.e.Config().Store.InTx(ctx, v.tenant, func(tx repository.Tx) error {
		return EraseLocal(tx, sp.Ref{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq}, v.now)
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := storedPII(t, pos, it); ok {
		t.Fatal("erasure removes the values")
	}
	if pos.e.StateHash() != want {
		t.Fatal("the hash must not change when a field is erased")
	}
}

func TestPA4_AStrippedFieldIsIncompleteAndRefetchedAndATamperedOneIsRefused(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	a := v.node(RoleDevice, "dev-a", sp.KindPOS)
	it := checkWithPII(t, a)
	n := v.node(RoleDevice, "dev-n", sp.KindWaiter)
	_ = n.c.Add(a.cred)
	stripped := it
	stripped.PII = nil
	if _, err := n.e.Ingest(ctx, fromCloud([]sp.Item{stripped}, seal(t, a, it))); err != nil {
		t.Fatal(err)
	}
	need := func() []sp.Ref {
		var refs []sp.Ref
		_ = n.e.Config().Store.InTx(ctx, v.tenant, func(tx repository.Tx) error {
			var err error
			refs, err = n.e.IncompletePII(tx, 10)
			return err
		})
		return refs
	}
	if refs := need(); len(refs) != 1 || refs[0].Seq != it.Seq {
		t.Fatalf("a commitment with no value is pii_incomplete and asked for again: %+v", refs)
	}
	// A value that does not match its commitment is dropped; the field stays incomplete.
	tampered := it
	tampered.PII = json.RawMessage(strings.ReplaceAll(string(it.PII), "Meera", "Mallory"))
	if _, err := n.e.Ingest(ctx, fromCloud([]sp.Item{tampered})); err != nil {
		t.Fatal(err)
	}
	if raw, ok := storedPII(t, n, it); ok && strings.Contains(raw, "Mallory") {
		t.Fatal("a tampered value was stored")
	}
	if len(need()) != 1 {
		t.Fatal("a refused value leaves the field incomplete")
	}
	// The real values completed on the next contact, and the fetch is no longer asked for.
	if _, err := n.e.Ingest(ctx, fromCloud([]sp.Item{it})); err != nil {
		t.Fatal(err)
	}
	if raw, ok := storedPII(t, n, it); !ok || !strings.Contains(raw, "Meera") || !strings.Contains(raw, "+919876543210") {
		t.Fatalf("the values were not completed: %q %v", raw, ok)
	}
	if len(need()) != 0 {
		t.Fatal("a complete op is not asked for again")
	}
	// A kds expects no value and asks for none.
	k := v.node(RoleDevice, "dev-k", sp.KindKDS)
	_ = k.c.Add(a.cred)
	if _, err := k.e.Ingest(ctx, fromCloud([]sp.Item{stripped}, seal(t, a, it))); err != nil {
		t.Fatal(err)
	}
	_ = k.e.Config().Store.InTx(ctx, v.tenant, func(tx repository.Tx) error {
		if refs, _ := k.e.IncompletePII(tx, 10); len(refs) != 0 {
			t.Fatalf("a kds fetches nothing: %+v", refs)
		}
		return nil
	})
}

func TestPA5_AValueArrivingAfterItsErasureIsDropped(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	a := v.node(RoleDevice, "dev-a", sp.KindPOS)
	it := checkWithPII(t, a)
	n := v.node(RoleDevice, "dev-n", sp.KindPOS)
	_ = n.c.Add(a.cred)
	ref := sp.Ref{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq}
	if err := n.e.Config().Store.InTx(ctx, v.tenant, func(tx repository.Tx) error { return EraseLocal(tx, ref, time.Now()) }); err != nil {
		t.Fatal(err)
	}
	if _, err := n.e.Ingest(ctx, fromCloud([]sp.Item{it}, seal(t, a, it))); err != nil {
		t.Fatal(err)
	}
	if _, ok := storedPII(t, n, it); ok {
		t.Fatal("a value that arrives after its erasure op must be dropped on receipt")
	}
	_ = n.e.Config().Store.InTx(ctx, v.tenant, func(tx repository.Tx) error {
		if refs, _ := n.e.IncompletePII(tx, 10); len(refs) != 0 {
			t.Fatalf("an erased field is not incomplete: %+v", refs)
		}
		return nil
	})
}
