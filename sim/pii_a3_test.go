package sim

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

func (w *World) piiOf(t *testing.T, e *engine.Engine, it sp.Item) (string, bool) {
	t.Helper()
	var raw string
	var ok bool
	if err := e.Config().Store.InTx(bg, w.Tenant, func(tx repository.Tx) error {
		var err error
		raw, ok, err = tx.GetPII(it.Stream, it.Origin, it.Seq)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return raw, ok
}

func devicesByKind(w *World) (pos []*Device, kds *Device) {
	for _, d := range w.Devices {
		if d.Kind == sp.KindKDS {
			kds = d
		} else if d.Kind == sp.KindPOS {
			pos = append(pos, d)
		}
	}
	return
}

// PA2, PA3 and X2 of ADR-0014 A3: a second till gets another till's buyer details from the hub alone (internet cut), a
// kitchen screen gets none, every node's state hash is equal, and an erasure removes the values everywhere without changing
// any hash.
func TestPA2_BuyerDetailsReachAnotherTillThroughTheHubAndNeverAKDS(t *testing.T) {
	w, _ := newTestWorld(t, 501, WorldOptions{Pos: 2, KDS: 1})
	pos, k := devicesByKind(w)
	a, b := pos[0], pos[1]
	it := must(a.Do(pCashier, engine.Input{Intent: "check.create",
		PII:  json.RawMessage(`{"check":{"c-gst":{"customer_name":"Meera Traders","customer_gstin":"33AAAAA0000A1Z5"}}}`),
		Muts: []sp.Mut{{E: "check", ID: "c-gst", K: sp.KInsert, F: map[string]any{"label": "B2B 1"}}}}))
	for _, d := range []*Device{a, b, k, a, b, k} { // no cloud contact at all: devices and hub only
		if err := d.SyncHub(bg); err != nil {
			t.Fatalf("%s: %v", d.ID, err)
		}
	}
	if raw, ok := w.piiOf(t, w.Hub.Engine(), it); !ok || !strings.Contains(raw, "33AAAAA0000A1Z5") {
		t.Fatalf("the hub relays and holds the buyer details: %q %v", raw, ok)
	}
	if raw, ok := w.piiOf(t, b.Eng, it); !ok || !strings.Contains(raw, "33AAAAA0000A1Z5") || !strings.Contains(raw, "Meera Traders") {
		t.Fatalf("the second till must hold the GSTIN to reprint the invoice offline: %q %v", raw, ok)
	}
	if raw, ok := w.piiOf(t, k.Eng, it); ok {
		t.Fatalf("a kds holds no personal data: %q", raw)
	}
	_ = k.Eng.Config().Store.InTx(bg, w.Tenant, func(tx repository.Tx) error {
		if refs, _ := k.Eng.IncompletePII(tx, 10); len(refs) != 0 {
			t.Fatalf("a kds fetches nothing: %+v", refs)
		}
		return nil
	})
	if refs := incomplete(t, b.Eng); len(refs) != 0 {
		t.Fatalf("nothing is pii_incomplete at the end: %+v", refs)
	}
	want := a.Eng.StateHash()
	for name, e := range map[string]*engine.Engine{"second till": b.Eng, "kds": k.Eng, "hub": w.Hub.Engine()} {
		if e.StateHash() != want {
			t.Fatalf("%s: state hash %s differs from the origin's %s", name, e.StateHash(), want)
		}
	}
	// The hub reaches the cloud; the cloud holds the values and the same row.
	if _, err := w.Hub.SyncUpstream(bg); err != nil {
		t.Fatal(err)
	}
	if raw, ok := w.gwPII(t, it); !ok || !strings.Contains(raw, "Meera Traders") {
		t.Fatalf("the cloud holds the values: %q %v", raw, ok)
	}
	// Erasure: the cloud-signed op reaches the hub and every device; the hash is the same before and after (X2).
	if _, err := w.GW.ErasePII(bg, w.Tenant, sp.Ref{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Hub.SyncUpstream(bg); err != nil {
		t.Fatal(err)
	}
	for _, d := range []*Device{a, b, k, a, b, k} {
		if err := d.SyncHub(bg); err != nil {
			t.Fatal(err)
		}
	}
	for name, e := range map[string]*engine.Engine{"origin": a.Eng, "second till": b.Eng, "hub": w.Hub.Engine()} {
		if _, ok := w.piiOf(t, e, it); ok {
			t.Fatalf("%s still holds the erased values", name)
		}
	}
	for name, e := range map[string]*engine.Engine{"origin": a.Eng, "second till": b.Eng, "kds": k.Eng, "hub": w.Hub.Engine()} {
		if e.StateHash() != want {
			t.Fatalf("%s: the state hash changed when the field was erased: %s, was %s", name, e.StateHash(), want)
		}
		row, ok := e.State().Row("check", "c-gst")
		if !ok || row["~c:customer_gstin"] == nil || row["customer_gstin"] != nil {
			t.Fatalf("%s: the commitment stays and no value is in the row: %v", name, row)
		}
	}
}

func incomplete(t *testing.T, e *engine.Engine) []sp.Ref {
	t.Helper()
	var refs []sp.Ref
	if err := e.Config().Store.InTx(context.Background(), e.Config().Tenant, func(tx repository.Tx) error {
		var err error
		refs, err = e.IncompletePII(tx, 10)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return refs
}
