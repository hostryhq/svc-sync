package sim

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hostryhq/svc-sync/engine"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// PP1 (ADR-0002 A3.6): with the placement switch off, a `pos` whose credential says `store: unprotected` pulls another origin's
// personal data from neither the hub nor the gateway: it receives the commitments only and its rows are pii_incomplete, while its
// own personal data is unaffected. With the dev switch on, the same device receives it (the soak's T1 placement check).
func TestPP1_AnUnprotectedTillReceivesCommitmentsOnlyFromHubAndGateway(t *testing.T) {
	for _, tc := range []struct {
		name string
		lift bool
	}{{"rule on", false}, {"dev switch lifts it", true}} {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := newTestWorld(t, 503, WorldOptions{Pos: 1, PIILift: tc.lift})
			a := w.Devices[0]
			b := must(w.AddDeviceStore("dev-unprotected", sp.KindPOS, sp.StoreUnprotected))
			it := must(a.Do(pCashier, engine.Input{Intent: "check.create",
				PII:  json.RawMessage(`{"check":{"c1":{"customer_name":"Meera","customer_phone":"+919876543210"}}}`),
				Muts: []sp.Mut{{E: "check", ID: "c1", K: sp.KInsert, F: map[string]any{"label": "Guest 1"}}}}))
			// Its own personal data: made on the unprotected till, relayed to the others, never lost to it.
			own := must(b.Do(pCashier, engine.Input{Intent: "check.create",
				PII:  json.RawMessage(`{"check":{"c2":{"customer_name":"Own Guest","customer_phone":"+919800000002"}}}`),
				Muts: []sp.Mut{{E: "check", ID: "c2", K: sp.KInsert, F: map[string]any{"label": "Guest 2"}}}}))
			for i := 0; i < 3; i++ {
				for _, d := range []*Device{a, b} {
					if err := d.SyncHub(bg); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := w.Hub.SyncUpstream(bg); err != nil {
				t.Fatal(err)
			}
			w.toCloud(t, a)
			for i := 0; i < 2; i++ { // the hub path and the direct cloud path
				if err := b.SyncCloud(bg); err != nil {
					t.Fatal(err)
				}
				if err := b.SyncHub(bg); err != nil {
					t.Fatal(err)
				}
			}
			raw, got := w.piiOf(t, b.Eng, it)
			if tc.lift {
				if !got || !strings.Contains(raw, "Meera") {
					t.Fatalf("with the dev switch on the unprotected till holds the values: %q %v", raw, got)
				}
			} else {
				if got {
					t.Fatalf("an unprotected till received another origin's personal data: %q", raw)
				}
				if refs := incomplete(t, b.Eng); len(refs) == 0 {
					t.Fatal("the row must be pii_incomplete on the unprotected till")
				}
				row, ok := b.Eng.State().Row("check", "c1")
				if !ok || row["~c:customer_phone"] == nil || row["customer_phone"] != nil {
					t.Fatalf("the commitment arrives and no value is in the row: %v", row)
				}
			}
			if raw, ok := w.piiOf(t, b.Eng, own); !ok || !strings.Contains(raw, "Own Guest") {
				t.Fatalf("its own personal data is unaffected: %q %v", raw, ok)
			}
			if raw, ok := w.piiOf(t, a.Eng, own); !ok || !strings.Contains(raw, "Own Guest") {
				t.Fatalf("the protected till receives the unprotected till's personal data (the rule is about the puller): %q %v", raw, ok)
			}
		})
	}
}
