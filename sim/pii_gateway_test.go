package sim

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hostryhq/svc-sync/engine"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// PA1 at the cloud: a pull and a snapshot answered to a kds carry the commitments and no pii; to a pos, waiter, personal or hub
// caller of the outlet they carry the values with their salts; a caller of another outlet gets nothing of the stream.
func TestPA1_GatewayPullAndSnapshotCarryNoPIIToAKDS(t *testing.T) {
	w, _ := newTestWorld(t, 502, WorldOptions{Pos: 1, KDS: 1, NoHub: true})
	pos, _ := devicesByKind(w)
	a := pos[0]
	it := must(a.Do(pCashier, engine.Input{Intent: "check.create",
		PII:  json.RawMessage(`{"check":{"c1":{"customer_name":"Meera","customer_phone":"+919876543210"}}}`),
		Muts: []sp.Mut{{E: "check", ID: "c1", K: sp.KInsert, F: map[string]any{"label": "Guest 1"}}}}))
	w.toCloud(t, a)
	for _, tc := range []struct {
		kind   string
		served bool
	}{{sp.KindPOS, true}, {sp.KindWaiter, true}, {sp.KindPersonal, true}, {sp.KindHub, true}, {sp.KindKDS, false}} {
		c := engine.Caller{ID: "x-" + tc.kind, Kind: tc.kind, Outlet: w.Outlet, Brand: w.Brand}
		resp, err := w.GW.Pull(bg, w.Tenant, c, sp.PullRequest{Vector: sp.Vector{}, Limit: 500})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, x := range resp.Items {
			if x.Origin != it.Origin || x.Seq != it.Seq || x.Stream != it.Stream {
				continue
			}
			found = true
			if got := len(x.PII) > 0; got != tc.served {
				t.Fatalf("pull to %s: pii=%v, want %v", tc.kind, got, tc.served)
			}
			if tc.served && !strings.Contains(string(x.PII), "~s:customer_name") {
				t.Fatalf("pull to %s: the salts travel with the values: %s", tc.kind, x.PII)
			}
			if !strings.Contains(x.Body, `"pii_c"`) {
				t.Fatalf("pull to %s: the commitments are in the body", tc.kind)
			}
		}
		if !found {
			t.Fatalf("pull to %s did not serve the op", tc.kind)
		}
		snap, err := w.GW.Snapshot(bg, w.Tenant, c)
		if err != nil {
			t.Fatal(err)
		}
		var row *sp.SnapshotRow
		for i := range snap.Rows {
			if snap.Rows[i].Entity == "check" && snap.Rows[i].ID == "c1" {
				row = &snap.Rows[i]
			}
		}
		if row == nil || row.PIIC["customer_name"] == "" || row.PIIC["customer_phone"] == "" {
			t.Fatalf("snapshot to %s: a row carries pii_c always: %+v", tc.kind, row)
		}
		if tc.served != (row.PII["customer_name"] == "Meera" && row.PII["~s:customer_name"] != nil) {
			t.Fatalf("snapshot to %s: pii %v, served=%v", tc.kind, row.PII, tc.served)
		}
		if _, leaked := row.Fields["customer_name"]; leaked {
			t.Fatalf("snapshot to %s: a pii value must never be in the row's fields", tc.kind)
		}
	}
}
