package sim

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hostryhq/svc-sync/engine"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// P2-L2: a pii value that does not match its commitment is dropped and a vendor alert names the origin.
func TestPIICommitmentMismatchRaisesAnAlertPerOrigin(t *testing.T) {
	w, _ := newTestWorld(t, 64, WorldOptions{Pos: 1, NoHub: true})
	a := w.Devices[0]
	it := must(a.Do(pCashier, engine.Input{Intent: "order.create", PII: json.RawMessage(`{"check":{"c1":{"customer_phone":"+910000000000"}}}`),
		Muts: []sp.Mut{{E: "order", ID: a.nextID("o"), K: sp.KInsert, F: map[string]any{"table": "t1"}}}}))
	req, err := a.Eng.Outbound(bg, sp.Vector{}, engine.OutboundOpts{})
	if err != nil || len(req.Items) == 0 {
		t.Fatalf("outbound: %v %d", err, len(req.Items))
	}
	for i := range req.Items {
		if len(req.Items[i].PII) > 0 {
			req.Items[i].PII = json.RawMessage(strings.ReplaceAll(string(req.Items[i].PII), "+910000000000", "+911111111111"))
		}
	}
	if _, err := w.GW.Push(bg, w.Tenant, engine.Caller{ID: a.ID, Kind: sp.KindPOS, Outlet: w.Outlet, Brand: w.Brand}, req); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, al := range must(w.GW.Alerts(bg, w.Tenant)) {
		found = found || (al.Audience == "vendor" && al.Kind == "pii_commitment_mismatch" && strings.HasPrefix(al.Detail, it.Origin+"/"))
	}
	if !found {
		t.Fatal("a vendor alert pii_commitment_mismatch naming the origin is expected")
	}
}
