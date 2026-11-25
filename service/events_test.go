package service_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/go-common/ids"
	gsync "github.com/hostryhq/go-common/sync"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	"github.com/hostryhq/svc-sync/sim"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Everything the gateway publishes as sync.op.<namespace> must be accepted by the one parser every consumer uses
// (go-common/sync.ParseOp): the exact body bytes, the hash, the key, the namespace, the pii without its salts, voids.
func TestPublishedOpEventsParseWithTheSharedParser(t *testing.T) {
	ctx := context.Background()
	w, err := sim.NewWorld(ctx, sim.NewRand(71), sim.WorldOptions{Pos: 1, NoHub: true, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	a := w.Devices[0]
	// A sale with personal data, a re-bill with two numbers, and a configuration op with a forged proof (voided).
	pii := json.RawMessage(`{"check":{"c1":{"customer_phone":"+910000000000"}}}`)
	if _, err := a.Do("m1", engine.Input{Intent: "order.create", PII: pii, Muts: []sp.Mut{{E: "order", ID: "o1", K: sp.KInsert, F: map[string]any{"table": "t1"}}}}); err != nil {
		t.Fatal(err)
	}
	fy := engine.FY(w.Clock.Now())
	if _, err := a.Do("m1", engine.Input{Intent: "bill.rebill", DocType: "credit_note", MutsFn: func(n string) []sp.Mut {
		return []sp.Mut{{E: "credit_note", ID: "cn1", K: sp.KInsert, F: map[string]any{"number": n}},
			{E: "bill", ID: "b1", K: sp.KInsert, F: map[string]any{"number": engine.FormatNumber(a.SaleCode(), fy, 1), "doc_type": "tax_invoice"}}}
	}}); err != nil {
		t.Fatal(err)
	}
	if err := a.SyncCloud(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := w.GW.RecordCloudOp(ctx, w.Tenant, "brand:"+w.Brand, sp.IntentVoid, []sp.Mut{{E: "sync_void", ID: "outlet:" + w.Outlet + "|" + a.ID + "|1", K: sp.KInsert,
		F: map[string]any{"origin": a.ID, "stream": "outlet:" + w.Outlet, "seq": int64(1), "reason": "refused"}}}); err != nil {
		t.Fatal(err)
	}
	var recs []repository.OpRec
	if err := w.GWStore.InTx(ctx, w.Tenant, func(tx repository.Tx) error {
		var err error
		recs, err = tx.ByArrival(0, 100)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	n, sawPII, sawVoid, sawTwoDocs := 0, false, false, false
	for _, rec := range recs {
		if rec.Status != repository.StAccepted && rec.Status != repository.StFlagged {
			continue
		}
		var pii json.RawMessage
		if raw, ok := gwPII(t, w, rec); ok {
			if pii, err = sp.StripSalts(json.RawMessage(raw)); err != nil {
				t.Fatal(err)
			}
		}
		env, err := service.BuildOpEvent(ids.New(), w.Tenant, time.Now(), "epoch-1", rec, pii)
		if err != nil {
			t.Fatalf("%s/%d: %v", rec.Origin, rec.Seq, err)
		}
		raw, err := env.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		op, err := gsync.ParseOp(raw)
		if err != nil {
			t.Fatalf("ParseOp refuses what the gateway emits (%s %s/%d): %v", env.Type, rec.Origin, rec.Seq, err)
		}
		if op.H != rec.H || op.Ref.Seq != rec.Seq || op.Ref.Origin != rec.Origin || op.Intent != rec.Intent || op.Status != rec.Status ||
			env.Subject() != "evt.sync.op."+service.Namespace(rec.Intent)+".v1" {
			t.Fatalf("parsed op differs from the stored one: %+v vs %+v", op, rec)
		}
		var data struct {
			Body string `json:"body"`
		}
		_ = json.Unmarshal(env.Data, &data)
		if data.Body != rec.Body {
			t.Fatal("the event must carry the exact body bytes")
		}
		n++
		if op.PII["check"]["c1"]["customer_phone"] == "+910000000000" {
			sawPII = true
			if strings.Contains(string(env.Data), "~s:") {
				t.Fatal("a salt reached the bus")
			}
		}
		sawVoid = sawVoid || len(op.Voids) == 1
		sawTwoDocs = sawTwoDocs || (op.Doc != nil && len(op.Muts) == 2)
	}
	if n < 3 || !sawPII || !sawVoid || !sawTwoDocs {
		t.Fatalf("ops %d pii %v void %v rebill %v", n, sawPII, sawVoid, sawTwoDocs)
	}
}

func gwPII(t *testing.T, w *sim.World, rec repository.OpRec) (string, bool) {
	t.Helper()
	var raw string
	var ok bool
	if err := w.GWStore.InTx(context.Background(), w.Tenant, func(tx repository.Tx) error {
		var err error
		raw, ok, err = tx.GetPII(rec.Stream, rec.Origin, rec.Seq)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return raw, ok
}
