package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hostryhq/go-common/events"
	gsync "github.com/hostryhq/go-common/sync"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	"github.com/hostryhq/svc-sync/sim"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

func outboxPayloads(t *testing.T, st repository.Store, typePrefix string) [][]byte {
	t.Helper()
	rs, err := st.DB().QueryContext(bg, `SELECT payload FROM outbox WHERE type LIKE $1 ORDER BY seq`, typePrefix+"%")
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out [][]byte
	for rs.Next() {
		var b []byte
		if err := rs.Scan(&b); err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

// The gateway publishes sync.op.<namespace> through the outbox in the storing transaction, for device ops and for
// emits, and the shared parser reads every one of them.
func TestOpEventsAndEmitOnPostgres(t *testing.T) {
	d := dsn(t)
	adm, err := repository.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer adm.Close()
	clean(t, adm)
	w, err := sim.NewWorld(bg, sim.NewRand(9), sim.WorldOptions{Dir: t.TempDir(), Pos: 2, CloudDSN: appDSN(t, d), Outbox: true})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	rng := sim.NewRand(10)
	for _, dv := range w.Devices {
		if _, err := dv.OrderOp(rng); err != nil {
			t.Fatal(err)
		}
		if _, err := dv.BillOp(rng); err != nil {
			t.Fatal(err)
		}
	}
	if rep := w.Quiesce(bg, 20); !rep.Converged {
		t.Fatal("no quiescence")
	}
	op := func(key, class string) service.EmitOp {
		auth := "menu.tax_class.edit"
		return service.EmitOp{Key: key, Stream: "brand:" + w.Brand, Intent: "menu.tax_class.set", IntentV: 1, Actor: "m1", AuthorisedBy: &auth,
			Muts: []sp.Mut{{E: "item", ID: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f5101", K: sp.KSet, F: map[string]any{"tax_class": class}}}}
	}
	res, err := w.GW.Emit(bg, w.Tenant, "catalog", []service.EmitOp{op("k1", "fnb_standard")})
	if err != nil || len(res) != 1 || res[0].Replayed {
		t.Fatalf("emit: %+v %v", res, err)
	}
	again, err := w.GW.Emit(bg, w.Tenant, "catalog", []service.EmitOp{op("k1", "fnb_standard")})
	if err != nil || !again[0].Replayed || again[0].Seq != res[0].Seq {
		t.Fatalf("replay: %+v %v", again, err)
	}
	if _, err := w.GW.Emit(bg, w.Tenant, "catalog", []service.EmitOp{op("k1", "other")}); err == nil || !strings.Contains(err.Error(), "emit refused") {
		t.Fatalf("same key, other content must be refused: %v", err)
	}
	all := outboxPayloads(t, adm, "sync.op.")
	if len(all) == 0 {
		t.Fatal("nothing was published")
	}
	menu := 0
	for _, raw := range all {
		o, err := gsync.ParseOp(raw)
		if err != nil {
			t.Fatalf("ParseOp refuses a published event: %v", err)
		}
		env, _ := events.Unmarshal(raw)
		if env.Subject() != "evt.sync.op."+o.Namespace+".v1" || env.Key != o.Ref.Stream+"|"+o.Ref.Origin {
			t.Fatalf("subject or key: %s %s", env.Subject(), env.Key)
		}
		if o.Namespace == "menu" && strings.HasPrefix(o.Ref.Origin, "cloud-") {
			menu++
		}
	}
	if menu != 1 {
		t.Fatalf("the emitted op is published exactly once (a replay stores nothing): %d", menu)
	}
}

// emit_dedup and series_numbers are tenant-owned: one tenant never sees another's keys or numbers.
func TestEmitDedupAndRegisterAreTenantIsolated(t *testing.T) {
	admin := dsn(t)
	ast, err := repository.Open(admin)
	if err != nil {
		t.Fatal(err)
	}
	clean(t, ast)
	_ = ast.Close()
	st, err := repository.Open(appDSN(t, admin))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a, b := "018f0000-0000-7000-8000-0000000000a0", "018f0000-0000-7000-8000-0000000000c0"
	if err := st.InTx(bg, a, func(tx repository.Tx) error {
		if err := tx.PutEmit(repository.EmitRec{Caller: "catalog", Key: "k", Content: "c", Origin: "cloud-1", Stream: "brand:b", Seq: 1}); err != nil {
			return err
		}
		return tx.PutRegister(repository.RegisterEntry{Code: "AAA", FY: "2627", Num: 1, Number: "AAA/2627/000001", DocType: "tax_invoice", Origin: "d", Stream: "outlet:o", Seq: 1, State: repository.StAccepted})
	}); err != nil {
		t.Fatal(err)
	}
	_ = st.InTx(bg, b, func(tx repository.Tx) error {
		if _, ok, _ := tx.GetEmit("catalog", "k"); ok {
			t.Error("tenant B sees tenant A's emit key")
		}
		if reg, _ := tx.Register(); len(reg) != 0 {
			t.Error("tenant B sees tenant A's register")
		}
		return nil
	})
	_ = st.InTx(bg, a, func(tx repository.Tx) error {
		if _, ok, _ := tx.GetEmit("catalog", "k"); !ok {
			t.Error("tenant A lost its emit key")
		}
		return nil
	})
}

// A held slot, a flagged op and an erasure are published id-only through the outbox in the storing transaction
// (api-specs events/sync): quarantine.recorded names the series code, number and document type, never content;
// op.flagged carries a coarse code; pii.erased carries ids.
func TestHoldFlagAndEraseEventsOnPostgres(t *testing.T) {
	d := dsn(t)
	adm, err := repository.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer adm.Close()
	clean(t, adm)
	w, err := sim.NewWorld(bg, sim.NewRand(21), sim.WorldOptions{Dir: t.TempDir(), Pos: 2, CloudDSN: appDSN(t, d), Outbox: true})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	rng := sim.NewRand(22)
	a, b := w.Devices[0], w.Devices[1]
	for _, dv := range []*sim.Device{a, b} {
		if _, err := dv.OrderOp(rng); err != nil {
			t.Fatal(err)
		}
	}
	a.SetBadSeries(b.SaleCode()) // a bills in b's series: held as foreign_series
	foreign, err := a.BillOp(rng)
	if err != nil {
		t.Fatal(err)
	}
	a.SetBadSeries("")
	w.Identity.SetSeriesState(w.Tenant, b.SaleCode(), directory.SeriesClosed)
	if _, err := b.BillOp(rng); err != nil { // b bills in its own closed series: kept, flagged
		t.Fatal(err)
	}
	if rep := w.Quiesce(bg, 20); !rep.Converged {
		t.Fatal("no quiescence")
	}
	if _, err := w.GW.ErasePII(bg, w.Tenant, sp.Ref{Origin: foreign.Origin, Stream: foreign.Stream, Seq: foreign.Seq}); err != nil {
		t.Fatal(err)
	}
	type ev struct {
		Type, Key string
		KeySeq    int64
		Data      map[string]any
	}
	read := func(typ string) []ev {
		var out []ev
		for _, raw := range outboxPayloads(t, adm, typ) {
			env, err := events.Unmarshal(raw)
			if err != nil {
				t.Fatalf("%s: %v", typ, err)
			}
			var e ev
			e.Type, e.Key, e.KeySeq = env.Type, env.Key, env.KeySeq
			if err := json.Unmarshal(env.Data, &e.Data); err != nil {
				t.Fatal(err)
			}
			out = append(out, e)
		}
		return out
	}
	q := read("sync.quarantine.recorded")
	if len(q) != 1 || q[0].Data["reason"] != service.ReasonForeignSeries || q[0].Data["series_code"] != b.SaleCode() ||
		q[0].Data["document_type"] == "" || q[0].Data["number"] == "" || q[0].KeySeq != foreign.Seq {
		t.Fatalf("quarantine.recorded: %+v", q)
	}
	for k := range q[0].Data {
		switch k {
		case "origin", "stream", "seq", "reason", "series_code", "number", "document_type":
		default:
			t.Fatalf("quarantine.recorded is id-only; it carries %q", k)
		}
	}
	f := read("sync.op.flagged")
	if len(f) != 1 || f[0].Data["code"] != service.MarkSeriesClosed || len(f[0].Data) != 4 {
		t.Fatalf("op.flagged: %+v", f)
	}
	if e := read("sync.pii.erased"); len(e) != 1 || e[0].Data["origin"] != foreign.Origin || len(e[0].Data) != 3 {
		t.Fatalf("pii.erased: %+v", e)
	}
}
