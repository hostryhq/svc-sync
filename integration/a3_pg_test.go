package integration

import (
	"strings"
	"testing"

	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/sim"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// ADR-0005 A3: the session verdict row, the approval verdict and the drain statement are tenant-owned (row-level
// security), a final verdict is never overwritten (identity is asked once), and a pending one is.
func TestSessionVerdictsAndDrainStatementsOnPostgres(t *testing.T) {
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
	row := repository.SessionRow{Origin: "dev-1", SID: "s1", Type: sp.SessionPin, Actor: "m1", PackV: 3, PinV: 2, OpenedAt: "2026-11-25T06:00:00.000Z", Verdict: repository.VerdictPending}
	if err := st.InTx(bg, a, func(tx repository.Tx) error {
		if err := tx.PutSessionRow(row); err != nil {
			return err
		}
		pend, err := tx.PendingSessions()
		if err != nil || len(pend) != 1 || pend[0].PackV != 3 || pend[0].PinV != 2 {
			t.Errorf("pending sessions: %+v %v", pend, err)
		}
		row.Verdict = repository.VerdictInvalid
		if err := tx.PutSessionRow(row); err != nil { // pending -> final
			return err
		}
		row.Verdict = repository.VerdictValid
		if err := tx.PutSessionRow(row); err != nil { // final stays
			return err
		}
		got, ok, err := tx.GetSession("dev-1", "s1")
		if err != nil || !ok || got.Verdict != repository.VerdictInvalid || got.Actor != "m1" {
			t.Errorf("a final verdict is kept: %+v %v %v", got, ok, err)
		}
		if err := tx.PutApprovalVerdict("dev-1", "ap-1", repository.VerdictValid); err != nil {
			return err
		}
		return tx.PutDrain(repository.DrainRec{Origin: "dev-1", Hash: strings.Repeat("a", 64), Statement: `{"origin":"dev-1"}`, State: repository.DrainSatisfied})
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.InTx(bg, b, func(tx repository.Tx) error {
		if _, ok, _ := tx.GetSession("dev-1", "s1"); ok {
			t.Error("tenant B sees tenant A's session verdict")
		}
		if _, ok, _ := tx.GetApprovalVerdict("dev-1", "ap-1"); ok {
			t.Error("tenant B sees tenant A's approval verdict")
		}
		if ds, _ := tx.Drains("dev-1"); len(ds) != 0 {
			t.Error("tenant B sees tenant A's drain statement")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.InTx(bg, a, func(tx repository.Tx) error {
		ds, err := tx.DrainsByState(repository.DrainSatisfied)
		if err != nil || len(ds) != 1 {
			t.Errorf("tenant A's statement: %+v %v", ds, err)
		}
		return tx.SetDrainState("dev-1", strings.Repeat("a", 64), repository.DrainReported)
	}); err != nil {
		t.Fatal(err)
	}
}

// The whole drain over Postgres: a revoked device's ops and its signed statement, with the gateway on the real store.
func TestDrainStatementOverPostgres(t *testing.T) {
	d := dsn(t)
	adm, err := repository.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	clean(t, adm)
	_ = adm.Close()
	w, err := sim.NewWorld(bg, sim.NewRand(12), sim.WorldOptions{Dir: t.TempDir(), Pos: 1, NoHub: true, CloudDSN: appDSN(t, d)})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	a := w.Devices[0]
	rng := sim.NewRand(13)
	if _, err := a.OrderOp(rng); err != nil {
		t.Fatal(err)
	}
	if _, err := a.BillOp(rng); err != nil {
		t.Fatal(err)
	}
	w.Identity.Revoke(a.ID, "revoked")
	if ok, err := w.Drain(bg, a); err != nil || !ok {
		t.Fatalf("the statement of a device that holds exactly what the gateway holds drains it: %v %v", ok, err)
	}
	if rep, ok := w.Identity.DrainReportOf(a.ID); !ok || len(rep.Statement) == 0 {
		t.Fatalf("identity was told with the statement: %+v", rep)
	}
}
