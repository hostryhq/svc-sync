package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/sim"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// P2-M1: erased personal data must not survive in the outbox, so a republish after a bus reset (every row inside the retention
// horizon marked unpublished again) carries no value and no salt.
func TestErasedPIIIsScrubbedFromTheOutboxBeforeARepublish(t *testing.T) {
	d := dsn(t)
	adm, err := repository.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer adm.Close()
	clean(t, adm)
	w, err := sim.NewWorld(bg, sim.NewRand(41), sim.WorldOptions{Dir: t.TempDir(), Pos: 1, NoHub: true, CloudDSN: appDSN(t, d), Outbox: true})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	a := w.Devices[0]
	it, err := a.Do("m1", engine.Input{Intent: "check.create",
		PII:  json.RawMessage(`{"check":{"c1":{"customer_name":"Meera Test","customer_phone":"+910000000000"}}}`),
		Muts: []sp.Mut{{E: "check", ID: "c1", K: sp.KInsert, F: map[string]any{"label": "Guest 1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SyncCloud(bg); err != nil {
		t.Fatal(err)
	}
	holds := func() int {
		var n int
		if err := adm.DB().QueryRowContext(bg, `SELECT count(*) FROM outbox WHERE convert_from(payload,'UTF8') LIKE '%Meera Test%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if holds() == 0 {
		t.Fatal("test needs the outbox to hold the value before the erasure")
	}
	if _, err := w.GW.ErasePII(bg, w.Tenant, sp.Ref{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq}); err != nil {
		t.Fatal(err)
	}
	// A bus reset marks every row of the horizon unpublished again.
	if _, err := adm.DB().ExecContext(bg, `UPDATE outbox SET published_at = NULL`); err != nil {
		t.Fatal(err)
	}
	if n := holds(); n != 0 {
		t.Fatalf("%d outbox rows still hold the erased value", n)
	}
	var salts int
	if err := adm.DB().QueryRowContext(bg, `SELECT count(*) FROM outbox WHERE strpos(convert_from(payload,'UTF8'), '~s:customer_name') > 0`).Scan(&salts); err != nil {
		t.Fatal(err)
	}
	if salts != 0 {
		t.Fatalf("%d outbox rows still hold the salt of an erased field", salts)
	}
	var kept int
	if err := adm.DB().QueryRowContext(bg, `SELECT count(*) FROM outbox WHERE type LIKE 'sync.op.%' AND strpos(convert_from(payload,'UTF8'), $1) > 0`, strings.ToLower(it.Origin)).Scan(&kept); err != nil || kept == 0 {
		t.Fatalf("the event itself stays (ids and commitments): %d %v", kept, err)
	}
}
