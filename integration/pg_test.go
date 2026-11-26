// Package integration runs the gateway against the real Postgres of the dev stack
// (infra/dev/compose.yaml). Skipped unless SYNC_PG_DSN is set, for example
//
//	SYNC_PG_DSN=postgres://hostry:hostry-dev-only@127.0.0.1:15432/hostry go test ./integration
//
// (the password is the dev stack's throwaway credential, not a secret).
package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"

	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/outbox"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	"github.com/hostryhq/svc-sync/sim"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

var bg = context.Background()

func dsn(t *testing.T) string {
	d := os.Getenv("SYNC_PG_DSN")
	if d == "" {
		t.Skip("SYNC_PG_DSN not set: no Postgres dev stack")
	}
	return d
}

// appDSN migrates with the admin DSN, creates the non-superuser role the service runs as (a
// superuser bypasses row-level security, which would make every isolation test meaningless) and
// returns a DSN for it. The role password is a throwaway dev value.
func appDSN(t *testing.T, admin string) string {
	t.Helper()
	st, err := repository.Open(admin)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, q := range []string{
		`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sync_app') THEN CREATE ROLE sync_app LOGIN PASSWORD 'sync-app-dev-only'; END IF; END $$`,
		`GRANT USAGE, CREATE ON SCHEMA public TO sync_app`,
		`GRANT ALL ON ALL TABLES IN SCHEMA public TO sync_app`,
		`GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO sync_app`,
	} {
		if _, err := st.DB().ExecContext(bg, q); err != nil {
			t.Fatal(err)
		}
	}
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("sync_app", "sync-app-dev-only")
	return u.String()
}

func clean(t *testing.T, st repository.Store) {
	t.Helper()
	_, err := st.DB().ExecContext(bg, `TRUNCATE ops, op_pii, seals, counters, meta, sessions, numbers, series_register, forks, recoveries, alerts, outbox, endorsements, attestations, restore_state, vendor_access_log, audit_log, approval_verdicts, drain_statements, series_numbers, emit_dedup`)
	if err != nil {
		t.Fatal(err)
	}
	// The epoch the dev world stamps into its platform database (the same instance here).
	if _, err := st.DB().ExecContext(bg, `DROP TABLE IF EXISTS restore_epoch`); err != nil {
		t.Fatal(err)
	}
}

func TestSimulatedRunsOnPostgres(t *testing.T) {
	d := dsn(t)
	feat := sim.AllFeatures
	feat.Rollback = false // the rollback scenario copies a SQLite file; Postgres restore is the DR drill (1e-3)
	for seed := uint64(1); seed <= 6; seed++ {
		st, err := repository.Open(d)
		if err != nil {
			t.Fatal(err)
		}
		clean(t, st)
		_ = st.Close()
		res, err := sim.Run(bg, sim.Options{Seed: seed, Steps: 250, Pos: 2, Waiters: 2, KDS: 1, Features: feat, CloudDSN: appDSN(t, d), Trace: true})
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for _, p := range res.Problems {
			t.Errorf("seed %d: %s", seed, p)
		}
	}
}

func TestRowLevelSecurityIsolatesTenants(t *testing.T) {
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
	put := func(tenant string) {
		err := st.InTx(bg, tenant, func(tx repository.Tx) error {
			return tx.PutOp(repository.OpRec{Stream: "outlet:o", Origin: "d1", Seq: 1, H: "h", PH: "p", Body: "{}", Status: repository.StAccepted})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	put(a)
	put(b) // same key, other tenant: both rows exist
	count := func(tenant string) int {
		n := 0
		_ = st.InTx(bg, tenant, func(tx repository.Tx) error {
			h, err := tx.Heads()
			n = len(h)
			return err
		})
		return n
	}
	if count(a) != 1 || count(b) != 1 || count("018f0000-0000-7000-8000-0000000000d0") != 0 {
		t.Fatal("each tenant sees only its own rows")
	}
	// Even a query that forgets the tenant predicate sees nothing without the tenant context.
	var n int
	if err := st.DB().QueryRowContext(bg, `SELECT count(*) FROM ops`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("no tenant context must see no rows, saw %d (%v)", n, err)
	}
	// Even with the predicate of tenant B, tenant A's context cannot read B's row.
	err = st.InTx(bg, a, func(tx repository.Tx) error {
		return tx.SQLTx().QueryRowContext(bg, `SELECT count(*) FROM ops WHERE tenant_id = $1`, b).Scan(&n)
	})
	if err != nil || n != 0 {
		t.Fatalf("cross-tenant read through a forged predicate returned %d rows (%v)", n, err)
	}
}

func TestOutboxRowIsWrittenInTheSameTransactionAsTheOp(t *testing.T) {
	admin := dsn(t)
	adm, err := repository.Open(admin)
	if err != nil {
		t.Fatal(err)
	}
	defer adm.Close()
	clean(t, adm)
	st, err := repository.Open(appDSN(t, admin))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tenant := "018f0000-0000-7000-8000-0000000000a0"
	env := func() events.Envelope {
		return events.Envelope{ID: ids.New(), Type: "sync.op.stored", V: 1, Source: "sync", TenantID: ids.ID(tenant), Key: "d1/outlet:o", KeySeq: 1,
			OccurredAt: time.Now(), Data: []byte(`{}`)}
	}
	failing := errors.New("boom")
	err = st.InTx(bg, tenant, func(tx repository.Tx) error {
		if err := tx.PutOp(repository.OpRec{Stream: "outlet:o", Origin: "d1", Seq: 1, H: "h", PH: "p", Body: "{}", Status: repository.StAccepted}); err != nil {
			return err
		}
		if err := outbox.Publish(bg, tx.SQLTx(), env()); err != nil {
			return err
		}
		return failing
	})
	if !errors.Is(err, failing) {
		t.Fatal(err)
	}
	if ops, out := rows(t, adm, "ops"), rows(t, adm, "outbox"); ops != 0 || out != 0 {
		t.Fatalf("a rolled-back transaction must store and publish nothing: ops=%d outbox=%d", ops, out)
	}
	_ = st.InTx(bg, tenant, func(tx repository.Tx) error {
		if err := tx.PutOp(repository.OpRec{Stream: "outlet:o", Origin: "d1", Seq: 1, H: "h", PH: "p", Body: "{}", Status: repository.StAccepted}); err != nil {
			t.Fatal(err)
		}
		return outbox.Publish(bg, tx.SQLTx(), env())
	})
	if ops, out := rows(t, adm, "ops"), rows(t, adm, "outbox"); ops != 1 || out != 1 {
		t.Fatalf("committed together: ops=%d outbox=%d", ops, out)
	}
}

// TestGatewayPublishesAcceptedOpsToTheOutbox drives the real gateway on Postgres and counts events.
func TestGatewayPublishesAcceptedOpsToTheOutbox(t *testing.T) {
	d := dsn(t)
	adm, err := repository.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer adm.Close()
	clean(t, adm)
	w, err := sim.NewWorld(bg, sim.NewRand(7), sim.WorldOptions{Dir: t.TempDir(), Pos: 2, CloudDSN: appDSN(t, d), Outbox: true})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	rng := sim.NewRand(8)
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
	accepted, out := rows(t, adm, "ops WHERE status IN ('accepted','flagged') AND origin NOT LIKE 'cloud-%'"), rows(t, adm, "outbox")
	if accepted == 0 || out != accepted {
		t.Fatalf("every accepted op has exactly one outbox event: accepted=%d outbox=%d", accepted, out)
	}
	for _, p := range w.CheckAll(bg, nil) {
		t.Error(p)
	}
}

func rows(t *testing.T, st repository.Store, from string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(bg, "SELECT count(*) FROM "+from).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

var _ = sp.ProtocolVersion
var _ *sql.DB

// A role that bypasses row-level security is refused at start-up; the service role passes.
func TestStartupRefusesARoleThatBypassesRowLevelSecurity(t *testing.T) {
	admin := dsn(t)
	ast, err := repository.Open(admin)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ast.Close() }()
	if err := ast.CheckAppRole(bg); !errors.Is(err, repository.ErrPrivilegedRole) {
		t.Fatalf("the dev stack's admin role must be refused, got %v", err)
	}
	st, err := repository.Open(appDSN(t, admin))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CheckAppRole(bg); err != nil {
		t.Fatalf("the service role must pass: %v", err)
	}
}

// The audit tables are tenant tables: another tenant's context, a forged predicate and no context at all
// see none of their rows.
func TestAuditTablesAreRowLevelIsolated(t *testing.T) {
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
	sink := &repository.AccessSink{S: st}
	for i, tenant := range []string{a, b} {
		err := st.InTx(bg, tenant, func(tx repository.Tx) error {
			if err := tx.PutAudit(repository.AuditRec{ID: ids.New().String(), At: time.Now(), Actor: "m", ActorType: "user", Action: "release", Origin: "d", Stream: "outlet:o", Seq: int64(i + 1), Reason: "r", Before: "quarantined", After: "accepted"}); err != nil {
				return err
			}
			return sink.RecordInTx(bg, tx.SQLTx(), auth.VendorAccessEntry{ID: ids.New(), Time: time.Now(), TenantID: tenant, VendorUser: "v", TokenType: auth.TypeSupport, ActionKey: "x", Outcome: auth.OutcomeOK})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"audit_log", "vendor_access_log"} {
		var n int
		if err := st.DB().QueryRowContext(bg, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s with no tenant context: %d rows (%v)", table, n, err)
		}
		err := st.InTx(bg, a, func(tx repository.Tx) error {
			return tx.SQLTx().QueryRowContext(bg, "SELECT count(*) FROM "+table+" WHERE tenant_id = $1", b).Scan(&n)
		})
		if err != nil || n != 0 {
			t.Fatalf("%s: tenant A read %d rows of tenant B through a forged predicate (%v)", table, n, err)
		}
		err = st.InTx(bg, a, func(tx repository.Tx) error {
			return tx.SQLTx().QueryRowContext(bg, "SELECT count(*) FROM "+table).Scan(&n)
		})
		if err != nil || n != 1 {
			t.Fatalf("%s: tenant A sees %d rows, want its own 1 (%v)", table, n, err)
		}
	}
}

// The audited transaction of go-auth commits the decision, its audit record and the vendor access row
// together on Postgres.
func TestSupportConfirmIsAuditedOnPostgres(t *testing.T) {
	d := dsn(t)
	adm, err := repository.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adm.Close() }()
	clean(t, adm)
	w, err := sim.NewWorld(bg, sim.NewRand(9), sim.WorldOptions{Dir: t.TempDir(), Pos: 2, CloudDSN: appDSN(t, d)})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	a, b := w.Devices[0], w.Devices[1]
	a.SetBadSeries(b.SaleCode())
	it, err := a.Do("m1", engine.Input{Intent: "bill.finalize", DocType: "tax_invoice", MutsFn: func(n string) []sp.Mut {
		return []sp.Mut{{E: "bill", ID: "b-pg-1", K: sp.KInsert, F: map[string]any{"number": n, "total_paise": int64(100)}}}
	}})
	a.SetBadSeries("")
	if err != nil {
		t.Skipf("the simulator cannot stage a foreign-series bill here: %v", err)
	}
	if err := a.SyncCloud(bg); err != nil {
		t.Fatal(err)
	}
	svc, err := w.Services.Signer("admin").Sign("sync", w.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	tok := w.Issuer.Mint(authtest.Spec{Type: auth.TypeSupport, Tenant: ids.ID(w.Tenant), Mode: auth.ModeAct, Grants: authtest.Grants(nil, service.PermQuarantineConfirm)})
	body, _ := json.Marshal(map[string]any{"origin": it.Origin, "stream": it.Stream, "seq": it.Seq, "reason": "cause confirmed", "h": it.H})
	req := httptest.NewRequest(http.MethodPost, "/sync/v1/quarantine/confirm", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(auth.ServiceTokenHeader, svc)
	rec := httptest.NewRecorder()
	w.CloudH.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	if n, v := rows(t, adm, "audit_log WHERE action = 'confirm'"), rows(t, adm, "vendor_access_log WHERE outcome = 'ok'"); n != 1 || v != 1 {
		t.Fatalf("one audit record and one vendor access row, got %d and %d", n, v)
	}
}
