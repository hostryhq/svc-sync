// Package repository is the persistence layer of the sync op store. One implementation serves
// both Postgres (gateway) and SQLite (hub and simulator devices); queries are written with `?`
// placeholders and rebound for Postgres. Every query is scoped by tenant_id; on Postgres the
// tenant is also set as app.tenant_id so row-level security applies (ADR-0003 section 6).
package repository

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // postgres driver
	_ "modernc.org/sqlite"             // pure-Go SQLite, no CGO (ADR-0002 S8)
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Op statuses (S11). placeholder and held_local are node-local states: a slot known only by hash,
// and a hub-held op that failed a structural check and is not relayed to peers.
const (
	StAccepted    = "accepted"
	StFlagged     = "flagged"
	StQuarantined = "quarantined"
	StVoided      = "voided"
	StPlaceholder = "placeholder"
	StHeldLocal   = "held_local"
)

// OpRec is one stored slot.
type OpRec struct {
	Tenant, Stream, Origin string
	Seq                    int64
	H, PH, Body            string
	Status, Reason, Marks  string
	Intent, HLC            string
	Arr                    int64
}

// EmitRec is the idempotency record of one emitted op: (tenant, caller, key) -> where it landed.
type EmitRec struct {
	Caller, Key, Content, Origin, Stream string
	Seq                                  int64
}

// EndorsementRec is a stored gateway endorsement (ADR-0002 A2.1).
type EndorsementRec struct {
	Stream, Origin string
	Seq            int64
	H, Rec, Kid    string
	Sig            string
}

// AttestationRec is a stored attestation of an adopting device.
type AttestationRec struct {
	Stream, Origin, Rec string
	Seq                 int64
	H, By, Kid, Sig     string
}

// SealRec is a stored seal.
type SealRec struct {
	Stream, Origin string
	Seq            int64
	H, Kid, Sig    string
}

// HasBody reports whether the slot holds the op body (not a placeholder).
func (o OpRec) HasBody() bool { return o.Body != "" }

// HeadRow is the highest slot of one (stream, origin).
type HeadRow struct {
	Stream, Origin string
	Seq            int64
}

// RegisterEntry is one row of the cloud series register.
type RegisterEntry struct {
	Tenant, Code, FY, Number, DocType, Origin, Stream string
	// DocID is the id of the bill or credit note row that carries the number ("" for a row written before it was kept).
	DocID       string
	Num, Seq    int64
	State, Mark string
}

// Recovery mirrors identity's record of a key-loss recovery.
type Recovery struct {
	Tenant, RecID, OldDevice, NewDevice string
	Attested                            string
	Drained                             bool
}

// Session verdicts (ADR-0005 A3.1 item 3). Empty means identity has not been asked yet (the open was held before
// its proof was judged).
const (
	VerdictValid   = "valid"
	VerdictInvalid = "invalid"
	VerdictLocked  = "locked"
	VerdictPending = "pending"
)

// SessionRow is one session of an origin: who opened it, under which pack and PIN version and when, and identity's
// verdict on its proof. One row per (tenant, origin, sid), whatever stream the ops of the session are in.
type SessionRow struct {
	Origin, SID, Type, Actor string
	PackV, PinV              int
	OpenedAt                 string
	Verdict                  string
}

// ApprovalRow is one approval of an origin (ADR-0014 A3.3 item 1): the record the approval op carries, identity's
// verdict on its proof and the op that cites it. One row per (tenant, origin, approval id).
type ApprovalRow struct {
	Origin, ID, Verdict string
	// Kind is the intent of the approving op: approval.grant or approval.self_confirm.
	Kind, SID, Intent, Permission, Target, ActionHash, Requester, Approver, Reason string
	// ApprovedAt is the `at` of the approving op.
	ApprovedAt string
	// Citer is "stream|origin|seq" of the op that cites the approval; CiterHLC its clock.
	Citer, CiterHLC string
}

// Drain statement states (ADR-0005 A3.3).
const (
	DrainSatisfied = "satisfied" // every check held; the report to identity is pending
	DrainReported  = "reported"  // identity has recorded it
	DrainRefused   = "refused"   // kept as fork evidence; nothing was reported
)

// DrainRec is a device-signed drain statement the gateway holds.
type DrainRec struct {
	Origin, Hash, Statement, State, Detail string
}

// Alert is an owner or vendor alert raised by a verdict.
type Alert struct {
	Tenant, Audience, Severity, Kind, Detail string
	ID                                       int64
}

// Store opens transactions.
type Store interface {
	// InTx runs fn in one transaction scoped to tenant (empty tenant only for platform tables).
	InTx(ctx context.Context, tenant string, fn func(Tx) error) error
	// Use runs fn on a transaction begun elsewhere (go-auth's audited transaction), tenant already set.
	Use(ctx context.Context, tenant string, tx *sql.Tx, fn func(Tx) error) error
	// Dialect is "sqlite" or "postgres".
	Dialect() string
	Close() error
	// DB exposes the pool for the outbox relay and health checks.
	DB() *sql.DB
}

// Tx is the set of operations the engine and the gateway need, all tenant-scoped.
type Tx interface {
	Tenant() string
	GetOp(stream, origin string, seq int64) (OpRec, bool, error)
	PutOp(o OpRec) error
	UpdateOp(o OpRec) error
	Head(stream, origin string) (seq int64, h string, err error)
	Heads() ([]HeadRow, error)
	Range(stream, origin string, after, upto int64, limit int) ([]OpRec, error)
	ByArrival(afterArr int64, limit int) ([]OpRec, error)
	ByStatus(status string) ([]OpRec, error)
	OpsByOrigin(origin string) ([]OpRec, error)
	PutSeal(stream, origin string, seq int64, h, kid, sig string) error
	SealSeqs(stream, origin string, after int64) ([]int64, error)
	GetSeal(stream, origin string, seq int64) (kid, sig, h string, ok bool, err error)
	MaxSealSeq(stream, origin string) (int64, error)
	// ReplaceSeal overwrites the seal at a slot (re-sealing after an op-signing key rotation).
	ReplaceSeal(stream, origin string, seq int64, h, kid, sig string) error
	// SealsOfOrigins lists the seals of origins starting with prefix (cloud-).
	SealsOfOrigins(prefix string) ([]SealRec, error)
	PutEndorsement(e EndorsementRec) error
	ReplaceEndorsement(e EndorsementRec) error
	GetEndorsement(stream, origin string, seq int64) (EndorsementRec, bool, error)
	EndorsementSeqs(stream, origin string, after int64) ([]int64, error)
	Endorsements() ([]EndorsementRec, error)
	PutAttestation(a AttestationRec) error
	Attestations(stream, origin string) ([]AttestationRec, error)
	DeleteMeta(k string) error
	// ResolveAlerts removes the open alerts of a kind and detail.
	ResolveAlerts(kind, detail string) error
	NextCounter(name string) (int64, error)
	NextNumber(code, fy string) (int64, error)
	PeekNumber(code, fy string) (int64, error)
	GetMeta(k string) (string, bool, error)
	// MetaPrefix lists the meta rows whose key starts with prefix.
	MetaPrefix(prefix string) (map[string]string, error)
	SetMeta(k, v string) error
	// PIIRefs lists the ops this node holds pii values for.
	PIIRefs() ([][3]string, error)
	PutPII(stream, origin string, seq int64, data string) error
	GetPII(stream, origin string, seq int64) (string, bool, error)
	ErasePII(stream, origin string, seq int64) error
	PutSession(origin, sid, stype, openedAt string) error
	SessionType(origin, sid string) (string, bool, error)
	// PutSessionRow stores the session with the verdict of its proof. A row whose verdict is already final
	// (valid, invalid, locked) is never overwritten: identity is asked once.
	PutSessionRow(r SessionRow) error
	GetSession(origin, sid string) (SessionRow, bool, error)
	// PendingSessions lists the sessions whose proof identity has not answered.
	PendingSessions() ([]SessionRow, error)
	PutApprovalVerdict(origin, approvalID, verdict string) error
	GetApprovalVerdict(origin, approvalID string) (string, bool, error)
	// PutApprovalRecord stores the record of an approval.grant or approval.self_confirm beside its verdict (the row exists).
	PutApprovalRecord(r ApprovalRow) error
	GetApproval(origin, approvalID string) (ApprovalRow, bool, error)
	// PendingApprovals lists the approvals whose proof identity has not answered.
	PendingApprovals() ([]ApprovalRow, error)
	// ClaimApproval sets the one op that cites the approval.
	ClaimApproval(origin, approvalID, citer, citerHLC string) error
	PutDrain(d DrainRec) error
	Drains(origin string) ([]DrainRec, error)
	SetDrainState(origin, hash, state string) error
	// DrainsByState lists the statements in a state across origins.
	DrainsByState(state string) ([]DrainRec, error)
	PutRegister(e RegisterEntry) error
	SetRegisterState(origin, stream string, seq int64, state, mark string) error
	Register() ([]RegisterEntry, error)
	// NumberHolder returns the register entry that keeps a legal number under a document id other than docID, written by an op
	// other than the given one that was accepted or flagged and is not marked duplicate_document (the first op keeps the number; a held op does not).
	NumberHolder(number, docID, origin, stream string, seq int64) (RegisterEntry, bool, error)
	PutFork(stream, origin string, seq int64, h, body, source string) error
	Forks() ([]string, error)
	PutRecovery(r Recovery) error
	GetRecovery(recID string) (Recovery, bool, error)
	RecoveryByOld(old string) (Recovery, bool, error)
	// PutAudit appends a tenant-visible decision record; Audit lists them.
	PutAudit(a AuditRec) error
	Audit() ([]AuditRec, error)
	AddAlert(audience, severity, kind, detail string) error
	Alerts() ([]Alert, error)
	// PutEmit and GetEmit are the idempotency record of the cloud emit (emit_dedup).
	PutEmit(e EmitRec) error
	GetEmit(caller, key string) (EmitRec, bool, error)
	// Exec is for service-owned tables in the same transaction (the outbox).
	Exec(query string, args ...any) error
	SQLTx() *sql.Tx
}

// SQL implements Store on database/sql.
type SQL struct {
	db *sql.DB
	pg bool
}

// Open opens a store. dsn "postgres://..." selects Postgres; anything else is a SQLite path or
// ":memory:" with a name ("file:name?mode=memory&cache=shared" is built for ":memory:").
func Open(dsn string) (*SQL, error) {
	s := &SQL{}
	var err error
	switch {
	case strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://"):
		s.pg = true
		s.db, err = sql.Open("pgx", dsn)
		if err == nil {
			s.db.SetMaxOpenConns(16)
		}
	default:
		path := dsn
		if path == "" || path == ":memory:" {
			path = "file::memory:?cache=shared"
		}
		q := "_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(OFF)"
		if strings.Contains(path, "?") {
			path += "&" + q
		} else {
			path += "?" + q
		}
		s.db, err = sql.Open("sqlite", path)
		if err == nil {
			s.db.SetMaxOpenConns(1) // single writer path (ADR-0007 C2)
			s.db.SetConnMaxLifetime(0)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := s.migrate(context.Background()); err != nil {
		_ = s.db.Close()
		return nil, err
	}
	return s, nil
}

// Dialect implements Store.
func (s *SQL) Dialect() string {
	if s.pg {
		return "postgres"
	}
	return "sqlite"
}

// Close implements Store.
func (s *SQL) Close() error { return s.db.Close() }

// DB implements Store.
func (s *SQL) DB() *sql.DB { return s.db }

func (s *SQL) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY)`); err != nil {
		return err
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		if strings.Contains(n, "_pg_") && !s.pg {
			continue
		}
		var have string
		err := s.db.QueryRowContext(ctx, s.rebind(`SELECT name FROM schema_migrations WHERE name = ?`), n).Scan(&have)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		raw, _ := migrationFS.ReadFile("migrations/" + n)
		if _, err := s.db.ExecContext(ctx, string(raw)); err != nil {
			return fmt.Errorf("migration %s: %w", n, err)
		}
		if _, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO schema_migrations (name) VALUES (?)`), n); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQL) rebind(q string) string {
	if !s.pg {
		return q
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
		} else {
			b.WriteByte(q[i])
		}
	}
	return b.String()
}

// InTx implements Store.
func (s *SQL) InTx(ctx context.Context, tenant string, fn func(Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if s.pg {
		// Tenant context for RLS; platform-level callers pass "" and see no tenant rows.
		if _, err := tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenant); err != nil {
			_ = tx.Rollback()
			return err
		}
		if tenant != "" {
			// One writer per tenant: ingest, verdicts and emits serialise on the tenant lock.
			if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", tenant); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
	}
	t := &sqlTx{s: s, tx: tx, ctx: ctx, tenant: tenant}
	if err := fn(t); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

type sqlTx struct {
	s      *SQL
	tx     *sql.Tx
	ctx    context.Context
	tenant string
}

func (t *sqlTx) Tenant() string { return t.tenant }
func (t *sqlTx) SQLTx() *sql.Tx { return t.tx }

func (t *sqlTx) exec(q string, a ...any) error {
	_, err := t.tx.ExecContext(t.ctx, t.s.rebind(q), a...)
	return err
}
func (t *sqlTx) Exec(q string, a ...any) error { return t.exec(q, a...) }

func (t *sqlTx) query(q string, a ...any) (*sql.Rows, error) {
	return t.tx.QueryContext(t.ctx, t.s.rebind(q), a...)
}

const opCols = `stream, origin, seq, h, ph, body, status, reason, marks, intent, hlc, arr`

func (t *sqlTx) scanOps(rows *sql.Rows) ([]OpRec, error) {
	defer rows.Close()
	var out []OpRec
	for rows.Next() {
		o := OpRec{Tenant: t.tenant}
		if err := rows.Scan(&o.Stream, &o.Origin, &o.Seq, &o.H, &o.PH, &o.Body, &o.Status, &o.Reason, &o.Marks, &o.Intent, &o.HLC, &o.Arr); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (t *sqlTx) GetOp(stream, origin string, seq int64) (OpRec, bool, error) {
	rows, err := t.query(`SELECT `+opCols+` FROM ops WHERE tenant_id=? AND stream=? AND origin=? AND seq=?`, t.tenant, stream, origin, seq)
	if err != nil {
		return OpRec{}, false, err
	}
	ops, err := t.scanOps(rows)
	if err != nil || len(ops) == 0 {
		return OpRec{}, false, err
	}
	return ops[0], true, nil
}

func (t *sqlTx) PutOp(o OpRec) error {
	if o.Arr == 0 {
		a, err := t.NextCounter("arr")
		if err != nil {
			return err
		}
		o.Arr = a
	}
	return t.exec(`INSERT INTO ops (tenant_id, `+opCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.tenant, o.Stream, o.Origin, o.Seq, o.H, o.PH, o.Body, o.Status, o.Reason, o.Marks, o.Intent, o.HLC, o.Arr)
}

func (t *sqlTx) UpdateOp(o OpRec) error {
	return t.exec(`UPDATE ops SET body=?, status=?, reason=?, marks=?, intent=?, hlc=? WHERE tenant_id=? AND stream=? AND origin=? AND seq=?`,
		o.Body, o.Status, o.Reason, o.Marks, o.Intent, o.HLC, t.tenant, o.Stream, o.Origin, o.Seq)
}

func (t *sqlTx) Head(stream, origin string) (int64, string, error) {
	var seq int64
	var h string
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT seq, h FROM ops WHERE tenant_id=? AND stream=? AND origin=? ORDER BY seq DESC LIMIT 1`),
		t.tenant, stream, origin).Scan(&seq, &h)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	return seq, h, err
}

func (t *sqlTx) Heads() ([]HeadRow, error) {
	rows, err := t.query(`SELECT stream, origin, MAX(seq) FROM ops WHERE tenant_id=? GROUP BY stream, origin ORDER BY stream, origin`, t.tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HeadRow
	for rows.Next() {
		var h HeadRow
		if err := rows.Scan(&h.Stream, &h.Origin, &h.Seq); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (t *sqlTx) Range(stream, origin string, after, upto int64, limit int) ([]OpRec, error) {
	rows, err := t.query(`SELECT `+opCols+` FROM ops WHERE tenant_id=? AND stream=? AND origin=? AND seq>? AND seq<=? ORDER BY seq LIMIT ?`,
		t.tenant, stream, origin, after, upto, limit)
	if err != nil {
		return nil, err
	}
	return t.scanOps(rows)
}

func (t *sqlTx) ByArrival(afterArr int64, limit int) ([]OpRec, error) {
	rows, err := t.query(`SELECT `+opCols+` FROM ops WHERE tenant_id=? AND arr>? ORDER BY arr LIMIT ?`, t.tenant, afterArr, limit)
	if err != nil {
		return nil, err
	}
	return t.scanOps(rows)
}

func (t *sqlTx) ByStatus(status string) ([]OpRec, error) {
	rows, err := t.query(`SELECT `+opCols+` FROM ops WHERE tenant_id=? AND status=? ORDER BY arr`, t.tenant, status)
	if err != nil {
		return nil, err
	}
	return t.scanOps(rows)
}

func (t *sqlTx) OpsByOrigin(origin string) ([]OpRec, error) {
	rows, err := t.query(`SELECT `+opCols+` FROM ops WHERE tenant_id=? AND origin=? ORDER BY stream, seq`, t.tenant, origin)
	if err != nil {
		return nil, err
	}
	return t.scanOps(rows)
}

func (t *sqlTx) PutSeal(stream, origin string, seq int64, h, kid, sig string) error {
	return t.exec(`INSERT INTO seals (tenant_id, stream, origin, seq, h, kid, sig) VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
		t.tenant, stream, origin, seq, h, kid, sig)
}

func (t *sqlTx) SealSeqs(stream, origin string, after int64) ([]int64, error) {
	rows, err := t.query(`SELECT seq FROM seals WHERE tenant_id=? AND stream=? AND origin=? AND seq>? ORDER BY seq`, t.tenant, stream, origin, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (t *sqlTx) GetSeal(stream, origin string, seq int64) (string, string, string, bool, error) {
	var kid, sig, h string
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT kid, sig, h FROM seals WHERE tenant_id=? AND stream=? AND origin=? AND seq=?`),
		t.tenant, stream, origin, seq).Scan(&kid, &sig, &h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", false, nil
	}
	return kid, sig, h, err == nil, err
}

func (t *sqlTx) MaxSealSeq(stream, origin string) (int64, error) {
	var n sql.NullInt64
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT MAX(seq) FROM seals WHERE tenant_id=? AND stream=? AND origin=?`), t.tenant, stream, origin).Scan(&n)
	return n.Int64, err
}

func (t *sqlTx) NextCounter(name string) (int64, error) {
	var v int64
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`INSERT INTO counters (tenant_id, name, v) VALUES (?,?,1) ON CONFLICT (tenant_id, name) DO UPDATE SET v = counters.v + 1 RETURNING v`),
		t.tenant, name).Scan(&v)
	return v, err
}

func (t *sqlTx) NextNumber(code, fy string) (int64, error) {
	var v int64
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`INSERT INTO numbers (tenant_id, code, fy, n) VALUES (?,?,?,1) ON CONFLICT (tenant_id, code, fy) DO UPDATE SET n = numbers.n + 1 RETURNING n`),
		t.tenant, code, fy).Scan(&v)
	return v, err
}

func (t *sqlTx) PeekNumber(code, fy string) (int64, error) {
	var v int64
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT n FROM numbers WHERE tenant_id=? AND code=? AND fy=?`), t.tenant, code, fy).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

func (t *sqlTx) GetMeta(k string) (string, bool, error) {
	var v string
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT v FROM meta WHERE tenant_id=? AND k=?`), t.tenant, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

func (t *sqlTx) SetMeta(k, v string) error {
	return t.exec(`INSERT INTO meta (tenant_id, k, v) VALUES (?,?,?) ON CONFLICT (tenant_id, k) DO UPDATE SET v = excluded.v`, t.tenant, k, v)
}

func (t *sqlTx) MetaPrefix(prefix string) (map[string]string, error) {
	rows, err := t.query(`SELECT k, v FROM meta WHERE tenant_id=? AND substr(k, 1, ?) = ? ORDER BY k`, t.tenant, len(prefix), prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (t *sqlTx) GetPII(stream, origin string, seq int64) (string, bool, error) {
	var v string
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT data FROM op_pii WHERE tenant_id=? AND stream=? AND origin=? AND seq=?`), t.tenant, stream, origin, seq).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

func (t *sqlTx) PutEmit(e EmitRec) error {
	return t.exec(`INSERT INTO emit_dedup (tenant_id, caller, key, content, origin, stream, seq) VALUES (?,?,?,?,?,?,?)`,
		t.tenant, e.Caller, e.Key, e.Content, e.Origin, e.Stream, e.Seq)
}

func (t *sqlTx) GetEmit(caller, key string) (EmitRec, bool, error) {
	e := EmitRec{Caller: caller, Key: key}
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT content, origin, stream, seq FROM emit_dedup WHERE tenant_id=? AND caller=? AND key=?`), t.tenant, caller, key).Scan(&e.Content, &e.Origin, &e.Stream, &e.Seq)
	if errors.Is(err, sql.ErrNoRows) {
		return e, false, nil
	}
	return e, err == nil, err
}

func (t *sqlTx) PIIRefs() ([][3]string, error) {
	rows, err := t.query(`SELECT stream, origin, seq FROM op_pii WHERE tenant_id=? ORDER BY stream, origin, seq`, t.tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][3]string
	for rows.Next() {
		var s, o string
		var q int64
		if err := rows.Scan(&s, &o, &q); err != nil {
			return nil, err
		}
		out = append(out, [3]string{s, o, strconv.FormatInt(q, 10)})
	}
	return out, rows.Err()
}

func (t *sqlTx) PutPII(stream, origin string, seq int64, data string) error {
	return t.exec(`INSERT INTO op_pii (tenant_id, stream, origin, seq, data) VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING`, t.tenant, stream, origin, seq, data)
}

func (t *sqlTx) ErasePII(stream, origin string, seq int64) error {
	if err := t.exec(`DELETE FROM op_pii WHERE tenant_id=? AND stream=? AND origin=? AND seq=?`, t.tenant, stream, origin, seq); err != nil {
		return err
	}
	if t.s.Dialect() != "postgres" {
		return nil // the outbox exists on the gateway's Postgres only
	}
	// P2-M1: the outbox copy of the op's event holds the values and salts; published rows are kept for the relay's retention and a
	// bus reset republishes them, so the pii is cut out of every row of the op (published or not) in the erasing transaction.
	_, err := t.tx.ExecContext(t.ctx, `UPDATE outbox SET payload = convert_to((convert_from(payload, 'UTF8')::jsonb #- '{data,pii}')::text, 'UTF8')
		WHERE tenant_id = $1 AND key = $2 AND key_seq = $3 AND type LIKE 'sync.op.%' AND convert_from(payload, 'UTF8')::jsonb #> '{data,pii}' IS NOT NULL`,
		t.tenant, stream+"|"+origin, seq)
	return err
}

func (t *sqlTx) PutSession(origin, sid, stype, openedAt string) error {
	return t.exec(`INSERT INTO sessions (tenant_id, origin, sid, stype, opened_at) VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING`, t.tenant, origin, sid, stype, openedAt)
}

func (t *sqlTx) SessionType(origin, sid string) (string, bool, error) {
	var v string
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT stype FROM sessions WHERE tenant_id=? AND origin=? AND sid=?`), t.tenant, origin, sid).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

const sessionCols = `origin, sid, stype, actor, pack_v, pin_v, opened_at, verdict`

func (t *sqlTx) PutSessionRow(r SessionRow) error {
	return t.exec(`INSERT INTO sessions (tenant_id, origin, sid, stype, actor, pack_v, pin_v, opened_at, verdict) VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT (tenant_id, origin, sid) DO UPDATE SET stype = excluded.stype, actor = excluded.actor, pack_v = excluded.pack_v,
		pin_v = excluded.pin_v, opened_at = excluded.opened_at, verdict = excluded.verdict
		WHERE sessions.verdict = '' OR sessions.verdict = 'pending'`,
		t.tenant, r.Origin, r.SID, r.Type, r.Actor, r.PackV, r.PinV, r.OpenedAt, r.Verdict)
}

func (t *sqlTx) GetSession(origin, sid string) (SessionRow, bool, error) {
	r := SessionRow{}
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT `+sessionCols+` FROM sessions WHERE tenant_id=? AND origin=? AND sid=?`), t.tenant, origin, sid).
		Scan(&r.Origin, &r.SID, &r.Type, &r.Actor, &r.PackV, &r.PinV, &r.OpenedAt, &r.Verdict)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionRow{}, false, nil
	}
	return r, err == nil, err
}

func (t *sqlTx) PendingSessions() ([]SessionRow, error) {
	rows, err := t.query(`SELECT `+sessionCols+` FROM sessions WHERE tenant_id=? AND verdict='pending' ORDER BY origin, sid`, t.tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		var r SessionRow
		if err := rows.Scan(&r.Origin, &r.SID, &r.Type, &r.Actor, &r.PackV, &r.PinV, &r.OpenedAt, &r.Verdict); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (t *sqlTx) PutApprovalVerdict(origin, approvalID, verdict string) error {
	return t.exec(`INSERT INTO approval_verdicts (tenant_id, origin, approval_id, verdict) VALUES (?,?,?,?)
		ON CONFLICT (tenant_id, origin, approval_id) DO UPDATE SET verdict = excluded.verdict WHERE approval_verdicts.verdict = 'pending'`,
		t.tenant, origin, approvalID, verdict)
}

func (t *sqlTx) GetApprovalVerdict(origin, approvalID string) (string, bool, error) {
	var v string
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT verdict FROM approval_verdicts WHERE tenant_id=? AND origin=? AND approval_id=?`), t.tenant, origin, approvalID).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

const approvalCols = `origin, approval_id, verdict, kind, sid, intent, permission, target, action_hash, requester, approver, reason, approved_at, citer, citer_hlc`

func (t *sqlTx) PutApprovalRecord(r ApprovalRow) error {
	return t.exec(`UPDATE approval_verdicts SET kind=?, sid=?, intent=?, permission=?, target=?, action_hash=?, requester=?, approver=?, reason=?, approved_at=?
		WHERE tenant_id=? AND origin=? AND approval_id=? AND kind=''`,
		r.Kind, r.SID, r.Intent, r.Permission, r.Target, r.ActionHash, r.Requester, r.Approver, r.Reason, r.ApprovedAt, t.tenant, r.Origin, r.ID)
}

func (t *sqlTx) GetApproval(origin, approvalID string) (ApprovalRow, bool, error) {
	var r ApprovalRow
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT `+approvalCols+` FROM approval_verdicts WHERE tenant_id=? AND origin=? AND approval_id=?`), t.tenant, origin, approvalID).
		Scan(&r.Origin, &r.ID, &r.Verdict, &r.Kind, &r.SID, &r.Intent, &r.Permission, &r.Target, &r.ActionHash, &r.Requester, &r.Approver, &r.Reason, &r.ApprovedAt, &r.Citer, &r.CiterHLC)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalRow{}, false, nil
	}
	return r, err == nil, err
}

func (t *sqlTx) PendingApprovals() ([]ApprovalRow, error) {
	rows, err := t.query(`SELECT `+approvalCols+` FROM approval_verdicts WHERE tenant_id=? AND verdict='pending' ORDER BY origin, approval_id`, t.tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ApprovalRow
	for rows.Next() {
		var r ApprovalRow
		if err := rows.Scan(&r.Origin, &r.ID, &r.Verdict, &r.Kind, &r.SID, &r.Intent, &r.Permission, &r.Target, &r.ActionHash, &r.Requester, &r.Approver, &r.Reason, &r.ApprovedAt, &r.Citer, &r.CiterHLC); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (t *sqlTx) ClaimApproval(origin, approvalID, citer, citerHLC string) error {
	return t.exec(`UPDATE approval_verdicts SET citer=?, citer_hlc=? WHERE tenant_id=? AND origin=? AND approval_id=?`, citer, citerHLC, t.tenant, origin, approvalID)
}

func (t *sqlTx) PutDrain(d DrainRec) error {
	return t.exec(`INSERT INTO drain_statements (tenant_id, origin, hash, statement, state, detail) VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
		t.tenant, d.Origin, d.Hash, d.Statement, d.State, d.Detail)
}

func (t *sqlTx) scanDrains(rows *sql.Rows, err error) ([]DrainRec, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DrainRec
	for rows.Next() {
		var d DrainRec
		if err := rows.Scan(&d.Origin, &d.Hash, &d.Statement, &d.State, &d.Detail); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (t *sqlTx) Drains(origin string) ([]DrainRec, error) {
	return t.scanDrains(t.query(`SELECT origin, hash, statement, state, detail FROM drain_statements WHERE tenant_id=? AND origin=? ORDER BY hash`, t.tenant, origin))
}

func (t *sqlTx) DrainsByState(state string) ([]DrainRec, error) {
	return t.scanDrains(t.query(`SELECT origin, hash, statement, state, detail FROM drain_statements WHERE tenant_id=? AND state=? ORDER BY origin, hash`, t.tenant, state))
}

func (t *sqlTx) SetDrainState(origin, hash, state string) error {
	return t.exec(`UPDATE drain_statements SET state=? WHERE tenant_id=? AND origin=? AND hash=?`, state, t.tenant, origin, hash)
}

func (t *sqlTx) PutRegister(e RegisterEntry) error {
	return t.exec(`INSERT INTO series_numbers (tenant_id, code, fy, num, number, doc_type, origin, stream, seq, state, mark, doc_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (tenant_id, origin, stream, seq, number) DO UPDATE SET state = excluded.state, mark = excluded.mark`,
		t.tenant, e.Code, e.FY, e.Num, e.Number, e.DocType, e.Origin, e.Stream, e.Seq, e.State, e.Mark, e.DocID)
}

func (t *sqlTx) SetRegisterState(origin, stream string, seq int64, state, mark string) error {
	return t.exec(`UPDATE series_numbers SET state=?, mark=? WHERE tenant_id=? AND origin=? AND stream=? AND seq=?`, state, mark, t.tenant, origin, stream, seq)
}

func (t *sqlTx) Register() ([]RegisterEntry, error) {
	rows, err := t.query(`SELECT code, fy, num, number, doc_type, origin, stream, seq, state, mark, doc_id FROM series_numbers WHERE tenant_id=? ORDER BY code, fy, num, origin, seq`, t.tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RegisterEntry
	for rows.Next() {
		e := RegisterEntry{Tenant: t.tenant}
		if err := rows.Scan(&e.Code, &e.FY, &e.Num, &e.Number, &e.DocType, &e.Origin, &e.Stream, &e.Seq, &e.State, &e.Mark, &e.DocID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (t *sqlTx) NumberHolder(number, docID, origin, stream string, seq int64) (RegisterEntry, bool, error) {
	e := RegisterEntry{Tenant: t.tenant}
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT code, fy, num, number, doc_type, origin, stream, seq, state, mark, doc_id FROM series_numbers
		WHERE tenant_id=? AND number=? AND doc_id<>'' AND doc_id<>? AND state IN ('accepted','flagged') AND mark<>'duplicate_document' AND NOT (origin=? AND stream=? AND seq=?)
		ORDER BY origin, seq LIMIT 1`), t.tenant, number, docID, origin, stream, seq).
		Scan(&e.Code, &e.FY, &e.Num, &e.Number, &e.DocType, &e.Origin, &e.Stream, &e.Seq, &e.State, &e.Mark, &e.DocID)
	if errors.Is(err, sql.ErrNoRows) {
		return RegisterEntry{}, false, nil
	}
	return e, err == nil, err
}

func (t *sqlTx) PutFork(stream, origin string, seq int64, h, body, source string) error {
	return t.exec(`INSERT INTO forks (tenant_id, stream, origin, seq, h, body, source) VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`, t.tenant, stream, origin, seq, h, body, source)
}

func (t *sqlTx) Forks() ([]string, error) {
	rows, err := t.query(`SELECT origin, stream, seq FROM forks WHERE tenant_id=? ORDER BY origin, stream, seq`, t.tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var o, s string
		var q int64
		if err := rows.Scan(&o, &s, &q); err != nil {
			return nil, err
		}
		out = append(out, o+"/"+s+"/"+strconv.FormatInt(q, 10))
	}
	return out, rows.Err()
}

func (t *sqlTx) PutRecovery(r Recovery) error {
	d := 0
	if r.Drained {
		d = 1
	}
	return t.exec(`INSERT INTO recoveries (tenant_id, rec_id, old_device, new_device, attested, drained) VALUES (?,?,?,?,?,?)
		ON CONFLICT (tenant_id, rec_id) DO UPDATE SET attested = excluded.attested, drained = excluded.drained`,
		t.tenant, r.RecID, r.OldDevice, r.NewDevice, r.Attested, d)
}

func (t *sqlTx) getRecovery(where string, arg string) (Recovery, bool, error) {
	var r Recovery
	var d int64
	r.Tenant = t.tenant
	err := t.tx.QueryRowContext(t.ctx, t.s.rebind(`SELECT rec_id, old_device, new_device, attested, drained FROM recoveries WHERE tenant_id=? AND `+where+`=?`), t.tenant, arg).
		Scan(&r.RecID, &r.OldDevice, &r.NewDevice, &r.Attested, &d)
	if errors.Is(err, sql.ErrNoRows) {
		return Recovery{}, false, nil
	}
	r.Drained = d == 1
	return r, err == nil, err
}

func (t *sqlTx) GetRecovery(id string) (Recovery, bool, error) { return t.getRecovery("rec_id", id) }
func (t *sqlTx) RecoveryByOld(old string) (Recovery, bool, error) {
	return t.getRecovery("old_device", old)
}

func (t *sqlTx) AddAlert(audience, severity, kind, detail string) error {
	id, err := t.NextCounter("alert")
	if err != nil {
		return err
	}
	return t.exec(`INSERT INTO alerts (tenant_id, id, audience, severity, kind, detail) VALUES (?,?,?,?,?,?)`, t.tenant, id, audience, severity, kind, detail)
}

func (t *sqlTx) Alerts() ([]Alert, error) {
	rows, err := t.query(`SELECT id, audience, severity, kind, detail FROM alerts WHERE tenant_id=? ORDER BY id`, t.tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		a := Alert{Tenant: t.tenant}
		if err := rows.Scan(&a.ID, &a.Audience, &a.Severity, &a.Kind, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
