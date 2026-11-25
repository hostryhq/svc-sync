package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/tenancy"
	"modernc.org/sqlite"
)

func init() {
	// go-common tenancy.SetDBContext runs `SELECT set_config('app.tenant_id', ...)`, which only
	// Postgres has. SQLite (the hub, the simulator and local runs) has no row-level security, so
	// the same call is a no-op there: the audited transaction of go-auth then works on both.
	_ = sqlite.RegisterScalarFunction("set_config", 3, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		return args[1], nil
	})
}

// AuditRec is one tenant-visible record of a decision on a held slot (review H2).
type AuditRec struct {
	ID        string
	At        time.Time
	Actor     string // principal subject
	ActorType string // user, support
	Action    string // release, discard, confirm
	Origin    string
	Stream    string
	Seq       int64
	Reason    string
	Before    string // status before
	After     string // status after
	RequestID string
}

func (t *sqlTx) PutAudit(a AuditRec) error {
	return t.exec(`INSERT INTO audit_log (tenant_id, id, occurred_at, actor, actor_type, action, origin, stream, seq, reason, before_status, after_status, request_id)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, t.tenant, a.ID, a.At.UTC().Format(time.RFC3339), a.Actor, a.ActorType, a.Action, a.Origin, a.Stream, a.Seq, a.Reason, a.Before, a.After, a.RequestID)
}

func (t *sqlTx) Audit() ([]AuditRec, error) {
	rows, err := t.query(`SELECT id, occurred_at, actor, actor_type, action, origin, stream, seq, reason, before_status, after_status, request_id FROM audit_log WHERE tenant_id=? ORDER BY occurred_at, id`, t.tenant)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditRec
	for rows.Next() {
		var a AuditRec
		var at string
		if err := rows.Scan(&a.ID, &at, &a.Actor, &a.ActorType, &a.Action, &a.Origin, &a.Stream, &a.Seq, &a.Reason, &a.Before, &a.After, &a.RequestID); err != nil {
			return nil, err
		}
		a.At, _ = time.Parse(time.RFC3339, at)
		out = append(out, a)
	}
	return out, rows.Err()
}

// Use runs fn on a transaction somebody else began (go-auth's audited transaction), so that the
// vendor access row and the action commit together. The tenant context is already set by the
// caller (tenancy.WithTx); on Postgres the per-tenant writer lock is taken here as in InTx.
func (s *SQL) Use(ctx context.Context, tenant string, tx *sql.Tx, fn func(Tx) error) error {
	if s.pg && tenant != "" {
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", tenant); err != nil {
			return err
		}
	}
	return fn(&sqlTx{s: s, tx: tx, ctx: ctx, tenant: tenant})
}

// AccessSink is the vendor_access_log hook of go-auth over this store (ADR-0013 V5).
type AccessSink struct{ S *SQL }

var _ auth.VendorAuditSink = (*AccessSink)(nil)

func (a *AccessSink) insert(ctx context.Context, x tenancy.Execer, e auth.VendorAccessEntry) error {
	tid, err := ids.Parse(e.TenantID)
	if err != nil {
		return err
	}
	tt := "vendor"
	if e.TokenType == auth.TypeSupport {
		tt = "support"
	}
	_, err = x.ExecContext(ctx, a.S.rebind(`INSERT INTO vendor_access_log (tenant_id, id, occurred_at, vendor_user, token_type, support_session_id, action_key, target_id, ticket_reference, outcome, result_count, request_id)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`), tid.String(), e.ID.String(), e.Time.UTC().Format(time.RFC3339), e.VendorUser, tt, nullable(e.SupportSession), e.ActionKey,
		nullable(e.TargetID), nullable(e.Ticket), e.Outcome, e.ResultCount, e.RequestID)
	return err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// RecordInTx implements auth.VendorAuditSink: the row commits with the action or not at all.
func (a *AccessSink) RecordInTx(ctx context.Context, x tenancy.Execer, e auth.VendorAccessEntry) error {
	return a.insert(ctx, x, e)
}

// RecordRefused implements auth.VendorAuditSink: a short transaction of its own.
func (a *AccessSink) RecordRefused(ctx context.Context, e auth.VendorAccessEntry) error {
	if e.TenantID == "" {
		return errors.New("repository: refused vendor request names no organisation")
	}
	e.Outcome = auth.OutcomeRefused
	return a.S.InTx(context.WithoutCancel(ctx), e.TenantID, func(tx Tx) error {
		return a.insert(ctx, tx.SQLTx(), e)
	})
}

// VendorAccess lists the vendor_access_log of the tenant (for tests and the vendor view).
func (s *SQL) VendorAccess(ctx context.Context, tenant string) ([]auth.VendorAccessEntry, error) {
	var out []auth.VendorAccessEntry
	err := s.InTx(ctx, tenant, func(tx Tx) error {
		rows, err := tx.SQLTx().QueryContext(ctx, s.rebind(`SELECT id, occurred_at, vendor_user, token_type, COALESCE(support_session_id,''), action_key, COALESCE(target_id,''), COALESCE(ticket_reference,''), outcome, COALESCE(result_count,0), request_id FROM vendor_access_log WHERE tenant_id=? ORDER BY occurred_at, id`), tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var e auth.VendorAccessEntry
			var id, at, tt string
			if err := rows.Scan(&id, &at, &e.VendorUser, &tt, &e.SupportSession, &e.ActionKey, &e.TargetID, &e.Ticket, &e.Outcome, &e.ResultCount, &e.RequestID); err != nil {
				return err
			}
			e.ID, e.TenantID = ids.ID(id), tenant
			e.Time, _ = time.Parse(time.RFC3339, at)
			e.TokenType = auth.TokenType(tt)
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// ErrPrivilegedRole is returned by CheckAppRole for a database role that bypasses row-level security.
var ErrPrivilegedRole = errors.New("repository: the database role is a superuser or has BYPASSRLS, so tenant isolation would not hold")

// CheckAppRole refuses a Postgres role that bypasses row-level security (TC-01, review M5 of the
// security review). Row-level security is the backstop of every tenant-scoped query; a superuser
// connection would turn it off without any error. Call it at start-up after the migrations. SQLite
// has no row-level security and passes.
func (s *SQL) CheckAppRole(ctx context.Context) error {
	if !s.pg {
		return nil
	}
	var privileged bool
	if err := s.db.QueryRowContext(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&privileged); err != nil {
		return err
	}
	if privileged {
		return ErrPrivilegedRole
	}
	return nil
}
