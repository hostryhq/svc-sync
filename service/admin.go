package service

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/logx"
	"github.com/hostryhq/go-common/tenancy"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// The permissions the manager and vendor endpoints need. They are not in api-specs/common/permissions.yaml
// yet: docs/poc-notes.md lists them with the flags to add (review H2).
const (
	PermQuarantineRead    = "sync.quarantine.read"
	PermQuarantineManage  = "sync.quarantine.manage"
	PermQuarantineConfirm = "sync.quarantine.confirm"
	PermExceptionsRead    = "sync.exceptions.read"
	PermRegisterRead      = "sync.register.read"
	PermDeviceRecover     = "device.recover"
)

// Audit actions.
const (
	ActionRelease = "release"
	ActionDiscard = "discard"
	ActionConfirm = "confirm"
	ActionEmit    = "emit"
)

// MaxReason bounds the free-text reason of a decision.
const MaxReason = 200

// Errors of the conditions on manager decisions (security ruling, Phase 1 final verdict).
var (
	// ErrSelfRelease: a member may not release or discard a hold on an op recorded in their own name.
	ErrSelfRelease = errors.New("service: a member cannot decide a hold on their own op")
	// ErrConfirmHash: a vendor confirmation must name the hash of the held op it is for.
	ErrConfirmHash = errors.New("service: the confirmation must carry the hash of the held op")
)

// guardedEntities are the entities of money, tax and bill numbers: a hold on an op that touches one
// of them (or carries a legal number) is a money or bill-number hold.
var guardedEntities = map[string]bool{"bill": true, "bill_line": true, "bill_tax_line": true, "payment": true, "refund": true,
	"credit_note": true, "credit_note_line": true, "credit_note_tax_line": true, "cash_event": true, "shift_close": true, "day_close": true}

func moneyHold(rec repository.OpRec) bool {
	b, err := sp.DecodeBody(rec.Body)
	if err != nil {
		return false
	}
	if len(b.Documents()) > 0 {
		return true
	}
	for _, m := range b.Muts {
		if guardedEntities[m.E] {
			return true
		}
	}
	return false
}

// decisionConditions applies the conditions on release and discard: no self-decision, and for a money or
// bill-number hold the approval a binding under caution needs (ADR-0005 A2.2).
func (g *Gateway) decisionConditions(ctx context.Context, rec repository.OpRec) error {
	p, _ := auth.PrincipalFrom(ctx)
	if b, err := sp.DecodeBody(rec.Body); err == nil && b.Actor != "" && b.Actor == p.Subject {
		return ErrSelfRelease
	}
	if moneyHold(rec) && p.UnderCaution(g.cfg.Now()) && !p.Approved {
		return apperr.New(apperr.Forbidden, auth.CodeApprovalRequired, "approval required for this operation on a new device")
	}
	return nil
}

// ErrReasonRequired is returned when a sensitive decision carries no reason.
var ErrReasonRequired = errors.New("service: a reason is required")

// outletOf is the outlet a stream belongs to; brand and tenant streams belong to no single outlet,
// so only an all-outlets grant reaches them.
func outletOf(stream string) string {
	if kind, id, ok := strings.Cut(stream, ":"); ok && kind == "outlet" {
		return id
	}
	return ""
}

func inScope(scope auth.OutletScope, stream string) bool {
	if o := outletOf(stream); o != "" {
		return scope.Contains(o)
	}
	return scope.All()
}

// audited runs fn in the audited transaction of go-auth: for a request on a vendor user's authority
// the vendor_access_log row commits with the work or the work does not happen. The tenant is the
// verified token's, never a parameter.
func (g *Gateway) audited(ctx context.Context, fn func(tx repository.Tx) error) error {
	tc, err := tenancy.Require(ctx)
	if err != nil {
		return err
	}
	tenant := tc.TenantID.String()
	return auth.WithAuditedTx(ctx, g.cfg.Store.DB(), func(ctx context.Context, sx *sql.Tx) error {
		return g.cfg.Store.Use(ctx, tenant, sx, fn)
	})
}

// ListQuarantine is the manager's held list, narrowed to the outlets the caller may see.
func (g *Gateway) ListQuarantine(ctx context.Context) ([]QuarantineItem, error) {
	return g.list(ctx, PermQuarantineRead, repository.StQuarantined, true)
}

// ListExceptions is the exceptions report: flagged ops with their marks.
func (g *Gateway) ListExceptions(ctx context.Context) ([]QuarantineItem, error) {
	return g.list(ctx, PermExceptionsRead, repository.StFlagged, false)
}

func (g *Gateway) list(ctx context.Context, perm, status string, withReason bool) ([]QuarantineItem, error) {
	scope, err := auth.ScopeFor(ctx, perm)
	if err != nil {
		return nil, err
	}
	out := []QuarantineItem{}
	err = g.audited(ctx, func(tx repository.Tx) error {
		recs, err := tx.ByStatus(status)
		if err != nil {
			return err
		}
		for _, r := range recs {
			if !inScope(scope, r.Stream) {
				continue
			}
			it := QuarantineItem{Ref: sp.Ref{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq}, Marks: splitMarks(r.Marks), Intent: r.Intent, Number: docNumber(r.Body)}
			if withReason {
				it.Reason = r.Reason
			}
			out = append(out, it)
		}
		auth.SetResultCount(ctx, len(out))
		return nil
	})
	return out, err
}

// ListRegister is the series register of the caller's outlets with its gap check.
func (g *Gateway) ListRegister(ctx context.Context) (RegisterReport, error) {
	scope, err := auth.ScopeFor(ctx, PermRegisterRead)
	if err != nil {
		return RegisterReport{}, err
	}
	tc, err := tenancy.Require(ctx)
	if err != nil {
		return RegisterReport{}, err
	}
	var rep RegisterReport
	err = g.audited(ctx, func(tx repository.Tx) error {
		var err error
		rep, err = registerReport(tx, func(e repository.RegisterEntry) bool { return inScope(scope, e.Stream) })
		auth.SetResultCount(ctx, len(rep.Entries))
		return err
	})
	_ = tc
	return rep, err
}

// ListAlerts lists the alerts the caller may read. Vendor-audience alerts (chain conflicts, gaps)
// are read in a support session only.
func (g *Gateway) ListAlerts(ctx context.Context) ([]repository.Alert, error) {
	if _, err := auth.ScopeFor(ctx, PermExceptionsRead); err != nil {
		return nil, err
	}
	p, _ := auth.PrincipalFrom(ctx)
	out := []repository.Alert{}
	err := g.audited(ctx, func(tx repository.Tx) error {
		all, err := tx.Alerts()
		if err != nil {
			return err
		}
		for _, a := range all {
			if a.Audience == "vendor" && p.Type != auth.TypeSupport {
				continue
			}
			out = append(out, a)
		}
		auth.SetResultCount(ctx, len(out))
		return nil
	})
	return out, err
}

func (g *Gateway) record(ctx context.Context, tx repository.Tx, action string, rec repository.OpRec, reason, before, after string) error {
	p, _ := auth.PrincipalFrom(ctx)
	return tx.PutAudit(repository.AuditRec{
		ID: g.cfg.IDs.New().String(), At: g.cfg.Now(), Actor: p.Subject, ActorType: string(p.Type), Action: action,
		Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq, Reason: reason, Before: before, After: after, RequestID: logx.RequestID(ctx),
	})
}

func checkReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > MaxReason {
		return "", ErrReasonRequired
	}
	return reason, nil
}

// lookup returns the held slot the caller may decide on: another outlet's slot is not found.
func lookup(ctx context.Context, tx repository.Tx, ref sp.Ref, perm string) (repository.OpRec, error) {
	rec, ok, err := tx.GetOp(ref.Stream, ref.Origin, ref.Seq)
	if err != nil {
		return rec, err
	}
	if !ok || rec.Status != repository.StQuarantined {
		return rec, ErrNotFound
	}
	if err := auth.Require(ctx, perm, outletOf(rec.Stream)); err != nil {
		return rec, err // 404 for another outlet, 403 when the permission is not held
	}
	return rec, nil
}

// ReleaseAs is the manager's release (S11): outlet-scoped, with the reason, and with the audit
// record in the same transaction as the status change. An unsealed tail also needs device.recover
// in a strong session; a chain-broken, foreign-series or fork hold needs the vendor confirmation.
func (g *Gateway) ReleaseAs(ctx context.Context, ref sp.Ref, reason string) (string, error) {
	reason, err := checkReason(reason)
	if err != nil {
		return "", err
	}
	var status string
	err = g.audited(ctx, func(tx repository.Tx) error {
		rec, err := lookup(ctx, tx, ref, PermQuarantineManage)
		if err != nil {
			return err
		}
		if err := g.decisionConditions(ctx, rec); err != nil {
			return err
		}
		o := ReleaseOpts{}
		if rec.Reason == ReasonUnsealedTail {
			if rerr := auth.Require(ctx, PermDeviceRecover, outletOf(rec.Stream)); rerr != nil {
				var ae *apperr.Error
				if errors.As(rerr, &ae) && ae.Code == auth.CodeApprovalRequired {
					return rerr // a new device: the approval of ADR-0005 A2.2 is needed
				}
				return ErrNeedsRecoverPerm
			}
			o.DeviceRecover = true
		}
		var before string
		status, before, err = g.releaseIn(tx, ref, o)
		if err != nil || status == "" {
			return err
		}
		after, _, _ := tx.GetOp(ref.Stream, ref.Origin, ref.Seq)
		auth.SetAuditTarget(ctx, ref.Key())
		if err := g.alert(tx, "owner", "medium", "hold_released", rec); err != nil { // the owner is told
			return err
		}
		return g.record(ctx, tx, ActionRelease, rec, reason, before, after.Status)
	})
	if err == nil && status != "" {
		tc, _ := tenancy.From(ctx)
		g.poker(tc.TenantID.String()).bump()
	}
	return status, err
}

// DiscardAs is the manager's discard, scoped, reasoned and audited like ReleaseAs.
func (g *Gateway) DiscardAs(ctx context.Context, ref sp.Ref, reason string) error {
	reason, err := checkReason(reason)
	if err != nil {
		return err
	}
	err = g.audited(ctx, func(tx repository.Tx) error {
		rec, err := lookup(ctx, tx, ref, PermQuarantineManage)
		if err != nil {
			return err
		}
		if err := g.decisionConditions(ctx, rec); err != nil {
			return err
		}
		before, err := g.discardIn(tx, ref)
		if err != nil {
			return err
		}
		auth.SetAuditTarget(ctx, ref.Key())
		if err := g.alert(tx, "owner", "medium", "hold_discarded", rec); err != nil {
			return err
		}
		return g.record(ctx, tx, ActionDiscard, rec, reason, before, repository.StVoided)
	})
	if err == nil {
		tc, _ := tenancy.From(ctx)
		g.poker(tc.TenantID.String()).bump()
	}
	return err
}

// ConfirmAs is Hostry support's confirmation of the cause of a chain-broken, foreign-series or fork
// hold (S11: "released only after vendor support has confirmed the cause"). It needs a support
// token in act mode and the support_actable permission; it releases nothing, it marks the slot so
// that the owner's manager can. A tenant member holding the permission is refused.
func (g *Gateway) ConfirmAs(ctx context.Context, ref sp.Ref, reason, h string) error {
	reason, err := checkReason(reason)
	if err != nil {
		return err
	}
	p, _ := auth.PrincipalFrom(ctx)
	if p.Type != auth.TypeSupport || p.Mode != auth.ModeAct {
		return apperr.New(apperr.Forbidden, auth.CodePermissionDenied, "permission denied")
	}
	return g.audited(ctx, func(tx repository.Tx) error {
		rec, err := lookup(ctx, tx, ref, PermQuarantineConfirm)
		if err != nil {
			return err
		}
		switch rec.Reason {
		case ReasonChainBroken, ReasonForeignSeries, ReasonFork:
		default:
			return ErrCannotRelease
		}
		if h == "" || h != rec.H {
			return ErrConfirmHash // bound to the content the supporter looked at
		}
		if hasMark(splitMarks(rec.Marks), MarkVendorConfirmed) {
			return nil
		}
		rec.Marks = strings.Trim(rec.Marks+","+MarkVendorConfirmed, ",")
		if err := tx.UpdateOp(rec); err != nil {
			return err
		}
		auth.SetAuditTarget(ctx, ref.Key())
		// The tenant is told (an owner alert) and the decision is in the tenant-visible audit log.
		if err := g.alert(tx, "owner", "high", "vendor_confirmed_hold", rec); err != nil {
			return err
		}
		return g.record(ctx, tx, ActionConfirm, rec, reason, repository.StQuarantined, repository.StQuarantined)
	})
}

// AuditLog lists the tenant's decision records (tests and the owner's audit view).
func (g *Gateway) AuditLog(ctx context.Context, tenant string) ([]repository.AuditRec, error) {
	var out []repository.AuditRec
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		var err error
		out, err = tx.Audit()
		return err
	})
	return out, err
}
