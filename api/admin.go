package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// maxAdminBody bounds the decision bodies (a ref and a reason).
const maxAdminBody = 4 << 10

// SyncPermissions are the permissions of the manager and vendor endpoints, with the catalogue
// flags they need. api-specs/common/permissions.yaml does not hold them yet; docs/poc-notes.md
// lists them for the next spec round. device.recover is identity's (ADR-0002 A1.3).
func SyncPermissions() []auth.Permission {
	return []auth.Permission{
		{Name: service.PermQuarantineRead, Owner: "sync", SupportViewable: true},
		{Name: service.PermExceptionsRead, Owner: "sync", SupportViewable: true},
		{Name: service.PermRegisterRead, Owner: "sync", SupportViewable: true},
		{Name: service.PermQuarantineManage, Owner: "sync", Sensitive: true},
		{Name: service.PermQuarantineConfirm, Owner: "sync", SupportActable: true},
		{Name: service.PermDeviceRecover, Owner: "identity", Sensitive: true, StrongOnly: true, OwnerGrant: true},
	}
}

// Catalogue is the permission catalogue the gateway's guard is built on until the generated one
// carries the sync permissions.
func Catalogue() *auth.Catalogue {
	c, err := auth.NewCatalogue(SyncPermissions()...)
	if err != nil {
		panic(err)
	}
	return c
}

// AdminAuth is what the guard of the manager and vendor endpoints is built from.
type AdminAuth struct {
	// Tenant verifies tenant-realm access tokens (member and support tokens).
	Tenant *auth.Verifier
	// Services verifies service tokens: a support token is useless without the admin service token (ADR-0013 V2).
	Services *auth.ServiceVerifier
	// Audit is the vendor_access_log hook; without it vendor requests are refused.
	Audit auth.VendorAuditSink
	// Approvals checks the approval token of a blocked operation on a new device (ADR-0005 A2.2); nil refuses them.
	Approvals *auth.ApprovalChecker
	Catalogue *auth.Catalogue
	Clock     clock.Clock
}

// Guard builds the go-auth guard. Every manager and vendor route goes through it: verification,
// token-type rules, support-needs-service-token, outlet scope, new-device caution, vendor audit.
func (a AdminAuth) Guard() *auth.Guard {
	cat := a.Catalogue
	if cat == nil {
		cat = Catalogue()
	}
	clk := a.Clock
	if clk == nil {
		clk = clock.System
	}
	return &auth.Guard{Catalogue: cat, Tenant: a.Tenant, Services: a.Services, Audit: a.Audit, Approvals: a.Approvals, Clock: clk}
}

// Decision is the body of release, discard and confirm: the held slot and why.
type Decision struct {
	sp.Ref
	// Reason is required by the service (1 to 200 characters); openapi/sync/v1 carries only the Ref.
	Reason string `json:"reason"`
	// H is the hash of the held op the confirmation is for (confirm only): the statement is bound to
	// the exact content the supporter looked at.
	H string `json:"h,omitempty"`
}

type heldDTO struct {
	Origin string `json:"origin"`
	Stream string `json:"stream"`
	Seq    int64  `json:"seq"`
	Reason string `json:"reason"`
	Intent string `json:"intent,omitempty"`
	Number string `json:"number,omitempty"`
}

type exceptionDTO struct {
	Origin string `json:"origin"`
	Stream string `json:"stream"`
	Seq    int64  `json:"seq"`
	Flag   string `json:"flag"`
	Intent string `json:"intent,omitempty"`
	Number string `json:"number,omitempty"`
}

type alertDTO struct {
	Code     string `json:"code"`
	Audience string `json:"audience,omitempty"`
	Severity string `json:"severity,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type registerRow struct {
	SeriesCode    string `json:"series_code"`
	FinancialYear string `json:"financial_year"`
	LastNumber    int64  `json:"last_number"`
	Gaps          int    `json:"gaps"`
	ForeignClaims int    `json:"foreign_claims"`
}

// registerRows summarises the register per series and financial year, as the contract lists it.
func registerRows(rep service.RegisterReport) []registerRow {
	type key struct{ code, fy string }
	rows := map[key]*registerRow{}
	get := func(code, fy string) *registerRow {
		k := key{code, fy}
		if rows[k] == nil {
			rows[k] = &registerRow{SeriesCode: code, FinancialYear: fy}
		}
		return rows[k]
	}
	for _, e := range rep.Entries {
		r := get(e.Code, e.FY)
		if e.Mark != service.MarkForeign && e.Mark != service.MarkUnknownSeries && e.Num > r.LastNumber {
			r.LastNumber = e.Num
		}
	}
	for _, g := range rep.Gaps {
		get(g.Code, g.FY).Gaps = len(g.Missing)
	}
	for _, e := range rep.Foreign {
		get(e.Code, e.FY).ForeignClaims++
	}
	out := make([]registerRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SeriesCode+out[i].FinancialYear < out[j].SeriesCode+out[j].FinancialYear
	})
	return out
}

// Admin mounts the manager-facing endpoints (and the internal emit operation, which needs the same guard): quarantine, exceptions, series register, alerts and the
// decisions on held slots. They need a member or support token, never a device token, so flags and
// attribution labels are unreachable from a device (A1.2 item 2, RB1). Authorisation is the
// guard's: each route declares its permission and the controller holds no rule of its own.
func Admin(mux *http.ServeMux, g *service.Gateway, a AdminAuth) {
	guard := a.Guard()
	get := func(pattern, op, perm string, fn func(ctx context.Context) (any, error)) {
		guard.Handle(mux, pattern, auth.Policy{OperationID: op, Permission: perm}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			out, err := fn(r.Context())
			if err != nil {
				apperr.WriteProblem(w, r, adminErr(err))
				return
			}
			writeJSON(w, r, Options{}, http.StatusOK, out)
		}))
	}
	post := func(pattern, op, perm string, fn func(ctx context.Context, d Decision) (any, error)) {
		guard.Handle(mux, pattern, auth.Policy{OperationID: op, Permission: perm}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var d Decision
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBody)).Decode(&d); err != nil {
				apperr.WriteProblem(w, r, apperr.New(apperr.Validation, "sync.bad_request", "bad body"))
				return
			}
			out, err := fn(r.Context(), d)
			if err != nil {
				apperr.WriteProblem(w, r, adminErr(err))
				return
			}
			writeJSON(w, r, Options{}, http.StatusOK, out)
		}))
	}
	// Response shapes are those of openapi/sync/v1 (listQuarantine, listExceptions, getSeriesRegister, listSyncAlerts).
	get("GET /sync/v1/quarantine", "listQuarantine", service.PermQuarantineRead, func(ctx context.Context) (any, error) {
		l, err := g.ListQuarantine(ctx)
		items := make([]heldDTO, 0, len(l))
		for _, q := range l {
			items = append(items, heldDTO{Origin: q.Ref.Origin, Stream: q.Ref.Stream, Seq: q.Ref.Seq, Reason: q.Reason, Intent: q.Intent, Number: q.Number})
		}
		return map[string]any{"items": items}, err
	})
	get("GET /sync/v1/exceptions", "listExceptions", service.PermExceptionsRead, func(ctx context.Context) (any, error) {
		l, err := g.ListExceptions(ctx)
		items := make([]exceptionDTO, 0, len(l))
		for _, q := range l {
			items = append(items, exceptionDTO{Origin: q.Ref.Origin, Stream: q.Ref.Stream, Seq: q.Ref.Seq, Flag: strings.Join(q.Marks, ","), Intent: q.Intent, Number: q.Number})
		}
		return map[string]any{"items": items}, err
	})
	get("GET /sync/v1/series-register", "getSeriesRegister", service.PermRegisterRead, func(ctx context.Context) (any, error) {
		rep, err := g.ListRegister(ctx)
		return map[string]any{"items": registerRows(rep)}, err
	})
	get("GET /sync/v1/alerts", "listSyncAlerts", service.PermExceptionsRead, func(ctx context.Context) (any, error) {
		l, err := g.ListAlerts(ctx)
		items := make([]alertDTO, 0, len(l))
		for _, a := range l {
			items = append(items, alertDTO{Code: a.Kind, Audience: a.Audience, Severity: a.Severity, Detail: a.Detail})
		}
		return map[string]any{"items": items}, err
	})
	post("POST /sync/v1/quarantine/release", "releaseQuarantine", service.PermQuarantineManage, func(ctx context.Context, d Decision) (any, error) {
		_, err := g.ReleaseAs(ctx, d.Ref, d.Reason)
		return d.Ref, err
	})
	post("POST /sync/v1/quarantine/discard", "discardQuarantine", service.PermQuarantineManage, func(ctx context.Context, d Decision) (any, error) {
		return d.Ref, g.DiscardAs(ctx, d.Ref, d.Reason)
	})
	post("POST /sync/v1/quarantine/confirm", "confirmSyncQuarantine", service.PermQuarantineConfirm, func(ctx context.Context, d Decision) (any, error) {
		return d.Ref, g.ConfirmAs(ctx, d.Ref, d.Reason, d.H)
	})
	Emit(mux, g, a) // POST /internal/v1/emit, behind the same guard (service tokens)
}

func adminErr(err error) error {
	switch {
	case errors.Is(err, service.ErrNotFound):
		return apperr.New(apperr.NotFound, "sync.not_found", "not found")
	case errors.Is(err, service.ErrReasonRequired):
		return apperr.New(apperr.Validation, "sync.reason_required", "a reason of 1 to 200 characters is required")
	case errors.Is(err, service.ErrSelfRelease):
		return apperr.New(apperr.Forbidden, "sync.self_decision", "a member cannot decide a hold on their own op")
	case errors.Is(err, service.ErrConfirmHash):
		return apperr.New(apperr.Validation, "sync.confirm_hash_required", "the confirmation must carry the hash of the held op")
	case errors.Is(err, service.ErrNeedsVendor), errors.Is(err, service.ErrNeedsRecoverPerm), errors.Is(err, service.ErrDiscardNumbered), errors.Is(err, service.ErrCannotRelease):
		return apperr.New(apperr.Conflict, "sync.decision_not_allowed", err.Error())
	}
	return mapErr(err)
}
