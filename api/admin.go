package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

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
	Reason string `json:"reason"`
}

// Admin mounts the manager-facing endpoints: quarantine, exceptions, series register, alerts and the
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
	get("GET /sync/v1/quarantine", "listSyncQuarantine", service.PermQuarantineRead, func(ctx context.Context) (any, error) { return g.ListQuarantine(ctx) })
	get("GET /sync/v1/exceptions", "listSyncExceptions", service.PermExceptionsRead, func(ctx context.Context) (any, error) { return g.ListExceptions(ctx) })
	get("GET /sync/v1/series-register", "getSyncSeriesRegister", service.PermRegisterRead, func(ctx context.Context) (any, error) { return g.ListRegister(ctx) })
	get("GET /sync/v1/alerts", "listSyncAlerts", service.PermExceptionsRead, func(ctx context.Context) (any, error) { return g.ListAlerts(ctx) })
	post("POST /sync/v1/quarantine/release", "releaseSyncQuarantine", service.PermQuarantineManage, func(ctx context.Context, d Decision) (any, error) {
		st, err := g.ReleaseAs(ctx, d.Ref, d.Reason)
		return map[string]string{"status": st}, err
	})
	post("POST /sync/v1/quarantine/discard", "discardSyncQuarantine", service.PermQuarantineManage, func(ctx context.Context, d Decision) (any, error) {
		return map[string]string{}, g.DiscardAs(ctx, d.Ref, d.Reason)
	})
	post("POST /sync/v1/quarantine/confirm", "confirmSyncQuarantine", service.PermQuarantineConfirm, func(ctx context.Context, d Decision) (any, error) {
		return map[string]string{}, g.ConfirmAs(ctx, d.Ref, d.Reason)
	})
}

func adminErr(err error) error {
	switch {
	case errors.Is(err, service.ErrNotFound):
		return apperr.New(apperr.NotFound, "sync.not_found", "not found")
	case errors.Is(err, service.ErrReasonRequired):
		return apperr.New(apperr.Validation, "sync.reason_required", "a reason of 1 to 200 characters is required")
	case errors.Is(err, service.ErrNeedsVendor), errors.Is(err, service.ErrNeedsRecoverPerm), errors.Is(err, service.ErrDiscardNumbered), errors.Is(err, service.ErrCannotRelease):
		return apperr.New(apperr.Conflict, "sync.decision_not_allowed", err.Error())
	}
	return mapErr(err)
}
