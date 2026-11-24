package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// GatewayBackend adapts the gateway service to the API.
type GatewayBackend struct{ G *service.Gateway }

// Hello implements Backend.
func (b GatewayBackend) Hello(ctx context.Context, p Principal, req sp.HelloRequest) (sp.HelloResponse, error) {
	return b.G.Hello(ctx, p.Tenant, p.Caller, req)
}

// Push implements Backend.
func (b GatewayBackend) Push(ctx context.Context, p Principal, req sp.PushRequest) (sp.PushResponse, error) {
	return b.G.Push(ctx, p.Tenant, p.Caller, req)
}

// Pull implements Backend.
func (b GatewayBackend) Pull(ctx context.Context, p Principal, req sp.PullRequest) (sp.PullResponse, error) {
	return b.G.Pull(ctx, p.Tenant, p.Caller, req)
}

// Upload implements Backend.
func (b GatewayBackend) Upload(ctx context.Context, p Principal, req sp.PushRequest) (sp.PushResponse, error) {
	r, err := b.G.QuarantineUpload(ctx, p.Tenant, p.Caller, req)
	if errors.Is(err, service.ErrForbidden) {
		return r, apperr.New(apperr.Forbidden, "sync.upload_not_authorised", "this token may not upload for that origin")
	}
	return r, err
}

// Snapshot implements Backend.
func (b GatewayBackend) Snapshot(ctx context.Context, p Principal) (sp.Snapshot, error) {
	return b.G.Snapshot(ctx, p.Tenant, p.Caller)
}

// Poke implements Backend.
func (b GatewayBackend) Poke(ctx context.Context, p Principal, after int64, wait time.Duration) int64 {
	return b.G.Poke(ctx, p.Tenant, after, wait)
}

// BearerAuth authenticates device and drain tokens with the go-auth verifier (ES256, issuer,
// audience, expiry, lifetime caps), then resolves the device in the directory. Tenant and outlet
// come from the verified token and the directory, never from the request body.
type BearerAuth struct {
	Verifier *auth.Verifier
	Dir      directory.Directory
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return h[7:]
	}
	return ""
}

func unauth() error {
	return apperr.New(apperr.Unauthenticated, "auth.invalid_token", "authentication required")
}

// Authenticate implements Authenticator.
func (a BearerAuth) Authenticate(r *http.Request, _ []byte, route Route) (Principal, error) {
	cl, err := a.Verifier.Verify(bearer(r))
	if err != nil {
		return Principal{}, unauth()
	}
	if cl.DeviceID == "" {
		return Principal{}, unauth()
	}
	switch {
	case route == RouteUpload && cl.Type != auth.TypeDrain:
		return Principal{}, apperr.New(apperr.Forbidden, "sync.upload_needs_drain_token", "the quarantine upload takes only a drain token")
	case route == RouteSync && cl.Type != auth.TypeDevice:
		// A drain token is refused at every endpoint except the upload (KL2).
		return Principal{}, unauth()
	}
	cred, ok := a.Dir.Credential(cl.TenantID, cl.DeviceID)
	if !ok {
		return Principal{}, unauth()
	}
	revoked, _ := a.Dir.Revoked(cl.TenantID, cl.DeviceID)
	c := engine.Caller{ID: cl.DeviceID, Kind: cred.Cred.Kind, Outlet: cred.Cred.OutletID, Brand: cred.Cred.BrandID}
	if cl.Type == auth.TypeDrain {
		c.Drain = true
		if strings.HasPrefix(cl.Subject, "recovers:") {
			c.Recovers = strings.TrimPrefix(cl.Subject, "recovers:")
		} else if !revoked {
			return Principal{}, unauth() // an ordinary drain token is for a revoked device
		}
	} else if revoked {
		return Principal{}, unauth() // a revoked device's access token is dead everywhere (ADR-0005 section 4)
	}
	return Principal{Tenant: cl.TenantID, Caller: c}, nil
}

// Admin mounts the manager-facing endpoints: quarantine, exceptions, series register, alerts. They
// need a member token (user or support), never a device token, so flags and attribution labels
// are unreachable from a device (A1.2 item 2, RB1).
func Admin(mux *http.ServeMux, g *service.Gateway, v *auth.Verifier) {
	type who struct {
		tenant string
		cl     *auth.Claims
	}
	authn := func(r *http.Request, perm string) (who, error) {
		cl, err := v.Verify(bearer(r))
		if err != nil || (cl.Type != auth.TypeUser && cl.Type != auth.TypeSupport) {
			return who{}, unauth()
		}
		if !granted(cl.Grants, perm) {
			return who{}, apperr.New(apperr.Forbidden, "auth.permission_denied", "permission denied")
		}
		return who{cl.TenantID, cl}, nil
	}
	handle := func(pattern, perm string, fn func(w who, r *http.Request) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			me, err := authn(r, perm)
			if err != nil {
				apperr.WriteProblem(w, r, err)
				return
			}
			out, err := fn(me, r)
			if err != nil {
				apperr.WriteProblem(w, r, adminErr(err))
				return
			}
			writeJSON(w, r, Options{}, http.StatusOK, out)
		})
	}
	handle("GET /sync/v1/quarantine", "sync.quarantine.manage", func(w who, r *http.Request) (any, error) {
		return g.Quarantine(r.Context(), w.tenant)
	})
	handle("GET /sync/v1/exceptions", "sync.exceptions.read", func(w who, r *http.Request) (any, error) {
		return g.Exceptions(r.Context(), w.tenant)
	})
	handle("GET /sync/v1/series-register", "sync.register.read", func(w who, r *http.Request) (any, error) {
		return g.Register(r.Context(), w.tenant)
	})
	handle("GET /sync/v1/alerts", "sync.exceptions.read", func(w who, r *http.Request) (any, error) {
		return g.Alerts(r.Context(), w.tenant)
	})
	handle("POST /sync/v1/quarantine/release", "sync.quarantine.manage", func(w who, r *http.Request) (any, error) {
		var ref sp.Ref
		if err := json.NewDecoder(r.Body).Decode(&ref); err != nil {
			return nil, apperr.New(apperr.Validation, "sync.bad_request", "bad body")
		}
		st, err := g.Release(r.Context(), w.tenant, ref, service.ReleaseOpts{
			// Vendor confirmation comes only from a support token in act mode (ADR-0005 A2.5).
			VendorConfirmed: w.cl.Type == auth.TypeSupport && w.cl.Mode == auth.ModeAct,
			DeviceRecover:   w.cl.Type == auth.TypeUser && granted(w.cl.Grants, "device.recover"),
		})
		return map[string]string{"status": st}, err
	})
	handle("POST /sync/v1/quarantine/discard", "sync.quarantine.manage", func(w who, r *http.Request) (any, error) {
		var ref sp.Ref
		if err := json.NewDecoder(r.Body).Decode(&ref); err != nil {
			return nil, apperr.New(apperr.Validation, "sync.bad_request", "bad body")
		}
		return map[string]string{}, g.Discard(r.Context(), w.tenant, ref)
	})
}

func adminErr(err error) error {
	switch {
	case errors.Is(err, service.ErrNotFound):
		return apperr.New(apperr.NotFound, "sync.not_found", "not found")
	case errors.Is(err, service.ErrNeedsVendor), errors.Is(err, service.ErrNeedsRecoverPerm), errors.Is(err, service.ErrDiscardNumbered), errors.Is(err, service.ErrCannotRelease):
		return apperr.New(apperr.Conflict, "sync.decision_not_allowed", err.Error())
	}
	return mapErr(err)
}

func granted(gs []auth.Grant, perm string) bool {
	for _, g := range gs {
		for _, p := range g.Perms {
			if p == perm || p == auth.Wildcard {
				return true
			}
		}
	}
	return false
}
