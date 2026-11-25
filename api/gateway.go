package api

import (
	"context"
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
	c := engine.Caller{ID: cl.DeviceID, Kind: cred.Cred.Kind, Store: cred.Cred.Store, Outlet: cred.Cred.OutletID, Brand: cred.Cred.BrandID}
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
