// Package double is the in-memory test double of the sync gateway (go-service-standard, test-strategy).
// It implements the public contract in api-specs openapi/sync/v1 (read through contract/specs) with deterministic time and ids,
// an in-memory store, a permissive-but-real identity stub, and failure injection (5xx, slow
// responses, dropped connections) so callers can test resilience. It runs the gateway service code
// on an in-memory SQLite store; the shared contract suite (contract/suite) is what keeps it honest.
package double

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-sync/api"
	"github.com/hostryhq/svc-sync/devepoch"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/identitystub"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Tenant and Outlet are the fixed ids of the double's single organisation.
const (
	Tenant = "018f0000-0000-7000-8000-0000000000a0"
	Outlet = "018f0000-0000-7000-8000-0000000000a1"
	Brand  = "018f0000-0000-7000-8000-0000000000b1"
)

// Double is the running double.
type Double struct {
	Identity *identitystub.Identity
	Issuer   *authtest.Issuer
	Services *authtest.ServiceRegistry
	Gateway  *service.Gateway
	Store    repository.Store

	mu      sync.Mutex
	now     time.Time
	h       http.Handler
	failN   int
	failSt  int
	delay   time.Duration
	devices int
	dropN   int
}

// New starts a double with a fixed clock (2026-11-24 09:00 IST).
func New(ctx context.Context) (*Double, error) {
	d := &Double{now: time.Date(2026, 11, 24, 3, 30, 0, 0, time.UTC)}
	var err error
	if d.Identity, err = identitystub.New(d.Now, nil); err != nil {
		return nil, err
	}
	d.Issuer = authtest.NewTenantIssuer(clock.Func(d.Now))
	d.Identity.SetMember(Tenant, "m1", "order.create", "order.edit", "payment.record", "bill.finalize", "bill.credit_note.create", "kds.bump", "session.open", "menu.manage", "menu.price.edit")
	if d.Store, err = repository.Open("file:double-" + fmt.Sprint(time.Now().UnixNano()) + "?mode=memory&cache=shared"); err != nil {
		return nil, err
	}
	ep, err := devepoch.Reader(ctx, "file:double-platform-"+fmt.Sprint(time.Now().UnixNano())+"?mode=memory&cache=shared")
	if err != nil {
		return nil, err
	}
	if d.Gateway, err = service.New(ctx, service.Config{Store: d.Store, Epoch: ep, Dir: d.Identity, OpKey: d.Identity.CloudKey, Now: d.Now}); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	api.Mount(mux, api.Options{Auth: api.BearerAuth{Verifier: d.Issuer.Verifier(), Dir: d.Identity}, Backend: api.GatewayBackend{G: d.Gateway}})
	d.Services = authtest.NewServiceRegistry(clock.Func(d.Now), "admin", "sync", "catalog", "billing", "orders")
	api.Admin(mux, d.Gateway, api.AdminAuth{Tenant: d.Issuer.Verifier(), Services: d.Services.Verifier("sync"),
		Audit: &repository.AccessSink{S: d.Store.(*repository.SQL)}, Clock: clock.Func(d.Now)})
	d.h = mux
	return d, nil
}

// ServiceToken mints a service token of the calling service for a tenant (empty tenant: a token that carries none).
func (d *Double) ServiceToken(caller, tenant string) string {
	tok, err := d.Services.Signer(caller).Sign("sync", tenant)
	if err != nil {
		panic(err)
	}
	return tok
}

// Now is the deterministic clock.
func (d *Double) Now() time.Time { d.mu.Lock(); defer d.mu.Unlock(); return d.now }

// Advance moves the clock.
func (d *Double) Advance(x time.Duration) { d.mu.Lock(); d.now = d.now.Add(x); d.mu.Unlock() }

// FailNext makes the next n requests answer with status (for example 503) without reaching the service.
func (d *Double) FailNext(n, status int) { d.mu.Lock(); d.failN, d.failSt = n, status; d.mu.Unlock() }

// DropNext makes the next n requests process normally but lose the response (the connection is
// aborted after the service committed), which is the case clients must be idempotent against.
func (d *Double) DropNext(n int) { d.mu.Lock(); d.dropN = n; d.mu.Unlock() }

// SetDelay slows every response.
func (d *Double) SetDelay(x time.Duration) { d.mu.Lock(); d.delay = x; d.mu.Unlock() }

// Handler is the double's HTTP handler, with failure injection in front.
func (d *Double) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		fail, st, delay, drop := d.failN > 0, d.failSt, d.delay, d.dropN > 0
		if fail {
			d.failN--
		} else if drop {
			d.dropN--
		}
		d.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		if fail {
			http.Error(w, "injected failure", st)
			return
		}
		if drop {
			d.h.ServeHTTP(discard{}, r)
			panic(http.ErrAbortHandler)
		}
		d.h.ServeHTTP(w, r)
	})
}

type discard struct{}

func (discard) Header() http.Header         { return http.Header{} }
func (discard) Write(b []byte) (int, error) { return len(b), nil }
func (discard) WriteHeader(int)             {}

// Dev is a registered device of the double.
type Dev struct {
	ID   string
	Kind string
	Key  *sp.KeyPair
	Cred sp.CredentialEnvelope
	Sale string
	d    *Double
}

// NewDevice registers a device with a sale and a credit-note series and a pack "v1".
func (d *Double) NewDevice(kind string) (*Dev, error) {
	d.mu.Lock()
	d.devices++
	id := fmt.Sprintf("dev-%02d-%s", d.devices, kind)
	d.mu.Unlock()
	kp, err := sp.NewKeyPair("k-"+id, nil)
	if err != nil {
		return nil, err
	}
	cred, err := d.Identity.Activate(Tenant, Outlet, Brand, id, kind, kp, "")
	if err != nil {
		return nil, err
	}
	dv := &Dev{ID: id, Kind: kind, Key: kp, Cred: cred, d: d}
	if kind == sp.KindPOS || kind == sp.KindWaiter {
		dv.Sale = d.Identity.IssueSeries(Tenant, id, "tax_invoice", directory.SeriesActive)
	}
	d.Identity.IssuePack(Tenant, id, "v1", 30*24*time.Hour)
	return dv, nil
}

// Token mints a device access token.
func (v *Dev) Token() string {
	return v.d.Issuer.Mint(authtest.Spec{Type: auth.TypeDevice, Tenant: ids.ID(Tenant), Device: v.ID})
}

// DrainToken mints a drain token (recovers non-empty for a recovery drain token).
func (v *Dev) DrainToken(recovers string) string {
	sub := ""
	if recovers != "" {
		sub = "recovers:" + recovers
	}
	return v.d.Issuer.Mint(authtest.Spec{Type: auth.TypeDrain, Tenant: ids.ID(Tenant), Device: v.ID, Subject: sub})
}
