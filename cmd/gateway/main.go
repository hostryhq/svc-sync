// Command gateway is the cloud sync gateway (ADR-0002 S11). Wiring only. Environment:
//
//	SYNC_DB_DSN    postgres:// DSN (or a SQLite path for local runs)
//	SYNC_ADDR      listen address (default :8081)
//	SYNC_DIRECTORY "identity" (the real directory, below) or "stub" (default; needs SYNC_DEV_STUB=1, local development only)
//	SYNC_DEV_STUB  "1" runs with the identity stub and a test token issuer (local development only)
//	HOSTRY_ENV, SYNC_DEV_REGISTER=1  mount /dev/v1 device registration and token routes (stub directory; dev, test or ci only; see internal/devreg)
//	SYNC_NATS_URL, SYNC_NATS_SEED_FILE, SYNC_RELAY_DSN  relay the outbox to NATS with go-common's outbox.Relay (config.go)
//
// The identity directory (ADR-0005 A3.2) is built from generated clients of svc-identity and svc-tenancy (realdir):
//
//	SYNC_IDENTITY_URL, SYNC_TENANCY_URL     base URLs of the two services
//	SYNC_SERVICE_SIGNING_KEY_FILE           PEM PKCS#8 P-256 key of sync's service tokens
//	SYNC_OP_SIGNING_KEY_FILE, SYNC_OP_KID   PEM PKCS#8 P-256 key that seals the gateway's own ops (public half in identity's packs)
//	SYNC_TENANT_JWKS                        identity's tenant JWKS (default SYNC_IDENTITY_URL/v1/jwks); verifies device and member tokens
//	SYNC_SERVICE_KEYS                       JWKS file of the service key registry (kid = service name); without it the internal routes (emit) and
//	                                        the vendor routes answer 401 to every service
//	SYNC_PLATFORM_DSN                       read-only DSN of platform_meta (the restore epoch); without it, only dev, test and ci fall back to
//	                                        an epoch of the service's own database
//	SYNC_DIRECTORY_STATE_FILE               optional file that persists the revocation cursor and set
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/restore"
	"github.com/hostryhq/svc-sync/api"
	"github.com/hostryhq/svc-sync/devepoch"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/identityclient"
	"github.com/hostryhq/svc-sync/identitystub"
	"github.com/hostryhq/svc-sync/internal/devreg"
	"github.com/hostryhq/svc-sync/realdir"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("gateway stopped", "err", err.Error())
		os.Exit(1)
	}
}

// wiring is what differs between the stub directory and the identity directory.
type wiring struct {
	dir      directory.Directory
	opKey    *sp.KeyPair
	tenant   *auth.Verifier
	services *auth.ServiceVerifier
	epoch    restore.EpochSource
	devMux   func(*http.ServeMux) // dev registration routes (stub only)
	ready    func() error
	// background runs until ctx ends (revocation poll, maintenance, event consumer).
	background func(ctx context.Context, gw *service.Gateway, log *slog.Logger)
	banner     string
}

func run(log *slog.Logger) error {
	dsn := os.Getenv("SYNC_DB_DSN")
	if dsn == "" {
		return errors.New("SYNC_DB_DSN is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var w wiring
	var err error
	switch d := os.Getenv("SYNC_DIRECTORY"); d {
	case "identity":
		w, err = identityWiring(ctx, dsn, log)
	case "", "stub":
		if os.Getenv("SYNC_DEV_STUB") != "1" {
			return errors.New("set SYNC_DIRECTORY=identity, or SYNC_DEV_STUB=1 for the stub directory (local development)")
		}
		if err := checkStub(os.Getenv("HOSTRY_ENV")); err != nil {
			return err
		}
		w, err = stubWiring(ctx, dsn)
	default:
		return fmt.Errorf("SYNC_DIRECTORY must be identity or stub, not %q", d)
	}
	if err != nil {
		return err
	}
	x, err := loadExtras(os.Getenv, dsn)
	if err != nil {
		return err
	}
	if x.DevRoutes && w.devMux == nil {
		return errors.New("SYNC_DEV_REGISTER needs the stub directory: the identity directory registers devices at identity")
	}
	addr := os.Getenv("SYNC_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	st, err := repository.Open(dsn)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.CheckAppRole(ctx); err != nil {
		if privilegedRoleAllowed(os.Getenv("HOSTRY_ENV")) {
			log.Warn("development only: " + err.Error())
		} else {
			return err // outside development a privileged role is refused
		}
	}
	gw, err := service.New(ctx, service.Config{Store: st, Epoch: w.epoch, Dir: w.dir, OpKey: w.opKey, Now: time.Now, Log: log, Outbox: st.Dialect() == "postgres"})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	api.Mount(mux, api.Options{Auth: api.BearerAuth{Verifier: w.tenant, Dir: w.dir}, Backend: api.GatewayBackend{G: gw}})
	api.Admin(mux, gw, api.AdminAuth{Tenant: w.tenant, Services: w.services, Audit: &repository.AccessSink{S: st}, Clock: clock.Func(time.Now)})
	if x.DevRoutes {
		w.devMux(mux)
		log.Warn("development only: device registration and token routes are mounted under /dev/v1")
	}
	if x.NatsURL != "" {
		if err := startRelay(ctx, x, st, dsn, log); err != nil {
			return err
		}
	}
	if w.background != nil {
		go w.background(ctx, gw, log)
	}
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("GET /readyz", func(rw http.ResponseWriter, r *http.Request) {
		if err := st.DB().PingContext(r.Context()); err != nil || gw.Guard().Check(r.Context()) != nil || (w.ready != nil && w.ready() != nil) {
			http.Error(rw, `{"status":"fail"}`, http.StatusServiceUnavailable)
			return
		}
		_, _ = rw.Write([]byte(`{"status":"ok"}`))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sc, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = srv.Shutdown(sc)
	}()
	log.Info("gateway listening ("+w.banner+")", "addr", addr, "epoch", gw.Epoch())
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func devOnly(env string) bool { return env == "dev" || env == "test" || env == "ci" }

// checkStub refuses SYNC_DEV_STUB (the stub directory with its in-process test issuer) outside dev, test and ci: whoever can set
// the variable must not be able to mint tokens the gateway trusts in a real environment (P2-M6).
func checkStub(env string) error {
	if !devOnly(env) {
		return fmt.Errorf("SYNC_DEV_STUB needs HOSTRY_ENV in dev, test or ci (got %q)", env)
	}
	return nil
}

// privilegedRoleAllowed says whether the gateway may start on a superuser or BYPASSRLS database role, which would void the
// row-level isolation of tenants: in dev, test and ci only, whatever SYNC_DEV_STUB says (P2-M6).
func privilegedRoleAllowed(env string) bool { return devOnly(env) }

func stubWiring(ctx context.Context, dsn string) (wiring, error) {
	id, err := identitystub.New(time.Now, nil)
	if err != nil {
		return wiring{}, err
	}
	issuer := authtest.NewTenantIssuer(clock.Func(time.Now))
	// Development only: a platform_meta of its own in the service database. Production reads the real
	// one with restore.NewReader(SYNC_PLATFORM_DSN).
	ep, err := devepoch.Reader(ctx, dsn)
	if err != nil {
		return wiring{}, err
	}
	services := authtest.NewServiceRegistry(clock.Func(time.Now), "admin", "sync", "catalog", "billing", "orders")
	w := wiring{dir: id, opKey: id.CloudKey, tenant: issuer.Verifier(), services: services.Verifier("sync"), epoch: ep, banner: "dev stub directory"}
	w.devMux = func(mux *http.ServeMux) {
		(&devreg.Registry{ID: id, Issuer: issuer, Now: time.Now, CloudURL: cloudURL(os.Getenv)}).Mount(mux)
	}
	return w, nil
}

// cloudURL is the URL a hub reaches this gateway at (SYNC_PUBLIC_URL, else the listen address on the loopback).
func cloudURL(get func(string) string) string {
	if u := get("SYNC_PUBLIC_URL"); u != "" {
		return u
	}
	addr := get("SYNC_ADDR")
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	return "http://" + addr
}

func identityWiring(ctx context.Context, dsn string, log *slog.Logger) (wiring, error) {
	dir, err := realdir.FromEnv(os.Getenv)
	if err != nil {
		return wiring{}, err
	}
	var problems []string
	opFile := os.Getenv("SYNC_OP_SIGNING_KEY_FILE")
	var opKey *sp.KeyPair
	if opFile == "" {
		problems = append(problems, "SYNC_OP_SIGNING_KEY_FILE is required")
	} else if k, err := identityclient.ReadKey(opFile); err != nil {
		problems = append(problems, "SYNC_OP_SIGNING_KEY_FILE: "+err.Error())
	} else {
		kid := os.Getenv("SYNC_OP_KID")
		if kid == "" {
			kid = "gateway-op-1"
		}
		opKey = &sp.KeyPair{Kid: kid, Priv: k}
	}
	jwks := os.Getenv("SYNC_TENANT_JWKS")
	if jwks == "" {
		jwks = strings.TrimRight(os.Getenv("SYNC_IDENTITY_URL"), "/") + "/v1/jwks"
	}
	var epoch restore.EpochSource
	switch pdsn := os.Getenv("SYNC_PLATFORM_DSN"); {
	case pdsn != "":
		epoch = restore.NewReader(pdsn)
	case devOnly(os.Getenv("HOSTRY_ENV")):
		if epoch, err = devepoch.Reader(ctx, dsn); err != nil {
			return wiring{}, err
		}
		log.Warn("development only: the restore epoch is read from the service's own database (SYNC_PLATFORM_DSN is not set)")
	default:
		problems = append(problems, "SYNC_PLATFORM_DSN is required outside dev, test and ci")
	}
	if len(problems) > 0 {
		return wiring{}, errors.New("gateway: " + strings.Join(problems, "; "))
	}
	keys := auth.NewCachedKeySet(keyLoader{src: jwks}, log)
	if err := keys.Refresh(ctx); err != nil {
		return wiring{}, fmt.Errorf("load the token signing keys from %s: %w", jwks, err)
	}
	go keys.Run(ctx, 5*time.Minute)
	svcKeys := auth.NewStaticKeySet(auth.KeyDoc{})
	if f := os.Getenv("SYNC_SERVICE_KEYS"); f != "" {
		doc, err := keyLoader{src: f}.Load(ctx)
		if err != nil {
			return wiring{}, fmt.Errorf("load the service keys from %s: %w", f, err)
		}
		svcKeys = auth.NewStaticKeySet(doc)
	} else {
		log.Warn("SYNC_SERVICE_KEYS is not set: no service token verifies, so emit and the vendor routes refuse every caller")
	}
	w := wiring{dir: dir, opKey: opKey, epoch: epoch, banner: "identity directory",
		tenant:   &auth.Verifier{Keys: keys, Issuer: envOr("SYNC_TENANT_ISSUER", "hostry-identity"), Audience: envOr("SYNC_TENANT_AUDIENCE", "hostry-tenant"), Realm: auth.RealmTenant},
		services: &auth.ServiceVerifier{Registry: svcKeys, Self: identityclient.ServiceName},
		ready:    dir.Ready}
	w.background = func(ctx context.Context, gw *service.Gateway, log *slog.Logger) {
		go dir.Run(ctx, 60*time.Second, func(err error) { log.Warn("revocation poll failed", "err", err.Error()) })
		go consumeTenancyEvents(ctx, dir, log)
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := gw.MaintainOnce(ctx); err != nil {
					log.Warn("maintenance", "err", err.Error())
				}
			}
		}
	}
	return w, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
