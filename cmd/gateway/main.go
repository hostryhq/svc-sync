// Command gateway is the cloud sync gateway (ADR-0002 S11). Wiring only. Environment:
//
//	SYNC_DB_DSN    postgres:// DSN (or a SQLite path for local runs)
//	SYNC_ADDR      listen address (default :8081)
//	SYNC_DEV_STUB  "1" runs with the identity stub and a test token issuer (local development only)
//
// The production directory (device credentials, series registry, packs, proof check) comes from
// generated clients of svc-identity and svc-tenancy, which Phase 1b delivers; until they are wired
// the gateway refuses to start without SYNC_DEV_STUB so that no stub can run by accident.
// There is no deployment in Phase 1 (ADR-0001 AM12); cmd/devstack is the runnable stack for tests.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/svc-sync/api"
	"github.com/hostryhq/svc-sync/devepoch"
	"github.com/hostryhq/svc-sync/identitystub"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("gateway stopped", "err", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	dsn := os.Getenv("SYNC_DB_DSN")
	if dsn == "" {
		return errors.New("SYNC_DB_DSN is required")
	}
	if os.Getenv("SYNC_DEV_STUB") != "1" {
		return errors.New("the identity and tenancy directory clients are not wired yet (Phase 1b); set SYNC_DEV_STUB=1 for local development")
	}
	addr := os.Getenv("SYNC_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	st, err := repository.Open(dsn)
	if err != nil {
		return err
	}
	defer st.Close()
	id, err := identitystub.New(time.Now, nil)
	if err != nil {
		return err
	}
	issuer := authtest.NewTenantIssuer(clock.Func(time.Now))
	// Development only: a platform_meta of its own in the service database. Production reads the real
	// one with restore.NewReader(SYNC_PLATFORM_DSN) once identity and tenancy clients exist.
	ep, err := devepoch.Reader(ctx, dsn)
	if err != nil {
		return err
	}
	gw, err := service.New(ctx, service.Config{Store: st, Epoch: ep, Dir: id, OpKey: id.CloudKey, Now: time.Now, Log: log, Outbox: st.Dialect() == "postgres"})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	api.Mount(mux, api.Options{Auth: api.BearerAuth{Verifier: issuer.Verifier(), Dir: id}, Backend: api.GatewayBackend{G: gw}})
	api.Admin(mux, gw, issuer.Verifier())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := st.DB().PingContext(r.Context()); err != nil || gw.Guard().Check(r.Context()) != nil {
			http.Error(w, `{"status":"fail"}`, http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sc, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = srv.Shutdown(sc)
	}()
	log.Info("gateway listening (dev stub directory)", "addr", addr, "epoch", gw.Epoch())
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
