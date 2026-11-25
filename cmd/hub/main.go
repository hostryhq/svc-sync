// Command hub is the restaurant LAN hub (ADR-0002 S8) as a plain binary. Running it as a Windows
// service is the installer's job (Phase 2). Configuration is environment only:
//
//	SYNC_HUB_PACK        path to the pack file (credential, keys, peers, staff, series grants)
//	SYNC_HUB_DB          SQLite path of the hub's op store (default ./hub.db)
//	SYNC_HUB_ADDR        listen address (default :8082)
//	SYNC_HUB_CLOUD_TOKEN_FILE  file holding the current cloud access token (refreshed by the installer
//	                     agent from identity); the hub syncs only on the LAN if it is unset
//	SYNC_HUB_MDNS        "0" to disable the mDNS advertisement
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/repository"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("hub stopped", "err", err.Error())
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func run(log *slog.Logger) error {
	packPath := os.Getenv("SYNC_HUB_PACK")
	if packPath == "" {
		return errors.New("SYNC_HUB_PACK is required")
	}
	cfg, pack, err := hub.LoadPack(packPath)
	if err != nil {
		return err
	}
	st, err := repository.Open(env("SYNC_HUB_DB", "hub.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	cfg.Store, cfg.Now, cfg.Log = st, time.Now, log
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	h, err := hub.New(ctx, cfg)
	if err != nil {
		return err
	}
	if tf := os.Getenv("SYNC_HUB_CLOUD_TOKEN_FILE"); tf != "" && pack.CloudURL != "" {
		h.SetUpstream(&engine.HTTPTransport{Base: pack.CloudURL, Authorize: func(r *http.Request, _ []byte) error {
			b, err := os.ReadFile(tf)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(b)))
			return nil
		}})
		go h.RunUpstream(ctx, 2*time.Second)
	}
	addr := env("SYNC_HUB_ADDR", ":8082")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if env("SYNC_HUB_MDNS", "1") != "0" {
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		p, _ := strconv.Atoi(port)
		if err := hub.Advertise(ctx, hub.Advertisement{HubID: cfg.Cred.Cred.DeviceID, Outlet: cfg.Outlet, Port: p, Version: 1}); err != nil {
			log.Warn("mDNS advertisement unavailable; devices fall back to QR or manual address", "err", err.Error())
		}
	}
	srv := &http.Server{Handler: h.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sc, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(sc)
	}()
	log.Info("hub listening", "addr", ln.Addr().String())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
