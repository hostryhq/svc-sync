package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/hub"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// identityNode builds the hub from identity's pack source: the stored pack, then a refresh when identity answers.
func identityNode(ctx context.Context, log *slog.Logger, get func(string) string) (*node, error) {
	dir := envOr(get, "SYNC_HUB_STATE_DIR", "hub-state")
	_, keyPath, dbPath := statePaths(dir)
	st, err := readState(dir)
	if err != nil {
		return nil, err
	}
	prov, err := provider(get)
	if err != nil {
		return nil, err
	}
	if prov.Tier() != st.Tier {
		return nil, errors.New("the key provider tier differs from the one this hub was activated with: " + st.Tier)
	}
	key, err := readKey(keyPath, prov)
	if err != nil {
		return nil, err
	}
	store, err := openStore(dbPath, prov)
	if err != nil {
		return nil, err
	}
	pack, err := hub.LoadStoredPack(ctx, store, st.Tenant, st.DeviceID, packPolicy(get))
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	key.Kid = pack.Cred.Kid
	cfg := hub.Config{Tenant: pack.Tenant, Outlet: pack.Outlet, Brand: pack.Brand, Cred: sp.CredentialEnvelope{Cred: pack.Cred}, CredJWS: pack.CredJWS, Key: key,
		IdentityPub: pack.IdentityKeys[0], CloudKeys: map[string]*hub.PubKey{pack.OpKid: pack.OpKey}, Store: store, Now: time.Now, Log: log,
		PIIToUnprotected: piiLift(get)}
	if len(pack.IdentityKeys) > 1 {
		cfg.IdentityNext = pack.IdentityKeys[1]
	}
	h, err := hub.New(ctx, cfg)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	if err := h.ApplyPack(ctx, pack); err != nil {
		_ = store.Close()
		return nil, err
	}
	n := &node{h: h, close: func() { _ = store.Close() }, cloudURL: get("SYNC_HUB_CLOUD_URL")}
	if base := get("SYNC_HUB_IDENTITY_URL"); base != "" {
		idc := &hub.IdentityClient{Base: base, Policy: packPolicy(get)}
		n.token = func(ctx context.Context) (string, error) { return idc.Token(ctx, st.DeviceID, key) }
		n.refresh = func(ctx context.Context) error {
			p, err := idc.Pack(ctx, st.DeviceID, key)
			if err != nil {
				return err
			}
			return h.ApplyPack(ctx, p)
		}
	}
	return n, nil
}

func piiLift(get func(string) string) bool {
	return get("SYNC_HUB_DEV_PII_LIFT") == "1" && envAllowsDev(get("HOSTRY_ENV"))
}

func run(log *slog.Logger, get func(string) string) error {
	if err := devlanGuard(get("HOSTRY_ENV")); err != nil {
		return err
	}
	if get("SYNC_HUB_DEV_PII_LIFT") == "1" && !envAllowsDev(get("HOSTRY_ENV")) {
		return errors.New("SYNC_HUB_DEV_PII_LIFT lifts the personal-data placement rule and needs HOSTRY_ENV dev, test or ci")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	n, ok, err := filePack(ctx, get, log)
	if err != nil {
		return err
	}
	if !ok {
		if n, err = identityNode(ctx, log, get); err != nil {
			return err
		}
	}
	defer n.close()
	return serve(ctx, log, get, n)
}

func serve(ctx context.Context, log *slog.Logger, get func(string) string, n *node) error {
	h := n.h
	if n.refresh != nil {
		rc, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := n.refresh(rc); err != nil {
			log.Warn("pack refresh at start failed; running on the stored pack", "err", err.Error())
		}
		cancel()
		h.SetPackRefresh(n.refresh)
	}
	if n.token != nil && n.cloudURL != "" {
		h.SetUpstream(&engine.HTTPTransport{Base: n.cloudURL, Authorize: func(r *http.Request, _ []byte) error {
			t, err := n.token(r.Context())
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+t)
			return nil
		}})
		go h.RunUpstream(ctx, 2*time.Second)
	}
	addr := envOr(get, "SYNC_HUB_ADDR", ":8082")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if get("SYNC_HUB_MDNS") != "0" {
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		p, _ := strconv.Atoi(port)
		if err := hub.Advertise(ctx, hub.Advertisement{HubID: h.ID(), Outlet: h.Outlet(), Port: p, Version: 1}); err != nil {
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
	var l net.Listener = tls.NewListener(ln, h.TLSConfig())
	mode := "tls1.3"
	if devlanBuild && plainRequested(get) {
		l, mode = ln, "PLAIN HTTP (devlan)"
	}
	log.Info("hub listening", "addr", ln.Addr().String(), "transport", mode)
	if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
