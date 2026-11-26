package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/keyprotect"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// activate registers this hub with identity (ADR-0002 A3.4 item 2): it makes the device key through the key provider, activates
// with the 8-character code, and stores the signed hub pack in the encrypted store. It needs the internet once.
func activate(log *slog.Logger, get func(string) string) error {
	if err := devlanGuard(get("HOSTRY_ENV")); err != nil {
		return err
	}
	dir := envOr(get, "SYNC_HUB_STATE_DIR", "hub-state")
	statePath, keyPath, dbPath := statePaths(dir)
	if _, err := os.Stat(statePath); err == nil {
		return errors.New("this hub is already activated; a replaced hub is a new device with a new activation code (A3.1 item 6)")
	}
	base, code := get("SYNC_HUB_IDENTITY_URL"), get("SYNC_HUB_ACTIVATION_CODE")
	if base == "" || code == "" {
		return errors.New("SYNC_HUB_IDENTITY_URL and SYNC_HUB_ACTIVATION_CODE are required")
	}
	if !strings.HasPrefix(base, "https://") && !envAllowsDev(get("HOSTRY_ENV")) {
		return errors.New("SYNC_HUB_IDENTITY_URL must be https outside HOSTRY_ENV dev, test and ci")
	}
	prov, err := provider(get)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	key, err := sp.NewKeyPair("", nil)
	if err != nil {
		return err
	}
	if err := writeKey(keyPath, prov, key); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	idc := &hub.IdentityClient{Base: base, Policy: packPolicy(get)}
	// The tier is shown to the owner at activation; a `dev` key file reports os-software and declares store unprotected (A3.5).
	act, err := idc.Activate(ctx, code, envOr(get, "SYNC_HUB_NAME", "Hub"), string(ids.New()), key, "os-software", keyprotect.StoreClaim(prov))
	if err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	st, err := openStore(dbPath, prov)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := hub.StorePack(ctx, st, act.Pack.Tenant, act.Pack.Raw); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(state{DeviceID: act.DeviceID, Tenant: act.Pack.Tenant, Outlet: act.Pack.Outlet, Brand: act.Pack.Brand,
		Tier: prov.Tier(), Store: act.Pack.Cred.Store}, "", "  ")
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		return err
	}
	log.Info("hub activated", "device_id", act.DeviceID, "key_tier", prov.Tier(), "store", act.Pack.Cred.Store, "pack_v", act.Pack.PackV)
	return nil
}
