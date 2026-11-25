package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/keyprotect"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// node is a hub ready to serve, whatever its pack source.
type node struct {
	h        *hub.Hub
	close    func()
	cloudURL string
	// token returns the bearer for the cloud gateway; nil means the hub syncs on the LAN only.
	token func(ctx context.Context) (string, error)
	// refresh fetches and applies a fresh pack; nil for the file source.
	refresh func(ctx context.Context) error
}

func envAllowsDev(env string) bool { return env == "dev" || env == "test" || env == "ci" }

func envOr(get func(string) string, k, def string) string {
	if v := get(k); v != "" {
		return v
	}
	return def
}

// provider chooses the key provider: DPAPI on Windows, the dev provider where it is allowed and asked for.
func provider(get func(string) string) (keyprotect.Provider, error) {
	which := get("SYNC_HUB_KEY_PROVIDER")
	if which == "" && runtime.GOOS == "windows" {
		which = "dpapi"
	}
	switch which {
	case "dpapi":
		return keyprotect.NewDPAPI()
	case "dev":
		return keyprotect.NewDev(get("HOSTRY_ENV"), get("SYNC_HUB_DEV_KEY_FILE"))
	}
	return nil, errors.New("SYNC_HUB_KEY_PROVIDER must be dpapi or dev (dpapi is Windows only; dev is for CI and refuses production)")
}

// state is what the hub keeps in the clear beside its encrypted store: ids and the tier, no secret. The device key is in
// device.key, wrapped by the key provider (A3.2 item 4); the pack is in the encrypted store.
type state struct {
	DeviceID string `json:"device_id"`
	Tenant   string `json:"tenant_id"`
	Outlet   string `json:"outlet_id"`
	Brand    string `json:"brand_id"`
	Tier     string `json:"key_tier"`
	Store    string `json:"store"`
}

func statePaths(dir string) (statePath, keyPath, dbPath string) {
	return filepath.Join(dir, "hub-device.json"), filepath.Join(dir, "device.key"), filepath.Join(dir, "hub.db")
}

func writeKey(path string, p keyprotect.Provider, k *sp.KeyPair) error {
	der, err := x509.MarshalPKCS8PrivateKey(k.Priv)
	if err != nil {
		return err
	}
	w, err := p.Wrap(der)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(w)), 0o600)
}

func readKey(path string, p keyprotect.Provider) (*sp.KeyPair, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	w, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, errors.New("device.key is not valid")
	}
	der, err := p.Unwrap(w)
	if err != nil {
		return nil, fmt.Errorf("device.key does not unwrap with this key provider: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	ec, ok := k.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("device.key does not hold an ECDSA key")
	}
	return &sp.KeyPair{Priv: ec}, nil
}

func readState(dir string) (state, error) {
	var s state
	sp, _, _ := statePaths(dir)
	b, err := os.ReadFile(sp)
	if err != nil {
		return s, fmt.Errorf("this hub is not activated (run `hub activate`): %w", err)
	}
	return s, json.Unmarshal(b, &s)
}

func openStore(dbPath string, p keyprotect.Provider) (*repository.SQL, error) {
	return repository.OpenEncrypted("file:"+dbPath, repository.EncryptOptions{Provider: p})
}
