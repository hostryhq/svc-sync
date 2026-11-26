//go:build devlan

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/repository"
)

// devlanBuild is true in a binary built with the tag devlan: it may serve plain HTTP and read a pack file (ADR-0002 A3.1 item 1,
// A3.4 item 5). Such a binary refuses to start outside HOSTRY_ENV dev, test and ci.
const devlanBuild = true

func devlanGuard(env string) error {
	if !envAllowsDev(env) {
		return fmt.Errorf("this binary was built with the devlan tag (plain HTTP listener, pack file) and refuses HOSTRY_ENV %q: dev, test or ci only", env)
	}
	return nil
}

// plainRequested reports whether the dev plain listener was asked for.
func plainRequested(get func(string) string) bool { return get("SYNC_HUB_PLAIN") == "1" }

// filePack is the `file` pack source (A3.4 item 5): the PoC JSON pack, with a cloud token file. devlan only.
func filePack(ctx context.Context, get func(string) string, log *slog.Logger) (*node, bool, error) {
	path := get("SYNC_HUB_PACK")
	if path == "" {
		return nil, false, nil
	}
	cfg, pack, err := hub.LoadPack(path)
	if err != nil {
		return nil, true, err
	}
	st, err := repository.Open(envOr(get, "SYNC_HUB_DB", "hub.db"))
	if err != nil {
		return nil, true, err
	}
	cfg.Store, cfg.Now, cfg.Log = st, hubNow, log
	cfg.PIIToUnprotected = get("SYNC_HUB_DEV_PII_LIFT") == "1"
	h, err := hub.New(ctx, cfg)
	if err != nil {
		_ = st.Close()
		return nil, true, err
	}
	n := &node{h: h, close: func() { _ = st.Close() }, cloudURL: pack.CloudURL}
	if tf := get("SYNC_HUB_CLOUD_TOKEN_FILE"); tf != "" {
		n.token = func(context.Context) (string, error) {
			b, err := os.ReadFile(tf)
			if err != nil {
				return "", err
			}
			t := strings.TrimSpace(string(b))
			if t == "" {
				return "", errors.New("empty cloud token file")
			}
			return t, nil
		}
	}
	return n, true, nil
}
