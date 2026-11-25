package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/bus"
	"github.com/hostryhq/svc-sync/realdir"
)

// keyLoader loads a JWKS document from an http(s) URL or a file (the service key registry).
type keyLoader struct{ src string }

// Load implements auth.KeyLoader.
func (k keyLoader) Load(ctx context.Context) (auth.KeyDoc, error) {
	var b []byte
	if strings.HasPrefix(k.src, "http://") || strings.HasPrefix(k.src, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.src, nil)
		if err != nil {
			return auth.KeyDoc{}, err
		}
		cl := &http.Client{Timeout: 5 * time.Second}
		resp, err := cl.Do(req)
		if err != nil {
			return auth.KeyDoc{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return auth.KeyDoc{}, errors.New("jwks: status " + resp.Status)
		}
		if b, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20)); err != nil {
			return auth.KeyDoc{}, err
		}
	} else {
		var err error
		if b, err = os.ReadFile(k.src); err != nil {
			return auth.KeyDoc{}, err
		}
	}
	keys, err := auth.ParseJWKS(b)
	return auth.KeyDoc{Keys: keys}, err
}

// consumeTenancyEvents drops the directory's cached paper bill books when tenancy registers one
// (tenancy.manual_book.registered, A3.2 row 8). Without SYNC_NATS_URL the 60-second cache time is the only bound.
// The series events are not in sync's subscription (the event schemas do not list sync), so a series issued
// or closed is seen within the same 60 seconds.
func consumeTenancyEvents(ctx context.Context, dir *realdir.Directory, log *slog.Logger) {
	url, seed := os.Getenv("SYNC_NATS_URL"), os.Getenv("SYNC_NATS_SEED_FILE")
	if url == "" || seed == "" {
		return
	}
	nc, err := bus.Connect(url, "sync", seed)
	if err != nil {
		log.Warn("tenancy event consumer: no bus", "err", err.Error())
		return
	}
	defer nc.Close()
	c, err := bus.BindConsumer(ctx, nc, "tenancy", "sync")
	if err != nil {
		log.Warn("tenancy event consumer: not bound", "err", err.Error())
		return
	}
	for ctx.Err() == nil {
		d, err := c.Next(ctx, 5*time.Second)
		if err != nil {
			if !errors.Is(err, bus.ErrNoMessage) && ctx.Err() == nil {
				time.Sleep(time.Second)
			}
			continue
		}
		var ev struct {
			Type     string `json:"type"`
			TenantID string `json:"tenant_id"`
			Data     struct {
				OutletIDs []string `json:"outlet_ids"`
			} `json:"data"`
		}
		if json.Unmarshal(d.Data(), &ev) == nil && ev.Type == "tenancy.manual_book.registered" {
			dir.DropBooks(ev.TenantID, ev.Data.OutletIDs...)
		}
		_ = d.Ack()
	}
}
