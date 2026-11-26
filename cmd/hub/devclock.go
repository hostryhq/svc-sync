package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// Dev-only clock control for the soak (T6 age cases, T13 stale blackout ticket). The hub's judgments of age (blackout tickets, credential
// expiry) read its own clock, which a harness cannot otherwise move. When SYNC_HUB_DEV_CLOCK_ADDR is set the hub serves
// /dev/clock on that address, plain HTTP, loopback only, and the hub clock is the wall clock plus a settable offset. Refused (the
// hub does not start) unless HOSTRY_ENV is dev, test or ci. Identity and the cloud keep judging on wall time, so a large offset
// shortens or lengthens only what the hub itself decides; the harness moves it back to 0 afterwards.

// hubNow is the clock the hub is built with; run replaces it when the dev clock is on.
var hubNow = time.Now

// offsetClock is the wall clock plus a settable offset.
type offsetClock struct {
	base func() time.Time
	mu   sync.Mutex
	off  time.Duration
}

func (c *offsetClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.base().Add(c.off)
}

func (c *offsetClock) offset() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.off
}

type clockBody struct {
	OffsetSeconds  *float64 `json:"offset_seconds"`
	AdvanceSeconds *float64 `json:"advance_seconds"`
}

type clockView struct {
	Now           string  `json:"now"`
	OffsetSeconds float64 `json:"offset_seconds"`
}

func (c *offsetClock) view(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(clockView{Now: c.now().UTC().Format(time.RFC3339Nano), OffsetSeconds: c.offset().Seconds()})
}

// handler serves GET /dev/clock (read) and POST /dev/clock with exactly one of {"offset_seconds":n} (set) or {"advance_seconds":n} (add).
func (c *offsetClock) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/dev/clock", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			c.view(w)
		case http.MethodPost:
			var b clockBody
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&b); err != nil || (b.OffsetSeconds == nil) == (b.AdvanceSeconds == nil) {
				http.Error(w, "send exactly one of offset_seconds or advance_seconds", http.StatusBadRequest)
				return
			}
			c.mu.Lock()
			if b.OffsetSeconds != nil {
				c.off = time.Duration(*b.OffsetSeconds * float64(time.Second))
			} else {
				c.off += time.Duration(*b.AdvanceSeconds * float64(time.Second))
			}
			c.mu.Unlock()
			c.view(w)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return mux
}

// devClock returns the hub's clock. Without SYNC_HUB_DEV_CLOCK_ADDR it is time.Now. With it (dev, test, ci only; loopback only) it
// starts the control listener, which stops with ctx, and logs nothing secret.
func devClock(ctx context.Context, get func(string) string) (func() time.Time, string, error) {
	addr := get("SYNC_HUB_DEV_CLOCK_ADDR")
	if addr == "" {
		return time.Now, "", nil
	}
	if !envAllowsDev(get("HOSTRY_ENV")) {
		return nil, "", errors.New("SYNC_HUB_DEV_CLOCK_ADDR moves the hub clock and needs HOSTRY_ENV dev, test or ci")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, "", errors.New("SYNC_HUB_DEV_CLOCK_ADDR must be a loopback address")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}
	c := &offsetClock{base: time.Now}
	srv := &http.Server{Handler: c.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	return c.now, ln.Addr().String(), nil
}
