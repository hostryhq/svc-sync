package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDevClockIsRefusedOutsideDevEnvironments(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		ok   bool
	}{
		{"off by default", map[string]string{"HOSTRY_ENV": "production"}, true},
		{"dev loopback", map[string]string{"HOSTRY_ENV": "dev", "SYNC_HUB_DEV_CLOCK_ADDR": "127.0.0.1:0"}, true},
		{"ci", map[string]string{"HOSTRY_ENV": "ci", "SYNC_HUB_DEV_CLOCK_ADDR": "127.0.0.1:0"}, true},
		{"production", map[string]string{"HOSTRY_ENV": "production", "SYNC_HUB_DEV_CLOCK_ADDR": "127.0.0.1:0"}, false},
		{"unset env", map[string]string{"SYNC_HUB_DEV_CLOCK_ADDR": "127.0.0.1:0"}, false},
		{"not loopback", map[string]string{"HOSTRY_ENV": "dev", "SYNC_HUB_DEV_CLOCK_ADDR": "0.0.0.0:9000"}, false},
		{"no host", map[string]string{"HOSTRY_ENV": "dev", "SYNC_HUB_DEV_CLOCK_ADDR": ":9000"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now, _, err := devClock(ctx, envOf(tc.env))
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v want ok=%v", err, tc.ok)
			}
			if tc.ok && now == nil {
				t.Fatal("no clock")
			}
		})
	}
}

func TestDevClockOffsetMovesTheHubClock(t *testing.T) {
	c := &offsetClock{base: func() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) }}
	h := c.handler()
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/dev/clock", strings.NewReader(body)))
		return w
	}
	if w := post(`{"advance_seconds":1500}`); w.Code != 200 {
		t.Fatalf("advance: %d %s", w.Code, w.Body)
	}
	if got := c.now(); !got.Equal(time.Date(2026, 1, 1, 12, 25, 0, 0, time.UTC)) {
		t.Fatalf("now = %v", got)
	}
	if w := post(`{"advance_seconds":60}`); w.Code != 200 || !c.now().Equal(time.Date(2026, 1, 1, 12, 26, 0, 0, time.UTC)) {
		t.Fatal("advance accumulates")
	}
	if w := post(`{"offset_seconds":-30}`); w.Code != 200 || !c.now().Equal(time.Date(2026, 1, 1, 11, 59, 30, 0, time.UTC)) {
		t.Fatal("offset replaces")
	}
	if w := post(`{"offset_seconds":1,"advance_seconds":1}`); w.Code != 400 {
		t.Fatalf("both fields: %d", w.Code)
	}
	if w := post(`{}`); w.Code != 400 {
		t.Fatalf("empty: %d", w.Code)
	}
	if w := post(`{"offset_seconds":0}`); w.Code != 200 || !c.now().Equal(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("reset to wall time")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dev/clock", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "2026-01-01T12:00:00Z") {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
}
