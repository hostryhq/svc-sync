// Package api is the controller layer: HTTP for Sync Protocol v1 under /sync/v1. It validates and
// authenticates, maps to and from the wire types and calls the service. It holds no business
// rules. The same handler fronts the cloud gateway and the LAN hub; only the Authenticator and
// the Backend differ (S10).
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/svc-sync/engine"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Route names the endpoint class so an authenticator can apply the token rules of ADR-0005:
// ordinary routes take a device token; the quarantine upload takes only a drain token.
type Route string

// Routes.
const (
	RouteSync   Route = "sync"
	RouteUpload Route = "upload"
)

// Principal is a verified caller.
type Principal struct {
	Tenant string
	Caller engine.Caller
}

// Authenticator verifies a request. body is the decoded request body (for signed assertions the
// raw bytes as sent are in raw).
type Authenticator interface {
	Authenticate(r *http.Request, raw []byte, route Route) (Principal, error)
}

// Backend is the node behind the API: the gateway or the hub.
type Backend interface {
	Hello(ctx context.Context, p Principal, req sp.HelloRequest) (sp.HelloResponse, error)
	Push(ctx context.Context, p Principal, req sp.PushRequest) (sp.PushResponse, error)
	Pull(ctx context.Context, p Principal, req sp.PullRequest) (sp.PullResponse, error)
	Upload(ctx context.Context, p Principal, req sp.PushRequest) (sp.PushResponse, error)
	Snapshot(ctx context.Context, p Principal) (sp.Snapshot, error)
	Poke(ctx context.Context, p Principal, after int64, wait time.Duration) int64
}

// ErrUnsupported is returned by a backend for an endpoint it does not offer (the hub has no
// quarantine upload, KL3).
var ErrUnsupported = errors.New("api: endpoint not offered by this node")

// Options configure the handler.
type Options struct {
	Auth    Authenticator
	Backend Backend
	// Sign adds a response proof (the hub's answer on the LAN).
	Sign func(h http.Header, r *http.Request, respBody []byte) error
}

const maxBody = 16 << 20

// Mount registers the sync routes on mux.
func Mount(mux *http.ServeMux, o Options) {
	h := &handler{o: o}
	mux.HandleFunc("POST /sync/v1/hello", h.post(RouteSync, func(ctx context.Context, p Principal, b []byte) (any, error) {
		var req sp.HelloRequest
		if err := decode(b, &req); err != nil {
			return nil, err
		}
		return o.Backend.Hello(ctx, p, req)
	}))
	mux.HandleFunc("POST /sync/v1/push", h.post(RouteSync, func(ctx context.Context, p Principal, b []byte) (any, error) {
		var req sp.PushRequest
		if err := decode(b, &req); err != nil {
			return nil, err
		}
		return o.Backend.Push(ctx, p, req)
	}))
	mux.HandleFunc("POST /sync/v1/pull", h.post(RouteSync, func(ctx context.Context, p Principal, b []byte) (any, error) {
		var req sp.PullRequest
		if err := decode(b, &req); err != nil {
			return nil, err
		}
		return o.Backend.Pull(ctx, p, req)
	}))
	mux.HandleFunc("POST /sync/v1/quarantine-upload", h.post(RouteUpload, func(ctx context.Context, p Principal, b []byte) (any, error) {
		var req sp.PushRequest
		if err := decode(b, &req); err != nil {
			return nil, err
		}
		return o.Backend.Upload(ctx, p, req)
	}))
	mux.HandleFunc("GET /sync/v1/snapshot", h.post(RouteSync, func(ctx context.Context, p Principal, _ []byte) (any, error) {
		return o.Backend.Snapshot(ctx, p)
	}))
	// Poke carries no data: it returns a counter that moves when the node has new ops, as a long
	// poll (no WebSocket dependency in the PoC; the device then pulls).
	mux.HandleFunc("GET /sync/v1/poke", func(w http.ResponseWriter, r *http.Request) {
		p, err := o.Auth.Authenticate(r, nil, RouteSync)
		if err != nil {
			apperr.WriteProblem(w, r, err)
			return
		}
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		wait := 25 * time.Second
		if s, err := strconv.Atoi(r.URL.Query().Get("wait")); err == nil && s >= 0 && s < 60 {
			wait = time.Duration(s) * time.Second
		}
		n := o.Backend.Poke(r.Context(), p, after, wait)
		writeJSON(w, r, o, http.StatusOK, map[string]int64{"n": n})
	})
}

type handler struct{ o Options }

func decode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return apperr.New(apperr.Validation, "sync.bad_request", "request body is not valid for this endpoint")
	}
	return nil
}

func (h *handler) post(route Route, fn func(context.Context, Principal, []byte) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			apperr.WriteProblem(w, r, apperr.New(apperr.Validation, "sync.bad_request", "unreadable body"))
			return
		}
		p, err := h.o.Auth.Authenticate(r, raw, route)
		if err != nil {
			apperr.WriteProblem(w, r, err)
			return
		}
		body := raw
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			if err == nil {
				body, err = io.ReadAll(io.LimitReader(zr, maxBody*4))
			}
			if err != nil {
				apperr.WriteProblem(w, r, apperr.New(apperr.Validation, "sync.bad_request", "bad gzip body"))
				return
			}
		}
		out, err := fn(r.Context(), p, body)
		if err != nil {
			apperr.WriteProblem(w, r, mapErr(err))
			return
		}
		if out == nil {
			out = map[string]string{}
		}
		writeJSON(w, r, h.o, http.StatusOK, out)
	}
}

func mapErr(err error) error {
	var ae *apperr.Error
	if errors.As(err, &ae) {
		return err
	}
	if errors.Is(err, ErrUnsupported) {
		return apperr.New(apperr.NotFound, "sync.not_offered", "this node does not offer the endpoint")
	}
	return apperr.Wrap(apperr.Internal, "sync.internal", "internal error", err)
}

func writeJSON(w http.ResponseWriter, r *http.Request, o Options, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		apperr.WriteProblem(w, r, err)
		return
	}
	if o.Sign != nil {
		if err := o.Sign(w.Header(), r, b); err != nil {
			apperr.WriteProblem(w, r, err)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
