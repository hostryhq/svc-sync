package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/tenancy"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// EmitPath is the cloud-origin emit operation (openapi/sync/v1 emitOps).
const EmitPath = "/internal/v1/emit"

// EmitCallers is x-service-callers of emitOps: the owners of cloud-origin intents (a test compares it
// with the contract).
var EmitCallers = []string{"catalog", "billing"}

// maxEmitBody bounds a request: 200 ops of at most 256 KiB of body plus 16 KiB of pii each, as
// the mutations travel in the request, plus slack.
const maxEmitBody = 200 * (sp.MaxBodyBytes + sp.MaxPIIBytes + 4096)

type emitOpDTO struct {
	Key          string          `json:"key"`
	Stream       string          `json:"stream"`
	Intent       string          `json:"intent"`
	IntentV      int             `json:"intent_v"`
	Muts         []sp.Mut        `json:"muts"`
	PII          json.RawMessage `json:"pii"`
	Actor        string          `json:"actor"`
	AuthorisedBy *string         `json:"authorised_by"`
	Approval     string          `json:"approval"`
}

type emitReqDTO struct {
	TenantID string      `json:"tenant_id"`
	Ops      []emitOpDTO `json:"ops"`
}

type emitResDTO struct {
	Key      string `json:"key"`
	Origin   string `json:"origin"`
	Stream   string `json:"stream"`
	Seq      int64  `json:"seq"`
	Replayed bool   `json:"replayed"`
}

// Emit mounts POST /internal/v1/emit behind the go-auth guard: a service token from a caller in
// EmitCallers, nothing else. The tenant of the request must equal the tenant the service token
// carries (security condition: a compromised caller must not write to another tenant's devices); a
// token without a tenant is refused. The Idempotency-Key header is accepted and ignored; idempotency
// is per op (tenant, caller, key).
func Emit(mux *http.ServeMux, g *service.Gateway, a AdminAuth) {
	guard := a.Guard()
	guard.Handle(mux, "POST "+EmitPath, auth.Policy{OperationID: "emitOps", Internal: true, Callers: EmitCallers, ServiceOnly: true},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			out, err := emitHandle(r, g)
			if err != nil {
				writeEmitError(w, r, err)
				return
			}
			writeJSON(w, r, Options{}, http.StatusOK, map[string]any{"ops": out})
		}))
}

func emitHandle(r *http.Request, g *service.Gateway) ([]emitResDTO, error) {
	tc, err := tenancy.Require(r.Context())
	if err != nil {
		return nil, apperr.New(apperr.Unauthenticated, "auth.tenant_missing", "tenant context missing")
	}
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.ServiceCaller == "" {
		return nil, apperr.New(apperr.Unauthenticated, "auth.invalid_token", "authentication required")
	}
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxEmitBody))
	if err != nil {
		return nil, apperr.New(apperr.Validation, "sync.bad_request", "unreadable body")
	}
	var req emitReqDTO
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		return nil, apperr.New(apperr.Validation, "sync.bad_request", "request body is not valid for this endpoint")
	}
	if req.TenantID != tc.TenantID.String() {
		// The body names a tenant other than the one the service token carries.
		return nil, apperr.New(apperr.Forbidden, "emit.tenant_mismatch", "the request tenant is not the tenant of the service token")
	}
	ops := make([]service.EmitOp, 0, len(req.Ops))
	for i, o := range req.Ops {
		muts, err := normaliseMuts(o.Muts)
		if err != nil {
			return nil, apperr.New(apperr.Validation, "sync.bad_request", fmt.Sprintf("op %d: %v", i, err))
		}
		var pii sp.PII
		if t := bytes.TrimSpace(o.PII); len(t) > 0 && string(t) != "null" {
			if len(t) > sp.MaxPIIBytes {
				return nil, apperr.New(apperr.Validation, service.EmitOpTooLarge, "pii is over the size limit")
			}
			pd := json.NewDecoder(bytes.NewReader(t))
			pd.UseNumber()
			if err := pd.Decode(&pii); err != nil {
				return nil, apperr.New(apperr.Validation, "sync.bad_request", fmt.Sprintf("op %d: pii is not entity -> row id -> field -> value", i))
			}
			if err := normalisePII(pii); err != nil {
				return nil, apperr.New(apperr.Validation, "sync.bad_request", fmt.Sprintf("op %d: %v", i, err))
			}
		}
		ops = append(ops, service.EmitOp{Key: o.Key, Stream: o.Stream, Intent: o.Intent, IntentV: o.IntentV, Muts: muts, PII: pii,
			Actor: o.Actor, AuthorisedBy: o.AuthorisedBy, Approval: o.Approval})
	}
	res, err := g.Emit(r.Context(), tc.TenantID.String(), p.ServiceCaller, ops)
	if err != nil {
		return nil, err
	}
	out := make([]emitResDTO, len(res))
	for i, x := range res {
		out[i] = emitResDTO{Key: x.Key, Origin: x.Origin, Stream: x.Stream, Seq: x.Seq, Replayed: x.Replayed}
	}
	return out, nil
}

func writeEmitError(w http.ResponseWriter, r *http.Request, err error) {
	var ee *service.EmitError
	switch {
	case errors.As(err, &ee):
		apperr.WriteProblem(w, r, apperr.New(apperr.Validation, ee.Code, ee.Detail))
	case errors.Is(err, service.ErrEmitUnavailable):
		w.Header().Set("Retry-After", "5")
		apperr.WriteProblem(w, r, apperr.New(apperr.Unavailable, "emit.unavailable", "cloud emit is unavailable, retry later"))
	default:
		apperr.WriteProblem(w, r, err)
	}
}

// normaliseMuts turns json.Number field values into int64 and refuses everything an op body may not
// carry: fractions, exponents and nested values. Only strings, booleans, integers and null remain.
func normaliseMuts(in []sp.Mut) ([]sp.Mut, error) {
	for i := range in {
		if err := normaliseFields(in[i].F); err != nil {
			return nil, fmt.Errorf("mut %d: %w", i, err)
		}
	}
	return in, nil
}

func normalisePII(p sp.PII) error {
	for _, rows := range p {
		for _, fields := range rows {
			if err := normaliseFields(fields); err != nil {
				return err
			}
		}
	}
	return nil
}

func normaliseFields(f map[string]any) error {
	for k, v := range f {
		switch x := v.(type) {
		case nil, bool, string:
		case json.Number:
			if strings.ContainsAny(x.String(), ".eE") {
				return fmt.Errorf("field %q is not an integer", k)
			}
			n, err := x.Int64()
			if err != nil || n > sp.MaxSafeInt || n < -sp.MaxSafeInt {
				return fmt.Errorf("field %q is outside the safe integer range", k)
			}
			f[k] = n
		default:
			return fmt.Errorf("field %q: nested values are not allowed", k)
		}
	}
	return nil
}
