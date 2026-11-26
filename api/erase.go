package api

import (
	"encoding/json"
	"errors"
	"net/http"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/apperr"
	"github.com/hostryhq/go-common/tenancy"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// ErasePath is the erasure operation (openapi/sync/v1 erasePii).
const ErasePath = "/internal/v1/pii/erase"

// EraseCallers is x-service-callers of erasePii: the owners of the pii side tables (ADR-0014 A2.1 item 7).
var EraseCallers = []string{"billing", "orders"}

// PermPIIErase is the permission of erasePii (a service-realm key of the catalogue).
const PermPIIErase = "sync.pii.erase"

// maxEraseBody bounds a request of 200 targets (each a few hundred bytes) with slack.
const maxEraseBody = 256 << 10

type eraseTargetDTO struct {
	Origin string `json:"origin"`
	Stream string `json:"stream"`
	Seq    int64  `json:"seq"`
}

type eraseReqDTO struct {
	Targets []eraseTargetDTO `json:"targets"`
}

type eraseResDTO struct {
	Origin      string `json:"origin"`
	Stream      string `json:"stream"`
	Seq         int64  `json:"seq"`
	EraseOrigin string `json:"erase_origin"`
	EraseSeq    int64  `json:"erase_seq"`
	Replayed    bool   `json:"replayed"`
}

// Erase mounts POST /internal/v1/pii/erase behind the go-auth guard: a service token of billing or orders,
// nothing else. The tenant is the service token's tenant claim (a token without one is refused by the guard);
// no body field names it. The caller has authorised the request online; the gateway does not re-check the
// user. Idempotency-Key is accepted and ignored: the target is the idempotency key.
func Erase(mux *http.ServeMux, g *service.Gateway, a AdminAuth) {
	a.Guard().Handle(mux, "POST "+ErasePath, auth.Policy{OperationID: "erasePii", Internal: true, Callers: EraseCallers, ServiceOnly: true},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tc, err := tenancy.Require(r.Context())
			if err != nil {
				apperr.WriteProblem(w, r, apperr.New(apperr.Unauthenticated, "auth.tenant_missing", "tenant context missing"))
				return
			}
			var req eraseReqDTO
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEraseBody)).Decode(&req); err != nil {
				apperr.WriteProblem(w, r, apperr.New(apperr.Validation, "sync.bad_request", "request body is not valid for this endpoint"))
				return
			}
			targets := make([]sp.Ref, len(req.Targets))
			for i, t := range req.Targets {
				if t.Origin == "" || t.Stream == "" || t.Seq < 1 {
					apperr.WriteProblem(w, r, apperr.New(apperr.Validation, "sync.bad_request", "a target needs origin, stream and seq >= 1"))
					return
				}
				targets[i] = sp.Ref{Origin: t.Origin, Stream: t.Stream, Seq: t.Seq}
			}
			res, err := g.ErasePIIBatch(r.Context(), tc.TenantID.String(), targets)
			var ee *service.EraseError
			switch {
			case errors.As(err, &ee):
				apperr.WriteProblem(w, r, apperr.New(apperr.Validation, ee.Code, "nothing was written"))
				return
			case errors.Is(err, service.ErrEmitUnavailable):
				w.Header().Set("Retry-After", "5")
				apperr.WriteProblem(w, r, apperr.New(apperr.Unavailable, "emit.unavailable", "cloud emit is unavailable, retry later"))
				return
			case err != nil:
				apperr.WriteProblem(w, r, err)
				return
			}
			out := make([]eraseResDTO, len(res))
			for i, x := range res {
				out[i] = eraseResDTO{Origin: x.Target.Origin, Stream: x.Target.Stream, Seq: x.Target.Seq, EraseOrigin: x.Erase.Origin, EraseSeq: x.Erase.Seq, Replayed: x.Replayed}
			}
			writeJSON(w, r, Options{}, http.StatusOK, map[string]any{"erasures": out})
		}))
}
