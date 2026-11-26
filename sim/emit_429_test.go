package sim

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Round 7 (O2-20): a caller over its emit rate gets 429 emit.rate_limited with Retry-After through emitOps, and nothing is stored;
// the same batch with the same keys is accepted once the bucket refilled.
func TestEmitOverTheRateAnswers429WithRetryAfter(t *testing.T) {
	w, _ := newTestWorld(t, 64, WorldOptions{Pos: 1})
	for i := 0; i < service.EmitBurst/sp.MaxEmitOps; i++ {
		ops := make([]service.EmitOp, sp.MaxEmitOps)
		for j := range ops {
			ops[j] = w.taxClassOp(string(rune('A'+i))+string(rune('a'+j/26))+string(rune('a'+j%26)), "m1")
		}
		if _, err := w.GW.Emit(bg, w.Tenant, "catalog", ops); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := w.Services.Signer("catalog").Sign("sync", w.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"tenant_id": w.Tenant, "ops": []map[string]any{{"key": "over-1", "stream": "brand:" + w.Brand, "intent": "menu.tax_class.set", "intent_v": 1,
		"actor": "m1", "authorised_by": "menu.tax_class.edit", "muts": []map[string]any{{"e": "item", "id": emitItem, "k": "set", "f": map[string]any{"tax_class": "fnb_standard"}}}}}})
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/internal/v1/emit", strings.NewReader(string(b)))
		req.Header.Set(auth.ServiceTokenHeader, svc)
		rec := httptest.NewRecorder()
		w.CloudH.ServeHTTP(rec, req)
		return rec
	}
	rec := call()
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), "emit.rate_limited") {
		t.Fatalf("got %d retry-after %q %s, want 429 emit.rate_limited with Retry-After", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("content type %q", ct)
	}
	w.Advance(5 * time.Second)
	if rec := call(); rec.Code != 200 {
		t.Fatalf("the same keys after the bucket refilled: got %d %s", rec.Code, rec.Body.String())
	}
}
