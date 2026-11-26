package suite

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	sp "github.com/hostryhq/svc-sync/syncproto"
)

const emitPath = "/internal/v1/emit"

func (tg Target) emitOp(key, taxClass string) map[string]any {
	return map[string]any{
		"key": key, "stream": "brand:" + tg.Brand, "intent": "menu.tax_class.set", "intent_v": 1,
		"muts":  []any{map[string]any{"e": "item", "id": "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f5101", "k": "set", "f": map[string]any{"tax_class": taxClass}}},
		"actor": "m1", "authorised_by": "menu.tax_class.edit",
	}
}

func (tg Target) emitReq(ops ...map[string]any) map[string]any {
	l := make([]any, len(ops))
	for i, o := range ops {
		l[i] = o
	}
	return map[string]any{"tenant_id": tg.Tenant, "ops": l}
}

type emitResp struct {
	Ops []struct {
		Key      string `json:"key"`
		Origin   string `json:"origin"`
		Stream   string `json:"stream"`
		Seq      int64  `json:"seq"`
		Replayed bool   `json:"replayed"`
	} `json:"ops"`
}

func problemCode(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, `"code":"`)
	if i < 0 {
		t.Fatalf("no problem code in %q", body)
	}
	rest := body[i+len(`"code":"`):]
	return rest[:strings.Index(rest, `"`)]
}

// runEmit is the contract of POST /internal/v1/emit (ADR-0014 A2.2).
func (tg Target) runEmit(t *testing.T) {
	if tg.ServiceToken == nil {
		return
	}
	cat := func() string { return tg.ServiceToken("catalog", tg.Tenant) }

	t.Run("emit stamps and seals a cloud-origin op, replays by key and refuses other content", func(t *testing.T) {
		var r1, r2 emitResp
		if rec := tg.doSvc(t, "POST", emitPath, cat(), tg.emitReq(tg.emitOp("k-emit-1", "fnb_standard")), &r1); rec.Code != 200 {
			t.Fatalf("emit: %d %s", rec.Code, rec.Body)
		}
		if len(r1.Ops) != 1 || !strings.HasPrefix(r1.Ops[0].Origin, "cloud-") || r1.Ops[0].Seq < 1 || r1.Ops[0].Replayed {
			t.Fatalf("first emit: %+v", r1)
		}
		tg.doSvc(t, "POST", emitPath, cat(), tg.emitReq(tg.emitOp("k-emit-1", "fnb_standard")), &r2)
		if len(r2.Ops) != 1 || !r2.Ops[0].Replayed || r2.Ops[0].Seq != r1.Ops[0].Seq || r2.Ops[0].Origin != r1.Ops[0].Origin {
			t.Fatalf("replay must answer the original identity: %+v", r2)
		}
		rec := tg.doSvc(t, "POST", emitPath, cat(), tg.emitReq(tg.emitOp("k-emit-1", "nonfood")), nil)
		if rec.Code != 422 || problemCode(t, rec.Body.String()) != "idempotency.mismatch" {
			t.Fatalf("same key, other content: %d %s", rec.Code, rec.Body)
		}
		// A device receives it as an ordinary cloud-origin op under the gateway's seal.
		b := tg.node(t)
		var p sp.PullResponse
		tg.do(t, "POST", "/sync/v1/pull", b.d.Token(), sp.PullRequest{Vector: sp.Vector{}}, &p)
		var got *sp.Item
		for i := range p.Items {
			if p.Items[i].Origin == r1.Ops[0].Origin && p.Items[i].Seq == r1.Ops[0].Seq && p.Items[i].Stream == r1.Ops[0].Stream {
				got = &p.Items[i]
			}
		}
		if got == nil {
			t.Fatalf("the emitted op is not served: %+v", p.Items)
		}
		body, err := sp.VerifyItem(*got)
		if err != nil || body.Intent != "menu.tax_class.set" || body.Actor != "m1" {
			t.Fatalf("emitted body: %+v %v", body, err)
		}
		sealed := false
		for _, s := range p.Seals {
			if s.Origin == got.Origin && s.Stream == got.Stream && s.Seq >= got.Seq && s.Verify(tg.CloudPub) {
				sealed = true
			}
		}
		if !sealed {
			t.Fatal("the emitted op is not covered by a gateway seal")
		}
	})

	t.Run("a refusal is 422 with a stable code and stores nothing", func(t *testing.T) {
		big := strings.Repeat("x", sp.MaxPIIBytes+1)
		cases := []struct {
			name   string
			caller string
			ops    []map[string]any
			code   string
		}{
			{"caller does not own the intent", "billing", []map[string]any{tg.emitOp("k-r1", "a")}, "emit.caller_not_owner"},
			{"unknown intent", "catalog", []map[string]any{with(tg.emitOp("k-r2", "a"), "intent", "no.such.intent")}, "emit.intent_unknown"},
			{"a device intent", "billing", []map[string]any{with(tg.emitOp("k-r3", "a"), "intent", "bill.finalize")}, "emit.intent_not_cloud"},
			{"entity not listed", "catalog", []map[string]any{with(tg.emitOp("k-r4", "a"), "muts", []any{map[string]any{"e": "category", "id": "c1", "k": "insert", "f": map[string]any{"name": "x"}}})}, "emit.entity_not_allowed"},
			{"stream of another tenant", "catalog", []map[string]any{with(tg.emitOp("k-r5", "a"), "stream", "brand:018f0000-0000-7000-8000-0000000000ee")}, "emit.stream_not_in_tenant"},
			{"stream kind the intent does not list", "catalog", []map[string]any{with(tg.emitOp("k-r6", "a"), "stream", "outlet:"+tg.Outlet)}, "emit.stream_not_in_tenant"},
			{"no ops", "catalog", nil, "emit.batch_size"},
			{"over the pii limit", "catalog", []map[string]any{with(tg.emitOp("k-r7", "a"), "pii", map[string]any{"item": map[string]any{"i": map[string]any{"n": big}}})}, "op.too_large"},
			{"over the body limit", "catalog", []map[string]any{with(tg.emitOp("k-r8", "a"), "muts", []any{map[string]any{"e": "item", "id": "i", "k": "set", "f": map[string]any{"tax_class": strings.Repeat("y", sp.MaxBodyBytes)}}})}, "op.too_large"},
		}
		for _, c := range cases {
			rec := tg.doSvc(t, "POST", emitPath, tg.ServiceToken(c.caller, tg.Tenant), tg.emitReq(c.ops...), nil)
			if rec.Code != 422 || problemCode(t, rec.Body.String()) != c.code {
				t.Errorf("%s: %d %s, want 422 %s", c.name, rec.Code, rec.Body, c.code)
			}
		}
		many := make([]map[string]any, sp.MaxEmitOps+1)
		for i := range many {
			many[i] = tg.emitOp(fmt.Sprintf("k-many-%d", i), "a")
		}
		if rec := tg.doSvc(t, "POST", emitPath, cat(), tg.emitReq(many...), nil); rec.Code != 422 || problemCode(t, rec.Body.String()) != "emit.batch_size" {
			t.Errorf("201 ops: %d %s", rec.Code, rec.Body)
		}
		// The batch is atomic: a good op beside a bad one is not stored.
		rec := tg.doSvc(t, "POST", emitPath, cat(), tg.emitReq(tg.emitOp("k-atomic", "a"), with(tg.emitOp("k-atomic-bad", "a"), "intent", "no.such.intent")), nil)
		var r emitResp
		if rec.Code != 422 {
			t.Fatalf("batch with a bad op: %d", rec.Code)
		}
		tg.doSvc(t, "POST", emitPath, cat(), tg.emitReq(tg.emitOp("k-atomic", "a")), &r)
		if len(r.Ops) != 1 || r.Ops[0].Replayed {
			t.Fatalf("the good op of a refused batch was stored: %+v", r)
		}
	})

	t.Run("only a catalog or billing service token for the request tenant is accepted", func(t *testing.T) {
		req := tg.emitReq(tg.emitOp("k-auth", "a"))
		if rec := tg.doSvc(t, "POST", emitPath, "", req, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("no token: %d", rec.Code)
		}
		if rec := tg.do(t, "POST", emitPath, tg.node(t).d.Token(), req, nil); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Errorf("device token: %d", rec.Code)
		}
		if rec := tg.doSvc(t, "POST", emitPath, tg.ServiceToken("admin", tg.Tenant), req, nil); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Errorf("a service that is not in x-service-callers: %d", rec.Code)
		}
		// The tenant in the token must equal the tenant of the request (security condition).
		other := tg.ServiceToken("catalog", "018f0000-0000-7000-8000-0000000000ff")
		if rec := tg.doSvc(t, "POST", emitPath, other, req, nil); rec.Code != http.StatusForbidden {
			t.Errorf("token of another tenant: %d %s", rec.Code, rec.Body)
		}
		if rec := tg.doSvc(t, "POST", emitPath, tg.ServiceToken("catalog", ""), req, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("token without a tenant: %d", rec.Code)
		}
	})
}

func with(m map[string]any, k string, v any) map[string]any {
	out := make(map[string]any, len(m))
	for a, b := range m {
		out[a] = b
	}
	out[k] = v
	return out
}
