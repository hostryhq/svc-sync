package suite

import (
	"strings"
	"testing"
)

const erasePath = "/internal/v1/pii/erase"

type eraseResp struct {
	Erasures []struct {
		Origin      string `json:"origin"`
		Stream      string `json:"stream"`
		Seq         int64  `json:"seq"`
		EraseOrigin string `json:"erase_origin"`
		EraseSeq    int64  `json:"erase_seq"`
		Replayed    bool   `json:"replayed"`
	} `json:"erasures"`
}

// runErase is the contract of POST /internal/v1/pii/erase (erasePii; ADR-0014 A2.1 item 7): billing and orders
// ask for the cloud-signed erasure op; the tenant is the service token's; the batch is atomic.
func (tg Target) runErase(t *testing.T) {
	if tg.ServiceToken == nil {
		return
	}
	bill := func() string { return tg.ServiceToken("billing", tg.Tenant) }
	var emitted emitResp
	if rec := tg.doSvc(t, "POST", emitPath, tg.ServiceToken("catalog", tg.Tenant), tg.emitReq(tg.emitOp("k-erase-target", "fnb_standard")), &emitted); rec.Code != 200 || len(emitted.Ops) != 1 {
		t.Fatalf("setup emit: %d %s", rec.Code, rec.Body)
	}
	target := map[string]any{"origin": emitted.Ops[0].Origin, "stream": emitted.Ops[0].Stream, "seq": emitted.Ops[0].Seq}
	req := func(ts ...map[string]any) map[string]any {
		l := make([]any, len(ts))
		for i, x := range ts {
			l[i] = x
		}
		return map[string]any{"targets": l}
	}

	t.Run("erase writes one cloud-signed erasure op per target and answers the first on a replay", func(t *testing.T) {
		var r1, r2 eraseResp
		if rec := tg.doSvc(t, "POST", erasePath, bill(), req(target), &r1); rec.Code != 200 {
			t.Fatalf("erase: %d %s", rec.Code, rec.Body)
		}
		if len(r1.Erasures) != 1 || r1.Erasures[0].Replayed || !strings.HasPrefix(r1.Erasures[0].EraseOrigin, "cloud-") || r1.Erasures[0].EraseSeq < 1 ||
			r1.Erasures[0].Origin != emitted.Ops[0].Origin || r1.Erasures[0].Seq != emitted.Ops[0].Seq {
			t.Fatalf("first erase: %+v", r1)
		}
		tg.doSvc(t, "POST", erasePath, tg.ServiceToken("orders", tg.Tenant), req(target), &r2)
		if len(r2.Erasures) != 1 || !r2.Erasures[0].Replayed || r2.Erasures[0].EraseSeq != r1.Erasures[0].EraseSeq || r2.Erasures[0].EraseOrigin != r1.Erasures[0].EraseOrigin {
			t.Fatalf("a second erasure must answer the first erasure op with replayed true: %+v", r2)
		}
	})

	t.Run("an unknown target is 422 erase.target_unknown and nothing is written for any target", func(t *testing.T) {
		var fresh eraseResp
		tg.doSvc(t, "POST", emitPath, tg.ServiceToken("catalog", tg.Tenant), tg.emitReq(tg.emitOp("k-erase-2", "nonfood")), &emitted)
		ok := map[string]any{"origin": emitted.Ops[0].Origin, "stream": emitted.Ops[0].Stream, "seq": emitted.Ops[0].Seq}
		ghost := map[string]any{"origin": emitted.Ops[0].Origin, "stream": emitted.Ops[0].Stream, "seq": int64(999999)}
		rec := tg.doSvc(t, "POST", erasePath, bill(), req(ok, ghost), nil)
		if rec.Code != 422 || problemCode(t, rec.Body.String()) != "erase.target_unknown" {
			t.Fatalf("unknown target: %d %s", rec.Code, rec.Body)
		}
		if rec := tg.doSvc(t, "POST", erasePath, bill(), req(ok), &fresh); rec.Code != 200 || len(fresh.Erasures) != 1 || fresh.Erasures[0].Replayed {
			t.Fatalf("the valid target of the refused batch must not have been erased: %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("no targets is 422 erase.batch_size; a caller outside x-service-callers is 403; no tenant claim is 401", func(t *testing.T) {
		if rec := tg.doSvc(t, "POST", erasePath, bill(), req(), nil); rec.Code != 422 || problemCode(t, rec.Body.String()) != "erase.batch_size" {
			t.Fatalf("no targets: %d %s", rec.Code, rec.Body)
		}
		if rec := tg.doSvc(t, "POST", erasePath, tg.ServiceToken("catalog", tg.Tenant), req(target), nil); rec.Code != 403 {
			t.Fatalf("catalog is not a caller: %d %s", rec.Code, rec.Body)
		}
		if rec := tg.doSvc(t, "POST", erasePath, tg.ServiceToken("billing", ""), req(target), nil); rec.Code != 401 {
			t.Fatalf("a token without a tenant: %d %s", rec.Code, rec.Body)
		}
		if rec := tg.do(t, "POST", erasePath, tg.node(t).d.Token(), req(target), nil); rec.Code == 200 {
			t.Fatalf("a device token must not erase: %d", rec.Code)
		}
	})
}
