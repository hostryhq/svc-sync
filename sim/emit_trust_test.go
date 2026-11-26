package sim

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

const emitItem = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f5101"

func (w *World) taxClassOp(key, actor string) service.EmitOp {
	by := "menu.tax_class.edit"
	return service.EmitOp{Key: key, Stream: "brand:" + w.Brand, Intent: "menu.tax_class.set", IntentV: 1, Actor: actor, AuthorisedBy: &by,
		Muts: []sp.Mut{{E: "item", ID: emitItem, K: sp.KSet, F: map[string]any{"tax_class": "fnb_standard"}}}}
}

func (w *World) importOp(key, actor, by string) service.EmitOp {
	return service.EmitOp{Key: key, Stream: "brand:" + w.Brand, Intent: "menu.import.apply", IntentV: 1, Actor: actor, AuthorisedBy: &by,
		Muts: []sp.Mut{{E: "item", ID: emitItem, K: sp.KSet, F: map[string]any{"tax_class": "fnb_standard"}}}}
}

// P2-M3 (f): a `support:` actor is refused on an intent that no support_actable permission authorises, and accepted on one
// authorised by catalog.import.
func TestEmitRefusesASupportActorWhereNoActablePermissionAuthorises(t *testing.T) {
	w, _ := newTestWorld(t, 61, WorldOptions{Pos: 1})
	for _, op := range []service.EmitOp{w.taxClassOp("s1", "support:vendor-user"), w.importOp("s2", "support:vendor-user", "menu.import")} {
		_, err := w.GW.Emit(bg, w.Tenant, "catalog", []service.EmitOp{op})
		var ee *service.EmitError
		if !asEmitErr(err, &ee) || ee.Code != service.EmitCallerNotOwner {
			t.Fatalf("%s as a support actor: got %v, want %s", op.Intent, err, service.EmitCallerNotOwner)
		}
	}
	if _, err := w.GW.Emit(bg, w.Tenant, "catalog", []service.EmitOp{w.importOp("s3", "support:vendor-user", "catalog.import")}); err != nil {
		t.Fatalf("a support actor authorised by catalog.import: %v", err)
	}
	if _, err := w.GW.Emit(bg, w.Tenant, "catalog", []service.EmitOp{w.taxClassOp("s4", "m1")}); err != nil {
		t.Fatalf("a member actor: %v", err)
	}
}

func asEmitErr(err error, out **service.EmitError) bool {
	ee, ok := err.(*service.EmitError)
	if ok {
		*out = ee
	}
	return ok
}

// P2-M3 (e): a caller has a rate and a burst of ops; a batch over what is left is refused whole (nothing stored) until the
// bucket refills; another caller has its own bucket.
func TestEmitIsRateLimitedPerCaller(t *testing.T) {
	w, _ := newTestWorld(t, 62, WorldOptions{Pos: 1})
	batch := func(prefix string) []service.EmitOp {
		ops := make([]service.EmitOp, sp.MaxEmitOps)
		for i := range ops {
			ops[i] = w.taxClassOp(prefix+string(rune('a'+i/26))+string(rune('a'+i%26)), "m1")
		}
		return ops
	}
	n := service.EmitBurst / sp.MaxEmitOps
	for i := 0; i < n; i++ {
		if _, err := w.GW.Emit(bg, w.Tenant, "catalog", batch(string(rune('A'+i)))); err != nil {
			t.Fatalf("batch %d inside the burst: %v", i, err)
		}
	}
	if _, err := w.GW.Emit(bg, w.Tenant, "catalog", batch("Z")); err != service.ErrEmitRateLimited {
		t.Fatalf("a batch over the burst: got %v, want ErrEmitRateLimited", err)
	}
	if _, err := w.GW.Emit(bg, w.Tenant, "billing", []service.EmitOp{{Key: "b1", Stream: "outlet:" + w.Outlet, Intent: "settings.discount_limit.set", IntentV: 1, Actor: "m1",
		AuthorisedBy: strp("bill.discount.limit.edit"), Muts: []sp.Mut{{E: "billing_settings", ID: emitItem, K: sp.KSet, F: map[string]any{"max_percent": int64(10)}}}}}); err != nil && err == service.ErrEmitRateLimited {
		t.Fatal("another caller has its own bucket")
	}
	w.Advance(time.Duration(sp.MaxEmitOps/service.EmitRatePerSecond+1) * time.Second)
	if _, err := w.GW.Emit(bg, w.Tenant, "catalog", batch("Y")); err != nil {
		t.Fatalf("after the bucket refilled: %v", err)
	}
}

func strp(s string) *string { return &s }

// P2-M3 (b): a user token forwarded with an emit is verified: its tenant must be the request's and its subject the op's actor.
func TestEmitVerifiesAForwardedUserToken(t *testing.T) {
	w, _ := newTestWorld(t, 63, WorldOptions{Pos: 1})
	svc, err := w.Services.Signer("catalog").Sign("sync", w.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	body := func(key string) map[string]any {
		return map[string]any{"tenant_id": w.Tenant, "ops": []map[string]any{{"key": key, "stream": "brand:" + w.Brand, "intent": "menu.tax_class.set", "intent_v": 1,
			"actor": "m1", "authorised_by": "menu.tax_class.edit", "muts": []map[string]any{{"e": "item", "id": emitItem, "k": "set", "f": map[string]any{"tax_class": "fnb_standard"}}}}}}
	}
	user := func(tenant, sub string) string {
		return w.Issuer.Mint(authtest.Spec{Type: auth.TypeUser, Tenant: ids.ID(tenant), Subject: sub, Grants: authtest.OwnerGrants()})
	}
	for _, tc := range []struct {
		name, token string
		want        int
	}{
		{"no user token (a queued emission)", "", 200},
		{"the actor's own token", user(w.Tenant, "m1"), 200},
		{"another member's token", user(w.Tenant, "m2"), 403},
		{"a token of another tenant", user("018f0000-0000-7000-8000-0000000000ff", "m1"), 403},
		{"a token that does not verify", "not.a.token", 401},
	} {
		code, out := w.adminCall("POST", "/internal/v1/emit", tc.token, svc, body("k-"+strings.ReplaceAll(tc.name, " ", "-")))
		if code != tc.want {
			t.Errorf("%s: got %d %s, want %d", tc.name, code, out, tc.want)
		}
		_ = json.Valid
	}
}
