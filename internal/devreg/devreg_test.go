package devreg_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/svc-sync/api"
	"github.com/hostryhq/svc-sync/devepoch"
	"github.com/hostryhq/svc-sync/identitystub"
	"github.com/hostryhq/svc-sync/internal/devreg"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

func TestGuardRefusesOutsideDevTestCI(t *testing.T) {
	for _, c := range []struct {
		env   string
		allow bool
		ok    bool
	}{{"dev", true, true}, {"test", true, true}, {"ci", true, true}, {"dev", false, false}, {"", true, false}, {"staging", true, false}, {"production", true, false}} {
		if err := devreg.Guard(c.env, c.allow); (err == nil) != c.ok {
			t.Errorf("Guard(%q, %v) = %v, want ok=%v", c.env, c.allow, err, c.ok)
		}
	}
}

func stack(t *testing.T) http.Handler {
	t.Helper()
	now := func() time.Time { return time.Date(2026, 11, 25, 5, 0, 0, 0, time.UTC) }
	id, err := identitystub.New(now, nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer := authtest.NewTenantIssuer(clock.Func(now))
	st, err := repository.Open("file:devreg-" + t.Name() + "?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ep, err := devepoch.Reader(context.Background(), "file:devreg-epoch-"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	gw, err := service.New(context.Background(), service.Config{Store: st, Epoch: ep, Dir: id, OpKey: id.CloudKey, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	api.Mount(mux, api.Options{Auth: api.BearerAuth{Verifier: issuer.Verifier(), Dir: id}, Backend: api.GatewayBackend{G: gw}})
	(&devreg.Registry{ID: id, Issuer: issuer, Now: now}).Mount(mux)
	return mux
}

func call(h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A device registered through the dev route can say hello with the token it was given and with one minted
// later; a device that was never registered cannot, and one tenant's device is not found by another tenant.
func TestRegisteredDeviceCanSyncAndOthersCannot(t *testing.T) {
	h := stack(t)
	const tenant, outlet, brand = "018f0000-0000-7000-8000-0000000000a0", "018f0000-0000-7000-8000-0000000000a1", "018f0000-0000-7000-8000-0000000000b1"
	reg := map[string]any{"tenant_id": tenant, "outlet_id": outlet, "brand_id": brand, "device_id": "dev-a", "kind": "pos",
		"series": []map[string]any{{"code": "AB2", "doc_type": "tax_invoice"}}, "members": []map[string]any{{"id": "m1"}}}
	rec := call(h, "POST", "/dev/v1/devices", "", reg)
	if rec.Code != 201 {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	var out devreg.RegisterResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Token == "" || out.PKCS8 == "" || out.Credential.Cred.DeviceID != "dev-a" || len(out.Series) != 1 || out.Series[0]["code"] != "AB2" {
		t.Fatalf("response: %+v", out)
	}
	if rec := call(h, "POST", "/dev/v1/devices", "", reg); rec.Code != 409 {
		t.Fatalf("registering twice: %d", rec.Code)
	}
	hello := sp.HelloRequest{Protocol: sp.ProtocolVersion}
	if rec := call(h, "POST", "/sync/v1/hello", out.Token, hello); rec.Code != 200 {
		t.Fatalf("hello with the registration token: %d %s", rec.Code, rec.Body)
	}
	var tok map[string]string
	rec = call(h, "POST", "/dev/v1/device-tokens", "", map[string]any{"tenant_id": tenant, "device_id": "dev-a"})
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if rec.Code != 200 || call(h, "POST", "/sync/v1/hello", tok["token"], hello).Code != 200 {
		t.Fatalf("minted token: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "POST", "/dev/v1/device-tokens", "", map[string]any{"tenant_id": "018f0000-0000-7000-8000-0000000000ff", "device_id": "dev-a"}); rec.Code != 404 {
		t.Fatalf("another tenant must not mint for the device: %d", rec.Code)
	}
	if rec := call(h, "POST", "/dev/v1/device-tokens", "", map[string]any{"tenant_id": tenant, "device_id": "ghost"}); rec.Code != 404 {
		t.Fatalf("unregistered device: %d", rec.Code)
	}
}
