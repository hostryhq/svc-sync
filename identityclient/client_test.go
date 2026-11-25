package identityclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/svc-sync/directory"
)

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(srv.URL, &auth.ServiceSigner{Name: ServiceName, Key: k}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) {}
	return c
}

// A retry after a 503 repeats the same Idempotency-Key (so it is a replay, never a second effect), every attempt
// carries a service token that names the tenant acted for, and a second 503 is "unavailable", never an answer.
func TestRetryReusesTheKeyAndTheTokenNamesTheTenant(t *testing.T) {
	var calls atomic.Int32
	var keys []string
	var tenants []string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		parts := strings.Split(r.Header.Get(auth.ServiceTokenHeader), ".")
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var cl struct {
			Tenant string `json:"tid"`
		}
		_ = json.Unmarshal(raw, &cl)
		tenants = append(tenants, cl.Tenant)
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"valid":false,"label":"unverified","locked":true}`))
	})
	v, err := c.VerifyProof(context.Background(), "tenant-a", ProofCheck{DeviceID: "d", MemberID: "m", SessionID: "s", PackV: 1, PinV: 1, OpenedAt: time.Now(), Proof: "p"})
	if err != nil || !v.Locked || v.Valid {
		t.Fatalf("%+v %v", v, err)
	}
	if len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] || tenants[0] != "tenant-a" || tenants[1] != "tenant-a" {
		t.Fatalf("keys %v tenants %v", keys, tenants)
	}
	// Two outages in a row: the caller is told "unavailable".
	d := &Directory{Client: testClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }),
		Proof: func(_, _, _, _ string) (ProofParams, bool) { return ProofParams{PackV: 1, PinV: 1}, true }}
	if got := d.CheckProof("t", "d", "m", "s", "p", false); got != directory.ProofUnavailable {
		t.Fatalf("an outage must never read as a verdict: %v", got)
	}
	// No pack and PIN versions known (the op does not carry them): never "valid".
	d.Proof = nil
	if got := d.CheckProof("t", "d", "m", "s", "p", false); got != directory.ProofUnavailable {
		t.Fatalf("without pin_v and opened_at the check cannot be asked: %v", got)
	}
}
