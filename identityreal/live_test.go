package identityreal

import (
	"context"
	"os"
	"testing"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/identityclient"
	"github.com/hostryhq/svc-sync/realdir"
	"github.com/hostryhq/svc-sync/tenancyclient"
)

// The directory against the identity and tenancy services running on the dev stack (their own ports): every route
// the gateway calls is reachable with sync's service token, answers 404 for what does not exist, and no lookup is
// refused (a 401 or 403 would count as a fault). It seeds nothing: the services are only read.
//
//	SYNC_LIVE_IDENTITY_URL, SYNC_LIVE_TENANCY_URL, SYNC_SERVICE_SIGNING_KEY_FILE
func TestLiveDirectoryAgainstTheRunningServices(t *testing.T) {
	idURL, tenURL, keyFile := os.Getenv("SYNC_LIVE_IDENTITY_URL"), os.Getenv("SYNC_LIVE_TENANCY_URL"), os.Getenv("SYNC_SERVICE_SIGNING_KEY_FILE")
	if idURL == "" || tenURL == "" || keyFile == "" {
		t.Skip("SYNC_LIVE_IDENTITY_URL, SYNC_LIVE_TENANCY_URL and SYNC_SERVICE_SIGNING_KEY_FILE not set: no running dev stack")
	}
	key, err := identityclient.ReadKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	signer := &auth.ServiceSigner{Name: identityclient.ServiceName, Key: key}
	ic, err := identityclient.New(idURL, signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	tc, err := tenancyclient.New(tenURL, signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := &realdir.Directory{Identity: ic, Tenancy: tc}
	tenant, device, member, outlet := string(ids.New()), string(ids.New()), string(ids.New()), string(ids.New())
	if err := d.Poll(context.Background()); err != nil {
		t.Fatalf("the revocation feed: %v", err)
	}
	if err := d.Ready(); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Credential(tenant, device); ok {
		t.Fatal("an unknown device has no credential")
	}
	if _, ok := d.PackFor(tenant, device, 1); ok {
		t.Fatal("an unknown device has no pack")
	}
	if d.StillHolds(tenant, outlet, member, "order.create") || d.InAnyPack(tenant, device, member) {
		t.Fatal("an unknown member holds nothing")
	}
	if _, ok := d.RecoveryFor(tenant, device); ok {
		t.Fatal("no recovery")
	}
	if _, lk := d.StrongSession(tenant, string(ids.New())); lk != directory.NotFound {
		t.Fatalf("an unknown session is not found (not unreachable): %v", lk)
	}
	if _, ok := d.SeriesFor(tenant, device, outlet, "AAA"); ok {
		t.Fatal("an unknown device has no series")
	}
	if d.StreamInTenant(tenant, "outlet:"+outlet) {
		t.Fatal("an unknown outlet is not the tenant's")
	}
	q := directory.ProofQuestion{Kind: directory.ProofKindSession, Device: device, Member: member, SID: string(ids.New()), PackV: 1, PinV: 1, Proof: "x", Key: "live-1"}
	if got := d.VerifyProof(tenant, q); got == directory.ProofValid || got == directory.ProofUnavailable {
		t.Fatalf("a proof for an unknown device is invalid, never valid and not unavailable: %v", got)
	}
	if f := d.Faults(); f != 0 {
		t.Fatalf("%d lookups were refused or failed: a route is not reachable with sync's service token", f)
	}
}
