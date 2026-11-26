package devreg_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/internal/devreg"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// The hub registered through the dev route comes back with the pack cmd/hub reads: it loads, names the outlet's other
// devices and the owner of each of their series, and the pack version the registry issued is the integer the client
// sends as pack_v (ADR-0005 A3.1).
func TestHubRegistrationProducesThePackTheHubBinaryReads(t *testing.T) {
	h := stack(t)
	const tenant, outlet, brand = "018f0000-0000-7000-8000-0000000000a0", "018f0000-0000-7000-8000-0000000000a1", "018f0000-0000-7000-8000-0000000000b1"
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{"tenant_id": tenant, "outlet_id": outlet, "brand_id": brand}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	rec := call(h, "POST", "/dev/v1/devices", "", with(map[string]any{"device_id": "dev-a", "kind": "pos", "pack_version": 3,
		"series": []map[string]any{{"code": "AB2", "doc_type": "tax_invoice"}}, "members": []map[string]any{{"id": "m1"}}}))
	var dev devreg.RegisterResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &dev)
	if rec.Code != 201 || dev.PackVersion != 3 {
		t.Fatalf("device: %d %s", rec.Code, rec.Body)
	}
	if rec := call(h, "POST", "/dev/v1/devices", "", with(map[string]any{"device_id": "dev-b", "kind": "pos", "pack_version": 0.5})); rec.Code != 400 {
		t.Fatalf("a pack version that is not an integer is refused: %d", rec.Code)
	}
	rec = call(h, "POST", "/dev/v1/devices", "", with(map[string]any{"device_id": "hub-1", "kind": "hub"}))
	var hubReg devreg.RegisterResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &hubReg)
	if rec.Code != 201 || hubReg.HubPack == nil || hubReg.PackVersion != 1 {
		t.Fatalf("hub: %d %s", rec.Code, rec.Body)
	}
	// Written again later, after another device joined: the route keeps the hub's key and rebuilds the rest.
	call(h, "POST", "/dev/v1/devices", "", with(map[string]any{"device_id": "dev-c", "kind": "waiter", "series": []map[string]any{{"code": "AC3", "doc_type": "tax_invoice", "status": "dormant"}}}))
	rec = call(h, "GET", "/dev/v1/hub-packs/hub-1?tenant_id="+tenant, "", nil)
	if rec.Code != 200 {
		t.Fatalf("hub pack: %d %s", rec.Code, rec.Body)
	}
	path := t.TempDir() + "/hub-pack.json"
	if err := os.WriteFile(path, rec.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, pack, err := hub.LoadPack(path)
	if err != nil {
		t.Fatalf("cmd/hub cannot read the pack: %v", err)
	}
	if cfg.Tenant != tenant || cfg.Outlet != outlet || cfg.Cred.Cred.Kind != sp.KindHub || len(pack.Peers) != 2 || !cfg.Members("m1") {
		t.Fatalf("pack: %+v", pack)
	}
	if d, ok := cfg.SeriesOwner("AB2"); !ok || d != "dev-a" {
		t.Fatalf("series owner of AB2: %q %v", d, ok)
	}
	if d, ok := cfg.SeriesOwner("AC3"); !ok || d != "dev-c" {
		t.Fatalf("series owner of AC3: %q %v", d, ok)
	}
	if rec := call(h, "GET", "/dev/v1/hub-packs/dev-a?tenant_id="+tenant, "", nil); rec.Code != 404 {
		t.Fatalf("a device that is not a hub has no pack: %d", rec.Code)
	}
}
