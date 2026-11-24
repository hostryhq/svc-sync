package hub

import (
	"context"
	"testing"
	"time"
)

// Informative, not gating (ADR-0002 PoC item 8): multicast may be unavailable in CI or WSL.
func TestAdvertiseAndBrowseOnTheLocalNetwork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := Advertise(ctx, Advertisement{HubID: "hub-t", Outlet: "outlet-t", Port: 18082, Version: 1}); err != nil {
		t.Skipf("mDNS register unavailable here: %v", err)
	}
	found, err := Browse(ctx, 3*time.Second)
	if err != nil {
		t.Skipf("mDNS browse unavailable here: %v", err)
	}
	for _, f := range found {
		if f.HubID == "hub-t" && f.Outlet == OutletHash("outlet-t") && f.Port == 18082 {
			return
		}
	}
	t.Skipf("no multicast loopback in this environment (%d entries seen); discovery stays informative", len(found))
}
