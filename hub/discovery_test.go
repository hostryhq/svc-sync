package hub

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// FuzzParseText feeds announcement TXT records as any host on the LAN could send them (review L6).
// The result must never exceed the bounds or carry anything but printable ASCII.
func FuzzParseText(f *testing.F) {
	f.Add("hub=hub-1", "outlet=abc123")
	f.Add("hub="+strings.Repeat("x", 500), "outlet=\x00\xff")
	f.Add("hub=", "outlet=")
	f.Fuzz(func(t *testing.T, a, b string) {
		hub, outlet := parseText([]string{a, b})
		for _, v := range []string{hub, outlet} {
			if len(v) > maxTextValue {
				t.Fatalf("value over the bound: %d", len(v))
			}
			for i := 0; i < len(v); i++ {
				if v[i] < 0x21 || v[i] > 0x7e {
					t.Fatalf("non-printable byte in %q", v)
				}
			}
		}
	})
}

func TestParseTextDropsOversizedAndNonPrintableValues(t *testing.T) {
	hub, outlet := parseText([]string{"hub=" + strings.Repeat("a", maxTextValue+1), "outlet=ok\x01", "hub=h1", "outlet=o1", "junk"})
	if hub != "h1" || outlet != "o1" {
		t.Fatalf("got %q %q", hub, outlet)
	}
}

// Informative, not gating (ADR-0002 PoC item 8): multicast may be unavailable in CI or WSL, and the
// test can only skip, so it runs on request (SYNC_MDNS_TEST=1) and never counts as coverage (review L8).
func TestAdvertiseAndBrowseOnTheLocalNetwork(t *testing.T) {
	if os.Getenv("SYNC_MDNS_TEST") == "" {
		t.Skip("set SYNC_MDNS_TEST=1 to try mDNS on this network")
	}
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
