package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/enbility/zeroconf/v2"
)

// ServiceType is the DNS-SD service the hub advertises (S9).
const ServiceType = "_hostry-hub._tcp"

// Advertisement is what a hub announces. Discovery finds an address only; trust comes from the
// device credentials (S10), so a fake hub announcing itself gains nothing.
type Advertisement struct {
	HubID   string
	Outlet  string
	Port    int
	Version int
}

// OutletHash is the TXT value that names the outlet without publishing its id.
func OutletHash(outlet string) string {
	s := sha256.Sum256([]byte("hostry-outlet-v1\n" + outlet))
	return hex.EncodeToString(s[:6])
}

// Advertise registers the hub on mDNS until ctx ends. Library choice (ADR-0002 S9, research r16):
// github.com/enbility/zeroconf/v2, a maintained fork of grandcat/zeroconf (last upstream release 2020),
// pure Go, used by EEBUS stacks; API-compatible so a swap costs an import.
func Advertise(ctx context.Context, a Advertisement) error {
	txt := []string{"hub=" + a.HubID, "outlet=" + OutletHash(a.Outlet), fmt.Sprintf("proto=%d", a.Version)}
	srv, err := zeroconf.Register("hostry-hub-"+OutletHash(a.Outlet), ServiceType, "local.", a.Port, txt, nil)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); srv.Shutdown() }()
	return nil
}

// Found is a hub seen on the network.
type Found struct {
	Host   string
	Addrs  []string
	Port   int
	HubID  string
	Outlet string // outlet hash
}

// Browse looks for hubs for up to timeout and returns those found (the native shell does this on
// devices; this is the Go side for tests and the hub-to-hub standby case).
func Browse(ctx context.Context, timeout time.Duration) ([]Found, error) {
	entries := make(chan *zeroconf.ServiceEntry)
	removed := make(chan *zeroconf.ServiceEntry, 16)
	go func() {
		for range removed {
		}
	}()
	var out []Found
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range entries {
			f := Found{Host: e.HostName, Port: e.Port}
			for _, a := range e.AddrIPv4 {
				f.Addrs = append(f.Addrs, a.String())
			}
			for _, t := range e.Text {
				switch {
				case len(t) > 4 && t[:4] == "hub=":
					f.HubID = t[4:]
				case len(t) > 7 && t[:7] == "outlet=":
					f.Outlet = t[7:]
				}
			}
			out = append(out, f)
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := zeroconf.Browse(cctx, ServiceType, "local.", entries, removed); err != nil {
		return nil, err
	}
	<-cctx.Done()
	select { // the library closes entries when the context ends
	case <-done:
	case <-time.After(time.Second):
	}
	return out, nil
}
