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

// maxTextValue bounds a TXT value read from the LAN: the input is untrusted (review L6).
const maxTextValue = 64

// parseText reads the hub id and outlet hash from the TXT records of an announcement. The records
// come from any host on the LAN, so values are bounded and restricted to printable ASCII; a value
// that does not fit is dropped. Discovery finds an address only; trust never rests on these values.
func parseText(txt []string) (hubID, outlet string) {
	val := func(t, prefix string) (string, bool) {
		if len(t) <= len(prefix) || t[:len(prefix)] != prefix || len(t)-len(prefix) > maxTextValue {
			return "", false
		}
		v := t[len(prefix):]
		for i := 0; i < len(v); i++ {
			if v[i] < 0x21 || v[i] > 0x7e {
				return "", false
			}
		}
		return v, true
	}
	for _, t := range txt {
		if v, ok := val(t, "hub="); ok {
			hubID = v
		} else if v, ok := val(t, "outlet="); ok {
			outlet = v
		}
	}
	return hubID, outlet
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
			f.HubID, f.Outlet = parseText(e.Text)
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
