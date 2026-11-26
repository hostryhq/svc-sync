// Package keyprotect wraps the hub's secrets under a key the operating system guards (ADR-0002 A3.2 item 3). A Provider wraps
// and unwraps small secrets: the hub's data key (which encrypts the hub database's value columns) and its device private key.
//
// Tiers, recorded at activation and shown to the owner:
//   - "hardware":    a key held in the PC's TPM. Not built; a gate (A3.5).
//   - "os-software": Windows DPAPI in the scope of the hub's own service account (NewDPAPI; windows only, no CGO).
//   - "dev":         a key file or environment value (NewDev). Linux CI and the soak only; it refuses to start outside
//     HOSTRY_ENV dev, test and ci, and a hub using it declares `store: unprotected` (A3.5 item 1).
package keyprotect

import (
	"errors"
	"fmt"
)

// Tiers.
const (
	TierHardware   = "hardware"
	TierOSSoftware = "os-software"
	TierDev        = "dev"
)

// Provider wraps and unwraps a secret. Wrapped bytes may be stored in the clear: they are useless without the provider's key.
type Provider interface {
	// Tier is the protection tier this provider gives.
	Tier() string
	Wrap(secret []byte) ([]byte, error)
	Unwrap(wrapped []byte) ([]byte, error)
}

// ErrUnsupported is returned by a provider that this platform or build does not offer.
var ErrUnsupported = errors.New("keyprotect: provider not available on this platform")

// ErrUnwrap is returned when wrapped bytes do not unwrap (another user, another machine, a damaged value).
var ErrUnwrap = errors.New("keyprotect: cannot unwrap")

// StoreClaim is the `store` claim a hub using p may make: `protected` for any tier but dev (ADR-0002 A3.5 item 1).
func StoreClaim(p Provider) string {
	if p.Tier() == TierDev {
		return "unprotected"
	}
	return "protected"
}

// devEnvOK reports whether env is one where the dev provider may run.
func devEnvOK(env string) bool {
	switch env {
	case "dev", "test", "ci":
		return true
	}
	return false
}

func errDevEnv(env string) error {
	return fmt.Errorf("keyprotect: the dev key provider is not production protection and refuses HOSTRY_ENV %q (dev, test or ci only)", env)
}
