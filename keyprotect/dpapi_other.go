//go:build !windows

package keyprotect

// DPAPI is the Windows `os-software` tier. On this platform it is not available.
type DPAPI struct{}

// NewDPAPI returns ErrUnsupported off Windows.
func NewDPAPI() (*DPAPI, error) { return nil, ErrUnsupported }

// Tier implements Provider.
func (*DPAPI) Tier() string { return TierOSSoftware }

// Wrap implements Provider.
func (*DPAPI) Wrap([]byte) ([]byte, error) { return nil, ErrUnsupported }

// Unwrap implements Provider.
func (*DPAPI) Unwrap([]byte) ([]byte, error) { return nil, ErrUnsupported }
