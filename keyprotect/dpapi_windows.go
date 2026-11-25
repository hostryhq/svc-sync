//go:build windows

package keyprotect

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPI is the `os-software` tier: Windows DPAPI in the scope of the account the hub runs under (the service account), not
// the machine scope, so another Windows user cannot unwrap what this account wrapped (HS1; measured on a Windows PC at the pilot
// gate, ADR-0002 A3.5). No CGO: the calls go through golang.org/x/sys/windows.
type DPAPI struct{}

// NewDPAPI returns the DPAPI provider.
func NewDPAPI() (*DPAPI, error) { return &DPAPI{}, nil }

// Tier implements Provider.
func (*DPAPI) Tier() string { return TierOSSoftware }

var entropy = []byte("hostry-hub-keyprotect-v1")

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func take(b *windows.DataBlob) []byte {
	out := append([]byte(nil), unsafe.Slice(b.Data, b.Size)...)
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return out
}

// Wrap implements Provider (CryptProtectData, user scope, no UI).
func (*DPAPI) Wrap(secret []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(secret), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// Unwrap implements Provider (CryptUnprotectData).
func (*DPAPI) Unwrap(wrapped []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(wrapped), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, ErrUnwrap
	}
	return take(&out), nil
}
