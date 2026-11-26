package identityclient

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// ServiceName is the name sync signs its service tokens under (the key id in identity's service key registry).
const ServiceName = "sync"

// ReadKey reads a PEM PKCS#8 P-256 private key from a file (the service signing key). Errors name no key material.
func ReadKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read the file")
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("not a PKCS#8 key")
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("not a P-256 key")
	}
	return ec, nil
}
