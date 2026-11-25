package identityclient

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	auth "github.com/hostryhq/go-auth"
)

// ServiceName is the name sync signs its service tokens under (the key id in identity's service key registry).
const ServiceName = "sync"

// FromEnv builds the directory from the environment, failing fast with every problem at once:
//
//	SYNC_IDENTITY_URL                base URL of the identity service (https outside development)
//	SYNC_SERVICE_SIGNING_KEY_FILE    PEM PKCS#8 P-256 private key of sync's service tokens (a file reference; never a value)
//
// The directory's Proof hook is left nil: the op does not carry pin_v and opened_at yet (see Directory).
func FromEnv(getenv func(string) string) (*Directory, error) {
	var problems []string
	base, keyFile := getenv("SYNC_IDENTITY_URL"), getenv("SYNC_SERVICE_SIGNING_KEY_FILE")
	if u, err := url.Parse(base); base == "" || err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		problems = append(problems, "SYNC_IDENTITY_URL must be an http(s) URL")
	}
	var key *ecdsa.PrivateKey
	if keyFile == "" {
		problems = append(problems, "SYNC_SERVICE_SIGNING_KEY_FILE is required")
	} else if k, err := readKey(keyFile); err != nil {
		problems = append(problems, "SYNC_SERVICE_SIGNING_KEY_FILE: "+err.Error())
	} else {
		key = k
	}
	if len(problems) > 0 {
		return nil, errors.New("identity directory: " + strings.Join(problems, "; "))
	}
	cl, err := New(base, &auth.ServiceSigner{Name: ServiceName, Key: key}, nil)
	if err != nil {
		return nil, err
	}
	return &Directory{Client: cl}, nil
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
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
