package hub

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Pack is the part of the offline pack the hub needs (ADR-0005 section 6): its own credential and key,
// the identity verification key, the gateway op-signing keys, the outlet's device credentials, staff
// and series grants. In the PoC it is a JSON file; the installer fetches it from identity at
// activation. PKCS8 is the hub's private key (a Windows DPAPI-protected file in production).
type Pack struct {
	Tenant      string                  `json:"tenant_id"`
	Outlet      string                  `json:"outlet_id"`
	Brand       string                  `json:"brand_id"`
	Kid         string                  `json:"kid"`
	Cred        sp.CredentialEnvelope   `json:"cred"`
	CredJWS     string                  `json:"cred_jws"`
	PKCS8       string                  `json:"pkcs8"`
	IdentityPub string                  `json:"identity_pub"`
	CloudKeys   map[string]string       `json:"cloud_keys"`
	Peers       []sp.CredentialEnvelope `json:"peers"`
	Members     []string                `json:"members"`
	SeriesOwner map[string]string       `json:"series_owner"`
	CloudURL    string                  `json:"cloud_url"`
}

// LoadPack reads a pack file and returns a ready Config (store and clock still to be set).
func LoadPack(path string) (Config, Pack, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, Pack{}, err
	}
	var p Pack
	if err := json.Unmarshal(raw, &p); err != nil {
		return Config{}, Pack{}, fmt.Errorf("pack: %w", err)
	}
	der, err := base64.RawURLEncoding.DecodeString(p.PKCS8)
	if err != nil {
		return Config{}, Pack{}, errors.New("pack: bad private key encoding")
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	ec, ok := k.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		return Config{}, Pack{}, errors.New("pack: private key is not ECDSA")
	}
	idPub, err := sp.DecodePub(p.IdentityPub)
	if err != nil {
		return Config{}, Pack{}, err
	}
	keys := map[string]*PubKey{}
	for kid, pub := range p.CloudKeys {
		if keys[kid], err = sp.DecodePub(pub); err != nil {
			return Config{}, Pack{}, err
		}
	}
	members := map[string]bool{}
	for _, m := range p.Members {
		members[m] = true
	}
	cfg := Config{Tenant: p.Tenant, Outlet: p.Outlet, Brand: p.Brand, Cred: p.Cred, CredJWS: p.CredJWS, Key: &sp.KeyPair{Kid: p.Cred.Cred.Kid, Priv: ec},
		IdentityPub: idPub, CloudKeys: keys, Peers: p.Peers,
		Members:     func(a string) bool { return members[a] },
		SeriesOwner: func(c string) (string, bool) { d, ok := p.SeriesOwner[c]; return d, ok }}
	return cfg, p, nil
}
