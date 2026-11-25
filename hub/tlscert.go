package hub

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"

	sp "github.com/hostryhq/svc-sync/syncproto"
)

// CertPeriod is how long a hub keeps one TLS key (ADR-0002 A3.1 item 2).
const CertPeriod = 7 * 24 * time.Hour

// tlsKeys holds the hub's TLS key pair and self-signed certificate. They are made in memory at each service start and again
// after CertPeriod of running; the key is never written anywhere. The certificate's names and dates mean nothing: no node
// checks them, every node proves the hub through the `hello` credentials and the spki binding instead.
type tlsKeys struct {
	mu   sync.Mutex
	now  func() time.Time
	cert tls.Certificate
	spki string
	born time.Time
}

func newTLSKeys(now func() time.Time) (*tlsKeys, error) {
	k := &tlsKeys{now: now}
	return k, k.rotate()
}

func (k *tlsKeys) rotate() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return err
	}
	now := k.now()
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "hostry-hub"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(400 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.cert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
	k.spki, k.born = sp.SPKIOf(leaf), now
	k.mu.Unlock()
	return nil
}

// current returns the certificate to present, rotating a key that is older than CertPeriod.
func (k *tlsKeys) current() *tls.Certificate {
	k.mu.Lock()
	due := k.now().Sub(k.born) >= CertPeriod
	k.mu.Unlock()
	if due {
		_ = k.rotate()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	c := k.cert
	return &c
}

func (k *tlsKeys) SPKI() string {
	k.current()
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.spki
}

// TLSConfig is the hub's TLS 1.3 server configuration: the self-signed in-memory certificate, no client certificate.
func (h *Hub) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return h.keys.current(), nil
		},
	}
}

// SPKI is the lower-case hex SHA-256 of the DER SubjectPublicKeyInfo of the certificate the hub presents now: what a device
// that reached this hub over TLS sees, and what both handshake proofs name.
func (h *Hub) SPKI() string { return h.keys.SPKI() }

// RotateTLSKey makes a new TLS key and certificate now (a service start does this; so does the 7-day rotation).
func (h *Hub) RotateTLSKey() error { return h.keys.rotate() }
