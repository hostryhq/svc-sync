package engine

import (
	"crypto/ecdsa"
	"errors"
	"strings"
	"sync"
	"time"

	sp "github.com/hostryhq/svc-sync/syncproto"
)

// CloudOriginPrefix starts every cloud-origin id: cloud-<epoch> (S16).
const CloudOriginPrefix = "cloud-"

// CredCache is what a hub or device knows of its peers: identity-signed credentials from its
// offline pack and from pull responses, and the gateway op-signing key from the pack.
type CredCache struct {
	mu          sync.Mutex
	identityPub *ecdsa.PublicKey
	cloudKeys   map[string]*ecdsa.PublicKey // kid -> key
	tenant      string
	outlet      string
	creds       map[string]sp.CredentialEnvelope
	now         func() time.Time
}

// NewCredCache builds a cache that accepts credentials of one tenant and outlet.
func NewCredCache(identityPub *ecdsa.PublicKey, tenant, outlet string, now func() time.Time) *CredCache {
	return &CredCache{identityPub: identityPub, tenant: tenant, outlet: outlet, creds: map[string]sp.CredentialEnvelope{}, cloudKeys: map[string]*ecdsa.PublicKey{}, now: now}
}

// AddCloudKey installs a gateway op-signing public key (delivered in every pack).
func (c *CredCache) AddCloudKey(kid string, pub *ecdsa.PublicKey) {
	c.mu.Lock()
	c.cloudKeys[kid] = pub
	c.mu.Unlock()
}

// ErrCredential is returned for a credential that is not acceptable.
var ErrCredential = errors.New("engine: credential not acceptable")

// Add verifies and stores a credential. A credential of another tenant or outlet, or with a bad
// identity signature, is refused. Expiry is checked on use for LAN authentication, not here, so
// the history of a since-expired device stays verifiable.
func (c *CredCache) Add(e sp.CredentialEnvelope) error {
	if !sp.VerifyCredential(c.identityPub, e) || e.Cred.TenantID != c.tenant || (c.outlet != "" && e.Cred.OutletID != c.outlet) {
		return ErrCredential
	}
	if _, err := e.Cred.PubKey(); err != nil {
		return ErrCredential
	}
	c.mu.Lock()
	c.creds[e.Cred.DeviceID] = e
	c.mu.Unlock()
	return nil
}

// Get returns a stored credential.
func (c *CredCache) Get(device string) (sp.CredentialEnvelope, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.creds[device]
	return e, ok
}

// OriginKey implements Trust.
func (c *CredCache) OriginKey(origin string) (*ecdsa.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.HasPrefix(origin, CloudOriginPrefix) {
		// The cloud seals with one op-signing key at a time; the seal names the kid, so try all.
		for _, k := range c.cloudKeys {
			return k, true
		}
		return nil, false
	}
	e, ok := c.creds[origin]
	if !ok {
		return nil, false
	}
	pub, err := e.Cred.PubKey()
	return pub, err == nil
}

// CloudKey returns the gateway op-signing key from the pack.
func (c *CredCache) CloudKey() (*ecdsa.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.cloudKeys {
		return k, true
	}
	return nil, false
}
