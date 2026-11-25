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

// OriginKey implements Trust. For a cloud-<epoch> origin it only says whether any op-signing key is
// installed: a seal is verified under the key its own kid names (OpKey), never under whichever key
// the cache happens to hold (review L8). The returned key is nil for a cloud origin.
func (c *CredCache) OriginKey(origin string) (*ecdsa.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.HasPrefix(origin, CloudOriginPrefix) {
		return nil, len(c.cloudKeys) > 0
	}
	e, ok := c.creds[origin]
	if !ok {
		return nil, false
	}
	pub, err := e.Cred.PubKey()
	return pub, err == nil
}

// RevokeCloudKey stops accepting seals and endorsements under an op-signing key (pack refresh
// after an emergency rotation, A2.1 item 6).
func (c *CredCache) RevokeCloudKey(kid string) {
	c.mu.Lock()
	delete(c.cloudKeys, kid)
	c.mu.Unlock()
}

// OpKey implements RecoveryTrust: the current op-signing key named by kid.
func (c *CredCache) OpKey(kid string) (*ecdsa.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k, ok := c.cloudKeys[kid]
	return k, ok
}

// Recoverers implements RecoveryTrust: the stored credentials that carry `recovers: origin`.
func (c *CredCache) Recoverers(origin string) []sp.CredentialEnvelope {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []sp.CredentialEnvelope
	for _, e := range c.creds {
		if e.Cred.Recovers == origin {
			out = append(out, e)
		}
	}
	return out
}
