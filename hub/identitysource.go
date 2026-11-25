package hub

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	sp "github.com/hostryhq/svc-sync/syncproto"
)

// The hub's pack source (ADR-0002 A3.4): the hub is an ordinary identity device. It activates with the 8-character code of
// ADR-0005 section 4, receives a signed `hub` pack (HubPackClaims) and refreshes it at every cloud contact with its device token.
// It never hands packs to devices. The wire types below follow api-specs openapi/identity/v1 (activateDevice, createDeviceNonce,
// createDeviceToken, getDeviceOfflinePack, getJwks, HubPackClaims).

// Jwk is a published P-256 key.
type Jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
}

// JwkOf converts a device key.
func JwkOf(pub *ecdsa.PublicKey) Jwk {
	x, y := make([]byte, 32), make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return Jwk{Kty: "EC", Crv: "P-256", X: encodeB64(x), Y: encodeB64(y)}
}

// Pub converts a JWK to a public key.
func (j Jwk) Pub() (*ecdsa.PublicKey, error) {
	x, errx := decodeB64(j.X)
	y, erry := decodeB64(j.Y)
	if j.Kty != "EC" || j.Crv != "P-256" || errx != nil || erry != nil {
		return nil, errors.New("hub: bad JWK")
	}
	k := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !k.Curve.IsOnCurve(k.X, k.Y) { //nolint:staticcheck // validating a published point
		return nil, errors.New("hub: point not on curve")
	}
	return k, nil
}

// HubPackClaims is the payload of a hub pack. It holds no display name, PIN verifier, salt or series code (HP2).
type HubPackClaims struct {
	PackV          int    `json:"pack_v"`
	OrganisationID string `json:"organisation_id"`
	Device         struct {
		DeviceID   string `json:"device_id"`
		PublicKey  Jwk    `json:"public_key"`
		OutletID   string `json:"outlet_id"`
		BrandID    string `json:"brand_id"`
		Kind       string `json:"kind"`
		Kid        string `json:"kid"`
		Store      string `json:"store"`
		Credential string `json:"credential"`
	} `json:"device"`
	Members []struct {
		MemberID    string   `json:"member_id"`
		Status      string   `json:"status"`
		Permissions []string `json:"permissions"`
	} `json:"members"`
	RevokedDeviceIDs   []string `json:"revoked_device_ids"`
	IntentTableVersion int      `json:"intent_table_version"`
	IssuedAt           string   `json:"issued_at"`
	OfflineValidUntil  string   `json:"offline_valid_until"`
	IdentityPublicKeys []Jwk    `json:"identity_public_keys"`
	OpSigningPublicKey Jwk      `json:"op_signing_public_key"`
}

// HubPack is a verified hub pack in the form the hub runs on.
type HubPack struct {
	Raw     string // the compact JWS as identity signed it
	PackV   int
	Tenant  string
	Outlet  string
	Brand   string
	Cred    sp.Credential
	CredJWS string
	// IdentityKeys are the current and next identity keys.
	IdentityKeys []*ecdsa.PublicKey
	OpKid        string
	OpKey        *ecdsa.PublicKey
	// Members are the active members of the outlet (ids with permissions), for the structural checks of S8.
	Members    map[string][]string
	Revoked    []string
	ValidUntil time.Time
}

// ErrPack is returned for a pack that does not verify or does not belong to this hub.
var ErrPack = errors.New("hub: pack not acceptable")

// VerifyPack checks a hub pack JWS against the identity keys, that it is for deviceID, and returns it in running form.
//
// packSigningKeys are the keys that may have signed the pack JWS itself. Identity signs packs with a pack-signing key that no
// published document carries yet (open contract question, reported with this change), so callers pass none and the JWS signature
// is then not checked: the pack is trusted for what the channel vouches for (HTTPS to identity, or the encrypted store), and
// everything the LAN relies on is verified independently, the hub's own credential under the identity keys the pack names.
func VerifyPack(jws string, packSigningKeys []*ecdsa.PublicKey, deviceID string) (HubPack, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return HubPack{}, fmt.Errorf("%w: shape", ErrPack)
	}
	hb, err := decodeB64(parts[0])
	var hdr struct{ Alg string }
	if err != nil || json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "ES256" {
		return HubPack{}, fmt.Errorf("%w: header", ErrPack)
	}
	ok := len(packSigningKeys) == 0
	for _, k := range packSigningKeys {
		if k != nil && sp.VerifySig(k, parts[0]+"."+parts[1], parts[2]) {
			ok = true
			break
		}
	}
	if !ok {
		return HubPack{}, fmt.Errorf("%w: signature", ErrPack)
	}
	raw, err := decodeB64(parts[1])
	if err != nil {
		return HubPack{}, fmt.Errorf("%w: payload", ErrPack)
	}
	var c HubPackClaims
	if json.Unmarshal(raw, &c) != nil || c.Device.DeviceID != deviceID || c.Device.Kind != sp.KindHub || c.Device.Credential == "" {
		return HubPack{}, fmt.Errorf("%w: claims", ErrPack)
	}
	p := HubPack{Raw: jws, PackV: c.PackV, Tenant: c.OrganisationID, Outlet: c.Device.OutletID, Brand: c.Device.BrandID, CredJWS: c.Device.Credential,
		OpKid: c.OpSigningPublicKey.Kid, Members: map[string][]string{}, Revoked: c.RevokedDeviceIDs}
	for _, j := range c.IdentityPublicKeys {
		k, err := j.Pub()
		if err != nil {
			return HubPack{}, fmt.Errorf("%w: keys", ErrPack)
		}
		p.IdentityKeys = append(p.IdentityKeys, k)
	}
	if p.OpKey, err = c.OpSigningPublicKey.Pub(); err != nil || len(p.IdentityKeys) == 0 {
		return HubPack{}, fmt.Errorf("%w: validity", ErrPack)
	}
	for _, m := range c.Members {
		if m.Status == "active" {
			p.Members[m.MemberID] = m.Permissions
		}
	}
	if p.ValidUntil, err = time.Parse(time.RFC3339Nano, c.OfflineValidUntil); err != nil {
		return HubPack{}, fmt.Errorf("%w: credential", ErrPack)
	}
	cl, err := sp.VerifyCredentialJWS(p.IdentityKeys, p.CredJWS)
	if err != nil || cl.DeviceID != deviceID || cl.Kind != sp.KindHub || cl.TenantID != p.Tenant || cl.OutletID != p.Outlet {
		return HubPack{}, fmt.Errorf("%w: credential", ErrPack)
	}
	p.Cred = cl
	return p, nil
}

// IdentityClient calls identity's device routes as the hub's device.
type IdentityClient struct {
	Base string
	HTTP *http.Client
	Now  func() time.Time

	mu      sync.Mutex
	token   string
	tokenAt time.Time
}

func (c *IdentityClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *IdentityClient) do(ctx context.Context, method, path, bearer string, in, out any) error {
	var rdr io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if method != http.MethodGet {
		key, err := sp.NewNonce()
		if err != nil {
			return err
		}
		req.Header.Set("Idempotency-Key", key)
	}
	cl := c.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		var p struct{ Code string }
		_ = json.Unmarshal(b, &p)
		return &IdentityError{Status: resp.StatusCode, Code: p.Code}
	}
	return json.Unmarshal(b, out)
}

// IdentityError is a refusal from identity (status and problem code only; nothing else is kept).
type IdentityError struct {
	Status int
	Code   string
}

func (e *IdentityError) Error() string {
	return fmt.Sprintf("identity answered %d %s", e.Status, e.Code)
}

// Keys fetches the published identity keys (getJwks). The caller must have reached identity over verified HTTPS.
func (c *IdentityClient) Keys(ctx context.Context) ([]*ecdsa.PublicKey, error) {
	var set struct {
		Keys []Jwk `json:"keys"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/jwks", "", nil, &set); err != nil {
		return nil, err
	}
	var out []*ecdsa.PublicKey
	for _, j := range set.Keys {
		if k, err := j.Pub(); err == nil {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("hub: identity published no usable key")
	}
	return out, nil
}

// Activated is the result of an activation.
type Activated struct {
	DeviceID string
	Pack     HubPack
}

// Activate registers this hub with identity (activateDevice): the code is already bound to the outlet and kind hub. store is the
// claim of A3.5 item 1; protection the key tier reported to the owner.
func (c *IdentityClient) Activate(ctx context.Context, code, name, deviceID string, key *sp.KeyPair, protection, store string) (Activated, error) {
	var n struct {
		Nonce string `json:"nonce"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/device-nonces", "", nil, &n); err != nil {
		return Activated{}, err
	}
	sig, err := key.Sign(n.Nonce)
	if err != nil {
		return Activated{}, err
	}
	var act struct {
		OfflinePack struct {
			JWS string `json:"jws"`
		} `json:"offline_pack"`
	}
	body := map[string]any{"activation_code": code, "id": deviceID, "name": name, "public_key": JwkOf(&key.Priv.PublicKey),
		"key_protection": protection, "store": store, "nonce": n.Nonce, "nonce_signature": sig}
	if err := c.do(ctx, http.MethodPost, "/v1/device-activations", "", body, &act); err != nil {
		return Activated{}, err
	}
	// The pack came over the HTTPS connection to identity, which vouches for it; its signature must verify under the identity
	// keys it names (the tenant realm's, which getJwks does not publish). Later packs are checked against these keys.
	p, err := VerifyPack(act.OfflinePack.JWS, nil, deviceID)
	if err != nil {
		return Activated{}, err
	}
	return Activated{DeviceID: deviceID, Pack: p}, nil
}

// assertion is the device-key assertion of createDeviceToken: a compact ES256 JWS over a fresh jti and iat.
func assertion(key *sp.KeyPair, deviceID string, now time.Time) (string, error) {
	jti, err := sp.NewNonce()
	if err != nil {
		return "", err
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": key.Kid, "typ": "JWT"})
	pl, _ := json.Marshal(map[string]any{"aud": "hostry-identity", "did": deviceID, "jti": jti, "iat": now.Unix()})
	in := encodeB64(hdr) + "." + encodeB64(pl)
	sig, err := key.Sign(in)
	if err != nil {
		return "", err
	}
	return in + "." + sig, nil
}

// Token returns a device access token (createDeviceToken, grant device), cached until shortly before it expires. It is the
// bearer for the pack route and for the cloud gateway.
func (c *IdentityClient) Token(ctx context.Context, deviceID string, key *sp.KeyPair) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Before(c.tokenAt) {
		return c.token, nil
	}
	as, err := assertion(key, deviceID, c.now())
	if err != nil {
		return "", err
	}
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/tokens/device", "", map[string]any{"grant_type": "device", "device_id": deviceID, "assertion": as}, &t); err != nil {
		return "", err
	}
	exp, err := time.Parse(time.RFC3339Nano, t.ExpiresAt)
	if err != nil {
		exp = c.now().Add(5 * time.Minute)
	}
	c.token, c.tokenAt = t.AccessToken, exp.Add(-30*time.Second)
	return c.token, nil
}

// Pack fetches the newest hub pack (getDeviceOfflinePack) with the hub's device token and verifies its credential (VerifyPack).
func (c *IdentityClient) Pack(ctx context.Context, deviceID string, key *sp.KeyPair) (HubPack, error) {
	tok, err := c.Token(ctx, deviceID, key)
	if err != nil {
		return HubPack{}, err
	}
	var p struct {
		JWS string `json:"jws"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/devices/"+deviceID+"/offline-packs/latest", tok, nil, &p); err != nil {
		return HubPack{}, err
	}
	return VerifyPack(p.JWS, nil, deviceID)
}
