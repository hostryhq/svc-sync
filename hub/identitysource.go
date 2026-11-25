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
	RevokedDeviceIDs   []string      `json:"revoked_device_ids"`
	IntentTableVersion int           `json:"intent_table_version"`
	IssuedAt           string        `json:"issued_at"`
	OfflineValidUntil  string        `json:"offline_valid_until"`
	IssuerEnv          string        `json:"issuer_env"`
	Peers              []HubPackPeer `json:"peers"`
	IdentityPublicKeys []Jwk         `json:"identity_public_keys"`
	OpSigningPublicKey Jwk           `json:"op_signing_public_key"`
}

// HubPackPeer is a peer device of the hub's outlet as the hub pack lists it (HubPackPeer in api-specs): the same facts as the
// peer's own PackDevice, so tablet-to-tablet relay needs no cloud contact first. It holds no member data.
type HubPackPeer struct {
	DeviceID   string `json:"device_id"`
	Kind       string `json:"kind"`
	Kid        string `json:"kid"`
	PublicKey  Jwk    `json:"public_key"`
	Store      string `json:"store"`
	Credential string `json:"credential"`
}

// PackJWSType is the `typ` header of a pack JWS.
const PackJWSType = "hostry-pack+jws"

// PackPolicy is what this hub build and environment accept of a pack's issuer (the `issuer_env` claim, signed with the pack).
type PackPolicy struct {
	// Env is this hub's HOSTRY_ENV. Live refuses a pack from any other issuer environment.
	Env string
	// DevLAN is true in a binary built with the tag devlan, which refuses a pack from a live issuer.
	DevLAN bool
}

// Accept judges an issuer_env claim: a known value, never a live pack in a devlan build, never a non-live pack in a live hub.
func (p PackPolicy) Accept(issuerEnv string) error {
	switch issuerEnv {
	case "dev", "test", "ci", "live":
	default:
		return fmt.Errorf("%w: issuer_env", ErrPack)
	}
	if p.DevLAN && issuerEnv == "live" {
		return fmt.Errorf("%w: a development build refuses a live pack", ErrPack)
	}
	if p.Env == "live" && issuerEnv != "live" {
		return fmt.Errorf("%w: a live hub refuses a pack from a %s issuer", ErrPack, issuerEnv)
	}
	return nil
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
	IssuerEnv  string
	// Peers are the outlet's other devices as the pack lists them, each credential verified under the identity keys.
	Peers []sp.Credential
}

// ErrPack is returned for a pack that does not verify or does not belong to this hub.
var ErrPack = errors.New("hub: pack not acceptable")

// VerifyPack checks a hub pack JWS and returns it in running form. The whole pack is verified: its header must be ES256 with
// typ hostry-pack+jws, its `kid` must name one of the `identity_public_keys` the pack itself carries, and the signature must
// verify under that key (the pack claims the current and the next identity key, also served by the identity JWKS). The pack is
// for deviceID, its hub credential and every peer credential verify under the same keys, and its issuer_env passes pol.
func VerifyPack(jws, deviceID string, pol PackPolicy) (HubPack, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return HubPack{}, fmt.Errorf("%w: shape", ErrPack)
	}
	hb, err := decodeB64(parts[0])
	var hdr struct{ Alg, Kid, Typ string }
	if err != nil || json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "ES256" || hdr.Typ != PackJWSType || hdr.Kid == "" {
		return HubPack{}, fmt.Errorf("%w: header", ErrPack)
	}
	raw, err := decodeB64(parts[1])
	if err != nil {
		return HubPack{}, fmt.Errorf("%w: payload", ErrPack)
	}
	var c HubPackClaims
	if json.Unmarshal(raw, &c) != nil || c.Device.DeviceID != deviceID || c.Device.Kind != sp.KindHub || c.Device.Credential == "" {
		return HubPack{}, fmt.Errorf("%w: claims", ErrPack)
	}
	var signer *ecdsa.PublicKey
	for _, j := range c.IdentityPublicKeys {
		if j.Kid != hdr.Kid {
			continue
		}
		if k, err := j.Pub(); err == nil {
			signer = k
		}
		break
	}
	if signer == nil || !sp.VerifySig(signer, parts[0]+"."+parts[1], parts[2]) {
		return HubPack{}, fmt.Errorf("%w: signature", ErrPack)
	}
	if err := pol.Accept(c.IssuerEnv); err != nil {
		return HubPack{}, err
	}
	p := HubPack{Raw: jws, PackV: c.PackV, Tenant: c.OrganisationID, Outlet: c.Device.OutletID, Brand: c.Device.BrandID, CredJWS: c.Device.Credential,
		OpKid: c.OpSigningPublicKey.Kid, IssuerEnv: c.IssuerEnv, Members: map[string][]string{}, Revoked: c.RevokedDeviceIDs}
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
	for _, pr := range c.Peers {
		pc, err := sp.VerifyCredentialJWS(p.IdentityKeys, pr.Credential)
		pk, kerr := pr.PublicKey.Pub()
		if err != nil || kerr != nil || pc.DeviceID != pr.DeviceID || pc.Kind != pr.Kind || pc.Kid != pr.Kid || pc.Store != pr.Store ||
			pc.TenantID != p.Tenant || pc.OutletID != p.Outlet || pc.Kind == sp.KindHub || pc.Pub != sp.EncodePub(pk) {
			return HubPack{}, fmt.Errorf("%w: peer", ErrPack)
		}
		p.Peers = append(p.Peers, pc)
	}
	return p, nil
}

// IdentityClient calls identity's device routes as the hub's device.
type IdentityClient struct {
	Base string
	HTTP *http.Client
	Now  func() time.Time
	// Policy is what this build accepts of a pack's issuer_env.
	Policy PackPolicy

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
	p, err := VerifyPack(act.OfflinePack.JWS, deviceID, c.Policy)
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
	return VerifyPack(p.JWS, deviceID, c.Policy)
}
