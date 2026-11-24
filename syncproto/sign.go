package syncproto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
)

var b64 = base64.RawURLEncoding

// KeyPair is an ES256 key. In production a device key is non-exportable and lives in the shell's
// keystore (ADR-0005, ADR-0007); here it is a software key for tests and the simulator.
type KeyPair struct {
	Kid  string
	Priv *ecdsa.PrivateKey
}

// NewKeyPair generates a P-256 key; r may be a seeded reader for deterministic tests.
func NewKeyPair(kid string, r io.Reader) (*KeyPair, error) {
	if r == nil {
		r = rand.Reader
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		return nil, err
	}
	return &KeyPair{Kid: kid, Priv: k}, nil
}

// PublicB64 is the uncompressed X9.62 point, base64url.
func (k *KeyPair) PublicB64() string { return EncodePub(&k.Priv.PublicKey) }

// EncodePub encodes a public key.
func EncodePub(p *ecdsa.PublicKey) string {
	return b64.EncodeToString(elliptic.Marshal(elliptic.P256(), p.X, p.Y)) //nolint:staticcheck // fixed-size point format is the wire format
}

// DecodePub decodes EncodePub output.
func DecodePub(s string) (*ecdsa.PublicKey, error) {
	raw, err := b64.DecodeString(s)
	if err != nil || len(raw) != 65 || raw[0] != 4 {
		return nil, errors.New("syncproto: bad public key")
	}
	x, y := new(big.Int).SetBytes(raw[1:33]), new(big.Int).SetBytes(raw[33:])
	if !elliptic.P256().IsOnCurve(x, y) { //nolint:staticcheck
		return nil, errors.New("syncproto: point not on curve")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// Sign signs msg (ES256, raw r||s, base64url).
func (k *KeyPair) Sign(msg string) (string, error) {
	d := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, k.Priv, d[:])
	if err != nil {
		return "", err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return b64.EncodeToString(out), nil
}

// VerifySig checks an ES256 signature over msg.
func VerifySig(pub *ecdsa.PublicKey, msg, sig string) bool {
	raw, err := b64.DecodeString(sig)
	if err != nil || len(raw) != 64 || pub == nil {
		return false
	}
	d := sha256.Sum256([]byte(msg))
	return ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]))
}

// Seal is the origin's signature over the hash of its op at Seq (S17). One seal covers the
// whole chain up to that op.
type Seal struct {
	Origin string `json:"origin"`
	Stream string `json:"stream"`
	Seq    int64  `json:"seq"`
	H      string `json:"h"`
	Kid    string `json:"kid"`
	Sig    string `json:"sig"`
}

// SealMessage is the signed text.
func SealMessage(origin, stream string, seq int64, h string) string {
	return "hostry-seal-v1\n" + origin + "\n" + stream + "\n" + strconv.FormatInt(seq, 10) + "\n" + h
}

// MakeSeal signs a seal.
func MakeSeal(k *KeyPair, origin, stream string, seq int64, h string) (Seal, error) {
	sig, err := k.Sign(SealMessage(origin, stream, seq, h))
	if err != nil {
		return Seal{}, err
	}
	return Seal{Origin: origin, Stream: stream, Seq: seq, H: h, Kid: k.Kid, Sig: sig}, nil
}

// Verify checks the seal against a public key.
func (s Seal) Verify(pub *ecdsa.PublicKey) bool {
	return VerifySig(pub, SealMessage(s.Origin, s.Stream, s.Seq, s.H), s.Sig)
}

// Attestation fixes the tail of a key-lost origin (A1.3 item 4), signed with the adopting
// device's new key.
type Attestation struct {
	Origin string `json:"origin"`
	Stream string `json:"stream"`
	Seq    int64  `json:"seq"`
	H      string `json:"h"`
	By     string `json:"by"`
	Rec    string `json:"rec"`
	Kid    string `json:"kid"`
	Sig    string `json:"sig"`
}

// AttestationMessage is the signed text.
func AttestationMessage(a Attestation) string {
	return "hostry-attest-v1\n" + a.Origin + "\n" + a.Stream + "\n" + strconv.FormatInt(a.Seq, 10) + "\n" + a.H + "\n" + a.By + "\n" + a.Rec
}

// MakeAttestation signs an attestation.
func MakeAttestation(k *KeyPair, a Attestation) (Attestation, error) {
	a.Kid = k.Kid
	sig, err := k.Sign(AttestationMessage(a))
	if err != nil {
		return a, err
	}
	a.Sig = sig
	return a, nil
}

// Verify checks the attestation against the adopting device's public key.
func (a Attestation) Verify(pub *ecdsa.PublicKey) bool {
	return VerifySig(pub, AttestationMessage(a), a.Sig)
}

// Device kinds.
const (
	KindPOS    = "pos"
	KindWaiter = "waiter"
	KindKDS    = "kds"
	KindHub    = "hub"
)

// Credential is an identity-signed device credential (the part of the offline pack that peers
// use, ADR-0005 section 6): who the device is and which public key it holds.
type Credential struct {
	DeviceID string `json:"device_id"`
	TenantID string `json:"tenant_id"`
	OutletID string `json:"outlet_id"`
	BrandID  string `json:"brand_id,omitempty"`
	Kind     string `json:"kind"`
	Kid      string `json:"kid"`
	Pub      string `json:"pub"`
	// Recovers names the key-lost device this one adopted (A1.3 item 3).
	Recovers string `json:"recovers,omitempty"`
	// NotAfter is Unix seconds; a node with an expired pack is refused on the LAN.
	NotAfter int64 `json:"not_after"`
}

// CredentialEnvelope is a credential with the identity service's signature over its canonical JSON.
type CredentialEnvelope struct {
	Cred Credential `json:"cred"`
	Sig  string     `json:"sig"`
}

// SignCredential has identity sign c.
func SignCredential(identity *KeyPair, c Credential) (CredentialEnvelope, error) {
	raw, err := CanonicalJSON(c)
	if err != nil {
		return CredentialEnvelope{}, err
	}
	sig, err := identity.Sign("hostry-cred-v1\n" + string(raw))
	return CredentialEnvelope{Cred: c, Sig: sig}, err
}

// VerifyCredential checks the identity signature.
func VerifyCredential(identityPub *ecdsa.PublicKey, e CredentialEnvelope) bool {
	raw, err := CanonicalJSON(e.Cred)
	if err != nil {
		return false
	}
	return VerifySig(identityPub, "hostry-cred-v1\n"+string(raw), e.Sig)
}

// PubKey returns the credential's public key.
func (c Credential) PubKey() (*ecdsa.PublicKey, error) { return DecodePub(c.Pub) }

// LAN request authentication (S10): a device presents its credential and signs the request
// with its device key. HeaderAssertion carries it; HeaderHubProof carries the hub's answer.
const (
	HeaderAssertion = "Hostry-Device-Assertion"
	HeaderHubProof  = "Hostry-Hub-Proof"
)

// Assertion is the per-request proof of possession on the LAN.
type Assertion struct {
	Cred CredentialEnvelope `json:"cred"`
	TS   int64              `json:"ts"`
	Sig  string             `json:"sig"`
}

// AssertionMessage is the signed text: method, path, timestamp and body hash.
func AssertionMessage(method, path string, ts int64, body []byte) string {
	return "hostry-lan-v1\n" + method + "\n" + path + "\n" + strconv.FormatInt(ts, 10) + "\n" + Hash(string(body))
}

// Encode serialises the assertion for the header.
func (a Assertion) Encode() (string, error) {
	raw, err := json.Marshal(a)
	return b64.EncodeToString(raw), err
}

// DecodeAssertion parses the header value.
func DecodeAssertion(s string) (Assertion, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return Assertion{}, err
	}
	var a Assertion
	if err := json.Unmarshal(raw, &a); err != nil {
		return Assertion{}, fmt.Errorf("assertion: %w", err)
	}
	return a, nil
}

// HubProof is the hub's signed answer binding its identity to the request it served.
type HubProof struct {
	Cred CredentialEnvelope `json:"cred"`
	Sig  string             `json:"sig"`
}

// HubProofMessage binds the request signature and the response body.
func HubProofMessage(requestSig string, respBody []byte) string {
	return "hostry-hub-v1\n" + requestSig + "\n" + Hash(string(respBody))
}
