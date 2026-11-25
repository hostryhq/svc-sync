package syncproto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// The LAN handshake of ADR-0002 A3.1 (sync/protocol-v1.md, "LAN handshake"; vectors lan_handshake). A device and a hub prove
// themselves to each other over a TLS 1.3 channel whose certificate nobody checks, binding both proofs to that certificate's
// key hash (`spki`), then the hub hands out a 15-minute session token.
const (
	// HeaderLanSession carries the LAN session token on every call after the handshake.
	HeaderLanSession = "Hostry-Lan-Session"
	// LanSessionTTLSeconds is the life of a LAN session token.
	LanSessionTTLSeconds = 900
	// LanTagHub and LanTagDevice are the final v1 domain tags of the two proofs.
	LanTagHub    = "hostry-lan-hub-v1"
	LanTagDevice = "hostry-lan-device-v1"
	// CredJWSType is the `typ` header of a LAN credential.
	CredJWSType = "hostry-cred+jws"
)

// Problem codes of the LAN handshake.
const (
	CodeLanSessionExpired    = "lan_session_expired"
	CodeLanCredentialRefused = "lan_credential_refused"
	CodeLanProofInvalid      = "lan_proof_invalid"
)

// LanHelloRequest is helloLan from the device.
type LanHelloRequest struct {
	Credential string `json:"credential"`
	NonceD     string `json:"nonce_d"`
}

// LanHelloResponse is the hub's answer to helloLan.
type LanHelloResponse struct {
	Credential string `json:"credential"`
	NonceH     string `json:"nonce_h"`
	HubProof   string `json:"hub_proof"`
}

// LanSessionRequest is openLanSession from the device.
type LanSessionRequest struct {
	NonceD      string `json:"nonce_d"`
	NonceH      string `json:"nonce_h"`
	DeviceProof string `json:"device_proof"`
}

// LanSession is the hub's answer to openLanSession.
type LanSession struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

// NewNonce returns 32 random bytes, base64url without padding (43 characters).
func NewNonce() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return b64.EncodeToString(b[:]), nil
}

// ValidNonce reports whether s is a 43-character base64url nonce or token of 32 bytes.
func ValidNonce(s string) bool {
	raw, err := b64.DecodeString(s)
	return err == nil && len(raw) == 32 && len(s) == 43
}

// SPKIOf is the lower-case hex SHA-256 of a certificate's DER SubjectPublicKeyInfo.
func SPKIOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// LanProofMessage is the text each side signs: the domain tag (LanTagHub or LanTagDevice), both nonces, both device ids and
// the spki, joined by newlines.
func LanProofMessage(tag, nonceD, nonceH, deviceID, hubID, spki string) string {
	return strings.Join([]string{tag, nonceD, nonceH, deviceID, hubID, spki}, "\n")
}

// SignCredentialJWS has identity issue the LAN credential of c: a compact ES256 JWS, header {alg, kid, typ}, payload the
// RFC 8785 JSON of the credential.
func SignCredentialJWS(identity *KeyPair, c Credential) (string, error) {
	hdr, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}{"ES256", identity.Kid, CredJWSType})
	if err != nil {
		return "", err
	}
	pl, err := CanonicalJSON(c)
	if err != nil {
		return "", err
	}
	in := b64.EncodeToString(hdr) + "." + b64.EncodeToString(pl)
	sig, err := identity.Sign(in)
	if err != nil {
		return "", err
	}
	return in + "." + sig, nil
}

// ErrCredentialJWS is returned for a LAN credential that does not verify.
var ErrCredentialJWS = errors.New("syncproto: LAN credential not acceptable")

// VerifyCredentialJWS checks a LAN credential against the identity keys of the node's own pack (current or next) and returns
// its claims. It judges only the signature and the shape; tenant, outlet, kind, expiry and revocation are the caller's.
func VerifyCredentialJWS(keys []*ecdsa.PublicKey, jws string) (Credential, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return Credential{}, ErrCredentialJWS
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return Credential{}, ErrCredentialJWS
	}
	var hdr struct{ Alg, Typ string }
	if json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "ES256" || hdr.Typ != CredJWSType {
		return Credential{}, ErrCredentialJWS
	}
	ok := false
	for _, k := range keys {
		if k != nil && VerifySig(k, parts[0]+"."+parts[1], parts[2]) {
			ok = true
			break
		}
	}
	if !ok {
		return Credential{}, ErrCredentialJWS
	}
	pl, err := b64.DecodeString(parts[1])
	if err != nil {
		return Credential{}, ErrCredentialJWS
	}
	var c Credential
	if json.Unmarshal(pl, &c) != nil || c.DeviceID == "" {
		return Credential{}, ErrCredentialJWS
	}
	if _, err := c.PubKey(); err != nil {
		return Credential{}, ErrCredentialJWS
	}
	return c, nil
}
