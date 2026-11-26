package syncproto

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/hostryhq/svc-sync/contract/specs"
)

type lanVec struct {
	Now         int64 `json:"now"`
	IdentityKey struct {
		Pub string `json:"pub"`
	} `json:"identity_key"`
	TLSSPKIDER string `json:"tls_spki_der"`
	SPKI       string `json:"spki"`
	NonceD     string `json:"nonce_d"`
	NonceH     string `json:"nonce_h"`
	Hub        struct {
		DeviceID   string `json:"device_id"`
		Credential string `json:"credential"`
	} `json:"hub"`
	Device struct {
		DeviceID   string `json:"device_id"`
		Credential string `json:"credential"`
	} `json:"device"`
	ProofCases []struct {
		Case      string `json:"case"`
		Role      string `json:"role"`
		SignerPub string `json:"signer_pub"`
		Message   string `json:"message"`
		Sig       string `json:"sig"`
		Valid     bool   `json:"valid"`
	} `json:"proof_cases"`
	CredentialCases []struct {
		Case         string  `json:"case"`
		Credential   string  `json:"credential"`
		ExpectKind   string  `json:"expect_kind"`
		ExpectOutlet string  `json:"expect_outlet"`
		Valid        bool    `json:"valid"`
		Reason       *string `json:"reason"`
	} `json:"credential_cases"`
	Session struct {
		TokenCases []struct {
			Token string `json:"token"`
			Valid bool   `json:"valid"`
		} `json:"token_cases"`
	} `json:"session"`
}

func loadLan(t *testing.T) lanVec {
	t.Helper()
	p, err := specs.Path("sync", "conformance", "v1.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		LAN lanVec `json:"lan_handshake"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v.LAN
}

// judge applies the credential checks the vector names, with this package's verifier.
func judge(l lanVec, id *ecdsa.PublicKey, jws, kind, outlet string) string {
	c, err := VerifyCredentialJWS([]*ecdsa.PublicKey{id}, jws)
	switch {
	case err != nil:
		return "signature"
	case c.NotAfter < l.Now:
		return "expired"
	case c.OutletID != outlet:
		return "outlet"
	case c.Kind != kind:
		return "kind"
	}
	return ""
}

// The LAN credential, proof message and session token shapes are the contract's (vectors lan_handshake).
func TestLanHandshakeVectors(t *testing.T) {
	l := loadLan(t)
	id, err := DecodePub(l.IdentityKey.Pub)
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.RawURLEncoding.DecodeString(l.TLSSPKIDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.ProofCases) < 5 || len(l.CredentialCases) < 6 {
		t.Fatal("lan_handshake vectors are required")
	}
	_ = der
	for _, c := range l.ProofCases {
		tag := LanTagDevice
		if c.Role == "hub" {
			tag = LanTagHub
		}
		if c.Valid {
			if want := LanProofMessage(tag, l.NonceD, l.NonceH, l.Device.DeviceID, l.Hub.DeviceID, l.SPKI); c.Message != want {
				t.Errorf("%s: LanProofMessage differs from the vector message", c.Case)
			}
		}
		pub, err := DecodePub(c.SignerPub)
		if err != nil {
			t.Fatal(err)
		}
		if got := VerifySig(pub, c.Message, c.Sig); got != c.Valid {
			t.Errorf("%s: signature valid=%v, vector says %v", c.Case, got, c.Valid)
		}
	}
	for _, c := range l.CredentialCases {
		want := ""
		if c.Reason != nil {
			want = *c.Reason
		}
		if got := judge(l, id, c.Credential, c.ExpectKind, c.ExpectOutlet); got != want || (got == "") != c.Valid {
			t.Errorf("%s: judged %q, vector says valid=%v reason %q", c.Case, got, c.Valid, want)
		}
	}
	for _, c := range l.Session.TokenCases {
		if ValidNonce(c.Token) != c.Valid {
			t.Errorf("token %q: ValidNonce=%v, vector says %v", c.Token, !c.Valid, c.Valid)
		}
	}
	// The vector credentials' payloads are the JCS of the Credential this package signs.
	for _, jws := range []string{l.Hub.Credential, l.Device.Credential} {
		c, err := VerifyCredentialJWS([]*ecdsa.PublicKey{id}, jws)
		if err != nil || c.Store != StoreProtected {
			t.Fatalf("vector credential: %v store %q", err, c.Store)
		}
		raw, _ := CanonicalJSON(c)
		if got := strings.Split(jws, ".")[1]; got != base64.RawURLEncoding.EncodeToString(raw) {
			t.Errorf("payload is not the JCS of the Credential struct (a field is missing or extra)")
		}
	}
}

func TestSignedCredentialJWSRoundTrips(t *testing.T) {
	idk, _ := NewKeyPair("k-test", nil)
	dev, _ := NewKeyPair("dev-1", nil)
	c := Credential{DeviceID: "d1", TenantID: "t", OutletID: "o", BrandID: "b", Kind: KindPOS, Kid: dev.Kid, Pub: dev.PublicB64(), Store: StoreProtected, NotAfter: 99}
	jws, err := SignCredentialJWS(idk, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyCredentialJWS([]*ecdsa.PublicKey{&idk.Priv.PublicKey}, jws)
	if err != nil || got != c {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	other, _ := NewKeyPair("k-other", nil)
	if _, err := VerifyCredentialJWS([]*ecdsa.PublicKey{&other.Priv.PublicKey}, jws); err == nil {
		t.Fatal("a credential signed by another issuer verified")
	}
}
