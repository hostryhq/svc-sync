package syncproto

import (
	"encoding/json"
	"os"
	"testing"
)

// The golden vectors in contract/vectors are the shared conformance data for every implementation
// of Sync Protocol v1 (Go here, TypeScript in client-core). Regenerate with SYNC_UPDATE_VECTORS=1.
type vectorFile struct {
	Canonical []struct {
		In, Out string
	} `json:"canonical"`
	Hash []struct {
		Body, H string
	} `json:"hash"`
	Genesis []struct {
		Origin, Stream, H string
	} `json:"genesis"`
	SealMessage []struct {
		Origin, Stream string
		Seq            int64
		H, Message     string
	} `json:"seal_message"`
	EndorseMessage []struct {
		Origin, Stream  string
		Seq             int64
		H, Rec, Message string
	} `json:"endorse_message"`
	AttestMessage []struct {
		Origin, Stream      string
		Seq                 int64
		H, By, Rec, Message string
	} `json:"attest_message"`
	// EndorseVerify: Valid is what a conforming verifier answers for the endorsement under Pub.
	EndorseVerify []struct {
		Case, Pub, Origin, Stream string
		Seq                       int64
		H, Rec, Kid, Sig          string
		Valid                     bool
	} `json:"endorse_verify"`
	HLC []struct {
		Ms      int64
		Counter uint16
		Hex     string
	} `json:"hlc"`
}

// Fixed signed examples (ES256 is randomised, so they are constants): an op-signing key, its
// signature over EndorseMessage and over the seal message of the same fields.
const (
	vecOpPub      = "BOLI_Yh8Lf-I2q3k5a-Wy_qIWWENpyprT7vOic-59ecsNzmvrxu6gNGfVU_8JWxHt8ep-v_qHuUStn5jSFzxjck"
	vecEndorseSig = "SDnPSTTpcZEnKfi60KnAKUgEhrBOvoWG4n-jQVOMGHuT6IPDFXl-JNmSbTSbi7KFho4wE3U2OfZRpbRY9XDvKw"
	vecSealSig    = "ScPMPCEs8sh6fUtAmfwofFU7Ydwh0rHC5uN1Dxf2up-Mj84Ty6YuI49uiecVG55fSPeweb39t0fStaW73SrYjg"
)

const vectorPath = "../contract/vectors/v1.json"

func buildVectors() vectorFile {
	var v vectorFile
	for _, in := range []string{
		`{"b":1,"a":[3,2,{"z":true,"y":null}],"c":"x"}`,
		`{"é":1,"e":2,"éx":3}`,
		"{\"s\":\"tab\\there \\u0001 \\\"q\\\" \\\\ é 中\"}",
		`{"n":-0,"m":9007199254740991,"k":[ ]}`,
		`{"emoji":"😀","😀":1,"￿":2}`,
	} {
		out, err := Canonicalize([]byte(in))
		if err != nil {
			panic(err)
		}
		v.Canonical = append(v.Canonical, struct{ In, Out string }{in, string(out)})
	}
	for _, b := range []string{`{"v":1}`, `{"a":"é"}`} {
		v.Hash = append(v.Hash, struct{ Body, H string }{b, Hash(b)})
	}
	v.Genesis = append(v.Genesis, struct{ Origin, Stream, H string }{"dev-a", "outlet:o1", GenesisHash("dev-a", "outlet:o1")})
	v.SealMessage = append(v.SealMessage, struct {
		Origin, Stream string
		Seq            int64
		H, Message     string
	}{"dev-a", "outlet:o1", 7, Hash("x"), SealMessage("dev-a", "outlet:o1", 7, Hash("x"))})
	v.EndorseMessage = append(v.EndorseMessage, struct {
		Origin, Stream  string
		Seq             int64
		H, Rec, Message string
	}{"dev-a", "outlet:o1", 7, Hash("x"), "rec-1", EndorseMessage("dev-a", "outlet:o1", 7, Hash("x"), "rec-1")})
	at := Attestation{Origin: "dev-a", Stream: "outlet:o1", Seq: 9, H: Hash("y"), By: "dev-a-r1", Rec: "rec-1"}
	v.AttestMessage = append(v.AttestMessage, struct {
		Origin, Stream      string
		Seq                 int64
		H, By, Rec, Message string
	}{at.Origin, at.Stream, at.Seq, at.H, at.By, at.Rec, AttestationMessage(at)})
	pub, _ := DecodePub(vecOpPub)
	for _, c := range []struct {
		name, rec, sig string
		seq            int64
	}{
		{"valid endorsement", "rec-1", vecEndorseSig, 7},
		{"different rec", "rec-2", vecEndorseSig, 7},
		{"different seq", "rec-1", vecEndorseSig, 8},
		{"seal-tag signature over the same fields is not an endorsement", "rec-1", vecSealSig, 7},
	} {
		e := Endorsement{Origin: "dev-a", Stream: "outlet:o1", Seq: c.seq, H: Hash("x"), Rec: c.rec, Kid: "gateway-op-1", Sig: c.sig}
		v.EndorseVerify = append(v.EndorseVerify, struct {
			Case, Pub, Origin, Stream string
			Seq                       int64
			H, Rec, Kid, Sig          string
			Valid                     bool
		}{c.name, vecOpPub, e.Origin, e.Stream, e.Seq, e.H, e.Rec, e.Kid, e.Sig, e.Verify(pub)})
	}
	for _, c := range []struct {
		ms int64
		c  uint16
	}{{1795000000000, 0}, {1795000000000, 65535}, {0, 1}} {
		v.HLC = append(v.HLC, struct {
			Ms      int64
			Counter uint16
			Hex     string
		}{c.ms, c.c, MakeHLC(c.ms, c.c).String()})
	}
	return v
}

func TestGoldenVectors(t *testing.T) {
	want := buildVectors()
	if os.Getenv("SYNC_UPDATE_VECTORS") == "1" {
		raw, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile(vectorPath, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var got vectorFile
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Fatalf("vectors file is out of date; run with SYNC_UPDATE_VECTORS=1\n%s\n%s", a, b)
	}
	// Canonical output must be a fixed point.
	for _, c := range got.Canonical {
		again, err := Canonicalize([]byte(c.Out))
		if err != nil || string(again) != c.Out {
			t.Fatalf("not idempotent: %q", c.Out)
		}
	}
}

func TestCanonicalRejectsFractionsAndExponents(t *testing.T) {
	for _, in := range []string{`{"a":1.5}`, `{"a":1e3}`, `{"a":9007199254740993}`} {
		if _, err := Canonicalize([]byte(in)); err == nil {
			t.Fatalf("%s must be refused (integer-only subset)", in)
		}
	}
}

func TestEndorsementVectorsHaveTheExpectedVerdicts(t *testing.T) {
	want := []bool{true, false, false, false}
	for i, c := range buildVectors().EndorseVerify {
		if c.Valid != want[i] {
			t.Fatalf("%s: valid=%v want %v", c.Case, c.Valid, want[i])
		}
	}
}
