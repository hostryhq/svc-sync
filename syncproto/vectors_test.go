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
	HLC []struct {
		Ms      int64
		Counter uint16
		Hex     string
	} `json:"hlc"`
}

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
