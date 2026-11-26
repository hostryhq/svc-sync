package syncproto

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/hostryhq/svc-sync/contract/specs"
)

// The shared conformance vectors live in api-specs (sync/conformance/v1.json, ADR-0002 S15) and are
// run here against this implementation; the same file is run by go-common and client-core.
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
	SizeLimit []struct {
		Field string
		Bytes int
		Valid bool
	} `json:"size_limit"`
	EmitBatch []struct {
		Ops   int
		Valid bool
	} `json:"emit_batch"`
	DrainStatement []struct {
		Case, Pub     string
		Statement     DrainStatement
		SignedMessage string `json:"signed_message"`
		StatementJCS  string `json:"statement_jcs"`
		StatementHash string `json:"statement_hash"`
		SigValid      bool   `json:"sig_valid"`
	} `json:"drain_statement"`
	ExamplePack map[string]string `json:"example_pack"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	p, err := specs.Path("sync", "conformance", "v1.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestConformanceVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.Canonical) == 0 || len(v.SizeLimit) < 4 || len(v.EmitBatch) < 4 {
		t.Fatal("the vector file lacks canonical, size_limit or emit_batch cases")
	}
	for _, c := range v.Canonical {
		got, err := Canonicalize([]byte(c.In))
		if err != nil || string(got) != c.Out {
			t.Errorf("canonical %q: got %q (%v), want %q", c.In, got, err, c.Out)
		}
	}
	for _, c := range v.Hash {
		if got := Hash(c.Body); got != c.H {
			t.Errorf("hash %q: %s want %s", c.Body, got, c.H)
		}
	}
	for _, c := range v.Genesis {
		if got := GenesisHash(c.Origin, c.Stream); got != c.H {
			t.Errorf("genesis %s/%s: %s want %s", c.Origin, c.Stream, got, c.H)
		}
	}
	for _, c := range v.SealMessage {
		if got := SealMessage(c.Origin, c.Stream, c.Seq, c.H); got != c.Message {
			t.Errorf("seal message %q want %q", got, c.Message)
		}
	}
	for _, c := range v.EndorseMessage {
		if got := EndorseMessage(c.Origin, c.Stream, c.Seq, c.H, c.Rec); got != c.Message {
			t.Errorf("endorse message %q want %q", got, c.Message)
		}
	}
	for _, c := range v.AttestMessage {
		a := Attestation{Origin: c.Origin, Stream: c.Stream, Seq: c.Seq, H: c.H, By: c.By, Rec: c.Rec}
		if got := AttestationMessage(a); got != c.Message {
			t.Errorf("attest message %q want %q", got, c.Message)
		}
	}
	for _, c := range v.EndorseVerify {
		pub, err := DecodePub(c.Pub)
		if err != nil {
			t.Fatal(err)
		}
		e := Endorsement{Origin: c.Origin, Stream: c.Stream, Seq: c.Seq, H: c.H, Rec: c.Rec, Kid: c.Kid, Sig: c.Sig}
		if got := e.Verify(pub); got != c.Valid {
			t.Errorf("endorsement case %q: valid=%v want %v", c.Case, got, c.Valid)
		}
	}
	for _, c := range v.HLC {
		if got := MakeHLC(c.Ms, c.Counter).String(); got != c.Hex {
			t.Errorf("hlc %d/%d: %s want %s", c.Ms, c.Counter, got, c.Hex)
		}
	}
	for _, c := range v.SizeLimit {
		body, pii := 0, 0
		if c.Field == "body" {
			body = c.Bytes
		} else {
			pii = c.Bytes
		}
		if got := CheckSize(body, pii) == nil; got != c.Valid {
			t.Errorf("size %s %d bytes: valid=%v want %v", c.Field, c.Bytes, got, c.Valid)
		}
	}
	for _, c := range v.EmitBatch {
		if got := c.Ops >= MinEmitOps && c.Ops <= MaxEmitOps; got != c.Valid {
			t.Errorf("emit batch %d: valid=%v want %v", c.Ops, got, c.Valid)
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

func TestDrainStatementVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.DrainStatement) < 3 {
		t.Fatal("drain_statement vectors are required (ADR-0005 A3.3)")
	}
	for _, c := range v.DrainStatement {
		msg, err := c.Statement.SignedMessage()
		if err != nil || msg != c.SignedMessage {
			t.Errorf("%s: signed message %q (%v), vector %q", c.Case, msg, err, c.SignedMessage)
		}
		pub, err := DecodePub(c.Pub)
		if err != nil {
			t.Fatalf("%s: %v", c.Case, err)
		}
		if got := c.Statement.Verify(pub); got != c.SigValid {
			t.Errorf("%s: signature valid=%v, vector says %v", c.Case, got, c.SigValid)
		}
		raw, err := drainJCS(c.Statement, true)
		if err != nil || string(raw) != c.StatementJCS {
			t.Errorf("%s: JCS with sig differs from the vector (%v)", c.Case, err)
		}
		if h, err := c.Statement.Hash(); err != nil || h != c.StatementHash {
			t.Errorf("%s: statement_hash %s (%v), vector %s", c.Case, h, err, c.StatementHash)
		}
	}
}
