package syncproto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/hostryhq/svc-sync/contract/specs"
)

type a3Vectors struct {
	ApprovalProof struct {
		ProofKey string `json:"proof_key"`
		Cases    []struct {
			Case       string `json:"case"`
			Kind       string `json:"kind"`
			Message    string `json:"message"`
			Proof      string `json:"proof"`
			ActionHash string `json:"action_hash"`
			DeviceID   string `json:"device_id"`
			MemberID   string `json:"member_id"`
			PackV      int    `json:"pack_v"`
			PinV       int    `json:"pin_v"`
			ApprovalID string `json:"approval_id"`
			Permission string `json:"permission"`
			Target     string `json:"target"`
			Requester  string `json:"requester_id"`
			ApprovedAt string `json:"approved_at"`
			Reason     string `json:"reason"`
			SessionID  string `json:"session_id"`
			OpenedAt   string `json:"opened_at"`
		} `json:"cases"`
	} `json:"approval_proof"`
	ActionHash []struct {
		Case            string         `json:"case"`
		Intent          string         `json:"intent"`
		Permission      string         `json:"permission"`
		Requester       string         `json:"requester"`
		Target          string         `json:"target"`
		ApprovalID      string         `json:"approval_id"`
		Reason          string         `json:"reason"`
		Values          map[string]any `json:"values"`
		JCS             string         `json:"jcs"`
		ActionHash      string         `json:"action_hash"`
		ApprovedHash    string         `json:"approved_action_hash"`
		MatchesApproved *bool          `json:"matches_approved"`
	} `json:"action_hash"`
	DigestRow []struct {
		Case        string            `json:"case"`
		ID          string            `json:"id"`
		PIIFields   []string          `json:"pii_fields"`
		Fields      map[string]any    `json:"fields"`
		PIIValues   map[string]any    `json:"pii_values"`
		Commitments map[string]string `json:"commitments"`
		RowText     string            `json:"row_text"`
	} `json:"digest_row"`
	PIIPlacement struct {
		Cases []struct {
			Kind      string `json:"kind"`
			PIIServed bool   `json:"pii_served"`
		} `json:"cases"`
	} `json:"pii_placement"`
}

func loadA3(t *testing.T) a3Vectors {
	t.Helper()
	p, err := specs.Path("sync", "conformance", "v1.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v a3Vectors
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestPIIPlacementVectors(t *testing.T) {
	v := loadA3(t)
	if len(v.PIIPlacement.Cases) < 5 {
		t.Fatal("pii_placement vectors are required (ADR-0014 A3.1)")
	}
	for _, c := range v.PIIPlacement.Cases {
		if ServesPII(c.Kind) != c.PIIServed {
			t.Errorf("kind %s: ServesPII=%v, vector says %v", c.Kind, !c.PIIServed, c.PIIServed)
		}
	}
}

func TestActionHashVectors(t *testing.T) {
	v := loadA3(t)
	if len(v.ActionHash) < 6 {
		t.Fatal("action_hash vectors are required (ADR-0014 A3.3)")
	}
	for _, c := range v.ActionHash {
		got, err := ActionHash(c.Intent, c.Permission, c.Requester, c.Target, c.ApprovalID, c.Reason, c.Values)
		if err != nil || got != c.ActionHash {
			t.Errorf("%s: action hash %s (%v), vector %s", c.Case, got, err, c.ActionHash)
		}
		if c.MatchesApproved != nil && !*c.MatchesApproved && got == c.ApprovedHash {
			t.Errorf("%s: another amount must give another hash", c.Case)
		}
	}
}

func TestApprovalProofVectors(t *testing.T) {
	v := loadA3(t)
	key, err := base64.RawURLEncoding.DecodeString(v.ApprovalProof.ProofKey)
	if err != nil || len(v.ApprovalProof.Cases) < 5 {
		t.Fatalf("approval_proof vectors are required (%v)", err)
	}
	for _, c := range v.ApprovalProof.Cases {
		msg := ""
		switch c.Kind {
		case "session":
			msg = SessionProofMessage(c.SessionID, c.DeviceID, c.MemberID, c.PackV, c.PinV, c.OpenedAt)
		default:
			msg = ApprovalProofMessage(c.ActionHash, c.DeviceID, c.MemberID, c.PackV, c.PinV, c.ApprovalID, c.Permission, c.Target, c.Requester, c.ApprovedAt, c.Reason)
		}
		if msg != c.Message {
			t.Errorf("%s: message %q, vector %q", c.Case, msg, c.Message)
		}
		if p := ProofMAC(key, msg); p != c.Proof {
			t.Errorf("%s: proof %s, vector %s", c.Case, p, c.Proof)
		}
	}
}

func TestDigestRowVectors(t *testing.T) {
	v := loadA3(t)
	if len(v.DigestRow) < 3 {
		t.Fatal("digest_row vectors are required (ADR-0014 A3.2)")
	}
	for _, c := range v.DigestRow {
		pii := map[string]bool{}
		for _, f := range c.PIIFields {
			pii[f] = true
		}
		withValues := map[string]any{}
		for k, x := range c.Fields {
			withValues[k] = x
		}
		for k, x := range c.PIIValues {
			withValues[k] = x
		}
		for name, fields := range map[string]map[string]any{"holding the values": withValues, "holding none": c.Fields} {
			got, err := RowText(c.ID, fields, pii, c.Commitments)
			if err != nil || got != c.RowText {
				t.Errorf("%s %s: %s (%v), vector %s", c.Case, name, got, err, c.RowText)
			}
		}
	}
}
