package syncproto

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPIICommitmentsRoundTripAndDropTampering(t *testing.T) {
	values := PII{"check": {"c1": {"customer_phone": "+910000000000", "customer_name": "Asha", "age_band": int64(3)}}}
	wire, commits, err := CommitPII(values, bytes.NewReader(bytes.Repeat([]byte{7, 9, 11, 13}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenPII(wire, commits)
	if err != nil || o.Dropped != 0 || o.Values["check"]["c1"]["customer_phone"] != "+910000000000" || o.Values["check"]["c1"]["age_band"] != int64(3) {
		t.Fatalf("round trip: %+v %v", o, err)
	}
	// A changed value, a missing salt and a field with no commitment are all dropped, never kept.
	var m map[string]map[string]map[string]any
	_ = json.Unmarshal(wire, &m)
	m["check"]["c1"]["customer_phone"] = "+911111111111"
	delete(m["check"]["c1"], "~s:customer_name")
	m["check"]["c1"]["extra"] = "x"
	bad, _ := json.Marshal(m)
	o, err = OpenPII(bad, commits)
	if err != nil || o.Dropped != 3 || o.Values["check"]["c1"]["age_band"] != int64(3) || len(o.Values["check"]["c1"]) != 1 {
		t.Fatalf("tampered: %+v %v", o, err)
	}
}

// The commitment is not a plain hash of the value: the same value commits differently under each salt, so a
// phone number cannot be guessed back from the sealed body (security ruling), and the body names no value.
func TestPIICommitmentIsSaltedAndHidesTheValue(t *testing.T) {
	v := PII{"check": {"c1": {"customer_phone": "+910000000000"}}}
	_, c1, _ := CommitPII(v, nil)
	_, c2, _ := CommitPII(v, nil)
	if c1["check"]["c1"]["customer_phone"] == c2["check"]["c1"]["customer_phone"] {
		t.Fatal("two commitments of one value are equal: no salt")
	}
	plain := Hash(`"+910000000000"`)
	if c1["check"]["c1"]["customer_phone"] == plain {
		t.Fatal("commitment is the plain hash of the value")
	}
	b := Body{PIIC: c1}
	txt, _ := EncodeBody(b)
	if strings.Contains(txt, "9100000") {
		t.Fatal("the sealed body carries the value")
	}
}

func TestStripSaltsLeavesValuesOnly(t *testing.T) {
	wire, _, _ := CommitPII(PII{"check": {"c1": {"customer_name": "Asha"}}}, nil)
	out, err := StripSalts(wire)
	if err != nil || string(out) != `{"check":{"c1":{"customer_name":"Asha"}}}` {
		t.Fatalf("%s %v", out, err)
	}
}
