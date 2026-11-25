package identitystub

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// SR-H5 (re-review): distinct wrong proofs on one session id each count; once locked the right
// proof is answered locked, never valid, for sales and configuration alike.
func TestDistinctWrongProofsOnOneSessionLock(t *testing.T) {
	now := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	id, err := New(func() time.Time { return now }, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		id.CheckProof("t1", "dev", "m1", "sid-1", fmt.Sprintf("wrong-%d", i), true)
	}
	if got := id.CheckProof("t1", "dev", "m1", "sid-1", id.MintProof(ProofQuestion{Kind: "session", Device: "dev", Member: "m1", SID: "sid-1"}), true); got != ProofLocked {
		t.Fatalf("right proof after 50 distinct wrong ones = %v, want locked", got)
	}
}

func TestIdenticalWrongProofRetryCountsOnce(t *testing.T) {
	now := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	id, _ := New(func() time.Time { return now }, rand.Reader)
	for i := 0; i < 20; i++ {
		id.CheckProof("t1", "d", "m1", "sid-1", "same-wrong", true)
	}
	if n := id.Failures("t1", "m1", "d"); n != 1 {
		t.Fatalf("failures = %d, want 1", n)
	}
}
