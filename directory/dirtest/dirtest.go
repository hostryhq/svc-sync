// Package dirtest is the contract test of the directory's proof check: the stub (identitystub) and
// the real identity client must answer the same. It exists because the gateway's verdicts depend on
// the answer, and the stub once answered `locked` for configuration ops only while real identity
// answers it for every op kind (security final verdict, Phase 1). Run it against the real client
// before the gateway is wired to svc-identity (cmd/gateway).
package dirtest

import (
	"testing"

	"github.com/hostryhq/svc-sync/directory"
)

// Target is a directory under test with the hooks a test needs to drive the failure counter.
type Target struct {
	Dir                   directory.Directory
	Tenant, Device, Actor string
	// Valid returns the proof the device holds for the actor.
	Valid func() string
	// Wrong returns the i-th distinct wrong proof.
	Wrong func(i int) string
}

// Run executes the contract.
func Run(t *testing.T, tg Target) {
	t.Helper()
	check := func(sid, proof string, config bool) directory.ProofResult {
		return tg.Dir.CheckProof(tg.Tenant, tg.Device, tg.Actor, sid, proof, config)
	}
	if got := check("s0", tg.Valid(), false); got != directory.ProofValid {
		t.Fatalf("a valid proof answers valid, got %v", got)
	}
	if got := check("s0", tg.Wrong(0), false); got != directory.ProofInvalid {
		t.Fatalf("a wrong trading proof answers invalid, got %v", got)
	}
	// Distinct wrong proofs lock the pair (5 in 15 minutes).
	for i := 1; i < 6; i++ {
		check("s0", tg.Wrong(i), i%2 == 0)
	}
	for _, config := range []bool{true, false} {
		if got := check("s1", tg.Valid(), config); got != directory.ProofLocked {
			t.Fatalf("a locked pair answers locked for every op kind (config=%v), got %v", config, got)
		}
		if got := check("s1", tg.Wrong(100), config); got != directory.ProofLocked {
			t.Fatalf("a wrong proof on a locked pair still answers locked (config=%v), got %v", config, got)
		}
	}
}
