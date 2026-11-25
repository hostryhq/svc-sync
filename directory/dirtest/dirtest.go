// Package dirtest is the contract test of the directory's proof check: the stub (identitystub) and
// the real identity client must answer the same. It exists because the gateway's verdicts depend on
// the answer, and the stub once answered `locked` for configuration ops only while real identity
// answers it for every op kind (security final verdict, Phase 1). It runs against the stub
// (identitystub/locked_test.go) and against the real identity service through identityclient
// (identityreal, a module of its own so that svc-identity stays out of this module's graph, and
// identityreal/live_test.go against a running identity).
package dirtest

import (
	"fmt"
	"testing"

	"github.com/hostryhq/svc-sync/directory"
)

// Target is a directory under test with the hooks a test needs to drive the failure counter.
type Target struct {
	Dir    directory.Directory
	Tenant string
	// Valid returns the question a device holding the actor's PIN asks in session sid: every field a session
	// proof is bound to (device, member, pack_v, pin_v, opening time) and the valid proof itself.
	Valid func(sid string) directory.ProofQuestion
	// Wrong returns the i-th distinct wrong proof.
	Wrong func(i int) string
}

// Run executes the contract.
func Run(t *testing.T, tg Target) {
	t.Helper()
	n := 0
	ask := func(sid, proof string) directory.ProofResult {
		q := tg.Valid(sid)
		if proof != "" {
			q.Proof = proof
		}
		n++
		q.Key = fmt.Sprintf("dirtest/%d", n) // a new op each time: never a replay
		return tg.Dir.VerifyProof(tg.Tenant, q)
	}
	if got := ask("s0", ""); got != directory.ProofValid {
		t.Fatalf("a valid proof answers valid, got %v", got)
	}
	if got := ask("s0", tg.Wrong(0)); got != directory.ProofInvalid {
		t.Fatalf("a wrong proof answers invalid, got %v", got)
	}
	// Distinct wrong proofs lock the pair (5 in 15 minutes). The question is the same for every kind of op the
	// proof later covers: identity never learns whether the op is a sale or a configuration change.
	for i := 1; i < 6; i++ {
		ask("s0", tg.Wrong(i))
	}
	for i := 0; i < 2; i++ {
		if got := ask("s1", ""); got != directory.ProofLocked {
			t.Fatalf("a locked pair answers locked, got %v", got)
		}
		if got := ask("s1", tg.Wrong(100+i)); got != directory.ProofLocked {
			t.Fatalf("a wrong proof on a locked pair still answers locked, got %v", got)
		}
	}
}
