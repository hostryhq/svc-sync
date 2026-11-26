package identitystub

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/directory/dirtest"
)

// The stub answers the proof check like real identity: locked for every op kind (security final
// verdict). The same suite runs against the real identity service in identityreal.
func TestStubAnswersLockedLikeRealIdentity(t *testing.T) {
	now := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	id, err := New(func() time.Time { return now }, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dirtest.Run(t, dirtest.Target{Dir: id, Tenant: "t1",
		Valid: func(sid string) directory.ProofQuestion {
			q := directory.ProofQuestion{Kind: directory.ProofKindSession, Device: "dev", Member: "m1", SID: sid, PackV: 1, PinV: 1, OpenedAt: now}
			q.Proof = id.MintProof(q)
			return q
		},
		Wrong: func(i int) string { return fmt.Sprintf("wrong-%d", i) }})
}
