package identitystub

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/directory/dirtest"
)

// The stub answers the proof check like real identity: locked for every op kind (security final
// verdict). The same suite must run against the real identity client before it is wired.
func TestStubAnswersLockedLikeRealIdentity(t *testing.T) {
	now := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	id, err := New(func() time.Time { return now }, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dirtest.Run(t, dirtest.Target{Dir: id, Tenant: "t1", Device: "dev", Actor: "m1",
		Valid: func() string { return id.MintProof("dev", "m1") },
		Wrong: func(i int) string { return fmt.Sprintf("wrong-%d", i) }})
}
