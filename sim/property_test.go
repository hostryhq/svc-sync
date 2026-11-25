package sim

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// seedsFromEnv lets CI and the test engineer widen the run: SYNC_SIM_SEEDS=200 SYNC_SIM_FROM=1000.
func seedsFromEnv(def int) (from uint64, n int) {
	from = 1
	n = def
	if v, err := strconv.Atoi(os.Getenv("SYNC_SIM_SEEDS")); err == nil && v > 0 {
		n = v
	}
	if v, err := strconv.ParseUint(os.Getenv("SYNC_SIM_FROM"), 10, 64); err == nil {
		from = v
	}
	return
}

func runSeeds(t *testing.T, name string, f Features, def, steps int) {
	from, n := seedsFromEnv(def)
	for seed := from; seed < from+uint64(n); seed++ {
		res, err := Run(context.Background(), Options{Seed: seed, Steps: steps, Pos: 2, Waiters: 2, KDS: 1, Features: f, Trace: true})
		if err != nil {
			t.Fatalf("%s seed %d: %v", name, seed, err)
		}
		if len(res.Problems) > 0 {
			var b strings.Builder
			for _, p := range res.Problems {
				fmt.Fprintf(&b, "  %s\n", p)
			}
			tail := res.Trace
			if len(tail) > 60 {
				tail = tail[len(tail)-60:]
			}
			t.Fatalf("%s seed %d diverged (reproduce: go run ./cmd/simulate -seed %d):\n%s\ntrace tail:\n  %s", name, seed, seed, b.String(), strings.Join(tail, "\n  "))
		}
	}
}

func TestPropertyPartitionsAndCrashesConverge(t *testing.T) {
	runSeeds(t, "partitions+crashes", Features{Partitions: true, Faults: true, Crashes: true, HubKills: true, Skew: true}, 8, 250)
}

func TestPropertyFullHazardSetConverges(t *testing.T) {
	runSeeds(t, "all hazards", AllFeatures, 6, 350)
}
