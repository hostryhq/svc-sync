// Command simulate runs the deterministic sync simulator (ADR-0002 S15).
//
//	go run ./cmd/simulate -seed 7                 one reproducible run, with its trace on failure
//	go run ./cmd/simulate -runs 200 -from 1000    a seed range
//	go run ./cmd/simulate -soak 30m               keep running fresh seeds for 30 wall-clock minutes
//
// Exit status is non-zero if any run found a divergence. Failing seeds are appended to
// .soak/failures.txt so they become regression cases.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hostryhq/svc-sync/sim"
)

func main() {
	seed := flag.Uint64("seed", 0, "run exactly this seed (0 = use -from/-runs)")
	from := flag.Uint64("from", 1, "first seed of a range")
	runs := flag.Int("runs", 20, "number of seeds in the range")
	steps := flag.Int("steps", 500, "scheduler steps per run")
	soak := flag.Duration("soak", 0, "wall-clock soak: keep running new seeds for this long")
	pos := flag.Int("pos", 2, "billing counters")
	waiters := flag.Int("waiters", 2, "waiter tablets")
	kds := flag.Int("kds", 1, "kitchen screens")
	noHazards := flag.Bool("calm", false, "no partitions, crashes, rollbacks or key loss (baseline)")
	pg := flag.String("pg", "", "Postgres DSN for the gateway store (dev stack); default SQLite")
	verbose := flag.Bool("v", false, "print every run")
	flag.Parse()

	feat := sim.AllFeatures
	if *noHazards {
		feat = sim.Features{}
	}
	ctx := context.Background()
	start := time.Now()
	var total, failed int
	var agg sim.Stats
	var seeds []string
	one := func(s uint64) bool {
		res, err := sim.Run(ctx, sim.Options{Seed: s, Steps: *steps, Pos: *pos, Waiters: *waiters, KDS: *kds, Features: feat, Trace: true, CloudDSN: *pg})
		total++
		if err != nil {
			fmt.Printf("seed %d: ERROR %v\n", s, err)
			failed++
			record(s, err.Error())
			return false
		}
		a := res.Stats
		agg.Ops += a.Ops
		agg.Bills += a.Bills
		agg.Held += a.Held
		agg.Voided += a.Voided
		agg.Flagged += a.Flagged
		agg.Crashes += a.Crashes
		agg.HubKills += a.HubKills
		agg.HubWipes += a.HubWipes
		agg.Rollbacks += a.Rollbacks
		agg.KeyLosses += a.KeyLosses
		agg.Injected += a.Injected
		agg.Partitions += a.Partitions
		agg.Net.Calls += a.Net.Calls
		agg.Net.Lost += a.Net.Lost
		agg.Net.LostAck += a.Net.LostAck
		agg.Net.Dups += a.Net.Dups
		agg.Net.Replays += a.Net.Replays
		if *verbose || len(res.Problems) > 0 {
			fmt.Printf("seed %-6d ops=%-5d held=%-3d voided=%-3d flagged=%-4d rollbacks=%d keylosses=%d crashes=%d problems=%d\n",
				s, a.Ops, a.Held, a.Voided, a.Flagged, a.Rollbacks, a.KeyLosses, a.Crashes, len(res.Problems))
		}
		if len(res.Problems) > 0 {
			failed++
			seeds = append(seeds, fmt.Sprint(s))
			var b strings.Builder
			for _, p := range res.Problems {
				fmt.Printf("  DIVERGENCE %s\n", p)
				fmt.Fprintf(&b, "%s; ", p)
			}
			tail := res.Trace
			if len(tail) > 40 {
				tail = tail[len(tail)-40:]
			}
			fmt.Printf("  trace tail:\n    %s\n", strings.Join(tail, "\n    "))
			record(s, b.String())
			return false
		}
		return true
	}
	switch {
	case *seed != 0:
		one(*seed)
	case *soak > 0:
		for s := *from; time.Since(start) < *soak; s++ {
			one(s)
		}
	default:
		for s := *from; s < *from+uint64(*runs); s++ {
			one(s)
		}
	}
	fmt.Printf("\n%d runs in %s, %d with divergences %v\n", total, time.Since(start).Round(time.Second), failed, seeds)
	fmt.Printf("ops=%d bills=%d held=%d voided=%d flagged=%d injected=%d | crashes=%d hub-restarts=%d hub-wipes=%d cloud-rollbacks=%d key-losses=%d partitions=%d\n",
		agg.Ops, agg.Bills, agg.Held, agg.Voided, agg.Flagged, agg.Injected, agg.Crashes, agg.HubKills, agg.HubWipes, agg.Rollbacks, agg.KeyLosses, agg.Partitions)
	fmt.Printf("network: calls=%d lost=%d lost-acks=%d duplicates=%d stale-replays=%d\n", agg.Net.Calls, agg.Net.Lost, agg.Net.LostAck, agg.Net.Dups, agg.Net.Replays)
	if failed > 0 {
		os.Exit(1)
	}
}

func record(seed uint64, what string) {
	_ = os.MkdirAll(".soak", 0o755)
	f, err := os.OpenFile(filepath.Join(".soak", "failures.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s seed=%d %s\n", time.Now().UTC().Format(time.RFC3339), seed, what)
}
