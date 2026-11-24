package sim

import (
	"context"
	"fmt"
	"sort"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Expect is the verdict an injected op must end in at the cloud.
type Expect struct {
	Status string
	Reason string
}

// Expectations are the verdict oracle of a run: injected ops and what the S11 table says about them.
type Expectations struct {
	Ops map[string]Expect // by sp.Ref.Key()
	// Foreign lists numbers deliberately claimed in a series that belongs to another device; they
	// are excluded from the uniqueness check (the register marks them instead).
	Foreign map[string]bool
}

// NewExpectations returns an empty oracle.
func NewExpectations() *Expectations {
	return &Expectations{Ops: map[string]Expect{}, Foreign: map[string]bool{}}
}

// Add records an expectation for an op item.
func (e *Expectations) Add(it sp.Item, status, reason string) {
	e.Ops[sp.Ref{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq}.Key()] = Expect{status, reason}
}

func readAll(ctx context.Context, st repository.Store, tenant string) (map[string]repository.OpRec, error) {
	out := map[string]repository.OpRec{}
	err := st.InTx(ctx, tenant, func(tx repository.Tx) error {
		var after int64
		for {
			page, err := tx.ByArrival(after, 2000)
			if err != nil || len(page) == 0 {
				return err
			}
			after = page[len(page)-1].Arr
			for _, r := range page {
				out[sp.Ref{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq}.Key()] = r
			}
		}
	})
	return out, err
}

func sumPayments(s *engine.State) int64 {
	var t int64
	for _, id := range s.IDs("payment") {
		r, _ := s.Row("payment", id)
		a, _ := r["amount_paise"].(int64)
		t += a
	}
	return t
}

// CheckAll asserts the S15 pass conditions after quiescence: equal vectors and state hashes on
// every node, gapless sequences and no reused identity at the cloud, every recorded op held by the
// cloud, unique and gapless legal numbers, reconciled payment totals, and the verdict oracle.
func (w *World) CheckAll(ctx context.Context, exp *Expectations) []Problem {
	var ps []Problem
	bad := func(check, f string, a ...any) { ps = append(ps, Problem{check, fmt.Sprintf(f, a...)}) }
	cloud, err := readAll(ctx, w.GWStore, w.Tenant)
	if err != nil {
		return []Problem{{"read-cloud", err.Error()}}
	}
	cs, cvec, err := w.CloudState(ctx)
	if err != nil {
		return []Problem{{"cloud-state", err.Error()}}
	}

	// 1. Convergence: vectors, state hash, detector output, payment totals.
	type node struct {
		name string
		st   *engine.State
		vec  sp.Vector
		ops  map[string]repository.OpRec
	}
	var nodes []node
	for _, d := range w.Devices {
		if d.KeyLost {
			continue
		}
		v, _ := d.Eng.Vector(ctx)
		ops, _ := readAll(ctx, d.Store, w.Tenant)
		nodes = append(nodes, node{"device " + d.ID, d.Eng.State(), v, ops})
	}
	if w.Hub != nil {
		v, _ := w.Hub.Engine().Vector(ctx)
		ops, _ := readAll(ctx, w.Hub.Engine().Config().Store, w.Tenant)
		nodes = append(nodes, node{"hub", w.Hub.Engine().State(), v, ops})
	}
	wantHash, wantDet, wantPay := cs.Hash(), cs.DetectorHash(), sumPayments(cs)
	for _, n := range nodes {
		if vecString(n.vec) != vecString(cvec) {
			bad("vector", "%s differs from cloud\n  node : %s\n  cloud: %s", n.name, vecString(n.vec), vecString(cvec))
		}
		if h := n.st.Hash(); h != wantHash {
			bad("state-hash", "%s state hash differs from cloud (%d rows vs %d)", n.name, n.st.RowCount(), cs.RowCount())
		}
		if h := n.st.DetectorHash(); h != wantDet {
			bad("detectors", "%s detector output differs from cloud", n.name)
		}
		if p := sumPayments(n.st); p != wantPay {
			bad("payments", "%s payment total %d != cloud %d", n.name, p, wantPay)
		}
		// 7. Identity: the same slot carries the same hash everywhere.
		for k, r := range n.ops {
			if c, ok := cloud[k]; ok && c.H != r.H {
				bad("identity-reuse", "%s holds %s with a different hash than the cloud", n.name, k)
			}
		}
	}

	// 2. Gapless per (origin, stream) at the cloud.
	count := map[string]int64{}
	for k, r := range cloud {
		_ = k
		count[sp.VKey(r.Origin, r.Stream)]++
	}
	for k, n := range count {
		if cvec[k] != n {
			bad("gapless", "%s has %d slots but head %d", k, n, cvec[k])
		}
	}

	// 3. Every op a device recorded is at the cloud; nothing a device recorded was dropped.
	for _, d := range w.Devices {
		for _, ref := range d.Recorded {
			r, ok := cloud[ref.Key()]
			if !ok {
				bad("lost-op", "%s recorded by %s is not at the cloud", ref.Key(), d.ID)
				continue
			}
			if r.Status == repository.StVoided || r.Status == repository.StQuarantined {
				// allowed only when the oracle expects it
				if exp == nil || exp.Ops[ref.Key()].Status == "" {
					if r.Status == repository.StQuarantined {
						bad("unexpected-hold", "%s ended %s (%s)", ref.Key(), r.Status, r.Reason)
					}
				}
			}
		}
	}

	// 4. Legal numbers: unique across devices, none longer than 16 characters, register gapless,
	// no finalised document ever voided.
	seen := map[string]string{}
	for _, d := range w.Devices {
		for _, n := range d.Numbers {
			if len(n) > 16 {
				bad("number-length", "%q is longer than 16 characters", n)
			}
			if exp != nil && exp.Foreign[n+"@"+d.ID] {
				continue
			}
			if o, dup := seen[n]; dup && o != d.ID {
				bad("number-unique", "%s issued by both %s and %s", n, o, d.ID)
			}
			seen[n] = d.ID
		}
	}
	rep, err := w.GW.Register(ctx, w.Tenant)
	if err != nil {
		bad("register", "%v", err)
	}
	for _, g := range rep.Gaps {
		bad("series-gap", "series %s/%s is missing %v", g.Code, g.FY, g.Missing)
	}
	for _, r := range cloud {
		if r.Status == repository.StVoided {
			if b, err := sp.DecodeBody(r.Body); err == nil && b.Doc != nil {
				bad("voided-document", "%s numbered %s was voided", sp.Ref{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq}.Key(), b.Doc.Number)
			}
		}
	}

	// 6. Verdict oracle.
	if exp != nil {
		keys := make([]string, 0, len(exp.Ops))
		for k := range exp.Ops {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			want := exp.Ops[k]
			r, ok := cloud[k]
			switch {
			case !ok:
				bad("verdict", "%s expected %s but the cloud has no such slot (a trading fact was dropped)", k, want.Status)
			case r.Status != want.Status || (want.Reason != "" && r.Reason != want.Reason):
				bad("verdict", "%s expected %s/%s, got %s/%s", k, want.Status, want.Reason, r.Status, r.Reason)
			}
		}
	}
	return ps
}
