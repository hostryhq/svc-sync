package sim

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

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
	// Reasons and Origins are holds that are allowed without a per-op expectation: a skewed
	// clock quarantines every later last-writer-wins op of that device for a while, and a
	// recovered origin's whole uploaded tail is held.
	Reasons map[string]bool
	Origins map[string]bool
}

// AllowReason permits any quarantine with this reason.
func (e *Expectations) AllowReason(r string) { e.Reasons[r] = true }

// AllowOrigin permits quarantines of every op of this origin (a recovered, key-lost origin).
func (e *Expectations) AllowOrigin(o string) { e.Origins[o] = true }

// NewExpectations returns an empty oracle.
func NewExpectations() *Expectations {
	return &Expectations{Ops: map[string]Expect{}, Foreign: map[string]bool{}, Reasons: map[string]bool{}, Origins: map[string]bool{}}
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
			bad("vector", "%s differs from cloud: %s%s", n.name, vecDiff(n.vec, cvec), slotDetail(cloud, n.vec, cvec))
		}
		if h := n.st.Hash(); h != wantHash {
			bad("state-hash", "%s state hash differs from cloud (%d rows vs %d)", n.name, n.st.RowCount(), cs.RowCount())
		}
		if h := n.st.DetectorHash(); h != wantDet {
			bad("detectors", "%s detector output differs from cloud: %s", n.name, violDiff(n.st.Detect(), cs.Detect()))
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
			_, ok := cloud[ref.Key()]
			if !ok {
				bad("lost-op", "%s recorded by %s is not at the cloud", ref.Key(), d.ID)
				continue
			}
		}
	}

	// 4. Legal numbers: unique across devices, none longer than 16 characters, register gapless,
	// no finalised document ever voided.
	seen := map[string]string{}
	for _, d := range w.Devices {
		for _, nr := range d.Numbers {
			n := nr.Number
			if len(n) > 16 {
				bad("number-length", "%q is longer than 16 characters", n)
			}
			if exp != nil && exp.Foreign[n+"@"+nr.Origin] {
				continue
			}
			if o, dup := seen[n]; dup && o != nr.Origin {
				bad("number-unique", "%s issued by both %s and %s", n, o, nr.Origin)
			}
			seen[n] = nr.Origin
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

	return ps
}

// CheckVerdicts runs the verdict oracle before the manager's review: every injected op ends in the
// state the S11 table gives it, no trading fact is dropped, and no op is held that nobody
// provoked.
func (w *World) CheckVerdicts(ctx context.Context, exp *Expectations) []Problem {
	var ps []Problem
	bad := func(check, f string, a ...any) { ps = append(ps, Problem{check, fmt.Sprintf(f, a...)}) }
	cloud, err := readAll(ctx, w.GWStore, w.Tenant)
	if err != nil {
		return []Problem{{"read-cloud", err.Error()}}
	}
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
		case exp.Origins[r.Origin] && (r.Reason == "revoked" || r.Reason == "unsealed_tail"):
			// the op reached the cloud only through the recovery upload: the revoked-origin and
			// unsealed-tail rows come before the rest of the table
		case r.Status == repository.StQuarantined && exp.Reasons[r.Reason] && r.Status != want.Status:
			// held for an earlier row of the table (a recovered origin, a clock-dragged device)
		case r.Status != want.Status || (want.Reason != "" && r.Reason != want.Reason):
			bad("verdict", "%s expected %s/%s, got %s/%s", k, want.Status, want.Reason, r.Status, r.Reason)
		}
	}
	for k, r := range cloud {
		if r.Status != repository.StQuarantined {
			continue
		}
		if _, listed := exp.Ops[k]; listed || exp.Reasons[r.Reason] || exp.Origins[r.Origin] {
			continue
		}
		bad("unexpected-hold", "%s ended quarantined (%s) with nothing provoking it", k, r.Reason)
	}
	return ps
}

// CheckReadBack asserts A1.2: after a direct pull from the cloud each device's own_held list is
// exactly the cloud's quarantined slots of its origin, with only the three coarse codes.
func (w *World) CheckReadBack(ctx context.Context) []Problem {
	var ps []Problem
	cloud, _ := readAll(ctx, w.GWStore, w.Tenant)
	for _, d := range w.Devices {
		if d.KeyLost {
			continue
		}
		if err := d.SyncCloud(ctx); err != nil {
			ps = append(ps, Problem{"read-back", fmt.Sprintf("%s: %v", d.ID, err)})
			continue
		}
		want := map[string]string{}
		for k, r := range cloud {
			if r.Origin == d.ID && r.Status == repository.StQuarantined {
				want[k] = engine.HoldCode(r.Reason)
			}
		}
		got := map[string]string{}
		for _, h := range d.CloudC.OwnHeld {
			got[sp.Ref{Origin: h.Origin, Stream: h.Stream, Seq: h.Seq}.Key()] = h.Code
			switch h.Code {
			case sp.HoldPending, sp.HoldManager, sp.HoldSupport:
			default:
				ps = append(ps, Problem{"read-back", fmt.Sprintf("%s was told %q: not one of the three hold codes", d.ID, h.Code)})
			}
		}
		if len(got) != len(want) {
			ps = append(ps, Problem{"read-back", fmt.Sprintf("%s shows %d slots needing attention, the cloud holds %d", d.ID, len(got), len(want))})
			continue
		}
		for k, c := range want {
			if got[k] != c {
				ps = append(ps, Problem{"read-back", fmt.Sprintf("%s slot %s: told %q, cloud code %q", d.ID, k, got[k], c)})
			}
		}
	}
	return ps
}

func vecDiff(a, b sp.Vector) string {
	var out []string
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var ks []string
	for k := range keys {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		if a[k] != b[k] {
			o, st, _ := sp.SplitVKey(k)
			out = append(out, fmt.Sprintf("%s [%.8s]: node %d cloud %d", o, st, a[k], b[k]))
		}
	}
	return strings.Join(out, "; ")
}

// slotDetail lists the cloud's state for the first slots a node lacks, to explain a stalled pull.
func slotDetail(cloud map[string]repository.OpRec, node, cvec sp.Vector) string {
	var out []string
	for k, c := range cvec {
		o, st, _ := sp.SplitVKey(k)
		for q := node[k] + 1; q <= c && q <= node[k]+3; q++ {
			if r, ok := cloud[sp.Ref{Origin: o, Stream: st, Seq: q}.Key()]; ok {
				out = append(out, fmt.Sprintf("%s#%d=%s/%s", o, q, r.Status, r.Reason))
			}
		}
	}
	sort.Strings(out)
	return " {" + strings.Join(out, ", ") + "}"
}

func violDiff(node, cloud []engine.Violation) string {
	set := func(vs []engine.Violation) map[string]bool {
		m := map[string]bool{}
		for _, v := range vs {
			b, _ := json.Marshal(v)
			m[string(b)] = true
		}
		return m
	}
	a, b := set(node), set(cloud)
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, "only on node "+k)
		}
	}
	for k := range b {
		if !a[k] {
			out = append(out, "only at cloud "+k)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "; ")
}

// slotDetail lists the cloud's state for the first slots a node lacks, to explain a stalled pull.
func slotDetail(cloud map[string]repository.OpRec, node, cvec sp.Vector) string {
	var out []string
	for k, c := range cvec {
		o, st, _ := sp.SplitVKey(k)
		for q := node[k] + 1; q <= c && q <= node[k]+3; q++ {
			if r, ok := cloud[sp.Ref{Origin: o, Stream: st, Seq: q}.Key()]; ok {
				out = append(out, fmt.Sprintf("%s#%d=%s/%s", o, q, r.Status, r.Reason))
			}
		}
	}
	sort.Strings(out)
	return " {" + strings.Join(out, ", ") + "}"
}
