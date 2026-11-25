package engine

import (
	"fmt"
	"testing"

	sp "github.com/hostryhq/svc-sync/syncproto"
)

type op struct {
	ref  sp.Ref
	hlc  sp.HLC
	muts []sp.Mut
}

func mk(origin string, seq int64, ms int64, muts ...sp.Mut) op {
	return op{sp.Ref{Origin: origin, Stream: "s", Seq: seq}, sp.MakeHLC(ms, 0), muts}
}

func ins(e, id string, f map[string]any) sp.Mut { return sp.Mut{E: e, ID: id, K: sp.KInsert, F: f} }

func permutations(n int) [][]int {
	var out [][]int
	var rec func(a []int, k int)
	rec = func(a []int, k int) {
		if k == len(a) {
			out = append(out, append([]int(nil), a...))
			return
		}
		for i := k; i < len(a); i++ {
			a[k], a[i] = a[i], a[k]
			rec(a, k+1)
			a[k], a[i] = a[i], a[k]
		}
	}
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	rec(idx, 0)
	return out
}

// applyAll applies the ops in the given order, voiding the named refs at the position voidAt.
func applyAll(ops []op, order []int, voids []sp.Ref) *State {
	s := NewState()
	for _, v := range voids {
		s.Void(v)
	}
	for _, i := range order {
		s.Apply(ops[i].ref, ops[i].hlc, ops[i].muts)
	}
	return s
}

func TestConflictPolicyPerEntityIsOrderIndependent(t *testing.T) {
	cases := []struct {
		name  string
		ops   []op
		check func(t *testing.T, s *State)
	}{
		{"append: duplicate insert of one id is one row, the lower stamp wins", []op{
			mk("a", 1, 10, ins("order", "o1", map[string]any{"token_no": int64(1)})),
			mk("b", 1, 20, ins("order", "o1", map[string]any{"token_no": int64(2)}))},
			func(t *testing.T, s *State) {
				if r, _ := s.Row("order", "o1"); r["token_no"] != int64(1) {
					t.Fatalf("got %v", r)
				}
			}},
		{"delta: concurrent deltas sum", []op{
			mk("a", 1, 10, sp.Mut{E: "stock_level", ID: "x", K: sp.KDelta, F: map[string]any{"qty_milli": int64(-3000)}}),
			mk("b", 1, 11, sp.Mut{E: "stock_level", ID: "x", K: sp.KDelta, F: map[string]any{"qty_milli": int64(5000)}}),
			mk("c", 1, 12, sp.Mut{E: "stock_level", ID: "x", K: sp.KDelta, F: map[string]any{"qty_milli": int64(-1000)}})},
			func(t *testing.T, s *State) {
				if r, _ := s.Row("stock_level", "x"); r["qty_milli"] != int64(1000) {
					t.Fatalf("got %v", r)
				}
			}},
		{"lww: the highest stamp wins, ties break on origin", []op{
			mk("a", 1, 10, ins("menu_item", "m", map[string]any{"name": "tea", "price_paise": int64(100)})),
			mk("b", 1, 30, sp.Mut{E: "menu_item", ID: "m", K: sp.KSet, F: map[string]any{"price_paise": int64(300)}}),
			mk("c", 1, 30, sp.Mut{E: "menu_item", ID: "m", K: sp.KSet, F: map[string]any{"price_paise": int64(200)}})},
			func(t *testing.T, s *State) {
				if r, _ := s.Row("menu_item", "m"); r["price_paise"] != int64(200) || r["name"] != "tea" {
					t.Fatalf("got %v", r) // b and c tie on the clock; the higher origin id wins
				}
			}},
		{"rank: a stale device cannot move a status backwards", []op{
			mk("a", 1, 10, ins("kds_item", "k", map[string]any{"status": "new"})),
			mk("b", 1, 40, sp.Mut{E: "kds_item", ID: "k", K: sp.KSet, F: map[string]any{"status": "ready"}}),
			mk("c", 1, 50, sp.Mut{E: "kds_item", ID: "k", K: sp.KSet, F: map[string]any{"status": "preparing"}})},
			func(t *testing.T, s *State) {
				if r, _ := s.Row("kds_item", "k"); r["status"] != "ready" {
					t.Fatalf("got %v", r)
				}
			}},
		{"tombstone: a later undel restores, a later del removes", []op{
			mk("a", 1, 10, ins("menu_item", "m", map[string]any{"name": "tea"})),
			mk("b", 1, 20, sp.Mut{E: "menu_item", ID: "m", K: sp.KDel}),
			mk("c", 1, 30, sp.Mut{E: "menu_item", ID: "m", K: sp.KUndel}),
			mk("d", 1, 40, sp.Mut{E: "menu_item", ID: "m", K: sp.KDel})},
			func(t *testing.T, s *State) {
				if _, ok := s.Row("menu_item", "m"); ok {
					t.Fatal("the last stamp is a del")
				}
			}},
		{"orphan tolerance: a set before its insert becomes visible when the parent arrives", []op{
			mk("b", 1, 20, sp.Mut{E: "menu_item", ID: "m", K: sp.KSet, F: map[string]any{"price_paise": int64(9)}}),
			mk("a", 1, 10, ins("menu_item", "m", map[string]any{"name": "tea"}))},
			func(t *testing.T, s *State) {
				if r, ok := s.Row("menu_item", "m"); !ok || r["price_paise"] != int64(9) {
					t.Fatalf("got %v %v", r, ok)
				}
			}},
		{"review: concurrent price edits are listed, the later one wins", []op{
			mk("a", 1, 10, ins("menu_item", "m", map[string]any{"price_paise": int64(100)})),
			func() op {
				o := mk("b", 1, 20, sp.Mut{E: "menu_item", ID: "m", K: sp.KSet, F: map[string]any{"price_paise": int64(150)}, Prev: map[string]string{"price_paise": sp.MakeHLC(10, 0).String()}})
				return o
			}(),
			mk("c", 1, 25, sp.Mut{E: "menu_item", ID: "m", K: sp.KSet, F: map[string]any{"price_paise": int64(170)}, Prev: map[string]string{"price_paise": sp.MakeHLC(10, 0).String()}})},
			func(t *testing.T, s *State) {
				if r, _ := s.Row("menu_item", "m"); r["price_paise"] != int64(170) {
					t.Fatalf("got %v", r)
				}
				v := s.Detect()
				if len(v) != 1 || v[0].Kind != ViolConcurrentReview {
					t.Fatalf("detector output: %+v", v)
				}
			}},
		{"guarded: two full payments on one bill are both kept and the overpayment detector fires", []op{
			mk("a", 1, 10, ins("bill", "b1", map[string]any{"total_paise": int64(1000), "order_id": "o1"})),
			mk("a", 2, 11, ins("payment", "p1", map[string]any{"bill_id": "b1", "amount_paise": int64(1000)})),
			mk("b", 1, 12, ins("payment", "p2", map[string]any{"bill_id": "b1", "amount_paise": int64(1000)}))},
			func(t *testing.T, s *State) {
				if len(s.IDs("payment")) != 2 {
					t.Fatal("a recorded payment is never dropped")
				}
				if v := s.Detect(); len(v) != 1 || v[0].Kind != ViolOverpayment {
					t.Fatalf("detector output: %+v", v)
				}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var want string
			for _, order := range permutations(len(c.ops)) {
				s := applyAll(c.ops, order, nil)
				if want == "" {
					want = s.Hash() + s.DetectorHash()
					c.check(t, s)
				} else if got := s.Hash() + s.DetectorHash(); got != want {
					t.Fatalf("order %v gives a different state", order)
				}
			}
		})
	}
}

func TestApplyTwiceAndInShuffledOrderGivesTheSameState(t *testing.T) {
	var ops []op
	for i := 0; i < 8; i++ {
		ops = append(ops, mk(fmt.Sprintf("d%d", i%3), int64(i/3+1), int64(10+i),
			sp.Mut{E: "stock_level", ID: "x", K: sp.KDelta, F: map[string]any{"qty_milli": int64(i + 1)}},
			ins("order", fmt.Sprintf("o%d", i), map[string]any{"t": int64(i)})))
	}
	once := NewState()
	for _, o := range ops {
		once.Apply(o.ref, o.hlc, o.muts)
	}
	twice := NewState()
	for i := len(ops) - 1; i >= 0; i-- {
		twice.Apply(ops[i].ref, ops[i].hlc, ops[i].muts)
	}
	for _, o := range ops {
		twice.Apply(o.ref, o.hlc, o.muts) // the whole log again
	}
	if once.Hash() != twice.Hash() {
		t.Fatal("replay must not change state")
	}
}

// The void scenario of S6: an unauthorised price edit relayed on the LAN, a later legitimate
// edit, then the cloud's refusal, in every arrival order: every node ends on the legitimate edit.
func TestVoidEndsOnTheLegitimateEditInEveryArrivalOrder(t *testing.T) {
	base := mk("a", 1, 10, ins("menu_item", "m", map[string]any{"name": "tea", "price_paise": int64(100)}))
	bad := mk("b", 1, 20, sp.Mut{E: "menu_item", ID: "m", K: sp.KSet, F: map[string]any{"price_paise": int64(1)}})
	good := mk("c", 1, 30, sp.Mut{E: "menu_item", ID: "m", K: sp.KSet, F: map[string]any{"price_paise": int64(250)}})
	steps := []string{"base", "bad", "good", "void"}
	for _, order := range permutations(len(steps)) {
		s := NewState()
		for _, i := range order {
			switch steps[i] {
			case "base":
				s.Apply(base.ref, base.hlc, base.muts)
			case "bad":
				s.Apply(bad.ref, bad.hlc, bad.muts)
			case "good":
				s.Apply(good.ref, good.hlc, good.muts)
			case "void":
				s.Void(bad.ref)
			}
		}
		if r, _ := s.Row("menu_item", "m"); r["price_paise"] != int64(250) {
			t.Fatalf("order %v: price %v", order, r["price_paise"])
		}
	}
	// And when the legitimate edit is absent, the void falls back to the previous value, not to "now".
	s := NewState()
	s.Apply(base.ref, base.hlc, base.muts)
	s.Apply(bad.ref, bad.hlc, bad.muts)
	s.Void(bad.ref)
	if r, _ := s.Row("menu_item", "m"); r["price_paise"] != int64(100) {
		t.Fatalf("got %v", r)
	}
}
