package engine

import (
	"os"
	"testing"

	"github.com/hostryhq/svc-sync/contract/specs"
	"github.com/hostryhq/svc-sync/engine/entitygen"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// The entity table is generated from the registry; a checked-in table that differs means the
// registry moved (or the table was edited by hand).
func TestEntityTableIsGenerated(t *testing.T) {
	dir, err := specs.Path("entities")
	if err != nil {
		t.Fatal(err)
	}
	want, err := entitygen.Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("entities_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("engine/entities_gen.go is out of date; run: go run ./cmd/genintents")
	}
}

// The registry entity `check` is mixed: an immutable field, a rank field, an lww field, and an
// lww_review group whose fields win together. Every arrival order gives one state.
func TestMixedRegistryEntityConvergesPerFieldPolicy(t *testing.T) {
	set := func(f map[string]any, prev map[string]string) sp.Mut {
		return sp.Mut{E: "check", ID: "c1", K: sp.KSet, F: f, Prev: prev}
	}
	ops := []op{
		mk("a", 1, 10, ins("check", "c1", map[string]any{"order_type": "dine_in", "status": "open", "label": "T1",
			"discount_kind": "percent", "discount_value": int64(10)})),
		mk("b", 1, 20, ins("check", "c1", map[string]any{"order_type": "takeaway"})), // immutable: the first insert wins
		mk("c", 1, 30, set(map[string]any{"label": "T2"}, nil)),
		mk("d", 1, 40, sp.Mut{E: "check", ID: "c1", K: sp.KRank, F: map[string]any{"status": "billed"}}),
		mk("e", 1, 50, sp.Mut{E: "check", ID: "c1", K: sp.KRank, F: map[string]any{"status": "closed_internal"}}), // backwards: loses
		// the discount group wins together: this set carries no discount_kind, so the group has none
		mk("f", 1, 60, set(map[string]any{"discount_value": int64(25)}, map[string]string{"discount_value": sp.MakeHLC(10, 0).String()})),
		// a set may not touch an immutable or rank field
		mk("g", 1, 70, set(map[string]any{"order_type": "counter", "status": "open", "unknown_field": "x"}, nil)),
	}
	var want string
	for n, ord := range permutations(len(ops)) {
		s := applyAll(ops, ord, nil)
		r, ok := s.Row("check", "c1")
		if !ok {
			t.Fatal("row missing")
		}
		if r["order_type"] != "dine_in" || r["status"] != "billed" || r["label"] != "T2" || r["discount_value"] != int64(25) {
			t.Fatalf("order %v: %v", ord, r)
		}
		if _, has := r["discount_kind"]; has {
			t.Fatalf("a group's fields win together; discount_kind must be unset: %v", r)
		}
		if _, has := r["unknown_field"]; has {
			t.Fatalf("a field the registry does not list is ignored: %v", r)
		}
		if n == 0 {
			want = s.Hash()
		} else if s.Hash() != want {
			t.Fatalf("order %v: state hash differs", ord)
		}
	}
}

func TestGuardedAndTombstoneComeFromTheRegistry(t *testing.T) {
	if !Entities["bill"].Guarded || !Entities["payment"].Guarded {
		t.Fatal("bill and payment are guarded entities")
	}
	if Entities["check"].Guarded || !Entities["item"].Tombstone || Entities["bill"].Tombstone {
		t.Fatal("guarded and tombstone flags must follow the registry")
	}
	if !Entities["item"].HasLWW() || Entities["bill"].HasLWW() {
		t.Fatal("item has lww fields, bill none")
	}
}
