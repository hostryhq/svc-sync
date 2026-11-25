package syncproto

import "testing"

// The binds of the registry (api-specs 1c94c67) name only fields the citing op records, so BoundValues finds each one.
func TestBoundValuesFollowTheRegistryBinds(t *testing.T) {
	for name, fields := range map[string]map[string]any{
		"bill.discount.over_limit": {"discount_kind": "percent", "discount_value": int64(25)},
		"bill.line.comp":           {"comp": true, "comp_reason_code_id": "rc-1"},
	} {
		in := Intents[name]
		if len(in.Binds) != len(fields) {
			t.Fatalf("%s binds %v, want the fields %v", name, in.Binds, fields)
		}
		b := Body{Muts: []Mut{{E: "x", ID: "1", K: KSet, F: fields}}}
		if v, ok := b.BoundValues(in.Binds); !ok || len(v) != len(fields) {
			t.Fatalf("%s: values %v ok=%v", name, v, ok)
		}
		if _, ok := (Body{Muts: []Mut{{E: "x", ID: "1", K: KSet, F: map[string]any{}}}}).BoundValues(in.Binds); ok {
			t.Fatalf("%s: a bound name the op does not set is a mismatch", name)
		}
	}
}
