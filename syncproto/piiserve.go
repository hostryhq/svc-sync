package syncproto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// ServesPII reports whether a node answering a pull or snapshot gives the pii object to a puller of this credential
// kind: pos, waiter, personal (bound to the outlet) and hub, never a kds (ADR-0014 A3.1 item 1; vectors pii_placement).
// The commitments are in the sealed body and reach every kind.
func ServesPII(kind string) bool {
	switch kind {
	case KindPOS, KindWaiter, KindPersonal, KindHub:
		return true
	}
	return false
}

// PIIMissing counts the commitments of an op that have no verified value in stored (this node's wire pii).
func PIIMissing(c PIICommit, stored json.RawMessage) int {
	have := map[string]map[string]map[string]json.RawMessage{}
	if len(bytes.TrimSpace(stored)) > 0 {
		_ = json.Unmarshal(stored, &have)
	}
	n := 0
	for e, rows := range c {
		for id, fields := range rows {
			for name := range fields {
				if _, ok := have[e][id][name]; !ok {
					n++
				}
			}
		}
	}
	return n
}

// MergePII adds the fields of add that old lacks (both verified wire pii) and returns the canonical union.
func MergePII(old, add json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(old)) == 0 {
		return add, nil
	}
	if len(bytes.TrimSpace(add)) == 0 {
		return old, nil
	}
	var a, b map[string]map[string]map[string]any
	dec := json.NewDecoder(bytes.NewReader(old))
	dec.UseNumber()
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPII, err)
	}
	dec = json.NewDecoder(bytes.NewReader(add))
	dec.UseNumber()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPII, err)
	}
	for e, rows := range b {
		if a[e] == nil {
			a[e] = map[string]map[string]any{}
		}
		for id, fields := range rows {
			if a[e][id] == nil {
				a[e][id] = map[string]any{}
			}
			for name, v := range fields {
				if _, ok := a[e][id][strings.TrimPrefix(name, piiSaltPrefix)]; ok {
					continue
				}
				a[e][id][name] = v
			}
		}
	}
	return CanonicalJSON(a)
}
