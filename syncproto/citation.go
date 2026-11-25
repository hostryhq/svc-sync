package syncproto

// IntentApprovalSelfConfirm is a member confirming their own PIN on a sensitive action they may do themselves: the same
// approval record and action proof as approval.grant with requester = approver = the actor. It never satisfies a two-person
// rule (ADR-0005 section 8, ADR-0014 A3.3).
const IntentApprovalSelfConfirm = "approval.self_confirm"

// ActionTarget is the `<entity>:<row id>` of the row the op inserts or sets: the first mutation of kind insert or set. It is
// the `target` an approval binds and the gateway recomputes (sync/protocol-v1.md, Action hash).
func (b Body) ActionTarget() string {
	for _, m := range b.Muts {
		if m.K == KInsert || m.K == KSet {
			return m.E + ":" + m.ID
		}
	}
	return ""
}

// BoundValues reads the `values` of the action hash: one member per name the intent lists in `proof.binds`, taken from the
// first mutation of the op that sets a field of that name (integers stay integers, ids strings). ok is false when a bound
// name is not set by the op, which is a mismatch. An intent that binds nothing gives `{}`.
func (b Body) BoundValues(binds []string) (map[string]any, bool) {
	out := make(map[string]any, len(binds))
	for _, name := range binds {
		found := false
		for _, m := range b.Muts {
			if v, ok := m.F[name]; ok && (m.K == KInsert || m.K == KSet) {
				out[name], found = v, true
				break
			}
		}
		if !found {
			return out, false
		}
	}
	return out, true
}
