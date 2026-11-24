package engine

import sp "github.com/hostryhq/svc-sync/syncproto"

// ZeroStamp is the `prev` of a field that has no value yet.
const ZeroStamp = "0000000000000000"

// FieldStamp returns the hex HLC of the candidate that currently wins a last-writer-wins field,
// or ZeroStamp when the field has no value. A writer sends it as `prev` so that a concurrent edit
// of a review field can be detected (S6).
func (s *State) FieldStamp(entity, id, field string) string {
	rw := s.rows[rowKey(entity, id)]
	if rw == nil {
		return ZeroStamp
	}
	var best *effect
	for i := range rw.fx {
		e := &rw.fx[i]
		if e.kind != sp.KInsert && e.kind != sp.KSet {
			continue
		}
		if _, ok := e.f[field]; !ok {
			continue
		}
		if best == nil || best.st.less(e.st) {
			best = e
		}
	}
	if best == nil {
		return ZeroStamp
	}
	return best.st.hlc.String()
}

// IDs lists the ids of the visible rows of an entity.
func (s *State) IDs(entity string) []string {
	var out []string
	for _, rw := range s.rows {
		if rw.entity == entity && s.derive(rw).exists {
			out = append(out, rw.id)
		}
	}
	return out
}
