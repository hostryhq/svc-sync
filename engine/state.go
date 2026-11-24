// Package engine is the Go sync core shared by the cloud gateway, the LAN hub and the
// simulator's devices: the generic apply engine (conflict policies of S6, candidates and the
// void set), the op store logic (chain, seals, version vector) and the node protocol client.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Policies of S6.
const (
	PolAppend = "append"
	PolLWW    = "lww"
	PolDelta  = "delta"
	PolRank   = "rank"
)

// EntityDef declares the conflict policy next to the entity (offline-first invariant 5).
// The demo entities exercise every policy; the real registry is api-specs/sync/entities.
type EntityDef struct {
	Policy string
	// Review lists lww fields whose concurrent edits need a manager (S6 "lww + review").
	Review map[string]bool
	// Rank gives, per field, the forward-only order of values (policy rank).
	Rank map[string][]string
}

// Entities is the demo schema registry.
var Entities = map[string]EntityDef{
	"order":       {Policy: PolAppend},
	"order_line":  {Policy: PolAppend},
	"kot":         {Policy: PolAppend},
	"bill":        {Policy: PolAppend},
	"credit_note": {Policy: PolAppend},
	"payment":     {Policy: PolAppend},
	"audit":       {Policy: PolAppend},
	"session":     {Policy: PolAppend},
	"approval":    {Policy: PolAppend},
	"sync_void":   {Policy: PolAppend},
	"stock_level": {Policy: PolDelta},
	"kds_item":    {Policy: PolRank, Rank: map[string][]string{"status": {"new", "preparing", "ready", "served"}}},
	"menu_item":   {Policy: PolLWW, Review: map[string]bool{"price_paise": true}},
}

type stamp struct {
	hlc    sp.HLC
	origin string
	seq    int64
	idx    int
}

func (a stamp) less(b stamp) bool {
	if a.hlc != b.hlc {
		return a.hlc < b.hlc
	}
	if a.origin != b.origin {
		return a.origin < b.origin
	}
	if a.seq != b.seq {
		return a.seq < b.seq
	}
	return a.idx < b.idx
}

func (a stamp) String() string { return fmt.Sprintf("%s.%s.%d.%d", a.hlc, a.origin, a.seq, a.idx) }

type effect struct {
	op   string
	st   stamp
	kind string
	f    map[string]any
	prev map[string]string
}

type row struct {
	entity, id string
	fx         []effect
}

// State is the materialised copy of the applied ops. It is a pure function of the set of
// applied ops and the void set, so two nodes holding the same ops hold the same state whatever
// the arrival order (S5). Every mutation keeps its effect until the cloud confirms it; here
// effects are kept for good, which is the "candidates" of S6 without trimming.
type State struct {
	rows    map[string]*row
	applied map[string]bool
	voids   map[string]bool
	byOp    map[string][]string // op key -> row keys touched
}

// NewState returns an empty state.
func NewState() *State {
	return &State{rows: map[string]*row{}, applied: map[string]bool{}, voids: map[string]bool{}, byOp: map[string][]string{}}
}

func rowKey(e, id string) string { return e + "\x00" + id }

// Applied reports whether the op has been applied (idempotent apply, S5).
func (s *State) Applied(r sp.Ref) bool { return s.applied[r.Key()] }

// IsVoided reports whether the op is in the void set.
func (s *State) IsVoided(r sp.Ref) bool { return s.voids[r.Key()] }

// Apply applies an op's mutations once. A voided op is marked applied and does nothing.
func (s *State) Apply(r sp.Ref, hlc sp.HLC, muts []sp.Mut) {
	k := r.Key()
	if s.applied[k] {
		return
	}
	s.applied[k] = true
	if s.voids[k] {
		return
	}
	for i, m := range muts {
		if _, ok := Entities[m.E]; !ok {
			continue // unknown entity: ignored for one release (invariant 8)
		}
		rk := rowKey(m.E, m.ID)
		rw := s.rows[rk]
		if rw == nil {
			rw = &row{entity: m.E, id: m.ID}
			s.rows[rk] = rw
		}
		rw.fx = append(rw.fx, effect{op: k, st: stamp{hlc, r.Origin, r.Seq, i}, kind: m.K, f: m.F, prev: m.Prev})
		s.byOp[k] = append(s.byOp[k], rk)
	}
}

// Void adds an op to the void set and removes its effects: the winner of every field it touched
// is recomputed from the remaining candidates, so a later legitimate edit is never overwritten.
func (s *State) Void(r sp.Ref) {
	k := r.Key()
	if s.voids[k] {
		return
	}
	s.voids[k] = true
	for _, rk := range s.byOp[k] {
		rw := s.rows[rk]
		kept := rw.fx[:0]
		for _, e := range rw.fx {
			if e.op != k {
				kept = append(kept, e)
			}
		}
		rw.fx = kept
	}
	delete(s.byOp, k)
}

// derived is the visible value of a row.
type derived struct {
	exists bool
	gone   bool
	fields map[string]any
}

func (s *State) derive(rw *row) derived {
	def := Entities[rw.entity]
	var ins, tomb []effect
	for _, e := range rw.fx {
		switch e.kind {
		case sp.KInsert:
			ins = append(ins, e)
			tomb = append(tomb, e)
		case sp.KUndel, sp.KDel:
			tomb = append(tomb, e)
		}
	}
	d := derived{fields: map[string]any{}}
	switch def.Policy {
	case PolDelta:
		if len(rw.fx) == 0 {
			return d
		}
		d.exists = true
		for _, e := range rw.fx {
			if e.kind == sp.KInsert || e.kind == sp.KDelta {
				for f, v := range e.f {
					n, _ := v.(int64)
					cur, _ := d.fields[f].(int64)
					d.fields[f] = cur + n
				}
			}
		}
		return d
	case PolAppend:
		if len(ins) == 0 {
			return d
		}
		first := ins[0]
		for _, e := range ins[1:] {
			if e.st.less(first.st) {
				first = e
			}
		}
		d.exists = true
		for f, v := range first.f {
			d.fields[f] = v
		}
		return d
	}
	// lww and rank
	if len(ins) == 0 {
		return d
	}
	best := map[string]effect{}
	for _, e := range rw.fx {
		if e.kind != sp.KInsert && e.kind != sp.KSet {
			continue
		}
		for f, v := range e.f {
			cur, ok := best[f]
			if !ok || s.beats(def, f, e, v, cur) {
				best[f] = e
			}
		}
	}
	for f, e := range best {
		d.fields[f] = e.f[f]
	}
	d.exists = true
	top := tomb[0]
	for _, e := range tomb[1:] {
		if top.st.less(e.st) {
			top = e
		}
	}
	if top.kind == sp.KDel {
		d.exists, d.gone = false, true
	}
	return d
}

// beats reports whether candidate e (value v) beats the current best for field f.
func (s *State) beats(def EntityDef, f string, e effect, v any, cur effect) bool {
	if order, ok := def.Rank[f]; ok {
		re, rc := rankOf(order, v), rankOf(order, cur.f[f])
		if re != rc {
			return re > rc
		}
	}
	return cur.st.less(e.st)
}

func rankOf(order []string, v any) int {
	str, _ := v.(string)
	for i, o := range order {
		if o == str {
			return i
		}
	}
	return -1
}

// Row returns the visible fields of a row.
func (s *State) Row(entity, id string) (map[string]any, bool) {
	rw := s.rows[rowKey(entity, id)]
	if rw == nil {
		return nil, false
	}
	d := s.derive(rw)
	return d.fields, d.exists
}

func (s *State) sortedRows() []*row {
	keys := make([]string, 0, len(s.rows))
	for k := range s.rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*row, 0, len(keys))
	for _, k := range keys {
		out = append(out, s.rows[k])
	}
	return out
}

// Hash is the canonical state hash: every visible row with its derived fields, in key order.
func (s *State) Hash() string {
	h := sha256.New()
	for _, rw := range s.sortedRows() {
		d := s.derive(rw)
		if !d.exists && !d.gone {
			continue
		}
		raw, _ := sp.CanonicalJSON(d.fields)
		fmt.Fprintf(h, "%s|%s|%v|%s\n", rw.entity, rw.id, d.gone, raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RowCount is the number of visible rows.
func (s *State) RowCount() int {
	n := 0
	for _, rw := range s.rows {
		if s.derive(rw).exists {
			n++
		}
	}
	return n
}

// Violation is a detector result: a derived query over the state, never an op (S6 guarded).
type Violation struct {
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	Detail string `json:"detail,omitempty"`
}

// Violation kinds.
const (
	ViolOverpayment      = "overpayment"
	ViolDuplicateFinal   = "duplicate_finalisation"
	ViolConcurrentReview = "concurrent_review_edit"
)

// Detect runs the detectors: overpayment, one finalisation per order, concurrent edits of
// review fields. Output is sorted and depends only on the applied set.
func (s *State) Detect() []Violation {
	var out []Violation
	billTotal := map[string]int64{}
	billsByOrder := map[string][]string{}
	paid := map[string]int64{}
	for _, rw := range s.sortedRows() {
		d := s.derive(rw)
		if !d.exists {
			continue
		}
		switch rw.entity {
		case "bill":
			t, _ := d.fields["total_paise"].(int64)
			billTotal[rw.id] = t
			if o, _ := d.fields["order_id"].(string); o != "" {
				billsByOrder[o] = append(billsByOrder[o], rw.id)
			}
		case "payment":
			b, _ := d.fields["bill_id"].(string)
			a, _ := d.fields["amount_paise"].(int64)
			paid[b] += a
		case "menu_item":
			out = append(out, s.reviewConflicts(rw)...)
		}
	}
	for b, p := range paid {
		if t, ok := billTotal[b]; ok && p > t {
			out = append(out, Violation{ViolOverpayment, b, fmt.Sprintf("paid %d of %d", p, t)})
		}
	}
	for o, bs := range billsByOrder {
		if len(bs) > 1 {
			sort.Strings(bs)
			out = append(out, Violation{ViolDuplicateFinal, o, strings.Join(bs, ",")})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// reviewConflicts finds concurrent edits of review fields: a candidate whose `prev` is not the
// stamp of the candidate just before it in stamp order was written without seeing it.
func (s *State) reviewConflicts(rw *row) []Violation {
	def := Entities[rw.entity]
	var out []Violation
	for f := range def.Review {
		var cands []effect
		for _, e := range rw.fx {
			if e.kind == sp.KSet || e.kind == sp.KInsert {
				if _, ok := e.f[f]; ok {
					cands = append(cands, e)
				}
			}
		}
		sort.Slice(cands, func(i, j int) bool { return cands[i].st.less(cands[j].st) })
		for i := 1; i < len(cands); i++ {
			if cands[i].kind == sp.KSet && cands[i].prev[f] != cands[i-1].st.hlc.String() {
				out = append(out, Violation{ViolConcurrentReview, rw.id + "." + f, cands[i].st.String()})
			}
		}
	}
	return out
}

// DetectorHash summarises Detect for convergence checks.
func (s *State) DetectorHash() string {
	raw, _ := json.Marshal(s.Detect())
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Snapshot materialises the visible rows.
func (s *State) Snapshot() []sp.SnapshotRow {
	var out []sp.SnapshotRow
	for _, rw := range s.sortedRows() {
		d := s.derive(rw)
		if d.exists || d.gone {
			out = append(out, sp.SnapshotRow{Entity: rw.entity, ID: rw.id, Fields: d.fields, Gone: d.gone})
		}
	}
	return out
}

// VoidedRefs lists the void set.
func (s *State) VoidedRefs() []string {
	out := make([]string, 0, len(s.voids))
	for k := range s.voids {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
