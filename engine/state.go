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
	"sync"

	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Policies of S6. A registry entity declares a policy per field (the FP constants); PolAppend,
// PolLWW, PolDelta, PolRank and PolMixed are the entity-level defaults of api-specs entities/ and
// of the simulator's demo entities.
const (
	PolAppend = "append"
	PolLWW    = "lww"
	PolDelta  = "delta"
	PolRank   = "rank"
	PolMixed  = "mixed"
)

// Field policies of the registry (ADR-0002 S6).
const (
	FPImmutable = "immutable"
	FPLWW       = "lww"
	FPLWWReview = "lww_review"
	FPDelta     = "delta"
	FPRank      = "rank"
)

// FieldDef is the conflict policy of one field of a registry entity.
type FieldDef struct {
	Policy string
	// Group: fields of one group win together (lww, lww_review).
	Group string
	// Order is the forward-only order of a rank field, lowest first.
	Order []string
	// PII marks a personal-data field: its value travels beside the op, only its commitment is in the body and
	// in every convergence hash (ADR-0014 A3.1, A3.2).
	PII bool
}

// EntityDef declares the conflict policy next to the entity (offline-first invariant 5). Entities
// is generated from the api-specs entity registry (entities_gen.go); the simulator and unit tests
// add demo entities with RegisterDemoEntities, which the gateway and hub binaries never call.
type EntityDef struct {
	// Policy is the entity default (append, lww, rank, mixed) or, for a demo entity, delta.
	Policy    string
	Tombstone bool
	Guarded   bool
	// Fields holds the per-field policies of a registry entity. A demo entity has none and uses
	// Policy, Review and Rank.
	Fields map[string]FieldDef
	// Review lists lww fields whose concurrent edits need a manager (demo entities only).
	Review map[string]bool
	// Rank gives, per field, the forward-only order of values (demo entities only).
	Rank map[string][]string
}

// field returns the policy of a field. A field a registry entity does not list (a newer client's)
// is kept as lww, so that no node loses it.
func (d EntityDef) field(name string) FieldDef {
	if f, ok := d.Fields[name]; ok {
		return f
	}
	if len(d.Fields) > 0 {
		return FieldDef{Policy: FPLWW}
	}
	switch d.Policy {
	case PolAppend:
		return FieldDef{Policy: FPImmutable}
	case PolDelta:
		return FieldDef{Policy: FPDelta}
	}
	if o, ok := d.Rank[name]; ok {
		return FieldDef{Policy: FPRank, Order: o}
	}
	if d.Review[name] {
		return FieldDef{Policy: FPLWWReview}
	}
	return FieldDef{Policy: FPLWW}
}

// HasLWW reports whether any field of the entity is resolved last-writer-wins.
func (d EntityDef) HasLWW() bool {
	if len(d.Fields) == 0 {
		return d.Policy == PolLWW
	}
	for _, f := range d.Fields {
		if f.Policy == FPLWW || f.Policy == FPLWWReview {
			return true
		}
	}
	return false
}

// reviewFields lists the lww_review fields of an entity, sorted.
func (d EntityDef) reviewFields() []string {
	var out []string
	for n, f := range d.Fields {
		if f.Policy == FPLWWReview {
			out = append(out, n)
		}
	}
	for n := range d.Review {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// groupKey is the resolution group of an lww or lww_review field (as go-common/sync).
func (f FieldDef) groupKey(name string) string {
	if f.Group != "" {
		return "g:" + f.Group
	}
	return "f:" + name
}

// Entities is the entity registry the apply state follows: the generated registry of api-specs
// entities/ (entities_gen.go), plus the demo entities in a simulator or test process.
var Entities = registryEntities()

var demoOnce sync.Once

// RegisterDemoEntities adds the entities that exist only in the simulator and the unit tests: the
// registry has no stock level or KDS item yet, and the simulator exercises every policy. The
// gateway and hub binaries never call it; ops of an unknown entity are ignored.
func RegisterDemoEntities() {
	demoOnce.Do(func() {
		for _, n := range []string{"audit", "session", "approval", "sync_void"} {
			Entities[n] = EntityDef{Policy: PolAppend}
		}
		Entities["stock_level"] = EntityDef{Policy: PolDelta}
		Entities["kds_item"] = EntityDef{Policy: PolRank, Tombstone: true, Rank: map[string][]string{"status": {"new", "preparing", "ready", "served"}}}
		Entities["menu_item"] = EntityDef{Policy: PolLWW, Tombstone: true, Review: map[string]bool{"price_paise": true}}
	})
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

// piiCommitPrefix names the member of a row text that holds the commitment of a pii field (ADR-0014 A3.2).
const piiCommitPrefix = "~c:"

type effect struct {
	ref  sp.Ref
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
func (s *State) Apply(r sp.Ref, hlc sp.HLC, muts []sp.Mut) { s.ApplyPII(r, hlc, muts, nil) }

// ApplyPII is Apply for an op that carries pii commitments (body.pii_c). A commitment of a field the entity declares
// `pii` becomes a candidate named "~c:<field>" that follows the field's own merge rule, so the state hash covers it
// and two nodes holding different winners for the field differ (ADR-0014 A3.2 item 1). A value is never an input.
func (s *State) ApplyPII(r sp.Ref, hlc sp.HLC, muts []sp.Mut, commits sp.PIICommit) {
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
		f := m.F
		if c := commits[m.E][m.ID]; len(c) > 0 {
			f = make(map[string]any, len(m.F)+len(c))
			for n, v := range m.F {
				f[n] = v
			}
			for n, h := range c {
				if fd, ok := Entities[m.E].Fields[n]; ok && fd.PII {
					f[piiCommitPrefix+n] = h
				}
			}
		}
		rw.fx = append(rw.fx, effect{ref: r, op: k, st: stamp{hlc, r.Origin, r.Seq, i}, kind: m.K, f: f, prev: m.Prev})
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
	// piiSrc is, per pii field, the op whose commitment won it (the op that holds the value).
	piiSrc map[string]sp.Ref
}

func (s *State) derive(rw *row) derived {
	def := Entities[rw.entity]
	registry := len(def.Fields) > 0
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
	if def.Policy == PolDelta && !registry { // a pure counter exists as soon as it has an effect
		if len(rw.fx) == 0 {
			return d
		}
		d.exists = true
	} else {
		if len(ins) == 0 {
			return d
		}
		d.exists = true
	}
	// Per field, by the policy of its registry entry (ADR-0002 S6). A kind only reaches a field
	// whose policy it may touch (go-common/sync kindAllows).
	first := map[string]effect{}     // immutable: the earliest insert that carries the field
	best := map[string]effect{}      // rank: the highest rank, then the highest stamp
	groupBest := map[string]effect{} // lww, lww_review: the highest stamp among the candidates of a group
	for _, e := range rw.fx {
		for f, v := range e.f {
			base := strings.TrimPrefix(f, piiCommitPrefix)
			fd := def.field(base)
			if registry {
				if _, known := def.Fields[base]; !known || !kindAllows(e.kind, fd.Policy) {
					continue
				}
			} else if e.kind != sp.KInsert && e.kind != sp.KSet && e.kind != sp.KRank && !(e.kind == sp.KDelta && fd.Policy == FPDelta) {
				continue
			}
			switch fd.Policy {
			case FPImmutable:
				if e.kind != sp.KInsert {
					continue
				}
				if cur, ok := first[f]; !ok || e.st.less(cur.st) {
					first[f] = e
				}
			case FPDelta:
				if e.kind == sp.KInsert || e.kind == sp.KDelta {
					n, _ := v.(int64)
					cur, _ := d.fields[f].(int64)
					d.fields[f] = cur + n
				}
			case FPRank:
				if e.kind == sp.KDel || e.kind == sp.KUndel {
					continue
				}
				if cur, ok := best[f]; !ok || beats(fd.Order, f, e, cur) {
					best[f] = e
				}
			default: // lww, lww_review
				g := fd.groupKey(base)
				if cur, ok := groupBest[g]; !ok || cur.st.less(e.st) {
					groupBest[g] = e
				}
			}
		}
	}
	for f, e := range first {
		d.fields[f] = e.f[f]
		d.noteSrc(f, e)
	}
	for f, e := range best {
		d.fields[f] = e.f[f]
		d.noteSrc(f, e)
	}
	for f := range fieldsOf(rw, def) {
		base := strings.TrimPrefix(f, piiCommitPrefix)
		fd := def.field(base)
		if fd.Policy != FPLWW && fd.Policy != FPLWWReview {
			continue
		}
		if e, ok := groupBest[fd.groupKey(base)]; ok {
			if v, has := e.f[f]; has {
				d.fields[f] = v
				d.noteSrc(f, e)
			}
		}
	}
	if def.Tombstone || (!registry && def.Policy != PolAppend && def.Policy != PolDelta) {
		top := tomb[0]
		for _, e := range tomb[1:] {
			if top.st.less(e.st) {
				top = e
			}
		}
		if top.kind == sp.KDel {
			d.exists, d.gone = false, true
		}
	}
	return d
}

func (d *derived) noteSrc(f string, e effect) {
	if !strings.HasPrefix(f, piiCommitPrefix) {
		return
	}
	if d.piiSrc == nil {
		d.piiSrc = map[string]sp.Ref{}
	}
	d.piiSrc[strings.TrimPrefix(f, piiCommitPrefix)] = e.ref
}

// fieldsOf lists the fields any effect of the row carries.
func fieldsOf(rw *row, _ EntityDef) map[string]struct{} {
	out := map[string]struct{}{}
	for _, e := range rw.fx {
		for f := range e.f {
			out[f] = struct{}{}
		}
	}
	return out
}

func kindAllows(kind, policy string) bool {
	switch kind {
	case sp.KInsert:
		return true
	case sp.KSet:
		return policy == FPLWW || policy == FPLWWReview
	case sp.KDelta:
		return policy == FPDelta
	case sp.KRank:
		return policy == FPRank
	}
	return false
}

// beats reports whether candidate e beats the current best for rank field f.
func beats(order []string, f string, e, cur effect) bool {
	re, rc := rankOf(order, e.f[f]), rankOf(order, cur.f[f])
	if re != rc {
		return re > rc
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
			// "two bills from one check" (registry: check_id; the simulator's demo bills: order_id)
			o, _ := d.fields["check_id"].(string)
			if o == "" {
				o, _ = d.fields["order_id"].(string)
			}
			if o != "" {
				billsByOrder[o] = append(billsByOrder[o], rw.id)
			}
		case "payment":
			b, _ := d.fields["bill_id"].(string)
			a, _ := d.fields["amount_paise"].(int64)
			paid[b] += a
		}
		if len(Entities[rw.entity].reviewFields()) > 0 {
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
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}

// reviewConflicts finds concurrent edits of review fields: a candidate whose `prev` is not the
// stamp of the candidate just before it in stamp order was written without seeing it.
func (s *State) reviewConflicts(rw *row) []Violation {
	def := Entities[rw.entity]
	var out []Violation
	for _, f := range def.reviewFields() {
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
			row := sp.SnapshotRow{Entity: rw.entity, ID: rw.id, Fields: map[string]any{}, Gone: d.gone, PIISrc: d.piiSrc}
			for n, v := range d.fields {
				if strings.HasPrefix(n, piiCommitPrefix) {
					if row.PIIC == nil {
						row.PIIC = map[string]string{}
					}
					row.PIIC[strings.TrimPrefix(n, piiCommitPrefix)], _ = v.(string)
					continue
				}
				row.Fields[n] = v
			}
			out = append(out, row)
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
