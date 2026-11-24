package engine

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Role of a node (S2).
type Role string

// Roles.
const (
	RoleDevice Role = "device"
	RoleHub    Role = "hub"
	RoleCloud  Role = "cloud"
)

// Trust resolves the public key an origin signs its seals with: a device key from an
// identity-signed credential, or the gateway op-signing key for a cloud-<epoch> origin.
type Trust interface {
	OriginKey(origin string) (*ecdsa.PublicKey, bool)
}

// Caller is the authenticated party of a request.
type Caller struct {
	ID     string
	Kind   string
	Outlet string
	Brand  string
	// Drain is set for a drain or recovery-drain token (quarantine-upload only).
	Drain bool
	// Recovers is the old origin a recovery drain token is limited to.
	Recovers string
	RecID    string
}

// Parsed is an op under judgement.
type Parsed struct {
	Item   sp.Item
	Body   sp.Body
	Opaque bool // body hashes correctly but is not a valid op body
}

// Verdict is the outcome for one op (S11).
type Verdict struct {
	Status string
	Reason string
	Marks  []string
	// Void asks the cloud to emit sync.void for the op (configuration refused).
	Void bool
}

// VerdictCtx tells a verdict function how the op arrived.
type VerdictCtx struct {
	Caller Caller
	Own    bool // pusher is the origin
	// Unsealed: covered only by a recovery attestation (A1.3).
	Unsealed bool
	// ChainBroken: the op is stored as received after a failed chain or seal check (N-4).
	ChainBroken bool
	// Recovery: arrived through quarantine-upload.
	Recovery bool
	// Sealed: a valid seal covers it.
	Sealed bool
}

// RecordAndSealTx records an op of this node's own origin and seals it in the same transaction.
// The gateway uses it for cloud-origin ops (voids, emits), which are sealed at once (S16, S17).
func (e *Engine) RecordAndSealTx(tx repository.Tx, in Input) (sp.Item, error) {
	it, _, err := e.recordTx(tx, in)
	if err != nil {
		return sp.Item{}, err
	}
	if _, _, err := e.sealAt(tx, in.Stream, e.cfg.Origin, it.Seq); err != nil {
		return sp.Item{}, err
	}
	return it, nil
}

// Hooks specialise the engine: the gateway sets all of them, the hub sets Verdict (structural
// checks), a device sets none.
type Hooks struct {
	// Authorize returns a refusal reason, or "" to accept the group from the caller.
	Authorize func(tx repository.Tx, c Caller, origin, stream string, recovery bool) string
	// Verdict judges an op that passed chain and seal checks (or was stored as chain-broken).
	Verdict func(tx repository.Tx, p *Parsed, vc VerdictCtx) Verdict
	// QuarantineOwnUnverified stores an authenticated origin's own unverifiable ops in quarantine
	// instead of refusing them (N-4). Cloud only.
	QuarantineOwnUnverified bool
	// Stored runs in the storing transaction for each new op (outbox, register, void emission).
	Stored func(tx repository.Tx, e *Engine, rec repository.OpRec, p *Parsed, v Verdict) error
	// OnFork is told about a slot whose stored content differs from what arrived.
	OnFork func(tx repository.Tx, c Caller, rec repository.OpRec, it sp.Item) error
}

// SeriesSource gives a billing device its legal number series (S7).
type SeriesSource interface {
	// Code returns the series code the device holds for the document type.
	Code(docType string) (string, bool)
}

// Config builds an Engine.
type Config struct {
	Role   Role
	Tenant string
	Outlet string
	// Origin is this node's own origin id: the device id, or cloud-<epoch>. Empty for a hub that
	// never records ops of its own.
	Origin string
	Key    *sp.KeyPair
	Store  repository.Store
	Trust  Trust
	Clock  *sp.Clock
	Hooks  Hooks
	Series SeriesSource
	// NoState skips the materialised state (the cloud keeps only the op log and verdicts).
	NoState bool
	// MaxAhead bounds the clock drift an observed stamp may drag the local clock by.
	MaxAhead time.Duration
}

// Engine is one node's op store logic. All writes go through one mutex and one transaction,
// the single-writer path of ADR-0007 C2.
type Engine struct {
	cfg Config
	mu  sync.Mutex
	st  *State
}

// New builds an engine; call Open before use.
func New(cfg Config) *Engine {
	if cfg.MaxAhead == 0 {
		cfg.MaxAhead = 10 * time.Minute
	}
	e := &Engine{cfg: cfg}
	if !cfg.NoState {
		e.st = NewState()
	}
	return e
}

// Config returns the engine configuration.
func (e *Engine) Config() Config { return e.cfg }

// State returns the materialised state (nil when NoState).
func (e *Engine) State() *State { return e.st }

// SetOrigin switches the node's own origin (the cloud, after a restore, opens cloud-<epoch>).
func (e *Engine) SetOrigin(o string) { e.mu.Lock(); e.cfg.Origin = o; e.mu.Unlock() }

// Open rebuilds the materialised state from the durable op log. Apply is idempotent and
// state is a function of the op set, so a crash at any point leaves nothing to repair.
func (e *Engine) Open(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.st == nil {
		return nil
	}
	e.st = NewState()
	var last sp.HLC
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		var after int64
		var voidOps []repository.OpRec
		var all []repository.OpRec
		for {
			page, err := tx.ByArrival(after, 2000)
			if err != nil {
				return err
			}
			if len(page) == 0 {
				break
			}
			after = page[len(page)-1].Arr
			all = append(all, page...)
		}
		for _, r := range all {
			if r.Intent == sp.IntentVoid && appliesLocally(r) {
				voidOps = append(voidOps, r)
			}
		}
		for _, r := range voidOps {
			if p, err := sp.DecodeBody(r.Body); err == nil {
				e.applyVoid(p)
			}
		}
		for _, r := range all {
			if !appliesLocally(r) {
				continue
			}
			p, err := sp.DecodeBody(r.Body)
			if err != nil {
				continue
			}
			e.applyBody(p)
			if r.Origin == e.cfg.Origin {
				if h, err := sp.ParseHLC(r.HLC); err == nil && h > last {
					last = h
				}
			}
		}
		return nil
	})
	if last > 0 {
		e.cfg.Clock.Restore(last)
	}
	return err
}

func appliesLocally(r repository.OpRec) bool {
	return r.Body != "" && (r.Status == repository.StAccepted || r.Status == repository.StFlagged)
}

func (e *Engine) applyVoid(b sp.Body) {
	for _, m := range b.Muts {
		if m.E == "sync_void" && m.K == sp.KInsert {
			o, _ := m.F["origin"].(string)
			s, _ := m.F["stream"].(string)
			q, _ := m.F["seq"].(int64)
			e.st.Void(sp.Ref{Origin: o, Stream: s, Seq: q})
		}
	}
}

// applyBody applies a decoded op to the state (caller holds e.mu).
func (e *Engine) applyBody(b sp.Body) {
	if e.st == nil {
		return
	}
	h, _ := sp.ParseHLC(b.HLC)
	e.st.Apply(sp.Ref{Origin: b.Origin, Stream: b.Stream, Seq: b.Seq}, h, b.Muts)
	if b.Intent == sp.IntentVoid {
		e.applyVoid(b)
	}
}

// Input is a local operation to record.
type Input struct {
	Stream   string
	Intent   string
	IntentV  int
	Actor    string
	SID      string
	PackV    string
	Approval string
	Proof    string
	// DocType allocates the next legal number of the device's series for this document type.
	DocType string
	// Muts builds the mutations; number is the allocated legal number (empty without DocType).
	Muts []sp.Mut
	// MutsFn is used instead of Muts when the mutations embed the number.
	MutsFn func(number string) []sp.Mut
	PII    json.RawMessage
	Clk    string
	// At overrides the op time (tests of clock skew); zero means the engine clock.
	At time.Time
}

// ErrNoSeries is returned when a number is requested for a document type with no series.
var ErrNoSeries = errors.New("engine: no series for document type")

// Record writes one op of this node's own origin: seq, ph, hlc, number and the op are allocated
// in one transaction (S4), then the op is applied locally.
func (e *Engine) Record(ctx context.Context, in Input) (sp.Item, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var item sp.Item
	var body sp.Body
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		var err error
		item, body, err = e.recordTx(tx, in)
		return err
	})
	if err != nil {
		return sp.Item{}, err
	}
	e.applyBody(body)
	return item, nil
}

// RecordTx is Record inside an existing transaction (the gateway emits voids in the verdict
// transaction). The caller applies nothing: the cloud keeps no state.
func (e *Engine) RecordTx(tx repository.Tx, in Input) (sp.Item, error) {
	it, _, err := e.recordTx(tx, in)
	return it, err
}

// IST is UTC+05:30, the zone of the invoice date (S7).
var IST = time.FixedZone("IST", 5*3600+1800)

// FY returns the financial year of t in IST as four digits, 2026-27 -> "2627" (S7).
func FY(t time.Time) string {
	t = t.In(IST)
	y := t.Year()
	if t.Month() < time.April {
		y--
	}
	return fmt.Sprintf("%02d%02d", y%100, (y+1)%100)
}

// FormatNumber renders <code>/<FY>/<running> (S7), at most 16 characters.
func FormatNumber(code, fy string, n int64) string { return fmt.Sprintf("%s/%s/%06d", code, fy, n) }

func (e *Engine) recordTx(tx repository.Tx, in Input) (sp.Item, sp.Body, error) {
	origin := e.cfg.Origin
	if origin == "" || e.cfg.Key == nil {
		return sp.Item{}, sp.Body{}, errors.New("engine: node has no origin or key")
	}
	seq, headH, err := tx.Head(in.Stream, origin)
	if err != nil {
		return sp.Item{}, sp.Body{}, err
	}
	ph := headH
	if seq == 0 {
		ph = sp.GenesisHash(origin, in.Stream)
	}
	at := in.At
	if at.IsZero() {
		at = e.cfg.Clock.Time()
	}
	b := sp.Body{
		V: 1, Origin: origin, Stream: in.Stream, Seq: seq + 1, PH: ph, HLC: e.cfg.Clock.Next().String(), Clk: in.Clk,
		TenantID: e.cfg.Tenant, Actor: in.Actor, SID: in.SID, PackV: in.PackV, Approval: in.Approval, Proof: in.Proof,
		Intent: in.Intent, IntentV: in.IntentV, At: at.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if b.Clk == "" {
		b.Clk = sp.ClkSync
	}
	if b.IntentV == 0 {
		b.IntentV = 1
	}
	number := ""
	if in.DocType != "" {
		if e.cfg.Series == nil {
			return sp.Item{}, sp.Body{}, ErrNoSeries
		}
		code, ok := e.cfg.Series.Code(in.DocType)
		if !ok {
			return sp.Item{}, sp.Body{}, ErrNoSeries
		}
		fy := FY(at)
		n, err := tx.NextNumber(code, fy)
		if err != nil {
			return sp.Item{}, sp.Body{}, err
		}
		number = FormatNumber(code, fy, n)
		b.Doc = &sp.Doc{Type: in.DocType, Number: number}
	}
	b.Muts = in.Muts
	if in.MutsFn != nil {
		b.Muts = in.MutsFn(number)
	}
	item, err := sp.NewItem(b, in.PII)
	if err != nil {
		return sp.Item{}, sp.Body{}, err
	}
	// Re-decode so the applied body is exactly what peers will derive from the bytes.
	body, err := sp.DecodeBody(item.Body)
	if err != nil {
		return sp.Item{}, sp.Body{}, err
	}
	rec := repository.OpRec{Tenant: e.cfg.Tenant, Stream: in.Stream, Origin: origin, Seq: b.Seq, H: item.H, PH: ph, Body: item.Body,
		Status: repository.StAccepted, Intent: b.Intent, HLC: b.HLC}
	if err := tx.PutOp(rec); err != nil {
		return sp.Item{}, sp.Body{}, err
	}
	if len(in.PII) > 0 {
		if err := tx.PutPII(in.Stream, origin, b.Seq, string(in.PII)); err != nil {
			return sp.Item{}, sp.Body{}, err
		}
	}
	if b.Intent == sp.IntentSessionOpen {
		for _, m := range b.Muts {
			if m.E == "session" {
				st, _ := m.F["type"].(string)
				if err := tx.PutSession(origin, m.ID, st); err != nil {
					return sp.Item{}, sp.Body{}, err
				}
			}
		}
	}
	return item, body, nil
}

// SealHead signs the head of this node's own origin in stream, if it has no seal there yet.
// It returns the seal at the head.
func (e *Engine) SealHead(ctx context.Context, stream string) (sp.Seal, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out sp.Seal
	var ok bool
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		var err error
		out, ok, err = e.sealAt(tx, stream, e.cfg.Origin, 0)
		return err
	})
	return out, ok, err
}

// sealAt returns (creating it if needed, for own origin) the seal at seq; seq 0 means the head.
func (e *Engine) sealAt(tx repository.Tx, stream, origin string, seq int64) (sp.Seal, bool, error) {
	if seq == 0 {
		head, _, err := tx.Head(stream, origin)
		if err != nil || head == 0 {
			return sp.Seal{}, false, err
		}
		seq = head
	}
	if kid, sig, h, ok, err := tx.GetSeal(stream, origin, seq); err != nil {
		return sp.Seal{}, false, err
	} else if ok {
		return sp.Seal{Origin: origin, Stream: stream, Seq: seq, H: h, Kid: kid, Sig: sig}, true, nil
	}
	if origin != e.cfg.Origin || e.cfg.Key == nil {
		return sp.Seal{}, false, nil
	}
	rec, ok, err := tx.GetOp(stream, origin, seq)
	if err != nil || !ok {
		return sp.Seal{}, false, err
	}
	s, err := sp.MakeSeal(e.cfg.Key, origin, stream, seq, rec.H)
	if err != nil {
		return sp.Seal{}, false, err
	}
	if err := tx.PutSeal(stream, origin, seq, rec.H, s.Kid, s.Sig); err != nil {
		return sp.Seal{}, false, err
	}
	return s, true, nil
}

// StoreSeal keeps a seal made while a key still existed (A1.3 item 8); a device calls it every
// 5 minutes while it holds unpushed ops, whether or not an upstream is reachable.
func (e *Engine) StoreSeals(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		heads, err := tx.Heads()
		if err != nil {
			return err
		}
		for _, h := range heads {
			if h.Origin == e.cfg.Origin {
				if _, _, err := e.sealAt(tx, h.Stream, h.Origin, 0); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// Vector returns the highest contiguous seq per (origin, stream).
func (e *Engine) Vector(ctx context.Context) (sp.Vector, error) {
	v := sp.Vector{}
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		hs, err := tx.Heads()
		if err != nil {
			return err
		}
		for _, h := range hs {
			v[sp.VKey(h.Origin, h.Stream)] = h.Seq
		}
		return nil
	})
	return v, err
}

// StateHash is the canonical state hash (empty for a NoState engine).
func (e *Engine) StateHash() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.st == nil {
		return ""
	}
	return e.st.Hash()
}

// WithState runs fn on the state under the engine lock.
func (e *Engine) WithState(fn func(*State)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.st != nil {
		fn(e.st)
	}
}

// OutboundOpts controls what a node offers upstream.
type OutboundOpts struct {
	// Limit caps the ops in one batch (default 500).
	Limit int
	// Others allows relaying ops of other origins (a hub always; a device only for re-offer).
	Others bool
	// Streams restricts the streams offered.
	Streams []string
}

// Outbound builds the push for an upstream whose vector is up: for each (origin, stream) the ops
// above the upstream's entry, ending at a seal. A node seals its own head before offering it.
func (e *Engine) Outbound(ctx context.Context, up sp.Vector, o OutboundOpts) (sp.PushRequest, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if o.Limit == 0 {
		o.Limit = 500
	}
	var req sp.PushRequest
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		heads, err := tx.Heads()
		if err != nil {
			return err
		}
		budget := o.Limit
		for _, h := range heads {
			if budget <= 0 {
				break
			}
			if len(o.Streams) > 0 && !contains(o.Streams, h.Stream) {
				continue
			}
			own := h.Origin == e.cfg.Origin
			if !own && !o.Others {
				continue
			}
			after := up[sp.VKey(h.Origin, h.Stream)]
			if h.Seq <= after {
				continue
			}
			upto := h.Seq
			if upto-after > int64(budget) {
				upto = after + int64(budget)
			}
			var seal sp.Seal
			if own {
				s, ok, err := e.sealAt(tx, h.Stream, h.Origin, upto)
				if err != nil || !ok {
					return err
				}
				seal = s
			} else {
				// A relay offers only what a seal covers.
				seals, err := tx.SealSeqs(h.Stream, h.Origin, after)
				if err != nil {
					return err
				}
				var cut int64
				for _, sq := range seals {
					if sq <= upto {
						cut = sq
					}
				}
				if cut == 0 && len(seals) > 0 && seals[0] > upto {
					cut = seals[0] // exceed the soft cap to reach the first seal
				}
				if cut == 0 {
					continue
				}
				upto = cut
				kid, sig, sh, ok, err := tx.GetSeal(h.Stream, h.Origin, cut)
				if err != nil || !ok {
					return err
				}
				seal = sp.Seal{Origin: h.Origin, Stream: h.Stream, Seq: cut, H: sh, Kid: kid, Sig: sig}
			}
			recs, err := tx.Range(h.Stream, h.Origin, after, upto, int(upto-after))
			if err != nil {
				return err
			}
			n := 0
			for _, r := range recs {
				if r.Body == "" {
					break // cannot offer a slot known only by hash; the body holder must
				}
				req.Items = append(req.Items, sp.Item{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq, H: r.H, Body: r.Body})
				n++
			}
			if n == 0 {
				continue
			}
			if int64(n) != upto-after {
				// Cut at the last contiguous op with a body: seal that op instead.
				last := recs[n-1].Seq
				if own {
					s, ok, err := e.sealAt(tx, h.Stream, h.Origin, last)
					if err != nil || !ok {
						return err
					}
					seal = s
				} else {
					kid, sig, sh, ok, err := tx.GetSeal(h.Stream, h.Origin, last)
					if err != nil {
						return err
					}
					if !ok {
						req.Items = req.Items[:len(req.Items)-n]
						continue
					}
					seal = sp.Seal{Origin: h.Origin, Stream: h.Stream, Seq: last, H: sh, Kid: kid, Sig: sig}
				}
			}
			req.Seals = append(req.Seals, seal)
			budget -= n
		}
		return nil
	})
	return req, err
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// IngestReq is a batch of slots arriving from a peer.
type IngestReq struct {
	Items        []sp.Item
	Seals        []sp.Seal
	Attestations []sp.Attestation
	Caller       Caller
	// FromUpstream marks a pull response: placeholders are allowed and trailing placeholders need no seal.
	FromUpstream bool
	// Recovery marks a quarantine-upload.
	Recovery bool
}

// IngestRes is what the batch did.
type IngestRes struct {
	Vector  sp.Vector
	Held    []sp.HeldSlot
	Refused []sp.Refusal
	New     []repository.OpRec
	// Drained is true when every group of a recovery upload reached its attested seq.
	Drained bool
}

type group struct {
	origin, stream string
	items          []sp.Item
}

func groupItems(items []sp.Item) []*group {
	idx := map[string]*group{}
	var out []*group
	for _, it := range items {
		k := sp.VKey(it.Origin, it.Stream)
		g := idx[k]
		if g == nil {
			g = &group{origin: it.Origin, stream: it.Stream}
			idx[k] = g
			out = append(out, g)
		}
		g.items = append(g.items, it)
	}
	return out
}

// HoldCode maps a quarantine reason to the coarse code a device may be told (A1.2).
func HoldCode(reason string) string {
	switch reason {
	case "config_pending":
		return sp.HoldPending
	case "chain_broken", "foreign_series", "fork":
		return sp.HoldSupport
	default:
		return sp.HoldManager
	}
}

// Ingest verifies and stores a batch. It is the one place where chain, seal and verdicts meet.
func (e *Engine) Ingest(ctx context.Context, req IngestReq) (IngestRes, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	res := IngestRes{Vector: sp.Vector{}}
	var applyList []sp.Body
	var observed []sp.HLC
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		res = IngestRes{Vector: sp.Vector{}}
		applyList, observed = nil, nil
		sealIdx := map[string]sp.Seal{}
		for _, s := range req.Seals {
			sealIdx[s.Origin+"/"+s.Stream+"/"+fmt.Sprint(s.Seq)] = s
		}
		attIdx := map[string]sp.Attestation{}
		for _, a := range req.Attestations {
			attIdx[sp.VKey(a.Origin, a.Stream)] = a
		}
		allDrained := req.Recovery
		for _, g := range groupItems(req.Items) {
			drained, err := e.ingestGroup(tx, req, g, sealIdx, attIdx, &res, &applyList, &observed)
			if err != nil {
				return err
			}
			if !drained {
				allDrained = false
			}
		}
		res.Drained = allDrained && len(attIdx) > 0
		return nil
	})
	if err != nil {
		return IngestRes{}, err
	}
	for _, b := range applyList {
		e.applyBody(b)
	}
	for _, h := range observed {
		e.cfg.Clock.Observe(h, e.cfg.MaxAhead)
	}
	return res, nil
}

func (e *Engine) ingestGroup(tx repository.Tx, req IngestReq, g *group, seals map[string]sp.Seal, atts map[string]sp.Attestation,
	res *IngestRes, apply *[]sp.Body, observed *[]sp.HLC) (bool, error) {

	refuse := func(from int, reason string) {
		for _, it := range g.items[from:] {
			res.Refused = append(res.Refused, sp.Refusal{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq, Reason: reason})
		}
	}
	if h := e.cfg.Hooks.Authorize; h != nil {
		if reason := h(tx, req.Caller, g.origin, g.stream, req.Recovery); reason != "" {
			refuse(0, reason)
			return false, nil
		}
	}
	head, headH, err := tx.Head(g.stream, g.origin)
	if err != nil {
		return false, err
	}
	res.Vector[sp.VKey(g.origin, g.stream)] = head
	// Skip slots already held; note releases and forks.
	items := g.items[:0:0]
	for _, it := range g.items {
		if it.Seq > head {
			items = append(items, it)
			continue
		}
		rec, ok, err := tx.GetOp(g.stream, g.origin, it.Seq)
		if err != nil {
			return false, err
		}
		if !ok {
			continue
		}
		switch {
		case rec.H != it.H:
			if !it.IsPlaceholder() && e.cfg.Hooks.OnFork != nil {
				if err := e.cfg.Hooks.OnFork(tx, req.Caller, rec, it); err != nil {
					return false, err
				}
			}
			if !it.IsPlaceholder() && !req.FromUpstream {
				res.Refused = append(res.Refused, sp.Refusal{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq, Reason: sp.ReasonFork})
			}
		case rec.Status == repository.StPlaceholder && !it.IsPlaceholder() && req.FromUpstream:
			// A released op reaching a node that held only its slot (RB3).
			if sp.Hash(it.Body) != rec.H {
				continue
			}
			b, err := sp.DecodeBody(it.Body)
			if err != nil {
				continue
			}
			rec.Body, rec.Status, rec.Intent, rec.HLC = it.Body, repository.StAccepted, b.Intent, b.HLC
			if err := tx.UpdateOp(rec); err != nil {
				return false, err
			}
			res.New = append(res.New, rec)
			*apply = append(*apply, b)
		}
	}
	if len(items) == 0 {
		return e.groupDrained(tx, g, head, atts)
	}
	// Contiguity.
	if items[0].Seq != head+1 {
		g.items = items
		refuse(0, sp.ReasonGap)
		return false, nil
	}
	for i := range items {
		if items[i].Seq != head+1+int64(i) {
			items = items[:i]
			break
		}
	}
	g.items = items
	pub, hasKey := e.cfg.Trust.OriginKey(g.origin)
	if !hasKey {
		refuse(0, sp.ReasonOrigin)
		return false, nil
	}
	if !req.FromUpstream {
		for _, it := range items {
			if it.IsPlaceholder() {
				refuse(0, sp.ReasonFramed)
				return false, nil
			}
		}
	}
	// Walk the chain; find the highest op covered by a valid seal.
	prevH := headH
	if head == 0 {
		prevH = sp.GenesisHash(g.origin, g.stream)
	}
	type step struct {
		p      *Parsed
		ph     string
		sealed bool
	}
	steps := make([]step, 0, len(items))
	chainOK := true
	covered := 0 // number of leading items covered by a valid seal at the last of them
	for i, it := range items {
		if it.IsPlaceholder() {
			if !req.FromUpstream {
				chainOK = false
				break
			}
			steps = append(steps, step{p: &Parsed{Item: it}})
			prevH = it.H
			continue
		}
		if sp.Hash(it.Body) != it.H {
			chainOK = false
			break
		}
		b, derr := sp.DecodeBody(it.Body)
		if derr != nil {
			steps = append(steps, step{p: &Parsed{Item: it, Opaque: true}})
			prevH = it.H
			continue
		}
		if b.Origin != it.Origin || b.Stream != it.Stream || b.Seq != it.Seq || b.PH != prevH {
			chainOK = false
			break
		}
		steps = append(steps, step{p: &Parsed{Item: it, Body: b}, ph: b.PH})
		prevH = it.H
		if s, ok := seals[it.Origin+"/"+it.Stream+"/"+fmt.Sprint(it.Seq)]; ok && s.H == it.H && s.Verify(pub) {
			covered = i + 1
			steps[i].sealed = true
		}
	}
	// Trailing placeholders from the cloud need no seal.
	if req.FromUpstream && chainOK {
		j := len(steps)
		for j > covered && steps[j-1].p.Item.IsPlaceholder() {
			j--
		}
		if j == covered {
			covered = len(steps)
		}
	}
	// An attestation fixes an unsealed tail (A1.3): ops after the last seal up to the attested seq.
	attTail := 0
	if att, ok := atts[sp.VKey(g.origin, g.stream)]; ok && chainOK && req.Recovery && len(items) > 0 {
		last := att.Seq
		if end := items[len(items)-1].Seq; end < last {
			last = end
		}
		if idx := int(last - items[0].Seq); idx >= 0 && idx < len(steps) && idx+1 > covered {
			if last != att.Seq || steps[idx].p.Item.H == att.H {
				attTail = idx + 1
			}
		}
	}
	good := covered
	if attTail > good {
		good = attTail
	}
	// Ops past what is covered: an authenticated origin's own are stored as chain-broken (N-4),
	// anyone else's are refused.
	if good < len(items) {
		if e.cfg.Hooks.QuarantineOwnUnverified && (req.Caller.ID == g.origin || (req.Recovery && req.Caller.Recovers == g.origin)) {
			// stored below with ChainBroken set
		} else {
			reason := sp.ReasonChain
			if chainOK {
				reason = sp.ReasonUnsealed
				last := items[len(items)-1]
				if _, ok := seals[last.Origin+"/"+last.Stream+"/"+fmt.Sprint(last.Seq)]; ok {
					reason = sp.ReasonSeal
				}
			}
			refuse(good, reason)
			items = items[:good]
		}
	}
	own := req.Caller.ID == g.origin
	for i, it := range items {
		rec := repository.OpRec{Tenant: e.cfg.Tenant, Stream: g.stream, Origin: g.origin, Seq: it.Seq, H: it.H}
		if it.IsPlaceholder() {
			rec.Status = repository.StPlaceholder
			if err := tx.PutOp(rec); err != nil {
				return false, err
			}
			res.New = append(res.New, rec)
			continue
		}
		var p *Parsed
		sealed := false
		if i < len(steps) {
			p, rec.PH, sealed = steps[i].p, steps[i].ph, steps[i].sealed
		} else {
			p = &Parsed{Item: it, Opaque: true}
			if b, err := sp.DecodeBody(it.Body); err == nil {
				p.Body, p.Opaque = b, false
			}
		}
		rec.Body = it.Body
		if !p.Opaque {
			rec.Intent, rec.HLC = p.Body.Intent, p.Body.HLC
		}
		v := Verdict{Status: repository.StAccepted}
		if e.cfg.Hooks.Verdict != nil {
			v = e.cfg.Hooks.Verdict(tx, p, VerdictCtx{Caller: req.Caller, Own: own, Recovery: req.Recovery,
				Sealed: i < covered, Unsealed: i >= covered && i < good, ChainBroken: i >= good})
		}
		// Seals that verified are kept and served with the ops.
		if sl, ok := seals[it.Origin+"/"+it.Stream+"/"+fmt.Sprint(it.Seq)]; ok && sealed {
			if err := tx.PutSeal(it.Stream, it.Origin, it.Seq, sl.H, sl.Kid, sl.Sig); err != nil {
				return false, err
			}
		}
		if err := e.storeOp(tx, &rec, &p.Body, v, res, apply, observed, p); err != nil {
			return false, err
		}
		if len(it.PII) > 0 {
			if err := tx.PutPII(it.Stream, it.Origin, it.Seq, string(it.PII)); err != nil {
				return false, err
			}
		}
	}
	if n := len(items); n > 0 {
		res.Vector[sp.VKey(g.origin, g.stream)] = items[n-1].Seq
	}
	return e.groupDrained(tx, g, res.Vector[sp.VKey(g.origin, g.stream)], atts)
}

func (e *Engine) groupDrained(tx repository.Tx, g *group, head int64, atts map[string]sp.Attestation) (bool, error) {
	a, ok := atts[sp.VKey(g.origin, g.stream)]
	if !ok {
		return false, nil
	}
	if head >= a.Seq {
		return true, nil
	}
	return false, nil
}

// storeOp writes one slot with its verdict and runs the in-transaction hooks.
func (e *Engine) storeOp(tx repository.Tx, rec *repository.OpRec, b *sp.Body, v Verdict, res *IngestRes, apply *[]sp.Body, observed *[]sp.HLC, p *Parsed) error {
	rec.Status, rec.Reason = v.Status, v.Reason
	rec.Marks = strings.Join(v.Marks, ",")
	if err := tx.PutOp(*rec); err != nil {
		return err
	}
	res.New = append(res.New, *rec)
	if v.Status == repository.StQuarantined {
		res.Held = append(res.Held, sp.HeldSlot{Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq, Code: HoldCode(v.Reason)})
	}
	if rec.Intent == sp.IntentSessionOpen && b != nil && !p.Opaque {
		for _, m := range b.Muts {
			if m.E == "session" {
				st, _ := m.F["type"].(string)
				if err := tx.PutSession(rec.Origin, m.ID, st); err != nil {
					return err
				}
			}
		}
	}
	if e.cfg.Hooks.Stored != nil {
		if err := e.cfg.Hooks.Stored(tx, e, *rec, p, v); err != nil {
			return err
		}
	}
	if (v.Status == repository.StAccepted || v.Status == repository.StFlagged) && b != nil && !p.Opaque {
		*apply = append(*apply, *b)
		if h, err := sp.ParseHLC(b.HLC); err == nil {
			*observed = append(*observed, h)
		}
	}
	return nil
}

// ServeOpts scopes a pull to what the caller may see.
type ServeOpts struct {
	Caller Caller
	// Streams the caller is bound to (empty means all).
	Streams []string
	// IsHub: the caller relays others' origins and gets RelayHeld.
	IsHub bool
}

// Serve answers a pull: slots above the caller's vector, up to a seal boundary, quarantined and
// voided slots as placeholders, plus released ops for slots the caller holds as placeholders.
func (e *Engine) Serve(ctx context.Context, req sp.PullRequest, o ServeOpts, creds func(origin string) (sp.CredentialEnvelope, bool)) (sp.PullResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	limit := req.Limit
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	resp := sp.PullResponse{Items: []sp.Item{}, OwnHeld: []sp.HeldSlot{}}
	seen := map[string]bool{}
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		heads, err := tx.Heads()
		if err != nil {
			return err
		}
		budget := limit
		for _, h := range heads {
			streams := req.Streams
			if len(streams) == 0 {
				streams = o.Streams
			}
			if len(streams) > 0 && !contains(streams, h.Stream) {
				continue
			}
			if len(o.Streams) > 0 && !contains(o.Streams, h.Stream) {
				continue
			}
			after := req.Vector[sp.VKey(h.Origin, h.Stream)]
			if h.Seq <= after {
				continue
			}
			if budget <= 0 {
				resp.More = true
				continue
			}
			recs, boundSeal, more, err := e.serveRange(tx, h, after, budget)
			if err != nil {
				return err
			}
			if more {
				resp.More = true
			}
			for _, r := range recs {
				it := sp.Item{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq, H: r.H}
				if r.Body != "" && (r.Status == repository.StAccepted || r.Status == repository.StFlagged) {
					it.Body = r.Body
				}
				resp.Items = append(resp.Items, it)
				budget--
			}
			if len(recs) > 0 {
				if boundSeal != nil {
					resp.Seals = append(resp.Seals, *boundSeal)
				}
				if !seen[h.Origin] {
					seen[h.Origin] = true
					if c, ok := creds(h.Origin); ok {
						resp.Creds = append(resp.Creds, c)
					}
				}
			}
		}
		// Released ops for slots the caller holds as placeholders.
		for _, r := range req.Placeholders {
			rec, ok, err := tx.GetOp(r.Stream, r.Origin, r.Seq)
			if err != nil {
				return err
			}
			if ok && rec.Body != "" && (rec.Status == repository.StAccepted || rec.Status == repository.StFlagged) {
				resp.Items = append(resp.Items, sp.Item{Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq, H: rec.H, Body: rec.Body})
				if !seen[rec.Origin] {
					seen[rec.Origin] = true
					if c, ok := creds(rec.Origin); ok {
						resp.Creds = append(resp.Creds, c)
					}
				}
			}
		}
		// Own held list (A1.2): the complete current set.
		held, err := tx.ByStatus(repository.StQuarantined)
		if err != nil {
			return err
		}
		for _, r := range held {
			slot := sp.HeldSlot{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq, Code: HoldCode(r.Reason)}
			if r.Origin == o.Caller.ID {
				resp.OwnHeld = append(resp.OwnHeld, slot)
			}
			if o.IsHub && r.Origin != o.Caller.ID {
				resp.RelayHeld = append(resp.RelayHeld, slot)
			}
		}
		return nil
	})
	return resp, err
}

// serveRange picks the slots of one (stream, origin) to serve: up to a seal boundary (so every
// full op is covered by a seal the puller can check), plus trailing placeholders.
func (e *Engine) serveRange(tx repository.Tx, h repository.HeadRow, after int64, budget int) ([]repository.OpRec, *sp.Seal, bool, error) {
	seals, err := tx.SealSeqs(h.Stream, h.Origin, after)
	if err != nil {
		return nil, nil, false, err
	}
	var cut int64
	for _, s := range seals {
		if s-after <= int64(budget) {
			cut = s
		}
	}
	if cut == 0 && len(seals) > 0 {
		cut = seals[0] // exceed the soft cap to reach the first seal: a batch is never unverifiable
	}
	var recs []repository.OpRec
	var seal *sp.Seal
	more := false
	if cut > 0 {
		recs, err = tx.Range(h.Stream, h.Origin, after, cut, int(cut-after))
		if err != nil {
			return nil, nil, false, err
		}
		kid, sig, sh, ok, err := tx.GetSeal(h.Stream, h.Origin, cut)
		if err != nil {
			return nil, nil, false, err
		}
		if ok {
			seal = &sp.Seal{Origin: h.Origin, Stream: h.Stream, Seq: cut, H: sh, Kid: kid, Sig: sig}
		}
		if cut < h.Seq {
			more = true
		}
	}
	// Trailing slots with no body served (quarantined / voided) need no seal.
	if cut == 0 || cut == seals[len(seals)-1] {
		start := cut
		if start == 0 {
			start = after
		}
		tail, err := tx.Range(h.Stream, h.Origin, start, h.Seq, 500)
		if err != nil {
			return nil, nil, false, err
		}
		for _, r := range tail {
			if r.Status == repository.StAccepted || r.Status == repository.StFlagged {
				break // an unsealed full op is never served
			}
			recs = append(recs, r)
		}
	}
	return recs, seal, more, nil
}

// Held lists the quarantined slots of one origin.
func (e *Engine) Held(ctx context.Context, origin string) ([]sp.HeldSlot, error) {
	var out []sp.HeldSlot
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		recs, err := tx.ByStatus(repository.StQuarantined)
		if err != nil {
			return err
		}
		for _, r := range recs {
			if origin == "" || r.Origin == origin {
				out = append(out, sp.HeldSlot{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq, Code: HoldCode(r.Reason)})
			}
		}
		return nil
	})
	return out, err
}

// Promote releases hub-held ops (structural check failed, S8) once the cloud holds them without
// holding them back: the cloud's verdict is authoritative, so an op it accepted may now be relayed
// to peers and applied here. It returns the number promoted.
func (e *Engine) Promote(ctx context.Context, up sp.Vector, held []sp.HeldSlot) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	heldSet := map[string]bool{}
	for _, h := range held {
		heldSet[sp.Ref{Origin: h.Origin, Stream: h.Stream, Seq: h.Seq}.Key()] = true
	}
	var apply []sp.Body
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		apply = nil
		recs, err := tx.ByStatus(repository.StHeldLocal)
		if err != nil {
			return err
		}
		for _, r := range recs {
			ref := sp.Ref{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq}
			if up[sp.VKey(r.Origin, r.Stream)] < r.Seq || heldSet[ref.Key()] {
				continue
			}
			b, err := sp.DecodeBody(r.Body)
			if err != nil {
				continue
			}
			r.Status = repository.StAccepted
			if err := tx.UpdateOp(r); err != nil {
				return err
			}
			apply = append(apply, b)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for _, b := range apply {
		e.applyBody(b)
	}
	return len(apply), nil
}

// RecoveryUpload builds the upload of a key-lost origin's unconfirmed ops (A1.3 item 4): every op
// above the cloud's vector in each stream, the stored seals, and one attestation per stream made
// by attest (signed with the adopting device's new key).
func (e *Engine) RecoveryUpload(ctx context.Context, old string, up sp.Vector, limit int, attest func(stream string, seq int64, h string) (sp.Attestation, error)) (sp.PushRequest, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit <= 0 {
		limit = 500
	}
	var req sp.PushRequest
	err := e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error {
		heads, err := tx.Heads()
		if err != nil {
			return err
		}
		for _, h := range heads {
			if h.Origin != old {
				continue
			}
			after := up[sp.VKey(old, h.Stream)]
			headRec, ok, err := tx.GetOp(h.Stream, old, h.Seq)
			if err != nil || !ok {
				return err
			}
			a, err := attest(h.Stream, h.Seq, headRec.H)
			if err != nil {
				return err
			}
			req.Attestations = append(req.Attestations, a)
			if h.Seq <= after {
				continue
			}
			recs, err := tx.Range(h.Stream, old, after, h.Seq, limit)
			if err != nil {
				return err
			}
			last := after
			for _, r := range recs {
				req.Items = append(req.Items, sp.Item{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq, H: r.H, Body: r.Body})
				last = r.Seq
			}
			seals, err := tx.SealSeqs(h.Stream, old, after)
			if err != nil {
				return err
			}
			for _, sq := range seals {
				if sq > last {
					break
				}
				kid, sig, sh, ok, err := tx.GetSeal(h.Stream, old, sq)
				if err != nil {
					return err
				}
				if ok {
					req.Seals = append(req.Seals, sp.Seal{Origin: old, Stream: h.Stream, Seq: sq, H: sh, Kid: kid, Sig: sig})
				}
			}
			break // one batch per call; the caller loops until drained
		}
		return nil
	})
	return req, err
}
