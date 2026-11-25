package engine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
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

// RecoveryTrust is what a node needs to check seals of cloud origins and endorsements (A2.1).
// CredCache (hub, device) and the gateway's trust implement it.
type RecoveryTrust interface {
	// OpKey returns the current gateway op-signing key named by kid; false if unknown or revoked.
	OpKey(kid string) (*ecdsa.PublicKey, bool)
	// Recoverers returns the identity-verified credentials that carry `recovers: origin`.
	Recoverers(origin string) []sp.CredentialEnvelope
}

// MarkUnsealed is the audit mark of an op accepted without an origin seal (A1.3 item 6, A2.1 item 4).
const MarkUnsealed = "unsealed"

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
	// PIIDropped counts pii fields of the item that did not match their commitment (syncproto/piic.go);
	// Item.PII holds only the verified fields once the node has opened it.
	PIIDropped int
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
	// Endorsed: no seal covers it, but a gateway endorsement with the recovery credential and the
	// adopting device's attestation does (A2.1). The op is a released unsealed-tail op.
	Endorsed bool
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
	// endorsed is true when the batch carries an endorsement for the group (A2.1 item 5).
	Authorize func(tx repository.Tx, c Caller, origin, stream string, recovery, endorsed bool) string
	// Verdict judges an op that passed chain and seal checks (or was stored as chain-broken).
	Verdict func(tx repository.Tx, p *Parsed, vc VerdictCtx) Verdict
	// QuarantineOwnUnverified stores an authenticated origin's own unverifiable ops in quarantine
	// instead of refusing them (N-4). Cloud only.
	QuarantineOwnUnverified bool
	// Stored runs in the storing transaction for each new op (outbox, register, void emission).
	Stored func(tx repository.Tx, e *Engine, rec repository.OpRec, p *Parsed, v Verdict) error
	// OnFork is told about a slot whose stored content differs from what arrived.
	OnFork func(tx repository.Tx, c Caller, rec repository.OpRec, it sp.Item) error
	// OnEndorsed is told about a quarantined slot that a node re-offers with a verified
	// endorsement, credential and attestation: the cloud takes it as released (A2.1 item 5).
	OnEndorsed func(tx repository.Tx, rec repository.OpRec, p *Parsed, en sp.Endorsement, att sp.Attestation) error
}

// SeriesSource gives a billing device its legal number series (S7).
type SeriesSource interface {
	// Code returns the series code the device holds for the document type.
	Code(docType string) (string, bool)
}

// Config builds an Engine.
type Config struct {
	// Entropy is the source of pii salts (default crypto/rand); the simulator injects a seeded one.
	Entropy io.Reader
	Role    Role
	Tenant  string
	Outlet  string
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
	PackV    int
	Approval string
	Proof    string
	// PinV accompanies Proof (session.open of a pin session, approval.grant; ADR-0005 A3.1).
	PinV int
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

// InTxLocked runs fn in one transaction of this node's tenant while holding the engine's write lock,
// so that cloud-origin ops recorded in it (emit, erasure) cannot race an ingest for the next seq.
func (e *Engine) InTxLocked(ctx context.Context, fn func(tx repository.Tx) error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.Store.InTx(ctx, e.cfg.Tenant, fn)
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
		TenantID: e.cfg.Tenant, Actor: in.Actor, SID: in.SID, PackV: in.PackV, Approval: in.Approval, Proof: in.Proof, PinV: in.PinV,
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
	var piiWire json.RawMessage
	if len(in.PII) > 0 {
		var values sp.PII
		dec := json.NewDecoder(bytes.NewReader(in.PII))
		dec.UseNumber()
		if err := dec.Decode(&values); err != nil {
			return sp.Item{}, sp.Body{}, fmt.Errorf("engine: pii must be entity -> row id -> field -> value: %w", err)
		}
		for _, rows := range values {
			for _, fields := range rows {
				for k, v := range fields {
					if n, ok := v.(json.Number); ok {
						x, err := n.Int64()
						if err != nil {
							return sp.Item{}, sp.Body{}, fmt.Errorf("engine: pii field %q is not an integer", k)
						}
						fields[k] = x
					}
				}
			}
		}
		var commits sp.PIICommit
		piiWire, commits, err = sp.CommitPII(values, e.cfg.Entropy)
		if err != nil {
			return sp.Item{}, sp.Body{}, err
		}
		b.PIIC = commits
		if err := sp.CheckSize(0, len(piiWire)); err != nil {
			return sp.Item{}, sp.Body{}, err
		}
	}
	item, err := sp.NewItem(b, piiWire)
	if err != nil {
		return sp.Item{}, sp.Body{}, err
	}
	if err := sp.CheckSize(len(item.Body), 0); err != nil {
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
	if len(piiWire) > 0 {
		if err := tx.PutPII(in.Stream, origin, b.Seq, string(piiWire)); err != nil {
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
	// Reoffer is set while the node's re-offer is open (A2.2): endorsed ops the upstream's vector
	// counts are offered again with their endorsements.
	Reoffer bool
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
				// A relay offers only what a seal or an endorsement covers.
				seals, err := boundaries(tx, h.Stream, h.Origin, after)
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
					cut = seals[0] // exceed the soft cap to reach the first boundary
				}
				if cut == 0 {
					continue
				}
				upto = cut
			}
			recs, err := tx.Range(h.Stream, h.Origin, after, upto, int(upto-after))
			if err != nil {
				return err
			}
			n := 0
			for _, r := range recs {
				if r.Body == "" || (!own && hasMarkS(r.Marks, MarkUnbound)) {
					break // cannot offer a slot known only by hash; the body holder must. An unbound op is never relayed (A2.8 item 1.3).
				}
				it := sp.Item{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq, H: r.H, Body: r.Body}
				if pii, ok, err := tx.GetPII(r.Stream, r.Origin, r.Seq); err != nil {
					return err
				} else if ok {
					it.PII = json.RawMessage(pii) // the verified values with their salts; erased ones are gone
				}
				req.Items = append(req.Items, it)
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
					upto = last
				}
			}
			if own {
				req.Seals = append(req.Seals, seal)
			} else {
				b, err := boundAt(tx, h.Stream, h.Origin, after, upto)
				if err != nil {
					return err
				}
				if b == nil {
					req.Items = req.Items[:len(req.Items)-n]
					continue
				}
				req.Seals = append(req.Seals, b.Seals...)
				req.Endorsements = append(req.Endorsements, b.Ends...)
				req.Attestations = append(req.Attestations, b.Atts...)
			}
			budget -= n
		}
		if o.Reoffer {
			return e.reofferEndorsed(tx, up, o, &req)
		}
		return nil
	})
	return req, err
}

// bound is what proves a served or pushed range: the seal at its end, or an endorsement at its end
// with the last origin seal before it and the stored attestations.
type bound struct {
	Seals []sp.Seal
	Ends  []sp.Endorsement
	Atts  []sp.Attestation
}

// boundaries lists, ascending, the seqs above after where a seal or an endorsement exists: the
// points where a relay may cut a batch (A2.1 item 3: an endorsement counts as a seal boundary).
func boundaries(tx repository.Tx, stream, origin string, after int64) ([]int64, error) {
	a, err := tx.SealSeqs(stream, origin, after)
	if err != nil {
		return nil, err
	}
	b, err := tx.EndorsementSeqs(stream, origin, after)
	if err != nil {
		return nil, err
	}
	out := make([]int64, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case j >= len(b) || (i < len(a) && a[i] < b[j]):
			out = append(out, a[i])
			i++
		case i >= len(a) || b[j] < a[i]:
			out = append(out, b[j])
			j++
		default:
			out = append(out, a[i])
			i++
			j++
		}
	}
	return out, nil
}

// boundAt builds the proof for a range ending at cut (after < seq <= cut), or nil if no seal or
// endorsement exists at cut.
func boundAt(tx repository.Tx, stream, origin string, after, cut int64) (*bound, error) {
	if kid, sig, h, ok, err := tx.GetSeal(stream, origin, cut); err != nil {
		return nil, err
	} else if ok {
		return &bound{Seals: []sp.Seal{{Origin: origin, Stream: stream, Seq: cut, H: h, Kid: kid, Sig: sig}}}, nil
	}
	_, ok, err := tx.GetEndorsement(stream, origin, cut)
	if err != nil || !ok {
		return nil, err
	}
	// Every endorsement in the range travels, not only the one at the cut: a node re-offers
	// per op after a cloud restore, and the cloud may have released only some of the tail.
	b := &bound{}
	eseqs, err := tx.EndorsementSeqs(stream, origin, after)
	if err != nil {
		return nil, err
	}
	for _, q := range eseqs {
		if q > cut {
			break
		}
		e, ok, err := tx.GetEndorsement(stream, origin, q)
		if err != nil {
			return nil, err
		}
		if ok {
			b.Ends = append(b.Ends, sp.Endorsement{Origin: origin, Stream: stream, Seq: q, H: e.H, Rec: e.Rec, Kid: e.Kid, Sig: e.Sig})
		}
	}
	// The origin seal before the tail keeps the sealed part of the batch unmarked.
	seals, err := tx.SealSeqs(stream, origin, after)
	if err != nil {
		return nil, err
	}
	var last int64
	for _, s := range seals {
		if s < cut {
			last = s
		}
	}
	if last > 0 {
		if kid, sig, h, ok, err := tx.GetSeal(stream, origin, last); err != nil {
			return nil, err
		} else if ok {
			b.Seals = append(b.Seals, sp.Seal{Origin: origin, Stream: stream, Seq: last, H: h, Kid: kid, Sig: sig})
		}
	}
	atts, err := tx.Attestations(stream, origin)
	if err != nil {
		return nil, err
	}
	for _, a := range atts {
		b.Atts = append(b.Atts, sp.Attestation{Origin: a.Origin, Stream: a.Stream, Seq: a.Seq, H: a.H, By: a.By, Rec: a.Rec, Kid: a.Kid, Sig: a.Sig})
	}
	return b, nil
}

// reofferEndorsed adds, for a node whose re-offer is open (S16 item 4, A2.2), the endorsed ops the
// upstream's vector already counts. The cloud may hold them only as quarantined after a restore;
// the endorsement lets it take them as released without asking the owner again (A2.1 item 5).
func (e *Engine) reofferEndorsed(tx repository.Tx, up sp.Vector, o OutboundOpts, req *sp.PushRequest) error {
	ends, err := tx.Endorsements()
	if err != nil {
		return err
	}
	seenAtt := map[string]bool{}
	var extra []sp.Item
	var extraEnds []sp.Endorsement
	n := 0
	for _, en := range ends {
		if (len(o.Streams) > 0 && !contains(o.Streams, en.Stream)) || en.Seq > up[sp.VKey(en.Origin, en.Stream)] || n >= o.Limit {
			continue
		}
		r, ok, err := tx.GetOp(en.Stream, en.Origin, en.Seq)
		if err != nil {
			return err
		}
		if !ok || r.Body == "" || r.H != en.H || (r.Status != repository.StAccepted && r.Status != repository.StFlagged) {
			continue
		}
		extra = append(extra, sp.Item{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq, H: r.H, Body: r.Body})
		extraEnds = append(extraEnds, sp.Endorsement{Origin: en.Origin, Stream: en.Stream, Seq: en.Seq, H: en.H, Rec: en.Rec, Kid: en.Kid, Sig: en.Sig})
		n++
		k := sp.VKey(en.Origin, en.Stream)
		if !seenAtt[k] {
			seenAtt[k] = true
			atts, err := tx.Attestations(en.Stream, en.Origin)
			if err != nil {
				return err
			}
			for _, a := range atts {
				req.Attestations = append(req.Attestations, sp.Attestation{Origin: a.Origin, Stream: a.Stream, Seq: a.Seq, H: a.H, By: a.By, Rec: a.Rec, Kid: a.Kid, Sig: a.Sig})
			}
		}
	}
	// Extras sit below the upstream's head, so they go first: a group stays in ascending order.
	req.Items = append(extra, req.Items...)
	req.Endorsements = append(req.Endorsements, extraEnds...)
	return nil
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
	Endorsements []sp.Endorsement
	Caller       Caller
	// FromUpstream marks a pull response: placeholders are allowed inside a sealed range.
	FromUpstream bool
	// FromCloud marks the upstream as the cloud itself. Only the cloud may serve a placeholder above
	// an origin's sealed head, and a body taken over a placeholder with no seal comes only from it
	// (A2.8 item 1.1; hubs and peers never).
	FromCloud bool
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
	// StaleCloudSeal: a cloud-origin seal under a key this node does not accept was refused (A2.8 item 2.2).
	StaleCloudSeal bool
}

type group struct {
	origin, stream string
	items          []sp.Item
	ends           map[string]sp.Endorsement // by origin/stream/seq
}

func endKey(origin, stream string, seq int64) string {
	return origin + "/" + stream + "/" + fmt.Sprint(seq)
}

func putAtt(tx repository.Tx, a sp.Attestation) error {
	return tx.PutAttestation(repository.AttestationRec{Stream: a.Stream, Origin: a.Origin, Rec: a.Rec, Seq: a.Seq, H: a.H, By: a.By, Kid: a.Kid, Sig: a.Sig})
}

// endorsedOK applies the verifier rule of A2.1 item 3 to one op: the endorsement verifies under a
// current op-signing key and matches (origin, stream, seq, h); the node holds the identity-signed
// credential of a device Y with `recovers: origin`; and an attestation for (origin, stream) with the
// same rec verifies under Y's key, covers the seq, and agrees with the op held at the attested seq
// (once held). held returns the hash held or in the batch at a seq. It returns the attestation used.
func (e *Engine) endorsedOK(tx repository.Tx, en sp.Endorsement, h string, batchAtts []sp.Attestation, held func(seq int64) (string, bool)) (sp.Attestation, bool) {
	rt, ok := e.cfg.Trust.(RecoveryTrust)
	if !ok || en.H != h || strings.HasPrefix(en.Origin, CloudOriginPrefix) {
		return sp.Attestation{}, false
	}
	key, ok := rt.OpKey(en.Kid)
	if !ok || !en.Verify(key) {
		return sp.Attestation{}, false
	}
	cands := append([]sp.Attestation(nil), batchAtts...)
	if stored, err := tx.Attestations(en.Stream, en.Origin); err == nil {
		for _, a := range stored {
			cands = append(cands, sp.Attestation{Origin: a.Origin, Stream: a.Stream, Seq: a.Seq, H: a.H, By: a.By, Rec: a.Rec, Kid: a.Kid, Sig: a.Sig})
		}
	}
	for _, y := range rt.Recoverers(en.Origin) {
		pub, err := y.Cred.PubKey()
		if err != nil {
			continue
		}
		for _, a := range cands {
			if a.Origin != en.Origin || a.Stream != en.Stream || a.Rec != en.Rec || a.By != y.Cred.DeviceID || en.Seq > a.Seq || !a.Verify(pub) {
				continue
			}
			if hh, have := held(a.Seq); have && hh != a.H {
				continue
			}
			return a, true
		}
	}
	return sp.Attestation{}, false
}

// heldHash returns the hash this node holds, or has in the batch, at a seq of (origin, stream).
func heldHash(tx repository.Tx, g *group, seq int64) (string, bool) {
	for _, it := range g.items {
		if it.Seq == seq {
			return it.H, true
		}
	}
	if r, ok, err := tx.GetOp(g.stream, g.origin, seq); err == nil && ok {
		return r.H, true
	}
	return "", false
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
	// Outlet streams first: a session.open is an outlet op, and the ops of its session in a brand or tenant stream
	// are judged from the stored session row (ADR-0005 A3.1 item 3), so the row must exist when they are judged.
	sort.SliceStable(out, func(i, j int) bool { return streamRank(out[i].stream) < streamRank(out[j].stream) })
	return out
}

func streamRank(stream string) int {
	if strings.HasPrefix(stream, "outlet:") {
		return 0
	}
	return 1
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
		endIdx := map[string]sp.Endorsement{}
		for _, en := range req.Endorsements {
			endIdx[en.Origin+"/"+en.Stream+"/"+fmt.Sprint(en.Seq)] = en
		}
		allDrained := req.Recovery
		for _, g := range groupItems(req.Items) {
			g.ends = endIdx
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
	if res.StaleCloudSeal {
		_ = e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error { return tx.SetMeta(metaStaleSeal, "1") })
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
	if req.FromUpstream {
		if gated, err := conflictGate(tx, g.origin, g.stream, req.FromCloud); err != nil {
			return false, err
		} else if gated {
			refuse(0, sp.ReasonChainConflict) // takes nothing more of this origin from that upstream (A2.8 item 1.4)
			return false, nil
		}
	}
	if h := e.cfg.Hooks.Authorize; h != nil {
		endorsed := false
		for _, it := range g.items {
			if _, ok := g.ends[endKey(it.Origin, it.Stream, it.Seq)]; ok {
				endorsed = true
				break
			}
		}
		if reason := h(tx, req.Caller, g.origin, g.stream, req.Recovery, endorsed); reason != "" {
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
		case rec.H == it.H && !it.IsPlaceholder() && rec.Status == repository.StQuarantined && e.cfg.Hooks.OnEndorsed != nil:
			// A node re-offers a released unsealed-tail op the cloud holds as quarantined (A2.1 item 5).
			if en, ok := g.ends[endKey(it.Origin, it.Stream, it.Seq)]; ok && sp.Hash(it.Body) == rec.H {
				if att, ok := e.endorsedOK(tx, en, rec.H, req.Attestations, func(q int64) (string, bool) { return heldHash(tx, g, q) }); ok {
					if b, err := sp.DecodeBody(it.Body); err == nil {
						if err := e.cfg.Hooks.OnEndorsed(tx, rec, &Parsed{Item: it, Body: b}, en, att); err != nil {
							return false, err
						}
						res.New = append(res.New, rec)
					}
				}
			}
		case rec.H == it.H && !it.IsPlaceholder() && req.FromUpstream && (rec.Status == repository.StAccepted || rec.Status == repository.StFlagged) && g.ends[endKey(it.Origin, it.Stream, it.Seq)].Sig != "":
			// A refreshed endorsement for an op held already (re-issued after a key rotation, A2.1
			// item 6): replace the stored one if the new one passes the whole rule.
			en := g.ends[endKey(it.Origin, it.Stream, it.Seq)]
			if old, ok, err := tx.GetEndorsement(it.Stream, it.Origin, it.Seq); err != nil {
				return false, err
			} else if ok && old.Sig != en.Sig {
				if att, ok := e.endorsedOK(tx, en, rec.H, req.Attestations, func(q int64) (string, bool) { return heldHash(tx, g, q) }); ok {
					if err := tx.ReplaceEndorsement(repository.EndorsementRec{Stream: en.Stream, Origin: en.Origin, Seq: en.Seq, H: en.H, Rec: en.Rec, Kid: en.Kid, Sig: en.Sig}); err != nil {
						return false, err
					}
					if err := putAtt(tx, att); err != nil {
						return false, err
					}
				}
			}
		case rec.H != it.H && req.FromUpstream && !it.IsPlaceholder():
			// An upstream serves a body that contradicts what this node holds at the slot: never
			// silent (A2.8 item 1.4). The node keeps what it holds.
			if err := e.conflict(tx, req, res, rec, it.H); err != nil {
				return false, err
			}
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
			// A released op reaching a node that held only its slot (RB3, A2.8 item 1).
			hb := sp.Hash(it.Body)
			b, derr := sp.DecodeBody(it.Body)
			if hb != rec.H {
				// The body contradicts the hash held for the slot: never silent.
				if err := e.conflict(tx, req, res, rec, hb); err != nil {
					return false, err
				}
				continue
			}
			if derr != nil {
				continue
			}
			if b.TenantID != e.cfg.Tenant || b.Origin != rec.Origin || b.Stream != rec.Stream || b.Seq != rec.Seq {
				res.Refused = append(res.Refused, sp.Refusal{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq, Reason: sp.ReasonFramed})
				continue
			}
			endorsed := false
			if en, has := g.ends[endKey(it.Origin, it.Stream, it.Seq)]; has {
				// An endorsement that comes with the body must pass the rule of A2.1 (the released
				// unsealed tail); it also binds the slot, naming (origin, stream, seq, h).
				att, ok := e.endorsedOK(tx, en, rec.H, req.Attestations, func(q int64) (string, bool) { return heldHash(tx, g, q) })
				if !ok {
					continue
				}
				if err := tx.PutEndorsement(repository.EndorsementRec{Stream: en.Stream, Origin: en.Origin, Seq: en.Seq, H: en.H, Rec: en.Rec, Kid: en.Kid, Sig: en.Sig}); err != nil {
					return false, err
				}
				if err := putAtt(tx, att); err != nil {
					return false, err
				}
				rec.Marks = MarkUnsealed
				endorsed = true
			}
			bind := bindOK
			if !endorsed {
				if !req.FromCloud && !e.sealedAtOrAbove(tx, seals, rec) {
					// No placeholder is filled by hash above the origin's sealed head except by the
					// cloud; above it only the endorsement rule of A2.1 applies (A2.8 item 1.1).
					res.Refused = append(res.Refused, sp.Refusal{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq, Reason: sp.ReasonUnsealed})
					continue
				}
				var seen string
				var berr error
				bind, seen, berr = e.bindSlot(tx, g, seals, rec, hb, b)
				if berr != nil {
					return false, berr
				}
				if bind == conflict {
					if err := e.conflict(tx, req, res, rec, seen); err != nil {
						return false, err
					}
					continue
				}
			}
			if bind == unbound {
				rec.Marks = withMark(rec.Marks, MarkUnbound)
				if err := addUnbound(tx, sp.Ref{Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq}); err != nil {
					return false, err
				}
			} else if rec.Seq > 1 {
				// The body is bound: the slot below, if it was taken unbound, is bound by this link.
				if lo, ok, err := tx.GetOp(rec.Stream, rec.Origin, rec.Seq-1); err != nil {
					return false, err
				} else if ok && lo.H == b.PH {
					if err := clearUnbound(tx, lo); err != nil {
						return false, err
					}
				}
			}
			rec.Body, rec.PH, rec.Status, rec.Intent, rec.HLC = it.Body, b.PH, repository.StAccepted, b.Intent, b.HLC
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
	// A new op that does not link to a head slot taken by hash and still unbound contradicts it
	// (A2.8 item 1.2: "when a later pull supplies the op above, the link is checked then").
	if req.FromUpstream && head > 0 && !items[0].IsPlaceholder() && sp.Hash(items[0].Body) == items[0].H {
		if hr, ok, err := tx.GetOp(g.stream, g.origin, head); err != nil {
			return false, err
		} else if ok && hasMarkS(hr.Marks, MarkUnbound) {
			if b0, derr := sp.DecodeBody(items[0].Body); derr == nil && b0.PH != hr.H {
				if err := noteConflict(tx, sp.Conflict{Origin: g.origin, Stream: g.stream, Seq: head, Held: hr.H, Seen: b0.PH}, srcOf(req.FromCloud)); err != nil {
					return false, err
				}
				refuse(0, sp.ReasonChainConflict)
				return false, nil
			}
		}
	}
	// A cloud-origin seal under a key this node does not accept is noted: the node reads that origin
	// from the cloud directly until its hub has refreshed the seal (A2.8 item 2.2).
	if req.FromUpstream && strings.HasPrefix(g.origin, CloudOriginPrefix) {
		if rt, ok := e.cfg.Trust.(RecoveryTrust); ok {
			for _, sl := range seals {
				if sl.Origin == g.origin && sl.Stream == g.stream {
					if _, ok := rt.OpKey(sl.Kid); !ok {
						res.StaleCloudSeal = true
					}
				}
			}
		}
	}
	// The signed body names the tenant; it must be this node's tenant (review M3). Neither the seal
	// nor the genesis hash binds it, so the check is here, for device, hub and cloud alike.
	for _, it := range items {
		if it.IsPlaceholder() || sp.Hash(it.Body) != it.H {
			continue
		}
		if b, derr := sp.DecodeBody(it.Body); derr == nil && b.TenantID != e.cfg.Tenant {
			refuse(0, sp.ReasonFramed)
			return false, nil
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
			if sl, ok := seals[it.Origin+"/"+it.Stream+"/"+fmt.Sprint(it.Seq)]; ok && chainOK && sl.H == it.H && e.sealOK(sl, g.origin, pub) {
				covered = i + 1
				steps[i].sealed = true
			}
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
		if s, ok := seals[it.Origin+"/"+it.Stream+"/"+fmt.Sprint(it.Seq)]; ok && s.H == it.H && e.sealOK(s, g.origin, pub) {
			covered = i + 1
			steps[i].sealed = true
		}
	}
	// The released unsealed tail of a key-lost origin: no seal covers it, an endorsement may
	// (A2.1 item 3). The highest verified endorsement covers the chain below it.
	sealCovered := covered
	endTo := 0
	endOK := map[int]sp.Endorsement{}
	var endAtts []sp.Attestation
	if !req.Recovery && len(g.ends) > 0 {
		held := func(q int64) (string, bool) { return heldHash(tx, g, q) }
		for i := len(steps) - 1; i >= sealCovered; i-- {
			en, ok := g.ends[endKey(items[i].Origin, items[i].Stream, items[i].Seq)]
			if !ok {
				continue
			}
			att, ok := e.endorsedOK(tx, en, items[i].H, req.Attestations, held)
			if !ok {
				continue
			}
			endTo = i + 1
			endAtts = append(endAtts, att)
			for j := sealCovered; j <= i; j++ {
				if ej, ok := g.ends[endKey(items[j].Origin, items[j].Stream, items[j].Seq)]; ok {
					if _, ok := e.endorsedOK(tx, ej, items[j].H, req.Attestations, held); ok {
						endOK[j] = ej
					}
				}
			}
			break
		}
		if endTo > covered {
			covered = endTo
		}
	}
	// Trailing placeholders from the cloud need no seal; from any other upstream a placeholder is
	// accepted only inside a range a seal or endorsement covers (A2.8 item 1.1).
	if req.FromUpstream && req.FromCloud && chainOK {
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
			// A seal that names a placeholder slot is kept too: it is what lets this node serve the slot
			// onward (a relay serves no placeholder above a sealed head, A2.8 item 1.1).
			if sl, ok := seals[it.Origin+"/"+it.Stream+"/"+fmt.Sprint(it.Seq)]; ok && i < len(steps) && steps[i].sealed {
				if err := tx.PutSeal(it.Stream, it.Origin, it.Seq, sl.H, sl.Kid, sl.Sig); err != nil {
					return false, err
				}
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
		if len(it.PII) > 0 {
			if err := e.openPII(tx, p); err != nil {
				return false, err
			}
		}
		v := Verdict{Status: repository.StAccepted}
		if e.cfg.Hooks.Verdict != nil {
			v = e.cfg.Hooks.Verdict(tx, p, VerdictCtx{Caller: req.Caller, Own: own, Recovery: req.Recovery,
				Sealed: i < sealCovered, Endorsed: i >= sealCovered && i < endTo, Unsealed: i >= covered && i < good, ChainBroken: i >= good})
		}
		if i >= sealCovered && i < endTo {
			// Every node marks an op accepted under an endorsement `unsealed` in its audit views (A2.1 item 4).
			if !contains(v.Marks, MarkUnsealed) {
				v.Marks = append(v.Marks, MarkUnsealed)
			}
			if en, ok := endOK[i]; ok {
				if err := tx.PutEndorsement(repository.EndorsementRec{Stream: en.Stream, Origin: en.Origin, Seq: en.Seq, H: en.H, Rec: en.Rec, Kid: en.Kid, Sig: en.Sig}); err != nil {
					return false, err
				}
			}
			for _, a := range endAtts {
				if err := putAtt(tx, a); err != nil {
					return false, err
				}
			}
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
	}
	if req.FromUpstream && head > 0 && len(items) > 0 && !items[0].IsPlaceholder() {
		// The first stored op links to the head slot: that binds a head taken unbound.
		if hr, ok, err := tx.GetOp(g.stream, g.origin, head); err != nil {
			return false, err
		} else if ok && hasMarkS(hr.Marks, MarkUnbound) {
			if b0, derr := sp.DecodeBody(items[0].Body); derr == nil && b0.PH == hr.H {
				if err := clearUnbound(tx, hr); err != nil {
					return false, err
				}
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
		if err := ApplyErasure(tx, b); err != nil {
			return err
		}
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
	// Recoverers returns the identity-signed credentials that carry `recovers: origin`; they are
	// served with an endorsed tail (A2.1 item 3).
	Recoverers func(origin string) []sp.CredentialEnvelope
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
			recs, bnd, more, err := e.serveRange(tx, h, after, budget)
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
				if bnd != nil {
					resp.Seals = append(resp.Seals, bnd.Seals...)
					resp.Endorsements = append(resp.Endorsements, bnd.Ends...)
					resp.Attestations = append(resp.Attestations, bnd.Atts...)
					if len(bnd.Ends) > 0 && o.Recoverers != nil {
						resp.Creds = append(resp.Creds, o.Recoverers(h.Origin)...)
					}
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
			if ok && rec.Body != "" && (rec.Status == repository.StAccepted || rec.Status == repository.StFlagged) && (e.cfg.Role == RoleCloud || !hasMarkS(rec.Marks, MarkUnbound)) {
				resp.Items = append(resp.Items, sp.Item{Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq, H: rec.H, Body: rec.Body})
				if en, ok, err := tx.GetEndorsement(rec.Stream, rec.Origin, rec.Seq); err != nil {
					return err
				} else if ok {
					// A released unsealed-tail op reaching a placeholder holder carries its endorsement (RB3, A2.1).
					resp.Endorsements = append(resp.Endorsements, sp.Endorsement{Origin: en.Origin, Stream: en.Stream, Seq: en.Seq, H: en.H, Rec: en.Rec, Kid: en.Kid, Sig: en.Sig})
					atts, err := tx.Attestations(rec.Stream, rec.Origin)
					if err != nil {
						return err
					}
					for _, a := range atts {
						resp.Attestations = append(resp.Attestations, sp.Attestation{Origin: a.Origin, Stream: a.Stream, Seq: a.Seq, H: a.H, By: a.By, Rec: a.Rec, Kid: a.Kid, Sig: a.Sig})
					}
					if o.Recoverers != nil {
						resp.Creds = append(resp.Creds, o.Recoverers(rec.Origin)...)
					}
				}
				if !seen[rec.Origin] {
					seen[rec.Origin] = true
					if c, ok := creds(rec.Origin); ok {
						resp.Creds = append(resp.Creds, c)
					}
				}
			}
		}
		// Cloud seals under a key the caller dropped: the current ones (A2.8 item 2).
		for _, r := range req.StaleSeals {
			if !strings.HasPrefix(r.Origin, CloudOriginPrefix) || (len(o.Streams) > 0 && !contains(o.Streams, r.Stream)) || len(resp.SealRefresh) >= 200 {
				continue
			}
			if kid, sig, h, ok, err := tx.GetSeal(r.Stream, r.Origin, r.Seq); err != nil {
				return err
			} else if ok {
				resp.SealRefresh = append(resp.SealRefresh, sp.Seal{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq, H: h, Kid: kid, Sig: sig})
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

// serveRange picks the slots of one (stream, origin) to serve: up to a seal or endorsement boundary
// (so every full op is covered by proof the puller can check), plus trailing placeholders.
func (e *Engine) serveRange(tx repository.Tx, h repository.HeadRow, after int64, budget int) ([]repository.OpRec, *bound, bool, error) {
	bounds, err := boundaries(tx, h.Stream, h.Origin, after)
	if err != nil {
		return nil, nil, false, err
	}
	if e.cfg.Role != RoleCloud {
		// A relay never serves an unbound op, nor anything after it in the origin's chain (A2.8 item 1.3).
		ub, err := unboundRefs(tx)
		if err != nil {
			return nil, nil, false, err
		}
		var first int64
		for _, u := range ub {
			if u.Origin == h.Origin && u.Stream == h.Stream && u.Seq > after && (first == 0 || u.Seq < first) {
				first = u.Seq
			}
		}
		if first > 0 {
			kept := bounds[:0:0]
			for _, b := range bounds {
				if b < first {
					kept = append(kept, b)
				}
			}
			bounds = kept
		}
	}
	var cut int64
	for _, s := range bounds {
		if s-after <= int64(budget) {
			cut = s
		}
	}
	if cut == 0 && len(bounds) > 0 {
		cut = bounds[0] // exceed the soft cap to reach the first boundary: a batch is never unverifiable
	}
	var recs []repository.OpRec
	var bnd *bound
	more := false
	if cut > 0 {
		recs, err = tx.Range(h.Stream, h.Origin, after, cut, int(cut-after))
		if err != nil {
			return nil, nil, false, err
		}
		if bnd, err = boundAt(tx, h.Stream, h.Origin, after, cut); err != nil {
			return nil, nil, false, err
		}
		if cut < h.Seq {
			more = true
		}
	}
	// Trailing slots with no body served (quarantined / voided) need no seal, from the cloud only: a
	// relay serves no placeholder above a sealed head (A2.8 item 1.1).
	if e.cfg.Role == RoleCloud && (cut == 0 || cut == bounds[len(bounds)-1]) {
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
	return recs, bnd, more, nil
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

// sealOK verifies a seal. A device origin's seal verifies under the origin's credential key only.
// A cloud-<epoch> origin's seal verifies under the op-signing key its kid names, if that key is
// current. An op-signing key never seals another origin: the released tail of a key-lost origin
// is covered by an endorsement instead (A2.1).
func (e *Engine) sealOK(s sp.Seal, origin string, originPub *ecdsa.PublicKey) bool {
	if strings.HasPrefix(origin, CloudOriginPrefix) {
		if rt, ok := e.cfg.Trust.(RecoveryTrust); ok {
			k, ok := rt.OpKey(s.Kid) // the named kid only; a revoked or unknown kid is refused
			return ok && s.Verify(k)
		}
		return false
	}
	return originPub != nil && s.Verify(originPub)
}
