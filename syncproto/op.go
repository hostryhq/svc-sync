package syncproto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ProtocolVersion is the Sync Protocol major version.
const ProtocolVersion = 1

// Mutation kinds (S4).
const (
	KInsert = "insert"
	KSet    = "set"
	KDelta  = "delta"
	KRank   = "rank"
	KDel    = "del"
	KUndel  = "undel"
)

// Clock source values of Body.Clk.
const (
	ClkSync   = "sync"
	ClkManual = "manual"
)

// Intent names the engine itself understands.
const (
	IntentVoid        = "sync.void"
	IntentPIIErase    = "sync.pii.erase"
	IntentSessionOpen = "session.open"
	// IntentApprovalGrant is the manager override at the counter; it carries an action proof (ADR-0005 section 8).
	IntentApprovalGrant = "approval.grant"
)

// Session types of a session.open (ADR-0005 section 7). Only a pin session carries a proof (A3.1).
const (
	SessionPin    = "pin"
	SessionStrong = "strong"
)

// TimeLayout is the layout of Body.At.
const TimeLayout = "2006-01-02T15:04:05.000Z"

// Mut is one generic mutation inside an op.
type Mut struct {
	E    string            `json:"e"`
	ID   string            `json:"id"`
	K    string            `json:"k"`
	F    map[string]any    `json:"f,omitempty"`
	Prev map[string]string `json:"prev,omitempty"`
}

// Doc marks the legal document number an op allocates (S7), for example
// {"type":"tax_invoice","number":"A07/2627/000123"}. The series code is the part before the
// first slash.
type Doc struct {
	Type   string `json:"type"`
	Number string `json:"number"`
}

// SeriesCode is the code part of the number.
func (d Doc) SeriesCode() string {
	if i := strings.IndexByte(d.Number, '/'); i >= 0 {
		return d.Number[:i]
	}
	return d.Number
}

// Body is the hashed part of an op (everything except pii).
type Body struct {
	V        int    `json:"v"`
	Origin   string `json:"origin"`
	Stream   string `json:"stream"`
	Seq      int64  `json:"seq"`
	PH       string `json:"ph"`
	HLC      string `json:"hlc"`
	Clk      string `json:"clk"`
	TenantID string `json:"tenant_id"`
	Actor    string `json:"actor,omitempty"`
	SID      string `json:"sid,omitempty"`
	// PackV is the offline pack version, a JSON integer >= 1 on every device-origin op (ADR-0005 A3.1).
	PackV    int    `json:"pack_v,omitempty"`
	Approval string `json:"approval,omitempty"`
	// Proof is the opaque PIN-derived session or action proof (ADR-0005 section 7-8). It travels only on
	// session.open of a pin session and on approval.grant, together with PinV (A3.1). Only the cloud can
	// check it; a hub never looks at it.
	Proof string `json:"proof,omitempty"`
	// PinV is the PIN version the proof was made under: the actor's on session.open, the approver's on approval.grant.
	PinV    int    `json:"pin_v,omitempty"`
	Intent  string `json:"intent"`
	IntentV int    `json:"intent_v"`
	At      string `json:"at"`
	Doc     *Doc   `json:"doc,omitempty"`
	// PIIC holds the salted per-field commitments of the op's pii (piic.go; provisional).
	PIIC PIICommit `json:"pii_c,omitempty"`
	Muts []Mut     `json:"muts"`
}

// Item is one op or one placeholder on the wire. Body is the canonical JSON text of the Body
// as a JSON string, so every relay forwards the exact bytes the origin hashed. Body empty means
// placeholder: the slot exists (it advances the vector) but its content is not delivered.
type Item struct {
	Origin string          `json:"origin"`
	Stream string          `json:"stream"`
	Seq    int64           `json:"seq"`
	H      string          `json:"h"`
	Body   string          `json:"body,omitempty"`
	PII    json.RawMessage `json:"pii,omitempty"`
}

// IsPlaceholder reports whether the item carries no body.
func (it Item) IsPlaceholder() bool { return it.Body == "" }

// Ref is the identity of an op.
type Ref struct {
	Origin string `json:"origin"`
	Stream string `json:"stream"`
	Seq    int64  `json:"seq"`
}

// Key is a stable text form of the identity.
func (r Ref) Key() string { return r.Origin + "/" + r.Stream + "/" + strconv.FormatInt(r.Seq, 10) }

// Hash is the SHA-256 (lowercase hex) of the exact body bytes.
func Hash(body string) string {
	s := sha256.Sum256([]byte(body))
	return hex.EncodeToString(s[:])
}

// GenesisHash is the `ph` of the first op of an origin in a stream.
func GenesisHash(origin, stream string) string {
	return Hash("hostry-genesis-v1\n" + origin + "\n" + stream)
}

// EncodeBody canonicalises b into the text that is hashed and sent.
func EncodeBody(b Body) (string, error) {
	if b.V == 0 {
		b.V = 1
	}
	if b.Muts == nil {
		b.Muts = []Mut{}
	}
	raw, err := CanonicalJSON(b)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// NewItem encodes b and returns the wire item with its hash.
func NewItem(b Body, pii json.RawMessage) (Item, error) {
	txt, err := EncodeBody(b)
	if err != nil {
		return Item{}, err
	}
	return Item{Origin: b.Origin, Stream: b.Stream, Seq: b.Seq, H: Hash(txt), Body: txt, PII: pii}, nil
}

// ErrBody is returned for a body that is not valid JSON of the Body shape.
var ErrBody = errors.New("syncproto: malformed op body")

// DecodeBody parses body text. Field values are normalised: integers become int64.
func DecodeBody(txt string) (Body, error) {
	dec := json.NewDecoder(strings.NewReader(txt))
	dec.UseNumber()
	var b Body
	if err := dec.Decode(&b); err != nil {
		return Body{}, fmt.Errorf("%w: %v", ErrBody, err)
	}
	for i := range b.Muts {
		for k, v := range b.Muts[i].F {
			if n, ok := v.(json.Number); ok {
				x, err := strconv.ParseInt(string(n), 10, 64)
				if err != nil {
					return Body{}, fmt.Errorf("%w: field %s is not an integer", ErrBody, k)
				}
				b.Muts[i].F[k] = x
			}
		}
	}
	if b.Origin == "" || b.Stream == "" || b.Seq < 1 || b.Intent == "" {
		return Body{}, fmt.Errorf("%w: identity fields missing", ErrBody)
	}
	return b, nil
}

// Canonical reports whether the text is already in canonical form.
func Canonical(txt string) bool {
	c, err := Canonicalize([]byte(txt))
	return err == nil && bytes.Equal(c, []byte(txt))
}

// VerifyItem checks the item's own consistency: hash matches body, identity fields match.
func VerifyItem(it Item) (Body, error) {
	if it.IsPlaceholder() {
		return Body{}, errors.New("syncproto: placeholder has no body")
	}
	if Hash(it.Body) != it.H {
		return Body{}, errors.New("syncproto: hash does not match body")
	}
	b, err := DecodeBody(it.Body)
	if err != nil {
		return Body{}, err
	}
	if b.Origin != it.Origin || b.Stream != it.Stream || b.Seq != it.Seq {
		return Body{}, errors.New("syncproto: item identity does not match body")
	}
	return b, nil
}

// Vector maps "origin/stream" to the highest contiguous seq held.
type Vector map[string]int64

// VKey builds a vector key.
func VKey(origin, stream string) string { return origin + "/" + stream }

// SplitVKey is the inverse of VKey.
func SplitVKey(k string) (origin, stream string, ok bool) {
	i := strings.IndexByte(k, '/')
	if i <= 0 {
		return "", "", false
	}
	return k[:i], k[i+1:], true
}

// Clone copies the vector.
func (v Vector) Clone() Vector {
	o := make(Vector, len(v))
	for k, s := range v {
		o[k] = s
	}
	return o
}

// Hold codes a device may be told about its own held ops (A1.2). A closed list.
const (
	HoldPending     = "pending"
	HoldManager     = "held_manager"
	HoldSupport     = "held_support"
	VoidReasonCloud = "refused"
)

// HeldSlot names one held slot and the coarse code.
type HeldSlot struct {
	Origin string `json:"origin"`
	Stream string `json:"stream"`
	Seq    int64  `json:"seq"`
	Code   string `json:"code"`
}

// Refusal reports an op the server did not store (nothing stored, not a verdict).
type Refusal struct {
	Origin string `json:"origin"`
	Stream string `json:"stream"`
	Seq    int64  `json:"seq"`
	Reason string `json:"reason"`
}

// Refusal reasons.
const (
	ReasonGap         = "gap"
	ReasonSeal        = "seal_invalid"
	ReasonChain       = "chain_invalid"
	ReasonOrigin      = "origin_not_in_outlet"
	ReasonStream      = "stream_outside_binding"
	ReasonRevoked     = "revoked"
	ReasonUnsealed    = "unsealed"
	ReasonFramed      = "framing"
	ReasonRecovery    = "recovery_not_authorised"
	ReasonRelayedOnly = "relay_not_allowed"
	ReasonFork        = "fork_evidence_kept"
	// ReasonChainConflict: a body or link contradicts what the node holds or a seal states (A2.8 item 1).
	ReasonChainConflict = "chain_conflict"
)

// HelloRequest opens a sync contact.
type HelloRequest struct {
	Protocol      int    `json:"protocol"`
	AppVersion    string `json:"app_version,omitempty"`
	SchemaVersion int    `json:"schema_version,omitempty"`
	Vector        Vector `json:"vector,omitempty"`
	// Epoch is the cloud epoch this node last synced under.
	Epoch string `json:"epoch,omitempty"`
	// CloudVector is the cloud vector the node last saw (a hub passes it on).
	CloudVector Vector `json:"cloud_vector,omitempty"`
	// Unbound lists the slots this node took by hash with no binding yet (A2.8 item 1.3). Only the
	// cloud answers it; a node lists it at every direct cloud hello.
	Unbound []Ref `json:"unbound,omitempty"`
	// Conflicts reports the chain conflicts this node recorded and has not yet reported (A2.8 item 1.4).
	Conflicts []Conflict `json:"chain_conflicts,omitempty"`
	// PIIErased acknowledges the cloud-signed erasures (intent sync.pii.erase) this node applied to
	// its rows, op log, caches and spool (PROVISIONAL; syncproto/piic.go, contract/README.md).
	PIIErased []Ref `json:"pii_erased,omitempty"`
}

// SlotHash is a slot with the hash a node holds or the cloud states for it.
type SlotHash struct {
	Origin string `json:"origin"`
	Stream string `json:"stream"`
	Seq    int64  `json:"seq"`
	H      string `json:"h"`
}

// Conflict is a recorded chain conflict: the hash the node holds and the one the upstream or the
// cloud contradicted it with (A2.8 item 1.4).
type Conflict struct {
	Origin string `json:"origin"`
	Stream string `json:"stream"`
	Seq    int64  `json:"seq"`
	Held   string `json:"held"`
	Seen   string `json:"seen,omitempty"`
}

// HelloResponse answers hello.
type HelloResponse struct {
	Protocol            int      `json:"protocol"`
	Role                string   `json:"role"`
	NodeID              string   `json:"node_id"`
	Time                string   `json:"time"`
	Epoch               string   `json:"epoch,omitempty"`
	Vector              Vector   `json:"vector"`
	CloudVector         Vector   `json:"cloud_vector,omitempty"`
	MinSupportedVersion string   `json:"min_supported_version"`
	SnapshotRequired    bool     `json:"snapshot_required"`
	Streams             []string `json:"streams"`
	// UnboundH answers HelloRequest.Unbound with the cloud's own hash for each slot it holds.
	UnboundH []SlotHash `json:"unbound_h,omitempty"`
}

// PushRequest delivers ops. Items must be in origin-sequence order per (origin, stream);
// each (origin, stream) group ends with an op covered by a seal in Seals.
type PushRequest struct {
	Items []Item `json:"items"`
	Seals []Seal `json:"seals,omitempty"`
	// Attestations: in a quarantine-upload, the adopting device's attestation of a key-lost origin's
	// tail; in a push, the attestations that go with Endorsements (a re-offer, A2.1 item 5).
	Attestations []Attestation `json:"attestations,omitempty"`
	// Endorsements covers released unsealed-tail ops (A2.1). Items and endorsements are independent:
	// a node re-offering after a cloud restore also sends endorsed ops the cloud already holds
	// as quarantined, so that the cloud can take them as released.
	Endorsements []Endorsement `json:"endorsements,omitempty"`
	// DrainStatement is the device-signed list of everything a revoked device holds: the last, empty upload of
	// a drain (ADR-0005 A3.3). Only quarantine-upload reads it.
	DrainStatement *DrainStatement `json:"drain_statement,omitempty"`
}

// PushResponse reports what the upstream now holds.
type PushResponse struct {
	Epoch   string     `json:"epoch,omitempty"`
	Vector  Vector     `json:"vector"`
	Held    []HeldSlot `json:"held,omitempty"`
	Refused []Refusal  `json:"refused,omitempty"`
	// Drained is set by quarantine-upload when the origin's attested tail is all held.
	Drained bool `json:"drained,omitempty"`
}

// PullRequest asks for ops beyond Vector.
type PullRequest struct {
	Vector  Vector   `json:"vector"`
	Streams []string `json:"streams,omitempty"`
	// Placeholders lists slots the caller holds only as placeholders, to receive them if released.
	Placeholders []Ref `json:"placeholders,omitempty"`
	// StaleSeals lists stored cloud-origin seals under an op-signing key the caller no longer accepts;
	// the answer carries the current seal for each (A2.8 item 2).
	StaleSeals []Ref `json:"stale_seals,omitempty"`
	Limit      int   `json:"limit,omitempty"`
}

// PullResponse returns the missing slots.
type PullResponse struct {
	Epoch string               `json:"epoch,omitempty"`
	Items []Item               `json:"items"`
	Seals []Seal               `json:"seals,omitempty"`
	Creds []CredentialEnvelope `json:"creds,omitempty"`
	// Endorsements, Attestations and the credentials of the adopting devices (in Creds) travel with
	// the ops of a released unsealed tail, as seals and credentials do (A2.1 item 3).
	Endorsements []Endorsement `json:"endorsements,omitempty"`
	Attestations []Attestation `json:"attestations,omitempty"`
	// SealRefresh answers PullRequest.StaleSeals with the seals as the upstream now holds them.
	SealRefresh []Seal `json:"seal_refresh,omitempty"`
	More        bool   `json:"more"`
	// OwnHeld is the complete current list of the caller's own held slots (A1.2).
	OwnHeld []HeldSlot `json:"own_held"`
	// RelayHeld is given to nodes with role hub: held slots of the origins it relays.
	RelayHeld []HeldSlot `json:"relay_held,omitempty"`
}

// Snapshot is the bootstrap state: rows and the vector they reflect.
type Snapshot struct {
	Vector Vector        `json:"vector"`
	Rows   []SnapshotRow `json:"rows"`
	Voids  []Ref         `json:"voids"`
	Epoch  string        `json:"epoch,omitempty"`
}

// SnapshotRow is one materialised row.
type SnapshotRow struct {
	Entity string         `json:"e"`
	ID     string         `json:"id"`
	Fields map[string]any `json:"f"`
	Gone   bool           `json:"gone,omitempty"`
	// PIIC is the commitment of every pii field the row holds; PII the values with their `~s:<field>` salts, only
	// for a caller whose credential kind receives them (ADR-0014 A3.1). Neither is part of Fields.
	PIIC map[string]string `json:"pii_c,omitempty"`
	PII  map[string]any    `json:"pii,omitempty"`
	// PIISrc names, per pii field, the op that holds its value; it is never on the wire.
	PIISrc map[string]Ref `json:"-"`
}

// VoidID is the row id of the sync_void record that names a refused op: "<stream>|<origin>|<seq>".
func VoidID(r Ref) string { return r.Stream + "|" + r.Origin + "|" + strconv.FormatInt(r.Seq, 10) }

// docFields names, per entity, the field marked doc_number in api-specs entities/ (checked against
// the registry by a test) and where the document type comes from: a field of the row, or a fixed type.
var docFields = map[string]struct{ Field, TypeField, Type string }{
	"bill":        {Field: "number", TypeField: "doc_type"},
	"credit_note": {Field: "number", Type: "credit_note"},
}

// DocFieldEntities lists the entities that carry a legal document number.
func DocFieldEntities() []string {
	out := make([]string, 0, len(docFields))
	for e := range docFields {
		out = append(out, e)
	}
	return out
}

// Documents lists every legal document number the op allocates: the one in `doc` first, then the
// number of every inserted row of an entity with a doc_number field (protocol-v1 "Several document
// numbers in one op": bill.rebill takes a credit note number and a new bill number in one
// transaction). Duplicates are listed once.
func (b Body) Documents() []Doc {
	var out []Doc
	seen := map[string]bool{}
	add := func(d Doc) {
		if d.Number != "" && !seen[d.Number] {
			seen[d.Number] = true
			out = append(out, d)
		}
	}
	if b.Doc != nil {
		add(*b.Doc)
	}
	for _, m := range b.Muts {
		df, ok := docFields[m.E]
		if !ok || m.K != KInsert {
			continue
		}
		n, _ := m.F[df.Field].(string)
		t := df.Type
		if df.TypeField != "" {
			t, _ = m.F[df.TypeField].(string)
		}
		add(Doc{Type: t, Number: n})
	}
	return out
}

// ParseNumber splits <code>/<FY>/<running>.
func (d Doc) ParseNumber() (code, fy string, n int64, ok bool) {
	parts := strings.Split(d.Number, "/")
	if len(parts) != 3 {
		return "", "", 0, false
	}
	n, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || n < 1 {
		return "", "", 0, false
	}
	return parts[0], parts[1], n, true
}
