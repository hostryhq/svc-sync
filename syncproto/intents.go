package syncproto

import "sync"

// Intent classes (S4, S11).
const (
	ClassTrading = "trading"
	ClassConfig  = "config"
	ClassControl = "control"
)

// Intent is one row of the canonical intent registry (api-specs sync/intents/*.yaml). The table
// itself is generated (intents_gen.go, cmd/genintents); it generates the gateway check (S11) and
// the hub structural check (S8). Permissions are catalogue keys (common/permissions.yaml).
type Intent struct {
	Name  string
	Class string
	// Owner is the service that owns the intent's meaning (or identity or gateway).
	Owner string
	// Permission is the catalogue key a device op needs; empty for control and cloud-origin intents.
	Permission string
	// AuthorisedBy lists the online permissions that authorise a cloud-origin emit.
	AuthorisedBy []string
	// Kinds are the device kinds allowed to record it; "cloud" alone for a gateway emit.
	Kinds []string
	// Sessions are the session types allowed to record it (empty for cloud origin).
	Sessions []string
	Streams  []string
	// Numbering is allocated, typed or none; Documents the document types it consumes.
	Numbering string
	Documents []string
	// Entities maps each touched entity to the mutation kinds the intent may use.
	Entities map[string][]string
	// Records are protocol records that are not synced entities (session, approval, sync_void, ...).
	Records   []string
	PIIFields []string
	// MaxV is the highest intent_v the gateway has an upcaster for (S13).
	MaxV int
}

// CloudKind is the device kind of an intent only the gateway emit may write.
const CloudKind = "cloud"

// Allows reports whether the device kind may record the intent.
func (i Intent) Allows(kind string) bool {
	for _, k := range i.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// CloudOrigin reports whether the intent is written only by the gateway emit.
func (i Intent) CloudOrigin() bool { return len(i.Kinds) == 1 && i.Kinds[0] == CloudKind }

// SessionDevice is the session type of a device session: no member, no PIN (a KDS screen).
const SessionDevice = "device"

// AllowsSession reports whether the intent may be recorded in a session of the type.
func (i Intent) AllowsSession(typ string) bool {
	for _, s := range i.Sessions {
		if s == typ {
			return true
		}
	}
	return false
}

// AllowsEntity reports whether the intent lists the entity with the mutation kind.
func (i Intent) AllowsEntity(entity, kind string) bool {
	for _, k := range i.Entities[entity] {
		if k == kind {
			return true
		}
	}
	return false
}

// HasRecord reports whether the intent lists the protocol record.
func (i Intent) HasRecord(rec string) bool {
	for _, r := range i.Records {
		if r == rec {
			return true
		}
	}
	return false
}

// Protocol records that are not synced entities.
const (
	RecordSyncVoid  = "sync_void"
	RecordPIIErase  = "pii_erase"
	RecordSeriesEnd = "series_close"
)

// init adds the one intent that is not in the registry yet: the cloud-signed erasure of an op's pii
// (PROVISIONAL, security ruling of the Phase 1 re-review; it needs an entry in sync/intents/cloud.yaml
// and a go-common record type). The record pii_erase has the id stream|origin|seq of the op whose pii
// is erased; nodes remove the stored values and salts and acknowledge in their next hello
// (contract/README.md).
func init() {
	Intents[IntentPIIErase] = Intent{Name: IntentPIIErase, Class: ClassControl, Owner: "gateway", Kinds: []string{CloudKind},
		Streams: []string{"outlet", "brand", "tenant"}, Numbering: "none", Records: []string{RecordPIIErase}, MaxV: 1}
}

var demoOnce sync.Once

// RegisterDemoIntents adds the intents that exist only in the simulator and the unit tests (the
// registry has no stock intent before Phase 4). The gateway and hub binaries never call it; a
// device op of such an intent is then refused like any unknown intent. Permission keys are
// prefixed demo. so that they can never be mistaken for catalogue keys.
func RegisterDemoIntents() {
	demoOnce.Do(func() {
		Intents["stock.move"] = Intent{Name: "stock.move", Class: ClassTrading, Owner: "demo", Permission: "demo.stock.move",
			Kinds: []string{KindPOS, KindWaiter}, Sessions: []string{"pin", "strong"}, Streams: []string{"outlet"}, Numbering: "none", MaxV: 1}
	})
}
