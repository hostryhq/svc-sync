// Package directory is the gateway's view of identity and tenancy: device credentials, the
// document-series registry, offline packs, members and the PIN-derived proof check. The real
// implementations are the identity and tenancy services (through generated clients); the
// identitystub package implements it for tests and the simulator.
package directory

import (
	"context"
	"encoding/json"
	"time"

	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Series states (S7).
const (
	SeriesActive  = "active"
	SeriesDormant = "dormant"
	SeriesClosed  = "closed"
)

// Pack is the part of a device's offline pack the sync side uses.
type Pack struct {
	Version int
	// Members maps member id to the permission set the pack granted.
	Members map[string]map[string]bool
	Expires time.Time
}

// Series kinds. A device series is issued to one device, which allocates its numbers; a manual_book series is a
// paper bill book the owner registered (ADR-0014 A1.6 item 4): it belongs to no device, billing devices of its
// outlets enter its numbers by hand, and the allocator never takes from it.
const (
	SeriesKindDevice     = "device"
	SeriesKindManualBook = "manual_book"
)

// SeriesInfo is one issued series. Kind is empty for a device series (the default). Outlets lists the outlets
// whose billing devices may enter a manual_book series; empty means every outlet of the tenant.
type SeriesInfo struct {
	Tenant, Code, Device, DocType, State string
	Kind                                 string
	Outlets                              []string
}

// ManualBook reports whether the series is a registered paper bill book.
func (s SeriesInfo) ManualBook() bool { return s.Kind == SeriesKindManualBook }

// ProofResult is identity's answer about a PIN-derived proof.
type ProofResult int

// Proof results. Locked and Unavailable exist for the gateway's verdicts (A1.2 item 4, S11).
const (
	ProofValid ProofResult = iota
	ProofMissing
	ProofInvalid
	ProofLocked
	ProofUnavailable
)

// RecoveryRec is the identity-side record of a key-loss recovery.
type RecoveryRec struct {
	ID, Tenant, Old, New string
	Code                 string
	Used                 bool
	Expires              time.Time
}

// Proof kinds of a ProofQuestion.
const (
	ProofKindSession  = "session"
	ProofKindApproval = "approval"
)

// ProofQuestion is one question to identity's verifyProof (ADR-0005 A3.1 item 2). The gateway asks once per
// proof-bearing op: Key is derived from (origin, stream, seq), so a retry or a re-offer of the same op is a
// replay at identity and never counts a failed session twice.
type ProofQuestion struct {
	Kind        string
	Device      string
	Member      string // the actor of a session, the approver of an approval
	SID         string
	PackV, PinV int
	OpenedAt    time.Time // the `at` of session.open
	Proof       string
	Key         string
	ApprovalID  string
	Permission  string
	Target      string
	Requester   string
	Reason      string
	ActionHash  string
	ApprovedAt  time.Time
}

// Lookup is the answer of a question that can fail to be answered: not found is never confused with unreachable.
type Lookup int

// Lookup results.
const (
	Found Lookup = iota
	NotFound
	Unreachable
)

// SessionFacts are the fixed facts of a strong session (identity's getSession).
type SessionFacts struct {
	Member, Device string
	Issued         time.Time
	// Ended is the time a revocation of the session was seen (zero while it is live).
	Ended time.Time
}

// DrainSeries is one entry of the series list of a drain statement.
type DrainSeries struct {
	SeriesID, Code, FY string
	LastNumber         int64
}

// DrainReport is what the gateway tells identity once a device-signed drain statement is satisfied (A3.3 item 4):
// the stored heads, the series list as the device stated it, and the statement itself, verbatim.
type DrainReport struct {
	// Key is the Idempotency-Key of the report: the statement hash, one key until identity answers.
	Key       string
	Through   map[string]int64
	Series    []DrainSeries
	Statement json.RawMessage
}

// Directory is what the gateway needs from identity and tenancy. Every lookup is within the
// given tenant: a code or device of another tenant is simply not found.
type Directory interface {
	Credential(tenant, device string) (sp.CredentialEnvelope, bool)
	Revoked(tenant, device string) (bool, string)
	// SeriesFor finds the series a document code names for an origin: a series issued to the device (tenancy's
	// listDeviceSeries, by device and not by code) or a registered paper book of its outlet. A code that is
	// neither is not found. A directory that can tell, may return a series of another device (Device differs).
	SeriesFor(tenant, device, outlet, code string) (SeriesInfo, bool)
	PackFor(tenant, device string, version int) (Pack, bool)
	InAnyPack(tenant, device, actor string) bool
	// StillHolds reports whether the member is active now and holds the permission at the outlet.
	StillHolds(tenant, outlet, actor, perm string) bool
	// VerifyProof asks identity about one proof. It is never answered from a stored earlier answer: the
	// gateway keeps the verdict per (origin, sid) itself.
	VerifyProof(tenant string, q ProofQuestion) ProofResult
	// StrongSession answers the fixed facts of a strong session (no proof travels with it, A3.1 item 5).
	StrongSession(tenant, sid string) (SessionFacts, Lookup)
	RecoveryFor(tenant, old string) (RecoveryRec, bool)
	Now() time.Time
}

// DrainRecorder is implemented by a directory that tells identity a revoked device is drained: every op it
// held is stored, so identity may start the wipe delay (identity's recordDeviceDrained). through is the
// highest stored sequence per stream of the device's own ops. A directory that does not implement it is
// simply not told; the gateway never depends on the answer to store ops.
type DrainRecorder interface {
	RecordDrained(ctx context.Context, tenant, device string, rep DrainReport) error
}

// Faulty is implemented by a directory whose lookups can fail (the real one). Faults counts the lookups that could not
// be asked or answered; the gateway compares it before and after it judges an op: when it moved, a configuration
// op waits and a trading fact is stored with the pending mark, because an unanswered question is never "found",
// "held" or "valid" (ADR-0005 A3.2).
type Faulty interface {
	Faults() uint64
}
