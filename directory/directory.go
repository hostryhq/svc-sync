// Package directory is the gateway's view of identity and tenancy: device credentials, the
// document-series registry, offline packs, members and the PIN-derived proof check. The real
// implementations are the identity and tenancy services (through generated clients); the
// identitystub package implements it for tests and the simulator.
package directory

import (
	"context"
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
	Version string
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

// Directory is what the gateway needs from identity and tenancy. Every lookup is within the
// given tenant: a code or device of another tenant is simply not found.
type Directory interface {
	Credential(tenant, device string) (sp.CredentialEnvelope, bool)
	Revoked(tenant, device string) (bool, string)
	Series(tenant, code string) (SeriesInfo, bool)
	PackFor(tenant, device, version string) (Pack, bool)
	InAnyPack(tenant, device, actor string) bool
	StillHolds(tenant, actor, perm string) bool
	CheckProof(tenant, device, actor, sid, proof string, configClass bool) ProofResult
	RecoveryFor(tenant, old string) (RecoveryRec, bool)
	Now() time.Time
}

// DrainRecorder is implemented by a directory that tells identity a revoked device is drained: every op it
// held is stored, so identity may start the wipe delay (identity's recordDeviceDrained). through is the
// highest stored sequence per stream of the device's own ops. A directory that does not implement it is
// simply not told; the gateway never depends on the answer to store ops.
type DrainRecorder interface {
	RecordDrained(ctx context.Context, tenant, device string, through map[string]int64) error
}
