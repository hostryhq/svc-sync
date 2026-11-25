// Package directory is the gateway's view of identity and tenancy: device credentials, the
// document-series registry, offline packs, members and the PIN-derived proof check. The real
// implementations are the identity and tenancy services (through generated clients); the
// identitystub package implements it for tests and the simulator.
package directory

import (
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

// SeriesInfo is one issued series.
type SeriesInfo struct {
	Tenant, Code, Device, DocType, State string
}

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
