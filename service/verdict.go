package service

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Quarantine and void reasons. Reasons stay in the cloud: a device is only ever told one of the
// three coarse hold codes (A1.2), and a void carries the single reason "refused".
const (
	ReasonOpaque         = "opaque_body"
	ReasonChainBroken    = "chain_broken"
	ReasonRevoked        = "revoked"
	ReasonUnsealedTail   = "unsealed_tail"
	ReasonForeignSeries  = "foreign_series"
	ReasonIntentNotAllow = "intent_not_allowed"
	ReasonActorUnknown   = "actor_unknown"
	ReasonClockReview    = "clock_review"
	ReasonConfigPending  = "config_pending"
	ReasonMalformed      = "malformed"
	ReasonFork           = "fork"
	ReasonProofFailed    = "proof_failed"
	ReasonProofLocked    = "proof_locked"
	ReasonPermAbsent     = "permission_absent"
	ReasonPermWithdrawn  = "permission_withdrawn"
	ReasonDiscarded      = "discarded"
)

// Marks recorded with a verdict (audit views, never sent to devices).
const (
	MarkAttributionUnverified = "attribution_unverified"
	MarkPermissionFlag        = "permission_flag"
	MarkSeriesClosed          = "series_closed"
	MarkDormantSeries         = "dormant_series"
	MarkDocTypeMismatch       = "doc_type_mismatch"
	MarkConfigShared          = "config_on_shared_device"
	MarkUnsealed              = "unsealed"
	MarkRecoveredSealed       = "recovered_sealed"
	MarkForeign               = "foreign_series"
	MarkUnknownSeries         = "unknown_series"
	MarkProofPending          = "proof_pending"
	MarkActivationFlag        = "series_activation"
	MarkFork                  = "fork"
	MarkReleased              = "released"
)

// releaseCtx tells judge which holds a manager's release has already cleared.
type releaseCtx struct {
	// Marks the op already carries (kept: a released unsealed op stays marked unsealed).
	Marks []string
}

func hasMark(marks []string, m string) bool {
	for _, x := range marks {
		if x == m {
			return true
		}
	}
	return false
}

// judge gives an op that passed chain and seal checks its verdict, in the order of S11 with the
// two A1.1 rows after "origin device is revoked" and A1.3's row for the unsealed tail. rel is
// non-nil when a manager has released the op: the holds that caused the quarantine are skipped
// and the remaining checks still run ("checked as above").
func (g *Gateway) judge(tx repository.Tx, p *engine.Parsed, vc engine.VerdictCtx, rel *releaseCtx) engine.Verdict {
	tenant := tx.Tenant()
	origin := p.Item.Origin
	dir := g.cfg.Dir
	if strings.HasPrefix(origin, engine.CloudOriginPrefix) {
		return engine.Verdict{Status: repository.StAccepted}
	}
	quarantine := func(reason string, marks ...string) engine.Verdict {
		return engine.Verdict{Status: repository.StQuarantined, Reason: reason, Marks: marks}
	}
	if rel == nil {
		if p.Opaque {
			return quarantine(ReasonOpaque)
		}
		if vc.ChainBroken {
			return quarantine(ReasonChainBroken)
		}
	}
	b := p.Body
	in, known := sp.Intents[b.Intent]
	class := in.Class
	if !known {
		class = sp.ClassTrading
	}
	config := class == sp.ClassConfig
	void := func(reason string) engine.Verdict {
		return engine.Verdict{Status: repository.StVoided, Reason: reason, Void: true}
	}
	refuse := func(reason string, marks ...string) engine.Verdict { // quarantine for trading, void for config
		if config {
			return void(reason)
		}
		return quarantine(reason, marks...)
	}
	if known && b.IntentV > in.MaxV {
		return quarantine(ReasonOpaque) // no upcaster for this intent_v (S13)
	}
	var marks []string
	if rel != nil {
		marks = append(marks, rel.Marks...)
		marks = append(marks, MarkReleased)
	}
	cred, _ := dir.Credential(tenant, origin)
	kind := cred.Cred.Kind
	revoked, _ := dir.Revoked(tenant, origin)

	// Origin device is revoked, including the recovery path; the unsealed tail of a key-lost origin.
	if rel == nil && (revoked || vc.Unsealed) {
		switch {
		case vc.Unsealed && config:
			return void(ReasonUnsealedTail) // A1.3 item 5 right column; KL11
		case vc.Unsealed:
			return quarantine(ReasonUnsealedTail, MarkUnsealed)
		case vc.Recovery && vc.Sealed:
			return quarantine(ReasonRevoked, MarkRecoveredSealed)
		default:
			return quarantine(ReasonRevoked)
		}
	}
	if vc.Unsealed || hasMark(marks, MarkUnsealed) {
		marks = append(marks, MarkUnsealed)
	}
	flagged := false
	flag := func(m string) { flagged = true; marks = append(marks, m) }

	// A1.1: a legal document number must come from a series issued to the origin device.
	if b.Doc != nil {
		if config {
			return quarantine(ReasonMalformed)
		}
		si, found := dir.Series(tenant, b.Doc.SeriesCode())
		switch {
		case !found && rel == nil:
			return quarantine(ReasonForeignSeries, MarkUnknownSeries)
		case !found:
			flag(MarkUnknownSeries) // released by a manager after vendor confirmation: kept, flagged
		case si.Device != origin && rel == nil:
			return quarantine(ReasonForeignSeries, MarkForeign)
		case si.Device != origin:
			flag(MarkForeign)
		default:
			if si.State == directory.SeriesClosed && !revoked {
				flag(MarkSeriesClosed)
			}
			if si.State == directory.SeriesDormant {
				if on, _, _ := tx.GetMeta("activated:" + si.Code); on == "" {
					flag(MarkDormantSeries)
				}
			}
			if si.DocType != b.Doc.Type {
				flag(MarkDocTypeMismatch)
			}
		}
	}
	// Intent not allowed for the device kind.
	if !known || !in.Allows(kind) {
		if rel == nil || config {
			return refuse(ReasonIntentNotAllow)
		}
		flag(ReasonIntentNotAllow) // a manager accepted the held sale: it stays, flagged
	}
	// Actor never appeared in any pack issued to the device.
	if b.Actor == "" || !dir.InAnyPack(tenant, origin, b.Actor) {
		if rel == nil || config {
			return refuse(ReasonActorUnknown)
		}
		flag(ReasonActorUnknown)
	}
	// Clock: a last-writer-wins op far ahead of the receiver, or stamped under a manual clock,
	// waits for review instead of being applied (S5).
	if config && touchesLWW(b.Muts) && rel == nil {
		h, _ := sp.ParseHLC(b.HLC)
		if b.Clk == sp.ClkManual || time.UnixMilli(h.Millis()).After(g.cfg.Now().Add(10*time.Minute)) {
			return quarantine(ReasonClockReview)
		}
	}
	// Session and action proofs (identity only). A configuration op waits if identity is down;
	// a sale never does (S11, A1.2 item 4).
	switch dir.CheckProof(tenant, origin, b.Actor, b.SID, b.Proof, config) {
	case directory.ProofValid:
	case directory.ProofMissing, directory.ProofInvalid:
		if config {
			return void(ReasonProofFailed)
		}
		flag(MarkAttributionUnverified)
	case directory.ProofLocked:
		if config {
			return void(ReasonProofLocked)
		}
	case directory.ProofUnavailable:
		if config {
			return quarantine(ReasonConfigPending)
		}
		marks = append(marks, MarkProofPending)
	}
	// Permission held in the op's own pack, then since withdrawn or pack expired (H-3: flagged, never rejected).
	pack, havePack := dir.PackFor(tenant, origin, b.PackV)
	if in.Permission != "" {
		if !havePack || !pack.Members[b.Actor][in.Permission] {
			if config {
				return void(ReasonPermAbsent)
			}
			flag(MarkPermissionFlag)
		} else {
			at, _ := time.Parse("2006-01-02T15:04:05.000Z", b.At)
			if !dir.StillHolds(tenant, b.Actor, in.Permission) || (!pack.Expires.IsZero() && at.After(pack.Expires)) {
				if config {
					return void(ReasonPermWithdrawn)
				}
				flag(MarkPermissionFlag)
			}
		}
	}
	if b.Intent == "series.activate" {
		flag(MarkActivationFlag) // an offline activation is flagged for the owner (S7)
	}
	if config {
		if st, _, _ := tx.SessionType(origin, b.SID); st == "pin" {
			marks = append(marks, MarkConfigShared)
		}
	}
	if flagged {
		return engine.Verdict{Status: repository.StFlagged, Marks: marks}
	}
	return engine.Verdict{Status: repository.StAccepted, Marks: marks}
}

func touchesLWW(muts []sp.Mut) bool {
	for _, m := range muts {
		if d, ok := engine.Entities[m.E]; ok && d.Policy == engine.PolLWW {
			return true
		}
	}
	return false
}

// stored runs in the storing transaction for every new slot: register, alerts, outbox, the
// activation record and the void a refused configuration op needs.
func (g *Gateway) stored(tx repository.Tx, e *engine.Engine, rec repository.OpRec, p *engine.Parsed, v engine.Verdict) error {
	marks := v.Marks
	if !p.Opaque && p.Body.Doc != nil {
		if err := g.register(tx, rec, p.Body, v); err != nil {
			return err
		}
	}
	switch v.Status {
	case repository.StQuarantined:
		aud := "owner"
		sev := "medium"
		switch v.Reason {
		case ReasonForeignSeries:
			sev = "high"
			if err := g.alert(tx, "vendor", "high", "foreign_series", rec); err != nil {
				return err
			}
		case ReasonChainBroken:
			if err := g.alert(tx, "vendor", "high", "chain_broken", rec); err != nil {
				return err
			}
		case ReasonUnsealedTail:
			if err := g.alert(tx, "vendor", "medium", "recovered_unsealed", rec); err != nil {
				return err
			}
		}
		if err := tx.AddAlert(aud, sev, "quarantined:"+v.Reason, fmt.Sprintf("%s/%s/%d", rec.Origin, rec.Stream, rec.Seq)); err != nil {
			return err
		}
	case repository.StFlagged, repository.StAccepted:
		if hasMark(marks, MarkAttributionUnverified) {
			if err := g.alert(tx, "owner", "medium", "attribution_unverified", rec); err != nil {
				return err
			}
		}
		if rec.Intent == "series.activate" && !p.Opaque {
			for _, m := range p.Body.Muts {
				if m.E == "series_activation" {
					if err := tx.SetMeta("activated:"+m.ID, "1"); err != nil {
						return err
					}
				}
			}
		}
		if err := g.publish(tx, rec); err != nil {
			return err
		}
	}
	if v.Void && !p.Opaque {
		_, err := e.RecordAndSealTx(tx, engine.Input{Stream: rec.Stream, Intent: sp.IntentVoid, Muts: []sp.Mut{{
			E: "sync_void", ID: sp.VoidID(sp.Ref{Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq}), K: sp.KInsert,
			F: map[string]any{"origin": rec.Origin, "stream": rec.Stream, "seq": rec.Seq, "reason": sp.VoidReasonCloud},
		}}})
		return err
	}
	return nil
}

// register keeps the series register: every number seen, whatever its verdict (S7, A1.1).
func (g *Gateway) register(tx repository.Tx, rec repository.OpRec, b sp.Body, v engine.Verdict) error {
	parts := strings.Split(b.Doc.Number, "/")
	if len(parts) != 3 {
		return nil
	}
	n, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil
	}
	state := v.Status
	if state == repository.StVoided {
		state = repository.StQuarantined
	}
	mark := ""
	for _, m := range []string{MarkForeign, MarkUnknownSeries, MarkUnsealed, MarkRecoveredSealed} {
		if hasMark(v.Marks, m) {
			mark = m
			break
		}
	}
	if mark == MarkUnsealed {
		mark = "recovered_unsealed"
	}
	return tx.PutRegister(repository.RegisterEntry{Code: parts[0], FY: parts[1], Num: n, Number: b.Doc.Number, DocType: b.Doc.Type,
		Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq, State: state, Mark: mark})
}

// onFork keeps a slot whose content differs from what the cloud holds: both versions stay, a
// vendor alert is raised, and the held slot is marked so that neither side is released by an
// owner alone (A1.3 items 4 and 9, KL4, KL5).
func (g *Gateway) onFork(tx repository.Tx, c engine.Caller, rec repository.OpRec, it sp.Item) error {
	if err := tx.PutFork(rec.Stream, rec.Origin, rec.Seq, it.H, it.Body, c.ID); err != nil {
		return err
	}
	if rec.Status == repository.StQuarantined && rec.Reason != ReasonFork {
		rec.Reason = ReasonFork
		rec.Marks = strings.Trim(rec.Marks+","+MarkFork, ",")
		if err := tx.UpdateOp(rec); err != nil {
			return err
		}
	}
	return tx.AddAlert("vendor", "high", "fork", fmt.Sprintf("%s/%s/%d", rec.Origin, rec.Stream, rec.Seq))
}
