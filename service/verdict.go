package service

import (
	"fmt"
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
	MarkManualBook            = "manual_book"
	MarkAfterClosure          = "after_closure"
	MarkActivationFlag        = "series_activation"
	MarkFork                  = "fork"
	MarkReleased              = "released"
	MarkPIIDropped            = "pii_dropped"
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
	if len(p.Item.Body) > sp.MaxBodyBytes {
		return quarantine(ReasonOpaque) // over the size limit: malformed (S11), kept as an opaque body, never published with its body
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

	// A1.1: every legal document number must come from a series issued to the origin device. One op may
	// carry several (bill.rebill: a credit note and a new bill); it never takes a series twice.
	if docs := b.Documents(); len(docs) > 0 {
		if config {
			return quarantine(ReasonMalformed)
		}
		codes := map[string]bool{}
		for _, doc := range docs {
			code, _, _, ok := doc.ParseNumber()
			if !ok || codes[code] {
				return quarantine(ReasonMalformed) // an op never takes a number twice from one series
			}
			codes[code] = true
		}
		for _, doc := range docs {
			si, found := dir.Series(tenant, doc.SeriesCode())
			switch {
			case found && si.ManualBook():
				// A paper bill book: entry-only, typed numbers from a billing device of one of its outlets.
				if !manualBookEntry(si, b.Intent, cred.Cred.OutletID) {
					if rel == nil {
						return quarantine(ReasonForeignSeries, MarkForeign)
					}
					flag(MarkForeign)
				} else {
					marks = append(marks, MarkManualBook)
					if si.State == directory.SeriesClosed {
						flag(MarkAfterClosure) // a page found after the book was closed is accepted and flagged
					}
				}
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
				if si.DocType != doc.Type {
					flag(MarkDocTypeMismatch)
				}
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
	// A device session (no member, no PIN: the KDS screen) has an actor of its own, device:<device id> with the
	// id equal to the op's origin (sync/protocol-v1.md, Attribution of device-session ops). It is allowed only
	// for an intent whose registry row lists the device's kind and the device session type (a KOT bump), and
	// only inside a session.open of type device by the same origin. No member is consulted and no proof exists;
	// the permission is judged against the device role template of the kind. Free text such as device-kds, or
	// another device's id, is an unknown actor.
	devActor := known && b.Actor == DeviceActorPrefix+origin && in.Allows(kind) && in.AllowsSession(sp.SessionDevice) && deviceSession(tx, origin, b)
	// Actor never appeared in any pack issued to the device.
	if !devActor && (b.Actor == "" || !dir.InAnyPack(tenant, origin, b.Actor)) {
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
	proof := directory.ProofValid
	if !devActor {
		proof = dir.CheckProof(tenant, origin, b.Actor, b.SID, b.Proof, config)
	}
	switch proof {
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
		flag(MarkAttributionUnverified) // identity answers locked for every op kind: a sale is kept, its actor unverified
	case directory.ProofUnavailable:
		if config {
			return quarantine(ReasonConfigPending)
		}
		marks = append(marks, MarkProofPending)
	}
	// Permission held in the op's own pack, then since withdrawn or pack expired (H-3: flagged, never rejected).
	pack, havePack := dir.PackFor(tenant, origin, b.PackV)
	if devActor {
		if in.Permission != "" && !DeviceRoleHolds(kind, in.Permission) {
			if config {
				return void(ReasonPermAbsent)
			}
			flag(MarkPermissionFlag)
		}
	} else if in.Permission != "" {
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

// DeviceActorPrefix starts the actor of a device session: device:<device id>.
const DeviceActorPrefix = "device:"

// deviceRoleTemplates are the permissions a device session holds, by device kind (x-provisional until the
// ADR-0005 role templates exist; the KDS role is kds.bump and menu.availability.set).
var deviceRoleTemplates = map[string][]string{
	sp.KindKDS: {"kds.bump", "menu.availability.set"},
}

// DeviceRoleHolds reports whether the device role template of the kind holds the permission.
func DeviceRoleHolds(kind, perm string) bool {
	for _, p := range deviceRoleTemplates[kind] {
		if p == perm {
			return true
		}
	}
	return false
}

// deviceSession reports whether the op is recorded in a session of type device opened by the same origin: the
// stored session row, or, for the session.open op itself, its own session mutation.
func deviceSession(tx repository.Tx, origin string, b sp.Body) bool {
	if b.Intent == sp.IntentSessionOpen {
		for _, m := range b.Muts {
			if m.E == "session" && m.ID == b.SID {
				t, _ := m.F["type"].(string)
				return t == sp.SessionDevice
			}
		}
		return false
	}
	st, ok, _ := tx.SessionType(origin, b.SID)
	return ok && st == sp.SessionDevice
}

// manualBookEntry reports whether an op may take a number from a paper bill book: the intent types the
// number (never allocates it) and the device's outlet is one the book was registered for.
func manualBookEntry(si directory.SeriesInfo, intent, outlet string) bool {
	in, known := sp.Intents[intent]
	if !known || in.Numbering != "typed" {
		return false
	}
	if len(si.Outlets) == 0 {
		return true
	}
	for _, o := range si.Outlets {
		if o == outlet {
			return true
		}
	}
	return false
}

func touchesLWW(muts []sp.Mut) bool {
	for _, m := range muts {
		if d, ok := engine.Entities[m.E]; ok && d.HasLWW() {
			return true
		}
	}
	return false
}

// stored runs in the storing transaction for every new slot: register, alerts, outbox, the
// activation record and the void a refused configuration op needs.
func (g *Gateway) stored(tx repository.Tx, e *engine.Engine, rec repository.OpRec, p *engine.Parsed, v engine.Verdict) error {
	marks := v.Marks
	if !p.Opaque && len(p.Body.Documents()) > 0 {
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
		var body *sp.Body
		if !p.Opaque {
			body = &p.Body
		}
		if err := g.publishQuarantined(tx, rec, v.Reason, body); err != nil {
			return err
		}
	case repository.StFlagged, repository.StAccepted:
		if hasMark(marks, MarkAttributionUnverified) {
			if err := g.alert(tx, "owner", "medium", "attribution_unverified", rec); err != nil {
				return err
			}
		}
		if rec.Intent == "series.close" && !p.Opaque {
			if err := g.noteSeriesClose(tx, rec, p.Body); err != nil {
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
		if v.Status == repository.StFlagged {
			if err := g.publishFlagged(tx, rec, marks); err != nil {
				return err
			}
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

// register keeps the series register: every number the op carries, whatever its verdict (S7, A1.1).
func (g *Gateway) register(tx repository.Tx, rec repository.OpRec, b sp.Body, v engine.Verdict) error {
	state := v.Status
	if state == repository.StVoided {
		state = repository.StQuarantined
	}
	mark := ""
	for _, m := range []string{MarkForeign, MarkUnknownSeries, MarkUnsealed, MarkRecoveredSealed, MarkManualBook} {
		if hasMark(v.Marks, m) {
			mark = m
			break
		}
	}
	if mark == MarkUnsealed {
		mark = "recovered_unsealed"
	}
	for _, doc := range b.Documents() {
		code, fy, n, ok := doc.ParseNumber()
		if !ok {
			continue
		}
		if err := tx.PutRegister(repository.RegisterEntry{Code: code, FY: fy, Num: n, Number: doc.Number, DocType: doc.Type,
			Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq, State: state, Mark: mark}); err != nil {
			return err
		}
		if err := g.recheckSeries(tx, code, fy); err != nil {
			return err
		}
	}
	return nil
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
