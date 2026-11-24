package service

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Errors of manager decisions on quarantine (S11).
var (
	ErrNeedsVendor      = errors.New("service: release needs vendor support confirmation")
	ErrNeedsRecoverPerm = errors.New("service: release of an unsealed tail needs device.recover")
	ErrCannotRelease    = errors.New("service: an opaque body cannot be released")
	ErrDiscardNumbered  = errors.New("service: an op that carries a legal document number cannot be discarded")
	ErrForbidden        = errors.New("service: not allowed")
)

// ReleaseOpts carries what the caller's authority allows.
type ReleaseOpts struct {
	// VendorConfirmed: Hostry support has confirmed the cause (chain broken, foreign series, fork).
	VendorConfirmed bool
	// DeviceRecover: the caller holds device.recover in a strong session.
	DeviceRecover bool
}

// QuarantineItem is one held slot as the manager sees it.
type QuarantineItem struct {
	Ref    sp.Ref   `json:"ref"`
	Reason string   `json:"reason"`
	Marks  []string `json:"marks,omitempty"`
	Intent string   `json:"intent,omitempty"`
	Number string   `json:"number,omitempty"`
}

func splitMarks(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func docNumber(body string) string {
	if body == "" {
		return ""
	}
	if b, err := sp.DecodeBody(body); err == nil && b.Doc != nil {
		return b.Doc.Number
	}
	return ""
}

// Quarantine lists the tenant's held slots (read with a member token only).
func (g *Gateway) Quarantine(ctx context.Context, tenant string) ([]QuarantineItem, error) {
	var out []QuarantineItem
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		recs, err := tx.ByStatus(repository.StQuarantined)
		if err != nil {
			return err
		}
		for _, r := range recs {
			out = append(out, QuarantineItem{Ref: sp.Ref{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq}, Reason: r.Reason, Marks: splitMarks(r.Marks), Intent: r.Intent, Number: docNumber(r.Body)})
		}
		return nil
	})
	return out, err
}

// Exceptions lists flagged ops with their marks: the manager's exceptions report. Flags and
// attribution labels are readable only through this call, with a member token (A1.2 item 2).
func (g *Gateway) Exceptions(ctx context.Context, tenant string) ([]QuarantineItem, error) {
	var out []QuarantineItem
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		recs, err := tx.ByStatus(repository.StFlagged)
		if err != nil {
			return err
		}
		for _, r := range recs {
			out = append(out, QuarantineItem{Ref: sp.Ref{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq}, Marks: splitMarks(r.Marks), Intent: r.Intent, Number: docNumber(r.Body)})
		}
		return nil
	})
	return out, err
}

// Release lets a held slot into normal processing, where it is checked as above (S11).
func (g *Gateway) Release(ctx context.Context, tenant string, ref sp.Ref, o ReleaseOpts) (string, error) {
	e := g.engineFor(tenant)
	var status string
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		rec, ok, err := tx.GetOp(ref.Stream, ref.Origin, ref.Seq)
		if err != nil {
			return err
		}
		if !ok || rec.Status != repository.StQuarantined {
			return ErrNotFound
		}
		switch rec.Reason {
		case ReasonChainBroken, ReasonForeignSeries, ReasonFork:
			if !o.VendorConfirmed {
				return ErrNeedsVendor
			}
		case ReasonUnsealedTail:
			if !o.DeviceRecover {
				return ErrNeedsRecoverPerm
			}
		case ReasonOpaque:
			return ErrCannotRelease
		}
		b, derr := sp.DecodeBody(rec.Body)
		if derr != nil {
			return ErrCannotRelease
		}
		p := &engine.Parsed{Item: sp.Item{Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq, H: rec.H, Body: rec.Body}, Body: b}
		var rel *releaseCtx
		if rec.Reason != ReasonConfigPending {
			rel = &releaseCtx{Marks: splitMarks(rec.Marks)}
		}
		v := g.judge(tx, p, engine.VerdictCtx{Own: false}, rel)
		if v.Status == repository.StQuarantined {
			return nil // still held (identity still down); nothing changes
		}
		rec.Status, rec.Reason, rec.Marks = v.Status, v.Reason, strings.Join(v.Marks, ",")
		if err := tx.UpdateOp(rec); err != nil {
			return err
		}
		status = v.Status
		if (v.Status == repository.StAccepted || v.Status == repository.StFlagged) && hasMark(v.Marks, MarkUnsealed) {
			// The tail has no origin seal: the gateway endorses the released op so that peers can take it.
			if _, _, _, have, err := tx.GetSeal(rec.Stream, rec.Origin, rec.Seq); err != nil {
				return err
			} else if !have {
				sl, err := sp.MakeSeal(g.cfg.OpKey, rec.Origin, rec.Stream, rec.Seq, rec.H)
				if err != nil {
					return err
				}
				if err := tx.PutSeal(rec.Stream, rec.Origin, rec.Seq, rec.H, sl.Kid, sl.Sig); err != nil {
					return err
				}
			}
		}
		return g.stored(tx, e, rec, p, v)
	})
	if err == nil && status != "" {
		g.poker(tenant).bump()
	}
	return status, err
}

// Discard removes a held slot's effect: allowed only for an op with no legal document number. It
// is carried out as a void so that LAN peers that already applied the op converge (S11).
func (g *Gateway) Discard(ctx context.Context, tenant string, ref sp.Ref) error {
	e := g.engineFor(tenant)
	return g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		rec, ok, err := tx.GetOp(ref.Stream, ref.Origin, ref.Seq)
		if err != nil {
			return err
		}
		if !ok || rec.Status != repository.StQuarantined {
			return ErrNotFound
		}
		b, derr := sp.DecodeBody(rec.Body)
		if derr != nil || b.Doc != nil || rec.Reason == ReasonForeignSeries {
			return ErrDiscardNumbered
		}
		rec.Status, rec.Reason = repository.StVoided, ReasonDiscarded
		if err := tx.UpdateOp(rec); err != nil {
			return err
		}
		return g.stored(tx, e, rec, &engine.Parsed{Item: sp.Item{Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq}, Body: b},
			engine.Verdict{Status: repository.StVoided, Reason: ReasonDiscarded, Void: true})
	})
}

// ReverifyPending re-judges configuration ops that waited for identity (S11, A1.2 item 4).
func (g *Gateway) ReverifyPending(ctx context.Context, tenant string) (int, error) {
	items, err := g.Quarantine(ctx, tenant)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range items {
		if it.Reason != ReasonConfigPending {
			continue
		}
		st, err := g.Release(ctx, tenant, it.Ref, ReleaseOpts{})
		if err != nil {
			return n, err
		}
		if st != "" {
			n++
		}
	}
	return n, nil
}

// Gap is a missing number in a series.
type Gap struct {
	Code    string  `json:"code"`
	FY      string  `json:"fy"`
	Missing []int64 `json:"missing"`
}

// RegisterReport is the tenant's series register with its gap check (S7, A1.1).
type RegisterReport struct {
	Entries []repository.RegisterEntry `json:"entries"`
	Gaps    []Gap                      `json:"gaps"`
	// Foreign lists numbers claimed in a series that belongs to another device of the tenant.
	Foreign []repository.RegisterEntry `json:"foreign"`
	// Unknown lists numbers whose code was never issued in the tenant.
	Unknown []repository.RegisterEntry `json:"unknown"`
}

// Register returns the series register of one tenant. Another tenant's register is never read.
func (g *Gateway) Register(ctx context.Context, tenant string) (RegisterReport, error) {
	var rep RegisterReport
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		entries, err := tx.Register()
		if err != nil {
			return err
		}
		rep.Entries = entries
		type key struct{ code, fy string }
		have := map[key]map[int64]bool{}
		for _, e := range entries {
			switch e.Mark {
			case MarkForeign:
				rep.Foreign = append(rep.Foreign, e)
				continue
			case MarkUnknownSeries:
				rep.Unknown = append(rep.Unknown, e)
				continue
			}
			k := key{e.Code, e.FY}
			if have[k] == nil {
				have[k] = map[int64]bool{}
			}
			have[k][e.Num] = true
		}
		for k, nums := range have {
			var max int64
			for n := range nums {
				if n > max {
					max = n
				}
			}
			var missing []int64
			for n := int64(1); n <= max; n++ {
				if !nums[n] {
					missing = append(missing, n)
				}
			}
			if len(missing) > 0 {
				rep.Gaps = append(rep.Gaps, Gap{Code: k.code, FY: k.fy, Missing: missing})
			}
		}
		sort.Slice(rep.Gaps, func(i, j int) bool { return rep.Gaps[i].Code+rep.Gaps[i].FY < rep.Gaps[j].Code+rep.Gaps[j].FY })
		return nil
	})
	return rep, err
}

// Alerts lists the tenant's alerts.
func (g *Gateway) Alerts(ctx context.Context, tenant string) ([]repository.Alert, error) {
	var out []repository.Alert
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		var err error
		out, err = tx.Alerts()
		return err
	})
	return out, err
}

type attested struct {
	Seq int64  `json:"seq"`
	H   string `json:"h"`
}

// QuarantineUpload is the one endpoint a revoked device may use, and the recovery upload of a
// key-lost origin (S10, A1.3). It stores the origin's own ops in quarantine without judging their
// content, and reports how far the origin is drained.
func (g *Gateway) QuarantineUpload(ctx context.Context, tenant string, c engine.Caller, req sp.PushRequest) (sp.PushResponse, error) {
	if !c.Drain {
		return sp.PushResponse{}, ErrForbidden
	}
	if err := g.refreshEpoch(ctx); err != nil {
		return sp.PushResponse{}, err
	}
	e := g.engineFor(tenant)
	var valid []sp.Attestation
	var refused []sp.Refusal
	if c.Recovers != "" {
		rec, ok := g.cfg.Dir.RecoveryFor(tenant, c.Recovers)
		cred, cok := g.cfg.Dir.Credential(tenant, c.ID)
		if !ok || !cok || rec.New != c.ID {
			return sp.PushResponse{}, ErrForbidden
		}
		pub, _ := cred.Cred.PubKey()
		fixed := map[string]attested{}
		if err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
			r, _, err := tx.GetRecovery(rec.ID)
			if err != nil {
				return err
			}
			if r.Attested != "" {
				_ = json.Unmarshal([]byte(r.Attested), &fixed)
			}
			changed := false
			for _, a := range req.Attestations {
				k := sp.VKey(a.Origin, a.Stream)
				if a.Origin != c.Recovers || a.By != c.ID || a.Rec != rec.ID || !a.Verify(pub) {
					refused = append(refused, sp.Refusal{Origin: a.Origin, Stream: a.Stream, Seq: a.Seq, Reason: sp.ReasonRecovery})
					continue
				}
				if prev, ok := fixed[k]; ok && (prev.Seq != a.Seq || prev.H != a.H) {
					// A second attestation with different content (KL6): refused, kept as fork evidence.
					if err := tx.PutFork(a.Stream, a.Origin, a.Seq, a.H, "", c.ID); err != nil {
						return err
					}
					refused = append(refused, sp.Refusal{Origin: a.Origin, Stream: a.Stream, Seq: a.Seq, Reason: sp.ReasonFork})
					continue
				}
				if _, ok := fixed[k]; !ok {
					fixed[k] = attested{a.Seq, a.H}
					changed = true
				}
				valid = append(valid, a)
			}
			if changed || r.RecID == "" {
				raw, _ := json.Marshal(fixed)
				return tx.PutRecovery(repository.Recovery{RecID: rec.ID, OldDevice: rec.Old, NewDevice: rec.New, Attested: string(raw), Drained: r.Drained})
			}
			return nil
		}); err != nil {
			return sp.PushResponse{}, err
		}
	}
	res, err := e.Ingest(ctx, engine.IngestReq{Items: req.Items, Seals: req.Seals, Attestations: valid, Caller: c, Recovery: true})
	if err != nil {
		return sp.PushResponse{}, err
	}
	resp := sp.PushResponse{Epoch: g.Epoch(), Vector: res.Vector, Held: res.Held, Refused: append(refused, res.Refused...)}
	if c.Recovers != "" && len(valid) > 0 {
		vec, err := e.Vector(ctx)
		if err != nil {
			return resp, err
		}
		drained := true
		for _, a := range valid {
			if vec[sp.VKey(a.Origin, a.Stream)] < a.Seq {
				drained = false
			}
		}
		resp.Drained = drained
		if drained {
			rec, _ := g.cfg.Dir.RecoveryFor(tenant, c.Recovers)
			_ = g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
				r, _, _ := tx.GetRecovery(rec.ID)
				r.RecID, r.OldDevice, r.NewDevice, r.Drained = rec.ID, rec.Old, rec.New, true
				return tx.PutRecovery(r)
			})
		}
	}
	if len(res.New) > 0 {
		g.poker(tenant).bump()
	}
	return resp, nil
}
