package sim

import (
	"context"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// StatementOf builds and signs the drain statement of a device (ADR-0005 A3.3 item 1): every stream in which its log
// holds an own-origin op with the head, and every series of its pack with the last number it allocated. edit may change
// the statement before it is signed (tests of a statement that does not match).
func (w *World) StatementOf(d *Device, key *sp.KeyPair, edit func(*sp.DrainStatement)) (sp.DrainStatement, error) {
	st := sp.DrainStatement{Origin: d.ID, By: d.ID, At: w.Clock.Now().UTC().Format("2006-01-02T15:04:05Z"), Streams: []sp.DrainStream{}, Series: []sp.DrainSeriesLast{}}
	fy := engine.FY(w.Clock.Now())
	err := d.Eng.InTxLocked(w.Ctx, func(tx repository.Tx) error {
		hs, err := tx.Heads()
		if err != nil {
			return err
		}
		for _, h := range hs {
			if h.Origin != d.ID {
				continue
			}
			op, _, err := tx.GetOp(h.Stream, h.Origin, h.Seq)
			if err != nil {
				return err
			}
			st.Streams = append(st.Streams, sp.DrainStream{Stream: h.Stream, Seq: h.Seq, H: op.H})
		}
		for _, s := range w.Identity.SeriesOf(w.Tenant, d.ID) {
			n, err := tx.PeekNumber(s.Code, fy)
			if err != nil {
				return err
			}
			st.Series = append(st.Series, sp.DrainSeriesLast{SeriesID: "series-" + s.Code, Code: s.Code, FY: fy, LastNumber: n})
		}
		return nil
	})
	if err != nil {
		return st, err
	}
	if edit != nil {
		edit(&st)
	}
	return sp.MakeDrainStatement(key, st)
}

// Drain runs the drain of a revoked device as the shell does (A3.3 item 2): upload the own ops with the drain token,
// then one last upload with no items and the signed statement. It reports whether the gateway answered drained.
func (w *World) Drain(ctx context.Context, d *Device) (bool, error) {
	req, err := d.Eng.Outbound(ctx, sp.Vector{}, engine.OutboundOpts{})
	if err != nil {
		return false, err
	}
	if _, err := w.UploadRevokedDrain(ctx, d, d.ID, d.Key, req); err != nil {
		return false, err
	}
	st, err := w.StatementOf(d, d.Key, nil)
	if err != nil {
		return false, err
	}
	resp, err := w.UploadRevokedDrain(ctx, d, d.ID, d.Key, sp.PushRequest{Items: []sp.Item{}, DrainStatement: &st})
	return resp.Drained, err
}
