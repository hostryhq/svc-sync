package sim

import (
	"testing"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// statementOf builds the drain statement a device signs: every stream in which its log holds an own-origin op with
// the head, and every series of its pack with the last number it allocated (ADR-0005 A3.3 item 1).
func (w *World) statementOf(t *testing.T, d *Device, key *sp.KeyPair, edit func(*sp.DrainStatement)) sp.DrainStatement {
	t.Helper()
	st := sp.DrainStatement{Origin: d.ID, By: d.ID, At: w.Clock.Now().UTC().Format("2006-01-02T15:04:05Z"), Streams: []sp.DrainStream{}, Series: []sp.DrainSeriesLast{}}
	must0(d.Eng.InTxLocked(bg, func(tx repository.Tx) error {
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
			n, err := tx.PeekNumber(s.Code, engine.FY(w.Clock.Now()))
			if err != nil {
				return err
			}
			st.Series = append(st.Series, sp.DrainSeriesLast{SeriesID: "series-" + s.Code, Code: s.Code, FY: engine.FY(w.Clock.Now()), LastNumber: n})
		}
		return nil
	}))
	if edit != nil {
		edit(&st)
	}
	signed, err := sp.MakeDrainStatement(key, st)
	must0(err)
	return signed
}

// drainWorld revokes a POS that holds unsent ops and uploads them to quarantine, as the drain token of the device.
func drainWorld(t *testing.T, seed uint64) (*World, *Device) {
	t.Helper()
	w, _ := newTestWorld(t, seed, WorldOptions{Pos: 1, NoHub: true})
	a := w.Devices[0]
	rng := NewRand(seed)
	must(a.OrderOp(rng))
	must(a.BillOp(rng))
	must(a.OrderOp(rng))
	w.Identity.Revoke(a.ID, "revoked")
	req := must(a.Eng.Outbound(bg, sp.Vector{}, engine.OutboundOpts{}))
	must(w.UploadRevokedDrain(bg, a, a.ID, a.Key, req))
	return w, a
}

func (w *World) sendStatement(t *testing.T, a *Device, st sp.DrainStatement) sp.PushResponse {
	t.Helper()
	return must(w.UploadRevokedDrain(bg, a, a.ID, a.Key, sp.PushRequest{Items: []sp.Item{}, DrainStatement: &st}))
}

// DR2: the gateway holds everything and the device is silent: nothing is reported. No timer, no inference.
func TestDR2_NoStatementNoReport(t *testing.T) {
	w, a := drainWorld(t, 91)
	resp := must(w.UploadRevokedDrain(bg, a, a.ID, a.Key, sp.PushRequest{Items: []sp.Item{}}))
	if resp.Drained {
		t.Fatal("an upload without a statement never reports a drain")
	}
	must(w.GW.ReportPendingDrains(bg, w.Tenant))
	if _, ok := w.Identity.Drained(a.ID); ok {
		t.Fatal("identity was told without a signed statement")
	}
}

// The device-signed statement is the one trigger: identity gets the stored heads, the series list as the device
// stated it, and the statement verbatim.
func TestDrainStatementReportsOnceTheGatewayHoldsExactlyTheStatedOps(t *testing.T) {
	w, a := drainWorld(t, 92)
	st := w.statementOf(t, a, a.Key, nil)
	resp := w.sendStatement(t, a, st)
	if !resp.Drained {
		t.Fatalf("a satisfied statement drains the device: %+v", resp)
	}
	rep, ok := w.Identity.DrainReportOf(a.ID)
	if !ok {
		t.Fatal("identity was not told")
	}
	hash := must(st.Hash())
	if rep.Key != hash || len(rep.Series) != len(st.Series) || len(rep.Statement) == 0 {
		t.Fatalf("report %+v", rep)
	}
	for _, s := range st.Streams {
		if rep.Through[s.Stream] != s.Seq {
			t.Fatalf("through %v, statement %v", rep.Through, st.Streams)
		}
	}
	// A replay of the same statement is answered the same and reports nothing new.
	if r := w.sendStatement(t, a, st); !r.Drained {
		t.Fatal("a replay of the accepted statement answers drained")
	}
}

// DR1: a statement that is short of the gateway's holdings (an op the device did not list), one that lists more than
// the gateway holds, and one with a wrong hash are stored as evidence and report nothing.
func TestDR1_AStatementThatDoesNotMatchWhatTheGatewayHoldsIsRefused(t *testing.T) {
	for name, edit := range map[string]func(*sp.DrainStatement){
		"short of the gateway's head": func(s *sp.DrainStatement) { s.Streams[0].Seq-- },
		"more than the gateway holds": func(s *sp.DrainStatement) { s.Streams[0].Seq++ },
		"wrong hash at the head":      func(s *sp.DrainStatement) { s.Streams[0].H = "00" + s.Streams[0].H[2:] },
		"a stream left out":           func(s *sp.DrainStatement) { s.Streams = s.Streams[:0] },
		"a number above the stated": func(s *sp.DrainStatement) {
			for i := range s.Series { // the device claims it never used a series it did use
				s.Series[i].LastNumber = 0
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			w, a := drainWorld(t, 93)
			st := w.statementOf(t, a, a.Key, edit)
			if resp := w.sendStatement(t, a, st); resp.Drained {
				t.Fatal("a statement that does not match must not drain")
			}
			if _, ok := w.Identity.Drained(a.ID); ok {
				t.Fatal("identity was told")
			}
			if alerts := must(w.GW.Alerts(bg, w.Tenant)); !hasAlert(alerts, "drain_statement_refused") {
				t.Fatalf("a vendor alert is raised: %+v", alerts)
			}
		})
	}
}

func hasAlert(as []repository.Alert, kind string) bool {
	for _, a := range as {
		if a.Kind == kind && a.Audience == "vendor" {
			return true
		}
	}
	return false
}

// A statement signed by another key, a device that is not revoked, a second different statement and an upload above
// a stated head are all refused and kept.
func TestDrainStatementSignerRevocationSecondStatementAndLateUpload(t *testing.T) {
	w, a := drainWorld(t, 94)
	other := must(sp.NewKeyPair(a.Key.Kid, nil))
	if resp := w.sendStatement(t, a, w.statementOf(t, a, other, nil)); resp.Drained {
		t.Fatal("a statement not signed with the device's key must be refused")
	}
	st := w.statementOf(t, a, a.Key, nil)
	if resp := w.sendStatement(t, a, st); !resp.Drained {
		t.Fatalf("the right statement drains: %+v", resp)
	}
	second := w.statementOf(t, a, a.Key, func(s *sp.DrainStatement) { s.At = "2026-01-01T00:00:00Z" })
	if resp := w.sendStatement(t, a, second); resp.Drained && must(second.Hash()) != must(st.Hash()) {
		t.Fatal("a second, different statement must be refused")
	}
	// An op above the stated head: refused as fork evidence, never stored.
	extra := must(a.OrderOp(NewRand(7)))
	resp := must(w.UploadRevokedDrain(bg, a, a.ID, a.Key, must(a.Eng.Outbound(bg, sp.Vector{}, engine.OutboundOpts{}))))
	refused := false
	for _, r := range resp.Refused {
		refused = refused || (r.Origin == extra.Origin && r.Seq == extra.Seq)
	}
	if !refused {
		t.Fatalf("an upload above the stated head is refused: %+v", resp.Refused)
	}
	if _, ok, _ := w.opAt(extra); ok {
		t.Fatal("the late op must not be stored")
	}
}

func (w *World) opAt(it sp.Item) (repository.OpRec, bool, error) {
	var r repository.OpRec
	var ok bool
	err := w.GWStore.InTx(bg, w.Tenant, func(tx repository.Tx) error {
		var err error
		r, ok, err = tx.GetOp(it.Stream, it.Origin, it.Seq)
		return err
	})
	return r, ok, err
}

// A device that is not revoked has no drain token: the upload is refused before any statement is read.
func TestDrainStatementNeedsARevokedDevice(t *testing.T) {
	w, _ := newTestWorld(t, 95, WorldOptions{Pos: 1, NoHub: true})
	a := w.Devices[0]
	must(a.OrderOp(NewRand(1)))
	st := w.statementOf(t, a, a.Key, nil)
	if resp, err := w.UploadRevokedDrain(bg, a, a.ID, a.Key, sp.PushRequest{Items: []sp.Item{}, DrainStatement: &st}); err == nil && resp.Drained {
		t.Fatalf("a device that is not revoked is not drained: %+v", resp)
	}
	if _, ok := w.Identity.Drained(a.ID); ok {
		t.Fatal("identity was told")
	}
}
