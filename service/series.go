package service

import (
	"encoding/json"
	"fmt"

	"github.com/hostryhq/go-common/events"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// metaSeriesClose is the meta key of a series statement: series-close:<code>:<fy>.
const metaSeriesClose = "series-close:"

// closeStmt is a device's statement that its series is closed and what its last number was
// (control intent series.close, ADR-0014 A2.5 item 2).
type closeStmt struct {
	Origin   string `json:"origin"`
	Stream   string `json:"stream"`
	SeriesID string `json:"series_id"`
	Last     int64  `json:"last"`
	Done     bool   `json:"done"`
	Gaps     int    `json:"gaps"`
}

func closeKey(code, fy string) string { return metaSeriesClose + code + ":" + fy }

// noteSeriesClose reads the series_close records of an accepted series.close op. The record is
// provisional (the registry names it, the shared parser does not know it): id = series id, fields
// code, fy, last_number. A repeated statement is ignored; a second statement with another last
// number is refused and alerted. A device may state only a series issued to it.
func (g *Gateway) noteSeriesClose(tx repository.Tx, rec repository.OpRec, b sp.Body) error {
	for _, m := range b.Muts {
		if m.E != sp.RecordSeriesEnd || m.K != sp.KInsert {
			continue
		}
		code, _ := m.F["code"].(string)
		fy, _ := m.F["fy"].(string)
		last, ok := m.F["last_number"].(int64)
		if code == "" || fy == "" || !ok || last < 0 {
			if err := g.alert(tx, "vendor", "medium", "series_close_malformed", rec); err != nil {
				return err
			}
			continue
		}
		if si, found := g.seriesOfOrigin(tx.Tenant(), rec.Origin, code); !found || si.Device != rec.Origin {
			if err := g.alert(tx, "vendor", "high", "series_close_foreign", rec); err != nil {
				return err
			}
			continue
		}
		key := closeKey(code, fy)
		if raw, ok, err := tx.GetMeta(key); err != nil {
			return err
		} else if ok {
			var prev closeStmt
			_ = json.Unmarshal([]byte(raw), &prev)
			if prev.Last != last {
				if err := g.alert(tx, "vendor", "high", "series_close_conflict", rec); err != nil {
					return err
				}
			}
			continue
		}
		raw, _ := json.Marshal(closeStmt{Origin: rec.Origin, Stream: rec.Stream, SeriesID: m.ID, Last: last})
		if err := tx.SetMeta(key, string(raw)); err != nil {
			return err
		}
		if err := g.recheckSeries(tx, code, fy); err != nil {
			return err
		}
	}
	return nil
}

// recheckSeries confirms the tail of a closed series: when the register holds every number up to the
// stated last number (a held number counts as held, never as a gap), the series is reconciled, once.
// Numbers still missing raise one owner alert and keep the statement open; a number that arrives
// later re-runs the check (register()).
func (g *Gateway) recheckSeries(tx repository.Tx, code, fy string) error {
	raw, ok, err := tx.GetMeta(closeKey(code, fy))
	if err != nil || !ok {
		return err
	}
	var st closeStmt
	if err := json.Unmarshal([]byte(raw), &st); err != nil || st.Done {
		return nil
	}
	all, err := tx.Register()
	if err != nil {
		return err
	}
	have := map[int64]bool{}
	for _, e := range all {
		if e.Code == code && e.FY == fy && e.Mark != MarkForeign && e.Mark != MarkUnknownSeries {
			have[e.Num] = true
		}
	}
	gaps := 0
	for n := int64(1); n <= st.Last; n++ {
		if !have[n] {
			gaps++
		}
	}
	if gaps > 0 {
		if st.Gaps == 0 { // alert once per statement
			st.Gaps = gaps
			out, _ := json.Marshal(st)
			if err := tx.SetMeta(closeKey(code, fy), string(out)); err != nil {
				return err
			}
			return tx.AddAlert("owner", "high", "series_tail_missing", fmt.Sprintf("%s/%s:%d", code, fy, gaps))
		}
		return nil
	}
	prevGaps := st.Gaps
	st.Done, st.Gaps = true, 0
	out, _ := json.Marshal(st)
	if err := tx.SetMeta(closeKey(code, fy), string(out)); err != nil {
		return err
	}
	if err := tx.ResolveAlerts("series_tail_missing", fmt.Sprintf("%s/%s:%d", code, fy, prevGaps)); err != nil {
		return err
	}
	return g.publishReconciled(tx, st)
}

// publishReconciled writes billing.series.reconciled (series id, last number, gap count; ADR-0014
// A2.5 item 2) to the outbox. Off by default: the event's x-publisher is billing, and the bus
// permissions are generated from it, so a relay from this service would be refused by the bus.
// The statement is still recorded; see docs notes (ADR needed: publisher of billing.series.reconciled).
func (g *Gateway) publishReconciled(tx repository.Tx, st closeStmt) error {
	if !g.cfg.ReconciledEvent || !g.outboxOn() {
		return nil
	}
	data, _ := json.Marshal(map[string]any{"series_id": st.SeriesID, "last_number": st.Last, "gap_count": 0})
	env := events.Envelope{ID: g.cfg.IDs.New(), Type: TypeSeriesReconciled, V: 1, Source: "billing", TenantID: ids.ID(tx.Tenant()),
		Key: st.SeriesID, KeySeq: 1, OccurredAt: g.cfg.Now(), Epoch: g.Epoch(), Data: data}
	if kind, sid, ok := splitStream(st.Stream); ok && kind == "outlet" {
		env.OutletID = ids.ID(sid)
	}
	return g.putOutbox(tx, env)
}

func splitStream(s string) (kind, id string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// SeriesState reports a series statement for tests and the owner's view: the stated last number and
// whether the series is reconciled.
func (g *Gateway) SeriesState(tx repository.Tx, code, fy string) (last int64, reconciled, stated bool, err error) {
	raw, ok, err := tx.GetMeta(closeKey(code, fy))
	if err != nil || !ok {
		return 0, false, false, err
	}
	var st closeStmt
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return 0, false, false, err
	}
	return st.Last, st.Done, true, nil
}

// seriesOfOrigin asks the directory for a series code as the origin device sees it.
func (g *Gateway) seriesOfOrigin(tenant, origin, code string) (directory.SeriesInfo, bool) {
	cred, _ := g.cfg.Dir.Credential(tenant, origin)
	return g.cfg.Dir.SeriesFor(tenant, origin, cred.Cred.OutletID, code)
}
