package sim

import (
	"context"
	"fmt"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// CheckOp records a check with the customer's name and GSTIN beside it (pii fields of the registry entity `check`, ADR-0014
// A3.1). The ref is kept for the placement check.
func (d *Device) CheckOp(rng *Rand) (sp.Item, error) {
	id := d.nextID("chk")
	pii := fmt.Sprintf(`{"check":{%q:{"customer_name":"Customer %d","customer_gstin":"33AAAAA%04dA1Z5"}}}`, id, rng.Range(1, 9999), rng.Range(0, 9999))
	it, err := d.Do(pCashier, engine.Input{Intent: "check.create", PII: []byte(pii),
		Muts: []sp.Mut{{E: "check", ID: id, K: sp.KInsert, F: map[string]any{"label": "Guest " + id}}}})
	if err == nil {
		d.W.PIIOps = append(d.W.PIIOps, sp.Ref{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq})
	}
	return it, err
}

// CheckPII is the placement half of T1 (ADR-0014 A3.2 item 3): once the world has quiesced, every pos, waiter and hub and the
// cloud holds the values of every check whose values survive anywhere, each verified against its commitment on receipt; no
// kds holds any; and no live staff node is left with a field it still asks for. A value that only a lost device ever held is
// gone with the device and is not demanded.
func (w *World) CheckPII(ctx context.Context) []Problem {
	var ps []Problem
	bad := func(check, f string, a ...any) { ps = append(ps, Problem{check, fmt.Sprintf(f, a...)}) }
	type node struct {
		name  string
		e     *engine.Engine
		store repository.Store
		staff bool
	}
	var nodes []node
	for _, d := range w.Devices {
		if d.KeyLost {
			continue
		}
		nodes = append(nodes, node{"device " + d.ID, d.Eng, d.Store, d.Kind != sp.KindKDS})
	}
	if w.Hub != nil {
		nodes = append(nodes, node{"hub", w.Hub.Engine(), w.Hub.Engine().Config().Store, true})
	}
	holds := func(store repository.Store, ref sp.Ref) bool {
		var ok bool
		_ = store.InTx(ctx, w.Tenant, func(tx repository.Tx) error {
			_, ok, _ = tx.GetPII(ref.Stream, ref.Origin, ref.Seq)
			return nil
		})
		return ok
	}
	lost := map[string]bool{}
	for _, ref := range w.PIIOps {
		survives := holds(w.GWStore, ref)
		for _, n := range nodes {
			if n.staff && holds(n.store, ref) {
				survives = true
			}
		}
		if !survives {
			lost[opKeyOf(ref)] = true
			continue
		}
		if !holds(w.GWStore, ref) {
			bad("pii-placement", "the cloud lacks the values of %s", ref.Key())
		}
		for _, n := range nodes {
			switch has := holds(n.store, ref); {
			case n.staff && !has:
				bad("pii-placement", "%s lacks the values of %s", n.name, ref.Key())
			case !n.staff && has:
				bad("pii-kds", "%s (a kds) holds the values of %s", n.name, ref.Key())
			}
		}
	}
	for _, n := range nodes {
		if !n.staff {
			continue
		}
		_ = n.store.InTx(ctx, w.Tenant, func(tx repository.Tx) error {
			refs, _ := n.e.IncompletePII(tx, 1000)
			for _, ref := range refs {
				if !lost[opKeyOf(ref)] {
					bad("pii-incomplete", "%s still asks for the values of %s", n.name, ref.Key())
				}
			}
			return nil
		})
	}
	return ps
}

func opKeyOf(r sp.Ref) string { return r.Stream + "|" + r.Origin + "|" + fmt.Sprint(r.Seq) }
