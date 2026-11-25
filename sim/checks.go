package sim

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// CloudState replays the cloud's accepted and flagged ops into a state, as a domain projection
// would; a quarantined or voided op contributes nothing.
func (w *World) CloudState(ctx context.Context) (*engine.State, sp.Vector, error) {
	st := engine.NewState()
	vec := sp.Vector{}
	err := w.GWStore.InTx(ctx, w.Tenant, func(tx repository.Tx) error {
		var after int64
		var all []repository.OpRec
		for {
			page, err := tx.ByArrival(after, 2000)
			if err != nil {
				return err
			}
			if len(page) == 0 {
				break
			}
			after = page[len(page)-1].Arr
			all = append(all, page...)
		}
		live := func(r repository.OpRec) bool {
			return r.Body != "" && (r.Status == repository.StAccepted || r.Status == repository.StFlagged)
		}
		for _, r := range all {
			if k := sp.VKey(r.Origin, r.Stream); r.Seq > vec[k] {
				vec[k] = r.Seq
			}
			if r.Intent == sp.IntentVoid && live(r) {
				if b, err := sp.DecodeBody(r.Body); err == nil {
					for _, m := range b.Muts {
						if m.E == "sync_void" {
							o, _ := m.F["origin"].(string)
							s, _ := m.F["stream"].(string)
							q, _ := m.F["seq"].(int64)
							st.Void(sp.Ref{Origin: o, Stream: s, Seq: q})
						}
					}
				}
			}
		}
		for _, r := range all {
			if !live(r) {
				continue
			}
			b, err := sp.DecodeBody(r.Body)
			if err != nil {
				continue
			}
			h, _ := sp.ParseHLC(b.HLC)
			st.ApplyPII(sp.Ref{Origin: b.Origin, Stream: b.Stream, Seq: b.Seq}, h, b.Muts, b.PIIC)
		}
		return nil
	})
	return st, vec, err
}

// QuiesceReport says how a quiesce ended.
type QuiesceReport struct {
	Rounds    int
	Converged bool
}

// Quiesce heals every link, lifts faults and syncs until nothing changes (S15: "after quiescence
// all nodes have equal vectors and an equal canonical state hash").
func (w *World) Quiesce(ctx context.Context, maxRounds int) QuiesceReport {
	for _, name := range w.linkNames() {
		w.Net.SetDown(name, false)
		w.Net.Faults(name, 0, 0, 0, 0)
	}
	prev := ""
	same := 0
	rep := QuiesceReport{}
	for r := 1; r <= maxRounds; r++ {
		rep.Rounds = r
		w.Advance(10 * time.Second) // 10 s per round
		if w.Hub != nil {
			_, _ = w.Hub.SyncUpstream(ctx)
		}
		for _, d := range w.Devices {
			if d.KeyLost {
				continue
			}
			_ = d.Sync(ctx)
		}
		if w.Hub != nil {
			_, _ = w.Hub.SyncUpstream(ctx)
		}
		_ = w.GW.MaintainOnce(ctx) // the gateway's worker: pending proofs asked again, waiting configuration judged again
		sig := w.signature(ctx)
		if os.Getenv("SYNC_DEBUG") != "" && w.HubUp != nil && len(w.Hub.LastRefused()) > 0 {
			fmt.Printf("round %d hub refused: %+v\n", r, w.Hub.LastRefused()[:min(3, len(w.Hub.LastRefused()))])
		}
		if sig == prev {
			same++
			if same >= 2 {
				rep.Converged = true
				return rep
			}
		} else {
			same = 0
		}
		prev = sig
	}
	return rep
}

func (w *World) linkNames() []string {
	names := []string{"hub-cloud"}
	for _, d := range w.Devices {
		names = append(names, "dev-hub:"+d.ID, "dev-cloud:"+d.ID)
		for _, o := range d.Recovered {
			names = append(names, "dev-hub:"+o, "dev-cloud:"+o)
		}
	}
	return names
}

func (w *World) signature(ctx context.Context) string {
	var b strings.Builder
	for _, d := range w.Devices {
		v, _ := d.Eng.Vector(ctx)
		fmt.Fprintf(&b, "%s:%s|", d.ID, vecString(v))
	}
	if w.Hub != nil {
		v, _ := w.Hub.Engine().Vector(ctx)
		fmt.Fprintf(&b, "hub:%s|", vecString(v))
	}
	_, cv, _ := w.CloudState(ctx)
	fmt.Fprintf(&b, "cloud:%s", vecString(cv))
	return b.String()
}

func vecString(v sp.Vector) string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%d,", k, v[k])
	}
	return b.String()
}

// Problem is one failed invariant.
type Problem struct {
	Check, Detail string
}

func (p Problem) String() string { return p.Check + ": " + p.Detail }
