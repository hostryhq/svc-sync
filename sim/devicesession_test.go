package sim

import (
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// A device session (a KDS) is exempt from the 16-hour limit of a pin session, lasts at most 26 hours and is re-opened
// each business day (sync/protocol-v1.md, Device-session lifetime): an op recorded 20 hours in is accepted, one 27 hours
// in is judged as one of a closed session, and a new session.open makes the next op clean again.
func TestDeviceSessionLivesTwentySixHoursAndIsReopened(t *testing.T) {
	w, _ := newTestWorld(t, 503, WorldOptions{Pos: 1, KDS: 1, NoHub: true})
	_, k := devicesByKind(w)
	own := service.DeviceActorPrefix + k.ID
	t0 := w.Clock.Now().Truncate(time.Millisecond)
	open := func(sid string, at time.Time) {
		must(k.record(engine.Input{Stream: "outlet:" + w.Outlet, Intent: sp.IntentSessionOpen, Actor: own, SID: sid, Proof: "none", At: at,
			Muts: []sp.Mut{{E: "session", ID: sid, K: sp.KInsert, F: map[string]any{"type": "device", "device": k.ID}}}}, true))
	}
	bump := func(sid string, at time.Time) sp.Item {
		return must(k.record(engine.Input{Stream: "outlet:" + w.Outlet, Intent: "kds.status", Actor: own, SID: sid, Proof: "none", At: at,
			Muts: []sp.Mut{{E: "kot_line", ID: "kl-1", K: sp.KRank, F: map[string]any{"status": "preparing"}}}}, true))
	}
	open("sd-1", t0)
	in20h := bump("sd-1", t0.Add(20*time.Hour)) // past a pin session's 16 hours
	in27h := bump("sd-1", t0.Add(27*time.Hour))
	open("sd-2", t0.Add(27*time.Hour))
	reopened := bump("sd-2", t0.Add(28*time.Hour))
	w.toCloud(t, k)
	if r := w.rec(t, in20h); r.Status != repository.StAccepted {
		t.Fatalf("20 hours into a device session: got %s %s %s, want accepted", r.Status, r.Reason, r.Marks)
	}
	if r := w.rec(t, in27h); r.Status != repository.StFlagged || !hasMark(r, service.MarkAttributionUnverified) {
		t.Fatalf("27 hours into a device session: got %s %s, want flagged as the op of a closed session", r.Status, r.Marks)
	}
	if r := w.rec(t, reopened); r.Status != repository.StAccepted {
		t.Fatalf("after a new session.open: got %s %s %s, want accepted", r.Status, r.Reason, r.Marks)
	}
}
