package sim

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Features switch the hazards of a run on.
type Features struct {
	Partitions, Faults, Crashes, HubKills, Skew bool
	Rollback, KeyLoss, Inject, FYRollover       bool
}

// AllFeatures is the full hazard set.
var AllFeatures = Features{true, true, true, true, true, true, true, true, true}

// Options describe one simulated run.
type Options struct {
	Seed     uint64
	Steps    int
	Pos      int
	Waiters  int
	KDS      int
	Features Features
	Dir      string
	CloudDSN string
	// Inspect is called with the finished world before it is closed (debugging and tests).
	Inspect func(*World)
	// Trace keeps a log of every action (the last 400 are returned).
	Trace bool
}

// Stats summarise what a run did.
type Stats struct {
	Ops, Bills, Credit, Held, Voided, Flagged   int
	Crashes, HubKills, HubWipes, Rollbacks      int
	KeyLosses, Injected, Partitions, QuiesceRds int
	Net                                         NetStats
	HubOK, HubFail, CloudDirect                 int
}

// Result is the outcome of one run.
type Result struct {
	Seed     uint64
	Problems []Problem
	Stats    Stats
	Trace    []string
}

type runner struct {
	w     *World
	rng   *Rand
	opt   Options
	exp   *Expectations
	st    Stats
	trace []string
	// rollback plan
	snapAt, rollAt int
	snapped        bool
	rolled         int
	epochN         int
	// key loss plan
	lossAt, recoverAt int
	lossDev           *Device
	removedAt         int
	removed           bool
	skewDev           *Device
}

func (r *runner) logf(f string, a ...any) {
	if r.opt.Trace {
		r.trace = append(r.trace, fmt.Sprintf(f, a...))
	}
}

// Run executes one seeded scenario and checks every invariant. The same options always give the
// same run.
func Run(ctx context.Context, opt Options) (*Result, error) {
	if opt.Steps == 0 {
		opt.Steps = 400
	}
	if opt.Pos == 0 {
		opt.Pos = 2
	}
	if opt.Dir == "" {
		d, err := os.MkdirTemp("", "sim-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(d)
		opt.Dir = d
	}
	rng := NewRand(opt.Seed)
	wo := WorldOptions{Dir: opt.Dir, Pos: opt.Pos, Waiters: opt.Waiters, KDS: opt.KDS, CloudDSN: opt.CloudDSN}
	if opt.Features.FYRollover && opt.Seed%2 == 0 {
		wo.Start = time.Date(2027, 3, 31, 17, 0, 0, 0, time.UTC) // 22:30 IST: rolls into FY 2027-28 mid-run
	}
	w, err := NewWorld(ctx, rng, wo)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	r := &runner{w: w, rng: rng, opt: opt, exp: NewExpectations()}
	f := opt.Features
	if f.Rollback {
		r.snapAt = opt.Steps/4 + rng.Intn(opt.Steps/8+1)
		r.rollAt = opt.Steps/2 + rng.Intn(opt.Steps/4+1)
	}
	if f.KeyLoss {
		r.lossAt = opt.Steps/5 + rng.Intn(opt.Steps/4+1)
		r.recoverAt = r.lossAt + 20 + rng.Intn(40)
	}
	if f.Inject {
		r.removedAt = opt.Steps/3 + rng.Intn(opt.Steps/3+1)
	}
	for step := 0; step < opt.Steps; step++ {
		w.Advance(time.Duration(rng.Range(1, 25)) * time.Second)
		for _, d := range w.Devices {
			d.SealTick()
		}
		if err := r.step(ctx, step); err != nil {
			return nil, fmt.Errorf("seed %d step %d: %w", opt.Seed, step, err)
		}
	}
	res := r.finish(ctx)
	if opt.Inspect != nil {
		opt.Inspect(w)
	}
	return res, nil
}

func (r *runner) pick() *Device {
	var live []*Device
	for _, d := range r.w.Devices {
		if !d.KeyLost {
			live = append(live, d)
		}
	}
	if len(live) == 0 {
		return nil
	}
	return live[r.rng.Intn(len(live))]
}

func (r *runner) step(ctx context.Context, step int) error {
	w, rng, f := r.w, r.rng, r.opt.Features
	// Scheduled events.
	if f.Rollback && step == r.snapAt {
		if err := w.SnapshotCloud("a"); err != nil {
			return err
		}
		r.snapped = true
		r.logf("%d snapshot cloud", step)
	}
	if f.Rollback && r.snapped && step == r.rollAt {
		r.epochN++
		r.logf("%d RESTORE cloud to snapshot, epoch %d", step, r.epochN)
		if err := w.RestoreCloud("a", fmt.Sprintf("restore-%d", r.epochN)); err != nil {
			return err
		}
		r.st.Rollbacks++
		r.rolled++
	}
	if f.KeyLoss && step == r.lossAt {
		for _, d := range w.Devices {
			if d.Kind == sp.KindPOS && !d.KeyLost {
				d.LoseKey()
				r.lossDev = d
				r.st.KeyLosses++
				r.logf("%d key loss on %s", step, d.ID)
				break
			}
		}
	}
	if f.KeyLoss && step == r.recoverAt && r.lossDev != nil && r.lossDev.KeyLost {
		if err := r.recover(ctx, r.lossDev); err != nil {
			return err
		}
	}
	if f.Inject && !r.removed && step == r.removedAt {
		w.Identity.RemoveMember(w.Tenant, pLeaver)
		r.removed = true
		r.logf("%d member %s removed while outlet offline", step, pLeaver)
	}

	n := rng.Intn(100)
	switch {
	case n < 46:
		return r.record(ctx, step)
	case n < 66:
		if d := r.pick(); d != nil {
			r.logf("%d sync %s", step, d.ID)
			_ = d.Sync(ctx)
		}
	case n < 74:
		if w.Hub != nil {
			r.logf("%d hub sync", step)
			_, _ = w.Hub.SyncUpstream(ctx)
		}
	case n < 80 && f.Partitions:
		r.partition(step)
	case n < 84 && f.Faults:
		names := w.linkNames()
		l := names[rng.Intn(len(names))]
		w.Net.Faults(l, 0.1*rng.R.Float64(), 0.1*rng.R.Float64(), 0.15*rng.R.Float64(), 0.1*rng.R.Float64())
		r.logf("%d faults on %s", step, l)
	case n < 88 && f.Crashes:
		if d := r.pick(); d != nil {
			r.logf("%d crash %s", step, d.ID)
			r.st.Crashes++
			return d.Crash()
		}
	case n < 90 && f.HubKills && w.Hub != nil:
		if rng.Chance(0.35) {
			r.logf("%d hub WIPE", step)
			r.st.HubWipes++
			return w.WipeHub()
		}
		r.logf("%d hub restart", step)
		r.st.HubKills++
		return w.RestartHub()
	case n < 92 && f.Skew:
		if d := r.pick(); d != nil {
			d.Skew = time.Duration(rng.Range(-60, 420)) * time.Second // up to +7 min
			r.logf("%d skew %s %v", step, d.ID, d.Skew)
		}
	case n < 94:
		// Time passes with nothing happening: a quiet spell (seals are stored on the way).
		w.Advance(time.Duration(rng.Range(1, 12)) * time.Minute)
	case n < 100 && f.Inject:
		return r.inject(ctx, step)
	}
	return nil
}

func (r *runner) partition(step int) {
	names := r.w.linkNames()
	l := names[r.rng.Intn(len(names))]
	down := !r.w.Net.IsDown(l)
	if r.rng.Chance(0.4) { // the internet goes down, whole
		down = true
		l = "hub-cloud"
		for _, d := range r.w.Devices {
			r.w.Net.SetDown("dev-cloud:"+d.ID, true)
		}
	}
	r.w.Net.SetDown(l, down)
	r.st.Partitions++
	r.logf("%d link %s down=%v", step, l, down)
	if r.rng.Chance(0.5) { // and it comes back
		for _, n := range names {
			r.w.Net.SetDown(n, false)
		}
	}
}

func (r *runner) record(ctx context.Context, step int) error {
	d := r.pick()
	if d == nil {
		return nil
	}
	rng := r.rng
	var err error
	var it sp.Item
	kind := rng.Intn(100)
	switch {
	case d.Kind == sp.KindKDS:
		it, err = d.KDSOp(rng)
	case kind < 30:
		it, err = d.OrderOp(rng)
	case kind < 40:
		it, err = d.KDSOp(rng)
	case kind < 56 && d.Billing():
		it, err = d.BillOp(rng)
		if err == nil {
			r.st.Bills++
		}
	case kind < 68 && d.Billing():
		it, err = d.PaymentOp(rng)
	case kind < 72 && d.Billing():
		it, err = d.CreditNoteOp(rng)
		if err == nil {
			r.st.Credit++
		}
	case kind < 82:
		it, err = d.StockOp(rng)
	case kind < 90 && d.Kind == sp.KindPOS: // menu.price.set is a POS (or personal device) intent in the registry
		it, err = d.PriceOp(rng)
	default:
		it, err = d.OrderOp(rng)
	}
	if err == nil {
		r.st.Ops++
		r.logf("%d %s %s seq=%d", step, d.ID, it.Stream, it.Seq)
	}
	return nil // a refused local op (no order yet, key lost) is not a failure of the run
}

func (r *runner) sidOf(d *Device, actor string) string {
	sid, _ := d.session(actor)
	return sid
}

// inject records an op that the verdict table must hold, flag or void, and registers the
// expectation (the oracle).
func (r *runner) inject(ctx context.Context, step int) error {
	d := r.pick()
	if d == nil || d.Kind == sp.KindKDS {
		return nil
	}
	rng := r.rng
	add := func(it sp.Item, err error, status, reason string) {
		if err == nil {
			r.exp.Add(it, status, reason)
			r.st.Injected++
			r.logf("%d INJECT %s -> %s/%s (%s seq=%d)", step, d.ID, status, reason, d.ID, it.Seq)
		}
	}
	switch rng.Intn(7) {
	case 0: // a number in another device's series (V1)
		var other *Device
		for _, o := range r.w.Devices {
			if o != d && o.saleCode != "" && !o.KeyLost {
				other = o
				break
			}
		}
		if other == nil || !d.Billing() {
			return nil
		}
		d.SetBadSeries(other.saleCode)
		it, err := d.BillOp(rng)
		d.SetBadSeries("")
		if err == nil {
			last := d.Numbers[len(d.Numbers)-1]
			r.exp.Foreign[last.Number+"@"+last.Origin] = true
		}
		add(it, err, repository.StQuarantined, service.ReasonForeignSeries)
	case 1: // an actor never in any pack (trading)
		sid := r.sidOf(d, pCashier)
		it, err := d.record(engine.Input{Stream: "outlet:" + r.w.Outlet, Intent: "stock.move", Actor: "ghost", SID: sid,
			Muts: []sp.Mut{{E: "stock_level", ID: "item-1", K: sp.KDelta, F: map[string]any{"qty_milli": int64(1000)}}}}, true)
		add(it, err, repository.StQuarantined, service.ReasonActorUnknown)
	case 2: // an invalid session proof on a sale: flagged, never rejected
		sid := r.sidOf(d, pCashier)
		it, err := d.record(engine.Input{Stream: "outlet:" + r.w.Outlet, Intent: "stock.move", Actor: pCashier, SID: sid, Proof: "bogus-proof",
			Muts: []sp.Mut{{E: "stock_level", ID: "item-2", K: sp.KDelta, F: map[string]any{"qty_milli": int64(-1000)}}}}, true)
		add(it, err, repository.StFlagged, "")
	case 3: // an invalid proof on a configuration change: voided
		if d.Kind != sp.KindPOS {
			return nil // menu.price.set is allowed for pos devices only
		}
		sid := r.sidOf(d, pManager)
		var prev string
		d.Eng.WithState(func(s *engine.State) { prev = s.FieldStamp("menu_item", "menu-9", "price_paise") })
		it, err := d.record(engine.Input{Stream: "brand:" + r.w.Brand, Intent: "menu.price.set", Actor: pManager, SID: sid, Proof: "bogus-proof",
			Muts: []sp.Mut{{E: "menu_item", ID: "menu-9", K: sp.KInsert, F: map[string]any{"name": "forged", "price_paise": int64(1)}, Prev: map[string]string{"price_paise": prev}}}}, true)
		add(it, err, repository.StVoided, service.ReasonProofFailed)
	case 4: // a member removed while the outlet was offline keeps selling: flagged, never rejected
		if !r.removed || !r.w.Identity.InAnyPack(r.w.Tenant, d.ID, pLeaver) {
			return nil // a pack issued after the removal never listed the member: that is actor_unknown, not flagged
		}
		sid := r.sidOf(d, pLeaver)
		it, err := d.record(engine.Input{Stream: "outlet:" + r.w.Outlet, Intent: "stock.move", Actor: pLeaver, SID: sid,
			Muts: []sp.Mut{{E: "stock_level", ID: "item-3", K: sp.KDelta, F: map[string]any{"qty_milli": int64(2000)}}}}, true)
		add(it, err, repository.StFlagged, "")
	case 5: // a dormant waiter series used before anyone activated it: flagged
		if d.Kind != sp.KindWaiter || d.activated || d.saleCode == "" {
			return nil
		}
		it, err := d.BillOp(rng)
		add(it, err, repository.StFlagged, "")
	case 6: // a last-writer-wins edit stamped far ahead of the receiver: held for review
		if d.Kind != sp.KindPOS {
			return nil
		}
		d.Skew = 36 * time.Hour
		it, err := d.PriceOp(rng)
		d.Skew = 0
		add(it, err, repository.StQuarantined, service.ReasonClockReview)
		r.exp.AllowReason(service.ReasonClockReview)
	}
	return nil
}

func (r *runner) recover(ctx context.Context, d *Device) error {
	r.logf("RECOVER %s", d.ID)
	rc, err := r.w.RecoverDevice(d, true)
	if err != nil {
		return err
	}
	r.exp.AllowOrigin(rc.Old)
	for i := 0; i < 30; i++ {
		if done, err := r.w.UploadRecovery(ctx, d, rc); err == nil && done {
			break
		}
	}
	return nil
}

// finish heals the world, recovers key-lost devices, quiesces, checks the verdicts, lets the
// manager review the held list, quiesces again and checks convergence.
func (r *runner) finish(ctx context.Context) *Result {
	w := r.w
	res := &Result{Seed: r.opt.Seed}
	for _, name := range w.linkNames() {
		w.Net.SetDown(name, false)
		w.Net.Faults(name, 0, 0, 0, 0)
	}
	for _, d := range w.Devices {
		if d.KeyLost {
			if err := r.recover(ctx, d); err != nil {
				res.Problems = append(res.Problems, Problem{"recover", err.Error()})
			}
		}
	}
	rep := w.Quiesce(ctx, 80)
	r.st.QuiesceRds = rep.Rounds
	if !rep.Converged {
		res.Problems = append(res.Problems, Problem{"quiesce", fmt.Sprintf("no quiescence in %d rounds", rep.Rounds)})
	}
	if os.Getenv("SYNC_DEBUG") != "" {
		_, cv, _ := w.CloudState(ctx)
		hv, _ := w.Hub.Engine().Vector(ctx)
		for _, d := range w.Devices {
			dv, _ := d.Eng.Vector(ctx)
			fmt.Printf("DBG %s vs cloud: %s | vs hub: %s | keylost=%v\n", d.ID, vecDiff(dv, cv), vecDiff(dv, hv), d.KeyLost)
		}
		fmt.Printf("DBG hub vs cloud: %s\n", vecDiff(hv, cv))
		_ = w.Hub.Engine().Config().Store.InTx(ctx, w.Tenant, func(tx repository.Tx) error {
			sq, _ := tx.SealSeqs("outlet:"+w.Outlet, "dev-02-pos", 0)
			fmt.Printf("DBG hub seals for dev-02: %v\n", sq)
			recs, _ := tx.Range("outlet:"+w.Outlet, "dev-02-pos", 8, 30, 30)
			for _, r := range recs {
				fmt.Printf("DBG hub slot %d status=%s body=%v\n", r.Seq, r.Status, r.Body != "")
			}
			return nil
		})
	}
	// Phase A: verdicts as the table says, and what devices are told equals what the cloud holds.
	res.Problems = append(res.Problems, w.CheckVerdicts(ctx, r.exp)...)
	res.Problems = append(res.Problems, w.CheckReadBack(ctx)...)
	// Phase B: the manager reviews the held list (vendor confirmation and device.recover granted).
	held, _ := w.GW.Quarantine(ctx, w.Tenant)
	r.st.Held = len(held)
	for _, q := range held {
		if _, err := w.GW.Release(ctx, w.Tenant, q.Ref, service.ReleaseOpts{VendorConfirmed: true, DeviceRecover: true}); err != nil {
			res.Problems = append(res.Problems, Problem{"release", fmt.Sprintf("%s: %v", q.Ref.Key(), err)})
		}
	}
	rep = w.Quiesce(ctx, 80)
	r.st.QuiesceRds += rep.Rounds
	if !rep.Converged {
		res.Problems = append(res.Problems, Problem{"quiesce", "no quiescence after review"})
	}
	res.Problems = append(res.Problems, w.CheckAll(ctx, r.exp)...)
	if left, _ := w.GW.Quarantine(ctx, w.Tenant); len(left) > 0 {
		res.Problems = append(res.Problems, Problem{"review", fmt.Sprintf("%d slots still held after release", len(left))})
	}
	cloud, _ := readAll(ctx, w.GWStore, w.Tenant)
	for _, rc := range cloud {
		switch rc.Status {
		case repository.StVoided:
			r.st.Voided++
		case repository.StFlagged:
			r.st.Flagged++
		}
	}
	r.st.Net = w.Net.Stats
	r.st.HubOK, r.st.HubFail, r.st.CloudDirect = w.Via.HubOK, w.Via.HubFail, w.Via.CloudDirect
	res.Stats = r.st
	res.Trace = r.trace
	if len(res.Trace) > 400 {
		res.Trace = res.Trace[len(res.Trace)-400:]
	}
	return res
}
