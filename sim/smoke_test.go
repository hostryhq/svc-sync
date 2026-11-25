package sim

import (
	"context"
	"testing"
)

func newTestWorld(t *testing.T, seed uint64, o WorldOptions) (*World, *Rand) {
	t.Helper()
	o.Dir = t.TempDir()
	if o.Pos == 0 {
		o.Pos = 2
	}
	rng := NewRand(seed)
	w, err := NewWorld(context.Background(), rng, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w, rng
}

func TestSmokeConvergesThroughHubAndCloud(t *testing.T) {
	w, rng := newTestWorld(t, 1, WorldOptions{Pos: 2, Waiters: 1, KDS: 1})
	ctx := context.Background()
	for i := 0; i < 6; i++ {
		for _, d := range w.Devices {
			if d.Kind == "kds" {
				continue
			}
			if _, err := d.OrderOp(rng); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, d := range w.Devices[:2] {
		if _, err := d.BillOp(rng); err != nil {
			t.Fatal(err)
		}
		if _, err := d.PaymentOp(rng); err != nil {
			t.Fatal(err)
		}
	}
	rep := w.Quiesce(ctx, 30)
	if !rep.Converged {
		t.Fatalf("did not converge in %d rounds", rep.Rounds)
	}
	cs, cv, _ := w.CloudState(ctx)
	if cs.RowCount() < 20 || len(cs.IDs("bill")) != 2 {
		t.Fatalf("cloud state looks empty: %d rows, %d bills, vector %v", cs.RowCount(), len(cs.IDs("bill")), cv)
	}
	for _, d := range w.Devices {
		t.Logf("%s sale=%s numbers=%v", d.ID, d.SaleCode(), d.Numbers)
	}
	for _, p := range w.CheckAll(ctx, nil) {
		t.Error(p)
	}
}
