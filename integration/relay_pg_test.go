package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hostryhq/go-common/outbox"
	"github.com/hostryhq/svc-sync/repository"
)

type recSink struct {
	mu  sync.Mutex
	ids []string
}

func (s *recSink) Publish(_ context.Context, _, id string, _ []byte) error {
	s.mu.Lock()
	s.ids = append(s.ids, id)
	s.mu.Unlock()
	return nil
}

func (s *recSink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.ids) }

// The gateway's own migrations carry outbox_relay_state, so go-common's relay (with its bus-generation check)
// can run on the service database without the harness applying library DDL (soak finding F2).
func TestMigrationsLetTheRelayRunWithItsGenerationCheck(t *testing.T) {
	st, err := repository.Open(dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	clean(t, st)
	if _, err := st.DB().ExecContext(bg, `DELETE FROM outbox_relay_state`); err != nil {
		t.Fatalf("outbox_relay_state is not migrated: %v", err)
	}
	if _, err := st.DB().ExecContext(bg, `INSERT INTO outbox (id, type, subject, tenant_id, payload) VALUES (gen_random_uuid(), 'sync.op.bill', 'hostry.sync.op.bill', 't1', '{}')`); err != nil {
		t.Fatal(err)
	}
	sink := &recSink{}
	ctx, cancel := context.WithTimeout(bg, 20*time.Second)
	defer cancel()
	rel := &outbox.Relay{DB: st.DB(), Sink: sink, LockKey: 7_464_011_199, Poll: 50 * time.Millisecond, Stream: "sync",
		Generation: func(context.Context) (string, error) { return "gen-1", nil }}
	done := make(chan error, 1)
	go func() { done <- rel.Run(ctx) }()
	for sink.count() < 1 && ctx.Err() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if sink.count() != 1 {
		t.Fatalf("the relay published %d events, want 1", sink.count())
	}
	var gen string
	if err := st.DB().QueryRowContext(bg, `SELECT generation FROM outbox_relay_state WHERE stream = 'sync'`).Scan(&gen); err != nil || gen != "gen-1" {
		t.Fatalf("relay state: %q %v", gen, err)
	}
}
