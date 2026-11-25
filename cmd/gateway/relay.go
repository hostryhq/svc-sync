package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"

	"github.com/hostryhq/go-common/bus"
	"github.com/hostryhq/go-common/outbox"
	"github.com/hostryhq/svc-sync/repository"
)

// relayLockKey is the advisory lock key of sync's relay (one active relay per database).
const relayLockKey = 7_464_011_104

// startRelay relays the gateway's transactional outbox to NATS with sync's own bus credential, the way every
// other service does (go-common outbox.Relay with its bus-generation check; the outbox_relay_state table comes
// from the service's migrations). It runs until ctx ends.
func startRelay(ctx context.Context, x extras, st repository.Store, dsn string, log *slog.Logger) error {
	db := st.DB()
	if x.RelayDSN != "" && x.RelayDSN != dsn {
		rdb, err := sql.Open("pgx", x.RelayDSN)
		if err != nil {
			return err
		}
		db = rdb
	}
	nc, err := bus.Connect(x.NatsURL, "sync", x.NatsSeed)
	if err != nil {
		return err
	}
	pub, err := bus.NewPublisher(nc)
	if err != nil {
		nc.Close()
		return err
	}
	rel := &outbox.Relay{DB: db, Sink: pub, LockKey: relayLockKey, Log: log, Generation: bus.GenerationFunc(nc, "sync"), Stream: "sync"}
	go func() {
		defer nc.Close()
		if err := rel.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("outbox relay stopped", "err", err.Error())
		}
	}()
	log.Info("outbox relay running", "bus", x.NatsURL)
	return nil
}
