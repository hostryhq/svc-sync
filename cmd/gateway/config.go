package main

import (
	"errors"
	"strings"

	"github.com/hostryhq/svc-sync/internal/devreg"
)

// extras is the optional wiring of the stub-directory gateway: the dev registration routes and the outbox relay.
type extras struct {
	DevRoutes bool
	NatsURL   string
	NatsSeed  string
	RelayDSN  string // empty: the gateway's own DSN
}

// loadExtras reads and validates the optional environment:
//
//	SYNC_DEV_REGISTER=1  dev registration and token routes (needs HOSTRY_ENV in dev, test or ci; refused otherwise)
//	SYNC_NATS_URL, SYNC_NATS_SEED_FILE  relay the outbox to NATS with sync's credential (both, Postgres only)
//	SYNC_RELAY_DSN       optional separate DSN for the relay (a role that may read all tenants' outbox rows)
func loadExtras(get func(string) string, dsn string) (extras, error) {
	x := extras{NatsURL: get("SYNC_NATS_URL"), NatsSeed: get("SYNC_NATS_SEED_FILE"), RelayDSN: get("SYNC_RELAY_DSN")}
	if get("SYNC_DEV_REGISTER") != "" {
		if err := devreg.Guard(get("HOSTRY_ENV"), get("SYNC_DEV_REGISTER") == "1"); err != nil {
			return x, err
		}
		x.DevRoutes = true
	}
	if (x.NatsURL == "") != (x.NatsSeed == "") {
		return x, errors.New("SYNC_NATS_URL and SYNC_NATS_SEED_FILE are set together or not at all")
	}
	if x.NatsURL != "" && !strings.HasPrefix(dsn, "postgres") {
		return x, errors.New("the outbox relay needs a Postgres SYNC_DB_DSN (the outbox is Postgres only)")
	}
	return x, nil
}
