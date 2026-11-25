# svc-sync

Sync gateway service: operation log, hub protocol, restore epoch, with its test double. Also holds the LAN hub
(`hub/`) and the deterministic simulator (`sim/`) of the Phase 1 offline-sync proof of concept (ADR-0002).

- Wire contract: in `api-specs` (`openapi/sync/v1`, `sync/protocol-v1.md`, `sync/conformance`, `sync/intents`, `entities`); `contract/README.md` says how it is read and checked. Phase 2 notes: `docs/phase2-notes.md`.
- Notes, findings and choices: `docs/poc-notes.md`.
- Layering: `api` -> `service` -> `repository`; `engine` and `syncproto` are the shared sync core (meant for `go-common/sync`).
- Test double: `double/`; shared contract suite: `contract/suite`.

## Run

```
go vet ./... && go test -race ./...
go run ./cmd/simulate -runs 100 -steps 500            # simulator; -soak 30m for a wall-clock soak
go run ./cmd/devstack -out /tmp/sync-fixture.json     # gateway + hub on real ports for client-core e2e
SYNC_HUB_PACK=<pack> SYNC_HUB_DB=hub.db go run ./cmd/hub
SYNC_DB_DSN=<dsn> HOSTRY_ENV=dev SYNC_DEV_STUB=1 go run ./cmd/gateway   # stub directory, local development only
SYNC_DB_DSN=<dsn> SYNC_DIRECTORY=identity ... go run ./cmd/gateway   # the real directory (below)
```

Tests that need the dev stack are skipped without it: `SYNC_PG_DSN` (integration, Postgres) and, in `identityreal/` (a module of its
own), `SYNC_IDENTITY_PG_DSN` (real identity over Postgres) and `SYNC_LIVE_IDENTITY_URL` / `SYNC_LIVE_TENANCY_URL` /
`SYNC_SERVICE_SIGNING_KEY_FILE` (the directory against the running services). `API_SPECS_DIR` names the api-specs checkout
(default: `../api-specs-p2`, then `../api-specs`).

## Configuration (environment only)

Gateway: `SYNC_DB_DSN`, `SYNC_ADDR`, `SYNC_DIRECTORY` (`identity`, or `stub` with `SYNC_DEV_STUB=1`; refused unless `HOSTRY_ENV` is dev, test or ci), `SYNC_DEV_REGISTER=1` with `HOSTRY_ENV` in dev, test or ci
(stub only: `/dev/v1` device registration, token minting and the hub pack), `SYNC_NATS_URL` + `SYNC_NATS_SEED_FILE` (outbox relay, and the
consumer of `tenancy.manual_book.registered`).
Identity directory (ADR-0005 A3.2; `cmd/gateway/main.go` lists every variable): `SYNC_IDENTITY_URL`, `SYNC_TENANCY_URL`,
`SYNC_SERVICE_SIGNING_KEY_FILE`, `SYNC_OP_SIGNING_KEY_FILE` (+ `SYNC_OP_KID`), `SYNC_TENANT_JWKS`, `SYNC_SERVICE_KEYS`, `SYNC_PLATFORM_DSN`,
`SYNC_DIRECTORY_STATE_FILE`. `/readyz` is ready once the revocation feed has been read once.
Hub: `SYNC_HUB_PACK`, `SYNC_HUB_DB`, `SYNC_HUB_ADDR`, `SYNC_HUB_CLOUD_TOKEN_FILE`, `SYNC_HUB_MDNS`.

## Local development

`go.work` is uncommitted (git-ignored) and lists `.`, `../go-common`, `../go-auth` for local development; the build does not need it (`GOWORK=off go build ./...`): `go.mod` pins both by pseudo-version.
No deployment exists (ADR-0001 AM12).
