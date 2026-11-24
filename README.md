# svc-sync

Sync gateway service: operation log, hub protocol, restore epoch, with its test double. Also holds the LAN hub
(`hub/`) and the deterministic simulator (`sim/`) of the Phase 1 offline-sync proof of concept (ADR-0002).

- Wire contract: `contract/sync-v1.openapi.yaml` and `contract/README.md` (normative rules), golden vectors in `contract/vectors/`.
- Notes, findings and choices: `docs/poc-notes.md`.
- Layering: `api` -> `service` -> `repository`; `engine` and `syncproto` are the shared sync core (meant for `go-common/sync`).
- Test double: `double/`; shared contract suite: `contract/suite`.

## Run

```
go vet ./... && go test -race ./...
go run ./cmd/simulate -runs 100 -steps 500            # simulator; -soak 30m for a wall-clock soak
go run ./cmd/devstack -out /tmp/sync-fixture.json     # gateway + hub on real ports for client-core e2e
SYNC_HUB_PACK=<pack> SYNC_HUB_DB=hub.db go run ./cmd/hub
SYNC_DB_DSN=<dsn> SYNC_DEV_STUB=1 go run ./cmd/gateway   # local development only
```

## Configuration (environment only)

Gateway: `SYNC_DB_DSN`, `SYNC_ADDR`, `SYNC_DEV_STUB` (until identity and tenancy clients exist).
Hub: `SYNC_HUB_PACK`, `SYNC_HUB_DB`, `SYNC_HUB_ADDR`, `SYNC_HUB_CLOUD_TOKEN_FILE`, `SYNC_HUB_MDNS`.

## Local development

`go.work` is uncommitted (git-ignored) and lists `.`, `../go-common`, `../go-auth`. `go.mod` pins both by pseudo-version.
No deployment exists (ADR-0001 AM12).
