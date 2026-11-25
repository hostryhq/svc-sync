# Phase 2 notes (svc-sync on feat/phase2-sync)

Contract: api-specs `feat/phase2-specs` @ 1462fb8; go-common `feat/phase2-libs` @ c6c0fc7; go-auth @ 7551373 (local `go.work`).
Everything marked PROVISIONAL waits for a ruling and is isolated as stated.

## Built
1. **Contract from api-specs.** `contract/specs` reads the checkout; no copy of the OpenAPI or the vectors is kept. Admin answers have the
   contract's shapes (`{items: [...]}`, Ref bodies, operation ids). Intents come from the registry: `cmd/genintents` writes
   `syncproto/intents_gen.go`; the PoC permission strings are gone (catalogue keys only; the stock demo intent exists only in the simulator).
2. **`sync.op.<namespace>` events** through the outbox, whole op: `data.body` is the exact stored bytes, `pii` the verified values without salts,
   key `<stream>|<origin>`, outlet id for an outlet stream, void under namespace `sync`. `service/events.go`; a test feeds every published op to
   `go-common/sync.ParseOp`. A quarantined op is never published. Over-size device ops are quarantined as opaque (never published with a body).
3. **Emit** `POST /internal/v1/emit` (`api/emit.go`, `service/emit.go`): go-auth guard, callers `catalog` and `billing`, tenant of the token must
   equal the request tenant, per-op idempotency `(tenant, caller, key)` in `emit_dedup` (same transaction as the op), checks of owner, cloud origin,
   entity and kind, stream kind and tenant, size and batch, atomic batch, origin/seq/ph/hlc and seal by the gateway only, 503 `emit.unavailable` with
   Retry-After when the gateway is not ready or its store fails, audit row per op.
4. **Register.** `series_numbers` (key includes the number) replaces `series_register` (kept one release, no longer written). `Body.Documents()`
   reads `doc` plus the `doc_number` field of every inserted `bill` / `credit_note` row; an op never takes a series twice (held as malformed).
   `series.close` is stored and the tail confirmed when the register holds every number up to the stated one; a missing number raises one owner
   alert. `rank` and `set` follow the entity policy in the engine's state; see the open item on the per-field engine.
5. **Personal data (PROVISIONAL).** Salted per-field commitments in the sealed body (`pii_c`), verified on ingest by every node; unverifiable fields
   are dropped and the op is marked `pii_dropped`. Cloud-signed erasure op `sync.pii.erase`; values and salts removed at the gateway, devices and hubs;
   acknowledgement in the next direct cloud hello (`pii_erased`). All of it behind `syncproto/piic.go` (`CommitPII`, `OpenPII`, `StripSalts`).
6. **Security conditions.** Vendor confirmation is bound to the hash of the held op, tells the owner (alert) and is in the tenant-visible audit
   log; release and discard: no self-decision, approval needed for a money or bill-number hold from a binding under caution, owner alert on every
   decision. The identity stub answers `locked` for every op kind like real identity (a sale on a locked pair is kept and its actor is flagged
   unverified; invalid proofs still count until the lock; the counter stays capped). One contract test (`directory/dirtest`) is to run against the
   stub (done) and the real identity client (not wired yet).

## Open items
1. **Emit token tenant.** The contract text says a service token carries no tenant; the security condition needs one. The gateway refuses a token
   without a tenant. `go-common/emit` `TokenSource` takes no tenant, so callers must mint a per-tenant token. Needs the contract text and the client changed.
2. **ADR needed: publisher of `billing.series.reconciled`.** The event's `x-publisher` is billing and bus permissions are generated from it, so a relay
   from this service would be refused. The gateway can publish it (`Config.ReconciledEvent`, off by default); billing reconciles from
   `identity.device.drained` itself. Decide who publishes.
3. **PII shape.** `client-core` sends `pii` with no commitment, so the gateway drops it until the TypeScript engine implements `CommitPII`. The salt key
   `~s:<field>` and the `pii_erased` hello field, the `sync.pii.erase` intent and the `pii_erase` / `series_close` records need entries in api-specs
   and in `go-common/sync` (the parser reads `series_close` and `pii_erase` as unknown entities and ignores them).
4. **Contract deviations kept on purpose.** `listQuarantine` is read with `sync.quarantine.read` (support-viewable) where the contract says
   `sync.quarantine.manage`; `POST /sync/v1/quarantine/confirm` is not in the contract; decisions require a `reason` (the contract's body is a Ref);
   lists carry no `received_at` / `detected_at` (not stored). New catalogue keys to list in permissions.yaml: `sync.quarantine.read`
   (`support_viewable`), `sync.quarantine.confirm` (`support_actable`).
5. **Stream ownership.** The directory has no "outlet/brand belongs to tenant" call; the stub implements `StreamInTenant`, and without it only tenant
   streams are accepted by emit. Tenancy's client must provide it.
6. **Entity policies in the engine.** The engine's apply state still uses the demo entity table (append, lww, delta, rank); the per-field policies of
   the real entity registry (`mixed`) are applied by `go-common/sync` in the services. Moving the engine to the registry is not done.
7. **Not published:** `sync.quarantine.recorded`, `sync.op.flagged`, `sync.pii.erased` is published on erasure only. Row ids of an emit are not
   checked for UUIDv5 derivation. Erasure acknowledgements from a device behind a hub arrive at its next direct cloud hello (no relay).
8. **go.mod** still pins go-common and go-auth by older pseudo-versions; the build uses `go.work` (c6c0fc7, 7551373). Pin them when the branches merge.
9. Simulator: `menu.price.set` is a `pos` (and `personal`) intent in the registry, so waiters no longer record it.
