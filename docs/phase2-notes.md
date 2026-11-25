# Phase 2 notes (svc-sync on feat/phase2-sync)

Contract: api-specs `feat/phase2-specs` @ 14c76fd (was b153c62); go-common `feat/phase2-libs` @ 92884d6 and go-auth `feat/phase2-auth` @ 94f1970 (pinned by pseudo-version in `go.mod`;
`GOWORK=off go build ./...` works); svc-identity `feat/phase2-identity` @ ebebd4c (`identityreal/go.mod`).

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
5. **Personal data (settled in api-specs, O2-12).** Salted per-field commitments in the sealed body (`pii_c`), verified on ingest by every node; unverifiable fields
   are dropped and the op is marked `pii_dropped`. Cloud-signed erasure op `sync.pii.erase`; values and salts removed at the gateway, devices and hubs;
   acknowledgement in the next direct cloud hello (`pii_erased`). The op event carries the verified values WITH their `~s:<field>` salts (the owner verifies again). All of it behind `syncproto/piic.go` (`CommitPII`, `OpenPII`).
6. **Security conditions.** Vendor confirmation is bound to the hash of the held op, tells the owner (alert) and is in the tenant-visible audit
   log; release and discard: no self-decision, approval needed for a money or bill-number hold from a binding under caution, owner alert on every
   decision. The identity stub answers `locked` for every op kind like real identity (a sale on a locked pair is kept and its actor is flagged
   unverified; invalid proofs still count until the lock; the counter stays capped). One contract test (`directory/dirtest`) is to run against the
   stub (done) and the real identity client (not wired yet).

7. **Entity registry in the engine.** `engine/entities_gen.go` is generated from api-specs `entities/` (`cmd/genintents`, checked by
   `TestEntityTableIsGenerated`): per-field policies (immutable, lww with groups that win together, lww_review, delta, rank), tombstone and
   guarded flags. Unknown fields of a registry entity are ignored, and a kind only touches the fields its policy allows (as `go-common/sync`).
   The demo entities (stock_level, kds_item, menu_item, audit, session, approval, sync_void) exist only in a simulator or test process
   (`engine.RegisterDemoEntities`). `service/admin.go` reads `Guarded` from the registry.
8. **Events.** `sync.quarantine.recorded` (reason, and series code / number / document type of the first number the op carries),
   `sync.op.flagged` (coarse code from the verdict's marks) and `sync.pii.erased` go through the outbox in the storing transaction.
   `TestHoldFlagAndEraseEventsOnPostgres`. `billing.series.reconciled` is billing's (O2-10), not published here.
9. **Identity client.** `identityclient` (generated from the identity contract, `oapi-codegen-identity.yaml`) with service tokens that name the tenant,
   a timeout per attempt and one retry on the same Idempotency-Key. `identityclient.Directory` implements `directory.Directory`: proof check,
   revocation feed, pack history, drain. `identityreal/` (own module) runs `directory/dirtest` against the real identity service layers, in memory
   and over Postgres: real and stub answer `locked` alike for every op kind.

## ADR-0005 A3 (feat/phase2-sync after 92d2288)
Contract api-specs `6e63014`, svc-identity `2ba5adc`, svc-tenancy `3792f07`. Items 1 to 3 of the list below are resolved by the amendment; see
`contract/README.md`, "ADR-0005 A3 on this side".
- **A3.1** `service/session.go`, `repository` `sessions` columns (actor, pack_v, pin_v, opened_at, verdict) and `approval_verdicts`; ingest takes outlet
  streams before brand and tenant streams so that a session's open is judged before its configuration ops.
- **A3.2** `realdir/` (caches, faults, revocation state), `identityclient/routes.go`, `tenancyclient/`. `SYNC_DIRECTORY=identity` starts and serves:
  checked against identity and tenancy running on the dev stack (own ports), `identityreal` live test, and the dirtest contract against the stub, real
  identity in memory and real identity over Postgres (stub and real answer `locked` alike).
- **A3.3** `syncproto/drain.go`, `service/drain.go`, `drain_statements` table; `sim.World.Drain` and `sim/drain_test.go` (DR1, DR2 and the signer,
  second statement and late upload cases). DR3 (the shell refuses a wipe order that quotes another statement) and DR4 (identity refuses a series set
  mismatch) are the shell's and identity's.
- **Dev routes** produce the hub pack `cmd/hub` reads (`GET /dev/v1/hub-packs/{device_id}`, and `hub_pack` in the registration of a hub), and pack versions
  are the integers the client sends as `pack_v`.
- Not done here: the day-digest rule of A3.5 (the owners' and `go-common/sync`'s). Infra's `up-full.sh` sets no `SYNC_TENANCY_URL`, `SYNC_OP_SIGNING_KEY_FILE` (the key is `keys/sync-op.key`) or
  `SYNC_SERVICE_KEYS` for sync, which the identity directory needs.

## Open items (earlier; 1 to 3 resolved by A3)
1. **ADR needed: how the gateway asks identity about a proof.** `verifyProof` needs `pin_v`, an integer `pack_v` and `opened_at`; the op body has `sid`,
   a text `pack_v` and `proof` only. The op wire (and client-core) must carry the missing fields, or identity must derive them.
2. **ADR needed: directory questions identity cannot answer.** No internal route gives sync a device's credential (public key, kind, outlet, brand),
   the permissions a pack granted (`PackFor`, `StillHolds`), key-loss recovery records, the revocation reason (`key_lost`), or series ownership
   (tenancy). `identityclient.Directory.Gaps()` lists them; they answer "not found", and `cmd/gateway` with `SYNC_DIRECTORY=identity` validates the
   client and refuses to start. Needs new internal routes in identity/tenancy, or a decision that the gateway holds device credentials itself.
3. **Drain criterion.** `Gateway.ReportDrained` sends identity the stored sequences of a revoked device, but nothing calls it: an early report wipes
   a device that still holds ops, and an ordinary drain has no attestation. Decide who declares a revoked device drained.
4. **Stream ownership.** The directory has no "outlet/brand belongs to tenant" call; the stub implements `StreamInTenant`, and without it only tenant
   streams are accepted by emit. Tenancy's client must provide it.
5. **Op flags afterwards.** `sync.op.flagged` is published at acceptance and at release; no flag is added to a stored op later today.
   `sync.quarantine.recorded` names only the first number of a multi-number op (bill.rebill); the contract has one `number` field.
6. **Not done.** Row ids of an emit are not checked for UUIDv5 derivation. Erasure acknowledgements from a device behind a hub arrive at its next direct
   cloud hello (no relay). The device-token verifier (JWKS), op-signing key and platform epoch of `cmd/gateway` are dev-only.
7. **A2.8 wire fields** (`unbound`, `chain_conflicts`, `unbound_h`, `stale_seals`, `seal_refresh`, refusal `chain_conflict`) are listed in
   `contract/README.md` for the spec owner.
8. Simulator: `menu.price.set` is a `pos` (and `personal`) intent in the registry, so waiters no longer record it.

## ADR-0014 Amendment A3 (feat/phase2-sync, contract api-specs `14c76fd`)
Built: A3.1/A3.2 (pii by credential kind, commitments in every hash, refetch of `pii_incomplete`, erasure unchanged), A3.3 (approval citation with
`approval_flag` reasons, `pending`, single citer, `approval.self_confirm`), device-session lifetime (26 hours), A3.4 (credential without `brand_id`
is a fault; dev routes and hub pack carry `kid` and `brand_id`). Tests: vectors (`syncproto/a3_vectors_test.go`), PA1 to PA5
(`engine/pii_a3_test.go`, `sim/pii_a3_test.go`, `sim/pii_gateway_test.go`), OV1 to OV5 (`service/approval_test.go`), device session
(`sim/devicesession_test.go`), and the simulator: checks with customer details are recorded in every run and `CheckPII` asserts placement
(staff devices, hub and cloud hold the values, no kds does, nothing left `pii_incomplete`).
Open and judgement calls:
- An approval is keyed by `(origin, approval id)`: citing an approval of another device stays `pending` and is never flagged.
- The wire has no way for the cloud to ask a node for values it lacks (the contract has no field for it). The gap is closed by the node
  re-offering its pii-bearing ops for a day after it hears of a restore epoch; a relay that held no values and pushed an op before the origin
  outside that window is not completed. Needs a contract field (`pii_need` in the hello answer) if it matters; not decided here.
- Random erasure is not in the simulator (a cloud rollback loses the erasure record at the cloud, so a node that missed it would re-offer the
  value); erasure is covered by PA2/X2, PA3 and PA5.
- `identityreal/` (own module) still pins svc-identity at the ADR-0005 A3 head; its live test needs svc-identity and svc-tenancy at round 5.
