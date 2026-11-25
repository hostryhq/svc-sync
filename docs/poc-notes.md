# Sync proof of concept: notes (ADR-0002, roadmap item 1e-1, server side)

Status: Phase 1 proof of concept. ADR-0002 with Amendment A1 (Proposed) applied provisionally with its
recommended answers (founder questions S1 to S3). Nothing here is a decision of record. Where the ADR is silent or
inconsistent, the conservative choice is listed under "Choices".

## What is built

| Path | What |
|---|---|
| `syncproto/` | Wire types, HLC, RFC 8785 canonical JSON (integer subset), hash chain, seals, attestations, credentials, LAN assertion, intent registry. Golden vectors in `contract/vectors/v1.json` |
| `engine/` | Generic apply engine (append, delta, lww + review, rank, tombstones, candidates, void set); op store logic (record, ingest with chain and seal checks and verdict hooks, serve to a seal boundary, outbound, recovery upload); sync client (hello, push, pull, re-offer) |
| `repository/` | One portable SQL schema for Postgres and SQLite; RLS on Postgres; migrations embedded, forward-only |
| `service/` | Gateway: verdict table S11 plus A1.1 and A1.3 rows, quarantine release and discard, series register, restore epoch, emit, outbox |
| `api/` | Controller layer: `/sync/v1` handlers, bearer auth with go-auth, admin endpoints with member tokens |
| `hub/` | LAN hub: device-key authentication with identity-signed credentials, hub proof on every answer, structural check, upstream sync, pack loader, mDNS |
| `identitystub/`, `directory/` | Stand-in for identity and tenancy: credentials, series registry unique per registration, packs, proof check with the shared failure counter, recovery records |
| `double/` | Test double with failure injection; `contract/suite` is the shared contract suite run against it and the real gateway |
| `sim/`, `cmd/simulate` | Deterministic simulator and soak mode |
| `cmd/gateway`, `cmd/hub`, `cmd/devstack` | Plain binaries; `devstack` runs both on real ports and writes the client-core end-to-end fixture |

## Findings (real, from running it)

1. **Placeholder at the hub after a cloud restore (simulator, seed 1).** A hub that holds only a placeholder for a slot whose body the
   restored cloud lost cannot forward it, and the origin never talks to the cloud while the hub is up. Fix, now in the
   contract: after an epoch change the origin also syncs with the cloud directly until its re-offer is complete.
   ADR-0002 S16 item 4 says devices re-offer to "the cloud"; it did not say a device with a hub must reach past it.
2. **Released unsealed tail cannot travel (KL1).** A released recovered tail has no origin seal, so nodes would never accept it
   and peers would never converge. The first PoC let the gateway op-signing key sign the ordinary seal message for any origin;
   ADR-0002 A2.1 replaced that (it would let the cloud key seal invented ops of any device). Now: a separate gateway
   `endorsement` (tag `hostry-endorse-v1`, carries the recovery id), accepted only with the identity-signed `recovers`
   credential and the adopting device's attestation (verifier rule in `contract/README.md`, cases KL12 to KL15).
3. **Hub must not refuse pulled ops of a revoked origin** (S17: revocation is enforced where ops are first accepted).
4. **LAN signature covers the bytes on the wire** (gzip body), found by the first hub run; recorded in the contract.
5. A mutation check: removing void application, re-offer after epoch change, or seal verification each makes the simulator or
   a unit test fail.

## Choices (conservative; no ADR needed unless the founder objects)

- Op body is carried as a JSON string holding canonical JSON, not as an embedded object, so relays cannot change bytes.
- Request bodies are JSON (gzip allowed), not NDJSON; poke is a long poll, not a WebSocket (no dependency).
- No TLS on the LAN in the PoC. The signed hub proof and device assertion are in; channel binding to a certificate is not.
- Materialised state is rebuilt from the op log on open (state is a function of the op set); no per-row SQL tables.
  Cloud keeps no state: projections are the domain services' job.
- Candidates are never trimmed. Review conflicts are derived from the full candidate set, so every node lists the same pairs.
- A hub-held (structural check failed) op is stored, pushed to the cloud and promoted when the cloud holds it without holding it back.
- Config op clock rule: quarantined if stamped more than 10 minutes ahead of the receiver or under `clk: manual`. Observing a
  remote stamp never drags the local clock more than 10 minutes ahead.
- Vendor confirmation for chain-broken, foreign-series and fork releases is a support token in act mode; `device.recover`
  (unsealed tail) is a grant on a user token. The trust model belongs to identity (ADR-0005 A2.5).
- Proof lock: a failed proof counts once per `sid`; a pair is locked at 5 failures in 15 minutes or 10 in 24 hours; a locked
  pair gets `locked` for configuration ops (voided without a check); trading ops are still verified and flagged.
- Identity unreachable: a config op waits in quarantine (`pending`), a trading op is accepted with a `proof_pending` mark.
- Series code alphabet follows the registry rule (no I, O, 0, 1); ADR-0002's example `A07/...` contains `0` and is not a valid code.
- The gateway raises "unrecoverable origin gap" after 24 hours of a node reporting a vector above the cloud's.
- The cloud never allocates a legal number; `emit` carries no document.
- Postgres service role must not be a superuser (it would bypass row-level security) and should be separate from the migrator
  role; the integration test uses `sync_app` with a throwaway dev password.
- Event published through the outbox: `sync.op.stored` v1 (source `sync`), data `{origin, stream, seq, h, intent, status}`;
  its schema should be added to `api-specs/events/sync/`. Not relayed to NATS here (no NATS needed for the PoC).
- Library for mDNS: `github.com/enbility/zeroconf/v2` (maintained fork of grandcat/zeroconf, API-compatible). Loopback browse works
  on this machine; a real two-router test is the hardware checklist.

## A2 follow-up (2026-11-25, provisional, ADR-0002 Amendment A2 Proposed)

- **A2.1** endorsement object, `endorsements` / `attestations` on the wire, verifier rule in `engine` (`endorsedOK`), nodes store and
  re-serve every endorsement with the tail; a released op over a placeholder is checked by the rule when an endorsement comes with
  it and taken by hash otherwise (requiring one, or a seal, broke relaying through a hub that had promoted the op: simulator seeds 1
  and 257 after the first cut). After a
  cloud restore a node re-offers endorsed ops below the cloud's vector and the gateway takes quarantined `unsealed_tail`
  slots as released (`OnEndorsed`). `Gateway.RotateOpKey` re-signs cloud seals and endorsements; nodes refresh stale
  endorsements by listing them in `placeholders`.
- **A2.2** `reoffered_epoch` (persisted) next to `epoch`; a hub's word opens, only a direct cloud hello with nothing left to push
  closes; ops the cloud keeps refusing do not count as left to push. The gateway clears the "unrecoverable origin gap" alert
  when the node's vector is no longer above the cloud's.
- **A2.4** the gateway uses `go-common/restore` (Reader once at start, `restore_state` table, `Guard` with a hook for the new
  cloud origin, `/readyz` through `Guard().Check`); `platform_meta` and `gateway_state` are no longer read. Development and
  the simulator stamp an epoch through `devepoch` (wraps `restoretest`).
- Residuals and open items: see "Fix wave" below (the by-hash residual and the stale-seal gap are now bound by the A2.8 rules).
- **Intent registry mapping (follow-up, not done in this pass):** the canonical registry is now
  `api-specs-p2/sync/intents/` (README maps the PoC names). `syncproto/intents.go` still uses PoC names and the permissions
  `bill.refund`, `payment.take`, `kds.update`, `menu.edit`, `stock.adjust`, which are not catalogue keys. The mapping touches the
  simulator's device ops and the contract suite as well, so it is a separate change: replace the table by one generated
  from the YAML files and map the demo names the TypeScript client uses.

## Fix wave after the Phase 1 reviews (2026-11-25)

Build: `go.mod` pins go-common 732c3b1 and go-auth b19b540; `GOWORK=off go build ./...` works (review M4, L6 pin).

**Manager and vendor endpoints (code review H2).** Every route is registered through `go-auth` `Guard` with a policy
(`api/admin.go`), on a catalogue that holds the permissions below until `api-specs/common/permissions.yaml` does. Support
tokens need the `admin` service token and never carry `*`, sensitive, strong-only or owner-grant permissions; vendor access
is in `vendor_access_log` (same transaction as the action, refusals in their own); lists and decisions are narrowed to the
caller's outlets (another outlet's slot is 404; a brand or tenant stream needs an all-outlets grant); release, discard and
confirm need a reason and write `audit_log` (actor, slot, reason, status before and after) in the same transaction as the
status change; bodies are limited to 4 KiB (L4). Step-up: none added (the ADR-0005 A2 step-up list is closed); caution applies
through `device.recover` (`strong_only`, checked when an unsealed tail is released: `approval_required` on a new device).

Permissions to add to the catalogue (key, service, flags):

| key | service | flags |
|---|---|---|
| `sync.quarantine.read` | sync | `support_viewable` |
| `sync.exceptions.read` | sync | `support_viewable` (also guards the alerts list; vendor-audience alerts show to a support session only) |
| `sync.register.read` | sync | `support_viewable` |
| `sync.quarantine.manage` | sync | `sensitive` (release and discard; reason and audit record) |
| `sync.quarantine.confirm` | sync | `support_actable` (Hostry's confirmation of a chain-broken, foreign-series or fork hold; the handler also refuses a non-support token) |
| `device.recover` | identity | `sensitive`, `strong_only`, `owner_grant` (ADR-0002 A1.3) |

Open for the security reviewer: `sync.quarantine.confirm` as the first `support_actable` permission (ADR-0005 A2.5 asks each
product spec to propose and the reviewer to sign); and whether release should be `strong_only` rather than `sensitive`
(a manager could not then release on a new device for 24 hours, which would be the simplest answer to "SIM-swapped manager
releases a held bill"). The permission names `sync.quarantine.read` and `confirm` are new; the three old names are unchanged.

**Placeholders, binding and conflicts (ADR-0002 A2.8, security ruling 4).** `engine/binding.go`, `contract/README.md`.
Hubs and peers serve and accept no placeholder above an origin's sealed head (only the cloud does); a body over a held
placeholder is checked against the hash held, the op below, a seal that names the slot and the op above, else marked
`unbound`; unbound ops are never relayed; every direct cloud `hello` lists them and the gateway answers with its own hash;
a contradiction is `chain_conflict` (refused, recorded, origin gated from that kind of upstream, reported at the next direct
cloud `hello`, one vendor alert per slot). `DirectCloudDue` tells the app when to reach the cloud directly (24 hours, an
unbound slot, an unreported conflict or a refused cloud seal). Seals that name placeholder slots are now stored and served.
Stale cloud seals are refreshed by relays (`stale_seals` / `seal_refresh`); seal verification is under the named `kid`
only (review L8). The signed body's `tenant_id` must be the node's tenant (review M3). Tests: `engine/a28_test.go` (PH1,
PH2, PH3, KR1, M3, L8) and the simulator (300 seeds, all hazards).
Not done here: the TypeScript engine in `client-core-sync` has none of this yet (hash-only promotion, trailing placeholders
from any upstream, no `unbound`, `chain_conflict` or `stale_seals`); it must follow the same rules and the shared vectors
before the `client-core` sync PR merges. The simulator does not yet script a lying hub end to end; the engine cases do.

**Other.** Startup refuses a Postgres role that is a superuser or has BYPASSRLS (`CheckAppRole`; integration case). A
non-UUID tenant on the outbox path is refused instead of silently skipping the event (L5). mDNS TXT values are bounded and
fuzzed (L6); the discovery test runs on request only (L8). Sync contract still not in `api-specs` (M5): open.

## Not built (out of scope or later)

Standby promotion, cloud archiving, role-filtered streams, a TypeScript snapshot client, the hub as a Windows service, real
identity and tenancy clients, DPAPI-protected hub storage, TLS with channel binding, per-op `pii` erasure endpoint, keystore signing
latency on Android, the real-router discovery spike, Postgres rollback in the simulator (the DR drill 1e-3 covers it).

## Running

```
go test ./...                                  # unit, cases V/RB/KL, property seeds, contract suite
go run ./cmd/simulate -runs 100 -steps 500     # seeded runs; -seed N reproduces one; -soak 30m for wall-clock soak
go run ./cmd/devstack -out /tmp/fixture.json   # gateway + hub for the client-core e2e (writes <out>.hub-pack.json too)
SYNC_PG_DSN=postgres://hostry:hostry-dev-only@127.0.0.1:15432/hostry go test ./integration
```
Dev stack: `docker compose -p sync -f infra/dev/compose.yaml up -d postgres` with `HOSTRY_PG_PORT=15432` (stop with `down`).
