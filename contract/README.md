# Sync Protocol v1: where the contract lives

svc-sync keeps no copy of the contract. It reads the **api-specs** repository (ADR-0002 A2.3):

| What | Path in api-specs |
|---|---|
| HTTP surface, including `emitOps` | `openapi/sync/v1/openapi.yaml` |
| Normative rules a schema cannot state (canonical form, hashing, chain, seal, endorsement, size limit, the op event) | `sync/protocol-v1.md` |
| Shared vectors (Go and TypeScript engines) | `sync/conformance/v1.json` |
| Intent registry (permissions, kinds, entities) | `sync/intents/*.yaml` |
| Entity registry (owners, policies, `doc_number`, `replicated_to`) | `entities/` |
| Bus events | `events/sync/*` |

Pinned version: branch `feat/phase2-specs` at `14c76fd` (round 5: ADR-0014 A3; before it `6e63014`, round 4b, ADR-0005 A3). The Go libraries are pinned in `go.mod` (go-common
`feat/phase2-libs` @ `92884d6`, go-auth `feat/phase2-auth` @ `94f1970`); svc-identity `feat/phase2-identity` @ `2ba5adc` and svc-tenancy
`feat/phase2-tenancy` @ `3792f07` in `identityreal/go.mod`. The checkout is found through `API_SPECS_DIR`, or as a sibling directory
`../api-specs-p2`, then `../api-specs` (`contract/specs`). Tests fail, not skip, without it.

## What is checked here
- `syncproto/vectors_test.go`: the shared vectors against this implementation.
- `syncproto/registry_test.go`: `intents_gen.go` is exactly what `go run ./cmd/genintents` writes from the registry; every
  device permission is a catalogue key (`common/permissions.yaml`); the document-number fields the gateway reads are the
  `doc_number` fields of `entities/`.
- `api/spec_test.go`: every OpenAPI example decodes strictly into the wire types and matches its own schema; emit callers.
- `contract/suite` (run against the real gateway in `sim` and against `double/`): every answer is validated against the
  operation's response schema, every error is an RFC 9457 problem with a code, and the emit contract (below).

## Emit (`POST /internal/v1/emit`)
Service token from `catalog` or `billing`; the gateway stamps `cloud-<epoch>`, seq, ph, hlc and seals each op. The tenant is the
**service token's** and must equal the request's `tenant_id` (403 `emit.tenant_mismatch`); a token without a tenant is refused (401)
(O2-11; go-common `emit.TokenSource(ctx, tenant)` mints it).

## Personal data (in api-specs since round 3, O2-12)
`syncproto/piic.go` is the only place that knows the construction and matches `go-common/sync` and `protocol-v1.md`: the sealed body
carries `pii_c` = per field `SHA-256(salt || JCS(value))`; wire `pii` = entity -> row id -> field -> value plus the field's salt under
`~s:<field>`; a node keeps only fields that verify (value and salt together). **The gateway publishes the verified values with their
salts** in the op event; the owning service verifies again. Erasure (`sync.pii.erase`, record `pii_erase`) removes values AND salts; the
commitments stay. The next direct cloud hello carries `pii_erased` (refs of the target ops).

## Wire fields of ADR-0002 A2.8 that api-specs does not carry (for the spec owner)
Implemented here and in `client-core-sync`; `protocol-v1.md` still says "no settled field name" and the OpenAPI has none of them.
| Where | Field | Shape | Meaning |
|---|---|---|---|
| `HelloRequest` | `unbound` | `[{origin, stream, seq}]` | slots the node took by hash with no binding yet; only the cloud answers; listed at every direct cloud hello |
| `HelloRequest` | `chain_conflicts` | `[{origin, stream, seq, held, seen?}]` | chain conflicts the node recorded and has not reported (`held` = hash the node holds, `seen` = the hash that contradicted it) |
| `HelloResponse` | `unbound_h` | `[{origin, stream, seq, h}]` | the cloud's own hash for each slot named in `unbound` that it holds |
| `PullRequest` | `stale_seals` | `[{origin, stream, seq}]` | stored cloud-origin seals under an op-signing key the caller no longer accepts |
| `PullResponse` | `seal_refresh` | `[Seal]` | the current seal for each `stale_seals` entry |
| `Refusal.reason` | `chain_conflict` | enum value | a body or link contradicts what the node holds or a seal states (add to the enum beside `fork_evidence_kept`) |

## ADR-0005 A3 on this side (resolved; was "open questions")
1. **Proof on the wire (A3.1).** `pack_v` is an integer on every device op; `proof` and `pin_v` ride only on `session.open` of a `pin` session and on
   `approval.grant`, and `at` of `session.open` is the opening time the proof binds (`syncproto.Body`). The gateway asks identity once per proof
   (`service/session.go`, `Idempotency-Key` from origin, stream and seq) and stores the verdict per `(tenant, origin, sid)` in `sessions`
   (migration 0013); every later op is judged from that row (same actor, within 16 hours); a strong session is judged from `getSession`.
   Identity unreachable is `pending`; `ResolveSessions` (the worker in `cmd/gateway`) asks again, clears the mark and flags a failure.
2. **Directory routes (A3.2).** `realdir` answers credential, pack grants, member grants, recovery, session facts, pack history (any pack),
   revocations with `reason` and `recovery_id` (cursor and set persisted), device series, outlet paper books and stream owner from
   `identityclient/gen` and `tenancyclient/gen` (generated from the bundled specs). Caches follow A3.2. A lookup that cannot be asked counts a fault
   (`directory.Faulty`): a configuration op then waits (`config_pending`), a trading fact keeps the pending mark.
3. **Drain statement (A3.3).** `quarantine-upload` takes `PushRequest.drain_statement` (`hostry-drain-v1`, `syncproto/drain.go`, the three vectors of
   `sync/conformance/v1.json`). The gateway reports drained only for a statement signed with the device's credential key that names exactly the ops it
   holds (`service/drain.go`); anything else is stored as evidence with a vendor alert. `ReportPendingDrains` calls `recordDeviceDrained` with the
   statement hash as its key until identity answers; nothing else calls it.

## Still open
- **Wire fields of A2.8** (table above) are in `protocol-v1.md` since round 4; `Refusal.reason` `chain_conflict` is in the OpenAPI.
- **Approval record fields.** `approval.grant` carries its record as a mutation `approval` (`id` = approval id; `permission`, `target`, `requester`,
  `approver`, `action_hash`, `reason`); the gateway reads those names for `verifyProof` (`ProofVerification` kind approval). The entity file does not
  name them yet.
- `cmd/gateway` series events: `tenancy.series.issued` and `.closed` do not list `sync` as subscriber, so a series is seen within the 60-second cache time.

## ADR-0014 A3 on this side (round 5, `14c76fd`)
- **Vectors.** `syncproto/a3_vectors_test.go` runs `pii_placement` (`ServesPII`), `digest_row` (`RowText`), `action_hash` (`ActionHash`,
  including the OV2 mismatch case) and `approval_proof` (`SessionProofMessage`, `ApprovalProofMessage`, `ProofMAC`) from the checkout.
- **A3.1 placement.** `engine.Serve` and `Gateway.Snapshot`/`Hub.Snapshot` give `pii` (values with their salts) to a puller of kind `pos`,
  `waiter`, `personal` or `hub` and never to a `kds`; the commitments (`pii_c`, in the body and on every snapshot row) reach every kind.
  A node of those kinds keeps `pii-need:<op>` for an op whose commitments have no value (`pii_incomplete`) and lists it in the `placeholders`
  of its next pull; the answer carries the op with its values, and a held op that arrives again with values is completed (verified, merged).
  The cloud restore re-offer (and a day after it) offers the pii-bearing ops again, so an op the cloud took first from a relay that held no
  values is completed (`engine.reofferPII`). The recovery upload carries the adopter's values.
- **A3.2 hash.** `State.ApplyPII` adds the commitment of each `pii` field (`entities_gen.go` marks them) as the candidate `~c:<field>`,
  merged by the field's own rule; `State.Hash` therefore covers commitments and no value, equal on every kind and unchanged by erasure.
- **A3.3 approval citation.** `service/approval.go`; table `approval_verdicts` holds the record (migration 0015). Wire addition read from the
  contract: intent `approval.self_confirm`; `Exception.reason` (`approval_flag`). Marks: `approval_flag` + `approval_reason:<reason>`,
  `approval_pending`, `approved_by:<member>`. An approval cited from another origin is not found and stays `pending` (it is keyed by origin).
- **Device sessions.** `deviceSessionExpired`: 26 hours, no PIN-session limit; the opening time is kept by `PutSession`.
- **A3.4.** A credential answer without `brand_id` is a fault (`identityclient`, `realdir`); stream binding uses the credential only.
  Dev routes: `brand_id` is required at registration and answered with `kid` (also in `device`), the hub pack carries `kid`.
