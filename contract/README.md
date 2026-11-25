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

Pinned version: branch `feat/phase2-specs` at `b153c62` (round 3; the Go libraries are pinned in `go.mod`: go-common `feat/phase2-libs` @ `92884d6`, go-auth `feat/phase2-auth` @ `94f1970`; svc-identity `feat/phase2-identity` @ `ebebd4c` in `identityreal/go.mod`). The checkout is found through `API_SPECS_DIR`, or as a
sibling directory `../api-specs`, then `../api-specs-p2` (`contract/specs`). Tests fail, not skip, without it.

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

## Open questions that need a decision (see docs/phase2-notes.md)
1. **Proof questions to identity.** `verifyProof` needs `pin_v`, `pack_v` as an integer and (for a session proof) `opened_at`; the op body
   carries `sid`, `pack_v` as text and `proof`, and nothing else. Until the wire carries them the gateway cannot ask identity
   (`identityclient.ProofParams` is the single hook).
2. **Directory questions identity cannot answer.** The contract's internal routes (`x-service-callers: sync`) are `listRevocations`,
   `recordDeviceDrained`, `verifyProof`, `checkPackHistory`. There is none for a device's credential (public key, kind, outlet, brand),
   the permissions a pack granted, key-loss recovery records, or the revocation reason (`key_lost`).
