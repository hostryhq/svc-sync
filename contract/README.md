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

Pinned version: branch `feat/phase2-specs` at `1462fb8`. The checkout is found through `API_SPECS_DIR`, or as a
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
**service token's** and must equal the request's `tenant_id` (403 `emit.tenant_mismatch`); a token without a tenant is refused (401).
The contract text says "a service token carries no tenant"; see open item 1 in `docs/phase2-notes.md`.

## Provisional, not in the contract yet (see docs/phase2-notes.md)
- **Personal data.** The sealed body carries `pii_c` = per field `SHA-256(salt || JCS(value))` (`syncproto/piic.go`, the only
  place that knows the construction). Wire `pii` = entity -> row id -> field -> value, plus the field's salt under the key
  `~s:<field>`. A node keeps only fields that verify. Erasure is the cloud-origin op `sync.pii.erase` (record `pii_erase`, id
  `stream|origin|seq` of the target): nodes remove values and salts from rows, op log, caches and spool, and discard later
  arrivals. **Acknowledgement:** the next hello to the cloud carries `pii_erased: [{origin, stream, seq}]` (refs of the
  *target* ops); the gateway records it per node; a node that only reaches a hub acknowledges at its next direct cloud hello.
- **`series.close`** records `series_close` (id = series id, fields `code`, `fy`, `last_number`).
- The `stale_seals`, `unbound`, `chain_conflicts`, `seal_refresh` and `unbound_h` fields of ADR-0002 A2.8 are implemented and are
  not in the OpenAPI yet (the contract says so).
