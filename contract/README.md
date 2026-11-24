# Sync Protocol v1 wire contract (PoC)

`sync-v1.openapi.yaml` is the machine-readable contract; this file holds the rules JSON Schema cannot
state. `vectors/v1.json` is the shared conformance data (canonical JSON, hashes, genesis hash, seal
message, HLC). Go checks it in `syncproto/vectors_test.go`; client-core checks the same file. Owned by
svc-sync during the Phase 1 proof of concept; it should move to `api-specs` (`openapi/sync`,
`sync/conformance`) when that repo takes sync.

## Framing and hashing
- An op travels as `Item{origin, stream, seq, h, body, pii}`. `body` is the **canonical JSON text of the op
  body as a JSON string**. Relays forward it byte for byte; every verifier hashes the UTF-8 bytes it
  received: `h = lowercase hex SHA-256(body)`. Nobody re-serialises (S17).
- Canonical form is RFC 8785 for the integer-only subset: sorted keys (UTF-16 order), no whitespace, minimal
  escapes, integers only within +-(2^53-1). Fractions and exponents are refused (money is paise).
- Chain: `ph` of op n is `h` of op n-1 of the same origin and stream; op 1 chains to
  `sha256("hostry-genesis-v1\n" + origin + "\n" + stream)`.
- Seal: ES256 (raw r||s, base64url) over `sha256("hostry-seal-v1\n" + origin + "\n" + stream + "\n" + seq + "\n" + h)`.
  A push group (origin, stream) must end at a sealed op; a node accepts nothing a valid seal does not cover.
  The hub and cloud serve ops only up to a seal boundary.
- **Gateway endorsement (PoC addition).** The released, previously unsealed tail of a key-lost origin has no
  origin seal. The gateway then signs the same seal message with its op-signing key; verifiers accept a seal
  that verifies under the origin key **or** under a known op-signing key. Clients need this to take that tail.
- Vectors are flat maps keyed `origin/stream`. Placeholders (no `body`) fill held slots and carry `h`.

## Sync void (answer to "is the assumed encoding right")
Confirmed with one correction: intent `sync.void` from origin `cloud-<epoch>`, one mutation
`{e:"sync_void", id:"<stream>|<origin>|<seq>", k:"insert", f:{origin, stream, seq, reason:"refused"}}`. The `id`
is `stream|origin|seq` (the client's form; the gateway now emits exactly this). `reason` is always `refused`.
The void is sealed by the gateway like any cloud-origin op. A node adds the named op to its void set.

## Keys: how the op-signing key reaches clients
Through the **signed offline pack** (ADR-0005 section 6), as `cloud_keys: {kid: pub}` (X9.62 uncompressed P-256 point,
base64url), together with the identity verification key. Never through `hello` (trust on first use would
defeat the seal). `KeyRing.addCloudKey(kid, pub)` is the right entry. Seals carry `kid`.

## Authentication
- Cloud: `Authorization: Bearer` go-auth device token (typ `device`). Drain tokens only at
  `quarantine-upload`; a recovery drain token has subject `recovers:<old device id>`.
- LAN hub: `Hostry-Device-Assertion` = base64url JSON `{cred, ts, sig}`, `sig` over
  `sha256("hostry-lan-v1\n" + METHOD + "\n" + path + "\n" + ts + "\n" + hex SHA-256 of the request body bytes **as sent**
  (after gzip, if gzipped))`. The hub answers every call with `Hostry-Hub-Proof` = base64url JSON `{cred, sig}`, `sig`
  over `sha256("hostry-hub-v1\n" + requestSig + "\n" + hex SHA-256 of the response body)`. Timestamp window 2 minutes.
  TLS is not in the PoC.

## hello
- `snapshot_required` is always `false`; the PoC does not need a snapshot client (`GET /snapshot` exists in its
  simplest form for tooling).
- A hub's `cloud_vector` is what the cloud confirmed to **that hub** at its last upstream contact. A device may
  treat its ops under it as delivered to the cloud (`in_cloud` via the hub). Intended.
- `epoch` is the cloud epoch. A change makes the node set a persisted re-offer flag. **A device whose upstream is a
  hub must also sync with the cloud directly while the flag is set**: after a restore the hub can hold only a
  placeholder for a slot whose body the cloud lost, so the origin is the only node that can deliver it (found
  by the simulator, seed 1). Clear the flag when a push of everything above the cloud's vector is empty.

## Verdicts and read-back
Devices learn about their own held slots only as `held` (push) and `own_held` (pull) with one of
`pending | held_manager | held_support`, and about refused configuration only through the `sync.void` op.
Flags, reasons and attribution labels exist only behind member-token admin endpoints.

## Document numbers
`<code>/<FY>/<running>`, `code` 3 characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (no I, O, 0, 1), FY as four
digits, six-digit running number. ADR-0002 S7 excludes `0` yet shows `A07/...`; the registry rule is followed and
the example is not a valid code (the stub registry issues `AAA`, `AAB`, ...). The PoC intent registry is
`syncproto/intents.go`; it also lists the demo intent names the TypeScript client uses.
