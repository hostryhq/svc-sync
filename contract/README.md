# Sync Protocol v1 wire contract (PoC)

`sync-v1.openapi.yaml` is the machine-readable contract; this file holds the rules JSON Schema cannot
state. `vectors/v1.json` is the shared conformance data (canonical JSON, hashes, genesis hash, seal
message, HLC, endorsement and attestation messages, endorsement verification cases). Go checks it in `syncproto/vectors_test.go`; client-core checks the same file. Owned by
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
- **Endorsement (ADR-0002 A2.1; replaces the PoC rule "an op-signing key may seal any origin").** The released,
  previously unsealed tail of a key-lost origin has no origin seal. The gateway signs a separate object
  `endorsement = {origin, stream, seq, h, rec, kid, sig}`: ES256 by an op-signing key (`cloud_keys` of the pack, named
  by `kid`) over `sha256("hostry-endorse-v1\n" + origin + "\n" + stream + "\n" + seq + "\n" + h + "\n" + rec)`; `rec` is
  the recovery id. One endorsement per released op, made in the release transaction (a voided configuration op gets none).
  Wire fields: `endorsements` and `attestations` (arrays) in the pull response, in the push request and in the
  quarantine-upload; the adopting device's credential travels in `creds` of a pull. **Seal rule:** a signature by an
  op-signing key under the `hostry-seal-v1` tag is valid only for a `cloud-<epoch>` origin (the seal's `kid` selects the
  key; a key the node does not hold, or has revoked, verifies nothing). It never seals a device origin.
- **Verifier rule (hub, device, gateway; identical).** An op of origin X that no seal of X covers is accepted only if
  (1) an endorsement for exactly `(origin, stream, seq, h)` verifies under a *current* op-signing key; (2) the node holds
  an identity-signed credential of a device Y with `recovers: X`; (3) an attestation for `(X, stream)` with the same `rec`
  verifies under Y's key, the op's `seq` is at or below the attested `seq`, and the op the node holds (or has in the
  batch) at the attested `seq` has the attested `h`. The chain check (`ph`) does the rest, so the highest verified
  endorsement of a batch covers the chain below it. Every op accepted this way is marked `unsealed` in the node's audit
  views. Anything else unsealed is refused (`unsealed`).
- **Serving and relaying endorsements (the client must do this too).** An endorsement counts as a seal boundary: a hub,
  device or gateway cuts a served or pushed batch at a seal *or* an endorsement. A batch whose cut is an endorsement carries
  **every endorsement in the range** (not only the last), the last origin seal in the range (so that the sealed part stays
  unmarked), the stored attestation(s), and in a pull the credential(s) of the adopting device. A node therefore must
  *store* what it verified (endorsements, attestations) and re-serve it with the ops. A released op answered for a
  `placeholders` entry carries its endorsement, attestation and the credential the same way. A node holding the
  placeholder verifies an endorsement that arrives with the body by the rule above and marks the op `unsealed`; a body that
  arrives with no endorsement is an ordinary released slot and is taken by hash, as before A2 (a residual: the same upstream
  gave the placeholder's hash).
- **After a cloud restore (A2.1 item 5).** While its re-offer is open a node's push also carries `items` + `endorsements`
  (+ `attestations`) for endorsed ops *at or below* the cloud's vector. The gateway takes a slot it holds as `quarantined`
  (`unsealed_tail`) as released, marked `unsealed`, with no owner action, if endorsement, credential and attestation
  verify. Tail ops that come back without an endorsement go back to quarantine through the recovery re-upload.
- **Key rotation (A2.1 item 6).** After an emergency rotation the gateway re-signs its cloud-origin seals and every
  endorsement under the new key. A node refreshes its pack (adds the new `cloud_keys` entry, drops the old) and then
  lists any op whose stored endorsement is under a dropped key in `placeholders`; the answer carries the re-issued
  endorsement and replaces the stored one. A node that holds only the new key converges from the cloud (or from a hub
  that has refreshed).
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
- `epoch` is the cloud epoch. **Re-offer (ADR-0002 A2.2).** Each node persists two meta values: `epoch` (the newest epoch
  heard from any upstream) and `reoffered_epoch` (the epoch it last finished re-offering for). The re-offer is **open** while
  they differ. A hub's `hello.epoch` may open it (when it differs from both values; a hub that repeats the already
  re-offered epoch is stale and ignored); the cloud's `hello.epoch` is authoritative. While it is open a device whose
  upstream is a hub also runs `hello` and push **against the cloud directly**, on its ordinary retry schedule, and keeps
  syncing with the hub: the hub may hold only a placeholder for a slot whose body the cloud lost, so the origin is the
  only node that can deliver it (simulator seed 1). The first push round of an open re-offer also carries the endorsed ops
  below the cloud's vector (above). **Closing:** only a direct cloud `hello` whose epoch equals the newest epoch, after
  which nothing is left to push, sets `reoffered_epoch = epoch`. An op the cloud refused (listed in `refused` of the push
  response) does not count as left to push, so one op refused for ever cannot hold the re-offer open. Every direct cloud
  contact for another reason (pack refresh, delivery of an op a hub will not relay) compares epoch and vector the same way.
  A device with no cloud route stays open; the gateway raises "unrecoverable origin gap" 24 hours after a node first reports
  a vector above the cloud's, and clears it when the node's vector is no longer above.

## Verdicts and read-back
Devices learn about their own held slots only as `held` (push) and `own_held` (pull) with one of
`pending | held_manager | held_support`, and about refused configuration only through the `sync.void` op.
Flags, reasons and attribution labels exist only behind member-token admin endpoints.

## Document numbers
`<code>/<FY>/<running>`, `code` 3 characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (no I, O, 0, 1), FY as four
digits, six-digit running number. ADR-0002 S7 excludes `0` yet shows `A07/...`; the registry rule is followed and
the example is not a valid code (the stub registry issues `AAA`, `AAB`, ...). The PoC intent registry is
`syncproto/intents.go`; it also lists the demo intent names the TypeScript client uses.
