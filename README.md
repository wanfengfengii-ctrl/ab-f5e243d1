# Telemetry Sequence Service

A backend-only, horizontally scalable ingestion service for industrial edge
devices. Devices may come back online after hours offline and retransmit events
out of order; proxies may disconnect after commit but before the response and
retry; the same device may be uploaded through two gateways at once. Audit
consumers only ever observe events that form a contiguous prefix beginning at
sequence `1`, carry a valid Ed25519 signature and an intact SHA-256 hash chain.
Any gap, conflicting candidate or wrong predecessor is surfaced as an
adjudicable conflict and never skipped.

- **Language/runtime:** Go (static binary, CGO-free), three roles in one image:
  `api`, `worker`, `gateway`.
- **Database/arbiter:** PostgreSQL 16. It is the *only* coordination mechanism
  between API instances and the background worker — there are no in-memory
  locks, in-process queues or single-instance assumptions.
- **No frontend.**

---

## 1. Quick start

Everything runs with Docker only; all Go modules are vendored, and the only
images fetched are `golang:1.27-alpine` (build stage), `alpine:3.20`
(runtime) and `postgres:16-alpine`.

```bash
# Start db + two API instances + background worker + reverse proxy.
docker compose up --build

# In another shell: one-shot acceptance job through the gateway.
docker compose run --rm verify
```

The service is then reachable at <http://localhost:8080> (the gateway is the
**only** host-published port). Override it with `API_PORT`:

```bash
API_PORT=18080 docker compose up --build
```

Health endpoints do not depend on external services:

- `GET /healthz` — liveness (`{"status":"ok"}`)
- `GET /readyz` — readiness, returns 503 unless PostgreSQL is reachable.

Configuration (all via environment):

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | — | PostgreSQL connection string (required) |
| `ADMIN_TOKEN` | — | Bearer token for rotation/adjudication/compaction (required) |
| `SERVER_SIGNING_KEY` | — | base64 of the 32-byte Ed25519 seed used to sign checkpoints (required) |
| `ROLE` | `api` | `api`, `worker` or `gateway` |
| `HTTP_ADDR` | `:8080` | Listen address |
| `UPSTREAM_URL` | — | gateway role only; comma-separated API base URLs |
| `MAX_BODY_BYTES` | `4194304` (4 MiB) | request body limit |
| `DEFAULT_PAGE_SIZE` / `MAX_PAGE_SIZE` | `100` / `500` | pagination limits |
| `WAIT_MAX_SECONDS` | `30` | maximum long-poll duration |
| `VIEW_TTL_SECONDS` | `600` | fixed read view lifetime |
| `COMPACTION_INTERVAL_SECONDS` | `30` | worker sweep interval |
| `COMPACTION_KEEP_EVENTS` | `200` | newest events always retained |
| `COMPACTION_MIN_AGE_SECONDS` | `120` | events younger than this are never compacted |
| `SHUTDOWN_TIMEOUT_SECONDS` | `20` | graceful shutdown budget |
| `LOG_LEVEL` | `info` | `debug|info|warn|error` (JSON logs to stdout) |

Run the Go test suite (unit tests need no database; integration tests need one
and are enabled with `DATABASE_URL` or `RUN_DB_TESTS=1`):

```bash
go test ./...
DATABASE_URL='postgres://user:pass@localhost/telemetry?sslmode=disable' go test ./...
```

---

## 2. Event wire format

Every event in a batch is:

```json
{
  "deviceId":   "plant-7/line-a",
  "sequence":   1,
  "eventId":    "evt-0001",
  "occurredAt": "2026-09-18T08:15:00.123456789Z",
  "keyVersion": 1,
  "prevDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "payload":    { "reading": 21.5, "tags": ["line-a", "press-3"], "unit": "°C" },
  "signature":  "O3ObFvT7bEMo1LpCBmktYjbreXj8imu9mQC7VAX6rZlgfSLfWtGLYpgDs8DaO07tDNt7Nl/11H/4ag7rhDS3CA=="
}
```

- `sequence` is per-device, starts at `1`, must be strictly monotone but may
  arrive in **any order**. A batch contains 1–500 events, and sequence numbers
  inside one batch must be unique.
- `eventId` is a free-form non-empty client identifier (≤ 200 chars).
- `occurredAt` is RFC 3339 date-time; it is normalized to UTC and serialized in
  the envelope using Go's `RFC3339Nano`, which preserves up to 9 fractional
  digits (e.g. `.123456789`, `.1234`).
- `keyVersion` selects the Ed25519 key generation that must have signed the
  event, based on the rotation boundary (see §6).
- `prevDigest` of sequence `1` **must** be the genesis anchor
  `sha256:` followed by 64 ASCII zeroes. Every later event must carry the
  digest of the actual predecessor event in the contiguous chain.
- `signature` is standard base64 of a 64-byte Ed25519 signature.

### 2.1 Deterministic payload canonicalization

Payload bytes are accepted as arbitrary JSON but are immediately re-encoded
with a fixed canonicalization before they are signed, hashed or stored. The
canonical form is defined by `internal/canonical` (a self-contained
RFC 8785 / JCS-style normalization):

1. **Objects:** members sorted ascending by key, compared as UTF-16 code unit
   sequences (exactly as JCS), shorter sequence first on a prefix.
2. **No insignificant whitespace** anywhere.
3. **Strings:** minimal escaping; `"`, `\`, and U+0000–U+001F escaped (short
   forms `\b \t \n \f \r`, else lowercase `\u00xx`). All other code points,
   including non-ASCII, are emitted as UTF-8 directly.
4. **Numbers:**
   - integer tokens (`-?(0|[1-9][0-9]*)`) are emitted verbatim with arbitrary
     precision, except `-0` → `0`;
   - every other finite number is parsed as IEEE-754 binary64 and emitted as the
     shortest fixed-point decimal that round-trips (equivalent to
     `strconv.FormatFloat(f, 'f', -1, 64)`); exponents are expanded
     (e.g. `1e3` → `1000`, `2.5E-2` → `0.025`, `1.50` → `1.5`);
   - `NaN`/`Infinity` are rejected, duplicate object member names are rejected,
     invalid UTF-8 and trailing JSON values are rejected.

Consequence: two payload documents that differ only in member order, whitespace
or equivalent float spelling canonicalize to the same bytes; results never
depend on Go's default `encoding/json` map ordering.

Example:

```text
input:      {"unit":"°C","reading":21.5,"tags":["line-a","press-3"]}
canonical:  {"reading":21.5,"tags":["line-a","press-3"],"unit":"°C"}
```

### 2.2 Event record (the digest input)

The digest input is the canonical JSON of this object:

```
{"deviceId":…,"eventId":…,"keyVersion":<int>,"occurredAt":<RFC3339Nano UTC string>,
 "payload":<canonical payload>,"prevDigest":…,"sequence":<int>}
```

It contains exactly seven members, no `domain` and no `signature`; canonical
key sorting determines the emitted order.

### 2.3 Digest format

```
digest = "sha256:" + lowercase_hex( SHA-256(record_canonical_bytes) )
```

32 bytes → 64 lowercase hex characters.

### 2.4 Signed bytes (exact definition)

The Ed25519 signature covers, byte for byte:

```
telemetry-event-v1\n
```

(the 17 ASCII characters including the trailing `0x0A`), immediately followed
by the canonical JSON of the signing envelope: the same object as the event
record plus the member `"domain":"telemetry-event-v1"`. After canonical
sorting the envelope is:

```
{"deviceId":…,"domain":"telemetry-event-v1","eventId":…,"keyVersion":…,
 "occurredAt":…,"payload":<canonical payload>,"prevDigest":…,"sequence":…}
```

The fixed prefix and the embedded domain both provide protocol domain
separation. Signatures are verified with the raw 32-byte public key of the
generation required for the event's sequence.

### 2.5 Reproducible worked example

All values below are produced by `go test ./internal/envelope/`
(`TestGoldenVectors`); the test fails if any byte changes.

- Ed25519 seed (hex): `1111…1111` (32 bytes of `0x11`)
- Public key (standard base64):
  `0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=`
- Raw payload:
  `{"unit":"°C","reading":21.5,"tags":["line-a","press-3"]}`
- Canonical payload:
  `{"reading":21.5,"tags":["line-a","press-3"],"unit":"°C"}`
- Canonical record (single line):

```
{"deviceId":"plant-7/line-a","eventId":"evt-0001","keyVersion":1,"occurredAt":"2026-09-18T08:15:00.123456789Z","payload":{"reading":21.5,"tags":["line-a","press-3"],"unit":"°C"},"prevDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","sequence":1}
```

- Signing bytes = `telemetry-event-v1\n` followed by the canonical envelope:

```
telemetry-event-v1
{"deviceId":"plant-7/line-a","domain":"telemetry-event-v1","eventId":"evt-0001","keyVersion":1,"occurredAt":"2026-09-18T08:15:00.123456789Z","payload":{"reading":21.5,"tags":["line-a","press-3"],"unit":"°C"},"prevDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","sequence":1}
```

- Digest:
  `sha256:a9791269d4cb57eed90af1067db55da593225f40725a121c7d0e6a8c85332a52`
- Signature (standard base64):
  `O3ObFvT7bEMo1LpCBmktYjbreXj8imu9mQC7VAX6rZlgfSLfWtGLYpgDs8DaO07tDNt7Nl/11H/4ag7rhDS3CA==`

You can reproduce the signature in any Ed25519 implementation by deriving the
private key from the seed above (RFC 8032), UTF-8-encoding the signing bytes
exactly as shown, and base64-encoding the 64-byte signature.

---

## 3. HTTP API (versioned under `/api/v1`)

All request/response bodies are `application/json`; unknown JSON fields are
rejected. Errors share the envelope

```json
{ "error": { "code": "stable_machine_code", "message": "human text",
             "details": { } } }
```

| Method & path | Auth | Purpose |
| --- | --- | --- |
| `POST /api/v1/devices` | — | register a device with its first Ed25519 key |
| `GET  /api/v1/devices/{id}` | — | status: revisions, watermark, keys, conflicts, checkpoint |
| `POST /api/v1/devices/{id}/keys` | admin | key rotation command |
| `POST /api/v1/devices/{id}/ingest` | — | batch ingestion (signed events + `requestId`) |
| `GET  /api/v1/devices/{id}/conflicts` | — | list open conflicts with candidates |
| `GET  /api/v1/devices/{id}/conflicts/{seq}` | — | one conflict with candidates |
| `POST /api/v1/devices/{id}/conflicts/{seq}/adjudicate` | admin | choose one candidate or reject all |
| `GET  /api/v1/devices/{id}/events` | — | open a fixed view / read a page (cursor) |
| `GET  /api/v1/devices/{id}/wait` | — | long-poll for new contiguous events |
| `POST /api/v1/devices/{id}/compaction/run` | admin | trigger one compaction pass |
| `GET  /api/v1/devices/{id}/checkpoint` | — | current signed checkpoint, if any |
| `GET  /api/v1/server/checkpoint-key` | — | server Ed25519 public key for verification |

### 3.1 Register

```bash
curl -sS -XPOST localhost:8080/api/v1/devices \
  -H 'Content-Type: application/json' \
  -d '{"deviceId":"plant-7/line-a",
       "publicKey":"0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc="}'
```

`publicKey` is standard/raw base64 of the 32 raw Ed25519 bytes. Registration
creates key generation `keyVersion = 1`, `effectiveSequence = 1`, and returns
the initial `controlRevision = 0`. Duplicate `deviceId` → `409 device_exists`.

### 3.2 Batch ingest

```http
POST /api/v1/devices/{id}/ingest
{ "requestId": "client-generated-unique-id",
  "events": [ {…event…}, … ] }
```

- Batch size 1–500. The **whole batch is atomic**: any malformed event, bad
  signature, wrong key generation or duplicate in-batch sequence rejects the
  batch without leaving a single candidate behind.
- `requestId` is caller-generated. The exact same request (same `requestId`
  **and** identical canonical content) always returns the first committed
  result and never duplicates events — including when the proxy retries after a
  disconnect, and under concurrent identical submissions.
- The request content identity is the SHA-256 of the canonical document
  `{"deviceId":…,"events":[{"digest":…,"signature":…}, …]}` with events sorted
  by `(digest, signature)` so it does not depend on array order or JSON
  formatting. The same `requestId` with different content is a stable
  `409 idempotency_content_mismatch`.
- Sealed sequences (≤ current watermark) accept only the already-visible
  digest; anything else is `422 sequence_sealed`.

Success response:

```json
{ "requestId": "…", "deviceId": "…",
  "contiguousHighWatermark": 7, "conflictRevision": 1,
  "storedSequences": [3], "duplicateSequences": [],
  "advancedSequences": [2,3,4,5,6,7],
  "conflicts": [ {"sequence":8,"reason":"divergent_candidates","status":"open","revision":3} ] }
```

### 3.3 Status and conflicts

`GET /devices/{id}` returns `controlRevision`, `conflictRevision`,
`contiguousHighWatermark`, `checkpointSequence`, key generations and the open
conflict list. Conflict reasons:

- `divergent_candidates` — at least two live, distinct candidates at the
  sequence (different digests).
- `wrong_predecessor` — a single live candidate whose `prevDigest` does not
  equal the digest of the actual predecessor.

Conflict objects carry a monotonic `revision` and, when applicable, every
candidate with `digest`, `eventId`, `keyVersion`, `status`
(`pending|chosen|accepted|rejected`) and `firstSeen`.

### 3.4 Adjudication

```http
POST /api/v1/devices/{id}/conflicts/{seq}/adjudicate
Authorization: Bearer $ADMIN_TOKEN
{ "commandId": "unique-command-id",
  "expectedConflictRevision": 3,
  "decision": "choose_candidate",
  "candidateDigest": "sha256:…" }
```

`decision` is `choose_candidate` (requires `candidateDigest`) or
`reject_all`. Guarantees:

- The command is idempotent by `commandId`; replaying it returns the stored
  first result byte-identically. Reusing the `commandId` with different content
  → `409 command_content_mismatch`.
- `expectedConflictRevision` must equal the current device conflict revision; a
  stale value → `409 conflict_revision_stale`, so a newer adjudication can never
  be overwritten.
- Choosing marks every competing candidate `rejected` and the chosen one
  `chosen`; rejecting all marks all live candidates `rejected`, after which
  clients may re-upload; an identical re-uploaded candidate becomes live again.
- Adjudication then attempts to advance the contiguous prefix. If the chosen
  candidate does not hash-chain to its predecessor, it cannot be made visible:
  the conflict reopens as `wrong_predecessor` and the response field
  `reopenedAs` reports it.
- Adjudication, candidate state changes and watermark movement commit in one
  transaction and remain consistent after a crash.

### 3.5 Fixed-view pagination

The first request opens an immutable snapshot:

```http
GET /api/v1/devices/{id}/events?limit=100
GET /api/v1/devices/{id}/events?startAfterSequence=8&limit=100
```

```json
{ "deviceId": "…", "viewId": "f1f5…", "viewHighWatermark": 7,
  "events": [ …accepted events… ],
  "nextCursor": "Eocv…base64url…" }
```

- The view's watermark is fixed at creation; commits that land while paging
  never mix in. Views live `VIEW_TTL_SECONDS`.
- `nextCursor` is `base64url(JSON(claims) || HMAC-SHA256)` and therefore
  unforgeable. Claims bind `deviceId`, `viewId` and the last delivered
  `position`. Tampering, use from another device, combining a cursor with
  `startAfterSequence`, moving a cursor backward, or reading beyond the view's
  watermark all return `400 invalid_cursor`.
- Events appear in sequence order and include all fields needed to re-verify
  signatures and the digest chain.

### 3.6 Waiting for new events

```http
GET /api/v1/devices/{id}/wait?afterSequence=7&timeoutSeconds=30&limit=100
```

- Waits at most 30s for accepted events with sequence `> afterSequence`.
  Timeout returns HTTP 200 with `"timedOut":true` and an empty `events` array.
- No lost wake-up: the waiter issues PostgreSQL `LISTEN` **before** reading the
  watermark on a dedicated connection; ingestion and adjudication `NOTIFY` in
  the same transaction that moves the watermark.
- Client disconnect cancels the request context, which interrupts the wait and
  releases the database connection; no waiters or connections leak.

### 3.7 Compaction and checkpoints

`POST /api/v1/devices/{id}/compaction/run` (admin; optional
`{"keepRecent":N,"minEventAgeSeconds":M}`) runs one pass immediately; the
background worker does the same periodically. Only accepted events in the
contiguous prefix can be deleted. A checkpoint is written atomically with the
deletion:

```json
{ "checkpoint": {
    "deviceId": "…", "sequence": 8,
    "digest": "sha256:<digest of the cutoff event>",
    "generatedAt": "2026-09-18T08:17:00.123456Z",
    "signature": "base64 Ed25519 signature" } }
```

Signed bytes:

```
TELEMETRY-CHECKPOINT-V1\n
{"deviceId":…,"digest":…,"generatedAt":…,"sequence":…}      (canonical JSON)
```

Verify with the public key at `GET /api/v1/server/checkpoint-key`. Compaction
cutoff is the minimum of: `high_watermark − keepRecent`, the oldest-age cutoff,
and the minimum `last_position` of every unexpired view — so it never removes
an event a valid view could still need. After the view expires, a cursor that
is behind the checkpoint gets:

```http
410 Gone
{ "error": { "code": "before_checkpoint",
   "details": { "resumeFromSequence": 9,
                "checkpoint": { …verifiable checkpoint… } } } }
```

Events are never both unreadable and uncovered by a checkpoint: cutoff digest
and row deletion commit together; a crashed pass safely retries and cannot
produce contradictory checkpoints (the persisted checkpoint only ever moves
forward).

---

## 4. Concurrency and crash model

### 4.1 Staging barrier

Correctness under same-sequence concurrency is provided by a per-device
PostgreSQL session advisory-lock barrier (`pg_advisory_lock_shared` /
`pg_advisory_xact_lock`), not by in-process mutexes:

1. an ingestion request acquires the **shared** barrier and runs the
   all-or-nothing staging transaction (validation, Ed25519 verification,
   candidate `INSERT`). Concurrent uploads for the device hold the shared lock
   simultaneously;
2. it then releases the shared lock and opens an advancement transaction that
   takes the barrier **exclusively** plus the device row `FOR UPDATE`. It can
   proceed only after every concurrently staging session finished, so all
   competing candidates for a sequence are durably visible;
3. rotation, adjudication and compaction take the same exclusive barrier.

A genuinely earlier request that completes before a later one starts wins the
frontier legitimately; two in-flight distinct uploads of the same sequence
**always** produce a conflict instead of a silent first-wins overwrite.
Identical digests collapse onto one row via the
`(device_id, sequence, digest)` primary key, so concurrent identical retries
create exactly one candidate.

### 4.2 Watermark advancement

Starting at the current watermark, the exclusive transaction walks forward:

- no live candidate → stop (gap);
- ≥2 live candidates → open/keep `divergent_candidates`, stop;
- exactly one candidate whose `prevDigest` ≠ predecessor digest → open/keep
  `wrong_predecessor`, stop;
- exactly one valid candidate → mark `accepted`, bump the watermark one step
  (conditional `UPDATE … WHERE contiguous_high_watermark = <old>`), close any
  blocking conflict, continue — one backfill can accept many staged events in
  a single pass, each with its `prevDigest` checked against the actual
  predecessor.

Readers therefore never observe a regressing watermark, duplicate sequences,
gaps or partial advancement: visibility is the set of `accepted` rows up to the
committed watermark. Every divergent sequence on the device (including ones
staged beyond a gap) is registered as a conflict inside the same transaction.

### 4.3 Failures and retries

- A failed batch commits *no candidates*. Its terminal error response is stored
  against the `requestId` (via a SAVEPOINT that rolls candidate work back while
  keeping the idempotency record), so the exact retry replays the same error.
- If a process dies between staging and responding, candidates are already
  durable. The next related request, an adjudication, the worker's periodic
  recovery sweep (`AdvanceAllDevices`) all rerun the idempotent advancement,
  so the watermark never gets permanently stuck.
- On startup every process waits for PostgreSQL and runs embedded,
  advisory-lock-guarded migrations.

### 4.4 Key rotation semantics

A rotation names a new `keyVersion` and `effectiveSequence` and requires the
current `expectedControlRevision`:

- `effectiveSequence` must be `> contiguousHighWatermark` and strictly greater
  than the previous generation's effective sequence;
- `keyVersion` must be greater than the latest one (duplicate/overlapping
  versions are deterministic `409`s);
- the new effective range must not contain any already-staged candidate:
  candidates there could only have been signed by the old key, so the command
  returns `409 rotation_boundary_occupied` carrying the occupied interval;
- generations are then strictly: `seq < effectiveSequence` → old key,
  `seq ≥ effectiveSequence` → new key. Out-of-order backfill of old events is
  still accepted; an old signature on/after the boundary is rejected
  (`key_generation_mismatch`); a boundary already occupied can never be
  reinterpreted.
- Rotation is idempotent by `commandId`; concurrent rotations serialize on the
  device row and the stale `expectedControlRevision` loses deterministically.

---

## 5. Limits and error codes

- Batch size: 1–500 events; request body ≤ 4 MiB (`413 request_body_too_large`);
  non-JSON content type → `415 unsupported_media_type`.
- Wait timeout: 0–30 s; page size 1–500.
- Selected codes: `device_exists (409)`, `device_not_found (404)`,
  `control_revision_stale (409)`, `conflict_revision_stale (409)`,
  `duplicate_key_version (409)`, `rotation_overlapping_effective_range (409)`,
  `rotation_boundary_occupied (409)`,
  `rotation_effective_sequence_too_low (409)`,
  `idempotency_content_mismatch (409)`, `command_content_mismatch (409)`,
  `conflict_already_resolved (409)`, `unauthorized (401)`,
  `batch_invalid|batch_mixed_devices|batch_duplicate_sequence|validation_error|
  invalid_json (400)`, `unknown_key_version|key_generation_mismatch|
  bad_signature|sequence_sealed (422)`, `invalid_cursor (400)`,
  `before_checkpoint (410)`, `request_body_too_large (413)`.

Observability: structured JSON request logs (method, path, status, latency),
panic recovery, and per-action worker logs. Shutdown is graceful: SIGTERM/SIGINT
stops accepting connections and drains in-flight requests within
`SHUTDOWN_TIMEOUT_SECONDS`.

---

## 6. Repository layout

```
cmd/telemetry/         binary entrypoint: api | worker | gateway (+ healthcheck)
cmd/verify/            one-shot compose acceptance job (HTTP-only)
internal/canonical/    deterministic JSON normalization (with unit vectors)
internal/envelope/     event record, signing bytes, digest, Ed25519 helpers
internal/cursor/       HMAC page cursors
internal/serverkey/    checkpoint signing key
internal/store/        PostgreSQL migrations (embedded) and all transactions
internal/httpapi/      versioned HTTP API
internal/worker/       recovery sweep + periodic compaction
internal/gateway/      buffering failover reverse proxy
internal/apierr/       stable error codes
internal/render/       error documents and HTTP status mapping
internal/config/       environment configuration
```

## 7. Security notes for deployment

- Replace `ADMIN_TOKEN` and `SERVER_SIGNING_KEY` (generate with e.g.
  `openssl rand -base64 32`). The compose defaults are for local acceptance
  only.
- Terminate TLS at your external load balancer; the gateway speaks plain HTTP
  inside the compose network.
- The gateway buffers request/response bodies (≤ 8 MiB) so a failed upstream
  can be retried before any byte reaches the client. POST retries are safe
  because all mutating endpoints are idempotent by `requestId`/`commandId`.
