-- Telemetry sequence service: initial schema.
-- PostgreSQL is the single source of truth across all API instances and the
-- background worker. All concurrency invariants are enforced here via row
-- locks, unique constraints and transactions.

-- Devices -------------------------------------------------------------------
CREATE TABLE devices (
    device_id                    text PRIMARY KEY,
    control_revision             bigint NOT NULL DEFAULT 0,
    -- Bumped on every conflict state change (open/update/resolve).
    conflict_revision            bigint NOT NULL DEFAULT 0,
    contiguous_high_watermark    bigint NOT NULL DEFAULT 0,
    -- Highest sequence covered by a durable checkpoint (0 when none).
    checkpoint_seq               bigint NOT NULL DEFAULT 0,
    created_at                   timestamptz NOT NULL DEFAULT now(),
    updated_at                   timestamptz NOT NULL DEFAULT now()
);

-- Key generations. effective_sequence is the first sequence at which the key
-- is valid: seq < effective_sequence uses the previous generation.
CREATE TABLE device_keys (
    device_id          text NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    key_version        int  NOT NULL CHECK (key_version >= 1),
    public_key         bytea NOT NULL,
    effective_sequence bigint NOT NULL CHECK (effective_sequence >= 1),
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, key_version)
);
CREATE INDEX device_keys_eff_idx ON device_keys (device_id, effective_sequence);

-- Event candidates ----------------------------------------------------------
-- status:
--   pending  - uploaded candidate, not yet part of the contiguous prefix
--   chosen   - explicitly selected by adjudication, awaiting contiguity
--   accepted - part of the visible contiguous prefix (immutable afterwards)
--   rejected - explicitly refused by adjudication
CREATE TABLE events (
    device_id         text NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    sequence          bigint NOT NULL CHECK (sequence >= 1),
    digest            text NOT NULL,
    event_id          text NOT NULL,
    occurred_at       text NOT NULL,            -- exact canonical RFC3339Nano UTC string
    key_version       int  NOT NULL,
    prev_digest       text NOT NULL,
    payload_canonical bytea NOT NULL,
    signature         bytea NOT NULL,
    status            text NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending','chosen','accepted','rejected')),
    first_seen        timestamptz NOT NULL DEFAULT now(),
    accepted_at       timestamptz,
    PRIMARY KEY (device_id, sequence, digest)
);
-- Only one accepted (or chosen+accepted) candidate per sequence is possible
-- through the advancement logic; additionally enforce it declaratively:
CREATE UNIQUE INDEX events_one_accepted_idx
    ON events (device_id, sequence) WHERE status = 'accepted';
CREATE INDEX events_device_status_seq_idx
    ON events (device_id, status, sequence);

-- Conflicts -----------------------------------------------------------------
CREATE TABLE conflicts (
    device_id     text NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    sequence      bigint NOT NULL,
    -- divergent_candidates: >=2 live candidates; wrong_predecessor: sole
    -- candidate's prevDigest does not match the actual predecessor.
    reason        text NOT NULL CHECK (reason IN ('divergent_candidates','wrong_predecessor')),
    status        text NOT NULL CHECK (status IN ('open','resolved')),
    -- Revision value of devices.conflict_revision at the latest state change.
    revision      bigint NOT NULL,
    resolution    text CHECK (resolution IS NULL OR resolution IN ('chose_candidate','rejected_all')),
    chosen_digest text,
    opened_at     timestamptz NOT NULL DEFAULT now(),
    resolved_at   timestamptz,
    PRIMARY KEY (device_id, sequence)
);

-- Idempotency records -------------------------------------------------------
CREATE TABLE ingest_requests (
    request_id    text PRIMARY KEY,
    device_id     text NOT NULL,
    content_hash  bytea NOT NULL,
    response_code int,                       -- NULL while the originating tx is in flight
    response      jsonb,                     -- NULL while the originating tx is in flight
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE admin_commands (
    command_id    text PRIMARY KEY,
    command_type  text NOT NULL,
    device_id     text,
    content_hash  bytea NOT NULL,
    response_code int NOT NULL,
    response      jsonb NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Fixed read views ----------------------------------------------------------
CREATE TABLE views (
    view_id         uuid PRIMARY KEY,
    device_id       text NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    high_watermark  bigint NOT NULL,
    -- furthest sequence any page of this view has delivered; compaction must
    -- not delete events this view may still need (initial: start-1).
    last_position   bigint NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL
);
CREATE INDEX views_device_idx ON views (device_id);

-- Checkpoints ---------------------------------------------------------------
CREATE TABLE checkpoints (
    device_id   text PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
    sequence    bigint NOT NULL,
    digest      text NOT NULL,
    signature   text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
