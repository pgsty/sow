-- Private target-scoped publication state. No table here is projected into a
-- Repository public root; Generation remains the fixed-width decimal TEXT
-- domain introduced by schema v7.

-- Durable high-water witness for wall-clock decisions.  Publication and
-- target maintenance advance this row before any remote mutation and reject a
-- clock that moves behind previously observed Repository time.
CREATE TABLE repository_time_witness (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    max_observed_at TEXT NOT NULL
) WITHOUT ROWID;

INSERT INTO repository_time_witness(singleton, max_observed_at)
SELECT 1, COALESCE(MAX(applied_at), '1970-01-01T00:00:00Z') FROM schema_migrations;

CREATE TABLE publication_target_bindings (
    target_identity TEXT PRIMARY KEY CHECK (
        length(target_identity) = 64 AND target_identity = lower(target_identity)
        AND target_identity NOT GLOB '*[^0-9a-f]*'
    ),
    target_storage_id TEXT NOT NULL CHECK (
        length(target_storage_id) = 64 AND target_storage_id = lower(target_storage_id)
        AND target_storage_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_id TEXT NOT NULL CHECK (length(repository_id) = 36),
    target_name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL CHECK (provider IN ('filesystem', 'r2')),
    endpoint TEXT NOT NULL,
    region TEXT NOT NULL,
    bucket TEXT NOT NULL,
    prefix TEXT NOT NULL,
    public_endpoint TEXT NOT NULL,
    max_cache_ttl_ns INTEGER NOT NULL CHECK (max_cache_ttl_ns >= 0),
    authoritative_workspace INTEGER NOT NULL CHECK (authoritative_workspace = 1),
    single_writer INTEGER NOT NULL CHECK (single_writer = 1),
    exclusive_write_authority INTEGER NOT NULL CHECK (exclusive_write_authority = 1),
    config_identity TEXT NOT NULL CHECK (
        length(config_identity) = 64 AND config_identity = lower(config_identity)
        AND config_identity NOT GLOB '*[^0-9a-f]*'
    ),
    bound_at TEXT NOT NULL,
    UNIQUE (target_storage_id, prefix)
) WITHOUT ROWID;

CREATE INDEX publication_target_storage_idx
ON publication_target_bindings(target_storage_id, prefix);

CREATE TABLE publication_target_heads (
    target_identity TEXT PRIMARY KEY REFERENCES publication_target_bindings(target_identity) ON DELETE RESTRICT,
    checkpoint_identity TEXT,
    generation TEXT NOT NULL DEFAULT '00000000000000000000' CHECK (
        length(generation) = 20 AND generation NOT GLOB '*[^0-9]*'
        AND generation <= '18446744073709551615'
    ),
    manifest_sha256 TEXT,
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    updated_at TEXT NOT NULL,
    CHECK ((checkpoint_identity IS NULL AND generation = '00000000000000000000' AND manifest_sha256 IS NULL)
        OR (checkpoint_identity IS NOT NULL AND generation > '00000000000000000000'
            AND length(checkpoint_identity) = 64 AND checkpoint_identity = lower(checkpoint_identity)
            AND checkpoint_identity NOT GLOB '*[^0-9a-f]*'
            AND length(manifest_sha256) = 64 AND manifest_sha256 = lower(manifest_sha256)
            AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'))
) WITHOUT ROWID;

CREATE TABLE publication_attempts (
    attempt_identity TEXT PRIMARY KEY CHECK (
        length(attempt_identity) = 64 AND attempt_identity = lower(attempt_identity)
        AND attempt_identity NOT GLOB '*[^0-9a-f]*'
    ),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    repository_id TEXT NOT NULL CHECK (length(repository_id) = 36),
    target_identity TEXT NOT NULL REFERENCES publication_target_bindings(target_identity) ON DELETE RESTRICT,
    base_checkpoint TEXT CHECK (base_checkpoint IS NULL OR (
        length(base_checkpoint) = 64 AND base_checkpoint = lower(base_checkpoint)
        AND base_checkpoint NOT GLOB '*[^0-9a-f]*'
    )),
    target_generation TEXT NOT NULL REFERENCES generations(generation) ON DELETE RESTRICT CHECK (
        length(target_generation) = 20 AND target_generation NOT GLOB '*[^0-9]*'
        AND target_generation > '00000000000000000000'
        AND target_generation <= '18446744073709551615'
    ),
    manifest_sha256 TEXT NOT NULL CHECK (
        length(manifest_sha256) = 64 AND manifest_sha256 = lower(manifest_sha256)
        AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    plan_sha256 TEXT NOT NULL CHECK (
        length(plan_sha256) = 64 AND plan_sha256 = lower(plan_sha256)
        AND plan_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    phase TEXT NOT NULL CHECK (phase IN (
        'planned', 'payload', 'immutable_metadata', 'pointer_prepared',
        'commit_intent', 'pointer_rollforward', 'verified', 'applied',
        'grace', 'deletion_verified', 'retained_reported', 'done', 'abandoned'
    )),
    commit_intent INTEGER NOT NULL CHECK (commit_intent IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (target_identity, target_generation, plan_sha256),
    CHECK ((phase IN ('planned', 'payload', 'immutable_metadata', 'pointer_prepared', 'abandoned') AND commit_intent = 0)
        OR (phase NOT IN ('planned', 'payload', 'immutable_metadata', 'pointer_prepared', 'abandoned') AND commit_intent = 1))
) WITHOUT ROWID;

CREATE UNIQUE INDEX publication_attempt_active_idx
ON publication_attempts(target_identity) WHERE phase IN (
    'planned', 'payload', 'immutable_metadata', 'pointer_prepared',
    'commit_intent', 'pointer_rollforward', 'verified', 'applied'
);

CREATE TABLE publication_attempt_views (
    attempt_identity TEXT NOT NULL REFERENCES publication_attempts(attempt_identity) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    view_id TEXT NOT NULL,
    pointer_path TEXT NOT NULL,
    old_identity TEXT,
    new_identity TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'prepared', 'applied', 'verified')),
    PRIMARY KEY (attempt_identity, view_id, pointer_path),
    UNIQUE (attempt_identity, sequence)
) WITHOUT ROWID;

-- Exact add-only objects left by a safely abandoned pre-commit attempt. They
-- are private target inventory evidence, not public control objects. Future
-- publication and maintenance must recognize these bytes rather than mistake
-- them for foreign writes; no payload copy is made here.
CREATE TABLE publication_abandoned_objects (
    attempt_identity TEXT NOT NULL REFERENCES publication_attempts(attempt_identity) ON DELETE CASCADE,
    path TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('payload', 'metadata')),
    size INTEGER NOT NULL CHECK (size >= 0),
    sha256 TEXT NOT NULL CHECK (
        length(sha256) = 64 AND sha256 = lower(sha256)
        AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    remote_identity TEXT NOT NULL CHECK (length(remote_identity) BETWEEN 1 AND 4096),
    PRIMARY KEY (attempt_identity, path)
) WITHOUT ROWID;

CREATE TABLE publication_checkpoints (
    checkpoint_identity TEXT PRIMARY KEY CHECK (
        length(checkpoint_identity) = 64 AND checkpoint_identity = lower(checkpoint_identity)
        AND checkpoint_identity NOT GLOB '*[^0-9a-f]*'
    ),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    repository_id TEXT NOT NULL CHECK (length(repository_id) = 36),
    target_identity TEXT NOT NULL REFERENCES publication_target_bindings(target_identity) ON DELETE RESTRICT,
    attempt_identity TEXT NOT NULL UNIQUE REFERENCES publication_attempts(attempt_identity) ON DELETE RESTRICT,
    generation TEXT NOT NULL REFERENCES generations(generation) ON DELETE RESTRICT CHECK (
        length(generation) = 20 AND generation NOT GLOB '*[^0-9]*'
        AND generation > '00000000000000000000'
        AND generation <= '18446744073709551615'
    ),
    manifest_sha256 TEXT NOT NULL CHECK (
        length(manifest_sha256) = 64 AND manifest_sha256 = lower(manifest_sha256)
        AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    inventory_identity TEXT NOT NULL CHECK (
        length(inventory_identity) = 64 AND inventory_identity = lower(inventory_identity)
        AND inventory_identity NOT GLOB '*[^0-9a-f]*'
    ),
    inventory_complete INTEGER NOT NULL CHECK (inventory_complete IN (0, 1)),
    applied_at TEXT NOT NULL,
    UNIQUE (target_identity, generation, manifest_sha256)
) WITHOUT ROWID;

CREATE TABLE publication_checkpoint_views (
    checkpoint_identity TEXT NOT NULL REFERENCES publication_checkpoints(checkpoint_identity) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    view_id TEXT NOT NULL,
    pointer_path TEXT NOT NULL,
    remote_identity TEXT NOT NULL,
    PRIMARY KEY (checkpoint_identity, view_id, pointer_path),
    UNIQUE (checkpoint_identity, sequence)
) WITHOUT ROWID;

CREATE TABLE publication_inventory (
    checkpoint_identity TEXT NOT NULL REFERENCES publication_checkpoints(checkpoint_identity) ON DELETE CASCADE,
    path TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('payload', 'metadata', 'pointer')),
    size INTEGER NOT NULL CHECK (size >= 0),
    sha256 TEXT NOT NULL CHECK (
        length(sha256) = 64 AND sha256 = lower(sha256)
        AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    remote_identity TEXT NOT NULL,
    PRIMARY KEY (checkpoint_identity, path)
) WITHOUT ROWID;

CREATE TABLE publication_grace_records (
    grace_identity TEXT PRIMARY KEY CHECK (
        length(grace_identity) = 64 AND grace_identity = lower(grace_identity)
        AND grace_identity NOT GLOB '*[^0-9a-f]*'
    ),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    target_identity TEXT NOT NULL REFERENCES publication_target_bindings(target_identity) ON DELETE RESTRICT,
    checkpoint_identity TEXT NOT NULL REFERENCES publication_checkpoints(checkpoint_identity) ON DELETE RESTRICT,
    verified_at TEXT NOT NULL,
    not_before TEXT NOT NULL,
    cache_policy_identity TEXT NOT NULL CHECK (
        length(cache_policy_identity) = 64 AND cache_policy_identity = lower(cache_policy_identity)
        AND cache_policy_identity NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('grace', 'deletion_verified', 'retained_reported')),
    UNIQUE (checkpoint_identity),
    CHECK (not_before >= verified_at)
) WITHOUT ROWID;

CREATE TABLE publication_candidate_reports (
    report_identity TEXT PRIMARY KEY CHECK (
        length(report_identity) = 64 AND report_identity = lower(report_identity)
        AND report_identity NOT GLOB '*[^0-9a-f]*'
    ),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    target_identity TEXT NOT NULL REFERENCES publication_target_bindings(target_identity) ON DELETE RESTRICT,
    checkpoint_identity TEXT NOT NULL REFERENCES publication_checkpoints(checkpoint_identity) ON DELETE RESTRICT,
    inventory_identity TEXT NOT NULL CHECK (
        length(inventory_identity) = 64 AND inventory_identity = lower(inventory_identity)
        AND inventory_identity NOT GLOB '*[^0-9a-f]*'
    ),
    mode TEXT NOT NULL CHECK (mode IN ('report_only', 'conditional_delete')),
    created_at TEXT NOT NULL,
    UNIQUE (target_identity, checkpoint_identity, inventory_identity)
) WITHOUT ROWID;

CREATE TABLE publication_candidates (
    report_identity TEXT NOT NULL REFERENCES publication_candidate_reports(report_identity) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    path TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('payload', 'metadata')),
    size INTEGER NOT NULL CHECK (size >= 0),
    sha256 TEXT NOT NULL CHECK (
        length(sha256) = 64 AND sha256 = lower(sha256)
        AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    remote_identity TEXT NOT NULL,
    PRIMARY KEY (report_identity, path),
    UNIQUE (report_identity, sequence)
) WITHOUT ROWID;

CREATE TABLE publication_deletion_receipts (
    receipt_identity TEXT PRIMARY KEY CHECK (
        length(receipt_identity) = 64 AND receipt_identity = lower(receipt_identity)
        AND receipt_identity NOT GLOB '*[^0-9a-f]*'
    ),
    report_identity TEXT NOT NULL REFERENCES publication_candidate_reports(report_identity) ON DELETE CASCADE,
    path TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('payload', 'metadata')),
    size INTEGER NOT NULL CHECK (size >= 0),
    sha256 TEXT NOT NULL CHECK (
        length(sha256) = 64 AND sha256 = lower(sha256)
        AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    remote_identity TEXT NOT NULL,
    storage_absent INTEGER NOT NULL CHECK (storage_absent = 1),
    public_absent INTEGER NOT NULL CHECK (public_absent = 1),
    observed_at TEXT NOT NULL,
    UNIQUE (report_identity, path)
) WITHOUT ROWID;

PRAGMA user_version = 8;
