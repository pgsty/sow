-- Every publication target binding mutation is retained as an immutable audit
-- revision.  The mutable binding row remains the efficient current projection;
-- these rows are the append-only evidence that explains how it got there.
CREATE TABLE publication_target_binding_revisions (
    target_identity TEXT NOT NULL REFERENCES publication_target_bindings(target_identity) ON DELETE RESTRICT CHECK (
        length(target_identity) = 64 AND target_identity = lower(target_identity)
        AND target_identity NOT GLOB '*[^0-9a-f]*'
    ),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    target_storage_id TEXT NOT NULL CHECK (
        length(target_storage_id) = 64 AND target_storage_id = lower(target_storage_id)
        AND target_storage_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_id TEXT NOT NULL CHECK (length(repository_id) = 36),
    target_name TEXT NOT NULL,
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
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 256),
    operator_confirmed INTEGER NOT NULL CHECK (operator_confirmed IN (0, 1)),
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (target_identity, revision)
) WITHOUT ROWID;

INSERT INTO publication_target_binding_revisions(
    target_identity, revision, target_storage_id, repository_id, target_name,
    provider, endpoint, region, bucket, prefix, public_endpoint,
    max_cache_ttl_ns, authoritative_workspace, single_writer,
    exclusive_write_authority, config_identity, reason, operator_confirmed,
    recorded_at
)
SELECT target_identity, 1, target_storage_id, repository_id, target_name,
       provider, endpoint, region, bucket, prefix, public_endpoint,
       max_cache_ttl_ns, authoritative_workspace, single_writer,
       exclusive_write_authority, config_identity, 'backfill', 0, bound_at
FROM publication_target_bindings
ORDER BY target_identity;

CREATE TRIGGER publication_target_binding_revisions_update_guard
BEFORE UPDATE ON publication_target_binding_revisions
BEGIN
    SELECT RAISE(ABORT, 'publication target binding revisions are append-only');
END;

CREATE TRIGGER publication_target_binding_revisions_delete_guard
BEFORE DELETE ON publication_target_binding_revisions
BEGIN
    SELECT RAISE(ABORT, 'publication target binding revisions are append-only');
END;

PRAGMA user_version = 12;
