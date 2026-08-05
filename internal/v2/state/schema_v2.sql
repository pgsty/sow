ALTER TABLE dists ADD COLUMN desired_revision INTEGER NOT NULL DEFAULT 0 CHECK (desired_revision >= 0);
ALTER TABLE dists ADD COLUMN built_config_sha256 TEXT NOT NULL DEFAULT '';
UPDATE dists SET built_config_sha256 = effective_config_sha256;

ALTER TABLE package_objects ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE package_objects ADD COLUMN source TEXT NOT NULL DEFAULT '';
ALTER TABLE package_objects ADD COLUMN version TEXT NOT NULL DEFAULT '';
ALTER TABLE package_objects ADD COLUMN epoch TEXT NOT NULL DEFAULT '';
ALTER TABLE package_objects ADD COLUMN release TEXT NOT NULL DEFAULT '';
ALTER TABLE package_objects ADD COLUMN canonical_arch TEXT NOT NULL DEFAULT 'neutral' CHECK (canonical_arch IN ('x86_64', 'aarch64', 'neutral'));
ALTER TABLE package_objects ADD COLUMN kind TEXT NOT NULL DEFAULT 'main' CHECK (kind IN ('main', 'debuginfo', 'debugsource', 'llvmjit', 'dbgsym', 'dbg'));
ALTER TABLE package_objects ADD COLUMN filename TEXT NOT NULL DEFAULT '';
ALTER TABLE package_objects ADD COLUMN payload_sha256 TEXT;
ALTER TABLE package_objects ADD COLUMN signature_key TEXT;
ALTER TABLE package_objects ADD COLUMN warning TEXT;
ALTER TABLE package_objects ADD COLUMN storage TEXT NOT NULL DEFAULT 'pool' CHECK (storage IN ('pending', 'pool'));
ALTER TABLE package_objects ADD COLUMN created_revision INTEGER NOT NULL DEFAULT 0 CHECK (created_revision >= 0);

CREATE UNIQUE INDEX package_objects_coordinate_idx ON package_objects(format, coordinate);
CREATE INDEX package_objects_name_idx ON package_objects(name, canonical_arch, version);
CREATE INDEX package_objects_payload_idx ON package_objects(format, coordinate, payload_sha256)
WHERE payload_sha256 IS NOT NULL;

ALTER TABLE memberships ADD COLUMN created_revision INTEGER NOT NULL DEFAULT 0 CHECK (created_revision >= 0);

CREATE TABLE built_memberships (
    dist_name TEXT NOT NULL REFERENCES dists(name) ON DELETE CASCADE,
    package_sha256 TEXT NOT NULL REFERENCES package_objects(sha256) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    PRIMARY KEY (dist_name, package_sha256)
);

INSERT INTO built_memberships(dist_name, package_sha256, generation)
SELECT m.dist_name, m.package_sha256, d.built_generation
FROM memberships AS m
JOIN dists AS d ON d.name = m.dist_name;

ALTER TABLE operations RENAME TO operations_v1;

CREATE TABLE operations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('planned', 'staged', 'applied', 'built', 'done', 'done_dirty', 'recovering', 'rolled_back', 'failed')),
    payload_json TEXT NOT NULL CHECK (length(payload_json) BETWEEN 1 AND 16777216),
    result_json TEXT NOT NULL DEFAULT '{}' CHECK (length(result_json) BETWEEN 2 AND 16777216),
    error_class TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO operations(id, kind, state, payload_json, result_json, error_class, created_at, updated_at)
SELECT id, kind, state, payload_json, '{}', error_class, created_at, updated_at
FROM operations_v1;

DROP INDEX operations_active_idx;
DROP TABLE operations_v1;

CREATE INDEX operations_active_idx ON operations(state)
WHERE state NOT IN ('done', 'done_dirty', 'rolled_back', 'failed');
CREATE INDEX operations_created_idx ON operations(created_at DESC, id DESC);

CREATE TABLE operation_events (
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    state TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    occurred_at TEXT NOT NULL,
    PRIMARY KEY (operation_id, sequence)
);

CREATE TABLE operation_packages (
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    input_path TEXT NOT NULL,
    package_sha256 TEXT,
    coordinate TEXT,
    disposition TEXT NOT NULL CHECK (disposition IN ('accepted', 'reused', 'excluded', 'failed', 'removed')),
    error_class TEXT,
    message TEXT,
    PRIMARY KEY (operation_id, sequence)
);

CREATE TABLE operation_memberships (
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    dist_name TEXT NOT NULL,
    package_sha256 TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('add', 'remove', 'keep', 'exclude', 'limit')),
    PRIMARY KEY (operation_id, sequence)
);

CREATE TABLE operation_files (
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    action TEXT NOT NULL CHECK (action IN ('add', 'update', 'delete')),
    phase TEXT NOT NULL CHECK (phase IN ('payload', 'metadata', 'pointer', 'delete')),
    path TEXT NOT NULL,
    size INTEGER CHECK (size IS NULL OR size >= 0),
    sha256 TEXT,
    PRIMARY KEY (operation_id, sequence)
);

CREATE TABLE generations (
    generation INTEGER PRIMARY KEY CHECK (generation > 0),
    previous_generation INTEGER NOT NULL CHECK (previous_generation >= 0),
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    manifest_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE generation_files (
    generation INTEGER NOT NULL REFERENCES generations(generation) ON DELETE CASCADE,
    path TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('payload', 'metadata', 'pointer')),
    size INTEGER NOT NULL CHECK (size >= 0),
    sha256 TEXT NOT NULL,
    PRIMARY KEY (generation, path)
);

CREATE INDEX generation_files_path_idx ON generation_files(path, generation);

PRAGMA user_version = 2;
