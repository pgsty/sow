CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE repository_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    desired_revision INTEGER NOT NULL DEFAULT 0 CHECK (desired_revision >= 0),
    built_generation INTEGER NOT NULL DEFAULT 0 CHECK (built_generation >= 0),
    status TEXT NOT NULL DEFAULT 'clean' CHECK (status IN ('clean', 'dirty', 'recovering', 'error')),
    dirty_reason TEXT
);

INSERT INTO repository_state(singleton) VALUES (1);

CREATE TABLE dists (
    name TEXT PRIMARY KEY,
    format TEXT NOT NULL CHECK (format IN ('rpm', 'deb')),
    effective_config_sha256 TEXT NOT NULL,
    built_generation INTEGER NOT NULL CHECK (built_generation >= 0)
);

CREATE TABLE dist_architectures (
    dist_name TEXT NOT NULL REFERENCES dists(name) ON DELETE CASCADE,
    family TEXT NOT NULL CHECK (family IN ('x86_64', 'aarch64')),
    ecosystem_arch TEXT NOT NULL,
    built_generation INTEGER NOT NULL CHECK (built_generation >= 0),
    PRIMARY KEY (dist_name, family)
);

CREATE TABLE package_objects (
    sha256 TEXT PRIMARY KEY,
    format TEXT NOT NULL CHECK (format IN ('rpm', 'deb')),
    coordinate TEXT NOT NULL,
    architecture TEXT NOT NULL,
    pool_path TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL CHECK (size >= 0)
);

CREATE TABLE memberships (
    dist_name TEXT NOT NULL REFERENCES dists(name) ON DELETE CASCADE,
    package_sha256 TEXT NOT NULL REFERENCES package_objects(sha256) ON DELETE RESTRICT,
    PRIMARY KEY (dist_name, package_sha256)
);

CREATE TABLE operations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('planned', 'staged', 'applied', 'built', 'done', 'rolled_back', 'failed')),
    payload_json TEXT NOT NULL CHECK (length(payload_json) BETWEEN 1 AND 16777216),
    error_class TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX operations_active_idx ON operations(state)
WHERE state NOT IN ('done', 'rolled_back', 'failed');

PRAGMA user_version = 1;
