-- Generation identity is a fixed-width decimal TEXT domain.  SQLite INTEGER
-- is signed and therefore cannot represent the complete uint64 GenerationID.
-- Rebuild every generation-bearing relation together so foreign-key identity
-- never observes a mixed domain.
PRAGMA defer_foreign_keys = ON;

CREATE TABLE repository_state_v7 (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    desired_revision INTEGER NOT NULL DEFAULT 0 CHECK (desired_revision >= 0),
    built_generation TEXT NOT NULL DEFAULT '00000000000000000000' CHECK (
		length(built_generation) = 20
		AND built_generation NOT GLOB '*[^0-9]*'
		AND built_generation <= '18446744073709551615'
    ),
    status TEXT NOT NULL DEFAULT 'clean' CHECK (status IN ('clean', 'dirty', 'recovering', 'error')),
    dirty_reason TEXT,
    repository_id TEXT NOT NULL CHECK (
        length(repository_id) = 36
        AND repository_id = lower(repository_id)
        AND substr(repository_id, 9, 1) = '-'
        AND substr(repository_id, 14, 1) = '-'
        AND substr(repository_id, 15, 1) = '4'
        AND substr(repository_id, 19, 1) = '-'
        AND substr(repository_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(repository_id, 24, 1) = '-'
        AND length(replace(repository_id, '-', '')) = 32
        AND replace(repository_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    layout_version TEXT NOT NULL CHECK (layout_version IN ('c2-v1', 'c2-to-single-v1', 'single-payload-v1')),
    transition_receipt_sha256 TEXT CHECK (
        transition_receipt_sha256 IS NULL OR (
            length(transition_receipt_sha256) = 64
            AND transition_receipt_sha256 = lower(transition_receipt_sha256)
            AND transition_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    CHECK (layout_version = 'single-payload-v1' OR transition_receipt_sha256 IS NULL)
);

INSERT INTO repository_state_v7(
    singleton, desired_revision, built_generation, status, dirty_reason,
    repository_id, layout_version, transition_receipt_sha256
)
SELECT singleton, desired_revision, printf('%020d', built_generation), status, dirty_reason,
       lower(
           hex(randomblob(4)) || '-' ||
           hex(randomblob(2)) || '-4' || substr(hex(randomblob(2)), 2, 3) || '-' ||
		   substr('89ab', (random() & 3) + 1, 1) || substr(hex(randomblob(2)), 2, 3) || '-' ||
           hex(randomblob(6))
       ),
       'c2-to-single-v1', NULL
FROM repository_state;

-- Private forward-only migration control.  The public journal remains frozen
-- at sow/transition/c2-to-single/v1; commit authority and the exact grace
-- deadline live in SQLite so editing journal time cannot authorize deletion.
CREATE TABLE layout_transition_control (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    repository_id TEXT NOT NULL CHECK (
        length(repository_id) = 36
        AND repository_id = lower(repository_id)
        AND substr(repository_id, 9, 1) = '-'
        AND substr(repository_id, 14, 1) = '-'
        AND substr(repository_id, 15, 1) = '4'
        AND substr(repository_id, 19, 1) = '-'
        AND substr(repository_id, 20, 1) IN ('8', '9', 'a', 'b')
        AND substr(repository_id, 24, 1) = '-'
        AND length(replace(repository_id, '-', '')) = 32
        AND replace(repository_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    base_generation TEXT NOT NULL CHECK (
        length(base_generation) = 20
        AND base_generation NOT GLOB '*[^0-9]*'
        AND base_generation <= '18446744073709551615'
    ),
    target_manifest_sha256 TEXT NOT NULL CHECK (
        length(target_manifest_sha256) = 64
        AND target_manifest_sha256 = lower(target_manifest_sha256)
        AND target_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    plan_identity_sha256 TEXT NOT NULL CHECK (
        length(plan_identity_sha256) = 64
        AND plan_identity_sha256 = lower(plan_identity_sha256)
        AND plan_identity_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    planned_at TEXT NOT NULL,
    commit_intent_at TEXT,
    not_before TEXT,
    CHECK ((commit_intent_at IS NULL AND not_before IS NULL)
        OR (commit_intent_at IS NOT NULL AND not_before IS NOT NULL))
) WITHOUT ROWID;

CREATE TABLE dists_v7 (
    name TEXT PRIMARY KEY,
    format TEXT NOT NULL CHECK (format IN ('rpm', 'deb')),
    effective_config_sha256 TEXT NOT NULL,
    built_generation TEXT NOT NULL CHECK (
		length(built_generation) = 20
		AND built_generation NOT GLOB '*[^0-9]*'
		AND built_generation <= '18446744073709551615'
    ),
    desired_revision INTEGER NOT NULL DEFAULT 0 CHECK (desired_revision >= 0),
    built_config_sha256 TEXT NOT NULL DEFAULT '',
    effective_signing_json TEXT NOT NULL DEFAULT '{}'
        CHECK (length(effective_signing_json) BETWEEN 2 AND 16777216 AND json_valid(effective_signing_json))
);

INSERT INTO dists_v7(name, format, effective_config_sha256, built_generation, desired_revision, built_config_sha256, effective_signing_json)
SELECT name, format, effective_config_sha256, printf('%020d', built_generation), desired_revision, built_config_sha256, effective_signing_json
FROM dists;

CREATE TABLE dist_architectures_v7 (
    dist_name TEXT NOT NULL REFERENCES dists_v7(name) ON DELETE CASCADE,
    family TEXT NOT NULL CHECK (family IN ('x86_64', 'aarch64')),
    ecosystem_arch TEXT NOT NULL,
    built_generation TEXT NOT NULL CHECK (
		length(built_generation) = 20
		AND built_generation NOT GLOB '*[^0-9]*'
		AND built_generation <= '18446744073709551615'
    ),
    PRIMARY KEY (dist_name, family)
);

INSERT INTO dist_architectures_v7(dist_name, family, ecosystem_arch, built_generation)
SELECT dist_name, family, ecosystem_arch, printf('%020d', built_generation)
FROM dist_architectures;

CREATE TABLE memberships_v7 (
    dist_name TEXT NOT NULL REFERENCES dists_v7(name) ON DELETE CASCADE,
    package_sha256 TEXT NOT NULL REFERENCES package_objects(sha256) ON DELETE RESTRICT,
    created_revision INTEGER NOT NULL DEFAULT 0 CHECK (created_revision >= 0),
    PRIMARY KEY (dist_name, package_sha256)
);

INSERT INTO memberships_v7(dist_name, package_sha256, created_revision)
SELECT dist_name, package_sha256, created_revision FROM memberships;

CREATE TABLE built_memberships_v7 (
    dist_name TEXT NOT NULL REFERENCES dists_v7(name) ON DELETE CASCADE,
    package_sha256 TEXT NOT NULL REFERENCES package_objects(sha256) ON DELETE RESTRICT,
    generation TEXT NOT NULL CHECK (
		length(generation) = 20
		AND generation NOT GLOB '*[^0-9]*'
		AND generation <= '18446744073709551615'
    ),
    PRIMARY KEY (dist_name, package_sha256)
);

INSERT INTO built_memberships_v7(dist_name, package_sha256, generation)
SELECT dist_name, package_sha256, printf('%020d', generation) FROM built_memberships;

CREATE TABLE prior_built_memberships_v7 (
    dist_name TEXT NOT NULL REFERENCES dists_v7(name) ON DELETE CASCADE,
    package_sha256 TEXT NOT NULL REFERENCES package_objects(sha256) ON DELETE RESTRICT,
    generation TEXT NOT NULL CHECK (
		length(generation) = 20
		AND generation NOT GLOB '*[^0-9]*'
		AND generation <= '18446744073709551615'
    ),
    PRIMARY KEY (dist_name, package_sha256)
);

INSERT INTO prior_built_memberships_v7(dist_name, package_sha256, generation)
SELECT dist_name, package_sha256, printf('%020d', generation) FROM prior_built_memberships;

CREATE TABLE dist_metadata_signers_v7 (
    dist_name TEXT PRIMARY KEY REFERENCES dists_v7(name) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL CHECK (
        (length(fingerprint) = 40 OR length(fingerprint) = 64)
        AND fingerprint = upper(fingerprint)
        AND fingerprint NOT GLOB '*[^0-9A-F]*'
    ),
    public_key BLOB NOT NULL CHECK (length(public_key) BETWEEN 1 AND 16777216)
);

INSERT INTO dist_metadata_signers_v7(dist_name, fingerprint, public_key)
SELECT dist_name, fingerprint, public_key FROM dist_metadata_signers;

CREATE TABLE generations_v7 (
    generation TEXT PRIMARY KEY CHECK (
        length(generation) = 20
		AND generation NOT GLOB '*[^0-9]*'
		AND generation > '00000000000000000000'
		AND generation <= '18446744073709551615'
    ),
    previous_generation TEXT NOT NULL CHECK (
		length(previous_generation) = 20
		AND previous_generation NOT GLOB '*[^0-9]*'
		AND previous_generation <= '18446744073709551615'
    ),
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
    manifest_sha256 TEXT NOT NULL,
    renderer_identity TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000' CHECK (
        length(renderer_identity) = 64
        AND renderer_identity = lower(renderer_identity)
        AND renderer_identity NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL
);

INSERT INTO generations_v7(generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at)
SELECT printf('%020d', generation), printf('%020d', previous_generation), operation_id, manifest_sha256,
       '0000000000000000000000000000000000000000000000000000000000000000', created_at
FROM generations;

CREATE TABLE generation_files_v7 (
    generation TEXT NOT NULL REFERENCES generations_v7(generation) ON DELETE CASCADE,
    path TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('payload', 'metadata', 'pointer')),
    size INTEGER NOT NULL CHECK (size >= 0),
    sha256 TEXT NOT NULL,
    PRIMARY KEY (generation, path)
);

INSERT INTO generation_files_v7(generation, path, phase, size, sha256)
SELECT printf('%020d', generation), path, phase, size, sha256 FROM generation_files;

-- Immutable per-Generation view signing identity.  The signing subsystem owns
-- the identity bytes; retained/export consumers only read this frozen record.
CREATE TABLE generation_view_signers (
    generation TEXT NOT NULL REFERENCES generations_v7(generation) ON DELETE CASCADE,
    view_id TEXT NOT NULL,
    signer_identity TEXT NOT NULL CHECK (
        signer_identity = 'none' OR (
            length(signer_identity) = 64
            AND signer_identity = lower(signer_identity)
            AND signer_identity NOT GLOB '*[^0-9a-f]*'
        )
    ),
    trusted_public_key BLOB CHECK (
        (signer_identity = 'none' AND trusted_public_key IS NULL)
        OR (signer_identity != 'none' AND length(trusted_public_key) BETWEEN 1 AND 16777216)
    ),
    PRIMARY KEY (generation, view_id)
) WITHOUT ROWID;

DROP TABLE generation_files;
DROP TABLE generations;
DROP TABLE dist_metadata_signers;
DROP TABLE prior_built_memberships;
DROP TABLE built_memberships;
DROP TABLE memberships;
DROP TABLE dist_architectures;
DROP TABLE dists;
DROP TABLE repository_state;

ALTER TABLE repository_state_v7 RENAME TO repository_state;
ALTER TABLE dists_v7 RENAME TO dists;
ALTER TABLE dist_architectures_v7 RENAME TO dist_architectures;
ALTER TABLE memberships_v7 RENAME TO memberships;
ALTER TABLE built_memberships_v7 RENAME TO built_memberships;
ALTER TABLE prior_built_memberships_v7 RENAME TO prior_built_memberships;
ALTER TABLE dist_metadata_signers_v7 RENAME TO dist_metadata_signers;
ALTER TABLE generations_v7 RENAME TO generations;
ALTER TABLE generation_files_v7 RENAME TO generation_files;

CREATE INDEX generation_files_path_idx ON generation_files(path, generation);

PRAGMA user_version = 7;
