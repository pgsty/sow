ALTER TABLE dists ADD COLUMN effective_signing_json TEXT NOT NULL DEFAULT '{}'
    CHECK (length(effective_signing_json) BETWEEN 2 AND 16777216 AND json_valid(effective_signing_json));

-- Public package-signing certificates are retained independently of mutable
-- file/env/agent references.  This lets read-only check authenticate an
-- already-built immutable RPM after the private signing capability has been
-- removed or a desired key has been rotated.
CREATE TABLE rpm_signing_keys (
    fingerprint TEXT PRIMARY KEY CHECK (
        (length(fingerprint) = 40 OR length(fingerprint) = 64)
        AND fingerprint = upper(fingerprint)
        AND fingerprint NOT GLOB '*[^0-9A-F]*'
    ),
    public_key BLOB NOT NULL CHECK (length(public_key) BETWEEN 1 AND 16777216)
);

PRAGMA user_version = 5;
