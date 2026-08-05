CREATE TABLE dist_metadata_signers (
    dist_name TEXT PRIMARY KEY REFERENCES dists(name) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL CHECK (
        (length(fingerprint) = 40 OR length(fingerprint) = 64)
        AND fingerprint = upper(fingerprint)
        AND fingerprint NOT GLOB '*[^0-9A-F]*'
    ),
    public_key BLOB NOT NULL CHECK (length(public_key) BETWEEN 1 AND 16777216)
);

-- C2 keeps exactly one prior Built Membership projection so clients that
-- fetched the immediately preceding repomd.xml can still reach its package
-- aliases.  This is deliberately per Dist; it must never become a
-- repository-wide alias set.
CREATE TABLE prior_built_memberships (
    dist_name TEXT NOT NULL REFERENCES dists(name) ON DELETE CASCADE,
    package_sha256 TEXT NOT NULL REFERENCES package_objects(sha256) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    PRIMARY KEY (dist_name, package_sha256)
);

PRAGMA user_version = 3;
