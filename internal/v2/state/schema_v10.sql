-- Package render facts are a rebuildable cache keyed by immutable object
-- digest.  They are deliberately separate from package_objects: operation
-- recovery and repository truth never depend on a cache row being present.
-- The optional fingerprint binds cached facts to one current Pool inode; all
-- fields are either present together or absent together.
CREATE TABLE package_facts (
    package_sha256 TEXT PRIMARY KEY REFERENCES package_objects(sha256) ON DELETE CASCADE,
    fact_schema TEXT NOT NULL CHECK (length(fact_schema) BETWEEN 1 AND 128),
    facts BLOB NOT NULL CHECK (length(facts) BETWEEN 2 AND 67108864),
    facts_sha256 TEXT NOT NULL CHECK (length(facts_sha256) = 64 AND facts_sha256 NOT GLOB '*[^0-9a-f]*'),
    device TEXT,
    inode TEXT,
    size INTEGER CHECK (size IS NULL OR size >= 0),
    mtime_ns INTEGER,
    ctime_ns INTEGER,
    CHECK (
        (device IS NULL AND inode IS NULL AND size IS NULL AND mtime_ns IS NULL AND ctime_ns IS NULL) OR
        (device IS NOT NULL AND device <> '' AND device NOT GLOB '*[^0-9]*' AND
         inode IS NOT NULL AND inode <> '' AND inode NOT GLOB '*[^0-9]*' AND
         size IS NOT NULL AND mtime_ns IS NOT NULL AND ctime_ns IS NOT NULL)
    )
);

PRAGMA user_version = 10;
