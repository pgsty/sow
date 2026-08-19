-- Repository status is a projection of Desired membership, Built membership,
-- and effective versus Built Dist configuration.  v0.3 Dist lifecycle writes
-- could incorrectly force this row clean while another Dist remained dirty.
-- Recompute the disposable status fields during the explicit schema upgrade so
-- an affected database can pass semantic validation and resume ordinary build.
UPDATE repository_state
SET status = 'clean', dirty_reason = NULL
WHERE singleton = 1;

UPDATE repository_state
SET status = 'dirty',
    dirty_reason = 'one or more dists differ from their built projections'
WHERE singleton = 1 AND EXISTS (
    SELECT 1 FROM dists AS d
    WHERE d.effective_config_sha256 != d.built_config_sha256
       OR EXISTS (SELECT package_sha256 FROM memberships WHERE dist_name = d.name
                  EXCEPT SELECT package_sha256 FROM built_memberships WHERE dist_name = d.name)
       OR EXISTS (SELECT package_sha256 FROM built_memberships WHERE dist_name = d.name
                  EXCEPT SELECT package_sha256 FROM memberships WHERE dist_name = d.name)
);

-- A v0.3 attempt could be abandoned, resurrected, and stopped again while its
-- first abandoned-object evidence rows remained attached to the now-active
-- attempt.  Active recovery already proves every remote object against the
-- old/new Generation closure, so stale abandoned evidence is neither needed
-- nor semantically valid once the attempt is no longer abandoned.
DELETE FROM publication_abandoned_objects
WHERE attempt_identity IN (
    SELECT attempt_identity FROM publication_attempts WHERE phase != 'abandoned'
);

-- v0.3 wrote signer rows only for build Generations.  A signed Dist created by
-- init/dist-new therefore has a signed historical manifest but no retained key
-- until its first build.  If that view changed before a later proven signer
-- row, the exact historical identity cannot be reconstructed soundly.  Keep
-- exact manifest coverage while representing that uncertainty explicitly;
-- trust consumers and every forward-propagation path reject this sentinel.
CREATE TABLE generation_view_signers_v11 (
    generation TEXT NOT NULL REFERENCES generations(generation) ON DELETE CASCADE,
    view_id TEXT NOT NULL,
    signer_identity TEXT NOT NULL CHECK (
        signer_identity IN ('none', 'unverified') OR (
            length(signer_identity) = 64
            AND signer_identity = lower(signer_identity)
            AND signer_identity NOT GLOB '*[^0-9a-f]*'
        )
    ),
    trusted_public_key BLOB CHECK (
        (signer_identity IN ('none', 'unverified') AND trusted_public_key IS NULL)
        OR (signer_identity NOT IN ('none', 'unverified') AND length(trusted_public_key) BETWEEN 1 AND 16777216)
    ),
    PRIMARY KEY (generation, view_id)
) WITHOUT ROWID;

INSERT INTO generation_view_signers_v11(generation, view_id, signer_identity, trusted_public_key)
SELECT generation, view_id, signer_identity, trusted_public_key
FROM generation_view_signers;

DROP TABLE generation_view_signers;
ALTER TABLE generation_view_signers_v11 RENAME TO generation_view_signers;

PRAGMA user_version = 11;
