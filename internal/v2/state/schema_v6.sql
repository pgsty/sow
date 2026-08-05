-- A primary OpenPGP fingerprint is an identity, not a certificate version.
-- Renewals can add signing subkeys, bindings, expiry extensions, or revocation
-- evidence without changing that fingerprint. Retain every exact public-only
-- certificate snapshot so a Built Generation can name the verifier bytes it
-- used instead of silently drifting to a later version of the same identity.
ALTER TABLE rpm_signing_keys RENAME TO rpm_signing_keys_v5;

CREATE TABLE rpm_signing_keys (
    fingerprint TEXT NOT NULL CHECK (
        (length(fingerprint) = 40 OR length(fingerprint) = 64)
        AND fingerprint = upper(fingerprint)
        AND fingerprint NOT GLOB '*[^0-9A-F]*'
    ),
    public_key BLOB NOT NULL CHECK (length(public_key) BETWEEN 1 AND 16777216),
    PRIMARY KEY (fingerprint, public_key)
) WITHOUT ROWID;

INSERT INTO rpm_signing_keys(fingerprint, public_key)
SELECT fingerprint, public_key FROM rpm_signing_keys_v5;

DROP TABLE rpm_signing_keys_v5;

PRAGMA user_version = 6;
