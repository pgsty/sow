# ADR-0031: Legacy Pro gated activation and checksum repair

Status: Accepted (2026-07-17)

## Context

The Pigsty-v1 source tree contains 15 large Pro TGZ files plus a zero-byte
`pro/checksums`. The migration fixture previously represented the same physical
`pro/` directory twice: an inactive inventory carrier at `path: pro` and an
inactive future owner at `path: gated/pro`. That shape could inventory bytes but
could not perform a zero-copy activation, because SOW rejects overlapping repo
ownership and adoption requires each source under its configured physical path.

Publishing the zero-byte checksum object is also invalid. Remote fsck
deliberately treats a checksum-shaped key with size zero as drift even when it
appears in the expected inventory. Silently removing the URL would lose the
useful compatibility key, while changing the production source would violate
the read-only migration boundary.

## Decision

1. Remove `asset-legacy-pro-inventory` after exact-copy review and activate
   `asset-pro-gated` directly at physical `path: pro`.
2. Preserve the already-frozen remote ownership root `public_path: gated/pro`,
   gated default pool, and stable-only confidentiality closure. The final owner
   declares both `cf` and `cos`; this is configuration intent, not a claim that
   either production target has been migrated.
3. Add `exclude: [checksums]` so the immutable zero-byte source remains
   untouched and outside the source baseline.
4. Bind the 15 archive names and SHA-256 values in
   `docs/migration/fixtures/pro-v4.4.0-checksums.sha256`. After exact stable
   adoption, inject that 1,479-byte file through ordinary
   `sow add --repo asset-pro-gated --dest checksums`. It therefore receives the
   same CAS, canonical Git, gated-view, materialization, fsck, GC, recovery, and
   publish semantics as every other asset.
5. Confidentiality admission for legacy adoption is transaction-wide and runs
   before any CAS object write. A gated→latest rejection must leave zero CAS
   objects, including when an earlier selected repository is otherwise valid.

The resulting local Basic fallback route is
`/pro/v1/basic/gated/pro/`, backed by `.sow/origin/gated/pro/`, with
`private, no-store`, Basic Auth, and a catch-all deny. Token routes use the same
relative `gated/pro/` ownership below the fixed `/pro/v1/{token}/` prefix.

## Consequences

- Production source bytes remain unchanged; `pro/checksums` stays zero bytes in
  the legacy tree while the canonical stable view carries a verified non-empty
  replacement.
- Stable adoption is zero-copy with respect to the source layout. No physical
  `pro`→`gated/pro` rebase is needed.
- Remote fsck cannot be made dirty by the known zero-byte checksum key in a new
  publication.
- Before production cutover, rollback is configuration-only: restore the
  inactive inventory carrier and remove the active owner from the candidate
  config. No production source or cloud object was mutated by acceptance.
- The historical standalone Pro bucket design remains superseded by ADR-0007.
  The Cloudflare bucket named `pro` and `pro.pigsty.io` were not used and are
  not evidence for this decision. Their later exact owner-designated test-only
  admission is governed independently by ADR-0032 and does not revive the
  standalone Pro-bucket design.

## Evidence

See `docs/evidence/2026-07-17-gated-pro-exact-copy-adoption.md` for the exact
source hash vector, negative confidentiality run, stable adoption, deterministic
checksum add, replay, archive traversal, materialization, L1, fsck, GC, and
Nginx route output.
