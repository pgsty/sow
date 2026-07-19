# ADR-0030: Audit-bound repair of legacy YUM indexes with missing bodies

Status: accepted
Date: 2026-07-16
Scope: zero-byte legacy adoption and YUM source-data repair

## Context

The full disposable Pigsty-v1 copy contains 30,274 YUM primary entries across
53 repository owners whose referenced RPM body is absent from the M0 serving
baseline. The entries represent 30,228 unique SHA-256 objects and
42,600,579,672 unique referenced bytes. Exact bodies should be restored first:
an official PGDG archive sample matched the recorded size and SHA-256, while
some historical testing RPMs are no longer present in either the official
current tree or archive.

Silently ignoring these entries would turn inconsistent historical metadata
into an unexplained data loss decision. Requiring an impossible byte recovery
for every removed upstream testing build would also make a coherent repaired
repository impossible. The product owner authorized SOW to recover or repair
missing packages with an explicit explanation on 2026-07-16.

## Decision

1. Default `init --adopt-content` continues to reject every YUM primary entry
   whose exact size/SHA-256 body is absent from the M0 baseline. It prints the
   complete, deterministically sorted blocker inventory and a SHA-256 over the
   exact blocker identities.
2. Exact body recovery from an approved upstream/current archive is preferred.
   A recovered body enters the disposable serving copy only after its size and
   SHA-256 match the primary entry. Neither SOW nor the migration helper may
   overwrite an existing path.
3. A reviewed remainder may be omitted only by rerunning with
   `--adopt-prune-missing-yum-confirm <sha256>`, where the value exactly matches
   the blocker-set digest from the current preflight. A stale, malformed,
   empty, or otherwise different set fails before CAS/view mutation.
4. The exception applies only to a YUM entry proved by repomd/primary whose
   body is absent from M0. It never admits or discards a body that M0 contains
   but no index proves; APT/YUM unindexed bodies still require explicit config
   quarantine or a source-index repair.
5. Adoption parses the selected indexes again during import. Every confirmed
   missing entry must be re-observed byte-for-byte, and no unreviewed missing
   entry may appear. Index drift between the two parses fails; any prior CAS
   writes remain unreachable objects and no canonical ref advances.
6. Each accepted omission is committed atomically as strict, sorted negative
   provenance at `provenance/legacy-pruned/<repo>.jsonl`. A receipt binds the
   repo/path/package identity, expected size/SHA-256, reason, confirmation-set
   digest and original baseline commit. Replay preserves the first immutable
   ledger and succeeds only when its identities still match the reviewed set.
   Every canonical mutation admission and `fsck` revalidates the complete Git
   history: once introduced, each ledger must remain present and byte-identical
   at HEAD; its baseline commit must be an ancestor of both HEAD and the
   repository's current canonical ref; its commit time must match the receipt;
   each claimed body must be absent from that baseline manifest; and all
   per-repo ledgers must recompute to the recorded cross-repo confirmation
   digest.
7. Adoption still reports `serving_tree_rewritten=false`. It does not edit the
   old primary metadata. A later explicit `materialize` creates and signs a new
   coherent YUM generation from the adopted intersection, including a valid
   zero-package repository when every stale entry was omitted.

This is the sole narrow exception to ADR-0027's default missing-body refusal;
there is no general `--ignore-missing`, force flag, or implicit rebuild.

## Consequences

- The operator must retain the exact private TSV named by the bounded default
  error (`.sow/reports/legacy-adoption-blockers-<sha256>.tsv`) and review the
  complete set, not only the at-most-20 inline preview. The report hash protects
  the complete diagnostic file; the separate confirmation digest binds only
  the sorted `indexed-body-missing` identities and remains an authorization
  boundary, not a convenience checksum.
- Recovery and omission can be mixed: restore every exact object still
  available, rerun preflight, then confirm only the smaller unavailable set.
- Historical serving bytes remain untouched until an explicit candidate
  materialization/cutover. Negative provenance explains every removed primary
  entry without falsely claiming the missing artifact was inspected.
- The mechanism does not by itself close the full Pigsty migration: the
  disposable copy still needs recovery execution, current-source replay,
  signed candidate validation and the separately authorized cutover.

## Evidence

- `TestInitAdoptContentPrunesMissingYUMOnlyWithExactAuditedSet` covers default
  rejection, wrong digest, between-pass drift, exact confirmation, zero CAS
  mutation, strict negative provenance, idempotent replay, signed empty YUM
  materialization, local fsck, and fail-closed historical ledger deletion and
  replacement.
- `TestLegacyIndexPruneReceiptIsStrictAndSorted` covers the receipt codec and
  ordered-ledger contract, including delimiter-bearing identity rejection.
- [Full-copy adoption evidence](../evidence/2026-07-16-legacy-tree-full-adoption-copy.md)
  records the real blocker inventory and disposable-copy boundary.
