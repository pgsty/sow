# ADR-0027: Legacy package adoption admission and canonicalization

Status: accepted (2026-07-15)

## Context

M0 intentionally records the legacy serving tree without changing a byte. A
later content adoption has a stronger job: every package entering CAS and a
canonical view must be proved by both the immutable M0 manifest and repository
metadata. A full disposable copy of the Pigsty-v1 tree exposed several real
legacy conditions that synthetic flat-layout fixtures did not cover:

- unindexed DEB files and YUM primary entries whose RPM body is absent;
- normalized, index-proven MSSQL RPM hrefs below legacy hash directories;
- source RPM entries carried by binary leaves;
- Percona noarch bytes replicated in binary leaves as well as a distinct
  noarch leaf; and
- an explicit Debian epoch zero in Packages omitted by the equivalent DEB
  control version.

Importing earlier repositories before detecting a later orphan left only safe,
GC-visible CAS objects, but it was still an avoidable side effect and made a
failed migration expensive to diagnose.

## Decision

Legacy package adoption uses transaction-wide two-phase admission.

1. Before any CAS write, all selected APT/YUM metadata is streamed into a
   temporary SQLite spool. Per-repository transactions and indexed
   `(repo, canonical_path)` lookups keep this bounded and avoid per-entry
   commits or quadratic collision scans.
2. Every `.deb`, `.ddeb`, and `.rpm` in the selected M0 baseline must be named
   by an index with the same size and SHA-256. Every index entry must resolve to
   a regular baseline file. Producer errors are aggregated by repository; a
   structurally incomplete repository does not emit misleading orphan counts.
3. A normalized, safe, index-proven legacy RPM href may be flat, canonical, or
   nested. Its destination is always the frozen
   `Packages/<package-name-initial>/<basename>.rpm` layout. A source already
   under `Packages/` with the wrong bucket is malformed and fails rather than
   being silently repaired.
4. Multiple physical source paths may collapse to one canonical RPM only when
   format, size, SHA-256 and pool are identical. Different bytes fail during
   admission, before CAS. Every source-to-canonical alias remains in the legacy
   provenance ledger.
5. For `noarch_mode: separate`, index-proven noarch replicas from binary leaves
   converge on the one noarch target leaf. Legacy source RPM entries retain the
   binary leaf that indexed them; this is a migration rule and does not widen
   ordinary add/sync routing for new source packages.
6. DEB body and Packages versions use Debian version semantics. In particular,
   omitted epoch zero equals explicit `0:`; different non-zero epochs do not.
7. There is no general `--ignore-missing`, orphan force flag, or implicit
   metadata rebuild. Unindexed bodies remain explicit source-data blockers
   until the operator repairs or separately quarantines the source repository.
   An indexed YUM body that is absent from M0 may use only the later,
   audit-bound exact-set repair in
   [ADR-0030](0030-audit-bound-legacy-yum-missing-body-prune.md); default
   adoption still refuses it.

Only after the complete admission succeeds may bounded workers inspect package
bodies and import expected objects. Views and legacy receipts are then committed
atomically; a later body failure may leave content-addressed, unreferenced CAS
objects but cannot advance a ref.

## Consequences

- M0 remains possible and byte preserving even when the old repository is
  internally inconsistent; local fsck continues to audit that exact baseline.
- Valid legacy layout differences are migrated without weakening the final YUM
  URL contract or losing source-path evidence.
- Broken old indexes fail closed with repository/path evidence and zero CAS
  mutation during membership admission. The ADR-0030 exception requires an
  exact current set digest and records negative provenance rather than hiding
  the repair.
- Adoption parses metadata twice (admission, then body import). This is an
  intentional bounded-memory trade-off; SQLite batching and indexes prevent
  the safety pass from becoming an fsync or quadratic bottleneck.
