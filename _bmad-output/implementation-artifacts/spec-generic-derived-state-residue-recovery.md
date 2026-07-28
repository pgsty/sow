---
title: 'Inventory and recover unjournaled derived-state writer residue'
type: 'feature'
created: '2026-07-28'
status: 'done'
review_loop_iteration: 0
baseline_commit: '71dcb5d'
context:
  - '{project-root}/_bmad-output/implementation-artifacts/deferred-work.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-derived-state-residue-removal-identity.md'
  - '{project-root}/docs/adr/0041-preserved-projection-orphan-quarantine.md'
---

<frozen-after-approval reason="closes the accepted generic-scanner deferred item without widening payload deletion authority">

## Intent

**Problem:** A process death can leave a strict random write temporary before
the replacement intent is durable. Generated publication sources and package
completion receipts are outside the three specialized journal scanners, so
the residue is currently neither visible to L1/fsck nor recoverable by a
supported command.

**Approach:** Stream a bounded inventory over the exact SOW-owned control
surfaces, report strict temporary and replacement-transaction state at L1,
and let explicit recovery converge valid transactions before deleting only
unowned strict nonce-bearing temporaries through exact inode quarantine.

## Boundaries & Constraints

**Always:** Scan root control files, generated publication state and the three
derived writer journal directories; bind every directory and file without
following symlinks; recover transactions before orphan temporaries; re-scan
after mutation; keep memory bounded.

**Ask First:** Adding a new managed control surface or changing a canonical
destination so it could itself match the temporary grammar.

**Never:** Traverse canonical Git, cache, CAS, materialized/origin payloads,
sync/stage scratch or arbitrary repository content; delete a final projection
stage; treat malformed, aliased or unsafe state as recoverable; mutate during
ordinary fsck/verify.

## Acceptance

- Ordinary L1/fsck reports every valid strict residue and pending replacement
  transaction without changing bytes.
- `--recover` first replays valid durable replacement transactions, then
  removes only remaining exact private write/install/removal temporaries and
  proves a clean re-scan.
- Same-byte/path replacements, hardlinks, symlinks, malformed names,
  directory replacement and cardinality excess preserve evidence and fail.
- Canonical Git, payload and scratch subtrees are demonstrably outside the
  scanner.

</frozen-after-approval>

## Tasks

- [x] Implement bounded descriptor-bound managed-surface inventory.
- [x] Integrate L1/fsck reporting and explicit recovery.
- [x] Gate shared writers against unowned local residue and reserve ambiguous
  canonical destination names.
- [x] Add real-filesystem ordinary/race, fault, scope and replay tests.
- [x] Close ADR, deferred ledger, traceability and delivery evidence.

## Spec Change Log

- Review against the older V-75/V-77 contracts found that a bare 16-hex
  write name is the former predictable digest-derived coordinate, not a
  private namespace capability. ADR-0041 already requires such names to be
  visible failures. V-84 therefore reports and preserves them; only current
  128-bit random names, install isolation and random removal quarantine are
  auto-recoverable.
- The managed walk also inventories V-80's strict empty directory-stage and
  quarantine forms in root and nested generated directories. Recovery
  delegates to V-80 before file transactions. Its `.preserved-<nonce>`
  foreign-replacement evidence remains non-recoverable and blocks mutation.

## Design Notes

The recovery order is directory stages, durable file-replacement carriers,
then unowned random file temporaries, with a fresh bounded inventory between
each class and a final clean inventory. Non-recoverable legacy or preserved
evidence aborts before the first mutation. Directory and file deletion both
retain exact descriptors through no-replace quarantine and the final parent
durability barrier.

## Verification

Final source passed all 894 CLI tests in six exhaustive ordinary and race
shards, every non-CLI package ordinary/race, full static analysis, real local
apt 1.2/2.4 and YUM/DNF EL7/8/9/10 consumption, fixed MinIO S3, all 47 edge
contracts, four CGO-free platform builds, 50k scale gates and a read-only
91,649-package/106.327-GB scan. Exact commands, timings, memory and failure
boundaries are recorded in
`docs/evidence/2026-07-28-generic-derived-state-residue-recovery.md`.
No cloud or production write occurred.
