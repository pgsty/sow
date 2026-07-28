---
title: 'Inventory and explicitly retire preserved projection audit quarantines'
type: 'feature'
created: '2026-07-28'
status: 'done'
review_loop_iteration: 1
baseline_commit: 'ac53577'
context:
  - '{project-root}/_bmad-output/implementation-artifacts/deferred-work.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-projection-stage-install-rollback-identity.md'
  - '{project-root}/docs/adr/0041-preserved-projection-orphan-quarantine.md'
---

<frozen-after-approval reason="derived directly from accepted ADR-0041 and its deferred operational closure">

## Intent

**Problem:** Recovery safely preserves an unowned final projection stage as a
strict `.preserved-<nonce>` audit quarantine, but ordinary L1/fsck cannot
inventory it and no command can retire it without manual filesystem deletion.

**Approach:** Stream a bounded, strict inventory through descriptor-bound
content and POSIX identity checks. Emit one exact retirement token per inode,
then allow `fsck` to retire exactly one named quarantine only when the current
token matches and the same held descriptor remains authoritative through
quarantine, unlink and directory fsync.

## Boundaries & Constraints

**Always:** Report every valid preserved asset/package quarantine as critical
L1/fsck drift; reject malformed, unsafe or more than 1,024 entries; bind the
token to kind, name, bytes, mode, device/inode, mtime, UID/GID and link count;
make a missing exact coordinate a safe replay result.

**Ask First:** Changing the preserved filename grammar, adding bulk retirement,
or making retirement part of GC/recovery.

**Never:** Delete during `--recover`, ordinary `fsck`, `verify` or GC; accept a
content digest alone as deletion authority; combine retirement with remote,
repair, selector or recovery modes; follow symlinks or remove a replacement.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|---|---|---|---|
| Inventory | strict asset/package preserved name | L1/fsck finding with kind, size, SHA-256 and retirement token | verification exit; bytes unchanged |
| Explicit retirement | exact name and current token | one descriptor-bound quarantine removed and parent fsynced | success with `retired=true` |
| Response-loss replay | exact name is already absent | no mutation | success with `already_absent=true` |
| Stale capability | replaced inode, changed bytes/metadata or wrong token | preserve current object | conflict with current-token mismatch |
| Hostile boundary | hardlink, symlink, unsafe mode/owner or final unlink race | never unlink | fail closed and retain evidence |
| Unbounded/malformed inventory | invalid grammar or more than 1,024 entries | no retirement or implicit cleanup | critical invalid-inventory finding |

</frozen-after-approval>

## Code Map

- `internal/cli/projection_audit_quarantine.go` -- streaming inventory,
  deterministic findings, inode-bound token and exact retirement.
- `internal/cli/app.go` -- `fsck --retire-preserved-projection NAME --confirm
  TOKEN` grammar and mutually exclusive command path.
- `internal/cli/verify.go` -- early L1 inventory before canonical recovery.
- `internal/cli/projection_audit_quarantine_test.go` -- real-filesystem CLI,
  stale-token, alias, replay, malformed and cardinality contracts.
- `docs/adr/0044-preserved-projection-audit-retirement.md` -- frozen
  operational and deletion-authority decision.

## Tasks & Acceptance

**Execution:**
- [x] Add bounded descriptor-bound inventory to ordinary fsck and verify L1.
- [x] Add one-at-a-time current-token retirement with no implicit recovery/GC
  deletion and safe response-loss replay.
- [x] Prove malformed, cardinality, stale inode, hardlink and final-unlink
  boundaries on real filesystems in ordinary and race suites.
- [x] Update CLI help, architecture, deferred work, traceability and
  reproducible delivery evidence.

**Acceptance Criteria:**
- Given a preserved audit copy, `fsck` and L1 list exact bytes and a retirement
  token while `--recover` leaves the inode unchanged.
- Given a current token, only that exact held inode can be retired; any
  pathname/identity/byte drift retains evidence and fails.
- Given a completed retirement replay, the same command is harmless and
  reports that the coordinate is already absent.

## Spec Change Log

- 2026-07-28: Implemented strict bounded inventory, quiescence-gated
  capability retirement, hostile-filesystem negatives, complete regression
  validation and reproducible clean delivery; closed as `done`.

## Verification

Focused ordinary/race CLI tests, adjacent fsck/verify/projection suites,
static analysis, four CGO-free builds, exhaustive CLI and non-CLI
ordinary/race suites, real apt/dnf compatibility, local MinIO, edge contracts
and byte-identical double clean delivery passed. Exact commands, timings and
external-state boundaries are recorded in
`docs/evidence/2026-07-28-preserved-projection-audit-retirement.md`.
