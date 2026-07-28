---
title: 'Freeze derived-state ownership and reject foreign hardlink aliases'
type: 'bugfix'
created: '2026-07-28'
status: 'done'
review_loop_iteration: 1
baseline_commit: 'da1645b'
context:
  - '{project-root}/_bmad-output/implementation-artifacts/deferred-work.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-derived-state-recursive-directory-durability.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-derived-state-replacement-outcome.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Descriptor and inode checks reject pathname replacement, but an
admitted group/other-writable directory or a retained hardlink to a control
file lets another local principal mutate derived state after verification.

**Approach:** Establish the process effective UID as the local-state trust
anchor, freeze ownership and writeability for every bound control directory,
and require every derived-state control file to be a private, singly linked
regular file at each bind, read, mutation, and cleanup boundary.

## Boundaries & Constraints

**Always:** Apply on Linux and macOS without CGO or external tools. The state
root's immediate parent and every control directory are real, owned by the
effective UID, not group/other writable, and retain exact UID/GID/mode while
bound. A control file additionally has link count one. Unsafe pre-existing or
raced-in evidence is preserved and fails closed; existing V81 recovery
carriers remain readable when safe.

**Ask First:** Changing public CLI/config/schema or `.sow` layout; supporting a
shared/sudo multi-operator trust model; deleting unsafe evidence; accessing
cloud, upstream, or production repositories.

**Never:** Chmod/chown an unsafe pre-existing object; follow symlinks; apply the
single-link rule to `.pool`, serving trees, materialized packages, trust routes,
or offline-archive payloads; claim protection from root, the same UID,
kernel-privileged mutation, or portable ACL inspection.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|---|---|---|---|
| Safe control state | effective-UID directories; private link-count-one files | normal write/replay/cleanup | unchanged result semantics |
| Unsafe directory | foreign owner or group/other writable parent/root/intermediate | no namespace mutation | reject with coordinate context |
| Aliased control | destination, temp, intent, carrier, or residue has link count greater than one | never trust or remove it | preserve evidence; recovery required where ownership is ambiguous |
| Boundary race | owner/mode/link count changes after bind or before commit/cleanup | no success or rollback claim | fail closed and retain transaction evidence |
| Legitimate payload links | CAS/serving/archive package inode has multiple links | existing workflow remains valid | no control-state admission applied |

</frozen-after-approval>

## Code Map

- `internal/cli/derived_state_security_{linux,darwin}.go` -- extract and compare
  effective-UID, UID/GID and link-count security identities.
- `internal/cli/derived_state_identity_{linux,darwin}.go` -- include ownership
  in directory mutation tokens without treating directory link count as one.
- `internal/cli/publish_plan.go` -- central root/intermediate directory
  admission and write-transaction boundaries.
- `internal/cli/derived_state_replacement.go` -- control-file identity,
  binding, replay, mutation and cleanup admission.
- `internal/cli/projection_intent_remove.go` and projection callers -- admit
  control intents/stages/residues without touching payload hardlinks.
- `internal/state/lock.go` -- bind the parent/root/locks authority and reject
  aliased lease/lock records before establishing or validating a lease.
- `internal/cli/*_test.go`, `internal/state/*_test.go` -- real-filesystem owner,
  permission, hardlink and boundary-race contracts.
- `docs/adr/0043-derived-state-hostile-writer-admission.md` -- threat model,
  invariants and explicit non-claims.

## Tasks & Acceptance

**Execution:**
- [x] Add platform-tagged security identity helpers and effective-UID
  admission; freeze UID/GID/mode across descriptor/path revalidation.
- [x] Enforce singly linked control files throughout replacement and projection
  intent/residue paths while preserving V81 outcome and replay semantics.
- [x] Add real-filesystem hostile-permission, hardlink-alias, race and
  payload-nonregression tests on Linux/macOS-compatible code paths.
- [x] Record ADR, deferred resolution, traceability and reproducible evidence;
  run focused race tests plus full static, platform, compatibility, scale and
  clean-delivery gates.

**Acceptance Criteria:**
- Given any unsafe root/intermediate/control object present before an
  operation, when SOW binds it, then SOW performs no derived-state namespace
  mutation and reports the exact violated admission rule.
- Given a foreign hardlink or security-identity change at any injected
  transaction boundary, when the operation returns or replays, then it never
  reports an unproved commit/rollback and never removes the foreign object.
- Given existing CAS, serving, trust-route and offline-archive hardlinks, when
  the full workflow runs, then their link topology and CLI behavior are
  unchanged.

## Spec Change Log

- 2026-07-28: Implemented effective-UID directory admission, frozen
  UID/GID/mode identities, singly linked control-file admission, native
  no-replace state-lock publication and exact hostile-writer recovery.
- 2026-07-28: Closed the final state-lock unlink boundary found by independent
  hostile-filesystem review, reran the focused and exhaustive ordinary/race
  suites, and received independent final `[]` reviews from both reviewers.
- 2026-07-28: Passed real apt 1.2/2.4, EL7 YUM, EL8/9/10 DNF, local MinIO,
  edge-contract, 50k, static-analysis, four-platform and clean-delivery gates;
  V-82 is complete without accessing any production repository or cloud
  resource.

## Design Notes

Directory link counts legitimately vary with children, so directory admission
freezes owner/group/mode while existing mutation epochs continue to observe
link-count changes. Control-file admission requires link count exactly one.
Exact GID is frozen but need not equal the process group because group writes
are forbidden. The PRD assumes one operator; this is defense in depth against a
different local principal, not a shared-workstation authorization system.

## Verification

**Commands:**
- Focused ordinary/race and real-filesystem fault tests for root, intermediate,
  canonical, temporary, carrier, intent and residue admission.
- Full ordinary/race test shards, vet/static/security/module gates, CGO-free
  Linux/macOS builds, local apt/dnf/Nginx compatibility, 50k scale and clean
  reconstruction.
