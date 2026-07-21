---
title: 'Bind projection residue cleanup and derived-state publication to exact file identity'
type: 'bugfix'
created: '2026-07-22'
status: 'done'
review_loop_iteration: 0
baseline_commit: 'ffcfbab'
context:
  - '{project-root}/docs/requirements-traceability.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Projection `--recover` residue cleanup and shared derived-state writes can act on a pathname after the inode at that pathname has changed. A concurrent or interrupted replacement can therefore be deleted or published as canonical state, violating FR-28/NFR-09 safe replay semantics.

**Approach:** Retain descriptor/inode identity for every private temporary, use random create-only names and no-replace isolation moves, and fail closed when the live coordinate no longer names the retained file.

## Boundaries & Constraints

**Always:** Preserve an unrelated replacement without overwrite; keep the prior canonical derived-state file unchanged on a failed install; fsync committed directory-coordinate changes; support Linux and macOS with the existing single-Go-binary boundary; keep successful and missing-residue operations idempotent.

**Ask First:** Any operation requiring real cloud credentials or mutation of a repository outside isolated local test roots.

**Never:** Delete a temporary solely by pathname after a race window; pre-delete a predictable temporary; publish bytes not bound to the writer's retained descriptor; access CO/COS or Cloudflare production repositories; weaken an error into silent success.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Exact recovery | Private regular orphan stage, including empty file | Remove exact inode and durably sync parent | Missing residue is an idempotent success |
| Replaced recovery coordinate | Orphan is renamed away and a canary takes its name | Preserve/restore canary without overwrite | Fail closed as unsafe residue |
| Derived-state success | Valid nested relative path and bytes | Random O_EXCL temp is fsynced, identity-checked, then atomically installed | Prior destination changes only at final verified rename |
| Legacy/present temp | Old deterministic temp or unrelated random sibling exists | Leave unrelated file byte-for-byte intact | Do not pre-delete or reuse it |
| Failure cleanup race | Writer-created temp is replaced before deferred cleanup | Preserve replacement | Return original failure; never path-delete replacement |
| Install race | Candidate is replaced before final install | Keep prior canonical destination and replacement | Restore without overwrite and return error |

</frozen-after-approval>

## Code Map

- `internal/cli/projection_intent_remove.go` -- descriptor-bound residue binding and shared no-replace quarantine removal primitive.
- `internal/cli/asset_projection_intent.go` -- asset recovery scanner using exact residue removal.
- `internal/cli/package_projection_intent.go` -- package recovery scanner using exact residue removal.
- `internal/cli/publish_plan.go` -- shared derived-state temporary creation, cleanup, isolation, and final installation.
- `internal/cli/projection_intent_removal_test.go` -- asset/package replacement-race and exact-empty-residue tests.
- `internal/cli/publish_provider_test.go` -- predictable temp, failure cleanup, and final-install race tests.
- `docs/evidence/2026-07-22-derived-state-residue-removal-identity.md` -- red/green, race, suite, static-analysis, and build evidence.

## Tasks & Acceptance

**Execution:**
- [x] `internal/cli/projection_intent_remove.go` and recovery callers -- bind orphan deletion to an opened private inode and reuse the no-replace quarantine commit.
- [x] `internal/cli/publish_plan.go` -- replace digest-derived temporaries with random O_EXCL files and exact failure/install commits.
- [x] `internal/cli/*_test.go` -- reproduce every old destructive race and cover exact/missing/empty success behavior.
- [x] `docs/evidence/2026-07-22-derived-state-residue-removal-identity.md` and traceability -- record current-source evidence and external-state boundary.

**Acceptance Criteria:**
- Given any injected pathname replacement at recovery, cleanup, or install boundaries, when the operation resumes, then unrelated bytes survive and the operation returns an error.
- Given the exact writer-owned file, when cleanup or install completes, then the correct coordinate is durably removed or atomically updated.
- Given current source, when focused ordinary/race tests, combined publication/projection tests, the full CLI suite, vet, Staticcheck, and supported target builds run, then all pass without network or cloud access.

## Spec Change Log

## Design Notes

The second random isolation name turns a mutable public temporary coordinate into a private verification coordinate. The retained read/write descriptor remains the authority: pathname metadata alone is never sufficient deletion or publication authority, and final installation re-hashes its exact bytes so same-inode metadata restoration cannot bypass the fence. The expected digest is frozen before any hook can mutate caller-owned memory. Retained root and leaf-directory identities are revalidated against their public coordinates before and after install, so directory replacement fails closed. Cleanup and close errors are joined into the caller-visible error instead of being discarded. Recovery recognizes legacy 16-hex write temps, current 32-hex write temps, install-isolation names and removal-quarantine names through one strict parser; all three journal cleaners retain their size ceilings and use exact-inode removal.

## Verification

**Commands:**
- `go test ./internal/cli -run 'Test(DerivedState|DerivedPublicationState|AssetProjectionRecovery|PackageProjectionRecovery|ProjectionRecovery|LocalServingJournalRecovery|ServingTopologyRecovery|SyncJournalTempCleanup)' -count=1` -- review-final focused edge cases pass.
- The same focused command with `-race` -- race build passes.
- `go test ./internal/cli -count=1 -timeout=25m` -- full CLI suite passes.
- `go test -race ./internal/cli -run 'Publish|Projection|MaterializationSelection|DerivedState|LocalServingJournal|ServingTopology' -count=1 -timeout=20m` -- adjacent publication/projection/recovery race suite passes.
- `go list ./... | rg -v '^github.com/pgsty/sow/internal/cli$' | xargs go test -count=1 -timeout=5m` -- every non-CLI package and clean-delivery check passes.
- `go vet ./... && staticcheck ./... && git diff --check` -- static analysis and patch hygiene pass.
- `CGO_ENABLED=0 go test -c` for Darwin/Linux amd64/arm64 plus Linux arm64 execution in a read-only, network-disabled container -- supported-target build and isolated runtime checks pass.

## Review Disposition

Blind Hunter and Edge Case Hunter independently found the stale recovery-name contracts, three path-deleting journal cleaners, the post-callback quarantine window, hidden unlink/sync errors, early descriptor close, and the post-hash install window. These current-patch findings were reproduced with failing tests and fixed. Confirmed broader pre-existing issues were recorded in `deferred-work.md`; no intent or frozen-spec gap was found, so `review_loop_iteration` remains zero.

## Suggested Review Order

**Exact commit authority**

- Start with the shared writer and its bound root, directory, inode and digest.
  [`publish_plan.go:1968`](../../internal/cli/publish_plan.go#L1968)

- Follow isolation, final revalidation and installed-destination byte proof.
  [`publish_plan.go:2132`](../../internal/cli/publish_plan.go#L2132)

- See public-root binding and idempotent exact-residue admission.
  [`projection_intent_remove.go:112`](../../internal/cli/projection_intent_remove.go#L112)

- Inspect quarantine revalidation, durable unlink and error propagation.
  [`projection_intent_remove.go:187`](../../internal/cli/projection_intent_remove.go#L187)

**Recovery name contract**

- Review the shared legacy/current/install/removal temporary parser.
  [`publish_plan.go:1929`](../../internal/cli/publish_plan.go#L1929)

- Confirm selected-set recovery retains size bounds and exact deletion.
  [`materialize_selection.go:1150`](../../internal/cli/materialize_selection.go#L1150)

- Confirm local-serving recovery uses the same capability contract.
  [`materialize_serving.go:1532`](../../internal/cli/materialize_serving.go#L1532)

- Confirm topology-removal recovery closes the final duplicate path cleaner.
  [`materialize_serving_topology.go:391`](../../internal/cli/materialize_serving_topology.go#L391)

**Fault evidence**

- Read the review-derived crash, replacement, unlink and idempotence tests.
  [`derived_state_recovery_contract_test.go:12`](../../internal/cli/derived_state_recovery_contract_test.go#L12)

- Compare writer-specific predictable-temp, mutation and coordinate fault tests.
  [`publish_provider_test.go:60`](../../internal/cli/publish_provider_test.go#L60)

- Compare asset/package orphan replacement fault tests.
  [`projection_intent_removal_test.go:241`](../../internal/cli/projection_intent_removal_test.go#L241)

- Finish with reproducible red/green, suite, build and isolation evidence.
  [`2026-07-22-derived-state-residue-removal-identity.md:1`](../../docs/evidence/2026-07-22-derived-state-residue-removal-identity.md#L1)

- Check the requirements ledger entry and external-state boundary.
  [`requirements-traceability.md:123`](../../docs/requirements-traceability.md#L123)
