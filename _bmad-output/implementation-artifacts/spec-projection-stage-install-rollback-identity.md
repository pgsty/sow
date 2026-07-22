---
title: 'Bind projection stage installation and prepare rollback to exact identities'
type: 'bugfix'
created: '2026-07-22'
status: 'done'
review_loop_iteration: 0
baseline_commit: 'bb00b57'
context:
  - '{project-root}/docs/requirements-traceability.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Asset and package projection preparation currently copy through a predictable temporary, install with an overwriting rename, and roll back installed stages by pathname. A source, temporary, destination, or rollback coordinate can therefore be replaced after validation, causing SOW to block on a special file, publish unrelated bytes, overwrite a competing stage, or delete a replacement. An intent rename may also commit before a later durability error; blindly rolling back its stages then leaves a durable intent without its recovery inputs.

**Approach:** Stream from an exact admitted source into a random create-only private temporary, retain and revalidate source/root/temp identities, isolate and re-hash the candidate, and install with a no-replace rename. Return frozen inode-plus-byte identities for every installed stage. On prepare failure, first determine whether the exact intent was committed; otherwise remove only those frozen stage inodes through no-replace quarantine and propagate every cleanup/durability conflict.

## Boundaries & Constraints

**Always:** Keep manifest copying bounded and streaming; preserve Linux/macOS support and the single-Go-binary runtime; reject symlinks, non-regular sources, size growth, and coordinate changes; preserve a concurrent destination or replacement; fsync successful coordinate changes; join the original error with cleanup errors and direct recoverable residue to `--recover`; retain all stages when the exact intent may already own them.

**Ask First:** Access to real cloud credentials or any mutation outside isolated local test roots.

**Never:** Pre-delete or reuse a deterministic temporary; overwrite an existing stage or intent; delete a rollback target based only on its pathname or digest; load a large manifest wholly into memory; touch CO/COS or Cloudflare production repositories; report a failed cleanup as success.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| Normal stage install | Exact private regular source, absent destination | Bounded stream, fsynced exact candidate, no-replace install, durable directory | Return object plus frozen installed identity |
| Legacy temporary | Existing `<stage>.tmp` canary | Canary remains byte-for-byte unchanged | Random O_EXCL temporary is used |
| Source mutation | Source is replaced, grows, or is non-regular | No stage is published and copying remains bounded | Fail closed; preserve unrelated coordinates |
| Candidate replacement | Temporary/isolation coordinate is replaced at a hook | Replacement survives | Return identity conflict and exact-cleanup error |
| Destination race | Competing stage appears before install | Competing bytes survive | No-replace install fails; writer-owned candidate is recovered or exactly removed |
| Prepare failure | Some config/manifests installed but no matching intent | Remove only the frozen writer-owned inodes in reverse order | Join original and cleanup/sync errors |
| Rollback replacement | A stage coordinate now names another inode, including same bytes | Replacement survives | Return cleanup conflict; residue requires `--recover` |
| Ambiguous intent commit | Intent write returns error but exact ID is readable | Keep every stage and intent | Return error explicitly requiring `--recover` |
| Competing intent | Another intent wins after initial absence check | Do not overwrite it; roll back exact owned stages | Preserve competing intent and report conflict |

</frozen-after-approval>

## Code Map

- `internal/cli/asset_projection_intent.go` -- streamed exact stage installer, asset prepare commit detection, and exact rollback.
- `internal/cli/package_projection_intent.go` -- package stage identity ledger, exact rollback, and intent commit detection.
- `internal/cli/projection_intent_remove.go` -- shared installed-stage identity and exact-inode rollback primitive.
- `internal/cli/materialize_archive_contract.go` -- retained nonblocking source descriptor and size-bounded single-pass archive admission.
- `internal/cli/materialize_serving.go` and `internal/cli/publish_plan.go` -- nonblocking exact read/cleanup bindings used by intent read-back and temporary rollback.
- `internal/cli/projection_stage_install_test.go` -- source/temp/destination install races and bounded-source tests.
- `internal/cli/projection_intent_removal_test.go` -- asset/package partial-prepare rollback, replacement, and ambiguous-commit tests.
- `docs/adr/0041-preserved-projection-orphan-quarantine.md` -- restart-safe handling of final stages that have no durable owner.
- `docs/evidence/2026-07-22-projection-stage-install-rollback-identity.md` -- red/green, race, suite, static-analysis, build, and isolation evidence.

## Tasks & Acceptance

**Execution:**
- [x] Implement random, descriptor-bound, streaming stage installation with exact source/temp/root verification and no-replace publication.
- [x] Return frozen installed inode and byte identities and remove them only through exact no-replace quarantine.
- [x] Convert asset/package prepare paths to named-error cleanup ledgers and exact-intent read-back after write errors.
- [x] Add deterministic hooks and red tests for all destructive race windows and bounded source admission.
- [x] Revalidate every installed stage immediately before and after create-only intent commit; preserve unowned final-stage residue for audit instead of rebinding it as deletion authority.
- [x] Record traceability and current-source verification evidence.

**Acceptance Criteria:**
- Given any injected source, temporary, destination, intent, or rollback replacement, when preparation resumes, then unrelated bytes survive and the command fails closed.
- Given a partial prepare with no committed matching intent, when rollback runs, then every exact writer-owned stage is durably removed and no other inode is deleted.
- Given an intent writer that installed the exact ID before returning an error, when prepare handles that error, then the intent and all frozen stages remain available to `--recover`.
- Given current source, when focused ordinary/race tests, full CLI tests, static analysis, supported target builds, and an isolated read-only runtime check run, then all pass without cloud access.

## Spec Change Log

## Design Notes

The rollback authority is an inode captured by the installer, not a later size/hash rebinding: a same-byte replacement is still unrelated. Byte identity remains an independent fence against mutation of the retained inode. The intent commit result is established by reading and validating the final intent ID after any writer error; a committed-but-not-durable result is recoverable ownership, while absence permits exact rollback.

Review exposed a restart boundary that cannot reconstruct that process-local inode capability. ADR-0041 therefore supersedes V-75's final-orphan deletion assumption: a final stage with no valid owning intent is moved to a strict `.preserved-<nonce>` audit coordinate, reported, and never implicitly deleted. Random temporary names remain cleanup capabilities. Strict scanners reject every other stage-prefix suffix, closing both the asset `.test-original` blind spot and the package scanner's former prefix-wide deletion authority.

The source inspector and stage copier now consume the same retained nonblocking descriptor, cap every drain/copy at admitted size plus one byte, and revalidate source coordinate, descriptor and root. Prepared stages are re-hashed before and after create-only intent installation; root identity is rechecked on both sides of ambiguous read-back. Exact removal has one final deterministic pre-unlink seam followed by repeated inode/byte verification. All test hooks are package-private seams around real filesystem operations; production behavior uses native Linux/macOS no-replace renames and no external runtime.

## Verification

Current source passed review-final focused ordinary/race
(`5.802s`/`7.949s`), all Projection ordinary/race
(`87.271s`/`193.995s`), the full CLI suite (`1326.431s`), and adjacent
publication/projection/recovery race coverage (`693.228s`, `708.60s` wall).
Every non-CLI package, vet, Staticcheck, and diff hygiene passed.
Static test binaries built for Darwin/Linux amd64/arm64; Linux arm64 then ran
the focused set in a read-only, network-disabled Debian 13 container. Exact
commands, hashes, coverage, red reproduction, and the external-state boundary
are recorded in
[`2026-07-22-projection-stage-install-rollback-identity.md`](../../docs/evidence/2026-07-22-projection-stage-install-rollback-identity.md).
Cloud credentials remained unset and no production or test bucket was touched.

## Review Disposition

Blind Hunter and Edge Case Hunter independently identified source FIFO blocking and unbounded drain, restrictive-umask mode loss, missing pre/post intent stage verification, state-root-unbound ambiguous read-back, missing-stage rollback success, broad restart cleanup, and a final deterministic unlink seam. Each current-patch finding was reproduced or covered by a deterministic boundary test and fixed. The reviewers also identified the pre-existing canonical `Store.Apply` staged-path reopen gap; it is recorded in `deferred-work.md` rather than misreported as part of this patch. ADR-0041 records the one behavior that supersedes V-75. No frozen intent gap was found, so `review_loop_iteration` remains zero.

## Suggested Review Order

- Follow retained source admission through `openExactOfflineArchiveInput`, `inspectOfflineArchiveOpenFile`, and `installPendingProjectionStageBound`.
- Inspect random temporary creation, explicit mode repair, no-replace isolation/final install, and retained-root cleanup in `installProjectionStageReader`.
- Check the pre/post intent stage vector in both prepare functions and the root-bound ambiguous commit branches.
- Review exact rollback plus final unlink revalidation in `projection_intent_remove.go`.
- Finish with the strict final/temp/preserved name grammar, ADR-0041 quarantine behavior, and the fault-injection tests in the two projection test files.
