---
title: 'Make derived-state replacement outcomes explicit and recoverable'
type: 'bugfix'
created: '2026-07-26'
status: 'done'
review_loop_iteration: 0
baseline_commit: '7c8bf16'
context:
  - '{project-root}/_bmad-output/implementation-artifacts/deferred-work.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-derived-state-residue-removal-identity.md'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-derived-state-recursive-directory-durability.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Canonical derived-state replacement currently overwrites the prior
destination and reports only an error plus a rename flag. A post-rename
verification or directory-fsync failure therefore cannot prove whether the new
state committed, the prior state was restored, or recovery is mandatory.

**Approach:** Preserve the exact prior inode with an atomic exchange, record a
durable prepared/committed replacement intent before and after the commit
barrier, and return an explicit fail-closed outcome. Recovery decides from the
intent plus bound new/prior identities; it never guesses from pathname
existence.

## Boundaries & Constraints

**Always:** Outcomes are exactly not-committed, committed, or
recovery-required, with zero value fail-closed. Existing destinations and new
candidates remain descriptor/inode/content bound. Prepared recovery rolls back;
committed recovery rolls forward. Every namespace phase is parent-fsynced and
revalidated against the absolute state root. A committed-with-error result
still stops its caller but retains recovery ownership.

**Ask First:** Changing canonical state schema or public `.sow` layout; deleting
unowned recovery evidence; accessing any cloud, upstream, or production
repository.

**Never:** Overwrite-rename an existing destination; copy the prior bytes as a
backup; infer commit from `Rename` success; report rollback unless the prior
inode or exact absence is restored and durable; let generic temp cleanup delete
a transaction-owned prior; use a two-rename fallback where atomic exchange is
unavailable; broaden this story into the separately deferred hostile-hardlink
or directory-writeability policy.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|---|---|---|---|
| New destination | exact candidate, canonical absent | no-replace install, durable commit, cleanup | pre-commit fault restores durable absence |
| Replacement | exact candidate and prior regular file | exchange retains prior until committed marker | pre-commit fault exchanges exact prior back |
| Commit cleanup fault | committed marker durable, prior retained | new canonical remains authoritative | return committed+error; replay cleans forward |
| Ambiguous rollback | sync/proof/exchange cannot close | new/prior/intent evidence retained | recovery-required; ordinary continuation blocked |
| Crash replay | prepared or committed durable intent | deterministic rollback or forward cleanup | third identity or malformed phase fails closed |
| Coordinate race | root/parent/destination/residue replaced | foreign object remains untouched | recovery-required with evidence path |

</frozen-after-approval>

## Code Map

- `internal/cli/derived_state_replacement.go` -- explicit outcome,
  replacement intent, exchange/rollback/forward-recovery protocol.
- `internal/cli/derived_state_atomic_{linux,darwin,other}.go` --
  descriptor-relative no-replace and atomic exchange implementation.
- `internal/cli/publish_plan.go` -- shared source writer/directory admission;
  generated publication sources propagate explicit recovery authorization
  into the replacement transaction.
- `internal/cli/offline_archive_projection_intent.go` -- stage ownership must
  consume the explicit result instead of inferring a commit by read-back.
- `internal/cli/{asset_projection_intent,package_projection_intent,materialize_selection,materialize_serving,materialize_serving_topology}.go`
  -- transaction-aware residue cleanup and caller stop/replay behavior.
- `internal/cli/derived_state_replacement_contract_test.go` -- outcome,
  fsync/crash/replacement/replay contract tests.
- `docs/adr/0042-derived-state-replacement-outcome.md` -- frozen local
  transaction and recovery contract.

## Tasks & Acceptance

**Execution:**
- [x] Implement a zero-value-fail-closed result API and migrate every production
  caller; retain an error-only helper only in tests.
- [x] Add durable prepared/committed intents, exact prior retention,
  descriptor-relative exchange/no-replace, compensation and restart recovery.
- [x] Route all derived-state residue scanners through transaction arbitration
  before legacy temporary cleanup.
- [x] Add real-filesystem fault, crash, concurrency and caller-ownership tests
  for every matrix row.
- [x] Record the final deferred resolution, traceability and clean-delivery
  identity; run post-review ordinary/race/static/cross-platform/performance
  gates on the unchanged source.

**Acceptance Criteria:**
- Given any injected failure after destination mutation, when the writer
  returns, then its result proves committed, proves exact durable rollback, or
  blocks continuation as recovery-required while retaining both identities.
- Given a process death at every durable phase, when recovery replays, then
  prepared work restores the exact prior/absence and committed work preserves
  the exact new bytes without deleting a foreign replacement.
- Given any production caller, when committed-with-error or recovery-required
  is returned, then it stops the current operation and preserves every
  higher-level stage/intent needed for replay.

## Spec Change Log

- 2026-07-28: Implementation and Step-3 verification complete; advanced to
  independent blind and edge-case review.
- 2026-07-28: First independent review produced patch findings only. The
  implementation now adds a committed-observed durability barrier, delays
  forward cleanup until final root/parent/destination proof, re-proves the
  outcome after carrier removal, preserves the source on recovery-required,
  rejects reserved destinations, uses a bounded transaction-derived
  source-trash name, covers prior-absent crash phases and all six scanners,
  injects real parent-fsync failures, and stops materialization when a
  completed-unit journal update fails. The separately deferred hostile
  hardlink/directory-writeability threat model remains outside this frozen
  story boundary.
- 2026-07-28: Second independent review found impossible carrier topologies,
  unbounded transaction-ID inventory, implicit publish replay, unstable carrier
  and payload identity capture, a lost combined trust/journal failure, and
  offline-archive preflight errors reported with the fail-closed zero outcome.
  The implementation now validates every carrier/phase topology before
  mutation, caps live transaction identities at 1,024, validates cleanup
  carriers before restoring them, compares mtime across bounded reads, requires
  explicit publish recovery, preserves both simultaneous materialization
  errors, and returns explicit not-committed for pre-writer archive failures.
  The review's remaining last-carrier and cleanup TOCTOU observations require a
  same-host writer able to mutate the admitted directory or retain a writable
  hardlink; that already-recorded threat-model expansion remains outside this
  frozen story and will be handled by its dedicated follow-up.
- 2026-07-28: Fresh third-round blind and edge-case reviews independently
  inspected the complete post-fix source, tests and evidence and both returned
  `[]`.
- 2026-07-28: Post-review terminal verification completed on that unchanged
  source: all 859 default CLI tests passed in six exhaustive ordinary and race
  shards; all 17 non-CLI packages, static/module/security gates, four
  CGO-free platform builds, isolated Linux/arm64 execution, real local
  apt/dnf/Nginx ordinary and race compatibility, 47 edge contracts, four fuzz
  targets, 50k scale paths, 50k unique-content adoption/replay, and the
  read-only 106.31 GB repository scan passed. Final clean-delivery
  reconstruction is performed only after this status edit so its identity is
  not invalidated by the evidence update.

## Design Notes

The durable intent is written without recursively using the derived-state
writer. It binds one transaction ID, canonical basename, candidate
size/SHA-256, exact prior-present state, and private residue names. The
prepared phase owns rollback; only a parent-fsynced committed phase transfers
ownership to forward cleanup. Linux `RENAME_EXCHANGE` and Darwin `RENAME_SWAP`
are the only replacement primitives.

## Verification

**Commands:**
- Focused ordinary/race outcome, fsync, crash and replay tests.
- Full `internal/cli` ordinary/race shards plus all non-CLI ordinary/race tests.
- `go vet ./...`, Staticcheck, module verification and vulnerability scan.
- Darwin/Linux amd64/arm64 static test builds and isolated Linux runtime tests.
- Current 50k adoption/materialize/publish/YUM/APT bounded-memory gates.

## Suggested Review Order

**Outcome contract and transaction core**

- Start with the frozen three-state replacement and replay decision.
  [`0042-derived-state-replacement-outcome.md:20`](../../docs/adr/0042-derived-state-replacement-outcome.md#L20)

- Make every caller consume committed, rolled-back, or recovery-required explicitly.
  [`derived_state_replacement.go:150`](../../internal/cli/derived_state_replacement.go#L150)

- Recover durable carriers by topology and exact candidate/prior identities.
  [`derived_state_replacement.go:1327`](../../internal/cli/derived_state_replacement.go#L1327)

- Install via no-replace or exchange while retaining rollback authority.
  [`derived_state_replacement.go:1423`](../../internal/cli/derived_state_replacement.go#L1423)

- Use Linux's native descriptor-relative atomic exchange without fallback.
  [`derived_state_atomic_linux.go:7`](../../internal/cli/derived_state_atomic_linux.go#L7)

- Keep Darwin behavior isomorphic with native rename-swap.
  [`derived_state_atomic_darwin.go:7`](../../internal/cli/derived_state_atomic_darwin.go#L7)

**Caller recovery ownership**

- Propagate explicit publish recovery into generated source replacement.
  [`publish_plan.go:1842`](../../internal/cli/publish_plan.go#L1842)

- Preserve offline archive stages according to the exact replacement outcome.
  [`offline_archive_projection_intent.go:253`](../../internal/cli/offline_archive_projection_intent.go#L253)

- Stop materialization when its completed-unit journal cannot commit durably.
  [`materialize_selection.go:1086`](../../internal/cli/materialize_selection.go#L1086)

**Adversarial and terminal proof**

- Walk process-death recovery across every durable prior-present/absent phase.
  [`derived_state_replacement_contract_test.go:136`](../../internal/cli/derived_state_replacement_contract_test.go#L136)

- Reject impossible carrier topology before any recovery mutation.
  [`derived_state_replacement_contract_test.go:634`](../../internal/cli/derived_state_replacement_contract_test.go#L634)

- Review exhaustive current-source gates and measured 50k behavior last.
  [`2026-07-28-derived-state-replacement-outcome.md:200`](../../docs/evidence/2026-07-28-derived-state-replacement-outcome.md#L200)
