---
title: 'Package repository historical continuity gate'
type: 'feature'
created: '2026-07-14'
status: 'done'
baseline_commit: '84800a60e01aaaf8dc5b189c3ddb1380930f4865'
review_loop_iteration: 0
context: []
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** A populated APT or YUM repository can currently be reclassified by editing canonical configuration, hiding drift behind a restored/matching HEAD, or preserving unsafe state only through an off-HEAD SOW ref. That breaks physical path ownership, incremental publication identity, and recovery guarantees.

**Approach:** Add a local, fail-closed historical admission gate that derives permanent package-repository ownership from non-empty manifest/view/snapshot/generation evidence across aggregate HEAD and every `refs/sow/*` ancestry, then enforce the frozen contract before load and again inside mutation locks.

## Boundaries & Constraints

**Always:** Freeze ID, type, normalized path, default pool, include/exclude sets, OS family/major/suite, APT arches/suites/effective suite-component mapping, YUM arches/noarch/compression, and CF/COS target affinity after first ownership. Treat `active: true` and omission as equal; populated repos may never be inactive. Permit only lifecycle `active` to `frozen` and package-keyring rotation. Keep upstream allow/deny mutable. Empty repos remain editable. Use Git ancestry, not timestamps. Reject delete/reintroduce, root reuse, missing reachable config, matching-HEAD drift, and off-HEAD ref drift.

**Ask First:** Any new migration mechanism that rewrites historical ownership, any weakening of the frozen fields, or any external/cloud verification.

**Never:** Contact CO/COS/Cloudflare production repositories, use credentials/network tests, mutate canonical state during validation, inflate repository-sized manifests on the ordinary path, or replace existing trust-closure checks.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|---------------------------|----------------|
| Empty repository | No non-empty ownership evidence | Contract edits accepted | N/A |
| Populated repository | Frozen field drifts in current or reachable history | Load/mutation rejected before canonical/CAS change | Conflict with commit/path evidence |
| Lifecycle/keyring | Active becomes frozen or package keyring rotates | Accepted; reverse lifecycle rejected | Fail closed on frozen to active |
| Reachability | Unsafe commit survives only under SOW ref or has skewed time | Still audited by ancestry | Invalid/missing config or object rejects |
| Continuity | Repo deleted/reintroduced or path reused by another ID | Rejected even if HEAD matches original | Explicit migration required |

</frozen-after-approval>

## Code Map

- `internal/cli/package_repository_contract.go` -- package ownership/history registry and semantic contract comparison.
- `internal/cli/package_repository_contract_test.go` -- red/green boundary, ancestry, ref, recovery, and GC tests.
- `internal/cli/app.go` -- load and staged-config admission hooks.
- `internal/cli/gc.go` -- lock-held pre-CAS/pre-delete revalidation.
- `internal/state/enumerate.go` -- existing ref, ancestry, and blob metadata APIs.
- `internal/serving/model.go` -- canonical YUM generation ownership path grammar.

## Tasks & Acceptance

**Execution:**
- [x] `internal/cli/package_repository_contract_test.go` -- establish red tests for every frozen field, exceptions, off-HEAD refs, deletion/reintroduction, root reuse, missing config, clock skew, load, locked mutation, and GC no-mutation behavior.
- [x] `internal/cli/package_repository_contract.go` -- implement bounded, read-only reachable-history ownership and continuity validation.
- [x] `internal/cli/app.go` and `internal/cli/gc.go` -- add minimal preflight and lock-held hooks.
- [x] Existing RPM package-keyring trust tests -- prove the allowed rotation exception preserves trust closure.

**Acceptance Criteria:**
- Given any non-empty package ownership evidence reachable from HEAD or a SOW ref, when a frozen contract or continuity rule is violated, then load and every relevant mutation fail before state/CAS mutation.
- Given an empty repository or permitted forward lifecycle/keyring change, when admitted, then validation succeeds without network or external runtime dependencies.
- Given a 32 MiB ownership manifest and extended history, when validating, then allocation stays well below payload size.

## Spec Change Log

## Design Notes

Reachable commits are deduplicated by hash and compared through ancestry. Ownership is established by blob identity/size; only bounded canonical config is decoded. Effective APT suite-component maps and semantic target booleans avoid YAML-shape false positives while preserving behavior.

## Verification

**Commands:**
- `env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN -u CLOUDFLARE_API_TOKEN -u TENCENTCLOUD_SECRET_ID -u TENCENTCLOUD_SECRET_KEY HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 GOPROXY=off go test -count=1 ./internal/cli -run 'PackageRepository|PackageKeyring|Trust'` -- focused local tests pass.
- Same environment with `go test -race -count=1 ./internal/cli -run 'PackageRepository'` -- race-focused tests pass.
- Same environment with `go test -count=1 ./...` and `go vet ./...` -- hermetic full suite and vet pass.

## Suggested Review Order

**Historical ownership model**

- Start with the permanent contract and current-config admission decision.
  [`package_repository_contract.go:30`](../../internal/cli/package_repository_contract.go#L30)

- Follow parent-topological lineage propagation for deletion, root reuse, and lifecycle monotonicity.
  [`package_repository_contract.go:204`](../../internal/cli/package_repository_contract.go#L204)

- Inspect HEAD plus `refs/sow/*` reachability and bounded metadata-only evidence scanning.
  [`package_repository_contract.go:413`](../../internal/cli/package_repository_contract.go#L413)

**CLI safety boundaries**

- Review the shared load and lock-held history gate composition.
  [`app.go:719`](../../internal/cli/app.go#L719)

- Confirm GC cannot open CAS before the lock-held gate.
  [`gc.go:52`](../../internal/cli/gc.go#L52)

**Behavioral proof**

- Frozen-field matrix documents exact invariants and permitted exceptions.
  [`package_repository_contract_test.go:76`](../../internal/cli/package_repository_contract_test.go#L76)

- Off-HEAD and missing-config negatives prove preservation-root closure.
  [`package_repository_contract_test.go:287`](../../internal/cli/package_repository_contract_test.go#L287)

- GC and 32 MiB tests prove no mutation and bounded manifest handling.
  [`package_repository_contract_test.go:337`](../../internal/cli/package_repository_contract_test.go#L337)

- ADR and evidence state the contract without upgrading cloud compatibility.
  [`0022-package-repository-history-continuity.md:1`](../../docs/adr/0022-package-repository-history-continuity.md#L1)
