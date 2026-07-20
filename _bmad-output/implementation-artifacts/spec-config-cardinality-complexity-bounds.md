---
title: 'Bound configuration topology and default expansion complexity'
type: 'bugfix'
created: '2026-07-20'
status: 'done'
review_loop_iteration: 1
baseline_commit: '17621ea9c1c23a603a253fe1ed585c6740c73eca'
context:
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md'
  - '{project-root}/docs/requirements-traceability.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 8 MiB 输入上限只约束 YAML 字节数；大量 repo/upstream 的 arch、suite 与 component 仍可在默认传播、笛卡尔叶展开和重复线性成员查找中放大为超线性 CPU 与乘法内存。

**Approach:** 在任何序列默认复制和昂贵拓扑校验前，对显式条目、默认展开条目和实际元数据叶收取统一的有限复杂度预算；同时把路径冲突和成员校验改为有界的线性或 `O(n log n)` 实现。

## Boundaries & Constraints

**Always:** 保持既有 8 MiB 字节合同；复杂度预算必须覆盖 repo/group/upstream/view 各集合、APT suite×component×arch 叶和省略 upstream arches/components 后的真实展开；越界时稳定失败且不得修改输入结构；现有示例、迁移配置和约 98 repo 的真实矩阵必须继续通过。

**Ask First:** 改变 `sow/v1` 字段语义、提高或降低冻结后的预算常量、引入新的运行时依赖，或访问任何真实云/生产仓库。

**Never:** 把包数量计入配置拓扑限制、静默截断选择器、在复制默认值后才拒绝、用计时型脆弱测试冒充复杂度证明，或弱化严格 schema/机密性/迁移合同。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| 正常矩阵 | 当前 example、PGDG 与迁移配置 | 解码、默认值和 canonical identity 不变 | N/A |
| 默认放大 | 大量 upstream 省略 arches/components 并指向宽 repo | 在复制前按 projected units 拒绝，原 slices 仍为 nil | 稳定配置错误，指出预算和触发字段 |
| APT 乘法 | suites×components×arches 超限但 YAML 小于 8 MiB | 在元数据叶展开前拒绝 | 不分配乘法结果、不进入路径/成员扫描 |
| 边界 | projected units 恰好等于或多于上限一项 | 等于上限可继续常规校验；多一项稳定拒绝 | 无整数溢出、无 panic |
| 冲突路径 | 大量非重叠路径或深层 ancestor 冲突 | 结果与既有二次参考算法一致 | 确定性报告第一组冲突 |

</frozen-after-approval>

## Code Map

- `internal/config/config.go` -- shared decode/default/validation entry, APT and upstream normalization, path ownership checks.
- `internal/config/complexity.go` -- overflow-safe topology accounting and frozen work-unit ceiling.
- `internal/config/yum_compat.go` -- compatibility projection topology validation over the same physical path universe.
- `internal/config/edge.go`, `internal/serving/nginx.go` -- indexed view/repo projection and one-pass configured-arch route expansion.
- `internal/config/complexity_test.go` -- arithmetic boundary, non-mutation, oracle-equivalence and shipped-config regression tests.
- `internal/cli/config_complexity_test.go` -- real `sow init` exit/state-mutation negative test.
- `_bmad-output/implementation-artifacts/deferred-work.md` -- authoritative open review item to resolve only after evidence passes.
- `docs/requirements-traceability.md`, `docs/evidence/` -- NFR-01/NFR-02/V-ledger evidence without upgrading cloud status.

## Tasks & Acceptance

**Execution:**
- [x] `internal/config/complexity.go` -- add overflow-safe topology accounting at the start of validation: 65,536 structural work units plus a 64 MiB derived-string-byte budget covering path expansion, default-copy canonical repetition and logical selector/metadata combinations.
- [x] `internal/config/config.go` -- replace quadratic path/prefix scans, self-membership path expansion, sparse suite normalization and repeated APT/upstream linear membership checks with deterministic indexed or sorting-based validation.
- [x] `internal/config/yum_compat.go`, `internal/config/edge.go`, and `internal/serving/nginx.go` -- keep compatibility/edge/serving projections inside the same bounded, indexed, one-pass configured-arch contract.
- [x] `internal/config/complexity_test.go` and `internal/cli/config_complexity_test.go` -- cover both exact limits, arithmetic overflow, long-string byte amplification, pre-default non-mutation, sparse suite and many-arch adversaries, randomized oracle equivalence, and real CLI zero-state-mutation rejection.
- [x] ADR, deferred ledger, traceability and evidence -- record exact constants, focused corrected-source commands, review-loop correction, invalidated first-candidate evidence, pending final gates, and local-only boundary.

**Acceptance Criteria:**
- Given a syntactically sub-8-MiB configuration whose projected defaults or metadata topology exceed the budget, when `Decode`/`Validate` runs, then it fails before sequence mutation or multiplicative allocation with a stable configuration error.
- Given any accepted topology, when repo/upstream/path validation runs, then work is bounded by the declared units plus sorting/string bytes rather than collection cross-products outside the budget.
- Given current shipped and migration fixtures, when focused ordinary/race and full config/CLI gates run, then behavior and canonical identities remain compatible.
- Given final source, when static, module, migration and clean-delivery gates run, then all pass without cloud or production access.

## Spec Change Log

### Review loop 1 — 2026-07-20

- **Triggering findings:** the first candidate charged only element cardinality, so one multi-MiB path/arch repeated through `ExpandedPaths` or upstream defaults could allocate GiB before the post-marshal size check. `ExpandedPaths` also re-scanned its own arch list for every member, and sparse `suite_components` normalization re-scanned every global component for every suite.
- **Amendment:** add an independent 64 MiB derived-string-byte ceiling before any expansion; explicitly require linear configured-arch expansion and per-suite sorting by one precomputed global component-order index. Extend tests with long-string, many-arch and sparse-suite adversaries whose structural unit counts remain below 65,536.
- **Known-bad state avoided:** a flat unit count that treats a multi-MiB string like a short atom, `PathForArch` self-membership inside `ExpandedPaths`, and suite normalization implemented as `for suite × for global component`.
- **KEEP:** preserve the 65,536 structural ceiling, overflow-safe arithmetic, rejection before sequence mutation, stable `ExitConfig` with no `.sow/.pool`, deterministic first-conflict compatibility, indexed upstream/YUM membership, current-fixture headroom, package-row exclusion, and the full ordinary/race/static/migration/clean-delivery evidence standard.
- **Main-agent correction before second review:** charge omitted and explicit-empty package-keyring defaults by actual default provenance; charge invalid zero-dimension default view/repo visits; count every YUM OS selector; replace residual edge/Nginx configured-arch, view-membership, repo-owner and sort-comparator rescans. Preserve the prior one-arch non-templated compatibility-carrier behavior.

## Design Notes

One structural work unit represents one decoded collection member, one copied default member, or one logical metadata/selection leaf. A separate derived-byte budget charges bytes that expansion would materialize or repeatedly serialize: templated repository paths, defaulted sequence values and every string coordinate in logical selector/metadata combinations. Both budgets use subtraction-before-addition and division-before-multiplication, so hostile cardinalities or byte weights cannot wrap `int`. Raw YAML remains independently capped at 8 MiB. Package rows remain governed by streaming/chunk limits and are deliberately unrelated to these configuration topology caps.

## Verification

**Required rerun after review loop 1:**
- Focused config ordinary/race including structural and derived-byte exact boundaries, many-arch expansion and sparse-suite normalization.
- Real CLI long-string/default-amplification rejection with no state mutation.
- All CLI tests in six ordinary/race shards and all non-CLI packages ordinary/race.
- Vet, repository Staticcheck profiles, root/nested module integrity, RPM provenance, fixed vulnerability scans, four static builds, seven migration suites and two post-document clean-delivery rebuilds.
- The pre-review candidate's green runs are invalidated by the three adversarial findings and must not be cited as final V-41 evidence.

## Suggested Review Order

1. [Budget model](../../internal/config/complexity.go) — Verify overflow-safe structural and derived-byte accounting.
2. [Validation integration](../../internal/config/config.go) — Check pre-default ordering and indexed normalization.
3. [Projection consumers](../../internal/config/edge.go) — Confirm view and repository lookups remain bounded.
4. [Nginx projection](../../internal/serving/nginx.go) — Confirm reused expansions and deterministic ownership.
5. [Boundary tests](../../internal/config/complexity_test.go) — Inspect exact limits, adversaries, and randomized oracles.
6. [CLI mutation guard](../../internal/cli/config_complexity_test.go) — Verify rejection leaves repository state absent.
7. [ADR](../../docs/adr/0040-bounded-configuration-topology.md) — Review frozen constants and change protocol.
8. [Evidence](../../docs/evidence/2026-07-20-config-topology-complexity-bound.md) — Reproduce full local-only verification.
