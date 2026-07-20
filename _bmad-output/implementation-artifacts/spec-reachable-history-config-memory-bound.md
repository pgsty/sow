---
title: 'Bound reachable-history configuration retention'
type: 'bugfix'
created: '2026-07-20'
status: 'done'
review_loop_iteration: 0
baseline_commit: '74b48977144718e3c340c1918a005e633de20397'
context:
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md'
  - '{project-root}/docs/requirements-traceability.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** asset 与 APT/YUM 物理所有权审计按 reachable commit 保存每个不同的已解码 `sow.yaml`；大量唯一、接近 8 MiB 的合法历史配置会让普通命令内存随历史长度增长，违反 NFR-02。

**Approach:** 引入按 Git blob identity 复用的固定容量历史配置 LRU，只保留最多两个已解码配置且其输入总量不超过 16 MiB；commit 只保存轻量 blob identity，需要时重新从 immutable Git 对象解码。历史所有权记录同时按真实冻结合同去重，所有 commit/ref/merge 仍完整审计，不以硬历史长度上限换取通过。

## Boundaries & Constraints

**Always:** 单 blob 继续执行 8 MiB 声明大小与 `limit+1` 实流双重门禁；cache miss 必须重读并重新校验预期 hash/size；缓存淘汰不得改变错误、连续性、分支合并、off-HEAD `refs/sow/*` 或 unsafe-history 判定；审计保持只读且不创建 repo 内临时状态。

**Ask First:** 修改 8/16 MiB 合同、对合法历史设置 commit/ref 数量硬上限、改变冻结所有权语义，或引入新的持久状态格式。

**Never:** 跳过被淘汰 commit、把 SQLite/磁盘缓存升级为正典、按时间替代 Git ancestry、吞掉对象漂移/读取错误，或触达任何云与生产仓库。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| 重复 blob | 多 commit 指向同一 config blob | 命中缓存并保持完整逐 commit evidence 审计 | identity 不一致则失败关闭 |
| 唯一 blob 洪泛 | 超过两份、每份不超过 8 MiB | LRU 淘汰后继续审计；峰值条目 ≤2、计费输入 ≤16 MiB | 不得因历史长度静默跳过 |
| 淘汰后的违规 | 早期/off-HEAD 配置含冻结合同漂移，之后有多份唯一配置 | 仍返回原有冲突并保持 HEAD/工作树不变 | `ExitConflict` 路径不弱化 |
| 读取/解码失败 | 缺失、超限、损坏或读取中漂移 | 错误不入缓存且下次独立审计重新读取 | 返回 commit/path/identity 上下文 |

</frozen-after-approval>

## Code Map

- `internal/cli/historical_config_cache.go` -- 共享固定条目/字节预算 LRU 与可观测统计。
- `internal/cli/asset_projection_contract.go` -- asset 历史由 commit→blob identity 按需取配置，合同记录去重。
- `internal/cli/package_repository_contract.go` -- package DAG 不再持有 commit→`*config.Config` 或无限 tree cache。
- `internal/cli/*historical*_test.go`, `asset_projection_contract_test.go`, `package_repository_contract_test.go` -- LRU 边界、淘汰、错误不缓存与真实历史负例。
- `docs/requirements-traceability.md`, `docs/evidence/` -- NFR-02/FR-41 的当前源码证据与边界。

## Tasks & Acceptance

**Execution:**
- [x] `internal/cli/historical_config_cache.go` -- 实现 blob-keyed LRU，淘汰发生在新解码前，并记录 current/peak entries 与 canonical bytes。
- [x] `internal/cli/asset_projection_contract.go` -- 删除 decoded/config-per-commit/tree 无界缓存，以按需 accessor 重写连续性读取并按合同去重记录。
- [x] `internal/cli/package_repository_contract.go` -- 用 commit identity + 有界 accessor 替代 `configs` map，传播读取错误并压缩 owner retention。
- [x] `internal/cli/*test.go` -- 覆盖命中、LRU 顺序、byte eviction、loader/decode error、merge/off-HEAD 与被淘汰历史违规。
- [x] trace/evidence/clean-delivery allowlist -- 记录 ordinary/race、内存统计与完整交付复验，不升级真云状态。

**Acceptance Criteria:**
- Given 任意数量的唯一合法 canonical blobs，when asset/package reachable-history audit 完成，then cache 统计始终不超过 2 entries/16 MiB 且没有 commit 配置指针表。
- Given 违规 commit 已被 LRU 淘汰，when 后续 lineage/continuity 再访问它，then 重新读取并返回与无淘汰实现等价的冲突。
- Given 同一 blob 被相邻 commit 复用，when 审计读取，then 只解码一次且逐 commit evidence 仍分别检查。
- Given cache loader、size/hash 或 decode 失败，when 再次调用，then 失败条目未被信任或缓存。

## Spec Change Log

- 2026-07-20: review candidate 实现完成；主代理独立 affected/focused ordinary/race、config/state ordinary/race、clean-delivery policy 与一次 fresh local-proxy delivery build 通过。最终 exhaustive 与双份 delivery identity 留到 adversarial review 后冻结源码重跑。
- 2026-07-20: adversarial review 的三项 patch finding 已关闭：owner/anchor 改为深度脱离的合同且冲突后不再增长；asset continuity 改为 commit-outer 两阶段线性解码并用 hash-only reintroduction；package lineage 改为单次 parents-first 全 repo 扫描、最后 child 后释放 frontier，且每 repo 只保留确定性最佳 finding。empty-evidence 负例现在定向逐出并重载违规 blob，不再由 owner-pair 快速失败代证。
- 2026-07-20: 冻结源码的 706 个 CLI tests 已完成六片 ordinary/race 全量门禁；non-CLI ordinary/race、vet/Staticcheck、module/provenance/vulnerability、四平台静态构建与七套迁移均通过。两次 fresh clean-delivery identity 由交付根外 V-42 记录，所有真实云开关保持关闭。

## Design Notes

缓存预算按原 canonical blob 字节计费，并以条目数提供独立的对象保留上限；在读取 body 后、解码新配置前先淘汰，避免“旧 cache + 新 decoded object”越过固定条目预算。LRU 只优化不可变 blob 的重复解析；commit 图、evidence 与 ancestry 仍以 commit 为单位验证。第二个 deferred item——配置 repo/upstream/arch/component 基数与默认展开复杂度——保持独立批次，不由本规格假装关闭。

## Verification

**Commands:**
- `go test -count=1 ./internal/cli -run 'HistoricalConfigCache|AssetProjection.*Bound|PackageRepository.*Bound|OffHead.*History'` -- expected: 边界、淘汰与违规负例通过。
- `go test -race -count=1 ./internal/cli -run 'HistoricalConfigCache|AssetProjection.*Bound|PackageRepository.*Bound|OffHead.*History'` -- expected: 无竞态。
- `go test -count=1 ./internal/cli` 与六片 exhaustive/race -- expected: 历史合同错误语义无回归。
- `go vet ./...`、两个 Staticcheck profile、module/provenance/migration/clean-delivery -- expected: 全部通过且只使用本地临时目录与只读 module proxy。

## Suggested Review Order

**缓存与驻留边界**

- 从固定容量 LRU 入口理解淘汰、重验与失败不缓存。
  [`historical_config_cache.go:67`](../../internal/cli/historical_config_cache.go#L67)

- 深度脱离 owner 合同，避免浅拷贝隐藏真实驻留。
  [`historical_config_cache.go:204`](../../internal/cli/historical_config_cache.go#L204)

**Asset 历史连续性**

- 首次扫描归并 owner 与最小 anchors，不保存配置指针。
  [`asset_projection_contract.go:217`](../../internal/cli/asset_projection_contract.go#L217)

- commit 外层扫描确保每阶段每配置至多解码一次。
  [`asset_projection_contract.go:619`](../../internal/cli/asset_projection_contract.go#L619)

- ancestry-aware 流式归并保持 merge 与 off-HEAD 语义。
  [`asset_projection_contract.go:697`](../../internal/cli/asset_projection_contract.go#L697)

**Package DAG 审计**

- admission 汇总充分 owner 证据后启动统一 lineage。
  [`package_repository_contract.go:27`](../../internal/cli/package_repository_contract.go#L27)

- 单次 parents-first 扫描推进全部 repo 并释放 frontier。
  [`package_repository_contract.go:248`](../../internal/cli/package_repository_contract.go#L248)

**回归与故障证据**

- 定向逐出后重载 empty-evidence asset 违规 blob。
  [`historical_config_cache_test.go:172`](../../internal/cli/historical_config_cache_test.go#L172)

- 定向逐出后由 package lineage 发现早期漂移。
  [`historical_config_cache_test.go:261`](../../internal/cli/historical_config_cache_test.go#L261)

- 深拷贝测试覆盖全部嵌套 slice、map 与 pointer。
  [`historical_config_cache_test.go:349`](../../internal/cli/historical_config_cache_test.go#L349)

- 重复 blob 命中仍保留逐 commit evidence identity。
  [`historical_config_cache_test.go:387`](../../internal/cli/historical_config_cache_test.go#L387)

**追踪与交付**

- V-39 与 NFR-02 记录 post-review 证据边界。
  [`requirements-traceability.md:105`](../../docs/requirements-traceability.md#L105)

- 日期化报告区分聚焦通过与待跑终验。
  [`2026-07-20-reachable-history-config-memory-bound.md:1`](../../docs/evidence/2026-07-20-reachable-history-config-memory-bound.md#L1)

- 产品清单纳入新增实现与测试文件。
  [`product-files.txt:91`](../../test/compat/cleandelivery/product-files.txt#L91)
