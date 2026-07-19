---
title: '存量本地仓库 CAS/view adoption bridge'
type: 'feature'
created: '2026-07-12'
status: 'done'
review_loop_iteration: 1
baseline_commit: '84800a60e01aaaf8dc5b189c3ddb1380930f4865'
context:
  - '{project-root}/docs/migration/runbook.md'
  - '{project-root}/docs/architecture.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** `sow init` 只能记录存量服务树基线，不能从现有 APT/YUM/asset 索引证明包成员、导入 CAS 并建立 view refs，导致迁移 Phase 2 仍需逐包重新 add。

**Approach:** 增加显式 `sow init --adopt-content`，在同一 state lock 内先完成原有零字节基线，再从真实索引流式验证并纳管 package/asset 字节，以单次 canonical transaction 建立 latest（默认）及可选 stable view、legacy receipt 与 refs；失败关闭且不改服务树。

## Boundaries & Constraints

**Always:** 默认 `sow init` 语义不变；adoption 只相信 baseline 和真实 Packages/repomd→primary；逐包校验 size/SHA256 并用生产 DEB/RPM parser 核对身份；CAS 可留下失败 orphan，但 canonical files/refs/cache 不得部分推进；pool 默认且只能来自 `repo.default_pool`，公开 view 强制 public 闭包；frozen repo 可纳管；流式处理并限制 worker/metadata；receipt 明示 legacy adoption，不声称上游签名 provenance。

**Ask First:** 真实仓库布局缺索引、同一路径被冲突索引引用、或需要超出 repo 默认 pool 的业务归类。

**Never:** 猜测未被索引证明的包成员；接受绝对路径、`..`、双斜杠、跨 repo、symlink/special file；在 adoption 中重写 serving bytes、生成索引或执行远端写入；绕过 stable append-only、公开机密性闭包或 frozen 后续写禁令。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| baseline only | `sow init` | 仅更新 manifests/config/repo refs/cache | 原有退出码与恢复语义 |
| APT adopt | raw/gz/xz/zst Packages | 精确 Filename/Size/SHA256、DEB 身份、CAS、leaf refs | 缺索引/逃逸/篡改时退出 4/6，view 零提交 |
| YUM adopt | repomd + gz/zst primary | canonical Packages/首字母路径、RPM 身份、可选签名验证 | metadata/包不一致即失败关闭 |
| asset adopt | repo baseline manifest | 所有 manifest 文件进入 CAS 与 all/all leaf | 任一文件变化时不推进 refs |
| repeat/frozen | 相同 baseline；frozen repo | `changed=false`；允许历史纳管 | 后续 add/sync 仍按既有规则拒绝 |
| confidentiality | gated default pool + latest | 不产生公开 ref | 直接拒绝，不提供 force |

</frozen-after-approval>

## Code Map

- `internal/cli/app.go` -- init flags、baseline 后 adoption 编排、退出码保真与 cache 验证。
- `internal/cli/adopt_content.go` -- baseline 对账、CAS import、view/receipt staging 与原子 Apply。
- `internal/upstream/local.go` -- 复用生产 metadata 安全边界的本地 APT/YUM 流式解析。
- `internal/provenance/legacy.go` -- schema 化 legacy-adoption JSONL receipt。
- `internal/cli/adopt_content_test.go` -- 真实 DEB/RPM E2E、负例、幂等、frozen、机密性和故障原子性。
- `docs/migration/runbook.md` -- 将 Phase 2 改为可执行并保留真实云边界。

## Tasks & Acceptance

**Execution:**
- [x] `internal/upstream/local.go` -- 暴露有界本地 index reader 与 APT/YUM candidate stream，复用现有 hardened parser。
- [x] `internal/provenance/legacy.go` -- 定义严格、确定性、可流式回读的 migration receipt。
- [x] `internal/cli/adopt_content.go` -- 实现索引成员证明、生产 parser 核验、并发 CAS 导入、外排 view staging、单事务 refs。
- [x] `internal/cli/app.go` -- 加入显式 flag/view 选择并保证原 init 默认路径不变。
- [x] 测试与 runbook -- 覆盖成功、逃逸、篡改、缺索引、部分失败、幂等、frozen 与机密性；真实 EL8 DNF adoption→materialize 客户端门禁由 `test/compat` 覆盖。
- [x] 50k asset adoption 专项实测；50,000 个路径/正文都唯一的小 asset 已通过真实 `cli.Main init --adopt-content` 完成 CAS/view/receipt/cache 精确闭合、8/8 实际 import worker 峰值、heap 上界、serving manifest 零改写与全量幂等重放。

**Acceptance Criteria:**
- Given 已建立 baseline 的真实 APT/YUM/asset 树，when 运行 adoption，then serving tree 字节不变、CAS/view/receipt 精确可追溯且 materialize/L1/fsck 能继续工作。
- Given 任一未证实、逃逸、篡改或机密性冲突输入，when adoption 失败，then view refs/cache 不推进且仅允许出现可审计 CAS orphan。
- Given 相同树重复执行，when baseline 和配置未变，then canonical HEAD/refs/receipt 保持幂等。

## Spec Change Log

- 2026-07-18：专项 perf 暴露并关闭此前缺失的本命令证据；生产 CLI 新增实际
  `peak_import_workers` 统计，日期化报告见
  [`../../docs/evidence/2026-07-18-legacy-adoption-50k-performance.md`](../../docs/evidence/2026-07-18-legacy-adoption-50k-performance.md)。
- 2026-07-18：Blind Hunter 与 Edge Case Hunter 的独立审查共识项全部修复：部分
  suite/arch 顺序纳管合并既有 view/receipt；两遍 APT/YUM 候选全集必须一致；metadata
  pathname/inode 在 hash→parse→close 全生命周期连续；Apply 前最终重扫 serving tree；旧
  receipt 校验 Git ancestor、commit time、原 manifest 与 canonical route；coded error 不再
  被统一降格为 verification；重复 cache rebuild 删除；大规模 blocker 使用 SQLite/精确
  磁盘报告/固定预览；50k 用四路 tuple closure、SQLite provenance、逐 CAS verify、5ms
  sampled heap 和 OS RSS 高水位取代 count-only/HeapAlloc-only 证据。

## Design Notes

package body 的 CAS import 可在 canonical commit 前发生；这使故障只产生可由 GC 报告的内容寻址 orphan。baseline repo ref commit 同时作为 receipt 的确定性 `config_commit` 与时间来源，避免重复 adoption 因墙钟变化失去幂等性。部分选择器重放保留并验证既有 receipt 的原始 ancestor anchor，不能用当前 commit/墙钟悄悄改写历史。

多文件 serving tree 的并发边界是显式 migration writer freeze：旧 Make/cron/container/cloud
writer 在整个调用期间保持撤销，SOW state lock 串行所有 SOW writer。最终 rescan 是该排他
边界内的读侧线性化检查，拒绝所有已观察 drift；它不声称用一次目录遍历锁住不合作的第三方
进程。runbook 要求紧邻 adoption 的三项 live writer-fence probe，并在冻结被破坏时重新建立
M0 baseline。50k cache 证据还逐行比较 canonical receipt 派生的
`receipt_id/artifact_sha256/format/kind/repo/source_path/pool/upstream_url/observed_at`
与 SQLite provenance stream，不再把等行数当作内容正确性。

## Verification

**Commands:**
- `go test -count=1 ./internal/upstream ./internal/provenance ./internal/cli -run 'Local|Legacy|AdoptContent'` -- E2E 与负例通过。
- `go test -race -count=1 ./internal/upstream ./internal/provenance ./internal/cli -run 'Local|Legacy|AdoptContent'` -- 并发导入无竞态。
- `go vet ./internal/upstream ./internal/provenance ./internal/cli` -- 静态检查通过。
- `go test -tags perf ./test/perf -run '^TestLegacyAssetAdoptionFiftyThousand$' -count=1 -v -timeout=35m` -- PASS 1156.07s；首次/replay 12m09s/6m12s，50,000 unique payload/CAS/view/receipt/cache/provenance，四路 tuple closure SHA-256 `845e39df…ca45a`，receipt/SQLite 九字段 provenance closure SHA-256 `1577eccd…ce57`，逐对象 CAS verify，peak import workers 8/8，5ms sampled peak/retained heap growth 125,097,504/553,888B，OS max RSS growth 138,985,472B，serving manifest 三次相同，replay `changed=false`。
- `go test ./internal/cli ./internal/upstream ./internal/catalog ./internal/repository -count=1 -timeout=40m` -- PASS 1720.604s / 3.817s / 5.070s / 5.994s；聚焦 adoption/CAS fast-path race 门禁 PASS，未报告竞态。
- `go vet ./...`、perf tag 编译与 `git diff --check` 均 PASS；最终 clean-delivery 身份在审查 patch 与文档冻结后重跑。
- 两个独立 `SOW_CLEAN_GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download test/compat/test-clean-delivery.sh ...` -- post-provenance/performance patch 均 PASS 且 archive `cmp=0`；product 534 files、delivery 677 files。当前完整身份只写入 repo 外交付验证记录，避免把交付 digest 嵌回交付内容形成自引用。
