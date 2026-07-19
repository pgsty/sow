---
title: '33-selector 合成物理仓库迁移 E2E'
type: 'feature'
created: '2026-07-14'
status: 'in-review'
review_loop_iteration: 0
baseline_commit: '84800a60e01aaaf8dc5b189c3ddb1380930f4865'
context:
  - '{project-root}/docs/migration/fixtures/selector-matrix.yaml'
  - '{project-root}/_bmad-output/implementation-artifacts/spec-legacy-pigsty-v1-migration-hardening.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 当前迁移证据只把 33 个 repo ID 作为 selector universe，而物理 adoption 仅覆盖固定 12-repo 子集；这不能证明全 selector 配置能从真实可解析制品和索引一次性零改写纳管。

**Approach:** 在临时目录为 selector matrix 的 12 asset、11 APT、10 YUM repo 构造最小真实 serving tree，用真实 SOW CLI 一次性 adoption 并验证 canonical state、CAS、SQLite、candidate materialization、幂等与本地回滚。

## Boundaries & Constraints

**Always:** 使用真实可解析 amd64/arm64 DEB、真实签名 RPM、Packages、repomd/primary 与 repository signature；无 `--repo` 执行全 selector `init --adopt-content`；源 repo manifests 在 adoption、重放、materialize 和 rollback 前后逐字节一致；断言 33 repos、73 leaves、53 payload receipts，以及 canonical/cache rebuild 一致。

**Ask First:** 只有发现必须修改产品 adoption 语义、配置冻结契约或需要真实供应商资源时暂停。

**Never:** 访问 CO/COS/CF 或任何实网；使用生产路径、生产 URL/凭据、空包、伪索引或 Mock CLI；把合成 fixture 称为旧生产树实测；修改真实 `/Users/vonng/pgsty/repo`。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| 全 selector adoption | 无 `.sow/.pool/_sow` 的 33-repo 合成真实树 | 53 payload、73 physical leaves、latest+stable 146 memberships，源树零改写 | 任一 selector/index/body 不闭合则测试失败 |
| 幂等重放 | 相同 config 与源树 | `changed=false`，HEAD、refs、receipts、cache stats 不变 | 不允许新 commit 或 source mutation |
| candidate/rollback | 真实签名 materialize 后切换到候选，再回旧 root | APT/YUM/asset 布局可验证；候选故障后旧树摘要恢复且重复回滚安全 | 候选不能污染旧 root |
| 网络逃逸 | `.invalid` URL 与拒绝连接 proxy | 所有命令本地通过，provider opt-in 始终关闭 | 任一联网依赖都会立即失败 |

</frozen-after-approval>

## Code Map

- `internal/cli/migration_all_selector_e2e_test.go` -- 构造与验证 33-selector 真实合成 serving tree，调用真实 CLI。
- `docs/migration/fixtures/selector-matrix.yaml` -- 33 repo 的冻结选择器、路径、suite/arch/compression 与本地无效端点。
- `internal/cli/adopt_content_test.go` -- 复用真实 key/RPM/CLI/legacy metadata helper 与现有边界。
- `docs/evidence/2026-07-14-legacy-family-e2e.md` -- 记录合成物理闭环与不等于生产迁移的边界。
- `internal/yumrepo/types.go` / `internal/cli/{yum,materialize_metadata}.go` -- 显式 frozen EL7 gzip 策略及两条 CLI 生成/激活接线。
- `docs/adr/0019-frozen-el7-yum-metadata-compatibility.md` -- 冻结兼容例外、拒绝边界与非生产等价声明。

## Tasks & Acceptance

**Execution:**
- [x] `internal/cli/migration_all_selector_e2e_test.go` -- 新增全 selector physical CLI E2E 与 manifest/ref/CAS/cache/candidate/rollback 断言。
- [x] `docs/migration/fixtures/selector-matrix.yaml` -- 仅补齐真实 RPM trust 所需配置，不改变 33 repo universe。
- [x] `docs/evidence/2026-07-14-legacy-family-e2e.md` -- 更新可复现命令、计数和诚实限制。
- [x] `internal/config` / `internal/yumrepo` / `internal/cli` -- 仅 frozen EL7 gzip 例外；active EL7、zstd、EL1-6、EL11+、modulemd 继续拒绝。

**Acceptance Criteria:**
- Given 33 个 selector 的合成真实物理树，when 在 invalid proxy 下运行真实 CLI adoption/replay/fsck/materialize/rollback，then 全部本地通过、源 bytes 不变、canonical/CAS/SQLite 与签名 metadata 精确闭合，且证据明确不冒充生产旧树。

## Spec Change Log

- 2026-07-14：全 selector 首次 materialize 暴露 `yum-pgsql-el7` 已在冻结迁移配置中，
  但通用 generator 只接受 EL8-10。经父任务明确授权，新增 ADR-0019 的最窄
  frozen+gzip Options 例外，并保持 `CompressionForEL(7)`、active/zstd/modulemd 拒绝；
  已知坏状态是把 EL7 普遍加入活跃支持矩阵或只把失败写成负例却继续声称命令等价。
  KEEP：全 33 selector adoption/fsck、真实 parser、source byte 不变、无云边界。
- 2026-07-14：审查发现原 YUM 合成源只有 zstd primary。fixture 改为按 repo policy
  生成完整 primary/filelists/other 后仅把 primary location 还原为 legacy flat RPM，重算
  repomd 和签名；source files 从 152 修正为 190。

## Design Notes

一个 repo 只保存每种架构一个 DEB，允许多个 suite 的真实 Packages 共同引用；每个 YUM arch leaf 使用同一真实 `noarch` RPM，但各自有独立且 compression 匹配的 primary/filelists/other、repomd/signature。candidate 先由产品建立 baseline，删 payload 后必须由产品 fsck 检出；切换用同目录临时 symlink + rename，不用 remove+symlink 的非原子窗口。该 fixture 只证明 selector-generalization，不代表旧 vendor 多-major 物理拓扑。

## Verification

**Commands:**
- `go test -count=1 ./internal/cli -run '^TestInitAdoptContentSynthetic33RepoGeneralization$' -v` -- ordinary 全闭环通过。
- `go test -race -count=1 ./internal/cli -run '^TestInitAdoptContentSynthetic33RepoGeneralization$'` -- 无竞态。
- `docs/migration/test-family-e2e.sh` -- 44 family、14 个业务 E2E、4 个突变负例全部通过。
- `go vet ./internal/config ./internal/yumrepo ./internal/cli && git diff --check` -- 静态与补丁检查通过。
