---
title: 'Bound configuration input and restore RPM vendor provenance'
type: 'bugfix'
created: '2026-07-20'
status: 'done'
review_loop_iteration: 0
baseline_commit: '93907d315dfcf4c0e2df18043669656f4804ee35'
context:
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md'
  - '{project-root}/docs/requirements-traceability.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** `sow.yaml` 在严格校验前仍会无界读入内存；vendored `cavaliergopher/rpm` 快照也存在一个未获批准的逐字节漂移。两者都会绕开发布输入的资源或来源边界。

**Approach:** 对所有共享配置入口统一实施 8 MiB、带一字节哨兵的解析前上限，并证明超限 CLI 在任何 `.sow` 状态创建前以配置错误失败；把 RPM fixture 恢复为固定 `v1.3.0` 上游原字节，不扩大允许 patch 集。

## Boundaries & Constraints

**Always:** 上限先于 YAML/schema/default；恰好 8 MiB 正常处理，8 MiB + 1 稳定拒绝；外部和历史 `config/sow.yaml` 共用边界；CLI 保持 `ExitConfig` 且不改 `.sow/.pool`；RPM gate 继续绑定 `v1.3.0`、既有 module sum 和非 allowlist 逐字节比较。

**Ask First:** 修改 8 MiB 合同、RPM 版本或 patch allowlist，引入运行时依赖，或写真实云/生产仓库。

**Never:** 静默截断、先解析后限流、扩大 allowlist 掩盖漂移、记录秘密，或访问 CO/COS/Cloudflare 正式生产资源。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| 正常配置 | 有效且小于上限的 `sow/v1` YAML | 与现有 schema/default 行为一致 | N/A |
| 精确边界 | 有效配置加注释填充至恰好 8 MiB | 正常解码 | N/A |
| 超限输入 | 任意 8 MiB + 1 字节流 | 不进入 YAML 解析，返回稳定大小错误 | CLI 退出 `ExitConfig`，不创建 `.sow` |
| Vendor 漂移 | 非 allowlist 文件与固定上游任意字节不同 | provenance gate 失败并指出相对路径 | 恢复上游字节；不得扩大 allowlist |

</frozen-after-approval>

## Code Map

- `internal/config/config.go` -- 所有外部 `sow.yaml` 的共享读取、解析和严格 schema 入口。
- `internal/state/transaction.go`, `internal/cli/app.go` -- canonical HEAD baseline 的声明大小与实际流式读取上限。
- `internal/cli/{publish_restore,asset_projection_contract,package_repository_contract,yum_compat_contract,yum_compat_workflow,materialize_route_receipts}.go` -- 历史 canonical config 读取路径。
- `internal/config/config_test.go`, `internal/cli/*test.go` -- 精确边界、退出码及空仓/存量仓零变更证明。
- `third_party/cavaliergopher-rpm/verify-upstream.sh` -- 固定版本、module sum 和非 allowlist 逐字节来源门禁。
- `third_party/cavaliergopher-rpm/testdata/RPM-GPG-KEY-CentOS-5` -- 本次恢复为上游原字节的 fixture。
- `test/compat/cleandelivery/` -- 在抽取归档中重跑 RPM provenance，并验证确定性交付。
- `README.md`, trace/evidence -- 操作者合同与验证账本。

## Tasks & Acceptance

**Execution:**
- [x] `internal/config/config.go` -- 以 `MaxConfigBytes+1` 哨兵有界读取，并在解析前拒绝超限输入。
- [x] `internal/config/config.go` -- 拒绝默认展开/规范化后超过同一上限的 canonical YAML，并让 sentinel 大小错误优先于同次 terminal read error。
- [x] `internal/state/transaction.go`, `internal/cli/app.go` -- 在外部配置打开前有界计算 canonical HEAD baseline identity。
- [x] `internal/cli/` -- 让所有 canonical config pre-read 使用同一 8 MiB helper/常量。
- [x] `internal/config/config_test.go`, `internal/cli/*test.go` -- 覆盖精确边界、超限错误、退出码及 `.sow/.pool/HEAD` 零变更。
- [x] `third_party/cavaliergopher-rpm/testdata/RPM-GPG-KEY-CentOS-5` -- 恢复固定上游字节并让现有 provenance gate 通过。
- [x] `test/compat/cleandelivery/main.go` -- 在抽取后的交付树执行 RPM provenance gate。
- [x] `README.md`, trace/evidence 与交付 allowlist -- 冻结证据，不升级真实云状态。

**Acceptance Criteria:**
- Given 任意配置消费者，when 输入超过 8 MiB，then 在 YAML 解析前得到稳定配置错误且读取量不超过上限加一字节。
- Given 空仓或已初始化仓，when `sow init` 读取超限文件，then 返回 `ExitConfig`，且 `.sow/.pool`、HEAD 和 canary 不变。
- Given reachable history 中存在超限 canonical config，when 历史合同读取，then 在统一 pre-read 边界失败关闭。
- Given 固定 `cavaliergopher/rpm@v1.3.0` module，when provenance script 比较本地快照，then 仅既有显式 patch 可漂移，所有 fixture 逐字节一致。
- Given 最终源码，when ordinary/race、静态、模块、vendor、迁移与双份 clean-delivery 门禁执行，then 全部通过且不触达任何生产仓库或云资源。

## Spec Change Log

## Design Notes

读取 `limit+1` 可区分合法边界与截断输入；同次读取既达到 sentinel 又返回 terminal error 时，稳定的超限错误优先。验证后的结构还必须能规范化为不超过同一上限的 canonical YAML，避免提交后自锁。RPM 修复只恢复缺失的最终空行，patch allowlist 不变。provenance 脚本以源码内固定 h1 为权威、每次使用 fresh GOMODCACHE extraction 并关闭外部 checksum service，使抽取交付可仅凭只读 module proxy 离线重放；下载 zip 仍须同时满足固定 h1 与逐文件比较。

## Verification

**Commands:**
- `go test -count=1 ./internal/config ./internal/cli -run 'OversizedConfig|ConfigAtSizeLimit|CanonicalConfigReader|PackageRepositoryHistoryRejects'` -- expected: 全部边界通过。
- `go test -race -count=1 ./internal/config ./internal/cli -run 'OversizedConfig|ConfigAtSizeLimit|CanonicalConfigReader|PackageRepositoryHistoryRejects'` -- expected: 无数据竞争。
- `bash third_party/cavaliergopher-rpm/verify-upstream.sh && (cd third_party/cavaliergopher-rpm && go test -count=1 ./... && go vet ./...)` -- expected: 固定来源与嵌套模块通过。
- `go vet ./... && go vet -tags perf ./internal/cli ./test/perf` -- expected: 无诊断。
- `SOW_CLEAN_GOPROXY=file:///read-only/module-proxy test/compat/test-clean-delivery.sh <isolated-root-a>`；对独立 `<isolated-root-b>` 重复，然后 `cmp` 两份归档 -- expected: 两次 fresh 重建的 file count、product/delivery/archive SHA 与归档字节完全一致。

## Suggested Review Order

**配置资源边界**

- 共享入口在解析前限读，并验证 canonical 展开仍满足同一上限。
  [`config.go:362`](../../internal/config/config.go#L362)

- Git blob 声明大小与实际流同时失败关闭。
  [`transaction.go:46`](../../internal/state/transaction.go#L46)

- CLI 在打开外部 YAML 前有界捕获 canonical baseline。
  [`app.go:1073`](../../internal/cli/app.go#L1073)

- 历史消费者统一经过单一 canonical 配置读取器。
  [`publish_restore.go:418`](../../internal/cli/publish_restore.go#L418)

- package history 图扫描复用相同共享上限。
  [`package_repository_contract.go:484`](../../internal/cli/package_repository_contract.go#L484)

**RPM 来源闭包**

- 固定 h1 与 fresh module cache 阻止缓存自证。
  [`verify-upstream.sh:4`](../../third_party/cavaliergopher-rpm/verify-upstream.sh#L4)

- 精确 fixture 字节免受 checkout 文本转换影响。
  [`.gitattributes:1`](../../.gitattributes#L1)

- 抽取后的交付树必须重跑 RPM provenance。
  [`main.go:303`](../../test/compat/cleandelivery/main.go#L303)

**负例与验收**

- Reader 边界覆盖 sentinel、terminal error 与 canonical 膨胀。
  [`config_test.go:24`](../../internal/config/config_test.go#L24)

- 真实 CLI 证明空仓与存量仓均零变更失败。
  [`app_test.go:403`](../../internal/cli/app_test.go#L403)

- 超限 Git blob 拒绝且兼容 API 保持原行为。
  [`transaction_test.go:1190`](../../internal/state/transaction_test.go#L1190)

- 当前实跑结果与明确边界集中在证据报告。
  [`2026-07-20-config-input-and-rpm-provenance-hardening.md:1`](../../docs/evidence/2026-07-20-config-input-and-rpm-provenance-hardening.md#L1)
