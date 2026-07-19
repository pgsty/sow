---
title: 'sow 产品完整实现'
type: 'feature'
created: '2026-07-11'
status: 'done'
review_loop_iteration: 0
baseline_commit: '84800a60e01aaaf8dc5b189c3ddb1380930f4865'
context:
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md'
  - '{project-root}/_bmad-output/planning-artifacts/research/technical-sow-repo-cli-tech-validation-research-2026-07-11.md'
  - '{project-root}/_bmad-output/brainstorming/brainstorm-sow-repo-cli-2026-07-11/brainstorm-intent.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 当前工程只有 IDE 示例代码，而 Pigsty 的 APT、YUM、asset 仓库仍依赖约 40 个 Makefile 目标、容器和人工发布步骤，无法满足状态可追溯、原子发布、商业机密门禁与历史钉版要求。

**Approach:** 实现一个零外部运行时依赖的 Go CLI，以 Git 承载的 manifest/ref 为正典、CAS 与可直接托管的物化树为数据面，并把索引、同步、视图、双目标发布、校验和边缘鉴权做成可恢复且可证据化验收的完整产品。

## Boundaries & Constraints

**Always:** 完整满足 G1–G6、FR-01–FR-42、NFR-01–NFR-09；manifest 是正典、SQLite 仅缓存；默认 O(变更集)；公开视图机密性闭包不可跳过；发布包含上传、翻转、purge、验证；latest URL 兼容；秘密仅经 env/CLI/secret provider；真实协议路径与 mock 测试并存。

**Ask First:** 真实 R2/COS/Cloudflare/EdgeOne 凭据与付费资源；会破坏现有远端或存量仓库的迁移；FR-17 商业 RPM 重签启动；用户未授权的生产发布。

**Never:** Python、Perl、gpg、createrepo_c、aptly 运行时；modulemd、zchunk、sqlite repodata、多 GPG key、造包、通用云抽象；把设计、stub、永真校验、mock-only 或局部里程碑当完成。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| 零字节纳管 | 存量发布树 | 生成排序 manifest、Git 基线和可重建缓存，不改发布字节 | 路径/读失败时无部分提交 |
| 增量变更 | add/rm/sync/promote + 选择器 | 更新 CAS、refs、索引和 manifest，stable/history 引用不被删除 | 事务日志可恢复，错误分类并非零退出 |
| 双目标发布 | cf/cos 可独立成功或失败 | 每目标差异上传、代际翻转、最小 purge、L2/L3 后独立推进 remote ref | 命令整体报告失败；成功目标不回滚，失败目标安全重放 |
| 机密泄漏 | public view 引用 gated 对象 | L1 必然失败且禁止发布 | 不允许 force/skip 绕过 |
| 中断/漂移 | 残留 journal 或 checkpoint 代际不符 | 检测、解释并幂等恢复 | CAS 冲突不覆盖远端 |

</frozen-after-approval>

## Code Map

- `cmd/sow/main.go`, `internal/cli/` -- 命令、选择器、帮助、退出码与依赖装配。
- `internal/config/`, `internal/state/` -- schema v1、manifest/ref、内嵌 Git 历史、SQLite 缓存与 checkpoint。
- `internal/repository/`, `internal/aptrepo/`, `internal/yumrepo/` -- CAS/物化/GC 与三类仓库引擎。
- `internal/syncer/`, `internal/provenance/` -- 累积同步、过滤、校验、断点与双条目收据。
- `internal/publish/` -- per-target saga、具体 S3/CAS 与厂商 purge SDK、checkpoint 和恢复。
- `internal/verify/`, `edge/`, `test/` -- L1–L4、机密负例、边缘契约、故障注入和真实客户端证据。
- `docs/requirements-traceability.md`, `docs/architecture.md`, `docs/adr/` -- 持续验收账本和冻结决策。

## Tasks & Acceptance

**Execution:**
- [x] `go.mod`, `cmd/sow/`, `internal/cli/`, `internal/config/` -- 建立单二进制命令面、严格配置与选择器。
- [x] `internal/state/`, `internal/repository/` -- 实现流式 manifest、Git refs、缓存重建、CAS、引用/GC、物化及零字节 init/fsck。
- [x] `internal/aptrepo/`, `internal/yumrepo/` -- 实现标准索引、压缩、by-hash、单 key 纯 Go 签名和安全翻转。
- [x] `internal/syncer/`, `internal/provenance/` -- 实现 APT/YUM 只加不删同步、过滤、断点重试、验签与收据。
- [x] `internal/views/`, `internal/publish/` -- 实现通道/快照/EOL/tgz 与双云独立事务、漂移、purge、恢复。
- [x] `internal/verify/`, `edge/`, `test/` -- 建立 L1–L4、边缘共享契约、真实 apt/dnf/S3、跨平台和 5 万包性能证据。
- [x] `docs/` -- 完成约 40 个旧目标映射、零字节迁移/回滚、部署恢复排障与持续审计账本。

Execution tasks are implemented; local legacy corpus repair and the current
`yum/infra` 216-RPM S0→S3 compatibility path are closed. Acceptance remains
open for the remaining inactive builder/gated handoff, dedicated
non-production provider/edge evidence, and production migration/revocation
recorded in `docs/requirements-traceability.md`. Checked execution boxes are
not a Goal completion declaration.

**Acceptance Criteria:**
- Given 干净环境和无秘密示例配置，when 构建并执行全部命令与迁移流程，then Linux/macOS 单二进制可独立运行且无外部仓库工具依赖。
- Given APT/YUM/asset 真实夹具，when add/sync/promote/materialize/publish/verify/fsck，then 标准 apt/dnf 客户端可消费、历史可钉、事务可重放且证据可复现。
- Given gated 包和任意公开视图组合，when 生成或发布索引，then 机密性闭包 100% 阻断泄漏。
- Given 两个远端存在滞后、漂移和注入中断，when 重试 publish，then API 量随变更集增长、检查点无丢失更新且两目标互不阻塞。
- Given 追踪矩阵与最终审计，when 检查全部合同，then 不存在未实现、部分实现、仅设计、无证据通过或范围内保留项。

## Spec Change Log

- 2026-07-16：owner 冻结 apt 最低 1.2、EL8 自 Pigsty v5.0.0 起 frozen；记录于 ADR-0029。
- 2026-07-16：fresh-copy 关闭 PGDG 30,274 missing-path corpus、完整 APT/YUM/asset 纳管、真 DNF、fsck/GC；修复 SQLite spool 多连接 writer，并用后续 660 项 ordinary/race 分片复验。历史 `yum/infra` builder-signed input gap 已由下一条 current-source exact-copy 证据关闭；剩余范围内阻断为专用非生产双云/边缘证据、inactive builder/gated handoff 和生产迁移/撤权窗口。
- 2026-07-17：当前只读 `yum/infra` 234-file 快照确认 216/216 RPM 已由 Pigsty key 签名；精确副本完成双架构 S0→S3、EL8/9/10 raw/strong DNF、L1/fsck/replay，并修复 carrier-wide manifest 对单 arch Nginx route 的错误比较。生产源未改，生产云未用；剩余边界为 inactive builder/gated handoff、专用非生产双云/边缘和生产迁移/撤权。
- 2026-07-18：审查修复成功命令吞掉状态锁释放错误，以及 readiness→bootstrap 间外来对象/provider-control 漂移窗口；普通/race、完整离线 compat、静态检查与双份干净交付通过。真实 POC-06 尚未执行，规格继续保持 `in-review`。
- 2026-07-19：当前源码在 owner 授权的空非生产 `cf:pro` 桶复验 R2 storage 与 main/beta raw custom-domain data-plane（最终 31.19s，退出后整桶为空）：当前对象两域精确 `MISS`，bucket 删除后仍 exact `HIT` 且 `max-age=1800`，因此只记为 purge 不可省略的负能力证据；同时让 CAS 物化最终 parent-cache/根绑定、bound Git parent、APT/YUM body spool 与 YUM history storage 的关闭失败进入返回错误，并保持主错误和 `os.IsNotExist` 分类。678 个 CLI 测试六分片 ordinary/race、non-CLI ordinary/race、真 apt/dnf/Nginx、静态/漏洞/edge/四平台及双份 clean-delivery 均通过。该复验仍不冒充 Worker/purge/negative verify、COS/EdgeOne 或完整 POC-06，规格继续保持 `in-review`。
- 2026-07-19：修复 confidential publication 可在 raw public custom domain 上先上传 `.sow/gated/` 再由 L3 失败的机密性窗口。两个 concrete provider 现在对任何 gated/Basic plan 在 journal、checkpoint 和首个远端 mutation 前匿名验证精确 `sow-edge-runtime/v2` 私有 404；public-only plan 零额外网络，caller CookieJar 既不能授权 canary 也不能污染 L3 read-back。真实 provider/CLI 故障注入证明 raw/redirect/旧 runtime/公开缓存等失败时 PUT/Copy/Delete/purge 为 0；共享 Cloudflare/EdgeOne 合同增至 42 项。owner 授权的 main/beta raw R2 域由产品 helper 真实只读负测并按预期拒绝，桶随后仍为空。最终 679 个 CLI ordinary/race 六分片、全部 non-CLI ordinary/race、vet/Staticcheck、双模块完整性/漏洞、四平台构建与两份 536-product/682-delivery 确定性 clean-delivery 均通过；身份记录在 external V-14/V-23 ledger。这不冒充 Worker 部署、private origin、purge/negative verify、COS/EdgeOne 或 POC-06 完成，规格继续保持 `in-review`。见 ADR-0037/V-23。

## Design Notes

PRD 是范围合同，Addendum 是更具体技术裁决；研究报告只证明技术可行性，不能替代本地或真实环境 PoC。用户已在 Goal 中批准保留完整产品范围并禁止在规格检查点暂停，因此本规格直接进入开发；任何外部凭据缺口只阻塞相应真实云证据，不阻塞本地实现。

## Verification

**Commands:**
- non-CLI `go test -count=1`/`go test -race -count=1` 与六个 `internal/cli` ordinary/race shard -- 单元、属性、集成、故障注入与 CLI E2E；CLI 大包按 CI 穷尽分片，避免 Go 单包默认 10 分钟闹钟。
- `go vet ./...`、`go mod verify`、`go mod tidy -diff`、nested RPM module provenance -- 静态、依赖与 fork 边界。
- `CGO_ENABLED=0 GOOS=<linux|darwin> GOARCH=<amd64|arm64> go build -trimpath ./cmd/sow` -- 四目标静态构建；Linux/arm64 另在 `--network none` 容器运行。
- `SOW_RUN_DOCKER_COMPAT=1 SOW_COMPAT_NGINX=1 go test -v ./test/compat` 与 `SOW_MINIO_TEST=1 ... TestMinIOS3Compatibility` -- 真 apt/dnf/Nginx 与本地 S3。
- `SOW_RUN_PERF=1 ... TestGenerateStreaming50000Performance`、`go test -tags perf ./test/perf`、`TestStrongYUMServingFiftyThousand` -- 5 万包吞吐、并行度和内存。
- `docs/migration/test-*.sh` -- 物理配置、旧 target、44-family、writer fence、consumer stage/apply/replay/rollback。

完整命令、严格离线环境和当前实测值以
`docs/evidence/2026-07-16-current-source-validation.md` 为准。

## Suggested Review Order

**产品主干**

- 先读不变量、正典状态与边界，再进入具体命令。
  [`architecture.md:28`](../../docs/architecture.md#L28)

- 单 CLI 入口集中分派命令并统一退出码。
  [`app.go:34`](../../internal/cli/app.go#L34)

- 严格 schema 冻结可配置能力与供应商边界。
  [`config.go:45`](../../internal/config/config.go#L45)

- Git worktree 是 manifest/ref 正典事务核心。
  [`store.go:22`](../../internal/state/store.go#L22)

**仓库生命周期**

- CAS 导入以摘要、长度与不可变路径固定制品身份。
  [`cas.go:34`](../../internal/repository/cas.go#L34)

- APT 生成器统一 Packages、Release、InRelease 与 by-hash。
  [`build.go:91`](../../internal/aptrepo/build.go#L91)

- YUM 生成器流式产生三类 repodata 与签名代际。
  [`generation.go:33`](../../internal/yumrepo/generation.go#L33)

- Sync 把发现、过滤、下载、provenance 与恢复连成事务。
  [`sync.go:175`](../../internal/cli/sync.go#L175)

**发布与访问控制**

- Per-target saga 封装差异、翻转、purge、验证与重放。
  [`saga.go:156`](../../internal/publish/saga.go#L156)

- Confidential plan 在任何远端 mutation 前证明 edge v2 的匿名私有拒绝语义。
  [`http_object.go:798`](../../internal/publish/http_object.go#L798)

- CLI 发布入口收敛选择器、恢复与双目标独立推进。
  [`publish.go:277`](../../internal/cli/publish.go#L277)

- L1–L4 runner 统一并行、上限与失败级别。
  [`model.go:254`](../../internal/verify/model.go#L254)

- 共享边缘合同执行 token、剥离与干净 URL 归一化。
  [`contract.mjs:30`](../../edge/shared/contract.mjs#L30)

**恢复与危险边界**

- 持久进程实例租约保护本地单写者与崩溃恢复。
  [`lock.go:427`](../../internal/state/lock.go#L427)

- 锁释放失败成为命令失败，不再只发 warning。
  [`state_lock_release.go:15`](../../internal/cli/state_lock_release.go#L15)

- Bootstrap 每次写前复核 lease-only 桶与 provider 闭包。
  [`real_cloud_cloudflare_bootstrap_test.go:656`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L656)

- Readiness loader 只返回同一次 Ed25519 校验的 receipt 字节。
  [`real_cloud_provider_readiness_test.go:701`](../../test/compat/real_cloud_provider_readiness_test.go#L701)

**迁移与验收证据**

- 需求账本明确区分已验证、未验证和外部受阻。
  [`requirements-traceability.md:32`](../../docs/requirements-traceability.md#L32)

- Bootstrap 与 provider log-sink 的可复用 R2 租约只以 conditional Put CAS 为 idle marker，
  接口不再授予 DeleteObject，stale holder 无法删除新持有者。
  [`real_cloud_cloudflare_bootstrap_test.go:824`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L824)

- 旧 Makefile 目标映射提供可执行替代与回滚门禁。
  [`make-target-map.md:239`](../../docs/migration/make-target-map.md#L239)

- 锁与云 bootstrap 负例记录最后一次干净交付身份。
  [`validation-selected-set-materialization-2026-07-13.md:910`](validation-selected-set-materialization-2026-07-13.md#L910)

- 辅助单测证明 release 失败传播且保留主错误。
  [`audit_fixes_test.go:194`](../../internal/cli/audit_fixes_test.go#L194)

- 云负例证明闭包漂移时内层 mutation 调用为零。
  [`real_cloud_cloudflare_bootstrap_test.go:1937`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L1937)
