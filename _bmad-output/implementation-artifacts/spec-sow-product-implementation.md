---
title: 'sow 产品完整实现'
type: 'feature'
created: '2026-07-11'
status: 'in-progress'
review_loop_iteration: 0
baseline_commit: 'NO_VCS'
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
- `internal/publish/`, `internal/remote/`, `internal/cdn/` -- per-target saga、S3/CAS、厂商 purge 与恢复。
- `internal/verify/`, `edge/`, `test/` -- L1–L4、机密负例、边缘契约、故障注入和真实客户端证据。
- `docs/requirements-traceability.md`, `docs/architecture.md`, `docs/adr/` -- 持续验收账本和冻结决策。

## Tasks & Acceptance

**Execution:**
- [ ] `go.mod`, `cmd/sow/`, `internal/cli/`, `internal/config/` -- 建立单二进制命令面、严格配置与选择器。
- [ ] `internal/state/`, `internal/repository/` -- 实现流式 manifest、Git refs、缓存重建、CAS、引用/GC、物化及零字节 init/fsck。
- [ ] `internal/aptrepo/`, `internal/yumrepo/` -- 实现标准索引、压缩、by-hash、单 key 纯 Go 签名和安全翻转。
- [ ] `internal/syncer/`, `internal/provenance/` -- 实现 APT/YUM 只加不删同步、过滤、断点重试、验签与收据。
- [ ] `internal/views/`, `internal/publish/`, `internal/remote/`, `internal/cdn/` -- 实现通道/快照/EOL/tgz 与双云独立事务、漂移、purge、恢复。
- [ ] `internal/verify/`, `edge/`, `test/` -- 建立 L1–L4、边缘共享契约、真实 apt/dnf/S3、跨平台和 5 万包性能证据。
- [ ] `docs/` -- 完成约 40 个旧目标映射、零字节迁移/回滚、部署恢复排障与最终审计报告。

**Acceptance Criteria:**
- Given 干净环境和无秘密示例配置，when 构建并执行全部命令与迁移流程，then Linux/macOS 单二进制可独立运行且无外部仓库工具依赖。
- Given APT/YUM/asset 真实夹具，when add/sync/promote/materialize/publish/verify/fsck，then 标准 apt/dnf 客户端可消费、历史可钉、事务可重放且证据可复现。
- Given gated 包和任意公开视图组合，when 生成或发布索引，then 机密性闭包 100% 阻断泄漏。
- Given 两个远端存在滞后、漂移和注入中断，when 重试 publish，then API 量随变更集增长、检查点无丢失更新且两目标互不阻塞。
- Given 追踪矩阵与最终审计，when 检查全部合同，then 不存在未实现、部分实现、仅设计、无证据通过或范围内保留项。

## Spec Change Log

## Design Notes

PRD 是范围合同，Addendum 是更具体技术裁决；研究报告只证明技术可行性，不能替代本地或真实环境 PoC。用户已在 Goal 中批准保留完整产品范围并禁止在规格检查点暂停，因此本规格直接进入开发；任何外部凭据缺口只阻塞相应真实云证据，不阻塞本地实现。

## Verification

**Commands:**
- `go test ./...` -- 单元、属性、集成、故障注入与 CLI E2E 全部通过。
- `go vet ./... && go build ./cmd/sow` -- 静态检查与本机构建通过。
- `GOOS=linux GOARCH=amd64 go build ./cmd/sow && GOOS=darwin GOARCH=arm64 go build ./cmd/sow` -- 目标平台交叉构建通过。
- `test/e2e/run-apt.sh && test/e2e/run-dnf.sh && test/e2e/run-s3.sh` -- 真实客户端与本地 S3 协议证据通过。
- `test/perf/run-50k.sh` -- 记录 5 万包吞吐、并行度、峰值内存与 API 计数。
