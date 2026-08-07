---
title: 'SOW v0.2.0 完工验收与本地封版'
type: 'chore'
created: '2026-08-05'
status: 'done'
review_loop_iteration: 0
context:
  - '{project-root}/design/v0.2/specs/spec.md'
  - '{project-root}/design/v0.2/evidence/2026-08-02-p1-p3-acceptance.md'
  - '{project-root}/design/v0.2/evidence/2026-08-02-p1-p3-traceability.md'
---

> **Historical v0.2 release record.** 该冻结任务只解释 tag `v0.2.0` 的源码、验收和本地
> 封版，不是下一版 layout/publish 合同；前向权威见 [`../next/`](../next/)。

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 当前 P0–P3 实现尚未形成可从干净 Git 快照重建的正式版本：根目录缺少统一开发入口，版本仍为开发态，工作区还混有未提交成果、内部设计材料及本地环境噪音。

**Approach:** 补齐 Makefile、发布版本面和使用文档；精确分类并清理工作区；从当前源码重新执行完整验收，通过后形成聚焦提交并创建本地注释标签 `v0.2.0`。

## Boundaries & Constraints

**Always:** 保留 P0–P3 正式源码、测试、契约、设计和验收证据；公开文档以独立 `sow.pgsty.com` checkout 为权威，本仓库内部材料统一进入 `design/`；只对已枚举且确认是环境噪音的路径做可恢复清理；`make test` 必须代表完整测试而非缩小范围；标签只能在当前提交全部门禁通过且工作区干净后创建；源码默认版本、构建注入版本和发布产物版本必须一致为 `0.2.0`；区分源码提交、本地标签、构建产物和远端发布四层证据。

**Ask First:** 发现必须改变已批准 P0–P3 外部行为、删除可能属于用户创作成果的文件、需要改写既有 Git 历史，或需要推送/发布到远端时暂停确认。

**Never:** 使用宽泛的 `git clean`、递归删除未验证目录、触碰 `~/pgsty/repo` 生产仓库、以 8 月 2 日旧验收代替当前 checkout 重测、在无远端且未授权时声称已发布。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| 本地开发 | `make build` 或 `make run ARGS=version` | 生成可执行文件；运行输出报告 `0.2.0` | Go 构建或程序失败时目标非零退出 |
| 完整测试 | `make test` | 对 `./...` 执行非缓存完整测试并设置合理超时 | 任一包失败即阻止封版 |
| 发布构建 | `make release` | 在 `dist/` 生成 Linux/macOS、amd64/arm64 四种带版本二进制及 `SHA256SUMS` | 任一交叉构建或校验生成失败时不产生成功结论 |
| 环境清理 | 工作区含 IDE、Finder 或生成式会话文件 | 仅移走已核验噪音，正式成果保留并纳入提交 | 遇到链接、路径越界、文件归属不明时停止 |
| 重复执行 | 已存在 `bin/`、`dist/` | 构建目标可重复运行，`make clean` 只处理这两个受管目录 | 不删除其他缓存或用户文件 |

</frozen-after-approval>

## Code Map

- `Makefile` -- 根目录统一的开发、检查、清理和发布入口。
- `internal/v2cli/help.go` -- CLI 默认版本及 `sow version` 输出。
- `.gitignore` -- 保留用户指定的 `docs/` 边界，并忽略构建产物和真实本地噪音。
- `README.md`、`CHANGELOG.md` -- v0.2 当前命令面、快速开始和版本说明。
- `test/compat/cleandelivery/*.txt` -- 干净交付文件清单，纳入新增根文件与正式文档。
- `design/v0.2/evidence/2026-08-05-release.md` -- 当前 checkout 的封版命令与结果证据。

## Tasks & Acceptance

**Execution:**
- [x] `Makefile` -- 实现 `help build run install test test-v2 vet lint check clean-delivery release clean`，并让默认目标可发现。
- [x] `internal/v2cli/help.go` -- 将默认版本封为 `0.2.0`，同时保留链接期覆盖能力。
- [x] `.gitignore`、`test/compat/cleandelivery/*.txt` -- 保留 `docs/` 忽略规则，登记 Makefile、README、CHANGELOG、`design/` 与发布证据，忽略 `bin/`、`dist/`。
- [x] `README.md`、`CHANGELOG.md` -- 以 v0.2 P0–P3 真实 CLI 替换过时 V1 指导，并说明本地发布边界。
- [x] 工作区 -- 枚举 `.DS_Store`、IDE 元数据和非产品会话日志；安全移出仓库，不删除正式规划/评审成果。
- [x] Git -- 检查完整 diff，形成可审计的功能/封版提交；所有验证成功后创建本地注释标签 `v0.2.0`。

**Acceptance Criteria:**
- Given 新开发者位于仓库根目录，when 执行 `make help/build/run/test/release/clean`，then 每个入口语义明确、可运行且失败会传播非零状态。
- Given `make release` 成功，when 检查四个产物，then 它们的平台架构、版本输出和 `SHA256SUMS` 全部匹配。
- Given 当前 checkout，when 执行格式、vet、staticcheck、完整普通测试、核心 race、clean-delivery 和封版归档回放，then 全部门禁通过且证据写入正式文档。
- Given 封版完成，when 检查 Git，then 工作区干净、`v0.2.0` 为注释标签并指向验收通过的封版提交；无远端推送或公开发布声明。

## Spec Change Log

- 2026-08-05: 用户明确公开文档权威位置是独立 `sow.pgsty.com` checkout；保留 `.gitignore` 的 `docs/` 规则，并把本轮内部材料迁入 `design/`，避免错误覆盖用户拥有的文档边界。

## Verification

**Commands:**
- `make check` -- 格式、静态检查、核心测试和交付清单通过。
- `make test` -- 当前 checkout 的 `go test -count=1 ./...` 全绿。
- `make race` -- v0.2 核心并发路径通过 race detector。
- `make release` -- 四平台产物和校验文件生成成功。
- `test/compat/test-clean-delivery.sh` -- 干净源归档可构建、可测试且无越界文件。
- 从 `git archive v0.2.0` 解包后执行 `make build test-v2 release` -- 标签快照可独立重建，版本为 `0.2.0`。
- `git status --short`、`git tag -n v0.2.0` -- 工作区干净且本地注释标签存在。
