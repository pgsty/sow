---
title: '闭合 offline archive residue 的 exact 删除权'
type: 'bugfix'
created: '2026-07-22'
status: 'done'
review_loop_iteration: 0
baseline_commit: 'cbeb439'
context:
  - '{project-root}/_bmad-output/implementation-artifacts/deferred-work.md'
  - '{project-root}/docs/requirements-traceability.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** `cleanupOfflineArchiveProjectionResidue` 对 state-root intent temp 与 0444 archive stage orphan 都执行 `ReadDir/Lstat -> Root.Remove(path)`；并发换包可让恢复删除未经准入的 replacement。intent temp 名称还只检查宽泛 prefix。

**Approach:** 以严格 derived-state temporary grammar 或 exact archive-stage final grammar 决定候选；在 bound root 中 no-follow/nonblocking 打开并保留 descriptor/inode，使用 no-replace quarantine 提交删除，在最终 unlink 前复核 coordinate/inode/type/mode/size/mtime。替换或 root/stage-directory 漂移失败关闭并恢复 replacement。

## Boundaries & Constraints

**Always:** 非 `--recover` 只报告 residue、不删除；`--recover` 只处理严格名称。state-root temp 保持 1 MiB 上限与 0600 private 合同；archive stage 只接受 0444 regular file。删除必须 fsync 精确父目录并在前后验证 root coordinate。多个 residue 按确定顺序处理，首个冲突停止且不误删 replacement。

**Ask First:** 改变 offline archive intent/stage schema、改变孤儿保留策略、访问云或生产资源。

**Never:** `Lstat` 授权后用 pathname 删除；follow symlink/FIFO/device；把未知 prefix 当合法 temp；按内容相同授权 replacement；整 archive 入内存；依赖 chmod 制造测试结果。

## I/O & Edge-Case Matrix

| 场景 | 预期 | 失败闭包 |
|---|---|---|
| 无 residue | 幂等成功 | 无 mutation |
| 合法 temp/stage，未 recover | 要求 `--recover` | 文件不变 |
| 合法 temp/stage，recover | exact quarantine→unlink→fsync | 只删准入 inode |
| bind 后同/异字节换包 | 拒绝 | replacement 原位存活，原 inode 不误删 |
| symlink/FIFO/错误 mode/超限 temp | 拒绝 | 不阻塞、不 follow |
| malformed temp prefix | unsafe error | 不忽略、不删除 |
| root/stage dir 换包 | 拒绝 | detached tree 不冒充成功 |

</frozen-after-approval>

## Code Map

- `internal/cli/offline_archive_projection_intent.go` -- residue scanner 与 bound cleanup。
- `internal/cli/projection_intent_remove.go` -- shared no-replace quarantine commit primitive。
- `internal/cli/materialize_archive_scanner_hardening_test.go` -- replacement、grammar、special-file、恢复回归。

## Tasks & Acceptance

**Execution:**
- [x] 严格分类 intent temp 与 0444 stage orphan，未知相邻名称 fail closed。
- [x] 从已绑定 state/stage root 准入 descriptor/inode，并复用 exact quarantine commit。
- [x] 为 temp/stage bind 后换包、malformed、FIFO/symlink、root replacement 与幂等恢复增加测试。
- [x] 更新 deferred、traceability、evidence 与 clean-delivery；完成 ordinary/race/full/static/cross-platform 门禁。

**Acceptance Criteria:**
- Given 一个已准入 residue，when coordinate 在删除提交前被 replacement 占用，then cleanup 失败且 replacement 原位存活。
- Given 合法 intent temp 或 0444 stage orphan，when `--recover`，then 只删除 exact inode、同步精确父目录并可幂等重放。
- Given malformed/special/unsafe residue，when 扫描，then 有界、无阻塞、零误删地失败关闭。

## Spec Change Log

- 无 frozen intent 变更。实现审查只补齐原契约内的 repeated quarantine、原 coordinate absence、durable intent owner、no-delete root 与 creation-time exact mode 边界。

## Design Notes

删除权在 descriptor bind 时产生，不从目录枚举或 pathname 继承；枚举只提供候选名称。archive stage 的 0444 模式与普通 private derived-state residue 的 0600 合同不同，因此共享 quarantine commit，但使用显式 stage admission policy。

## Verification

**已完成：**
- focused ordinary/race：`13.589s` / `20.383s`；新增高风险集合 50 次重放 `4.748s`。
- offline archive/derived-state 相邻 ordinary/race：`63.351s` / `83.872s`。
- inherited `umask 0500` 子进程创建 exact `0700` directory + `0600` file：10 次 ordinary `1.223s`、race `2.844s`。
- focused coverage：scanner 86.9%，exact policies/parser/classifier 100%，binder 86.7%，remover 76.7%，shared commit 76.3%，writer 72.4%。
- `go vet ./internal/cli`、`staticcheck ./internal/cli`、`git diff --check` 与 standalone clean-delivery `2.135s` 通过。
- Darwin/Linux amd64/arm64 静态 test build 与 Linux arm64 root、read-only、network-none 容器 focused set 通过。
- `go test ./... -count=1 -timeout=30m` -- CLI `1370.025s`，全部功能包、compat 与 clean-delivery 通过。
- 完整命令、红测与外部边界见 [V-79 evidence](../../docs/evidence/2026-07-22-offline-archive-residue-removal-identity.md)。

## Review Disposition

- Blind Hunter：`[]`。
- Edge Case Hunter：`[]`。
- 审查中发现并关闭 stable quarantine base、原 coordinate reoccupation、intent ownership、no-delete root/stage absence、post-write mode 与 inherited owner-execute umask 边界。
- 未改变 frozen intent；`review_loop_iteration: 0`。

## Suggested Review Order

1. [offline archive residue scanner、grammar 与 root/intent fence](../../internal/cli/offline_archive_projection_intent.go#L363)
2. [shared stable no-replace quarantine commit](../../internal/cli/projection_intent_remove.go#L480)
3. [exact derived-state writer 与 creation mode](../../internal/cli/publish_plan.go#L1969) 和 [Unix umask 初始化](../../internal/cli/umask_unix.go#L1)
4. [故障注入与恢复测试](../../internal/cli/materialize_archive_scanner_hardening_test.go#L133)
5. [V-79 evidence](../../docs/evidence/2026-07-22-offline-archive-residue-removal-identity.md) 与 [需求追踪](../../docs/requirements-traceability.md)
