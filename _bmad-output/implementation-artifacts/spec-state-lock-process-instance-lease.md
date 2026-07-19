---
title: 'State lock process-instance lease'
type: 'bugfix'
created: '2026-07-15'
status: 'done'
review_loop_iteration: 0
baseline_commit: 'f0b9632c8a6a504a83931d84e79570252ef62a39'
context:
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '{project-root}/docs/adr/0001-core-contracts.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 当前本地状态锁只持久化 PID、操作和开始时间，并用 `kill(pid, 0)` 判断存活。崩溃后 PID 被无关进程复用时，即使显式 `--recover` 也会被永久误判为仍由原进程持有，破坏 FR-28/NFR-09 的可恢复性。

**Approach:** 让新锁持久化协议版本、随机锁 ID，以及操作系统提供的进程实例身份：Linux 为 boot ID + `/proc/<pid>/stat` starttime，macOS 为 boot time + `sysctl`/`kinfo_proc` starttime。恢复时比较当前 PID 对应的实例身份；相同才阻断，不同即为可恢复陈旧锁。

## Boundaries & Constraints

**Always:** 精确存活实例必须阻断所有竞争者；PID 存活但实例身份不匹配时必须视为陈旧并允许显式恢复；恢复前保留旧记录；持有者必须校验目录、锁 inode、锁 ID 与进程实例身份；身份探测不可用时失败关闭；Linux/macOS 同构并保持单 Go 二进制、零外部运行时依赖。

**Ask First:** 若实现需要改变公开 CLI 参数、手工删除锁、放宽状态目录安全边界或引入非 Go 运行时，必须停下确认。

**Never:** 不得访问或修改 `/Users/vonng/pgsty/repo`；不得访问生产云；不得用超时推断锁过期；不得自动夺取仍可能由旧版 SOW 持有的 legacy 活 PID 锁；不得修改 materialize/archive 文件。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| 精确实例存活 | 当前 PID 的 OS 身份与记录相同 | 普通与 `--recover` 都阻断 | 返回锁冲突，不改名记录 |
| PID 复用 | 当前 PID 存活，但 OS 身份与记录不同 | 普通模式报告陈旧；`--recover` 保留旧记录后取得新锁 | 不依据 PID 单独拒绝恢复 |
| 进程死亡 | 新协议记录 PID 已死 | `--recover` 安全恢复 | 普通模式要求恢复 |
| 身份探测不可用 | PID 存活但 OS 身份读取失败 | 普通与 `--recover` 都阻断 | 返回不可安全判断，不改名记录 |
| legacy 活 PID | 无协议身份的旧记录，PID 存活 | 保守阻断，包括 `--recover` | 明示 legacy 无法安全判定 |
| legacy 死 PID | 无协议身份的旧记录，PID 已死 | `--recover` 保留并迁移 | 普通模式要求恢复 |
| 记录损坏/身份篡改 | 未知协议、混合字段、非法实例 ID 或持有中被改写 | 自动恢复失败关闭；持有者校验/释放拒绝删除非本实例记录 | 保留证据供人工检查 |

</frozen-after-approval>

## Code Map

- `internal/state/lock.go` -- 状态目录绑定、锁记录生命周期、恢复判定与持有者校验。
- `internal/state/process_identity.go` -- 版本化身份模型、严格校验与可注入读取边界。
- `internal/state/process_identity_linux.go` -- Linux boot ID 与 `/proc` starttime 读取。
- `internal/state/process_identity_darwin.go` -- macOS boot/start time 的纯 Go sysctl 读取。
- `internal/state/lock_instance_test.go` -- 精确实例、PID 复用、死亡、legacy 与篡改回归测试。
- `docs/adr/0025-state-lock-process-instance-lease.md` -- 新旧锁协议和失败恢复语义。

## Tasks & Acceptance

**Execution:**
- [x] `internal/state/lock.go` -- 增加版本化实例记录、稳定 lease 文件、恢复分类、持有期身份校验和保守 legacy 迁移。
- [x] `internal/state/process_identity*.go` -- 用 OS 启动实例 + 进程启动 token 实现可比较身份，不依赖外部命令。
- [x] `internal/state/lock_instance_test.go` -- 覆盖矩阵中的正常、边界、跨进程和篡改路径。
- [x] `docs/adr/0025-state-lock-process-instance-lease.md` -- 冻结协议与运维恢复边界。
- [x] `docs/evidence/2026-07-19-state-lock-atomic-publication.md` -- 固化当前源码、真实崩溃点和证据边界。

**Acceptance Criteria:**
- Given 同一锁的精确进程实例仍持有 lease, when 另一调用带或不带 `--recover`, then 调用失败且现有记录不变。
- Given 新协议锁残留且 PID 被活进程复用, when 调用 `--recover`, then 旧记录被保留且新实例成功取得锁。
- Given dead PID、legacy 活/死 PID、损坏或篡改记录, when 执行相应恢复与校验, then 行为严格符合矩阵且不会删除无法证明归属的记录。
- Given 当前 Darwin 与 Linux 目标, when 构建并运行聚焦测试/race/vet, then 全部通过且无云或生产仓库访问。

## Spec Change Log

- 2026-07-19：恢复本规格验收时发现“create 空 `state.lock` → encode”之间存在真实崩溃窗口；改为私有 inode 完整写入并 fsync，再以 create-only hardlink 原子发布。真实子进程退出测试覆盖发布点前后、部分 unpublished 记录、返回错误清理和后续恢复。
- 2026-07-19：独立边界审查发现原子发布完成到权限协调之间尚未绑定可见路径；完整 holder 绑定现提前到任何 chmod 之前，路径替换负例证明 replacement/evidence/control mode 均不被触碰。最终盲审与边界复核均无剩余高置信 finding。

## Design Notes

boot token 区分重启前后的 PID 空间，process start token 区分同一次启动中的 PID 复用，随机 lock ID 则绑定一次具体的锁获取与持有者校验。legacy 记录没有实例证明，所以只有 PID 已死时才允许自动迁移；身份探测失败、损坏或未知协议都不能证明原实例已退出，自动恢复失败关闭。

权威 `state.lock` 也必须自身可恢复：完整 v1 记录先写入 mode-0600 的 `state.lock.unpublished-<lock-id>` 并 fsync，持有同一 inode 的 flock 后通过 hardlink 单点提交。提交前崩溃不产生权威锁且保留 unpublished 证据；提交后崩溃只留下完整记录，沿既有 `--recover` 路径保留旧证据并取得新锁。

## Verification

**Commands:**
- `go test -count=1 ./internal/state` -- PASS（4.693s），含真实 Darwin 身份探测与原子发布崩溃矩阵。
- `go test -race -count=1 ./internal/state` -- PASS（11.105s），并发、跨进程与身份注册无竞态。
- `go vet ./internal/state`；`staticcheck -checks='SA*,S1*' ./internal/state` -- PASS，无输出。
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/sow-state-linux-amd64.test ./internal/state` 与 Darwin arm64 对应命令 -- PASS。
- `go test ./... -run '^$'` -- PASS（14.158s），全模块测试源码重新编译，无云或生产仓库访问。
- `SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 SOW_RUN_REAL_UPSTREAM=0 go test -count=1 ./test/compat/cleandelivery` -- PASS（1.954s），新增证据文件已纳入干净交付闭包。

## Suggested Review Order

**原子权威记录**

- 私有完整 inode 通过 create-only hardlink 提供单点提交。
  [`lock.go:298`](../../internal/state/lock.go#L298)

- 完整 holder 绑定先于任何权限或正典状态变更。
  [`lock.go:680`](../../internal/state/lock.go#L680)

- ADR 冻结提交点两侧的崩溃与证据语义。
  [`0025-state-lock-process-instance-lease.md:38`](../../docs/adr/0025-state-lock-process-instance-lease.md#L38)

**故障与边界证据**

- 真实子进程分别在原子提交前后退出并重放。
  [`lock_instance_test.go:808`](../../internal/state/lock_instance_test.go#L808)

- 可见路径替换必须在 permission reconciliation 前失败。
  [`lock_instance_test.go:1011`](../../internal/state/lock_instance_test.go#L1011)

- 日期化报告汇总命令、结果与明确外部边界。
  [`2026-07-19-state-lock-atomic-publication.md:7`](../../docs/evidence/2026-07-19-state-lock-atomic-publication.md#L7)

**需求账本**

- V-28 将本地闭合与仍开放的真双云门禁分开。
  [`requirements-traceability.md:96`](../../docs/requirements-traceability.md#L96)
