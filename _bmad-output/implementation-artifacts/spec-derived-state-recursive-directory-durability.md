---
title: '闭合 derived-state 递归目录创建的持久化链'
type: 'bugfix'
created: '2026-07-22'
status: 'done'
review_loop_iteration: 0
baseline_commit: '818a2de'
context:
  - '{project-root}/_bmad-output/implementation-artifacts/deferred-work.md'
  - '{project-root}/docs/requirements-traceability.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** `writeDerivedStateFile` 以一次 `Root.MkdirAll` 创建任意深度目录，只在最终文件安装后同步 leaf；新祖先 entry 在崩溃后可能从 durable namespace 消失，而调用方已收到成功。路径绑定也发生在整棵目录创建之后，无法证明每一级创建期间未被替换。

**Approach:** 从已绑定 state root 开始逐 component 创建/打开目录。每个新 entry 必须先在 bound parent 中 create-only 建立，绑定其 descriptor/inode，再 fsync 精确 parent，随后复核 state-root、parent 与 child coordinate；只有完整祖先链 durable 且仍指向准入 inode，文件 writer 才可创建临时文件。

## Boundaries & Constraints

**Always:** 绝对 state-root identity 与每级目录 identity 必须贯穿；只接受真实非 symlink directory；新目录使用 0700 请求模式；每个新 entry 恰好同步其直接父目录；任何 mkdir/open/stat/sync/coordinate 错误立即失败且不继续创建更深目录或文件。已成功 durable 的空目录可由安全重放复用。

**Ask First:** 改变 `.sow` 布局、删除空目录、改变现有 canonical state schema、访问云或生产资源。

**Never:** `MkdirAll` 后只同步 leaf；按 pathname `os.MkdirAll`/`os.Chmod` 修复；follow symlink；把 `EEXIST` 当作本次 create 成功；在父目录 sync 失败后继续写文件；依赖测试 Mock 代替真实 fsync 路径。

## I/O & Edge-Case Matrix

| 场景 | 预期 | 失败闭包 |
|---|---|---|
| 所有祖先已存在 | descriptor 逐级绑定，无创建 sync | 目录换包拒绝 |
| 创建一到多级祖先 | 每级 create→bind→parent fsync→revalidate | 顺序确定、成功可重放 |
| 第 N 级 parent fsync 失败 | 立即返回错误 | N 级可保留；N+1 与文件不存在 |
| create/bind/sync 后 child 换包 | 拒绝 | detached/new tree 均不被写入 |
| parent/state-root 换包 | 拒绝 | replacement 与 detached tree 保持不变 |
| symlink/file/错误 component | 拒绝 | 不穿越、不创建后续路径 |

</frozen-after-approval>

## Code Map

- `internal/cli/publish_plan.go` -- shared writer 与递归 durable directory binder。
- `internal/cli/derived_state_recovery_contract_test.go` -- 多级顺序、sync 故障、换包与重放测试。

## Tasks & Acceptance

**Execution:**
- [x] 实现从 bound state root 逐级 create/open/bind/fsync/revalidate 的目录协议。
- [x] 让 `writeDerivedStateFile` 直接消费最终 bound root/handle/identity，不再调用 `MkdirAll`。
- [x] 增加多级 sync 顺序、sync failure、child/parent/root replacement、existing-tree replay 与 symlink/file 负例。
- [x] 更新 deferred、traceability、evidence 与 clean-delivery；完成 ordinary/race/full/static/cross-platform 门禁。

**Acceptance Criteria:**
- Given 三层祖先均不存在，when writer 成功，then 每个新 entry 的直接父目录按根到叶顺序 fsync，最终文件 exact 安装。
- Given 第 N 层 parent fsync 失败，when writer 返回，then 不创建 N+1 层或 canonical/temp 文件，安全重放可收敛。
- Given 任一级在 bind/sync 边界被 replacement 占用，when writer 复核，then 失败且不向 replacement 或 detached tree 写文件。

## Spec Change Log

- frozen intent 无变更。实现审查在原边界内补齐严格 crash-stage grammar、并发 recovery claim、foreign replacement preservation、balanced sibling mutation fence、短期 mutation epoch、无封印文件系统的 fail-safe scan 降级、最终绝对根复核与 inherited-umask/setgid residue repair。

## Design Notes

目录 entry 的 durability 属于其父目录；leaf file fsync/rename/leaf-directory fsync 不能替代祖先 entry 的逐级持久化。空目录不是事务提交，因此错误后保留已同步层并由重放复用是安全且幂等的。

随机 stage 只用于获得本进程可持有的创建 capability；最终 component 仍以 no-replace rename 安装。严格 stage/quarantine 名称可以在重启后恢复，而 `.preserved-<nonce>` 明确脱离自动恢复 grammar，避免把并发 replacement 误当 writer-owned residue。

正常写路径通过 parent device/inode/ctime/mtime/link-count/size/blocks/mode
token 与短期 lease 避免为紧邻文件重扫大目录；未知 mutation 或 lease
过期先执行流式 recovery scan。Linux 与 Darwin 的 token/seal 分平台实现。
若 writable filesystem 不允许 descriptor timestamp seal 或无法精确表达
marker，正确性降级为每个 guard 边界全扫描并禁止 clean-cache admission，
而不是拒绝本来可写的仓库或静默复用旧 cache。

## Verification

2026-07-26 的 local-only 当前源码验证：

- focused ordinary/race 分别 `4.296s`/`6.477s`；derived-state、projection
  与 offline-archive 邻接 ordinary/race 分别 `174.185s`/`235.530s`。
- 高风险 fault/replacement/cache/recovery 集合在当前源码上 ordinary 20 次
  (`114.281s`)、race 10 次 (`80.595s`) 与 Linux arm64 断网、只读根、
  no-capability 容器 20 次全部通过。
- 六片完整 `internal/cli` ordinary/race、全部 non-CLI ordinary/race、
  clean-delivery ordinary/race (`2.758s`/`50.721s`)、`go vet ./...`、
  `staticcheck ./...`、`go mod verify`、本地缓存的 `govulncheck v1.6.0`
  以及 Darwin/Linux × amd64/arm64 静态 test build 全部通过。嵌套
  RPM module 的 ordinary/race/vet/module/vulnerability 通过；其两个
  pre-existing U1000 staticcheck 报告保持显式，不伪报全绿。
- 50k 普通 legacy adoption 使用 8/8 workers，retained heap
  `+538,400B`；APT、YUM、materialize、publish、upstream、CDN 与
  incremental preflight 的普通/race 性能证据通过。额外的 50k
  legacy SQLite race 尝试在 60 分钟预算内仍活跃且未报告 data race，
  明确不计为通过。
- 原子 coverage：writer `73.3%`、binder `78.3%`、recovery `73.5%`、
  cache admission `71.7%`、root/directory fence 各 `85.7%`。

完整命令、故障矩阵、时延与边界记录见
`docs/evidence/2026-07-26-derived-state-recursive-directory-durability.md`。
测试仅使用本地临时目录和合成只读 fixture；未加载凭据、未访问网络、
云或生产仓库。

## Review Result

Edge Case Hunter 最终返回 `[]`。Blind Hunter 的唯一 medium finding 是
traceability 页首日期与 NFR-09 汇总行未引用 V-80；现已更新为
2026-07-26，并把 V-80 evidence 显式接入 NFR-09。实现层无未处理 finding。

## Suggested Review Order

**Writer and durable ancestry**

- 从唯一共享 writer 入口理解全链 identity、install 与最终 cache 边界。
  [`publish_plan.go:2214`](../../internal/cli/publish_plan.go#L2214)

- 逐 component 私有 stage、no-replace 安装和 exact-parent fsync。
  [`publish_plan.go:2471`](../../internal/cli/publish_plan.go#L2471)

**Recovery and mutation fencing**

- 最终 cache 只接受 live epoch 与完整 root/directory 复核。
  [`publish_plan.go:2375`](../../internal/cli/publish_plan.go#L2375)

- 流式扫描、并发 claim 和 foreign replacement preservation 闭合重启恢复。
  [`publish_plan.go:2783`](../../internal/cli/publish_plan.go#L2783)

- exact empty-stage retirement 保持 quarantine 与坐标删除权。
  [`publish_plan.go:3023`](../../internal/cli/publish_plan.go#L3023)

- Linux identity token 与短期 future-mtime epoch。
  [`derived_state_identity_linux.go:15`](../../internal/cli/derived_state_identity_linux.go#L15)

- Darwin 同构 identity token 与 seal 降级。
  [`derived_state_identity_darwin.go:15`](../../internal/cli/derived_state_identity_darwin.go#L15)

**Adversarial proof and delivery**

- 故障注入覆盖 ancestor sync、replacement、cache、recovery 与并发。
  [`derived_state_recovery_contract_test.go:18`](../../internal/cli/derived_state_recovery_contract_test.go#L18)

- SIGKILL harness 先终止并 wait，再读取并发 child output。
  [`materialize_asset_hardening_test.go:757`](../../internal/cli/materialize_asset_hardening_test.go#L757)

- 当前源码 ordinary/race/container/50k 门禁和明确未通过边界。
  [`2026-07-26-derived-state-recursive-directory-durability.md:94`](../../docs/evidence/2026-07-26-derived-state-recursive-directory-durability.md#L94)

- V-80 与 NFR-09 汇总均链接可复现证据。
  [`requirements-traceability.md:127`](../../docs/requirements-traceability.md#L127)

- clean-delivery 清单纳入新源码、spec 与 evidence。
  [`product-files.txt:5`](../../test/compat/cleandelivery/product-files.txt#L5)
