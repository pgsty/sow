---
title: '干净环境本地生命周期与缓存恢复闭环'
type: 'bugfix'
created: '2026-07-29'
status: 'done'
review_loop_iteration: 0
baseline_commit: 'd84fe72dd32c01ee5d0ea90fb1d1d5209e0c2aeb'
context:
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 交付包已能从空目录完成 asset 的 init/add/promote/materialize/fsck 与真实进程中断恢复，但尚未以生产二进制闭合 rm、GC 和幂等重放。实测删除 `.sow/cache/state.db` 后，`sow fsck --recover` 会错误报告 clean，幂等 `sow add` 也成功退出但不重建缓存，违反 FR-02 的“manifest 正典、SQLite 可随时重建”契约。

**Approach:** 让显式 `--recover` 在进入审计或状态变更前总是从 canonical Git 重建并 fsync SQLite 投影；随后把 add/promote/materialize/rm/GC 的重放、精确确认、缓存删除恢复和最终 fsck 串入随交付归档执行的真实 CLI E2E。

## Boundaries & Constraints

**Always:** manifest/ref/CAS 是唯一恢复输入；普通命令仍不得静默掩盖无标记缓存漂移；显式恢复必须在状态锁内完成并输出可理解收据；GC 必须先 dry-run，再以当前 `gc_set_sha256` 精确确认；测试只写 `/private/tmp` 隔离树且清空云凭据。

**Ask First:** 任何真实云、生产仓库或不可逆外部资源操作；改变 canonical 历史保留策略的产品默认值。

**Never:** 从 SQLite 反向修复 manifest；让 fsck 在缓存仍缺失或错误 HEAD 时报告 clean；用内存 fake 代替生产二进制；访问或写入 `/Users/vonng/pgsty/repo`、CO/COS/Cloudflare 生产资源。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| 显式缓存恢复 | canonical HEAD 有效，cache 缺失/陈旧/损坏 | `fsck --recover` 原子重建 cache、报告恢复收据并完成审计 | canonical 输入或重建失败时非零退出，不报告 clean |
| 生命周期删除 | beta/latest 不再引用 asset，历史窗口已安全收窄 | rm 重放无变化；GC dry-run 给出绑定摘要，确认后删除 orphan | 陈旧/错误确认摘要拒绝且不删除 |
| 幂等重放 | 相同 add/promote/materialize/rm/GC 请求 | canonical 结果、物化结果和最终 fsck 收敛 | 不制造重复 ref、对象或残留 journal |

</frozen-after-approval>

## Code Map

- `internal/cli/app.go` -- `prepareCanonicalState` 与 fsck 显式恢复入口。
- `test/compat/clean_room_mvp_test.go` -- 构建生产二进制并执行随归档交付的干净环境 E2E。
- `README.md` -- 无云凭据 MVP、缓存恢复、rm/GC 两阶段操作说明。
- `docs/requirements-traceability.md` -- FR-02/FR-11/FR-13 的当前证据映射。

## Tasks & Acceptance

**Execution:**
- [x] `internal/cli/app.go` -- 使所有显式 `--recover` 在非零 canonical HEAD 上重建 SQLite，并保留已有 transaction/residue 恢复顺序。
- [x] `internal/cli/verify_cache_test.go` -- 覆盖无 pending marker 的缺失、错误 schema/HEAD 与失败关闭。
- [x] `test/compat/clean_room_mvp_test.go` -- 用生产进程闭合幂等重放、双视图 rm、cache 删除恢复、GC 当前摘要确认/陈旧摘要拒绝和最终 fsck。
- [x] `README.md`, `docs/requirements-traceability.md` -- 写明可执行命令与证据边界，不把本地结果冒充云端验收。
- [x] 怀疑式复审 -- 修复空 asset 视图无法收敛物化树、sync 自动恢复越权重建 cache、SQLite rebuild 残留和 replacement source 语法边界。
- [x] 两位独立复审者复核全部发现，均返回 `resolved`，无 defer/reject 项。

**Acceptance Criteria:**
- Given 从随交付示例建立的本地仓库且 cache 被删除，when 运行 `sow fsck --recover`，then cache 由 canonical Git 重建、L1 与 fsck 均通过且输出恢复收据。
- Given asset 已从 beta/latest 移除且只剩可回收 CAS 引用，when 先 dry-run 再提交精确摘要，then 对象被删除；旧摘要重放被拒绝，新 dry-run 为零 orphan。
- Given 同一归档在隔离 HOME/GOMODCACHE 中执行，when clean-delivery 验证运行，then 全流程只使用归档内源码、生产二进制与本地临时目录。

## Spec Change Log

- 2026-07-30: 实现显式 cache 重建与生产二进制全生命周期 E2E；全量回归进一步关闭 final-removal quarantine/同目录 writer 并发窗口，并把两个 scheduler-dependent 测试夹具改为事件驱动断言配合独立 deadlock budget。
- 2026-07-30: review patch 闭合空视图 exact materialize、自动 sync journal/cache 权限分离、SIGKILL SQLite residue、replacement-intent source 语法与变化后非空 GC 集合；两位复审者复核无未解决项。

## Design Notes

`--recover` 是操作者显式选择的昂贵恢复路径，因此每次从 canonical HEAD 全量重建 cache 是可接受且确定的；普通无 `--recover` 路径仍保持增量和失败可见。GC 测试只在副本配置中把历史窗口设为 1，以制造最小、确定的 orphan，不改变产品默认值 32。

## Review Classification

| Finding | Classification | Resolution |
|---|---|---|
| pure final-removal 被 replacement intent 当作 source | `patch` | replacement intent 仅接受 write/install temporary；residue scanner 仍接受 final-removal quarantine |
| directory-writer 回归测试可能无限等待 | `patch` | 所有 release 后 drain 均有独立 5 秒 deadlock guard |
| 删除后的 asset 仍留在显式 Nginx export | `patch` | E2E 重新 materialize 并要求 `pruned=1`；空 prefix route 可被 exact-empty receipt 安全验证 |
| sync journal 自动恢复顺带修复无标记 cache | `patch` | 分离 state journal recovery 与 operator-authorized cache rebuild |
| SIGKILL 留下 `state-*.db` 无界残留 | `patch` | bounded inventory；普通命令失败可见，marker/显式恢复原子删除并 fsync |
| README 的默认 32-commit GC 示例不可直接 apply | `patch` | 默认流程只 dry-run；新增隔离 retention=1 的完整可执行两阶段示例 |
| stale GC 证据只覆盖空集合重放 | `patch` | 生产 CLI 创建变化后的非空 orphan 集合，旧摘要拒绝且新对象仍存在 |

No finding was classified as `intent_gap`, `bad_spec`, or `defer`.

## Verification

**Commands:**
- `go test -count=1 ./internal/cli -run 'Catalog|Cache|FSCK'` -- cache 恢复及负例通过。
- `go test -count=3 ./test/compat -run '^TestShippedExampleSupportsCleanRoomLocalMVP$'` -- 真实 CLI 生命周期稳定重放。
- `go test -race -count=1 ./test/compat -run '^TestShippedExampleSupportsCleanRoomLocalMVP$'` -- 无数据竞争。
- `go vet ./...`、`staticcheck ./...`、四目标 `go test -c ./test/compat` -- 静态与可移植性通过。
- `SOW_CLEAN_GOPROXY=https://goproxy.cn,direct SOW_CLEAN_GOSUMDB=sum.golang.google.cn test/compat/test-clean-delivery.sh <OUT>` -- 提取归档后重新执行完整闭环。

**Results:**

- review-final shipped clean-room actual binary：`44.127s`；
- review-final full CLI ordinary 六片：`967.972/1158.894/410.389/1345.198/829.995/328.519s`；
- pre-review full CLI race 六片：`1148.060/1713.842/843.406/1416.292/1714.782/808.821s`；review patch 的 catalog/serving 完整 ordinary/race 为 `7.673/10.226s`、`25.533/28.278s`，五类直接 CLI 边界 focused race 通过；
- non-CLI ordinary/race 全绿；compat `78.895/63.197s`，clean-delivery policy `13.974/82.724s`；
- current vet、Staticcheck、module verify/tidy diff、diff-check 与 Darwin/Linux amd64/arm64 CGO-free CLI/compat build 全绿；Darwin arm64 CLI SHA-256 `411a2da3b71e5a0d76089dfa6c1f4ea9b9fce007a27a30b7b0704c344b5b87dd`；
- 最终两次冻结源码 clean-delivery identity 仅记录在交付根外 V-90 validation ledger。

## Suggested Review Order

**Recovery authority and cache durability**

- 从入口分离显式 cache 修复与 journal 自动恢复。
  [`app.go:974`](../../internal/cli/app.go#L974)

- 有界盘点并 fsync 清理 SIGKILL 遗留 SQLite 文件。
  [`catalog.go:42`](../../internal/catalog/catalog.go#L42)

- 普通 sync 重放不再获得额外 cache 修复权限。
  [`sync.go:684`](../../internal/cli/sync.go#L684)

**Hostable deletion and durable derived state**

- exact-empty receipt 安全容纳已删除的空服务前缀。
  [`validate_route_root.go:259`](../../internal/serving/validate_route_root.go#L259)

- 所有 exact removal 与 writer 共用目录级串行锁。
  [`projection_intent_remove.go:318`](../../internal/cli/projection_intent_remove.go#L318)

- replacement intent 拒绝 final-removal quarantine 充当输入。
  [`derived_state_replacement.go:106`](../../internal/cli/derived_state_replacement.go#L106)

- 严格区分可恢复 removal 与 write/install 临时名。
  [`publish_plan.go:2163`](../../internal/cli/publish_plan.go#L2163)

**Actual-binary acceptance evidence**

- 一条生产 CLI 流程闭合删除、GC、恢复与中断重放。
  [`clean_room_mvp_test.go:22`](../../test/compat/clean_room_mvp_test.go#L22)

- cache 残留普通失败、显式恢复及非空数据库均有断言。
  [`verify_cache_test.go:444`](../../internal/cli/verify_cache_test.go#L444)

- exact sync journal 不会重建无标记缺失 cache。
  [`materialize_top_level_recovery_test.go:280`](../../internal/cli/materialize_top_level_recovery_test.go#L280)

- 空路由通过，随后新增可见文件仍失败。
  [`validate_route_root_test.go:50`](../../internal/serving/validate_route_root_test.go#L50)

- final removal 与并发 writer 的事件顺序确定可证。
  [`derived_state_residue_audit_test.go:592`](../../internal/cli/derived_state_residue_audit_test.go#L592)

**Operator contract and traceability**

- README 给出默认安全流程与隔离 destructive GC 演示。
  [`README.md:44`](../../README.md#L44)

- 复审发现、修复与安全边界集中记录。
  [`2026-07-29-mvp-and-cloudflare-bootstrap-readiness.md:350`](../../docs/evidence/2026-07-29-mvp-and-cloudflare-bootstrap-readiness.md#L350)

- FR-02/12/13 映射到当前可复现证据。
  [`requirements-traceability.md:164`](../../docs/requirements-traceability.md#L164)
