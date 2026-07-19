---
title: 'R2 bootstrap 两阶段租约恢复标记'
type: 'bugfix'
created: '2026-07-19'
status: 'done'
review_loop_iteration: 0
baseline_commit: '98ca15f48f30eeb94481de18f71f2b04d2c23ac4'
context:
  - '{project-root}/docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md'
  - '{project-root}/docs/evidence/2026-07-19-r2-resource-stable-lease-rotation.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** `recoverExpiredRealCloudCloudflareBootstrapLease` 先把远端 expired live lease CAS 成 idle，再写本地 recovery receipt；若进程在两步间中断，另一执行可取得 idle，使被恢复 lease 的精确 provenance 无法重放。

**Approach:** 把恢复改成远端 `live -> recovery-pending -> idle` 两阶段协议：pending marker 持续阻塞普通执行并完整绑定旧 lease 与恢复执行；只有精确本地 receipt 已原子持久化并重新读取后，才能用 pending ETag CAS 到绑定该 receipt 的 recovery idle marker。

## Boundaries & Constraints

**Always:** 继续使用 readiness-resource 派生的唯一 key；所有远端变化只用精确 ETag conditional Put；pending 对普通 apply/rollback/readiness 均为 owning/closed 状态；同 run/plan 可从任一中断点安全重放；receipt 必须先完整落盘、fsync、no-replace，再允许最终 idle；recover-lease 只持有 R2 authority；失败保留可诊断状态且零 Delete。

**Ask First:** 任何写入 CO/COS、Cloudflare 正式仓库，或扩大用户已授权的 `pro` 空桶边界的真实云操作。

**Never:** 不把 pending 当 idle；不允许其他 run/plan 接管 pending；不以无条件覆盖、删除、超时猜测或仅内存 Mock 消除故障窗口；不兼容性地接受未部署的旧协议对象而弱化 fail-closed。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| 首次恢复 | exact expired live，无 receipt | CAS 为 pending，持久化 exact receipt，再 CAS 为 recovery idle | 任一步失败停在 live 或 pending，绝不提前开放 acquisition |
| pending 重放 | 同 run/plan pending，receipt 缺失或已存在 | 重建字节一致 receipt并完成 idle；并发同 run 幂等收敛 | receipt/marker/ETag 不一致则 fail closed |
| idle 重放 | recovery idle + exact receipt | 零写返回成功并验证完整 provenance 链 | 普通 release idle 或 receipt 漂移拒绝 |
| 竞争恢复 | live/pending 被其他 run、plan、resource 或 ETag占用 | 不接管、不覆盖 | 返回可操作的 ownership/identity错误 |
| 中断注入 | live->pending后、receipt安装后、pending->idle响应丢失 | 每个状态都可由同 run安全恢复 | 不产生 Delete、第二 key或部分 final file |

</frozen-after-approval>

## Code Map

- `test/compat/real_cloud_cloudflare_bootstrap_test.go` -- bootstrap lease schemas、R2 CAS 状态机、recover-lease runtime与故障注入测试。
- `test/compat/real_cloud_provider_readiness_test.go` -- bucket closure admission；pending 必须被 readiness 拒绝。
- `docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md` -- 冻结两阶段状态、恢复权威与失败语义。
- `docs/evidence/`、`docs/requirements-traceability.md` -- 可复现证据、FR-28/NFR-09追踪与未触云边界。
- `_bmad-output/implementation-artifacts/deferred-work.md` -- 关闭本故事对应的既有中断窗口条目。

## Tasks & Acceptance

**Execution:**
- [x] `test/compat/real_cloud_cloudflare_bootstrap_test.go` -- 增加 canonical pending/恢复 idle/receipt绑定模型，把 recover-lease 编排拆为可重放 begin、durable receipt、complete 三步。
- [x] `test/compat/real_cloud_cloudflare_bootstrap_test.go`、`test/compat/real_cloud_provider_readiness_test.go` -- 覆盖所有中断窗、并发/跨计划接管、响应丢失、字节/ETag漂移、readiness拒绝与零 Delete。
- [x] `docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md`、架构/追踪/证据 -- 冻结协议并记录普通/race/static/clean-delivery证据。
- [x] `_bmad-output/implementation-artifacts/deferred-work.md` -- 以实现和测试证据把原条目标为 resolved，不删除历史。

**Acceptance Criteria:**
- Given 任一 recovery 中断点，when 相同 run/plan重放，then 唯一远端 key最终收敛到绑定 durable receipt 的 recovery idle且旧 lease provenance逐字节可验。
- Given pending/live/idle上的异 run、异 plan、异 resource、stale ETag或伪造 receipt，when recover/apply/readiness运行，then 在授权扩大或 Worker credential读取前失败关闭。
- Given ordinary、`-race`、静态检查与 clean-delivery，when 从当前源码执行，then 无 Delete、无数据竞争、无真实云写入且两份交付归档字节一致。

## Spec Change Log

- 2026-07-19 review patch: recovery receipt now names the actual pending start
  time and embeds the complete expired lease, eliminating an ambiguous audit
  timestamp and preserving byte-exact provenance after the remote marker moves.
- 2026-07-19 edge patch: live schema v3 carries an ordered recovery lineage.
  Completion accepts only the exact idle or a later marker containing the exact
  pending/receipt pair; tests cover immediate acquisition, release, another
  completed recovery, later live replay, unrelated live rejection, duplicates
  and capacity-before-CAS failure.

## Design Notes

pending marker 不设自动超时接管：它是恢复事务的 fencing record，不是新 lease。若恢复进程崩溃，操作者重用同一 run ID、plan和私有 workspace即可继续；让其他执行按时钟抢占会重新制造 provenance 丢失。最终 recovery idle同时绑定 recovered lease、pending canonical SHA与本地 canonical receipt SHA，形成 `expired live -> pending -> receipt -> idle` 的可审计闭包。

审查后把完成 pair 追加到所有后继状态保留的 canonical lineage。这样 final
Put 的响应丢失即使与下一 holder 或下一次 recovery 竞争，旧 receipt 仍可只读验明
后继关系；1024 项容量在 live→pending CAS 前检查，不会制造不可完成的 pending。

## Review Outcome

- Blind review: 修正 receipt 时间字段语义，并把完整 recovered lease 纳入持久回执。
- Edge review: 修复 final Put 成功/响应丢失后被立即 holder 推进，以及第二次 recovery
  后旧 receipt 失去因果证明的竞态；合法后继必须携带 exact canonical lineage。
- Acceptance audit: focused/full ordinary/race、vet、Staticcheck 与 lineage 负例通过；
  双份 clean-delivery 逐字节一致。未发起任何云请求。

## Verification

**Commands:**
- focused ordinary/race -- PASS `1.126s`/`2.460s`，real-cloud opt-in为0。
- full compat ordinary/race -- PASS `10.266s`/`14.318s`。
- `go vet ./test/compat`、project-profile `staticcheck`、`git diff --check` -- PASS。
- 两个独立 fresh-cache clean-delivery 与 `cmp` -- product `344f731c…08ea8` / 536，
  delivery `6ef5584c…eb238` / 685，archive `c1e01fd8…c1c0c5`，逐字节一致；
  完整路径与摘要见外部验证账本。
- 非权威 unsharded `go test ./...` 再现既有 `internal/cli` 10 分钟累计 fsync
  timeout；当时显示的 exact test 单独运行 `3.081s` PASS。V-26 所属 compat 与正式
  clean-delivery 门禁均通过，此结果不冒充全仓整包通过。

## Suggested Review Order

**协议意图**

- 冻结两阶段 fencing、谱系与无 Delete 不变量。
  [`0034-cloudflare-nonproduction-worker-bootstrap.md:89`](../../docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md#L89)

- 总览 live、pending、idle 与 receipt 数据合同。
  [`real_cloud_cloudflare_bootstrap_test.go:129`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L129)

**恢复状态机**

- 先验证有界谱系，再允许任何后继追加。
  [`real_cloud_cloudflare_bootstrap_test.go:623`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L623)

- exact expired live 仅能 CAS 为 owning pending。
  [`real_cloud_cloudflare_bootstrap_test.go:1116`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L1116)

- 本地 receipt 以 complete-inode、no-replace 方式持久化。
  [`real_cloud_cloudflare_bootstrap_test.go:1270`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L1270)

- completion 接受 exact marker 或带精确谱系的后继。
  [`real_cloud_cloudflare_bootstrap_test.go:1336`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L1336)

- 真实 opt-in 入口串联 begin、persist、complete。
  [`real_cloud_cloudflare_bootstrap_test.go:2254`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L2254)

**故障与边界**

- 覆盖每个 committed phase、响应丢失与跨代 replay。
  [`real_cloud_cloudflare_bootstrap_test.go:3208`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L3208)

- 拒绝异 run/plan/resource pending 与 readiness admission。
  [`real_cloud_cloudflare_bootstrap_test.go:3410`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L3410)

- 拒绝 stale CAS、伪造回执、重复及饱和谱系。
  [`real_cloud_cloudflare_bootstrap_test.go:3463`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L3463)

**证据与追踪**

- 汇总 ordinary/race/static/clean-delivery 与未触云边界。
  [`2026-07-19-r2-bootstrap-two-phase-recovery.md:1`](../../docs/evidence/2026-07-19-r2-bootstrap-two-phase-recovery.md#L1)

- 将 V-26 映射回 FR-28、NFR-09 与开放 POC。
  [`requirements-traceability.md:94`](../../docs/requirements-traceability.md#L94)

- 保留并关闭原始中断窗口账本项。
  [`deferred-work.md:10`](deferred-work.md#L10)
