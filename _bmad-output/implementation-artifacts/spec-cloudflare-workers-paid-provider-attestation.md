---
title: 'Cloudflare Workers Paid 供应商证据链'
type: 'bugfix'
created: '2026-07-29T00:00:00+08:00'
status: 'done'
review_loop_iteration: 0
baseline_commit: 'f2f34ab'
context:
  - '{project-root}/docs/adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 真实云验收把 Cloudflare 原始证据固定为仅 Enterprise 可用的 zone `http_requests` Logpush，与 NFR-07 冻结的 Workers Paid 成本契约冲突，导致合格的非生产验收环境也无法完成证据闭包。

**Approach:** 改用 Workers Paid 可用的 account `workers_trace_events` 数据集；仅由鉴权 Worker 发出受限、无秘密、可与客户端 `CF-Ray` 关联的结构化记录，并对任务、脚本、版本、原始 NDJSON 和共享账号隔离进行严格校验。

## Boundaries & Constraints

**Always:** 鉴权 Worker 唯一启用 `logpush`；任务以 exact `ScriptName` 过滤并全采样写入逐次隔离的 R2 前缀；解析器逐层拒绝未知、重复、缺失和错误类型字段；持久证据不得含 token、Authorization、原始 URL 或存储凭据；仍盘点 zone Logpush，防止共享资源旁路采集受审域名或写入专用 raw bucket。

**Ask First:** 创建真实 Cloudflare token、Worker、route、Logpush job 或写入远端桶；任何生产账号、生产 zone、生产仓库与正式发布域名上的变更。

**Never:** 依赖 Enterprise HTTP Logs；以 Worker 自报字段代替 provider envelope、活动脚本版本或远端任务证明；降低全采样、脚本过滤、双次稳定读取、secret 扫描和失败闭合要求；触碰 CO/CF 生产仓库。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| 正常请求 | `https-bearer`、合法 `CF-Ray`、可观察缓存状态 | Worker 输出一条 v1 结构化日志；Trace parser 绑定活动脚本/版本、colo、clean URL digest 与缓存证据 | 任一 provider/Worker 字段不一致即拒绝 attestation |
| 非可关联请求 | 缺失或矛盾的 ray/colo、非 bearer transport | 不输出 provider join record | 不影响正常响应 |
| 任务漂移 | 错 dataset/filter/fields/sample/destination 或重复任务 | 真实云预检失败 | 不读取业务 bearer，不启动验收流量 |
| 原始日志污染 | 多条日志、异常、未知/重复字段、token/URL 或版本错配 | parser 失败闭合 | 原始缓冲区清零，不生成 durable fact |

</frozen-after-approval>

## Code Map

- `edge/cloudflare/worker.mjs` -- 生成可关联且无秘密的 Workers Trace record。
- `edge/test/contract.test.mjs` -- 锁定日志 schema、抑制条件与泄密负例。
- `test/compat/real_cloud_cloudflare_bootstrap_test.go` -- 按 Worker 角色冻结 `logpush` 部署设置。
- `test/compat/real_cloud_provider_attestation_test.go` -- account job 控制、共享资源隔离、Trace NDJSON 严格解析与 loopback SDK。
- `docs/adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md` -- 记录 Paid-plan 技术定案与恢复语义。

## Tasks & Acceptance

**Execution:**
- [x] `edge/cloudflare/worker.mjs`、`edge/test/contract.test.mjs` -- 输出并测试固定十字段的 secret-free join event。
- [x] `test/compat/real_cloud_cloudflare_bootstrap_test.go` -- auth=true、origin/verifier=false 精确验证 `logpush`。
- [x] `test/compat/real_cloud_provider_attestation_test.go` -- 改为 account Workers Trace job，完成多层 exact parser、共享账号/zone 隔离和故障负例。
- [x] `docs/adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md`、证据索引与追踪矩阵 -- 消除 Enterprise 依赖并标明真实环境尚未运行的边界。

**Acceptance Criteria:**
- Given Workers Paid 合同，when 离线 SDK/HTTP loopback 验收运行，then 不出现 Enterprise-only API，auth Worker、account task、provider envelope 与业务观测可重放关联。
- Given token、URL、异常、重复字段、错脚本/版本或任务重叠，when 收集器运行，then 在 durable fact 前失败且不泄密。
- Given 本地 corrected tree，when edge build/tests、focused ordinary/race compat tests 与静态检查运行，then 全部通过且真实云 opt-in 保持关闭。

## Spec Change Log

- 2026-07-29: 以 account `workers_trace_events` 替换 Enterprise-only
  `http_requests`，加入 Worker probe event、严格原始日志解析、共享账号隔离、
  mutation 前双供应商 inventory gate 与 Paid-plan 运维证据。
- 2026-07-29 review: 修正官方 `!eq` 运算符、把 `logpush` 纳入安全摘要、
  清零 SDK 部分错误响应中的凭据，并补齐 bucket overlap 与 clean-delivery 门禁。

## Design Notes

`request_id` 使用 `CF-Ray` 的十六进制主体，`provider_request_id` 使用固定 `trace-` 前缀；Trace envelope 的 `ScriptName`、`ScriptVersion.id` 和 `EventTimestampMs` 来自供应商，Worker 只提供可与业务 stage 关联的最小事件。该分层避免让自报数据冒充 provider 身份。

## Verification

**Commands:**
- `cd edge && npm run build && npm test` -- 共享边缘合同全部通过。
- `go test -timeout 20m -count=1 ./test/compat -run 'RealCloud(Cloudflare|Provider)'` -- PASS，`1.397s`。
- `go test -race -timeout 20m -count=1 ./test/compat -run 'RealCloud(Cloudflare|Provider)'` -- PASS，`3.224s`。
- `go test -timeout 30m -count=1 ./test/compat` -- PASS，`10.306s`。
- `go test -race -timeout 30m -count=1 ./test/compat` -- PASS，`15.268s`。
- `go vet ./...` -- 无静态错误。
- `staticcheck ./...`、`git diff --check` -- PASS。
- `go test -timeout 45m -count=1 ./...` -- 所有产品包通过，含
  `internal/cli 1830.482s`；首次仅因两份新证据未进发行白名单而失败。
- 补齐白名单后 `go test -timeout 5m -count=1
  ./test/compat/cleandelivery` -- PASS，最终复验 `2.348s`。

所有 Go 验证均显式清除了 AWS、Cloudflare 与腾讯云凭据，关闭 real-cloud、
real-edge、real-upstream 与 Docker opt-in；本轮没有发出供应商请求或远端写入。

## Suggested Review Order

**技术定案**

- 先确认 Paid-plan 数据集、隔离边界与恢复语义。
  [`0035-cloudflare-provider-attestation-and-log-sink-lease.md:162`](../../docs/adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md#L162)

**请求与供应商证据**

- 鉴权 Worker 只为显式 probe 输出十字段无秘密事件。
  [`worker.mjs:54`](../../edge/cloudflare/worker.mjs#L54)

- 客户端仅向 Cloudflare 附加 probe，且不转发到 origin。
  [`real_edge_multipop_test.go:831`](../../test/compat/real_edge_multipop_test.go#L831)

- 严格解析 Trace envelope、活动版本与业务观测闭包。
  [`real_cloud_provider_attestation_test.go:3927`](../../test/compat/real_cloud_provider_attestation_test.go#L3927)

**变更安全与恢复**

- 两供应商 inventory 预检先于任何日志目标 mutation。
  [`real_cloud_provider_attestation_test.go:775`](../../test/compat/real_cloud_provider_attestation_test.go#L775)

- 同桶目的地与官方过滤器按失败关闭规则识别。
  [`real_cloud_provider_attestation_test.go:2938`](../../test/compat/real_cloud_provider_attestation_test.go#L2938)

- Cloudflare 传播窗口在首个 probe 和恢复重放后强制等待。
  [`real_cloud_acceptance_program_test.go:611`](../../test/compat/real_cloud_acceptance_program_test.go#L611)

- bootstrap 精确区分 auth 与 service-only Worker 的 Logpush 状态。
  [`real_cloud_cloudflare_bootstrap_test.go:1722`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L1722)

**验证与证据**

- 边缘合同锁定 schema、静默路径与凭据剥离。
  [`contract.test.mjs:488`](../../edge/test/contract.test.mjs#L488)

- 官方 SDK loopback 覆盖零写入安全门与完整采集闭包。
  [`real_cloud_provider_attestation_test.go:5967`](../../test/compat/real_cloud_provider_attestation_test.go#L5967)

- 复现命令、最终耗时与尚未通过的真实云边界。
  [`2026-07-29-cloudflare-workers-paid-provider-attestation.md:65`](../../docs/evidence/2026-07-29-cloudflare-workers-paid-provider-attestation.md#L65)
