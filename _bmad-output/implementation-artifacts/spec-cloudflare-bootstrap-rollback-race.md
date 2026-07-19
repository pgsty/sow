---
title: '收紧 Cloudflare bootstrap 回滚删除竞态'
type: 'bugfix'
created: '2026-07-18'
status: 'done'
review_loop_iteration: 1
baseline_commit: '84800a60e01aaaf8dc5b189c3ddb1380930f4865'
context:
  - 'docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 回滚先检查 route/Worker 身份，再经 leased wrapper 续租和全量 provider closure 后执行无条件删除，扩大了 Cloudflare 不支持条件删除所固有的 TOCTOU 窗口。

**Approach:** 把期望身份传入删除适配器；leased wrapper 先续租，再由真实适配器紧邻执行身份读取与删除。对供应商没有文档化 CAS 的边界保持明确，不声称能序列化 SOW 之外的管理员写入。

## Boundaries & Constraints

**Always:** 仅删除 sealed apply receipt 中的 exact route ID 与 auth/origin Worker；每次 mutation 前续租并复核 bucket/provider closure；漂移 fail closed；verifier 永不删除；重放安全；真实 SDK 与 fake 使用同一 checked-delete 接口。

**Ask First:** 扩大到 `pro` 测试 tuple 之外的云资源、引入未文档化 HTTP 前置条件、改变 verifier 所有权或生产资源边界。

**Never:** 写 CO/COS 或 Cloudflare 生产仓库；把 GET→DELETE 描述成供应商原子 CAS；用 `force=true`；用人工清理代替可恢复回滚。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|---------------------------|----------------|
| receipt-matching rollback | 当前 route/Worker 与 sealed receipt 一致 | 续租后紧邻 recheck→delete，最终 absence closure 通过 | N/A |
| drift before checked delete | route body 或 Worker deployment/version/ETag 已变 | 不发对应 DELETE，不删重建资源 | 返回 identity drift，保留租约供安全恢复 |
| lease/provider drift | 续租、bucket 或 zone/domain closure 改变 | inner recheck/delete 不运行 | fail closed |
| provider success then client error | DELETE 已生效但响应失败 | 下一次重放识别已收敛步骤并继续 | 不删除额外资源 |

</frozen-after-approval>

## Code Map

- `test/compat/real_cloud_cloudflare_bootstrap_test.go` -- bootstrap control、leased mutation boundary、SDK/fake 适配器和故障测试。
- `docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md` -- 冻结供应商能力边界与回滚语义。
- `docs/evidence/2026-07-18-cloudflare-pro-domain-readiness.md` -- exact non-production tuple 与当前真实云证据边界。

## Tasks & Acceptance

**Execution:**
- [x] `test/compat/real_cloud_cloudflare_bootstrap_test.go` -- 用 expected-identity checked delete 替换分离式检查/删除，并保持续租在 inner check 之前。
- [x] `test/compat/real_cloud_cloudflare_bootstrap_test.go` -- 增加 route/Worker 漂移、调用顺序、lease/provider 闭包与 replay 故障测试。
- [x] `docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md` -- 记录官方 API 无 CAS、收紧后的 HTTP 边界和不作出的并发承诺。

**Acceptance Criteria:**
- Given sealed receipt and unchanged exact resources, when rollback runs, then only matching routes/auth/origin are deleted and verifier remains byte/binding/identity-equivalent.
- Given drift injected immediately before an inner checked delete, when rollback runs, then that DELETE is not issued and the replacement survives.
- Given lease or provider closure renewal failure, when rollback reaches a mutation, then no inner checked-delete call occurs.
- Given current Cloudflare API lacks documented conditional delete, when docs and tests describe safety, then they distinguish SOW lease serialization from external-admin concurrency.

## Spec Change Log

- 2026-07-18: 独立 blind/edge 审查后补齐租约预算、精确探测、附件/版本闭包、响应丢失重放、rollback readiness 预检与 R2-only lease recovery。
- 2026-07-19: follow-up 安全审计把 readiness seal 从未加密 digest 升级为 Ed25519 v2；bootstrap plan 钉住 signer 公钥，私钥 seed 仅由环境注入，重算 envelope 或攻击者换钥均不能伪造 mutation readiness。

## Design Notes

Cloudflare Route Delete accepts only zone ID + route ID; Worker Delete accepts account ID + `force`. Neither current official API nor cloudflare-go v7.7.0 exposes a conditional delete precondition. The implementation therefore renews and revalidates the lease/provider closure, requires a full mutation-time budget, then exact-probes receipt identities even if provider inventory omitted them. Route deletion has an adjacent exact GET; Worker deletion rechecks account/zone attachments, exact schedules, active identity and the entire version set, with its final version page adjacent to DELETE. These remain non-atomic provider request sequences. The lease uses local wall time and is not an external-admin or cross-host clock-skew fencing token; the bounded deadline reduces the avoidable window without inventing a stronger guarantee.

## Verification

**Commands:**
- `go test ./test/compat -run 'TestRealCloudCloudflareBootstrap' -count=1` -- focused bootstrap suite passes.
- `go test -race ./test/compat -run 'TestRealCloudCloudflareBootstrap' -count=1` -- focused suite passes under race detector.
- `go test [-race] ./test/compat -run 'TestRealCloudProviderReadinessContractIsScopedAndRedacted|TestRealCloudCloudflareBootstrapReadinessSealRejectsLocalForgery|TestRealCloudCloudflareBootstrapPlanIsClosedAndDeterministic|TestRealCloudCloudflareBootstrapPlanBuilderConsumesExactEdgeContract|TestRealCloudCloudflareBootstrapSelectionFailsBeforeCredentials' -count=1` -- ordinary/race PASS；覆盖篡改后重算 SHA/size、攻击者换钥、malformed signer 与 plan key pin。
- `go test ./test/compat -count=1` -- ordinary compatibility package passes without cloud opt-ins.
- `go test -race ./test/compat -count=1` -- full compatibility package passes under the race detector.
- `go vet ./test/compat` -- compatibility package passes static analysis.
- `go test ./internal/publish -count=1` -- R2-only control client and publication provider tests pass.
- `git diff --check` -- no whitespace errors.

## Suggested Review Order

**安全契约**

- 先看回滚身份闭包、供应商非原子边界与明确限制。
  [`0034-cloudflare-nonproduction-worker-bootstrap.md:100`](../../docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md#L100)

**删除竞态边界**

- 每次变更先续租、复核 provider closure 并保留完整时间预算。
  [`real_cloud_cloudflare_bootstrap_test.go:196`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L196)

- 路由使用 receipt 精确身份执行紧邻 GET→DELETE。
  [`real_cloud_cloudflare_bootstrap_test.go:992`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L992)

- Worker 删除复核附件、活跃状态和完整版本集合。
  [`real_cloud_cloudflare_bootstrap_test.go:1023`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L1023)

**预检与最小权限**

- apply/rollback readiness 在凭据或客户端之前强制验证。
  [`real_cloud_cloudflare_bootstrap_registry_test.go:445`](../../test/compat/real_cloud_cloudflare_bootstrap_registry_test.go#L445)

- recover-lease 分支只构造 R2 lease store。
  [`real_cloud_cloudflare_bootstrap_test.go:315`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L315)

- 专用 R2 control client 从类型面移除 CDN 权限。
  [`http_cloudflare.go:34`](../../internal/publish/http_cloudflare.go#L34)

**回归证据**

- 真实 SDK 协议验证版本漂移、草稿版本和最终读取邻接。
  [`real_cloud_cloudflare_bootstrap_test.go:2999`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L2999)

- 供应商已成功但响应丢失时重放安全收敛。
  [`real_cloud_cloudflare_bootstrap_test.go:2398`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L2398)

- inventory 漏项仍按 receipt 精确探测目标身份。
  [`real_cloud_cloudflare_bootstrap_test.go:2567`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L2567)

- R2-only 客户端不需要 CDN token 或 endpoint。
  [`http_provider_test.go:108`](../../internal/publish/http_provider_test.go#L108)
