---
title: 'Cloudflare 非生产 bootstrap 支持静态 entitlement'
type: 'feature'
created: '2026-07-20T00:00:00+08:00'
status: 'done'
review_loop_iteration: 0
baseline_commit: '7a54e79'
context:
  - '{project-root}/docs/adr/0004-edge-token-verifier-deployment-contract.md'
  - '{project-root}/docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Cloudflare edge runtime 已支持 `env://NAME` 静态 entitlement，但真实非生产 bootstrap 只接受 `provider://ID`，强制预存独立 verifier Worker，把 PRD 未要求的商业服务变成 token PoC 前置阻塞。

**Approach:** 将 plan、绑定审计、apply/rollback 与 SDK 协议扩展为严格联合类型：保留 provider-service，新增由 edge contract 声明、运行时注入的 static-secret。秘密不进入持久证据。

## Boundaries & Constraints

**Always:** 模式由正典 `--edge-contract cf` 决定；provider 仍要求独立 verifier 的精确身份与不可公开证明；static 只能有一个与 `env://NAME` 同名的 `secret_text`，值在 mutation gate 后读取并于上传前严格校验；保持租约、共享 zone 闭包、精确路由、幂等与秘密擦除。

**Ask First:** 写生产/非指定资源；扩大到 DNS、custom domain、cache rules、其他 Worker 或仓库 payload；改变 provider 契约。

**Never:** 持久化 token、token SHA 列表、entitlement JSON 或凭据；用 plain-text 代替 secret；provider 静默降级；写任何正式仓库。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| provider | provider service contract | 保持三 Worker 闭包 | verifier 漂移在 mutation 前失败 |
| static | env secret contract | 只管理 auth/origin 与两路由 | 缺失、超限、非正典 entitlement 上传前失败 |
| static 重放/回滚 | sealed receipt | apply 无副作用；rollback 精确删除 | 外部漂移或 receipt 篡改失败关闭 |
| 类型混淆 | contract 与模式字段冲突 | plan 拒绝 | 不读取凭据或发请求 |

</frozen-after-approval>

## Code Map

- `internal/config/edge.go` -- provider/env contract 与 secret 名来源。
- `test/compat/real_cloud_cloudflare_bootstrap_registry_test.go` -- plan/descriptor 与离线闭包。
- `test/compat/real_cloud_cloudflare_bootstrap_test.go` -- SDK、事务、receipt、回滚。
- `edge/shared/contract.mjs` -- entitlement JSON 权威语义。
- `docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md` -- mutation 权限契约。

## Tasks & Acceptance

**Execution:**
- [x] `test/compat/real_cloud_cloudflare_bootstrap_registry_test.go` -- 升级闭合 provider/static plan 联合类型。
- [x] `test/compat/real_cloud_cloudflare_bootstrap_test.go` -- static secret 注入、SDK binding、库存/receipt/apply/rollback。
- [x] `internal/config/edge.go` -- 拒绝 variable/secret/service 跨类型同名，避免供应商 binding 歧义。
- [x] `test/compat/*_test.go` -- 覆盖类型混淆、泄漏、wire、重放和漂移负例。
- [x] `docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md` 与追踪证据 -- 冻结 static PoC 边界。

**Acceptance Criteria:**
- Given 合法 contract，when plan round-trip，then 模式字段确定且闭合。
- Given static plan，when SDK 上传 auth，then 只有正典变量、ORIGIN service 和一个 secret_text，且持久证据无 secret。
- Given provider fixture，when apply/rollback，then三 Worker 门禁无回归。
- Given模式混淆、非法 secret 或库存漂移，when 执行，then 首次相关 mutation 前无泄漏地失败。

## Spec Change Log

- 2026-07-20：初始实现完成；进入双路 adversarial review。实现保持 frozen intent，真实云 opt-in 全部关闭。
- 2026-07-20 review patch：Blind Hunter 发现 `env://ORIGIN` 等跨类型同名可生成重复 binding；共享 Go contract 与 bootstrap plan 现均在 provider request 前拒绝。
- 2026-07-20 review patch：secret leak detector 原先只绑定完整 entitlement JSON；现同时绑定每个 64-hex token digest，单条泄漏也会失败。
- 2026-07-20 review patch：Cloudflare 不回显 secret 值，未封存 static apply 不能证明旧 auth 使用当前 entitlement；恢复现于租约内精确删除同 run routes/auth 后重建，sealed replay 仍为纯观察。
- 2026-07-20 review patch：5,001-byte 负例原先同时带 trailing-space 非正典错误；现改为重新 marshal 的合法 5,001-byte JSON，单独证明 provider size gate。
- 2026-07-20 review patch：Edge Hunter 补出 TestMain readiness/evidence/watcher 三个 process-control env；均加入 static secret 保留名负例。
- 2026-07-20 review patch：sealed static replay 原先在 receipt 分支前仍读取 secret；runtime 现只建 R2/API 客户端，secret 延迟到无 receipt、已持租约且 readiness 复核后的 mutation 分支，closure 后再次验证 15 分钟余量。
- 2026-07-20 review patch：Blind Hunter 证明 `env://SOW_BASIC_ENTITLEMENTS` 会让同一 digest 文档同时授权 token 与 Basic；共享 config/bootstrap 均保留该独立安全 binding，并增加 15m/15m-1s TTL 边界。

## Design Notes

plan 记录 verifier `kind` 与非秘密部署形状。provider 记录 service/evidence；static 只记录 contract 中的 secret 名。Cloudflare 不回显 secret 值，因此 receipt 证明 binding 名/type，远端正负 probe 另证实际值和行为。
static entitlement 还受 Cloudflare 每个 Worker variable 5 KB 上限约束；本地采用保守的 5,000-byte
闭边界，并以 exact-limit/limit+1 测试防止 loopback SDK 自证掩盖真实 provider 拒绝。
所有 runtime binding 名共享一个闭合 namespace；static secret 还排除 bootstrap 自身控制环境变量。
Cloudflare 不回显 secret 值，因此 receipt 前中断的 static state 不被直接采纳：apply lease checked-delete
同 run routes/auth 后以当前 secret 重建；sealed receipt replay 仍纯只读，rollback 仍不读取 secret。

## Verification

**Commands:**
- `go test ./test/compat -run 'Cloudflare.*Bootstrap' -count=1` / race -- `1.073s` / `2.451s` PASS。
- `go test ./internal/config ./test/compat -count=1` -- `1.002s` / `14.912s` PASS。
- `go test -race ./internal/config ./test/compat -count=1` -- `11.873s` / `18.312s` PASS。
- `go test ./... -run '^$' -count=1`、edge 47/47 -- PASS。
- `go vet ./...`、项目 Staticcheck profile、`SA*,S1*` 与 `git diff --check` -- PASS。
- Blind/Edge 最终 corrected-tree review：Edge `[]`；Blind 代码 findings 清零，仅文档计时刷新已处理。
- 全部命令未读取云凭据或访问/写入测试及生产云资源。

## Suggested Review Order

1. 先看共享 binding namespace 与产品 contract 的强制边界：
   [internal/config/edge.go#L90](../../internal/config/edge.go#L90)、[internal/config/edge.go#L340](../../internal/config/edge.go#L340)
2. 再看 provider/static 严格联合类型与产品配置直连：
   [real_cloud_cloudflare_bootstrap_registry_test.go#L240](../../test/compat/real_cloud_cloudflare_bootstrap_registry_test.go#L240)、[real_cloud_cloudflare_bootstrap_registry_test.go#L991](../../test/compat/real_cloud_cloudflare_bootstrap_registry_test.go#L991)
3. 审查 secret 正典性、5 KB 与 15 分钟门禁：
   [real_cloud_cloudflare_bootstrap_test.go#L389](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L389)、[real_cloud_cloudflare_bootstrap_test.go#L450](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L450)
4. 审查 opaque-secret 中断恢复与真实 bootstrap 事务入口：
   [real_cloud_cloudflare_bootstrap_test.go#L2040](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L2040)、[real_cloud_cloudflare_bootstrap_test.go#L2455](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L2455)
5. 核对官方 SDK multipart 中唯一 `secret_text` binding：
   [real_cloud_cloudflare_bootstrap_test.go#L4612](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L4612)
6. 最后核对冻结决策与本轮证据边界：
   [ADR-0034#L57](../../docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md#L57)、[2026-07-20 evidence#L1](../../docs/evidence/2026-07-20-cloudflare-static-entitlement-bootstrap.md#L1)
