---
title: '真实云 provider attestation 支持静态 verifier'
type: 'feature'
created: '2026-07-20T00:00:00+08:00'
status: 'done'
review_loop_iteration: 11
baseline_commit: 'e833a90'
context:
  - '{project-root}/docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md'
  - '{project-root}/docs/adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Cloudflare bootstrap 已能用 `env://NAME` 部署两个 Worker，但完整 provider attestation、acceptance ledger 与 loopback SDK 仍强制第三个 verifier Worker，静态非生产 PoC 因而无法进入同一证据闭包。

**Approach:** 将 attestation 配置和证据升级为 provider/static 严格联合类型；static 从正典产品 contract 推导 secret binding，只证明名称、类型、闭合 runtime 与远端行为，绝不读取或持久化 secret 值。

## Boundaries & Constraints

**Always:** product config 是模式正典；provider 保持三 Worker 与独立部署摘要；static 只验 auth/origin、auth 上唯一 entitlement secret、两路由与禁用暴露；Cloudflare/EdgeOne runtime 必须同构；旧证据不能被新 schema 静默接受。

**Ask First:** 写真实云、改 provider 商业契约、扩大 DNS/custom-domain/log sink 或仓库 payload 范围。

**Never:** 将 entitlement JSON、token digest 清单、bearer 或 API 凭据写入 config、ledger、日志或错误；用空字段假装 provider 证据通过；接触生产仓库。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| provider | `provider://id` | 三 Worker 与 EdgeOne HTTPS verifier 闭包保持 | 任一独立摘要/身份缺失即失败 |
| static | `env://NAME` | 两 Worker；auth/EdgeOne runtime 各含 exact secret | 第三 Worker 或 provider 字段出现即失败 |
| mode confusion | product/config/evidence 不一致 | 首次 provider request 前拒绝 | 不读取凭据、不产 durable fact |
| ledger replay | v4 provider/static fact | 按 kind 校验互斥字段 | v3/混合/空证据拒绝 |

</frozen-after-approval>

## Code Map

- `test/compat/real_cloud_test.go` -- 真实验收产品配置与静态 secret 名。
- `test/compat/real_cloud_provider_attestation_test.go` -- config、SDK 收集、证据与 loopback provider。
- `test/compat/real_cloud_cloudflare_bootstrap_test.go` -- official SDK immutable-runtime fixture shared with attestation closure。
- `test/compat/real_cloud_acceptance_ledger_test.go` -- durable fact 严格联合类型。
- `docs/adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md` -- attestation 决策。
- `docs/requirements-traceability.md` -- FR-38/POC-06 证据边界。

## Tasks & Acceptance

**Execution:**
- [x] 升级 config/collector/deployment identity schema，加入 verifier kind/name 严格联合类型。
- [x] static Cloudflare 只收集 auth/origin，并在 auth binding 中证明 exact `secret_text`。
- [x] static EdgeOne runtime 证明同名 secret，禁止 provider URL/bearer/deployment 字段。
- [x] acceptance ledger 按 kind 校验互斥身份、摘要和 ETag。
- [x] provider/static loopback SDK、混淆、额外 Worker/secret 与重放负例。
- [x] ADR、追踪矩阵与离线证据更新。

**Acceptance Criteria:**
- Given static product contract, when config decode and provider collection run, then no verifier Worker API request is issued and durable fact contains no secret.
- Given provider fixture, when the same suite runs, then all existing three-Worker evidence remains valid.
- Given mixed fields, extra verifier Worker, wrong secret name or provider/static ledger substitution, then validation fails closed.
- Given corrected tree, when ordinary/race/SDK/edge/static checks run, then all pass with real-cloud opt-ins off.

## Spec Change Log

- 2026-07-20：从 `e833a90` 开始实现；所有真实云 mutation opt-in 保持关闭。
- 2026-07-20：实现完成并进入双重独立审查；corrected-tree compat/race/compile/vet/staticcheck/edge 全绿。
- 2026-07-20 review loop 1：关闭 attestation 自选产品模式、ledger 跨配置拼接和 verifier 语法放宽；EdgeOne 只接受 `secret` 类型且 value 已脱敏，拒绝同名 plaintext 冒充。
- 2026-07-20 review loop 2：Cloudflare binding 按 SDK union 关闭残留能力字段；ledger 从 exact product YAML 持久绑定 canonical verifier reference，拒绝语法合法的跨 secret 名拼接；harness 升级 v8。
- 2026-07-20 review loop 3：active 两 stage × 两 vendor 的 product config 摘要闭包前移到六组 provider/publisher credential 读取前，并由读取哨兵负例锁定。
- 2026-07-20 review loop 4：provider 入口拆出不读 entitlement bearer 的 resource-only loader；两层哨兵覆盖八个秘密变量；Cloudflare 要求显式 non-null bindings array 与 raw string value，拒绝 SDK 零值吞掉的缺失/null/错类型响应。
- 2026-07-20 review loop 5：不信任 SDK 对重复 object key 的投影；独立解析 raw resources，要求 bindings/script/script_runtime 三键各恰好一次、类型正确且无未知键。
- 2026-07-20 review loop 6：继续逐 token 关闭 nested script/runtime/limits；duplicate etag/limits、string `cpu_ms`、non-string flag 与缺失/未知键均失败。
- 2026-07-20 review loop 7：补全 official SDK immutable-runtime fixture，并对独立 `/settings` raw body 做 exact outer/cache/limit/observability/logs/traces token-walk；duplicate/missing/wrong-type/null projection 全部失败。
- 2026-07-20 review loop 8：将 raw settings binding 规范化多集合与 active immutable version 精确对账；schedule/subdomain raw 响应要求 exact empty array/explicit false，拒绝 null、重复键与 capability drift。
- 2026-07-20 review loop 9：完整 routing/inventory 独立重检复用同一 subdomain raw predicate，不能由 SDK null/duplicate false 零值伪造 workers.dev/preview 已关闭。
- 2026-07-20 review loop 10：Tencent SDK 丢弃 raw JSON，故专用限长/清零 transport 在 SDK 前 exact token-walk runtime wire，duplicate `Type`/`Value`、null/unknown/missing/wrong-type 均失败。
- 2026-07-20 review loop 11：wire guard 在 HTTP status 分支前统一限读/关闭/清零；非 200 返回固定错误，Tencent SDK 不能无界读取或嵌入 oversized error body。
- 2026-07-20：review-loop-11 corrected tree 经 Blind/Edge 两路独立复审均返回 `[]`，状态置为 done。

## Suggested Review Order

1. `test/compat/real_cloud_provider_attestation_test.go:282`：resource-only 入口、外部产品配置与 stage/config 的 pre-credential 顺序。
2. `test/compat/real_cloud_provider_attestation_test.go:1734`、`:1953`、`:2121` 与 `:2385`：Cloudflare active Worker、raw resources/settings/schedule/exposure exact closure 与 binding union 对账。
3. `test/compat/real_cloud_provider_attestation_test.go:298`、`:3282` 与 `:4864`：EdgeOne provider/static runtime、pre-SDK raw wire guard 与脱敏 `secret` 合同。
4. `test/compat/real_cloud_acceptance_ledger_test.go:363`：产品 YAML verifier binding、v8 ledger 重放与 provider/static durable union。
5. `test/compat/real_cloud_provider_attestation_test.go:4287`、`:4322`、`:4505`、`:4742`、`:4772`、`:4824`、`:5054` 与 `:5128`：credential-read、duplicate/null/type/capability confusion、static/provider SDK 回归。
6. `docs/evidence/2026-07-20-static-provider-attestation.md`：corrected-tree 命令、计时与仍开放的真实云证据边界。
