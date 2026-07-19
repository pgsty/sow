---
title: '双云私有源站部署闭合'
type: 'feature'
created: '2026-07-12T00:00:00+08:00'
status: 'done'
baseline_commit: '84800a60e01aaaf8dc5b189c3ddb1380930f4865'
review_loop_iteration: 2
context:
  - '{project-root}/docs/adr/0004-edge-token-verifier-deployment-contract.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 双云鉴权适配器依赖的私有源站不是仓库内可部署制品：Cloudflare 配置引用不存在的 service Worker，EdgeOne 依赖未定义的 bearer gateway；当前真云 harness 也无法证明 CDN 请求实际穿过这些组件。

**Approach:** 提供 service-only Cloudflare R2 origin Worker；EdgeOne 直接以冻结的 COS bucket/region 和 SigV4 GET/HEAD 回源。两端复用严格对象 key/URL 安全合同，补齐单文件构建、部署清单、最小权限和 opt-in 真云探针。

## Boundaries & Constraints

**Always:** 只允许 GET/HEAD；对象 key、host、scheme、method fail closed；Cloudflare origin 无公开 route；COS host 从 bucket+region 推导且凭据只发往该 host；错误 private/no-store；客户 token/Basic credential 不进入源站 URL/签名或日志；404 fallback 与 HEAD 保持现有路由语义。

**Ask First:** 需要真实 R2/COS/Cloudflare/EdgeOne 写入、部署、付费或凭据时暂停并保留为外部 PoC。

**Never:** 通用云抽象、公开 origin gateway、Workers/Edge Cache API、把秘密写入配置/测试/日志、修改 Go CLI materialize/adoption、把本地契约测试称为真云通过。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| R2 GET/HEAD | 内部固定 host + 安全 key | R2 object body/metadata/ETag；HEAD 无 body | 404/存储故障为 private no-store |
| COS GET/HEAD | 冻结 bucket/region + 平台 secret | 向唯一 COS host 发 SigV4 请求 | 配置、crypto、fetch 故障 fail closed |
| Pro fallback | gated key 404、public key 存在 | 第二个干净、同源、已签名请求成功 | 非 404 不继续 fallback |
| 恶意路径 | scheme-shaped、编码、query、穿越、错 host | 不能改变 origin 或泄露 secret | 404/503 且不接触存储 |

</frozen-after-approval>

## Code Map

- `edge/shared/private-origin.mjs` -- 双端 key/URL 安全原语。
- `edge/cloudflare/origin.mjs` -- service-only R2 GET/HEAD Worker。
- `edge/edgeone/function.mjs` -- COS SigV4 私有回源适配器。
- `edge/build.mjs`、`edge/dist/*` -- 真正无相对 import 的可部署单文件。
- `edge/test/contract.test.mjs` -- 双端共享路由、SSRF、fallback、HEAD 与 origin 测试。
- `test/compat/real_cloud_test.go` -- opt-in CDN→edge→private-origin 探针。

## Tasks & Acceptance

**Execution:**
- [x] 新增共享私有源站合同与 Cloudflare R2 Worker、部署配置。
- [x] 用 COS SigV4 GET/HEAD 替代 EdgeOne bearer gateway，并冻结供应商 host。
- [x] 修复 bundle 构建，更新 dist、变量/秘密/最小权限文档。
- [x] 扩展本地契约测试和真云资源/harness 探针。
- [x] 保留 main/beta 同 host `https-bearer` 接口，并强制 beta alias/generation/mirrorlist/fallback 整组走 beta host。
- [x] 将 routed pointer/delete 的 client URL 与 exact `.sow/*` clean-key purge 收入同一 plan 闭包。

**Acceptance Criteria:**
- Given 两个有效对象，when 两端执行 GET/HEAD 与 gated→public fallback，then 返回相同对象语义且所有源站 URL 无客户凭据。
- Given 恶意 key、host、method 或配置，when handler 执行，then 不接触 R2/COS 或不把 SigV4 secret 发往非 COS host。
- Given 构建完成，when 检查 dist，then 三个部署产物无相对 import 且源码测试与 bundle smoke test 通过。
- Given 真云资源尚未提供，when 默认测试执行，then 无网络/秘密读取且报告真云 PoC 仍开放。
- Given `r2-service` 或 `cos-sigv4`，when 返回对象，then 明确报告 cache `BYPASS`，不得作为 FR-38 HIT/tiered/purge 证据。
- Given POC-06 使用 `https-bearer`，when 两个不同 token 请求真正 gated 对象并经历一次 paired exact client/clean-key purge，then anonymous public 与 direct clean URL 均为 edge-contract 404、两 token clean URL digest 相同、第二 token 为供应商 `HIT`，purge 后返回新字节且第二 token 再次 `HIT`；事务 L3 可能在外部 token A 前已 refill，因此不伪造必然 MISS。否则回退 Basic no-store。

## Spec Change Log

- Iteration 1 — 审查发现 R2 Worker binding/S3 API 与 EdgeOne 跨 host COS Fetch 均不进入所需常规 CDN cache。规格补充 direct adapters 只能证明私有读取且必须标记 `BYPASS`，保留同 host `https-bearer` global-fetch interface，并把双 token、真 gated、HIT、最小 purge 与 Basic no-store 写成 POC-06 门禁。KEEP：固定供应商 host、SigV4、service-only R2、Range/HEAD、SSRF/redirect/secret 负例与三个 standalone bundle。
- Iteration 2 — 审查发现 beta clean fetch 错用 main host，且 client-visible purge 未必失效 clean cache key。两 adapter 现按首个 `.sow/beta/` key 把整组 fallback 固定到 beta host，并只接受与声明 main/beta origin 完全相等的 alias；publish plan 强制 routed pointer/delete 同时包含 client CDNPath 与 exact `.sow/*` clean-key purge，缺失/额外均拒绝。真云 gate 升级为双独立 token、gated-only 两代字节、anonymous 404、same digest、second-token HIT、GET/HEAD/Range 与 paired purge refresh。

## Design Notes

Cloudflare service binding 本身是 capability，origin Worker 只绑定 R2 且无公开 route。EdgeOne 直接签 COS 请求可少部署一个 bearer gateway；endpoint 不接受任意 URL，而由已验证 bucket 与 region 机械生成。两条 direct transport 都绕过供应商 CDN cache，仅是安全/正确性 adapter。`https-bearer` 保留 main/beta clean same-host global Fetch 候选，内部 fetch URL 与 plan 中 exact `.sow/*` purge key 必须逐字一致；只有真云双 token HIT/tiered/purge 可升级 FR-38。standalone Nginx Basic 必须 no-store。

## Verification

**Commands:**
- `cd edge && npm run build && npm test` -- dist 当前且 26/26 合同测试通过。
- `node --check edge/dist/cloudflare-worker.mjs && node --check edge/dist/cloudflare-origin-worker.mjs && node --check edge/dist/edgeone.js` -- 单文件语法有效。
- `go test ./test/compat -run 'RealCloud' -count=1` -- 默认跳过真云，所有本地 harness guard 通过。

## Suggested Review Order

**Clean routing and cache identity**

- Shared entry point binds public view to every origin request.
  [`contract.mjs:90`](../../edge/shared/contract.mjs#L90)

- Cloudflare selects exact main/beta origins and rejects alias drift.
  [`worker.mjs:75`](../../edge/cloudflare/worker.mjs#L75)

- EdgeOne preserves the same origin-view contract before SigV4 fallback.
  [`function.mjs:84`](../../edge/edgeone/function.mjs#L84)

**Deployable private transports**

- Service-only R2 handler confines host, method, key, conditions, and ranges.
  [`origin.mjs:11`](../../edge/cloudflare/origin.mjs#L11)

- Direct COS transport derives one host and signs GET/HEAD without redirects.
  [`function.mjs:61`](../../edge/edgeone/function.mjs#L61)

**Transactional purge closure**

- CDN planning derives verification and paired exact purge surfaces separately.
  [`plan.go:168`](../../internal/publish/plan.go#L168)

- Routed pointers and deletes cannot omit or expand clean-key invalidation.
  [`plan.go:505`](../../internal/publish/plan.go#L505)

**Evidence and deployment boundary**

- Shared tests distinguish direct BYPASS from candidate HIT and beta-host routing.
  [`contract.test.mjs:385`](../../edge/test/contract.test.mjs#L385)

- Live harness requires two tokens, gated-only bytes, HIT, paired purge, and ranges.
  [`real_cloud_test.go:569`](../../test/compat/real_cloud_test.go#L569)

- ADR enumerates every client URL to exact clean-cache purge mapping.
  [`0012-private-origin-deployment-contract.md:65`](../../docs/adr/0012-private-origin-deployment-contract.md#L65)

- Cloudflare candidate pins non-recursive same-zone Fetch semantics explicitly.
  [`wrangler.cache-poc.toml.example:10`](../../edge/cloudflare/wrangler.cache-poc.toml.example#L10)
