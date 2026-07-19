# ADR-0012: 双云私有源站传输与缓存拓扑边界

Status: provisional — private-origin transports accepted; FR-38 cache topology pending POC-06

Date: 2026-07-12

## Context

FR-38 要求两个鉴权边缘组件在验 token 后向不含客户凭据的干净 URL 发子请求。原实现的
Cloudflare 配置引用了仓库中不存在的 `sow-private-repository-origin` service，EdgeOne
则假定外部存在一个接受 bearer 的 HTTPS gateway。二者都不是可从本仓库部署、测试和审计
的完整链路；任意 origin URL 还扩大了 SSRF 与供应商 secret 外送风险。

## Decision: deployable private-origin transports

Cloudflare 使用两个最小 Worker：公开鉴权 Worker 只持有 `ORIGIN`/`TOKEN_VERIFIER`
service binding；私有 origin Worker 只持有 `REPOSITORY` R2 binding。origin Worker 无
workers.dev、preview URL 或公开 route，只接受 service binding 使用的固定 HTTPS host、
GET/HEAD 和严格 canonical key。它负责 R2 metadata、ETag、conditional 和 Range 响应，不
提供 List/Put/Delete。

EdgeOne 不再依赖 bearer gateway。函数从冻结的 bucket 与 region 推导唯一
`<bucket>.cos.<region>.myqcloud.com` host，用平台 secret 经 Web Crypto 生成 S3 SigV4
GET/HEAD。对象 key 在签名前验证并按 AWS URI 规则编码；签名请求使用 `redirect: manual`，
任何 3xx 都转为私有 `502`。配置不接受可指向第三方的 origin URL，因此 COS
Authorization、SecretID/session token 不会被发送到非 COS host。

两端保留同一 gated→public 404 fallback、Range/HEAD、响应头清洗和
`X-SOW-Edge-Contract: sow-edge-runtime/v2` 部署标识。Cloudflare origin 错误和所有 Pro
客户端响应均为 `private, no-store`。

两端以显式 `SOW_ORIGIN_MODE` 区分传输，不允许静默回退：Cloudflare 的
`r2-service` 和 EdgeOne 的 `cos-sigv4` 是可部署、可审计的私有读取路径；二者均在响应中
报告 `X-SOW-Origin-Cache-Status: BYPASS`。它们**不满足、也不宣称满足** FR-38 的常规
CDN/tiered cache 归一化。

## Preserved cache-topology interface

两端同时保留 `SOW_ORIGIN_MODE=https-bearer`：token/Basic 在边缘鉴权后被剥离，再对
同 host 干净 URL 发 global `fetch`，只携带独立 origin bearer。beta public view 的 alias、
strong generation、静态 mirrorlist 与 `.sow/beta/` shared payload fallback 整组固定使用
`SOW_BETA_BASE_URL`，namespace/view 不一致即失败；latest/Pro 使用 `SOW_PUBLIC_BASE_URL`。
若保留 `SOW_ORIGIN_BASE_URL` / `SOW_BETA_ORIGIN_BASE_URL` 别名，
它们必须分别与这两个声明值完全相同，不能成为任意 origin URL。
该模式报告规范化的供应商 cache status 与 clean URL SHA-256，供两个不同 token 的真云
HIT/Purge PoC 对账。EdgeOne 强制同 host，因为官方 Fetch 合同只在入站 host、fetch URL
host 和 Host header 相同的情况下访问节点缓存或回源。

这个接口只是 POC-06 候选拓扑，不是本地通过项。部署必须证明：外部请求不能匿名访问
`.sow/gated`；两个 token 收敛同一 clean URL；第二 token 命中相同 cache entry；最小 purge
后返回新字节并由后一个 token 报告 HIT。发布必须同时使客户端翻转/指针 URL 与其实际
读取的 credential-free clean cache key 失效；只 purge `/pro/v1/basic/...` 不能证明
`.sow/gated/...` 已失效。`publish.Plan` 已将这两个 exact URL 作为 routed pointer/delete
的强制闭包，缺失或额外扩张均拒绝；供应商实际 purge/cache 行为仍由 POC-06 验证。若 Cloudflare custom-domain/WAF 或 EdgeOne same-host
topology 无法同时满足机密性与缓存层级，商业入口回退独立 Basic Auth no-store。

Cloudflare 候选配置显式锁定 `global_fetch_private_origin`：same-zone global Fetch 因而绕过
映射 Worker 与 Cloudflare 安全规则直达 zone origin；若改为
`global_fetch_strictly_public`，请求会回到 public front door 并可能递归鉴权 Worker。因此
same-host origin 必须自行验证独立 `SOW_ORIGIN_BEARER`，不能把 WAF 当成 origin 认证。
由于子请求携带 `Authorization`，origin 响应还必须显式允许共享缓存（`public`、
`s-maxage` 或 `must-revalidate`），且不得含 `private`、`no-store`、`Set-Cookie` 或
`Vary: Authorization`；否则 Cloudflare 会报告 `BYPASS`，POC-06 必须失败。

## Exact purge mapping

`publish.Plan` 的 pointer/delete purge 必须与 edge 实际 Fetch URL 逐字一致：

| 入口 | client/read-back URL | clean cache URL |
|---|---|---|
| latest APT `InRelease`、YUM `repomd.xml` + `.asc`、mutable asset | `/<legacy-path>` | 同一 URL，因此只 purge 一次 |
| beta APT/YUM flip 与 mutable asset alias | beta host `/<legacy-path>` | beta host `/.sow/beta/<legacy-path>` |
| stable APT/YUM flip 与 mutable asset | `/pro/v1/basic/<legacy-path>` | `/.sow/gated/<legacy-path>` |
| stable YUM channel / 动态 mirrorlist | `/pro/v1/basic/_sow/v1/mirrorlist/<view>/<repo>/<os>/<arch>.txt` | `/.sow/channels/<view>/<repo>/<os>/<arch>.json` |
| snapshot route | `/pro/v1/basic/_sow/v1/snapshots/<id>/_route.json` | `/.sow/snapshots/<id>.json` |
| latest/beta OSS 静态 mirrorlist | `/_sow/v1/mirrorlist/<view>/<repo>/<os>/<arch>.txt` | 同一 host/URL，因此只 purge 一次 |

强 generation 与 content-addressed 对象不可变，不进入 purge。删除使用同一 client + clean
映射，但 `VerifyAbsent` 只从 client URL 执行；clean URL 是内部失效键，不是公开验证 API。

## Permissions and secrets

- Cloudflare origin 服务只有 R2 binding；部署权限仅覆盖两个 Worker 及该 binding，R2
  保持无公开 development/custom-domain 访问。
- EdgeOne COS 身份只授予 `name/cos:GetObject`、`name/cos:HeadObject`，资源限定为
  `qcs::cos:<region>:uid/<appid>:<bucket-with-appid>/*`；不得授予 List/Put/Delete/ACL。
- `SOW_COS_SECRET_ID`、`SOW_COS_SECRET_KEY`、可选 `SOW_COS_SESSION_TOKEN` 和 verifier
  secret 只存在于供应商 secret store，互相独立。

## Consequences

- 仓库现在包含两个云端私有源站路径的完整部署制品，不再依赖未定义组件。
- [ADR-0037](0037-pre-upload-confidential-edge-denial-attestation.md) 进一步要求任何 gated
  publication 在首个远端 mutation 前，从配置的客户端域匿名取得当前 v2 runtime 的精确
  private 404；raw bucket/custom-domain 404、旧 Worker 或公开 cache 响应均失败，且无跳过面。
  该 data-plane 门是本 ADR 部署合同的必要条件，不替代完整 provider inventory/lease/POC。
- EdgeOne 少部署一个 gateway，但边缘运行时必须提供 Fetch 与 Web Crypto。
- 本地契约可证明请求、签名、SSRF、fallback、Range 和 cache-observation interface；不能
  证明供应商 cache HIT、tiered cache、WAF 机密性或 purge。
- Cloudflare 官方明确 Worker API binding/S3 API 直读不经过 cache，只有 R2 custom domain
  进入 Cloudflare Cache；EdgeOne 跨 host COS fetch 同样不符合其节点缓存 Fetch 条件。
- 独立 Nginx Basic Auth 回退保持 `private,no-store`。仅在边缘先鉴权再发 clean subrequest
  时，Authorization 才可安全排除于共享 cache key。

## Protocol references

- Cloudflare R2 Workers API：<https://developers.cloudflare.com/r2/api/workers/workers-api-reference/>
- Cloudflare R2 cache 边界：<https://developers.cloudflare.com/r2/reference/consistency/>
- Cloudflare R2 custom domain cache：<https://developers.cloudflare.com/r2/buckets/public-buckets/>
- Cloudflare same-zone global Fetch compatibility：<https://developers.cloudflare.com/workers/configuration/compatibility-flags/#global-fetch-strictly-public>
- Cloudflare fetch cache/purge URL：<https://developers.cloudflare.com/workers/reference/how-the-cache-works/#single-file-purge-assets-cached-by-a-worker>
- Cloudflare Authorization/cache 条件：<https://developers.cloudflare.com/cache/concepts/cache-control/#conditions>
- EdgeOne Fetch 同 host cache 条件：<https://cloud.tencent.com/document/product/1552/81897>
- 腾讯 COS 的 AWS S3 SDK 兼容入口：<https://cloud.tencent.com/document/product/436/37421>
- 腾讯 COS 策略 action/resource 语法：<https://cloud.tencent.com/document/product/436/18023>
