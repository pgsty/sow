# ADR-0037: gated 发布前必须证明版本化边缘拒绝合同

Status: accepted

Date: 2026-07-19

## Context

R2/COS 的签名对象 API 与客户端访问域是两条不同的数据面。一个 bucket 即使只通过签名
API 写入，也可能同时被 custom domain 或供应商公开入口匿名读取。2026-07-19 在 owner
授权的非生产 Cloudflare `pro` 桶实测确认：写入的 run-owned 对象可从 main/beta raw
custom domain 匿名取得，删除 bucket object 后还会保留 1800 秒 exact stale HIT。

此前 `CloudflarePreflight` / `EdgeOnePreflight` 只验证计划 URL 与 Basic 凭据的本地形状。
因此把 `cdn.base_url` 错配到 raw public custom domain 时，stable/snapshot 发布可能先把
`.sow/gated/...` 上传，再在 L3 失败。失败虽然不会提交最终 checkpoint，却已经泄露了闭源
字节；这违反 FR-33/FR-36，且重放不能撤销已经发生的匿名读取。

## Decision

每次 publication 在本地 request 校验后、journal acquire 和任何远端 checkpoint/lock/
PUT/COPY/DELETE/purge 之前执行 provider preflight：

1. public-only plan 只做既有 URL/凭据形状校验，不新增网络请求，保持 latest/beta OSS 路径
   的可用性与增量成本。
2. 以下任一条件把 plan 判为 confidential：对象或删除命中 `.sow/gated/`；对象/删除的
   `CDNPath` 命中 `/pro/v1/basic/`；任一 purge、positive verify、unchanged probe 或
   absence verify URL 命中该 Basic 路由。持久计划不能通过只改某一列表绕过门禁。
3. confidential plan 必须向 configured CDN base 的固定保留路径
   `/.sow/gated/.sow-confidentiality-preflight` 发匿名 GET。请求不携带 token、Basic、
   Cookie 或 secret；即使 caller 提供带 `http.CookieJar` 的 client，也以 Jar-free copy
   执行。请求显式使用 `Accept-Encoding: identity`、no-store/no-cache，且不跟随 redirect。
4. 只有共享 edge runtime 的精确私有拒绝合同可通过：HTTP 404、正文 `not_found\n`、
   `X-SOW-Edge-Contract: sow-edge-runtime/v2`、`Content-Type: text/plain; charset=utf-8`、
   `X-Content-Type-Options: nosniff`，以及语义上精确的
   `private, no-store, max-age=0`。Location、Set-Cookie、WWW-Authenticate、内容编码、
   clean-URL/origin transport/cache 标记、重复 runtime header、长度漂移、超出 64 字节、
   read/close 失败均拒绝。
5. 任一失败返回 `ErrCapability`，保留 context cancellation 与 response close 原错误身份。
   产品不提供跳过开关；Cloudflare 与 EdgeOne 使用同一 Go 判定函数和同一 v2 schema 常量。

## Ordering and recovery

`Publisher.Run` 把带 context 的 preflight 放在 journal acquire 之前。失败不会创建本地
publication journal，也不会读取或修改 package source，更不会取得远端 lock/checkpoint。
CLI 在构造 parent expectation 时可能进行只读 checkpoint observation，但 preflight 失败后
PUT/COPY/DELETE/purge 必须保持为零。相同事务重放会重新执行门禁，不能依赖进程级缓存。

## Consequences and boundary

- raw bucket 404、供应商 HTML 404、旧 v1 Worker 或公开缓存响应都不能冒充边缘部署。
- 普通 L3 CDN read-back 同样清除 ambient CookieJar；Basic 路由只允许配置显式提供的
  Basic credential，public 路由不获得第二条 cookie 鉴权通道。
- stable/snapshot 的首个 gated mutation 现在受 data-plane deployment identity 保护；正常
  public-only 发布没有额外网络 RTT。
- 该探测是必要条件，不是 POC-06 的替代品。它不能证明不存在另一个公开 bucket alias，
  不能消除探测后外部管理员改 route 的 TOCTOU，也不能证明 token verifier、private origin、
  purge、multi-PoP/cache-log 或 COS/EdgeOne 真供应商行为。ADR-0034/0035 的 sealed deployment、
  provider inventory 与 lease 仍负责这些控制面边界。
- 当前 owner 授权的 `pro.pigsty.io` / `beta.pro.pigsty.io` raw custom domain 会按设计失败，
  直至 v2 auth Worker 真正接管且 private-origin/route 合同通过。失败是安全状态，不应通过
  放宽 canary 来适配裸桶。
- 本门禁只能防止 SOW 新增 gated 泄露；既有外部写入或已经公开的对象必须由独立安全处置
  清理，不能依赖一次 publication 修复。

## Evidence

实现和可复现实跑见
[2026-07-19 confidential edge preflight evidence](../evidence/2026-07-19-confidential-edge-preflight.md)。
