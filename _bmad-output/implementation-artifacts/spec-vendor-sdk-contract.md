---
title: '冻结厂商 SDK 契约'
type: 'refactor'
created: '2026-07-12'
status: 'done'
review_loop_iteration: 0
baseline_commit: '84800a60e01aaaf8dc5b189c3ddb1380930f4865'
context:
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 当前 R2/COS 对象操作、Cloudflare purge 与 EdgeOne purge 都由 SOW 手写 HTTP 签名和协议，违反 PRD 冻结的“对象存储共用一个 S3 SDK、CDN 分别使用两家具体 SDK”契约。

**Approach:** 用 AWS SDK for Go v2 S3 同时承载 R2 与 COS，用 cloudflare-go 和腾讯云 TEO Go SDK 承载各自 purge；保留现有厂商条件头、能力探针、精确 URL、任务完成等待与失败关闭语义。

## Boundaries & Constraints

**Always:** 固定官方模块版本；R2/COS 共用同一个 S3 客户端实现；继续签名绑定完整性元数据与条件头；保持无重定向、无隐式整桶 list、显式批次、条件冲突错误分类和 COS 每次发布的 versioning 探针。

**Ask First:** 只有官方 SDK 无法表达且中间件也无法安全补齐的条件语义，或替换会迫使真实供应商契约降级时才停止并上报。

**Never:** 不新增通用云插件抽象；不保留可达的手写 SigV4/TC3/CDN REST 备用路径；不把真实云缺凭据伪报为通过；不放宽现有 URL/secret/条件写验证。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| R2/COS object | get/head/list/put/copy/delete | 两目标经同一 AWS S3 SDK，厂商条件头在 SDK 签名前注入 | 404/409/412/501 映射到既有领域错误 |
| Cloudflare purge | 精确 URL，超过 100 条 | cloudflare-go 按 100 条分批 purge | 任一批失败即失败关闭 |
| EdgeOne purge | 精确 URL | TEO SDK 创建任务并轮询同一 JobId 到 success | 错配、未知或失败状态拒绝提交 |
| COS capability | 未版本化/已启用/已暂停 | 每次调用 SDK GetBucketVersioning | Enabled/Suspended/未知状态返回 ErrCapability |

</frozen-after-approval>

## Code Map

- `internal/publish/http_object.go` -- R2/COS 共用 S3 SDK 客户端与厂商方言中间件。
- `internal/publish/http_cloudflare.go` -- R2 provider 与 Cloudflare SDK purge。
- `internal/publish/http_tencent.go` -- COS provider 与 TEO SDK purge/轮询。
- `internal/publish/*http*_test.go` -- 协议、失败关闭和 SDK 类型契约。
- `go.mod` / `go.sum` -- 官方 SDK 固定版本。

## Tasks & Acceptance

**Execution:**
- [x] `internal/publish/http_object.go` -- 用 AWS SDK v2 S3 替换手写对象 HTTP/SigV4，同时保留 R2/COS 条件语义。
- [x] `internal/publish/http_cloudflare.go` -- 用 cloudflare-go v7 精确 purge。
- [x] `internal/publish/http_tencent.go` -- 用腾讯 TEO SDK 创建并等待 purge。
- [x] `internal/publish/*_test.go` -- 更新协议夹具并证明具体 SDK 构造与失败关闭。
- [x] `go.mod` / `go.sum` / ADR -- 固定版本并记录边界。

**Acceptance Criteria:**
- Given cf 与 cos 构造器，when 检查对象客户端，then 两者均持有同一 AWS S3 SDK 实现且分别持有 Cloudflare v7 与 TEO v20220901 客户端。
- Given 已有聚焦协议测试，when 执行，then 条件写、复制、删除、versioning 探针、精确 purge 和任务等待语义继续通过。
- Given 源码扫描，when 搜索签名与手写 CDN API，then 不再存在可达的自研 SigV4/TC3/purge 实现。

## Spec Change Log

## Design Notes

AWS SDK 输入覆盖标准条件字段；R2 Copy 与 COS forbid-overwrite/COS header 方言由 Smithy finalize 中间件在官方签名器之前转换并签名绑定。响应仅做 COS metadata 名称兼容和有界读取，不绕过 SDK 解析。

## Verification

**Commands:**
- `go test -count=1 ./internal/publish ./internal/cli` -- expected: PASS
- `go vet ./internal/publish ./internal/cli` -- expected: PASS
- `go mod verify` -- expected: all modules verified

## Suggested Review Order

**共享对象存储边界**

- 从单一 S3 SDK 构造器理解双目标共享模型。
  [`http_object.go:94`](../../internal/publish/http_object.go#L94)

- 在官方签名前投影闭集厂商条件头。
  [`http_object.go:362`](../../internal/publish/http_object.go#L362)

- 有界响应、根校验和 COS metadata 兼容集中处理。
  [`http_object.go:486`](../../internal/publish/http_object.go#L486)

**具体 CDN SDK**

- Cloudflare v7 客户端与 100 URL 精确批次。
  [`http_cloudflare.go:39`](../../internal/publish/http_cloudflare.go#L39)

- Tencent TEO 构造、零重试与拒绝重定向。
  [`http_tencent.go:55`](../../internal/publish/http_tencent.go#L55)

- EdgeOne 创建任务后绑定同一 JobId 等待完成。
  [`http_tencent.go:155`](../../internal/publish/http_tencent.go#L155)

**契约与负例**

- 编译期确认一个 S3 SDK 加两个具体 CDN SDK。
  [`audit_http_test.go:232`](../../internal/publish/audit_http_test.go#L232)

- HTTP-200 内嵌 Error 与超大 XML 均失败关闭。
  [`http_provider_test.go:284`](../../internal/publish/http_provider_test.go#L284)

- 固定官方模块版本并保持可重现依赖图。
  [`go.mod:7`](../../go.mod#L7)

- ADR 记录允许的中间件缝隙与真云证据边界。
  [`0016-frozen-vendor-sdk-boundary.md:1`](../../docs/adr/0016-frozen-vendor-sdk-boundary.md#L1)
