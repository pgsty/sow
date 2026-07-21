# 2026-07-18 真实 Cloudflare R2 存储协议证据

## 结论

在 owner 明确授权、编译期 registry 精确固定的非生产 Cloudflare `pro` 空桶完成了真实
S3 协议测试。未读取、写入或清理任何生产 CO/COS/Cloudflare 仓库。

实测通过：create-only PUT、stale `PutObject If-Match` 拒绝、两个并发 CAS 恰好一个赢家、
HEAD、流式 GET、正文/metadata/ETag 一致性、stale source CopyObject 拒绝、正确 source ETag
server-side copy。实测同时证明 R2 **不支持条件 DeleteObject**：故意错误的 delete ETag
返回成功并删除本次 run-owned copy；其余对象只在 run lease 前后稳定、连续两次
HEAD→streamed GET 正文身份一致后，调用明确无条件的 provider cleanup。该 storage-only
用例没有构造 publication checkpoint，也不把这一步伪报为真实 Publisher checkpoint-fenced
事务。测试前、独立超时上下文 defer 清理后及 `rclone` 清单均证明 bucket 为空。

## 固定资源与安全门

```text
account_id = 72cdbd1b54f7add44ecbd3d986399481
r2_endpoint = https://72cdbd1b54f7add44ecbd3d986399481.r2.cloudflarestorage.com
bucket = pro
run_id = sow-r2-storage-20260718-211500
```

入口在 credential/network 前强制：全局非生产确认、exact provider-readiness resource JSON、
endpoint+bucket 绑定确认、route-safe run ID，以及首次 ListObjectsV2 结果必须为零。cleanup
只接受 `.sow/acceptance/r2-storage/<run-id>/` 下本次登记的 exact key，且连续两次当前正文
size/SHA-256/ETag 必须命中本次 body allowlist；每次 payload cleanup 前后还重验 run lease。
协议 context 超时后 defer 使用独立两分钟 context；任一 payload 未确认 absent 时保留 lease，
不执行“列出后清桶”。secret 只在进程环境中组装，测试输出和错误经过 secret fragment 泄漏断言。

## 实跑命令

credential 值由本机已有 `rclone cf:` 配置在同一个 shell 内转成严格 JSON；以下省略该值，
命令没有把 access key 或 secret 写入文件或 stdout：

```bash
SOW_RUN_REAL_CLOUD_R2_STORAGE=1 \
SOW_REAL_CLOUD_NONPRODUCTION_CONFIRM='I-CONFIRM-DEDICATED-DISPOSABLE-NON-PRODUCTION-SOW-TEST-RESOURCES' \
SOW_REAL_CLOUD_PROVIDER_READINESS_RESOURCE_JSON='<exact registry resource JSON>' \
SOW_REAL_CLOUD_R2_STORAGE_CONFIRM='I-CONFIRM-MUTATING-ONLY-THE-PINNED-EMPTY-R2-BUCKET:https://72cdbd1b54f7add44ecbd3d986399481.r2.cloudflarestorage.com/pro' \
SOW_REAL_CLOUD_RUN_ID='sow-r2-storage-20260718-211500' \
SOW_REAL_CF_STORAGE_JSON='<strict env-only credential JSON>' \
go test ./test/compat -run '^TestRealCloudR2StorageProtocol$' -count=1 -v -timeout=5m
```

原始终端结果：

```text
=== RUN   TestRealCloudR2StorageProtocol
real R2 storage PASS run=sow-r2-storage-20260718-211500 operations=create-only+cas-race+head+stream-get+copy-source-cas+delete-capability-probe+identity-bound-unconditional-cleanup conditional_delete=false empty_before=true empty_after=true
--- PASS: TestRealCloudR2StorageProtocol (29.48s)
PASS
ok github.com/pgsty/sow/test/compat 30.189s
```

退出后独立验证：

```bash
rclone lsf cf:pro --recursive --max-depth -1
```

退出码 `0`，stdout 为空，即对象数为零。

## 2026-07-19 当前源码复验

使用同一编译期 registry、同一 owner 授权的 `cf:pro` 空桶和新的
`sow-r2-storage-20260719-01` run identity 再次执行相同协议门禁。测试
`27.06s`、package `27.755s` 通过，仍报告
`conditional_delete=false empty_before=true empty_after=true`；随后的独立
`rclone lsf cf:pro --recursive --max-depth -1` 退出 0 且 stdout 为空。本次凭据仍只由
本机 `rclone` 配置在单个 shell 进程内转换为 env-only 严格 JSON，没有写入工作区、命令输出
或日志。测试只写入并清理本次 `.sow/acceptance/r2-storage/` 前缀，未访问其他 bucket、
生产仓库或 Cloudflare control-plane。

```text
=== RUN   TestRealCloudR2StorageProtocol
real R2 storage PASS run=sow-r2-storage-20260719-01 operations=create-only+cas-race+head+stream-get+copy-source-cas+delete-capability-probe+identity-bound-unconditional-cleanup conditional_delete=false empty_before=true empty_after=true
--- PASS: TestRealCloudR2StorageProtocol (27.06s)
PASS
ok github.com/pgsty/sow/test/compat 27.755s
```

## 2026-07-19 main/beta custom-domain data-plane follow-up

当前测试进一步把匿名 `https://pro.pigsty.io` 与
`https://beta.pro.pigsty.io` 的 raw R2 custom-domain GET 收进同一运行租约。
联网前仍要求 exact compiled registry、空桶、bucket-bound confirmation 和 route-safe run ID；
custom-domain key 另外被硬限制为
`.sow/acceptance/r2-storage/<run-id>/object.bin`。请求不携带 token、Basic Auth
或 S3 凭据，禁止 redirect/cookie/content encoding/Worker contract header，响应必须有规范
`CF-Ray`，且当前对象的 status/body/length/ETag 必须与刚刚通过 HEAD+streamed GET 证明的
R2 CAS winner 完全一致。

第一次 `sow-r2-domain-20260719-01` 运行在对象清理后的 CDN 检查按设计失败：R2 清单已经
为空，但 main 域仍返回本次精确 52 字节对象、相同 ETag、`CF-Cache-Status: HIT`、
`Cache-Control: max-age=1800`；独立检查确认 beta 域行为相同。这个失败证明请求端
`Cache-Control: no-store, no-cache, max-age=0` 不能替代供应商 purge，不能把“bucket 空”
冒充“CDN 已失效”。失败路径的独立 cleanup 仍把 bucket 收敛为空，未删除任何 foreign key。

测试随后冻结删除后判定：只接受 404，或 exact run-owned stale cache。后者必须同时满足
200、相同 body/length/ETag、`HIT|STALE|UPDATING`、单值非负 `Age`、唯一且不超过 24h 的
`max-age`，并且 `Age <= max-age`；任何 foreign body、redirect、共享 HIT 出现在对象仍应为
current 的阶段、无界 TTL 或非 owner-designated host 都失败关闭且不触网。ordinary/race
合同测试与 `go vet ./test/compat` 通过。

最终当前源码 `sow-r2-domain-20260719-04` 真实通过：两个域首次读取均为 FRA 的 `MISS`，
R2 删除后两个域均为 exact run-owned `HIT`、`max-age=1800`；这被明确记录为 purge 尚未执行的
负能力证据，不是 negative CDN verify 通过。测试 `31.19s`、package `31.708s`；退出后的
独立 `rclone lsf cf:pro --recursive --max-depth -1` 退出 0、stdout 为空。

```text
=== RUN   TestRealCloudR2StorageProtocol
real R2 storage PASS run=sow-r2-domain-20260719-04 operations=create-only+cas-race+head+stream-get+main-beta-custom-domain+copy-source-cas+delete-capability-probe+identity-bound-unconditional-cleanup+custom-domain-post-delete-observation conditional_delete=false custom_domain_present=main=CURRENT-MISS/FRA,beta=CURRENT-MISS/FRA custom_domain_after_delete=main=STALE-HIT/FRA/max-age=1800,beta=STALE-HIT/FRA/max-age=1800 empty_before=true empty_after=true
--- PASS: TestRealCloudR2StorageProtocol (31.19s)
PASS
ok github.com/pgsty/sow/test/compat 31.708s
```

缓存中的正文只是本次非秘密、run-owned 测试字符串，会按供应商 `max-age=1800` 自动过期；
它不是 bucket 对象，也没有被伪报为已 purge。整个 follow-up 没有 control-plane token、Worker、
purge API、其他 bucket、`cos:` 或生产资源访问。

## 2026-07-22 current-source revalidation

Commit `9b481e994265d7b9e623c08a4014cadf8e233bb7` used the exact pinned resource
again with run `sow-r2-storage-20260722-020100`. The credential was reconstructed
only inside the test shell from the existing `rclone cf:` reference; neither key
was printed or written. The current test passed in 33.97s (package 34.901s):

```text
real R2 storage PASS run=sow-r2-storage-20260722-020100 operations=create-only+cas-race+head+stream-get+main-beta-custom-domain+copy-source-cas+delete-capability-probe+identity-bound-unconditional-cleanup+custom-domain-post-delete-observation conditional_delete=false custom_domain_present=main=CURRENT-MISS/FRA,beta=CURRENT-MISS/FRA custom_domain_after_delete=main=STALE-HIT/FRA/max-age=1800,beta=STALE-HIT/FRA/max-age=1800 empty_before=true empty_after=true
```

An independent recursive `rclone lsf cf:pro` immediately afterwards returned
zero objects. No other bucket, Cloudflare control-plane API, CO/COS or production
repository was contacted.

## 能力判定

| 原语 | 真实结果 | 产品处理 |
|---|---|---|
| `PutObject If-None-Match:*` | 重复 create 返回冲突 | 可用于 immutable/create-only |
| `PutObject If-Match` | stale ETag 冲突；并发两写 1 success/1 conflict | 可用于 R2 checkpoint CAS |
| HEAD + streamed GET | size/SHA/ETag/正文一致 | 可用于删除前内容证据 |
| Copy source ETag + destination create-only | stale source 被拒，正确 source 成功 | 可用于 snapshot server-side copy |
| `DeleteObject If-Match` | 错误 ETag 仍成功删除 | 不可宣称条件删除；默认 fail closed |
| identity-bound unconditional provider cleanup | 双次正文证明、lease 前后稳定、删除后 absent，清理后为空 | 只证明测试清理安全；不冒充真实 Publisher checkpoint/purge/commit |
| main+beta raw R2 custom domain | 当前对象匿名 GET 的正文/长度/ETag 一致；删除后仍 exact HIT，`max-age=1800` | 证明 raw custom-domain data plane，也证明 purge 不可由请求端 no-cache 或 bucket delete 代替 |

Cloudflare 官方 S3 兼容表没有为 DeleteObject 列出条件操作，Delete Object 文档也只描述
无条件删除；R2 扩展中的条件头是 CopyObject source 条件，不是 DeleteObject 条件：

- <https://developers.cloudflare.com/r2/api/s3/api/>
- <https://developers.cloudflare.com/r2/objects/delete-objects/>
- <https://developers.cloudflare.com/r2/api/s3/extensions/>

## 本地故障与恢复证据

`go test ./internal/publish -run TestAssetServingDeleteLegacyHashFallbackAndForeignDriftFailClosed`
覆盖：任何 delete plan 都在 publication lock 与 mutable write 前探测；只有 stale `If-Match`
成功且 exact probe absent 才能选择 fallback，网络/HEAD/cleanup 不确定性保持失败闭锁；默认模式
在 live key 前拒绝忽略条件的端点。其余负例覆盖连续两次正文证明、R2 checkpoint/COS
generation-lock 围栏、二次证明漂移、紧邻 DELETE 围栏漂移、committed COS repair token、
concrete provider 缺失 fallback、删除已生效但响应丢失后重放且不发第二次 DELETE。HTTP 协议测试还证明显式 fallback 请求没有伪造
`If-Match`，并仍由 SigV4 签名。

## 尚未关闭

本证据只关闭 R2 storage data-plane 与 raw main/beta custom-domain 当前对象读取的上述原语，
不关闭真实 Publisher 的 checkpoint-fenced delete→purge→negative verify→checkpoint commit、
Cloudflare Worker、CDN purge/失效、multi-PoP/cache-log 归因、provider deployment/log
attestation、COS/EdgeOne 或完整 POC-06。真实 COS DeleteObject 与
create-only generation-lock 仍需专用非生产资源；任何生产仓库继续永久禁止测试。
