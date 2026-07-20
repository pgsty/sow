---
title: '真实 R2 发布事务与远端 generation 审计'
type: 'feature'
created: '2026-07-20'
status: 'done'
baseline_commit: 'b9fd82195e25779eda220503e1f2a0fd9e322cef'
review_loop_iteration: 0
context:
  - '_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 当前真实 Cloudflare R2 证据只验证了底层存储协议和 storage-only `fsck`，尚未证明产品 CLI 能把差异上传、generation、checkpoint CAS、purge 回执、发布后校验、远端审计和幂等重放串成一个真实 R2 发布事务。

**Approach:** 增加显式 opt-in 的兼容验收，运行真实 `sow add/promote/publish/fsck` 并只把对象数据面放行到用户指定的空 `pro` 桶；CDN 与 purge 使用本地 TLS/协议适配器，形成真实存储加本地控制面的混合证据，且明确不冒充 Cloudflare 控制面 PoC。

## Boundaries & Constraints

**Always:** 首次写入前必须同时通过仓库钉死资源清单、精确确认短语、非生产声明、route-safe run ID、严格凭据 JSON 和空桶检查；网络只允许精确的 `pro.<account>.r2.cloudflarestorage.com` 与本地 TLS 服务，`api.cloudflare.com` 必须在进程内拦截；成功 PUT 的精确 key/body 身份自动进入清理 allowlist；清理前后都校验 lease，最终证明桶为空；输出、错误和证据不得泄露秘密。

**Ask First:** 只有需要写入除钉死 `pro` 桶之外的云资源、调用真实 Cloudflare purge/Worker/Zone 控制面、使用付费资源或修改生产域名时才暂停。本批不得触发这些条件。

**Never:** 不访问或写入 CO/COS、Cloudflare 生产仓库；不创建 API token；不请求 `pro.pigsty.io` 或 `beta.pro.pigsty.io` 真实自定义域；不把本地 purge/CDN 适配器称为供应商真实 PoC；不对未被 lease 与精确内容身份约束的对象执行删除；不降低现有发布安全检查。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| 首次发布 | 钉死空桶、真实 R2 凭据、本地 public asset | CLI 完成 generation/checkpoint、一次最小 purge、CDN 内容校验和本地远端状态提交 | 任一身份或网络边界不符时首个云写入前失败 |
| 幂等重放 | 本地 ref 与远端 checkpoint 未变 | `publish` 返回 `status=unchanged`，不新增 PUT/purge | 漂移或 CAS 冲突按验证错误失败 |
| 远端审计 | 已发布 generation/checkpoint | adoption 与普通 `fsck` 均完整覆盖并可重放 | 内容/ETag/计划/回执不一致时拒绝提交审计状态 |
| 漂移恢复 | run-owned payload 被 CAS 替换后再恢复 | `fsck` 检出漂移且 Git HEAD 不变；精确 CAS 恢复后通过 | stale ETag 或非 owned 对象不得覆盖/删除 |
| 清理 | 成功或中途失败 | 只删除已记录精确身份的 run-owned 对象，lease 最后删除，桶恢复为空 | 发现外来或身份不明对象时拒绝删除并报告 |

</frozen-after-approval>

## Code Map

- `test/compat/real_cloud_r2_publication_test.go` -- opt-in 真实 R2 发布事务、网络防火墙、身份跟踪与恢复验收。
- `test/compat/real_cloud_r2_storage_test.go` -- 复用真实 R2 owned-object 清理、List/HEAD/GET 校验工具。
- `test/compat/real_cloud_provider_readiness_registry_test.go` -- 复用非生产资源清单、严格解码和环境身份闸门。
- `internal/cli/publish.go` -- 被真实调用的产品发布入口与幂等快路径。
- `internal/cli/remote_audit.go` -- 被真实调用的 adoption/常规远端 `fsck` 路径。
- `docs/requirements-traceability.md` -- 更新需求状态与证据定位。
- `docs/evidence/2026-07-20-r2-publication-storage-transaction.md` -- 记录命令、边界、结果与未覆盖项。

## Tasks & Acceptance

**Execution:**
- [x] `test/compat/real_cloud_r2_publication_test.go` -- 实现安全闸门、真实发布、重放、审计、漂移恢复和身份约束清理。
- [x] `test/compat/real_cloud_r2_publication_test.go` -- 增加网络路由与清理边界的离线负例测试。
- [x] `docs/evidence/2026-07-20-r2-publication-storage-transaction.md` -- 写入可复现且不夸大的真实运行证据。
- [x] `docs/requirements-traceability.md` 与证据索引 -- 将 R2 存储部分闭环，保留真实 CDN/purge/COS 阻断。
- [x] 干净交付清单 -- 纳入新增产品测试和证据，并执行双重重建。

**Acceptance Criteria:**
- Given 精确钉死且初始为空的 `pro` 桶，when 执行 opt-in 验收，then 实际产品 CLI 完成首次发布、幂等重放、已发布 generation/checkpoint 审计、漂移拒绝、CAS 恢复和空桶收尾。
- Given 任意非 R2/本地/被拦截 CF API 的网络目标或不精确资源身份，when 测试准备或执行请求，then 在不产生越界云写入的前提下失败。
- Given 真实运行输出，when 更新追踪矩阵，then 仅声明 R2 数据面及产品事务已验证，真实 Cloudflare purge/CDN 与 COS/EdgeOne 仍明确未通过。

## Spec Change Log

- 2026-07-20 adversarial review（Blind Hunter + Edge Case Hunter）：将预注册 PUT ownership、代理/独立 Host 绕过、无 live-lease 复验、宽泛 DELETE、仅计数的 CDN/key/顺序证据分类为 `patch` 并全部修复；硬进程终止时测试 cleanup ledger 不持久化分类为证据边界澄清，不冒充 crash-cleanup；受 Go 顶层测试调度、显式串行 mutex 和完整 CLI 调用生命周期约束的 `http.DefaultTransport` 临时注入分类为 `reject`，底层真实 R2 transport 已独立 clone、禁代理并锁死 Dial authority。`review_loop_iteration` 不增加，因为 intent/spec 无需重写。

## Design Notes

网络适配器只在这个非并行兼容测试的完整 CLI 调用生命周期内替换默认传输，并由进程 mutex 串行；委托的真实 R2 transport 是标准 transport 的独立 clone，禁用环境代理，DialContext 只允许精确 R2 authority。R2 请求保持 AWS SigV4 和真实 TLS；独立 `Host` override 被拒绝。本地 CDN 通过独立 storage-only 客户端读取当前 R2 对象；Cloudflare purge 请求必须精确匹配 zone、Bearer、URL 集合后才返回带 `CF-Ray` 的本地协议回执。

只有供应商明确返回 2xx 后，exact key/body 才进入 confirmed-success ownership ledger；显式拒绝和 ambiguous transport error 均不授予删除权。每个非 lease mutation 都通过独立直连客户端即时复验 lease body+ETag；产品阶段全部 DELETE 失败关闭，cleanup 只有在连续 identity proof 后才能签发一次性 key/body/ETag capability，并在真正 DELETE 前再次直读证明。测试还绑定五个精确远端 key、pointer+archive 两个精确 CDN GET 及 lock→upload→pointer→purge→verify→checkpoint commit 的事件偏序。defer 能收敛本进程仍存活的失败；timeout、SIGKILL 或进程崩溃不会运行 defer，且本测试不把内存 ownership map 冒充 crash-safe 清理账本。此边界不影响产品自身 durable publication journal 的既有故障注入证据。

## Verification

**Commands:**
- `go test ./test/compat -run 'TestRealCloudR2Publication' -count=1` -- 离线边界测试通过，真实用例默认 skip。
- 带显式 opt-in、精确资源 JSON/确认短语和环境凭据运行同一测试 -- 真实 R2 事务通过且前后桶为空。
- 全部 non-CLI package ordinary/race、CLI compile gate、`go vet ./...` 与两组 Staticcheck profile -- 受影响回归与静态检查通过；产品 CLI 源未变化，穷尽 CLI shard 沿用当前产品证据。
- 干净源树双重重建并比较摘要 -- 产品源码和交付归档身份一致。

## Suggested Review Order

**Transaction and cloud-write safety**

- 从真实 CLI 入口理解完整发布、审计、漂移与清理闭环。
  [`real_cloud_r2_publication_test.go:44`](../../test/compat/real_cloud_r2_publication_test.go#L44)

- 禁用代理并把真实 socket 锁定到唯一 R2 authority。
  [`real_cloud_r2_publication_test.go:771`](../../test/compat/real_cloud_r2_publication_test.go#L771)

- 每次写入复验 lease，成功后记 ownership，拒绝产品 DELETE。
  [`real_cloud_r2_publication_test.go:572`](../../test/compat/real_cloud_r2_publication_test.go#L572)

- 只为已确认身份签发一次性清理 capability。
  [`real_cloud_r2_publication_test.go:742`](../../test/compat/real_cloud_r2_publication_test.go#L742)

**Evidence integrity**

- 精确约束 upload、flip、purge、verify 与 checkpoint 提交偏序。
  [`real_cloud_r2_publication_test.go:800`](../../test/compat/real_cloud_r2_publication_test.go#L800)

- 通用清理器在最终身份复验后调用可选授权钩子。
  [`real_cloud_r2_storage_test.go:711`](../../test/compat/real_cloud_r2_storage_test.go#L711)

- 区分真实 R2、进程内适配器、失败边界与未覆盖能力。
  [`2026-07-20-r2-publication-storage-transaction.md:1`](../../docs/evidence/2026-07-20-r2-publication-storage-transaction.md#L1)

**Traceability and delivery**

- V-36 保留真实 CDN、COS/EdgeOne 与生产迁移阻断。
  [`requirements-traceability.md:103`](../../docs/requirements-traceability.md#L103)

- 产品 allowlist 纳入真实 R2 发布验收。
  [`product-files.txt:480`](../../test/compat/cleandelivery/product-files.txt#L480)

- 交付附加清单纳入 spec 与证据报告。
  [`delivery-extra-files.txt:3`](../../test/compat/cleandelivery/delivery-extra-files.txt#L3)
