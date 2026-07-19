---
title: 'R2 readiness 资源稳定租约闭包'
type: 'bugfix'
created: '2026-07-19'
status: 'done'
review_loop_iteration: 0
baseline_commit: 'f4a88c87b39a2599629625df5d140dd8b0da28dd'
context:
  - '{project-root}/docs/adr/0033-provider-scoped-readiness-registry.md'
  - '{project-root}/docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md'
  - '{project-root}/docs/adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** readiness v3 允许一个 CAS-retired bootstrap idle marker，但 marker key 绑定 plan SHA。Worker bundle、签名公钥或运行参数轮换后，新 plan 会被旧 marker 永久阻塞；若另建新 key，又会留下多个控制对象并让 readiness 永久失败。provider log-sink 的稳定 key 同样错误地要求 idle/expired lease 仍绑定当前 deployment SHA，正常部署轮换会失去可重放性。

**Approach:** bootstrap 序列化 key 改为绑定 readiness resource SHA，plan SHA 只绑定每次 live lease；同一资源上的旧 plan idle marker或已过期 live lease可由新 plan 以 exact ETag CAS 接管，live holder仍严格阻塞。log-sink 保持 dedicated raw bucket 根下的单一稳定 key，允许同 account/zone 的历史 deployment idle/expired lease 被当前 deployment CAS 接管。

## Boundaries & Constraints

**Always:** 仅用 Get/List/conditional Put；CAS 后按返回 ETag 与正文读回；readiness 只接受空桶或唯一、当前 readiness-resource key 下的 canonical idle marker；live lease 不因 plan/deployment 轮换被抢占；生产资源零写入。

**Ask First:** 真实 Worker、route、purge、日志控制面变更或任何非 `pro` 测试资源写入。

**Never:** DeleteObject、按新版本另建第二个协调 key、无条件覆盖、把本地协议测试冒充真实云通过，或弱化 CO/COS/生产仓库禁写边界。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| plan 轮换 | 同 readiness resource 的旧 plan idle marker | 新 plan 在同一 key 上 CAS 接管，最终仍仅一个 marker | ETag/正文/资源身份漂移则 fail closed |
| 崩溃后轮换 | 同资源旧 plan live lease 已过期 | 新 plan CAS 接管或 recover 后重放 | 未过期 live lease必须拒绝 |
| 外来 marker | 错 resource key、错 account/zone、多个对象或 payload | readiness/bootstrap 均拒绝 | Worker/route mutation 为 0 |
| deployment 轮换 | 同 account/zone、同 log-sink key 的历史 idle/expired lease | 当前 deployment CAS 接管 | live 或 provider 身份漂移则拒绝 |

</frozen-after-approval>

## Code Map

- `test/compat/real_cloud_provider_readiness_test.go` -- v3 bucket closure、sealed receipt loader与负例。
- `test/compat/real_cloud_cloudflare_bootstrap_test.go` -- bootstrap lease key、acquire/release/recovery和真实 opt-in入口。
- `test/compat/real_cloud_provider_attestation_test.go` -- provider log-sink lease rotation语义。
- `test/compat/real_cloud_test.go`、`real_cloud_acceptance_ledger_test.go` -- real-cloud 私有元数据完整 inode/no-replace 安装原语。
- `docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md`, `docs/adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md` -- 持久契约与运维恢复说明。

## Tasks & Acceptance

**Execution:**
- [x] `test/compat/real_cloud_cloudflare_bootstrap_test.go` -- 将 key 固定到 readiness-resource，允许同资源跨 plan CAS 接管并让 recovery receipt绑定被恢复的旧 plan。
- [x] `test/compat/real_cloud_provider_readiness_test.go` -- 证明唯一 marker 的 key属于当前 resource，拒绝旧 plan key、外来/多对象与 list/GET 漂移。
- [x] `test/compat/real_cloud_provider_attestation_test.go` -- 允许同 provider deployment轮换，仍拒绝 live或跨 account/zone接管。
- [x] `test/compat/real_cloud_provider_readiness_test.go` -- receipt/seal 每个 final path 原子发布；故障注入证明 receipt-only 半对可精确续写，seal-only/unsafe/divergent 失败关闭。
- [x] `test/compat/real_cloud_test.go` -- recovery receipt 与其他 exclusive real-cloud metadata 复用完整 inode/no-replace installer，不留下 partial final file。
- [x] `docs/`, trace matrix与外部验证账本 -- 更正 plan-key/readiness v2旧措辞并记录复现证据。

**Acceptance Criteria:**
- Given 同一 readiness resource 的两个不同 plan，when 旧 plan release 后新 plan acquire/release，then bucket 始终只有同一资源稳定 key且 stale holder不能改写新 holder。
- Given 历史 deployment lease，when deployment SHA轮换，then idle/expired可CAS重放而live lease继续阻塞。
- Given current-source普通/race测试与静态检查，when 执行兼容包验证，then 无 Delete调用、无数据竞争、无未解释失败且不产生云写入。

## Spec Change Log

- 2026-07-19 review：lease/idle v2 正文补入 readiness-resource/raw-bucket 身份；recovery receipt v2 补入完整旧 lease digest；普通 bootstrap acquisition 对 expired live 改为要求先执行 `recover-lease`；readiness 本地 pair 允许最多一分钟反向时钟偏移。保留同资源跨版本稳定 key、ETag CAS、live holder阻塞与零 Delete 不变量。

## Design Notes

plan/deployment digest是一次执行内容身份，不应同时充当跨版本互斥锁命名空间。协调 key必须由资源/控制面身份稳定派生，resource SHA也必须进入 lease/idle canonical body，防止正文跨资源搬移；版本 digest留在live/idle正文与回执中用于审计，ETag才是所有权 fencing token。expired live bootstrap lease 只能先由 recover-lease 退役，普通 apply/rollback 不得绕过 durable recovery receipt。

## Verification

**Commands:**
- `go test ./test/compat -run 'ProviderReadinessReceiptPair|CloudflareReadiness|CloudflareBootstrap|ProviderLogSinkLease|RealCloudPrivateBootstrapAtomicWindows|RegistryCandidate|PersistentRealCloudWorkspace' -count=1` -- PASS `0.964s`。
- 同选择集 `go test -race` -- PASS `2.276s`。
- `go test ./test/compat -count=1` -- PASS `7.650s`；`go test -race ./test/compat -count=1` -- PASS `11.576s`，全部 real-cloud opt-in显式为 `0`。
- `go vet ./test/compat`、project-profile `staticcheck`、`git diff --check` -- PASS。
- 两个独立 clean-delivery 与 `cmp` -- product `7e040fcb…7b14` / 536，delivery `b18ce454…ab13` / 684，archive `99f44e66…2595`，字节一致。

## Review Outcome

- Blind/edge review 的 resource/raw-bucket relocation、expired-live recovery bypass、recovered lease字段漏绑与 bounded clock rollback 已修复并加入负例。
- V-24 legacy-key/dual-lock findings不适用于已部署状态：V-24 registries关闭且真实云 mutation 为零；V-25 对任何意外 legacy object保持 fail closed，不自动删除。
- provider log-sink expiry replay是既有、显式设计的幂等跨供应商恢复语义；live holder仍阻塞且最终控制面必须精确收敛。
- remote recovery idle CAS 与本地 receipt 之间的既有中断窗口已按工作流登记到 `deferred-work.md`；长期 Goal保持 active，下一轮单独实现两阶段 recovery marker。
- writable hard-link finding不构成同用户威胁模型下的完整性绕过；Ed25519 seal仍绑定 exact receipt bytes，writer对完成路径保持 no-replace。

## Suggested Review Order

**资源稳定 bootstrap 协议**

- 从稳定 key 与 v2 正文身份开始理解版本/资源分离。
  [`real_cloud_cloudflare_bootstrap_test.go:563`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L563)

- Acquisition只接管 idle；expired live强制先留恢复证据。
  [`real_cloud_cloudflare_bootstrap_test.go:686`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L686)

- Recovery receipt绑定旧 plan及完整 canonical lease。
  [`real_cloud_cloudflare_bootstrap_test.go:964`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L964)

**Readiness 闭包与本地恢复**

- 唯一 marker同时校验 key、resource SHA、ETag与正文。
  [`real_cloud_provider_readiness_test.go:203`](../../test/compat/real_cloud_provider_readiness_test.go#L203)

- Receipt/seal分步发布可精确续写且拒绝危险半对。
  [`real_cloud_provider_readiness_test.go:651`](../../test/compat/real_cloud_provider_readiness_test.go#L651)

- Loader只返回已验签的同一次 pathname read。
  [`real_cloud_provider_readiness_test.go:859`](../../test/compat/real_cloud_provider_readiness_test.go#L859)

**Provider log-sink 轮换**

- Raw-bucket根级稳定 key消除 raw-root/deployment 分叉。
  [`real_cloud_provider_attestation_test.go:445`](../../test/compat/real_cloud_provider_attestation_test.go#L445)

- v2 body绑定 bucket，live/idle/expired分支统一CAS。
  [`real_cloud_provider_attestation_test.go:535`](../../test/compat/real_cloud_provider_attestation_test.go#L535)

**耐久性与证据**

- 所有 exclusive metadata复用完整 inode no-replace安装。
  [`real_cloud_test.go:3045`](../../test/compat/real_cloud_test.go#L3045)

- 跨 plan、stale holder与旧 lease完整绑定的主回归。
  [`real_cloud_cloudflare_bootstrap_test.go:2331`](../../test/compat/real_cloud_cloudflare_bootstrap_test.go#L2331)

- Receipt-only中断、时钟回拨与unsafe half-pair故障注入。
  [`real_cloud_provider_readiness_test.go:1065`](../../test/compat/real_cloud_provider_readiness_test.go#L1065)

- 可复现边界与未触云声明集中在V-25证据页。
  [`2026-07-19-r2-resource-stable-lease-rotation.md:19`](../../docs/evidence/2026-07-19-r2-resource-stable-lease-rotation.md#L19)
