---
title: 'R2 删除能力与 checkpoint 围栏降级'
type: 'bugfix'
created: '2026-07-18T19:00:00+08:00'
status: 'done'
review_loop_iteration: 0
baseline_commit: '84800a60e01aaaf8dc5b189c3ddb1380930f4865'
context:
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md'
  - '{project-root}/docs/adr/0011-evidence-bound-remote-deletion.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 真实 Cloudflare R2 实测证明 `PutObject` 条件写可用，但 `DeleteObject` 忽略 `If-Match`；现有发布器把条件删除当作供应商必备能力，会让合法删除永久失败，若直接接受无条件删除又会破坏证据绑定的不变量。

**Approach:** 默认继续要求供应商条件删除并失败闭锁；仅在配置显式选择 `checkpoint-fenced`、且运维已撤销旧写者时，允许在远端 checkpoint ETag 不变、删除对象连续两次完整流式身份一致的条件下执行供应商无条件删除，并在删除后证明对象缺失与 checkpoint 未漂移。

## Boundaries & Constraints

**Always:** 仅允许现有封闭 `PlannedDelete` 类；所有检查与删除留在同一 saga/journal；默认配置为 `conditional`；能力探针必须先证明条件删除不可用；fallback 必须绑定已获取的 checkpoint ETag、重复 size/SHA/ETag/正文校验、删除后 origin absence 与 checkpoint 不变；失败可安全重放；真实测试只使用用户明确授权的空 `pro` 桶且清理精确 run-owned key。

**Ask First:** 新增或使用任何生产资源、真实 COS/EdgeOne 资源、改变多写者业务假设，或使 `checkpoint-fenced` 成为默认值。

**Never:** 把 R2 无条件删除伪报为 CAS；把 fallback 扩展到任意 key；扫描或改写其他 bucket；弱化机密性闭包、checkpoint CAS、最小 purge 或发布后验证；引入通用云抽象或外部运行时。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| 原生条件删除 | stale `If-Match` 被供应商拒绝且对象仍存在 | 使用正确 ETag 条件删除 | 任一能力证明异常即失败闭锁 |
| R2 显式降级 | 条件探针显示端点忽略条件；mode=`checkpoint-fenced` | 连续双证明后无条件删除，随后验证 absence/checkpoint | 任一漂移均保留未知字节并中止 |
| 默认 R2 | 条件探针显示端点忽略条件；mode 省略或 `conditional` | 不触碰 live key | 返回 capability error |
| 中断重放 | 删除已生效但响应或本地 journal 持久化丢失 | 重放观察 absence，继续 purge/verify/checkpoint | 不执行第二次不受约束删除 |
| 外部漂移 | checkpoint 或候选对象在两次证明之间变化 | 不删除 | 返回 conflict/drift，journal 保持可恢复 |

</frozen-after-approval>

## Code Map

- `internal/config/config.go` -- 冻结 `storage.delete_mode` schema、默认值与枚举校验。
- `internal/publish/provider.go` -- R2/COS 显式 checkpoint-fenced 删除能力接口。
- `internal/publish/{driver,saga}.go` -- 能力探针、双重身份校验、checkpoint 围栏、删除后闭包与重放。
- `internal/publish/http_{object,cloudflare,tencent}.go` -- 供应商 SDK 的明确无条件删除入口。
- `internal/cli/{publish_provider,publish_remote}.go` -- 配置到 Publisher 的唯一启用路径。
- `test/compat/real_cloud_r2_storage_test.go` -- 真实 R2 Put/Head/Get/Copy/Delete 能力与 run-owned 清理。
- `docs/adr/0036-provider-delete-capability-and-checkpoint-fenced-fallback.md` -- 供应商事实、安全边界与运维前提。

## Tasks & Acceptance

**Execution:**
- [x] 修复全部 `targetDriver` 测试替身并补齐配置/CLI wiring 测试。
- [x] 增加 checkpoint 漂移、二次正文漂移、响应丢失重放、缺失 fallback 接口负例。
- [x] 在授权 R2 空桶运行真实协议测试并证明测试前后为空。
- [x] 更新 ADR、示例配置、迁移手册、证据索引与需求追踪，删除旧的错误供应商假设。
- [x] 运行 publish race、compat、vet、staticcheck、clean-delivery 与全套测试。

**Acceptance Criteria:**
- Given 未显式启用 fallback 的 R2 端点会忽略 `DeleteObject If-Match`，when 发布计划包含 live delete，then 发布在触碰 live key 前以 capability error 失败。
- Given 已显式启用 `checkpoint-fenced` 且单写者前提成立，when 对象与 checkpoint 全程稳定，then 删除、purge、验证与 checkpoint commit 在同一可恢复事务中完成。
- Given checkpoint 或对象在任一证明边界漂移，when fallback 运行，then 未知字节不会被删除且错误可诊断。
- Given 授权的 `pro` R2 桶初始为空，when 真实协议用例完成，then Put CAS/Copy/读取证据可复现、条件删除缺失被如实记录、桶恢复为空。

## Spec Change Log

- 2026-07-18 review patch: 能力回退只接受 stale delete 成功且 probe absent 的专用证据；
  probe 移到 publication lock 与 live mutation 之前；无条件 DELETE 紧邻前再验围栏；
  committed COS 重放保留 durable generation-lock token。真云清理改为独立 context、
  双次 streamed body identity、run lease 和 absence 证明，并删除了将 storage-only
  cleanup 冒充 Publisher checkpoint-fenced 事务的证据表述。

## Design Notes

该降级没有伪造供应商 CAS：无条件 DELETE 前最后一个极小竞争窗口只能由 PRD 已冻结的单操作者/单开发机假设与旧写凭据撤销来封闭。若未来要求多写者，必须改用供应商真正提供的条件删除、版本化对象或另一个可线性化协调原语。

## Verification

**Commands:**
- `go test -race ./internal/publish -count=1` -- 默认失败闭锁、fallback 和故障重放全部通过。
- `go test ./internal/config ./internal/cli -count=1` -- schema 默认/拒绝值与 CLI wiring 通过。
- `SOW_RUN_REAL_CLOUD_R2_STORAGE=1 ... go test ./test/compat -run '^TestRealCloudR2StorageProtocol$' -count=1 -v` -- 仅授权桶的真实协议证据通过。
- `go vet ./... && /tmp/sow-staticcheck-go1.26.5 -checks='SA*,-SA1019' ./...` -- 无新增静态语义问题。
- `go test ./... -timeout=30m` -- 全套回归通过。

**2026-07-18 post-review current-source results:**

- `go test ./internal/publish -count=1` PASS (`7.995s`); `go test -race ./internal/publish -count=1` PASS (`10.821s`).
- exact config and CLI delete-mode wiring tests PASS (`0.495s`, `0.553s`); forged-body and response-loss
  cleanup tests PASS inside the focused compat package (`1.991s`).
- `go test -race ./test/compat -count=1 -timeout=30m` PASS (`12.044s`).
- `go vet ./...` and `/tmp/sow-staticcheck-go1.26.5 -checks='SA*,-SA1019' ./...` PASS.
- isolated-cache clean delivery PASS with 533 product files and 675 delivery files:
  product SHA-256 `4e7a96c9830aec837a8437a027c9a4c3e9e0c7ce64cfadc69014b5ab7368a9ed`,
  delivery SHA-256 `d395ce35cef88ec35a450ac68ed0c2137c966230fe723c9c10a4d25b2d7647bb`,
  archive SHA-256 `132490fad9b1b44e989aef10f55097ad93ec0f84ad3954c252c4c2183872f7f2`.
- `go test ./... -count=1 -timeout=30m` PASS; `internal/cli` was the longest package at `1233.318s`;
  publish/state/compat also passed at `23.596s`/`34.793s`/`31.886s`.
- hardened real R2 storage protocol PASS (`29.48s` test, `30.189s` package), reported
  `empty_before=true empty_after=true`; independent recursive `rclone lsf cf:pro` produced empty stdout.
  This storage-only proof does not claim a real Publisher checkpoint/purge/commit transaction.

## Suggested Review Order

**Saga admission and destructive boundary**

- Select delete capability before acquiring the publication fence or mutating live routes.
  [`saga.go:262`](../../internal/publish/saga.go#L262)

- Bind two body proofs and an immediate fence recheck around unconditional DELETE.
  [`saga.go:1255`](../../internal/publish/saga.go#L1255)

- Admit fallback only for the exact stale-success plus probe-absence outcome.
  [`saga.go:1284`](../../internal/publish/saga.go#L1284)

- Preserve the durable COS generation-lock token during committed repair replay.
  [`saga.go:315`](../../internal/publish/saga.go#L315)

**Provider and configuration contracts**

- Keep R2 and COS fence verification provider-specific and fail-closed.
  [`driver.go:208`](../../internal/publish/driver.go#L208)

- Expose deliberately named unconditional primitives without pretending they are CAS.
  [`provider.go:90`](../../internal/publish/provider.go#L90)

- Default schema to conditional deletion; checkpoint-fenced remains explicit opt-in.
  [`config.go:567`](../../internal/config/config.go#L567)

- Wire the frozen target mode into the only CLI Publisher construction path.
  [`publish_remote.go:50`](../../internal/cli/publish_remote.go#L50)

**Adversarial and real-provider evidence**

- Cover ambiguous probes, proof/fence drift, response loss, and COS replay.
  [`saga_test.go:715`](../../internal/publish/saga_test.go#L715)

- Reject forged cleanup metadata and accept only absence-proven response loss.
  [`real_cloud_test.go:1678`](../../test/compat/real_cloud_test.go#L1678)

- Restrict real R2 cleanup to double-proven run-owned bytes under a lease.
  [`real_cloud_r2_storage_test.go:335`](../../test/compat/real_cloud_r2_storage_test.go#L335)

- Record the explicit single-writer boundary and unfinished real transaction PoC.
  [`0036-provider-delete-capability-and-checkpoint-fenced-fallback.md:26`](../../docs/adr/0036-provider-delete-capability-and-checkpoint-fenced-fallback.md#L26)

- Separate verified storage primitives from unexecuted Publisher/CDN closure.
  [`2026-07-18-real-r2-storage-protocol.md:65`](../../docs/evidence/2026-07-18-real-r2-storage-protocol.md#L65)
