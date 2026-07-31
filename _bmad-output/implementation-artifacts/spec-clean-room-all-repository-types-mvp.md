---
title: '干净交付中的 APT/YUM/asset 三仓库 MVP'
type: 'feature'
created: '2026-07-30T00:00:00+08:00'
status: 'done'
review_loop_iteration: 2
baseline_commit: 'af72e00d698dff7924e52a3b09e4f2f65c422a1f'
context:
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '{project-root}/sow.example.yaml'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 归档内的干净环境 MVP 只闭合 asset；APT/YUM 其他测试不能证明最终归档仍可完成包级生命周期。

**Approach:** 用临时仓库 signer、真实 DEB、已签 RPM 和独立 RPM keyring，让归档内生产二进制完成三仓库 add→promote→materialize→L1/fsck→rm→reconcile，并检查关键字节。

## Boundaries & Constraints

**Always:** 使用交付内生产 CLI；私钥仅在临时目录经文件参数注入；只在 disposable 配置分离 RPM trust；关闭联网 opt-in 与云凭据。

**Ask First:** 任何真实云、生产仓库、正式域名、外部凭据或不可逆迁移写入。

**Never:** 用 Mock、`gpg`、包构建器、脚本运行时或容器造证据；放宽签名、机密性、YUM 成对翻转或 APT by-hash；写生产资源或 `/Users/vonng/pgsty/repo`。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| 首次闭环 | 空根、shipped config、真实 DEB/RPM/asset | add、promote、物化、L1/fsck 通过且产物可托管 | 缺索引、签名、包体或 receipt 即失败 |
| 幂等重放 | 相同输入/视图 | HEAD 不漂移，报告 unchanged/existing | 额外正典变化或残留即失败 |
| 包级删除 | latest/beta 删除 DEB/RPM 后重物化 | 新空视图自洽，旧包不从当前索引发现；YUM successor 可按冻结窗口保留不可索引 payload | 当前索引仍引用旧包、超窗残留或闭包不完整即失败 |

</frozen-after-approval>

## Code Map

- `test/compat/clean_room_mvp_test.go` -- 构建生产二进制并执行归档强制的本地生命周期。
- `test/compat/client_compat_test.go` -- OpenPGP 与真实 DEB/RPM helper。
- `test/compat/cleandelivery/` -- 归档和抽取树门禁。
- `docs/requirements-traceability.md` -- 验证账本。

## Tasks & Acceptance

**Execution:**
- [x] `test/compat/clean_room_mvp_test.go` -- 加入 signer、RPM keyring 与三仓库 CLI 生命周期；断言 exact HEAD/physical no-op 幂等、hostable 产物和删除闭包；测试自身清空 provider 凭据与 opt-in。
- [x] 产品实现文件 -- 空签名索引允许 absent payload scope；索引非空/unsafe/racing tree 失败关闭，且不增加 present tree 的额外全量 walk。
- [x] `README.md`、证据与追踪矩阵 -- 区分 asset 示例、归档内三仓库实测和仅 asset 的 SIGKILL 恢复。
- [x] `test/compat/cleandelivery/` -- 加入本 spec 与证据，并让单次门禁在两个独立抽取树执行 lifecycle。

**Acceptance Criteria:**
- Given 两个独立 fresh 交付抽取树，when 运行 clean-delivery，then 归档字节一致且生产 CLI 完成三仓库闭环。
- Given add/promote/materialize/rm/recovery，when 普通与 race 测试执行，then L1/fsck、签名、by-hash、strong YUM route 与 exact 删除通过。
- Given 无云凭据和 provider opt-in，when 验证执行，then 不发生任何云、生产仓库或 `/Users/vonng/pgsty/repo` 写入。

## Spec Change Log

- 2026-07-30 review loop 1 (`bad_spec`): frozen deletion row incorrectly
  required a removed RPM body to be unreachable from the current generation.
  Architecture and real in-flight DNF evidence require each successor to keep
  the bounded, unindexed prior payload closure. Amended the row to require an
  empty current index while preserving that compatibility body. Avoid the
  known-bad state where a pointer flip strands a client holding prior metadata.
  KEEP: production executable, real DEB/signed RPM, independent package
  keyring, ephemeral signer, exact signed-index assertions, and bounded YUM
  retention must survive re-derivation.
- 2026-07-30 implementation: 三仓库 actual-binary 闭环暴露并关闭末包删除后
  absent `pool/Packages` 被 L1 误报 unsafe；只有签名索引闭包为空时才按空
  manifest 接受，索引仍引用包与 unsafe tree 负例保持失败关闭。
- 2026-07-30 review loop 1 implementation: snapshot 的 generic filesystem
  check 同样接受 absent empty scope；absence stream 在 open/read/close 绑定
  缺失状态，present tree 只保留一次 shape audit 加一次 hash scan。显式 YUM
  导出重放保留已有 target-bound `_sow` 路由，随后由 topology 精确清外来路由，
  因而 canonical HEAD、payload 和 serving route 均为 physical no-op。
- 2026-07-30 review loop 1 delivery: clean-room 自行清空 provider 凭据/opt-in，
  exact mirrorlist host、HEAD 与 package no-op 字段全部冻结；单次 clean-delivery
  在两个抽取树均通过。冷缓存暴露原 4 分钟总时限不足，现测试总预算 12 分钟，
  SIGKILL fence 自身仍保持独立 90 秒硬上限。
- 2026-07-30 review loop 2 (`bad_spec`): 非冻结 Design Notes 错误允许 Go
  fixture builder，与冻结的“不得用包构建器造证据”直接冲突。改为解码并使用
  交付内已签入、已由生产 parser 验证的真实 DEB fixture；禁止把测试 helper
  生成的合成包当成归档 MVP 证据。KEEP: 生产 executable、临时 metadata
  signer、真实 DEB/原签名 RPM、独立 RPM package keyring、三仓库 lifecycle、
  exact signed-index/by-hash/strong-YUM assertions、bounded YUM retention、
  inputless asset SIGKILL recovery 与双抽取树门禁全部保留。
- 2026-07-30 review loop 2 implementation: clean-room 子进程改为 allowlist
  环境，ambient SOW signer/provider/session/container credentials 均不可继承；
  materialize 重放增加 serving `created=false`/`pointer=unchanged`、零 mutation
  与 mirrorlist/repodata/package inode 不变断言；inner Go test 显式 `-timeout
  15m`。显式 target 的 `_sow` 保留从“整树扫描”收紧为 canonical
  target/view/leaf keep-set，任意无主文件被 exact reconcile 与 tgz 排除。
  optional absent payload 绑定 root/父目录 inode 并预先验证 scope/pattern。
- 2026-07-30 review loop 2 adversarial closure: exact reconcile 的 shadow policy
  改为显式三态，只有真实 canonical root 可排除其 operator 顶层目录；任意
  sub-target/isolated serving tree 均把 `.sow`、`.pool`、`.git` 纳入精确闭包，
  regular file 通过绑定描述符清理，symlink/special 失败关闭。YUM
  `ValidateRootWithProof` 在同一个 retained `os.Root` 上绑定并重证
  `repomd.xml`、`.asc` 与 primary/filelists/other 五个文件；L1 也从该 root
  解析，目录、repomd、签名和 artifact 替换负例全部失败。最终 proof 保留
  cancellation error chain，不把取消误报为 integrity drift。显式 target
  同时报告并幂等重放 frozen compatibility generation/pointer。
- 2026-07-30 review-final verification: adversarial reviewers 均无剩余
  High/Medium；903-test CLI ordinary/race 以互斥 exact 分片覆盖，所有测试
  通过。两次批次超时的 active test 仅运行 5/17/37 秒，拆片后通过；一个
  12-process overload 的 30 秒测试局部墙钟失败在独立连续 3 次 race 中
  32.827 秒全部通过。非 CLI、full compat ordinary/race、vet、Staticcheck、
  module checks 与四目标 CGO-free build 全绿。

## Design Notes

DEB 与 RPM 均从交付内已签入的真实二进制 fixture 解码；测试 helper 不生成包。
被测路径始终是新构建的 `cmd/sow`；RPM 原签名与仓库 metadata 使用不同信任身份。
“当前索引不发现旧包”按 [architecture](../../docs/architecture.md) 的 strong-YUM
合同解释：current mirrorlist/primary 不索引旧 RPM，但 immutable successor
generation 在配置窗口内保留 prior payload hardlink，让已读取旧 metadata 的
in-flight DNF 完成；fresh client 不会请求它。

## Verification

**Commands:**
- 证据文档定义的 `safe` allowlist 前缀适用于以下所有命令。
- `safe go test -timeout 15m -count=1 ./test/compat -run '^TestShippedExampleSupportsCleanRoomLocalMVP$'` -- 生产二进制三仓库生命周期通过。
- `safe go test -race -timeout 15m -count=1 ./test/compat -run '^TestShippedExampleSupportsCleanRoomLocalMVP$'` -- 同路径无数据竞争。
- `safe go test -count=1 ./test/compat/cleandelivery` -- 交付 policy package 通过。
- `safe go test -count=1 ./test/compat -run '^TestRequirementsTraceabilityLedger'` -- 两个需求账本门禁通过。
- `test/compat/test-clean-delivery.sh <fresh-root>` 两次 -- 独立归档字节一致。
- `safe go vet ./...`、`safe staticcheck ./...` 与 `git diff --check` -- 静态与补丁检查通过。

**Observed candidate:** focused ordinary/race、full compat ordinary/race、全 Go
package ordinary/race、vet/Staticcheck 与四目标 CGO-free build 均通过。review-loop-1
clean-delivery 使用本机只读 Go module file proxy、全新 HOME/GOMODCACHE/GOCACHE，
生成相同的 595-file product、805-file delivery，并在两个独立抽取树逐一通过：
product `3c8854e0b98e3d26257ce200727dac1d1f3a43f2b671c8fcf3e6af13cf8eb009`，
delivery `0bff3f322fa977fcd01c480cf14fe0949ea26f8a4440dc31648a337adcd11090`，
archive `2c7127d7f9f6856005daf7e309f3b4142413dc86773b683c37ecec209d8ed1a0`。
这些明确是 review-loop-1 candidate；review-final 文档编辑后由 archive 外部
handoff 重新记录最终身份，避免证据文件自引用。

## Suggested Review Order

**端到端产品闭环**

- 从生产二进制入口理解三类仓库生命周期与不变量。
  [`clean_room_mvp_test.go:26`](../../test/compat/clean_room_mvp_test.go#L26)

- 显式导出同时报告普通与冻结兼容代际。
  [`materialize.go:691`](../../internal/cli/materialize.go#L691)

- 双归档门禁在两个 fresh 抽取树重复执行闭环。
  [`main.go:240`](../../test/compat/cleandelivery/main.go#L240)

**精确物化与遮蔽点**

- exact reconcile 只对真实正典根保留 operator 目录豁免。
  [`reconcile.go:28`](../../internal/repository/reconcile.go#L28)

- 显式 shadow policy 防止 sub-target 隐藏无主控制文件。
  [`scan.go:59`](../../internal/manifest/scan.go#L59)

- frozen compatibility 路由进入显式导出和幂等归档。
  [`materialize_archive_compatibility_test.go:25`](../../internal/cli/materialize_archive_compatibility_test.go#L25)

**签名闭包与 TOCTOU**

- retained root 一次绑定 YUM 签名对及三类 metadata。
  [`validate.go:85`](../../internal/yumrepo/validate.go#L85)

- L1 从同一 capability 解析并最终重证五文件 proof。
  [`yum.go:90`](../../internal/verify/yum.go#L90)

- absent payload witness 绑定 root、父目录和持续缺失状态。
  [`path.go:273`](../../internal/verify/path.go#L273)

- snapshot L1 证明空索引允许缺失 payload 树。
  [`materialize_snapshot_test.go:30`](../../internal/cli/materialize_snapshot_test.go#L30)

**对抗回归与交付证据**

- 整个 repodata 目录替换必须被 L1 最终 proof 拒绝。
  [`engine_test.go:212`](../../internal/verify/engine_test.go#L212)

- generation 在签名后被替换必须失败关闭。
  [`generation_test.go:196`](../../internal/yumrepo/generation_test.go#L196)

- shadow regular file 精确清理且 hardlink 保持不变。
  [`reconcile_test.go:15`](../../internal/repository/reconcile_test.go#L15)

- 最终边界、命令和实测结果集中在证据账本。
  [`2026-07-30-clean-room-all-repository-types-mvp.md:1`](../../docs/evidence/2026-07-30-clean-room-all-repository-types-mvp.md#L1)
