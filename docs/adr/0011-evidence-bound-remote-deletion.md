# ADR-0011：证据绑定的远端删除闭包

> **历史 V1 ADR。** 可复用其 fail-closed 原则，但 next 的 target-scoped deletion fence
> 以 [`../../design/next/specs/state-publication.md`](../../design/next/specs/state-publication.md) 为准。

- 状态：Accepted
- 日期：2026-07-12
- 决策范围：FR-07、FR-09、FR-11、FR-25、FR-27、FR-28、NFR-09
- 供应商能力细化：[ADR-0036](0036-provider-delete-capability-and-checkpoint-fenced-fallback.md)

## 背景

`manifest.Diff` 的普通 `Removed` 过去只用于审计，不能自动变成对象存储删除：包体、
索引、generation、checkpoint、channel 和 CAS archive 都可能仍被历史或其他视图引用。
但两个产品合同确实要求远端字节消失：asset 从可变视图移除后，原直达 URL 必须失效；
APT sealed by-hash ledger 判定过期、且已无 retained Release 引用的不可变索引必须清理。
若把前者继续当“远端永不删”，`sow rm` 对用户仍可见；若把后者只在本地清理，对象存储
则无限积累。反过来，直接把所有 `Removed` 传给 DELETE 会破坏历史钉版与恢复。

## 决策

1. `PlannedDelete` 是封闭 union，而不是任意 key。允许的 class 只有
   `snapshot-owned`、`asset-serving`、`apt-by-hash` 和 restore-only `restore-index-serving`。旧 snapshot plan 可缺省 class
   继续重放；新计划绑定 `source_path`、`remote_key`、旧 size 与 SHA-256。
2. `asset-serving` 必须来自该 target 的旧 `content.tsv` 中、本轮选中 asset projection
   的 removed entry。latest、beta、stable 的远端键分别严格映射为逻辑路径、
   `.sow/beta/<path>`、`.sow/gated/<path>`；CDN 路径分别是公开路径、公开 beta 路径、
   `/pro/v1/basic/<path>`。`objects/sha256` archive、APT `dists/pool`、YUM
   `Packages/repodata` 与所有 `.sow` 控制键不能编码成该 class。
3. `apt-by-hash` 必须同时满足：旧 target content manifest 给出精确 size/SHA；当前
   canonical sealed ledger 的 identity 正确；当前 `Release` SHA 等于 ledger 的
   `LiveGeneration`；路径不在任何当前 retained generation；同一路径存在于 Git 祖先中的
   一份有效 sealed ledger。因 tombstone 来自 Git 历史而不是一次性内存 cleanup plan，
   cf 成功提交后，滞后的 cos 仍能独立生成同一删除。
4. saga 在 DELETE 前实时 HEAD。size 或显式 `sow-sha256` 不符即 drift；即使 metadata
   声称匹配，也必须以同一非空 ETag 做流式 GET，并校验完整 size、正文 SHA 与 HEAD→GET
   稳定性，因为外部写者可以保留或伪造自定义 metadata。HEAD 已缺失则不 DELETE；若随后
   出现未知字节，最终 HEAD 发现 residue 并失败，不会误删。每个需要真实删除的 transaction
   先在 `.sow/probes/conditional-delete/<transaction-sha>` 创建确定性自有对象，用故意错误的
   `If-Match` DELETE。默认 `storage.delete_mode=conditional` 要求 conflict + 对象仍在，再以
   正确 ETag 删除；忽略条件的端点在 live key 前以 capability error 失败。若显式配置
   `checkpoint-fenced`，则按 ADR-0036 在撤销旧写者的单写者边界内，重验远端发布围栏并对 live
   body 连续执行第二次完整 streamed identity proof，之后才调用明确的无条件供应商删除；删除后
   仍须证明 origin absent 与围栏未变。该模式不伪称供应商 CAS，其最后窗口由 PRD 单操作者假设
   和 writer revocation 封闭。DELETE 后立即 HEAD absent，事务末再次验证。
5. asset serving URL 是 mutable reachability，因此 DELETE 后必须执行最小 exact purge，
   并只接受 CDN 404/410。纯 asset-removal 计划可用这组完整 negative closure 作为 L3
   证据，不制造已经不存在的正向 probe。APT by-hash 没有 mutable 路由，不 purge CDN，
   但仍强制 origin absence。混合 snapshot/by-hash deletion 继续携带存活正向 probe。
6. 删除、purge 与 negative verify 都进入原 publish journal/checkpoint 事务。失败目标可
   重放，成功目标不回滚；phase 已越过 mutable closure 的恢复必须重新 purge/verify。
   remote inventory 仅在 checkpoint 成功后移除对应 key。
7. asset 的本地 CAS、Git view 历史和 mutable asset 的远端 `objects/sha256/<sha>` archive
   不删除。向前恢复旧 generation 时从这些证据重建并重新 PUT serving key。普通 package、
   非 by-hash APT/YUM metadata 和 YUM package removal 继续只记录 `Plan.Removed`、保留远端
   字节。
8. 历史代 restore 只在 `beta`/`latest` 使用 `asset-serving`/`restore-index-serving`：planner 先重新计算并比对 parent
   `content.tsv` 摘要与 parent generation 的 `content_manifest_sha256`，再要求 removed path 落在
   parent `DesiredCommit` 的 canonical config 所证明的 exact root 下。source path、remote key、size、
   SHA 与 clean CDN path 全部写入新 generation plan。asset 删除 serving key；APT/YUM 只删除
   beta/latest `dists`、legacy `repodata` 和 public mirrorlist。pool/Packages 与 immutable generation
   永久排除。parent ref 无法由其 canonical config 投影、snapshot 或 stable 均不获该权限。
   active generation channels 和 local remote refs 在同一事务中精确收敛。

## 结果

- `sow rm` 对 asset 的用户可见语义与本地 view 一致，同时不牺牲恢复能力。
- APT retain=N 同时约束本地树和每个独立远端，不依赖 ListObjects，远端调用仍为
  O(过期路径数)。
- 任意 key 删除、错误 metadata、损坏 ledger、live Release 不一致、stale CDN 与
  HEAD/GET 漂移都失败闭锁。
- snapshot 旧 journal 保持可解码；新增计划使用显式 class 与内容证据。

## 验证

可复现命令、真实 CLI/SigV4/CDN 协议夹具、双 target 错峰删除与故障负例见
[远端删除合同证据](../evidence/2026-07-12-evidence-bound-remote-deletion.md)。
