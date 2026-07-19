# 前向远端历史代恢复证据 — 2026-07-12

## 环境与范围

- worktree：`/Users/vonng/pgsty/sow`
- host：Darwin arm64
- Go：1.26.5
- 操作面：`sow publish --restore-generation N --target cf|cos`
- 范围：真实 CLI、文件系统、embedded canonical Git、CAS、APT/YUM 生成与 OpenPGP；
  R2/Cloudflare 和 COS/EdgeOne 使用供应商协议 transport fixture，不冒充真实云 PoC

## 复现命令与实测结果

```bash
cd /Users/vonng/pgsty/sow

go test ./internal/cli \
  -run 'Test(PublishCLI.*Restore|PublishRestore|PublishAfterRestore|PublishCOSLockedCrash|ResolveStablePublicationPools|LoadHistoricalTargetPublication|PrepareHistoricalPublication|PublishCLIYUMSnapshotUsesExactIntentStableRouteAndServerSideCopy|CleanupStaleRestoreMaterializations|PublishStartupCleansStaleRestoreMaterializations)' \
  -count=1 -v

go test -race ./internal/cli \
  -run 'Test(PublishRestoreAssetPathRemovalUsesEvidenceBoundDeleteAndReplays|PublishRestoreLatestRemovesConfiguredExtraAssetLeaf|PublishRestoreRemovesAPTAndYUMTopologyTransactionally|RestoreAssetDeleteRequiresExactParentManifestBinding|PrepareHistoricalPublicationFailsClosedOnMissingRefAndTopologyRemoval|PublishRestoreGenerationRebuildsSignedAPTAndYUMIntent|PublishRestoreStableAppendOnlyRegressionFailsBeforeRemoteMutation)' \
  -count=1

go test ./internal/cli -count=1

go vet ./internal/cli ./internal/publish ./internal/state
go build ./cmd/sow
git diff --check
```

本轮全部退出 0：

```text
restore focused (merged):        ok github.com/pgsty/sow/internal/cli 47.592s
full CLI merged:                 ok github.com/pgsty/sow/internal/cli 269.371s
full affected race merged:       ok github.com/pgsty/sow/internal/cli 334.161s
vet/build/diff-check: PASS
```

上述结果均来自 [final local audit](2026-07-12-final-local-audit.md) 所绑定的同一 320-file
product-source；真供应商 restore 仍是独立外部门禁。

## 已证明的闭包

1. asset beta generation 1 发布后推进到 generation 2，再 restore generation 1：远端
   checkpoint 创建 generation 3、parent=2，target remote ref 指回 generation 1 的历史
   commit，mutable asset 正文恢复为旧字节，而当前 local beta ref 不倒退。
2. restore 走完整 publication saga，产生差异 PUT、pointer flip、最小 purge、CDN read-back、
   committed checkpoint、local remote-ref advance，并写
   `remotes/<target>/restores/<new-generation>.json`。同一命令完成后重放为 unchanged，
   不重复 PUT/purge/read-back，也不再推进 generation。
3. 在 `purged` phase 后注入崩溃，transaction ID 已包含 source generation 与冻结的
   canonical desired HEAD。误跑普通
   publish 会退出 6，输出无秘密 transaction ID 和准确的
   `--restore-generation 1 --target cf` 重放提示，且没有远端 mutation；正确 CLI 随后从
   同一个 generation/plan 恢复；越过 mutable closure 的 replay 会再次执行最小 purge/验证，
   最终 checkpoint/ref/正文闭合。
4. 一个真实 DEB 和一个真实 RPM 各发布两代后恢复第一代：APT Packages/Release/
   InRelease/Release.gpg 重新生成并通过 OpenPGP 校验；YUM primary/filelists/other、
   repomd.xml/.asc 以 EL10 zstd 重新生成并通过 production validator；raw pair 与 immutable
   generation pair 相同，channel 指向新 generation，purge 集包含 APT InRelease、YUM pair
   和 mirrorlist。该测试证明生成器/签名器/解析器闭包，不代替系统 apt/dnf client。
5. beta restore 在 target 已有 current latest intent 时，只替换 beta 历史 ref/正文；latest
   generation ref、remote ref 和公开正文不变。随后普通 beta publish 从 restore generation
   继续创建下一代并恢复 current local desired，没有 checkpoint 倒退或手工解锁步骤。
6. COS restore 使用 COS SigV4/conditional-write 与 EdgeOne purge 协议路径；只推进 COS
   generation/ref/object，CF generation 和正文保持第二代，证明 target 独立追踪。
7. COS restore 和普通 COS publish 都在 `locked` 后注入崩溃，再让另一个 target/本地事务
   推进 canonical HEAD；相同命令从 transaction ID 恢复原 desired commit 和 generation hash，
   成功续跑。普通 publish 不能接管 restore transaction，restore 也不能接管普通 transaction。
8. YUM gated snapshot 发布后先推进其他 intent，再在已知完整 inventory 下按 retention
   删除 route/ref/tree；restore 历史 snapshot 创建 current+1，重新 server-side Copy payload、
   写 route、purge、Basic CDN read-back，并通过 snapshot L2/L3/L4。immutable local snapshot
   ref 不移动，remote ref 恢复，完成重放不重复 PUT/Copy/purge。
9. 缺历史 CAS、当前配置摘要漂移、缺 checkpoint、checkpoint parent/desired closure、缺
   plan/content、target-global 与 intent-scoped plan 不同、历史 ref commit 不在 canonical
   HEAD history时均失败闭锁。source plan 摘要进入 restore audit，但旧 plan 不参与新发布；
   新 plan 从重建树生成。CAS/配置负例记录调用计数，证明没有 PUT、purge 或 CDN probe
   越过前置门禁。隔离重建目录在成功和可控失败后都会删除，避免隐藏 hardlink 延长 CAS
   可达性；普通 publish 的真实 CLI 测试还预置了模拟 SIGKILL 残留，并证明下一次 publish
   在独占锁下、远端事务前输出 recovery marker 且清扫整个 namespace。清扫 helper 另有
   serving-tree 保留、幂等和 symlink 逃逸负例，外部目标字节保持不变。
10. historical stable/snapshot pool 分类从 `refOverrides` 的历史 commit 读取。负例把同路径
   historical pool 设为 gated、current local ref 设为 public，最终 classifier 仍只产生
   `.sow/gated/...` key；partial historical APT intent 缺少未选 arch 时不会误拒，但所需 path
   分类不完整仍失败闭锁。该层没有网络调用。
11. stable 第一代只有一个包、当前第二代又加入包时，restore 在 PUT/purge/CDN 前以
   `stable rollback is fail-closed` 拒绝，证明 FR-19 append-only 优先于旧 ref 回退。
12. source generation 若缺少 parent 当前同一 intent 的 ref，只有 exact ref 能从 parent
   `DesiredCommit` 的 canonical config 投影、且 intent 为 `beta`/`latest` 才获删除授权。latest
   两 asset leaf 的真实 CLI 用例将第二 leaf 逐 path 做 proof/conditional DELETE/purge/404，创建
   generation 3 并把 active/remote ref vector 收敛回 historical 单 leaf；伪造且 parent config
   不可表示的 ref 仍在远端动作前失败。
13. 同一 beta asset ref 的 current generation 新增 mutable `latest` path 后，恢复不含该 path
   的旧代生成 exact `DeleteAssetServing`（parent content digest、source path、remote key、size、
   SHA、clean CDN route 全绑定）。故障注入令 purge 后 CDN 仍返回 stale 200，首次发布不提交；
   replay 不重复 DELETE，但重新 purge 并要求 404 后提交。`objects/sha256/<sha>` archive 与历史
   sibling 保留。stable append-only 回退仍在 0 PUT/purge/CDN mutation 下拒绝。
14. 混合配置含 YUM+asset 但历史 intent 只有 asset 时，不提供 private GPG key 仍可完成
   restore；签名材料需求只由 historical intent leaves 决定。若 parent 已携带 package ref，
   配置的 public trust anchor 仍须与 committed `repository_key_sha256` 连续；原地换钥会在
   historical tree 重建与远端 mutation 前拒绝。APT/YUM source 还复用 shared private/public
   pairing preflight，configured public key 与 private signing key 不匹配同样发布前拒绝。
15. CLI 拒绝 generation 0、未显式选择 target、多 target，以及 restore 与
   view/snapshot/repo/OS/arch selector 的组合。
16. retention-only plan 即使 `Objects=0` 也携带一个未被删除的 prior same-intent positive
   probe，并为 routed delete 记录 exact `VerifyAbsent`。saga 在 checkpoint 前同时证明 storage
   HEAD absence 与 CDN 404/410；stale storage、stale CDN 200、崩溃重放均有故障注入。独立 L3
   不跟随 redirect，同源 absolute 302→404 与 200 都报 `CDN_ABSENCE_DRIFT`。
17. restore 重建 snapshot 后，旧 intent plan 保持原字节。intent-scoped L2/L3 从 current
   target-global committed generation 和排序 `inventory.tsv` 判断 supersession：只有 active ref
   且 exact route/payload key 已重建才抑制旧 negative；同 snapshot 未重建 payload、另一个 retired
   snapshot 与 current-global plan 仍审计。missing、malformed、unsorted inventory 均失败闭锁，
   streaming membership 的内存只随 historical delete-set 增长。
18. ref-only restore 在其 source generation 后穿插其他 intent 仍生成
   `Objects=0, Probes=1`，真实 CLI 执行 CDN GET，post-hoc L3 不会以空 checks 静默通过；probe
   候选会排除当前 plan 正在删除的 URL。
19. 混合 parent 携带 A 签 YUM、historical intent 仅含 asset 时，将原 public trust anchor
   换成 B 后 restore 在物化前返回 conflict 并要求恢复 recorded key；PUT、purge、CDN probe
   计数不变，没有 transaction entry 或 restore materialization tree。
20. YUM `ChannelState` 的 L2 按真实服务面审计：stable GET canonical private channel JSON，
   beta/latest 从 target base、generation、legacy root 重构并严格 GET static mirrorlist。latest
   immediate L2 通过；删除其 mirrorlist 的负例得到 `REMOTE_CHANNEL_MISSING`。Cloudflare Worker
   与 EdgeOne 合同测试均证明已删除 snapshot route 的 origin 404/410 原样返回，不降级为 503。
21. 历史 adopted payload 不会因 restore 被盲目 create-only PUT：恢复器从 source commit 只向旧
   history 扫描 generation/checkpoint/plan/intent/content 完整成功闭包，把 adopted 计划项逐项绑定
   当代 `content.tsv`，并要求当前 `inventory.coverage=complete` 且 key/size/SHA 精确一致。direct
   gen1 与跨代 carried proof 均免 PUT；对象若在之后被合法删除、inventory 为 partial/缺失/畸形/
   mismatch，恢复分别退回普通 PUT或失败闭锁。DesiredCommit 不存在、指向未来、post-source 证明
   与伪造 plan/content 均不能授权继承。
22. latest 第一代只含 asset，第二代加入真实 DEB+RPM topology 后 restore 第一代：planner 从
   parent committed config 生成 APT/YUM 空 exact-replace scope，`restore-index-serving` 仅删除
   `dists`、legacy `repodata` 与 public mirrorlist；pool/Packages 和 generation 2 immutable metadata
   保留。条件 DELETE capability probe、逐 key ETag、purge/404、generation/channel/ref、recoverable
   local remote-ref delete 全部闭合；独立 L3 对 15 个 negative URL 通过。snapshot/stable topology
   仍不获该权限。
23. YUM topology removal 必须让每个 parent-only public channel 与 parent generation 的
   `ChannelState` 精确一一对应；缺失、重复或不可投影 channel 在远端 mutation 前失败。mirrorlist
   删除正文使用 parent generation 自己提交的 canonical config，而不是 source/current 配置猜测，
   因而跨代 CDN base 变化不会制造错误摘要。成功提交同时以可恢复本地事务删除陈旧 channel 文件
   和多余 remote refs；L2 对期望集合与实际集合做双向相等审计。

## 语义边界

- source 不是任意 Git checkout。它必须是目标在 canonical HEAD 历史中成功提交且同时
  具有闭合 generation/checkpoint/content/ref、同 commit 同 intent 的 plan 投影证据的旧
  generation；当前配置摘要必须相同。旧 plan 只以 SHA-256 进入审计，新 plan 必须重建。
- checkpoint 永不倒退。restore 总是创建 current+1，只替换 source intent 的完整 ref
  vector，其他 intent 保持 current；本地 current view/snapshot ref 不移动。
- restore/ordinary transaction ID 都冻结 desired HEAD；restore 还冻结 source generation。
  COS lock 后 canonical HEAD 前进不会造成 generation-hash 活锁，错误命令也不能接管事务。
- 旧云对象不是正典，命令从 historical canonical ref 和本地 CAS 隔离重建并重新校验。
- stable/snapshot 的 pool 分类来自相同 historical ref。stable 受 FR-19 约束，只有 historical
  与 current stable ref vector 完全相同时才允许；要钉旧版本必须恢复 snapshot，不能从 stable
  索引移除后来版本。
- restore 后 target remote ref 有意可能不同于当前 local desired ref；普通 L2 desired-state
  对比会报告这一 drift。restore 自身必须先完成 generation/content/head/CDN read-back，
  运维随后按 runbook 保存审计文件并执行该历史 intent 的 L3/L4 验证。
- restore 的 topology removal 权限覆盖 parent committed config 可精确投影的 `beta`/`latest`
  asset/APT/YUM leaf。APT/YUM 只删除服务入口，不删除包体或 immutable generation；snapshot
  topology 仍失败闭锁，stable regression 是独立且有意的永久安全门禁。
- 尚未执行真实 R2/Cloudflare 与 COS/EdgeOne restore。需要真实凭据、bucket/CDN 基线和
  获批窗口分别演练两目标的 purge、公开 URL、checkpoint、重放及恢复到 current desired；
  在此之前不能把供应商生产回滚标为通过。
