# 证据绑定的远端删除合同（2026-07-12）

## 验收边界

本证据闭合三条真实产品代码路径：asset `rm` 后直达 URL 不再可访问；APT
by-hash retain=N 在 cf/cos 两个独立 target code path 上执行过期 key 删除；历史 restore
可把 beta/latest asset 与 APT/YUM topology 安全收敛到旧 ref vector。制品、CLI
与供应商客户端代码是真实产品实现，远端边界是本地签名 HTTP/SigV4/CDN 协议夹具；这里的
cf/cos 名称不表示真实 R2/COS/Cloudflare/EdgeOne 已连接。它不把普通 `Plan.Removed` 当成
DELETE，不以文档或内存 mock 代替协议执行；真实供应商凭据验证仍单列为外部 PoC。

## 实跑命令

```text
$ go test -count=1 ./internal/publish
ok github.com/pgsty/sow/internal/publish

$ go test -count=1 ./internal/cli \
    -run 'TestPublishCLIAssetRemoveDeletesBothServingRoutesAndRestoreReputs|TestPublishCLIAPTByHashRetentionDeletesBothTargetsAcrossStaggeredPublishes|TestPublishRestoreRemovesAPTAndYUMTopologyTransactionally|TestAuthorizedAssetDelete|TestAuthorizedAPTByHashDelete|TestNegativeOnlyAssetPublication|TestPublishRestoreGenerationResumesAfterPurgedCrash'
ok github.com/pgsty/sow/internal/cli

$ go test -count=1 ./internal/cli
ok github.com/pgsty/sow/internal/cli 269.371s

$ go test -race -count=1 ./internal/publish \
    -run 'TestAssetServingDelete|TestSnapshotRetention|TestPlanAllowsOnlyEvidence|TestDecodePlanKeepsLegacy'
ok github.com/pgsty/sow/internal/publish

$ go test -race -count=1 ./internal/cli \
    -run 'TestPublishCLIAssetRemoveDeletesBothServingRoutesAndRestoreReputs|TestPublishCLIAPTByHashRetentionDeletesBothTargetsAcrossStaggeredPublishes|TestAuthorized|TestNegativeOnly'
ok github.com/pgsty/sow/internal/cli

$ go vet ./...

$ go test -run '^$' ./...
# exit 0；所有 package 编译通过，未执行测试

$ git diff --check
```

本次所有合并后修改以 [final local audit](2026-07-12-final-local-audit.md) 的 320-file
product-source 摘要绑定：全仓 CLI 269.371s、publish 11.970s；完整受影响 race 集
CLI 334.161s、publish 9.200s、state 10.717s；`go vet`、`go mod verify` 与
`git diff --check` 均退出 0。restore 聚焦组另为 47.592s。

## Asset CLI/协议闭环

`TestPublishCLIAssetRemoveDeletesBothServingRoutesAndRestoreReputs` 通过真实 `Main` 顺序执行：

1. `add` → beta 发布到 cf/cos → `promote beta latest` → latest 发布到 cf/cos；
2. 将两个 origin 的 serving object 保持原字节但移除 `sow-sha256` metadata，模拟零字节
   纳管的 legacy 对象；
3. `rm --view latest` 后先发布 cf；注入 purge 后仍返回旧对象的 stale CDN，L3 必须失败，
   checkpoint 不提交；
4. 恢复正常 purge 后用同一 transaction 重放：origin 已 absent 时不再 DELETE，仍重新
   purge 并要求 404；随后 cos 独立完成自己的 HEAD→GET hash→DELETE→HEAD absent→purge→404；
5. `/pkg/latest` 在全球/国内 CDN 均为 404，beta serving key 仍存在，
   `objects/sha256/<sha>` archive 仍存在；无变化重放不再 DELETE；
6. 两个 target 分别 `publish --restore-generation 2`，serving key 以历史精确字节重新 PUT。

`TestAuthorizedAssetDeleteUsesExactViewProjection` 另以非 mutable pattern 锁定 immutable
asset path，证明 immutable 与 mutable serving key 都生成同一 `asset-serving` 删除合同。

## APT 三代、双 target 错峰闭环

`TestPublishCLIAPTByHashRetentionDeletesBothTargetsAcrossStaggeredPublishes` 用纯 Go 生成三份
真实 `.deb`，每次经真实 APT generator/OpenPGP 生成 Packages/Release/InRelease/by-hash，
并通过签名的 S3 HTTP provider 路径发布：

1. retain=2；第一、第二代先同时发布到 cf/cos，确认第一代三个 by-hash key 在两端存在；
2. 第三代生成后，当前 sealed ledger 只保留第二、第三代，Git 祖先仍保存第一代 ownership；
3. 只发布 cf，精确删除第一代三个 key并保留后两代；cf 的 remote-state Git commit 完成后，
   再单独发布滞后的 cos，仍从历史 ledger 生成并执行相同三个 DELETE；
4. by-hash 删除不进入 CDN purge；两端 storage HEAD 均 absent；再次发布两个 target 均
   `status=unchanged`，DELETE 计数不增长。

## Forward restore 的 mutable topology 删除

- `TestPublishRestoreAssetPathRemovalUsesEvidenceBoundDeleteAndReplays`：beta 同一 ref 的第二代新增
  mutable `latest` serving path；restore 第一代生成 exact `asset-serving` 删除。注入 stale CDN
  使首次 L3 失败，origin 已删除但 checkpoint 未提交；同 transaction replay 不重复 DELETE，
  必须重新 purge/404 才提交。plan 精确绑定 parent manifest 中的 source path、remote key、size、
  SHA 与 CDN path，`objects/sha256` archive 保留。
- `TestPublishRestoreLatestRemovesConfiguredExtraAssetLeaf`：静态配置含两个 asset repo；latest 第一代
  只有一个 leaf，第二代加入另一个 leaf。restore 第一代把已配置 extra leaf 作为空 exact-replace
  scope，逐 path 执行同一删除闭包，并从新 generation active ref vector 移除该 leaf。
- `TestPublishRestoreRemovesAPTAndYUMTopologyTransactionally`：latest 第一代只有 asset，第二代在
  同一冻结配置中加入真实 DEB/RPM ref。restore 第一代从 parent canonical config 建立空 APT/YUM
  exact-replace scope，删除 `dists`、legacy `repodata` 与 public mirrorlist，完整执行条件 DELETE、
  purge、404 和 checkpoint；pool/Packages 与 generation 2 immutable archive 保留，active channel、
  target generation ref vector 及本地 `refs/sow/remotes/cf/...` 精确收敛，随后独立 L3 通过。
- `TestPrepareHistoricalPublicationFailsClosedOnMissingRefAndTopologyRemoval` 证明 parent-only YUM ref
  只有在 parent `DesiredCommit` 的 canonical config 可精确投影时才获授权；任意伪造 ref 仍失败。
  stable append-only 负例继续在远端 mutation 前拒绝。

## 失败闭锁

- plan class/path validation 拒绝 checkpoint、generation、private channel、CAS archive、APT pool、
  YUM Packages、stable/snapshot topology、digest/key 不一致及任意 class；restore-only class 仅接受
  beta/latest APT `dists`、YUM `repodata` 与 public mirrorlist。
- remote 显式 digest/size 漂移在 DELETE 前停止；即使自定义 metadata 声称摘要匹配，删除授权
  也必须执行 HEAD→streamed GET 并逐字节 hash。负例用同尺寸外来正文伪造旧 `sow-sha256`，
  saga 返回 `ErrDrift` 且不发 DELETE；metadata 只能早期拒绝，不能作为破坏性内容证据。
- HEAD 返回 absent 后注入 foreign object：saga 不发 DELETE，最终 residue 检查失败。
- HEAD/GET proof 后注入 foreign overwrite：live DELETE 携带原 ETag，provider 返回 conflict，foreign
  bytes 保留。另一个负例让 provider 忽略 `If-Match`；SOW 自有 capability probe 被错误删除后，
  saga 在 live key 前返回 `ErrCapability`。pinned MinIO 的真实 S3 边界也复现并闭锁同一行为。
- 2026-07-18 的真实 R2 运行确认 Cloudflare 同样忽略 DeleteObject `If-Match`。默认模式仍保持上述
  fail-closed；ADR-0036 新增显式 `checkpoint-fenced` 单写者模式，负例覆盖远端围栏漂移、两次 streamed
  proof 之间正文漂移、缺失 provider extension 与删除响应丢失重放。真实命令和空桶前后证据见
  [真实 R2 存储协议](2026-07-18-real-r2-storage-protocol.md)。
- stale storage、stale CDN、delete/purge 丢响应及 journal 重放均有独立故障注入覆盖。
- current ledger 仍保留 shared hash 时不删；live Release 与 ledger 不一致、或 Git 历史没有
  sealed ownership 时不生成删除计划。
- target-wide baseline 同时过期 selector 外 snapshot 时，该 removed path 由 snapshot retention
  专属计划处理，不会被 asset/by-hash 授权器误分类；完整 CLI 包回归覆盖该交叉场景。

## 双目标顺序与恢复隔离

- `TestPublishCLIDefaultViewsStopsFailedTargetAndContinuesSibling` 在 COS beta 的真实供应商协议
  PUT 路径注入失败；COS 不得继续 latest/stable，CF 仍依次提交 beta/latest/stable，命令最终
  返回 partial，而不是回滚成功目标或让失败目标跳过代际。
- `TestPublishCLIDefaultSnapshotRecoveryFailureDoesNotBlockSibling` 先在 COS snapshot `locked`
  durable phase 注入中断，再令默认命令的精确 snapshot 恢复失败；COS 被隔离，CF 仍提交三视图
  与 retained snapshot。失败目标没有 generation 2–4，对应兄弟目标最终 checkpoint 为 snapshot
  generation 4。
