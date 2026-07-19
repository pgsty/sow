# APT 选择器事务闭包与 snapshot 增量物化证据

日期：2026-07-12

## 合同

APT 的 `Release` / `InRelease` 是 suite-wide 指针。`publish --os <suite>
--arch <arch>` 中的 arch 只用于触发该 suite，不能把事务缩成单一
`binary-<arch>`。目标 content manifest 必须同时满足：

- 选中 suite 的全部配置架构、Packages/by-hash 与实际引用 payload 形成闭包；
- 未选 suite 的 metadata/ref/pending change 不进入本轮 plan 或 PUT；
- 共享 `pool/` 对 selected paths 流式 upsert，保留 sibling/historical extras；
- 固定 `.sow/materialized/snapshots/<id>` 根的 partial replay 不裁掉未选 repo/arch；
- L1 `--os` 只审选中 suite，`--arch` 仍审该 suite 的全部架构。

## 红灯复现

修复前运行：

```bash
go test -run TestPublishCLIPartialAPTIsSuiteWideAndSnapshotSafe \
  -count=1 ./internal/cli
```

5.35s 后失败：target content manifest 缺少本地已经推进的
`jammy-arm64_2.0-1_arm64.deb`。原因是 partial selected manifest 只保留一个
arch，却用整个 APT source root 做 `ReplaceManifestScopes`；同一路径也会删除
未选 suite sibling。snapshot preparation 则把 partial payload 对固定 snapshot
根执行全根 `ReconcileExact`。

## 实现证据

- `publicationSelectionScopes` 把 partial APT ownership 表达为
  `dists/<selected-suite>` exact replace + `pool/` exact-path upsert。
- `ReplaceManifestSelection` / `DropManifestSelection` 都是双排序流单遍合并，
  常量额外内存；首次引入 latest scope 也不会强制 sibling payload 重传。
- publish preflight、projection、snapshot preparation 与 L1 view/ref checks 使用同一
  suite-wide arch closure。
- snapshot 先把当前固定根与 selector-owned payload 合并成 cumulative desired，
  再调用全树 `ReconcileExact`，从而保留未选 sibling 且仍精确清理选中 leaf。
- APT partial L1 验证完整选中 suite；共享 pool 采用“selected references 必须存在且
  相同、unselected extras 可存在”的子集闭包。full L1 仍执行双向 exact pool 与完整
  suite-set 检查。

## 通过的回归面

```bash
go test -run TestPublishCLIPartialAPTIsSuiteWideAndSnapshotSafe \
  -count=1 -v ./internal/cli
# PASS（最新重跑 11.433s）

go test -run 'TestPublishManifestSelectionReplacesSuiteAndUpsertsSharedPool|TestPublishManifest|TestFilterAPTPublication' \
  -count=1 ./internal/cli
# PASS（1.043s）

go test -count=1 ./internal/verify
# PASS（2.100s）

go test -race -run TestPublishCLIPartialAPTIsSuiteWideAndSnapshotSafe \
  -count=1 ./internal/cli
# PASS（16.199s）

go test -race -count=1 ./internal/verify
# PASS（3.334s）
```

真实 CLI 用例包含：

1. 两个 APT repo、同 repo 两 suite、每 suite 两 arch 的首次完整发布；
2. 未选 bookworm 留有真实 pending v2，同时 jammy arm64 变化，只执行
   `publish --os jammy --arch amd64`；
3. target desired/plan 保留 jammy sibling closure 与旧 bookworm，PUT/plan/ref 不含
   pending bookworm；随后 full publish 才推进 bookworm ref/bytes；
4. 同一 immutable snapshot 先完整 publish，再按单 repo/arch replay，本地 snapshot
   根、target content manifest 与累计 ref vector 均保留 sibling；
5. 健康 full root 的 partial L1 通过；临时隐藏 unselected bookworm 时 partial 通过而
   full L1 失败；篡改 selected jammy 的 arm64 Packages 时，即使 CLI 选择 amd64，
   partial L1 仍失败。

## 边界

这里证明本地文件系统、canonical Git、真实 CLI 与签名 S3/CDN 协议夹具的选择器
语义，不替代真实 R2/COS/Cloudflare/EdgeOne 发布 PoC，也不解决 apt<1.2 fixed
alias 的跨对象原子性政策缺口。
