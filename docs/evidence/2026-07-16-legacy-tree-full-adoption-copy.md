# 2026-07-16 完整存量树副本纳管证据

> **历史阶段报告：已被后续 fresh-copy 收口证据取代。** 本文保留首次发现
> `apt-infra` orphan、PGDG 30,274 条缺体与 parser/scanner 修复的原始审计链；
> 不再代表当前最终状态。29,499 个 PGDG path 的官方恢复、775 个稳定 404 path 的
> audit-bound 裁剪、当前 package trust、真实 DNF、最终 fsck/GC 与幂等结果见
> [新鲜副本完整收口报告](2026-07-16-fresh-full-content-adoption.md)。

## 结论

本轮只在 APFS 副本
`/private/tmp/sow-prod-repo-adopt-20260715/repo` 上执行写操作。生产源
`/Users/vonng/pgsty/repo` 只读，未作为任何 `sow` 命令的 `--root`；CO、
Cloudflare、COS 和其他生产云资源均未用于测试。三个目录 inode 分别为：

| 角色 | 路径 | inode |
|---|---|---:|
| 生产源（只读） | `/Users/vonng/pgsty/repo` | `5551832` |
| 只读核验副本 | `/private/tmp/sow-prod-repo-copy.8szcW6/repo` | `74638033` |
| 可写纳管副本 | `/private/tmp/sow-prod-repo-adopt-20260715/repo` | `79596792` |

纳管前 75,034 个 serving 文件的安全快照 SHA-256 为
`37175cc53dc9ceb1dc221120616f25007453b1f4d9bca2a9d129318b877ab2db`；
它排除 `.git`、`.sow`、`.pool` 以及已评审的敏感路径，且在只读副本和可写
副本上完全相同。本文不记录、读取或复制 private key、token、passphrase。

最终 asset/当前 APT 重放使用的本地二进制为
`/private/tmp/sow-asset-member-fix-20260716`，SHA-256
`69e70aeef42abb692f5f73d7c2c39ce1e7dfe36a82c55fd4473f64bfc1ab71bc`。
它从当前 dirty source 直接构建；该 hash 只绑定本轮可执行字节，不冒充 clean Git revision。

这次运行已经真实完成 M0、10 个可证明 APT owner、13 个非 PGDG YUM
owner 和 8 个 active public asset owner 的 CAS/ref/provenance 纳管；所有成功
路径均报告 `serving_tree_rewritten=false`。它也真实发现并保持了两个源数据
阻断：`apt-infra` 有 22 个无索引证明的 DEB，53 个 PGDG YUM owner 的
`primary.xml` 共 30,274 条记录引用了基线中不存在的 RPM。因此本文是完整树副本的真实
纳管/拒绝证据，不把源数据不一致伪报成全量迁移完成。

后续只读签名盘点又确认独立的 `yum/infra` compatibility carrier 含 216 个 RPM
路径，其中 194 条由 Pigsty key 签名、22 条没有嵌入签名。完整 exact set 见
[signature inventory](2026-07-16-yum-infra-package-signature-inventory.md)。它不会影响已完成的
ordinary owner adoption，但在 builder 提供 signed replacements 前会正确阻止 ADR-0021
S1 freeze；这不是 EL8 v5.0.0 lifecycle 本身。

## M0 零字节纳管

使用 `docs/migration/fixtures/pigsty-v1.yaml` 和副本根执行 `sow init`：

```text
baseline committed=e71e5f1d33a665d0c485facb900108dbcda72ddd repos=95
config_sha256=65570b264295dd02526b508159e422ed0c8f9743f630a775f76e6a04ca0f10fc
cache rebuilt entries=74943
```

M0 后 `.pool` 为 0 byte，`.sow` 约 44 MiB；`bin` 的 12 个公开 carrier
文件（81,651 bytes）和 `pro` 的 16 个 gated carrier 文件
（23,497,439,223 bytes）只进入 immutable inventory manifest，不进入
CAS、view、publish 或 remote。紧接着的 full local fsck 对 95 个 active
repo 全部报告 `added=0 removed=0 changed=0`：

```text
fsck clean repos=95 targets=0 at=2026-07-15T19:01:59Z
```

## 包纳管的 transaction-wide admission

`--adopt-content` 在任何 worker 写 CAS 前，先解析所有 selected package
index，并要求每个 package-shaped baseline path 都有精确 index membership；
一个 repo 的晚期错误不会给较早 repo 留下新 object。该规则在完整副本上
拒绝了：

```text
repo apt-infra contains 22 package(s) that no repository index proves;
first=apt/infra/pool/main/r/rustfs/rustfs_1.0.0-a94_amd64.deb
```

使用当前 diagnostic binary 对同一可写副本重新执行完整 preflight 后，报告了 53 个
PGDG YUM owner 的 **30,274 条**缺体引用（不是“53 个 RPM”）；例如：

```text
preflight legacy index membership for repo yum-pgdg-13-el10:
YUM primary references untracked path .../credcheck_13-3.0-2PGDG.rhel10.aarch64.rpm
```

完整 line-oriented 报告为
`/private/tmp/sow-legacy-adoption-blockers-20260716.txt`：30,413 行、9,157,248 bytes，
SHA-256
`eb8e08a60283fe6635f4ea72eb2401b3018ad3b1dd9c515da4a0d4822157af9c`。
其中 YUM 缺体集合为 30,274 个 indexed path、42,601,092,935 referenced bytes；按
SHA-256 去重后为 30,228 个 object、42,600,579,672 bytes。用于这次只读诊断的 binary
为 `/private/tmp/sow-missing-inventory-20260716`，SHA-256
`ca05f0a6bc0f582cf9dfae11fdcfd2ab9188bff8249d3d1b1eea3f7f479e257a`。

产品实现现按 [ADR-0030](../adr/0030-audit-bound-legacy-yum-missing-body-prune.md)
提供窄化的两阶段修复：默认仍输出完整 blocker 与 exact set digest；只有显式传入同一
`--adopt-prune-missing-yum-confirm` 才会遗漏该集合，并为每条遗漏提交
`sow-legacy-index-prune/v1` 负向 provenance。focused current-source E2E 已实际通过：

```text
go test ./internal/cli \
  -run '^TestInitAdoptContentPrunesMissingYUMOnlyWithExactAuditedSet$' \
  -count=1 -v
--- PASS: TestInitAdoptContentPrunesMissingYUMOnlyWithExactAuditedSet (2.72s)
ok github.com/pgsty/sow/internal/cli 4.057s
```

该测试覆盖默认拒绝、wrong digest、两次解析之间的 metadata 变化、exact confirm、
零 CAS body、严格 ledger、幂等重放、零包 signed YUM candidate、fsck，以及历史账本删除/
替换负例；账本还绑定 repo ref 的 M0 祖先。它证明修复机制，不冒充完整 30,274 条副本
修复已经完成。

失败前后的 frozen orphan-set membership 相同；该批次没有新增 CAS object。
没有加入 `--force`、ignore list 或猜测 membership 的旁路。

13 个没有该源数据缺陷的 YUM owner 真实成功：

```text
adopt-content commit=e35f94ef8c38322d54c266185c56df213297ccdb changed=true
payloads=16582 bytes=18100060900 leaves=24 receipts=16582
serving_tree_rewritten=false yum_metadata_signature=not-claimed
```

`not-claimed` 是有意的：本轮没有受信 public keyring，故不把 legacy
metadata 或 RPM signature 冒充为已验证。

## DEB control-only 解析内存修复

第一次 40,480-DEB 纳管在 canonical transaction 完成后，SQLite catalog
重建的 RSS 增长到约 51.6 GiB。macOS sample 将增长定位到
`catalog.RebuildContext -> ensurePackage -> deb.Load`：第三方 loader 在只需
control metadata 时仍打开 `data.tar.*` decoder，且部分 decoder 的 Close
不会释放底层对象。为保护宿主，只对副本进程发送 SIGINT；生产源未触碰。

`internal/aptrepo/package.go` 现只用已批准的 `deb.LoadAr` 与
`control.Unmarshal` 读取 `debian-binary` 和唯一 `control.tar.*`，要求唯一
非空 `data.tar.*` 但不实例化它。结构重复、缺失、错误版本全部 fail closed；
专门测试用不可读 `data.tar.zst` 证明 metadata inspection 不打开 data
decoder。显式 `--recover` 先按 frozen journal 重建 cache，然后安全重放：

```text
adopt-content commit=5aa7bad21f7b2b4f3e5b22d083a809a4e04fe0b7 changed=false
payloads=40480 bytes=39114324884 leaves=52 receipts=40480
cache_entries=74943 serving_tree_rewritten=false
maximum resident set size=434192384
peak memory footprint=384566208
```

这把 observed RSS 从约 51.6 GiB 降到约 414 MiB；恢复不是通过删除 journal
或重做 serving tree 实现。设计见
[ADR-0028](../adr/0028-control-only-deb-inspection.md)。

asset scanner 修复后的最终产品 binary 又对同一 10-repo APT 集合做完整当前源码重放，
结果仍收敛到后续 asset commit，没有生成新 commit：

```text
adopt-content commit=fdaca2d8e96551da3a57bbdcade40d45d474e708 changed=false
payloads=40480 bytes=39114324884 leaves=52 receipts=40480
cache_entries=74943 serving_tree_rewritten=false
1925.41 real; maximum resident set size=406487040; peak memory footprint=364905432
```

本次墙钟明显由本地磁盘等待主导，故报告 1,925 秒实测，不沿用较早 731 秒结果；
两次 RSS 均维持约 400 MiB，而非按包数累积 decoder。

## Asset 保密 admission 与真实 corpus

每个 asset 在 CAS/ref 变更前同时经过 canonical digest taint receipt 与
in-band SOW archive marker admission。完整 corpus 暴露了两类不能靠扩展名
处理的普通内容：

1. `ext/sol/src/rdkit_202503.6-4.debian.tar.xz` 内有随机 `1f8b` 字节对；
2. `pkg/pig/v1.3.3/pig_1.3.3-1_amd64.deb` 内有合法、marker-free、且使用
   deterministic gzip header 的普通成员。

扫描器现只把 SOW writer 的 deterministic envelope 作为 embedded candidate；
完整解析该 gzip member、CRC/ISIZE 和 tar policy marker。完整但 marker-free
的成员后继续扫描宿主余下 bytes；畸形 SOW candidate fail closed。测试同时
证明原始 marker、仅移除 FCOMMENT 的 payload marker、跨 64 KiB 边界和前置
普通 gzip 后的 gated SOW archive 仍被拒绝。详见
[ADR-0026](../adr/0026-offline-archive-projection-intent.md)。

8 个 active public asset owner 的真实结果：

```text
adopt-content commit=fdaca2d8e96551da3a57bbdcade40d45d474e708 changed=true
payloads=958 bytes=8339654632 leaves=8 receipts=958 cache_entries=74943
serving_tree_rewritten=false
maximum resident set size=186597376
```

同一 binary、selector 和源树完整重放：

```text
adopt-content commit=fdaca2d8e96551da3a57bbdcade40d45d474e708 changed=false
payloads=958 bytes=8339654632 leaves=8 receipts=958 cache_entries=74943
serving_tree_rewritten=false
maximum resident set size=193789952
```

`asset-root-both`、`asset-root-cos` 和 `asset-gated` 各自以 exit 3 和
`selectors matched no active repositories` 在扫描前拒绝；三次之后 HEAD 仍为
`fdaca2d8e96551da3a57bbdcade40d45d474e708`，canonical worktree clean。

## Post-adoption fsck 与 GC audit

最终 HEAD 上的 local-only full fsck 退出 0：

```text
fsck canonical_git_roots=4 commits=7 blobs=211 blob_bytes=54716748 drift=0
fsck materialized_route_partitions=0 ledgers=0 files=0 drift=0
fsck canonical_asset_projection_drift=0
fsck clean repos=95 targets=0
18.17 real; maximum resident set size=58966016
```

随后只运行 `sow gc` dry-run，没有 `--apply` 或 confirmation：

```text
root_files=1123 references=911075 reachable=58111 orphans=0 missing=0
serving_generations_installed=0 serving_generation_orphans=0 serving_target_orphans=0
gc_set_sha256=ba73df7614f5c29ca7b4b0e27bb87da5cd8e6b354e6765d60dd4b0814aadf644
deleted=0 deleted_bytes=0
1139.06 real; maximum resident set size=155533312
```

早期失败批次曾留下 179 个未引用 object；最终 dry-run 的 `orphans=0` 证明这些
bytes 后来被成功 APT transaction 的 refs/provenance 接管，而不是继续作为垃圾存在。
没有为追求“干净数字”执行任何删除。

最后重新运行 sensitive-path-safe serving snapshot：

```text
snapshot=.../serving-after-adopt.tsv files=75034
before_sha256=37175cc53dc9ceb1dc221120616f25007453b1f4d9bca2a9d129318b877ab2db
after_sha256=37175cc53dc9ceb1dc221120616f25007453b1f4d9bca2a9d129318b877ab2db
cmp -s exit=0
```

因此本轮所有成功/失败/recovery/idempotent adoption 都保持了原 serving bytes；新增
的约 68 GiB CAS 与 canonical state 只存在于 `.pool/.sow` 控制树。

## 仍未闭合的迁移项

- `apt-infra` 的 22 个无索引 DEB 已完成分类：20 个 `stash/**` 是旧 builder handoff，
  2 个 rustfs a94 是 reprepro DB 与 Packages 均不引用的 orphan（b8 才是 indexed
  version）。完整物理迁移配置现将两类路径显式 quarantine，保留原字节、不纳入
  当前 APT view，也不猜测历史 membership；待在可写副本重跑 M0/adoption 复验。
- 53 个 PGDG YUM owner 的 30,274 条缺体引用正在按 exact size/SHA-256 从官方 PGDG
  current/archive 恢复；官方 archive 样本
  `credcheck_13-3.0-2PGDG.rhel10.aarch64.rpm` 的 37,088 bytes 与 SHA-256
  `c0b1a360a9507522298f8f4272fbc9785851849dbd0aa505f1003bbdafb71fc0`
  已与 local primary 完全匹配。部分历史 testing RPM 在两个官方入口均为 404；完整
  fetch 完成后，只有仍不可恢复的 exact remainder 才可按 ADR-0030 确认并生成与实际
  bodies 一致的新 signed metadata。当前尚未完成整批 install/adoption，不能升级为通过。
- 本轮没有可信 legacy YUM/RPM keyring，故没有 metadata/package trust claim。
- `yum/infra` 的 public Pigsty key 已能验证 194/216 个 RPM；其余 22 个路径（21 个
  unique objects）是未签 self-built builder 输入，本机没有同 NEVRA 已签替代物。FR-17
  禁止 SOW 隐式重签；必须由 builder 交付已签对象，再生索引并建立 fresh M0/S0 后才能
  运行真实 compatibility S1→S3。
- inactive root-key builder/rebase、gated Pro 正式 owner、
  Nginx cutover、旧 writer/IAM 撤权和双云生产切换均未执行。
- 真实非生产 R2/Cloudflare/COS/EdgeOne 资源尚未提供；生产资源禁止测试，
  本文的本地副本证据不替代 POC-06。

因此 MIG-05 已从 synthetic fixture 推进到完整存量树副本的真实 M0、可证明
子集纳管和源数据 fail-closed 诊断，但在上述 owner 数据与外部非生产资源
闭合前仍是 `实现中`，Goal 不得标记完成。
