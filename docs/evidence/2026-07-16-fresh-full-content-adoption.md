# 2026-07-16 新鲜副本完整内容纳管与真实 DNF 收口证据

## 结论

本轮在新建可写副本
`/private/tmp/sow-prod-repo-adopt-fresh-20260716/repo` 上完成了当前迁移配置内
APT、ordinary YUM 与 active public asset 的完整内容纳管、幂等重放、PGDG
缺体修复、真实 DNF 消费、全树 `fsck` 和 GC dry-run。生产源
`/Users/vonng/pgsty/repo` 始终只读，且从未作为 `sow --root`；其 inode
`5551832` 未变，可写副本 inode 为 `84167566`。

没有使用 CO/COS、Cloudflare、EdgeOne 或任何生产 bucket、Zone、domain 做测试。
用户提供的 Cloudflare bucket `pro` 与 `pro.pigsty.io` 因不满足专用非生产资源
命名和生产域隔离门禁而没有被探测或使用。全部云凭据在 Go 门禁中清空，真实云、
边缘和 purge watcher opt-in 固定为 `0`。

纳管前 75,034 个安全 serving 文件快照仍为：

```text
37175cc53dc9ceb1dc221120616f25007453b1f4d9bca2a9d129318b877ab2db
```

快照排除 `.git`、`.sow`、`.pool` 与既有敏感路径。`bin/fileauth.txt`、
`docker/private.asc`、`docker/yum-syncer/private.asc`、`key` 没有被读取、
复制或写入证据。所有成功纳管均报告 `serving_tree_rewritten=false`。

## 当前二进制与 SQLite 并发修复

本轮最终纳管二进制：

```text
path=/private/tmp/sow-current-adoption-fixed.OS1cmU/sow
sha256=ca38abb7a3521d22e01c41239060fcfb6f99d2fd1e573427b7b72858841964a4
version=sow 0.1.0-dev darwin/arm64 go1.26.5
```

完整 PGDG 并行导入首次暴露 SQLite `database is locked`。根因不是数据库损坏，
而是 missing-YUM producer 的 prune receipt 与 result consumer 的 payload/entry
写入并发；WAL 仍只有一个 writer，原 `PRAGMA busy_timeout` 只作用于创建 schema
的连接，没有进入后续懒打开连接。

`internal/cli/adopt_content.go` 现把 `_pragma=busy_timeout(5000)` 写入 DSN，保证
每个连接都生效；spool 写操作由 mutex 串行化，payload collision 检查与
payload/entry insert 合并为同一事务。`internal/cli/adopt_content_test.go` 新增：

- 8 个连接逐一验证 `busy_timeout=5000`；
- prune writer 与 payload writer 并发压力；
- collision 事务回归。

聚焦 ordinary 连续 20 次与 race 连续 3 次均通过；完整 current-source ordinary
CI 六分片也通过：

| 分片 | tests | ordinary | race |
|---|---:|---:|---:|
| `^Test[A-F]` | 145 | 277.283s | 606.758s |
| `^Test[G-M]` | 141 | 306.488s | 432.536s |
| `^Test[N-O]` | 51 | 71.683s | 87.381s |
| `^Test[P-Q]` | 144 | 806.766s | 641.521s |
| `^Test[R-V]` | 119 | 320.367s | 267.126s |
| `^Test([W-Z]|[^A-Z]|$)` | 59 | 56.861s | 49.235s |

合计 659 个 default-build CLI tests，六个 regex 穷尽且互斥。直接把 659 项放进
单一 `go test ./internal/cli` 会超过 Go 默认 10 分钟包级闹钟；正式 CI 本来就按
上述六片运行，每片均低于 15 分钟门禁。这不是断言失败或死锁，不修改产品
`fsync`/恢复语义来掩盖测试时长。

首次 current-source G–M race 长跑暴露
`TestLocalYUMServingRunsIndependentLeafWorkersConcurrently` 的测试调度假设：测试声明
两个 leaf 都到 `generation-ready` 后才取消，但原 hook 没有显式 barrier，race 下可能
在第二个 leaf 仍为 `install-intent` 时取消。产品的两个 phase 都可恢复，失败不是生产
断言；测试仍按其更强承诺修正为两个 hook 都到达后再取消。聚焦 race 连续 10 次
`68.628s` PASS，随后完整 G–M race `432.536s` PASS。生产 journal、`fsync`、
commit order 和恢复代码均未放宽。

## PGDG 缺体恢复与审计绑定裁剪

历史报告发现 53 个 PGDG owner 的 `primary.xml` 共有 30,274 个缺体 path，
对应 30,228 个 unique object。当前修复只从 PGDG 官方 current/archive 只读下载，
并逐个核对 metadata size/SHA-256：

```text
recovered_paths=29499
recovered_objects=29453
recovered_bytes=40040817258
```

官方入口稳定返回 404 的最终 remainder 为：

```text
paths=775
objects=775
bytes=2559762414
confirmation_sha256=5d953cd75dd4650a92752ef8a6b42dd9d6b78f815f157d999a036184b0aa866a
```

失败明细保存在 repo 外：
`/private/tmp/sow-pgdg-recovery-evidence-20260716/fetch-failures.tsv`，SHA-256
`d4dd1a...`。十份 canonical prune ledger 合计精确 775 条 receipt，只有同一
complete-set digest 的显式确认才可提交；默认、wrong digest、两次解析 drift、
ledger 删除/替换都 fail closed。

PGDG package trust 使用官方 RHEL public key：

```text
key=/private/tmp/sow-pgdg-rhel-package-key-20260716.asc
sha256=a70c9527426017d00fa4e6f9d2941d515357a27a7be82e155248ece53bbe5453
fingerprint=D4BF08AE67A0B4C7A1DBCCD240BCA2B408B40D20
```

完整 PGDG 纳管：

```text
commit=c76def0858ef2afbbabdb7f247caca03a958e86e
changed=true payloads=44372 bytes=58263514658 leaves=104 receipts=44372
pruned=775 cache_entries=104420 serving_tree_rewritten=false
elapsed=386.25s max_rss=150437888
```

相同 binary、selector、配置和副本重放：

```text
commit=c76def0858ef2afbbabdb7f247caca03a958e86e
changed=false payloads=44372 bytes=58263514658 leaves=104 receipts=44372
pruned=775 cache_entries=104420 serving_tree_rewritten=false
elapsed=501.63s max_rss=189988864
```

这关闭了历史 30,274 缺体 corpus：29,499 个 path 以官方原字节恢复，775 个
稳定 404 path 以 exact negative provenance 从新索引排除；没有 force、模糊
ignore list 或猜测 membership。

## 其他 YUM 信任与纳管

只读签名盘点确认 gpsql、mssql、pgsql RPM 的 signer key id 均为
`b9bd8b20`；Percona 为 `8507efa5`。当前临时迁移配置将其绑定到 public-only
keyring：

```text
Pigsty fingerprint=9592A7BC7A682E7333376E09E7935D8DB9BD8B20
Pigsty key sha256=17b9c7727c3a4d3b77463299ade471b28a8ba97da263e6bbb02986a578de0882
Percona fingerprint=4D1BB29D63D98E422B2113B19334A25F8507EFA5
Percona key sha256=59d263e9...
config sha256=9d7ea088544c34abf022da1f0671d8d752280b4411e01215b5abac61502cf2eb
```

Pigsty-signed ordinary YUM：

```text
commit=00d0759cbac224291c606a3816c869dbf8c1a290
payloads=15562 bytes=13517434079 leaves=15 receipts=15562
elapsed=782.12s max_rss=267812864 serving_tree_rewritten=false
```

Percona：

```text
commit=3715a445340b05068d834bfbd2f706aa5774b2f5
payloads=1020 bytes=4582626821 leaves=9 receipts=1020
elapsed=1643.48s max_rss=272023552 serving_tree_rewritten=false
```

`yum-infra-legacy-compat` 在本报告运行时按 FR-17 正确隔离了当时 22 个没有
embedded signature 的 path。2026-07-17 的后续只读快照确认当前 216 个 RPM
path 已全部由 Pigsty key 验签，并在精确可写副本完成 ADR-0021 S0→S3、
EL8/9/10 双架构强签名 DNF、L1、`fsck` 与幂等重放；见
[`2026-07-17-yum-infra-current-compatibility-cutover.md`](2026-07-17-yum-infra-current-compatibility-cutover.md)。
因此历史 builder input 缺口已关闭，且关闭方式没有让 SOW 隐式重签或降低校验。

## APT 与 asset 纳管

当前 physical config 已把 `apt-infra` 的 20 个 `stash/**` builder handoff 与
2 个未被 Packages/reprepro 引用的 rustfs a94 body 显式 quarantine。当前 active
APT owner 纳管结果：

```text
commit=93c41f772ee83dd5b5bf1bacc1f62debf91cebf3
payloads=40659 bytes=45941265068 leaves=54 receipts=40659
elapsed=885.09s max_rss=612532224 serving_tree_rewritten=false
```

8 个 active public asset owner：

```text
commit=7864bb664f4ded28a09054a79efbc7f74720f8e3
payloads=958 bytes=8339654632 leaves=8 receipts=958
elapsed=6223.05s max_rss=274808832 serving_tree_rewritten=false
```

asset 墙钟如实记录为 6,223 秒。该路径必须完整扫描归档内部 confidentiality
marker，不能只按扩展名或索引跳过内容；本次 RSS 保持有界，但 APFS 大文件读取和
解压/校验墙钟仍需作为性能观察保留。inactive root/gated/inventory carrier 仍只进入
M0 manifest，不进入 public view、CAS 或 publish。

## 真实 DNF 消费

从 canonical PGDG leaf 物化 EL10/x86_64 repository，当前 generation 为
`09578067286210687545`，receipt commit
`6d8137516fbd4121d4f680e405ee48a6035361df`。生成树包含 320 个 package entry、
187,910,554 bytes，primary/filelists/other 均为 zstd，并有 `repomd.xml` 与
`repomd.xml.asc`。

真实客户端使用本地 `almalinux:10`、`--network none`、
`--disablerepo='*'`，同时启用 `repo_gpgcheck=1` 与 `gpgcheck=1`：

```text
dnf makecache: PASS
dnf install postgresql18-docs: PASS
installed=postgresql18-docs-18.1-1PGDG.rhel10.x86_64
```

最初把 8 把历史 PGDG key 全部导入 Alma 10 时被系统 crypto policy 正确拒绝；
改用该仓库当前官方 RHEL key 后通过。另一次安装 `postgresql18-libs` 只因断网基础
镜像缺 `libldap.so.2` 依赖失败，不是 metadata、repo signature 或 package signature
失败；选择无外部依赖的 `postgresql18-docs` 后完成真实 install。

## 最终 fsck 与 GC dry-run

fresh-copy 最终 `sow fsck`：

```text
canonical_git_pre_recovery_roots=9 commits=11 blobs=401 blob_bytes=93258352 drift=0
legacy_prune_ledgers=10 receipts=775 confirmation_sets=1 drift=0
materialized_route_partitions=1 ledgers=1 files=3 drift=0
canonical_asset_projection_drift=0
95 repos: added=0 removed=0 changed=0
serving_checks=3 drift=0
fsck clean repos=95 targets=0 at=2026-07-16T18:18:51Z
```

随后只运行 GC dry-run，没有 `--apply` 或删除确认：

```text
root_files=3463 references=2771036 reachable=102343 orphans=0 missing=0
serving_generations_installed=2
serving_generation_orphans=0 serving_tombstones=0 serving_target_orphans=0
gc_set_sha256=ba73df7614f5c29ca7b4b0e27bb87da5cd8e6b354e6765d60dd4b0814aadf644
deleted=0 deleted_bytes=0
elapsed=1211.08s max_rss=252952576
```

## 已关闭与仍开放的边界

本报告关闭：

- 完整副本 PGDG 缺体恢复/remainder 裁剪/纳管/幂等；
- active APT、ordinary YUM、Percona 与 public asset 的 CAS/ref/provenance 纳管；
- 当前 PGDG signer trust 与真实 EL10 DNF `makecache/install`；
- full local fsck、prune ledger、物化 receipt 与 GC orphan/missing 审计；
- SQLite 多连接并发 writer 回归；
- 后续精确副本已关闭 `yum/infra` 216-RPM package trust 与 S0→S3
  EL8/9/10 双架构兼容切换，详见 2026-07-17 报告。

仍开放：

- inactive root builder/gated Pro rebase；
- 生产 Nginx/consumer cutover、writer/IAM 撤权、双云切换与回滚；
- 经 registry 审核的专用非生产 R2/COS/Cloudflare/EdgeOne 真环境证据；
- 上线后的事故、时延、成本和多 PoP 运营指标。

因此 fresh-copy 内容修复与 `yum/infra` 本地兼容输入均已闭合，不再是当前阻塞；
Goal 仍不能完成，当前硬边界是专用非生产云/边缘资源、inactive builder/gated
handoff 和生产迁移/撤权窗口。
