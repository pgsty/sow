# 当前 `yum/infra` 精确副本兼容切换证据 — 2026-07-17

## 结论

当前只读生产源 `/Users/vonng/pgsty/repo/yum/infra` 的精确副本已完成
ADR-0021 定义的 S0→S1→S2→S3、本地 Nginx 物化、EL8/9/10 双架构真实 DNF
消费、L1、`fsck` 与幂等重放。测试没有写生产树、CO/COS、Cloudflare、
EdgeOne、bucket、Zone 或生产域。

本轮关闭了此前的 builder package-signature 输入阻断：当前 216 个 RPM path
全部由 Pigsty public key 验证为 `digests signatures OK`，且精确副本中的
216 个 RPM 与本轮只读源快照逐字节一致。历史 2026-07-16 的 22-path unsigned
盘点仍保留为发现链，但不再描述当前源状态。

这不是生产切换：repository metadata 使用一次性测试 key，所有 canonical state、
候选、generation、Nginx 和客户端写入都在 `/private/tmp`。生产 repository key
签发、维护窗口、consumer 变更、writer/IAM 撤权和双云发布仍需单独执行。

## 安全边界与源字节证明

精确副本根：

```text
/private/tmp/sow-yum-infra-exact-20260717.f19S3I
```

在复制前、复制后和全部测试结束后，对生产源 234 个普通文件按相同排序生成
SHA-256 manifest；三个 manifest 以及最终流式重算的摘要均为：

```text
files=234
manifest_sha256=b44a86b71c39700a575f9bb869e49e66f093bf453dd863a638f0ab02315649c7
```

生产源只被 `find`、hash 和只读复制访问；SOW 的 `--root` 始终指向临时
workspace。Cloudflare bucket `pro`、`pro.pigsty.io` 以及任何 Pigsty
生产资源均未探测。

当前源每个架构 leaf 还各有一个未被 RPM membership 使用的根级
`modules.yaml`。SOW 不生成 modulemd，S0 admission 也不允许把该 builder
handoff sidecar 当普通仓库文件，因此仅在可写副本中精确 quarantine 这两个
文件；生产源未改。既有 `repodata/*-modules-*.yaml.gz` 作为 frozen legacy
输入保留，SOW 没有生成、解析或扩展 modulemd。quarantine 后 S0 是 232 个文件：
216 个 RPM 与 16 个既有 repodata 文件。

## 两条签名链

package trust 只包含当前 Pigsty public key：

```text
fingerprint=9592A7BC7A682E7333376E09E7935D8DB9BD8B20
key_sha256=17b9c7727c3a4d3b77463299ade471b28a8ba97da263e6bbb02986a578de0882
verified_rpm_paths=216
```

repository metadata 使用本轮一次性测试 key：

```text
fingerprint=3229B8779731D7D3B329434F48026556BEE060EE
public_sha256=af78a5c0e6e2b58a7156255ef3e51cd565b883fe4a218ade24a91faa64bf0c68
private_sha256=ab335ed8ce9e862d251fb13520153429b72421d26b0ffe8736aa0ed40a5fddf0
```

测试 key 只证明纯 Go `repomd.xml.asc` 生成和真实 DNF 接受；它不是生产
private key，也不授权生产写入。

## S0、S1 与 S2

零字节 carrier adoption：

```text
S0 commit=19f808d756b4a5bcd11709619015d100e9fbd655
files=232 bytes=8688183728
```

以当前源中 byte-identical、Pigsty-signed 的 `pg_exporter-1.3.0-1` 两个架构
包建立 owner/ref 后，S1 为：

| arch | source commit | packages | bytes | source SHA-256 |
|---|---|---:|---:|---|
| aarch64 | `410b9286b018d98ec923a552583f339a400374fc` | 108 | 4,251,347,417 | `f9de013e…` |
| x86_64 | `1df7e1752168609dfb13b04791d0dc918971906f` | 108 | 4,434,929,405 | `56f4544d…` |

候选与 S2 freeze：

| arch | candidate repomd SHA-256 | freeze commit | cutover confirm |
|---|---|---|---|
| aarch64 | `c059d235…` | `9c3c5fb18a0902add9378df8c1705b52555a2fc4` | `sha256:ec33db4dcc8cb2f46af58b43bbce1793706ca47bf069ab04961bdab18ba6ad0d` |
| x86_64 | `ebdeedad…` | `a7e9da41638e3c39c93291de00e478a966fc6db3` | `sha256:46fcb0913eddb61d63a82590617d3acd22ae4a45428a781e6c705091048c2aa0` |

S2 raw compatibility alias 在 `gpgcheck=1`、`repo_gpgcheck=0` 下由
EL8/9/10 × aarch64/x86_64 六组真实 DNF 完成
`pg_exporter-1.3.0-1.<arch>` 安装。该阶段只是迁移桥；S3 不保留
`repo_gpgcheck=0`。

## 多架构 Nginx admission 缺陷与修复

第一次用双架构 carrier 生成 Nginx include 时，当前产品正确发现了一个未被
单架构测试覆盖的实现缺陷：

```text
raw compatibility tree changed after stage audit: added=0 removed=116 changed=0
```

`validateRawNginxCompatibilityClosure` 当时把单个 route root 的扫描结果与整个
双架构 carrier manifest 比较，因而把兄弟架构的 116 条记录误判为 removed。
现在 admission 先把 carrier manifest 投影到当前 route root，再做最终 ABA/drift
复核；hostability 扫描同样跳过兄弟架构而不放宽当前 route 的 unexpected-file
拒绝。

新增
`TestRawNginxCompatibilityClosureProjectsMultiArchCarrierManifest` 同时覆盖两个
合法架构和当前 route 的额外文件负例；聚焦 ordinary/race 均通过。完整 660-test
CLI ordinary/race 分片结果记录在 current-source 报告。

## S3、Nginx 与真实 DNF

S3 canonical authority：

| arch | cutover commit | event SHA-256 | rollback confirm |
|---|---|---|---|
| aarch64 | `d3b68a543fb394af6d5f65ea927c69948807efc9` | `bb4deadf09238ff80a51b589b5b2bd11d9f07ab2a46a92aec932887e119870bf` | `sha256:6563718f1175882184a20fb0a86a297fb1442210aa960abc93eb2f28db870fe0` |
| x86_64 | `abfa955adb2c95925badb519a726f6aa194294d4` | `2471a24338a738c95dfe7a07866afd6882f22d9c43a59edc2efa625af6594d2d` | `sha256:18f2f7a8ac133213d2ef138ebf4bce69f6d842fb7565bbfd39e552128ec4d267` |

ordinary materialize 创建 compatibility generations：

```text
aarch64=05665800675731103338
x86_64=07752629222972134748
nginx_include_sha256=783babecfd8ca85772ed75c4587c33aa8d35d0e615078408a5a15b81e20c24cb
```

Nginx 只监听 `127.0.0.1:18765`，使用生成的 exact allowlist；容器内静态
loopback proxy 只把同一端口转发到 `host.docker.internal`，从而保持
mirrorlist 返回的 clean URL 与 generation identity 不变。全部外部 repo 被
`--disablerepo='*'` 禁用。

| EL | aarch64 client | x86_64 client | DNF | result |
|---:|---|---|---:|---|
| 8 | AlmaLinux 8.10 | Rocky Linux 8.10 | 4.7.0 | PASS |
| 9 | AlmaLinux 9 | Rocky Linux 9.8 | 4.14.0 | PASS |
| 10 | AlmaLinux 10 | Rocky Linux 10.2 | 4.20.0 | PASS |

六组均执行：

- `repo_gpgcheck=1` 验证 generation 内的 `repomd.xml.asc`；
- `repoquery --list` 与 `repoquery --changelogs` 读取
  primary/filelists/other；
- `gpgcheck=1` 实际安装精确 `pg_exporter-1.3.0-1.<arch>`；
- 从 DNF cache 对下载 RPM 执行 `rpm -K`，结果均为
  `digests signatures OK`；
- package URL 固定在上述 20 位不可变 generation，而不是 raw alias。

## 完整性、重放与回滚证据

当前精确副本最终检查：

```text
fsck canonical_git_roots=9 commits=16 blobs=49 blob_bytes=227164 drift=0
fsck repo=infra-el9 added=0 removed=0 changed=0
fsck repo=infra-legacy-carrier added=0 removed=0 changed=0
fsck yum_compatibility=infra-legacy-aarch64 stage=S3-active clean=true
fsck yum_compatibility=infra-legacy-x86-64 stage=S3-active clean=true
fsck serving_checks=10 drift=0
fsck clean repos=2 targets=0

verify outcome=passed exit=0 info=0 warnings=0 errors=0 critical=0
```

对两个 arch 使用原 cutover token 重放均返回 `changed=false active=true`，
event SHA、serving link 与 rollback token 不变。

另一个较早的完整可写 fixture 已对同一状态机执行 S2→S3、幂等 replay、
rollback、raw EL8 双架构消费、re-cutover、strong EL8 双架构消费和最终
`fsck`。那个 fixture 混合了稍早快照，不作为“当前生产字节”证明；本报告的
精确 fixture 提供当前字节与六组 S3 消费证明，两者合并覆盖当前内容和完整恢复
状态机，未把生产树用于演练。

## 剩余边界

本地 `yum/infra` package blocker 与多架构兼容引擎缺陷已关闭。仍未关闭：

- 专用、registry 审核且明显非生产的 R2/COS/Cloudflare/EdgeOne 真环境；
- 生产 repository key、安全注入与维护窗口；
- 生产 Nginx、28 个 consumer、双云对象/CDN 的切换与回滚；
- 旧 writer、scheduler、bucket IAM/ACL 撤权及切换后 URL/ETag/cache 对比；
- 上线后的事故、延迟、成本和多 PoP 指标。

`pro` bucket 和 `pro.pigsty.io` 属于被禁止的生产资源边界，不是可接受的
测试替代物。Goal 因上述外部验收与生产迁移仍保持 active。
