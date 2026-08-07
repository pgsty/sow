# Acceptance matrix

任何“实现 next design”的声明都必须绑定当前 checkout、binary、命令、exit code、
日志 hash 与 retained lab。历史 v0.2 C2 PASS 只能作迁移基线。

## Current implementation evidence

当前源码实现与本地 unit/fault/mock 结果记录在
[`../evidence/2026-08-05-implementation.md`](../evidence/2026-08-05-implementation.md)。
它支持“implemented / locally verified”声明，不满足下述 immutable fixture lock 与 live
client/target 条件，因此不能把真实 APT/DNF HTTP、export reposync、proxy 或 R2 单元格升为
PASS。默认 EL reposync 对 canonical Repository 是 `UNSUPPORTED`；R2 physical delete 是
`DISABLED/REPORT-ONLY`，两者都不是通过生成 payload alias 来补绿的待办。

每次 release candidate 必须先提交不可变 `design/next/evidence/fixture-lock.json`：记录每个
client/origin container 的完整 OCI digest、OS release、APT/DNF/plugin 精确版本、架构，
以及 HTTP origin 的镜像 digest、启动参数、无 rewrite 配置与 raw/decoded request-log
格式；真实 target 记录 provider、region、bucket、non-root prefix 与 capability probe digest，
不记录 secret。没有这份 lock 的执行不能产生 PASS。历史 DNF4 baseline 固定为
`almalinux:9@sha256:d2515c769e7b73f95c4fde38c0a505336ff38f14990c0b7253b77060a049a743`
（AlmaLinux 9.8 / DNF 4.14.0）；Fedora 42、Ubuntu 22.04、Debian 12 与 origin 的实际 digest
在首个 next evidence commit 中冻结，在此之前仍是 named required cells，而非已验证输入。

| Gate | Required proof |
| --- | --- |
| Canonical tree | `pool/ + dists/` 精确扫描；`dists/` 下零 `.rpm/.deb` payload、零 per-view `pool/`；每个 Package Object 只有一个 canonical Pool path |
| Href algorithm | 多层 Dist/view、non-root prefix、required trailing slash；typed unescaped path → uppercase `%HH` → XML escape；`%`/`+`/`:`/`^`、absolute/root-relative/backslash/encoded traversal golden 全覆盖；renderer/checker 共用计算并用最终 file/HTTP URI round-trip |
| Leading-slash negative | pinned EL9 DNF ordinary file/HTTP 与 default reposync；分别记录 generic URI、DNF `lstrip` 与 reposync local-target 行为，不把 `/pool/...` 误报为可移植 Repository-root URL |
| APT | Ubuntu 22.04 APT 2.4 + Debian 12 APT 2.6 起步，amd64/arm64/all × file/HTTP；`Filename` raw path 与 `%3a`/`%3A`/`+`/`:` golden、URI `%25` encode-once 和服务端 decoded key；`Acquire-By-Hash: yes`、stale Release 并发 fetch、refresh/query/download/checksum/install；多 Dist 引用不增加 Pool payload |
| DNF ordinary | AlmaLinux 9 DNF4 + Fedora 42 DNF5 起步，arch/noarch × file/HTTP makecache、repoquery/location、download、checksum、install；服务端日志只见规范化 canonical Pool path |
| Default EL reposync | pinned EL9 记录 expected rejection 与准确诊断；其他 EL/DNF 逐项 pass/fail/unverified；不得通过生成 alias 让 gate 变绿 |
| Safe-write best effort | 支持该选项的社区 DNF4/DNF5 可选验证 multi-view 输出、碰撞与 metadata closure；结果单列，不升级为 EL 合同或 fallback |
| Whole-root relocation | 绑定 settled Generation 的 locked handoff；完整 Repository 搬到不同绝对目录、HTTP prefix 后复验 manifest 并通过普通客户端 |
| Leaf negative | 只复制 architecture view 必须得到可解释失败；文档和 CLI 不宣称 leaf standalone |
| Static object storage | 首发必须在真实 nonproduction Cloudflare R2 target 使用 non-root prefix 上传 `pool/ + dists/`；payload key 数等于 canonical live Package Object/path 数；GET/HEAD/Range/ETag/cache/auth、dot-segment normalization 与 ACL 通过；验证 conditional delete 不可用时 remote delete fail closed、只报告 retained candidates；S3/COS 仍分别验收 |
| Target state | 一个 Repository 同时让 target A/B 停在不同 Generation；Publication Attempt、local owner binding、per-view roll-forward、unexpected ETag、crash replay、Applied Checkpoint 与 local/remote roots 均不串 target；同 repository ID 的 exact/ancestor/descendant/empty-prefix overlap 全拒绝，non-overlapping siblings 正例通过；filesystem 另覆盖不同 endpoint spelling 展开到同一/祖先/后代 effective path 的拒绝；single-writer 与 exclusive storage write-authority 边界写入 evidence，provider 不能 prefix-scope 时证明专用 bucket/单 Workspace registry，不宣称跨 workspace 原子仲裁 |
| Protocol pointers | 多 RPM/APT view fault matrix；commit intent 必须早于任何 mutable APT stable alias/pointer，signature-first/commit-pointer 顺序、bounded mixed generation、strict-client transient failure、APT by-hash 与最终 all-view verification符合 `state-publication.md`；pre-commit fault 可 `publish --abort`，只登记 exact add-only orphan evidence且不远端 copy/delete，post-intent abort 拒绝并前向恢复；configured applied target 下 Dist/arch/signing pointer withdrawal 在本地 mutation 前拒绝 |
| State wire | `GenerationID` 的 20-digit JSON-string 边界（0、1、2^53-1、2^53、MaxUint64）、manifest/Changeset ASCII size（0、1、2^53、MaxInt64、MaxInt64+1 拒绝）、retained/export RFC 8785 bytes、migration alias-size/receipt golden 全跨实现一致；JSON number、短 generation、前导零 size、duplicate key 与 top-level/nested unknown v1 field 均拒绝 |
| Changes | terminal `changes --base 0` path/size/SHA 与真实树完全一致；payload 每 path 一条；non-terminal build/migration 必须 fail closed；canonical delta 可 round-trip，独立 target plan 按 protocol pointer order fault-replay，两种序列各自保留 golden |
| Generation/snapshot | 多 Dist、多架构、多 retained generation/snapshot-like ref 后 payload key 数不增加；只增加 metadata/refset；零文件 Generation 的 retained `manifest.tsv` 可为零字节并能 ls/rm/GC |
| GC | local 与 per-target remote closure 分开；checkpoint/inventory/object identity/not-before/cache absence 全绑定；未知或漂移证据 fail closed；无 link-count 依赖；最后引用前绝不删 Pool；R2 的 required PASS 是 remote-delete disabled，physical remote delete 仅在另行验证 atomic conditional delete 的 target 上升级为 PASS |
| Export copy | 新的 absent/empty root且与 Repository、`.sow`、所有 configured filesystem target effective root 双向不重叠；`sow-rpm-leaf-v1` exact marker schema，manifest 只覆盖 `repodata/ + pool/` 并排除 control files；`:`/`%` managed RPM basename encode-once；`signed`/`.asc` 四种组合（两正两负）、wrong bound signer identity、GenerationID boundaries、unknown field、非法 Dist/arch、marker-last crash 与 size vectors 全覆盖；普通 static server、default EL reposync 与目标旧工具消费；不提供 in-place replace，修改/删除 export 不影响 canonical Repository |
| Export hardlink | 仅显式同设备可信只读目标允许；跨设备拒绝，hostile writer/独立完整性保证明确退出；共享 inode 风险可见；不得进入 publish/changes/GC |
| Migration | frozen `sow/v2`/schema-v6 可只读检查，普通 writer 不隐式迁移，只有 explicit migration opener 写 schema；versioned transition journal；pre-commit `repo migrate --abort` 正例、post-intent 拒绝；commit-intent 后只 roll forward，grace 期 `changes` 拒绝，alias receipt 后提交 terminal Generation；每个 crash point收敛；支持 conditional delete 的 target 可原地迁移，R2 必须用新空 prefix 切换且 next prefix 从未出现 view-local payload key |
| Third-party tools | Pulp/Nexus/Artifactory/Foreman 等逐项标 `pass/fail/unverified`；未验证不得写“兼容”，失败以 whole-root controlled handoff/export 绕开 |

最低发布判定：canonical tree、href/leading-slash、初始 APT/DNF、whole-root handoff、
target state/pointers、Changes、migration、GC、copy export 与至少一个真实对象存储 target
必须通过；其余平台只能明确列为未验证，不能由 EL9/file PoC 或 mock target 外推。
当前具备 source/local/mock evidence；release-candidate fixture lock、live client 与真实
nonproduction R2 evidence 尚未完成。
