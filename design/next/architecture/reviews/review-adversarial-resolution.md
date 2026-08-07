# Adversarial interoperability resolution review

> **Historical pre-implementation snapshot.** 本文逐轮保留当时的 PARTIAL/OPEN 结论，不能
> 覆盖后来的 specification closure 或当前实现证据；现状见
> [`../../evidence/2026-08-05-implementation.md`](../../evidence/2026-08-05-implementation.md)。

日期：2026-08-05

范围：逐项复核 [`review-adversarial.md`](review-adversarial.md) 的 15 个 finding，并只以修订后的 `SPEC.md` companions 与 `ARCHITECTURE-SPINE.md` 为权威。`RESOLVED` 表示在规范接受域内已不能再构造两个合法但不互操作的实现；`PARTIAL` 表示核心决定已固定、仍有最小分叉；`OPEN` 表示原问题基本未被约束。

结论：原 15 项为 **8 RESOLVED / 7 PARTIAL / 0 OPEN**。修订显著闭合了 RPM URI、Pool path、Repository UUID、Generation/Changeset、protocol pointer、grace 和 transition/`changes` 语义，但仍不足以让第二个实现无损接管第一个实现的 remote publication、snapshot/retained state、export replacement 或 migration journal。另发现 **1 个新 OPEN**：APT `Filename` 对允许的 URI-reserved Pool bytes 没有与 RPM 等价的唯一编码合同。因此整体结论是 **PARTIAL，尚不能宣称 cross-implementation state/publication interoperability**。

- **F01 — RESOLVED — RPM base URI 目录语义。** [`repository-layout.md:62-79`](../../specs/repository-layout.md) 已要求 retrieval base 是以 `/` 结尾的 directory URI，并让 file/HTTP checker 使用最终实际 URI；无尾斜杠还进入 golden vectors。最小 incompatibility：无。一个实现可以选择拒绝、另一个可以先规范化用户输入，但进入 renderer 的合法 canonical base 已唯一，不会再产生不同 href/request path。

- **F02 — RESOLVED — RPM href byte-to-URI 编码。** [`repository-layout.md:67-84`](../../specs/repository-layout.md) 已固定未转义 ASCII 输入、literal navigation、RFC 3986 unreserved 集、uppercase `%HH`、`% -> %25`、XML escaping 次序和 decode-once round-trip，并给出 `%2F`/`+` golden。最小 incompatibility：无，原先 raw/pre-escaped 双实现不再同时合规。APT 的独立缺口见 N01。

- **F03 — RESOLVED — canonical Pool path function。** [`repository-layout.md:114-129`](../../specs/repository-layout.md) 已版本化为 `sow-managed-pool-v1`，冻结 ASCII grammar、first-or-literal-lowercase-`lib*` shard、大小写保持和 digest/path 双向唯一。最小 incompatibility：无；首字符与 `lib` 四字符两种实现不再都合规。

- **F04 — PARTIAL — Repository/publish-prefix identity。** 持久 UUID、endpoint/prefix canonical form、prefix overlap 与 owner CAS 的语义已由 [`state-publication.md:14-31`](../../specs/state-publication.md) 固定；但 `target identity` 自身包含 prefix，随后“同一 target 上”的 ancestor/descendant 检查没有另行定义排除 prefix 的 storage namespace identity，owner binding 的远端发现 key/record 也明确可后定。最小 incompatibility：实现 A 把 owner binding 写在 `<prefix>/.sow-owner.json` 并按 `(provider,endpoint,bucket)` 检查所有 prefix；实现 B 把 binding 放在本地表并把含 prefix 的完整 tuple 当“target”。二者都遵守字段语义，但 B 无法发现/接管 A，且不能判定 sibling/ancestor prefix 已由谁占用。需要冻结 `target_storage_id`、全 scope overlap 查询规则与 owner record 的 provider-neutral discovery location/schema。

- **F05 — RESOLVED — rename/restore/workspace relocation identity。** [`state-publication.md:16-21`](../../specs/state-publication.md) 明确 UUID 与 name/path/URL 解耦，rename/restore/relocation 保留 ID，fork 生成新 ID，只复制 public tree 不携带 publish authority。最小 incompatibility：无；绝对路径派生 identity 已不合规。

- **F06 — PARTIAL — Generation/snapshot/refset wire。** [`state-publication.md:72-107`](../../specs/state-publication.md) 已固定 physical manifest、digest、exact delta 和按 path 排序的 payload/metadata refset；但没有冻结 snapshot/refset record 的 JSON schema、字段类型、domain string 与单一 refset digest 公式，只要求 snapshot identity 引用“Generation/refset digest”，snapshot naming/state machine仍 deferred。最小 incompatibility：实现 A 让 snapshot 直接引用完整 Generation manifest SHA；实现 B 对 payload refset 与 metadata refset 分别求 digest再封装一个 snapshot digest。二者都引用已验证 digest且不复制 payload，却不能交换 snapshot record或同意 snapshot identity。应冻结 local retained/snapshot record schema及唯一 digest domain。

- **F07 — PARTIAL — retained metadata storage/recovery。** [`publication-retention.md:62-72`](../../specs/publication-retention.md) 与 [`state-publication.md:98-107`](../../specs/state-publication.md) 已要求 `.sow/<repo>/retained/<generation>/...` 保存 exact bytes、path/size/SHA、signer identity，禁止重渲染；这解决了“live `dists` 累积还是以后重建”的语义分叉。剩余最小 incompatibility：实现 A 在 generation 下镜像 public paths并用 TSV 索引，实现 B 在同一根下按 SHA CAS 存 bytes、用 SQLite 索引；两者都满足文字，但第二实现无法从第一实现的 workspace恢复/发布 retained Generation。需要冻结 retained manifest/receipt、byte object layout或一个强制 export/import interchange format。

- **F08 — PARTIAL — external export profile。** [`compatibility.md:35-74`](../../specs/compatibility.md) 已把布局收敛到唯一 `sow-rpm-leaf-v1`、leaf-local `pool/...`、重建 RPM-MD、绑定 Generation closure 和一致 signing policy；原先 `Packages/` 与 `pool/` 两种 profile 分叉已消失。仍可构造的最小 incompatibility：文档称 `manifest.tsv` 是“exact regular-file closure”，但 export root 同时含 `manifest.tsv` 与最后安装且包含 manifest digest 的 `.sow-export.json`。实现 A 只把 `repodata/ + pool/` 视为 closure；实现 B 把 control files也视为 regular-file inventory，会遇到 manifest self-hash/marker cycle并拒绝 A。必须明确 manifest coverage 排除哪些 control files及 verifier 如何处理它们。

- **F09 — PARTIAL — export ownership marker。** marker 路径、JCS、核心字段、last-install 和 replace owner已规定，但 [`compatibility.md:56-73`](../../specs/compatibility.md) 使用“至少包含”，没有完整字段类型、unknown-field/unknown-minor 策略、marker identity、`export target` 字段定义，也没有 versioned replace journal schema。最小 incompatibility：实现 A 增加 `created_at` extension并把 generation 编为 JSON number；实现 B 对 schema v1 拒绝 unknown field或要求 generation string，因而不能验证/replace A 的 completed export；两者都可声称遵守“至少包含”与 exact marker。应冻结完整 schema、extension policy、target binding和 replace recovery record。

- **F10 — RESOLVED — full manifest/incremental Changeset。** [`state-publication.md:72-96`](../../specs/state-publication.md) 已固定 record shape、manifest digest、bytewise path order、exact base/target path delta、phase/path order与 non-terminal fail-closed；Spine 也显式继承 v0.2 wire。最小 incompatibility：无；重复列出所有 live payload 已不再是合法 incremental delta。

- **F11 — RESOLVED — protocol pointer commit order。** [`state-publication.md:109-161`](../../specs/state-publication.md) 已把 view 定为 commit unit，记录 commit intent/expected identity/forward-only replay，并分别冻结 RPM signature-first/`repomd.xml`-last 与 APT by-hash/stable aliases/`Release.gpg`/`Release`/`InRelease` 次序，同时承认严格客户端的短暂失败窗口。最小 incompatibility：无；不同 publisher不能再自由选择相反顺序并同时合规。

- **F12 — RESOLVED — grace clock/evidence。** [`state-publication.md:163-176`](../../specs/state-publication.md) 已固定 per-target checkpoint、公开 endpoint验证后的起点、不可缩短 `not_before`、30 天与 TTL+24h 下限、clock/TTL unknown fail-closed及 conditional deletion witness。最小 incompatibility：无；从 local build 开始计时的实现已明确不合规。

- **F13 — PARTIAL — remote inventory/checkpoint interchange。** [`state-publication.md:33-70`](../../specs/state-publication.md) 已正确拆分 target-neutral Generation 与 target-scoped Attempt/Checkpoint/Grace，并要求 RFC 8785 canonical JSON、CAS和字段无损交换；但列出的 records仍是伪 schema：没有实际 `schema` 字段/major规则、字段类型、domain-string常量、`views` 的规范排序键，且 owner record、Inventory、Publication Plan、DeletionReceipt 根本没有 canonical record。物理 discovery location也仍 deferred。最小 incompatibility：实现 A 令 `inventory_identity` 为排序 TSV 的 SHA，`plan_sha256` 绑定逐 key JSON plan；实现 B 令 inventory identity 为 provider inventory version并把 plan存在不同 control key。二者都能填现有 checkpoint字段，却无法验证或恢复对方的 in-flight Attempt。需要 provider-neutral JSON Schemas、domain constants、inventory/plan/owner/delete-receipt wire与可发现位置；SDK调用才可以继续 deferred。

- **F14 — RESOLVED — migration grace 中的 `changes --base 0` 矛盾。** [`migration.md:38-75`](../../specs/migration.md)、[`state-publication.md:93-102`](../../specs/state-publication.md) 与 AD-27 现在一致规定 transitional inventory独立、普通 changes/publish/GC fail closed、alias receipt删除后才原子提交 terminal next Generation。最小 incompatibility：无；扫描真实 aliases与排除 aliases不再是两个合法 `changes` 实现。

- **F15 — PARTIAL — transition journal/recovery。** 固定 path、JCS、layout versions、phase、legacy inventory、per-view old/new identity、commit-intent后 forward-only和 final atomic commit 已显著收敛 [`migration.md:38-80`](../../specs/migration.md)。但完整 JSON schema、字段类型、array/order、per-view substate、alias deletion receipt identity和 journal digest仍未冻结；更重要的是 `commit_intent` 后“自动恢复只能 roll forward”（line 50）与“aliases删除前可恢复旧 pointer”（line 84）没有区分 manual rollback是否允许、由哪个新 journal/authority执行。最小 incompatibility：实现 A 在 commit_intent后拒绝任何 old-pointer恢复；实现 B 接受 operator rollback并恢复 v0.2 pointers，只要 aliases尚在。二者都可引用现有文字，随后不能接管彼此的 transition state。应删除回退许可或定义显式、CAS-bound rollback transition及完整 journal/receipt schema。

- **N01 — OPEN — APT `Filename` 缺少 canonical path-to-URI encoding。** AD-26 名义上绑定 APT，但 [`repository-layout.md:36-49`](../../specs/repository-layout.md) 只规定 `Filename: pool/...`，而同文件的 `sow-managed-pool-v1` 允许 `%`、`+`、`:`, `^` 等 data bytes；精确 `%HH`/decode-once规则只写在 RPM href section。最小 incompatibility：对 canonical DEB path中的字面 `%2F`，实现 A 在 `Packages` 写 raw `%2F`，实现 B 写 `%252F`；两者都能声称字段是 archive-root-relative `pool/...`，但 APT/HTTP层会形成不同请求 path/object key。需要给 APT `Filename` 冻结 typed input、输出 spelling、percent处理与 file/HTTP golden vectors，或把 DEB Pool component grammar收窄到无需转义的字符集。

## Release implication

当前修订可作为单实现的实现规格继续推进，但在以下四项补齐前，不能把第二实现接管或跨版本恢复作为验收能力：provider-neutral publication records与发现位置、snapshot/retained interchange、完整 export marker/manifest closure、完整 transition journal/rollback authority。N01 还必须在 APT renderer落地前关闭，否则“一个 canonical Pool path”仍不能推出“一个 canonical request URL”。
