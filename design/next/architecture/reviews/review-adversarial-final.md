# Final adversarial interoperability and ambiguity review

> **Historical pre-implementation snapshot.** 本文保留基线 `6c84f9e` 上的原始评审、
> 中间 verdict 与 closure 轨迹；其中“当前源码/状态”不描述现在的 0.3 工作树。当前事实以
> [`../../evidence/2026-08-05-implementation.md`](../../evidence/2026-08-05-implementation.md)
> 为准，未完成的 live gates 仍以 acceptance matrix 为准。

日期：2026-08-05

范围：当前工作树中的 `design/next` 前向合同，重点复核 N01、F04、F06/F07、
F08/F09、F13 与 F15，并尝试构造两个独立实现都能声称合规、却不能交换产物或在同一
crash point 收敛的最小反例。

## Verdict

- **核心设计：READY。** Repository-scoped single-payload、APT raw `Filename`、RPM
  parent-relative href、private retained wire、external export、single-writer authority、
  target-scoped publication 与 forward-only C2 migration 已形成一致的架构。原复核项的
  语义分叉均已关闭；F04 与 F13 是通过明确缩小支持域关闭，而不是补建远端全局控制面。
- **精确 wire gate：CONDITIONAL READY。** 新发现 N02 与 N03：RFC 8785 JSON 中的
  `uint64` 数值域、以及 migration delete receipt 的 `size` byte encoding 尚未唯一化。
  两项都不要求重开物理布局或状态所有权决策，但必须在独立实现互操作声明前冻结。
- **对外声明：受限。** 本设计不承诺跨独立 workspace 的 prefix 仲裁、丢失 private state
  后的 live publisher 接管、Repository-wide instantaneous flip、默认 EL reposync、leaf-only
  mirror、任意 proxy/repository manager，或 R2 physical remote GC。
- **实现与 evidence：未完成。** 当前状态仍是 `approved-unimplemented`；next APT/HTTP、
  DNF5、R2 publication、export、target recovery、GC 与 migration 的 required cells 还没有
  retained PASS evidence。

因此可以把架构交给实现，但不能把“设计已闭合”改写成“能力已实现/已验证”，也不能在
N02/N03 未冻结前宣称所有 v1 private/interchange records 都能跨语言 byte-identical 互认。

## Focused resolution recheck

- **N01 — RESOLVED — APT `Filename`。** [`repository-layout.md:51-73`](../../specs/repository-layout.md)
  已区分 canonical path/key、raw `Packages` field 与 retrieval URI：renderer 逐 byte 写
  `PoolPath`，只允许普通安全 basename bytes 加字面 `%3a`/`%3A`，拒绝其他 `%HH`、孤立
  `%` 与 encoded separator；URI 层才把 `%` 编成 `%25`，decode 恰好一次回到同一 key。
  `%3a`/`%3A` spelling、`+` 与 `:` 也进入 file/HTTP gate
  ([`acceptance-matrix.md:20`](../../specs/acceptance-matrix.md))。raw `%3a` 与预先写成
  `%253a` 的两个 Packages renderer 不再都合规。

- **F04 — RESOLVED BY SCOPE — authority 与 prefix overlap。** `target_storage_id` 明确
  排除 prefix，`target_identity` 再加入 canonical prefix；一个 Workspace registry 检查
  same/ancestor/descendant overlap
  ([`state-publication.md:23-33`](../../specs/state-publication.md))。公开 prefix 明确不放 owner
  marker 或 target-global trie；支持域改为 authoritative workspace、single writer 与包含
  namespace 的独占写 authority，无法 prefix-scope 时使用专用 bucket 或同一 Workspace
  registry ([`state-publication.md:34-45`](../../specs/state-publication.md))。因此它没有解决
  distributed arbitration，而是准确地不再声称具备该能力；在这个收窄后的支持域内，原
  A/B owner-record discovery 反例不成立。

- **F06 — RESOLVED — Generation/snapshot/refset identity。** terminal Generation manifest
  的 line format、排序、digest 与 exact delta 已固定
  ([`state-publication.md:93-117`](../../specs/state-publication.md))；retained state 又固定
  payload/metadata refset 的 domain、NUL、原始 manifest lines、record schema 与 record
  identity ([`publication-retention.md:81-97`](../../specs/publication-retention.md))。
  snapshot/freeze/channel 可以延后命名与 CLI，但只能引用该 retained-record identity，不能
  自创另一套 refset digest。

- **F07 — RESOLVED — retained bytes 的位置与恢复。** 首版 layout 已唯一固定为
  `.sow/<repo>/retained/<generation-20d>/{record.json,manifest.tsv,metadata/...}`；`metadata/`
  镜像 exact Repository-relative non-payload paths，并保存 checksum metadata、stable alias、
  pointer 与 signature companion 的原始 bytes
  ([`publication-retention.md:70-95`](../../specs/publication-retention.md))。恢复不再允许选择
  “重渲染旧签名”或“继续把旧 metadata 堆在 live dists”这两个不互操作方案。

- **F08 — RESOLVED — export closure。** `sow-rpm-leaf-v1` 只有一个 leaf-local `pool/...`
  profile，RPM-MD 必须重建，签名 policy 继承绑定 Generation；`manifest.tsv` 只覆盖
  `repodata/ + pool/` regular files，并明确排除自身与 marker，verifier 分两步验证 data
  closure 和 manifest digest
  ([`compatibility.md:35-65`](../../specs/compatibility.md))。self-hash/marker cycle 已消失。

- **F09 — RESOLVED — export marker/replace。** `.sow-export.json` 已冻结为 RFC 8785 JSON，
  v1 恰好七个字段、逐字段类型/enum、拒绝 unknown field，并在 data 与 manifest fsync/复验
  后最后安装。v1 删除了 in-place replace；重新导出必须使用新的 root
  ([`compatibility.md:60-74`](../../specs/compatibility.md))。因此不再需要未定义的 replace
  journal，也不存在两个 exporter 各自扩展 v1 marker 后仍自称兼容的空间。N02 是跨多个
  JCS record 的新数值域问题，不是原 marker closure/extension 分叉复发。

- **F13 — RESOLVED BY SCOPE — remote state。** PublicationAttempt、AppliedCheckpoint 与
  GraceRecord 的 required semantic fields、owner、排序与 CAS preservation 已固定，但文档
  明确说它们不是 interchange wire，SQLite/JSON serialization、digest 与 discovery location
  属于一个实现的 private state
  ([`state-publication.md:47-91`](../../specs/state-publication.md))。跨 binary family/workspace
  takeover、lost-state adoption 被明确列为未来单独批准的能力
  ([`SPEC.md:90-96`](../../specs/SPEC.md))。因此 prior A/B inventory/plan encoding 反例仍说明
  “不能跨实现接管”，但这已经是声明过的 non-goal，不能再作为当前支持域内矛盾。

- **F15 — RECOVERY RESOLVED；WIRE 仍受 N03 约束。** journal path、top-level fields、layout
  versions、phase、commit-intent predicate、pointer/alias array ordering、path containment、
  receipt field、journal identity 与 terminal receipt 已固定
  ([`migration.md:38-91`](../../specs/migration.md))。rollback 也已唯一化：commit-intent 前可
  放弃 private stage；之后自动与人工操作都只能按原 journal/CAS roll forward，任何 C2
  artifact 都只能生成在 canonical Repository/prefix 之外
  ([`migration.md:123-136`](../../specs/migration.md))。旧的“同一 crash point 可 forward 或
  rollback”分叉已关闭；剩余问题只是 N03 所述 receipt input bytes 未完全写明。

## New adversarial findings and tightening points

- **N02 — RFC 8785 与 `JSON uint64` 的接受域不一致。** retained record、export marker 与
  migration journal 分别把 generation 写成 RFC 8785 canonical JSON 的 `JSON uint64`
  ([`publication-retention.md:90-95`](../../specs/publication-retention.md)、
  [`compatibility.md:60-65`](../../specs/compatibility.md)、
  [`migration.md:66-81`](../../specs/migration.md))。JCS 要求 number 可表示为 IEEE-754
  double，并建议更长整数用 JSON string；大于 `2^53-1` 的 uint64 不能保持整数精度
  ([RFC 8785 section 3.1](https://www.rfc-editor.org/rfc/rfc8785.html#section-3.1))。实现 A 可按
  Go `uint64` 保留 `9007199254740993`，实现 B 的 JCS/JavaScript parser 会把它舍入；二者会
  得到不同 canonical bytes/record identity。v1 必须二选一：把接受域限制为 I-JSON safe
  integer 并对越界 hard-fail，或把 generation 改成规范十进制 string。三处 wire 必须同选。

- **N03 — alias deletion receipt 没有冻结 `size` 的 byte encoding。** migration 将 receipt
  定义为 `SHA256(domain NUL path NUL size NUL sha256)`，但没有说明 `size` 是无前导零 ASCII
  decimal、JCS number token，还是 fixed-width unsigned bytes
  ([`migration.md:83-91`](../../specs/migration.md))。实现 A 对 ASCII `123` 求 hash，实现 B
  对 big-endian uint64 求 hash，二者的 journal 都能满足当前字段 schema，却不能验证对方的
  deletion receipt。应明确每个 component 的 bytes、整数范围与是否存在 terminal NUL，并
  为 size `0`、`1`、`2^53` boundary 建 golden vectors。

- **GenerationFile 与 FileChange 共用的 `phase` 伪语法仍容易误读。** 文档把
  `phase = payload|metadata|pointer|delete` 写在两个 record 后面，但 terminal manifest 又必须
  精确等于现存 regular-file inventory，且 delete change 没有 size/SHA
  ([`state-publication.md:93-117`](../../specs/state-publication.md))。唯一自洽解释是
  `GenerationFile.phase` 只能是前三者，`delete` 只属于 `FileChange{op=delete}`。这不是新的
  合法实现分叉，因为 exact-tree invariant 排除了 manifest tombstone；实现规格仍应把两个 enum
  分开写，避免生成一个语法上看似允许、语义上必然失败的 manifest。

- **Changeset canonical order 不是 protocol mutation order，必须在实现接口上继续分离。**
  Changeset 要求 pointer phase 内按 path 排序
  ([`state-publication.md:104-107`](../../specs/state-publication.md))，但 RPM 必须先写
  `repomd.xml.asc` 再 CAS `repomd.xml`，APT 必须按 `Release.gpg -> Release -> InRelease`
  推进 ([`state-publication.md:164-183`](../../specs/state-publication.md))；纯 path order 对两者都
  不是安全 apply order。后者是更具体的强规则，所以当前合同可满足，但实现若把 Changeset
  当作可直接串流的执行计划就会违规。Publication planner 与 Changeset serializer 应有独立
  golden/fault tests。

- **prefix overlap 的正文措辞应与 Spine 的“所有 binding”保持一致。** Spine 要求一个
  Workspace registry 拒绝 same/ancestor/descendant prefixes
  ([`ARCHITECTURE-SPINE.md:103-107`](../ARCHITECTURE-SPINE.md))；state companion 写成拒绝
  “两个 Repository owner”使用重叠 prefix
  ([`state-publication.md:31-33`](../../specs/state-publication.md))。若同一 `repository_id` 被错误地
  配置为同一 storage 上两个相同/嵌套 target bindings，后一句可能被实现为允许。single-writer
  前提使这不是 distributed-arbitration blocker，但 registry preflight 应按 binding 而不是只按
  owner-ID difference 断言。

- **`<generation-20d>` 是 layout token，但 zero-padding 仍只存在于占位符名字。** retained
  layout 声称首版固定，却没有用一句规范文字说明它是恰好 20 位、ASCII decimal、左侧补零、
  范围与 record generation 必须相等
  ([`publication-retention.md:70-79`](../../specs/publication-retention.md))。目录枚举型 importer
  可能分别接受 `42`、`00000000000000000042` 或两者。应把这一点作为 retained-wire parser
  assertion；它不改变 refset/metadata ownership。

- **export 的 signing-policy 一致性不是 self-describing。** exporter 必须继承绑定 Generation
  的 metadata signing policy，但 exact marker 没有 signer/policy identity
  ([`compatibility.md:50-65`](../../specs/compatibility.md))。拥有 source Repository state 的
  verifier 可以比较；只拿到 standalone export 的通用 verifier只能验证“存在的签名是否有效”，
  不能证明“缺失签名是否符合 source policy”。因此当前 profile 可作为可消费 leaf，却不能单靠
  export bytes 证明 policy inheritance；要么把该证明明确列为 source-bound verification，要么
  在下一 marker major version加入 policy identity，不能向 v1 偷加 unknown field。

- **marker 中 `dist`/`arch` 的“canonical string”对独立 consumer 仍是 opaque token。** exact
  schema 只要求 canonical non-empty string，未在 next contract 给出 grammar/case mapping
  ([`compatibility.md:60-65`](../../specs/compatibility.md))。这不影响 manifest closure 或 reposync
  consumption，但 importer 不得据此声称能把 export 无歧义重新挂回任意 Repository 的逻辑
  Dist/View；若未来需要 round-trip import，应新开 profile/schema，而不是从字符串猜 identity。

- **APT encode-once 目前是规范，不是实际客户端事实。** N01 的 wire 已唯一，但 APT 2.4/2.6
  对 `%3a`/`%3A`、`+`、`:` 的 file/HTTP request 与 server-decoded key 仍是 required evidence，
  尚未 PASS ([`acceptance-matrix.md:20`](../../specs/acceptance-matrix.md))。在 retained fixture
  出现前，只能说 renderer contract 没有歧义，不能说目标 APT 组合已经接受该 contract。

- **R2 completion 只证明 publish 与 delete-disabled，不证明 physical remote GC。** 所有前向
  文档现已一致要求 R2 保留并报告 unreachable candidates
  ([`state-publication.md:189-216`](../../specs/state-publication.md)、
  [`acceptance-matrix.md:26-31`](../../specs/acceptance-matrix.md))；C2 migration 也必须使用新空
  prefix，并在旧 prefix 未退役前禁止宣称整个 target storage 已去重
  ([`migration.md:110-121`](../../specs/migration.md))。这是正确的受限声明，不是 remote GC
  implementation 的替代品。

- **当前 binary 与 evidence 仍停留在 C2 truth boundary。** README 与 SPEC 明确写成
  approved/unimplemented ([`README.md:41-51`](../../README.md)、
  [`SPEC.md:18-21`](../../specs/SPEC.md))，acceptance matrix 也只有 required proof，没有 next
  PASS ([`acceptance-matrix.md:37-40`](../../specs/acceptance-matrix.md))。因此本 review 的
  `RESOLVED` 只表示规范分叉关闭；不能用于宣称 renderer、publisher、exporter、GC 或 migrator
  已经存在，更不能覆盖历史 v0.2 C2 证据。

## Claim envelope after this review

- 可以声明：在一个 Repository、一个 publish prefix、一个 authoritative workspace/single
  writer 与独占写 authority 的边界内，canonical public tree 只存一份 package payload；APT
  raw path 与 RPM href 的规范表达唯一；retained/export/migration 的主要 ownership 与 recovery
  方向已经固定。
- 必须附带：default EL reposync unsupported；leaf-only copy unsupported；independent workspace
  arbitration、lost-state live adoption 与 cross-implementation remote takeover 不在 v1；R2
  remote delete disabled；direct-static 只有 per-view commit，允许 bounded mixed generation。
- 在 N02/N03 修订且 acceptance evidence 到位前，不得声明：所有 v1 JCS/receipt bytes 可跨语言
  互认、next 客户端/target 已兼容、R2 已完成物理 GC、或当前 binary 已实现 single-payload
  projection。

## Post-review closure

增量复核日期：2026-08-05。以下结论基于本 review 之后的最新 `design/next/specs`；关于
N02/N03 仍为 open、export marker 缺少 signing 字段，以及 `<generation-20d>`/phase/plan/
same-owner overlap 尚未冻结的旧文字，均由本节取代。

- **N02 — CLOSED。** [`state-publication.md:98-111`](../../specs/state-publication.md) 现在把
  Generation identity 固定成恰好 20 个 ASCII decimal digits、左侧补零、范围
  `0..18446744073709551615`；所有 RFC 8785 或跨文件 identity 都必须使用 JSON string，禁止
  JSON number。它完整保留 uint64，又不经过 IEEE-754 number serialization，原先
  `9007199254740993` 在 Go/JavaScript 间舍入的反例不再成立。

- **N02 的三个 public/interchange consumer 已一致改为同一 token。** retained record 使用
  20-digit `GenerationID` string，并要求目录 token/record/manifest 指向同一 Generation
  ([`publication-retention.md:90-101`](../../specs/publication-retention.md))；export marker 同样
  使用该 string ([`compatibility.md:61-70`](../../specs/compatibility.md))；migration
  `base_generation` 也使用该 string
  ([`migration.md:66-80`](../../specs/migration.md))。没有残留的 core `JSON uint64` 字段。

- **N02 的零值边界自洽。** [`state-publication.md:108-110`](../../specs/state-publication.md)
  明确 retained/export generation 必须大于零，只有 base sentinel 可以是全零；retained
  directory 又拒绝短写、符号、空格和超 uint64 输入。20-digit lexical order 因而与
  Generation numeric order 一致。实现验收仍应加入 `0`、`1`、`2^53-1`、`2^53` 与 uint64 max
  的跨语言 JCS vectors；这是 evidence 补强，不再是规范 blocker。

- **N03 — CLOSED。** [`migration.md:83-96`](../../specs/migration.md) 现在把 alias `size`
  固定为 JSON string 中的无前导零 ASCII decimal，范围 `0..9223372036854775807`；receipt
  输入固定为 domain、canonical repository UUID、path、同一 ASCII size 与 lowercase SHA，
  component 间恰好一个 NUL，末尾没有 terminal NUL。ASCII 与 fixed-width/big-endian 两种
  实现不能再同时声称合规。

- **N03 的关键极值已经进入 normative vectors。** size `0`、`1`、`9007199254740992` 与
  `9223372036854775807` 被 [`migration.md:94-96`](../../specs/migration.md) 强制进入 golden
  vectors；加入 `repository_id` 还避免了两个 Repository 对相同 legacy path/bytes 产生可互换
  receipt。acceptance 的 migration crash matrix 必须实际保留这些 vector outputs，才能把
  CLOSED design 升格为 PASS evidence。

- **phase 收紧自洽。** [`state-publication.md:98-106`](../../specs/state-publication.md) 已把
  `GenerationFile.phase` 收窄为 `payload|metadata|pointer`，并让 `delete` 只在
  `FileChange{op=delete}` 中合法。这与 terminal manifest 必须精确等于现存 regular-file
  inventory 的规则一致；manifest tombstone 不再有语法入口。

- **Changeset 与 publication plan 已明确分层。** [`state-publication.md:113-119`](../../specs/state-publication.md)
  规定 Changeset 只是 declarative/canonical delta，publisher 必须生成独立 target plan，并以
  RPM/APT protocol pointer 顺序覆盖 pointer phase 的 lexical path order。该规则与 RPM
  signature-first、APT `Release.gpg -> Release -> InRelease`
  ([`state-publication.md:176-195`](../../specs/state-publication.md)) 同时可满足，原先把
  Changeset 直接串流而暴露错误 pointer 的反例已关闭。

- **Changes acceptance 的一句话仍落后于 plan 分层，但不构成规范分叉。** 当前
  [`acceptance-matrix.md:29`](../../specs/acceptance-matrix.md) 仍写“增量按 canonical
  phase/path 可重放”，容易被读成按该顺序执行 remote mutation；同表 protocol-pointer gate
  与 state companion 的更具体规则会使这种实现验收失败。最小修复是改成“canonical delta
  可 round-trip；独立 target plan 按 protocol pointer order fault-replay”，并保留两个序列的
  独立 golden tests。

- **same-owner overlap 已关闭。** [`state-publication.md:23-34`](../../specs/state-publication.md)
  明确 registry 按 `target_storage_id` 拒绝任意两个 target bindings 的 same/ancestor/descendant
  prefixes，即使 `repository_id` 相同；empty prefix 继续与全部 prefix 冲突。这与 Spine 的
  local-overlap rule 和 single-writer/exclusive-authority 支持域一致，不再允许用“同一个 owner”
  绕过 preflight。

- **overlap evidence 还应覆盖刚冻结的反例。** [`acceptance-matrix.md:27`](../../specs/acceptance-matrix.md)
  只泛称 prefix-overlap preflight。最小补强是保留 same repository ID 的 exact duplicate、
  ancestor、descendant、empty-prefix 四组拒绝 fixtures，以及两个 non-overlapping sibling
  bindings 的正例。这是 acceptance coverage 缺口，不是 authority design blocker。

- **export marker 的 presence/absence 与 view identity 已明显收紧。** marker 现在固定
  GenerationID string、Dist grammar、`x86_64|aarch64` view enum、`signed` boolean 与
  `signer_identity`；`signed=true` 要求 manifest 覆盖并验证 `repodata/repomd.xml.asc`，false
  则要求该文件不存在
  ([`compatibility.md:61-70`](../../specs/compatibility.md))。这关闭了 unsigned export 与
  “漏签但仍完整”无法区分，以及旧 review 所述 `dist`/`arch` opaque-token 分叉。

- **export `signer_identity` 仍不是 byte-exact function，阻塞 deterministic marker
  interoperability。** [`compatibility.md:66-67`](../../specs/compatibility.md) 说它是
  “normalized signing policy + public-key identity”的 SHA-256，但没有冻结 policy serialization、
  public-key identity bytes、domain separator、component delimiter 或 concatenation order。
  实现 A 可 hash canonical policy JSON + OpenPGP fingerprint，实现 B 可 hash effective config
  digest + canonical public certificate；二者都能输出合法 lowercase 64-hex，却会为同一 bound
  Generation 生成不同 marker。最小修复是让该字段**逐 byte 等于 bound Generation 已持久化的
  `signer_identity`**，并规定 source-bound verifier 必须比较相等；若要求 standalone recompute，
  则必须另行冻结类似
  `SHA256("sow/export-signer/v1" NUL policy_sha256 NUL public_key_sha256)` 的完整输入 wire，且
  明确验证 `.asc` 所用公钥必须产生同一 identity。二者选一，不能保留自然语言拼接。

- **export acceptance 尚未证明新增 marker 状态机。** [`acceptance-matrix.md:32`](../../specs/acceptance-matrix.md)
  仍只泛称 exact marker/schema/signature。最小补强是 signed/unsigned 正例、`signed` 与 `.asc`
  四种错配负例、wrong signer identity、GenerationID boundary、unknown field、非法 Dist/arch
  与 marker-last crash fixtures。在上述 `signer_identity` function 冻结前，F09 的 schema
  parse/closure 可以视为 CLOSED，但“相同输入产生唯一 marker identity”仍是 PARTIAL。

- **manifest/export size 的 lexical spelling 已唯一，但接受范围仍未前向重述。**
  [`state-publication.md:111-116`](../../specs/state-publication.md) 与
  [`compatibility.md:56-60`](../../specs/compatibility.md) 都固定无前导零 ASCII decimal，却没有像
  migration alias size 一样写出 upper bound。当前继承的 v0.2 `GenerationFile.Size` 是 signed
  64-bit，实际首发 target 也远小于该上限，所以这不阻塞当前架构；为避免未来 importer 一个用
  int64、另一个用 arbitrary precision，最小修复是两处统一声明
  `0..9223372036854775807` 并加入 max+1 拒绝 vector。

- **migration nested-object 的 strictness 应由 tests 明示。** [`migration.md:66-91`](../../specs/migration.md)
  已写“v1 journal 恰好包含并拒绝其他字段”，并列出 pointer/alias object shapes；最安全的实现
  解释是 unknown-field rejection 递归适用于 nested objects。acceptance 应加入 nested unknown
  field 与 duplicate-key 负例，避免一个 parser 只严格检查 top level。该文字已有唯一合理解释，
  因此不是新的 recovery blocker。

- **最终增量门禁：架构 READY；exact export marker 仍有一个局部 blocker；实现/evidence
  仍未完成。** N02、N03、phase、Changeset-plan 与 overlap 可以从 open/conditional 状态移为
  CLOSED。唯一需要在 cross-implementation `sow-rpm-leaf-v1` deterministic-marker 声明前修复的
  wire 是 `compatibility.md:66-67` 的 signer identity derivation；acceptance wording/vectors 与
  manifest size bound 是最小跟进项。所有这些仍是 approved requirements，不能据此把当前 C2
  binary 或尚未运行的 next matrix 写成 PASS。

### Final closure after bound signer inheritance

本小节复核上述局部 blocker 的后续修订，并取代本节此前“exact export marker 仍为
PARTIAL”的判断。

- **Deterministic export `signer_identity` blocker — CLOSED。**
  [`state-publication.md:144-149`](../../specs/state-publication.md) 现在要求每个 Built Generation
  的 RPM view 持久化 immutable signing record：unsigned 为 `none`，signed 为 lowercase
  64-hex identity，并绑定验证该 view metadata signature 的 trusted public key。该 per-view
  record 是衍生格式唯一的 byte source，不允许 export 从 policy 文本、OpenPGP packets 或当前
  config 重算 identity。

- **Exporter 不再拥有第二个 identity algorithm。** [`compatibility.md:61-71`](../../specs/compatibility.md)
  规定 signed marker 的 `signer_identity` 必须逐 byte 等于 bound Built Generation 对应 RPM
  view record；因此不论 signing subsystem 最初如何产生该 opaque identity，同一个 bound
  Generation/view 的所有合规 exporter 都只能复制同一个值。先前 canonical-policy JSON 与
  certificate/fingerprint 两种 hash 算法都不再是合法 export 实现。

- **Source-bound verification 已闭合。** exporter 与 source-bound verifier 都必须把 marker
  identity 与 bound signing record 做 exact equality，并用该 record 绑定的 trusted public key
  验证 `repomd.xml.asc`
  ([`compatibility.md:68-72`](../../specs/compatibility.md))。marker identity、source policy owner、
  verification key 与实际 detached signature 现在形成同一条 closure；仅比较 64-hex spelling
  已不合规。

- **Standalone verification 的 authority 边界已闭合。** 没有 source state 的 verifier 必须由
  external trust configuration 把 marker 中同一 identity 映射到同一 public key，不能从 marker
  自封信任，也不能自行重算 policy/key hash
  ([`compatibility.md:68-71`](../../specs/compatibility.md))。因此 profile 是可独立消费、可由外部
  trust 验证的 leaf，但 marker 本身不是 trust anchor；这与 source-bound inheritance 没有混成
  一个虚假的 self-authenticating claim。

- **Signed/unsigned 对称规则无分叉。** unsigned Built view 的 source record 与 marker 都必须是
  `none` 且 `.asc` 不存在；signed view 必须复制 64-hex identity、manifest 覆盖 `.asc` 并完成
  signature verification ([`state-publication.md:144-149`](../../specs/state-publication.md)、
  [`compatibility.md:65-74`](../../specs/compatibility.md))。`signed=false + .asc`、
  `signed=true + missing .asc`、wrong identity 与 wrong key 都不能成为 completed export。

- **Marker exactness 不等于 reproducible-build identity，且当前文字没有越界承诺。** marker
  确定地绑定一个实际 export manifest 与 source signer record；spec 没有声称两个独立的
  RPM-MD regeneration 必须产生 byte-identical timestamps/signature bytes。只要各自 data closure、
  manifest digest 与 source/externally trusted signer verification 成立，输出 bytes 可以不同；
  这不再构成 marker schema/interchange 分叉。

- **Manifest/Changeset/export size range — CLOSED。**
  [`state-publication.md:108-120`](../../specs/state-publication.md) 与
  [`compatibility.md:56-60`](../../specs/compatibility.md) 现在都使用无前导零 ASCII decimal，
  范围统一为 `0..9223372036854775807`，超过 MaxInt64 必须拒绝。它与 migration alias size 的
  JSON-string/receipt domain 一致，int64 parser 与 arbitrary-precision parser 不再拥有不同的
  合法接受域。

- **Nested strict JSON — CLOSED。** [`migration.md:66-97`](../../specs/migration.md) 已明确
  unknown-field rejection 递归适用于 top-level 与每个 pointer/alias object，并拒绝任意层级
  duplicate member name；receipt size/domain/golden vectors 保持不变。宽松 nested parser 不能
  再生成一个合规但严格 parser 无法接管的 transition journal。

- **Overlap 与 Changeset-plan acceptance 已追上 normative rules。**
  [`acceptance-matrix.md:27-30`](../../specs/acceptance-matrix.md) 现在要求同 repository ID 的
  exact/ancestor/descendant/empty-prefix 全拒绝、siblings 正例通过，并把 canonical delta
  round-trip 与独立 target plan 的 protocol-pointer fault replay 分开保留 golden。上节指出的
  same-owner 与“按 Changeset lexical order 直接发布”验收歧义已消失。

- **Export/state-wire vectors 已覆盖这轮收紧。** [`acceptance-matrix.md:29-33`](../../specs/acceptance-matrix.md)
  加入 GenerationID/JCS、MaxInt64+1、migration receipt、duplicate/unknown JSON、signed/`.asc`
  组合、wrong bound signer identity、非法 Dist/arch、marker-last crash 与 size vectors。`0` 在
  base sentinel 中合法、在 retained/export generation 中仍按 state contract 拒绝；实现证据应
  在 fixture 中记录各上下文的 expected result，不能只记录输入值。

- **最终门禁：没有剩余 design/wire blocker。** N01、N02、N03、F04、F06/F07、F08/F09、
  F13、F15，以及后续 phase/plan/overlap/size/nested/signing 收紧，在已声明的支持域内均已
  CLOSED。架构与 deterministic export marker 都是 READY；remote cross-workspace adoption、
  R2 physical delete、default EL reposync 等仍是明确的 claim exclusions，而不是未关闭的设计
  分叉。当前 binary 与 next acceptance evidence 依然未完成，任何 READY 结论只适用于规范。
