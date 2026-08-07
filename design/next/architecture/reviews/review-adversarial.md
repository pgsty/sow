# Adversarial interoperability review

> **Historical pre-implementation snapshot.** 以下 finding 是修订前合同的输入，不是当前
> 0.3 缺陷清单；关闭状态见同目录 resolution/final，当前实现与未验证边界见
> [`../../evidence/2026-08-05-implementation.md`](../../evidence/2026-08-05-implementation.md)。

日期：2026-08-05

范围：`design/next` 的 Repository layout、href、Generation/refset、external export、publication/GC 与 v0.2 migration 合同。

方法：只报告能够构造出“两个实现都可按当前文字声称合规，但不能消费、恢复或安全接管彼此产物/状态”的分叉；同时检查规范内部是否存在无法同时满足的规则。

结论：核心物理决策已经足够封闭——canonical public tree 是 `pool/ + dists/`、package payload 只在 root Pool 出现一次、完整 Repository 才是搬迁/发布单元、canonical package alias 被禁止。互操作合同尚未封闭；以下 15 处会让独立 renderer、publisher、GC、exporter 或 migrator 产生不兼容结果，其中迁移 grace 期间的 `changes 0` 规则还是直接矛盾。冻结这些 wire/state 细节前，可以实现一个内部自洽的 next 版本，但不能声称两个独立实现能够交换仓库或接管恢复。

- **RPM base URI 的目录语义没有冻结。** [`repository-layout.md:52-70`](../../specs/repository-layout.md) 定义从 view root 计算 href，却没有要求配置和实际 retrieval base URI 必须以 `/` 结尾。实现 A 把 `https://h/r/dists/el9/x86_64/` 作为目录 base；实现 B 原样保留合法配置 `https://h/r/dists/el9/x86_64`，但仍用同一个 Repository-relative view root 做内部 round-trip。两者都会生成 `../../../pool/...` 并通过自己的 checker；按 [RFC 3986 section 5.2.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-5.2.3)，无尾斜杠 base 会先丢弃 `x86_64` 这一段，最终请求可越过 `/r/`。合同需要规定 canonical base URI、尾斜杠归一化，以及 checker 必须同时用最终 `file:`/HTTP retrieval URI 验证，而不只是用 POSIX path 验证。

- **href 的 byte-to-URI 编码函数没有唯一结果。** [`repository-layout.md:61-68`](../../specs/repository-layout.md) 只要求“一致 escaping”和“non-canonical escaping”拒绝，但没有定义输入是文件名原始字节、Unicode 字符串还是已转义 URI segment，也没有冻结 UTF-8、Unicode normalization、允许保持未转义的 sub-delims、百分号处理和十六进制大小写。对字面文件名 `pkg%2Fdebug+1.rpm`，实现 A 会把 `%` 编为 `%25`，实现 B 会把 `%2F` 当作已有 escape；两者都能用自己的 inverse resolver round-trip，却会请求不同 path/key，甚至把一个 segment 变成两个。应给出规范化伪代码与 golden vectors，并明确只编码一次、`%` 必须作为数据编码、UTF-8 与 uppercase percent triplet 规则。

- **canonical Pool path 算法只是被称为“既有算法”，没有进入前向规范。** [`repository-layout.md:99-107`](../../specs/repository-layout.md) 写成 `pool/<prefix>/<source>/<filename>`，但没有规定 `<prefix>` 对 `lib*`、大小写、非 ASCII source、空 source、debug/source packages 的精确派生；[`README.md:9-14`](../../README.md) 又声明 v0.2 只作历史证据，不能决定 next。实现 A 可复制 v0.2 的 `lib` 四字符 shard 规则，实现 B 可按示意取首字符，二者都符合当前 companion 的字面形状，却产生不同 Pool path、href、manifest 和 collision 结果。应在 next 合同中完整重述并版本化 path function，而不是靠实现历史隐式继承。

- **Repository 与 publish prefix 没有规范化的持久 identity。** [`ARCHITECTURE-SPINE.md:50-55`](../ARCHITECTURE-SPINE.md) 把 Repository/prefix 规定为 checkpoint、inventory、authorization 和 GC 边界，但未定义 identity 是 repo name、数据库 UUID、绝对路径、target name，还是 provider/bucket/prefix tuple。实现 A 把 `s3://bucket/repos/acme` 与 `s3://bucket/repos/acme/` 视为不同边界；实现 B 去掉尾斜杠后把它们视为同一边界。两者可能写入完全相同的 object keys，却持有不同锁、checkpoint 和删除 closure。应冻结持久 Repository ID、target identity、prefix 的 byte-level normalization，并在写入前拒绝两个 owner 的相同或祖先/后代重叠 prefix。

- **Repository rename、restore 和 workspace relocation 的身份继承未定义。** 全根搬迁被声明为 required，但状态边界仍以“一个 Repository”表述。实现 A 以配置中的 repo name 为身份，复制到新 workspace 后可继续接管原 remote checkpoint；实现 B 以创建时绝对 root 或新生成 UUID 为身份并拒绝接管。两者都保持 `pool/ + dists/` 相对关系，却不能读取或安全推进对方的 remote generation。应明确 name 是否不可变身份、UUID 是否随备份保留，以及 clone/adopt/fork 各自必须产生何种新 identity。

- **Generation、snapshot 与 payload refset 没有 canonical wire representation。** [`publication-retention.md:44-59`](../../specs/publication-retention.md) 要求 metadata identity、digest/path set、前代和 renderer identity，但没有 schema、字段域、排序、重复处理、hash domain 或 unknown-field 规则；snapshot CLI/命名又在 [`ARCHITECTURE-SPINE.md:142-147`](../ARCHITECTURE-SPINE.md) 明确 deferred。实现 A 可对按 path 排序的 JSON 求 generation ID，实现 B 可对按 digest 排序的 CBOR 求 ID；逻辑 refset 相同却无法比较 identity、导入 snapshot 或继续对方的 generation chain。这个 defer 可以保留，但在 schema 冻结前，CAP-5 只能是单实现语义，不能作为跨实现互操作承诺。

- **retained Generation 的旧 metadata 放置和恢复方式不唯一。** [`publication-retention.md:53-59`](../../specs/publication-retention.md) 说保留点增加“必要的旧 metadata”，同时禁止公开 `snapshots/`/`release/` 顶级目录，但没有规定这些 bytes 是继续留在当前 `dists/.../repodata`、放进私有 `.sow`、按内容寻址保存，还是允许以后用旧 renderer/key 重建。实现 A 在 live `repodata` 累积旧 checksum-named 文件并把它们纳入 `changes 0`；实现 B 只在 `.sow` 留 manifest/refset，恢复时重渲染。两者都可声称没有复制 payload，但一个 publisher 无法从另一个的状态精确恢复旧签名 metadata，完整 manifest 也不同。应冻结 metadata retention namespace、byte identity、签名材料与 publish/restore 规则。

- **external export 有两个允许布局，却没有 profile/discriminator 与 href 重写合同。** [`compatibility.md:34-55`](../../specs/compatibility.md) 允许 `pool/... or Packages/...`，但未规定选择条件、RPM Location 的映射、repodata 是否必须重建、签名是否继承/重签，以及 export 自身的 manifest schema。实现 A 生成 `Packages/p/pkg.rpm` 并在重签后的 metadata 中写 `Packages/...`；实现 B 生成 `pool/p/pkg.rpm` 并写 `pool/...`。两者都是可独立消费的 copy export，却会被只认识另一布局的 validator/importer 拒绝。应定义带版本 discriminator 的一个或多个 export profiles，每个 profile 固定布局、href、签名和验证算法。

- **external export ownership marker 没有 wire contract。** 规则允许空目录，或具有“精确 SOW ownership marker”的目录执行 `--replace`，但 marker 的路径、schema、export ID、source Repository/generation binding、method、完整 manifest digest 和 CAS/replace 语义都未定义。实现 A 写 `.sow-export.json`，实现 B 写 `.sow/owner`; 两者都认为自己的 marker 精确，却都不能安全替换对方生成的 export。应在实现前冻结 marker schema 和原子 replace/recovery 状态机，否则“可交换的 disposable export”只在同一 binary 内成立。

- **full manifest 与 incremental Changeset 的交换语义仍依赖隐含 v0.2 实现。** [`SPEC.md:44-47`](../../specs/SPEC.md) 和 [`publication-retention.md:17-42`](../../specs/publication-retention.md) 规定 phase 顺序和 `changes 0`，但没有前向 wire schema、base generation identity、update 与 delete+add 选择、no-op、path sort、重复项或 replay precondition。实现 A 可在每代 delta 中重复列出所有仍 live payload 一次，实现 B 只列新增 payload；两者都满足“每 path 每代至多一次”和 phase ordering，但接收方无法判断输入是全量、幂等 upsert 还是严格 delta。应冻结 manifest/changes schema、domain-separated digest、base/target IDs 和 replay compare-and-set 条件。

- **“pointer phase”没有规定协议内 commit point 的精确顺序。** [`ARCHITECTURE-SPINE.md:86-90`](../ARCHITECTURE-SPINE.md) 只说 immutable metadata 后发布 protocol pointers。实现 A 可先 PUT 新 `repomd.xml` 再 PUT `repomd.xml.asc`；实现 B 可先 PUT `.asc` 再 PUT XML，两者都把二者放在 pointer phase，但前者会短暂暴露新 XML 配旧签名。APT 的 `Release`、`Release.gpg`、`InRelease` 也有同样分叉。应分别冻结 RPM 与 APT 的唯一 mutable commit point、同名 key 更新顺序、旧/new pair 可接受窗口和 post-flip verification；否则两个 publisher 的 crash recovery 不能安全接管彼此。

- **grace root 的时钟与证据未定义，GC 会得出不同删除时刻。** [`publication-retention.md:27-40`](../../specs/publication-retention.md) 要求 stale-client grace，但没有 duration source、开始事件、按 local build 还是每个 remote target 计时、失败重试是否重置、时钟回退处理或持久 witness。实现 A 从本地 pointer exchange 开始计时；实现 B 从 remote pointer 验证成功开始计时。慢 target 上 A 会在 B 仍认为对象 live 时删除 payload。应定义 per-prefix grace record、单调/UTC 字段、开始门、最短期限与 deletion witness 的 canonical schema。

- **remote inventory/checkpoint 被架构依赖却又整体 deferred。** AD-17 把 inventory/checkpoint 纳入去重与 GC 边界，CAP-4/5 要求可发布和可回收；但 [`ARCHITECTURE-SPINE.md:142-147`](../ARCHITECTURE-SPINE.md) 将 checkpoint wire 与供应商实现一并 deferred。实现 A 用 LIST 当前状态和本地 SQLite，允许删除任何不在 refset 的 key；实现 B 要求远端 create-only inventory 与 conditional checkpoint 才删除。两者都遵守一对一路径和 pointer-last，却无法恢复对方的半完成 publish，也不能同意哪些 extra key 是 owned/orphan/foreign。应把 provider-neutral checkpoint、inventory、operation journal、CAS 和 ownership/adoption 语义从 SDK defer 中分离出来先冻结。

- **迁移 grace 期间，`changes 0` 的两条强规则无法同时满足。** [`migration.md:45-52`](../../specs/migration.md) 要求旧 `dists/<dist>/<arch>/pool/...` aliases 暂留，但不出现在新 Generation manifest；[`SPEC.md:44-47`](../../specs/SPEC.md) 又要求 `changes 0` 与真实 `pool/ + dists/` regular files 完全一致，[`publication-retention.md:41-42`](../../specs/publication-retention.md) 同时明确 `changes 0` 不含历史 C2 alias。实现 A 扫描真实树并列出 aliases，会违反 exclude；实现 B 排除 aliases，会违反 exact-tree。需要显式 transitional layout/version：定义 migration-owned extras 的独立 manifest、此阶段 `changes` 的输出/拒绝行为，以及何时原子切换到 next invariant。

- **迁移 journal、跨 view crash 决策与旧 alias 删除证据没有可交换状态机。** [`migration.md:38-65`](../../specs/migration.md) 允许逐 view 切 pointer，并要求每个 crash point 收敛到完整旧代或新代，但没有规定中途 mixed-view 状态的 durable phases、roll-forward/rollback 选择、schema migration commit point，以及“精确旧 manifest”存放在哪里。实现 A 在第三个 view 后崩溃并选择 roll-forward；实现 B 接管同一 workspace 后可能按自己的规则 rollback，或把未进入新 Generation 的 aliases 当 unmanaged files。应冻结 layout-version transition journal、old/new manifest digests、每 view phase、唯一 recovery direction 和 alias deletion receipt；旧 binary、新 binary 与第二实现才可能 fail closed 而不是互相改写。
