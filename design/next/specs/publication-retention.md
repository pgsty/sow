# Publication, generations, snapshots, and GC

## Implementation status

当前 0.3 源码已实现 target-neutral Generation、private retained exact bytes/refset、local
GC、target-scoped attempt/checkpoint/grace/candidate report，以及 filesystem conditional
delete receipt 与 R2 retain/report-only maintenance；相应本地 fault/mock tests 已覆盖。
真实 target/cache absence 与真实客户端 grace 行为仍是 release evidence gate。

## Publish prefix contract

一个 Repository 在一个 target 上拥有一个 publish prefix。Repository Built Generation
保持 target-neutral；该 prefix 是单一 payload 的远端去重边界，也是 target-scoped
Publication Attempt、inventory、checkpoint、鉴权与删除证据边界：

```text
<publish-prefix>/pool/...
<publish-prefix>/dists/...
```

不同 Repository 即使含相同 digest，也使用各自 prefix；同一 Repository 发布到
不同 target/prefix，也各自保存一份。当前设计不建立 bucket-global CAS，也不要求
edge URL-to-object mapper。

publish manifest 只列规范化的 Repository-relative paths：

- package payload：每个 canonical `pool/...` path 一条；
- metadata：每个 Dist/view 的 checksum-named index/by-hash path；
- pointer：`repomd.xml`、`Release`、`InRelease` 等 mutable entry；
- delete：完成 grace 与可达性判断后的旧 path。

metadata 中的 `../../../pool/...` 是客户端寻址表达式，不是 manifest path 或 object
key。publish 必须上传实际的 `pool/...` key，绝不创建含 dot segment 的 key。

持久 `repository_id`、target identity、prefix overlap preflight 与 publish authority 规则见
[`state-publication.md`](state-publication.md)。

## Publication order

```text
canonical payloads
  -> immutable/checksum-named metadata
  -> durable commit intent
  -> mutable APT stable aliases / protocol pointers
  -> verification and stale-client grace
  -> evidence-fenced deletion
```

- payload 先于任何引用它的新 metadata；同 digest/key 已存在且 size/hash 一致时复用。
- metadata 完整上传并验证后，先固化 commit intent，再刷新 mutable APT stable aliases，
  最后推进 `repomd.xml`、`Release`、`InRelease` 等协议指针。
- 删除不与 pointer flip 同步发生；旧 metadata 可能已被客户端读取，相关 payload 在
  grace 结束前仍必须保留。
- `changes --base 0` 只在 terminal steady layout 可用，且是当前 Built Generation 的
  完整 `pool/ + dists/` 交付清单；不包含 `.sow`、数据库、export 或历史 C2 alias。

直接对象存储的实际 transaction 是 target-scoped、per-view roll-forward：第一个 mutable
stable alias 或 pointer 写入前持久化 commit intent，之后只前向恢复；全部 view 验证后才推进
Applied Checkpoint。commit intent 前可显式 abandon，但只能保留已 reconcile 的 add-only
payload/immutable-metadata evidence，不复制或删除 target object。
RPM 签名 companion、APT Acquire-By-Hash、bounded mixed-view 窗口和删除 fence 的唯一顺序
由 [`state-publication.md`](state-publication.md) 定义，不能只凭上面的四阶段口号实现。

## Generation and snapshot model

Built Generation 记录：

- 当前 metadata tree identity；
- canonical payload digest/path set；
- 前代与 Changeset；
- renderer/signing/config identity。

保留旧 Generation 不复制 payload，只增加 manifest/refset 和必要的旧 metadata。旧
metadata 的 exact bytes、path/size/SHA-256、renderer 与 signer identity 保存在
`.sow/<repo>/retained/<generation>/...` 的 Repository 私有校验区；恢复不得依赖重渲染
重现旧签名。公开 stale metadata 只在 delivery grace 内保留，并由 maintenance
Generation/target inventory 精确记账。
未来若提供 snapshot/freeze/channel API，也必须遵守同一规则：snapshot 类似 commit，
保存 metadata identity 与 payload reference set，而不是 CopyObject payload。

### Retained state wire

为避免两个实现都声称“保存 refset”却无法互相恢复，首版私有 retained layout 固定为：

```text
.sow/<repo>/retained/<generation-20d>/
├── record.json
├── manifest.tsv
└── metadata/<exact Repository-relative non-payload path>...
```

- `manifest.tsv` 是该 terminal Built Generation 已定义的完整 manifest bytes；空 Repository
  Generation 合法时它可以是零字节。非空时按 path
  bytewise 排序，每行 `sha256 SP size SP phase SP path LF`；它引用 canonical root
  `pool/...` payload，但 retained 目录绝不复制这些 payload bytes。
- `metadata/` 逐 path 保存 manifest 中所有现存 non-payload regular file 的 exact bytes，
  包括 checksum index、stable alias、pointer 与签名 companion；每项 size/SHA 必须与
  manifest 一致。目录本身和这些 private control files 不进入 Built Generation。
- `payload_refset_sha256` 是 ASCII domain `sow/payload-refset/v1`、一个 NUL byte，再接
  manifest 中所有 `phase=payload` 原始行的 SHA-256；`metadata_refset_sha256` 对所有
  non-payload 原始行使用 domain `sow/metadata-refset/v1`。空集合仍按 domain + NUL 求值。
- `record.json` 使用 RFC 8785 canonical JSON；v1 恰好包含并拒绝其他字段：
  `schema="sow/retained/v1"`、canonical `repository_id`、20-digit `GenerationID` JSON
  string `generation`、
  lowercase 64-hex `manifest_sha256`/`payload_refset_sha256`/
  `metadata_refset_sha256`/`renderer_identity`，以及 `signer_identity`（`"none"` 或
  lowercase 64-hex）。record identity 是 ASCII domain `sow/retained-record/v1`、NUL
  与 canonical JSON bytes 的 SHA-256。
- `<generation-20d>` 恰好是 record `generation` 的 20 个 ASCII digits，按左侧 `0` 补齐，
  不接受短写、`+`、空格或超过 uint64 的值；目录 token、record 与 manifest identity 必须
  指向同一 Generation。
- snapshot/freeze/channel 名称若以后出现，只能在 Repository state 中引用这个
  retained-record identity；不得另创 payload copy、另一种 refset digest 或依赖重渲染。

这是一种 workspace interchange wire，不意味着复制公开 `pool/ + dists/` 的操作者自动
取得远端发布 authority；target state 仍须单独保留或经过未来显式 adoption。

本设计不增加公开 `snapshots/` 或 `release/` 顶级目录。可公开寻址的 snapshot-like
结果应作为 `dists/` 下的 metadata view/普通 Dist 表达；其不可变性、命名和 CLI
状态机留给后续产品规格。无论表达方式如何，每个 href 最终仍解析到同一 root Pool。

## Repository-wide reachability

local GC 的 live closure 至少为：

```text
current Desired/Built Membership
union retained Built Generations
union retained snapshot/view refsets
union active recovery/pending operations
union stale-client grace roots
union non-terminal target Publication Attempt source roots
```

已安全 abandon 的 Publication Attempt 不再冻结本地 source bytes；它保存的是 target-scoped
object evidence 而不是第二份 payload。远端对象若从未被后续 checkpoint inventory 接纳，
保持“已知但尚未授权删除”；支持安全删除的 target 也要先经后续 checkpoint/grace/candidate
流程，R2 则继续 report-only。这样解冻本地 mutation 不会把远端残留伪装为 foreign write，
也不会为了回滚制造副本。

remote GC 另按每个 target 的 Applied Checkpoint、in-flight Attempt、inventory 与 grace
独立计算；不能因另一个 target 已推进就删除当前 target 的 key。

“计算 remote garbage”与“物理删除”是两个状态：所有 target 都必须能报告 unreachable
candidate；只有具备 `state-publication.md` deletion preconditions 的 target 才能执行删除。
Cloudflare R2 的首版行为是保留并报告，不能把对象仍在远端写成 GC PASS。

GC 以 manifest/reference 为证据，不读取 inode link count。一个 package 从某个 Dist
移除，只删除该 Membership 与后续 metadata 引用；只有当它不在整个 Repository
closure 中且 grace 已过，canonical Pool path 才可删除。

`check` 必须同时证明：

- 每个 metadata package location 解析到一个 closure 内的 canonical Pool path；
- 每个 manifest payload 的 size/SHA-256 与 Package Object 一致；
- 没有 package payload 出现在 `dists/`；
- 当前/保留 refset 不引用缺失 payload；
- 待删除对象不被任一 live root 引用。

若 configured target 已有 Applied Checkpoint，prospective local Generation 还必须保留该
checkpoint 对受影响 Dist 的 pointer set。撤销 Dist/architecture/signature companion 前要先
退役/解绑 target，或以新名称和新 prefix 重新发布；不能依赖之后的 publish 把旧 pointer
“删掉”。

## Access-control consequence

RPM package 请求从 `/dists/...` 解析到同一 Repository prefix 下的 `/pool/...`。
因此授权策略必须覆盖 prefix root，不能仅保护 view 路径。若同一 Repository 的
public/private Dist 不能共享相同 payload ACL，必须拆成不同 Repository/publish
prefix，或使用统一 private origin + edge authorization；静态单 key 不可能同时拥有
两套互斥 ACL。target preflight 必须检测一个 Package Object 是否被不兼容 visibility
views 共用；direct-static target 遇到该配置硬拒绝，不能只靠文档警告。

该安全边界也是接受 Repository-scoped 而非 bucket-global Pool 的原因之一：每个
Repository/prefix 可以独立配置访问、checkpoint、inventory、retention 与删除权限。
