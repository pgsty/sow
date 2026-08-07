# Identity, state, publication, and recovery contract

本文件冻结 `pool/ + dists/` 物理设计之上的状态所有权与恢复语义。供应商 SDK、
CLI 拼写与 Repository 私有 DB schema 由实现管理；v1 不承诺不同实现无状态接管 live
publisher。实现细节不得改变以下 identity、commit unit、roll-forward 与 deletion fence，
也不得向公开 prefix 增加 control object。

## Verification status

这些条款已经落入当前 0.3 state/config/managed publication 实现，并由本地
unit/fault/mock tests 覆盖 identity、overlap、attempt/checkpoint/grace、multi-target、
filesystem conditional delete 与 R2 report-only 路径。真实 R2、真实 HTTP client/cache
与跨进程/跨 workspace deployment 仍未验证；只有
[`acceptance-matrix.md`](acceptance-matrix.md) 的 retained live evidence 可以把对应外部
单元格升为 PASS。

## Repository and target identity

- 每个 Repository 有一个持久、不可复用的 `repository_id`，使用小写 canonical UUIDv4。
  它存入 Repository SQLite；Repository name、workspace 绝对路径和 publish URL 都不是
  identity。
- rename、restore 和 whole-workspace relocation 保留 `repository_id`。从备份分叉为可
  独立写入的新 Repository 时必须显式 fork 并生成新 ID；只复制公开 `pool/ + dists/`
  不携带发布权限，也不能接管 checkpoint。
- `target_storage_id` 是版本化 provider identity 加 canonical endpoint、region、
  bucket/container 的 tuple；`target_identity` 再加 canonical publish prefix。endpoint
  禁止 userinfo/query/fragment，scheme/host
  小写、IDN 使用 ASCII spelling、默认 port 删除；provider adapter 必须输出并持久化唯一
  canonical form。非空 prefix 使用 `/` 分隔、不以 `/` 开头或结尾、无空/`.`/`..`
  segment、backslash、query、fragment 或 percent-encoded separator；配置必须已是 canonical
  spelling，不能静默把两个拼写折叠后继续。空 prefix 只允许独占整个 bucket/container，
  并在 overlap 判定中视为所有其他 prefix 的 ancestor。
- 同一 Workspace 的 target registry 按 `target_storage_id` 拒绝任意两个 target bindings
  使用相同或 ancestor/descendant prefix，即使二者具有相同 `repository_id`；本地绑定是
  `repository_id + target_identity`，rename/restore 保留，fork 不继承。空 prefix 仍与该
  storage 下所有 prefix 冲突。
- filesystem adapter 还必须比较 `file:` endpoint 与 prefix 展开后的 canonical effective
  filesystem path。即使两个 endpoint tuple/URL spelling 不同，只要实际路径相同或互为
  ancestor/descendant 就拒绝；不能用 identity 拼写差异绕过本地 overlap fence。
- canonical public prefix 只允许 `pool/ + dists/`，本设计也明确不引入 bucket-global owner
  registry 或 prefix-trie CAS。因此它**不宣称**能在两个独立 SOW workspace 之间原子发现/
  仲裁重叠 prefix。受支持的运行边界要求一个 authoritative workspace/single writer，且
  provider credential/operational policy 让该 authoritative workspace 对包含此 prefix 的
  storage namespace 拥有独占写权限；若 provider 不能把 credential 收窄到 prefix（例如
  只能按 bucket），必须使用专用 bucket 或保证该 bucket 的所有 SOW prefixes 都只由同一
  Workspace registry 管理。独立 SOW 实例或 out-of-band writer 并发写同一或重叠 prefix
  属于 unsupported deployment。
- 远端每个既有 object/pointer 仍使用 expected identity CAS 检测竞争。丢失本地 binding、
  prefix 已非空却没有可验证 checkpoint，或发现 unexpected remote object 时只能 read-only
  reconcile，不得写入或删除。只复制公开 `pool/ + dists/` 从不授予发布 authority；自动
  cross-workspace adoption 不属于 v1。

## Target-neutral build versus target-scoped publication

状态 owner 明确分成两层：

| State | Owner | Meaning |
| --- | --- | --- |
| Desired/Built Membership, Package Object | Repository | 与任何 target 无关的本地业务状态 |
| Built Generation and Changeset | Repository | 一棵 canonical local delivery tree 的版本与物理 delta |
| retained generation/snapshot refset | Repository | payload 与 exact metadata bytes 的本地保留根 |
| Publication Attempt | Repository + target identity | 把一个 Built Generation 应用到一个 prefix 的可恢复事务 |
| Applied Checkpoint and observed Inventory | Repository + target identity | 该 prefix 已验证服务到哪一代、拥有哪些 keys |
| grace and deletion evidence | Repository + target identity | 该 target 独立的最早删除时刻；仅支持时保存 compare-and-delete 证明 |

target A 可以停在 Generation 10，target B 可以推进到 Generation 12；这不会创建两个
本地 Built Generation 身份。local GC 包含 current/retained/snapshot/recovery roots，以及
所有 non-terminal Publication Attempt 仍需的 source bytes。remote GC 只按该 target 的
Applied Checkpoint、in-flight Attempt、retained public view 与 grace roots计算，不能用
另一个 target 或仅用本地 current Generation 推断。

这些 target-scoped records 存在 Workspace private state（Repository SQLite 与受管 journal）
中；remote identity/ETag/version 只是它们引用的公开 object 证据。publish prefix 内不写
`.sow-owner`、checkpoint、attempt 或 receipt object。丢失 private state 后只能审计公开
`pool/ + dists/`，不能从静态树恢复写入 authority。

下面是实现必须持久化的 **semantic record shape**，不是跨实现 interchange wire：

```text
PublicationAttempt v1:
  repository_id, target_identity, base_checkpoint, target_generation,
  manifest_sha256, plan_sha256, phase, commit_intent,
  views[{view_id, pointer_path, old_identity, new_identity, state}]

PublicationAbandonedObject v1:
  attempt_identity, path, phase, size, sha256, remote_identity

AppliedCheckpoint v1:
  repository_id, target_identity, generation, manifest_sha256,
  inventory_identity, views[{view_id, pointer_path, remote_identity}], applied_at

GraceRecord v1:
  checkpoint_identity, verified_at, not_before, cache_policy_identity
```

数组按 `view_id,pointer_path` 排序，重复 view/path 拒绝。一个实现内部的所有 provider
adapter 必须无损保存这些字段与 CAS precondition，并通过 schema migration 保持 crash
recovery；具体 SQLite/JSON wire、record digest 与 discovery location不是 public Repository
合同。需要跨 binary family/workspace 接管时，必须先另行批准 state export/import/adoption
规格，不能从这些示意字段自行推导。

## Canonical Generation and Changeset

next 继续使用 v0.2 的 target-neutral physical record，不重新发明隐式格式：

```text
GenerationID         = exactly 20 ASCII decimal digits, zero-padded on the left
GenerationFile       = {path, phase, size, sha256}
GenerationFile.phase = payload | metadata | pointer
FileChange           = {op, path, phase, size?, sha256?}
FileChange.op        = add | update | delete
FileChange.phase     = payload | metadata | pointer        when op=add|update
                     | delete                              when op=delete
```

`GenerationID` 表示 `0..18446744073709551615`，例如 generation 42 是
`00000000000000000042`；需要 RFC 8785 JSON 或跨文件 identity 时始终作为 JSON string，
不能写成 JSON number。retained/export 的 generation 必须大于零；base sentinel 可为全零。
文本 manifest/Changeset 的 `size` 使用无前导零 ASCII decimal（零只写 `0`），范围固定为
`0..9223372036854775807`；更大的值拒绝，不能由实现自行扩大为 arbitrary precision。

- manifest 按 Repository-relative `path` bytewise 升序；path 唯一且 canonical。
- manifest digest 是每行 `sha256 SP size SP phase SP path LF` 的 SHA-256。
- Changeset 必须恰好等于 base/target manifests 的 path delta；非 delete 按
  `payload, metadata, pointer` 后按 path 排序，delete 最后按 path 排序。
- Changeset 是 declarative/canonical delta，不是可直接串流的 publication plan。publisher
  必须从它生成独立的 target plan，并用本文件后述 RPM/APT protocol pointer 顺序覆盖
  pointer-phase 的纯 path 排序；两种序列分别做 golden/fault test。
- `payload` 只允许 root `pool/...`。`dists/.../pool/...` 永远不能进入 next steady-state
  manifest。
- Package Object SHA-256 与 canonical Pool path 是双向唯一关系。已有 digest 只有在所有
  immutable facts（包括 source、filename、identity 与 Pool path）相同时才幂等；同 digest
  不同 facts 或同 path 不同 digest 都是 hard conflict。

Built Generation manifest 与 `changes --base 0` 在 **terminal steady layout** 中必须精确
等于公开 `pool/ + dists/` regular-file inventory。任何 non-terminal build、publish-local
exchange 或 layout migration 都使普通 `changes` fail closed；该操作自己的 journal/
transition inventory 是唯一可重放输入。

retained Generation 的 exact metadata bytes 保存在 Repository 私有 state 的内容校验区，
按 generation、path、size、SHA-256 与签名 identity 索引；不得依赖重新渲染重现旧签名。
旧 checksum-named metadata 在本地公开树的 grace 期间仍属于当时代 delivery inventory；
grace 清理作为一个有 manifest/Changeset 的 maintenance Generation 提交。公开
snapshot-like view 则是 `dists/` 下正常 metadata view，进入当前 manifest。

retained payload refset 复用 Generation manifest 中的 root `pool/...` records，metadata
refset 复用 non-payload records并指向私有 exact bytes。它们的目录、record schema、domain
digest 与 snapshot identity 引用由
[`publication-retention.md`](publication-retention.md#retained-state-wire) 唯一冻结；
不能自定义另一套无排序 wire。

每个 Built Generation 的 RPM view signing record 还必须持久化 `signer_identity`：unsigned
view 固定为 `none`，signed view 为 signing subsystem 已冻结的 lowercase 64-hex identity，
并绑定验证该 view metadata signature 的 trusted public key。这个 identity 是后续 retained
state 与 compatibility export 的逐 byte source of truth；这些衍生格式不得从自然语言 policy、
OpenPGP packet 或当前配置自行重算另一个值。signing subsystem 自身如何产生该 identity 属于
独立签名规格，但一旦 Built Generation 成立就不可变。

## Publication attempt and commit unit

直接静态对象 prefix 没有多 key 原子替换，因此 next **不承诺整个 Repository 瞬时同代**。
协议 view 是最小可见 commit unit；一次 Publication Attempt 仍绑定一个 target generation、
完整 plan digest、base checkpoint 与每个 pointer 的 expected remote identity。

状态机至少包含：

```text
planned -> payload -> immutable_metadata -> pointer_prepared
        -> commit_intent -> pointer_rollforward -> verified -> applied
        -> grace -> deletion_verified -> done
                 -> retained_reported -> done
pointer_prepared -> abandoned -> planned  # same deterministic plan may retry
```

- `commit_intent` 前不得改变任何 mutable public name；只允许 create-only canonical payload
  与 checksum-addressed immutable metadata。精确 reconcile 后可显式放弃 attempt。
- 放弃不复制或删除 target object。已经存在的 add-only object 以 path/phase/size/SHA-256/
  remote identity 保存为 target-scoped private evidence；mutable stable alias 与 protocol
  pointer 永远不能进入该 evidence。后续同一或不同 plan 必须识别这些已知 bytes，冲突则
  fail closed；一旦它们被 checkpoint inventory 接纳，才进入正常 grace/GC 生命周期。
- `commit_intent` 必须在第一个 mutable stable alias 或 protocol pointer write 前持久化。
  此后自动恢复只能按已记录顺序
  roll forward；不能由另一个进程自行选择 rollback。
- 每次 pointer update 都校验 expected ETag/version/digest。unexpected remote mutation 使
  Attempt 进入 reconcile/error；不得 blind overwrite。
- 多 view 切换中允许短暂 mixed generation。old/new 两代 payload 与 metadata closure 在
  Attempt applied 且各 view grace 到期前都是 remote roots。
- grace 后，支持安全删除的 target 走 `deletion_verified`；不支持的 target 把 exact
  unreachable candidate report 持久化后走 `retained_reported`。两者都可结束 Attempt，但
  后者的 Applied Checkpoint inventory 继续记录那些 keys，且不能报告 reclaimed bytes。
- 只有全部目标 view 的 commit pointer、签名 companion、公开 GET/HEAD 与 manifest closure
  验证通过后，才以 compare-and-set 写 Applied Checkpoint。crash replay 必须幂等继续同一
  plan；不同 base/target plan 不能接管。

这个 bounded mixed-view 窗口是 direct-static 与“不新增 Repository-level route pointer”
共同决定的明确代价。需要 Repository-wide instant flip 的部署必须使用外部 generation
router；它不是 canonical static contract。

## Protocol pointer order

RPM view：

1. 上传 payload 与 checksum-named repodata；
2. 若启用 repo metadata signing，先写新 `repomd.xml.asc` companion；
3. 以 `repomd.xml` 作为该 view commit pointer 最后 compare-and-set；
4. 验证 XML、signature 与所有 referenced metadata/payload。

signature-first 到 XML flip 之间，严格验签客户端可能短暂 fail closed；这是 direct object
hosting 的已接受可用性窗口，不能宣称 signed pair 多对象原子。unsigned view 只以
`repomd.xml` 为 commit pointer。

APT view：

1. `Release` 必须声明 `Acquire-By-Hash: yes`；先上传 checksum/by-hash immutable indexes；
2. 持久化整个 Attempt 的 commit intent；从这里起 crash recovery 只能前向；
3. 再刷新 `Packages`/`Packages.gz`/`Sources` 等 stable compatibility aliases；
4. signed 模式依次写 `Release.gpg`、`Release`，以 self-contained `InRelease` 为最终 commit
   pointer；unsigned 模式以 `Release` 为 commit pointer；
5. 验证 by-hash、Release checksums、签名与 payload closure。

远端 required APT contract 只对支持并实际使用 Acquire-By-Hash 的客户端承诺无 index
checksum race。non-by-hash 客户端在 stable alias 更新窗口可能暂时失败，不能宣传为
zero-downtime；本地 filesystem handoff可继续使用同文件系统 directory exchange。

## Published pointer withdrawal fence

只要一个 target binding 仍在 `sow.yml` 中且已有 Applied Checkpoint，普通 Repository
mutation 就不得让受影响 Dist 的任何 checkpoint pointer 从 prospective Generation 中消失。
这包括删除 Dist、移除 architecture view、关闭 RPM/APT metadata signing 而移除 signature
companion。实现必须在 Desired/config/public tree 发生变化前拒绝，而不是等 publish 时才发现
无法从旧 checkpoint 收敛。运维者要有意退役该公开面时，先从配置解绑/退役旧 target；若要
保留旧 prefix，再以不同 target 名称与新的 non-overlapping prefix 建立新发布关系。旧 target
的私有 checkpoint/evidence 不因解绑而伪装成已删除远端对象。

## Grace and evidence-fenced deletion

- 每个 target/prefix 独立保存 `verified_at`、不可缩短的 `not_before` 与所依据的 checkpoint。
  grace 从 Applied Checkpoint 和公开 endpoint 验证都成功后开始；失败/重试只能延后。
- 默认最短 grace 为 30 天。配置不得低于该 target 宣告的最大 metadata/CDN TTL 加 24 小时
  safety margin；系统时钟回退、未知 TTL 或缺失 witness 都 fail closed。
- delete plan 绑定 repository ID、target identity、Applied Checkpoint、inventory digest/
  version、pointer ETag/version、key、expected object ETag/version 或 size+SHA-256，以及
  `not_before`。任一证据变化都必须重新 reconcile/计算，旧 confirmation 不授权新集合。
- delete 使用 conditional operation；已不存在只在同一 inventory/ownership proof 下视为
  幂等成功。删除后 storage HEAD 与公开 endpoint/cache 都必须证明 absent，才记录
  deletion receipt。
- 不具备 conditional delete、inventory ownership、cache absence 或 checkpoint CAS 的
  target 允许 publish/add/update，但 remote delete 必须禁用；unreachable keys 只报告为
  retained candidates，不得把“未删除”报成 GC 完成。这会增加历史垃圾占用，但不会为同一
  live Package Object 生成 per-view/per-snapshot duplicate key。

## Initial release matrix

next 首个实现至少固定并保留以下 exact image/digest evidence：

- AlmaLinux 9 DNF4 与 Fedora 42 DNF5：file + HTTP ordinary client；leading-slash negative；
  default reposync limitation单列；
- Ubuntu 22.04 APT 2.4 与 Debian 12 APT 2.6：file + HTTP + Acquire-By-Hash stale-Release
  concurrent fetch；
- 一个真实 Cloudflare R2 nonproduction target：non-root prefix、GET/HEAD/Range、ETag、auth、
  pointer fault recovery，以及因缺少 atomic conditional delete 而 fail-closed 禁用 remote
  delete；R2 不作为 physical remote-GC PASS；
- whole-root locked handoff、RPM export、v0.2 layout migration crash matrix。

其他 EL、APT、DNF、proxy、WAF、repository manager 和对象存储只能标 `unverified`，不能由
上述最小矩阵外推。
