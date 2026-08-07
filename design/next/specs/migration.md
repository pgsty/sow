# Migration from v0.2 C2

## Truth boundary

归档的 `v0.2.0` binary 生成：

```text
<repo>/pool/...                         # canonical package
<repo>/dists/<dist>/<arch>/pool/...    # C2 hardlink alias
<repo>/dists/<dist>/<arch>/repodata/...
```

本迁移完成后应为：

```text
<repo>/pool/...                         # only package payload path
<repo>/dists/<dist>/<arch>/repodata/... # parent-relative href
```

当前 0.3 已实现显式 `sow repo migrate`、versioned transition journal、grace、alias
receipt 与 forward-only crash replay。迁移执行本身不等于外部兼容矩阵通过；v0.2 仓库在
显式迁移前仍按 v0.2 contract 读取，并且普通 v3 mutation fail closed。

truth boundary 是“兼容读取”和“升级写入”分离：`sow/v2` config 与 schema-v6 SQLite 可由
只读 discovery/query/status/check surface 打开，Generation INTEGER 只在该只读域解释；普通
writer 只接受当前 schema，绝不因一次 add/build/check 旁路升级。只有 `repo migrate` 使用专用
migration opener 把 config/schema/layout 一起纳入 journaled transition。若 transition 尚未
commit intent，可用 `sow repo migrate [NAME] --abort` 恢复 C2；之后只能前向完成。

## Implementation seams

| Area | Current v0.2 behavior | Required next behavior |
| --- | --- | --- |
| `internal/v2/managed/render_packages.go` | fan-out C2 aliases，跟踪 pending link count | renderer 直接读取 canonical source；为每个 view 计算 href；不创建 payload alias |
| `internal/yumrepo/rpm.go`, `types.go` | managed `Location` 必须是 `pool/...` | 分离 canonical Pool path 与 rendered href；共同调用安全 resolver/validator |
| `internal/v2/managed/check.go` | 验证 view alias、`SameFile`/link identity | 验证 href resolution、containment、size/digest、manifest closure 和 `dists/` 无 payload |
| `internal/v2/state` generation schema | prior membership 主要保护 C2 aliases | 泛化为 retained-generation payload refset/grace root，不依赖物理 alias |
| generation/changes renderer | alias 是物理交付 path | 每个 package 只列 canonical Pool path；metadata/pointer 仍按 view 列出 |
| PoC/client tests | 默认 reposync 是必须通过的 gate | 普通 DNF 是 required；默认 EL reposync 是 expected limitation；export 独立验收 |

实现时应保留既有 Repository、Dist、Membership、Package Object、Desired/Built、
Operation Journal 与 Changeset 所有权；这不是回到 V1 Git/CAS、target-global pool 或
route-aware serving 的授权。

## In-place migration sequence

迁移使用 versioned Repository transition journal，而不是普通 Generation manifest 伪装
中间态。journal 绑定 `repository_id`、old/new layout version、base/target Generation
manifest、精确 legacy alias inventory、每个 view 的 old/new pointer digest、phase 与 grace
deadline。phase 固定为：

```text
planned -> staged -> commit_intent -> pointer_rollforward
        -> grace -> alias_delete -> final_manifest -> done
```

`commit_intent` 在第一个新 pointer 前持久化；之后自动恢复只能 roll forward。transition
未终态时，普通 `changes`/publish/GC fail closed，只能由该 journal 的 exact migration plan
继续；这消除了“物理树仍有 aliases、next manifest 又必须排除 aliases”的矛盾。

首个实现固定 journal 为 RFC 8785 canonical JSON
`.sow/<repo>/transitions/c2-to-single-v1.json`。schema migration 先把 Repository
`layout_version` 从 `c2-v1` 改为 `c2-to-single-v1` 并提升 SQLite user/schema version；旧
binary 遇到新 schema 必须在任何 filesystem mutation 前失败。最后一次事务把它改为
`single-payload-v1` 并安装 final manifest，之后才删除 transition journal。

v0.2 Repository 没有 `repository_id`。首次 migration 在同一个 SQLite schema transaction
中生成一个 canonical lowercase UUIDv4，先持久化到 Repository row，再把同一值写入 journal；
crash replay 必须复用它，绝不能重新生成。两个在此之前独立复制的 v0.2 workspace 各自
migrate 后是两个 Repository/fork，不能共享 publish authority；需要保留同一 identity 时必须
复制已经包含 UUID 的完整 private state，而不是只复制 public tree。

v1 journal 恰好包含并拒绝其他字段；unknown-field rejection 递归适用于 top-level 与每个
nested pointer/alias object，任何层级的 duplicate JSON member name 都拒绝：

```text
schema = "sow/transition/c2-to-single/v1"
repository_id = canonical UUID string
from_layout = "c2-v1"
to_layout = "single-payload-v1"
base_generation = 20-digit GenerationID JSON string
base_manifest_sha256, target_manifest_sha256 = lowercase 64-hex
phase = planned|staged|commit_intent|pointer_rollforward|grace|
        alias_delete|final_manifest|done
commit_intent = boolean
grace_not_before = null | UTC RFC3339 seconds string
pointers[] = {view_id, kind, path, old_sha256, new_sha256, state}
legacy_aliases[] = {path, size, sha256, state, receipt_sha256}
```

`kind` 是 `signature_companion|commit_pointer`，`state` 对 pointer 是 `old|new`，对 alias
是 `present|deleted`；alias `size` 是 JSON string，内容为 `0` 或无前导零 ASCII decimal，
范围 `0..9223372036854775807`。未删除 alias 的 `receipt_sha256` 必须为 null，删除后为
`SHA256("sow/c2-alias-delete/v1" NUL repository_id NUL path NUL ASCII-decimal-size NUL sha256)`。pointers
按 bytewise `view_id`、固定 kind rank（signature companion 先于 commit pointer）、path
排序，aliases 按 path bytewise 排序，重复项拒绝。所有 path 都是 canonical
Repository-relative path；pointer 必须位于 `dists/`，alias 必须位于
`dists/<dist>/<arch>/pool/`。journal identity 是 ASCII domain
`sow/transition/c2-to-single/v1`、NUL 与 canonical JSON bytes 的 SHA-256。
`commit_intent=true` 当且仅当 phase 不早于同名 phase；`grace_not_before` 只能在 grace 及
之后非 null。done record 的 digest 先作为 transition receipt 写入 SQLite，再删除 journal。
alias receipt 各 component 使用上面已定义的原始 ASCII bytes，separator 恰好一个 NUL，
最后的 lowercase SHA-256 后**没有** terminal NUL；size `0`、`1`、`9007199254740992` 与
`9223372036854775807` 必须进入 golden vectors。

1. 取得 Repository 写锁，完成/回滚所有 v0.2 Operation，并运行当前 v0.2 full check。
2. 在同文件系统私有 stage 中，用 canonical Pool sources 渲染全部新 RPM metadata；
   不创建 C2 aliases。
3. 用 next checker 验证每个 href 恰好解析到既有 root Pool object，并完成 file/HTTP
   客户端门禁。
4. 写入 `commit_intent`，先安装 immutable metadata，再按 journal 固定顺序逐 view
   roll forward `repomd.xml`/signature pointer。mixed-view 窗口允许存在，但 old/new closure
   都受 transition inventory 保护；此时尚不提交 next steady-state Built Generation。
5. 暂时保留旧 C2 aliases：已经读取旧 metadata 的客户端仍会请求 view-local
   `pool/...`。grace 期间它们只出现在 legacy transition inventory，不得进入 next
   Generation manifest；`changes` 明确不可用，而不是返回一个不精确清单。
6. grace 结束且没有旧 generation/recovery 引用后，按精确旧 manifest 删除
   `dists/<dist>/<arch>/pool/...`；每项删除记录 receipt，只影响 aliases，不触碰 root Pool。
7. `check` 证明 `dists/` 无 package payload后，扫描 terminal public tree，原子提交
   next layout version、Built Generation 与 Changeset；随后 `changes --base 0` 必须与真实树
   一致，最后把 transition 记为 done。

对象存储 target 只有在提供 atomic conditional delete、可验证 inventory ownership 与
cache absence 时，才允许原 prefix in-place migration：保存 base checkpoint、commit
intent、per-view pointer state、legacy-key inventory 与 delete receipt；先确保 canonical
`pool/...` key，roll forward 新 metadata/pointer，等待 grace，再条件删除旧 view-local
payload keys。

Cloudflare R2 这类不提供该 delete primitive 的 target **不得**原地清理 C2 keys，也不能把
unconditional bulk delete 包装成迁移成功。它必须把 next tree 发布到新的、空的、
non-overlapping publish prefix，验证并切换外部 consumer/route；旧 prefix 作为独立 legacy
Repository prefix 整体退役，之后由已撤销写入者的 provider lifecycle 或明确的人工运营流程
处理。切换期两套 prefix 各自计费是迁移成本，但新的 next prefix 从第一天起只有一个 payload
key；旧 prefix 未清空前不得宣称全 target storage 已去重。

## Rollback

- `commit_intent` 前没有公开 pointer 改变；可以删除私有 stage、恢复
  `layout_version=c2-v1` 并通过 `repo migrate --abort` 放弃本次 transition。
- `commit_intent` 持久化后，无论 aliases 是否已经删除，自动恢复和人工操作都不得把
  pointer 恢复到 v0.2 generation；唯一合法恢复方向是按原 journal 与 CAS precondition
  完成 `pointer_rollforward -> grace -> alias_delete -> final_manifest -> done`。这避免同一
  crash point 因操作者或实现不同而产生两种 canonical 结果。
- 任何从 canonical Pool 重建的 C2 compatibility
  artifact 都必须位于 canonical Repository/publish prefix 之外，遵守 external export
  ownership，且不能成为 Generation、pointer target、publish input 或 GC root；正常恢复
  只允许继续 forward。
- schema migration 必须 forward-only 且保存明确 layout version；旧 binary 遇到新
  schema/layout 必须硬失败，不得把 metadata-only view 误判为损坏并补建 aliases。

## Documentation and evidence disposition

- `design/v0.2/evidence` 与旧 PoC 保留原始结果，继续证明 v0.2 C2。
- `design/v0.2` 的规范入口标记 superseded，并指向 `design/next`。
- 新验收证据写入 next 目录或未来版本目录，不覆盖旧日志、hash 或 PASS 结论。
