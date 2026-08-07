# SOW next design

状态：**源码实现完成；本地与 mock 验证已覆盖；发布级外部证据未完成**（2026-08-05）。

本目录是下一版 Repository 物理布局、发布与兼容策略的唯一前向权威。它不改写
`v0.2.0` 的实现事实：v0.2 使用 C2 view-local package hardlink，并已按当时的
`reposync` 门禁完成验收；下一版明确撤销该选择。

## 权威顺序

1. [`specs/SPEC.md`](specs/SPEC.md) 与其 companions：能力、布局、状态所有权、发布恢复、约束和验收合同。
2. [`architecture/ARCHITECTURE-SPINE.md`](architecture/ARCHITECTURE-SPINE.md)：实现单元不得分叉的架构不变量。
3. [`research/rpm-shared-pool-reposync-compatibility.md`](research/rpm-shared-pool-reposync-compatibility.md)：协议、客户端和取舍依据。
4. [`architecture/reviews/`](architecture/reviews/)：独立评审与关闭记录；它们是 gate evidence，
   不是新增权威来源。
5. [`evidence/`](evidence/)：当前 checkout 的分层实现证据与尚未完成的 release gates。
6. [`../v0.2/`](../v0.2/)：已发布实现、历史评审与验收证据；只证明 v0.2，不再决定下一版布局。
7. 根目录 `docs/`、`docs/adr/` 与 `_bmad-output/`：归档 V1 Git/CAS/route
   brownfield；即使被旧实现规格直接引用，也只解释 V1，不得覆盖本目录。

## 已批准结论

- canonical Repository 根目录直接包含 `pool/` 与 `dists/`；不增加 `release/`、
  `reposync/` 或 package alias 顶级目录。
- “包体只存一份”的边界是单个 `Repository / publish prefix`。不同 Repository、
  不同目标 prefix 之间不去重。
- APT 继续使用 archive-root `pool/...`；RPM view 的 `<location href>` 从 view root
  计算到 canonical Pool 的父级相对路径。
- package hardlink 不再是 Repository 正确性条件；正式发布和快照不得为每个
  Dist、architecture、generation 或 snapshot 制造 payload alias。
- 默认 EL `reposync` 不属于兼容承诺。需要自包含 leaf 时使用显式、仓库外的
  compatibility export，默认 copy，受控环境才允许 opt-in hardlink。
- `pool/ + dists/` 是完整的复制、静态托管和对象存储发布单元；单个 RPM view
  不是独立仓库交付物。
- Built Generation/Changeset 属于 Repository；Publication Attempt/Applied Checkpoint/
  grace/delete evidence 属于具体 target prefix。direct-static 多 view 发布按 durable
  commit intent 逐 view roll forward，不虚构对象存储的多 key 原子性。
- commit intent 前只允许 create-only payload 与 checksum-addressed metadata 写入；此时
  `publish --abort` 可在精确 reconcile 后释放本地写门禁，已存在对象只登记为 target-scoped
  私有 inventory evidence，不复制、不删除。APT stable alias 与所有 protocol pointer 都在
  commit intent 后写入；此后只能前向恢复。
- 已有 Applied Checkpoint 的 configured target 会冻结其公开 pointer 集。删除 Dist/architecture
  或关闭 metadata signing 前，必须先从配置退役/解绑该 target，或用新名称和新 prefix 建立
  替代 target；不能生成一个无法从旧 checkpoint 安全收敛的新 Generation。
- canonical prefix 不放 owner marker 或 bucket-global registry；受支持发布要求一个
  authoritative workspace、single writer 与独占 storage write authority；provider 不能
  prefix-scope 时使用专用 bucket 或同一 Workspace registry。独立 workspace/out-of-band
  writer 的分布式 prefix 仲裁不在合同内。
- 缺少 atomic conditional delete 的 target（当前包括 Cloudflare R2）可发布但必须禁用
  remote delete；从 C2 迁移到这类 target 使用新的空 prefix，不在旧 prefix 上冒险清理。
- 当前 0.3 源码已经实现 metadata-only renderer/checker、UUID/schema v7/v8、迁移、
  retained wire、local GC、filesystem/R2 target-scoped publication、target GC 与 external
  export；相应 Go unit/fault/mock tests 是本地实现证据。
- frozen `sow/v2`/schema-v6 workspace 可由只读查询与 status 检查；普通 writer 不会顺手
  升级 schema/config。只有显式 `repo migrate` 能进入升级事务，且 pre-commit transition
  可用 `repo migrate --abort` 放弃。
- 真实 APT/DNF HTTP client matrix、completed export 的默认 EL reposync 正例、真实
  nonproduction R2 与第三方 repository manager 仍是 `UNVERIFIED`，不能从 mock 或 v0.2
  的 AlmaLinux 9 `file://` PoC 外推成兼容 PASS。R2 physical delete 是明确禁用能力，
  不是待补的成功路径。

## 版本边界

| 版本/目录 | 物理布局 | 状态 |
| --- | --- | --- |
| `v0.2.0`, `design/v0.2` | root Pool + C2 view-local package hardlinks | 已实现、历史冻结 |
| current 0.3 / `design/next` | root Pool + metadata-only views + computed parent-relative RPM href | 已实现；release evidence pending |

可以把本目录描述为当前 0.3 源码能力；只有
[`specs/acceptance-matrix.md`](specs/acceptance-matrix.md) 对应的 retained live evidence
完成后，才可以把尚未验证的客户端、HTTP/proxy 或真实对象存储单元格写成 release PASS。

## 已实现操作面

```text
sow repo migrate [NAME] [--abort]
sow retain add|ls|rm ...
sow publish TARGET [--abort]
sow gc [TARGET]
sow export rpm-leaf DIST ARCH DIR [--hardlink]
```

`sow gc` 不带参数时执行 Repository-local GC；带 target 时执行 target-scoped maintenance。
filesystem target 只有在 grace 与 exact absence receipt 完整时才条件删除；R2 只保存 exact
candidate report，永不调用 remote delete。

`publish --abort` 只适用于尚未持久化 commit intent 的 active attempt；它删除 filesystem
private stage，但不删除 target object。若这些 add-only object 尚未被后续 checkpoint 接纳，
它们继续作为私有 abandoned-object evidence 存在；后续 publish 可按 path/size/SHA/remote
identity 识别并复用，证据冲突则 fail closed。`repo migrate --abort` 同样只允许 pre-commit。

所有 filesystem target 除比较 provider identity/prefix 外，还比较 endpoint + prefix 展开后的
canonical effective path；任一同路径或祖先/后代重叠均拒绝。external RPM export 也不能与
Repository、`.sow` 或任何 configured filesystem publish root 双向重叠。

target 是 `sow.yml` 的 private publication binding；以下字段是实现接受的最小形状：

```yaml
schema: sow/v3
architectures: [x86_64, aarch64]
repos:
  repo:
    dists: {}
targets:
  local:
    repository: repo
    provider: filesystem
    endpoint: file:///srv/sow-target
    prefix: repos/repo
    public_endpoint: file:///srv/sow-target/repos/repo/
    max_cache_ttl: 0s
    authoritative_workspace: true
    single_writer: true
    exclusive_write_authority: true
  r2:
    repository: repo
    provider: r2
    endpoint: https://account-id.r2.cloudflarestorage.com
    region: auto
    bucket: dedicated-sow-bucket
    prefix: repos/repo
    credential: env://SOW_R2_CREDENTIAL
    public_endpoint: https://repo.example.com/repos/repo/
    max_cache_ttl: 24h0m0s
    authoritative_workspace: true
    single_writer: true
    exclusive_write_authority: true
```

credential 只能引用 `env://NAME` 或 `file:///absolute/path`；引用内容是 strict JSON：
`{"access_key_id":"...","secret_access_key":"..."}`，可选
`session_token`。inline secret 不进入 `sow.yml`。
