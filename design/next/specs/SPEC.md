---
id: SPEC-sow-repository-single-payload
companions:
  - repository-layout.md
  - compatibility.md
  - state-publication.md
  - publication-retention.md
  - migration.md
  - acceptance-matrix.md
  - ../architecture/ARCHITECTURE-SPINE.md
  - ../research/rpm-shared-pool-reposync-compatibility.md
  - ../evidence/2026-08-05-implementation.md
sources:
  - ../../v0.2/specs/spec.md
  - ../../v0.2/architecture/architecture-spine.md
  - ../../v0.2/research/rpm-shared-pool-reposync-compatibility.md
---

> **Canonical forward contract.** 本 SPEC 与 `companions:` 是下一版实现、迁移和验收的完整合同。`design/v0.2` 只保留历史实现与证据，不得覆盖本合同。

> **Evidence status:** implemented in the current 0.3 source tree and covered by
> local unit/fault/mock verification. Live APT/DNF HTTP clients, completed-export
> reposync, real R2, proxy and third-party compatibility remain `UNVERIFIED`; local
> implementation evidence is not a release PASS for those cells.

# SOW Repository-scoped single-payload design

## Why

v0.2 为满足默认 EL `reposync`，在每个 RPM architecture view 中为同一包体建立
C2 hardlink alias。本地 POSIX 文件系统可共享 inode，但对象存储会把每个路径
上传成独立完整对象；Dist、架构、快照越多，远端容量和上传量越接近按视图倍增。
下一版优先保证单个 Repository/publish prefix 内每个 Package Object 只有一个
canonical payload path，同时保留 APT、普通 DNF、直接静态托管、可搬迁交付树、
Generation/Changeset 与安全回收。

## Capabilities

- **CAP-1**
  - **intent:** 运维者可在一个 Repository 中让任意数量的 Dist 与 architecture view 共享同一 Package Object，而不复制包体。
  - **success:** 每个 Built Generation 的 `dists/` 下不存在 RPM/DEB payload；Repository 与任一 publish prefix 内，每个 live Package Object 恰有一个 `pool/...` payload path/key。

- **CAP-2**
  - **intent:** 标准 APT 客户端可从 Repository archive root 消费多个 Dist 和架构。
  - **success:** `Packages` 的 `Filename: pool/...` 在 file/HTTP 客户端上完成 refresh、query、download、checksum 与 install；同一 DEB 被多个 Dist 引用时 Pool 字节不增加。

- **CAP-3**
  - **intent:** 普通 DNF 客户端可从 metadata-only RPM view 获取 root Pool 中的 native 与 neutral 包。
  - **success:** renderer 从实际 view root 与 canonical Pool path 计算 `<location href>`；支持矩阵中的 DNF file/HTTP refresh、query、download、checksum 与 install 通过，且服务器/对象存储只收到规范化后的 canonical `pool/...` 请求。

- **CAP-4**
  - **intent:** Built Generation 与 Changeset 可精确描述并发布一个不含 package alias 的静态 Repository。
  - **success:** terminal steady layout 中，`changes --base 0` 与 `pool/ + dists/` 的 regular-file path、size、SHA-256 完全一致；Repository Built Generation 与 target Publication Checkpoint 分属不同 owner，增量按 payload、metadata、per-view pointer、grace/delete 顺序可恢复执行，任一 payload path 每代至多出现一次。
  - **safety:** commit intent 前的 target attempt 可显式 abandon，只保留 exact add-only object evidence且不复制/删除远端对象；commit intent 后只前向恢复。configured target 已发布的 pointer 不能被普通 local mutation静默撤销。

- **CAP-5**
  - **intent:** 保留 Generation、快照式视图与旧客户端宽限期时不复制 package payload。
  - **success:** 每个保留点只增加 metadata、manifest/refset 与控制状态；GC 仅删除不在 Repository-wide live/retained/snapshot/grace closure 中的 canonical Pool 对象。缺少 atomic conditional delete 的 remote target 必须保留并报告 unreachable keys，不能冒险删除或宣称 physical GC 完成。

- **CAP-6**
  - **intent:** 需要自包含 RPM leaf 或旧镜像工具时，运维者可显式生成独立兼容导出。
  - **success:** export 位于 canonical Repository/publish prefix 之外，默认 copy；hardlink 必须显式 opt-in、同文件系统且目标受控只读。删除 export 不改变 Repository 状态，export 也不成为 Generation、Changeset、publish 或 GC root。

- **CAP-7**
  - **intent:** 运维者可区分协议兼容、普通客户端兼容、镜像工具兼容与对象存储发布兼容。
  - **success:** `check` 验证 href 解析、Repository containment、digest/size、metadata 与 manifest closure，而不要求 `SameFile`/link count；验收矩阵分别报告 APT、DNF、reposync、第三方镜像和真实对象存储结果。

## Constraints

- canonical layout 固定为 `<workspace>/<repo>/{pool,dists}`；不得引入 canonical `release/`、`reposync/`、per-view `pool/` 或其他 package alias 树。
- Package Object、Desired/Built、Generation 与 Changeset 是 Repository-scoped；
  Publication Attempt、Applied Checkpoint、remote inventory/grace/delete evidence 是
  Repository + target publish prefix scoped。不同 Repository/prefix 可各自保存一份。
- APT `Filename` 逐 byte 使用 archive-root-relative canonical `pool/...` path spelling，
  不是 URI；仅 URI retrieval 层对字面 `%` 等 byte 编码。RPM href 使用 POSIX URL path
  语义从实际 view root计算，禁止写死 `../../../` 深度。
- RPM href 不使用 `/pool/...` 根绝对 URL、部署域名、absolute `xml:base`、redirect object 或必须依赖 edge rewrite 的虚拟路径作为 canonical 正确性条件。
- package hardlink 不得出现在 canonical Repository、remote manifest 或 snapshot payload 中，也不得通过 `SameFile`、inode 或 link count 定义包正确性。
- `pool/ + dists/` 整体是 relocation、mirror、authorization 和 publish unit；只复制一个 `dists/<dist>/<arch>` leaf 不受支持。
- 默认 EL `dnf reposync` 不属于成功标准。社区 DNF4/DNF5 的 `--safe-write-path` 只作为显式 best-effort 兼容路径，不改变正式合同。
- Repository 发布鉴权必须覆盖整个 publish prefix，包括 `pool/`；只保护 `dists/` 会绕过访问控制。
- pointer-last、checksum-named metadata、APT by-hash、旧客户端 grace 和删除证据门禁继续成立；
  commit intent 必须早于 mutable APT stable alias 与 protocol pointer。
- direct-static object publication 的可见 commit unit 是一个协议 view；多 view rollout
  允许 bounded mixed generation，并在第一项 mutable APT stable alias 或 protocol pointer
  写入前持久化 forward-only commit intent。完整语义见
  [`state-publication.md`](state-publication.md)。
- 当前 0.3 binary/source implements 本 SPEC 的 canonical layout、迁移、retention、
  export、local/target GC 与 filesystem/R2 publication surface。只有 acceptance matrix
  的对应 live evidence 完成后，才可宣称那些外部 client/target compatibility cells PASS。

## Non-goals

- 全 workspace、全 bucket、全账号或跨 Repository 的 payload 去重。
- 默认 EL8/EL9/EL10 零参数 `reposync`、任意第三方仓库管理器或任意 HTTP proxy 的无条件兼容。
- 把单个 Dist/architecture leaf 定义为可独立复制的完整仓库。
- 用强制 edge router、absolute URL 或全局 CAS 改写现有 Repository 所有权模型。
- 在没有 target-global owner registry 时，为多个独立 workspace 或 out-of-band writer 提供
  重叠 publish-prefix 的分布式互斥；受支持部署依赖 storage namespace 独占写 authority
  与 single writer，provider 不能 prefix-scope 时使用专用 bucket 或同一 Workspace registry。
- 在本 SPEC 中冻结 snapshot CLI、命名策略或远端供应商实现；这里只固定它们不得复制 payload。
- 在没有显式 state export/import 规格时，让另一个实现或丢失本地控制状态的 workspace
  自动接管 live remote publication。此版本只支持保留 Repository state 的恢复，以及
  人工授权、完整 reconcile 后的未来 adoption 流程。

## Success signal

同一 RPM/DEB 同时属于多个 Dist/architecture/retained view 后，本地 Repository 与
每个对象存储 publish prefix 仍只有一个 canonical payload；APT 与普通 DNF 在
file/HTTP 上可安装，`changes --base 0` 可直接重建 `pool/ + dists/`，默认 EL reposync
失败被准确报告为已接受的兼容限制而不是触发 package alias 回归。
