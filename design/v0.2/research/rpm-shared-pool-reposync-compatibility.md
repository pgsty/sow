---
stepsCompleted: [1, 2, 3]
inputDocuments: []
workflowType: 'research'
lastStep: 3
research_type: 'technical'
research_topic: 'SOW RPM shared pool and DNF reposync compatibility'
research_goals: 'Explain the EL architecture-specific hard-link pool, determine why shared physical RPM objects referenced through location href are rejected by reposync, compare APT pool behavior, evaluate root-relative URLs and better repository layouts, and recommend a consistent design.'
user_name: 'Vonng'
date: '2026-08-05'
web_research_enabled: true
source_verification: true
forward_status: superseded-by-design-next
---

# Research Report: technical

> **Superseded decision record.** 本文保留调查过程与被评估的替代方案，但其 workspace/target-global CAS + route-mapper 推荐已撤销。已批准结论是单个 Repository/publish prefix 内 one payload、canonical 根直接 `pool/ + dists/`、RPM parent-relative href、默认 EL reposync 不支持；见 [`../../next/research/rpm-shared-pool-reposync-compatibility.md`](../../next/research/rpm-shared-pool-reposync-compatibility.md)。下文与该结论冲突的段落只能作为 discarded alternative 阅读。

**Date:** 2026-08-05
**Author:** Vonng
**Research Type:** technical

---

## Research Overview

[Research overview and methodology will be appended here]

---

<!-- Content will be appended sequentially through research workflow steps -->

## Technical Research Scope Confirmation

**Research Topic:** SOW RPM shared pool and DNF reposync compatibility
**Research Goals:** Explain the EL architecture-specific hard-link pool, determine why shared physical RPM objects referenced through location href are rejected by reposync, compare APT pool behavior, evaluate root-relative URLs and better repository layouts, and recommend a consistent design.

**Technical Research Scope:**

- Architecture Analysis - repository object store and published-view layout
- Implementation Approaches - RPM-MD and APT metadata generation and mirroring behavior
- Technology Stack - SOW, createrepo_c, DNF/librepo/reposync, APT/reprepro
- Integration Patterns - URL resolution, repository roots, HTTP publication, and mirror tools
- Performance Considerations - byte deduplication, portability, atomic publication, and operational cost

**Research Methodology:**

- Current checkout inspection and reproducible local experiments
- Current official specifications, documentation, and upstream source verification
- Multi-source validation for critical technical claims
- Explicit separation of normative behavior, client implementation behavior, and design inference

**Scope Confirmed:** 2026-08-05

**Non-negotiable publication invariant added:** Within each Repository and target publish prefix, object storage must contain exactly one canonical payload object per Package Object/path. Per-dist, per-architecture, or per-snapshot hardlink aliases are not a valid publication mechanism because object stores materialize every key as a separate full object. Cross-Repository and cross-prefix deduplication is explicitly out of scope. Local inode deduplication must not define repository correctness.

**Priority revision:** Default EL `reposync` compatibility is optional and may be dropped. The architecture should first maximize single-key object storage, ordinary DNF/APT consumption, direct static hosting, relocatability, `file://` where feasible, simple mirroring, and protocol-native metadata; reposync must not force abandonment of several stronger properties.

## Technology Stack Analysis

### Programming Languages and Repository Model

SOW 的活动 v2 实现使用 Go 直接生成 RPM-MD XML 与 APT control metadata，并用 SQLite 保存 Package Object、Dist Membership 和 Built Generation。RPM 与 DEB 共享“一个 canonical package object、多份索引 membership”的逻辑模型，但发布协议的寻址基准不同，因此不能仅靠统一目录名得到相同的物理布局。

当前 checkout 中，RPM renderer 把每个 `dists/<dist>/<family>` 当作一个独立 RPM repository root；它为该 view 创建 `pool/...` regular hardlink，再把同一个安全的 `pool/...` 写入 `<location href>`。DEB renderer 则把 `Filename: pool/...` 直接写入嵌套在 `dists/.../binary-*` 下的 `Packages`，包体只存在于 archive-root `pool/`。关键实现见 [`render_packages.go`](../../../internal/v2/managed/render_packages.go) 和 [`packages.go`](../../../internal/aptrepo/packages.go)。

这不是 EL9 专用分支：`v0.2.0` 的所有 managed RPM architecture view 都使用 C2；EL9 只是当前 PoC 的实际客户端环境。这里描述的是已发布 v0.2 实现，下一版已明确取代该布局。

_语言与数据模型：Go、SQLite、RPM-MD XML、Debian control paragraphs。_
_置信度：高，来自当前 checkout 的直接源码检查。_

### RPM-MD、DNF 与 createrepo_c

`createrepo_c` 把 `location_href` 定义为包在 repository 中的相对位置，并另有 `location_base`；DNF 下载层把 package location 和可选 base URL 分开交给 librepo。[createrepo_c 官方 API](https://rpm-software-management.github.io/createrepo_c/python/lib.html)将 `location_href` 描述为 relative location；[DNF 官方源码](https://github.com/rpm-software-management/dnf/blob/master/dnf/repo.py#L1906-L1929)显示 `pkg.location` 被作为 `relative_url`，`pkg.baseurl` 被作为 `base_url`。

RPM repository 的常规部署单位就是包含 `repodata/` 的 baseurl 目录。Fedora 的官方开发文档建议“每个 distribution-architecture 一个目录”，在该目录运行 `createrepo_c`，再把这个目录暴露为 `baseurl`。[Fedora RPM repository 指南](https://developer.fedoraproject.org/deployment/rpm/about.html#create-yum-dnf-repository)。这解释了为什么 SOW 的每个架构 view 都被客户端视作完整且独立的仓库根。

普通 DNF 能下载 `../../../pool/...`，因为远端 URL 解析允许它从 view baseurl 回到共享 pool；但 `reposync` 还必须决定本地镜像文件名。EL9 的插件执行：

```python
pkg_download_path = os.path.realpath(os.path.join(repo_target, pkg.location))
if not pkg_download_path.startswith(os.path.join(repo_target, '')):
    raise Error("outside of download path")
```

因此 `../../../pool/...` 规范化后逃出 `<download-path>/<repoid>/`，在任何网络下载之前就被拒绝。上游当前实现仍保留同一个 containment check，只是允许用户显式扩大 `safe_write_path`；见 [`dnf-plugins-core` reposync 源码](https://github.com/rpm-software-management/dnf-plugins-core/blob/master/plugins/reposync.py#L1217-L1256)。

当前固定 AlmaLinux 9.8 镜像实测为 `dnf 4.14.0`、`python3-dnf-plugins-core 4.3.0-26.el9`，帮助中没有 `--safe-write-path`。上游在 dnf-plugins-core 4.4.1 才加入该参数；[官方发布说明](https://dnf-plugins-core.readthedocs.io/en/latest/release_notes.html#release-notes)与[官方 reposync 文档](https://dnf-plugins-core.readthedocs.io/en/latest/reposync.html)都说明它专门用于 `../packages_store/...` 这类 repository 外位置，并警告允许范围内的文件可能被覆盖。

更关键的是，Red Hat 明确没有把该选项交付到 RHEL：其原因是可能重新引入 reposync 路径穿越漏洞 CVE-2018-10897。[Red Hat Bugzilla 1898089](https://bugzilla.redhat.com/show_bug.cgi?id=1898089)记录了 WONTFIX 决定；[RHSA-2018:2284](https://access.redhat.com/errata/RHSA-2018%3A2284)说明原漏洞是 reposync 路径校验不当导致目录穿越。

_工具栈：createrepo_c、RPM-MD、DNF/libdnf/librepo、dnf-plugins-core reposync。_
_置信度：高；当前 EL9 二进制、上游源码和厂商安全决策互相印证。_

### APT、reprepro 与共享 Pool

APT 的协议模型不同。sources entry 中的 URI 本身就是 archive root；`dists/<suite>/.../Packages` 只是从该根取到的索引。`Packages` 中的 mandatory `Filename` 明确定义为相对于 repository base directory 的 canonical path，并建议不得包含 `.` 或 `..`。Debian 的格式文档同时明确说明，为避免文件重复，包通常只保存在 archive-root `pool/` 中。[Debian Repository Format](https://wiki.debian.org/DebianRepository/Format#Overview)。

所以：

```text
deb https://host/archive stable main
index    = https://host/archive/dists/stable/main/binary-amd64/Packages
Filename = pool/main/p/pkg/pkg.deb
payload  = https://host/archive/pool/main/p/pkg/pkg.deb
```

索引的位置不会改变 `Filename` 的基准。APT 无需通过 `../../../pool` 从 architecture index 目录爬回 archive root，也就不需要为每个架构创建包体 hardlink alias。

`reprepro` 的实现也遵循这一模型：它在同一个 repository base 下管理 `pool/` 与 `dists/`，在数据库中维护哪些 distribution 引用 pool 文件，并提供 `rereference`、`dumpunreferenced` 和 `deleteunreferenced`；同一包被不同 distribution 使用时不复制 pool 文件。[reprepro 官方 Debian manpage](https://manpages.debian.org/trixie/reprepro/reprepro.1.en.html)。

APT 仍可能为 `by-hash` index 创建 hardlink，但那是索引原子获取/保留策略，不是为了解决 package payload 从各架构 view 的寻址。

_工具栈：APT/libapt、Packages/Release/InRelease、reprepro、archive-root pool。_
_置信度：高，来自 Debian repository format 与 reprepro 文档。_

### Filesystem and Storage Technologies

C2 依赖 POSIX 同文件系统 hardlink：root pool path 与每个 RPM view alias 是同一 inode，因而本地只有一份数据块，但有多个目录项。`noarch` 会出现在所有 architecture view；native RPM 只进入匹配 view。当前 `sow check` 不仅校验字节，还要求 alias 与 canonical pool object 是同一文件，因此 hardlink 是 managed workspace 的不变式，而不是可选性能优化。

这一模型的边界很清楚：

- 同文件系统本地工作区：一份数据块，多路径，自包含 file/HTTP repository。
- 普通目录复制但不保留 hardlink：客户端仍工作，但目标端变成多份字节。
- S3/R2/COS 等对象存储：对象 key 没有 inode/hardlink 语义，每个 view path 都是独立对象；远端容量与上传量不再去重。
- 不支持 hardlink或跨设备的构建目录：当前构建硬失败。

因此 C2 同时承担了两件事：本地容量去重，以及把每个 architecture baseurl 物化成 reposync 认可的自包含普通文件树。前者是存储优化，后者是兼容性要求；把两者绑成一个强不变式，是设计复杂度的主要来源。

_存储栈：POSIX filesystem hardlinks、regular-file static tree、object storage publication。_
_置信度：高，来自当前实现与 PoC 的 inode/copy 验证。_

### Development and Verification Tools

当前 PoC 使用 pinned AlmaLinux 9.8、DNF 4.14.0、RPM 4.16.1.3 与 createrepo_c 0.20.1，覆盖 native + noarch、forced aarch64，以及 `makecache`、`repoquery`、download、install 和 `reposync`。原始 `../../../pool/...` 只有 reposync 失败；C2 `pool/...` 全部通过。证据位于 [`test/poc/yum-relative-pool`](../../../test/poc/yum-relative-pool/README.md)。

但兼容矩阵仍有限：它不能自动外推到 Yum 3、所有 EL minor、DNF5、zypper 或所有 object-store delivery。上游 DNF4 4.4.1 和 DNF5 已有 `--safe-write-path`，而 RHEL 8/9 downstream 因安全策略不提供它，说明这里必须分别记录“协议可表达”“社区客户端可配置”和“EL 默认工具可无参数消费”三个层次。

### Cloud Infrastructure and Deployment

部署方式决定哪些替代方案成立：

- 纯静态目录、`file://`、任意 HTTP server、可搬迁离线副本：要求每个 baseurl 下的 href 自包含；C2 满足。
- Nginx/CDN rewrite：可让 view-local `pool/...` 在服务端映射到 root pool，不需要 hardlink，但 `file://` 和普通静态复制不再成立。
- symlink：本地 HTTP/file 可用，但对象存储与不保留 symlink 的复制器不具备同样语义。
- absolute URL 或 absolute `xml:base`：可以把包体放到独立 canonical origin，但 metadata 绑定部署位置，镜像后的 metadata 不再天然自包含。
- parent-relative href + upstream `--safe-write-path`：保留单 pool，但要求镜像操作者使用额外高风险参数，且 RHEL/EL 默认 reposync 不支持。

### Technology Adoption Trends

行业默认仍是两种不同模型：APT 以 archive root 为寻址与去重边界；RPM/DNF 通常以每个 distribution/architecture baseurl 为完整 repository 边界。社区版 DNF4/DNF5开始为跨 repository-root payload 提供显式 escape hatch，但 EL downstream 的安全决策说明，这不能当作通用仓库契约。

由此得到技术栈层面的初步判断：当前 APT/RPM 不一致有协议与工具链依据；真正值得重新评估的不是“为何不强行一致”，而是 SOW 是否必须同时保留“每架构独立 RPM baseurl”“无特殊服务器的自包含静态树”“标准 EL reposync 零额外参数”“远端仍只存一份字节”这四个目标。现有 C2 只同时满足前三个，并仅在本地满足第四个。

## Integration Patterns Analysis

### Revised Non-Negotiable Boundary

对象存储以 object key 为身份，不存在 POSIX inode 或 hardlink。Amazon S3 的数据模型是 flat object namespace，复制操作创建另一个 object；Cloudflare R2 同样以每次 `put(key, value)` 创建的 key/object 为存储单位。[Amazon S3 object-key model](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html)、[Amazon S3 CopyObject semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/copy-object.html)、[Cloudflare R2 Workers API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/)。因此发布正确性必须新增硬约束：每个 Repository/publish prefix、每个 Package Object/canonical Pool path 只能有一个 payload key；workspace hardlink 最多是私有事务或显式导出优化，不能进入 remote manifest 语义。

现存完整发布路径（V1 `internal/cli`；当前活动 V2 明确尚未纳入 publish/snapshot）违反这一约束并非偶然。YUM snapshot payload 被分类到 `.sow/gated/snapshots/<snapshot>/yum/...`，随后显式改为 `ObjectCopyImmutable`，以当前稳定包作为 server-side copy source；见 [`publish_plan.go`](../../../internal/cli/publish_plan.go#L1486) 与 [`publish_plan.go`](../../../internal/cli/publish_plan.go#L1663)。[`validateSnapshotCopy`](../../../internal/publish/plan.go#L1131)还把“snapshot 下必须有 Packages payload key”固定成协议校验。相反，APT snapshot pool 已使用 `ObjectReuseImmutable`；未来 V2 发布模型中的 YUM 应采用同样的存储引用原则，而不是继承该复制协议。

### Addressing API: Separate URL Namespace from Object Namespace

RPM-MD 已经把 package remote base 与 relative location 分为两个字段。libdnf 文档把 `<location xml:base>` 暴露为 package base URL，把 `<location href>` 暴露为 relative location；DNF 下载时再分别把 `pkg.baseurl` 与 `pkg.location` 传给 librepo。[libdnf Package API](https://libdnf.readthedocs.io/en/latest/api/libdnf_rpm_package.html)、[DNF payload implementation](https://github.com/rpm-software-management/dnf/blob/master/dnf/repo.py#L1906-L1929)。reposync 的本地 containment check 则只依据 `pkg.location`。[dnf-plugins-core reposync](https://github.com/rpm-software-management/dnf-plugins-core/blob/master/plugins/reposync.py#L1217-L1256)

这给出两个可行集成模式：

1. **Absolute `xml:base`：** metadata 使用安全的 `href="pool/..."`，但把远端 base 固定到 canonical payload origin。协议与 EL9 客户端可工作，但 metadata 会绑定部署域名；reposync 下载的 metadata 仍指向原 origin，镜像不再自包含。
2. **Closed URL namespace + server-side mapping：** metadata 只写 `href="pool/..."`。客户端仍请求 `<view-base>/pool/...`，HTTP/edge 层把该 URL 内部映射到唯一 canonical object key。reposync 的本地路径保持在 repo root 内；它下载后的副本自然包含真实 `pool/...` 文件，因此又成为无需路由的普通静态镜像。

第二种模式把三个概念明确分开：

| 层 | 示例 | 持久性 |
|---|---|---|
| Canonical object key | `pool/sha256/02/<digest>/<nevra>.rpm` | 全 workspace/target 唯一、不可变 |
| Immutable metadata key | `.sow/generations/42/yum/el9/x86_64/repodata/...` | 每 generation 一份 metadata |
| Client URL | `/_sow/v1/g/42/yum/el9/x86_64/pool/sha256/...rpm` | 虚拟路由，可多对一映射 canonical key |

SOW 当前已经区分 `RemoteKey` 与 `CDNPath`，并通过 generation-pinned mirrorlist 暴露 `/_sow/v1/g/<generation>/...`；因此这不是引入全新的发布层，而是把已有 metadata route 机制扩展到 payload。当前本地 Nginx generator 也已经为 generation route 生成 alias，只是仍假设 package 位于 generation tree；见 [`nginx.go`](../../../internal/serving/nginx.go#L381)。Nginx 原生支持 internal URI rewrite；Cloudflare Worker 可通过 route 读取任意 R2 key；EdgeOne 支持正则回源 URL rewrite。[Nginx rewrite module](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html)、[Cloudflare Workers routes](https://developers.cloudflare.com/workers/configuration/routing/routes/)、[Cloudflare R2 binding](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/)、[EdgeOne origin URL rewrite](https://cloud.tencent.com/document/product/1552/71009)。

### Current EL9 Interoperability Experiment

在 AlmaLinux 9.8、DNF 4.14.0、dnf-plugins-core 4.3.0、libdnf 0.69.0、librepo 1.19.0 上进行了两个临时 PoC：

- absolute `xml:base` + safe `href`：makecache、download、install、reposync 全通过；但 `reposync --download-metadata` 原样保留 absolute base，从新镜像使用 metadata 时 payload 仍回源原站。
- 无 `xml:base`、仅 `href="pool/..."`，发布端 HTTP mapper 把 `/view/pool/...` 映射到唯一 `objects/<sha>.rpm`：download、install、reposync 全通过。reposync 输出 `view/pool/...rpm` 与 `view/repodata/...`，随后由普通静态 HTTP server 提供该副本时仍可正常安装。

这证明 reposync 要求的是**客户端 URL namespace 闭合**，并不要求对象存储中存在同名 key，更不要求 hardlink。URL-to-object mapping 可以在发布网关完成。

### Snapshot and Generation Integration

正确的 snapshot 应类似 Git commit：保存 metadata generation、ref vector 和 payload digest set，而不是复制 blobs。建议的发布顺序为：

1. 对每个新 digest 执行 create-if-absent canonical payload PUT；
2. 上传只包含 repodata 的 immutable generation；
3. 写入 snapshot manifest 或 channel pointer；
4. 翻转 generation-pinned mirrorlist；
5. GC 只删除未被任何 channel、retained generation、snapshot 或 grace window 引用的 canonical payload。

同一个 snapshot 无论包含多少 dist/arch，都只增加 metadata、manifest 和 route state；重复 package payload 增量为零。恢复历史 generation 同样只重用 object references，不做 CopyObject。

### Conditions That Must Be Relaxed

要满足 object-store single-payload invariant，应明确放宽或删除以下旧条件：

- 删除“C2 hardlink 是冻结发布布局”；hardlink 只能出现在显式的 disposable offline materialization 中。
- 保留 Repository 作为去重、锁、Generation、Changeset、publish prefix 与 GC 边界；不同 Repository/prefix 不去重是已接受取舍。
- 保留完整 Repository root 的 `file://`、普通 HTTP 与静态搬迁；只放弃单 architecture leaf 自包含。
- 保留 `pool/ + dists/` 到对象 key 的一对一发布；publish 仍按 payload/metadata/pointer/delete phase 执行，但不要求 URL-to-object route mapper。
- raw static YUM baseurl 继续是普通 DNF 的正式入口；默认 EL reposync 降为 unsupported，不能反向强迫 payload alias。

“workspace 必须位于 repository 根”可以作为 root-bound 安全约束，也便于拥有统一 `pool/`，但它本身不能修复 reposync：reposync 检查的是镜像端 `<download-path>/<repoid>`，不知道构建机 workspace 在哪里。最终采用的约束是**每个 Repository/publish prefix 保持一个 root Pool，所有 Dist/retained view 的 metadata 引用该 Pool，whole Repository 是 mirror/auth/GC unit**；不建立 workspace-global payload namespace，也不强制 HTTP mapping。

### Integration Security and Operations

每个 Repository publish prefix 的鉴权必须覆盖 `pool/` 与 `dists/`，不能只保护 view path。若一个静态 prefix 内需要互斥 public/private ACL，应拆分 Repository/prefix 或使用统一 private origin + edge authorization。任何可选 mapper 都只能接受 metadata 允许的 canonical path grammar，并正确处理 `GET`、`HEAD`、Range、ETag、Content-Length 与 checksum；它不是 canonical layout 的必需组件。[Cloudflare Workers cache integration](https://developers.cloudflare.com/cache/interaction-cloudflare-products/workers/)、[EdgeOne cache guidance](https://cloud.tencent.com/document/product/1552/96052)。

S3 website redirect object 只能在 website endpoint 生效，REST endpoint 会返回 redirect object 本身，因此不能作为 R2/COS/多目标通用契约。[Amazon S3 website redirect behavior](https://docs.aws.amazon.com/AmazonS3/latest/userguide/how-to-page-redirect.html)。Combined multi-architecture RPM repo 可以减少 metadata/view 数量，但不能消除跨 snapshot payload duplication，也不是根本解法。

在仍需纯静态 object-key = URL-path 托管时，可把“同一 EL major + 同一 channel”的 x86_64、aarch64、noarch 合并成一套 RPM-MD，以减少每架构视图；DNF/repoquery 会按 package arch 求解，reposync 则可用 `--arch=<target> --arch=noarch` 过滤。[DNF reposync options](https://dnf-plugins-core.readthedocs.io/en/latest/reposync.html)。但不同 EL major、不同 snapshot 仍需要独立 metadata root，所以它只能降低倍数，不能替代全局 CAS + route mapping。

### Integration-Level Recommendation

本研究最初提出的 workspace/target-global CAS + route-aware HTTP namespace **未被采纳**。最终首选模式是：**Repository-scoped root Pool + metadata-only `dists/` + computed parent-relative RPM href + object-key-equals-canonical-path**。Absolute/root-relative URL、redirect objects、强制 mapper 与 per-view package hardlinks均不进入正式发布契约；默认 EL reposync 明确降为 unsupported，standalone 需求由 whole-root mirror 或 external export 解决。
