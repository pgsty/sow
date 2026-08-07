# RPM shared Pool, reposync, and object-storage compatibility

状态：2026-08-05 设计定案依据。规范结论以
[`../specs/SPEC.md`](../specs/SPEC.md) 与
[`../architecture/ARCHITECTURE-SPINE.md`](../architecture/ARCHITECTURE-SPINE.md)
为准。

证据纪律：本文区分 **observed**、**officially documented**、**implemented locally**
与 **unverified**。当前 renderer/publisher/export 已实现并有 unit/fault/mock evidence；
除 pinned AlmaLinux 9 `file://` PoC 外，不把本地测试写成真实客户端或对象存储兼容
PASS。官方链接访问于 2026-08-05，最终 release evidence 仍须固定
client/image/source revision。

## Executive conclusion

已批准采用 Repository-scoped archive-root shared Pool：canonical tree 仍是根目录直接
`pool/ + dists/`，RPM package location 从 architecture view 使用计算出的父级相对
href 指向 root Pool。一个 Repository/publish prefix 内，每个 Package Object 只有
一个 payload path/key；不同 Repository/prefix 不去重。

产品合同的代价是默认 EL `dnf reposync` 不再受支持。已保留的实际失败只覆盖 pinned
AlmaLinux 9/DNF4；其余 EL/DNF 是未验证矩阵项。这个代价比 per-view/per-snapshot payload
复制、强制 edge mapper、部署域名绑定或 target-global CAS 更小，也更符合现有
Repository/Generation/Changeset 所有权。需要自包含交付时，设计要求使用绑定 settled
Generation 的 whole-root controlled handoff 或显式 external export；两者已有实现层，
但真实 relocation/client 与 reposync consumption 仍待验收。

## What the v0.2 PoC actually proved

[`test/poc/yum-relative-pool`](../../../test/poc/yum-relative-pool/README.md)
在 pinned AlmaLinux 9.8 / DNF 4.14.0 上证明：

- `../../../pool/...` 可被普通 DNF makecache、repoquery、download 和 install 消费；
- 同一 metadata 被默认 `dnf reposync` 拒绝，因为规范化后的本地写入目标逃出
  `<download-path>/<repoid>`；
- C2 view-local `pool/...` hardlink aliases 可以让该 reposync 通过；
- 不保留 hardlink identity 的 copy 仍能工作，但会把每个 alias 变成独立完整文件。

因此 PoC 证明的是“普通 DNF 路径有效、reposync 本地 containment 不兼容、C2 用
payload duplication 换 reposync”，而不是“RPM 协议要求每 view 一份包”。v0.2
当时把 reposync 设为硬门禁，所以选择 C2；本次用户明确重排优先级后，该产品选择
可以且应当撤销。

## Why reposync rejects a valid package URL

createrepo_c API 将 RPM-MD `location_href` 描述为 package relative location。目标
AlmaLinux 9/DNF4 fixture 以 repository base URL 解析它，所以该 view 可以回到同一
archive root Pool。[createrepo_c 官方 API](https://rpm-software-management.github.io/createrepo_c/python/lib.html)

createrepo_c API 是生产工具字段说明，不是所有 RPM-MD consumer 的 normative URI
保证；parent segments、`xml:base` 与 escaping 必须逐客户端验证。

reposync 还要选择本地落点。上游文档规定每个下载仓库默认位于
`<download-path>/<repoid>`，`--safe-write-path` 用于显式允许写到 repo 目录之外，
并警告允许范围内的任意文件可能被覆盖。
[DNF4 reposync](https://dnf-plugins-core.readthedocs.io/en/latest/reposync.html)
与 [DNF5 reposync](https://dnf5.readthedocs.io/en/stable/dnf5_plugins/reposync.8.html)
都保留这个区分。

Red Hat 对相对 parent path 的问题记录同时指出，普通 download/install 能工作；
RHEL 因可能重新引入 CVE-2018-10897 路径穿越风险，未把 `--safe-write-path` 作为
受支持能力交付。因此 SOW 不能把上游可选 flag 外推成默认 EL 合同。
[Red Hat Bug 1898089](https://bugzilla.redhat.com/show_bug.cgi?id=1898089)

`--safe-write-path` 的 multi-view output、碰撞与 metadata closure 尚无 retained PoC，
只能标为 documented/unverified。

已验证的 AlmaLinux 9 结论是：reposync 拒绝的是**镜像机本地写边界**，而同一 fixture
的普通 DNF 可达。改变构建机 Workspace 根、使用硬链接或上传方式都不会改变该客户端
的 containment check；其他 EL/DNF 不能由此自动外推。

## Why APT does not need aliases

APT source URI 定义 archive root，`dists/.../Packages` 只是 index 位置；mandatory
`Filename` 相对 repository base directory。Debian repository format 还明确说明，
为避免重复，package 通常统一放在 archive-root `pool/`。
[Debian Repository Format](https://wiki.debian.org/DebianRepository/Format)

```text
archive root = https://host/repo
index        = /repo/dists/noble/main/binary-amd64/Packages
Filename     = pool/main/p/pkg/pkg_1.0_amd64.deb
payload      = /repo/pool/main/p/pkg/pkg_1.0_amd64.deb
```

APT index location 不改变 `Filename` 的解析基准，所以不需要 `../../../`，更不需要
每架构 package hardlink。APT by-hash 的额外 path 是 index metadata 的原子获取与
保留机制，不能类比成 payload alias。

## URL path versus object key

RPM href 可以含 parent segments；客户端把它与 view URL 合并后，实际请求是同一
publish prefix 下规范化的 `pool/...` URL。libcurl 默认消解 URL 中的 `/../` 和
`/./`；只有显式 `CURLOPT_PATH_AS_IS` 才保留它们。
[libcurl `CURLOPT_PATH_AS_IS`](https://curl.se/libcurl/c/CURLOPT_PATH_AS_IS.html)

这只证明 libcurl 的默认行为，不证明 librepo、proxy、WAF、CDN 或对象存储 endpoint
没有覆盖该选项；下面的 request path 是 approved expected mapping，必须由真实 HTTP/
object-target 请求日志升格为 observed PASS。

对象存储实际上传的是 canonical tree path，不是 href 字符串：

```text
metadata href: ../../../pool/p/pkg/pkg.rpm
request path:  /<prefix>/pool/p/pkg/pkg.rpm
object key:    <prefix>/pool/p/pkg/pkg.rpm
```

S3 的 key 唯一标识 object，prefix 只是 flat namespace 的组织方式；不同 alias key
就是不同 object。AWS 也提示 period-only path segments 会被不同工具规范化并导致
不一致，因此 manifest/key 中必须只使用 canonical `pool/...`，绝不上传含 `..` 的
key。[Amazon S3 object-key model](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html)

## Alternatives evaluated

| Alternative | Ordinary DNF evidence | Default reposync | Static prefix / relocation | One payload key | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| C2 per-view hardlinks + `pool/...` | observed DNF4/file | observed DNF4 PASS | copy works; payload multiplies | no | retire |
| Parent-relative href to root Pool | observed one DNF4/file fixture | observed DNF4 FAIL | whole-root HTTP/object unverified | by layout | adopt requirement |
| Root-leading `/pool/...` href | client-dependent | source-inspected/unretained; fixture pending | non-portable semantics | unclear | reject |
| Absolute `xml:base` | reported; evidence not retained here | reported downloadable | binds metadata to origin | by layout | reject canonical use |
| Edge URL-to-object mapper | technically viable, external | can close URL namespace | requires special serving | yes | optional external projection only |
| View symlink to root Pool | observed DNF4/file | observed PASS | object store cannot preserve semantics | no portable key model | reject |
| Combined multi-arch RPM repo | unverified here | tool-dependent | reduces views only | by layout | independent optimization |
| External copy/hardlink export | locally implemented | must PASS before fallback claim | standalone derived artifact | canonical prefix unchanged | adopted implementation |

### Root-absolute href is not the missing option

按通用 URI 解析，`href="/pool/..."` 是 host-root-relative；但目标 EL9 DNF4 的
package/repo URL 构造会先 `lstrip("/")`，可能把它当成 base-relative。相反，同一版本
reposync 的本地 `join` 会把 leading slash 当 absolute target 并触发 containment。
这种 client-dependent 双重语义不能稳定表示 Repository root，也不能作为 non-root
prefix、file/offline relocation 或镜像安全合同；因此仍拒绝，但不再声称所有 DNF 都会
请求 host-root。

### A route mapper solves a different product

让 metadata 写安全的 view-local `pool/...`，再由 Nginx/Worker 把多个 URL 映射到
一个 object，确实可以同时满足 reposync 和远端单 object。但代价是：canonical
Repository 不能再被任意静态 server、`file://` 或 object-key-equals-path 直接托管；
每个 target 都必须实现并验证 GET/HEAD/Range/cache/auth rewrite。SOW 当前目标无需
为一个可放弃的 reposync 命令引入这个强依赖，因此只把 mapper 留作外部兼容投影。

## Final trade-off

批准保留（待 next acceptance）：

- 既有 Repository ownership 与 `pool/ + dists/` 根布局；
- APT archive-root Pool；
- 普通 DNF file/HTTP consumption（目前只有 pinned DNF4/file 局部证据）；
- metadata 不绑定域名、完整 Repository 可搬迁；
- terminal `changes --base 0` 直接对应可复制/可上传的物理树；
- 每个 Repository/publish prefix 一个 canonical payload；
- snapshot/retained generation 零 payload copy；
- object-key-equals-path 的普通静态发布。

对象存储的能力仍按 operation 分层：Cloudflare R2 是首个真实 static-publication target，
但它当前不提供本设计要求的 atomic conditional delete，因此只验收 publish/recovery 与
remote-delete fail-closed。已有 C2 prefix 迁移到 R2 时使用新空 prefix；不能把无条件删除
包装成安全 GC。

放弃或降级：

- 默认 EL reposync；
- 单 architecture leaf 自包含；
- 未实测第三方 mirror/proxy 的普遍兼容。

绕开：

- whole-root controlled handoff 保留 canonical layout（实现层存在，live relocation 未验证）；
- 支持 `--safe-write-path` 的社区客户端可显式试验，当前不承诺可用 fallback；
- 真正需要 standalone leaf 时使用并验收 `sow-rpm-leaf-v1` external export，默认 copy、
  hardlink 仅限可信只读且明确退出 hostile-writer 保证的本地优化。

这是一个局部且可解释的兼容性让步，不需要改变 Repository、Workspace、Dist、
Generation 或 Changeset 的主要产品模型。
