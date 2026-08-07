# Repository layout and addressing contract

## Canonical tree

```text
<workspace>/
├── sow.yml
├── .sow/
│   ├── <repo>.db
│   └── <repo>/{stage,recovery,pending,retained,transitions}
└── <repo>/                       # Repository root / publish prefix root
    ├── pool/                     # canonical package payloads only
    │   └── <prefix>/<source>/<filename>
    └── dists/                    # metadata and protocol pointers only
        ├── <rpm-dist>/<arch>/repodata/...
        └── <deb-dist>/main/binary-<arch>/Packages...
```

Repository 根下只有既有的 `pool/` 与 `dists/` 两个公开主目录。`.sow` 是 Workspace
私有控制面，不在 Repository publish prefix 内。任何 `release/`、`reposync/`、
`dists/.../pool/`、per-generation payload tree 或 per-snapshot payload tree 都不是
canonical layout。

一个 Repository 在一个 target 上映射到一个 publish prefix：

```text
local:  <workspace>/<repo>/pool/p/pkg/pkg.rpm
remote: <publish-prefix>/pool/p/pkg/pkg.rpm
```

路径一对一映射；不把 href 字面量（其中可能含 `..`）当 object key。客户端先按
URL 语义把 view URL 与 href 解析为 canonical `/.../pool/...` 请求，远端实际只
存储规范化后的 `pool/...` key。当前 renderer/checker 与 filesystem/R2 mocked publisher
已经实现这一映射；真实 HTTP client/proxy/object-target 仍须按 acceptance matrix 实测。

## APT addressing

APT source URI 指向 Repository archive root。`Packages` 位于 `dists/...`，但包体
字段始终相对 archive root：

```text
index:    <repo>/dists/noble/main/binary-amd64/Packages
Filename: pool/p/pkg/pkg_1.0_amd64.deb
payload:  <repo>/pool/p/pkg/pkg_1.0_amd64.deb
```

一个 DEB 可被任意数量的 suite/component/architecture index 引用，不增加 payload
path。APT by-hash 可为小型 index metadata 建立额外路径；它不是 package payload
去重例外。

`Filename` 的值是 **canonical Repository path 的原始 ASCII spelling**，不是已经生成的
URI reference。APT renderer 必须逐 byte 写入 `PackageObject.PoolPath`，不做 URL quoting、
decode 或大小写归一化。DEB 的 managed basename 以 ASCII 字母/数字开头、以 `.deb`
结尾；中间只允许 `A-Za-z0-9+._:~-`，或 Debian epoch 常见的字面 `%3a`/`%3A`；其他
`%HH`、孤立 `%`、slash、backslash、控制字符与 encoded dot/separator 全部拒绝。DEB
source 继续服从 `[a-z0-9][a-z0-9+.-]*`。因此字面 `%2F` 永远不能成为合法 DEB Pool
component。

这也固定了 encoding layer：

```text
canonical path/key: pool/f/foo/foo_1%3a2_amd64.deb
Packages field:     Filename: pool/f/foo/foo_1%3a2_amd64.deb
canonical URI path: pool/f/foo/foo_1%253a2_amd64.deb
decode once:        pool/f/foo/foo_1%3a2_amd64.deb
```

URI 构造层才把上述字面 `%` 编成 `%25`；`Packages` renderer 绝不能抢先做这一步。
file/HTTP checker 必须分别验证 raw field 等于 Pool path，以及 URI decode 恰好一次后等于
同一 path。`%3a` 与 `%3A` 是两个可保留的输入 spelling；实现不得互相改写，且既有的
case-insensitive full-path collision 门禁仍适用。`+` 与 `:` 等合法 path byte 也必须进入
file/HTTP golden vectors，但客户端可使用任何等价 URI spelling，服务端解析后的 key 必须
唯一等于 canonical Pool path。

## RPM addressing

每个 `dists/<dist>/<arch>` 是 DNF baseurl 对应的 RPM view。metadata 的 package
location 从该 view root 指向 Repository root Pool。例如：

```text
view:    dists/el9/x86_64
payload: pool/p/pkg/pkg-1.0-1.x86_64.rpm
href:    ../../../pool/p/pkg/pkg-1.0-1.x86_64.rpm
```

`../../../` 只是这个深度下的结果，不是模板常量。renderer 必须：

1. 分别取得规范化的 Repository-relative view root 和 canonical Pool path；
2. view retrieval base 是 directory URI，canonical spelling 必须以 `/` 结尾；HTTP 与
   `file:` checker 都使用最终实际 base URI，而不是只验证 filesystem string；
3. 对未转义的 ASCII Repository path segments 使用 POSIX segment 计算相对路径；只有
   计算生成的前导 navigation segments 可为字面 `..`；
4. data segment 的 byte-to-URI 规则固定为 RFC 3986 unreserved
   `ALPHA / DIGIT / "-" / "." / "_" / "~"` 原样保留，其余 byte 使用大写 `%HH`；
   `%` 永远是数据并编码为 `%25`，不能把输入当成预转义 URI；
5. 完整 URI escaping 完成后再做 XML attribute escaping；不编码 `/`，不产生
   query/fragment；
6. 以标准 URI relative-reference 解析把 href round-trip 到 view retrieval base，decode
   恰好一次后必须等于原 canonical Pool path；
7. 拒绝解析后离开 Repository、落到 `dists/` payload alias、出现空/`.` data segment、
   backslash、NUL 或非 canonical escaping 的结果。

`check` 与 renderer 必须调用同一个纯函数，不能各自实现路径深度算法。

Golden vectors 至少包含字面 `pkg%2Fdebug+1.rpm` →
`pkg%252Fdebug%2B1.rpm`、`:`, `^`, encoded dot/separator、无尾斜杠 base 与 non-root
publish prefix。公共 path grammar 当前只接受下面定义的 ASCII component，不存在
Unicode normalization 分叉。

### 为什么不用 `/pool/...`

通用 URI resolver 会把 `/pool/...` 解释为 host-root；但目标 EL9 DNF4 会先
`lstrip("/")`，可能把同一值重新当成 package/repository-base-relative，而 reposync
又会在本地 `join` 中把它视为绝对路径并触发 containment。也就是说其语义随客户端
变化，既不能可靠表示 host-root，也不能可靠表示 Repository root；它还破坏
non-root prefix、`file://` 搬迁和镜像安全。因此 canonical metadata 禁止 leading slash，
并用单独的 EL9 ordinary/repo-sync fixture 保留这一负结论。

### 为什么不用 absolute `xml:base`

absolute base 会把 metadata 绑定到一个 origin。镜像带走 metadata 后仍可能回源，
同一目录无法在 file、HTTP、多域名和对象存储 prefix 之间无修改搬迁。它只可作为
外部系统自己的非自包含投影，不进入 SOW canonical metadata。

## Relocation and mirroring unit

只有完整 Repository root 是可搬迁单元：

```text
copy <repo>/pool/  -> <destination>/pool/
copy <repo>/dists/ -> <destination>/dists/
```

目的地可以换绝对目录、host、bucket 或 prefix，只要两棵子树的相对关系不变。
单独复制 `dists/<dist>/<arch>` 会丢失 href 指向的 Pool，明确不受支持。需要自包含
leaf 时必须走 compatibility export。

## Path identity and collision

- Package Object 继续以最终完整字节 SHA-256 标识。Managed Pool path function
  version `sow-managed-pool-v1` 的输入是未转义 ASCII `source` 与 `filename`：每个
  component 非空、不是 `.`/`..`，且 byte 只能属于
  `[A-Za-z0-9._+~^:%-]`。`prefix = lower(source[0])`；若 source 以字面小写
  `lib` 开头，则 prefix 是 `lower(source[:min(4,len(source))])`。输出恰为
  `pool/<prefix>/<source>/<filename>`，source/filename 大小写保持不变。DEB 再应用上节
  更窄的 source/basename grammar；RPM 使用公共 grammar。
- 同一 Repository 中，同一逻辑坐标或同一 canonical Pool path 映射不同字节时
  硬拒绝，不允许覆盖。
- SHA-256 与 Pool path 双向唯一；同 digest 只有所有 immutable package facts 都相同才
  是幂等，否则 hard conflict。case-insensitive Pool path collision 同样拒绝，以保持
  macOS/Linux relocation 一致。
- 同一对象进入多个 Dist 只增加 Membership/metadata 引用。
- 不同 Repository 或不同 publish prefix 的相同字节允许分别存在，这是已接受的
  去重边界，不是遗漏。

Repository 与 target/prefix 的持久 identity、重命名/restore/fork 规则见
[`state-publication.md`](state-publication.md)。
