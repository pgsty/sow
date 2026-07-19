# ADR-0020：旧物理拓扑、选择器组与公开路径所有权

- 状态：Accepted（本地 canonical builder 已闭合；真实迁移仍未闭合）
- 日期：2026-07-14
- 决策范围：G5、FR-09、FR-23、FR-41、FR-42、COMP-01、MIG-02、MIG-05

## 背景

早期迁移夹具用 33 个 repo ID / 73 个 leaf 覆盖了迁移账本里出现的选择器名称，
但它使用隔离的 `selectors/**` 路径，只能证明动词与选择器能够被 CLI 一般化执行。
它不是 `/Users/vonng/pgsty/repo` 的物理拓扑，也不能证明旧 URL 可等价迁移。

2026-07-14 的只读本地盘点（没有运行 Make recipe、没有访问网络或任何 CO/COS/CF
资源）得到以下当前事实：

| 范围 | 当前物理 leaf |
|---|---:|
| APT `binary-*` index | 74 |
| APT infra / mssql / percona / pgdg / pgsql | 2 / 6 / 12 / 40 / 14 |
| YUM `repodata/repomd.xml` | 131 |
| YUM `repodata/repomd.xml.asc` | 0 |
| YUM infra / pgsql / mssql / gpsql / percona / pgdg | 2 / 7 / 5 / 3 / 9 / 105 |
| 旧 `pro/` 普通文件 | 16 |
| 根级精确公开 key | 7 |
| 根级公开目录前缀 | 8 |

这揭示了四类原 schema 无法忠实表达的事实：

1. APT PGDG 的 stable suite 只有 `main`，testing suite 则有 `main,18,19`；
   bullseye 与活跃 suite 的 lifecycle 也不同。全局 `suites × components` 会生成不存在
   的 index，单 repo lifecycle 会错误放开或冻结其它 suite。
2. YUM PGDG 是几十个按产品线、EL major、arch 分区的物理 repo；`yum-pgdg` 不是一个
   双架构 leaf。Percona 还把 `noarch` 作为独立 repodata 根。
3. Makefile 把 `/get`、`/pig`、`/pkg`、`/beta`、`/cc`、`/claude`、`/ray` 写成 bucket
   根级 object，而本地还存在 `/pkg/pig/`。对象存储允许 key `pkg` 与 prefix `pkg/`
   共存，POSIX 文件系统不允许同一路径同时是文件与目录。
4. 同一物理 repo 的几十个精确 ID 不能退化为 glob。否则新增路径会在没有 config
   review、config SHA 变化和恢复记录变化的情况下静默进入一次发布。

## 决策

### 1. 物理 repo 与 repo group 分离

- 每个可独立扫描、建索引、恢复和发布的物理 repo 使用稳定、唯一的 repo ID。
- `repo_groups` 是 config 中显式、扁平、无 glob 的 `group -> [physical repo IDs]`
  映射。group 不得与 repo ID 冲突，不得嵌套，成员必须存在且无重复。
- `--repo` 可接受 repo ID 或 group；group 在 OS/arch narrowing 之前展开为精确物理
  ID。transaction、ref、checkpoint 和恢复日志只记录展开后的物理 leaf。
- group membership 是 canonical config 的一部分并进入 config SHA。成员变化因此必然
  触发 review/恢复身份变化，不能静默扩大旧 Make target 的作用域。

### 2. APT suite 是 component 与 lifecycle 的所有权边界

- 继续保留 `apt.suites` / `apt.components` 作为矩形配置简写。
- 非矩形 archive 使用覆盖全部 suite 的 `suite_components`；每个值非空且只能引用全局
  component，所有 suite 的并集必须精确等于 `components`。
- 混合生命周期使用覆盖全部 suite 的 `suite_lifecycle`，值只允许 `active|frozen`；未
  配置时回退 `os.lifecycle`。
- add/rm/sync/promote、legacy adoption、Packages/Release 生成、snapshot/recovery、
  L1-L4 probe 都必须从所处理 suite 读取这两个精确合同。全局 component 只可用于解析
  shared pool 路径，不能授权某个 suite 的 index 或写入。

### 3. asset 的物理路径与公开 legacy 路径分离

- 普通 asset 的公开路径默认等于 `repo.path`，保持现有配置兼容。
- 根级兼容 object 使用显式 asset 公开路径映射：canonical/hardlink 文件位于互不重叠
  的物理目录，publish plan 把该目录下的精确允许项投影到 bucket 根 key。
- bucket 根映射必须声明有限的 exact root-key allowlist；不得使用 `**`、目录或隐式
  全根 ownership。不同 repo 的 exact key 不得重复，且 config SHA 绑定映射。
- 本地 Nginx 以 `location = /key` 精确 alias 服务这些文件；`/pkg` 的 exact alias 与
  `/pkg/` 前缀可同时存在。兼容测试必须用真实 Nginx 同时请求两者，默认 location 仍
  fail closed。SOW 不接管 Nginx 进程，但提供的配置/迁移步骤必须是可执行、可验证的。
- `.io` 与 `.cc` 的同名脚本正文当前不同。SOW 不允许 target-specific body override。
  外部 builder 现在钉住八个源 identity，并确定性产出一份同时携带 global/China exact host、
  strict override 与 fallback 语义的 canonical body；SOW 只接收其 SHA-256/size handoff。
  本地正文收敛已经完成，但真实 URL 回归/cutover 前仍不得声称生产迁移完成。

为使 M0 能在正文收敛和 gated rebase 之前完整记录旧物理树，asset 可声明
`active: false`、`kind: inventory`、`inventory_carrier: true`：

- carrier 只在 `sow init` 与无 `--target` 的本地 `sow fsck` 中可选；普通选择器、
  `--adopt-content`、add/rm/sync/materialize/publish 和远端 fsck 都排除它；
- carrier 必须使用非根 `public_path`，不得声明 root key 或 mutable path；inactive 状态使
  它不产生 view、Nginx/edge route、upstream 或 remote key；
- `bin` carrier 必须显式排除 `fileauth.txt`。该文件不得被打开、哈希或写入 canonical
  state；`pro` carrier 只把现有 gated bytes 纳入本地 M0 manifest，不把它们提升为 stable；
- carrier baseline 与待发布 canonical repo 使用不同 ID/physical root。canonical repo 在
  builder/rebase 完成前保持 inactive；shared/COS-only builder 的本地 digest-bound handoff
  通过后已显式激活对应 owner，这不改变 carrier 的历史事实或授权云写入。

这是一条只读 inventory 契约，不是 legacy→canonical rename、正文选择或信任声明。

### 4. 特殊旧树的处置

- `asset-src` 与 `src` 必须合并为同一个物理 `/src/` owner；迁移账本不得再让两个 ID
  认领同一路径。
- 旧 `pro/` 的 16 个文件必须进入一个显式 gated asset migration inventory，再迁入
  OSS/Pro 合一 bucket 的 stable/gated view；`co-pro` 的笼统 stable 发布不是纳管证据。
- `yum/pgdg/17/redhat/rhel-10-aarch64/rhel-10.0-aarch64/` 的 nested repodata 在确认
  primary 引用与真实消费者前不是独立 repo。它必须有 ADR 记录的 quarantine/compat
  决定；不得既忽略 URL 又把父子 overlap 伪装为已支持。
- `yum/infra/{arch}` 是跨 EL 共用的旧 gzip URL。它需要独立 compatibility projection
  与按 EL 的 canonical lifecycle 决策；不得继续用 synthetic `EL9/zstd` 冒充。具体
  projection/ref 结构在实现前单独冻结，且 frozen EL7 的 ADR-0019 约束不被放宽。
- 当前 131 个旧 YUM leaf 均没有 `repomd.xml.asc`。legacy adoption 默认仍严格验证
  `repomd.xml -> primary -> RPM` 的 size/SHA-256 证据链，但输出
  `yum_metadata_signature=not-claimed`，不得从新的 repository signing key 或 RPM package
  keyring 推断旧 metadata 的签名身份。只有操作员显式提供 public-only
  `--legacy-metadata-keyring` 时，CLI 才在 canonical state 写入前冻结 keyring digest，并要求
  每个选中 YUM leaf 的 `.asc` 均通过验签后输出 `verified`。RPM payload signer 仍由
  `yum.package_keyring` 在 materialize/publish/L1 边界独立验证；两类信任不能互相替代。

## 验收门禁

1. 提交固定摘要的本地只读 inventory 工具与 machine fixture；任何 APT/YUM/root asset/
   gated-pro 拓扑漂移都使测试失败。
2. 提交可解码的完整迁移 config，group 展开后的物理 repo/leaf/path 集与 machine fixture
   精确相等；33/73 synthetic fixture 继续保留，但只标为 selector generalization。
3. 本地临时复制树完成零字节 `init`、`--adopt-content`、SQLite rebuild、candidate
   materialize、L1/fsck、原子切换和 rollback；source bytes 在切换前不得改变。
4. 用真实 Nginx 同时验证根 exact key、`/pkg` 文件与 `/pkg/pig/` 目录、APT/YUM 旧 URL、
   default-deny control paths。对象存储协议测试验证 source path 到 legacy key 的一一映射。
5. 真实 CO/COS/CF 生产仓库在任何情况下都不得用于测试。云端证据只能来自单独登记、
   独立审核、明确 non-production 的资源；当前空注册表保持 fail closed。

## 结果

- 迁移规模由可重放 inventory 决定，不再由 PRD 的“约 40 target”或 synthetic leaf 数推断。
- repo group 恢复了 Make alias 的易用性，同时保留 config-SHA-bound 的精确作用域。
- APT 稀疏 index 不会被全笛卡尔配置凭空制造；frozen suite 的写入门禁不会误伤同 archive
  的活跃 suite。
- 根级 object 与目录前缀可以在 bucket 和 Nginx 上保持旧 URL，而不破坏 POSIX 安全模型。
- 本 ADR 不把当前本地盘点升级为生产迁移、真实 CDN 或真实云通过证据。
