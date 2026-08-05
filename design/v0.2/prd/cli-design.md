# sow V2 CLI 设计候选（历史探索稿，已废弃）

> 状态：superseded，仅保留为探索记录；下文包含已经删除的命令、modulemd 与旧配置位置，不得作为阶段一实现依据。
> 规范性取代文档：[`api-contract.md`](./api-contract.md)；产品需求：[`prd.md`](./prd.md)。
> 本文件不再维护一致性，也不接受增量修订。
> 安全边界：`/Users/vonng/pgsty/repo` 仅作为只读事实来源；任何后续实验只能在 `/Users/vonng/repo/sow-v2-lab/` 中进行。

## 1. 设计结论

V2 对外提供两种明确分离的工作模式：

| 模式 | Managed repository | Plain repository |
| --- | --- | --- |
| 用途 | 长期维护正式 APT / YUM 仓库 | Pigsty 离线源、临时源、简单 flat 仓库 |
| 状态 | `.sow/config.yml` + 每个 repository 一份 SQLite | 无配置要求、无 SQLite、无持久成员状态 |
| 布局 | `<repo>/pool/` + `<repo>/dists/` | 包文件全部平铺在一个目录 |
| 成员 | dist 中显式的 package 引用 | 当前目录中通过校验和过滤的包 |
| 主要命令 | `add/rm/copy/move/pull/build/check/changes/gc` | `plain build/plain check` |
| 桥梁 | `sow export --layout plain` | 不会反向、隐式纳入 managed 状态 |

共同原则：

1. 一次只写一个 repository；同一 repository 的并发写请求排队。
2. 所有状态变更与构建以 repository 为原子性边界；跨 repository 不承诺原子性。
3. `filter` 与 `Limit` 是 dist 不变式，所有入口都必须执行，不能只在 `pull` 时执行。
4. 状态变更与静态索引构建分离。变更先提交 SQLite / pool 并把 dist 标为 dirty；`build` 再产生静态树。
5. `sow` 不上传、不发布、不保存 endpoint。构建完成后的 repository 目录可被外部 `rsync` / `rclone` 直接复制。
6. plain 模式只生成或替换元数据，绝不删除、移动、改名或重签目录中的包文件。

## 2. Workspace 与默认布局

```text
workspace/
├── .sow/
│   ├── config.yml
│   ├── infra.db
│   ├── pgsql.db
│   ├── changes/
│   ├── rejected/
│   └── stage/
├── infra/
│   ├── pool/
│   └── dists/
└── pgsql/
    ├── pool/
    └── dists/
```

- `.sow/config.yml`：repository、dist、filter、Limit、pull、签名和渲染策略的权威来源。
- `.sow/<repo>.db`：包事实、dist 成员、操作日志、build generation 和 changes ledger 的权威来源。
- `<repo>/pool/`：包字节权威来源。
- `<repo>/dists/`：可重建的协议投影。
- 每个 repository 独占自己的 pool、dists 和数据库；不做跨 repository 去重。

## 3. 全局参数

```text
-C, --workspace DIR       workspace 根；默认从 cwd 向上寻找 .sow/config.yml
    --config FILE         显式配置文件；与 --workspace 互斥
-r, --repo NAME           选择 repository
-j, --jobs N              内部并发度；默认逻辑 CPU 数
-n, --dry-run             只解析、校验并打印计划，不提交状态
    --json                输出稳定的机器可读 JSON
-q, --quiet               只输出错误与最终结果
-v, --verbose             可重复，增加诊断信息
    --lock-timeout DUR     等待写锁；0 表示无限等待，默认 0
    --no-wait              遇到其他写者立即失败
```

repository 的选择规则：

1. 显式 `--repo` 优先。
2. 当前目录位于某个 repository 目录内时，可推断该 repository。
3. workspace 只有一个 repository 时，可自动选择。
4. 其余情况必须显式指定，禁止“猜一个”。

退出码建议固定为：

| 退出码 | 含义 |
| --- | --- |
| `0` | 成功，包括确定性的 no-op |
| `1` | 操作失败，状态未按请求提交 |
| `2` | 参数或配置错误 |
| `3` | 部分成功，例如批量 add 中好包已提交、坏包已隔离 |
| `4` | 写锁等待超时或 `--no-wait` 失败 |
| `5` | 完整性或验收检查失败 |

## 4. 命令总览

```text
sow init
sow config check|show
sow repo ls|new|show|status|rm

sow add
sow rm
sow ls
sow show
sow where
sow rejected ls|show|retry|purge

sow dist ls|new|show|rm
sow copy
sow move
sow pull
sow diff

sow build
sow check
sow changes
sow log
sow log export|prune
sow gc
sow backup create|verify|restore
sow export
sow doctor

sow plain build|check
```

首期明确没有：`push`、`sync`、`publish`、远端 endpoint、Web 服务、特殊 snapshot / freeze 状态。

## 5. Workspace、配置与 repository

### 5.1 `sow init`

```bash
sow init [DIR] [--name NAME]
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| `DIR` | 当前目录 | 创建 workspace 的目录 |
| `--name NAME` | 目录名 | 写入配置的人类可读名称 |

规则：目标存在但非空时拒绝接管；已存在 `.sow/` 时为 no-op 或报告配置错误，不覆盖。

### 5.2 `sow config`

```bash
sow config check [FILE]
sow config show [--effective] [--repo NAME]
```

| 参数 | 适用命令 | 语义 |
| --- | --- | --- |
| `FILE` | `check` | 校验指定配置；省略时校验当前 workspace |
| `--effective` | `show` | 展示默认值展开后的有效配置 |
| `--repo NAME` | `show` | 只展示一个 repository 的有效配置 |

用户可以手工编辑 `.sow/config.yml`；`repo new/rm` 与 `dist new/rm` 只是安全的配置编辑器，不建立第二套配置权威。

### 5.3 `sow repo`

```bash
sow repo ls
sow repo new NAME [--path RELPATH]
sow repo show NAME
sow repo status [NAME]
sow repo rm NAME [--purge --yes --confirm NAME]
```

| 参数 | 适用命令 | 默认 | 语义 |
| --- | --- | --- | --- |
| `--path RELPATH` | `new` | `NAME` | repository 制成品目录，相对 workspace |
| `--purge` | `rm` | false | 同时删除 SOW 拥有的 DB、pool 与 dists；无此参数只允许移除空 repository |
| `--yes` | `rm --purge` | false | 允许非交互执行 |
| `--confirm NAME` | `rm --purge` | 无 | 必须与 repository 名完全一致 |

`repo status` 至少输出：配置摘要、state generation、built generation、dirty dist、pool 对象数、changes 可用范围。`--purge` 不允许递归删除未知路径，也不跟随符号链接。

## 6. 包管理命令

### 6.1 `sow add`

```bash
sow add PATH... --to DIST... \
  [--manifest FILE] [--recursive] [--strict]

sow add PATH... --route \
  [--manifest FILE] [--recursive] [--strict]
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| `PATH...` | 必填 | 包文件或目录；源文件只读，不移动、不删除 |
| `--to DIST...` | 与 `--route` 二选一 | 加入一个或多个明确的目标 dist |
| `--route` | 与 `--to` 二选一 | 按配置中的路由规则选择目标 dist |
| `--manifest FILE` | 无 | 读取构建系统提供的批次、目标平台等补充事实 |
| `--recursive` | false | 递归扫描目录；默认只扫描参数目录顶层 |
| `--strict` | false | 整批全成或全败；默认合法包提交、坏包隔离、退出码 3 |

入库顺序固定为：解析与校验 → RPM 签名策略 → 最终 SHA-256 → 冲突检查 → pool 落盘 → 目标 policy → SQLite 单事务提交。

冲突规则固定为：同一最终 SHA-256 重复加入是 no-op；同一逻辑键对应不同 SHA-256 硬失败；同一 pool path 对应不同 SHA-256 也硬失败。若候选没有被任何目标 dist 的 policy 接受，新对象不会作为无主包偷偷留在 pool 中。

RPM 签名策略来自 repository 配置：

- `never`：不签。
- `fill`：只给未签名包补签；有效已有签名保留；默认策略。
- `always`：使用配置 key 重签。
- 没有 key 时，有效策略为 `never`。

每个目标 dist 都对候选成员执行自己的 filter 与 Limit。被目标策略排除的包不会成为该 dist 成员，命令必须明确报告，不能静默成功。

### 6.2 `sow rm`

```bash
sow rm --from DIST... \
  (--match FORMULA | --list FILE | --source-list FILE | --all) \
  [--allow-empty] [--yes]
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| `--from DIST...` | 必填 | 从一个或多个 dist 移除引用 |
| `--match FORMULA` | 三选一 | 公式选择器 |
| `--list FILE` | 三选一 | 每行一个二进制包名 |
| `--source-list FILE` | 三选一 | 每行一个源包名 |
| `--all` | false | 选择全部成员；必须同时给 `--yes` |
| `--allow-empty` | false | 允许零匹配；默认零匹配视为拼写或规则错误 |
| `--yes` | false | 对大范围删除计划非交互确认 |

该命令只删除成员引用，不直接删除 pool 对象；物理回收只能由 `gc` 完成。

### 6.3 `sow ls`、`show`、`where`

```bash
sow ls DIST [--match FORMULA] [--format table|json|nevra|filename]
sow ls --pool [--match FORMULA] [--format table|json|nevra|filename]
sow show PACKAGE_REF [--format text|json]
sow where PACKAGE_REF [--format table|json]
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| `--pool` | false | 查看 repository 中的全部包，而非某个 dist |
| `--match FORMULA` | 全部 | 过滤结果 |
| `--format` | `table` / `text` | 选择人类或机器输出 |
| `PACKAGE_REF` | 必填 | 接受 DB id、完整 SHA-256 或完整逻辑键；短名字有歧义时失败 |

### 6.4 `sow rejected`

```bash
sow rejected ls [--since DUR]
sow rejected show ID
sow rejected retry ID... (--to DIST... | --route) [--strict]
sow rejected purge --before TIME --yes
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| `--since DUR` | 全部 | 按隔离时间过滤 |
| `--to` / `--route` | 必填 | retry 的目标选择 |
| `--strict` | false | retry 批次全成或全败 |
| `--before TIME` | 必填 | 只清理指定时间前的隔离输入与诊断 |
| `--yes` | false | 确认物理删除 rejected 文件 |

## 7. Dist 与集合运算

### 7.1 `sow dist`

```bash
sow dist ls
sow dist new NAME [--format rpm|deb] \
  [--from DIST] [--architectures A,B] [--component NAME] \
  [--limit N] [--filter FORMULA]
sow dist show NAME
sow dist rm NAME [--yes]
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| `--format rpm|deb` | 新建时必填；有 `--from` 时继承 | 一个 dist 只渲染一种协议 |
| `--from DIST` | 无 | 复制现有成员和渲染 / policy 设置；不复制 pull source rule |
| `--architectures A,B` | 配置默认 | 允许的架构集合 |
| `--component NAME` | `main` | APT component；RPM 不适用 |
| `--limit N` | `0` | `0` 保留所有版本，正整数保留最新 N 个，负数非法 |
| `--filter FORMULA` | 无 | dist 成员必须始终满足的过滤条件 |
| `--yes` | false | 删除 dist 定义、成员和衍生元数据的确认；pool 字节仍交给 GC |

Limit 在一个 dist 内按 `(binary name, architecture)` 分组，并使用 RPM EVR 或 Debian version 的原生比较规则选出最新 N 个。包唯一逻辑键仍是：

- RPM：`(name, epoch, version, release, arch)`。
- DEB：`(name, version, arch)`。

### 7.2 `sow copy`

```bash
sow copy SOURCE TARGET [--match FORMULA]
```

复制包引用，不复制包字节。目标 dist 的 filter 与 Limit 始终执行。首期没有 `--replace`；来源中没有的包不会从目标自动消失。

### 7.3 `sow move`

```bash
sow move SOURCE TARGET --match FORMULA [--allow-empty]
```

同一 repository 内原子执行“目标接受 + 来源移除”。只有真正被目标 policy 接受的包才会从来源删除；被目标拒绝的包继续留在来源，避免隐式丢包。

### 7.4 `sow pull`

```bash
sow pull [DIST...] [--rule NAME]
```

`pull` 是沿用 reprepro 的本地集合术语，不访问网络。每个目标 dist 的语义固定为：

```text
existing target members
UNION selected packages from all configured source rules
→ target filter over the whole set
→ target Limit over the whole set
→ atomic commit
```

- `DIST...`：只刷新指定目标；省略时刷新所有配置了 pull rule 的目标。
- `--rule NAME`：只运行具名规则，方便调试。
- source 中消失但仍符合目标规则的既有包不会被自动删除。
- 需要下架时使用显式 `sow rm`。
- exact reconcile / mirror 语义后置，不进入首期。

V2 不提供 `push`，避免同一操作出现两个相反方向的名字。

### 7.5 `sow diff`

```bash
sow diff A B [--match FORMULA] [--format table|md|json]
```

输出 A 与 B 的成员差异、版本升降级、架构缺口和 policy 造成的排除，不改变状态。

## 8. 构建、校验与变化集合

### 8.1 `sow build`

```bash
sow build [DIST...] \
  [--affected | --all] \
  [--check quick|full|none] \
  [--keep-stage]
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| `DIST...` | 所有 dirty dist | 只构建指定 dist 及其视图 |
| `--affected` | 默认 | 只构建输入状态变化的 dist / view |
| `--all` | false | 强制重建全部 dist / view |
| `--check` | `quick` | 原子换入前的检查强度 |
| `--keep-stage` | false | 失败时保留 stage 供排障 |

affected 判据必须包括：成员集合、renderer 版本、压缩策略、签名配置、附加元数据和布局配置；不能只比较成员哈希。

一次成功 build 形成一个 repository generation，并独立保留 changes ledger。pool 新对象先就位，完整 dists 树在 stage 验证后换入。首期不提供隐藏式 `add --build --sync`；自动化脚本显式串联各步骤。

### 8.2 `sow check`

```bash
sow check [DIST...] [--quick | --full] \
  [--pool] [--metadata] [--signatures] [--modulemd] \
  [--closure --against SOURCE,...] [--matrix] [--orphan]
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| `--quick` | 默认 | 配置、DB、dirty 状态、索引结构、引用闭包与轻量签名检查 |
| `--full` | false | 重新哈希 pool 与全部索引文件 |
| `--pool` | false | 强制检查包字节、路径和数据库事实 |
| `--metadata` | false | 强制检查 Packages / Release / repomd 的内部引用与校验和 |
| `--signatures` | false | 验证包签名与 repository 元数据签名 |
| `--modulemd` | false | 验证 modulemd 结构、NSVCA、arch、defaults 与 artifact 闭包 |
| `--closure` | false | 检查安装依赖闭包 |
| `--against SOURCE,...` | 配置值 | closure 假定可用的其他源 |
| `--matrix` | false | 检查配置声明的平台 / 架构 / PG 大版本矩阵 |
| `--orphan` | false | 检查 debug 等派生产物是否缺主包 |

`check` 永远只读，不提供隐式 repair。

### 8.3 `sow changes`

```bash
sow changes
sow changes --from GENERATION [--to GENERATION]
sow changes --format summary|jsonl|paths
sow changes --format rclone -o DIR
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| 无 generation 参数 | 上一 generation → 当前 generation | 展示最近一次 build 的物理变化 |
| `--from` | 无 | 起始 generation |
| `--to` | 当前 generation | 结束 generation |
| `--format` | `summary` | 输出格式 |
| `-o DIR` | stdout | `rclone` 格式的输出目录 |

JSONL 最低字段：

```json
{"op":"add|update|delete","path":"repo-relative/path","phase":"payload|metadata|pointer|delete","size":123,"sha256":"..."}
```

`--format rclone` 产生：

```text
01-payload.upload.txt
02-metadata.upload.txt
03-pointer.upload.txt
90-delete.txt
```

SOW 只描述本地 generation 之间的变化，不调用 rclone、不保存远端凭据，也不执行远端删除。

changes ledger 与审计日志分开；`log prune` 不得破坏尚可查询的 generation diff。

## 9. 审计、维护与恢复

### 9.1 `sow log`

```bash
sow log [--since DUR] [--op OP] [--dist DIST] [--package NAME]
sow log export -o FILE [--before TIME] [--format jsonl|csv]
sow log prune --before TIME --yes [--vacuum]
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| `--since DUR` | 全部 | 时间范围 |
| `--op OP` | 全部 | 操作类型 |
| `--dist DIST` | 全部 | dist 过滤 |
| `--package NAME` | 全部 | 包生命周期过滤 |
| `--before TIME` | 必填 | export / prune 的截止时间 |
| `--format` | `jsonl` | 导出格式 |
| `--yes` | false | 确认日志删除 |
| `--vacuum` | false | prune 后回收 SQLite 空间 |

第一阶段日志与状态在同一 SQLite 中，但 prune 只能删除审计行，不能删除 package、member、build generation、changes 或 recovery journal。

### 9.2 `sow gc`

```bash
sow gc [--grace DUR] [--max-delete N]
sow gc --apply [--grace DUR] [--max-delete N] --confirm REPO
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| 无 `--apply` | dry-run | 永远先展示候选、字节数和原因 |
| `--grace DUR` | 配置值，例如 30d | 对象脱离最后引用后的最短等待时间 |
| `--max-delete N` | 配置安全阈值 | 超出时硬失败，要求重新审阅计划 |
| `--confirm REPO` | apply 必填 | 防止选错 repository |

被任何 dist、当前 build、recovery journal 或保留 generation 引用的对象绝不删除。外部 rsync / rclone 的远端状态不是 GC root，命令必须明确警告。

### 9.3 `sow backup`

```bash
sow backup create -o DIR [-r REPO | --all-repos]
sow backup verify DIR
sow backup restore DIR --into EMPTY_WORKSPACE
```

备份包含 config、SQLite 一致快照、schema 版本、配置摘要和恢复清单；默认不包含 pool 与 dists。命令必须打印：control-plane backup only，包字节需要单独备份。

restore 首期只允许恢复到空 workspace，不覆盖现有 `.sow/`。

### 9.4 `sow doctor`

```bash
sow doctor [--full]
```

检查当前平台、文件系统能力、SQLite、GPG 可用性、key 权限、workspace 配置与锁状态；只读，不修复。

## 10. Plain / flat repository

### 10.1 布局与不变式

RPM plain repository：

```text
pigsty/
├── *.rpm
├── repodata/
└── repo_complete       # 仅兼容模式可选
```

DEB plain repository：

```text
pigsty/
├── *.deb
├── Packages
├── Packages.gz
└── repo_complete       # 仅兼容模式可选
```

约束：

1. 一个 plain 目录对应一种格式、一个目标架构切片；`x86_64 + noarch` 或 `amd64 + all` 视为一个切片。
2. `--format auto` 只在目录中恰好存在一种包格式时成功；RPM / DEB 混放会失败并要求显式整理目录。
3. 默认只扫描目录顶层，不递归。
4. 目录中有什么只是候选；filter 与 Limit 只决定索引成员，不删除未索引的包文件。
5. `Limit: 0` 明确表示索引全部版本；这不同于某些 `dpkg-scanpackages` 默认只选一个版本的历史行为。
6. 元数据在同一文件系统的 stage 中完整生成、校验后替换；completion marker 最后写入。
7. 首次遇到非 SOW 生成的既有元数据时拒绝覆盖；需要显式 `--replace-metadata`。后续可根据 SOW ownership marker 安全替换。

### 10.2 `sow plain build`

```bash
sow plain build DIR \
  [--format auto|rpm|deb] \
  [--target PLATFORM] [--arch ARCH] \
  [--filter FORMULA] [--limit N] \
  [--compression auto|gzip|xz|zstd] \
  [--modulemd none|inject|preserve|generate] \
  [--modulemd-file FILE] \
  [--module-name NAME] [--module-stream STREAM] \
  [--module-version UINT64] [--module-context CONTEXT] \
  [--module-profile NAME=SELECTOR] \
  [--module-default-stream] [--module-default-profile NAME] \
  [--allow-orphan-modular] \
  [--compat pigsty] \
  [--completion-file NAME] [--completion-digest md5|sha256] \
  [--replace-metadata] \
  [--changes FILE] [--changes-format jsonl|paths|rclone]
```

通用参数：

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| `DIR` | 必填 | 包和输出元数据所在的同一 flat 目录 |
| `--format` | `auto` | 目录中只有一种格式时推断；混放失败 |
| `--target` | 无 | `el7/el8/el9/el10/debian11/debian12/debian13/ubuntu20.04/22.04/24.04/26.04`；modulemd 时必填 |
| `--arch` | 从包集合唯一推断 | 只接受该架构及 `noarch/all`；多个原生架构时必须显式拆目录 |
| `--filter` | 无 | 只影响索引成员，不删除文件 |
| `--limit` | `0` | 每个 `(name, arch)` 索引的最新版本数；0 为全部 |
| `--compression` | 目标平台的兼容默认值 | 生成的压缩变体；不允许选择目标客户端不支持的格式 |
| `--compat pigsty` | false | 采用 Pigsty 根目录布局并生成兼容 completion 文件；不会硬编码删除 i386/i686 或特定 Patroni 版本，也不会隐式启用 modulemd |
| `--completion-file` | 无；Pigsty 兼容为 `repo_complete` | 成功完成后最后写入的清单文件 |
| `--completion-digest` | `sha256`；Pigsty 兼容为 `md5` | 清单摘要；Pigsty 模式输出兼容 GNU `md5sum` 格式 |
| `--replace-metadata` | false | 首次接管未知既有元数据时允许替换；仍不触碰包文件 |
| `--changes` | 无 | 把本次旧索引 → 新索引的变化写入文件或目录 |
| `--changes-format` | `jsonl` | 一次性 changes 输出格式；plain 不持久保存 generation ledger |

### 10.3 modulemd 的产品决定

`modulemd` 不是“多生成一个无害文件”。活动 module stream 会参与 DNF 的 modular filtering；`module_hotfixes=1` 只让指定 repository 的 RPM 不受过滤，并不保证其 EVR 一定胜出。经典 `repo2module` 还会生成默认 stream 和 `everything` 默认 profile，可能改变求解和安装行为。

因此没有 `auto` 模式，默认必须是 `none`：

| 模式 | 语义 | 使用场景 |
| --- | --- | --- |
| `none` | 不产生 modules 记录 | 普通非模块化 Pigsty RPM 仓库，默认推荐 |
| `inject` | 注入并验证用户提供的 modulemd | 有意维护真正模块仓库 |
| `preserve` | 从既有 repodata 保留 modules 元数据并验证 artifact 闭包 | 透明重建或迁移 |
| `generate` | 显式生成一个 repo-wide 模块；不自动声明默认 stream / profile | EL8/EL9 兼容实验，必须做真实 DNF 验收 |

modulemd 参数：

| 参数 | 适用模式 | 默认 / 规则 |
| --- | --- | --- |
| `--modulemd-file FILE` | `inject` | 必填，可重复 |
| `--module-name NAME` | `generate` | 目录 basename |
| `--module-stream STREAM` | `generate` | `stable` |
| `--module-version UINT64` | `generate` | `1` |
| `--module-context CONTEXT` | `generate` | 成员哈希前 8 字符，确保 artifact 集变化时身份变化 |
| `--module-profile NAME=SELECTOR` | `generate` | 无默认 profile；可重复 |
| `--module-default-stream` | `generate` | false；显式 opt-in |
| `--module-default-profile NAME` | `generate` | 无；显式 opt-in |
| `--allow-orphan-modular` | `none` | false；默认拒绝带 modularity label 却没有对应 modulemd 的 RPM |

`inject` / `preserve` / `generate` 都必须验证 YAML、NSVCA 唯一性、arch、defaults 冲突以及 artifact NEVRA 对当前视图的闭包。混合架构不能共用一个含糊的 module arch。

对于普通 Pigsty EL8 / EL9 仓库，推荐客户端继续使用：

1. repo 配置中的 `module_hotfixes=1`，保证该 repo 的包不被 modular filtering 隐藏。
2. 明确执行 `dnf module disable postgresql`，消除发行版 PostgreSQL module 的状态与候选干扰。
3. 不默认生成 repo-wide modulemd；只有真实客户兼容测试证明需要时才显式使用 `generate`。

若要精确复刻历史 `repo2module -s stable` 的默认模块行为，调用者必须显式声明 `everything` profile、默认 stream 和默认 profile；SOW 不把这组三个有副作用的选择折叠进 `--compat pigsty`。

参考：[DNF modularity](https://dnf.readthedocs.io/en/latest/modularity.html)、[DNF configuration reference](https://dnf.readthedocs.io/en/latest/conf_ref.html)、[RHEL 10 software-management changes](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/considerations_in_adopting_rhel_10/software-management)。

### 10.4 `sow plain check`

```bash
sow plain check DIR [--full] \
  [--format auto|rpm|deb] [--target PLATFORM] [--arch ARCH] \
  [--metadata] [--signatures] [--modulemd]
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| `--full` | false | 重新解析包、重算全部摘要并核对索引 |
| `--format` | `auto` | 显式限制格式或唯一推断 |
| `--target` / `--arch` | 从 ownership marker / 包集合推断 | 核对平台切片 |
| `--metadata` | true | 验证 Packages 或 repomd 及其引用 |
| `--signatures` | false | 验证现有包 / 元数据签名，不修改它们 |
| `--modulemd` | 存在时自动 | 验证 modulemd 与 artifact 闭包 |

## 11. 从 managed dist 导出 plain repository

```bash
sow export DIST -o DIR --layout plain \
  [--arch ARCH] [--target PLATFORM] \
  [--method copy|hardlink] [--replace] \
  [--compat pigsty] \
  [--modulemd none|inject|preserve|generate] \
  [--modulemd-file FILE]
```

| 参数 | 默认 | 语义 |
| --- | --- | --- |
| `--layout` | 首期只支持 `plain` | 明确导出布局 |
| `--arch` | dist 的单一架构时推断 | 导出该架构与 `noarch/all` |
| `--target` | dist 配置 | plain 校验目标 |
| `--method` | `copy` | `hardlink` 只允许同一文件系统，并警告导出不是独立副本 |
| `--replace` | false | 只替换带 SOW ownership marker 的旧导出；不清空任意目录 |
| `--compat pigsty` | false | 透传 plain 的兼容布局与 completion marker |
| modulemd 参数 | `none` | 透传给同一 plain renderer / checker |

输出目录默认必须为空。导出完成后不依赖 `.sow/`，可以直接打包或由 file://、HTTP 静态服务使用。

## 12. 典型 User Stories

### US1：初始化一个多 repository workspace

```bash
sow init /Users/vonng/repo/sow-v2-lab
cd /Users/vonng/repo/sow-v2-lab
sow repo new infra
sow repo new pgsql
sow repo status
```

验收：`.sow/` 与 `infra/pgsql` 同级；每个 repository 有自己的 DB、pool、dists；不会发现或修改 `/Users/vonng/pgsty/repo`。

### US2：批量导入每月构建结果

```bash
sow add /path/to/build-output/ --recursive \
  -r pgsql --to staging
```

验收：合法包提交到 pool 与 staging；坏包进入 rejected；输入目录不变；部分失败返回退出码 3；重试同一内容为 no-op。

### US3：生成只保留最新版、排除 debug 的 OSS dist

配置：

```yaml
dists:
  el9:
    format: rpm
    architectures: [x86_64, aarch64]
    filter: '!kind (in {debuginfo,debugsource,llvmjit})'
    limit: 1
    pull:
      - from: released-el9
```

执行：

```bash
sow pull el9 -r pgsql
sow diff released-el9 el9 -r pgsql
```

验收：el9 中永远没有 debug 类包，每个 `(name, arch)` 只有最新版本；source 中消失的合规旧包不会被隐式下架。

### US4：直接 add / copy 也不能绕过 OSS policy

```bash
sow add ./foo-debuginfo.rpm -r pgsql --to el9
sow copy released-el9 el9 -r pgsql --match 'name (~ foo*)'
```

验收：两个入口都重新执行 el9 filter / Limit；debug 包不成为成员；输出明确解释排除原因。

### US5：构建并验证正式静态树

```bash
sow build -r pgsql --affected
sow check -r pgsql --metadata --signatures --matrix
sow repo status -r pgsql
```

验收：dirty dist 清零；APT / DNF 索引内部引用闭合；repository 目录在 build 返回后可直接复制。

### US6：让外部 rclone 消费 changes

```bash
sow changes -r pgsql --from 41 --to 42 \
  --format rclone -o /tmp/pgsql-gen42
```

验收：得到 payload、metadata、pointer、delete 四阶段文件；SOW 不读取远端凭据，也不执行上传或删除。

### US7：建立仍可修改的月度快照与客户 dist

```bash
sow dist new el9-pro-202607 -r pgsql --from el9-pro
sow dist new el9-pro-acme -r pgsql --from el9-pro-202607
sow build el9-pro-202607 el9-pro-acme -r pgsql
```

验收：两者都是普通 dist，没有 frozen 状态；`--from` 不继承 pull rule，后续只有显式变更才会改变成员。

### US8：构建推荐的 Pigsty EL9 plain RPM 源

```bash
sow plain build /www/pigsty \
  --format rpm --target el9 --arch x86_64 \
  --modulemd none --compat pigsty
```

验收：包文件不变；生成 repodata 与兼容 `repo_complete`；客户端 repo 使用 `module_hotfixes=1`，并禁用发行版 PostgreSQL module。

### US9：显式试验 EL8 modulemd

```bash
sow plain build /www/pigsty \
  --format rpm --target el8 --arch x86_64 \
  --modulemd generate \
  --module-name pigsty --module-stream stable \
  --compat pigsty --replace-metadata

sow plain check /www/pigsty --full --modulemd
```

验收：repomd 中恰有一个 modules 记录；module arch 与 artifact 闭包正确；没有隐式默认 stream 或默认 profile；还必须在真实 EL8 DNF 上做 list/info/install 验收。

### US10：构建 Ubuntu 24.04 plain APT 源

```bash
sow plain build /www/pigsty \
  --format deb --target ubuntu24.04 --arch amd64 \
  --compat pigsty
```

验收：生成 `Packages` 与 `Packages.gz`；全部版本默认被索引；`deb [trusted=yes] file:/www/pigsty ./` 可消费；包文件不变。

### US11：从 managed dist 导出离线源

```bash
sow export noble -r pgsql -o /tmp/pigsty-noble \
  --layout plain --arch amd64 --target ubuntu24.04 \
  --compat pigsty
sow plain check /tmp/pigsty-noble --full
```

验收：输出不依赖 workspace / SQLite，可直接打 tarball；默认复制而不是 hardlink。

### US12：备份控制面、收缩日志、回收孤儿对象

```bash
sow backup create --all-repos -o /backup/sow-control
sow backup verify /backup/sow-control
sow log export -r pgsql -o /backup/pgsql-log.jsonl --before 2026-01-01
sow log prune -r pgsql --before 2026-01-01 --yes --vacuum
sow gc -r pgsql --grace 30d
sow gc -r pgsql --grace 30d --apply --confirm pgsql
```

验收：备份明确不含包字节；日志清理不破坏 changes；GC 不触碰任何 dist、build、recovery 或保留 generation 引用的对象。

## 13. 建议删除或后置的 V1 命令

| V1 / 候选命令 | V2 处理 |
| --- | --- |
| `push` | 删除；目标 dist 运行本地 `pull` |
| `sync` / `publish` | 删除；外部 rsync / rclone 消费目录或 changes |
| endpoint 管理 | 删除 |
| 特殊 snapshot / freeze | 删除；使用普通 dist |
| `materialize` | managed 用 `build`，flat 输出用 `export` |
| `fsck` / `verify` | 收敛为只读 `check` |
| 独立 `sign` | 包签名进入 `add`，索引签名进入 `build`；key rotation 后置 |
| `serve` | 首期不做，避免把一次性 CLI 变成服务 |
| mirror / upstream fetch | 后置能力 |
| exact reconcile | 后置能力；首期 pull 只有 merge-then-prune |

## 14. 本轮需要确认的产品契约

1. 命令采用紧凑的顶层 `add/rm/ls/copy/pull/build`，而不是更长的 `package add/dist refresh`。
2. `pull` 保留 reprepro 术语，但明确只做本地集合运算；没有 `push`。
3. filter / Limit 是 dist 不变式，add、copy、move、pull 全部执行。
4. add 默认部分成功并隔离坏包；`--strict` 才整批回滚。
5. 状态变更不自动 build；首期脚本显式串联。
6. changes 是独立 generation ledger，不依赖可清理的审计日志。
7. plain 是无状态 renderer，只改元数据，不改包文件。
8. 一个 plain 目录只支持一种格式和一个原生架构切片。
9. plain 默认 `Limit: 0`，索引全部版本。
10. modulemd 默认 `none`，不提供自动模式；inject / preserve 是稳定能力，generate 是显式能力。
11. `--compat pigsty` 只负责布局和 completion marker，不偷偷启用 modulemd 或硬编码历史删除策略。
12. 普通 Pigsty EL8 / EL9 首选 `module_hotfixes=1 + dnf module disable postgresql`；modulemd generate 必须由真实客户端测试证明必要。
