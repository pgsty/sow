---
title: sow V2 阶段一 API 契约
status: approved
version: 0.2
created: 2026-08-01
updated: 2026-08-02
---

# sow V2 阶段一 API 契约

> **v0.2 历史 API/布局合同。** CLI 行为仍用于解释 `v0.2.0`；其中“相对 Pool 必须通过 reposync”与后续 C2 修正不再是前向要求。下一版 Repository layout、href、publish 与 export 边界见 [`../../next/specs/SPEC.md`](../../next/specs/SPEC.md)。

## 0. 契约地位

本文是 `sow` V2 阶段一公共 CLI 的规范性文件，回答三个问题：有哪些命令、每条命令有哪些参数、成功或失败分别改变什么状态。PRD 说明为什么做以及如何验收；本文约束用户能够观察到的 API。

阶段一只提供两条闭环：

1. **Plain：**把当前平铺目录中的 RPM / DEB 直接建成简单仓库。
2. **Managed：**在 `Workspace → Repository → Dist → Membership` 模型中维护长期仓库。

凡本文没有列出的命令、参数或隐式推断，阶段一都不提供。尤其没有 `route`、manifest、rejected、modulemd、sync/publish、远端 endpoint、pull/copy/move、GC 或公式过滤器。

## 1. 设计原则

1. **默认正确。** `add` / `rm` 成功时默认已经更新索引；跳过构建必须显式写 `--skip`。
2. **架构自动。** 架构来自包头，用户不在 `add` 时填写；配置只声明允许上限。
3. **目标明确。** Repository 与 Dist 只能由明确参数、当前目录或唯一候选推断；不能猜频道或平台。
4. **协议视图永远自洽。** Dirty 表示 Desired State 领先于 Built Generation，不表示客户端可见索引半成品；客户端只能沿协议指针读到完整的旧或新 view。
5. **一个概念一个命令。** `status` 看便宜状态，`check` 做完整校验，`build` 收敛状态，`changes` 看静态文件差异，`log` 看语义操作。
6. **本地交付。** Repository 目录本身就是 rsync / rclone 的输入；`sow` 不理解远端。

## 2. 两种运行模式

### 2.1 Plain 模式

`sow create` 不读取 `sow.yml`，没有 SQLite，不做 Workspace 发现。它只管理目标目录中自己生成的索引文件；除显式 `--pigsty` 外不删除任何包。

### 2.2 Managed 模式

除 `create`、`help`、`version`、`init` 外，命令都运行在一个 Workspace 中。每个 Repository 独占：

- `<workspace>/<repo>/pool/`
- `<workspace>/<repo>/dists/`
- `<workspace>/.sow/<repo>.db`
- `<workspace>/.sow/<repo>/` 下的锁、stage、durable pending payload 与恢复文件

Repository 是锁、事务恢复、Generation 与 Changeset 的边界。跨 Repository 不去重，也不承诺原子提交。

`init`、`repo new`、`repo rm` 发生在目标 Repository 数据库存在之前或删除之后，因此使用 `.sow/workspace.lock` 与 `.sow/workspace-ops/` 中的轻量 durable file journal。其余 Repository 内写命令使用该 Repository SQLite 的 Operation Journal。阶段一不为此引入第二个 workspace SQLite。

### 2.3 Managed 静态布局

一个 Repository 可以同时拥有 RPM Dist 与 DEB Dist，两侧共用一个 Pool：

```text
pgsql/
├── pool/
│   └── <prefix>/<source>/<filename>
└── dists/
    ├── el9/
    │   ├── x86_64/repodata/
    │   └── aarch64/repodata/
    └── noble/
        ├── Release
        ├── InRelease              # configured metadata key
        ├── Release.gpg            # configured metadata key
        └── main/
            ├── binary-amd64/Packages{,.gz}
            └── binary-arm64/Packages{,.gz}
```

- Pool path 为 `pool/<prefix>/<source>/<filename>`；`prefix` 采用 Debian 规则：普通 source 取首字符，`lib*` 取前四字符，并统一转为 ASCII 小写。`source` 与 `filename` 保持原始大小写；同一 Repository 内拒绝大小写不敏感时会碰撞的完整 Pool path，确保默认 macOS 文件系统与 Linux 之间可移植。
- RPM source 优先取 `SOURCERPM`，DEB source 优先取 `Source`；字段缺失时回落到 binary name 并明确记录 warning。阶段一不接纳 SRPM/DSC。
- APT component 固定为 `main`；YUM 没有 component。阶段一不提供 component 参数。
- YUM 只生成 canonical per-architecture view，不额外生成混合架构 aggregate view。
- APT `Filename` 从 archive root 指向 `pool/...`；YUM package location 从当前 architecture view 使用相对路径指向共享 Pool。这个 YUM 布局是 P1 前置技术门禁：必须先用真实 DNF/YUM 与 reposync 证明按实际深度计算的 `../../../pool/...` 可用，才允许冻结 schema/renderer；若失败必须回到产品/架构重选布局，不能偷换成写死绝对 URL。

## 3. 公共语法

```text
sow [GLOBAL OPTIONS] COMMAND [ARGS]
```

### 3.1 全局参数

| 参数 | 默认 | 适用范围 | 契约 |
| --- | --- | --- | --- |
| `-C, --workdir DIR` | 无 | Managed | Workspace 发现的起始目录；不是配置文件路径 |
| `-r, --repo NAME` | 自动选择 | Repository 作用域命令 | 显式选择一个 Repository，优先级最高 |
| `-d, --dist NAME` | 自动选择或全体，依命令而定 | Dist 作用域命令 | 可重复；显式选择一个或多个 Dist |
| `-T, --timeout DUR` | `0` | 会取得写锁的命令 | 等待锁的最长时间；`0` 表示一直等待 |
| `-N, --no-wait` | false | 会取得写锁的命令 | 锁被占用时立即失败；与非默认 `--timeout` 互斥 |
| `--json` | false | 全部数据输出命令 | 输出稳定机器可读结构；诊断仍写 stderr |

`--help` 与 `--version` 遵循普通 CLI 约定。阶段一不提供全局 `--format`、`--yes`、`--dry-run`、`-q/-v` 或 `--config`。

### 3.2 并行参数

`-j, --jobs N` 只出现在确实执行包解析、哈希、渲染或完整校验的命令上：`create`、`add`、`rm`、`build`、`check`。

- 默认：当前机器逻辑 CPU 数。
- `N` 必须大于等于 1。
- 并行不得改变输出顺序、选择结果、版本比较或 Changeset 内容。

### 3.3 Workspace 发现

Managed 命令按以下顺序寻找最近祖先中的 `sow.yml`：

1. 提供 `--workdir`：从该目录向上查找。
2. 否则：从当前目录向上查找。
3. 前两者未找到：从 `SOW_DIR` 指向的目录向上查找。
4. 仍未找到：退出并提示 `sow init`、`--workdir` 与 `SOW_DIR`。

找到第一个 `sow.yml` 后停止，不跨越该 Workspace 继续寻找。`sow create` 不参与此算法。

`--workdir` 只改变 Workspace/Repository/Dist 发现的 start directory，不执行 `chdir`；命令中的相对 `PATH`、`DIR`、`FILE` 仍相对真实 cwd 解析。

### 3.4 Repository 选择

需要一个 Repository 的命令按以下顺序选择：

1. 显式 `-r/--repo`。
2. 命令起始目录位于 `<workspace>/<repo>/` 内。
3. Workspace 只有一个 Repository。
4. 否则失败并列出候选，要求显式 `-r`。

`repo new/rm` 的位置参数已经明确目标，不再接受 `-r`。`where` 默认查当前 Workspace 的全部 Repository，`-r` 用于收窄。

### 3.5 Dist 选择

需要一个或多个 Dist 的命令按以下顺序选择：

1. 一个或多个显式 `-d/--dist`。
2. 命令起始目录位于 `<workspace>/<repo>/dists/<dist>/` 内。
3. 选定 Repository 只有一个 Dist。
4. 否则失败并列出候选，要求显式 `-d`。

`build`、`check` 与 `status` 在没有 `-d` 时默认作用于选定 Repository 的全部 Dist；`add`、`rm`、`ls` 必须得到明确的 Dist 集合。

### 3.6 公共值语法

- Repository/Dist 名称：`[a-z0-9][a-z0-9._-]*`，不得为 `.`、`..`、`.sow`、`pool`、`dists` 或与 Workspace 保留文件冲突的名字。
- `DUR`：Go duration 语法的 `ms/s/m/h` 组合或字面量 `0`；阶段一不引入含糊的 month/year。
- `BEFORE`：ISO-8601 日期 `YYYY-MM-DD` 或带时区 RFC 3339 timestamp；日期按本地时区零点解释并在输出中回显绝对时间。
- `GENERATION`/`OPERATION`：非负十进制整数；Generation 0 表示空基线。
- 所有相对文件路径相对真实 cwd；输出 Changeset 中的路径永远相对 Repository 根并使用 `/` 分隔。

## 4. 阶段一命令树

```text
sow create [DIR] [-j N] [--pigsty] [-S KEY [--overwrite]]
sow init [DIR]

sow config check
sow config show [--all]

sow repo ls
sow repo new NAME
sow repo show [NAME]
sow repo rm NAME [-f|--force]

sow dist ls
sow dist new NAME --format rpm|deb
sow dist show NAME
sow dist rm NAME [-f|--force]

sow add PATH... [-R|--recursive] [--skip] [-j N]
sow rm PACKAGE... [-c|--check] [--skip] [-j N]
sow ls
sow show PACKAGE
sow where PACKAGE

sow status
sow build [-j N]
sow check [-j N]
sow changes [BASE_GENERATION]

sow log [OPERATION]
sow log export [FILE]
sow log prune BEFORE
```

表中省略了适用的全局 `-C/-r/-d/-T/-N/--json`，并不表示这些命令不支持它们。

### 4.1 参数适用矩阵

下表是阶段一的封闭参数集合；未列出的参数必须报 usage error，不能被静默忽略。

| 命令 | 位置/局部参数 | 可用公共参数 |
| --- | --- | --- |
| `create` | `[DIR]`, `-j/--jobs`, `--pigsty`, `-S/--sign-with KEY`, `--overwrite` | `-T/--timeout`, `-N/--no-wait`, `--json` |
| `init` | `[DIR]` | `--json` |
| `config check` | 无 | `-C/--workdir`, `--json` |
| `config show` | `--all` | `-C`, `-r`, `-d`, `--json` |
| `repo ls` | 无 | `-C`, `--json` |
| `repo new` | `NAME` | `-C`, `-T`, `-N`, `--json` |
| `repo show` | `[NAME]` | `-C`, `-r`（NAME 省略时）, `--json` |
| `repo rm` | `NAME`, `-f/--force` | `-C`, `-T`, `-N`, `--json` |
| `dist ls` | 无 | `-C`, `-r`, `--json` |
| `dist new` | `NAME`, `--format rpm|deb` | `-C`, `-r`, `-T`, `-N`, `--json` |
| `dist show` | `NAME` | `-C`, `-r`, `--json` |
| `dist rm` | `NAME`, `-f/--force` | `-C`, `-r`, `-T`, `-N`, `--json` |
| `add` | `PATH...`, `-R/--recursive`, `--skip`, `-j` | `-C`, `-r`, `-d`（可重复）, `-T`, `-N`, `--json` |
| `rm` | `PACKAGE...`, `-c/--check`, `--skip`, `-j` | `-C`, `-r`, `-d`（可重复）, `-T`, `-N`, `--json` |
| `ls` | 无 | `-C`, `-r`, `-d`（可重复）, `--json` |
| `show` | `PACKAGE` | `-C`, `-r`, `-d`（可重复）, `--json` |
| `where` | `PACKAGE` | `-C`, `-r`, `-d`（可重复）, `--json` |
| `status` | 无 | `-C`, `-r`, `-d`（可重复）, `--json` |
| `build` | `-j` | `-C`, `-r`, `-d`（可重复）, `-T`, `-N`, `--json` |
| `check` | `-j` | `-C`, `-r`, `-d`（可重复）, `--json` |
| `changes` | `[BASE_GENERATION]` | `-C`, `-r`, `--json` |
| `log` | `[OPERATION]` | `-C`, `-r`, `-d`（过滤）, `--json` |
| `log export` | `[FILE]` | `-C`, `-r`, `-d`（过滤） |
| `log prune` | `BEFORE` | `-C`, `-r`, `-T`, `-N`, `--json` |

若 `repo show NAME` 同时给出 `-r`，二者必须相同，否则在读取状态前失败。局部短写 `-j` 在表中均表示 `-j/--jobs N`。

## 5. Plain API

### 5.1 `sow create`

```text
sow create [DIR] [-j N] [--pigsty] [-S KEY [--overwrite]]
```

**目的：**把 `DIR` 顶层现有 RPM / DEB 生成成 flat repository。`DIR` 默认为当前目录。

**扫描：**

- 只读取 `DIR` 顶层普通文件中的 `.rpm` 与 `.deb`。
- 不递归、不跟随符号链接、不读取 Workspace 配置。
- RPM 与 DEB 可共存；存在 RPM 时生成 `repodata/`，存在 DEB 时生成 `Packages` 与 `Packages.gz`。
- Flat metadata 只引用同目录包：RPM location 为 basename，DEB `Filename` 为 `./<basename>`，同时适用于 `file://` 与 HTTP 根。
- 自动从包头读取全部架构；Plain 模式没有架构参数或架构许可表。
- 所有有效版本进入索引；同一逻辑坐标对应不同内容时硬失败。

**默认行为：**

- 不生成 `repo_complete`。
- 若目标已经存在 `repo_complete`，默认模式在写索引前失败并提示改用 `--pigsty` 或由用户显式移走 marker；不得留下内容过期但仍表示“完成”的旧 marker。
- 未给出 `--sign-with` 时，不删除、移动、重命名、重签或改写任何包。
- 不生成、注入、透传或验证 modulemd。
- 只替换 SOW 已知的索引路径；未知文件保持不变。

**`-S/--sign-with KEY`：**这是 Plain RPM 包签名的显式授权。`KEY` 必须是去掉可选 `0x` 前缀后的 16、40 或 64 位十六进制 GPG key ID/fingerprint；SOW 将其规范化为大写并通过命令行 RPM macro `_gpg_name` 传给环境中的 `rpm --addsign`。私钥、passphrase、GPG home、pinentry/agent 与额外 RPM macro 都由运行环境提供，SOW 不接收、持久化或回显秘密。

- 默认只对没有可解析 OpenPGP 嵌入签名的保留 RPM 补签；已有任意可解析嵌入签名的 RPM 保持原字节。
- `--overwrite` 必须与 `--sign-with` 同时出现，改用 `rpm --resign` 对全部保留 RPM 强制重签。
- 签名只发生在同文件系统私有 stage 副本。每个结果必须重新解析出嵌入签名，保持 signature-neutral digest 与 NEVRA 不变，并以最终完整字节 SHA-256 生成 rpm-md；重复的相同输入字节只签一次再复制同一最终字节。
- 所有签名及 metadata 均成功验证后才持久化 Plain journal；journal 将 RPM 替换放在 metadata pointer 前，并绑定原/新 SHA-256。进程终止后的恢复必须使用完全相同的 `--sign-with/--overwrite` 授权，不能以较弱参数静默重放。
- `--sign-with` 要求目录至少包含一个顶层 RPM；DEB-only 目录、缺少 `rpm` 可执行文件、key/agent/passphrase 不可用或签名验证失败都在公开提交前失败。

Plain flat 目录没有 generation pointer，包体与 `repomd.xml` 也无法用一个 POSIX rename 同时切换；因此普通并发读者不获得跨多文件瞬时原子性。SOW 保证 durable journal 可恢复为完整操作终态；`--pigsty` 调用方还必须把 `repo_complete` 缺失视为构建中门禁。

**`--pigsty`：**这是显式的兼容与清理开关，同时启用以下不可拆分行为：

1. 根据解析后的包事实排除并删除 32 位 x86 包：RPM `i386/i486/i586/i686`，DEB `i386`。
2. 根据包头删除二进制包名恰为 `patroni` 且 upstream version 恰为 `3.0.4` 的 RPM / DEB。RPM 比较 `VERSION`，忽略 epoch 与 release；DEB 从完整 version 中剥离 epoch 与 Debian revision 后比较 upstream version。`3.0.4+foo` 不算精确命中。
3. 在全部索引成功后生成 `repo_complete`。内容为剩余顶层 RPM / DEB 的 SHA-256，按 basename 字节序稳定排序，格式为 `<sha256><两个空格><basename>`。

清理只触碰已成功解析并命中上述规则的顶层普通包文件；不得按宽泛 glob 删除目录或未知文件。实现必须先生成并验证“不含待清理包”的新索引；进入提交窗口前暂时撤下已有 `repo_complete`，再切换索引，把待清理包原子 rename 到同文件系统 recovery trash，最后原子写入新的 `repo_complete`，成功后才清空 trash。这样以 marker 为门禁的调用方不会把中间状态当成完成，客户端也不会看到索引指向已删除包。

**锁与提交：**对目标目录取得 Plain 写锁，服从 `--timeout/--no-wait`。元数据先写同一文件系统的 stage，验证后再切换；失败时旧索引继续可用。相同输入重复运行应为 no-op 或产生语义等价索引。

同一次 create 发现 RPM 与 DEB 时，两套 renderer 属于同一个 Plain Operation：必须先全部 stage/验证再开始切换；崩溃造成的跨格式中间状态由轻量 journal 在下一次调用时完成或回滚，不能把其中一套成功当成整个命令成功。

**失败：**

- 没有受支持包、包解析失败、坐标冲突、签名/验证失败、渲染失败或目标不可写时非零退出。
- `--pigsty` 在完成清理前发生崩溃时，下一次 `create --pigsty` 必须根据轻量恢复记录幂等收敛；Plain 模式仍不建立 SQLite。
- 验收必须在 journal 落盘后、旧 marker 撤下后、每类 metadata pointer 切换后、每个 package rename 后、新 marker 换入前后分别注入进程终止；重跑只能得到完整旧状态或完整新状态，trash 不得丢包，完成 marker 不得与包清单不符。

## 6. Workspace 与配置 API

### 6.1 `sow init`

```text
sow init [DIR]
```

在 `DIR`（默认当前目录）创建根级 `sow.yml` 与 `.sow/`。

- 写入 `schema: sow/v2` 与默认 `architectures: [x86_64, aarch64]`。
- 不自动创建 Repository。
- 已存在 `sow.yml` 时不覆盖；重复运行只报告现状。
- 非空目录可初始化，但若已有与 SOW 保留路径冲突的文件则失败。
- 如果配置文件定义了 repo 和 dists ，则应该一并完成初始化（但不用碰已经完成的）

### 6.2 `sow config check`

只读解析并校验完整 `sow.yml`：schema、名称、路径冲突、架构许可、Dist 格式、Policy 与签名引用。它不创建目录、不改数据库、不自动修正配置。

### 6.3 `sow config show`

```text
sow config show [--all]
```

- 默认：显示当前选择作用域的紧凑有效配置。
- `--all`：显示完整 Workspace，并展开默认值、继承的架构与规范化别名。
- 密钥材料和 passphrase 永不输出；只显示引用与 fingerprint。

## 7. Repository 与 Dist API

### 7.1 `sow repo ls`

只读列出 Workspace 中所有 Repository：名称、是否 protected、Dist 数量、Built Generation 与 clean/dirty/recovering 状态。

### 7.2 `sow repo new`

```text
sow repo new NAME
```

原子更新 `sow.yml`，创建固定目录 `<workspace>/<NAME>/{pool,dists}`、SQLite 与私有状态目录。不允许指定 path。成功后的空 Repository 为 Generation 0、clean。

### 7.3 `sow repo show`

```text
sow repo show [NAME]
```

NAME 省略时使用 Repository 选择规则。只读显示路径、配置、包对象数、Dist、Generation、dirty 原因与最近操作。

### 7.4 `sow repo rm`

```text
sow repo rm NAME [-f|--force]
```

- 无 `-f`：只删除没有 Dist、Membership 与 Package Object 的空 Repository。
- 有 `-f`：删除 SOW 明确拥有的该 Repository 配置、数据库、pool、dists 与私有状态。
- `protected: true` 时即使有 `-f` 也拒绝；用户必须先修改并通过 `config check`。
- 不跟随符号链接，不越出固定 Repository 路径。

### 7.5 `sow dist ls`

只读列出选定 Repository 的全部平铺 Dist：名称、format、有效架构、Policy、成员数、Built Generation 与 dirty 状态。

### 7.6 `sow dist new`

```text
sow dist new NAME --format rpm|deb
```

创建一个普通、可继续修改的 Dist。唯一业务参数是 `--format`；架构继承配置，不接受 `--arch`。

- Dist 名对 SOW 是不透明字符串；beta、production、客户与快照只是命名约定。
- 创建时生成该格式的空索引并形成新 Built Generation。
- Policy 通过 `sow.yml` 编辑，不在命令行重复建模。

### 7.7 `sow dist show`

```text
sow dist show NAME
```

只读显示 format、有效架构、Policy、Desired/Built 成员计数、Generation 与相关 dirty 原因。

### 7.8 `sow dist rm`

```text
sow dist rm NAME [-f|--force]
```

- 无 `-f`：只删除空 Dist。
- 有 `-f`：删除该 Dist 的 Membership 与衍生索引。
- 永不因删除 Dist 而删除 Pool 包字节；阶段一没有 GC。
- Repository 的 `protected` 只禁止整个 Repository 删除，不妨碍正常 Dist 维护。

## 8. 架构契约

### 8.1 规范化架构族

配置使用 SOW 的 canonical family，而不是把两个生态的名字当成四种架构：

| Canonical family | RPM 包头 / view | DEB 包头 / view | 免架构包 |
| --- | --- | --- | --- |
| `x86_64` | `x86_64` | `amd64` | RPM `noarch` / DEB `all` |
| `aarch64` | `aarch64` | `arm64` | RPM `noarch` / DEB `all` |

因此 `amd64` 与 `x86_64` 是同一 CPU family 的生态别名；`arm64` 与 `aarch64` 同理。`config show --all` 总是展示 canonical family。

### 8.2 许可上限

Workspace 根配置：

```yaml
schema: sow/v2
architectures: [x86_64, aarch64]
```

- 这是 SOW 允许管理的原生架构上限，默认即上表两项。
- Dist 默认继承全部；高级用户可在 `sow.yml` 为某个 Dist 声明其子集，但 CLI 不要求用户逐次操心。
- 未来 `riscv64`、`loong64` 等必须先由当前 SOW 版本实现，再显式加入配置；不能仅靠遇到一个包就静默扩容。

### 8.3 入库与视图规则

1. `add` 从包头读取 format 与 architecture。
2. 原生架构不在 Workspace 许可表中：该包失败，错误指出检测值与需要修改的配置。
3. 原生包只进入 format 相同且有效架构包含该 family 的目标 Dist，并只出现在匹配 view。
4. RPM `noarch` / DEB `all` 只建立一个 Package Object 与一个 Dist Membership，但渲染进该目标 Dist 的全部有效架构 view。
5. 免架构包不会自动加入未被 `-d` 选中的其他 Dist。
6. 从许可表移除架构时，若仍有 Dist 配置、Membership 或 Built Generation 使用它，`config check/build` 必须拒绝；加入架构后相关 Dist 变 dirty，下一次 build 生成新 view。

该模型沿用 reprepro 的核心做法：发行版配置先声明 Architecture，包的 `Architecture` 字段必须匹配；`all` 包再扩展到已声明的各架构索引，而不是让包输入反向修改配置。

## 9. 包身份与唯一性契约

### 9.1 三层身份

**物理对象（Content Object）：**签名策略处理完成后的完整包字节，以 SHA-256 为身份；Repository 内不可变。

对象在 `--skip` 后可以先位于私有 `.sow/<repo>/pending/`；只有成功 build 才进入公开 `pool/`。位置不改变内容身份。

RPM 额外保存一个 **signature-neutral payload digest**：对除 RPM signature header 外的不可变 header+payload 计算 SHA-256。它只用于识别“同一 unsigned RPM 的重复入库”，不是公开对象身份，也不能绕过逻辑坐标唯一约束。

**逻辑坐标（Package Coordinate）：**

- RPM：`(format, name, epoch, version, release, arch)`，即 NEVRA。
- DEB：`(format, package, version, architecture)`；Debian version 已包含 epoch 与 revision。

**成员关系（Membership）：**`(dist, content_sha256)` 唯一；Architecture View 只是渲染投影，不创建第二份 Membership。

### 9.2 冲突规则

| 情况 | 结果 |
| --- | --- |
| 同一 SHA-256 再加入 | no-op，可给新的 Dist 增加引用 |
| 同一逻辑坐标、同一 SHA-256 | 同一 Package Object |
| 同一 RPM 坐标、同 signature-neutral digest，且既有对象满足当前签名策略 | 视为同一 unsigned payload 的重试，复用既有最终对象 |
| 同一逻辑坐标、不同 SHA-256 | 硬冲突，不覆盖、不任选其一 |
| 同一包名/架构、不同版本 | 允许；由 Dist Limit 决定 Membership |
| 同一 SHA-256 属于多个 Dist | Pool 仍只有一份 |
| 两个 Repository 含相同 SHA-256 | 各自保存，不跨 Repository 去重 |

Filename 不是身份。Pool path 是由规范化事实推导的存储位置；同 path 不同 SHA-256 同样是冲突。

这一约束刻意区分业界常见的两层问题：内容校验和适合识别签名不同但 NEVRA 相同的物理文件；Repository 内再用逻辑坐标唯一约束阻止客户端面对两个不可区分的候选。阶段一不提供 `--replace`；重签导致字节变化时，应提高 release，或以后设计独立的 key rotation/replace 工作流。

### 9.3 Limit

`limit` 在每个 Dist 内按 `(binary name, native architecture)` 分组：

- `0`：保留全部版本。
- 正整数 `N`：按 RPM EVR 或 Debian version 原生规则保留最新 N 个 Membership。
- 负数：配置错误。

`noarch/all` 作为自己的 native architecture 只计数一次，虽然会渲染到多个 view。Limit 与 exclude 在每次 Membership 写入和因配置变化触发的 build 中强制执行。

阶段一不保存“被 Policy 压掉但将来可自动复活”的候选 Membership：exclude/Limit 移除的是实际 Desired Membership。收紧 Policy 后 build 可以继续移除不合规成员；放宽 exclude 或提高 Limit 不会猜测性地复活旧成员，用户必须重新 `add`。Pool 中残留字节不等于该 Dist 的候选集合。

### 9.4 Exclude 规则

阶段一只接受一个可完全验收的最小规则形态：`exclude` 是 rule 列表；rule 内字段做 AND，同字段的多个 pattern 做 OR，多个 rule 之间做 OR。任一 rule 命中即排除。字段和求值顺序不影响结果。

```yaml
exclude:
  - kind: [debuginfo, debugsource, dbgsym, dbg, llvmjit]
  - name: ["test-*", "*-experimental"]
    arch: [aarch64]
```

允许字段：

| 字段 | 规范化值 |
| --- | --- |
| `name` | binary package name |
| `source` | 规范化 source name |
| `arch` | `x86_64`、`aarch64`、`neutral` |
| `kind` | 下表固定枚举 |
| `format` | `rpm`、`deb` |

pattern 为区分大小写的 exact 或 shell glob（`* ? []`）；不支持 regex、版本比较、否定或公式。未知字段、空 rule、非法 glob 在 `config check` 时失败。

`kind` 由 binary name 确定，优先使用最具体后缀：

| Format | name 后缀 | kind |
| --- | --- | --- |
| RPM | `-debuginfo` | `debuginfo` |
| RPM | `-debugsource` | `debugsource` |
| RPM | `-llvmjit` | `llvmjit` |
| DEB | `-dbgsym` | `dbgsym` |
| DEB | `-dbg` | `dbg` |
| 任意 | 以上均不匹配 | `main` |

Policy 顺序固定为 exclude 后 Limit。分类结果由 `show --json` 暴露并进入 golden tests，不能依赖文件所在目录或当前主机。

## 10. Package Mutation API

### 10.1 `sow add`

```text
sow add PATH... [-R|--recursive] [--skip] [-j N]
```

**输入与目标：**

- `PATH` 可为文件或目录；目录默认只扫描顶层，`-R` 才递归。
- 必须选择一个 Repository 与一个或多个目标 Dist。
- 混合 RPM / DEB 批次允许：每个包只考虑 format 匹配的目标 Dist；若一个包没有任何兼容目标则该包失败。
- 不使用 manifest、目录名路由或主机 OS 推断目标。

**处理顺序：**

1. 取得 Repository 写锁并恢复未完成 Operation。
2. 在 SQLite 中提交 `planned` Operation。
3. 只读解析输入，计算逻辑坐标、输入字节 SHA-256；RPM 同时计算 signature-neutral payload digest。
4. 校验架构许可并查询既有坐标：满足下述 retry reuse 规则则复用已有对象；同坐标但不能复用则硬冲突。
5. 对尚不存在的坐标，才在 stage 副本上执行可选 RPM 签名并计算最终 SHA-256，再校验内容/path 唯一性。
6. 对目标 Membership 执行 merge，再对完整 Dist 集合执行 exclude 与 Limit。
7. 提交 Desired State；新包字节持久化到私有 pending content store。
8. 默认构建所有受影响 Dist：先把仍被 Desired Membership 需要的 pending 对象发布进 Pool，再生成索引；一次命令中每个 Dist 最多构建一次。

**RPM 签名模式：**

- `never`：保持输入字节。
- `fill`：无签名或签名不受信任时使用配置 key 签名；已有由 `trusted_keys`（配置 key 的 public half 自动包含）验证通过的签名时保持。存在 key 时默认 `fill`。
- `always`：确保最终包由配置 key 有效签名；已经由该 key 有效签名时保持字节，否则重签 stage 副本。

没有 key 时只能使用 `never`。任何模式都不改输入文件。

**签名重试幂等：**签名包含时间等非确定字段，因此同一 unsigned RPM 不能每次先重签再比较最终 SHA。若逻辑坐标已存在：

- 输入完整字节 SHA-256 与既有对象相同：直接复用。
- RPM signature-neutral digest 相同，且既有对象满足当前策略：复用既有最终字节，不再签名。`fill` 要求既有对象由当前 `trusted_keys` 验证通过；`always` 要求由当前配置 key 有效签名。
- `never` 除完整字节相同外不做 signature-neutral 复用，因为该模式承诺保留输入字节。
- payload digest 不同，或已有对象不满足当前签名策略：硬冲突；不得借 add 原地重签同坐标。

因此同一 unsigned RPM 重复 add 是稳定 no-op，同时仍保持“同坐标只有一个最终内容对象”。

**Policy 结果：**

- exclude 命中的包可被明确报告为 `excluded`，不算解析失败；若未被任何 Dist 接受，不写无主 Pool 对象。
- Limit 造成的旧 Membership 移除与新 Membership 增加属于同一 Operation。
- 一个包可在部分 Dist 接受、部分 Dist 因 format/architecture/policy 跳过；逐 Dist 报告。

**批次失败：**合法且无冲突的包可以提交，非法包保持原位置并逐项报错；只要存在失败项，整体退出为“部分成功”。阶段一没有 rejected 目录。

**`--skip`：**完成步骤 1–7 后结束，Repository 变 dirty；Built Generation 以及公开 `pool/ + dists/` 保持原样。Operation 记录 `done_dirty`。新包在私有 pending store 中耐久保存，后续 build 才发布；该选项不会制造半套新索引或改变可复制目录。

### 10.2 `sow rm`

```text
sow rm PACKAGE... [-c|--check] [--skip] [-j N]
```

只删除所选 Dist 的 Membership，不直接删除 Pool 字节。

`PACKAGE` 接受：

- `sha256:<hex>`；
- RPM 逻辑坐标 `rpm:<NEVRA>`；
- DEB 逻辑坐标 `deb:<name>=<version>:<architecture>`；
- 完整 filename；
- 裸二进制包名。裸名称表示所选 Dist 中该名称的全部版本与原生架构。

`sow ls` 必须直接输出上述 SHA-256 reference 与规范化 coordinate，用户不需要手工拼接。其他模糊短引用必须失败并列出候选。

- `-c/--check`：计算并打印将移除的 Membership、Policy 后果与若立即 build 会产生的文件变化，不写任何状态。
- 实际执行默认自动 build；`--skip` 只更新 Desired State 并标 dirty。
- `--check` 与 `--skip` 互斥。
- `--check` 不取得写锁；若同时显式给出 `--timeout/--no-wait`，按 usage error 处理，避免用户误以为预览会等待写事务。
- 无匹配时失败；没有 `--allow-empty`、`--all`、`--yes`、`--source-list`。

### 10.3 查询命令

```text
sow ls
sow show PACKAGE
sow where PACKAGE
```

- `ls`：列出所选 Dist 的 Desired Membership；若 dirty，明确显示 Built Generation 尚未包含哪些变化。
- `show`：默认在选定 Repository 内查找，`-d` 仅收窄候选/Membership；显示一个 Package Object 的坐标、SHA-256、签名、pool path、规范化事实与 Membership；歧义时失败并列候选。
- `where`：默认在 Workspace 全部 Repository 中查一个引用所在的 Dist；`-r/-d` 可收窄。
- 三者都只读，支持统一 `--json`，没有 `--pool`、`--match` 或各自的 format 参数。
- `show/where` 的 PACKAGE 使用与 `rm` 相同的 exact reference/coordinate/filename/name 语法；裸 name 匹配多个对象时列出候选并失败，不像 `rm` 那样解释为批量删除。

## 11. 状态、构建与校验 API

### 11.1 状态模型

每个 Repository 同时维护：

- **Desired Revision：**SQLite 中最新 Package Object、Membership、Policy 计算结果。
- **Built Generation：**当前 `dists/` 静态树对应的完整已验证版本。

状态只有四类：

| 状态 | 含义 | 客户端静态树 |
| --- | --- | --- |
| `clean` | Desired 与 Built 一致 | 当前各 view 完整可用 |
| `dirty` | Desired 领先，通常来自 `--skip` 或配置变化 | 旧 Built view 仍完整可用 |
| `recovering` | 存在未完成 Operation，下一写命令须先恢复 | 每个 view 只能暴露最后完成的协议指针 |
| `error` | 自动恢复无法安全决定，需要人工处理 | 最后完成的 view 不得被覆盖 |

### 11.2 `sow status`

便宜、只读、不做全量哈希。显示：Repository 状态、Desired Revision、Built Generation、dirty Dist、pending payload 数量/字节、未完成 Operation、锁持有者与最近完成 Operation。

`status` 不自动恢复、不把“存在旧但自洽的 Generation”误报为索引损坏。

只要状态数据库可读，`status` 在 clean/dirty/recovering/error 下都返回 0，让脚本读取结构化 state；只有无法读取/解析状态时返回完整性错误。是否 ready-to-copy 由输出字段明确给出，严格门禁使用 `sow check`。

`build` 是阶段一唯一显式 forward-recovery 入口：它会先尝试完成或回滚可判定的非终态 Operation。`error` 专指 journal/DB/文件证据互相矛盾、工具无法安全自动选择的情况；此时 build 拒绝覆盖，用户从备份恢复后再运行 check/build。阶段一不提供可能猜错的 `repair --force`。

### 11.3 `sow build`

```text
sow build [-j N]
```

取得写锁，先恢复未完成 Operation，再把当前 Desired State 收敛成新 Built Generation。

- 无 `-d`：构建选定 Repository 的全部受影响 Dist。
- 有重复 `-d`：只收敛所选 Dist；其他 dirty Dist 保持 dirty。
- build 再次执行当前 Policy，因此手工修改 limit/exclude 后可通过 build 收敛。
- 这种收敛是单向约束检查：收紧 Policy 可移除成员，放宽 Policy 不会从 Pool 反推并恢复历史成员。
- 所有元数据在同文件系统 stage 完成、校验、签名后切换；RPM 的 `repomd.xml`、APT 的 `Release/InRelease` 等协议指针最后替换。实现必须用 checksum-named metadata 与 APT by-hash（或经真实客户端证明等价的机制）保证旧/新客户端不会取得悬空引用。
- 一个 build Operation 可以覆盖多个 Dist，但阶段一不承诺并发读者在同一瞬间看到所有 Dist 一起翻代；承诺的是每个协议 view 始终自洽，以及命令返回后全部目标属于同一 Built Generation。
- 输入与 renderer 配置没有变化时 no-op，不增加 Generation。
- 成功后为实际变化创建一个单调递增 Built Generation 与物理 Changeset。

**Managed metadata 签名：**只由 `sow.yml` 控制，没有临时 CLI override。

- RPM architecture view 始终生成 `repodata/repomd.xml`；配置 `signing.rpm.metadata.key` 时同时原子生成 ASCII-armored `repodata/repomd.xml.asc`。
- DEB Dist 始终生成 `Release`；配置 `signing.deb.metadata.key` 时同时生成 clearsigned `InRelease` 与 detached armored `Release.gpg`。未配置 key 时不生成这两个签名文件。
- key 引用或 fingerprint 变化使相关 Dist dirty；build 重新签名并形成新 Generation。
- `config check` 验证 key 引用可解析且适用于签名；`config show --all` 只显示引用与 fingerprint；`check` 验证所有声明的签名与文件 hash。
- key/passphrase 可以来自文件、agent 或 `env://` 引用，但秘密内容永不写入 config、SQLite、log、JSON 或错误文本。

### 11.4 `sow check`

```text
sow check [-j N]
```

完整、只读校验所选 Repository/Dist：配置、SQLite 关系、Pool 与 pending payload 的 SHA-256、包坐标、签名、Desired Membership、Built metadata、索引引用与 Architecture View。

- Dirty 时分别验证 Desired State 与旧 Built Generation，并返回“尚未 ready-to-copy”，而不是声称静态树半损坏。
- 不 repair、不 build、不恢复 Operation。
- 结果按配置、状态、包字节、索引、签名分层输出。

### 11.5 自动 build 矩阵

| 命令 | 默认 | 带 `--skip` |
| --- | --- | --- |
| `add` | 更新 Desired、发布 Pool、受影响索引与 Generation | 更新 Desired/private pending，公开树不变，标 dirty |
| `rm` | 更新 Desired、受影响索引与 Generation | 更新 Desired，标 dirty |
| `dist new` | 创建空索引与 Generation | 不支持 |
| `dist rm` | 删除衍生索引并形成 Generation | 不支持 |
| `build` | 收敛 dirty/配置变化 | 不适用 |
| `repo new/rm` | 不调用 dist build | 不适用 |

## 12. Operation Journal、Changeset 与 Log

### 12.1 Operation Journal

每个 Repository 内写命令必须先在该 Repository SQLite 提交一条应用级 Operation，再产生外部文件副作用。最小生命周期：

```text
planned → staged → applied → built → done
                         └────────→ done_dirty
   any nonterminal → recovering → built / rolled_back
   pre-apply error  → failed
```

- `planned`：命令、参数、目标与预期动作已经持久化。
- `staged`：新包/元数据已经写入临时位置并校验。
- `applied`：Desired State 与所需 private pending payload 已提交；公开 Pool 尚可保持旧 Generation 状态。
- `built`：完整静态 Generation 已切换。
- `done` / `done_dirty`：终态；可作为审计日志。

Operation 子记录保存 package、membership 与 file action。下一条写命令开始前必须检查所有非终态 Operation，并以幂等步骤完成或回滚；不能直接忽略。

Workspace 生命周期是明确例外：`init/repo new/repo rm` 使用 §2.2 的 workspace file journal，因为目标 Repository DB 尚不存在或将被删除。`dist new/rm` 已有 Repository DB，仍走 SQLite Operation Journal。

默认 build 的 mutation 若在 `applied` 后渲染失败，命令返回失败，旧 Built view 继续服务，Operation 保持可恢复状态；当前进程能安全回滚则标 `rolled_back`，否则 Repository 为 `recovering`，下一写命令必须先继续或回滚。只有用户显式给出 `--skip` 才能以 `done_dirty` 正常结束。

这不是 SQLite 的 `journal_mode=WAL`。SQLite WAL 只负责 SQLite 页面事务与单写并发；它不会替 SOW 原子协调 Pool、stage 和 `dists/` 文件。应用级 Operation Journal 才负责跨数据库记录与 POSIX 文件动作的恢复。

### 12.2 `sow changes`

```text
sow changes [BASE_GENERATION]
```

- 无参数：显示最近一个 Built Generation 相对其前一代的 Repository 物理文件变化。
- 指定 BASE：显示 BASE 到当前 Built Generation 的净物理变化；`0` 表示生成当前 Built Generation 的完整 Repository 交付清单（`pool/` 与 `dists/`），不包含 `sow.yml/.sow`。
- Dirty Desired State 不进入 changes；输出会警告 Repository dirty，并仍以当前 Built Generation 为终点。
- Repository 为 `recovering/error` 时 changes 拒绝输出可同步计划；必须先完成恢复或从备份恢复，避免把未决文件动作误当成 Generation。

默认文本输出适合人工查看。`--json` 至少包含：

```json
{
  "base": 41,
  "generation": 43,
  "dirty": false,
  "changes": [
    {
      "op": "add",
      "path": "pool/p/pkg/pkg.rpm",
      "phase": "payload",
      "size": 123,
      "sha256": "..."
    }
  ]
}
```

`op` 为 `add/update/delete`；`phase` 为 `payload/metadata/pointer/delete`。外部工具可以按 phase 顺序转换为 rclone 操作，但 SOW 不生成 endpoint 配置、不调用 rclone。

Changeset 选择的是成功 build 后的**物理交付树**。`--skip` 的新内容位于私有 pending store，不提前改变公共 Pool，也不进入 changes；下一次 build 只把届时仍被 Desired Membership 需要的对象发布为 `payload`。若对象在 build 前已被 rm/Policy 移除且没有其他 Desired 引用，恢复流程可以丢弃对应 private pending 文件，它从未成为公开 Pool 的 GC 问题。Repository 处于 clean/dirty 终态时，`changes 0`、Built Generation manifest 与可直接 rsync 的 `pool/ + dists/` 文件集合一致；recovering 中若已有 payload 被临时提升，恢复必须完成或删除这些未提交对象后才能重新输出 changes。

Changeset 是 Repository Built Generation 级别的输出，不接受 `-d`；需要单个 Dist 的消费者仍从完整 changes 中按 repository-relative path 过滤。

### 12.3 `sow log`

```text
sow log [OPERATION]
sow log export [FILE]
sow log prune BEFORE
```

- 无参数：按新到旧显示最近 50 条 Operation。
- 指定 Operation ID：显示状态迁移、包、Membership、文件变化、耗时与错误。
- `-d` 对查询与 export 表示只显示/导出触及该 Dist 的 Operation。
- `export`：将可清理的终态 Operation 以 JSONL 写入 FILE；FILE 省略或为 `-` 时写 stdout。
- `prune BEFORE`：Repository 级删除给定 ISO-8601 日期/时间之前的已终态审计记录并安全压缩数据库；不接受 `-d`，避免产生半条 Operation。

`prune` 永不删除非终态 Operation、当前恢复所需记录、Package/Membership 当前状态、Built Generation 或 Changeset。Log 与 Changeset 在第一阶段位于同一 SQLite，但语义与保留规则不同。

## 13. 配置最小示例

```yaml
schema: sow/v2
architectures: [x86_64, aarch64]

repos:
  pgsql:
    protected: true
    signing:
      rpm:
        packages:
          mode: fill
          key: env://SOW_RPM_PACKAGE_KEY
          trusted_keys: [keys/pgdg.asc]
        metadata:
          key: env://SOW_REPO_METADATA_KEY
      deb:
        metadata:
          key: env://SOW_REPO_METADATA_KEY
    dists:
      el9:
        format: rpm
        limit: 1
        exclude:
          - kind: [debuginfo, debugsource, llvmjit]
      el9-beta:
        format: rpm
        limit: 0
      noble:
        format: deb
        limit: 1
```

Dist 只有在需要缩窄 Workspace 上限时才声明 canonical `architectures` 子集。`sow dist new` 不要求这项参数。

## 14. 典型 User Stories

### US-1：创建普通 flat 仓库

```bash
cd /srv/offline
sow create
```

结果：RPM、DEB 或两者的 flat 索引自动生成；包文件不变；没有 `repo_complete`。

### US-2：替代 Pigsty 现有 plain 构建

```bash
sow create /www/pigsty -j 8 --pigsty
```

结果：清除解析确认为 32 位 x86 与 Patroni 3.0.4 的包，生成索引，并最后生成 SHA-256 `repo_complete`；不生成 modulemd。

### US-3：初始化多 Repository Workspace

```bash
mkdir -p ~/repo && cd ~/repo
sow init
sow repo new infra
sow repo new pgsql
sow dist new el9 --format rpm -r pgsql
sow dist new noble --format deb -r pgsql
```

结果：根目录只有一个 `sow.yml`；每个 Repository 有独立 pool、dists 与 SQLite。

### US-4：把免架构包加入多个 Dist

```bash
sow add ./build/foo-1.0-1.noarch.rpm \
  -r pgsql -d el9 -d el9-beta
```

结果：自动识别 `noarch`；Pool 只有一个对象；两个 Dist 的 x86_64 与 aarch64 view 都包含它；返回前索引完成。

### US-5：批量导入后统一构建

```bash
sow add ./build/ -R -r pgsql -d el9 --skip
sow status -r pgsql
sow build -r pgsql -j 12
sow check -r pgsql
```

结果：add 后 Desired 领先、旧 Generation 仍自洽；build 一次收敛；check 证明新静态树可复制。

### US-6：Policy 自动执行

```bash
sow add ./monthly/ -R -r pgsql -d el9
```

若 `el9` 配置为排除 debug 且 `limit: 1`，add 先 merge，再排除 debug，并移除各 name/arch 的过时 Membership；Pool 字节不由此 GC。

### US-7：安全下架

```bash
sow rm patroni -r pgsql -d el9 -c
sow rm patroni -r pgsql -d el9
```

第一条只预览；第二条移除所选 Dist 内 patroni 的全部版本/架构 Membership 并自动重建索引。

### US-8：给外部 rclone 消费变化

```bash
sow changes 41 -r pgsql --json > changes-41-current.json
```

外部脚本按 `payload → metadata → pointer → delete` 消费；SOW 不持有远端凭据或状态。

### US-9：导出并收缩审计日志

```bash
sow log export pgsql-ops.jsonl -r pgsql
sow log prune 2026-01-01 -r pgsql
```

当前状态、未完成恢复记录与 Generation Changeset 不受影响。

### US-10：阻止未知架构静默进入

```bash
sow add ./foo.riscv64.rpm -r pgsql -d el9
```

结果：命令报告检测到 `riscv64`，但 Workspace 仅允许 `x86_64/aarch64`；它不创建目录、不改配置。只有实现已支持且用户显式修改 `sow.yml` 后才可接纳。

## 15. 退出码与输出契约

| 退出码 | 含义 |
| --- | --- |
| `0` | 完整成功或幂等 no-op |
| `1` | 运行时 I/O、解析、渲染、签名或未知内部错误 |
| `2` | CLI 用法、Workspace 发现或配置错误 |
| `3` | 批次部分成功；至少一个项目已提交、至少一个失败 |
| `4` | 写锁立即失败或等待超时 |
| `5` | 完整性/恢复错误，或 `check` 判定当前结果不可交付 |
| `6` | 架构/目标不兼容、逻辑坐标冲突、protected 门禁或无匹配等预期拒绝 |

人类可读结果写 stdout，警告与诊断写 stderr。`--json` 使用版本化顶层 `schema: sow.cli/v1`，并至少包含 `command`、`ok`、`repository`、`operation`、`result`、`errors`；即使退出非零，已经提交的部分成功项目也必须完整列出。

## 16. 阶段一明确不提供

- `route` 及其配置占位。
- modulemd 的生成、注入、保留、检查与相关参数。
- `sync`、`publish`、endpoint、CDN、对象存储或远端锁。
- `pull`、`push`、`copy`、`move`、`promote`、snapshot 状态机。
- manifest、rejected quarantine、公式/list/source-list 选择器。
- SRPM、DSC 与源包索引。
- GC、跨 Repository 去重、多机多写、服务或 Web UI。

这些能力不得以空命令、隐藏 flag 或未兑现的配置键提前进入阶段一 API。
