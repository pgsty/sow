---
title: sow V2 阶段一 — 本地 APT / YUM 仓库管理器
status: approved
created: 2026-07-31
updated: 2026-08-02
api_contract: ./api-contract.md
---

# sow V2 阶段一 PRD

## 0. 文档目的与状态

本文重新定义 `sow` V2 阶段一的产品边界、用户价值、功能需求和验收标准。公共命令、参数、默认值、状态变化和退出码以同目录的 [API 契约](./api-contract.md) 为准；本文不再维护第二份略有差异的 CLI 清单。

本文已由产品所有者于 2026-08-02 确认 P1–P3 完整落地目标，状态为 **approved**。V1 已归档，只作为可复用实现资产与失败经验，不继承其远端发布模型、目录布局、命令面或状态机。

## 1. 背景与问题

Pigsty 当前同时维护 APT 与 YUM 仓库。已有工具链能工作，但长期暴露出四类问题：

1. 仓库维护与 CDN、对象存储、同步发布耦合，核心边界过大。
2. APT 与 YUM 被当成两套产品管理，包、索引、架构与状态模型不统一。
3. reprepro 的 Repository/Dist/Pool 模型经过长期实践，但它的配置、数据库与静态产物混在同一交付目录，且使用了不再需要的历史技术选择。
4. 日常仍需要最简单的 flat repository：把一个目录中的 RPM / DEB 直接生成索引。这个最常用的短路径不应被复杂 managed 模型绑架。

V2 因而按绿地项目设计，同时有选择地复用 V1 已验证的包解析、版本比较、索引渲染、签名校验与安全文件操作能力。

## 2. 产品愿景

`sow` 是一个纯本地、单机单写、纯 Go 单二进制的 APT / YUM 仓库管理器。它只负责把本地包字节和声明式成员关系变成正确、完整、可直接复制的静态仓库树。

阶段一提供两个从用户任务出发的垂直闭环：

- **Plain 闭环：**一条 `sow create` 将平铺 RPM / DEB 目录变成可用软件源。
- **Managed 闭环：**一个 Workspace 管理多个 Repository；每个 Repository 管理共享 Pool、平铺 Dist、SQLite 状态与静态 Generation。

产品不关心这些目录如何上传、同步或发布。成功构建后的 Repository 目录可以被 rsync/rclone 原样复制；增量消费者通过本地 Changeset 得知路径变化。

## 3. 目标用户与核心任务

### 3.1 目标用户

阶段一只有一个角色：在 macOS 或 Linux 的本地 POSIX 文件系统上维护 Pigsty 软件仓库的单一运维者。

- 同时只允许一个写者。
- 多个写调用简单排队；无需服务端、多用户权限或分布式锁。
- 用户负责备份 `sow.yml`、每个 Repository SQLite、private pending payload 与 Pool。

### 3.2 Jobs To Be Done

- 我已经有一批 RPM / DEB，希望一条命令把当前目录变成可用的简单软件源。
- 我希望在一个 Workspace 中维护 infra、pgsql 等多个互不影响的 Repository。
- 我希望把一个包显式加入一个或多个 Dist，而 Repository 内只保存一份包字节。
- 我不想在 add 时填写架构；工具应从包头识别，并自动把 `noarch/all` 放入所有适用 view。
- 我希望 OSS Dist 始终排除 debug，并只保留每个包的最新版本，而不是每次手工清理。
- 我希望 `add/rm` 默认立即产生完整索引；批量操作时又能显式延迟构建，最后一次收敛。
- 我希望崩溃后工具能知道做到哪一步，既可恢复，又可追溯谁改变了哪些包与文件。
- 我希望得到本地 Generation 差异给外部 rclone 消费，但不让 SOW 持有任何远端状态。

## 4. 产品模型

### 4.1 层次与所有权

```text
Workspace
├── sow.yml
├── .sow/
│   ├── <repo>.db
│   └── <repo>/          private lock, stage, recovery state
└── Repository
    ├── pool/            immutable package bytes
    └── dists/
        └── Dist         explicit membership set
            └── Architecture Views
```

- **Workspace** 是发现与配置边界，根目录只有一份固定名称 `sow.yml`。
- **Repository** 是 Pool、SQLite、写锁、恢复、Generation 与 Changeset 边界。
- **Dist** 是一种包格式的具名成员集合；beta、production、客户与快照均平铺为普通 Dist，快照仍可修改。
- **Architecture View** 是 Dist Membership 的渲染投影，不是额外成员关系。
- 跨 Repository 不去重，也不承诺原子提交。

### 4.2 静态交付布局

```text
workspace/
├── sow.yml
├── .sow/
│   ├── infra.db
│   └── pgsql.db
├── infra/
│   ├── pool/
│   └── dists/
└── pgsql/
    ├── pool/
    └── dists/
        ├── el9/x86_64/repodata/
        ├── el9/aarch64/repodata/
        └── noble/
            ├── Release
            └── main/binary-{amd64,arm64}/Packages.gz
```

`.sow/` 与 `sow.yml` 位于 Repository 的并列上层，因此交付时只需复制 `infra/` 或 `pgsql/`；私有数据库、配置、锁和 stage 不会混入静态产物。

RPM 与 DEB 共用 `pool/<prefix>/<source>/<filename>`：普通 source 的 prefix 取首字符，`lib*` 沿用 Debian 的前四字符规则，再把 prefix 统一转为 ASCII 小写；source 与 filename 保持原始大小写。完整 Pool path 若在大小写不敏感比较下碰撞则拒绝，避免默认 macOS 文件系统生成的 Repository 搬到 Linux 后丢失路径身份。source 从 RPM `SOURCERPM` 或 DEB `Source` 读取，缺失时回落到 binary name 并告警。APT component 在阶段一固定为 `main`；YUM 只生成按 canonical architecture 划分的 view，不生成额外混合架构 view。两侧索引都以相对位置引用 Repository 内共享 Pool，不把部署 URL 固化进 metadata。

### 4.3 Desired State 与 Built Generation

Managed Repository 同时维护两种明确状态：

- **Desired State：**SQLite 中当前 Package Object、Membership 和 Policy 结果。
- **Built Generation：**当前 `dists/` 对应的最后一组完整、已验证协议视图。

正常 `add/rm` 同时更新二者。`--no-build` 只推进 Desired State，并把新包字节耐久保存到私有 `.sow/<repo>/pending/`；公开 `pool/ + dists/` 仍保持旧 Built Generation。`sow build` 再将仍需要的对象发布到 Pool 并生成索引。Dirty 是产品状态，不是数据损坏。

## 5. 关键产品决定

### 5.1 架构自动管理

用户不在 `add` 时指定架构。SOW 从包头识别，并用 canonical CPU family 统一两个生态：

| Canonical family | RPM | DEB |
| --- | --- | --- |
| `x86_64` | `x86_64` | `amd64` |
| `aarch64` | `aarch64` | `arm64` |

Workspace `sow.yml` 默认声明 `architectures: [x86_64, aarch64]`，作为允许上限。未列出的原生架构硬失败并提示修改配置，不能静默创建；未来 loong64/riscv64 必须同时满足“当前二进制已支持”和“用户显式允许”。

RPM `noarch` 与 DEB `all` 各自仍是一个对象、一个 Dist Membership，但自动进入该目标 Dist 的所有有效 Architecture View。它们不会自动加入未选择的其他 Dist。

这一选择与 reprepro 的成熟做法一致：先由发行版配置声明允许 Architecture，再校验包头并把 `all` 扩展到已声明架构，而不是让输入包反向修改仓库配置。[reprepro manual](https://manpages.debian.org/trixie/reprepro/reprepro.1.en.html)

### 5.2 包唯一性

阶段一采用三层模型：

1. **物理身份：**最终包字节的 SHA-256。
2. **逻辑坐标：**RPM NEVRA；DEB `(package, version, architecture)`。
3. **成员身份：**`(dist, content_sha256)`。

同 SHA-256 重复加入为 no-op；同一逻辑坐标不同 SHA-256 在同一 Repository 中硬冲突；同名不同版本允许，由 Limit 决定保留几个 Membership。这兼顾了 Pulp 所指出的“NEVRA 不能区分签名不同的物理 RPM”，也遵循 Debian/aptly 在单仓库中禁止同坐标映射到不同内容的约束。[Pulp RPM FAQ](https://docs.pulpproject.org/en/2.18/plugins/pulp_rpm/user-guide/faq.html) [Debian Repository Format](https://wiki.debian.org/DebianRepository/Format) [aptly repo add](https://www.aptly.info/doc/aptly/repo/add/)

阶段一不提供静默 replace。需要替换同坐标内容时应提高 release；密钥轮换以后单独设计。

### 5.3 Policy 是写入不变式

Dist Policy 至少包括：

- `limit: 0` 保留所有版本；正整数 N 保留每个 `(binary name, native architecture)` 最新 N 个。
- `exclude` 按规范化 name/source/arch/kind/format 的 exact 或 glob 列表排除。

`add` 的语义是：解析 → merge Membership → 对完整集合执行 exclude/Limit → 提交。任何写入路径都不能绕过 Policy。典型 OSS Dist 因而可稳定表达“没有 debug、每个包只留最新版本”。

Policy 移除的是实际 Desired Membership，阶段一不另存可自动复活的候选集合。收紧配置时 build 可继续删除不合规成员；放宽 exclude 或提高 Limit 不会从 Pool 猜测恢复历史成员，用户需重新 add。

### 5.4 Operation Journal

每个 Repository 内写命令先提交一条 `planned` Operation，再产生 Pool、stage、SQLite 与 dists 文件副作用；随后逐步标记 staged/applied/built/done 或失败/回滚。Operation 既是崩溃恢复 journal，也是语义审计日志。`init/repo new/repo rm` 因目标 DB 尚不存在或将被删除，使用 `.sow/` 下的 workspace file journal，不增加第二个 workspace SQLite。

这与 SQLite 自身 WAL 不是一回事。SQLite WAL 负责数据库页面的原子提交和单写并发，不能协调外部 Pool 与静态索引文件；跨介质恢复必须由应用级 Operation Journal 完成。[SQLite WAL](https://sqlite.org/wal.html)

## 6. 阶段一功能需求

公共用法详见 [API 契约](./api-contract.md)。以下 FR 只定义产品能力与验收结果。

### FR-1：Plain 单命令建仓

用户可以运行 `sow create [DIR]`，DIR 默认当前目录，无需 Workspace、配置或数据库。

**验收：**

- 只扫描顶层普通 `.rpm/.deb`，不递归、不跟随符号链接。
- RPM-only、DEB-only、混合目录分别生成正确索引。
- 自动处理目录内全部架构与有效版本。
- 未给出签名参数时默认不删除或修改任何包，不生成 `repo_complete`，不处理 modulemd。
- 默认模式遇到既有 `repo_complete` 时先失败，避免重建索引后留下过期 completion marker；兼容目录必须显式使用 `--pigsty`。
- 可用 `-S/--sign-with KEY` 只补签未签名 RPM；已有嵌入签名保持原字节。额外给出 `--overwrite` 时用同一 key 重签全部保留 RPM，且 `--overwrite` 单独出现是 usage error。
- 签名发生在私有副本；必须证明 signature-neutral digest 与 NEVRA 不变，rpm-md 引用签名后的最终 SHA-256，签名失败不得改变公开包或索引。
- 无支持包、解析失败、同坐标内容冲突或渲染失败时非零退出，旧索引继续可用。

### FR-2：Plain 并行与 Pigsty 兼容

`sow create` 支持 `-j/--jobs`，默认逻辑 CPU 数；显式 `--pigsty` 执行 Pigsty 特定清理并生成完成标记。

**验收：**

- 根据包头而不是文件名宽泛 glob，删除 RPM i386/i486/i586/i686、DEB i386，以及 binary name 恰为 `patroni`、upstream version 恰为 3.0.4 的包；RPM 忽略 epoch/release，DEB 剥离 epoch/Debian revision，`3.0.4+foo` 不命中。
- 只删除顶层已解析普通包文件，不删除目录、symlink 或未知文件。
- 清理后的索引先成功切换，再删除不再被索引引用的包。
- 最后生成 SHA-256 `repo_complete`，内容只含剩余 RPM/DEB，按 basename 稳定排序。
- 不生成 modulemd。
- 待删包先 rename 到同文件系统 recovery trash，新 marker 成功换入后再清空；在 journal、marker、metadata pointer、package rename 各崩溃点注入进程终止，重跑只能收敛到完整旧/新状态。

### FR-3：Workspace 初始化与发现

`sow init [DIR]` 创建根级 `sow.yml` 与 `.sow/`，没有 `--name`；Managed 命令固定发现该文件。

**验收：**

- 发现优先级为 `--workdir` → 当前目录向上 → `SOW_DIR` 向上。
- 使用最近祖先的 `sow.yml`，不跨 Workspace。
- `config check` 只读校验；`config show --all` 展示完整有效配置。
- `sow create` 不受 Workspace 发现影响。

### FR-4：Repository 生命周期

一个 Workspace 可维护多个固定路径 Repository，每个独占 Pool、dists、SQLite 与私有 stage。

**验收：**

- `repo new NAME` 不接受自定义 path。
- Repository 选择优先级为显式 `-r` → cwd 所属 Repository → 唯一 Repository；否则失败。
- 空 Repository 可直接删除；非空需要唯一的 `-f/--force`。
- `protected: true` 阻止整个 Repository 删除，`-f` 不可绕过。

### FR-5：平铺 Dist 生命周期

一个 Repository 可包含多个 RPM/DEB Dist；每个 Dist 只有一种 format，命名不承载特殊状态机。

**验收：**

- `dist new NAME --format rpm|deb` 不要求架构参数，继承有效架构。
- beta/prod/snapshot/customer Dist 均可修改。
- `dist rm -f` 删除 Membership 与衍生索引，但不删除 Pool 包字节。
- 空 Dist 创建后即有可消费的空索引。

### FR-6：架构许可与自动视图

SOW 必须自动解析、规范化并维护架构。

**验收：**

- x86_64/amd64 与 aarch64/arm64 正确映射为两个 canonical family。
- 原生包只进入匹配的 view；noarch/all 进入目标 Dist 的全部有效 view。
- 未许可架构在任何状态写入前失败，错误同时给出检测值、许可值与修复位置。
- 从配置移除仍被引用架构时拒绝；新增受支持架构后相关 Dist 标 dirty 并由 build 创建 view。

### FR-7：不可变 Package Object 与幂等 Add

`add` 只读输入，在 stage 副本上按配置执行 RPM 签名，再以最终 SHA-256 建立对象。

**验收：**

- RPM 签名模式为 `never/fill/always`；有 key 默认 fill，无 key 等价 never。
- RPM 保存排除 signature header 的 signature-neutral payload digest；同坐标、同 payload 且既有对象满足 fill/always 策略时直接复用，不再次生成含新时间戳的签名，保证 unsigned 输入重复 add 幂等。
- 同 SHA-256 no-op；同坐标不同 SHA-256 硬失败，不覆盖。
- 一个对象可加入多个显式 `-d`，Pool 仍只有一份。
- 批次允许合法项提交、非法项留在原处并报告，整体返回部分成功；没有 rejected 存储。
- 使用 `--no-build` 时新对象先进入私有 pending content store；成功 build 后才进入公开 Pool，内容 SHA-256 不变。

### FR-8：Policy Reconcile

所有 Membership 写入必须执行目标 Dist 当前 Policy。

**验收：**

- merge 后排除 debug 等不符合规则的包。
- exclude 使用封闭规则语法：rule 间 OR、rule 内字段 AND、字段内 pattern OR；字段仅 name/source/arch/kind/format，pattern 仅区分大小写 exact/glob。
- kind 至少稳定区分 RPM debuginfo/debugsource/llvmjit、DEB dbgsym/dbg 与 main，并由 `show --json` 暴露以做 golden test。
- `limit: 1` 自动移除过时 Membership；`limit: 0` 不限版本。
- Policy 排除结果逐 Dist 报告；未被任何 Dist 接受的新对象不写 Pool。
- 配置变更后 `build` 再执行 Policy，不能通过编辑配置制造永久违规状态。
- 放宽 Policy 不复活已移除成员；Pool 字节不构成 Dist 意图，恢复成员必须显式重新 add。

### FR-9：默认构建与显式 Dirty

`add/rm` 默认在成功返回前构建受影响索引，同时支持 `--no-build` 批处理。

**验收：**

- 默认一次命令中每个受影响 Dist 最多构建一次。
- `--no-build` 只推进 Desired State/private pending，公开 Pool 与旧 Built Generation 保持不变且完整可复制。
- `status` 明确列出 dirty Dist、Desired Revision 与 Built Generation。
- `build` 将全部或选定 dirty Dist 收敛；无变化时 no-op，不增加 Generation。
- 默认 mutation 在 Desired 已提交后 build 失败时返回失败并保持旧 Built view；能安全回滚则 rolled_back，否则进入 recovering，由下一次 build 先恢复。只有显式 `--no-build` 才能以正常 `done_dirty` 结束。

### FR-10：安全 Remove

`rm` 只删除所选 Dist Membership，不直接删除 Pool 字节。

**验收：**

- `rm -c/--check` 预览将删除的成员和索引变化，不写状态。
- 裸 binary name 表示选中 Dist 中该名称全部版本/架构；精确 ref/SHA/filename 可删单一对象。
- 模糊引用列候选并失败；无匹配失败。
- 没有 source-list、allow-empty、all、yes。

### FR-11：查询与便宜状态

`ls/show/where/status` 提供统一的人类输出和 `--json`。

**验收：**

- `ls/show/where` 支持 `-r/-d` 收窄，没有 pool/match/format 参数。
- dirty 时查询 Desired State，并明确标注尚未进入 Built Generation 的差异。
- `status` 不做全量哈希，不自动恢复，只展示 clean/dirty/recovering/error、锁与最近 Operation。

### FR-12：完整 Build 与 Check

`build` 是唯一把 Desired State 收敛为 Built Generation 的显式命令；`check` 是端到端只读验证。

**验收：**

- metadata 在同文件系统 stage 完成、验证、签名后切换，协议指针最后替换；RPM 使用 checksum-named metadata，APT 使用 by-hash 或经真实客户端证明等价的机制。
- 配置 RPM metadata key 时生成并验证 `repodata/repomd.xml.asc`；DEB 始终生成 `Release`，配置 metadata key 时同时生成 `InRelease` 与 `Release.gpg`。key/fingerprint 变化使相关 Dist dirty；秘密不得进入 config 展示、DB、log 或 JSON。
- 一个 Operation 可构建多个 Dist；阶段一只承诺每个 view 在切换过程中自洽、命令返回后目标属于同一 Built Generation，不承诺并发读者观察到跨 Dist 的瞬时原子翻代。
- 任意崩溃点只能让各协议 view 的指针保持在旧完整内容，或切到新完整内容，并留下可恢复 Operation；不得指向尚不存在的 metadata/package。
- `check` 验证配置、DB、Pool SHA-256、包坐标、Membership、签名、索引引用与架构 view。
- dirty 时分别证明旧 Built Generation 自洽和 Desired State 合法，但返回“尚未 ready-to-copy”；不 repair。

### FR-13：应用级恢复与审计

写命令以 Operation Journal 记录计划、阶段与结果；下一写命令必须先处理非终态 Operation。

**验收：**

- 在任何 Pool/metadata 外部副作用之前持久化 `planned`。
- 故障注入覆盖 staged、applied、built 前后的恢复与回滚。
- `sow log [OPERATION]` 可审计包、Membership、文件变化、耗时与错误。
- `log export` 输出 JSONL；`log prune` 只清理终态审计记录并压缩 SQLite，绝不删除恢复、当前状态或 Changeset 所需数据。

### FR-14：Built Changeset

每个实际变化的 Repository Built Generation 保存本地文件净变化，供人工查看和外部工具消费。

**验收：**

- `changes` 默认显示最新一代；指定 Base 时给出 Base 到当前 Built Generation 的净变化。
- Changeset 是 Repository 级 API，不接受 `-d`；消费者可按路径自行过滤。
- JSON 包含 add/update/delete、repository-relative path、payload/metadata/pointer/delete phase、size 与 SHA-256。
- Changeset 描述整个物理交付目录而不是索引引用闭包；`changes 0` 与直接复制 `pool/ + dists/` 的文件集合一致。
- `--no-build` 的新 payload 留在 `.sow/` 私有 pending，不提前改变交付树；下一次成功 build 只发布届时仍被 Desired Membership 需要的对象。构建前已无引用的 pending 可安全丢弃。
- clean/dirty 终态下 Generation manifest 与公开 `pool/ + dists/` 完全一致；recovering/error 时 changes 拒绝生成同步计划，直到未决文件动作完成、回滚或从备份恢复。
- SOW 不保存 endpoint、不调用 rclone、不执行远端删除。

## 7. 非功能需求

### NFR-1：平台与依赖

- 纯 Go 单二进制，不依赖 `createrepo_c`、`dpkg-scanpackages`、repo2module 或 modifyrepo_c。
- macOS/Linux × x86_64/aarch64 完整可用。
- Plain `create --sign-with` 是唯一活动的外部运行时例外：需要环境中的 RPM/GPG 工具链；不使用该参数时仍为纯 Go 路径。
- 单机、本地 POSIX、单写；阶段一不支持网络文件系统或多写者。

### NFR-2：正确性与恢复

- Repository 是恢复与提交边界。
- SQLite 使用适合本地单写的事务模式；应用级 Operation Journal 负责跨 DB/文件恢复。
- Pool 对象不可变；同名不同内容不覆盖。
- Static tree 只暴露完整 Generation。
- 用户负责定期备份 `sow.yml`、`.sow/*.db`、dirty 时的 `.sow/<repo>/pending/` 与 Repository Pool；lock/stage 不需要备份，dists 可重建。

### NFR-3：性能

2026-08-01 对只读生产目录 `/Users/vonng/pgsty/repo/{yum,apt}/{infra,pgsql}` 的基线为 34,184 个 RPM/DEB、包字节合计约 50.18 GiB；具体分布为 YUM infra 204、YUM pgsql 16,627、APT infra 182、APT pgsql 17,171。

- Plain 的解析、SHA-256 与渲染支持并行，默认逻辑 CPU 数。
- Managed 初次导入必须读取并哈希全部包，单独计时。
- 初次导入后，当前规模的完整 rebuild 目标为 2 分钟内；月度常规更新期望在合理的一两分钟范围内完成。
- 正确性优先；预渲染 cache 与复杂增量优化只有在真实 profile 证明需要时进入后续设计。

### NFR-4：确定性与脚本化

- 相同输入、配置和签名条件产生等价索引、稳定排序和相同 Membership 选择。
- 并行度不影响结果。
- stdout/stderr 分离；`--json` 在失败与部分成功时仍完整报告已提交项。
- no-op、部分成功、锁失败、配置错误、内容冲突和完整性失败有稳定可区分的退出码。

### NFR-5：协议兼容

- Tier 1：EL9/10、Debian 12/13、Ubuntu 22.04/24.04/26.04，两个 canonical 架构族。
- 尽力兼容：EL7/8、Debian 11、Ubuntu 20.04。
- “文件生成成功”不是验收；必须用真实 APT/DNF 验证 metadata refresh、包定位、校验与安装。
- YUM Architecture View 到共享 Pool 的相对 location 必须通过真实 DNF/YUM 与 reposync 测试。

### NFR-6：安全边界

- 生产仓库 `/Users/vonng/pgsty/repo` 在开发与实验中严格只读。
- 可破坏性实验只允许在用户提供的测试仓库 `/Users/vonng/repo` 范围内。
- 递归删除前必须证明目标是当前 Workspace/Repository 自有路径，且不跟随 symlink。
- `--pigsty` 是 Plain 包删除的唯一显式授权；默认 create 不删除包。
- `--sign-with` 是 Plain RPM 字节修改的唯一显式授权；`--overwrite` 进一步授权对已有签名的保留 RPM 全量重签。

## 8. 实现与验收顺序

### P0 — Plain Create（最高优先级）

- FR-1、FR-2。
- RPM-only、DEB-only、混合目录 golden fixtures。
- `-j` 确定性测试；`--pigsty` 精确清理与 SHA-256 marker。
- `--sign-with` 的未签补签、已有签名保持、`--overwrite` 全量重签、签名失败零公开副作用与 crash recovery。
- 对 `--pigsty` 的 journal 落盘、旧 marker 撤下、metadata pointer 切换、package recovery rename、新 marker 换入逐点做 crash injection。
- 四个编译平台与 Tier 1 真实客户端最小闭环。

### P1 — Managed Control Plane

- FR-3 至 FR-6。
- 在冻结 managed YUM layout/schema 前，先以真实 DNF/YUM 与 reposync 验证 architecture view 的相对 `../../../pool/...` href；失败则回到产品/架构重选布局，不得改用硬编码绝对 URL 糊过去。
- `sow.yml`、固定布局、repo/dist 生命周期、锁、SQLite schema。
- canonical architecture family 与 noarch/all view projection。

### P2 — Mutation and Recovery

- FR-7 至 FR-10、FR-13。
- 包解析/签名/身份、Policy、add/rm、默认 build、`--no-build`、Operation Journal。
- crash injection 证明旧 Generation 与自动恢复。

### P3 — Verification and Handoff

- FR-11、FR-12、FR-14。
- 查询、status、完整 build/check、Generation/Changeset、log export/prune。
- 34,184 包基线性能与真实客户端矩阵验收。

P0–P3 都属于 V2 阶段一；它们是交付顺序，不是四个长期兼容版本。每个切片必须垂直可验收后再进入下一片。

## 9. 成功指标

### Primary

- **SM-1 Plain 替代成功：**`sow create` 能替代 Pigsty 现有 createrepo/dpkg-scanpackages 路径；`--pigsty` 只删除指定包并生成 SHA-256 marker；不需要 modulemd。
- **SM-2 Managed 月度闭环：**用真实 infra/pgsql 更新完成 add → policy reconcile → build → check → changes，产物可直接复制并被 APT/DNF 使用。
- **SM-3 架构零操心：**普通 add 不需要任何 arch 参数；原生架构正确分 view，noarch/all 自动 fan-out，未知架构明确失败。
- **SM-4 崩溃可恢复：**在每个 Operation 阶段杀进程后，下一写命令能完成或回滚；客户端始终只能看到最后完整 Generation。

### Secondary

- 当前 34,184 包规模的 clean rebuild 不超过 2 分钟。
- 重复 create/add 为 no-op；同坐标不同内容 100% 被拒绝。
- 外部脚本能仅凭 changes JSON 正确生成 payload/metadata/pointer/delete 顺序。

### Counter-metrics

- 不以加入更多命令衡量成功。
- 不通过跳过 SHA-256、包头解析、Policy 或真实客户端测试换取性能。
- 不为追求“一条命令总成功”而静默新增架构、猜 Dist 或覆盖同坐标包。

## 10. 明确非目标

阶段一不做：

- modulemd 的生成、注入、保留、验证或 CLI 参数。
- Route 及配置占位；manifest 与 rejected quarantine。
- pull/push/copy/move/promote、公式/list/source-list 选择器。
- sync/publish、CDN、对象存储、远端 endpoint 与远端状态。
- GC、managed export、mirror/fetch、访问控制。
- SRPM、DSC 与源包索引。
- 特殊 snapshot/freeze/readonly 状态。
- 跨 Repository 去重/事务、多机多写、服务、Web UI、包构建或客户端包管理。

## 11. V1 资产复用边界

### 优先评估复用

- RPM/DEB 包头解析与规范化事实。
- RPM EVR、Debian version 比较。
- rpm-md 与 APT Packages/Release 渲染。
- GPG/RPM 签名与验证适配层。
- SHA-256、稳定排序、同文件系统 stage/rename 与路径安全辅助函数。
- 已有真实客户端 fixtures 与协议测试经验。

### 只作参考、不继承

- 远端 publish/sync/provider/CDN 模型。
- CAS、freeze、vault、派生 view、复杂 generation retention。
- V1 `sow.example.yaml` schema 与路径布局。
- modulemd、route、manifest、rejected 相关实现。
- Berkeley DB 或任何为旧兼容保留的数据层。

复用的单位是经过测试的独立模块，不是 V1 的产品骨架。任何候选必须先证明符合 V2 API、数据所有权与错误语义。

## 12. 主要风险与缓解

| 风险 | 影响 | 阶段一缓解 |
| --- | --- | --- |
| SQLite 与多个 POSIX 文件不是单一事务 | 崩溃留下跨层半状态 | Repository 锁、Operation Journal、同 FS stage、幂等恢复、旧 Generation 保留 |
| `--no-build` 被误认为仓库损坏 | 运维者不清楚哪一代可发布 | 显式 Desired/Built、status dirty、check 分层、changes 只看 Built |
| 同 NEVRA 不同签名字节 | 客户端选择含糊或静默覆盖 | SHA-256 内容身份 + Repository 内坐标唯一约束；无 replace |
| 静默发现新架构 | 意外扩展制品与公开面 | 配置许可上限、未知架构硬失败、config check |
| Pigsty 清理误删 | Plain 目录不可恢复 | 仅显式 `--pigsty`；解析事实精确匹配；仅顶层普通包；先切索引后删除 |
| RPM 相对 location 的客户端差异 | DNF/reposync 找不到共享 Pool | Tier 1/兼容矩阵 PoC，在布局冻结前用真实客户端验证 |
| Operation log 无限增长 | SQLite 膨胀 | 同库但分表；终态 log 可 export/prune；恢复与 Changeset 永不被误删 |

## 13. 已确认的产品契约

产品所有者于 2026-08-02 确认以下整体契约：

1. Plain 默认纯建索引；只有 `--pigsty` 才精确清理包并生成 SHA-256 `repo_complete`。
2. 配置只使用 `x86_64/aarch64` canonical family；`amd64/arm64` 是生态输出别名，不是额外配置项。
3. 同一 Repository 内“同逻辑坐标、不同 SHA-256”硬失败，阶段一没有 replace。
4. `add/rm` 默认 build；`--no-build` 产生明确 dirty，旧 Generation 仍是唯一可复制版本。
5. Operation Journal 与审计 log 同库；`log export/prune` 属于阶段一，但不能触碰恢复、状态与 Changeset。
6. Route、pull、modulemd、sync/publish、GC 全部不进入阶段一 API，也不放空占位。

本节与 [API 契约](./api-contract.md) 已进入 P1–P3 实现与验收基线；YUM 物理布局采用已通过 P1 门禁的 C2 view-local hardlink 修正，而非被 reposync 证伪的 `../../../pool` href 候选。
