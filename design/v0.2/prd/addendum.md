# sow V2 阶段一 PRD 技术附录

> 本文保存 PRD 下游需要的取舍理由、行业依据、恢复边界、V1 资产盘点和验证事实。产品范围以 `prd.md` 为准，公共 CLI 以 `api-contract.md` 为准。

## 1. 配置与发现取舍

### 1.1 根级 `sow.yml`

| 位置 | 优点 | 缺点 | 结论 |
| --- | --- | --- | --- |
| `<workspace>/.sow/config.yml` | 控制文件集中 | 不可见、名字泛化、向上发现不直观 | 放弃 |
| `<workspace>/sow.yml` | 明确归属、容易发现和版本管理、与制成品隔离 | 根目录多一个可见文件 | 采用 |

最终边界：`sow.yml` 是用户意图，`.sow/` 是机器状态，Repository 目录是可整体复制的静态交付单元。

### 1.2 发现算法

1. 有 `-C/--workdir` 时，从该目录向上寻找最近 `sow.yml`。
2. 否则从 cwd 向上寻找。
3. 两者未找到时，再从 `SOW_DIR` 向上寻找。
4. 找到最近一个即停止。
5. `sow create` 完全不调用该算法。

Repository 推断使用原始 start directory，而不是发现后的 Workspace 根。显式 `-r` 永远优先；cwd 属于某 Repository 时其次；只有一个 Repository 时才自动选择。

## 2. 为什么 Plain 是 `sow create`

- Plain 是 P0 首个垂直交付，不应藏在 `sow plain build` 下。
- `create` 与 createrepo 的用户心智一致：从当前包文件创建索引。
- `build` 专用于 Managed Desired State → Built Generation 收敛。
- `create` 是否发现 `sow.yml` 不会改变语义，因此在任何目录都可预测。

### 2.1 现有 Pigsty 基线

只读检查 `/Users/vonng/pgsty/pigsty/roles/repo/tasks/build.yml:195-239`：

- RPM 运行 `createrepo_c`；EL8/9 过去还运行 repo2module/modifyrepo。
- DEB 运行 `dpkg-scanpackages` 生成 `Packages.gz`。
- RPM 清理 i686（原任务仅 EL7），DEB 清理 i386；两侧清理匹配 Patroni 3.0.4 的文件。
- 最后对 RPM 或 DEB 写 MD5 `repo_complete`。

V2 的通用 `sow create` 只建索引，不清理、不生成 marker。显式 `--pigsty` 才启用经过收敛的新契约：

- 依据包头事实清理 RPM i386/i486/i586/i686、DEB i386。
- 依据 exact binary name `patroni` 与 exact upstream version `3.0.4` 清理包，不执行 `rm -rf patroni*3.0.4*` 这种宽泛 glob。RPM 使用 VERSION、忽略 epoch/release；DEB 剥离 epoch 与 Debian revision 后比较，`3.0.4+foo` 不命中。
- marker 改为 SHA-256，按 basename 稳定排序。
- modulemd 完全移除。

Plain RPM 另有独立的显式签名授权：`-S/--sign-with KEY` 默认只在私有 stage 补签没有嵌入签名的保留 RPM；与 `--overwrite` 同时出现时，用该 key 重签全部保留 RPM。实现调用环境中的 `rpm --addsign/--resign`，但不接收或保存 passphrase；签名后必须重新验证嵌入签名、signature-neutral digest 与 NEVRA，并让 rpm-md 和 `repo_complete` 绑定最终字节。

### 2.2 `--pigsty` 的安全提交顺序

Plain 没有 SQLite，但清理包与切换索引仍需要轻量 durable journal。建议顺序：

1. 解析全部顶层普通包，确定保留集、清理集与坐标冲突。
2. 若显式签名，在 stage 副本执行并验证全部 RPM 签名，再对最终包字节生成并校验完整 stage metadata。
3. 预计算最终保留包 SHA-256 marker。
4. 进入提交窗口前，把已有 `repo_complete` 原子移到恢复 staging，使 marker 检查者明确看到“构建中”。
5. 先按 journal 原子替换已签名 RPM，再切换不再引用清理集、且引用最终 RPM 字节的新 metadata；RPM 指针 `repomd.xml` 最后换入。
6. 把命中的包逐个原子 rename 到同文件系统 recovery trash，不直接 unlink。
7. 最后原子换入新 `repo_complete`，再清空 trash 并清除 journal；若回滚旧 metadata，则同时恢复 RPM pre-image、旧 metadata、trash 中的清理包和旧 marker。

这样在切换前，旧索引引用的包仍存在；切换后，待清理包即使短暂残留也只是未被索引的冗余，不会产生悬空引用。崩溃后下次同命令根据 journal 幂等完成。

故障注入必须覆盖：journal fsync 后、旧 marker 撤下后、RPM/DEB 各 pointer 切换后、每个 package rename 后、新 marker rename 前后。任一点重启都只能恢复旧整态或完成新整态，不能丢包或留下错误 completion marker。

## 3. 架构模型与行业依据

### 3.1 Canonical family

SOW 配置只使用两个当前支持的 canonical family：

- `x86_64`：RPM `x86_64`，DEB `amd64`。
- `aarch64`：RPM `aarch64`，DEB `arm64`。

RPM `noarch` 与 DEB `all` 是 neutral architecture。它们建立单一 Membership，但渲染到目标 Dist 的全部有效 view。

这避免把 `amd64/x86_64` 或 `arm64/aarch64` 误当成四种 CPU 架构，也让未来 loong64/riscv64 的加入成为显式 schema 能力，而不是输入包触发的目录副作用。

### 3.2 为什么未知架构硬失败

reprepro 的 distribution 配置要求列出 `Architectures`，入库会对照包的 `Architecture` 字段；`all` 包可以再 flood 到已声明架构。它不会因为遇到一个新架构包就静默扩展 distribution。[reprepro manual](https://manpages.debian.org/trixie/reprepro/reprepro.1.en.html)

SOW 采用相同边界：

- 架构自动识别，用户不用在 add 时填写。
- 配置是允许上限；未知值在写状态前失败。
- noarch/all 只 fan-out 到显式目标 Dist 的已允许 view。
- 添加配置架构使相关 Dist dirty；移除仍在使用的架构失败。

“自动管理”在这里表示自动解析、归一化、投影视图与维护索引，而不是自动改写用户配置。

### 3.3 YUM 相对 Pool 是前置 Gate

相对 package location 目前是产品选择，不是已经证明的兼容事实。P1 开始时必须先建最小双架构 fixture，用真实 DNF/YUM 完成 makecache/install，并用 reposync 同步 `dists/<dist>/<arch>/repodata` 中指向共享 `pool/` 的相对 href。这个 PoC 通过前不得冻结 managed layout、SQLite schema 中的 view path 或 renderer API；失败则回到产品/架构重选布局，绝不把部署域名写死进 metadata。

## 4. 唯一性为何采用三层模型

### 4.1 内容、坐标、成员

- Content Object：签名处理后的 SHA-256。
- RPM Coordinate：`(name, epoch, version, release, arch)`。
- DEB Coordinate：`(package, version, architecture)`。
- Membership：`(dist, content_sha256)`。

### 4.2 行业结论

- Pulp RPM 以 checksum 识别物理 RPM，因为相同 NEVRA 可能因签名不同而有不同字节，NEVRA 不足以做内容身份。[Pulp RPM FAQ](https://docs.pulpproject.org/en/2.18/plugins/pulp_rpm/user-guide/faq.html)
- Debian Repository Format 明确不应在一个仓库放置同 package/version/architecture 的不同内容。[Debian Repository Format](https://wiki.debian.org/DebianRepository/Format)
- aptly 默认同样拒绝同 `(architecture, name, version)` 对应不同文件，只有显式 force-replace 才改写。[aptly repo add](https://www.aptly.info/doc/aptly/repo/add/)
- reprepro 不会用同版本包直接更新既有包；强制替换需要先删除旧条目。[reprepro manual](https://manpages.debian.org/trixie/reprepro/reprepro.1.en.html)

因此阶段一采用：SHA-256 识别不可变字节；同一 Repository 再对逻辑坐标施加唯一映射，防止客户端面对两个同坐标候选。多个版本仍可共存；Limit 只改变 Dist Membership。

Filename 不是身份。重签同 NEVRA 会改变 SHA-256，因而阶段一硬冲突；推荐提高 release，未来再单独设计 key rotation/replace。

### 4.3 RPM 签名重试

RPM signature header 可包含时间等非确定字段。若每次 add 都先对同一 unsigned RPM 重签，再比较最终 SHA-256，第二次会错误地产生“同 NEVRA 不同内容”。

实现应在首次解析时计算并保存 signature-neutral payload digest：对 signature header 之外的 immutable header+payload 做 SHA-256。重复 add 的判据是：

- 完整字节 SHA 相同，直接复用。
- payload digest 相同且既有对象满足当前 fill/always 策略，复用既有已签名字节，不再签名；fill 的“有效”由 `trusted_keys` 验证，配置 signing key 的 public half 自动加入信任集。
- payload 不同或既有签名不满足策略，硬冲突；不借 add 原地重签。

这个 digest 只是 retry comparator，不是公共身份；最终 Content Object 仍以完整已签名字节 SHA-256 为主键。

### 4.4 Managed metadata 签名

签名是 config contract，不提供命令行临时覆盖：

- RPM package key/mode 与 RPM metadata key 分开配置。
- 配置 RPM metadata key 时生成 `repodata/repomd.xml.asc`。
- DEB 始终生成 `Release`；配置 DEB metadata key 时生成 `InRelease` 与 `Release.gpg`。
- key fingerprint 改变是 renderer input，相关 Dist 必须 dirty/rebuild。
- config/show/log/JSON 只允许出现引用与 fingerprint，不得出现 secret/passphrase。

## 5. Desired/Built 双状态

### 5.1 为什么增加 `--no-build`

默认仍是“成功即就绪”：`add/rm` 返回 0 时索引已经更新。月度批量导入可能包含多次命令，显式 `--no-build` 可避免每次重建。

`--no-build` 不允许把数据库与客户端视图含糊地称为“不一致”。模型中本来就有两条版本：

- Desired Revision 已提交最新包和 Membership；新包字节可耐久保存在私有 pending store。
- Built Generation 保持最后完整静态树。

Repository 标记 dirty；`status` 展示差异；`build` 收敛；`check` 分别验证两层。外部复制应只在 clean 或明确指定 Built Generation 时进行。

### 5.2 Policy 时机

`add` 无论是否 build，都先对 Desired Membership 应用 merge、exclude 与 Limit。旧版本被 Limit 移出 Membership 后仍留在 Pool，阶段一没有 GC。`build` 也会根据当前配置重新 reconcile，处理用户手工修改 Policy 的情况。

这里的 reconcile 只会把当前 Membership 收紧到新规则；阶段一不持久化 rejected/pruned candidate set。放宽 exclude 或把 Limit 从 1 改成 3 不会从 Pool 猜测哪两个旧版本应恢复，必须重新 add。这个限制保留了“Dist 是显式成员集合”的核心语义。

### 5.3 Exclude 的封闭语义

`exclude` 是 rule list：rule 间 OR、rule 内字段 AND、同字段 patterns OR。允许字段仅 `name/source/arch/kind/format`；pattern 仅区分大小写 exact/glob。kind 的首期 classifier 固定为 RPM 的 debuginfo/debugsource/llvmjit、DEB 的 dbgsym/dbg，其余 main；arch 规范化为 x86_64/aarch64/neutral。先 exclude，再 Limit。任何未知字段、非法 glob 或空 rule 都在 config check 失败。

## 6. Operation Journal 与 SQLite WAL

一次 Managed mutation 可能同时改变：

1. stage 中的包字节或签名副本；
2. SQLite package/member/op/generation 记录；
3. Pool 新对象；
4. Dist metadata 与签名；
5. Built Changeset。

SQLite WAL 只能保证 SQLite 自己的页面提交和读写并发，不能把任意 POSIX 文件纳入同一事务。[SQLite WAL](https://sqlite.org/wal.html)

因此采用应用级 Operation Journal：

```text
planned → staged → applied → built → done
                         └────────→ done_dirty
```

- `planned` 必须在任何外部副作用前提交。
- 每一步都要有幂等完成条件与可判断的旧/新文件 hash。
- 下一写命令先恢复所有非终态 Operation。
- 非终态记录永不 prune。
- 终态 Operation 兼作审计；Built Changeset 单独保留，不能因 log prune 消失。

`init/repo new/repo rm` 不能依赖目标 Repository DB：前两者执行时 DB 尚不存在，后者会删除 DB。它们使用 `.sow/workspace.lock` 与轻量 file journal，留下足够的旧/新 `sow.yml` hash、目标路径和阶段信息；不为此增加 workspace SQLite。`dist new/rm` 已有 Repository DB，仍使用普通 Operation 表。

默认 mutation 已进入 `applied` 后若 build 失败，不可伪装成成功的 `done_dirty`。应优先安全回滚；无法立即回滚时保持非终态并把 Repository 标成 recovering，旧协议 view 继续可用，下一写命令先恢复。

架构阶段需要把每个 crash point 的 forward-complete/rollback 判据写成状态表，并以 kill/fault injection 测试，而不是只依赖 happy-path transaction。

## 7. Changeset 语义

`changes` 描述 Built Generation 之间的 Repository 物理交付树差异，不等同于 Operation log：

- Operation log：用户做了什么、哪些 Membership 改了、是否 dirty/失败。
- Changeset：从某个 Built Generation 到当前代，外部复制需要增删改哪些路径。

`--no-build` 可以产生 Operation 和私有 pending payload，但不改变公共 `pool/ + dists/`。下一次成功 build 只把届时仍被 Desired Membership 需要的 pending 对象发布到 Pool；已无引用的 private pending 可以恢复性清理。Changeset 因而始终描述成功 Built Generation 的物理交付树；在 clean/dirty 终态，`changes 0` 与直接复制 Repository 目录一致，recovering/error 时拒绝输出同步计划。

JSON phase 固定为 payload、metadata、pointer、delete，使外部消费者能保证对象先于索引、索引先于指针、删除最后执行。SOW 不保存 rclone endpoint，也不执行远端动作。

## 8. V1 资产提取

### 优先复用候选

- RPM/DEB 包头解析与规范化事实。
- RPM EVR、Debian version 比较。
- APT Packages/Release 与 YUM rpm-md 编码、压缩和签名。
- SHA-256、稳定排序、stage/fsync/rename 与路径安全原语。
- 本地索引闭包检查和真实客户端测试 fixture。
- 集合运算内核，但必须重包装成 Dist Membership/Policy 语义。

### 不进入 V2 阶段一骨架

- 远端 publish、bucket inventory、CDN、provider checkpoint、边缘鉴权。
- Git refs/TSV manifest、CAS generation retention、freeze/vault/gated pool。
- V1 配置 schema、写死的路径与频道策略。
- modulemd、route、manifest、rejected。

复用候选必须逐项通过 V2 Package identity、错误语义、纯本地所有权与 API 契约测试。旧代码存在不等于已经证明可复用。

## 9. 实证规模与验证边界

2026-08-01 只读统计 `/Users/vonng/pgsty/repo/{yum,apt}/{infra,pgsql}`：

| 路径 | 包数 |
| --- | ---: |
| `yum/infra` | 204 |
| `yum/pgsql` | 16,627 |
| `apt/infra` | 182 |
| `apt/pgsql` | 17,171 |
| **合计** | **34,184** |

这些 RPM/DEB 文件的 stat size 合计约 **50.18 GiB**。这是容量基线，不是 V2 已达到性能目标的证明。

验证必须分层：

- 源码与 schema 检查。
- 单元/属性/故障注入测试。
- 本地 Build Generation 与 Changeset。
- 真实 APT/DNF refresh、包定位、校验、安装、reposync。
- 外部 rsync/rclone 行为；这不属于 SOW 成功返回本身。

生产仓库 `/Users/vonng/pgsty/repo` 永远只读。任何写入、删除、故障注入和性能实验只能使用 `/Users/vonng/repo` 下的测试区域或显式临时目录。
