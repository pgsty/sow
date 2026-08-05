# SOW V2 Architecture Spine 对抗审查

日期：2026-08-01
审查对象：[`architecture-spine.md`](../architecture-spine.md)
对照实现基线：[`architecture.md`](../../architecture.md)

## 审查判定

当前 Spine 可以表达设计意图，但还不能作为两个独立实现单元之间的互操作契约。它冻结了组件名称和原则，却没有冻结持久化字节、锁集合、跨 journal 的恢复优先级、协议指针集合及 P1 状态语义。下面每个案例都存在两个同时遵守现有 AD 的实现；它们单独看都合理，组合后却会丢更新、拒绝对方数据、选择相反恢复结果，或向客户端暴露不同代的状态。

## Findings

1. **标为 `final` 的 Spine 同时保留了未决的 YUM layout/schema。** 实现单元 A 可按 AD-3 和基线 §11 把 `dists/<dist>/<arch>` 以及候选 `../../../pool/...` 固化进 `dist_architectures.view_path`；实现单元 B 可按 AD-13 拒绝固化 view path 和 renderer location API，等待真实客户端 gate。两者都遵守文字，但 A 产出的 schema 和 href 无法成为 B 的稳定输入。这不是一个已采纳的架构决定，而是一个尚未完成的门禁。必须把 PoC 证据的路径、fixture/hash、客户端矩阵和结论作为决策输入，随后冻结 repository base、view path、href 的 slash/escaping/normalization 规则及对应 migration；在此之前 Spine 不能同时宣称 `status: final`。

2. **`dist new/rm` 对 `sow.yml` 与 Repository SQLite 的写所有权没有闭合。** 单元 A 可把 `sow.yml` 视为用户意图正典，修改配置并取得 Workspace 锁；单元 B 可把 Dist 生命周期视为 Repository 内事务，只取得 Repository 锁并写 `dists/operations`，因为 AD-6 明确要求它使用 SQLite Operation Journal。基线 §6.3 的 payload 又包含 config old/new hash，却没有规定该命令是否以及何时替换配置、是否必须同时持有 Workspace 锁。两个 Repository 并发执行 `dist new` 时，两个进程可各自合法地原子替换同一个 `sow.yml`，后写者覆盖前写者，而任一 Repository journal 都不能恢复另一个 Repository 被丢失的配置更新。契约必须明确 Dist 命令的 config mutation、Workspace→Repository 完整锁集合、对旧配置字节的 CAS，以及 DB/config 的统一提交与恢复顺序。

3. **配置 hash 没有定义成可交换的数据。** 单元 A 可对 `sow.yml` 原始字节做 SHA-256；单元 B 可对严格解析、默认展开和架构规范化后的 canonical model 做 SHA-256；两者都满足“old/new config hash”。用户只增加注释、调整 map 顺序或改变换行后，A 会判断 journal 证据冲突，B 会判断语义未变并继续恢复。必须分别命名并版本化 `source_bytes_sha256` 与 `effective_config_sha256`，冻结 canonical encoding；所有 journal 字段必须指定使用哪一种，不能只写“config hash”。

4. **`.sow` 的物理所有权、Repository 的逻辑所有权和 `repo rm` 的锁身份互相冲突。** AD-3 一方面称 Workspace 拥有 `.sow`，另一方面称 Repository 拥有其中的 DB/private state；AD-6 又把 `repo rm` 交给 Workspace journal。单元 A 可只持有 `workspace.lock` 后整体移动 `.sow/<repo>`；单元 B 可只持有 `.sow/<repo>/lock` 执行 Repository 写操作。更严重的是，若持锁文件随 private state 被 rename，另一进程可以在原路径创建新 lock inode 并成功 `flock`，从而绕过仍锁住旧 inode 的进程。契约必须为 `repo rm` 规定 Workspace→Repository 双锁、一个在删除期间地址稳定且不可重建的 Repository lock inode、禁止新命令进入的 tombstone，以及 DB/private/repository 三者的唯一删除 owner。

5. **“schema version 1”不是 SQLite 互操作契约。** 单元 A 可使用整数 generation、复合主键和对 migration SQL 原始字节的 checksum；单元 B 可使用文本 generation、代理键并对规范化 SQL 做 checksum。两者都可设置 `user_version=1`、维护 `schema_migrations`、启用 WAL/FULL，并声称符合 AD-7；它们却会把对方 DB 判为损坏或误读字段。必须把精确 DDL、列类型/nullability/default、PK/UK/FK/check、状态枚举、时间/ID 编码、migration ID、checksum 算法与被 checksum 的确切字节纳入契约，并用跨实现 open/migrate fixture 验证。

6. **Config 与 SQLite 漂移时没有唯一裁决表。** 崩溃可留下“配置已有 Dist、DB 尚无 Dist”“DB 已有 Dist、配置尚无 Dist”“两者都有但 format/hash 不同”等状态。单元 A 可依据 AD-12 把有效配置当 desired state，补齐 DB/view；单元 B 可依据“有效现有对象只读证据”保留 DB 并拒绝覆盖，或把 DB 反映回配置。两者都符合增量 init，却会对同一磁盘状态做相反动作。必须逐命令冻结 config、DB、目录、pointer 每种存在/哈希组合的 old/new/冲突判定，并指出哪一个 durable bit 是提交决定；不能把“幂等”留给实现自行解释。

7. **Workspace journal 与 Repository journal 没有恢复优先级和支配关系。** 假设一次 `dist new` 留下非终态 SQLite Operation，随后一次 `repo rm` 留下非终态 workspace operation。单元 A 可先按“下一次 Workspace 写命令恢复全部 workspace ops”继续删除 Repository；单元 B 可先按“下一次 Repository 写命令恢复非终态 Operation”完成 Dist、写回配置和 pointer。两者分别遵守 AD-6，却会一个删除、一个复活相同对象。契约必须规定 discovery 后的全局恢复顺序、workspace lifecycle operation 对 repo operation 的支配规则、`repo rm` 开始前对非终态 repo operation 的门禁，以及任何恢复路径所需的锁集合。

8. **三个 journal 都没有冻结可发现、可解析的 wire format。** Plain 只规定“目标目录中的版本化 JSON”，Workspace 只规定 `<id>.json`，SQLite Operation 只规定“versioned payload”；文件名、schema URI、字段类型、phase 枚举、operation ID、相对路径编码、未知版本行为和 terminal record 清理规则都未定义。写入单元 A 使用数字 phase 和 UUID 文件名，恢复单元 B 使用字符串 phase 并只寻找固定文件名，两者都满足当前文字但互不识别。必须给出三个 journal 的 exact schema/golden、发现算法、write-ahead phase transition、fsync 边界、未知版本退出码和向后读取规则。

9. **恢复方向没有由 durable commit decision 决定。** 在 `--pigsty` 已切换 RPM pointer、尚未切换 DEB pointer 时，单元 A 可因“当前进程能判断则 rollback pointers”恢复旧状态；单元 B 可因“重启后 forward-complete”完成新状态。现有 phase 只是进度，不足以区分“副作用已发生但 phase 尚未持久化”的 crash window；仅凭文件 hash，两种方向都可能安全且都满足“最终旧或新”。这会让不同版本或不同恢复模块对同一 journal 做相反决定。必须在第一项公开副作用前持久化不可逆的 commit intent，冻结每个故障点的 evidence predicate、唯一恢复方向和 phase/fsync 顺序；证据冲突才返回 5。

10. **Pointer-last 只约束单文件，未定义一次 Plain mixed Operation 的可见性。** 默认 mixed create 至少有 RPM `repomd.xml`、DEB `Packages` 和 `Packages.gz` 三个客户端入口，却没有全局 pointer/marker。单元 A 可先切 RPM，单元 B 可先切 DEB；两者都遵守 AD-9，崩溃时却分别暴露“新 RPM/旧 DEB”和“旧 RPM/新 DEB”。基线又称 mixed 是一个 Operation、正常错误回滚全部 pointer，但没有说明运行中或进程终止后的半代可见性是否允许。契约必须明确保证究竟是“每个协议 view 自洽、重跑后整体收敛”还是“RPM+DEB 始终同代”；若要求后者，当前多个根级文件的 POSIX rename 方案缺少可实现的统一可见性指针。

11. **APT 的“协议 pointer”不是一个文件，切换集合与客户端优先级未定义。** Plain 同时发布 `Packages` 与 `Packages.gz`；Managed unsigned 模式发布 `Release`，signed 模式同时发布 `Release`、`InRelease`、`Release.gpg`，APT 客户端会因配置不同选择不同入口。单元 A 可把 `Packages.gz`/`InRelease` 当最后 pointer，单元 B 可把 `Packages`/`Release` 当最后 pointer；都符合“`Release/InRelease` 等 pointer last”，但不同客户端可能同时看到不同代，恢复时也会选择不同 canonical pointer。必须按签名模式冻结内容安装顺序、每个 client-visible pointer 的权威性、旧 by-hash 保留期、签名三件套的一致性规则，以及各 rename 前后的恢复判据。

12. **固定 private stage 与“同文件系统 rename”并不等价。** 布局把 stage 固定在 `<workspace>/.sow/<repo>/stage`，目标 pointer 在 `<workspace>/<repo>/dists`；Repository 目录完全可能是 Workspace 下的独立 mount。单元 A 可遵守固定布局使用 private stage，最终得到 `EXDEV`；单元 B 可遵守 AD-9，在目标 Repository 内创建隐藏 stage 以保证同 filesystem，却偏离固定 ownership/path。必须选择并冻结一个规则：初始化时验证 `.sow` 与 Repository `st_dev` 相同并拒绝跨设备布局，或把可 rename 的 stage 固定到每个目标 filesystem，同时明确其安全、恢复和清理所有权。

13. **新 Dist 的多 view 激活没有原子边界。** 单元 A 可逐个 architecture view 安装空 `repomd.xml`/APT pointer，最后更新 DB `done`；单元 B 可先完整构造 `<dist>` 目录，再对整个新 Dist 做一次 atomic directory rename。两者都满足 AD-9 和“空 Dist 可消费”，但 A 会暂时暴露只有 x86_64 或只有 amd64 的 Dist，B 不会；崩溃恢复所依据的目录证据也不同。契约必须分别规定 `dist new`、`init` 补 view 和未来更新已有 Dist 的 activation unit，并冻结 config 可见、DB row、Dist directory、各 view pointer 与 Built Generation 的顺序。

14. **P1 状态模型与 P2/P3 absence 自相矛盾。** AD-14 只允许 P2/P3 “internal data seams”，但基线 v1 schema 已要求 `package_objects`、`memberships`、Desired Revision、Built Generation 以及各级 built generation；同一文档 §14 又不加限定地说不注册 `rm/ls/show/check`，字面上会同时排除 P1 必需的 `repo/dist rm/ls/show` 和 `config check`。此外 P1 的 `dist new/rm` 必须形成 Built Generation 并用 SQLite Operation Journal，而 PRD 切片又把 Generation/Operation Journal 放到 P2/P3。单元 A 可在 P1 创建并递增 Generation、落下空 P2 tables；单元 B 可按 absence 原则省略它们、Generation 恒为 0，并移除所有同名命令。两者都有文本依据但 CLI、DB 与恢复完全不兼容。契约必须列出 fully-qualified 的 P1 命令与 forbidden top-level/package commands，定义 P1 可观察的最小 Generation/Operation 语义，并决定 P2 tables 是本次精确冻结的 schema 还是未来 migration，不能同时称其“已存在”与“未激活”。

在上述条款闭合前，独立实现之间无法仅凭 AD 达成持久化与恢复互操作；因此该 Spine 不应作为可直接并行编码的最终 build substrate。
