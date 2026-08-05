# sow V2 阶段一 API 契约 Adversarial Review

审查对象：`api-contract.md` 0.2、`prd.md` 与 `addendum.md`。本次从三份最新文档重新建立事实基线，不沿用旧版 CLI 结论。审查边界为公共命令、参数作用域、自动选择、Desired/Built/Generation/Changeset/Log 状态机、失败后置条件和跨文档一致性。

**Verdict: NOT READY FOR ARCHITECTURE OR STORY BREAKDOWN.** 产品边界已经比 V1 清晰，但当前 API 仍无法导出唯一、可测的实现；尤其是写操作失败、Policy 配置变更、Repository 创建/删除和 Changeset 的后置条件必须先封闭。

## Findings

- **默认 `add/rm` 的 build 失败后置条件没有定义。** `add` 先提交 Desired State 与 Pool，然后默认 build（`api-contract.md:372-398`）；`rm` 也默认 build（`api-contract.md:417-419`）。如果解析、Desired 与 Pool 成功，但渲染、签名、校验或切换失败，文档没有说命令是回滚 Desired/Pool，还是保留它们并以 `done_dirty`、`failed` 或非终态结束。这直接决定同一条失败命令是否已经改变用户状态，也决定下次写入是恢复还是重试。必须为每个阶段给出唯一的可观测后置条件和退出码优先级。

- **批次部分成功与默认 build 失败的组合语义是空的。** 合法包可以提交、非法包导致退出码 3（`api-contract.md:396,695`），但合法部分之后的 build 还可以再失败。此时应返回 1、3、5 还是其他码，`--json.ok`、Operation 终态、已提交包和 dirty 状态都未定义。“部分成功”必须是完整的组合状态机，不能只是一个退出码名称。

- **`build` 无法凭当前数据模型实现文档承诺的 Policy reconcile。** Policy 后只保留有效 Membership；Limit 淘汰的旧版本和 exclude 拒绝的包不再有“这个 Dist 曾经希望它”的 candidate/intent 关系（`api-contract.md:378-393`）。然而 `build` 又承诺手工修改 limit/exclude 后重新 reconcile（`api-contract.md:469`，`prd.md:252`，`addendum.md:121-123`）。将 `limit: 1` 改为 `2`、或移除 exclude，无法知道要把哪些 Pool Object 恢复为 Membership。必须二选一：持久化未经 Policy 的 candidate intent，或明确 Policy 放宽不会自动恢复包，需要用户重新 `add`。

- **Operation Journal 的“每个 Repository 写命令先写同一 SQLite”不能覆盖 `repo new/rm`。** `repo new` 在操作前还没有 `<repo>.db`，`repo rm -f` 又会删除承载 journal 的 DB 和私有恢复目录（`api-contract.md:220-245`），与 `api-contract.md:501-517` 的全称约束矛盾。这两条命令还同时修改 `sow.yml`、目录和 DB，恰好是最需要恢复边界的操作。需要 Workspace 级 journal/tombstone，或明确它们不属于该状态机并另立契约。

- **状态可以进入 `error`，但公共 API 没有任何可以离开 `error` 的路径。** `status` 只读，`check` 明确不恢复，下一写命令只能自动恢复“可安全决定”的 Operation（`api-contract.md:444-483`）。一旦自动恢复无法决定，文档只说需要人工处理，却没有 `recover/resolve`、可审查的手工 runbook 或受控状态转换。这会产生永久无法写入的 Repository。Plain `--pigsty` 的轻量 journal 同样没有不可自动恢复时的 API。

- **Changeset 同时被定义为“物理文件差异”和“Built Generation 可达闭包差异”，两者不是同一件事。** `--no-build` 已经把新包写入实体 `pool/`（`api-contract.md:398`），但文档要求该路径到首次被 Built Generation 引用时才在 changes 中作为 `add/payload` 出现（`api-contract.md:525-548`，`addendum.md:152-161`）。对文件系统来说，它在 base 与 current 两个时点都已存在，不是物理 add。`changes 0` 所谓“当前完整静态树清单”也没说是否包含从未被任何 Generation 引用的 Pool Object。必须把 Generation 定义为一个显式 closure manifest，并将 changes 称为 closure/publication delta；或真正按物理树比较，不能两种语义混用。

- **部分 Dist build 没有完整的 Repository Generation 模型。** `build -d A` 可以只收敛 A，其他 dirty Dist 保持旧状态（`api-contract.md:467-472`），但 Built Generation 又是 Repository 级单调编号。契约没有定义新 Generation 是否包含整个 Repository 的每 Dist 精确 built revision，`dist show` 显示的“Built Generation”是最后改动本 Dist 的代，还是当前 Repository 代，也不清楚。没有全树 manifest 或 per-dist built-revision map，`changes BASE`、dirty 判定和恢复都会得出不同实现。

- **用户手工编辑 `sow.yml` 的并发、生效时机和 dirty 判定没有契约。** 配置是用户意图，Policy 和 Dist 架构子集只能通过手工编辑设置（`api-contract.md:261,295-315,565-592`）。但编辑不取 Repository 锁、不写 Operation，也没有定义写命令在解析后、等锁后、提交前如何重验 config digest。`config check` 在 `api-contract.md:200-203` 看起来只解析 YAML，但 `api-contract.md:315` 又要它根据 Membership/Built Generation 拒绝移除架构，作用域自相矛盾。需要明确 config-only validation、state-aware validation、配置摘要与操作期间变更检测。

- **Repository 自动选择使用的“命令起始目录”在 `--workdir` 和 `SOW_DIR` 下不可判定。** Workspace 发现可从 `--workdir`、cwd 或 `SOW_DIR` 三个起点成功（`api-contract.md:75-84`），Repository 推断又依赖“命令起始目录位于 repo 内”（`api-contract.md:86-95`，`addendum.md:24`）。例如 cwd 在 repo A，但 `-C` 指向 repo B；或 cwd 在 Workspace 外，`SOW_DIR` 指向 repo B，都有两种合理答案。必须定义“成功发现 Workspace 的那个 origin”是否也是 scope inference origin，并给出冲突示例。

- **位置参数与全局 `-r/-d` 的互斥关系没有出现在公共语法中。** `repo show [NAME]`、`dist show NAME`、`repo/dist new/rm NAME` 都可以同时收到全局 selector，但只有 `repo new/rm` 明确说不接受 `-r`（`api-contract.md:54-65,95,108-143`）。`dist show foo -d bar`、`repo show foo -r bar`、`dist new foo -d bar` 应拒绝、忽略还是取交集未定义。`config show` 在多 Repository Workspace 根目录调用时，“当前选择作用域”也没有选择规则。

- **Repository/Dist 名字被称为“不透明字符串”，却直接映射为文件系统路径和 APT suite，没有合法语法。** `repo new NAME` 创建 `<workspace>/<NAME>`，Dist 创建 `dists/<NAME>`（`api-contract.md:220-226,251-260`），但没有禁止 `/`、`..`、绝对路径、NUL/控制字符、前导点、大小写折叠或 Unicode normalization collision。这不只是实现细节；它决定 macOS/Linux 上同一配置是否指向同一个 Repository，以及删除命令能否证明边界。

- **`check` 没有一个可重复的并发读取快照。** `--timeout/--no-wait` 只属于写锁命令（`api-contract.md:61-62`），`check` 明确只读，却要同时验证 YAML、SQLite、Pool 字节、Desired、Built metadata 与签名（`api-contract.md:474-484`）。它与 `add/build` 并发时可以读到不同时刻的 DB snapshot、Pool rename 和 Generation 切换，从而将合法操作误报为损坏。必须要么取 Repository shared/exclusive lock，要么绑定 config hash + DB read transaction + Built manifest 并在结束时检测世代变更后重试。

- **Plain 首次接管现有 createrepo/dpkg-scanpackages 索引的所有权规则缺失。** `create` 只管理“自己生成”的索引，只替换 SOW “已知”索引路径（`api-contract.md:35,168`），但 P0 的成功指标是直接替代已有 Pigsty 路径（`prd.md:399`，`addendum.md:33-47`）。首次面对 createrepo_c 的 `repodata/`、旧 `Packages.gz`、旧 `repo_complete` 时，没有 ownership marker，也没有 `--adopt/--replace-metadata`。保留旧 Release/签名/附加 repodata 可以产生互相矛盾的索引，直接替换整个目录又违反“只管理自己产物”。必须列出精确保留/接管/删除路径和首次迁移授权。

- **Plain `--pigsty` journal 的保留路径、授权延续与不同下一条命令的行为没有定义。** API 只说下一次 `create --pigsty` 必须恢复（`api-contract.md:170-183`）。如果崩溃后用户运行普通 `sow create`，它是应拒绝、以前一次授权继续删包，还是忽略 journal 重建包含待清理包的索引？“Plain 不建状态”与需要耐久 lock/journal 文件也需要保留名称、权限、清理和未知文件冲突契约。

- **RPM `fill/always` 与“重复 add 为 no-op”不兼容。** 内容身份是签名后字节（`api-contract.md:323`），`fill` 每次遇到同一份 unsigned 输入都要签名，`always` 也可能重签其他 key 的包（`api-contract.md:376,382-388`）。RPM 签名通常包含时间等可变字节，所以同一 unsigned 文件二次 add 可得到同坐标、不同 SHA，被当成硬冲突；这与 `prd.md:238,407` 的幂等承诺矛盾。需要确定性签名，或额外的 unsigned payload identity/已有坐标签名策略。

- **Managed metadata 签名是 build/check 的必要输入，但公共配置 API 只给了 RPM 包签名示例。** `build` 要在 stage 中签名，`check` 要验证签名（`api-contract.md:470,480`），PRD 也把 APT Release/YUM rpm-md 编码和签名列为核心能力（`prd.md:435-436`）。但最小 schema 只有 `signing.rpm.mode/key`（`api-contract.md:571-590`），没有 APT Release/InRelease、YUM repomd 签名开关、key reference/passphrase、无 key 时是否允许 unsigned、resolved key fingerprint 是否进入 build fingerprint。因此空 Dist 和普通 build 的可观测产物不唯一。

- **`exclude` 是写入不变式，但它的配置语法与事实归一化未被 API 定义。** PRD 声称支持 name/source/arch/kind/format 的 exact 或 glob（`prd.md:144-151`），API 只给了 `exclude.kind` 列表例子（`api-contract.md:579-583`）。没有 glob dialect、大小写、字段间 AND/OR、同字段多值、RPM/DEB source 缺失、`kind` 分类算法、canonical arch 还是 native arch 的规则。不封闭这些规则，Policy 结果无法做确定性验收。

- **Dist 只有 format/architecture，没有平台或 distro 边界，因而“默认正确”并不阻止把 EL10 RPM 明确加入名为 `el9` 的 Dist。** `add` 只检查 format、architecture 和 Policy（`api-contract.md:365-394`），Dist 名又明确是不透明字符串。这可以是有意的“用户显式选择即信任”，但必须在 API 和 `check` 边界中明说；否则用户会合理地以为包头的 disttag/distro 也是自动管理的一部分。

- **Plain 同时生成 RPM 和 DEB 索引时的一致性边界没有定义。** 文档允许两种包共存并同时生成 `repodata/`、`Packages`和 `Packages.gz`（`api-contract.md:153-161`），又声称失败时旧索引继续可用（`api-contract.md:178-183`）。POSIX 不能用一个 rename 同时切换这些独立路径。需要说明跨协议混合新旧索引是否仍算一个合法 Plain Generation，以及 `--pigsty` 何时才允许删包。

- **`check` 在 dirty 时的退出契约与“旧 Built Generation 完整可用”混在一个结果中。** API 要求分别验证 Desired 和旧 Built，然后返回“尚未 ready-to-copy”（`api-contract.md:480-484`），退出码 5 又同时表示完整性/恢复错误或不可交付（`api-contract.md:697`）。这会让 CI 无法区分“两层都正确但尚未 build”与“字节/索引已损坏”。需要独立 readiness 字段/退出码，或明确 dirty `check` 是 integrity success 还是 command failure。

- **退出码 6 与正常 Policy exclusion 直接冲突。** `add` 明确说 exclude 命中可报告为 `excluded`，不算解析失败（`api-contract.md:390-396`），但退出码 6 的文字是“架构、Policy 或逻辑坐标冲突导致内容被拒绝”（`api-contract.md:698`）。当唯一输入被 exclude，或一个包在部分 Dist accepted/部分 Dist excluded 时，是 0、3 还是 6 无法推导。

- **破坏性命令缺少与其风险相称的预览和确认契约。** `repo rm -f` 可删除 Pool、DB、dists 和恢复状态，`dist rm -f` 可删除整个 Dist，`log prune BEFORE` 可不经 export 永久删审计数据（`api-contract.md:236-280,550-563`），却故意不提供全局 dry-run/yes，也没有命令级 preview/精确目标确认。只有 `rm package -c` 可预览，与 NFR-6 的删除边界不对称。`log prune` 还没有定义 BEFORE 的 timezone、边界包含性和已存在 export 文件的覆盖行为。

- **用户被要求备份 SQLite，但阶段一没有安全备份 API 或取锁协议。** PRD 明确把 `sow.yml`、SQLite 和 Pool 备份交给用户（`prd.md:47,334`），但不提供 `backup`、不提供只取锁的 snapshot 命令，也没有文档化 WAL/SHM 安全拷贝流程。直接复制正在 WAL 模式运行的 `.db` 不是完整的备份契约。如果 `backup` 确实后置，阶段一至少必须给出可审查的停写+备份步骤。

- **Pool 与 metadata 的公开路径仍不是稳定 API。** 文档展示 `pool/` 和 `dists/`，但没有定义 Pool 分片、source 名归一化、保留 filename 还是 canonical filename、APT `Filename`、YUM `location_href` 和架构 view 到共享 Pool 的精确相对路径契约。`api-contract.md:343` 却已经把同 pool path/不同 SHA 定义为公开冲突，`changes` 也输出 repository-relative path。路径算法不封闭，冲突规则和 Changeset 都无法写成契约测试。

- **`repo show` 与 `status` 重复了大部分可观测信息，违背“一个概念一个命令”。** `repo show` 输出 Generation、dirty reason 和最近 Operation（`api-contract.md:228-234`），`status` 又输出 Repository state、Desired/Built、dirty Dist、未完成/最近 Operation 和锁（`api-contract.md:453-457`）。需要把 `repo show` 限定为静态配置/容量清单，或删除重复状态字段；否则两条命令在并发和 dirty 时很容易出现不同快照。

- **`rm` 的 filename selector 与“Filename 不是身份”之间缺少精确规则。** API 接受“完整 filename”（`api-contract.md:408-415`），却又明确 Filename 不是身份（`api-contract.md:343`）。“完整”是输入 basename、canonical pool-relative path，还是用户原始路径没有定义；多个 Pool 子目录存在相同 basename 时是否列候选也没有明说。应只接受 canonical reference/SHA/pool-relative path，或把 filename 明确定义为可歧义选择器。
