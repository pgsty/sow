# PRD Quality Review — sow V2 阶段一

## Review snapshot

本评审只针对以下冻结快照；没有修改三份规范文件：

- `prd.md`: `5308594624298abffa7fcd224a8738cac15da4d5b2b454123763e6e6a102a6b4`
- `api-contract.md`: `3af3f02c5ee58cb93e65d9330a63414cb2207d6a889dbbb6ca4d5756a3c44ed5`
- `addendum.md`: `916d06e0580f54b24190c3263ee2b81eb39de92f6726999b8348c027177ecbba`

## Overall verdict

**有条件不通过（NOT READY FOR ARCHITECTURE / STORY BREAKDOWN）。** 这已经是一份有明确产品论点、诚实边界和高度具体 API 的优秀草案，Plain/Managed 两条闭环、Desired/Built 双状态、物理 Changeset 以及非目标都已基本收敛；不需要推倒重写。但签名幂等、仓库元数据签名、Policy 匹配、YUM 相对 Pool 可行性和 `--pigsty` 破坏性语义仍有五个会改变数据模型或验收结果的高优先级缺口，关闭后才适合把状态改为 approved。

## Decision-readiness — thin

PRD 对大多数真正困难的选择都作了明确决定：单机单写、Workspace 多 Repository、每 Repository 独占 Pool/SQLite、相对 Pool、无自动复活候选、默认 build、无 GC/远端状态。这比“保留所有选项”强得多。然而，当前又在 §13 声称“没有阻塞 Architecture 的隐藏假设”，而下面三个问题仍会改变身份模型、配置 schema 或目录布局，因此这个 readiness 声明尚未成立。

### Findings

- **[high] RPM 签名与重复 `add` 的幂等承诺没有闭合**（PRD §5.2、FR-7、SM Secondary；API §9.1、§10.1）— 处理顺序是“先对 stage 副本签名，再计算最终 SHA-256，再做坐标唯一性”；`fill/always` 只保证“输入已经由目标 key 签名”时不改字节。若用户隔一段时间重新加入同一个原始未签名 RPM，或同一个由别的 key 签名的 RPM，契约没有保证第二次签名字节稳定，也没有保存签名前身份来复用第一次生成的对象；于是同 NEVRA 可能得到新 SHA-256，反而触发硬冲突。这与“重复 add 为 no-op”直接冲突。*Fix:* 三选一并写成规范：保存签名前 payload identity + key/policy fingerprint 并复用现有签名对象；证明并要求确定性签名；或把幂等承诺明确缩小为“相同最终字节”。增加跨进程、跨时间重复加入同一未签名 RPM 的验收测试。
- **[high] Managed 元数据签名是承诺，却没有公共配置和产物契约**（PRD FR-12/NFR-4；API §2.3、§11.3、§13）— `build` 承诺 metadata “签名后切换”，布局列出 `InRelease`，`check` 也检查签名；但唯一配置只有 `signing.rpm.mode/key`，其语义是 RPM 包入库签名。没有说明 APT `InRelease`/`Release.gpg`、YUM `repomd.xml.asc` 是否生成、使用哪个 key、无 key 时是合法 unsigned 还是 build 失败、key 轮换与签名时间戳如何影响 no-op Generation。Architecture 无法从当前契约唯一实现。*Fix:* 增加独立的 repository-metadata signing schema、默认值、精确输出文件、缺 key/坏 key 行为及 `check` 验收；若阶段一不做，则删掉“签名后切换”和必有 `InRelease` 的承诺。
- **[high] YUM 相对 Pool location 的可行性门禁排在布局冻结之后**（PRD NFR-5、§8 P1/P3、§12 风险；API §2.3）— 文档自己把 DNF/YUM/reposync 对 `../..` 相对 href 的兼容性列为“布局冻结前 PoC”，但实施顺序在 P1 固定 layout/schema，到 P3 才跑真实客户端矩阵。一旦 P3 失败，会倒逼 Repository root、view baseurl、Pool 位置或去重模型重做。*Fix:* 把最小 PoC 设为进入 P1/Architecture 的前置 gate：至少覆盖 HTTP 与 `file://`、Tier 1 DNF、兼容目标 YUM 3/DNF 4/5 以及 reposync；记录解析后的实际请求路径。失败时必须回到布局决策，而不是作为 P3 bug 修补。

## Substance over theater — strong

没有 persona、愿景或 NFR 家具。文档用生产目录只读统计得到 34,184 个包、约 50.18 GiB 的真实容量基线；用户任务、命令、状态、退出码和故障边界都具体到可观察结果。V1 复用也被定义为候选模块而非“已有代码所以自然可复用”，证据层级诚实。

### Findings

- **[medium] “完整 rebuild 2 分钟”还不是可重复的性能验收**（PRD NFR-3、SM Secondary、P3）— 缺少参考机器、冷/热文件缓存、Repository/Dist/view 数、压缩与签名配置、是否复用已解析事实、测量起止点和重复次数；不同实现可以用完全不同的 workload 宣称通过。*Fix:* 在验收附件固定 benchmark manifest、硬件档位、cache 条件、命令、输出校验与统计口径，并把初次 import、clean rebuild、月度增量分开报告。

## Strategic coherence — strong

产品 thesis 清楚：SOW 只把本地包与显式成员关系收敛成可复制静态树；Plain 解决最短日常路径，Managed 解决长期成员管理，远端发布被明确切掉。FR、阶段顺序、Primary SM 与 Counter-metrics 都围绕这个 thesis，而不是命令数量或抽象扩展性。Changeset 改为描述完整物理交付树后，也与“Repository 目录可直接复制”一致。

### Findings

- **[medium] `delete` phase 容易被误读为可立即执行的远端发布计划**（PRD FR-14/SM Secondary；API §12.2；附录 §7）— 本地物理 diff 可以准确包含 delete，但远端客户端可能仍持有旧 `repomd.xml`/`Release` 并继续请求旧 metadata；只有“pointer 后 delete”并不能替代 grace period。附录又正确说明外部 rsync/rclone 行为不是 SOW 成功证明。*Fix:* 明确 Changeset 是完整的本地事实而非远端安全时序授权；外部消费者必须自行实施缓存失效与 delete grace。若目标真是“仅凭 JSON 即可安全发布”，则需要在 schema 中携带 `not_before`/保留代等策略信息。

## Done-ness clarity — adequate

FR-1 至 FR-14 几乎都有可测试后果，尤其 dirty/recovering、先 stage 后 pointer、`changes 0`、unknown architecture 与 production/test 边界写得很好。退出码和参数闭集也显著降低了 Story 拆分歧义。以下核心规则仍无法只凭文档写出唯一的验收 oracle。

### Findings

- **[high] `exclude` 与规范化 `kind` 尚不足以证明“OSS 没有 debug”**（PRD §5.3、FR-8；API §9.3、§10.1、§13）— 文档只说 name/source/arch/kind/format 支持 exact 或 glob，示例给出 `kind: [debuginfo, debugsource, llvmjit]`，但没有定义 `kind` 如何从 RPM/DEB 包头或命名推导、DEB dbgsym 如何分类、glob 语法/转义/大小写、同字段与跨字段是 OR 还是 AND、canonical arch 还是原生 arch。两种实现都可能“符合文字”却选出不同 Membership。*Fix:* 给出封闭 Policy schema、字段归一化表、匹配组合规则和顺序；用真实 RPM debuginfo/debugsource/llvmjit、DEB dbgsym、普通包的 golden table 验收。
- **[high] `--pigsty` 的 DEB 3.0.4 删除判据和破坏性恢复验收仍不唯一**（PRD FR-2/P0；API §5.1；附录 §2.2）— RPM 有独立 Version/Release，故“version=3.0.4、release 不限”清楚；DEB 的 `Version` 同时包含 epoch、upstream version 与 Debian revision，`3.0.4-1...` 是否命中没有定义。该歧义直接决定删除哪些真实文件。API 描述了轻量 journal，但 P0 验收也没有要求在撤 marker、两套 metadata 切换、逐包删除、写新 marker 各边界做 fault injection。*Fix:* 明确比较 Debian upstream version（或明确完整 Version）及 epoch/revision 规则，列出命中/不命中样例；把每个破坏性边界的 kill/retry/rollback 测试加入 P0 gate，并验证 symlink/未知文件始终未被触碰。
- **[medium] 批次“有失败即部分成功”与退出码 3 的定义冲突**（PRD FR-7；API §10.1、§15）— §10.1 写“只要存在失败项”就部分成功，§15 又要求“至少一个项目已提交、至少一个失败”。全批解析失败、全批坐标冲突或全部目标不兼容时没有提交，不应返回部分成功；全部被 Policy 排除是否算成功/no-op 也未说明。*Fix:* 写出 all-success、mixed committed/failed、all-failed、all-excluded 四格状态/退出码表。
- **[medium] Plain 重复执行的结果标准前后不一致**（PRD SM Secondary；API §5.1；NFR-4）— PRD 要求重复 `create` 为 no-op，API 允许“no-op 或语义等价索引”。带时间戳或不同压缩头但语义相同的 metadata 究竟能否改写，决定脚本是否能用 mtime/hash 判断变化。*Fix:* 选择字节级 no-op 或协议级等价，并为 Plain 明确定义；若选择前者，规定稳定 revision/timestamp/compression 或输入指纹跳过机制。

## Scope honesty — strong

非目标是本稿最强的部分之一：modulemd、Route、pull/copy、sync/publish、GC、SRPM/DSC、多写者等都被明确移除，而且没有留下空 flag/config 占位。生产仓库只读、测试仓库可破坏以及“外部复制不是 SOW 成功证明”都清楚地区分了源码、静态产物和远端发布证据。

### Findings

- **[medium] Workspace lifecycle journal 的审计边界没有诚实落到公共 API**（PRD §5.4/FR-13；API §2.2、§12.1–12.3）— 文档称 Operation 同时是恢复 journal 与语义审计，但 `init/repo new/repo rm` 使用 workspace file journal；公开 `sow log` 却是 Repository/SQLite 作用域，尤其 `repo rm` 完成后数据库已被删除。规范没有说明这些 destructive lifecycle 操作是否保留、如何查询/export/prune。*Fix:* 要么定义 workspace journal 的终态保留与只读查询 API，要么明确它只负责恢复、不属于审计承诺，并相应收窄“所有写命令可审计”的表述。
- **[low] “没有阻塞 Architecture 的隐藏假设”是过度结论**（PRD §13）— 当前仍有相对 href PoC 和 signing/Policy 契约缺口。*Fix:* 在高优先级项关闭前改为显式 blocking checklist；关闭后再恢复该句。

## Downstream usability — adequate

PRD、API 契约、技术附录的规范层级清楚；FR/NFR/US 编号连续，命令参数矩阵、状态机、退出码和典型故事都可以直接供 Architecture 与 Story 提取。单一运维者的场景也无需虚构命名 persona。主要障碍不是文档组织，而是上述几个公共配置与选择规则仍无唯一语义。

### Findings

- **[medium] 配置是公共 API，却只有“最小示例”而没有完整可提取 schema**（API §6、§8、§13）— Repository/Dist 继承、Policy、package signing、未来 metadata signing、key URI、默认值与 unknown-key handling 分散在正文。Architecture 可以补 schema，但 Story/测试无法确认其是否改变了产品契约。*Fix:* 在批准前增加一份封闭的 `sow.yml` schema 表或 JSON Schema，列出所有阶段一允许字段、类型、默认、继承、互斥、未知字段行为和敏感值规则。
- **[low] `Package Object` 与 `Content Object` 有轻微术语漂移**（PRD §4.3/FR-7；API §9.1、§10.3）— 两者似乎指同一个最终 SHA-256 对象，但名称交替。*Fix:* 增加五到十项紧凑 Glossary，并选定一个规范名。

## Shape fit — strong

这是内部、单操作者、协议密集的 CLI 技术产品，采用 capability spec + command contract + 少量典型故事，比完整 UX journey 或多 persona PRD 更合适。低层的 stage、SHA-256、pointer-last、Operation Journal 等细节大多是用户可观察的安全不变式，而不是无意义的实现绑架；唯一越界是相对 Pool 目录方案在真实客户端 PoC 前就接近被当成已冻结架构，这已在 Decision-readiness 中标出。

## Mechanical notes

- `FR-1..FR-14`、`NFR-1..NFR-6`、`US-1..US-10` 连续且无重复。
- PRD 与 API 均为 `draft`，规范层级和本地交叉引用一致；未发现 modulemd、Route、pull 或 sync 的残留命令/参数。
- Plain 默认无删除、`--pigsty` 显式授权、arch allowlist、`limit: 0`、Policy 放宽不复活、`add/rm` 默认 build、private pending 以及 Changeset=物理交付树均与最新产品决定一致。
- 没有 Assumption Index；对于这份由产品所有者直接确认、并把剩余项写成明确契约的内部 PRD，这本身不是缺陷。高优先级项关闭前，应把它们列为 blocking decisions，而不是隐藏在 Architecture 中自行决定。
