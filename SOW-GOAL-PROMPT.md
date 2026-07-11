# SOW 全量实现 Goal 提示词

你正在 `/Users/vonng/pgsty/sow` 工作。请先创建并持续执行一个长期 Goal；不要只制定计划、生成架构文档或完成单个里程碑后停止。

## Goal

把当前近乎空白的 SOW 工程完整实现为 Brainstorm、技术调研、PRD 与 Addendum 所定义的产品状态：一个可投入实际使用的、Go 编写的 Pigsty 软件仓库管理 CLI。它以“制品仓库的 git”为核心模型，完整管理 APT、YUM 与 asset 仓库，覆盖本地状态、包生命周期、上游同步、通道/视图/快照、原子发布、校验审计、双云对象存储/CDN，以及 Pro 商业访问控制。

只有当你通过证据化验收，确信所有范围内 PRD 要求均已真实实现且没有未处理的阻断项时，才可将 Goal 标记为完成。这里的“完成”指可运行、可测试、可运维的产品实现，不是设计稿、代码骨架、接口占位、Mock 演示、单个 happy path，或 M0/M1 等局部里程碑完成。

## 权威输入

开始前完整阅读以下文件；执行期间反复以原文校准，不要仅依赖本提示词的摘要：

1. `/Users/vonng/pgsty/sow/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md`
2. `/Users/vonng/pgsty/sow/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md`
3. `/Users/vonng/pgsty/sow/_bmad-output/planning-artifacts/research/technical-sow-repo-cli-tech-validation-research-2026-07-11.md`
4. `/Users/vonng/pgsty/sow/_bmad-output/brainstorming/brainstorm-sow-repo-cli-2026-07-11/brainstorm-intent.md`

解释优先级如下：PRD 是范围与验收合同；Addendum 是技术定案及对 PRD 的细化；技术调研是已验证的实现边界、风险和 PoC 依据；Brainstorm 用于理解产品意图和不应被实现细节消解的核心原则。若内容冲突，优先遵循更具体、更新且已冻结的决策，并用 ADR 记录判断。不要悄悄弱化要求。

## 执行要求

1. 先检查实际工作区、现有代码、用户改动和可用运行环境，建立 PRD 可追踪矩阵，覆盖 G1–G6、FR-01–FR-42、NFR-01–NFR-09、兼容/迁移冻结项、风险、PoC 与开放问题。此矩阵是持续更新的执行账本，不是用来代替实现的文档工作。
2. 补齐必要的架构与解决方案设计，尽早冻结 PRD 要求的不可逆契约，包括目录布局、manifest/ref/remote checkpoint 模型、配置 schema、URL/快照命名、YUM 成对翻转、provenance 双条目、边缘组件同构接口和失败恢复语义。保持设计精炼，以能指导实现、测试和迁移为度。
3. 按依赖关系迭代实现并持续集成。可以参考 M0–M4 的顺序，但里程碑只是路径，不是完成条件。所有 PRD 范围内功能，以及标为“延后但非不做”的能力，都必须进入最终实现；FR-17 明确规定的 RPM 重签分阶段策略按原契约执行，不擅自提前扩大范围。
4. 保持单一 Go CLI、Linux/macOS、零外部运行时依赖这一硬约束。解析层与自研边界必须遵守 Addendum；不要为了省事重新依赖 Python、Perl、gpg、createrepo_c 或把 aptly 当运行时组件。不要实现 PRD 明确排除的 modulemd、zchunk、sqlite repodata、通用云抽象或造包能力。
5. 实现完整命令面：`sow init`、`add`、`rm`、`sync`、`promote`、`publish`、`verify`、`fsck`、`materialize`，以及 PRD 要求的动词 × 选择器模型、可理解的帮助、错误、退出码、幂等和恢复行为。
6. 保护不可破坏的产品不变量：本地树可直接由 Nginx 托管；manifest 是正典、SQLite 仅为可重建缓存；默认路径按变更集增量工作；公开视图的机密性闭包不可绕过；发布必须把差异上传、索引翻转、最小 purge 和发布后验证收进同一事务；中断可检测、可恢复、可安全重放；latest 既有 URL 契约保持兼容。
7. 不把伪实现当完成。核心路径不得遗留 `TODO`、空函数、永远成功的校验、只覆盖内存 Mock 的适配器或无法被真实 CLI 调用的代码。Mock/Fake 只用于分层测试，必须同时存在真实文件系统、真实客户端协议和真实供应商集成路径。
8. 对开放问题先用文档、现有仓库、协议约束和可逆默认值推进；把决定记录为 ADR 和配置默认值。只有涉及不可逆业务选择、缺失凭据、真实云资源、付费或危险外部变更，且本地可完成工作已穷尽时，才向用户提出一个最小、具体的问题。不要拿开放问题当作停止整个 Goal 的理由。
9. 保留用户已有修改，避免无关重构。所有秘密只能通过环境变量、CLI 或安全的 secret provider 注入，测试和日志不得泄露密钥、token 或 passphrase。
10. 每轮都应推进实际代码和验证；遇到失败先诊断并修复。计划、状态报告和文档不能替代实现。除非 Goal 真实完成或出现必须由用户/外部环境解除的硬阻断，否则持续工作。

## 必须建立的验证证据

至少建立并实际运行以下验证面；根据实现风险继续补充：

- 单元测试、属性/边界测试、集成测试、故障注入与中断恢复测试、CLI 端到端测试。
- APT 仓库真实生成与消费：Packages/Release/InRelease、by-hash、签名、通道/快照，以及真实 `apt update/install` 验证。
- YUM 仓库真实生成与消费：primary/filelists/other、repomd 与 `.asc`、EL8 gz、EL9/10 zstd、成对翻转，以及真实 dnf 验证。
- asset、CAS pool、hardlink 物化、引用计数、GC、孤儿审计、manifest/SQLite 重建一致性。
- `sync` 的只加不删、过滤、校验、重试/断点和 RPM/DEB provenance 证据链。
- `publish` 的 O(变更集) 差异、双目标独立跟踪、远端 checkpoint/CAS、最小 purge、漂移检测、失败重放与幂等性。
- L1–L4 校验和不可跳过的机密性闭包负例测试；必须证明 gated 包无法通过公开索引泄漏。
- beta/latest/stable、promote、历史钉版、快照、EOL 冻结归档与离线 tgz 的完整工作流。
- Cloudflare Worker 与 EdgeOne 边缘函数的共享契约测试，覆盖 token 校验、剥离、干净 URL 缓存归一化、动态 mirrorlist 和 Basic Auth 回退。
- Linux/macOS 构建；大仓库流式内存行为与按 repo/component/arch 并行能力；以约 5 万包规模验证没有单线程或整库载入瓶颈，并记录结果。
- 从旧 Makefile 工作流迁移的对应表与可执行迁移/回滚说明，证明约 40 个旧目标已被 SOW 命令覆盖，存量仓库可先零字节纳管。

真实云验证需要凭据时，先用本地 S3 兼容环境、供应商契约测试和可重复的测试夹具把实现推进到最大程度；随后明确列出仍需真实环境完成的最小验证步骤并请求所需条件。未经真实验证，不得把相应 PoC 伪报为通过；Goal 保持未完成，除非用户明确批准书面豁免或接受替代证据。

## 完成判定

在宣告完成前执行一次独立、怀疑式的最终审计，并同时满足：

1. 可追踪矩阵中 G1–G6、FR-01–FR-42、NFR-01–NFR-09 以及冻结契约均有明确的实现位置和可复现验证证据，没有 `未实现`、`部分实现`、`仅设计` 或无依据的 `通过`。
2. 所有自动化测试、静态检查、构建、真实 apt/dnf 兼容测试和适用的云/边缘 PoC 通过；测试不是仅对 Mock 自证。
3. 从干净环境可依据文档构建、配置、运行、迁移、发布、恢复和排障；示例配置不含秘密且与实际 schema 一致。
4. PRD 中的成功指标和反指标均有测量结果或直接证据；带 `[ASSUMPTION]` 的数值要报告实测，不得默认为通过。
5. 没有会阻断真实使用的 TODO、已知严重缺陷、未处置安全问题、未决数据迁移或隐藏的人工发布步骤；CDN purge 不能退化为操作员记忆中的可选步骤。
6. 最终交付报告列出：实现摘要、关键架构决策、需求追踪结果、测试/性能/兼容证据、迁移说明、已知限制。任何保留项都必须证明属于 PRD 明确的范围外事项，而不是未完成工作。

最终完成标准由你负责判断，但判断必须建立在上述逐条证据上。不要要求用户替你确认“看起来差不多”；也不要因为代码量大、会话变长或已取得阶段性成果而降低标准。只有你确信实现已经完整达到 PRD 描绘的状态时，才将 Goal 标记为完成。
