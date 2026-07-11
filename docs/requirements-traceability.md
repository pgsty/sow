# SOW 需求可追踪矩阵

> 状态：初始化执行账本  
> 建立日期：2026-07-11  
> 适用范围：SOW 全量产品实现，不以 M0–M4 任一局部里程碑替代最终验收。

## 1. 用途与权威来源

本文件是实现和验收的持续账本，不是设计完成证明。每次实现、测试、迁移或 PoC 后，应在同一变更中更新对应条目的状态、实现位置与可复现证据。

权威来源缩写：

- `PRD`：`_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md`
- `ADD`：`_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md`
- `GOAL`：`SOW-GOAL-PROMPT.md`
- 解释优先级：PRD 是范围与验收合同，Addendum 是更具体的技术定案；冲突按更新、更具体且已冻结的决策解释，并记录 ADR（GOAL:L13-L20）。

计划实现位置是当前代码布局假设，不是冻结合同。架构调整目录时必须同步更新本矩阵，需求 ID 不得丢失。

## 2. 状态枚举与证据规则

| 状态 | 含义 |
|---|---|
| `未实现` | 没有可由真实 CLI 调用的完整实现；设计稿、接口、骨架、TODO、空函数或 Mock 演示均属于此状态。 |
| `实现中` | 已有部分代码，但仍有路径、错误处理、恢复语义或真实适配器未完成。 |
| `已实现/未验证` | 实现已接入真实 CLI，但尚无足够的可复现验收证据。 |
| `未验证` | 指标、兼容性、风险或 PoC 尚无当前环境的有效测量结果。 |
| `已验证` | 有可复现命令、环境说明、测试输出或产物，并覆盖真实协议/文件系统/供应商路径。 |
| `已冻结` | 仅用于开放问题：具体值已由 ADR 与配置默认值定案；不表示依赖它的功能已实现。 |
| `未决` | 仅供开放问题使用；尚未由 ADR 和配置默认值冻结。 |
| `受阻` | 已穷尽本地可行工作，明确记录所缺凭据、真实资源或不可逆业务决定。 |
| `范围外` | 仅用于 PRD 明确排除项，不得用于隐藏未完成范围内工作。 |

证据纪律：

1. 设计文档、技术调研、类型定义、编译成功和 Mock-only 测试不能单独将条目标为 `已验证`。
2. `已验证` 的证据列必须包含可复现命令、执行环境、结果摘要，并优先链接保存的日志、报告或测试产物。
3. apt/dnf、真实文件系统、本地 S3 兼容服务、真实云/CDN 各是不同证据层，不得相互冒充。
4. 真实云凭据缺失时，先完成本地 S3 与供应商契约测试；相应云 PoC 仍保持 `未验证`（GOAL:L51）。
5. 最终完成前所有范围内条目必须没有 `未实现`、`实现中`、`已实现/未验证`、`未验证`、`未决` 或无依据的通过（GOAL:L55-L62）。

## 3. 当前总览

| 类别 | 总数 | 当前结果 |
|---|---:|---|
| 成功指标 G1–G6 | 6 | 0 已验证，6 未验证 |
| 功能需求 FR-01–FR-42 | 42 | 6 实现中，36 未实现 |
| 非功能需求 NFR-01–NFR-09 | 9 | 4 实现中，5 未验证 |
| 冻结契约 FZ-01–FZ-08 | 8 | 0 已实现，8 未实现 |
| 开放问题 OQ-1–OQ-5 | 5 | 3 已冻结，2 未决 |
| 上线 PoC | 7 | 0 已验证，7 未验证 |

## 4. 成功指标与反指标

### 4.1 G1–G6

| ID | 要求 | 来源 | 初始状态 | 计划实现/测量位置 | 当前证据 |
|---|---|---|---|---|---|
| G1 | 元数据不匹配、漏 purge 类发布事故归零 | PRD:L35 | 未验证 | `internal/publish/`、`internal/verify/`；故障注入和发布恢复 E2E | 无；待事务故障矩阵与运行记录 |
| G2 | 加包由单命令完成；`[ASSUMPTION] <1 分钟` | PRD:L36 | 未验证 | `cmd/sow/`、`internal/app/add/`；`test/bench/add/` | 无；待真实 deb/rpm 加包计时 |
| G3 | 日常发布远端 API 调用量为 O(变更集) | PRD:L37 | 未验证 | `internal/publish/diff/`、provider 调用计数器 | 无；待不同仓库规模、固定变更集的调用数报告 |
| G4 | 公开索引机密性违规由机器门禁 100% 拦截 | PRD:L38 | 未验证 | `internal/verify/confidentiality/`；负例 E2E | 无；待 gated 包公开闭包泄漏负例 |
| G5 | 约 40 个 Makefile 目标全部由 sow 命令替代并退役 | PRD:L39 | 未验证 | 本文第 11 节、`docs/migration/`、CLI E2E | 无；待逐目标清点、映射和执行证据 |
| G6 | M0 后本地与 cf/cos 漂移清零并保持 | PRD:L40 | 未验证 | `internal/fsck/`、`internal/publish/checkpoint/` | 无；待基线、修复后及重复对账报告 |

### 4.2 反指标

| ID | 不得恶化的指标 | 来源 | 初始状态 | 计划证据 | 当前证据 |
|---|---|---|---|---|---|
| ANTI-01 | 常规增量发布不得显著变慢；`[ASSUMPTION] <10 分钟` | PRD:L42-L44 | 未验证 | 固定变更集的双目标发布计时及 API 计数 | 无 |
| ANTI-02 | 存储成本不升；合一仓库预计每云节省约 60GB | PRD:L45；ADD:L71-L75 | 未验证 | 迁移前后对象数、逻辑/物理字节及账单估算 | 无 |
| ANTI-03 | OSS `latest` 现有 URL 契约不破坏 | PRD:L46；PRD:L175 | 未验证 | 旧 URL 清单、迁移前后 HTTP/apt/dnf 回归 | 无 |

## 5. 功能需求

### 5.1 状态模型与纳管

| ID | 要求摘要 | 来源 | 初始状态 | 计划实现位置 | 当前证据 |
|---|---|---|---|---|---|
| FR-01 | 每仓库维护排序 TSV manifest，字段为 path/size/sha256；Git 承载正典与历史 | PRD:L92 | 实现中 | `internal/manifest/`、`internal/state/`、`.sow/state/manifests/` | `go test ./internal/manifest ./internal/state`；真实 72,310 包确定性外部排序见 `docs/evidence/2026-07-11-manifest-72k-performance.md`；完整 ref 模型待实现 |
| FR-02 | SQLite 是 gitignored、可由 manifest 重建的只读缓存 | PRD:L93 | 实现中 | `internal/catalog/`、`.sow/cache/state.db` | `go test ./internal/catalog` 真实创建 SQLite、删除并由 canonical manifest 重建同一 2 行结果；依赖/包查询投影待扩展 |
| FR-03 | cf/cos 独立已发布 ref，可各自滞后；算差异无需远端 API | PRD:L94 | 未实现 | `internal/publish/refs/`、`.sow/refs/remotes/` | 无；待双目标独立 ref 与零调用 diff 测试 |
| FR-04 | bucket checkpoint 为 `.sow/manifest.json` 加代际号；GET 检漂移，CAS 兼发布锁 | PRD:L95 | 未实现 | `internal/publish/checkpoint/`、`internal/cloudflare/`、`internal/tencent/` | 无；待真实条件写、漂移和竞争测试 |
| FR-05 | `sow init` 扫描现有树，实现零字节纳管 | PRD:L96 | 实现中 | `internal/cli/app.go`、`internal/manifest/`、`internal/state/` | `go test ./internal/cli -run TestInitAndFSCKEndToEnd` 证明现有发布文件字节不变、幂等 Git baseline；真实存量树正式纳管与远端基线仍待执行 |
| FR-06 | 默认增量检查变更；显式 fsck 才全量审计 | PRD:L97 | 实现中 | `internal/manifest.Diff`、`sow fsck` | 流式本地 diff 与退出码 4 已由 CLI E2E 覆盖；add/rm 增量提交和远端 ListObjects 审计未实现 |

### 5.2 仓库引擎

| ID | 要求摘要 | 来源 | 初始状态 | 计划实现位置 | 当前证据 |
|---|---|---|---|---|---|
| FR-07 | 自研 APT Packages/Release/InRelease；Day 1 by-hash、SHA256 路径、保留 N 版清理 | PRD:L101；ADD:L14,L29 | 未实现 | `internal/repo/apt/` | 无；待真实 apt update/install、快照、by-hash 测试 |
| FR-08 | 自研 YUM primary/filelists/other/repomd；EL9/10 zstd、EL8 gz；repomd 与 asc 成对翻转 | PRD:L102；ADD:L15 | 未实现 | `internal/repo/yum/`、`internal/publish/yumflip/` | 无；待真实 dnf、压缩矩阵及中断翻转测试 |
| FR-09 | asset 仓库无索引，只参与 manifest/publish，覆盖 bin/src/pkg/etc/img | PRD:L103 | 未实现 | `internal/repo/asset/` | 无；待 asset CLI 与发布 E2E |
| FR-10 | 单 GPG key，env/CLI 注入，纯 Go OpenPGP，Linux/macOS，不执行 gpg | PRD:L104；ADD:L13 | 未实现 | `internal/signing/`、`internal/secret/` | 无；待 apt/dnf 签名验证与依赖/进程审计 |

### 5.3 包生命周期

| ID | 要求摘要 | 来源 | 初始状态 | 计划实现位置 | 当前证据 |
|---|---|---|---|---|---|
| FR-11 | `add/rm` 自动识别 deb/rpm、推断 repo/OS/arch、入池、签名并建索引 | PRD:L108 | 未实现 | `internal/app/add/`、`internal/app/remove/`、CLI | 无；待多格式、多架构、歧义和错误路径 E2E |
| FR-12 | `.pool/` SHA256 CAS + hardlink 物化；`.sow/`/`.pool/` 遮蔽；树根可由 Nginx 直接托管 | PRD:L109 | 未实现 | `internal/pool/`、`internal/materialize/` | 无；待 inode、跨文件系统降级及 Nginx 消费测试 |
| FR-13 | 引用计数、自动 GC、孤儿审计 | PRD:L110 | 未实现 | `internal/pool/refs/`、`internal/pool/gc/` | 无；待属性测试、崩溃恢复和孤儿夹具 |

### 5.4 上游同步与 provenance

| ID | 要求摘要 | 来源 | 初始状态 | 计划实现位置 | 当前证据 |
|---|---|---|---|---|---|
| FR-14 | 自研 Go 同步器，只加不删，永久保留上游旧版本 | PRD:L114；ADD:L16,L21 | 未实现 | `internal/sync/` | 无；待上游删包后本地仍保留的集成测试 |
| FR-15 | 包名+架构 glob/正则黑白名单；debuginfo 独立过滤；不做依赖自动补全 | PRD:L115 | 未实现 | `internal/sync/filter/` | 无；待组合、边界、非法正则和 public/pro 过滤测试 |
| FR-16 | RPM/DEB 不对称 provenance，保存上游 URL、校验信息和签名根证据 | PRD:L116；ADD:L49-L56 | 未实现 | `internal/provenance/` | 无；待真实 RPM/DEB 上游夹具与证据链验证 |
| FR-17 | Day 1 不重签镜像 rpm；自建包构建时签；全量重签须商业需求和 EL9/10 真机前置验证 | PRD:L117；ADD:L17,L82-L83 | 未实现 | `internal/policy/rpmsign/`、`docs/operations/signing.md` | 无；待“不重签字节保持”及自建包 `rpm -K` 证据 |

### 5.5 通道、视图与快照

| ID | 要求摘要 | 来源 | 初始状态 | 计划实现位置 | 当前证据 |
|---|---|---|---|---|---|
| FR-18 | beta/latest/stable 为 manifest 视图；入池进 beta，promote 为清单运算 | PRD:L121 | 未实现 | `internal/view/`、`internal/app/promote/` | 无；待通道代数、幂等 promote 与 CLI E2E |
| FR-19 | stable 包永不消失并支持 apt/dnf 全历史原生钉版 | PRD:L122 | 未实现 | `internal/view/stable/` | 无；待多代包、rm/GC 负例和真实钉版安装 |
| FR-20 | 快照是 manifest Git ref；APT 共享 pool+suite；YUM 独立 hardlink 树并支持远端 copy | PRD:L123 | 未实现 | `internal/snapshot/`、APT/YUM materializer | 无；待多快照及历史消费测试 |
| FR-21 | APT dists 别名；YUM mirrorlist/metalink 指针；通道切换不复制包体 | PRD:L124 | 未实现 | `internal/channel/` | 无；待指针翻转、purge 和客户端回归 |
| FR-22 | bucket 只物化 stable 与最近 N 月，老快照按需重建 | PRD:L125 | 未实现 | `internal/materialize/retention/` | 无；N 未冻结，待保留窗口/重建测试 |
| FR-23 | `materialize` 从任意 ref 生成 hardlink 树；离线 tgz 经 asset 发布闭环 | PRD:L126 | 未实现 | `internal/materialize/`、`internal/artifact/tar/` | 无；待 tgz 内容、校验和及离线消费 E2E |
| FR-24 | EOL OS 冻结归档；EL8 停止新构建并固定 gz repodata | PRD:L127 | 未实现 | `internal/view/eol/`、配置策略 | 无；冻结版本未决，待 EOL 工作流测试 |

### 5.6 发布事务

| ID | 要求摘要 | 来源 | 初始状态 | 计划实现位置 | 当前证据 |
|---|---|---|---|---|---|
| FR-25 | publish 将差异上传、索引翻转、最小 purge、发布后验证收为整体动作；任一步失败返回失败 | PRD:L131 | 未实现 | `internal/publish/transaction/` | 无；待逐阶段故障注入与 CLI 非零退出测试 |
| FR-26 | 内容寻址先上传，最后翻转；APT 为 InRelease，YUM 为 repomd+xml.asc 对 | PRD:L132 | 未实现 | `internal/publish/flip/` | 无；待客户端并发读取和中断点测试 |
| FR-27 | 仅 purge 翻转点和通道指针；旧索引仍始终自洽 | PRD:L133 | 未实现 | `internal/cloudflare/purge/`、`internal/tencent/purge/` | 无；待精确 URL 集与旧代际消费测试 |
| FR-28 | CAS checkpoint 兼发布锁；中断可检测、报告、安全重放、幂等 | PRD:L134 | 未实现 | `internal/publish/journal/`、`checkpoint/` | 无；待进程 kill、网络失败和重复 publish 测试 |

### 5.7 校验体系

| ID | 要求摘要 | 来源 | 初始状态 | 计划实现位置 | 当前证据 |
|---|---|---|---|---|---|
| FR-29 | L1 索引与包双向一致且签名有效 | PRD:L138 | 未实现 | `internal/verify/l1/` | 无；待缺包、多余包、篡改签名负例 |
| FR-30 | L2 本地与远端 manifest 对账 | PRD:L139 | 未实现 | `internal/verify/l2/` | 无；待缺失/多余/摘要漂移夹具 |
| FR-31 | L3 发布后穿 CDN 验证 | PRD:L140 | 未实现 | `internal/verify/l3/` | 无；待本地代理及真实 CDN 证据 |
| FR-32 | L4 模拟真实 apt/dnf 客户端端到端验证 | PRD:L141 | 未实现 | `internal/verify/l4/`、`test/compat/` | 无；待真实 apt/dnf 容器或 VM 运行日志 |
| FR-33 | public 视图闭包必须是 public pool 子集；门禁不可跳过 | PRD:L142 | 未实现 | `internal/verify/confidentiality/` | 无；待 gated 泄漏负例和所有发布入口绕过测试 |
| FR-34 | `verify` 可跑 L1-L4 全部或子集；`fsck` 全量 ListObjects 并报告遗留垃圾 | PRD:L143 | 未实现 | CLI、`internal/fsck/` | 无；待选择器、漂移分类和真实对象列表测试 |

### 5.8 商业访问控制与边缘组件

| ID | 要求摘要 | 来源 | 初始状态 | 计划实现位置 | 当前证据 |
|---|---|---|---|---|---|
| FR-35 | 每云一个合一仓库；OSS/Pro 为元数据视图，避免追加同步/裁剪导出 | PRD:L147；ADD:L69-L75 | 未实现 | `internal/view/access/`、布局 ADR | 无；待同池双视图与存储比较 |
| FR-36 | public/gated 按机密性分池；闭源包必须在真实门控前缀 | PRD:L148 | 未实现 | `internal/pool/security/`、配置校验 | 无；待错误分池和公开引用负例 |
| FR-37 | token-in-path；全部元数据使用相对 href | PRD:L149；ADD:L47 | 未实现 | `edge/contract/`、APT/YUM URL 生成器 | 无；待 apt/dnf token 路径消费测试 |
| FR-38 | Cloudflare Worker 与 EdgeOne 同构、共享测试；验 token、剥离、干净 URL 子请求、模板回填 | PRD:L150；ADD:L41-L47 | 未实现 | `edge/contract/`、`edge/cloudflare/`、`edge/edgeone/` | 无；待供应商运行时契约测试及真实 PoC |
| FR-39 | Pro mirrorlist 动态读取指针并回填 token；OSS mirrorlist 静态 | PRD:L151 | 未实现 | `edge/contract/mirrorlist/` | 无；待 token 隔离和模板边界测试 |
| FR-40 | Basic Auth 为唯一回退；query token 和自定义 header 排除 | PRD:L152 | 未实现 | 两家边缘实现、`docs/operations/access.md` | 无；待 apt auth.conf、dnf 凭据真实测试 |

### 5.9 配置与命令面

| ID | 要求摘要 | 来源 | 初始状态 | 计划实现位置 | 当前证据 |
|---|---|---|---|---|---|
| FR-41 | `sow.yaml` 声明 gpg/pools/repos/upstreams/views/targets | PRD:L156；ADD:L58-L67 | 实现中 | `internal/config/`、`sow.example.yaml` | `go test ./internal/config` 覆盖 `sow/v1`、unknown field、引用、秘密引用、冻结值、EL8/9 压缩；供应商操作时的延迟 secret 解析与 schema 迁移待实现 |
| FR-42 | 所有命令采用动词 × repo/OS/arch/view 选择器 | PRD:L157 | 实现中 | `internal/cli/app.go` | init/fsck 已支持重复或逗号分隔 repo/OS/arch 选择器、空匹配失败；view 与其余动词尚未实现 |

## 6. 非功能需求

| ID | 要求摘要 | 来源 | 初始状态 | 计划实现/验证位置 | 当前证据 |
|---|---|---|---|---|---|
| NFR-01 | repo/component/arch 并行；5 万包级不得单线程卡死 | PRD:L161；ADD:L35 | 实现中 | `internal/manifest/scan.go`、`test/perf/manifest_large_test.go` | 72,310 包使用 18 worker、7.91s、CPU time > wall time；见 `docs/evidence/2026-07-11-manifest-72k-performance.md`；索引/link/publish 调度未实现，不能整体通过 |
| NFR-02 | manifest/index 流式或惰性处理，不整库入内存 | PRD:L162；ADD:L36 | 实现中 | 外部 run sort+k-way merge、流式 reader/diff/catalog | 72,310 包/89.86GB 最大 RSS 92,094,464 bytes；见性能证据；APT/YUM XML/index 尚未实现，不能整体通过 |
| NFR-03 | 日常远端 API O(变更集)，只在 fsck 全扫 | PRD:L163 | 未验证 | provider 调用计数、规模不变量测试 | 无 |
| NFR-04 | 单 Go 二进制，Linux/macOS，零 Python/Perl/gpg/createrepo_c 等运行时依赖 | PRD:L164 | 实现中 | Go module、build matrix、干净主机 E2E、进程审计 | 当前 init/fsck 为纯 Go 且 `CGO_ENABLED=0` linux/amd64、darwin/arm64 构建通过；完整命令面与干净主机证据待补 |
| NFR-05 | apt >=1.2 by-hash；老客户端原子翻转兜底；EL9/10 zstd、EL8 gz | PRD:L165 | 未验证 | `test/compat/apt/`、`test/compat/dnf/` | 无 |
| NFR-06 | 签名链完整；秘密不落镜像/明文配置；token 不进公开缓存键；真机签名用例进 CI | PRD:L166 | 未验证 | signing E2E、secret/log 扫描、edge cache-key 测试 | 无 |
| NFR-07 | 存储少量重复可接受；APT 共享 pool；CDN 零客户碎片；CF 无需 Enterprise | PRD:L167 | 未验证 | 存储统计、不同 token cache hit PoC、成本报告 | 无 |
| NFR-08 | 全部变更有 Git 历史；镜像有 provenance；漂移可检测报告 | PRD:L168 | 实现中 | `internal/state/`、`internal/provenance/`、fsck | baseline 内嵌 Git 与本地漂移报告有真实 CLI E2E；refs/provenance/远端漂移未实现 |
| NFR-09 | 发布中断可恢复重放；两云可独立滞后且互不阻塞 | PRD:L169 | 未验证 | 双目标状态机和逐阶段故障注入 | 无 |

## 7. 冻结兼容契约

PRD 中已经写下决策不等于产品已经实现；以下初始状态均保持 `未实现`。

| ID | 冻结项 | 来源 | 初始状态 | 计划 ADR/实现位置 | 当前证据 |
|---|---|---|---|---|---|
| FZ-01 | `.sow/`、`.pool/` 加现有发布树；本地树即 bucket 镜像；latest URL 不变 | PRD:L175 | 未实现 | `docs/adr/0001-local-layout.md`、manifest/materialize | 无 |
| FZ-02 | YUM `Packages/<首字母>/`；禁止跨仓库 `../` href；迁移绑定结构调整阶段 | PRD:L176 | 未实现 | `docs/adr/0002-yum-layout.md`、YUM engine | 无 |
| FZ-03 | 通道名 beta/latest/stable，加后续 snapshot | PRD:L177 | 未实现 | `docs/adr/0003-channel-naming.md`、config validation | 无 |
| FZ-04 | token URL 与快照 ID 命名空间冻结；具体格式须架构阶段定案 | PRD:L178 | 未实现 | `docs/adr/0004-url-and-snapshot-naming.md` | 无；OQ-1/OQ-3 未决 |
| FZ-05 | 单 GPG key | PRD:L179 | 未实现 | `docs/adr/0005-signing.md`、config/signing | 无 |
| FZ-06 | repomd.xml 与 `.asc` 成对原子翻转语义 | PRD:L180 | 未实现 | `docs/adr/0006-yum-paired-flip.md` | 无 |
| FZ-07 | RPM/DEB provenance 不对称双条目 schema | PRD:L181；ADD:L49-L56 | 未实现 | `docs/adr/0007-provenance.md`、provenance package | 无 |
| FZ-08 | Cloudflare/EdgeOne 边缘鉴权组件同构接口 | PRD:L182 | 未实现 | `docs/adr/0008-edge-contract.md`、`edge/contract/` | 无 |

### 7.1 其他兼容合同

| ID | 合同 | 来源 | 初始状态 | 计划证据 | 当前证据 |
|---|---|---|---|---|---|
| COMP-01 | 本地树根直接由 Nginx 托管，无 sow 运行时 | PRD:L53,L109 | 未验证 | Nginx 指向物化根并由 apt/dnf/HTTP 消费 | 无 |
| COMP-02 | apt >=1.2 使用 by-hash，老客户端仍由翻转语义兜底 | PRD:L165 | 未验证 | apt 版本矩阵 | 无 |
| COMP-03 | EL9/10 zstd、EL8 gz | PRD:L102,L165 | 未验证 | dnf 版本/OS 矩阵 | 无 |
| COMP-04 | APT 快照为标准 suite，YUM 通道为标准 mirrorlist/metalink | PRD:L123-L124 | 未验证 | 原生客户端无插件消费 | 无 |
| COMP-05 | `dnf module disable postgresql` 等行为仅由安装文档处理 | PRD:L165 | 未验证 | 安装文档与真实客户端步骤 | 无 |

## 8. Addendum 技术边界

| ID | 技术定案 | 来源 | 初始状态 | 计划位置/检查 | 当前证据 |
|---|---|---|---|---|---|
| TECH-01 | deb/control/version/dependency 解析采用 `pault.ag/go/debian` | ADD:L11 | 未实现 | `go.mod`、APT parser；依赖审计 | 无 |
| TECH-02 | RPM 全字段头解析采用 `cavaliergopher/rpm` | ADD:L12 | 未实现 | `go.mod`、RPM parser；真实包夹具 | 无 |
| TECH-03 | OpenPGP 采用 ProtonMail go-crypto，不执行 gpg | ADD:L13 | 未实现 | signing package；进程/依赖审计 | 无 |
| TECH-04 | APT 索引装配、压缩、checksum、by-hash 自研 | ADD:L14 | 未实现 | `internal/repo/apt/` | 无 |
| TECH-05 | YUM XML、压缩和 SHA256 命名自研 | ADD:L15 | 未实现 | `internal/repo/yum/` | 无 |
| TECH-06 | 同步器自研并包含下载校验、验签和 provenance | ADD:L16 | 未实现 | `internal/sync/` | 无 |
| TECH-07 | RPM 重签延后并受真机验证门禁 | ADD:L17 | 未实现 | 策略门禁；不得默认开启 | 无 |
| TECH-08 | 不做 sqlite primary_db/modulemd/zchunk | ADD:L18 | 未验证 | 依赖、产物和命令面负向审计 | 无 |
| TECH-09 | 不 import aptly，只允许参考源码 | ADD:L20 | 未验证 | `go list -deps` 与许可证审计 | 无 |
| TECH-10 | 不采用 Workers Cache API；鉴权后以干净 URL 子请求归一缓存 | ADD:L43-L47 | 未实现 | edge implementations/contract tests | 无 |

## 9. 明确范围外项

这些条目用于防止范围蔓延；初始保持 `未验证`，直至依赖、命令面和产物审计证明没有误实现或运行时依赖。

| ID | 排除项 | 来源 | 初始状态 | 计划负向证据 | 当前证据 |
|---|---|---|---|---|---|
| OUT-01 | PostgreSQL 不是核心依赖，仅可选导出目标 | PRD:L67 | 未验证 | `go list -deps`、干净运行环境 | 无 |
| OUT-02 | 不做通用云抽象，使用 Cloudflare/腾讯具体客户端 | PRD:L68 | 未验证 | 架构与依赖审计 | 无 |
| OUT-03 | 不做 modulemd、zchunk、sqlite repodata | PRD:L69 | 未验证 | 产物扫描与 CLI 帮助审计 | 无 |
| OUT-04 | 不做多 GPG key 体系 | PRD:L70 | 未验证 | config schema 负例 | 无 |
| OUT-05 | 不造 deb/rpm，只管理既有制品 | PRD:L71 | 未验证 | CLI/依赖/文档审计 | 无 |

## 10. 迁移账本

### 10.1 迁移合同

| ID | 迁移要求 | 来源 | 初始状态 | 计划位置/证据 | 当前证据 |
|---|---|---|---|---|---|
| MIG-01 | 先 `sow init` 建基线，再对 cf/cos 做首次 fsck 和遗留垃圾报告 | PRD:L192 | 未实现 | `docs/migration/zero-byte-onboarding.md`、真实存量树报告 | 无 |
| MIG-02 | 四个 Makefile 约 40 个业务目标逐项映射到 sow 命令 | PRD:L15,L39；GOAL:L49 | 未实现 | `docs/migration/make-target-map.md`、每行 E2E 证据 | 无；不得按命令族笼统宣称覆盖 |
| MIG-03 | latest 旧 URL 全部保持兼容 | PRD:L46,L175 | 未验证 | 迁移前 URL 基线与迁移后回归 | 无；具体 URL 清单尚未建立 |
| MIG-04 | YUM 首字母拆分、by-hash、快照/指针、合一布局按结构调整阶段迁移 | PRD:L176,L194 | 未实现 | `docs/migration/layout-migration.md` | 无 |
| MIG-05 | 存量仓库先零字节纳管，再分阶段结构迁移 | PRD:L186,L192 | 未实现 | 每阶段 checksum、manifest diff 和停止/恢复点 | 无 |
| MIG-06 | 提供可执行回滚说明，不隐藏人工发布/purge 步骤 | GOAL:L49,L59-L61 | 未实现 | `docs/migration/rollback.md`、回滚演练日志 | 无 |
| MIG-07 | 回写旧 Pro 设计，正式废止双云双独立 pro bucket | PRD:L184；ADD:L69-L77 | 未实现 | 旧设计文档变更链接及迁移说明 | 无 |
| MIG-08 | 仅当全部旧目标映射、存量数据验收和回滚演练通过后退役 Makefile | PRD:L39,L186 | 未验证 | 退役门禁清单 | 无 |

### 10.2 旧 Makefile 清点入口

以下只是发现入口，不是覆盖证明。精确目标数、别名、依赖关系和副作用必须落入 `MIG-02` 的逐目标映射。

| 旧文件 | 当前已观察的目标族 | 初始状态 | 新命令目标 | 当前证据 |
|---|---|---|---|---|
| `/Users/vonng/pgsty/repo/Makefile` | copy、co/cf 上传、infra/pgsql/pgdg/percona、pro、asset 类目标 | 未实现 | `add/sync/publish/fsck` 加选择器 | 仅发现文件与 target 名；未做语义/副作用审计 |
| `/Users/vonng/pgsty/repo/apt/Makefile` | init/add/rm/list/trim、suite、cf/cos upload、上游获取 | 未实现 | `init/add/rm/sync/publish/verify` | 仅发现；未逐目标映射 |
| `/Users/vonng/pgsty/repo/yum/Makefile` | build/sign、infra/pgsql/percona | 未实现 | `add/sync/publish/verify` | 仅发现；未逐目标映射 |
| `/Users/vonng/pgsty/repo/docker/Makefile` | 容器生命周期以及 sign/build 包装目标 | 未实现 | 原生 Go CLI；容器包装目标退役 | 仅发现；未证明零外部运行时替代 |

## 11. 风险账本

| ID | 风险 | 来源 | 初始状态 | 缓解/验证计划 | 当前证据 |
|---|---|---|---|---|---|
| RISK-01 | go-crypto 签名产物客户端兼容性 | PRD:L202 | 未验证 | apt/dnf 真机矩阵常驻 CI | 无 |
| RISK-02 | EdgeOne 缓存是 per-node 还是共享/tiered 尚未证实 | PRD:L203；ADD:L81 | 未验证 | 真实 EdgeOne PoC；失败启用 Basic Auth | 无 |
| RISK-03 | RPM 重签可能破坏 EL9/10 SHA256 摘要 | PRD:L204；ADD:L83 | 未验证 | Day 1 禁用；启用前真机 rpm -K | 无；风险通过策略规避但 PoC 未通过 |
| RISK-04 | 对象存储上的半残 by-hash | PRD:L205；ADD:L37 | 未验证 | 与发布路径统一实现；中断/旧客户端测试 | 无 |
| RISK-05 | 5 万包单线程或 OOM | PRD:L206；ADD:L35-L36 | 未验证 | 并行、流式实现及性能/内存 profile | 无 |
| RISK-06 | R2/COS、CDN SDK、EdgeOne 是外部依赖且真实验证需资源 | PRD:L208 | 未验证 | 本地 S3、供应商契约、随后真实云最小验证 | 无 |

## 12. PoC 与强制验证面

| ID | PoC/验证 | 来源 | 初始状态 | 计划环境与通过标准 | 当前证据 |
|---|---|---|---|---|---|
| POC-01 | EdgeOne 不同 token 请求归一到同一干净 URL 缓存，并确认 tiered cache 行为 | ADD:L81 | 未验证 | 真实 EdgeOne；可观测 HIT/缓存层级；失败记录并切 Basic Auth | 无 |
| POC-02 | go-crypto InRelease 被真实 `apt update/install` 接受 | ADD:L82；GOAL:L40 | 未验证 | 受支持 apt 版本矩阵，签名与 by-hash 同时开启 | 无 |
| POC-03 | repomd.xml.asc 被真实 `dnf --setopt=repo_gpgcheck=1` 接受 | ADD:L82；GOAL:L41 | 未验证 | EL8/9/10 压缩矩阵与签名验证 | 无 |
| POC-04 | 若未来启用 RPM 重签，go-rpmutils/go-crypto 产物通过 EL9/10 `rpm -K` | ADD:L82-L83 | 未验证 | 条件 PoC；未满足商业启动条件前不得冒充范围内已通过 | 无 |
| POC-05 | 本地 S3 兼容环境验证 checkpoint CAS、差异发布、失败重放和幂等 | GOAL:L44,L51 | 未验证 | 可重复本地服务与故障注入夹具 | 无 |
| POC-06 | Cloudflare R2/Worker/CDN 与腾讯 COS/EdgeOne/CDN 的真实目标验证 | GOAL:L47,L51 | 未验证 | 两个真实目标独立发布、purge、穿 CDN 校验 | 无；凭据/资源条件尚未登记 |
| POC-07 | 约 5 万包并行和流式内存行为 | PRD:L161-L163,L206；GOAL:L48 | 未验证 | 记录硬件、包数、耗时、峰值 RSS、并行度和 API 数 | manifest 子系统部分证据：72,310 包、89.86GB、18 worker、7.91s、峰值 RSS 92.1MB，见 `docs/evidence/2026-07-11-manifest-72k-performance.md`；索引/materialize/publish 未实现，故保持未验证 |

强制测试层级还必须覆盖（GOAL:L37-L49）：单元、属性/边界、集成、故障注入、中断恢复、CLI E2E、asset/CAS/GC、sync/provenance、L1-L4、机密性负例、通道/钉版/快照/EOL/tgz、边缘共享契约、Linux/macOS 构建以及迁移/回滚。实现后应将每项拆成可链接的证据记录。

## 13. 开放问题

| ID | 问题 | 来源 | 初始状态 | 计划决策位置 | 当前证据/阻塞条件 |
|---|---|---|---|---|---|
| OQ-1 | token URL 前缀具体格式 | PRD:L212 | 已冻结 | `docs/adr/0001-core-contracts.md`、`internal/config/` | `/pro/v1/{token}/`；schema v1 拒绝其他值；边缘实现与真实验证仍未完成 |
| OQ-2 | EdgeOne 缓存层级是否满足要求 | PRD:L213 | 未决 | PoC 报告与 access ADR | 无；真实 EdgeOne 验证，失败回退 Basic Auth |
| OQ-3 | 快照 ID 最终格式；候选 `<suite>-YYYYMMDD` | PRD:L214 | 已冻结 | `docs/adr/0001-core-contracts.md`、`config.SnapshotIDFormat` | UTC `<suite>-YYYYMMDD`，同 suite/日不同 commit 冲突；实现待补 |
| OQ-4 | bucket 物化最近 N 个月中的 N | PRD:L215 | 已冻结 | ADR、`state.snapshot_materialization_months` | 默认 6 个自然月、正整数可配；存储测算与保留实现待补 |
| OQ-5 | 从哪个 Pigsty 版本开始冻结 EL8 | PRD:L216 | 未决 | EOL ADR、配置默认值、迁移说明 | 无；不可逆业务决定，实施前需 owner 决策 |

开放问题不得阻断其他可逆、本地可完成工作；先依据协议、存量仓库和可逆默认值推进，只有真实资源、付费或不可逆业务选择才升级询问（GOAL:L31）。

## 14. 已知合同张力（必须以 ADR 消歧）

| ID | 张力 | 初始状态 | 必须保持的不变量 |
|---|---|---|---|
| ADR-T01 | FR-25 整体 publish 失败语义 vs NFR-09 双云独立滞后 | 未实现 | 每目标独立 checkpoint/journal；任一失败 CLI 非零；已成功目标不伪回滚；失败目标可安全重放 |
| ADR-T02 | YUM 两对象“成对原子” vs S3 单对象原子能力 | 未实现 | 客户端任何可观察状态都不得组合不匹配的 repomd.xml 与 asc |
| ADR-T03 | `sow rm` vs stable 包永不消失 | 未实现 | rm 不得破坏 stable/history 引用；GC 仅回收所有 ref 均未引用对象 |
| ADR-T04 | Git 承载正典 vs 零外部运行时依赖 | 未实现 | 不依赖系统 git 可执行文件，同时保留可审计 Git 历史 |
| ADR-T05 | FR-03 差异计算零远端 API vs checkpoint GET/CAS | 未实现 | diff 纯本地；远端调用仅用于漂移/事务控制且有计数证据 |
| ADR-T06 | beta/latest 都是公开视图 vs FR-35 的“OSS=latest”简写 | 未实现 | beta 与 latest 均受不可跳过的 public 闭包门禁 |
| ADR-T07 | 单 Go CLI vs 两家边缘函数运行时 | 未实现 | CLI 保持单 Go 二进制；边缘共享行为契约但不制造通用云抽象 |
| ADR-T08 | FZ-04 称命名空间冻结，但 OQ-1/OQ-3 的具体值未定 | 未实现 | 在依赖实现扩散前冻结字符串格式并建立兼容测试 |

## 15. 更新与最终审计规则

每次更新条目时：

1. 保留来源行号；填写真实实现文件和测试文件。
2. 在证据列写入可复现命令、环境、日期、结果与日志/报告路径。
3. 若只完成 Mock、接口或 happy path，最高只能标为 `实现中`。
4. 真实云未运行时，供应商相关条目必须保持 `未验证`，除非用户书面接受替代证据或豁免。
5. `[ASSUMPTION]` 指标必须记录实测值，不得因测试“通过”而默认满足。
6. 最终独立怀疑式审计必须检查 TODO/空实现/永真校验、秘密泄漏、迁移债、人工 purge、真实 apt/dnf、双云/边缘 PoC、性能与跨平台构建。
7. 只有本矩阵所有范围内要求均有实现位置和可复现证据，且没有未处理阻断项时，Goal 才可完成。
