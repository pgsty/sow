---
title: sow — Pigsty 软件仓库管理 CLI
status: draft
created: 2026-07-11
updated: 2026-07-11
inputs:
  - _bmad-output/brainstorming/brainstorm-sow-repo-cli-2026-07-11/brainstorm-intent.md
  - _bmad-output/planning-artifacts/research/technical-sow-repo-cli-tech-validation-research-2026-07-11.md
---

# sow — Pigsty 软件仓库管理 CLI PRD

## 1. 概述

**sow = 制品仓库的 git**：本地工作树是真相源、manifest 即 refs、bucket 即 remote、通道即分支视图。单一 Go CLI 完成 APT/YUM 仓库原生管理、上游镜像同步、增量上传与 CDN 缓存失效，取代现有 Makefile 体系（4 个 Makefile 约 40 个目标，7 维笛卡尔积手抄展开）。

本 PRD 覆盖**整个交付系统**：sow CLI 本体、仓库布局与 URL 契约、通道与商业视图语义、双云鉴权边缘组件。利害定位：内部专用工具，但承载商业版发布与营收——主干按内部工具篇幅精炼，机密性闭包、发布事务、URL 契约等不可逆决策按发布级严谨度处理。

## 2. 背景与问题

现有 Makefile 体系存在三大结构性缺陷，各自已造成真实事故：

1. **状态失联**：构建态与发布态之间无校验，发布后才发现元数据不匹配（co-yum 错依赖 bug 即笛卡尔积手抄的直接产物）。
2. **流程遗忘**：CDN purge 是人肉可选步骤，漏刷导致用户端报错。
3. **操作繁琐**：加一个包要复制到 stash、开容器，仪式化且易错。

三根支柱分别灭绝之：**manifest 治状态失联、事务治流程遗忘、视图治通道管理**。

本次重构的主要商业动因：Pigsty 商业版（Pro）需要 gated 闭源商业池，Day 1 必做。技术调研（见输入②）已确证全部关键技术假设成立，无阻塞性风险。

## 3. 目标与成功指标

| # | 指标 | 目标值 |
|---|---|---|
| G1 | 发布事故（元数据不匹配 / 漏 purge 类线上事故） | 归零 |
| G2 | 加包操作 | 单命令完成，[ASSUMPTION] < 1 分钟（现状：复制 stash + 开容器） |
| G3 | 日常发布的远端 API 调用量 | O(变更集)，非 O(仓库全量) |
| G4 | 机密性闭包违规（闭源包泄漏进公开索引） | 机器门禁 100% 拦截，违规即构建失败 |
| G5 | 存量 Makefile 体系 | 约 40 个目标全部由 sow 命令替代退役 |
| G6 | M0 纳管后本地↔远端漂移项 | 清零并保持 |

**反指标（不得恶化）**：

- 发布总时长不因事务化显著变差（[ASSUMPTION] 常规增量发布 < 10 分钟）。
- 存储成本不升：Pro/OSS 合一仓库预计省约 60GB，每云一桶。
- OSS 用户现有 URL 契约（latest 通道）不破坏。

## 4. 用户与工作流

- **主操作者**：Pigsty 维护者。[ASSUMPTION] 单操作者、单开发机，无多写者并发需求——发布锁的目标是防中断残留与外部误动，不是防多人协作冲突。
- **OSS 用户**：标准 apt/dnf 客户端，通过公开通道（beta/latest）消费，体验必须与任何标准仓库无差别。
- **Pro 企业客户**：持 token 访问商业元数据视图（stable/快照），核心诉求是钉版（`apt install foo=1.2.3` / `dnf install foo-1.2.3` 全历史可钉）、SLA 与溯源。
- **镜像站运营者**：整树拉取，本地目录扔给 Nginx 即可托管——本地树本身就是仓库最终形态。

**代表工作流**（轻量旅程，内部工具降档）：

- *维护者发新包*：`sow add foo.rpm` 自动识别格式、推断目标仓库/OS/arch、入池建索引 → 包进入 beta 视图 → 验证后 `sow promote beta latest` → `sow publish` 原子完成差异上传、索引翻转、purge、验证。全程无容器、无 stash、无人肉 purge。
- *企业客户钉版*：客户 `.repo`/sources.list 指向含 token 的 stable 通道，`dnf install foo-1.2.3` 安装两年前的历史版本——包永不消失。u20/d11 等 EOL 系统上，客户仍能从冻结归档拉包（"别人下架，我们还在"）。
- *镜像站同步*：rsync/整树拉取本地树根，Nginx 指向即服务，无需任何 sow 运行时。

## 5. 范围

**范围内**：manifest 状态模型与纳管；APT/YUM/asset 三类仓库引擎；包生命周期（add/rm/池/GC）;上游同步与 provenance 台账；通道/视图/快照与离线 tgz 闭环；原子发布事务；四层校验与机密性门禁；Pro/OSS 合一商业访问控制与双云鉴权边缘组件；sow.yaml 配置模型。

**范围外（明确不做）**：

- PostgreSQL 依赖——PG 仅为可选导出目标（对接扩展目录生态），sow 核心不依赖。
- 通用性抽象层——CDN/存储直接用 Cloudflare / 腾讯云具体 SDK，内部工具不过度设计。
- modulemd（EL10 已废、自建仓库只发普通包）、zchunk（非默认必需）、sqlite repodata（createrepo_c 1.0 已默认不产）。
- 多 GPG key 体系——单 key 策略已冻结。
- 造包能力——sow 只管理既有 deb/rpm，不构建包。

**延后（有意识排期，非不做）**：snapshot 固定时刻快照通道（Day 1 后追加，与 stable 同属商业特性）；RPM 包级重签能力（见 FR-17）。

## 6. 功能需求

命令面即产品表面：

| 命令 | 语义 |
|---|---|
| `sow init` | 扫本地树建基线 manifest（M0 零字节纳管） |
| `sow add` / `sow rm` | 单命令入库/减包：自动识别、推断归属、签名建索引 |
| `sow sync` | 上游镜像同步：只加不删喂包池，记录 provenance |
| `sow promote` | 通道晋升（beta→latest 等），纯清单运算 |
| `sow publish` | 原子发布事务：差异上传→索引翻转→purge 最小集→验证 |
| `sow verify` | 独立执行 L1–L4 校验（含机密性闭包） |
| `sow fsck` | 昂贵审计路径：全量 ListObjects 对账、漂移报告 |
| `sow materialize` | 按 manifest ref 物化视图/快照（亦供离线 tgz 打包） |

### 6.1 状态模型与纳管

- **FR-01** 每仓库维护一个当前态 manifest（排序 TSV，一行一文件：path/size/sha256），由 git 仓库承载为正典——git diff 天然即变更记录，全部历史可追溯。
- **FR-02** 派生查询层为 SQLite 只读缓存：可随时从 manifest 重建、gitignore 不入库，支撑依赖闭包等查询。
- **FR-03** 每个发布目标（cf/cos）维护一份"已发布跟踪清单"（类 refs/remotes），允许两云各自滞后；发布差异 = 本地树 vs 跟踪清单，**零远端 API 调用**即可算出精确差异文件集。
- **FR-04** 每个 bucket 内保存一份远端检查点对象（`.sow/manifest.json` + 代际号）：1 次 GET 检测漂移（他人动过 bucket / 上次发布中断），CAS 写入兼做发布锁。
- **FR-05** `sow init` 扫描本地树建立基线 manifest，实现对存量仓库的零字节变更纳管。
- **FR-06** 全系统贯彻两类操作模式：便宜的增量默认路径（stash→commit 式，只检查变化部分）+ 昂贵的显式审计路径（`sow fsck` 全量对账）。

### 6.2 仓库引擎

- **FR-07** APT 引擎自研：Packages/Release 索引装配、InRelease 签名、**by-hash 布局 Day 1 内建**（SHA256 目录、`Acquire-By-Hash: yes`、保留 N 版自动清旧），与对象存储发布路径统一设计。
- **FR-08** YUM 引擎自研：primary/filelists/other.xml 生成 + repomd.xml 汇总；压缩策略按 OS 分派——EL9/EL10 全线 zstd，EL8 冻结定格 gz；repomd.xml 与 repomd.xml.asc 为**成对原子翻转单元**（否则验签竞态）。
- **FR-09** asset 无索引仓库类型：bin 引导脚本 / src 源码 tgz / pkg 工具二进制 / etc / img 统一建模为"只有 manifest + publish 事务、跳过索引生成"的仓库，脚本管理需求零成本并入。
- **FR-10** GPG 签名：单 key 策略；key/passphrase 支持环境变量与 CLI 参数注入；纯 Go OpenPGP 实现，不 fork/exec 外部 gpg；工具在 Linux/macOS 本地原生运行——告别"密钥烤镜像"。

### 6.3 包生命周期

- **FR-11** `sow add`/`sow rm` 单命令完成入库/减包：自动识别 deb/rpm、推断目标仓库/OS/arch、入池、签名、建索引——消灭容器与 stash 仪式。
- **FR-12** 本地存储为 CAS 池（`.pool/`，包实体按哈希只存一份）+ 物化树（bucket 的 1:1 hardlink 镜像，物化近零成本）；`.sow/` 与 `.pool/` 为遮蔽点目录；**本地树本身必须是仓库最终形态，Nginx 指树根即可托管**。
- **FR-13** 池文件引用计数与 GC：自动回收无引用文件，提供孤儿文件审计（规避 reprepro 式手动三步 GC）。

### 6.4 上游同步与供应链

- **FR-14** `sow sync` 自研 Go 同步器（调研确证无现成工具满足需求交集）：**只加不删**的累积式镜像——上游删旧版我们照样保有历史，与 Pro 保全历史需求天然互锁。
- **FR-15** 同步过滤器：作用于包名+架构的 glob/正则黑白名单（pgdg 只同步 Pigsty 用到的子集）；debuginfo 是独立过滤维度（OSS 视图丢弃省体积，Pro 保留）。不实现依赖闭包自动补全——同步名单本身应是自洽闭包。
- **FR-16** provenance 供应链台账，按 RPM/DEB 签名信任链不对称设计双条目 schema：RPM 条目 = 上游 URL + 上游索引 sha256/size + 逐字节保存的原文件（嵌入签名随之保留）；DEB 条目 = 上游 URL + Packages 条目 sha256 + **保存被签名的上游 InRelease/Release 文件本身**（.deb 无嵌入签名）。"我们重建，但保留收据"。
- **FR-17** 包级签名策略**分阶段**：Day 1 镜像 rpm 保留上游嵌入签名、不重签（规避 sha256 摘要坑）；自建包在构建时即用 Pigsty key 签名；全量重签为 Pigsty 单 key 列为商业版延后能力（企业客户单 key 诉求出现时再启动，启动前置条件：go-rpmutils 对 EL9/10 sha256 摘要行为的真机验证）。

### 6.5 通道、视图与快照

- **FR-18** Day 1 三通道：**beta**（开源，自建包先行发布位 + pgdg-testing 镜像）、**latest**（开源精选集）、**stable**（商业，完整历史）。通道即 manifest 视图，发布列车 = 视图代数：入池即进 beta，`sow promote` 为纯清单运算，stable 全量视图自动包含一切转正内容。
- **FR-19** stable 语义（配置与文档必须显式定义）：**包永不消失 + 原生钉版**——`apt install foo=1.2.3` / `dnf install foo-1.2.3` 全历史可钉。非 Debian 式"旧而冻结"；钉版能力是对企业的真实卖点。
- **FR-20** 快照 = manifest 的一个 git ref。APT：单 archive 根 + 共享 pool + 快照即套件（[ASSUMPTION] 快照 ID 格式 `<suite>-YYYYMMDD`，如 `dists/jammy-20260701`），客户端用 suite 名钉版本，每快照仅增一套小体积 dists 元数据——完全标准。YUM：每快照独立 repo 树，本地 hardlink 零成本，bucket 上未变包用 server-side copy 晋升免重传。
- **FR-21** 通道指针（包体永不重复拷贝）：APT 用 dists 别名（小索引 Suite 字段对齐后重签，Debian 官方 stable→trixie 同款）；YUM 用 mirrorlist/metalink 原生间接层（`.repo` 写 `mirrorlist=...stable.txt`，通道翻转 = 改一个小文件 + purge 它）。
- **FR-22** 快照物化策略：bucket 只物化 stable + 最近 N 个月（[ASSUMPTION] N 待定，见 OQ-4），更老快照按需从池 + manifest 重建——历史全保、存储成本封顶。
- **FR-23** `sow materialize` 按 manifest ref 物化任意视图/快照为 hardlink 树；Pro 离线 tgz（pigsty-pkg-*.tgz）= 视图的衍生构建产物：materialize 某 OS 视图 → 打 tar → 进 asset 仓库发布，sow 闭环负责。
- **FR-24** EOL OS 冻结归档（Pro 卖点）：u20/d11/EL8 等停止活跃构建后，历史全在池 + manifest，Pro 继续提供冻结快照仓库。EL8 即按此模式处理：不再活跃构建，新包不进 EL8，repodata 压缩随冻结定格为 gz。

### 6.6 发布事务

- **FR-25** `sow publish` 是原子事务：差异上传 → 索引翻转 → purge 最小集 → 验证，为一个整体动作，任何一环失败整体报错——**不存在"忘了某步"**。
- **FR-26** 内容寻址 + 单点翻转：先上传包体与 hash 命名的元数据，最后原子翻转发布点。翻转集合：APT = `{InRelease}`；YUM = `{repomd.xml, repomd.xml.asc}` 成对。
- **FR-27** purge 最小集：只 purge 翻转点文件与通道指针文件，无需 Purge Everything；即便漏 purge，旧索引引用的旧文件仍在、依然自洽。
- **FR-28** 发布锁与中断恢复：远端检查点 CAS 写入兼做发布锁；中断的发布可安全重放（幂等），下次发布前能检测并报告上次中断残留。

### 6.7 校验体系

- **FR-29** L1 仓库内部闭包校验：索引↔包双向一致 + 签名有效。
- **FR-30** L2 本地↔远端 manifest 对账。
- **FR-31** L3 发布后穿 CDN 验证。
- **FR-32** L4 模拟 apt/dnf 客户端端到端验证。
- **FR-33** **机密性闭包门禁**（L1 门禁项，发布级严谨度）：公开视图（beta/latest）元数据的引用闭包必须 ⊆ public 池，机制上杜绝闭源包泄漏进开源索引——商业风险变成机器门禁，违规即失败，不可跳过。
- **FR-34** `sow verify` 可独立执行 L1–L4 全套或子集；`sow fsck` 执行昂贵审计：对指定目录全量 ListObjects 对账、输出漂移报告（含 bucket 中的遗留垃圾：reprepro 内部目录、死镜像、0 字节 checksums）。

### 6.8 商业访问控制与边缘组件

- **FR-35** Pro/OSS 合一仓库：一个物理仓库，靠元数据控制访问。OSS = latest、无 debuginfo 的"精选集"公开元数据；Pro 靠 token 前缀访问企业元数据——一仓两视图，构造上永远一致（"OSS↔Pro 追加同步/裁剪导出"需求整个蒸发），每云一桶。
- **FR-36** 分池按机密性、不按商业通道：public 池 / gated 池；OSS/Pro 只是元数据命名空间。未来若有闭源 Pro 专属包，必须放真 token 门控前缀，禁止"索引里不写"的隐匿式安全。
- **FR-37** token-in-path 访问方案（调研确证为唯一可行路径方案）：apt/yum 元数据全用相对 href，token 前缀天然全程携带。
- **FR-38** 双云鉴权边缘组件（Cloudflare Worker + EdgeOne 边缘函数）**同构实现、共享测试用例**，统一逻辑：验 token → 剥 token → 干净 URL 子请求（缓存归一化，全客户收敛同一缓存条目，零碎片化）→ 回填 mirrorlist 模板。
- **FR-39** Pro 通道 mirrorlist 由边缘组件动态模板化（读指针对象 + 回填请求 token）；OSS 无 token，纯静态文件。
- **FR-40** 鉴权回退方案：Basic Auth（apt auth.conf / dnf baseurl 凭据，Authorization 头不进缓存键）——边缘函数不可用或超预算时的唯一有效回退；token-in-query 与自定义 header 已确证出局。

### 6.9 配置模型

- **FR-41** `sow.yaml` 声明式矩阵配置，需声明维度：gpg（单 key）/ pools（public/gated）/ repos（apt|yum|asset × OS × arch）/ upstreams（URL、过滤器、provenance）/ views（beta/latest/stable 及过滤规则）/ targets（cf/cos 各自端点、CDN、已发布 ref）。具体 schema 留给架构阶段。
- **FR-42** 命令面 = 动词 × 选择器：取代 Makefile 笛卡尔积手抄展开，任意命令可按 repo/OS/arch/view 维度选择作用范围。

## 7. 非功能需求

- **NFR-01 性能**：索引生成与文件链接按 repo/component/arch 并行，5 万包级仓库发布不得单线程卡死（aptly #421 教训）。
- **NFR-02 内存**：manifest 与索引流式/惰性处理，不整库载入内存（aptly #761 OOM 教训）；排序 TSV 天然支持流式。
- **NFR-03 增量性**：日常操作远端 API 调用 O(变更集)；全量扫描只在显式 `fsck` 发生——远端 API 调用真金白银。
- **NFR-04 可移植性**：单 Go 二进制，Linux/macOS，零外部运行时依赖（无 Python/Perl/gpg/createrepo_c）；唯一外部服务依赖 = S3 API + 两家 CDN SDK。
- **NFR-05 客户端兼容矩阵**：apt ≥ 1.2（by-hash）；老客户端靠原子翻转兜底（by-hash 是兜底不是替代）；EL9/10 zstd、EL8 gz；`dnf module disable postgresql` 类客户端行为写入安装文档而非仓库侧解决。
- **NFR-06 安全**：签名信任链完整（InRelease clearsign / repomd detached sign / 自建包构建时签名）；密钥经 env/CLI 注入、不落镜像不落配置文件明文；token 不得进入公开 CDN 缓存键；三类签名产物各建真机端到端验证用例（apt update / dnf repo_gpgcheck=1 / rpm -K）纳入 CI。
- **NFR-07 成本**：对象存储接受少量重复（主要 noarch 跨架构，R2/COS 无去重语义已确证）；APT 侧靠共享 pool 布局省存储；CDN 缓存零客户碎片化；Cloudflare 侧 Workers Paid（$5/月）+ R2 免出网即可，无需 Enterprise。
- **NFR-08 可审计性**：全部状态变更有 git 历史；镜像包有 provenance 收据；远端漂移可检测可报告。
- **NFR-09 事务可靠性**：发布中断可检测、可恢复、可安全重放；两云发布目标允许各自滞后，互不阻塞。

## 8. 兼容与迁移契约（"趁早定死"冻结清单）

以下决策改起来伤筋动骨，**现在冻结**：

1. 本地根布局：`.sow/` `.pool/` 点目录 + 现有树即 bucket 镜像；**latest 通道保持现有 URL 契约不变**。
2. YUM `Packages/<首字母>/` 拆分（Fedora/EPEL 标准做法、全客户端兼容；跨仓库 `../` 共享池 href 非标准，不上线上）：唯一破坏 hotlink 的变更，实施与 M2 绑定，但决定现在冻结。
3. 通道命名：beta / latest / stable（+ 后续 snapshot）。
4. 快照 ID 格式与 token URL 方案：命名空间现在冻结，具体格式值为架构阶段先决项（OQ-1/OQ-3）。
5. GPG 单 key 策略。
6. YUM 翻转文件对语义（repomd.xml + .asc 成对原子）——调研新增。
7. provenance 双条目 schema（RPM/DEB 不对称）——调研新增。
8. 边缘鉴权组件双云同构接口——调研新增。

**废止决策记录**：本设计有意识推翻此前 Pro 设计文档的"双云双 bucket 独立 pro 桶"方案（合一仓库使其失效）；回写该文档为遗留待办。

**迁移总方针**：先一步到位设计出好方案，再慢慢迁移过去；新方案尽量兼容现有方案，但若不兼容且方案足够好，不介意做大迁移。优先级：①存量仓库尽快纳入 sow 管理；②结构性调整趁现在还有机会赶紧做；③其余走一步看一步。

## 9. 里程碑

[ASSUMPTION] M0 与优先级次序为定案；M1–M4 分组为起草推断，待确认。

- **M0 纳管（零字节变更，立即启动，不依赖任何自研组件）**：`sow init` 建基线 manifest → 首次 `fsck` 对账 cf/cos → 漂移报告（顺带清点 bucket 遗留垃圾）。
- **M1 索引引擎**：YUM repodata 生成先行（无现成库、规格已查清）→ APT Packages/Release 装配（有 pault.ag 库借力）→ 签名编排 + 三类真机验证用例进 CI。
- **M2 结构性调整**：YUM 首字母拆分、by-hash 上线、快照与通道指针、Pro/OSS 合一布局落位。
- **M3 同步器**：`sow sync` + provenance 台账；过渡期现有 Makefile 同步路径继续服役。
- **M4 商业版**：token + 双云边缘组件（EdgeOne 缓存层级 PoC 前置）+ 机密性门禁强制化 + stable 通道与 EOL 冻结归档上线。

## 10. 风险与依赖

| 风险 | 等级 | 缓解 |
|---|---|---|
| go-crypto 产签的客户端兼容性（间接证据链） | 中 | 三类签名产物真机验证用例纳入 CI（NFR-06），上线前必过 |
| EdgeOne 边缘函数缓存层级未确证（per-node vs 共享） | 中 | 商业版上线前 PoC 实测（M4 前置）；不达标则回退 Basic Auth |
| rpm 重签 sha256 摘要坑 | 高→已规避 | Day 1 不重签（FR-17）；未来启用前须真机验证 |
| 对象存储 by-hash 半残（aptly S3 前车之鉴） | 低 | by-hash 与发布路径统一设计，不做文件系统特性移植 |
| 大仓库发布性能（单线程/OOM，aptly 教训） | 低 | NFR-01/02 并行化 + 流式处理为硬性要求 |

**外部依赖**：CF R2 / 腾讯 COS（S3 API）、Cloudflare / 腾讯云 CDN SDK、EdgeOne 边缘函数（商业版）。

## 11. 开放问题

- **OQ-1** token URL 前缀具体格式——趁早定死项，架构阶段先决，owner: Vonng。
- **OQ-2** EdgeOne 缓存层级 PoC——M4 前置，不达标回退 Basic Auth，owner: Vonng。
- **OQ-3** 快照 ID 格式最终值确认（[ASSUMPTION] `<suite>-YYYYMMDD`）——架构阶段与 OQ-1 一并冻结。
- **OQ-4** 快照物化窗口 N（bucket 保留最近几个月）——影响存储成本上限，可延至 M2 实施前定。
- **OQ-5** EL8 冻结时点（自哪个 Pigsty 版本起 EL8 不再活跃构建）——业务决策，M2 前定。
