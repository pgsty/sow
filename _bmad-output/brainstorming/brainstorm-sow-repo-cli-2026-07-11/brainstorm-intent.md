---
type: brainstorm-intent
topic: sow —— Go 编写的 Pigsty 软件仓库管理 CLI
date: 2026-07-11
source: .memlog.md（同目录）
consumers: bmad-prd / bmad-architecture / bmad-spec
---

# sow 意图文档

## 1. 定位与约束

**一句话**：sow = 制品仓库的 git —— 本地工作树是真相源、manifest 即 refs、bucket 即 remote、通道即分支视图；单一 Go CLI 完成 APT/YUM 仓库原生管理、上游镜像同步、增量上传与 CDN 缓存失效，取代现有 Makefile 体系（4 个 Makefile 约 40 个目标 = 7 维笛卡尔积手抄展开，co-yum 错依赖 bug 即手抄产物）。

**动因（三大历史翻车）**：①构建态与发布态无校验，发布后才发现元数据不匹配；②CDN purge 是人肉可选步骤，漏刷致用户端报错；③加包要复制到 stash、开容器，繁琐无聊。三根支柱分别灭绝之：manifest 治状态失联、事务治流程遗忘、视图治通道管理。

**硬约束**：
- 本地目录本身必须是仓库最终形态——可整体扔给 Nginx 直接托管（拉镜像站点刚需）；本地树与对象存储树持续一致（允许少量遮蔽文件）。
- 内部专用工具，不过度设计：CDN/存储直接用具体厂商 SDK，不追求强通用性。
- 不能靠反复扫远端对账（耗时 + API 调用真金白银）。
- 本次重构主要动因是做商业版：gated 闭源商业池 Day 1 必做。

## 2. 核心决议清单

### 状态模型
- **本地真相源**：本地开发机目录是真正真相源（上游）；对象存储是权威交付副本、但只是本地的滞后快照。
- **manifest git 仓库（正典）**：每仓库一个当前态 manifest（排序 TSV，一行一文件：path/size/sha256），git diff 天然 = 变更记录，全部历史可追溯。派生层 = SQLite 只读缓存（可随时重建、gitignore，供依赖闭包等查询）；PG 仅为可选导出目标（对接扩展目录生态），sow 核心不依赖 PG。
- **远端跟踪清单**：每个发布目标（cf/cos）一个"已发布 ref"（类 refs/remotes），两云允许各自滞后；下次 diff = 本地树 vs 跟踪清单，零远端 API 调用；rclone `--files-from` 精确传差异文件。
- **远端检查点对象**：bucket 内存一份 `.sow/manifest.json` + 代际号，1 次 GET 检测漂移（他人动过 bucket / 上次发布中断），CAS 写入兼做发布锁。
- **两类操作**（便宜默认路径 + 昂贵审计路径，全系统反复复现的模式）：①增量更新 = stash→commit 式，只检查变化部分；②大检查 = `sow fsck` 对指定目录做 rsync 式全量 ListObjects 深审计。

### 发布事务
- **发布是事务**：上传 + 索引 + purge + 验证是一个原子动作，任何一环失败整体报错，不存在"忘了某步"。
- **内容寻址 + 单点翻转**：APT 用 by-hash 布局（reprepro 不支持，Go 原生可以），YUM 天然 hash 命名 repodata；发布 = 先传包体与 hash 元数据，最后翻转 InRelease / repomd.xml 单文件。
- **purge 最小集**：只需 purge 翻转点文件（InRelease/repomd.xml），无需 Purge Everything；即便漏 purge，旧索引引用的旧文件仍在、依然自洽。
- **校验四层**：L1 仓库内部闭包（索引↔包双向 + 签名）；L2 本地↔远端 manifest 对账；L3 发布后穿 CDN 验证；L4 模拟 apt/dnf 客户端端到端。
- **机密性闭包校验（L1 门禁项）**：公开视图（beta/latest）元数据的引用闭包必须 ⊆ public 池，机制上杜绝闭源包泄漏进开源索引——商业风险变成机器门禁。

### 引擎选型
- **Go 原生自研优先**：reprepro 非必须，条件放宽为"客户端接口不变即可"，服务端布局随便折腾；Go 生态有现成解析库就用（APT 有现成的用现成的，YUM 没有就自研）。
- **aptly 作参考**：快照模型采纳 aptly snapshot 同款（快照即套件）；aptly 与 reprepro 布局差异列专项调研。
- **GPG 方案**：假设本地已有 GPG key（可由环境变量提供），passphrase 支持 env/CLI 参数；工具本地原生跑（Linux/macOS），可用系统 gpg 或 Go 库；告别"密钥烤镜像"。单 key 策略（见"趁早定死"清单）。

### 上游同步
- **全面 rebuild + Pigsty 自签，不采用 verbatim**："一个仓库走天下"供应链责任自负；且 PGDG 上游只留最新版，verbatim 无法满足 Pro 保全历史的需求。reposync 替代方案先调研开源现成实现。
- **累积式镜像（rebuild 解锁）**：上游 sync 只加不删（喂进包池）；上游删旧版我们照样保有历史——rebuild 与保历史需求天然互锁。
- **供应链台账（provenance）**：manifest 记录每个镜像包的上游 URL + 原始 sha256 + 原始签名——"我们重签，但保留收据"，回应企业客户溯源诉求。
- **同步过滤器**：包名黑白名单（pgdg 只同步 Pigsty 用到的子集）；debuginfo 是视图过滤的独立维度（OSS 丢弃省体积，Pro 保留）。

### 存储与 CDN
- **存储统一 S3 兼容接口**：CF R2 与腾讯 COS 都是标准 S3，单 SDK 覆盖。
- **CDN 直接用两家 SDK**：Cloudflare + 腾讯云，缓存失效 API 各用各的，不做抽象层。
- **无去重事实（已确证）**：R2/COS/两家 CDN 均无内容去重/硬链接语义，每 key 独立计费，CDN 缓存按 URL 为键；S3 server-side CopyObject 省的是公网流量不是存储；远端省存储只能靠布局（APT 共享 pool）或接受成本。对象存储接受少量重复（主要是 noarch 跨架构）。

### 仓库布局
- **本地布局**：`.sow/`（manifest+缓存）与 `.pool/`（CAS 池，包实体按哈希只存一份）为遮蔽点目录；物化树 = bucket 的 1:1 hardlink 镜像（物化近零成本），Nginx 直接指树根即可托管。"仓库"退化为 manifest 视图，视图运算即清单运算。
- **YUM 首字母拆分**：`Packages/<首字母>/` 布局（primary.xml 的 location href 可含子目录），Fedora/EPEL 标准做法、全客户端兼容；跨仓库共享池（`../` href）非标准有兼容风险，不上线上。
- **APT 快照**：单 archive 根 + 共享 pool + 快照即套件（如 `dists/jammy-20260701`），客户端用 suite 名钉版本；pool 只存一份，每快照仅增一套小体积 dists 元数据——完全标准。
- **YUM 快照**：每快照独立 repo 树，本地 hardlink 零成本；bucket 上未变包用 server-side copy 晋升免重传。
- **通道指针（定案，包体永不重复拷贝）**：APT 用 dists 别名（一套几 MB 小索引，Suite 字段对齐后重签——Debian 官方 dists/stable→trixie 同款）；YUM 用 mirrorlist/metalink 原生间接层（.repo 写 `mirrorlist=...stable.txt`，该文件一行指向当前快照 baseurl；通道翻转 = 改一个小文件 + purge 它）。
- **快照物化策略**：快照本质 = manifest 的一个 git ref；bucket 只物化 stable + 最近 N 个月，更老快照按需从池 + manifest 重建——历史全保、存储成本封顶。
- **资产集合统一建模**：bin 引导脚本 / src 源码 tgz / pkg 工具二进制 / etc / img = "无索引 manifest 仓库"（只有 manifest + publish 事务，跳过索引生成），脚本管理需求零成本并入。pro 离线 tgz（pigsty-pkg-*.tgz）= 视图的衍生构建产物：materialize 某 OS 视图→打 tar→进 asset 仓库发布，sow 闭环负责。

### 商业模型
- **Pro/OSS 合一仓库**：一个物理仓库，靠元数据控制访问；OSS = latest、无 debuginfo 的"精选集"公开元数据，Pro 靠 token 前缀访问企业元数据——一仓两视图。合一使"OSS↔Pro 追加同步/裁剪导出"需求整个蒸发（同池两视图，构造上永远一致），存储省约 60GB，fsck 对账目标减半，每云一桶。**注意：此决议有意识地推翻此前 Pro 设计文档的"双云双 bucket 独立 pro 桶"方案，需回写该文档。**
- **分池按机密性、不按商业通道**：public 池 / gated 池；OSS/Pro 只是元数据命名空间。Pro 卖的是策展与服务（快照/钉版/SLA）而非比特机密——元数据即产品；未来若有闭源 Pro 专属包，必须放真 token 门控前缀，不能靠"索引里不写"的隐匿式安全。
- **通道**：Day 1 三通道——beta（开源）/ latest（开源）/ stable（完整历史，商业）；snapshot（固定时刻快照）后续追加，与 stable 同属商业特性。beta/testing 是矩阵自然槽位（pgdg-testing 上游已镜像，自建包也走 beta 先行发布）。
- **stable 语义（配置与文档必须定义清楚）**：包永不消失 + 可原生钉版（`apt install foo=1.2.3` / `dnf install foo-1.2.3` 全历史可钉），非 Debian 式"旧而冻结"——钉版能力是对企业的真实卖点。
- **发布列车 = 视图代数**：自建包入池即进 beta 视图；`sow promote beta→latest` 是纯清单运算；stable = 全量视图，自动包含一切转正内容。
- **token-in-path + 鉴权 Worker**：apt/yum 元数据全用相对 href，token 前缀天然全程携带；鉴权 Worker 把 token 路径统一映射到 public/gated 两类池。Pro 的 mirrorlist 与静态文件冲突（返回的绝对 URL 需含客户 token）→ 由鉴权 Worker 动态模板化 mirrorlist（读指针对象 + 回填请求中的 token）；OSS 无 token，纯静态。
- **EOL OS 冻结归档 = Pro 卖点**：u20/d11 停止活跃构建后，历史全在池 + manifest，Pro 继续提供冻结快照仓库——"别人下架，我们还在"。

## 3. sow.yaml 配置模型雏形与命令面草图

**设计原则**：declare 矩阵 + 命令 = 动词 × 选择器，取代 Makefile 的笛卡尔积手抄展开。

配置模型需声明的维度（源自会话素材，具体 schema 留给架构阶段）：

```yaml
# sow.yaml 雏形（示意）
gpg:            # 单 key；key/passphrase 可从 env/CLI 读取
pools:          # public / gated（按机密性分池）
repos:          # 每仓库：类型 apt|yum|asset(无索引)、OS、arch
upstreams:      # 上游源：URL、同步过滤器（包名黑白名单、debuginfo）、provenance 记录
views:          # 通道视图：beta / latest / stable（+后续 snapshot）及其过滤规则
targets:        # 发布目标：cf / cos（各自的 S3 端点、CDN SDK、已发布 ref）
```

命令面草图（动词均出自会话决议）：

| 命令 | 语义 |
|---|---|
| `sow init` | 扫本地树建基线 manifest（M0 零字节变更纳管） |
| `sow add` / `sow rm` | 单命令入库/减包：自动识别 deb/rpm、推断目标仓库/OS/arch，Go 原生签名建索引——消灭容器与 stash 仪式 |
| `sow sync` | 上游镜像同步：只加不删喂包池，记录 provenance |
| `sow promote` | 通道晋升（beta→latest 等），纯清单运算 |
| `sow publish` | 原子发布事务：差异上传→翻转 InRelease/repomd.xml→purge 最小集→四层验证 |
| `sow verify` | 独立跑 L1–L4 校验（含机密性闭包） |
| `sow fsck` | 昂贵审计路径：全量 ListObjects 对账、漂移报告 |
| `sow materialize` | 按 manifest ref 物化视图/快照（hardlink 树；亦供离线 tgz 打包） |

## 4. 调研任务清单（待验证项）

1. aptly 与 reprepro 的布局差异——专项调研。
2. 上游同步（reposync 替代）的开源现成方案盘点。
3. Go 生态 APT/YUM 解析库盘点（决定"用现成"与"自研"的边界）。
4. token-in-path 导致 CDN 缓存按客户碎片化：查 Cloudflare 自定义 cache key 与腾讯 EdgeOne 的对应能力。
5. 回写 Pro 设计文档：正式废止"双云双 bucket 独立 pro 桶"决策（非调研，为遗留待办）。

## 5. 施工方针

**总方针**：先一步到位设计出好方案，再慢慢迁移过去；新方案尽量兼容现有方案，但若不兼容且方案足够好，不介意做大迁移。

**优先级**：①存量仓库尽快纳入 sow 管理；②结构性调整趁现在还有机会赶紧做；③其余走一步看一步。

**M0（纳入管理，零字节变更）**：`sow init` 建基线 manifest（扫本地树）→ 首次 `fsck` 对账 cf/cos → 漂移报告（顺带揪出 bucket 里的 reprepro 内部目录、死镜像、0 字节 checksums）。

**"趁早定死"清单（改起来伤筋动骨，现在冻结决定）**：
- 本地根布局：`.sow/` `.pool/` 点目录 + 现有树即 bucket 镜像；latest 保持现有 URL 契约。
- YUM `Packages/<首字母>/` 拆分：唯一破坏 hotlink 的变更，实施与 M2 绑定，但决定现在冻结。
- 通道命名、快照 ID 格式、token URL 方案。
- GPG 单 key 策略。
