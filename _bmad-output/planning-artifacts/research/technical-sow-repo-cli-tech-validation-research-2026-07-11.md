---
stepsCompleted: [1, 2, 3, 4, 5, 6]
inputDocuments:
  - '{project-root}/_bmad-output/brainstorming/brainstorm-sow-repo-cli-2026-07-11/brainstorm-intent.md'
workflowType: 'research'
lastStep: 1
research_type: 'technical'
research_topic: 'sow 仓库 CLI 关键技术验证：aptly/reprepro 布局差异、上游同步开源方案、Go APT/YUM 解析库生态、CDN 自定义 cache key 能力'
research_goals: '验证 brainstorm 意图文档第 4 节全部待验证项，为 PRD 与架构阶段提供技术选型依据：①自研 APT 引擎的服务端布局与快照模型参考；②sow sync 包装现成工具 vs 自研的边界；③Go 生态 APT/YUM 库"用现成 vs 自研"边界（含 go-rpmutils 签名过 dnf 校验、modulemd、EL10 zstd repodata）；④token-in-path 的 CDN 缓存碎片化风险（Cloudflare cache key + 腾讯 EdgeOne）'
user_name: 'Vonng'
date: '2026-07-11'
web_research_enabled: true
source_verification: true
---

# Research Report: technical

**Date:** 2026-07-11
**Author:** Vonng
**Research Type:** technical

---

## Research Overview

本研究验证 sow（Pigsty 软件仓库管理 CLI）brainstorm 意图文档第 4 节的全部四个待验证项：①aptly vs reprepro 布局差异；②上游同步开源方案盘点；③Go 生态 APT/YUM 解析库盘点；④CDN 自定义 cache key 能力。研究由四个并行调研代理执行，全部结论基于当前联网检索（官方文档优先、多源交叉验证），关键断言附来源 URL 与置信度标注。

**总结论：意图文档的全部关键技术假设成立，无一被推翻。** 四项定案：APT 引擎自研（快照模型抄 aptly、池与引用计数抄 reprepro、by-hash 与原子发布是差异化空间）；`sow sync` 自研 Go 同步器（无现成工具满足三硬需求）；解析层用现成 Go 库、索引生成与签名编排自研；token-in-path 可行（靠鉴权边缘函数干净子请求归一化缓存，无需 CF Enterprise）。完整执行摘要见文末 Research Synthesis 章节。

**目录**：Technology Stack Analysis（调研项③：Go 库生态与"用现成 vs 自研"边界）→ Integration Patterns Analysis（调研项④：CDN 缓存归一化、客户端协议、签名信任链）→ Architectural Patterns and Design（调研项①：aptly/reprepro 对比与借鉴/规避清单）→ Implementation Approaches（调研项②：同步方案定案与实施路线）→ Research Synthesis（执行摘要、断言验证结果、新增发现、遗留 PoC 清单）

---

<!-- Content will be appended sequentially through research workflow steps -->

## Technical Research Scope Confirmation

**Research Topic:** sow 仓库 CLI 关键技术验证：aptly/reprepro 布局差异、上游同步开源方案、Go APT/YUM 解析库生态、CDN 自定义 cache key 能力

**Research Goals:** 验证 brainstorm 意图文档第 4 节全部待验证项，为 PRD 与架构阶段提供技术选型依据。

**四个调研项及核心问题：**

1. **aptly vs reprepro 布局差异** — pool 布局、dists 生成、快照模型的结构性差异；by-hash 支持确证；sow 自研 APT 引擎的借鉴与规避清单
2. **上游同步开源方案盘点** — reposync/aptly mirror/apt-mirror/Pulp 等方案对"只加不删、同步过滤器、provenance 记录"三个硬需求的覆盖；包装 vs 自研结论
3. **Go 生态 APT/YUM 解析库盘点** — APT/YUM 侧现成库能力边界；go-rpmutils 签名能否过 dnf 校验；modulemd 必要性；EL10 zstd repodata 兼容性；createrepo_c 输出规格
4. **CDN 自定义 cache key 能力** — Cloudflare Cache Rules 与腾讯 EdgeOne 能否将 token 段从缓存键剥离；token-in-path 方案可行性结论

**Research Methodology:**

- 当前联网检索 + 多源交叉验证，官方文档优先
- 关键技术断言标注来源与置信度
- 结论直接面向 PRD/架构阶段的选型决策

**Scope Confirmed:** 2026-07-11

## Technology Stack Analysis

> 本节回答调研项③（Go 生态 APT/YUM 解析库盘点）并给出整体技术景观。核心结论：**Go 生态在"解析/读取"层有成熟可用库；"索引生成"层没有生产级现成库，必须自研；签名层用 ProtonMail/go-crypto 自己编排是正解且有生产先例。**

### 语言与运行时定调

Go 单二进制方案成立且是最优路径：解析层有成熟库兜底，无需引入 Python（reposync/createrepo）、Perl（debmirror）运行时依赖。现有工具中 aptly 本身是 Go/MIT，可作源码级参考；reprepro 是 C/GPL-2，只能参考设计。签名统一走纯 Go OpenPGP 实现，避免 fork/exec 外部 gpg（aptly 因 shell 调 gpg 踩过 TTY/passphrase/gpg2 一系列坑）。

### APT 侧 Go 库

**`pault.ag/go/debian`（推荐，解析层全覆盖）** — Debian 官方 archive 收录的库（`golang-pault-go-debian-dev`），BSD-3/MIT 双许可，活跃维护（`deb` 子包 2025-07 仍有发布）：

- `deb`：读 `.deb`（自带 ar 容器解析，无需 blakesmith/ar），支持 tar.gz/xz/bz2。**只读，不能造包**（sow 不需要造包）
- `control`：解析 control / Packages(BinaryIndex) / Release / .dsc / .changes；写侧有通用 `Marshal()` 与流式 `Encoder`
- `version`：Debian 版本比较（等价 `dpkg --compare-versions`），省掉 epoch:upstream-revision 自研坑
- `dependency`：依赖表达式解析

**能力边界（划定自研范围）**：该库**没有** Packages 索引装配、Release 生成、checksum 计算、by-hash/压缩变体逻辑——索引"成品"必须自研（可借 `control.Encoder` 输出段落，装配/压缩/校验和/Release 汇总自写）。

**aptly 不建议 import**：它是 CLI 应用而非库（`main`/`internal` 结构、耦合自有存储模型），但其 `pgp/internal.go`（纯 Go OpenPGP 签名 provider）是"如何用 go-crypto 签 Release/InRelease"的现成参考代码——读源码借鉴，不 import。

_Source: https://pkg.go.dev/pault.ag/go/debian/deb 、https://pkg.go.dev/pault.ag/go/debian/control 、https://www.aptly.info/doc/feature/pgp-providers/_ （置信度：高）

### YUM 侧 Go 库

**`github.com/cavaliergopher/rpm`（推荐用于读取/建索引）** — v1.3.0（2025-04），BSD-3，活跃。字段最全：NEVRA、Provides/Requires/Conflicts/Obsoletes/Recommends 等全部依赖关系、`Files()`（含 digest/flags/owner）、`GPGSignature()`、包级 `GPGCheck()/MD5Check()` 验签。**只读——但这正是生成 primary/filelists/other.xml 所需的全部字段来源。**

**`github.com/sassoftware/go-rpmutils`** — v0.4.0（2024-05），Apache-2.0。读取能力与 cavaliergopher 重叠但 API 不如后者直观；其独特价值是 `SignRpmStream()` 能签 rpm（生产先例：sassoftware 自家签名服务器 relic）。**重要坑**：其签名逻辑历史上默认假设 header/payload 为 MD5+SHA1 摘要，对现代 EL9/EL10 的 SHA256 摘要 rpm 直接签会报 "md5 digest mismatch"（relic issue #35）——重签现代 rpm 前必须确认版本已处理 sha256 摘要，或干脆不重签。

**旁证（nfpm 路线）**：Go 生态最主流打包器 nfpm 不用 go-rpmutils 签名，而是用 `google/rpmpack` + go-crypto 直签 rpm 摘要——证明"go-crypto 直接产 rpm 签名"这条路通且被海量生产验证（但那是造新包时签，非重签已有包）。

_Source: https://pkg.go.dev/github.com/cavaliergopher/rpm 、https://github.com/sassoftware/relic/issues/35 、https://pkg.go.dev/github.com/goreleaser/nfpm/v2/internal/sign_ （置信度：高）

### repodata 生成：无生产级现成库，确证自研

- `stianwa/createrepo`：唯一"纯 Go createrepo"，但 README 明写 "do not use for production"，GPL-3.0（许可污染风险）、不支持 zstd、无签名——**不可用**
- `radepal/go-yum`：只读写 repomd.xml + 生成老式 sqlite primary_db，路线已过时——不适用
- **自研成本可控**：cavaliergopher/rpm 提供全部字段，primary/filelists/other.xml schema 公开稳定（openSUSE Standards Rpm Metadata），按模板输出 + zstd 压缩 + sha256 命名 + repomd.xml 即可

_Source: https://github.com/stianwa/createrepo 、https://en.opensuse.org/openSUSE:Standards_Rpm_Metadata_ （置信度：高）

### repodata 格式关键规格（自研依据）

- **createrepo_c 1.0（EL9/EL10 现役版本）默认行为**：压缩已改 zstd（`primary.xml.zst` 等）；**默认不再生成 sqlite db**（sow 可直接不做）；zchunk（.zck）非默认必需（一期不做）
- **dnf 对 zstd 的支持自 Fedora 30 / RHEL 8.4 起**（经 libsolv）。压缩策略：**EL9/EL10 全线 zstd；EL8 用 gz**（8.0–8.3 不支持 zstd）；EL7 已 EOL 可忽略
- **repomd.xml 签名**：detached `repomd.xml.asc`，客户端 `repo_gpgcheck=1` 时先验签再读元数据。已知竞态坑：客户端可能拿到旧 repomd.xml + 新 .asc 导致验签失败——**发布时 repomd.xml 与 .asc 必须原子更新**（与 sow 发布事务设计天然契合）

_Source: https://fedoraproject.org/wiki/Changes/createrepo_c_1.0.0 、https://github.com/rpm-software-management/libdnf/issues/1592_ （置信度：高）

### modulemd 必要性：确证不需要

- **EL10 modularity 已死**：RHEL 10 不再分发 modular 内容，DNF5 移除 `dnf module` 子命令；EL9 中 modularity 已废弃/边缘化
- **EL8 的 `dnf module disable postgresql` 是客户端行为**：针对的是 OS 自带 AppStream 里的 postgresql module，PGDG 自己的 EL8 仓库并不发 modulemd——**sow 自建仓库只发普通包，完全不需要 modules.yaml**，只需在安装文档提醒客户端 disable

_Source: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/10.1_release_notes/deprecated-features 、https://bugzilla.redhat.com/show_bug.cgi?id=1718201_ （置信度：高）

### GPG/OpenPGP 底座

**`github.com/ProtonMail/go-crypto`** — v1.4.1（2026-03），BSD-3，是已废弃的 `golang.org/x/crypto/openpgp` 的事实标准替代。能力覆盖 detached sign（repomd.xml.asc、Release.gpg）、clearsign（InRelease）、RSA 与 Ed25519。三条生产链路旁证兼容性：nfpm 用它签 deb/rpm、go-rpmutils 用它签 rpm、aptly internal provider 用它签 Release/InRelease。

**注意**：产签方向缺乏"APT/dnf 已接受"的直接权威文档，属间接证据链——每类产物（InRelease / repomd.xml.asc / rpm 重签）上线前必须用真实 `apt update`、`dnf --setopt=repo_gpgcheck=1`、`rpm -K` 端到端验证一次。（置信度：成熟度高 / 具体产物兼容性中，需自测）

_Source: https://github.com/ProtonMail/go-crypto 、https://pkg.go.dev/github.com/ProtonMail/go-crypto/openpgp/clearsign_

### "用现成 vs 自研"边界总表

| 能力点 | 决策 | 库 / 方案 | 风险 |
|---|---|---|---|
| .deb 解析 | 用现成 | `pault.ag/go/debian/deb` | 无 |
| control/Packages/Release 解析 | 用现成 | `pault.ag/go/debian/control` | 无 |
| Debian 版本比较 | 用现成 | `pault.ag/go/debian/version` | 无 |
| **Packages 索引装配 + Release 生成** | **自研** | 借 `control.Encoder`，装配/压缩/checksum/by-hash 自写 | 低（格式稳定） |
| InRelease/Release.gpg 签名 | 自研（用库） | go-crypto clearsign+detached，参考 aptly `pgp/internal.go` | 中（需真机 apt 验证） |
| .rpm 头解析 | 用现成 | `cavaliergopher/rpm` | 无 |
| .rpm 重签 | 视需要 | 优先不重签；必要时 go-rpmutils/go-crypto | 高（sha256 摘要坑） |
| **repodata 生成** | **自研** | cavaliergopher 取字段 + 自写 XML + zstd | 低（schema 公开） |
| repodata 压缩策略 | 自研决策 | EL9/10 zstd；EL8 gz | 低 |
| repomd.xml.asc 签名 | 自研（用库） | go-crypto detached | 中（需原子发布） |
| sqlite primary_db | 不做 | createrepo_c 1.0 已默认不产 | 无 |
| modulemd | 不做 | EL10 已废，自建普通包仓库不需要 | 无 |
| zchunk | 一期不做 | 非默认必需 | 无 |
| GPG 底座 | 用现成 | `ProtonMail/go-crypto`，避免 fork/exec gpg | 无 |

### 现有工具平台景观（概览）

| 工具 | 语言/License | 定位 | 对 sow 的角色 |
|---|---|---|---|
| aptly | Go / MIT | APT 仓库管理，快照一等公民 | 快照模型与签名代码的源码级参考；不 import |
| reprepro | C / GPL-2 | APT 仓库管理，引用计数共享池 | 设计参考（池+引用计数）；无 by-hash 无快照 |
| createrepo_c | C / GPL | YUM repodata 生成 | 格式规格参照物；sow 自研替代 |
| dnf reposync | Python | YUM 镜像同步 | 语义参考（默认只加不删）；不依赖 |
| Pulp | Python 服务端 | 全功能仓库平台 | additive sync 语义参考；对单机 CLI 过重 |

（各工具深入分析见后续"架构模式"与"实现研究"章节）

## Integration Patterns Analysis

> 本节回答调研项④（CDN 自定义 cache key）并覆盖 sow 的全部系统集成面：CDN 边缘、apt/dnf 客户端协议、签名信任链、对象存储。

### CDN 边缘集成：token-in-path 缓存归一化（调研项④定案）

**一句话结论：token-in-path 可行且是唯一正确选择；缓存归一化不靠"自定义 cache key 剥 path"（两家 CDN 都不支持），而靠"鉴权边缘函数用干净 URL 发子请求"这一标准模式；Cloudflare 侧不需要 Enterprise。**

**Cloudflare 侧事实：**

- Cache Rules 的 Custom Cache Key 只能作用于 query string / header / cookie / host，**没有任何改写或忽略 URL path 段的选项**；且 header/cookie/host 维度均为 Enterprise 专属。默认缓存键 = host + path + query，token 段无法通过配置剥离
- Workers `fetch(req, {cf: {cacheKey}})` 显式自定义缓存键是 **Enterprise-only**——但根本不需要它
- **标准解法（官方确认的行为）**：Worker 默认按"子请求 URL"而非"入站 URL"计算缓存键。鉴权 Worker 校验 token 后 `fetch()` 到不含 token 的干净 R2 路径，所有客户收敛到同一缓存条目，天然零碎片化；走常规 CDN 缓存（tiered cache 可用、可正常 purge），**Workers Paid $5/月 + R2 免出网即可**
- Workers Cache API（`caches.default`）虽全套餐可用，但是 per-colo 的、不走 tiered cache、无法标准 purge——**不如干净子请求方案，不采用**

_Source: https://developers.cloudflare.com/cache/how-to/cache-rules/settings/ 、https://developers.cloudflare.com/workers/examples/cache-using-fetch/ 、https://developers.cloudflare.com/workers/reference/how-the-cache-works/_ （置信度：高）

**腾讯云 EdgeOne 侧事实：**

- 自定义 Cache Key 仅支持查询字符串 / HTTP 头 / Cookie 三个维度，同样**不能忽略或改写 path 段**
- **已证实的陷阱**：回源 URL 重写只改回源 URL，官方文档明确"该功能不影响节点缓存"——单用回源重写把 `/token/pkg` 重写为 `/pkg`，缓存键仍按含 token 的原始 URL 计算，**碎片化照旧**
- **对称实现路径**：EdgeOne 边缘函数（全套餐可用，含免费额度）提供 Fetch / Cache API / Web Crypto，可实现 token 校验 + 干净 URL 归一化
- **遗留 PoC 项（置信度：中）**：文档未明确边缘函数的 `caches.default` 是 per-node 还是共享，也未明确子请求 fetch 是否写入 EdgeOne 常规分层缓存——**上线前需实测**：不同 token 的请求在同一节点是否命中同一缓存条目、是否享受中间源
- 腾讯云传统 CDN 缓存键同样只能处理 query 参数，且边缘函数能力弱于 EdgeOne——**不是有效回退**

_Source: https://cloud.tencent.com/document/product/1552/95264 、https://cloud.tencent.com/document/product/1552/71009 、https://edgeone.ai/developer/examples/hub-usingthecacheapi_ （置信度：高，PoC 项除外）

### apt/dnf 客户端协议互操作（鉴权方案兜底对比）

| 方案 | apt | dnf/yum | CDN 缓存行为 | 结论 |
|---|---|---|---|---|
| **token-in-path** | ✅ 前缀天然携带 | ✅ 同 | 边缘函数归一化后零碎片 | **主方案** |
| token-in-query | ❌ **根本不可行**：apt 把 `/dists/...` 追加在 URI 之后，query 被塞进路径中间，URL 结构破坏 | ❌ 同理 | — | 出局 |
| 自定义 header | ✅ `Acquire::http::Header` | ❌ **无原生每仓库自定义头** | — | 不对称，出局 |
| **Basic Auth** | ✅ `/etc/apt/auth.conf(.d)`（netrc 格式） | ✅ `baseurl=https://user:pass@host/` | Authorization 头默认不进缓存键，**天然去重** | **唯一有效回退** |
| 接受碎片化 | — | — | 同一包 × 每客户 × 每 PoP 各存一份 | Pigsty 多客户共享同批包场景代价放大 N 倍，不接受 |

token-in-query 的不可行性反过来证明了 token-in-path 的正确性：token 作为前缀，后续路径干净追加。

_Source: https://manpages.debian.org/unstable/apt/sources.list.5.en.html 、https://manpages.debian.org/testing/apt/apt_auth.conf.5.en.html_ （置信度：高；header/Basic Auth 细节中高）

### 签名信任链互操作（provenance 表结构依据）

**RPM 与 DEB 的签名信任链结构性不对称**——直接决定 provenance 账本的字段设计：

- **RPM**：GPG 签名嵌在包头（RPM header）内，**签名随文件走**。逐字节保存 `.rpm` 原文件 = 原始签名天然保留。provenance 条目：`上游 URL + primary.xml 中的 sha256/size + 原文件本身`（可另存上游 `repomd.xml.asc` 作元数据级证据）
- **DEB**：`.deb` 包体**根本没有签名**。信任链是 `InRelease/Release.gpg`（签名根）→ `Packages` 索引 sha256 → `.deb` sha256。要保留"原始签名证据"，**必须保存那份被签名的上游 InRelease/Release 文件 + 对应 Packages 条目**——没有别的东西可留
- 这个不对称也解释了为什么没有任何现成同步工具能产出完整 provenance 账本

**sow 产出侧的签名互操作**（承接 Step 2 结论）：InRelease 用 go-crypto clearsign、repomd.xml.asc 用 detached sign；repomd.xml 与 .asc 的原子更新是已知竞态坑（客户端拿到旧 xml + 新 asc 即验签失败），必须纳入发布事务的翻转集合——即 sow 的"单点翻转"集合实际为 `{InRelease}`（APT）与 `{repomd.xml, repomd.xml.asc}`（YUM，两文件需同时原子翻转）。

_Source: https://www.debian.org/doc/manuals/securing-debian-manual/deb-pack-sign.en.html 、https://blog.packagecloud.io/how-to-gpg-sign-and-verify-deb-packages-and-apt-repositories/ 、https://github.com/openresty/openresty/issues/1112_ （置信度：高）

### by-hash 获取协议（Hash Sum Mismatch 消除）

APT `Acquire-By-Hash`（apt ≥ 1.2.0）：索引文件以不可变 hash 名存放于 `dists/<suite>/<component>/binary-<arch>/by-hash/SHA256/<hash>`，Release 标 `Acquire-By-Hash: yes`。解决的竞态：apt 先取 Release 再取 Packages，两次之间服务端更新则校验和不匹配。**注意 by-hash 是兜底不是替代**——即便有 by-hash，InRelease 翻转仍须原子（覆盖不支持 by-hash 的老客户端）；aptly 在 S3 后端的 by-hash 曾失效（issue #692），教训是 by-hash 必须与对象存储发布路径统一设计而非文件系统特性的移植。

_Source: https://bugs.debian.org/820660 、https://github.com/aptly-dev/aptly/issues/692_ （置信度：高）

### 对象存储与 CDN purge 集成

- **存储接口**：CF R2 与腾讯 COS 均为标准 S3 兼容接口，单 SDK 覆盖（意图文档既有决议，本次调研无反例）
- **CDN purge**：Cloudflare 与腾讯各用各的 SDK（意图文档既有决议）；purge 最小集 = 翻转点文件（InRelease / repomd.xml + repomd.xml.asc / mirrorlist 指针文件）
- **Pro mirrorlist 动态化**：Pro 通道的 mirrorlist 返回的绝对 URL 需含客户 token → 由鉴权 Worker/边缘函数动态模板化（读指针对象 + 回填请求 token）；OSS 无 token 纯静态——与本节"鉴权边缘函数"是同一个组件，架构上合并为一处

### 集成模式结论

1. **双云鉴权组件对称**：Cloudflare 鉴权 Worker + EdgeOne 边缘函数，同一逻辑（验 token → 剥 token → 干净 URL 子请求 → 回填 mirrorlist 模板），建议同构实现共享测试用例
2. **回退排序**：边缘函数不可用/超预算 → Basic Auth（两端原生 + Authorization 不进缓存键）；query-token 与自定义 header 均已出局
3. **上线前 PoC 清单**：①EdgeOne 边缘函数缓存层级实测；②go-crypto 三类签名产物的真机端到端验证（apt update / dnf repo_gpgcheck / rpm -K）

## Architectural Patterns and Design

> 本节回答调研项①（aptly vs reprepro 布局差异），产出 sow 自研引擎的"借鉴清单 + 规避清单"。
>
> **战略结论：sow = aptly 的快照模型与内容寻址 + reprepro 的共享池/引用计数/可读布局 + 两者都没做好的"并发安全原子发布 + 全后端一致 by-hash"。前两块是抄作业，最后一块是差异化。**

### 服务端布局架构对比

**aptly：两层结构（内部内容寻址池 + 对外发布池）**

三段式根目录（`rootDir`）：
- `db/` — 元数据库，默认 goleveldb（嵌入式单进程），1.5+ 可选 etcd 后端
- `pool/` — 内部包池，**按校验和寻址**（1.1.0 起 SHA256 派生多级前缀路径），对人不可读，是"存储层"不直接对外
- `public/` — 对外发布目录，标准 Debian archive 布局；发布时从内部池**链接**过去（默认 hardlink，可选 symlink/copy）

**reprepro：单层共享池 + 引用计数**

单 `basedir` 下 `conf/ db/ dists/ pool/`：
- `pool/` — 全仓库单一共享池，按 `pool/<component>/<源包名首字母>/<源包名>/` 组织，**人类可读、直接对外服务**
- `db/` — Berkeley DB：`checksums.db`（全池校验和）、`packages.db`、`references.db`（**引用计数**）、`contents.cache.db`。手册强调"这是永久数据非缓存"
- 引用计数是核心机制：`dumpreferences`/`dumpunreferenced` 审计、`deleteunreferenced` 清理孤儿文件

**对 sow 的映射**：sow 的 `.pool/`（CAS 池）+ 物化树（hardlink 镜像）设计正好综合两家——内部寻址按 hash（aptly 式），对外 pool 用人类可读布局（reprepro 式），两者兼得。

_Source: https://www.aptly.info/doc/configuration/ 、https://www.aptly.info/doc/feature/filesystem/ 、https://manpages.debian.org/unstable/reprepro/reprepro.1.en.html_ （置信度：高）

### 快照模型对比（确证：aptly 独有）

**aptly——快照是一等公民**：快照 = 不可变的包引用列表，可源自 mirror/local repo/其他快照；支持**快照代数**：`filter`（按查询产生新快照）、`merge`（多快照合并）、`pull`（带依赖拉取）、`diff`；快照可作为 suite 发布，`publish switch` 原子切换实现升级/回滚。

**reprepro——没有真正的快照（确证）**：只有 `gensnapshot`，将某 dist 的静态拷贝导出到 `dists/<codename>/snapshots/<dir>/`，是"冻结的 dists 导出"而非可运算的一等对象。已知硬伤：无自动 GC——被快照引用的文件必须手动 `rm` 目录 + `unreferencesnapshot` + `deleteunreferenced` 三步走。

**对 sow 的映射**：意图文档"快照即 manifest 的 git ref、视图运算即清单运算"的设计与 aptly 快照代数同构且更彻底（manifest diff/merge 天然免费）；`sow promote` 对应 `publish switch` 的原子切换语义。

_Source: https://www.aptly.info/doc/overview/ 、https://www.aptly.info/doc/aptly/snapshot/merge/_ （置信度：高）

### by-hash 支持对比（关键验证点，双确证）

- **aptly 支持**：`-acquire-by-hash` 由 PR #664 合入（1.2.0 目标版本）；实现细节：by-hash 目录用 symlink（为 S3/Swift 抽象出接口，对象存储退化为 copy）、只保留两版索引自动删旧。**已知坑：S3 后端上 by-hash 曾失效（issue #692）**
- **reprepro 不支持（确证到 5.4.x）**：Debian bug #820660 自 2016 年开放至今；2021 年有 PoC（Salsa MR）但从未合入；2025-07 的第三方权威旁证明言 "it never landed in reprepro"

**对 sow 的映射**：意图文档"APT 用 by-hash 布局（reprepro 不支持，Go 原生可以）"的断言**成立**。设计要点：by-hash 从第一天内建（SHA256/SHA1/MD5Sum 三目录、Release 标 `Acquire-By-Hash: yes`、保留 N 版自动清旧），且必须与对象存储发布路径统一设计，避免重蹈 aptly S3 半残 by-hash 的覆辙。

_Source: https://github.com/aptly-dev/aptly/pull/551 、https://github.com/aptly-dev/aptly/issues/692 、https://bugs.debian.org/820660 、https://arnaudr.io/2025/07/17/acquire-by-hash-for-apt-packages-repositories-and-the-lack-of-it-in-kali-linux/_ （置信度：高）

### 池共享与去重模式对比

- **reprepro**："发布层即共享池"——单一全局池跨所有 distribution/component 共享，同一文件被多 dist 引用只存一份，引用计数管生命周期。天然去重、语义干净、可审计
- **aptly**：两级去重——内部池按内容寻址（导入多 repo 内部只存一份）+ 发布层每个 prefix 独立 `pool/` 用 hardlink 链回（靠 inode 共享）；**跨文件系统/对象存储/symlink 模式则去重退化为副本**

**对 sow 的映射**：本地侧走 reprepro 语义（共享池 + 引用计数 + `dumpunreferenced` 式审计工具），物化用 aptly 式 hardlink；远端对象存储无去重（Step 2 前会话已确证 R2/COS 无内容去重），靠 APT 共享 pool 布局省存储、YUM 接受重复。

_Source: https://manpages.debian.org/unstable/reprepro/reprepro.1.en.html 、https://github.com/aptly-dev/aptly/issues/132_ （置信度：高）

### 已知坑清单（性能与并发架构教训）

**aptly：**
- 发布慢：~50k 包时索引生成 + 链接**单线程**、磁盘 IO 受限（#421）
- 内存爆：`db cleanup` 多快照场景 >8GB（#761）、大 mirror 发布 OOM（#338）
- `publish switch` 极慢（aptly-discuss 报告）
- **LevelDB 单写者、无多进程并发**——跨进程需外部锁，这正是后来加 etcd 后端的动机
- 对象存储弱：大仓库 S3 发布问题（#297）、by-hash on S3 失效（#692）

**reprepro：**
- 无 by-hash → 在线更新时 Hash Sum Mismatch 竞态（整个 by-hash 需求的由来）
- 无真快照 + 手动 GC
- Berkeley DB 单进程锁全局串行；上游 2019 年停滞后才缓慢复活（已被 salvage，5.4.0 改过 DB 布局）

_Source: https://github.com/aptly-dev/aptly/issues/421 、/issues/761 、/issues/338 、/issues/297 、https://groups.google.com/g/aptly-discuss/c/5z4IDxFELTI_ （置信度：高）

### sow 自研引擎：借鉴清单

1. **快照作为一等不可变对象 + 快照代数**（filter/merge/pull）——抄 aptly；sow 的 manifest ref 模型天然更强
2. **内容寻址内部池（全 SHA256）+ 发布层 hardlink 复用**——抄 aptly，cheap 去重 + 原子物化
3. **共享池 + 引用计数做跨 dist/component 去重与 GC**——抄 reprepro，语义清晰可审计
4. **对外 pool 人类可读布局**（`pool/<comp>/<prefix>/<src>/`）——抄 reprepro，内部寻址可 hash，两者兼得
5. **by-hash 从第一天内建**，与对象存储发布路径统一设计
6. **复用 aptly `deb`/`pgp` 包**作为库或源码级参考（MIT 友好）
7. **"DB 即真相、索引可从 DB 重建"的纪律**——抄 reprepro（sow 中 manifest 即真相，SQLite 是可重建缓存，与此同构）

### sow 自研引擎：规避清单

1. **别把单进程嵌入式 KV 当唯一并发方案**——aptly 事后补 etcd、reprepro 全局锁都是教训；sow 靠内容寻址 FS 布局 + 单点原子翻转天然规避大部分并发问题，但发布锁（远端 CAS 检查点）仍需设计
2. **别让索引生成 + 链接单线程**——按 repo/component/arch 并行，避免 5 万包发布卡死
3. **别整库载入内存**——流式/惰性遍历（aptly #761 教训），manifest 排序 TSV 天然支持流式处理
4. **别在对象存储上做半残 by-hash**——FS 与对象存储统一走"先写新索引与 by-hash、最后原子翻转 InRelease"的发布事务
5. **别学 reprepro 的手动快照 GC**——引用计数自动回收
6. **发布必须原子**——即便有 by-hash，翻转点文件切换也要原子（覆盖老客户端），YUM 侧 repomd.xml + .asc 成对翻转（见集成模式章节）

## Implementation Approaches and Technology Adoption

> 本节回答调研项②（上游同步开源方案盘点），定案 `sow sync` 的实现路线，并给出整体实施建议。
>
> **结论：自研 Go 核心同步器，复用解析库，不包装整装工具。**（置信度：中高）

### 上游同步候选方案逐项分析

**dnf reposync（YUM 侧标准工具）**
- 只加不删 ✅ 默认满足（`--delete` 是显式开关）
- 过滤器 △ 无 CLI 标志，靠 `.repo` 配置的 `includepkgs=/excludepkgs=`；`--newest-only` 有坑：只下最新包但 repodata 仍列旧包，需 createrepo_c --update 修复
- provenance ✗ `--gpgcheck` 只校验不记录；账本需自建
- 嵌入 Go 难度：高——Python/dnf 插件，只能 shell out，要求宿主装 dnf + createrepo_c，**仅 RPM 系可跑**

_Source: https://dnf-plugins-core.readthedocs.io/en/latest/reposync.html_ （置信度：高）

**aptly mirror（APT 侧）**
- 过滤器 ✅ 同类最强：`-filter` 完整 package query 语言 + `-filter-with-deps` 依赖闭包
- 只加不删 ⚠️ **最大的坑**：裸 `mirror update` 是"镜像当前上游状态"，上游删包本地跟着删；累积必须换 local-repo 导入模式或 snapshot merge `-no-remove`
- provenance △ 有 checksum 库但不导出含上游 URL 的 per-package 账本
- 仅 APT；Go 写的但是单体应用，只能 CLI/API 调用

_Source: https://www.aptly.info/doc/aptly/mirror/create/ 、https://groups.google.com/g/aptly-discuss/c/r4Vz2mwzEEM_ （置信度：高）

**debmirror / apt-mirror**
- debmirror：Perl，Debian 仍在维护；过滤靠正则（--include/--exclude），默认 cleanup 会删文件需关闭；无 provenance
- apt-mirror：原版已弃维护（有 Python 社区 fork apt-mirror2），过滤弱——出局

_Source: https://manpages.debian.org/unstable/debmirror/debmirror.1.en.html_ （置信度：高）

**Pulp（pulp_rpm / pulp_deb）**
- 只加不删 ✅ 语义最干净：`sync_policy=additive`（默认）
- 过滤器 ✗ **致命短板**：pulp_rpm 无按包名的 sync 白名单（feature request 长期未实现）；pulp_deb 只能按 dist/component/arch 过滤
- 架构过重：Django + PostgreSQL + Redis + worker 的服务端，对单机 Go CLI 是数量级的过度设计

_Source: https://pulpproject.org/pulp_rpm/docs/user/tutorials/create_sync_publish/ 、https://pulp.plan.io/issues/206_ （置信度：高）

**其他**：Nexus/Artifactory proxy 是按需缓存非主动镜像（内容留存取决于缓存淘汰，与"只加不删"目标不合）；Docker CE 仓库就是标准 apt/yum 仓库，用统一同步逻辑直接覆盖，无需特殊处理；**Go 生态没有现成的仓库同步器整装工具**。

### 能力对照表

| 方案 | 只加不删 | 包名过滤 | provenance | APT | YUM | 嵌入 Go CLI | 维护状态 |
|---|---|---|---|---|---|---|---|
| dnf reposync | ✅ 默认 | △ .repo 配置 | ✗ | ✗ | ✅ | ✗ shell out，仅 RPM 系 | 活跃 |
| aptly mirror | ⚠️ 须 local-repo 模式 | ✅ 最强 | △ | ✅ | ✗ | △ CLI/API | 活跃 |
| debmirror | △ 须关 cleanup | ✅ 正则 | ✗ | ✅ | ✗ | ✗ Perl | 维护中 |
| apt-mirror | ~ | ✗ | ✗ | ✅ | ✗ | ✗ | 弃维护 |
| Pulp | ✅ additive | ✗ **无包名过滤** | ✅ 但重 | ✅ | ✅ | ✗✗ 服务端 | 活跃 |
| **自研 Go** | ✅ 自定义 | ✅ 自定义 | ✅ **唯一能做全** | ✅ | ✅ | 原生 | — |

### 自研定案的三条理由

1. **三个硬需求的交集，没有任何单一工具满足**。包装路线 = aptly（还得改用 local-repo 累积模式）+ reposync（过滤塞 .repo）+ 自写 provenance 层 + 累积逻辑，引入 Go/Python 双运行时、两套各有坑的语义，而最有价值的部分（provenance 账本 + 统一累积池）**无论如何都得自己写**——包装没省掉核心工作，只多了协调成本
2. **同步核心其实很小**：取元数据（repomd.xml→primary / InRelease→Packages）→ 解析 → 与本地池 diff → 并行 GET → sha256 校验 → GPG 验签 → 写 provenance。胶水部分：gzip/xz/zstd 解压、流式 XML、断点续传、重试限速、镜像站 302
3. **解析层有成熟 Go 库兜底**（见技术栈章节），不是从零写解析器

**过滤器复杂度按需砍**：需求是"pgdg 保子集 + 丢 debuginfo"，一个作用在 Name+Arch 上的 glob/正则 allow-deny 表就够，**不必实现 aptly 的依赖闭包机器**——Pigsty 的同步名单本身就应是自洽闭包。若未来需要"按名单自动补依赖闭包"，aptly `-filter-with-deps` 的实现是参考标准。

### provenance 账本实现要点（基于 RPM/DEB 签名不对称）

- **RPM 条目**：`上游 URL + primary.xml 的 sha256/size + 逐字节保存的 .rpm 原文件`（嵌入签名随之保留），可另存上游 `repomd.xml.asc`
- **DEB 条目**：`上游 URL + Packages 条目 sha256 + 保存被签名的上游 InRelease/Release 文件`（.deb 无嵌入签名，签名根只在 Release 上）

### 实施路线建议（承接意图文档 M0 方针）

1. **M0（纳管，零字节变更）**：`sow init` 扫本地树建基线 manifest → 首次 `fsck` 对账 cf/cos——**不依赖任何本节自研组件**，可立即启动
2. **索引引擎自研顺序**：YUM repodata 生成先行（无现成库、格式规格已查清、字段来源已定 cavaliergopher/rpm）→ APT Packages/Release 装配（有 pault.ag 库借力）→ 签名编排（go-crypto，配真机验证用例）
3. **sync 自研在索引引擎之后**：sync 产出只是"往池里加文件 + 写 provenance"，与索引生成解耦；过渡期现有 Makefile 的同步路径可继续服役
4. **风险缓解**：三个签名产物（InRelease / repomd.xml.asc / rpm 重签）各建一个真机端到端验证用例（apt update / dnf repo_gpgcheck / rpm -K），纳入 CI；EdgeOne 缓存层级 PoC 在商业版上线前完成

### 成本与资源

- 全自研范围收敛为：**索引生成（两格式）+ 签名编排 + 同步器 + manifest/事务层**，解析层全部站在现成库上
- 运行时零外部依赖（无 Python/Perl/gpg/createrepo_c），单 Go 二进制跨 Linux/macOS——与"内部专用工具、Nginx 可直接托管"的硬约束一致
- 唯一接受的外部服务依赖：对象存储 S3 API + 两家 CDN SDK（意图文档既有决议）

## Research Synthesis

### Executive Summary

本研究对 sow 的四个关键技术分叉点做了联网验证，**意图文档的全部关键技术假设成立，无一被推翻**，且调研过程中产出了七项超出原调研范围的新增发现（详见下文）。四项定案共同指向同一个结论：sow 的"Go 单二进制 + manifest 真相源 + 发布事务"架构在技术上完全站得住——解析层有成熟库兜底、自研范围收敛且格式规格全部查清、商业版 URL 方案的缓存难题有标准解法且成本低廉（CF 侧 $5/月，无需 Enterprise）。

更重要的战略判断：现有工具（aptly/reprepro）在**并发安全原子发布与全后端一致 by-hash**上都有硬伤，这恰好是 sow 发布事务设计的核心价值——sow 不是重复造轮子，而是在两家都没做好的维度上建立差异化。

### 四项调研定案速查表

| # | 调研项 | 定案 | 关键依据 | 置信度 |
|---|---|---|---|---|
| ① | aptly vs reprepro | **自研引擎：快照模型抄 aptly，共享池/引用计数抄 reprepro，by-hash 与原子发布自建差异化** | reprepro 无 by-hash（bug #820660 九年未合入）、无真快照；aptly Go/MIT 可源码参考但单进程 LevelDB/单线程发布是教训 | 高 |
| ② | 上游同步方案 | **自研 Go 同步器，不包装整装工具** | 无任何工具同时满足"只加不删+包名过滤+provenance"；同步核心小，provenance 反正得自己写 | 中高 |
| ③ | Go 库生态 | **解析层用现成（pault.ag/go/debian + cavaliergopher/rpm + go-crypto），索引生成与签名编排自研** | 无生产级 Go createrepo；repodata/Packages 格式规格公开稳定；nfpm/aptly/relic 三条生产链路旁证 go-crypto 可行 | 高 |
| ④ | CDN cache key | **token-in-path 可行：鉴权边缘函数用干净 URL 子请求归一化缓存；无需 CF Enterprise** | 两家 CDN 的 cache key 配置均不能剥 path 段，但 Worker 子请求 URL 即缓存键是官方确认行为；Basic Auth 是唯一有效回退 | 高（EdgeOne 缓存层级除外，中） |

### 意图文档断言验证结果

**确证成立的断言：**
- "APT 用 by-hash 布局（reprepro 不支持，Go 原生可以）" ✅ 双确证
- "aptly 快照模型可采纳（快照即套件）" ✅ 且 sow 的 manifest ref 模型天然更强
- "YUM 没有现成 Go 库就自研" ✅ 确证无生产级 Go createrepo，自研成本可控
- "存储统一 S3 兼容接口、CDN 各用各的 SDK" ✅ 无反例
- "token-in-path + 鉴权 Worker" ✅ 且被证明是唯一可行的 URL 方案（query 对 apt 根本不可行）

**需要补充/细化的点（非推翻）：**
- "purge 最小集 = 翻转点文件"：YUM 侧翻转点实为**两个文件成对**（repomd.xml + repomd.xml.asc 须同时原子翻转，否则验签竞态）
- "供应链台账记录原始签名"：RPM/DEB 结构性不对称——RPM 保原文件即保签名，**DEB 必须保存上游 InRelease 文件本身**（.deb 无嵌入签名）
- "Pro mirrorlist 由 Worker 动态模板化"：确认与 CDN 缓存归一化是**同一个边缘组件**，架构上合并

### 新增发现（调研前未知，需纳入架构设计）

1. **RPM/DEB 签名信任链不对称** → 直接决定 provenance 表结构（两种条目类型）
2. **YUM 翻转集合是文件对** → 发布事务的原子翻转单元需支持多文件
3. **token-in-query 对 apt 根本不可行** → 反向锁死 token-in-path 为唯一路径方案，Basic Auth 为唯一回退
4. **EdgeOne 回源 URL 重写不影响缓存键**（官方文档确认）→ 单用重写规则碎片化照旧，必须走边缘函数
5. **go-rpmutils 的 sha256 摘要坑**（relic #35）→ 若重签现代 EL9/10 rpm 必须先验证版本行为
6. **aptly 三大架构教训**（单进程 KV、单线程发布、S3 半残 by-hash）→ 写入规避清单
7. **EL8 zstd 分界在 8.4** → repodata 压缩策略需按 OS 版本分派（EL9/10 zstd，EL8 gz）

### 遗留验证项（上线前 PoC 清单）

1. **EdgeOne 边缘函数缓存层级实测**（置信度中）：确认子请求是否写入共享/分层缓存而非仅 per-node——决定 EdgeOne 侧命中率能否对齐 Cloudflare
2. **go-crypto 三类签名产物真机验证**：InRelease（apt update）、repomd.xml.asc（dnf repo_gpgcheck=1）、rpm 重签（rpm -K）——建议做成 CI 常驻用例
3. **EL8 最低支持 minor 版本决策**（业务决策，非技术验证）：决定 EL8 repodata 用 gz 还是 zstd

### 对 PRD/架构阶段的输入建议

- **"趁早定死"清单可新增三项**：YUM 翻转文件对语义、provenance 双条目 schema、边缘鉴权组件的双云同构接口
- **命令面无需变更**：调研结果未动摇意图文档的 8 命令草图；`sow verify` 的 L1–L4 校验获得了具体的技术落点（by-hash 一致性、repomd 文件对、机密性闭包）
- **实施顺序确认**：M0 纳管不依赖任何自研组件可立即启动；索引引擎 YUM 先行（规格已查清）、APT 借力现成库随后；sync 与索引解耦最后做
- **风险登记簿**：go-crypto 兼容性（中风险，真机用例缓解）、EdgeOne 缓存层级（中风险，PoC 缓解）、rpm 重签摘要坑（高风险，优先"不重签"规避）

### 研究方法与来源核查

- **方法**：四个并行研究代理分项调研，全部要求 WebSearch/WebFetch 联网核实、禁止仅凭训练数据作答；官方文档（aptly.info、manpages.debian.org、developers.cloudflare.com、cloud.tencent.com、fedoraproject.org、docs.redhat.com）优先于博客与论坛
- **来源标注**：每个技术断言附来源 URL；无法多源确证的结论显式标注置信度（高/中/低）
- **局限性**：go-crypto 产签的客户端兼容性为间接证据链（生产项目旁证而非权威文档）；EdgeOne 边缘函数缓存层级文档未明确；两者均已列入 PoC 清单而非当作已验证事实

### Conclusion

四个技术分叉点全部收束，无阻塞性风险。sow 可以带着"技术假设已验证"的状态进入 PRD 与架构阶段；本报告的速查表、借鉴/规避清单、PoC 清单可直接作为架构文档的引用材料。

---

**Technical Research Completion Date:** 2026-07-11
**Source Verification:** 全部技术断言附当前来源；间接证据与未决项显式标注置信度
**Overall Confidence Level:** 高（两项中置信度事项已列入 PoC 清单）
