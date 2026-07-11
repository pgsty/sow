# sow PRD Addendum

> 本文档承载不属于 PRD 主干、但下游文档（架构/解决方案设计）需要的深度内容。主要来源：技术验证调研报告（`technical-sow-repo-cli-tech-validation-research-2026-07-11.md`，下称"调研报告"）与意图文档。此处为定案摘录 + 指针；完整论证与来源 URL 见调研报告原文。

## 1. 技术选型定案（供架构阶段直接引用）

### "用现成 vs 自研"边界

| 能力点 | 决策 | 库 / 方案 |
|---|---|---|
| .deb / control / Packages / Release 解析、Debian 版本比较 | 用现成 | `pault.ag/go/debian`（deb/control/version/dependency 子包） |
| .rpm 头解析（全字段：NEVRA、依赖、Files、签名） | 用现成 | `github.com/cavaliergopher/rpm` |
| GPG/OpenPGP 底座（clearsign / detached sign） | 用现成 | `github.com/ProtonMail/go-crypto`（不 fork gpg） |
| Packages 索引装配 + Release 生成 + by-hash | **自研** | 借 `control.Encoder` 输出段落，装配/压缩/checksum 自写 |
| YUM repodata 生成（primary/filelists/other + repomd） | **自研** | cavaliergopher 取字段 + 模板 XML + zstd/gz + sha256 命名 |
| 上游同步器 | **自研** | 取元数据→解析→池 diff→并行 GET→校验→验签→写 provenance |
| rpm 重签 | 延后 | go-rpmutils（sha256 摘要坑，启用前真机验证）或 go-crypto 直签 |
| sqlite primary_db / modulemd / zchunk | 不做 | createrepo_c 1.0 已默认不产 sqlite；EL10 modularity 已死 |

- aptly（Go/MIT）**不 import**，作源码级参考：其 `pgp/internal.go` 是 go-crypto 签 Release/InRelease 的现成参考代码。
- 同步方案对照结论：reposync/aptly mirror/debmirror/apt-mirror/Pulp 无一同时满足"只加不删 + 包名过滤 + provenance"，且 provenance 与累积池无论如何都得自己写——包装没省核心工作，只多协调成本。

### 借鉴清单（自研引擎设计输入）

1. 快照作为一等不可变对象 + 快照代数（filter/merge/pull）——抄 aptly；manifest ref 模型天然更强。
2. 内容寻址内部池（SHA256）+ 发布层 hardlink 复用——抄 aptly。
3. 共享池 + 引用计数做去重与 GC——抄 reprepro。
4. 对外 pool 人类可读布局 `pool/<comp>/<prefix>/<src>/`——抄 reprepro。
5. by-hash Day 1 内建，与对象存储发布路径统一设计。
6. "manifest 即真相、SQLite 可重建缓存"纪律——与 reprepro"DB 即真相、索引可重建"同构。

### 规避清单（前车之鉴）

1. 单进程嵌入式 KV 当唯一并发方案（aptly LevelDB 事后补 etcd、reprepro 全局锁）——sow 靠内容寻址布局 + 单点原子翻转规避，发布锁走远端 CAS 检查点。
2. 索引生成 + 链接单线程（aptly #421，5 万包卡死）。
3. 整库载入内存（aptly #761，>8GB OOM）。
4. 对象存储上做半残 by-hash（aptly #692）。
5. 手动快照 GC（reprepro 三步走）。
6. 非原子翻转（即便有 by-hash，仍须覆盖老客户端；YUM 侧文件对成对翻转）。

## 2. CDN 缓存归一化机制（FR-38 的技术依据)

- 两家 CDN 的自定义 cache key 配置均**不能剥离 path 段**（Cloudflare Cache Rules 仅 query/header/cookie/host 且多为 Enterprise；EdgeOne 仅 query/header/cookie）。
- 标准解法：鉴权边缘函数校验 token 后，用**不含 token 的干净 URL 发子请求**——Worker 按子请求 URL 计缓存键（官方确认行为），全客户收敛同一缓存条目。Cloudflare 侧 Workers Paid $5/月即可，无需 Enterprise。
- **已证实陷阱**：EdgeOne 回源 URL 重写不影响节点缓存键——单用重写规则，碎片化照旧，必须走边缘函数。
- Workers Cache API（`caches.default`）per-colo、不走 tiered cache、无法标准 purge——不采用。
- token-in-query 对 apt 根本不可行（apt 把 `/dists/...` 追加在 URI 后，query 被塞进路径中间）——反向锁死 token-in-path 为唯一路径方案。

## 3. provenance 双条目 schema（FR-16 细化）

| 格式 | 条目字段 | 签名证据 |
|---|---|---|
| RPM | 上游 URL + primary.xml 的 sha256/size | 逐字节保存 .rpm 原文件（嵌入签名随之保留）；可另存上游 repomd.xml.asc |
| DEB | 上游 URL + Packages 条目 sha256 | **保存被签名的上游 InRelease/Release 文件本身**（.deb 无嵌入签名，签名根只在 Release） |

此不对称是"没有任何现成同步工具能产出完整 provenance 账本"的结构性原因。

## 4. sow.yaml 配置雏形（schema 留给架构阶段）

```yaml
gpg:            # 单 key；key/passphrase 可从 env/CLI 读取
pools:          # public / gated（按机密性分池）
repos:          # 每仓库：类型 apt|yum|asset(无索引)、OS、arch
upstreams:      # 上游源：URL、同步过滤器（包名黑白名单、debuginfo）、provenance 记录
views:          # 通道视图：beta / latest / stable（+后续 snapshot）及其过滤规则
targets:        # 发布目标：cf / cos（各自 S3 端点、CDN SDK、已发布 ref）
```

## 5. 废止决策：Pro 双云双 bucket 独立桶方案

此前 Pro 设计文档采用"双云各设独立 pro 桶"。本轮设计以 **Pro/OSS 合一仓库**（一物理仓库、元数据双视图、按机密性分池）有意识推翻之。理由：

- "OSS↔Pro 追加同步/裁剪导出"需求整个蒸发——同池两视图，构造上永远一致。
- 存储省约 60GB；fsck 对账目标减半；每云一桶。
- Pro 卖的是策展与服务（快照/钉版/SLA/EOL 归档）而非比特机密——元数据即产品。

**遗留待办**：回写原 Pro 设计文档，正式废止旧方案。

## 6. 上线前 PoC / 验证清单

1. EdgeOne 边缘函数缓存层级实测：不同 token 请求在同一节点是否命中同一缓存条目、是否享受分层缓存（M4 前置；不达标回退 Basic Auth）。
2. go-crypto 三类签名产物真机端到端验证：InRelease（`apt update`）、repomd.xml.asc（`dnf --setopt=repo_gpgcheck=1`）、rpm 重签（`rpm -K`，仅在启用重签时）——做成 CI 常驻用例。
3. （若启用重签）go-rpmutils 对 EL9/10 sha256 摘要 rpm 的行为验证（relic issue #35 前车之鉴）。
