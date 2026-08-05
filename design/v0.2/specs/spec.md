---
id: SPEC-sow-v2-p1-p3
companions:
  - acceptance-matrix.md
  - brownfield.md
  - ../../planning-artifacts/prds/prd-sow-2026-07-31/api-contract.md
sources:
  - ../../planning-artifacts/prds/prd-sow-2026-07-31/prd.md
  - ../../planning-artifacts/prds/prd-sow-2026-07-31/addendum.md
---

> **Canonical contract.** This SPEC and the files in `companions:` are the complete, preservation-validated contract for what to build, test, and validate. Source documents listed in frontmatter are for traceability only.

# SOW V2 P1–P3 完整实现与验收

## Why

P0 已证明 SOW 能把平铺 RPM/DEB 目录制成客户端可用的简单仓库，但长期维护仍缺少包成员变更、策略、恢复、查询、完整校验和可交付增量。目标是把当前 P1 控制面扩展成纯本地、单机单写、可恢复且可直接复制的完整 Managed APT/YUM 仓库管理器，并以真实客户端和当前 34,184 包规模证明结果，而不是以命令存在或文件生成作为完成标准。

## Capabilities

- **CAP-1**
  - **intent:** 运维者可以发现并校验 Workspace，并原子管理固定路径的 Repository 与 Dist 生命周期。
  - **success:** 封闭 CLI、严格配置、选择规则、锁、可恢复 CRUD、protected/路径门禁及可消费空 view 全部通过契约测试与真实客户端验证。

- **CAP-2**
  - **intent:** SOW 自动规范化受支持的 RPM/DEB 架构并把 native 与 neutral 包投影到正确 view。
  - **success:** x86_64/amd64、aarch64/arm64、noarch/all 在 C2 view-local hardlink 布局下通过 DNF/APT 与 reposync；未知或未许可架构在任何状态写入前被拒绝。

- **CAP-3**
  - **intent:** 运维者可以把本地 RPM/DEB 加入一个或多个 Dist，并由不可变内容、逻辑坐标与 Membership 三层身份消除歧义。
  - **success:** 输入文件不变，同内容幂等、跨 Dist 单对象复用、同坐标异内容硬冲突，混合批次返回确定性的部分成功结果且不发布无主对象。

- **CAP-4**
  - **intent:** Managed RPM 可按 `never/fill/always` 策略安全签名并在重复导入时复用既有最终对象。
  - **success:** signature-neutral payload 重试、trusted key 验证、fill/always 重签、secret redaction 与最终 rpm-md checksum 均通过真实 key、失败和重复执行测试。

- **CAP-5**
  - **intent:** 每条 Membership 写路径都对完整 Desired 集合执行封闭的 exclude 与 Limit 策略。
  - **success:** 分类、exact/glob、rule/field/pattern 布尔语义、exclude-before-Limit、RPM EVR/Debian version 排序及配置变更 reconcile 均有 golden/属性测试；放宽策略不隐式复活成员。

- **CAP-6**
  - **intent:** 运维者可以预览并删除精确对象或指定名称的 Dist Membership，而不直接删除 Pool 对象。
  - **success:** exact reference、coordinate、filename 与 name-wide 删除可预测；歧义/无匹配拒绝，`--check` 纯读，默认 build 与 `--skip` 语义正确。

- **CAP-7**
  - **intent:** Desired Revision、private pending content 与 Built Generation 是显式且可独立验证的状态。
  - **success:** 默认 mutation 返回时 ready-to-copy；`--skip` 只推进 Desired/private pending 并保持公共树逐字节不变；选择性/no-op build、dirty 原因及每 Dist 至多一次构建成立。

- **CAP-8**
  - **intent:** 每次 Managed 写入都由 durable SQLite Operation Journal 协调数据库、pending、Pool、metadata 和指针动作。
  - **success:** `planned` 先于副作用；每个阶段的 SIGKILL/fault injection 只收敛到完整旧代或新代；下一写命令幂等完成或回滚，非零 JSON 保留已提交的 partial result。

- **CAP-9**
  - **intent:** 运维者可以查询 Desired package/membership，并低成本查看 Repository 的 clean/dirty/recovering/error 状态。
  - **success:** `ls/show/where` 精确解析与歧义列表正确；`status` 不全量哈希、不恢复、不写状态，并诚实暴露 ready-to-copy、锁和最近 Operation。

- **CAP-10**
  - **intent:** `build` 将合法 Desired State 渲染、验证、签名并 pointer-last 发布为完整 Built Generation。
  - **success:** RPM 生成 `repomd.xml` 及配置时的 `repomd.xml.asc`；DEB 始终生成 `Release`，配置时生成 `InRelease`/`Release.gpg`；key fingerprint 变化标 dirty，任何 crash point 无悬空 package/metadata 引用。

- **CAP-11**
  - **intent:** `check` 对配置、SQLite、Pool/pending、包身份与签名、Membership、metadata 引用和架构投影执行端到端只读验证。
  - **success:** clean 证明 ready-to-copy；dirty 分别证明旧 Built 与新 Desired 合法但返回不可交付；recovering/error 给出完整性判定且不 repair/build/recover。

- **CAP-12**
  - **intent:** 每个实际变化的 Built Generation 提供 Repository 物理交付树 Changeset。
  - **success:** `changes 0` 与 `pool/ + dists/` 文件集合、size 和 SHA-256 完全一致；任意保留 Base 到当前代的净 add/update/delete 正确，phase 固定为 payload/metadata/pointer/delete，recovering/error 拒绝输出同步计划。

- **CAP-13**
  - **intent:** 运维者可以查询、JSONL 导出并按时间清理终态审计 Operation。
  - **success:** `log` 完整呈现状态迁移、包、Membership、文件、耗时和错误；`prune` 绝不删除非终态恢复、当前状态、Generation 或 Changeset 数据，并安全压缩 SQLite。

- **CAP-14**
  - **intent:** 完整产品在目标平台、真实客户端和 Pigsty 当前规模下保持确定性、兼容性与可操作性能。
  - **success:** 普通/race/static/clean-delivery/四目标构建通过；Tier 1 APT/DNF 完成 file/HTTP refresh、query、download、checksum、install 与 reposync；34,184 包约 50.18 GiB 的安全副本 clean rebuild 可重复地不超过两分钟。

## Constraints

- 公共命令、参数、默认值、输出、状态与退出码以 adopted `api-contract.md` 为最高优先级；`--skip` 是正式名称，PRD 中旧 `--no-build` 文案不进入 API。
- 保持已验收 P0 Plain create/RPM signing 的 metadata 语义、权限、原子恢复和 CLI 不回归。
- C2 是冻结布局：root Pool 拥有 canonical object；每个 architecture view 只建立同文件系统 regular hardlink alias，metadata 使用无 `..` 的 `pool/...` href；不支持时硬失败，不静默复制降级。
- Repository 是单写锁、恢复、Generation 与 Changeset 边界；不同 Repository 不去重、不做跨仓原子事务。
- Package Object 以最终完整字节 SHA-256 标识且不可变；同 Repository 内逻辑坐标只允许映射一个内容。
- 所有公开 metadata 从同文件系统私有 stage 完成校验与 fsync，package/metadata 先于协议 pointer；路径必须 root-bound 且不跟随 symlink。
- CLI 与 `sow.yml` schema 封闭；未知命令、flag、配置键、policy 字段和假占位均失败。
- secret/passphrase 不得进入 config 展示、SQLite、Operation、log、JSON、Changeset、诊断或证据；只能持久化引用与 fingerprint。
- 开发和验收不得把 `/Users/vonng/pgsty/repo` 用作写目标或容器写挂载；写入、签名、故障注入和性能实验只在 `/Users/vonng/repo` lab 或显式临时目录。
- 未经用户另行授权，不 commit、push、签名生产仓库、上传或发布。

## Non-goals

- modulemd、route、manifest、rejected quarantine、公式/list/source-list 选择器。
- sync/publish、远端 endpoint/CDN/object store、pull/push/copy/move/promote。
- GC、managed export、mirror/fetch、SRPM/DSC/source index、跨 Repository 去重。
- snapshot/freeze/readonly 特殊状态机、多机多写、服务、Web UI、包构建或客户端包管理。
- 通过跳过哈希、包头解析、Policy、签名校验、故障恢复或真实客户端测试换取性能。

## Success signal

在安全的 repo2/离线包副本上，运维者能够执行 `init → add --skip → status → build → check → changes → query/log`，再由 APT/DNF/reposync 直接消费并安装；逐阶段杀进程后下一写命令自动恢复，`changes 0` 精确描述可复制树，34,184 包 clean rebuild 在两分钟内完成，同时生产仓库没有成为任何写路径。

## Assumptions

- 用户要求完整落地 P1–P3，视为确认 PRD 第 13 节六项产品契约及 API v0.2；唯一已证伪并被当前 P1 实现替代的是原 `../../../pool` 物理 href 候选，正式采用 C2。
- 当前 P1 代码和历史报告仅是 brownfield 起点；最终结论必须绑定最终 checkout、当前二进制和 retained evidence。
