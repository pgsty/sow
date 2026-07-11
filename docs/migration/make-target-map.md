# 旧 Makefile → SOW 迁移账本

> 状态：静态审计完成，迁移与运行验证均未开始  
> 审计日期：2026-07-11  
> 目的：为 G5“约 40 个旧业务目标全部由 SOW 替代退役”建立逐目标、不可漏项的基线。

## 1. 审计边界与计数

本账本完整逐行审计以下四个文件，不执行其中任何 recipe，也不连接 rclone、rsync、Docker、Cloudflare 或腾讯云：

- `LEGACY-ROOT`：`/Users/vonng/pgsty/repo/Makefile`（129 个逻辑行，末行无换行符）
- `LEGACY-APT`：`/Users/vonng/pgsty/repo/apt/Makefile`（252 行）
- `LEGACY-YUM`：`/Users/vonng/pgsty/repo/yum/Makefile`（48 行）
- `LEGACY-DOCKER`：`/Users/vonng/pgsty/repo/docker/Makefile`（176 行）

静态解析得到的 concrete `<文件,target>` 对如下。这里按每个名字计数，因此包含编排别名、同义别名和容器包装目标；不同文件中的同名 target 分别计数。

| 文件 | concrete target 数 | 本账本覆盖 |
|---|---:|---:|
| 根 Makefile | 52 | 52 |
| APT Makefile | 70 | 70 |
| YUM Makefile | 14 | 14 |
| Docker Makefile | 40 | 40 |
| 合计 | **176** | **176** |

PRD 的“4 个 Makefile、约 40 个目标”是业务复杂度量级，不是这四个文件的 raw target 名数量。G5 只有在以下三类目标都得到处置后才可通过：

1. 仓库业务目标由真实 SOW CLI 行为覆盖并有等价/改进证据。
2. 编排别名由“动词 × 选择器”替代，并验证原依赖展开没有漏项。
3. 容器生命周期、造包或收集类范围外目标有明确退役/移交路径；不能仅贴“范围外”标签后从 G5 清单消失。

所有映射命令都是未来 CLI 意图示例，最终语法以实现后的 `sow --help` 为准。当前一律不得视为已迁移或已验证。

## 2. 状态、风险与回滚代码

### 2.1 状态

- `未迁移/未验证`：属于 SOW 产品职责，但尚无真实命令等价证据。
- `范围缺口/未验证`：旧行为有业务用途，但当前 PRD 命令面没有明确等价语义，必须 ADR 决策。
- `待退役/未验证`：属于容器生命周期、造包或收集辅助；SOW 不应照搬，但退役/移交尚未验证。
- `策略禁止/未验证`：旧行为与冻结策略冲突，必须证明已阻止而不是移植。

### 2.2 风险级别

- `R0`：只读、帮助或输出。
- `R1`：写本地派生文件，可重新生成。
- `R2`：删除/覆盖本地内容，或原地修改包字节。
- `R3`：可能删除/覆盖远端对象，或产生双目标部分成功；当前均无事务、checkpoint、purge 和发布后验证。
- `R4`：秘密进入镜像/命令行、任意命令执行或大范围不可逆破坏。

### 2.3 回滚代码

- `RB-A`：保留旧 asset 树；恢复上一个 manifest/ref，重新 materialize，并按目标 publish+purge+verify。
- `RB-R`：恢复上一个 APT/YUM manifest/ref 与 CAS 引用，重新 materialize；任何 GC 前保留快照。
- `RB-P`：按 cf/cos 独立远端 checkpoint 恢复上一个发布 ref，再执行最小 purge 和穿 CDN 验证。
- `RB-L`：执行破坏性本地迁移前做只读 manifest、checksum 和目录备份；失败时整体恢复，不从部分生成目录续跑。
- `RB-X`：保留旧外部工作流直到 SOW 真机 E2E 通过；若新流程失败，停止 SOW 并回到旧工具，不混用两套写者。
- `RB-B`：保留外部构建/收集流水线；SOW 只接收其最终 deb/rpm，不负责回滚构建系统。

## 3. 必须先修正或冻结的现状

### 3.1 已确认的静态缺陷与危险语义

1. **`cf-yum` 错依赖已确认**：`LEGACY-ROOT:L105` 依赖 `cf-yum-infra cf-apt-pgsql`，第二项应是 YUM pgsql 路径而不是 APT。它会漏传 `yum/pgsql` 并意外触发 `apt/pgsql` 上传。未来映射必须是 `sow publish --target cf --type yum --repo infra,pgsql`，且用选择器展开测试锁死。
2. 根 Makefile 所有 rclone 发布使用 `sync`，会删除目标端多余对象；没有 manifest、checkpoint、CDN purge 或发布后验证（`LEGACY-ROOT:L34-L117`）。
3. APT 发布同样使用 `rclone sync`，双目标只是 Make 依赖组合，不是事务；没有独立远端跟踪或 purge（`LEGACY-APT:L171-L222`）。
4. `MAX_AGE` 在 `LEGACY-ROOT:L7-L9` 声称可覆盖 `co-pig`，但所有实际 asset sync 均未引用该变量；`co-img` 反而硬编码 `24h`（L29-L30）。
5. `up-src` 打印的两个 URL 域名为 `reoo.pigsty.*`，是静态拼写错误（`LEGACY-ROOT:L66-L68`）。
6. `rm-pig` recipe 为 `reprepro -b infra generic pig`，疑似缺失 `remove` 子命令；本审计未执行它（`LEGACY-APT:L86-L87`）。
7. APT `purge` 最后一项使用 `percona/stash/stash/*.deb`，与 add 路径 `percona/stash/*.deb` 不一致，疑似无法清理预期目录（`LEGACY-APT:L58-L67`）。
8. `init-*` 先 `rm -rf db,dists,pool` 再重建；任何中途失败都会留下半仓库（`LEGACY-APT:L128-L149`）。
9. `pushd`/`pulld` 使用 `rsync --delete`，方向选错会删除目标端文件（`LEGACY-APT:L159-L166`）。
10. YUM `.PHONE` 是拼写错误，且列出不存在的 `build-extra`；文件中的 `build` 脚本又与 target 同名（`LEGACY-YUM:L48`）。APT 的 `.PHONY` 也只覆盖部分目标（`LEGACY-APT:L249-L252`），根 Makefile 没有 `.PHONY`。
11. YUM `sign*` 用 mtime 选择文件并原地 `rpm --addsign`，会改变 RPM 字节，无法区分上游镜像包与自建包，违反 FR-17 Day 1 策略（`LEGACY-YUM:L32-L46`）。
12. Docker `image` 将 `GPG_PASSPHRASE` 作为 build arg 传入镜像构建命令（`LEGACY-DOCKER:L72-L81`）；被引用 Dockerfile 还把它写入镜像层内的 rpm macro。该路径必须退役，禁止迁入 SOW。
13. Docker `exec CMD=...` 可在挂载真实 YUM 树的容器内执行任意 shell（`LEGACY-DOCKER:L143-L146`）；所有容器 build/sign wrapper 都直接修改 host bind mount。
14. COS 有 pgdg 上传目标，CF 没有对应 `cf-pgdg`、`cf-apt-pgdg` 或 `cf-yum-pgdg`；这是需确认的发布面不对称，不能在迁移时擅自补齐或丢弃。
15. YUM build 调用的旧脚本生成 modulemd，而 PRD 明确排除 modulemd；迁移时只保留标准 primary/filelists/other/repomd 能力。
16. COS 路径写法不一致：根文件用 `cos:/repo-1304744452`，APT 文件用 `cos://repo-1304744452/apt`（`LEGACY-ROOT:L4`；`LEGACY-APT:L12`）。迁移前必须用真实对象 key 基线确认前导斜杠语义，不能照抄字符串。

### 3.2 `latest` URL 基线

以下是**本地树和 Makefile 的静态基线，不是远端已验证结果**：

- CF 根为 `cf:/repo`，COS 根为 `cos:/repo-1304744452`（`LEGACY-ROOT:L3-L5`）。
- 根 Makefile 注释明确列出 `https://repo.pigsty.io/pkg/pig/latest`，并列出 `/get`、`/src/checksums`、`/src/pigsty-*.tgz` 与 `/pkg/pig/v*/`（`LEGACY-ROOT:L121-L128`）。
- 本地 `/Users/vonng/pgsty/repo/pkg/pig/latest` 是 5 字节普通文件，当前内容为 `1.5.1`；它随 `cf-pig`/`co-pig` 整目录发布到两端 `/pkg/pig/latest`。基线 URL 是 `https://repo.pigsty.io/pkg/pig/latest`，国内对应路径为 `https://repo.pigsty.cc/pkg/pig/latest`（后者尚未做远端 HTTP 验证）。该文件 URL 和“正文为版本号”的语义必须保持兼容。
- 本地 `/Users/vonng/pgsty/repo/pkg/ray/latest` 是 6 字节普通文件，当前内容为 `5.44.1`，由 `co-ray` 发布到 COS `/pkg/ray/latest`；它也是 asset 兼容基线，但不是 repository channel。
- APT 当前公开布局没有 `/latest/` 段：现有路径直接位于 `/apt/infra/`、`/apt/pgsql/` 及其 suite 子树；YUM 同理直接位于 `/yum/infra/`、`/yum/pgsql/` 等。未来 `latest` 视图必须继续物化在这些现有路径，新 beta/stable/snapshot 命名空间不得迫使 OSS 客户改 URL。
- 当前 asset 根还发布 `/get`、`/pig`、`/pkg`、`/beta`、`/ray`、`/cc`、`/claude`、`/img/`、`/ext/`、`/src/`、`/pkg/pig/`、`/pkg/claude/`、`/pkg/ray/`、`/etc/`、`/dba/`。这里的 `/beta` 是引导脚本文件，不应与未来 repository `beta` view 混淆。
- 远端域名到对象根、HTTP 状态、重定向、ETag、实际内容和 CDN 缓存尚未在本账本中验证，迁移前必须另存 URL 清单和响应摘要。

## 4. 根 Makefile：52/52

来源：`/Users/vonng/pgsty/repo/Makefile`。

| ID | target | 类别 | 依赖/别名 | 当前副作用 | 风险 | 未来 SOW 动词 × 选择器 | 状态 | 回滚 |
|---|---|---|---|---|---|---|---|---|
| ROOT-01 | `copy-auth` | Pro 鉴权配置 | 无 | `rclone copyto` 将本地 `bin/fileauth.txt` 覆盖到 COS 根 `/fileauth.txt` | R4：安全敏感文件，单对象覆盖，无版本/验证 | 鉴权数据安全 provider + `sow publish --repo edge-auth --target cos`；schema/secret ADR 先决 | 范围缺口/未验证 | RB-A、RB-P |
| ROOT-02 | `copy-bin` | asset 业务 | 无 | 覆盖 CF `/get,/pig,/pkg` 与 COS `/get,/pig,/pkg,/cc,/claude` | R3：多个单对象可部分成功，无 purge | `sow add` 到配置化 asset repos，再 `sow publish --target cf,cos` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-03 | `copy-beta` | asset 业务 | 无 | 覆盖两端 `/beta` 及 COS `/ray` | R3：部分成功；名称与 repo beta view 易混 | 配置独立 asset 名，`sow add` + `sow publish --repo asset-bootstrap` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-04 | `co-img` | asset 业务 | 无 | 只上传 24h 内 `img/` 到 COS，`copy` 不删远端 | R1/R3：时间窗可能漏文件；无 manifest | `sow add --repo img` + `sow publish --repo img --target cos`，按 manifest 差异 | 未迁移/未验证 | RB-A、RB-P |
| ROOT-05 | `ext-list` | 辅助清单 | 无 | `ls -a` 覆盖 `pkg/ext/README.md` | R1：包含 `.`/`..`，格式非稳定契约 | 若仍需兼容输出，由 manifest inventory 派生产物；否则明确退役 | 范围缺口/未验证 | RB-L |
| ROOT-06 | `cf-ext` | asset 发布 | 无 | `rclone sync ext/` 到 CF `/ext/` | R3：删除远端多余对象，无 purge | `sow publish --repo ext --target cf` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-07 | `co-ext` | asset 发布 | 无 | `rclone sync ext/` 到 COS `/ext/` | R3：同上 | `sow publish --repo ext --target cos` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-08 | `md5-src` | asset 元数据 | 无 | `md5sum *.tgz` 覆盖 `src/checksums` | R1：外部运行时、MD5、空 glob 风险 | manifest SHA256 + 兼容 `checksums` 派生产物，经 `materialize` | 未迁移/未验证 | RB-A、RB-L |
| ROOT-09 | `cf-src` | asset 发布 | 无 | `rclone sync src/` 到 CF `/src/` | R3：远端删除，无 purge | `sow publish --repo src --target cf` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-10 | `co-src` | asset 发布 | 无 | `rclone sync src/` 到 COS `/src/` | R3：远端删除，无 purge | `sow publish --repo src --target cos` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-11 | `cf-pig` | asset 发布 | 无 | 同步 `pkg/pig/` 到 CF，含 `/latest` 指针 | R3：可能删历史版本或 latest，无原子指针 | `sow publish --repo pkg-pig --target cf`；latest 兼容门禁 | 未迁移/未验证 | RB-A、RB-P |
| ROOT-12 | `co-pig` | asset 发布 | 无 | 同步 `pkg/pig/` 到 COS | R3：同上；注释所称 MAX_AGE 实际未生效 | `sow publish --repo pkg-pig --target cos` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-13 | `co-claude` | asset 发布 | 无 | 同步 `pkg/claude/` 到 COS | R3：远端删除 | `sow publish --repo pkg-claude --target cos` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-14 | `co-ray` | asset 发布 | 无 | 同步 `pkg/ray/` 到 COS | R3：远端删除，可能影响 `/latest` | `sow publish --repo pkg-ray --target cos` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-15 | `cf-etc` | asset 发布 | 无 | 同步 `etc/` 到 CF | R3：远端删除 | `sow publish --repo etc --target cf` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-16 | `co-etc` | asset 发布 | 无 | 同步 `etc/` 到 COS | R3：远端删除 | `sow publish --repo etc --target cos` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-17 | `cf-dba` | asset 发布 | 无 | 同步 `dba/` 到 CF | R3：远端删除 | `sow publish --repo dba --target cf` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-18 | `co-dba` | asset 发布 | 无 | 同步 `dba/` 到 COS | R3：远端删除 | `sow publish --repo dba --target cos` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-19 | `up-pig` | 编排别名 | `co-pig cf-pig` | 依赖顺序上传两端；任一端可独立成功 | R3：没有目标独立 checkpoint | `sow publish --repo pkg-pig --target cf,cos` | 未迁移/未验证 | RB-P |
| ROOT-20 | `up-dba` | 编排别名 | `co-dba cf-dba` | 上传两端 dba | R3：部分成功 | `sow publish --repo dba --target cf,cos` | 未迁移/未验证 | RB-P |
| ROOT-21 | `up-etc` | 编排别名 | `co-etc cf-etc` | 上传两端 etc | R3：部分成功 | `sow publish --repo etc --target cf,cos` | 未迁移/未验证 | RB-P |
| ROOT-22 | `up-src` | 编排别名 | `md5-src co-src cf-src` | 生成 checksums、上传两端、打印两个拼错域名 | R3：部分成功且输出误导 | `sow add/materialize/publish --repo src --target cf,cos` | 未迁移/未验证 | RB-A、RB-P |
| ROOT-23 | `ss` | 别名 | `up-src` | 完全继承 up-src | R3：同上 | 与 `up-src` 相同；别名退役 | 未迁移/未验证 | RB-A、RB-P |
| ROOT-24 | `co-upload` | 编排别名 | `co-infra co-pgsql` | COS 上传 APT+YUM 的 infra/pgsql | R3：四棵树可部分成功 | `sow publish --target cos --repo infra,pgsql`，repo type 由选择器展开 | 未迁移/未验证 | RB-P |
| ROOT-25 | `co-infra` | 编排别名 | `co-apt-infra co-yum-infra` | COS 上传 APT/YUM infra | R3：部分成功 | `sow publish --target cos --repo infra` | 未迁移/未验证 | RB-P |
| ROOT-26 | `co-pgsql` | 编排别名 | `co-apt-pgsql co-yum-pgsql` | COS 上传 APT/YUM pgsql | R3：部分成功 | `sow publish --target cos --repo pgsql` | 未迁移/未验证 | RB-P |
| ROOT-27 | `co-pgdg` | 编排别名 | `co-apt-pgdg co-yum-pgdg` | COS 上传 APT/YUM pgdg | R3：部分成功 | `sow publish --target cos --repo pgdg` | 未迁移/未验证 | RB-P |
| ROOT-28 | `co-percona` | 编排别名 | `co-apt-percona co-yum-percona` | COS 上传 APT/YUM percona | R3：部分成功 | `sow publish --target cos --repo percona` | 未迁移/未验证 | RB-P |
| ROOT-29 | `co-apt` | 编排别名 | `co-apt-infra co-apt-pgsql` | COS 上传两个 APT repo，不含 pgdg/percona | R3：名称看似“全部”但只是子集 | `sow publish --target cos --type apt --repo infra,pgsql` | 未迁移/未验证 | RB-P |
| ROOT-30 | `co-yum` | 编排别名 | `co-yum-infra co-yum-pgsql` | COS 上传两个 YUM repo，不含 pgdg/percona | R3：同上 | `sow publish --target cos --type yum --repo infra,pgsql` | 未迁移/未验证 | RB-P |
| ROOT-31 | `co-yum-infra` | YUM 发布 | 无 | `rclone sync yum/infra/` 到 COS | R3：远端删除，无 repomd pair/purge | `sow publish --target cos --type yum --repo infra` | 未迁移/未验证 | RB-P |
| ROOT-32 | `co-yum-pgsql` | YUM 发布 | 无 | 同步 `yum/pgsql/` 到 COS | R3：同上 | `sow publish --target cos --type yum --repo pgsql` | 未迁移/未验证 | RB-P |
| ROOT-33 | `co-yum-pgdg` | YUM 上游镜像发布 | 无 | 同步 `yum/pgdg/` 到 COS | R3：远端删除上游历史的可能性 | `sow sync --repo pgdg` 后 `sow publish --target cos --type yum --repo pgdg` | 未迁移/未验证 | RB-P |
| ROOT-34 | `co-yum-percona` | YUM 上游镜像发布 | 无 | 同步 `yum/percona/` 到 COS | R3：同上 | `sow sync --repo percona` 后 publish | 未迁移/未验证 | RB-P |
| ROOT-35 | `co-apt-infra` | APT 发布 | 无 | 同步 `apt/infra/` 到 COS | R3：远端删除，无 InRelease 翻转/purge | `sow publish --target cos --type apt --repo infra` | 未迁移/未验证 | RB-P |
| ROOT-36 | `co-apt-pgsql` | APT 发布 | 无 | 同步 `apt/pgsql/` 到 COS | R3：同上 | `sow publish --target cos --type apt --repo pgsql` | 未迁移/未验证 | RB-P |
| ROOT-37 | `co-apt-pgdg` | APT 上游镜像发布 | 无 | 同步 `apt/pgdg/` 到 COS | R3：远端删除上游历史的可能性 | `sow sync --repo pgdg` 后 publish | 未迁移/未验证 | RB-P |
| ROOT-38 | `co-apt-percona` | APT 上游镜像发布 | 无 | 同步 `apt/percona/` 到 COS | R3：同上 | `sow sync --repo percona` 后 publish | 未迁移/未验证 | RB-P |
| ROOT-39 | `co-pro-get` | 旧 Pro 拉取 | 无 | `rclone sync` 从 COS `/pro/` 到本地 `pro/`，会删除本地多余文件 | R3：反向破坏本地；旧双仓设计已废止 | 一次性迁移程序：先只读 manifest/fsck 再纳入合一池；无长期 pull 动词 | 范围缺口/未验证 | RB-L、RB-X |
| ROOT-40 | `co-pro` | 旧 Pro 发布 | 无 | 同步本地 `pro/` 到 COS `/pro/` | R3：旧布局、远端删除、无鉴权事务 | 合一池 stable/gated view 的 `sow publish --view stable --target cos` | 未迁移/未验证 | RB-P、RB-X |
| ROOT-41 | `cf-upload` | 编排别名 | `cf-infra cf-pgsql` | CF 上传 APT+YUM infra/pgsql | R3：四棵树部分成功 | `sow publish --target cf --repo infra,pgsql` | 未迁移/未验证 | RB-P |
| ROOT-42 | `cf-infra` | 编排别名 | `cf-apt-infra cf-yum-infra` | CF 上传 APT/YUM infra | R3：部分成功 | `sow publish --target cf --repo infra` | 未迁移/未验证 | RB-P |
| ROOT-43 | `cf-pgsql` | 编排别名 | `cf-apt-pgsql cf-yum-pgsql` | CF 上传 APT/YUM pgsql | R3：部分成功 | `sow publish --target cf --repo pgsql` | 未迁移/未验证 | RB-P |
| ROOT-44 | `cf-percona` | 编排别名 | `cf-apt-percona cf-yum-percona` | CF 上传 APT/YUM percona | R3：部分成功 | `sow publish --target cf --repo percona` | 未迁移/未验证 | RB-P |
| ROOT-45 | `cf-apt` | 编排别名 | `cf-apt-infra cf-apt-pgsql` | CF 上传两个 APT repo | R3：子集名称含混 | `sow publish --target cf --type apt --repo infra,pgsql` | 未迁移/未验证 | RB-P |
| ROOT-46 | `cf-yum` | **错误编排别名** | 实际为 `cf-yum-infra cf-apt-pgsql` | 漏传 yum/pgsql，误传 apt/pgsql | R3：已确认依赖错误 | 必须映射为 `sow publish --target cf --type yum --repo infra,pgsql` 并锁定展开测试 | 未迁移/未验证 | RB-P |
| ROOT-47 | `cf-yum-infra` | YUM 发布 | 无 | 同步 `yum/infra/` 到 CF | R3：远端删除，无 pair/purge | `sow publish --target cf --type yum --repo infra` | 未迁移/未验证 | RB-P |
| ROOT-48 | `cf-yum-pgsql` | YUM 发布 | 无 | 同步 `yum/pgsql/` 到 CF | R3：同上 | `sow publish --target cf --type yum --repo pgsql` | 未迁移/未验证 | RB-P |
| ROOT-49 | `cf-yum-percona` | YUM 上游镜像发布 | 无 | 同步 `yum/percona/` 到 CF | R3：远端删除历史可能性 | `sow sync --repo percona` 后 publish | 未迁移/未验证 | RB-P |
| ROOT-50 | `cf-apt-infra` | APT 发布 | 无 | 同步 `apt/infra/` 到 CF | R3：远端删除，无翻转/purge | `sow publish --target cf --type apt --repo infra` | 未迁移/未验证 | RB-P |
| ROOT-51 | `cf-apt-pgsql` | APT 发布 | 无 | 同步 `apt/pgsql/` 到 CF | R3：同上 | `sow publish --target cf --type apt --repo pgsql` | 未迁移/未验证 | RB-P |
| ROOT-52 | `cf-apt-percona` | APT 上游镜像发布 | 无 | 同步 `apt/percona/` 到 CF | R3：远端删除历史可能性 | `sow sync --repo percona` 后 publish | 未迁移/未验证 | RB-P |

## 5. APT Makefile：70/70

来源：`/Users/vonng/pgsty/repo/apt/Makefile`。

| ID | target | 类别 | 依赖/别名 | 当前副作用 | 风险 | 未来 SOW 动词 × 选择器 | 状态 | 回滚 |
|---|---|---|---|---|---|---|---|---|
| APT-01 | `init` | APT 纳管初始化 | 无 | 建 `infra`、`pgsql` 的 conf/db/dists/pool 目录 | R1：只建部分布局，可能掩盖配置缺失 | `sow init --repo apt/infra,apt/pgsql`，零字节扫描现有树 | 未迁移/未验证 | RB-L、RB-X |
| APT-02 | `clean` | stash 清理 | 无 | `rm -rf stash/*`，只清 APT 根级 stash | R2：不可逆且可能不是实际 suite stash；非 phony | 新流程直接 `sow add <files>`，不再要求 stash；旧 target 待退役 | 待退役/未验证 | RB-L |
| APT-03 | `add-infra` | APT 加包 | 无 | reprepro 将 `infra/stash/*.deb` 加入 generic | R2：外部 runtime，批量 glob，无事务 | `sow add infra/stash/*.deb --type apt --repo infra --os generic` | 未迁移/未验证 | RB-R、RB-X |
| APT-04 | `add-percona` | APT 加包 | 无 | 依次向 noble/resolute/jammy/focal/bookworm/bullseye 加包 | R2：六步可部分成功，文件名推断脆弱 | `sow add percona/stash/*.deb --type apt --repo percona`，自动推断 OS/arch | 未迁移/未验证 | RB-R、RB-X |
| APT-05 | `add-oss` | 编排别名 | `add-jammy add-trixie add-noble add-resolute add-bookworm` | 顺序向五个活跃 suite 加 stash | R2：部分成功；OSS 集合硬编码 | `sow add <files> --repo pgsql --os jammy,trixie,noble,resolute,bookworm --view beta` | 未迁移/未验证 | RB-R |
| APT-06 | `add-all` | 编排别名 | focal/jammy/noble/resolute/bookworm/bullseye/trixie | 向全部七个 suite 加包 | R2：部分成功；EOL/active 混合 | `sow add` + OS 选择器；EOL 策略门禁 | 未迁移/未验证 | RB-R |
| APT-07 | `add-debian` | 编排别名 | `add-bookworm add-bullseye add-trixie` | 向 Debian 三 suite 加包 | R2：部分成功 | `sow add --repo pgsql --os bookworm,bullseye,trixie` | 未迁移/未验证 | RB-R |
| APT-08 | `add-ubuntu` | 编排别名 | `add-focal add-jammy add-noble add-resolute` | 向 Ubuntu 四 suite 加包 | R2：部分成功 | `sow add --repo pgsql --os focal,jammy,noble,resolute` | 未迁移/未验证 | RB-R |
| APT-09 | `add-focal` | APT 加包 | 无 | reprepro 加 `pgsql/focal/stash/*.deb` 到 focal | R2：外部 runtime；focal EOL 策略未冻结 | `sow add ... --type apt --repo pgsql --os focal`，受 EOL 门禁 | 未迁移/未验证 | RB-R |
| APT-10 | `add-jammy` | APT 加包 | 无 | 加 jammy stash | R2：非事务 glob | `sow add ... --type apt --repo pgsql --os jammy` | 未迁移/未验证 | RB-R |
| APT-11 | `add-noble` | APT 加包 | 无 | 加 noble stash | R2：非事务 glob | `sow add ... --type apt --repo pgsql --os noble` | 未迁移/未验证 | RB-R |
| APT-12 | `add-resolute` | APT 加包 | 无 | 加 resolute stash | R2：非事务 glob | `sow add ... --type apt --repo pgsql --os resolute` | 未迁移/未验证 | RB-R |
| APT-13 | `add-bullseye` | APT 加包 | 无 | 加 bullseye stash | R2：EOL 策略未冻结 | `sow add ... --type apt --repo pgsql --os bullseye`，受 EOL 门禁 | 未迁移/未验证 | RB-R |
| APT-14 | `add-bookworm` | APT 加包 | 无 | 加 bookworm stash | R2：非事务 glob | `sow add ... --type apt --repo pgsql --os bookworm` | 未迁移/未验证 | RB-R |
| APT-15 | `add-trixie` | APT 加包 | 无 | 加 trixie stash | R2：非事务 glob | `sow add ... --type apt --repo pgsql --os trixie` | 未迁移/未验证 | RB-R |
| APT-16 | `adda` | 快捷别名 | jammy/noble/resolute/bookworm；不含 trixie | 加四个 suite | R2：名称无语义，集合与 add-oss 不同 | 用显式 OS 选择器替代，别名退役 | 未迁移/未验证 | RB-R |
| APT-17 | `purge` | stash 清理 | 无 | 删除 infra 和七 suite stash；percona 路径疑似写错为 stash/stash | R2：不可逆、路径错误、无 dry-run | 直接 add 消除 stash 仪式；不迁移删除命令 | 待退役/未验证 | RB-L |
| APT-18 | `ls-infra` | 仓库清单 | 无 | reprepro 列 generic | R0：只读但依赖外部 runtime | `sow verify --level 1 --type apt --repo infra --os generic` 的 inventory 报告 | 未迁移/未验证 | RB-X |
| APT-19 | `ls-focal` | 仓库清单 | 无 | 列 focal | R0 | `sow verify --level 1 --repo pgsql --os focal` | 未迁移/未验证 | RB-X |
| APT-20 | `ls-jammy` | 仓库清单 | 无 | 列 jammy | R0 | `sow verify --level 1 --repo pgsql --os jammy` | 未迁移/未验证 | RB-X |
| APT-21 | `ls-noble` | 仓库清单 | 无 | 列 noble | R0 | `sow verify --level 1 --repo pgsql --os noble` | 未迁移/未验证 | RB-X |
| APT-22 | `ls-resolute` | 仓库清单 | 无 | 列 resolute | R0 | `sow verify --level 1 --repo pgsql --os resolute` | 未迁移/未验证 | RB-X |
| APT-23 | `ls-bullseye` | 仓库清单 | 无 | 列 bullseye | R0 | `sow verify --level 1 --repo pgsql --os bullseye` | 未迁移/未验证 | RB-X |
| APT-24 | `ls-bookworm` | 仓库清单 | 无 | 列 bookworm | R0 | `sow verify --level 1 --repo pgsql --os bookworm` | 未迁移/未验证 | RB-X |
| APT-25 | `ls-trixie` | 仓库清单 | 无 | 列 trixie | R0 | `sow verify --level 1 --repo pgsql --os trixie` | 未迁移/未验证 | RB-X |
| APT-26 | `rm-pig` | APT 减包 | 无 | recipe 疑似漏 `remove`，静态看不能正确删除 pig | R2：若修正后会改索引/引用；现 recipe 未执行验证 | `sow rm pig --type apt --repo infra --os generic`；stable/history 保护 | 未迁移/未验证 | RB-R |
| APT-27 | `trim-dump` | 孤儿审计 | 无 | 对 infra 和七 suite 执行 `dumpunreferenced` | R0：只读报告但分散且无统一 manifest | `sow fsck --type apt --report orphans` | 未迁移/未验证 | RB-X |
| APT-28 | `trim` | 物理 GC | 无 | 对 infra 和七 suite `deleteunreferenced` | R2：不可逆删除；可能破坏历史钉版 | `sow rm` 后引用计数 GC；stable/snapshot 引用不可删；先 fsck | 未迁移/未验证 | RB-R、RB-L |
| APT-29 | `pgsql-include` | APT 加包 | 无 | 以旧 `-b pgsql` 布局将 PostgreSQL 16 包加到 bookworm/jammy | R2：与当前 per-suite base 布局不一致，可能是遗留路径 | `sow add` 自动推断；旧布局先零字节审计 | 未迁移/未验证 | RB-R、RB-X |
| APT-30 | `init-all` | 破坏性编排 | 七个 `init-*` | 删除并从 `~/pgsty/apt/<suite>` 重建七仓 | R4：多仓部分重建、无快照、失败留半仓 | 对源包先 `sow init/add` 到 CAS，再从 ref materialize；禁止原地 rm -rf | 未迁移/未验证 | RB-L、RB-R |
| APT-31 | `init-focal` | 破坏性重建 | 无 | 删除 focal db/dists/pool，再导入 `~/pgsty/apt/focal/*.deb` | R4：整仓不可逆 | `sow add` 源目录 + 新 ref materialize，验证后切换 | 未迁移/未验证 | RB-L、RB-R |
| APT-32 | `init-jammy` | 破坏性重建 | 无 | 同上，jammy | R4 | 同上，`--os jammy` | 未迁移/未验证 | RB-L、RB-R |
| APT-33 | `init-noble` | 破坏性重建 | 无 | 同上，noble | R4 | 同上，`--os noble` | 未迁移/未验证 | RB-L、RB-R |
| APT-34 | `init-resolute` | 破坏性重建 | 无 | 同上，resolute | R4 | 同上，`--os resolute` | 未迁移/未验证 | RB-L、RB-R |
| APT-35 | `init-bullseye` | 破坏性重建 | 无 | 同上，bullseye | R4 | 同上，`--os bullseye` 且 EOL 策略门禁 | 未迁移/未验证 | RB-L、RB-R |
| APT-36 | `init-bookworm` | 破坏性重建 | 无 | 同上，bookworm | R4 | 同上，`--os bookworm` | 未迁移/未验证 | RB-L、RB-R |
| APT-37 | `init-trixie` | 破坏性重建 | 无 | 同上，trixie | R4 | 同上，`--os trixie` | 未迁移/未验证 | RB-L、RB-R |
| APT-38 | `gen` | 辅助清单 | 无 | 执行 `list/gen`，随后显示 `git diff list/*` | R1：自定义派生产物，语义未纳入 PRD | 由 manifest/SQLite 生成 inventory 报告；格式是否兼容须 ADR | 范围缺口/未验证 | RB-L、RB-X |
| APT-39 | `push` | 开发机复制 | 无 | `rsync -avc ./` 到 `sv:/data/pkg/apt`，不删除目标额外文件 | R3：SSH/rsync 外部依赖，无 manifest/checkpoint | 若 sv 是正式 target，需冻结具体 target 能力；否则迁出仓库发布 SOP | 范围缺口/未验证 | RB-X |
| APT-40 | `pushd` | 开发机镜像 | 无 | 带 `--delete` 推整个 APT 树到 sv | R4：远端大范围删除，方向误用危险 | 不直接迁入；正式发布只能走受跟踪的 `sow publish --target <frozen>` | 范围缺口/未验证 | RB-X、RB-P |
| APT-41 | `pull` | 开发机复制 | 无 | 从 sv 增量复制到本地，不删本地额外文件 | R2：可覆盖本地正典；远端反客为主 | SOW 以本地为真相，不提供日常 pull；只允许受控一次性纳管程序 | 范围缺口/未验证 | RB-L、RB-X |
| APT-42 | `pulld` | 开发机镜像 | 无 | 从 sv 带 `--delete` 覆盖本地整棵 APT 树 | R4：可删除本地正典、manifest 和工作文件 | 禁止迁入日常 CLI；一次性迁移须只读下载到隔离目录再 init | 策略禁止/未验证 | RB-L、RB-X |
| APT-43 | `upload` | 双目标编排 | `cf-upload cos-upload` | 发布 CF 与 COS 的 infra/pgsql | R3：任一目标可部分成功，无独立 ref | `sow publish --type apt --repo infra,pgsql --target cf,cos` | 未迁移/未验证 | RB-P |
| APT-44 | `upload-infra` | 双目标编排 | `cf-infra cos-infra` | 发布 APT infra 到两端 | R3：部分成功 | `sow publish --type apt --repo infra --target cf,cos` | 未迁移/未验证 | RB-P |
| APT-45 | `upload-pgsql` | 双目标编排 | `cf-pgsql cos-pgsql` | 发布 APT pgsql 到两端 | R3：部分成功 | `sow publish --type apt --repo pgsql --target cf,cos` | 未迁移/未验证 | RB-P |
| APT-46 | `cf-upload` | CF 编排 | `cf-infra cf-pgsql` | 发布两个 APT repo 到 CF | R3：部分成功 | `sow publish --type apt --repo infra,pgsql --target cf` | 未迁移/未验证 | RB-P |
| APT-47 | `cf-infra` | APT 发布 | 无 | `rclone sync ./infra/` 到 CF `/apt/infra/` | R3：远端删除，无 InRelease 最后翻转/purge | `sow publish --type apt --repo infra --target cf` | 未迁移/未验证 | RB-P |
| APT-48 | `cf-pgsql` | APT 发布 | 无 | 同步全部 `./pgsql/` 到 CF `/apt/pgsql/` | R3：七 suite 可在上传过程中不一致 | `sow publish --type apt --repo pgsql --target cf` | 未迁移/未验证 | RB-P |
| APT-49 | `cf-jammy` | APT suite 发布 | 无 | 同步 pgsql/jammy 到 CF 对应路径 | R3：远端删除，无翻转/purge | `sow publish --type apt --repo pgsql --os jammy --target cf` | 未迁移/未验证 | RB-P |
| APT-50 | `cf-noble` | APT suite 发布 | 无 | 同步 noble 到 CF | R3：同上 | `sow publish --type apt --repo pgsql --os noble --target cf` | 未迁移/未验证 | RB-P |
| APT-51 | `cf-resolute` | APT suite 发布 | 无 | 同步 resolute 到 CF | R3：同上 | `sow publish --type apt --repo pgsql --os resolute --target cf` | 未迁移/未验证 | RB-P |
| APT-52 | `cf-focal` | APT suite 发布 | 无 | 同步 focal 到 CF | R3：同上；EOL | `sow publish --type apt --repo pgsql --os focal --target cf`，冻结 view | 未迁移/未验证 | RB-P |
| APT-53 | `cf-bookworm` | APT suite 发布 | 无 | 同步 bookworm 到 CF | R3：同上 | `sow publish --type apt --repo pgsql --os bookworm --target cf` | 未迁移/未验证 | RB-P |
| APT-54 | `cf-bullseye` | APT suite 发布 | 无 | 同步 bullseye 到 CF | R3：同上；EOL | `sow publish --type apt --repo pgsql --os bullseye --target cf`，冻结 view | 未迁移/未验证 | RB-P |
| APT-55 | `cf-trixie` | APT suite 发布 | 无 | 同步 trixie 到 CF | R3：同上 | `sow publish --type apt --repo pgsql --os trixie --target cf` | 未迁移/未验证 | RB-P |
| APT-56 | `cf-mssql` | APT repo 发布 | 无 | 同步 `./mssql/` 到 CF `/apt/mssql/` | R3：远端删除；未在主要编排依赖中 | `sow publish --type apt --repo mssql --target cf`，先纳入配置矩阵 | 未迁移/未验证 | RB-P |
| APT-57 | `cos-upload` | COS 编排 | `cos-infra cos-pgsql` | 发布两个 APT repo 到 COS | R3：部分成功 | `sow publish --type apt --repo infra,pgsql --target cos` | 未迁移/未验证 | RB-P |
| APT-58 | `cos-infra` | APT 发布 | 无 | 同步 infra 到 COS `/apt/infra/` | R3：远端删除，无翻转/purge | `sow publish --type apt --repo infra --target cos` | 未迁移/未验证 | RB-P |
| APT-59 | `cos-pgsql` | APT 发布 | 无 | 同步全部 pgsql 到 COS | R3：suite 间部分状态 | `sow publish --type apt --repo pgsql --target cos` | 未迁移/未验证 | RB-P |
| APT-60 | `cos-focal` | APT suite 发布 | 无 | 同步 focal 到 COS | R3：远端删除；EOL | `sow publish --type apt --repo pgsql --os focal --target cos` | 未迁移/未验证 | RB-P |
| APT-61 | `cos-jammy` | APT suite 发布 | 无 | 同步 jammy 到 COS | R3：远端删除 | `sow publish --type apt --repo pgsql --os jammy --target cos` | 未迁移/未验证 | RB-P |
| APT-62 | `cos-noble` | APT suite 发布 | 无 | 同步 noble 到 COS | R3：远端删除 | `sow publish --type apt --repo pgsql --os noble --target cos` | 未迁移/未验证 | RB-P |
| APT-63 | `cos-resolute` | APT suite 发布 | 无 | 同步 resolute 到 COS | R3：远端删除 | `sow publish --type apt --repo pgsql --os resolute --target cos` | 未迁移/未验证 | RB-P |
| APT-64 | `cos-bullseye` | APT suite 发布 | 无 | 同步 bullseye 到 COS | R3：远端删除；EOL | `sow publish --type apt --repo pgsql --os bullseye --target cos` | 未迁移/未验证 | RB-P |
| APT-65 | `cos-bookworm` | APT suite 发布 | 无 | 同步 bookworm 到 COS | R3：远端删除 | `sow publish --type apt --repo pgsql --os bookworm --target cos` | 未迁移/未验证 | RB-P |
| APT-66 | `cos-trixie` | APT suite 发布 | 无 | 同步 trixie 到 COS | R3：远端删除 | `sow publish --type apt --repo pgsql --os trixie --target cos` | 未迁移/未验证 | RB-P |
| APT-67 | `cos-mssql` | APT repo 发布 | 无 | 同步 mssql 到 COS | R3：远端删除；未在主要编排依赖中 | `sow publish --type apt --repo mssql --target cos` | 未迁移/未验证 | RB-P |
| APT-68 | `parade` | 外部产物收集 | 无 | 从 `~/pgsty/paradedb/` 复制五个 suite 的已构建 deb 到 stash | R2：glob/覆盖、部分复制；不建索引 | 外部 builder 直接把产物路径交给 `sow add --repo pgsql`；不复制 stash | 待退役/未验证 | RB-B、RB-L |
| APT-69 | `get-d13` | 容器产物收集 | 无 | 删除临时目录，从 Docker `d13` 拷包，强制移动到 trixie stash，再删临时目录 | R4：rm -rf/mv -f，依赖容器，部分失败 | 收集留在外部构建流水线；最终目录交 `sow add --os trixie` | 待退役/未验证 | RB-B、RB-L |
| APT-70 | `get-d13a` | 容器产物收集 | 无 | 同上，从 `d13a` 收集另一架构 | R4：同上 | 外部 builder handoff + `sow add --os trixie --arch arm64` | 待退役/未验证 | RB-B、RB-L |

## 6. YUM Makefile：14/14

来源：`/Users/vonng/pgsty/repo/yum/Makefile`。`./build` 实际调用 createrepo_c，并尝试生成 modulemd；这里只记录由 Makefile 触发的可观察职责，不把旧脚本实现带入 SOW。

| ID | target | 类别 | 依赖/别名 | 当前副作用 | 风险 | 未来 SOW 动词 × 选择器 | 状态 | 回滚 |
|---|---|---|---|---|---|---|---|---|
| YUM-01 | `default` | 编排入口 | `sign build` | 先按 mtime 重签近期 rpm，再建 pgsql/infra repodata | R4：改包字节；make -j 时顺序也非事务保证 | 不保留该复合入口；`sow add` 保持上游 rpm 字节并原生建索引，随后 verify/publish | 策略禁止/未验证 | RB-R、RB-X |
| YUM-02 | `build` | YUM 索引编排 | `build-pgsql build-infra` | 为 pgsql 六矩阵和 infra 双架构生成旧式 repodata/modulemd | R2：原地覆盖 repodata；无签名 pair | 正常由 `sow add/rm` 更新索引；重建用 `sow materialize --type yum --repo pgsql,infra` | 未迁移/未验证 | RB-R、RB-X |
| YUM-03 | `build-all` | YUM 索引编排 | `build-pgsql build-infra build-other` | 额外重建 EL7/mssql/ivory/gpsql | R2：多仓部分成功，包含范围外 modulemd | `sow materialize` + repo/OS/arch 选择器；EOL 只允许冻结 ref | 未迁移/未验证 | RB-R、RB-X |
| YUM-04 | `build-infra` | YUM 索引 | 无 | 对 `infra/x86_64`、`infra/aarch64` 调 `./build` | R2：原地 repodata，两个架构可部分成功 | `sow materialize --type yum --repo infra --arch amd64,arm64` | 未迁移/未验证 | RB-R |
| YUM-05 | `build-pgsql` | YUM 索引 | 无 | 对 EL8/9/10 × x86_64/aarch64 六目录建 repodata | R2：六步部分成功 | `sow materialize --type yum --repo pgsql --os el8,el9,el10 --arch amd64,arm64` | 未迁移/未验证 | RB-R |
| YUM-06 | `build-other` | YUM/EOL 索引 | 无 | 重建 pgsql el7、mssql el7/8/9、ivory el7/8/9、gpsql el7/8/9 x86_64 | R2：EOL 与活跃混合；modulemd；不含 ARM 多数路径 | 配置化 repo selector；EOL 走冻结 materialize，不擅自继续活跃构建 | 未迁移/未验证 | RB-R、RB-X |
| YUM-07 | `build-percona` | YUM 上游镜像索引 | 无 | 对 percona EL8/9 × 双架构建 repodata | R2：四步部分成功；可能重建上游元数据 | `sow sync --repo percona` + 原生索引/materialize | 未迁移/未验证 | RB-R |
| YUM-08 | `sign` | RPM 原地重签 | 无 | 对 pgsql/infra 1000 分钟内 rpm 执行 `rpm --addsign` | R4：mtime 非确定、改字节、混淆上游/自建来源 | Day 1 禁止镜像重签；自建包由 builder 签，SOW 只 `verify --level 1` | 策略禁止/未验证 | RB-X；已改字节须从来源/CAS 原件恢复 |
| YUM-09 | `sign10` | RPM 原地重签 | 无 | 对全树 10 分钟内 rpm 重签 | R4：同上，范围由时钟决定 | 不迁移；FR-17 策略门禁 | 策略禁止/未验证 | RB-X、RB-R |
| YUM-10 | `sign100` | RPM 原地重签 | 无 | 对全树 100 分钟内 rpm 重签 | R4 | 不迁移；FR-17 策略门禁 | 策略禁止/未验证 | RB-X、RB-R |
| YUM-11 | `sign1000` | RPM 原地重签 | 无 | 对全树 1000 分钟内 rpm 重签 | R4 | 不迁移；FR-17 策略门禁 | 策略禁止/未验证 | RB-X、RB-R |
| YUM-12 | `sign-all` | RPM 全量重签 | 无 | 对当前树全部 rpm 原地重签 | R4：最大破坏面，无备份/摘要真机门禁 | 不迁移；未来仅在 FR-17 商业条件满足后另行设计 | 策略禁止/未验证 | RB-X、RB-R |
| YUM-13 | `sign-pgsql` | RPM 原地重签 | 无 | 对 pgsql 3000 分钟内 rpm 重签 | R4：上游与自建不区分 | 不迁移；builder 签自建包，SOW 验证 | 策略禁止/未验证 | RB-X、RB-R |
| YUM-14 | `sign-infra` | RPM 原地重签 | 无 | 对 infra 3000 分钟内 rpm 重签 | R4：同上 | 不迁移；builder 签自建包，SOW 验证 | 策略禁止/未验证 | RB-X、RB-R |

## 7. Docker Makefile：40/40

来源：`/Users/vonng/pgsty/repo/docker/Makefile`。该文件是 host-side 容器包装层；SOW 的零外部运行时约束要求最终退役此层，而不是在 Go CLI 中复刻 Docker 生命周期。

| ID | target | 类别 | 依赖/别名 | 当前副作用 | 风险 | 未来 SOW 动词 × 选择器 | 状态 | 回滚 |
|---|---|---|---|---|---|---|---|---|
| DKR-01 | `default` | 帮助入口 | `help` | 打印 Docker wrapper 帮助 | R0 | `sow --help`；Docker 入口退役 | 待退役/未验证 | RB-X |
| DKR-02 | `help` | 帮助 | 无 | 打印容器与内部 make shortcut | R0 | SOW 命令帮助覆盖仓库业务；外部 builder 自有帮助 | 待退役/未验证 | RB-X |
| DKR-03 | `image` | 容器生命周期 | 无 | 校验口令后以 build arg 构建 `dnfupdate` 镜像 | R4：口令出现在命令/build arg，并被引用 Dockerfile 烤入镜像层 | 禁止迁入；纯 Go signing/index engine 替代容器 runtime | 待退役/未验证 | RB-X；删除旧镜像前保留应急环境但不得再注入生产秘密 |
| DKR-04 | `container` | 容器生命周期 | 无 | 忽略错误强删同名容器，再创建并 bind mount host YUM 树 | R4：可删错误容器；容器直接写真实树 | 不迁入；SOW 直接在显式 root 工作 | 待退役/未验证 | RB-X |
| DKR-05 | `up` | 容器生命周期 | 与 `start` 同规则 | 启动容器 | R1 | 无 SOW 对应；退役 | 待退役/未验证 | RB-X |
| DKR-06 | `start` | 同义别名 | 与 `up` 同规则 | 启动容器 | R1 | 无 SOW 对应；退役 | 待退役/未验证 | RB-X |
| DKR-07 | `down` | 容器生命周期 | 与 `stop` 同规则 | 停止容器，忽略错误 | R1 | 无 SOW 对应；退役 | 待退役/未验证 | RB-X |
| DKR-08 | `stop` | 同义别名 | 与 `down` 同规则 | 停止容器 | R1 | 无 SOW 对应；退役 | 待退役/未验证 | RB-X |
| DKR-09 | `rm` | 容器生命周期 | 与 `clean` 同规则 | 强删同名容器，忽略错误 | R2：与 `sow rm` 名称相同但语义完全不同 | 不映射到 `sow rm`；容器操作退役 | 待退役/未验证 | RB-X |
| DKR-10 | `clean` | 同义别名 | 与 `rm` 同规则 | 强删容器 | R2 | 无 SOW 对应；退役 | 待退役/未验证 | RB-X |
| DKR-11 | `purge` | 容器生命周期 | `rm` | 删容器后强删镜像 | R2：不可逆移除应急环境 | 无 SOW 对应；退役 | 待退役/未验证 | RB-X |
| DKR-12 | `rebuild` | 容器编排 | `purge image container up` | 删除并重建镜像/容器 | R4：make -j 下依赖无顺序边；口令进入 build | 无 SOW 对应；原生 CLI 构建由 Go toolchain/CI 管理 | 待退役/未验证 | RB-X |
| DKR-13 | `restart` | 容器编排 | `stop start` | 停止并启动容器 | R2：make -j 顺序不受事务保护 | 无 SOW 对应；退役 | 待退役/未验证 | RB-X |
| DKR-14 | `recreate` | 容器编排 | `rm container up` | 删除并重建容器 | R3：bind mount 写者切换，make -j 顺序风险 | 无 SOW 对应；退役 | 待退役/未验证 | RB-X |
| DKR-15 | `status` | 容器诊断 | 与 `ps` 同规则 | `docker ps` 查看同名容器 | R0 | SOW 状态由 `verify/fsck` 表达；容器诊断退役 | 待退役/未验证 | RB-X |
| DKR-16 | `ps` | 同义别名 | 与 `status` 同规则 | 同上 | R0 | 同上 | 待退役/未验证 | RB-X |
| DKR-17 | `logs` | 容器诊断 | 无 | 持续 tail 容器日志 | R0：阻塞交互 | SOW 输出结构化运行日志；容器日志退役 | 待退役/未验证 | RB-X |
| DKR-18 | `inspect` | 容器诊断 | 无 | `docker inspect` | R0：可能显示环境/挂载细节 | 无 SOW 对应；退役 | 待退役/未验证 | RB-X |
| DKR-19 | `shell` | 容器交互 | 与 `sh` 同规则 | 进入挂载真实 YUM 树的 bash | R4：可任意改 host tree，绕过 manifest | SOW 不提供绕过状态模型的 shell；退役 | 待退役/未验证 | RB-X |
| DKR-20 | `sh` | 同义别名 | 与 `shell` 同规则 | 同上 | R4 | 同上 | 待退役/未验证 | RB-X |
| DKR-21 | `exec` | 容器交互 | `CMD` 参数 | 在挂载真实树的容器执行任意 `bash -lc` | R4：任意命令与 shell 注入面，可绕过所有门禁 | 禁止迁入；所有写操作只能走 SOW 显式动词 | 待退役/未验证 | RB-X |
| DKR-22 | `sign` | YUM wrapper | 容器内 `make sign` | 触发 YUM-08 原地重签 | R4：秘密镜像+改包字节 | FR-17 Day 1 禁止；仅 `sow verify` | 策略禁止/未验证 | RB-X、RB-R |
| DKR-23 | `sign10` | YUM wrapper | 容器内 `make sign10` | 触发 YUM-09 | R4 | 禁止迁入 | 策略禁止/未验证 | RB-X、RB-R |
| DKR-24 | `sign100` | YUM wrapper | 容器内 `make sign100` | 触发 YUM-10 | R4 | 禁止迁入 | 策略禁止/未验证 | RB-X、RB-R |
| DKR-25 | `sign1000` | YUM wrapper | 容器内 `make sign1000` | 触发 YUM-11 | R4 | 禁止迁入 | 策略禁止/未验证 | RB-X、RB-R |
| DKR-26 | `sign-all` | YUM wrapper | 容器内 `make sign-all` | 触发 YUM-12 全量重签 | R4：最大破坏面 | 禁止迁入；未来重签仍受单独商业门禁 | 策略禁止/未验证 | RB-X、RB-R |
| DKR-27 | `sign-pgsql` | YUM wrapper | 容器内 `make sign-pgsql` | 触发 YUM-13 | R4 | 禁止迁入 | 策略禁止/未验证 | RB-X、RB-R |
| DKR-28 | `sign-infra` | YUM wrapper | 容器内 `make sign-infra` | 触发 YUM-14 | R4 | 禁止迁入 | 策略禁止/未验证 | RB-X、RB-R |
| DKR-29 | `build` | YUM wrapper | 容器内 `make build` | 触发 YUM-02，直接改 host repodata | R3：容器/外部 runtime、无原子翻转 | SOW add/rm 自动建索引，或 `sow materialize --repo pgsql,infra` | 待退役/未验证 | RB-R、RB-X |
| DKR-30 | `build-all` | YUM wrapper | 容器内 `make build-all` | 触发 YUM-03 | R3：多仓部分成功 | SOW materialize + 选择器 | 待退役/未验证 | RB-R、RB-X |
| DKR-31 | `build-pgsql` | YUM wrapper | 容器内 `make build-pgsql` | 触发 YUM-05 | R3 | `sow materialize --type yum --repo pgsql` | 待退役/未验证 | RB-R、RB-X |
| DKR-32 | `build-infra` | YUM wrapper | 容器内 `make build-infra` | 触发 YUM-04 | R3 | `sow materialize --type yum --repo infra` | 待退役/未验证 | RB-R、RB-X |
| DKR-33 | `build-other` | YUM wrapper | 容器内 `make build-other` | 触发 YUM-06 | R3：EOL/旧 repo 混合 | 配置化 materialize；EOL 冻结策略 | 待退役/未验证 | RB-R、RB-X |
| DKR-34 | `build-percona` | YUM wrapper | 容器内 `make build-percona` | 触发 YUM-07 | R3 | `sow sync/materialize --repo percona` | 待退役/未验证 | RB-R、RB-X |
| DKR-35 | `pg` | 快捷别名 | 容器内 `make build-pgsql` | 与 DKR-31 相同 | R3 | 显式 repo 选择器替代 | 待退役/未验证 | RB-R、RB-X |
| DKR-36 | `pgsql` | 快捷别名 | 容器内 `make build-pgsql` | 与 DKR-31 相同 | R3 | 显式 repo 选择器替代 | 待退役/未验证 | RB-R、RB-X |
| DKR-37 | `infra` | 快捷别名 | 容器内 `make build-infra` | 与 DKR-32 相同 | R3 | 显式 repo 选择器替代 | 待退役/未验证 | RB-R、RB-X |
| DKR-38 | `other` | 快捷别名 | 容器内 `make build-other` | 与 DKR-33 相同 | R3 | 显式 repo/OS 选择器替代 | 待退役/未验证 | RB-R、RB-X |
| DKR-39 | `percona` | 快捷别名 | 容器内 `make build-percona` | 与 DKR-34 相同 | R3 | 显式 repo 选择器替代 | 待退役/未验证 | RB-R、RB-X |
| DKR-40 | `psql` | 外部调试 | 无 | 在容器启动交互式 psql（若存在） | R1：PG 不是 SOW 核心依赖 | 无 SOW 对应；数据库调试移交外部运维工具 | 待退役/未验证 | RB-X |

## 8. 迁移分类结果

分类不会改变 176 个 `<文件,target>` 对均需处置的事实：

- **必须由 SOW 真实覆盖**：APT/YUM/asset 的 add、rm、索引生成、inventory/orphan 审计、sync、publish、双目标编排、stable/history 保护与 latest 兼容。
- **用选择器消除的别名**：`add-*`、`cf-*`、`co/cos-*`、`upload*`、`build-*` 等。必须对每个旧依赖集合做 selector expansion 黄金测试，尤其是已出错的 `cf-yum`。
- **必须退役而非复刻**：Docker image/container/up/down/shell/exec、stash 清理仪式、外部 gpg/rpm 重签、createrepo/modulemd 容器包装。
- **外部构建/收集移交**：`parade`、`get-d13`、`get-d13a`。造包/容器收集继续属于 builder，但其最终产物必须能直接交给 `sow add`，并有 handoff 文档和 E2E。
- **当前合同缺口**：sv push/pull、`co-pro-get`、`ext-list`/`gen` 的精确兼容输出、鉴权文件部署。这些不能静默丢弃；要么补充可接受的 SOW 语义，要么经 ADR 证明业务流程已废止并给出替代操作面。

## 9. G5 与退役验收门禁

G5 当前状态仍为 **未验证**。必须同时满足以下条件后才能把本账本或总追踪矩阵中的 G5 标为通过：

1. 176 个 `<文件,target>` 对全部有最终处置；本文件不存在 `未迁移/未验证`、`范围缺口/未验证`、`待退役/未验证` 或 `策略禁止/未验证`。
2. 每个业务 target 都有真实 CLI E2E，证明选择器展开、文件集合、索引结果、签名、远端差异、purge 和发布后验证。
3. `cf-yum` 回归测试证明只选择 `yum/infra` 与 `yum/pgsql`，绝不触碰 APT。
4. rclone `sync` 的隐式删除语义已被 manifest diff、引用保护、checkpoint 和显式 GC 取代；不得通过“新 CLI 也做全量 sync”冒充等价。
5. CF/COS 各自滞后、失败重放和回滚均演练；一个目标成功、另一个失败时状态可解释且可恢复。
6. `/pkg/pig/latest` 正文版本指针、现有 APT/YUM channel-less URL 和其他公开 asset URL 有迁移前基线、迁移后真实 HTTP/apt/dnf 回归。
7. Docker wrapper、外部 gpg/rpm、reprepro、createrepo_c、modulemd、rclone、rsync 不再是 SOW 日常运行时依赖。
8. 外部 builder handoff 已文档化并验证，不把造包责任偷渡进 SOW，也不遗漏最终 `sow add`。
9. 所有破坏性迁移先执行 RB-L 基线与备份；从旧写者切换后禁止两套工具同时修改同一发布树。
10. 完成一次独立审计：重新静态枚举四个 Makefile target，与本账本逐项比对，并保存机器可读差异为零的证据。

## 10. 尚未执行的验证

本次只有静态文件审计。以下均未执行、不得据此声称通过：

- 任何旧 Make target；
- 任何 rclone/rsync/Docker/reprepro/rpm/createrepo 命令；
- CF/COS 对象清单和 checkpoint；
- 公开 URL、重定向、内容、签名或 CDN 缓存；
- SOW CLI 的任何等价命令；
- 迁移、回滚、故障注入或真实 apt/dnf 消费。
