# 旧 Makefile → SOW 迁移账本

> 状态：176/176 旧目标已形成机器可审计处置，44 个操作族已证明是精确分区；当前 CLI
> 动词/flag 及表内 repo/os/arch selector 已由脚本和完整物理 Pigsty-v1 配置验证；
> 本地 Pigsty-v1 布局 adoption/回滚夹具已执行。生产旧树切换、真实 URL、旧 writer 撤权
> 与双云/CDN 回滚仍未验证。
> 审计日期：2026-07-14
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

表中反引号包裹的 `sow ...` 是按当前二进制校验的命令模板，不是未来语法。模板中的
`<files>`、`<sha256>` 等仍需操作员替换，repo ID 则要求迁移配置采用表中不冲突的
`apt-*`、`yum-*`、`asset-*` 命名。机器处置闭合只证明“没有漏 target、没有悬空语义”，
不等于生产迁移或远端验证已经完成。

### 1.1 “约 40”如何由真实文件得到

当前文件不是字面上的约 40 个 target，而是 **176 个普通命名 target**。按“同一副作用、仅 selector/alias/wrapper 不同”做互斥归并，得到 **44 个操作族**。这给出了“约 40”的可复核含义，而不是用 PRD 数字替代盘点。每个 target 只落入下表一个族，族内计数总和仍为 176。

| 族 | 真实 target（同前缀） | 数量 |
|---|---|---:|
| R01 | ROOT `copy-auth` | 1 |
| R02 | ROOT `copy-bin copy-beta` | 2 |
| R03 | ROOT `co-img` | 1 |
| R04 | ROOT `ext-list` | 1 |
| R05 | ROOT `cf-ext co-ext` | 2 |
| R06 | ROOT `md5-src` | 1 |
| R07 | ROOT `cf-src co-src up-src ss` | 4 |
| R08 | ROOT `cf-pig co-pig up-pig` | 3 |
| R09 | ROOT `co-claude` | 1 |
| R10 | ROOT `co-ray` | 1 |
| R11 | ROOT `cf-etc co-etc up-etc` | 3 |
| R12 | ROOT `cf-dba co-dba up-dba` | 3 |
| R13 | ROOT `co-upload co-infra co-pgsql co-pgdg co-percona co-apt co-yum cf-upload cf-infra cf-pgsql cf-percona cf-apt cf-yum` | 13 |
| R14 | ROOT `co-yum-infra co-yum-pgsql co-yum-pgdg co-yum-percona cf-yum-infra cf-yum-pgsql cf-yum-percona` | 7 |
| R15 | ROOT `co-apt-infra co-apt-pgsql co-apt-pgdg co-apt-percona cf-apt-infra cf-apt-pgsql cf-apt-percona` | 7 |
| R16 | ROOT `co-pro-get co-pro` | 2 |
| A01 | APT `init` | 1 |
| A02 | APT `clean purge` | 2 |
| A03 | APT `add-infra` | 1 |
| A04 | APT `add-percona` | 1 |
| A05 | APT `add-oss add-all add-debian add-ubuntu add-focal add-jammy add-noble add-resolute add-bullseye add-bookworm add-trixie adda` | 12 |
| A06 | APT `ls-infra ls-focal ls-jammy ls-noble ls-resolute ls-bullseye ls-bookworm ls-trixie` | 8 |
| A07 | APT `rm-pig` | 1 |
| A08 | APT `trim-dump trim` | 2 |
| A09 | APT `pgsql-include` | 1 |
| A10 | APT `init-all init-focal init-jammy init-noble init-resolute init-bullseye init-bookworm init-trixie` | 8 |
| A11 | APT `gen` | 1 |
| A12 | APT `push pushd pull pulld` | 4 |
| A13 | APT `upload upload-infra upload-pgsql cf-upload cf-infra cf-pgsql cf-jammy cf-noble cf-resolute cf-focal cf-bookworm cf-bullseye cf-trixie cf-mssql cos-upload cos-infra cos-pgsql cos-focal cos-jammy cos-noble cos-resolute cos-bullseye cos-bookworm cos-trixie cos-mssql` | 25 |
| A14 | APT `parade` | 1 |
| A15 | APT `get-d13 get-d13a` | 2 |
| Y01 | YUM `default` | 1 |
| Y02 | YUM `build build-infra build-pgsql` | 3 |
| Y03 | YUM `build-all build-other` | 2 |
| Y04 | YUM `build-percona` | 1 |
| Y05 | YUM `sign sign10 sign100 sign1000 sign-pgsql sign-infra` | 6 |
| Y06 | YUM `sign-all` | 1 |
| D01 | DKR `default help` | 2 |
| D02 | DKR `image container up start down stop rm clean purge rebuild restart recreate` | 12 |
| D03 | DKR `status ps logs inspect` | 4 |
| D04 | DKR `shell sh exec` | 3 |
| D05 | DKR `sign sign10 sign100 sign1000 sign-all sign-pgsql sign-infra` | 7 |
| D06 | DKR `build build-all build-pgsql build-infra build-other build-percona pg pgsql infra other percona` | 11 |
| D07 | DKR `psql` | 1 |
| **合计** | **16 + 15 + 6 + 7 = 44 个操作族** | **176** |

这 44 族不是 SOW 必须复制的 44 个命令：R13/A13 等笛卡尔积别名应由 selector 消除；D02–D07 多数应退役或移交；Y05/Y06 必须按 FR-17 禁止，而不是复刻。

### 1.2 可重复审计与输入指纹

执行下列命令会重新解析四个 Makefile，逐项比较 176 个 target，校验输入文件固定摘要、
行号/ID/处置枚举/回滚码，并临时构建当前 SOW 二进制探测表内每个动词和 flag。任何 source
内容变化（即使 target 名不变）、表行缺失、未知处置或 CLI 漂移都会非零退出；只有所有
门禁通过后才会写出规范化 TSV：

```bash
docs/migration/audit-legacy-targets.sh \
  --legacy-root /Users/vonng/pgsty/repo \
  --emit-tsv /absolute/evidence/legacy-target-map.tsv

docs/migration/test-audit-legacy-targets.sh /Users/vonng/pgsty/repo
docs/migration/test-family-e2e.sh
```

2026-07-12 审计输入为：

| 文件 | SHA-256 |
|---|---|
| root `Makefile` | `434851089902ebc3f0ab402c81a3b407a420a4f4ec9c8368a10494f21d4c1a8c` |
| `apt/Makefile` | `1077efce002f193466351f16424841a9d7eecc4e8ca61382cf4ba7b5635c8945` |
| `apt/list/gen` | `d1f89aea35e672c10b0e0e0151035f34f2ed3d2be039d61dee10ad65393a118c` |
| `yum/Makefile` | `32a7800a577213e4b257a4116f75986a95a55e8b8909baa8bc54f475cb4953f3` |
| `yum/build` | `e7837003d1498dd80d1ab7aded299c5b577399b37a8257c7e81c5427f795c27a` |
| `docker/Makefile` | `1629076293514cadb1fcaf8b2e734ff1b715bd9af4a086f56c3a4284e38bfd2e` |
| `docker/Dockerfile` | `f9d821210669b82132e3232581e3aa69d98256c2e1257b30ed59ddb8f7ba4966` |

普通 target 的 176 不含特殊 `.PHONY` 声明。YUM 的 `.PHONE` 不是特殊声明，而是拼写错误形成的真实 dot-rule；它又依赖不存在的 `build-extra`。审计脚本把这两个语法异常单独锁定，不把它们伪装成业务能力。

审计使用两个不同目的的非秘密配置，不能混为生产配置：

- [`fixtures/pigsty-v1.yaml`](fixtures/pigsty-v1.yaml) 与
  [`fixtures/pigsty-v1-migration-ledger.tsv`](fixtures/pigsty-v1-migration-ledger.tsv) 共同构成
  完整本地物理迁移合同：98 repo ID / 135 ledger row 精确展开 74 个 APT index 与
  130 个 ordinary YUM leaf，并逐项处置 1 个 EL9 compatibility policy owner、2 个精确
  compatibility projection、1 个 nested child、7 个根 exact key、8 个根 prefix 和 16 个 gated pro
  文件。Pro owner 已在只读生产源精确副本完成本地 stable adoption/checksum replacement，
  其生产 cutover 仍未声明；合同不含 target endpoint、cloud credential、私钥或 entitlement。
  其余 signer/lifecycle 未验证项仍显式保留为 non-claim。两个 `yum/infra/{arch}` leaf 由同一个 inactive、
  不可选 carrier 承载；aarch64/x86_64 projection 显式绑定专用 policy owner，且二者都不进入普通 group。
- [`fixtures/pigsty-v1-synthetic.yaml`](fixtures/pigsty-v1-synthetic.yaml) 保留原来的 12-repo
  pgsql 局部形状，只供 legacy parser/adoption 回归，禁止再称为完整 physical fixture。
- [`fixtures/selector-matrix.yaml`](fixtures/selector-matrix.yaml) 仅保留为 33-repo / 73-leaf
  通用选择器回归，不再充当迁移映射的 oracle。`TestLegacyMigrationMapClosesFamiliesAndSelectors`
  逐条解析 176 行命令模板，改用完整 `pigsty-v1.yaml` 展开 repo/group/os/arch，并把每条命令的
  suite/component/OS/arch/source/route/lifecycle 精确 tuple 集与
  [`make-target-selector-golden.tsv`](fixtures/make-target-selector-golden.tsv) 的独立摘要比较；同数量
  换叶、物理 ID/路径漂移或把 compatibility carrier 混入普通 selector 均失败。它不执行远端业务副作用，
  因而不冒充逐 target E2E。
- [`fixtures/family-e2e.tsv`](fixtures/family-e2e.tsv) 为 44 个操作族逐项绑定真实
  CLI/filesystem/DEB/RPM/parser/provider-protocol 测试，或显式 retire/policy/handoff/migration
  contract。`test-family-e2e.sh` 以 `GOPROXY=off` 运行其中所有 16 个去重测试（含直接加载
  physical config 的 aarch64 与 Nginx/Edge x86_64 compatibility 状态机）及实际二进制
  adoption/rollback，并用 4 个临时突变夹具证明缺族、Help 冒充、错误 disposition 与 publish
  缺 provider 均 fail closed；本地 provider protocol 不冒充真实云。

## 2. 状态、风险与回滚代码

### 2.1 机器处置 schema

四张目标表共同构成 `sow-legacy-target-map/v1`。审核脚本只接受下列闭合枚举：
处置边界的架构决定见 [ADR-0005](../adr/0005-legacy-make-target-dispositions.md)。

- `sow-cli`：旧业务副作用由当前 SOW 动词/选择器取代；替代列必须至少含一条可探测的
  `` `sow ...` `` 命令模板。
- `retire`：旧目标只服务于已废止的 stash/reprepro/container 辅助面，无运行时替代。
- `policy-reject`：旧行为违反冻结策略（秘密烤镜像、原地 RPM 重签、任意 shell、无状态
  `--delete` 等），必须禁止而不是移植。
- `external-handoff`：造包、容器收集、文档/checksum/兼容 asset 正文生成，或非 cf/cos
  文件传输属于外部 builder/运维；边界止于最终 canonical 制品交给 `sow add`。
- `migration-only`：只允许在冻结窗口把旧远端下载到隔离目录，再以
  `sow init --adopt-content` 纳管；不提供长期 pull。

处置值不携带“已生产验证”的含义。真实 E2E 与退役门禁在第 9 节单独判定。

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
- `RB-B`：保留外部构建/生成/收集流水线；SOW 只接收其最终 asset/deb/rpm，不负责回滚构建系统。

## 3. 必须先修正或冻结的现状

### 3.1 已确认的静态缺陷与危险语义

1. **`cf-yum` 错依赖已确认**：`LEGACY-ROOT:L105` 依赖 `cf-yum-infra cf-apt-pgsql`，第二项应是 YUM pgsql 路径而不是 APT。它会漏传 `yum/pgsql` 并意外触发 `apt/pgsql` 上传。普通叶子的映射必须是 `sow publish --target cf --repo yum-pgsql`；mixed-EL `yum/infra/{arch}` 不得伪装成普通 selector，只能走 ADR-0021 的 compatibility 状态机。两部分均由物理选择器/专用命令门禁锁死。
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
17. APT `gen` 直接调用 `apt/list/gen`；该脚本硬编码 `cd ~/pgsty/repo/apt`，用 reprepro 重写 7 个 `list/pgsql.<suite>` 和 `list/infra`，随后 Makefile 只打印 `git diff`。这些 list 文件是自定义派生产物，不等同于客户端 Packages 索引。
18. `yum/build` 对每个输入目录先原地运行 `createrepo_c`，再默认执行 `repo2module` 与 `modifyrepo_c`。其 EL7 判断检查的是目录内容是否含字符串 `el7`，不是输入路径名，不能可靠阻止 modulemd。SOW 不继承该行为。
19. Dockerfile 将 `private.asc` 复制进 build context layer，并把 passphrase 写入 `/root/.rpmmacros`；后续删除 `/tmp/private.asc` 不能从既有镜像层清除秘密。本审计只记录文件指纹，未读取或持久化私钥内容。

### 3.2 `latest` URL 基线

以下是**本地树和 Makefile 的静态基线，不是远端已验证结果**：

- CF 根为 `cf:/repo`，COS 根为 `cos:/repo-1304744452`（`LEGACY-ROOT:L3-L5`）。
- 根 Makefile 注释明确列出 `https://repo.pigsty.io/pkg/pig/latest`，并列出 `/get`、`/src/checksums`、`/src/pigsty-*.tgz` 与 `/pkg/pig/v*/`（`LEGACY-ROOT:L121-L128`）。
- 本地 `/Users/vonng/pgsty/repo/pkg/pig/latest` 是 5 字节普通文件，当前内容为 `1.5.1`；它随 `cf-pig`/`co-pig` 整目录发布到两端 `/pkg/pig/latest`。基线 URL 是 `https://repo.pigsty.io/pkg/pig/latest`，国内对应路径为 `https://repo.pigsty.cc/pkg/pig/latest`（后者尚未做远端 HTTP 验证）。该文件 URL 和“正文为版本号”的语义必须保持兼容。
- 本地 `/Users/vonng/pgsty/repo/pkg/ray/latest` 是 6 字节普通文件，当前内容为 `5.44.1`，由 `co-ray` 发布到 COS `/pkg/ray/latest`；它也是 asset 兼容基线，但不是 repository channel。
- APT 当前公开布局没有 `/latest/` 段：现有路径直接位于 `/apt/infra/`、`/apt/pgsql/` 及其 suite 子树；YUM 同理直接位于 `/yum/infra/`、`/yum/pgsql/` 等。未来 `latest` 视图必须继续物化在这些现有路径，新 beta/stable/snapshot 命名空间不得迫使 OSS 客户改 URL。
- 当前 asset 根还发布 `/get`、`/pig`、`/pkg`、`/beta`、`/ray`、`/cc`、`/claude`、`/img/`、`/ext/`、`/src/`、`/pkg/pig/`、`/pkg/claude/`、`/pkg/ray/`、`/etc/`、`/dba/`。这里的 `/beta` 是引导脚本文件，不应与未来 repository `beta` view 混淆。
- 远端域名到对象根、HTTP 状态、重定向、ETag、实际内容和 CDN 缓存尚未在本账本中验证，迁移前必须另存 URL 清单和响应摘要。

### 3.3 2026-07-12 当前 SOW CLI 真相

本次从当前工作树构建并执行了 `sow help` 和各命令 `--help`。命令“存在”只说明调用面已接入，不代表已经通过本账本的旧行为等价验证。

| 命令 | 当前接入 | 当前选择面/边界 | 对迁移的含义 |
|---|---|---|---|
| `init` | 是 | `repo/os/arch`；`--adopt-content --view latest,stable`；可选 public-only `--legacy-metadata-keyring` | 默认零字节 baseline；显式 adoption 从真实索引/CAS 建 view，不改服务树；旧 YUM metadata 签名只在显式 keyring 下声明 verified |
| `fsck` | 是 | 本地 `repo/os/arch`；远端 `target`；显式 `--adopt-remote-inventory` | 本地全量 drift；远端双 List/HEAD/GET adoption 与垃圾报告；不是 L1–L4 的别名 |
| `add` | 是 | `repo/os/arch` + `type=auto|asset|rpm|deb`；APT component；view 由 pool/debug 决定 | DEB/RPM/asset 进入 CAS、view、索引和服务树；没有 `--view` |
| `rm` | 是 | `repo/os/arch/view` | 已有 mutable-view 调用面；stable/frozen 保护仍需迁移 E2E |
| `sync` | 是 | `upstream/repo/os/arch` | 已有调用面；真实 PGDG/Percona、断点和 provenance 迁移证据未完成 |
| `gc` | 是 | 全局 root；默认 dry-run；`--apply --confirm <orphan-set-sha256>` | 完整替代物理 trim；迁移冻结期先只运行 dry-run |
| `promote` | 是 | `repo/os/arch` + source/destination view | ref 运算存在；promote 后完整 serving index 更新尚无迁移 E2E |
| `materialize` | 是 | 必需 view/snapshot positional；`repo/os/arch`；可选 target/tgz | latest 可刷新服务树；专用 target 为隔离 hardlink 投影；不是客户端验收的替代物 |
| `publish` | 是 | `view` 或 `snapshot` × `target cf,cos` × `repo/os/arch` | 差异上传、checkpoint、翻转、purge、L3/L4 后按目标独立提交；真实云仍需凭据验收 |
| `verify` | 是 | `--layer L1,L2,L3,L4|all` × view/snapshot/target/repo/os/arch | 四层都有真实检查；L3/L4 是 Go 协议探针，系统 apt/dnf 与供应商边缘仍是独立兼容证据 |

审核脚本会拒绝表中不存在的动词或 flag；repo 类型通过唯一 repo ID 表达，不虚构
`publish/fsck/materialize --type`，校验层只使用 `--layer`。如果 CLI surface 变化，必须先更新
实现/映射并重新生成 TSV，不能让文档继续漂移。

## 4. 根 Makefile：52/52

来源：`/Users/vonng/pgsty/repo/Makefile`。

| ID | target | 类别 | 依赖/别名 | 当前副作用 | 风险 | 当前替代/明确边界（生产证据另计） | 机器处置 | 回滚 |
|---|---|---|---|---|---|---|---|---|
| ROOT-01 | `copy-auth` | Pro 鉴权配置 | 无 | `rclone copyto` 将本地 `bin/fileauth.txt` 覆盖到 COS 根 `/fileauth.txt` | R4：安全敏感文件，单对象覆盖，无版本/验证 | 退役根目录 `fileauth.txt`；授权数据改由边缘 entitlement/secret provider 注入，禁止作为 asset 发布 | policy-reject | RB-X |
| ROOT-02 | `copy-bin` | asset 业务 | 无 | 以 `get.io/get.cc`、`pig.io/pig.cc`、`pkg.io/pkg.cc` 向 CF/COS 同名 key 发布不同正文；另写 COS `/cc,/claude` | R3：多个单对象可部分成功，无 purge；同 key 双正文违背单一 canonical view | 退役 target-specific bundle。受审 external builder 已钉住六个源 identity，生成 mirror-aware canonical `get/pig/pkg`；最终逐个执行 `sow add <file> --repo asset-root-both --dest <key>` 与 `sow publish --repo asset-root-both --target cf,cos`。真实 SOW 本地 handoff 已通过且对应 physical owner 按 exact affinity 激活；COS-only `/cc`、`/claude` 由独立 `asset-root-cos` exact-copy owner 管理。真实 URL/cutover/publish 仍 pending | external-handoff | RB-B、RB-A、RB-P |
| ROOT-03 | `copy-beta` | asset 业务 | 无 | 以 `beta.io/beta.cc` 向两端 `/beta` 发布不同正文，另写 COS `/ray` | R3：部分成功；同 key 双正文违背单一 canonical view；名称与 repo beta view 易混 | 同一 builder 已把两个 beta 源收敛为 canonical `/beta`；最终执行 `sow add <file> --repo asset-root-both --dest beta` 与 `sow publish --repo asset-root-both --target cf,cos`。真实 SOW 本地 handoff和 COS-only `/ray` 的 `asset-root-cos` exact-copy 已通过，physical owners 已按 exact affinity 激活；生产 URL/cutover 仍 pending | external-handoff | RB-B、RB-A、RB-P |
| ROOT-04 | `co-img` | asset 业务 | 无 | 只上传 24h 内 `img/` 到 COS，`copy` 不删远端 | R1/R3：时间窗可能漏文件；无 manifest | `sow add <files> --repo asset-img` 后 `sow publish --repo asset-img --target cos`，按 manifest 差异 | sow-cli | RB-A、RB-P |
| ROOT-05 | `ext-list` | 辅助清单 | 无 | `ls -a` 覆盖 `pkg/ext/README.md` | R1：包含 `.`/`..`，格式非稳定契约 | 退役不稳定的 `ls -a` 派生产物；如该 README 仍属公开契约，由文档/构建流水线生成后作为普通 asset 交给 `sow add <README.md> --repo asset-ext` | external-handoff | RB-B、RB-L |
| ROOT-06 | `cf-ext` | asset 发布 | 无 | `rclone sync ext/` 到 CF `/ext/` | R3：删除远端多余对象，无 purge | `sow publish --repo asset-ext --target cf` | sow-cli | RB-A、RB-P |
| ROOT-07 | `co-ext` | asset 发布 | 无 | `rclone sync ext/` 到 COS `/ext/` | R3：同上 | `sow publish --repo asset-ext --target cos` | sow-cli | RB-A、RB-P |
| ROOT-08 | `md5-src` | asset 元数据 | 无 | `md5sum *.tgz` 覆盖 `src/checksums` | R1：外部运行时、MD5、空 glob 风险 | SOW manifest 以 SHA-256 为正典；若旧 `src/checksums` URL 仍需保留，由制品构建流水线生成该兼容文件后执行 `sow add <checksums> --repo asset-src --dest checksums` | external-handoff | RB-B、RB-L |
| ROOT-09 | `cf-src` | asset 发布 | 无 | `rclone sync src/` 到 CF `/src/` | R3：远端删除，无 purge | `sow publish --repo asset-src --target cf` | sow-cli | RB-A、RB-P |
| ROOT-10 | `co-src` | asset 发布 | 无 | `rclone sync src/` 到 COS `/src/` | R3：远端删除，无 purge | `sow publish --repo asset-src --target cos` | sow-cli | RB-A、RB-P |
| ROOT-11 | `cf-pig` | asset 发布 | 无 | 同步 `pkg/pig/` 到 CF，含 `/latest` 指针 | R3：可能删历史版本或 latest，无原子指针 | `sow publish --repo asset-pkg-pig --target cf`；latest 兼容门禁 | sow-cli | RB-A、RB-P |
| ROOT-12 | `co-pig` | asset 发布 | 无 | 同步 `pkg/pig/` 到 COS | R3：同上；注释所称 MAX_AGE 实际未生效 | `sow publish --repo asset-pkg-pig --target cos` | sow-cli | RB-A、RB-P |
| ROOT-13 | `co-claude` | asset 发布 | 无 | 同步 `pkg/claude/` 到 COS | R3：远端删除 | `sow publish --repo asset-pkg-claude --target cos` | sow-cli | RB-A、RB-P |
| ROOT-14 | `co-ray` | asset 发布 | 无 | 同步 `pkg/ray/` 到 COS | R3：远端删除，可能影响 `/latest` | `sow publish --repo asset-pkg-ray --target cos` | sow-cli | RB-A、RB-P |
| ROOT-15 | `cf-etc` | asset 发布 | 无 | 同步 `etc/` 到 CF | R3：远端删除 | `sow publish --repo asset-etc --target cf` | sow-cli | RB-A、RB-P |
| ROOT-16 | `co-etc` | asset 发布 | 无 | 同步 `etc/` 到 COS | R3：远端删除 | `sow publish --repo asset-etc --target cos` | sow-cli | RB-A、RB-P |
| ROOT-17 | `cf-dba` | asset 发布 | 无 | 同步 `dba/` 到 CF | R3：远端删除 | `sow publish --repo asset-dba --target cf` | sow-cli | RB-A、RB-P |
| ROOT-18 | `co-dba` | asset 发布 | 无 | 同步 `dba/` 到 COS | R3：远端删除 | `sow publish --repo asset-dba --target cos` | sow-cli | RB-A、RB-P |
| ROOT-19 | `up-pig` | 编排别名 | `co-pig cf-pig` | 依赖顺序上传两端；任一端可独立成功 | R3：没有目标独立 checkpoint | `sow publish --repo asset-pkg-pig --target cf,cos` | sow-cli | RB-P |
| ROOT-20 | `up-dba` | 编排别名 | `co-dba cf-dba` | 上传两端 dba | R3：部分成功 | `sow publish --repo asset-dba --target cf,cos` | sow-cli | RB-P |
| ROOT-21 | `up-etc` | 编排别名 | `co-etc cf-etc` | 上传两端 etc | R3：部分成功 | `sow publish --repo asset-etc --target cf,cos` | sow-cli | RB-P |
| ROOT-22 | `up-src` | 编排别名 | `md5-src co-src cf-src` | 生成 checksums、上传两端、打印两个拼错域名 | R3：部分成功且输出误导 | 兼容文件先 `sow add <files> --repo asset-src`，再 `sow materialize latest --repo asset-src` 与 `sow publish --repo asset-src --target cf,cos` | sow-cli | RB-A、RB-P |
| ROOT-23 | `ss` | 别名 | `up-src` | 完全继承 up-src | R3：同上 | 与 ROOT-22 相同：`sow add <files> --repo asset-src` 后 `sow publish --repo asset-src --target cf,cos`；旧别名退役 | sow-cli | RB-A、RB-P |
| ROOT-24 | `co-upload` | 编排别名 | `co-infra co-pgsql` | COS 上传 APT+YUM 的 infra/pgsql | R3：四棵树可部分成功 | 普通叶子执行 `sow publish --target cos --repo apt-infra,apt-pgsql,yum-pgsql`；mixed-EL infra 只随 ADR-0021 已激活 projection 的 policy owner 发布，不能进入普通 selector | sow-cli | RB-P |
| ROOT-25 | `co-infra` | 编排别名 | `co-apt-infra co-yum-infra` | COS 上传 APT/YUM infra | R3：部分成功 | APT 执行 `sow publish --target cos --repo apt-infra`；mixed-EL YUM 先逐 projection 执行 `sow compatibility yum-adopt --id <id>` 及 ADR-0021 S1→S3 流程，再随 exact policy owner 发布 | sow-cli | RB-P |
| ROOT-26 | `co-pgsql` | 编排别名 | `co-apt-pgsql co-yum-pgsql` | COS 上传 APT/YUM pgsql | R3：部分成功 | `sow publish --target cos --repo apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie,yum-pgsql-el7,yum-pgsql-el8,yum-pgsql-el9,yum-pgsql-el10` | sow-cli | RB-P |
| ROOT-27 | `co-pgdg` | 编排别名 | `co-apt-pgdg co-yum-pgdg` | COS 上传 APT/YUM pgdg | R3：部分成功 | `sow publish --target cos --repo apt-pgdg,yum-pgdg` | sow-cli | RB-P |
| ROOT-28 | `co-percona` | 编排别名 | `co-apt-percona co-yum-percona` | COS 上传 APT/YUM percona | R3：部分成功 | `sow publish --target cos --repo apt-percona,yum-percona` | sow-cli | RB-P |
| ROOT-29 | `co-apt` | 编排别名 | `co-apt-infra co-apt-pgsql` | COS 上传两个 APT repo，不含 pgdg/percona | R3：名称看似“全部”但只是子集 | `sow publish --target cos --repo apt-infra,apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie` | sow-cli | RB-P |
| ROOT-30 | `co-yum` | 编排别名 | `co-yum-infra co-yum-pgsql` | COS 上传两个 YUM repo，不含 pgdg/percona | R3：同上 | 普通叶子执行 `sow publish --target cos --repo yum-pgsql`；mixed-EL infra 只随 ADR-0021 已激活 projection 的 exact policy owner 发布 | sow-cli | RB-P |
| ROOT-31 | `co-yum-infra` | YUM 发布 | 无 | `rclone sync yum/infra/` 到 COS | R3：远端删除，无 repomd pair/purge | 禁止普通 repo selector；逐 projection 由 `sow compatibility yum-adopt --id <id>` 开始完成 ADR-0021 S0→S3，最终随 exact policy owner 的 latest publish 原子发布 | sow-cli | RB-P |
| ROOT-32 | `co-yum-pgsql` | YUM 发布 | 无 | 同步 `yum/pgsql/` 到 COS | R3：同上 | `sow publish --target cos --repo yum-pgsql-el7,yum-pgsql-el8,yum-pgsql-el9,yum-pgsql-el10` | sow-cli | RB-P |
| ROOT-33 | `co-yum-pgdg` | YUM 上游镜像发布 | 无 | 同步 `yum/pgdg/` 到 COS | R3：远端删除上游历史的可能性 | `sow sync --repo yum-pgdg` 后 `sow publish --target cos --repo yum-pgdg` | sow-cli | RB-P |
| ROOT-34 | `co-yum-percona` | YUM 上游镜像发布 | 无 | 同步 `yum/percona/` 到 COS | R3：同上 | `sow sync --repo yum-percona` 后 `sow publish --target cos --repo yum-percona` | sow-cli | RB-P |
| ROOT-35 | `co-apt-infra` | APT 发布 | 无 | 同步 `apt/infra/` 到 COS | R3：远端删除，无 InRelease 翻转/purge | `sow publish --target cos --repo apt-infra` | sow-cli | RB-P |
| ROOT-36 | `co-apt-pgsql` | APT 发布 | 无 | 同步 `apt/pgsql/` 到 COS | R3：同上 | `sow publish --target cos --repo apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie` | sow-cli | RB-P |
| ROOT-37 | `co-apt-pgdg` | APT 上游镜像发布 | 无 | 同步 `apt/pgdg/` 到 COS | R3：远端删除上游历史的可能性 | `sow sync --repo apt-pgdg` 后 `sow publish --target cos --repo apt-pgdg` | sow-cli | RB-P |
| ROOT-38 | `co-apt-percona` | APT 上游镜像发布 | 无 | 同步 `apt/percona/` 到 COS | R3：同上 | `sow sync --repo apt-percona` 后 `sow publish --target cos --repo apt-percona` | sow-cli | RB-P |
| ROOT-39 | `co-pro-get` | 旧 Pro 拉取 | 无 | `rclone sync` 从 COS `/pro/` 到本地 `pro/`，会删除本地多余文件 | R3：反向破坏本地；旧双仓设计已废止 | 仅迁移期由外部工具只读下载到隔离目录，再用 `sow init --adopt-content --view stable` 纳入合一池；不提供长期 pull 动词 | migration-only | RB-L、RB-X |
| ROOT-40 | `co-pro` | 旧 Pro 发布 | 无 | 同步本地 `pro/` 到 COS `/pro/` | R3：旧布局、远端删除、无鉴权事务 | 合一池 stable/gated view 的 `sow publish --view stable --target cos` | sow-cli | RB-P、RB-X |
| ROOT-41 | `cf-upload` | 编排别名 | `cf-infra cf-pgsql` | CF 上传 APT+YUM infra/pgsql | R3：四棵树部分成功 | 普通叶子执行 `sow publish --target cf --repo apt-infra,apt-pgsql,yum-pgsql`；mixed-EL infra 只随 ADR-0021 已激活 projection 的 policy owner 发布 | sow-cli | RB-P |
| ROOT-42 | `cf-infra` | 编排别名 | `cf-apt-infra cf-yum-infra` | CF 上传 APT/YUM infra | R3：部分成功 | APT 执行 `sow publish --target cf --repo apt-infra`；mixed-EL YUM 先用 `sow compatibility yum-adopt --id <id>` 进入专用状态机，再随 exact policy owner 发布 | sow-cli | RB-P |
| ROOT-43 | `cf-pgsql` | 编排别名 | `cf-apt-pgsql cf-yum-pgsql` | CF 上传 APT/YUM pgsql | R3：部分成功 | `sow publish --target cf --repo apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie,yum-pgsql-el7,yum-pgsql-el8,yum-pgsql-el9,yum-pgsql-el10` | sow-cli | RB-P |
| ROOT-44 | `cf-percona` | 编排别名 | `cf-apt-percona cf-yum-percona` | CF 上传 APT/YUM percona | R3：部分成功 | `sow publish --target cf --repo apt-percona,yum-percona` | sow-cli | RB-P |
| ROOT-45 | `cf-apt` | 编排别名 | `cf-apt-infra cf-apt-pgsql` | CF 上传两个 APT repo | R3：子集名称含混 | `sow publish --target cf --repo apt-infra,apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie` | sow-cli | RB-P |
| ROOT-46 | `cf-yum` | **错误编排别名** | 实际为 `cf-yum-infra cf-apt-pgsql` | 漏传 yum/pgsql，误传 apt/pgsql | R3：已确认依赖错误 | 普通叶子必须映射为 `sow publish --target cf --repo yum-pgsql` 并锁定 exact leaf；mixed-EL infra 另走 ADR-0021 compatibility 状态机，不得用不存在的 `yum-infra` selector | sow-cli | RB-P |
| ROOT-47 | `cf-yum-infra` | YUM 发布 | 无 | 同步 `yum/infra/` 到 CF | R3：远端删除，无 pair/purge | 禁止普通 repo selector；逐 projection 由 `sow compatibility yum-adopt --id <id>` 开始完成 ADR-0021 S0→S3，最终随 exact policy owner 的 latest publish 原子发布 | sow-cli | RB-P |
| ROOT-48 | `cf-yum-pgsql` | YUM 发布 | 无 | 同步 `yum/pgsql/` 到 CF | R3：同上 | `sow publish --target cf --repo yum-pgsql-el7,yum-pgsql-el8,yum-pgsql-el9,yum-pgsql-el10` | sow-cli | RB-P |
| ROOT-49 | `cf-yum-percona` | YUM 上游镜像发布 | 无 | 同步 `yum/percona/` 到 CF | R3：远端删除历史可能性 | `sow sync --repo yum-percona` 后 `sow publish --target cf --repo yum-percona` | sow-cli | RB-P |
| ROOT-50 | `cf-apt-infra` | APT 发布 | 无 | 同步 `apt/infra/` 到 CF | R3：远端删除，无翻转/purge | `sow publish --target cf --repo apt-infra` | sow-cli | RB-P |
| ROOT-51 | `cf-apt-pgsql` | APT 发布 | 无 | 同步 `apt/pgsql/` 到 CF | R3：同上 | `sow publish --target cf --repo apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie` | sow-cli | RB-P |
| ROOT-52 | `cf-apt-percona` | APT 上游镜像发布 | 无 | 同步 `apt/percona/` 到 CF | R3：远端删除历史可能性 | `sow sync --repo apt-percona` 后 `sow publish --target cf --repo apt-percona` | sow-cli | RB-P |

## 5. APT Makefile：70/70

来源：`/Users/vonng/pgsty/repo/apt/Makefile`。

| ID | target | 类别 | 依赖/别名 | 当前副作用 | 风险 | 当前替代/明确边界（生产证据另计） | 机器处置 | 回滚 |
|---|---|---|---|---|---|---|---|---|
| APT-01 | `init` | APT 纳管初始化 | 无 | 建 `infra`、`pgsql` 的 conf/db/dists/pool 目录 | R1：只建部分布局，可能掩盖配置缺失 | `sow init --repo apt-infra,apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie`，零字节扫描现有树 | sow-cli | RB-L、RB-X |
| APT-02 | `clean` | stash 清理 | 无 | `rm -rf stash/*`，只清 APT 根级 stash | R2：不可逆且可能不是实际 suite stash；非 phony | 新流程直接 `sow add <files>`，不再要求 stash；旧 target 待退役 | retire | RB-L |
| APT-03 | `add-infra` | APT 加包 | 无 | reprepro 将 `infra/stash/*.deb` 加入 generic | R2：外部 runtime，批量 glob，无事务 | `sow add <files> --repo apt-infra --os generic` | sow-cli | RB-R、RB-X |
| APT-04 | `add-percona` | APT 加包 | 无 | 依次向 noble/resolute/jammy/focal/bookworm/bullseye 加包 | R2：六步可部分成功，文件名推断脆弱 | `sow add <files> --repo apt-percona`；OS/arch 由包与配置矩阵推断 | sow-cli | RB-R、RB-X |
| APT-05 | `add-oss` | 编排别名 | `add-jammy add-trixie add-noble add-resolute add-bookworm` | 顺序向五个活跃 suite 加 stash | R2：部分成功；OSS 集合硬编码 | `sow add <files> --repo apt-pgsql-jammy,apt-pgsql-trixie,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bookworm --os jammy,trixie,noble,resolute,bookworm`；public 包自动进入 beta | sow-cli | RB-R |
| APT-06 | `add-all` | 编排别名 | focal/jammy/noble/resolute/bookworm/bullseye/trixie | 向全部七个 suite 加包 | R2：部分成功；EOL/active 混合 | `sow add <files> --repo apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bookworm,apt-pgsql-bullseye,apt-pgsql-trixie --os focal,jammy,noble,resolute,bookworm,bullseye,trixie`；frozen leaf 会拒绝写入 | sow-cli | RB-R |
| APT-07 | `add-debian` | 编排别名 | `add-bookworm add-bullseye add-trixie` | 向 Debian 三 suite 加包 | R2：部分成功 | `sow add <files> --repo apt-pgsql-bookworm,apt-pgsql-bullseye,apt-pgsql-trixie --os bookworm,bullseye,trixie` | sow-cli | RB-R |
| APT-08 | `add-ubuntu` | 编排别名 | `add-focal add-jammy add-noble add-resolute` | 向 Ubuntu 四 suite 加包 | R2：部分成功 | `sow add <files> --repo apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute --os focal,jammy,noble,resolute` | sow-cli | RB-R |
| APT-09 | `add-focal` | APT 加包 | 无 | reprepro 加 `pgsql/focal/stash/*.deb` 到 focal | R2：外部 runtime；focal EOL 策略未冻结 | `sow add ... --repo apt-pgsql-focal --os focal`，受 EOL 门禁 | sow-cli | RB-R |
| APT-10 | `add-jammy` | APT 加包 | 无 | 加 jammy stash | R2：非事务 glob | `sow add ... --repo apt-pgsql-jammy --os jammy` | sow-cli | RB-R |
| APT-11 | `add-noble` | APT 加包 | 无 | 加 noble stash | R2：非事务 glob | `sow add ... --repo apt-pgsql-noble --os noble` | sow-cli | RB-R |
| APT-12 | `add-resolute` | APT 加包 | 无 | 加 resolute stash | R2：非事务 glob | `sow add ... --repo apt-pgsql-resolute --os resolute` | sow-cli | RB-R |
| APT-13 | `add-bullseye` | APT 加包 | 无 | 加 bullseye stash | R2：EOL 策略未冻结 | `sow add ... --repo apt-pgsql-bullseye --os bullseye`，受 EOL 门禁 | sow-cli | RB-R |
| APT-14 | `add-bookworm` | APT 加包 | 无 | 加 bookworm stash | R2：非事务 glob | `sow add ... --repo apt-pgsql-bookworm --os bookworm` | sow-cli | RB-R |
| APT-15 | `add-trixie` | APT 加包 | 无 | 加 trixie stash | R2：非事务 glob | `sow add ... --repo apt-pgsql-trixie --os trixie` | sow-cli | RB-R |
| APT-16 | `adda` | 快捷别名 | jammy/noble/resolute/bookworm；不含 trixie | 加四个 suite | R2：名称无语义，集合与 add-oss 不同 | `sow add <files> --repo apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bookworm --os jammy,noble,resolute,bookworm`；旧别名退役 | sow-cli | RB-R |
| APT-17 | `purge` | stash 清理 | 无 | 删除 infra 和七 suite stash；percona 路径疑似写错为 stash/stash | R2：不可逆、路径错误、无 dry-run | 直接 add 消除 stash 仪式；不迁移删除命令 | retire | RB-L |
| APT-18 | `ls-infra` | 仓库清单 | 无 | reprepro 列 generic | R0：只读但依赖外部 runtime | 退役人读 `reprepro list` 输出；机器 inventory 由 canonical manifest/SQLite 承载，完整性另用 `sow verify --layer L1 --repo apt-infra --os generic`，不宣称输出等价 | retire | RB-X |
| APT-19 | `ls-focal` | 仓库清单 | 无 | 列 focal | R0 | 同 APT-18；manifest/catalog 是 inventory，`sow verify --layer L1 --repo apt-pgsql-focal --os focal` 只做闭包校验 | retire | RB-X |
| APT-20 | `ls-jammy` | 仓库清单 | 无 | 列 jammy | R0 | 同 APT-18；`sow verify --layer L1 --repo apt-pgsql-jammy --os jammy` 不承诺复刻列表文本 | retire | RB-X |
| APT-21 | `ls-noble` | 仓库清单 | 无 | 列 noble | R0 | 同 APT-18；`sow verify --layer L1 --repo apt-pgsql-noble --os noble` 不承诺复刻列表文本 | retire | RB-X |
| APT-22 | `ls-resolute` | 仓库清单 | 无 | 列 resolute | R0 | 同 APT-18；`sow verify --layer L1 --repo apt-pgsql-resolute --os resolute` 不承诺复刻列表文本 | retire | RB-X |
| APT-23 | `ls-bullseye` | 仓库清单 | 无 | 列 bullseye | R0 | 同 APT-18；`sow verify --layer L1 --repo apt-pgsql-bullseye --os bullseye` 不承诺复刻列表文本 | retire | RB-X |
| APT-24 | `ls-bookworm` | 仓库清单 | 无 | 列 bookworm | R0 | 同 APT-18；`sow verify --layer L1 --repo apt-pgsql-bookworm --os bookworm` 不承诺复刻列表文本 | retire | RB-X |
| APT-25 | `ls-trixie` | 仓库清单 | 无 | 列 trixie | R0 | 同 APT-18；`sow verify --layer L1 --repo apt-pgsql-trixie --os trixie` 不承诺复刻列表文本 | retire | RB-X |
| APT-26 | `rm-pig` | APT 减包 | 无 | recipe 疑似漏 `remove`，静态看不能正确删除 pig | R2：若修正后会改索引/引用；现 recipe 未执行验证 | `sow rm pig --repo apt-infra --os generic`；stable/history 保护 | sow-cli | RB-R |
| APT-27 | `trim-dump` | 孤儿审计 | 无 | 对 infra 和七 suite 执行 `dumpunreferenced` | R0：只读报告但分散且无统一 manifest | `sow gc --limit 1000` 以 dry-run 报告 CAS orphan；`sow fsck --repo apt-infra,apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie` 独立报告服务树漂移 | sow-cli | RB-X |
| APT-28 | `trim` | 物理 GC | 无 | 对 infra 和七 suite `deleteunreferenced` | R2：不可逆删除；可能破坏历史钉版 | 先 `sow gc --limit 1000` 获取 orphan set，再由同一摘要显式执行 `sow gc --apply --confirm <sha256>`；stable/snapshot 引用不可删 | sow-cli | RB-R、RB-L |
| APT-29 | `pgsql-include` | APT 加包 | 无 | 以旧 `-b pgsql` 布局将 PostgreSQL 16 包加到 bookworm/jammy | R2：与当前 per-suite base 布局不一致，可能是遗留路径 | 旧树先 `sow init --repo apt-pgsql-bookworm,apt-pgsql-jammy` 审计，再用 `sow add <files> --repo apt-pgsql-bookworm,apt-pgsql-jammy --os bookworm,jammy` | sow-cli | RB-R、RB-X |
| APT-30 | `init-all` | 破坏性编排 | 七个 `init-*` | 删除并从 `~/pgsty/apt/<suite>` 重建七仓 | R4：多仓部分重建、无快照、失败留半仓 | 对源包执行 `sow add <files> --repo apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie`，再从 ref 以 `sow materialize latest --repo apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie` 构造隔离树；禁止原地 rm -rf | sow-cli | RB-L、RB-R |
| APT-31 | `init-focal` | 破坏性重建 | 无 | 删除 focal db/dists/pool，再导入 `~/pgsty/apt/focal/*.deb` | R4：整仓不可逆 | `sow add <files> --repo apt-pgsql-focal --os focal` 后 `sow materialize latest --repo apt-pgsql-focal --os focal`；frozen 配置会拒绝新增 | sow-cli | RB-L、RB-R |
| APT-32 | `init-jammy` | 破坏性重建 | 无 | 同上，jammy | R4 | `sow add <files> --repo apt-pgsql-jammy --os jammy` 后 `sow materialize latest --repo apt-pgsql-jammy --os jammy` | sow-cli | RB-L、RB-R |
| APT-33 | `init-noble` | 破坏性重建 | 无 | 同上，noble | R4 | `sow add <files> --repo apt-pgsql-noble --os noble` 后 `sow materialize latest --repo apt-pgsql-noble --os noble` | sow-cli | RB-L、RB-R |
| APT-34 | `init-resolute` | 破坏性重建 | 无 | 同上，resolute | R4 | `sow add <files> --repo apt-pgsql-resolute --os resolute` 后 `sow materialize latest --repo apt-pgsql-resolute --os resolute` | sow-cli | RB-L、RB-R |
| APT-35 | `init-bullseye` | 破坏性重建 | 无 | 同上，bullseye | R4 | frozen leaf 不可新增；历史纳管用 `sow init --adopt-content --repo apt-pgsql-bullseye --os bullseye --view stable`，再 `sow materialize stable --repo apt-pgsql-bullseye --os bullseye` | sow-cli | RB-L、RB-R |
| APT-36 | `init-bookworm` | 破坏性重建 | 无 | 同上，bookworm | R4 | `sow add <files> --repo apt-pgsql-bookworm --os bookworm` 后 `sow materialize latest --repo apt-pgsql-bookworm --os bookworm` | sow-cli | RB-L、RB-R |
| APT-37 | `init-trixie` | 破坏性重建 | 无 | 同上，trixie | R4 | `sow add <files> --repo apt-pgsql-trixie --os trixie` 后 `sow materialize latest --repo apt-pgsql-trixie --os trixie` | sow-cli | RB-L、RB-R |
| APT-38 | `gen` | 辅助清单 | 无 | 执行 `list/gen`，随后显示 `git diff list/*` | R1：自定义派生产物，语义未纳入 PRD | 退役 reprepro 输入清单；SOW 以 `sow.yaml`、manifest 和可重建 SQLite catalog 为配置/查询面，不承诺旧 `list/*` 格式 | retire | RB-L、RB-X |
| APT-39 | `push` | 开发机复制 | 无 | `rsync -avc ./` 到 `sv:/data/pkg/apt`，不删除目标额外文件 | R3：SSH/rsync 外部依赖，无 manifest/checkpoint | `sv` 不在 PRD 冻结的 cf/cos 目标内；开发机文件传输移交外部运维，不能作为发布成功证据 | external-handoff | RB-X |
| APT-40 | `pushd` | 开发机镜像 | 无 | 带 `--delete` 推整个 APT 树到 sv | R4：远端大范围删除，方向误用危险 | 禁止用 `rsync --delete` 代替发布；若 `sv` 后续成为正式目标，必须另立需求实现 checkpoint/purge/verify，而非复用此 target | policy-reject | RB-X、RB-P |
| APT-41 | `pull` | 开发机复制 | 无 | 从 sv 增量复制到本地，不删本地额外文件 | R2：可覆盖本地正典；远端反客为主 | 仅迁移期由外部工具下载到隔离目录，再执行 `sow init --adopt-content`；SOW 本地正典不提供日常 pull | migration-only | RB-L、RB-X |
| APT-42 | `pulld` | 开发机镜像 | 无 | 从 sv 带 `--delete` 覆盖本地整棵 APT 树 | R4：可删除本地正典、manifest 和工作文件 | 禁止迁入日常 CLI；一次性迁移须只读下载到隔离目录再 init | policy-reject | RB-L、RB-X |
| APT-43 | `upload` | 双目标编排 | `cf-upload cos-upload` | 发布 CF 与 COS 的 infra/pgsql | R3：任一目标可部分成功，无独立 ref | `sow publish --repo apt-infra,apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie --target cf,cos` | sow-cli | RB-P |
| APT-44 | `upload-infra` | 双目标编排 | `cf-infra cos-infra` | 发布 APT infra 到两端 | R3：部分成功 | `sow publish --repo apt-infra --target cf,cos` | sow-cli | RB-P |
| APT-45 | `upload-pgsql` | 双目标编排 | `cf-pgsql cos-pgsql` | 发布 APT pgsql 到两端 | R3：部分成功 | `sow publish --repo apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie --target cf,cos` | sow-cli | RB-P |
| APT-46 | `cf-upload` | CF 编排 | `cf-infra cf-pgsql` | 发布两个 APT repo 到 CF | R3：部分成功 | `sow publish --repo apt-infra,apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie --target cf` | sow-cli | RB-P |
| APT-47 | `cf-infra` | APT 发布 | 无 | `rclone sync ./infra/` 到 CF `/apt/infra/` | R3：远端删除，无 InRelease 最后翻转/purge | `sow publish --repo apt-infra --target cf` | sow-cli | RB-P |
| APT-48 | `cf-pgsql` | APT 发布 | 无 | 同步全部 `./pgsql/` 到 CF `/apt/pgsql/` | R3：七 suite 可在上传过程中不一致 | `sow publish --repo apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie --target cf` | sow-cli | RB-P |
| APT-49 | `cf-jammy` | APT suite 发布 | 无 | 同步 pgsql/jammy 到 CF 对应路径 | R3：远端删除，无翻转/purge | `sow publish --repo apt-pgsql-jammy --os jammy --target cf` | sow-cli | RB-P |
| APT-50 | `cf-noble` | APT suite 发布 | 无 | 同步 noble 到 CF | R3：同上 | `sow publish --repo apt-pgsql-noble --os noble --target cf` | sow-cli | RB-P |
| APT-51 | `cf-resolute` | APT suite 发布 | 无 | 同步 resolute 到 CF | R3：同上 | `sow publish --repo apt-pgsql-resolute --os resolute --target cf` | sow-cli | RB-P |
| APT-52 | `cf-focal` | APT suite 发布 | 无 | 同步 focal 到 CF | R3：同上；EOL | `sow publish --repo apt-pgsql-focal --os focal --target cf`，冻结 view | sow-cli | RB-P |
| APT-53 | `cf-bookworm` | APT suite 发布 | 无 | 同步 bookworm 到 CF | R3：同上 | `sow publish --repo apt-pgsql-bookworm --os bookworm --target cf` | sow-cli | RB-P |
| APT-54 | `cf-bullseye` | APT suite 发布 | 无 | 同步 bullseye 到 CF | R3：同上；EOL | `sow publish --repo apt-pgsql-bullseye --os bullseye --target cf`，冻结 view | sow-cli | RB-P |
| APT-55 | `cf-trixie` | APT suite 发布 | 无 | 同步 trixie 到 CF | R3：同上 | `sow publish --repo apt-pgsql-trixie --os trixie --target cf` | sow-cli | RB-P |
| APT-56 | `cf-mssql` | APT repo 发布 | 无 | 同步 `./mssql/` 到 CF `/apt/mssql/` | R3：远端删除；未在主要编排依赖中 | `sow publish --repo apt-mssql --target cf`，先纳入配置矩阵 | sow-cli | RB-P |
| APT-57 | `cos-upload` | COS 编排 | `cos-infra cos-pgsql` | 发布两个 APT repo 到 COS | R3：部分成功 | `sow publish --repo apt-infra,apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie --target cos` | sow-cli | RB-P |
| APT-58 | `cos-infra` | APT 发布 | 无 | 同步 infra 到 COS `/apt/infra/` | R3：远端删除，无翻转/purge | `sow publish --repo apt-infra --target cos` | sow-cli | RB-P |
| APT-59 | `cos-pgsql` | APT 发布 | 无 | 同步全部 pgsql 到 COS | R3：suite 间部分状态 | `sow publish --repo apt-pgsql-focal,apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bullseye,apt-pgsql-bookworm,apt-pgsql-trixie --target cos` | sow-cli | RB-P |
| APT-60 | `cos-focal` | APT suite 发布 | 无 | 同步 focal 到 COS | R3：远端删除；EOL | `sow publish --repo apt-pgsql-focal --os focal --target cos` | sow-cli | RB-P |
| APT-61 | `cos-jammy` | APT suite 发布 | 无 | 同步 jammy 到 COS | R3：远端删除 | `sow publish --repo apt-pgsql-jammy --os jammy --target cos` | sow-cli | RB-P |
| APT-62 | `cos-noble` | APT suite 发布 | 无 | 同步 noble 到 COS | R3：远端删除 | `sow publish --repo apt-pgsql-noble --os noble --target cos` | sow-cli | RB-P |
| APT-63 | `cos-resolute` | APT suite 发布 | 无 | 同步 resolute 到 COS | R3：远端删除 | `sow publish --repo apt-pgsql-resolute --os resolute --target cos` | sow-cli | RB-P |
| APT-64 | `cos-bullseye` | APT suite 发布 | 无 | 同步 bullseye 到 COS | R3：远端删除；EOL | `sow publish --repo apt-pgsql-bullseye --os bullseye --target cos` | sow-cli | RB-P |
| APT-65 | `cos-bookworm` | APT suite 发布 | 无 | 同步 bookworm 到 COS | R3：远端删除 | `sow publish --repo apt-pgsql-bookworm --os bookworm --target cos` | sow-cli | RB-P |
| APT-66 | `cos-trixie` | APT suite 发布 | 无 | 同步 trixie 到 COS | R3：远端删除 | `sow publish --repo apt-pgsql-trixie --os trixie --target cos` | sow-cli | RB-P |
| APT-67 | `cos-mssql` | APT repo 发布 | 无 | 同步 mssql 到 COS | R3：远端删除；未在主要编排依赖中 | `sow publish --repo apt-mssql --target cos` | sow-cli | RB-P |
| APT-68 | `parade` | 外部产物收集 | 无 | 从 `~/pgsty/paradedb/` 复制五个 suite 的已构建 deb 到 stash | R2：glob/覆盖、部分复制；不建索引 | 外部 builder 直接把最终 DEB 路径交给对应的 `sow add <files> --repo apt-pgsql-jammy,apt-pgsql-noble,apt-pgsql-resolute,apt-pgsql-bookworm,apt-pgsql-trixie`；不复制 stash | external-handoff | RB-B、RB-L |
| APT-69 | `get-d13` | 容器产物收集 | 无 | 删除临时目录，从 Docker `d13` 拷包，强制移动到 trixie stash，再删临时目录 | R4：rm -rf/mv -f，依赖容器，部分失败 | 容器收集留在外部 builder；最终 amd64 DEB 目录交给 `sow add <files> --repo apt-pgsql-trixie --os trixie --arch amd64` | external-handoff | RB-B、RB-L |
| APT-70 | `get-d13a` | 容器产物收集 | 无 | 同上，从 `d13a` 收集另一架构 | R4：同上 | 容器收集留在外部 builder；最终 arm64 DEB 目录交给 `sow add <files> --repo apt-pgsql-trixie --os trixie --arch arm64` | external-handoff | RB-B、RB-L |

## 6. YUM Makefile：14/14

来源：`/Users/vonng/pgsty/repo/yum/Makefile`。`./build` 实际调用 createrepo_c，并尝试生成 modulemd；这里只记录由 Makefile 触发的可观察职责，不把旧脚本实现带入 SOW。

| ID | target | 类别 | 依赖/别名 | 当前副作用 | 风险 | 当前替代/明确边界（生产证据另计） | 机器处置 | 回滚 |
|---|---|---|---|---|---|---|---|---|
| YUM-01 | `default` | 编排入口 | `sign build` | 先按 mtime 重签近期 rpm，再建 pgsql/infra repodata | R4：改包字节；make -j 时顺序也非事务保证 | 不保留该复合入口；`sow add` 保持上游 rpm 字节并原生建索引，随后 verify/publish | policy-reject | RB-R、RB-X |
| YUM-02 | `build` | YUM 索引编排 | `build-pgsql build-infra` | 为 pgsql 六矩阵和 infra 双架构生成旧式 repodata/modulemd | R2：原地覆盖 repodata；无签名 pair | 普通 pgsql 日常 `sow add <files> --repo yum-pgsql-el8,yum-pgsql-el9,yum-pgsql-el10`，重建用 `sow materialize latest --repo yum-pgsql-el8,yum-pgsql-el9,yum-pgsql-el10`；mixed-EL infra 禁止普通写入，只能从 `sow compatibility yum-adopt --id <id>` 开始走 ADR-0021 | sow-cli | RB-R、RB-X |
| YUM-03 | `build-all` | YUM 索引编排 | `build-pgsql build-infra build-other` | 额外重建 EL7/mssql/ivory/gpsql | R2：多仓部分成功，包含范围外 modulemd | 普通物理叶子执行 `sow materialize latest --repo yum-pgsql,yum-mssql,yum-gpsql`；EOL 只从 frozen ref 重建。旧 ivory 没有 inventoried repomd owner，明确退役而非伪造 selector；infra 另走 ADR-0021 | sow-cli | RB-R、RB-X |
| YUM-04 | `build-infra` | YUM 索引 | 无 | 对 `infra/x86_64`、`infra/aarch64` 调 `./build` | R2：原地 repodata，两个架构可部分成功 | 禁止 ordinary materialize；逐 projection 用 `sow compatibility yum-candidate --id <id> --output <dir>` 生成隔离候选，再 freeze/cutover，完整步骤见 ADR-0021 | sow-cli | RB-R |
| YUM-05 | `build-pgsql` | YUM 索引 | 无 | 对 EL8/9/10 × x86_64/aarch64 六目录建 repodata | R2：六步部分成功 | `sow materialize latest --repo yum-pgsql-el8,yum-pgsql-el9,yum-pgsql-el10 --os el8,el9,el10 --arch x86_64,aarch64` | sow-cli | RB-R |
| YUM-06 | `build-other` | YUM/EOL 索引 | 无 | 重建 pgsql el7、mssql el7/8/9、ivory el7/8/9、gpsql el7/8/9 x86_64 | R2：EOL 与活跃混合；modulemd；不含 ARM 多数路径 | `sow materialize latest --repo yum-mssql,yum-gpsql --arch x86_64`；EOL leaf 使用 frozen ref；旧 ivory 无 inventoried repomd owner，明确退役 | sow-cli | RB-R、RB-X |
| YUM-07 | `build-percona` | YUM 上游镜像索引 | 无 | 对 percona EL8/9 × 双架构建 repodata | R2：四步部分成功；可能重建上游元数据 | `sow sync --repo yum-percona` 后执行 `sow materialize latest --repo yum-percona` | sow-cli | RB-R |
| YUM-08 | `sign` | RPM 原地重签 | 无 | 对 pgsql/infra 1000 分钟内 rpm 执行 `rpm --addsign` | R4：mtime 非确定、改字节、混淆上游/自建来源 | Day 1 禁止镜像重签；自建包由 builder 签，SOW 只 `verify --layer L1` | policy-reject | RB-X；已改字节须从来源/CAS 原件恢复 |
| YUM-09 | `sign10` | RPM 原地重签 | 无 | 对全树 10 分钟内 rpm 重签 | R4：同上，范围由时钟决定 | 不迁移；FR-17 策略门禁 | policy-reject | RB-X、RB-R |
| YUM-10 | `sign100` | RPM 原地重签 | 无 | 对全树 100 分钟内 rpm 重签 | R4 | 不迁移；FR-17 策略门禁 | policy-reject | RB-X、RB-R |
| YUM-11 | `sign1000` | RPM 原地重签 | 无 | 对全树 1000 分钟内 rpm 重签 | R4 | 不迁移；FR-17 策略门禁 | policy-reject | RB-X、RB-R |
| YUM-12 | `sign-all` | RPM 全量重签 | 无 | 对当前树全部 rpm 原地重签 | R4：最大破坏面，无备份/摘要真机门禁 | 不迁移；未来仅在 FR-17 商业条件满足后另行设计 | policy-reject | RB-X、RB-R |
| YUM-13 | `sign-pgsql` | RPM 原地重签 | 无 | 对 pgsql 3000 分钟内 rpm 重签 | R4：上游与自建不区分 | 不迁移；builder 签自建包，SOW 验证 | policy-reject | RB-X、RB-R |
| YUM-14 | `sign-infra` | RPM 原地重签 | 无 | 对 infra 3000 分钟内 rpm 重签 | R4：同上 | 不迁移；builder 签自建包，SOW 验证 | policy-reject | RB-X、RB-R |

## 7. Docker Makefile：40/40

来源：`/Users/vonng/pgsty/repo/docker/Makefile`。该文件是 host-side 容器包装层；SOW 的零外部运行时约束要求最终退役此层，而不是在 Go CLI 中复刻 Docker 生命周期。

| ID | target | 类别 | 依赖/别名 | 当前副作用 | 风险 | 当前替代/明确边界（生产证据另计） | 机器处置 | 回滚 |
|---|---|---|---|---|---|---|---|---|
| DKR-01 | `default` | 帮助入口 | `help` | 打印 Docker wrapper 帮助 | R0 | Docker 入口整体退役；`sow --help` 可用于导航，但不是该 wrapper 帮助正文的业务等价实现 | retire | RB-X |
| DKR-02 | `help` | 帮助 | 无 | 打印容器与内部 make shortcut | R0 | 随容器 wrapper 退役；外部 builder 维护自身帮助，不用 `sow --help` 冒充输出或职责等价 | retire | RB-X |
| DKR-03 | `image` | 容器生命周期 | 无 | 校验口令后以 build arg 构建 `dnfupdate` 镜像 | R4：口令出现在命令/build arg，并被引用 Dockerfile 烤入镜像层 | 禁止迁入；纯 Go signing/index engine 替代容器 runtime | retire | RB-X；删除旧镜像前保留应急环境但不得再注入生产秘密 |
| DKR-04 | `container` | 容器生命周期 | 无 | 忽略错误强删同名容器，再创建并 bind mount host YUM 树 | R4：可删错误容器；容器直接写真实树 | 不迁入；SOW 直接在显式 root 工作 | retire | RB-X |
| DKR-05 | `up` | 容器生命周期 | 与 `start` 同规则 | 启动容器 | R1 | 无 SOW 对应；退役 | retire | RB-X |
| DKR-06 | `start` | 同义别名 | 与 `up` 同规则 | 启动容器 | R1 | 无 SOW 对应；退役 | retire | RB-X |
| DKR-07 | `down` | 容器生命周期 | 与 `stop` 同规则 | 停止容器，忽略错误 | R1 | 无 SOW 对应；退役 | retire | RB-X |
| DKR-08 | `stop` | 同义别名 | 与 `down` 同规则 | 停止容器 | R1 | 无 SOW 对应；退役 | retire | RB-X |
| DKR-09 | `rm` | 容器生命周期 | 与 `clean` 同规则 | 强删同名容器，忽略错误 | R2：与 `sow rm` 名称相同但语义完全不同 | 不映射到 `sow rm`；容器操作退役 | retire | RB-X |
| DKR-10 | `clean` | 同义别名 | 与 `rm` 同规则 | 强删容器 | R2 | 无 SOW 对应；退役 | retire | RB-X |
| DKR-11 | `purge` | 容器生命周期 | `rm` | 删容器后强删镜像 | R2：不可逆移除应急环境 | 无 SOW 对应；退役 | retire | RB-X |
| DKR-12 | `rebuild` | 容器编排 | `purge image container up` | 删除并重建镜像/容器 | R4：make -j 下依赖无顺序边；口令进入 build | 无 SOW 对应；原生 CLI 构建由 Go toolchain/CI 管理 | retire | RB-X |
| DKR-13 | `restart` | 容器编排 | `stop start` | 停止并启动容器 | R2：make -j 顺序不受事务保护 | 无 SOW 对应；退役 | retire | RB-X |
| DKR-14 | `recreate` | 容器编排 | `rm container up` | 删除并重建容器 | R3：bind mount 写者切换，make -j 顺序风险 | 无 SOW 对应；退役 | retire | RB-X |
| DKR-15 | `status` | 容器诊断 | 与 `ps` 同规则 | `docker ps` 查看同名容器 | R0 | 退役容器生命周期诊断；`sow verify`/`fsck` 是仓库校验，不宣称等价于容器状态 | retire | RB-X |
| DKR-16 | `ps` | 同义别名 | 与 `status` 同规则 | 同上 | R0 | 与 DKR-15 同样退役，不映射为仓库状态命令 | retire | RB-X |
| DKR-17 | `logs` | 容器诊断 | 无 | 持续 tail 容器日志 | R0：阻塞交互 | SOW 输出结构化运行日志；容器日志退役 | retire | RB-X |
| DKR-18 | `inspect` | 容器诊断 | 无 | `docker inspect` | R0：可能显示环境/挂载细节 | 无 SOW 对应；退役 | retire | RB-X |
| DKR-19 | `shell` | 容器交互 | 与 `sh` 同规则 | 进入挂载真实 YUM 树的 bash | R4：可任意改 host tree，绕过 manifest | SOW 不提供绕过状态模型的 shell；退役 | retire | RB-X |
| DKR-20 | `sh` | 同义别名 | 与 `shell` 同规则 | 同上 | R4 | 同上 | retire | RB-X |
| DKR-21 | `exec` | 容器交互 | `CMD` 参数 | 在挂载真实树的容器执行任意 `bash -lc` | R4：任意命令与 shell 注入面，可绕过所有门禁 | 禁止迁入；所有写操作只能走 SOW 显式动词 | retire | RB-X |
| DKR-22 | `sign` | YUM wrapper | 容器内 `make sign` | 触发 YUM-08 原地重签 | R4：秘密镜像+改包字节 | FR-17 Day 1 禁止；仅 `sow verify` | policy-reject | RB-X、RB-R |
| DKR-23 | `sign10` | YUM wrapper | 容器内 `make sign10` | 触发 YUM-09 | R4 | 禁止迁入 | policy-reject | RB-X、RB-R |
| DKR-24 | `sign100` | YUM wrapper | 容器内 `make sign100` | 触发 YUM-10 | R4 | 禁止迁入 | policy-reject | RB-X、RB-R |
| DKR-25 | `sign1000` | YUM wrapper | 容器内 `make sign1000` | 触发 YUM-11 | R4 | 禁止迁入 | policy-reject | RB-X、RB-R |
| DKR-26 | `sign-all` | YUM wrapper | 容器内 `make sign-all` | 触发 YUM-12 全量重签 | R4：最大破坏面 | 禁止迁入；未来重签仍受单独商业门禁 | policy-reject | RB-X、RB-R |
| DKR-27 | `sign-pgsql` | YUM wrapper | 容器内 `make sign-pgsql` | 触发 YUM-13 | R4 | 禁止迁入 | policy-reject | RB-X、RB-R |
| DKR-28 | `sign-infra` | YUM wrapper | 容器内 `make sign-infra` | 触发 YUM-14 | R4 | 禁止迁入 | policy-reject | RB-X、RB-R |
| DKR-29 | `build` | YUM wrapper | 容器内 `make build` | 触发 YUM-02，直接改 host repodata | R3：容器/外部 runtime、无原子翻转 | 普通 pgsql 用 `sow add <files> --repo yum-pgsql-el8,yum-pgsql-el9,yum-pgsql-el10`，重建用 `sow materialize latest --repo yum-pgsql-el8,yum-pgsql-el9,yum-pgsql-el10`；mixed-EL infra 从 `sow compatibility yum-adopt --id <id>` 开始走专用状态机 | sow-cli | RB-R、RB-X |
| DKR-30 | `build-all` | YUM wrapper | 容器内 `make build-all` | 触发 YUM-03 | R3：多仓部分成功 | `sow materialize latest --repo yum-pgsql,yum-mssql,yum-gpsql`；frozen leaf 只从既有 ref 重建，ivory 无物理 owner 明确退役，infra 另走 ADR-0021 | sow-cli | RB-R、RB-X |
| DKR-31 | `build-pgsql` | YUM wrapper | 容器内 `make build-pgsql` | 触发 YUM-05 | R3 | `sow materialize latest --repo yum-pgsql-el8,yum-pgsql-el9,yum-pgsql-el10` | sow-cli | RB-R、RB-X |
| DKR-32 | `build-infra` | YUM wrapper | 容器内 `make build-infra` | 触发 YUM-04 | R3 | 逐 projection 用 `sow compatibility yum-candidate --id <id> --output <dir>` 建隔离候选，再按 ADR-0021 freeze/cutover | sow-cli | RB-R、RB-X |
| DKR-33 | `build-other` | YUM wrapper | 容器内 `make build-other` | 触发 YUM-06 | R3：EOL/旧 repo 混合 | `sow materialize latest --repo yum-mssql,yum-gpsql`；EOL leaf 使用 frozen ref，ivory 明确退役 | sow-cli | RB-R、RB-X |
| DKR-34 | `build-percona` | YUM wrapper | 容器内 `make build-percona` | 触发 YUM-07 | R3 | `sow sync --repo yum-percona` 后执行 `sow materialize latest --repo yum-percona` | sow-cli | RB-R、RB-X |
| DKR-35 | `pg` | 快捷别名 | 容器内 `make build-pgsql` | 与 DKR-31 相同 | R3 | 显式替换为 `sow materialize latest --repo yum-pgsql-el8,yum-pgsql-el9,yum-pgsql-el10` | sow-cli | RB-R、RB-X |
| DKR-36 | `pgsql` | 快捷别名 | 容器内 `make build-pgsql` | 与 DKR-31 相同 | R3 | 显式替换为 `sow materialize latest --repo yum-pgsql-el8,yum-pgsql-el9,yum-pgsql-el10` | sow-cli | RB-R、RB-X |
| DKR-37 | `infra` | 快捷别名 | 容器内 `make build-infra` | 与 DKR-32 相同 | R3 | 显式替换为 `sow compatibility yum-candidate --id <id> --output <dir>` 起始的 ADR-0021 专用流程 | sow-cli | RB-R、RB-X |
| DKR-38 | `other` | 快捷别名 | 容器内 `make build-other` | 与 DKR-33 相同 | R3 | 显式替换为 `sow materialize latest --repo yum-mssql,yum-gpsql`；ivory 无物理 owner，退役 | sow-cli | RB-R、RB-X |
| DKR-39 | `percona` | 快捷别名 | 容器内 `make build-percona` | 与 DKR-34 相同 | R3 | `sow sync --repo yum-percona` 后执行 `sow materialize latest --repo yum-percona` | sow-cli | RB-R、RB-X |
| DKR-40 | `psql` | 外部调试 | 无 | 在容器启动交互式 psql（若存在） | R1：PG 不是 SOW 核心依赖 | 无 SOW 对应；数据库调试移交外部运维工具 | retire | RB-X |

## 8. 机器处置结果

分类不会改变 176 个 `<文件,target>` 对均需处置的事实。当前闭合计数由审核脚本从表行
实时计算，不能手工豁免：

| 机器处置 | target 数 |
|---|---:|
| `sow-cli` | 115 |
| `retire` | 33 |
| `policy-reject` | 18 |
| `external-handoff` | 8 |
| `migration-only` | 2 |
| **合计** | **176** |

- **必须由 SOW 真实覆盖**：APT/YUM/asset 的 add、rm、索引生成、inventory/orphan 审计、sync、publish、双目标编排、stable/history 保护与 latest 兼容。
- **用选择器消除的别名**：`add-*`、`cf-*`、`co/cos-*`、`upload*`、`build-*` 等。必须对每个旧依赖集合做 selector expansion 黄金测试，尤其是已出错的 `cf-yum`。
- **必须退役而非复刻**：Docker help/image/container/up/down/shell/exec、stash 清理仪式、外部 gpg/rpm 重签、createrepo/modulemd 容器包装。`sow --help` 只是新 CLI 导航，不是旧 Docker wrapper 帮助面的业务等价证据。
- **外部构建/生成/收集移交**：`copy-bin`、`copy-beta`、`ext-list`、`md5-src`、`parade`、
  `get-d13`、`get-d13a`。造包、容器收集和兼容 asset 正文生成继续属于 builder，但最终
  产物必须以逐输入 `--expected-object sha256:<digest>:<size>` 直接交给 `sow add`；
  [handoff 合同](builder-handoff.md)及 asset/DEB/RPM E2E 已进入产品测试。特别是旧 `.io/.cc` 脚本向
  两个 target 的同一 key 发布不同正文；SOW 的单一 canonical view 不允许把这种分叉
  偷渡为 target-specific override。受审 external builder 已把八个源收敛为四个 canonical
  正文；无歧义的 COS-only `/cc`、`/claude`、`/ray` 也已从只读源完成 digest-bound exact-copy。
  物理迁移 fixture 分别激活 target-affinity=`cf,cos` 与 `cos` 的 owner；没有执行生产或云发布。
- **原 7 个悬空语义已显式处置**：ROOT-01 禁止把鉴权数据库当 asset；ROOT-05/08 由
  外部文档/构建产物交 SOW；ROOT-39 与 APT-41 仅允许隔离迁移；APT-38 退役 reprepro
  list；APT-39 移交非生产 `sv` 传输；APT-40/42 禁止无 checkpoint 的 `--delete`。
- **本地产品路径已存在但生产仍受门禁**：`publish`、L1–L4、content adoption 都已有当前
  CLI；真实 cf/cos/EdgeOne/Cloudflare 回滚、旧 URL 与完整客户端矩阵必须按第 9 节另取证，
  不能因为 115 行有命令模板而批量标成生产通过。Docker `default/help`、`ls-*` 与 Docker `status/ps` 已明确
  退役；ROOT-02/03 已有 canonical builder/SOW handoff，但生产 URL/cutover 未验证，不能据此冲高覆盖计数。
- **当前结构闭包证据**：44 个族对 176 target 是无重叠、无遗漏的精确分区；46 个 alias-like
  target 中 36 个 `sow-cli` 行及所有其他表内普通 SOW selector 命令都能在完整物理配置上解析并
  匹配独立 exact-leaf golden，compatibility 命令则绑定专用 verb/flag surface。该证据锁住命令模板、
  suite/component/OS/arch/path 集合和配置 schema，不证明文件/索引/远端副作用已等价。

## 9. G5 与退役验收门禁

G5 当前状态为 **实现中、未通过**。必须同时满足以下条件后才能把本账本或总追踪矩阵中的 G5 标为通过：

1. `audit-legacy-targets.sh` 对 44-family/176-target 精确分区、源指纹、处置 schema 与当前 CLI
   surface/闭合 enum 全部退出 0，物理 selector golden 测试覆盖所有表内 selector 命令，并保存 177 行
   （header + 176 target）规范化 TSV；任何旧源/map/config 漂移必须重新审计。
2. 44 个操作族的本地合同必须持续通过：每个含 `sow-cli` 的族绑定真实 CLI/FS/parser，发布族
   绑定本地 provider protocol；其他族绑定显式 disposition。最终仍须对每个生产 target 证明
   文件集合、签名、远端差异、purge 和发布后验证，并补齐真实 handoff/权限撤销证据。
3. `cf-yum` 回归测试证明只选择 `yum/infra` 与 `yum/pgsql`，绝不触碰 APT。
4. rclone `sync` 的隐式删除语义已被 manifest diff、引用保护、checkpoint 和显式 GC 取代；不得通过“新 CLI 也做全量 sync”冒充等价。
5. CF/COS 各自滞后、失败重放和回滚均演练；一个目标成功、另一个失败时状态可解释且可恢复。
6. `/pkg/pig/latest` 正文版本指针、现有 APT/YUM channel-less URL 和其他公开 asset URL 有迁移前基线、迁移后真实 HTTP/apt/dnf 回归。
7. Docker wrapper、外部 gpg/rpm、reprepro、createrepo_c、modulemd、rclone、rsync 不再是 SOW 日常运行时依赖。
8. 外部 builder handoff 已文档化并验证，不把造包/兼容正文生成责任偷渡进 SOW，也不遗漏
   digest-bound 的最终 `sow add`；ROOT-02/03 的 `.io/.cc` 同 key 异正文已收敛为单一 canonical 内容。
9. 所有破坏性迁移先执行 RB-L 基线与备份；从旧写者切换后禁止两套工具同时修改同一发布树。
10. 完成一次独立审计：重新静态枚举四个 Makefile target，与本账本逐项比对，并保存机器
    可读差异为零的证据；本轮本地 audit 只满足这一静态门禁，不替代前 2–9 项。

## 10. 当前证据边界

本地已执行：旧源固定摘要 + 176/176 target/处置/CLI 审核；33-repo selector universe 与
12-repo synthetic 子集 ID/path 对账；完整 98-repo/135-row config/ledger 对 74 APT index、130 ordinary
YUM leaf、专用 EL9 policy owner、双架构 compatibility projection、nested quarantine、root assets 和 active gated Pro owner 的双向集合门禁及突变负例；
44-family E2E/disposition contract 及 5 个突变负例；16 个真实
CLI/FS/parser/provider-protocol 测试；`sow init --adopt-content` 的 suite-nested APT、flat-RPM
YUM 与 asset 测试；零重写与幂等；flat source→canonical
`Packages/<首字母>/` receipt；隔离 materialize；本地 symlink 切换后回退到只读 legacy
root；以及 writer-revoke preflight 正负例 fixture。复现命令与实测输出见
`docs/evidence/2026-07-12-legacy-migration-audit.md` 与
`docs/evidence/2026-07-14-legacy-family-e2e.md`；2026-07-19 的完整物理 selector、
双架构 family 证据、5 个突变负例与 device/inode writer-fence 收口见
`docs/evidence/2026-07-19-legacy-migration-review-hardening.md`。后续完整存量树副本的 95-active-repo M0、
可证明 APT/YUM/asset 子集纳管与源数据 fail-closed 见
`docs/evidence/2026-07-16-legacy-tree-full-adoption-copy.md`；它仍不等于生产 cutover。

以下仍未执行、不得据此声称通过：

- 任何旧 Make recipe，及任何真实 rclone/rsync/Docker/reprepro/rpm/createrepo 命令；
- 生产 CF/COS 对象清单、checkpoint、purge、失败重放与远端回滚；
- 生产公开 URL、重定向、正文、签名或 CDN 缓存前后对比；
- 真实旧仓库的全量 materialize/origin 切换与完整 apt/dnf 矩阵；
- `external-handoff` 的真实 builder 交付与 `retire`/`policy-reject` 的权限撤销；本地
  writer-fence 夹具不能替代 scheduler、container、主机权限和云 IAM 的生产撤权证据。
