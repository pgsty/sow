# 旧仓物理拓扑盘点证据

本证据面固定 2026-07-14 时 `/Users/vonng/pgsty/repo` 的**本地物理源盘点**，用于阻止
迁移配置继续建立在 33 repo / 73 leaf 的 synthetic selector fixture 上。它不是零字节纳管
通过证据，不证明 URL 等价迁移，也没有验证任何对象存储、CDN 或生产资源。

## 安全与只读边界

- `audit-physical-topology.sh` 只接受绝对本地目录，不执行 Make recipe，也没有网络或云调用。
- 任何情况下都不读取、`stat` 或散列旧仓的 `bin/fileauth.txt`。根 Makefile 中对应 recipe
  只作为文本被显式跳过；公开根脚本则受闭合 allowlist 约束。
- 这份 2026-07-14 inventory 生成时，只有公开的 APT `Packages`、YUM `repomd.xml`、
  根脚本和 7 个审阅过的构建源文件记录 SHA-256；`pro/` 当时只记录普通文件路径与
  `stat` 字节数。2026-07-17 用户授权只读后，另在精确副本完成 15 个 TGZ 的 SHA-256、
  gzip/tar 和 gated adoption，证据见 `../evidence/2026-07-17-gated-pro-exact-copy-adoption.md`。
- 工具不访问 CO/COS/Cloudflare，也不能把本地结果解释成任何云或生产验证。真实 CO/COS/CF
  生产仓库在任何情况下都不得用于测试。

## 固定事实

机器快照位于 `fixtures/legacy-physical-topology.tsv`。每个非注释行包含 6 个 TSV 字段：

```text
kind  logical_path  physical_path  scope_or_family  bytes  sha256
```

其中 `scope_or_family` 的 `cf` / `co` 只是从本地 Makefile 抽取的旧目标标签；审计器不会
解析这些变量指向的 endpoint，更不会对相应生产资源发起探测。

当前快照精确固定：

| 范围 | 总数 | 分布 / 说明 |
|---|---:|---|
| APT `binary-*` index | 74 | infra 2、mssql 6、percona 12、pgdg 40、pgsql 14 |
| YUM `repomd.xml` | 131 | gpsql 3、infra 2、mssql 5、percona 9、pgdg 105、pgsql 7 |
| PGDG nested child | 1 | `yum/pgdg/17/redhat/rhel-10-aarch64/rhel-10.0-aarch64` |
| 根级 exact key | 7 | `/get`、`/pig`、`/pkg`、`/beta`、`/cc`、`/claude`、`/ray` |
| 根级目录 prefix | 8 | `/img/`、`/ext/`、`/src/`、`/pkg/pig/`、`/pkg/claude/`、`/pkg/ray/`、`/etc/`、`/dba/` |
| `pro/` 普通文件 | 16 | 路径与字节数；不含内容 SHA |

快照同时固定以下公开源文件 SHA-256；任一 recipe/source 字节变化都要求重新审计，而不能
靠“目标名没变”继续沿用迁移判断：

| 文件 | SHA-256 |
|---|---|
| `Makefile` | `434851089902ebc3f0ab402c81a3b407a420a4f4ec9c8368a10494f21d4c1a8c` |
| `apt/Makefile` | `1077efce002f193466351f16424841a9d7eecc4e8ca61382cf4ba7b5635c8945` |
| `apt/list/gen` | `d1f89aea35e672c10b0e0e0151035f34f2ed3d2be039d61dee10ad65393a118c` |
| `yum/Makefile` | `32a7800a577213e4b257a4116f75986a95a55e8b8909baa8bc54f475cb4953f3` |
| `yum/build` | `e7837003d1498dd80d1ab7aded299c5b577399b37a8257c7e81c5427f795c27a` |
| `docker/Makefile` | `1629076293514cadb1fcaf8b2e734ff1b715bd9af4a086f56c3a4284e38bfd2e` |
| `docker/Dockerfile` | `f9d821210669b82132e3232581e3aa69d98256c2e1257b30ed59ddb8f7ba4966` |

## 可复现命令

从 SOW 工程根执行：

```sh
docs/migration/audit-physical-topology.sh \
  --legacy-root /Users/vonng/pgsty/repo

docs/migration/test-audit-physical-topology.sh
docs/migration/test-physical-migration-config.sh
```

第一条命令重新枚举本地树并与固定快照逐行比较；任何计数、路径、允许散列的公开文件内容、
root key/prefix ownership 或 gated pro 路径/字节数/文件类型漂移都会 fail closed。第二条
命令完全使用临时合成树，覆盖正例、计数漂移、路径漂移、源文件 hash 漂移、公开 index hash
漂移、未审阅根源文件和 gated pro 非普通文件；所有负例只修改临时目录。

`--snapshot` 可指向独立 fixture，供 hermetic 测试复用同一审计器；默认 canonical fixture
仍额外硬门禁 74 / 131 / 1 / 7 / 8 / 16、APT/YUM family 分布、nested child 与 exact
key/prefix 集合，测试 fixture 不能弱化这些本地旧仓事实。

第三条命令只读取上述 machine snapshot、完整 `pigsty-v1.yaml` 和显式 migration ledger，
以 production config decoder 展开并执行双向 set equality：98 个 repo ID、74 个 APT index、
130 个普通 YUM leaf、1 个仅供兼容候选生成的 EL9 policy owner、2 个精确 compatibility
projection、7/8 个根 key/prefix 与 16 个 gated pro 文件必须恰好一次闭合。它还用
临时突变证明：12-repo 与 33/73 synthetic fixture 不能冒充物理合同，缺 APT index、伪造
lifecycle 证据、解除 nested quarantine、Percona 退回 noarch replication、把 inactive infra
carrier 加入 group 或改变 asset target affinity 都会非零失败。脚本在执行前清空云凭据、
关闭全部 real-cloud/upstream opt-in、设置 `GOPROXY=off` 并把外部代理指向 loopback blackhole；
不会访问旧仓、网络或任何 CO/COS/CF 资源。

## 明确保留项

- PGDG nested child 已在迁移 ledger 中 fail-closed 处置为 `quarantine-overlap`，不会成为
  独立 repo，父 repo 也显式 exclude；它最终应 alias、删除还是形成独立 compatibility URL，
  仍须消费者证据与后续 ADR 决定。
- `yum/infra/{arch}` 的两个 leaf 仍由 inactive、无 ref/view/upstream 单元的 carrier
  表达；aarch64/x86_64 两条 projection 显式绑定独立 EL9 policy owner，carrier 与 policy owner
  均不进入普通 repo group。跨 EL gzip compatibility projection 已在精确副本完成 S0→S3 与六组 strong DNF，
  但 production cutover 未执行，不能把本地 closure 写成现场迁移通过。
- 旧 `bin/` 仍由 inactive、不可路由、不可 generic-adopt 的 asset inventory carrier 纳入
  M0/local-fsck 基线，且 `bin/fileauth.txt` 保持在显式 exclude 边界之外。`pro/` carrier 已
  被 active gated owner 替换：物理 `path: pro` 零字节纳管，legacy 空 checksum 排除后由
  gated `sow add` 生成的 reviewed checksum 替代。
- APT sparse suite/component、Percona separate noarch、asset physical/public ownership 与 target
  affinity 已成为 machine contract；gated `pro/` 已在本地精确副本完成 stable/Nginx
  projection，根 exact key 与真实 object-store 投影仍未执行。
- `.io` 与 `.cc` 根脚本的 SHA 不同是被固定的当前事实，不是正文已经收敛的证明。
- 本页的 hermetic config 门禁自身没有运行完整旧树 `sow init --adopt-content`、materialize、
  真实 Nginx、apt/dnf 或云端流程；完整副本运行另见日期化 evidence，不能用配置闭环替代
  MIG-02、MIG-05 或任何真实云 PoC。
