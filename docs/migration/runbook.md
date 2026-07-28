# 存量仓库纳管、迁移与回滚 Runbook

> 状态：**Phase 0–2 已有可执行本地路径**。`sow init --adopt-content` 可从真实
> APT/YUM 索引和 asset baseline 建立 CAS/view/legacy receipt，且该 adoption 本身不写
> 服务树；随后的显式 `materialize` 是结构迁移，会重建并重签 metadata。Phase 3–5
> 仍需按各自门禁取得真实 client、云/CDN 与回滚证据后才能用于生产切换或 Makefile
> 退役。若 `LEGACY_ROOT` 正被 Nginx 直接托管，Phase 1 之前还必须先通过第 2.3 节的
> 控制目录拒绝门禁；否则 `.sow/` 状态或 adoption 写入的 `.pool/` CAS 可能被公开读取。
> Phase 5 的 writer-revoke preflight 已有可执行脚本和 fail-closed 夹具，但当前未在生产
> 主机运行，也未独立查询云 IAM；不得把夹具或操作员声明写成真实撤权已完成。
> **测试安全边界：任何 CO/COS/Cloudflare 生产 bucket、仓库、domain 或 zone 都不得用于
> 测试、PoC、性能测量、故障注入、purge 演练或“只读基线”采集。**本文出现的生产
> `--target cf|cos` 步骤仅描述获批迁移窗口中的真实运维动作，不是当前开发验收命令；测试
> 必须改用另外登记、独立审核、明确 non-production 的专用资源与独立 config。当前注册表
> 为空时保持 fail closed，不能临时借用生产资源补证据。
>
> 本文故意区分“今天可运行的命令”和“退役前必须补齐的命令”。出现 `BLOCKED` 的门禁不能由手工 rclone、reprepro 或“运维记得 purge”绕过。

## 1. 固定输入和证据目录

以下示例在 Linux/macOS 的 Bash 中运行。`EVIDENCE` 必须位于仓库根之外；脚本会拒绝把基线写进服务树。

```bash
set -euo pipefail
export SOW_SRC=/Users/vonng/pgsty/sow
export LEGACY_ROOT=/Users/vonng/pgsty/repo
export SOW_CONFIG=/absolute/path/to/migration-sow.yaml
export EVIDENCE=/absolute/path/to/sow-migration-evidence
export SOW_BIN="$EVIDENCE/bin/sow"

test -d "$SOW_SRC/.git"
test -d "$LEGACY_ROOT/apt"
test -d "$LEGACY_ROOT/yum"
test -f "$SOW_CONFIG"
case "$EVIDENCE" in "$LEGACY_ROOT"|"$LEGACY_ROOT"/*) exit 2;; esac
mkdir -p "$EVIDENCE/bin"
cd "$SOW_SRC"
go build -trimpath -o "$SOW_BIN" ./cmd/sow
"$SOW_BIN" version | tee "$EVIDENCE/sow-version.txt"
```

`migration-sow.yaml` 必须使用真实 repo ID/path/OS/arch，不可直接把 `sow.example.yaml` 当生产矩阵。至少逐项确认：

- APT 的现有公开路径仍是 `apt/infra`、`apt/pgsql/<suite>` 等，不插入 `/latest/`；
- YUM 的现有公开路径仍是 `yum/infra/<arch>`、`yum/pgsql/elN.<arch>` 等；未来 `Packages/<首字母>/` 调整只能在 staging 中做；
- asset 的 `/get`、`/pig`、`/pkg/pig/latest` 等 key 和文件正文语义不变；
- `focal`、`bullseye`、EL7 等 EOL 矩阵标记为 frozen，不混入 active selector；
- 受支持 APT 客户端必须为 apt >= 1.2；更旧客户端在切换前升级，不能依赖 fixed-alias
  多键替换或不安全选项；EL8 从 Pigsty v5.0.0 起冻结，只允许既有字节与 gzip repodata；
- secret 只引用 `env://...` 或受保护的 secret file，证据目录和日志不保存值；
- CF/COS endpoint 的前导斜杠语义由真实 bucket 清单确认，不能照抄两个旧 Makefile 中互相不一致的 rclone URL。
- repo ID 在全局唯一，建议使用 `apt-infra`、`yum-infra`、`asset-src` 这类前缀；当前 CLI
  没有也不需要 `publish/fsck/materialize --type`。
- 每个 YUM repo 的 `yum.package_keyring` 必须是 public-only bundle，覆盖全部存量 RPM
  signer 与 Pigsty 自建包 signer。迁移前从存量树枚举 signer key ID/fingerprint；缺 key
  时不得用 `gpgcheck=0`、`repo_gpgcheck=0` 或仅凭 repomd 签名继续。旧 signer 只要仍被
  stable、snapshot 或 history 引用，就必须同时保留在 SOW 与客户端 package bundle 中。
- `edge.token_verifier` 使用 `provider://...` 非秘密部署引用；真实 entitlement/token/Basic
  数据只经边缘运行环境 secret/provider 注入，不把旧 `fileauth.txt` 配成 asset。

[`fixtures/pigsty-v1.yaml`](fixtures/pigsty-v1.yaml) 是可加载、无秘密的**完整物理迁移
合同**，不是生产即用配置。它以 98 个 repo ID 表达 11 个 APT archive、74 个 YUM path
template 和 13 个 asset owner；展开后与固定盘点逐路径闭合为 74 个 APT index、130 个普通
YUM leaf、7 个根 exact key、8 个根 prefix 和 16 个 gated pro 文件。APT PGDG 的 sparse
suite/component 与 per-suite lifecycle、Percona 的独立 noarch repodata、asset target
affinity 和 repo_groups 均为 machine-gated 合同。

相邻的 [`fixtures/pigsty-v1-migration-ledger.tsv`](fixtures/pigsty-v1-migration-ledger.tsv)
明确把 lifecycle 标成 `policy-unverified`，把 APT Release signer 标成
`not-inventory`，把旧 YUM metadata 标成 `not-claimed`、RPM package keyring 标成
`unverified`；这些值是可逆且 fail-closed 的迁移默认，不是通过声明。两个
`yum/infra/{arch}` leaf 仅由 inactive inventory carrier 表达，处置为
`quarantine-compat`，不进入任何 repo_group、view、ref、publish target 或 upstream；PGDG
nested child 不成为 repo，处置为 `quarantine-overlap`，并由父 repo exclude。

`apt-infra` 还显式排除 `stash/**` 和两个 `rustfs_1.0.0-a94_*.deb`。前者是旧
builder handoff，不是可服务 pool；后者经 Packages、reprepro `packages.db` 与
`references.db` 三方核对均未被引用，而 `1.0.0-b8` 才是当前索引版本。迁移只在配置中
quarantine，绝不删除或移动源字节；若以后确需 a94，必须作为有明确 suite/component 的
新输入重新接纳，不能把文件存在本身当作历史 membership 证明。

旧 `bin/` 由 `active:false` 的 asset inventory carrier 建立 M0/local-fsck 基线；其
`public_path` 只是一条非根、不可路由的 ownership identity，普通 selector、generic
`init --adopt-content`、view、publish、remote fsck 与 edge 均不能使用 carrier。
2026-07-17 后，gated Pro、COS-only ROOT 与 shared ROOT canonical owner 已分别通过本地
exact-copy/canonical-builder/SOW handoff 并按 exact target affinity 激活；这只允许进入后续
staging，不授权生产 publish。shared ROOT 必须重新运行受审 builder，禁止从两份旧正文任意
挑一份。`bin/fileauth.txt` 永不进入 manifest。

旧 12-repo 局部夹具改名为
[`fixtures/pigsty-v1-synthetic.yaml`](fixtures/pigsty-v1-synthetic.yaml)，只继续服务已存在的
legacy adoption 回归；[`fixtures/selector-matrix.yaml`](fixtures/selector-matrix.yaml) 仍只证明
33-repo / 73-leaf selector generalization。`test-physical-migration-config.sh` 对这两个 fixture
都有必须失败的负例，禁止它们冒充完整物理迁移证据。复制完整合同到仓库外受保护路径后，
仍必须补齐真实 public-only signer bundle、审核 lifecycle、冻结 infra compatibility
projection、收敛 target-specific 根脚本正文，并按后续门禁配置独立 non-production target；
不得添加或测试任何生产 CO/COS/CF 资源。

### 1.1 本地回归夹具

下列命令不执行 Make recipe、不连接外部远端：账本审计证明 fail-closed；family harness
把 44 个操作族逐项绑定到真实 CLI/FS/parser/本地 provider-protocol 测试或显式 disposition；
并用仅位于临时目录的 5 个突变夹具验证缺族、Help 冒充、错误处置、publish 缺 provider
和 compatibility 架构证据缺口均被拒绝；
adoption fixture 则证明 asset adoption→隔离 materialize→坏候选检测→切回 untouched
legacy root：

```bash
cd "$SOW_SRC"
docs/migration/test-audit-legacy-targets.sh "$LEGACY_ROOT"
docs/migration/test-family-e2e.sh
docs/migration/test-local-adoption-rollback.sh
docs/migration/test-writer-fence-preflight.sh
```

这只是可重复本地证据；不能代替生产 Nginx reload、真实旧仓全量 client、主机/云撤权或
双云回滚。

## 2. Phase 0：只读盘点

### 2.1 锁定旧工作流版本

先运行机器账本审计；它不执行任何 Make recipe：

```bash
cd "$SOW_SRC"
docs/migration/audit-legacy-targets.sh \
  --legacy-root "$LEGACY_ROOT" \
  --sow-bin "$SOW_BIN" \
  --emit-tsv "$EVIDENCE/legacy-target-map.tsv" \
  | tee "$EVIDENCE/legacy-target-audit.txt"
grep -F 'targets root=52 apt=70 yum=14 docker=40 total=176' \
  "$EVIDENCE/legacy-target-audit.txt"
grep -F 'ledger coverage: exact' "$EVIDENCE/legacy-target-audit.txt"
grep -F 'disposition closure: exact' "$EVIDENCE/legacy-target-audit.txt"
grep -F 'cli surface/enums: current' "$EVIDENCE/legacy-target-audit.txt"
grep -F 'cli semantic equivalence: not asserted' "$EVIDENCE/legacy-target-audit.txt"
test "$(wc -l < "$EVIDENCE/legacy-target-map.tsv" | tr -d ' ')" = 177
```

若 source fingerprint、target 集、处置 schema 或 CLI flag 任一变化，脚本会非零退出且不写
TSV。停止并重新审阅语义；不要在旧 Makefile/CLI 变化后沿用旧审计结论。

### 2.2 保存服务字节基线

在覆盖整个扫描的写入冻结窗口内运行；至少停止会修改同一树的 Make、rclone、rsync、
reprepro、createrepo、rpm signing 和 bind-mounted Docker container。脚本对每个文件做
hash 前后 size 检查，但不能把多文件树变成原子快照，也不能排除 hash 区间外的同尺寸
重写；没有外部 writer freeze 就不能把 TSV 当零字节迁移基线。脚本默认加载
[`fixtures/legacy-sensitive-paths.txt`](fixtures/legacy-sensitive-paths.txt)：这些已审核的非服务
secret 路径会被完全略过，正文、size、digest 与 path 都不进入 TSV，文件也不会被打开。
新增的敏感文件名若未审核会在任何普通文件 hash 前失败；额外的精确相对路径清单可作为
第三个参数传入。不要用宽泛目录排除代替逐文件审核：

```bash
cd "$SOW_SRC"
docs/migration/snapshot-serving-tree.sh \
  "$LEGACY_ROOT" "$EVIDENCE/serving-before.tsv"

# 如存量树另有已审核的非服务 secret，只写路径、不写值：
# docs/migration/snapshot-serving-tree.sh \
#   "$LEGACY_ROOT" "$EVIDENCE/serving-before.tsv" \
#   "$EVIDENCE/reviewed-sensitive-paths.txt"
```

另存以下外部基线，但当前仓库没有自动化实现，故必须标为人工采集而非 SOW 验证：

- CF 与 COS 的完整 object key、size、SHA-256/ETag、metadata；
- `https://repo.pigsty.io/pkg/pig/latest` 及国内对应 URL 的状态、正文、重定向、缓存头；
- APT/YUM 所有现有客户端 URL；
- Nginx/CDN origin 与公开域名映射。
- 最近一次与本次候选变更集同规模的旧 Make/rclone 发布日志：开始/结束 UTC、上传对象与
  字节数、两云各自耗时、purge/验证耗时、网络出口及失败重试。若历史日志不足，必须在
  冻结的 staging 副本上计时一次旧流程，不得为测量触碰生产 bucket。迁移后用同仓库、同
  变更集和相近网络窗口重跑 SOW；ANTI-01 同时要求总事务 `<10 min` 与相对旧流程不显著变慢。

不要把访问密钥、token、passphrase、`fileauth.txt` 正文、其 digest/size，或 Docker 镜像里的
私钥写入证据目录。敏感路径清单只能含仓库相对路径；不得把 secret 值误当成清单内容。

### 2.3 控制目录拒绝门禁（生产 adoption 前置，当前环境 BLOCKED）

在任何 `sow init` 或 `init --adopt-content` 写入公开 origin 根之前，先由仓库外的 Nginx
配置建立 default-deny allowlist：只允许 `sow.yaml` 声明的公开仓库前缀、`/_sow/` 和公开
签名 key，其他路径统一 404。仅拒绝 `/.sow/`、`/.pool/`、`/.git/` 不足以保护同根的
`sow.yaml` 或运维 secret 文件。reload 后再用无秘密 canary 同时探测直连 origin 和所有
公开域名。仅仅因为文件尚不存在而得到 404 不能作为证据；探测时本地文件必须真实存在。
下面的地址需替换成生产值，状态只能是 403/404，任何 2xx/3xx 都立即停止：

```bash
export ORIGIN_HOST=repo.pigsty.io
export ORIGIN_IP=192.0.2.10                 # 替换为真实 private/origin IP
export PUBLIC_BASES='https://repo.pigsty.io https://repo.pigsty.cc'
CONTROL_CANARY="sow-control-deny-$(date +%Y%m%d%H%M%S)-$$"
ROOT_CANARY="sow-operator-secret-deny-$(date +%Y%m%d%H%M%S)-$$"

mkdir -p "$LEGACY_ROOT/.sow" "$LEGACY_ROOT/.pool"
printf 'non-secret deny probe\n' > "$LEGACY_ROOT/.sow/$CONTROL_CANARY"
printf 'non-secret deny probe\n' > "$LEGACY_ROOT/.pool/$CONTROL_CANARY"
printf 'non-secret deny probe\n' > "$LEGACY_ROOT/$ROOT_CANARY"
trap 'rm -f "$LEGACY_ROOT/.sow/$CONTROL_CANARY" "$LEGACY_ROOT/.pool/$CONTROL_CANARY" "$LEGACY_ROOT/$ROOT_CANARY"' EXIT

for control in .sow .pool; do
  code=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --resolve "$ORIGIN_HOST:443:$ORIGIN_IP" \
    "https://$ORIGIN_HOST/$control/$CONTROL_CANARY?deny_probe=$CONTROL_CANARY")
  case "$code" in 403|404) ;; *) echo "origin exposes /$control: HTTP $code" >&2; exit 1;; esac
  printf 'origin %s %s\n' "$control" "$code" | tee -a "$EVIDENCE/control-path-deny.txt"

  for base in $PUBLIC_BASES; do
    code=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
      -H 'Cache-Control: no-cache' "$base/$control/$CONTROL_CANARY?deny_probe=$CONTROL_CANARY")
    case "$code" in 403|404) ;; *) echo "$base exposes /$control: HTTP $code" >&2; exit 1;; esac
    printf '%s %s %s\n' "$base" "$control" "$code" | tee -a "$EVIDENCE/control-path-deny.txt"
  done
done

for control in sow.yaml "$ROOT_CANARY"; do
  test -f "$LEGACY_ROOT/$control" || { echo "deny probe does not exist: $control" >&2; exit 1; }
  code=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --resolve "$ORIGIN_HOST:443:$ORIGIN_IP" "https://$ORIGIN_HOST/$control?deny_probe=$ROOT_CANARY")
  case "$code" in 403|404) ;; *) echo "origin exposes /$control: HTTP $code" >&2; exit 1;; esac
  printf 'origin %s %s\n' "$control" "$code" | tee -a "$EVIDENCE/control-path-deny.txt"
  for base in $PUBLIC_BASES; do
    code=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
      -H 'Cache-Control: no-cache' "$base/$control?deny_probe=$ROOT_CANARY")
    case "$code" in 403|404) ;; *) echo "$base exposes /$control: HTTP $code" >&2; exit 1;; esac
    printf '%s %s %s\n' "$base" "$control" "$code" | tee -a "$EVIDENCE/control-path-deny.txt"
  done
done
rm -f "$LEGACY_ROOT/.sow/$CONTROL_CANARY" "$LEGACY_ROOT/.pool/$CONTROL_CANARY" "$LEGACY_ROOT/$ROOT_CANARY"
trap - EXIT
```

还必须保存已生效 Nginx location/deny 配置和 reload 结果。SOW 不管理 Nginx；没有真实
origin 地址/维护窗口时该门禁保持 `BLOCKED`，不得以本地 fixture 代替后继续生产 adoption。

## 3. Phase 1：零字节纳管（当前可执行）

`sow init` 只在 `LEGACY_ROOT/.sow/` 建立正典状态与 SQLite cache；它不应改变已有服务文件。
为保证扫描一致性，本阶段仍要求旧写者静止，并且第 2.3 节控制目录拒绝门禁已经通过。

```bash
"$SOW_BIN" init \
  --config "$SOW_CONFIG" \
  --root "$LEGACY_ROOT" \
  --workers 8

"$SOW_BIN" fsck \
  --config "$SOW_CONFIG" \
  --root "$LEGACY_ROOT" \
  --limit 200 \
  | tee "$EVIDENCE/fsck-after-init.txt"

# 每个目标必须单独、显式纳管；该命令只读远端，但会提交本地 canonical
# inventory/content baseline。执行期间旧发布者必须继续保持静止。
"$SOW_BIN" fsck \
  --config "$SOW_CONFIG" \
  --root "$LEGACY_ROOT" \
  --target cf \
  --adopt-remote-inventory \
  --workers 8 \
  --limit 200 \
  | tee "$EVIDENCE/fsck-adopt-cf.txt"

"$SOW_BIN" fsck \
  --config "$SOW_CONFIG" \
  --root "$LEGACY_ROOT" \
  --target cos \
  --adopt-remote-inventory \
  --workers 8 \
  --limit 200 \
  | tee "$EVIDENCE/fsck-adopt-cos.txt"

cd "$SOW_SRC"
docs/migration/snapshot-serving-tree.sh \
  "$LEGACY_ROOT" "$EVIDENCE/serving-after-init.tsv"
cmp "$EVIDENCE/serving-before.tsv" "$EVIDENCE/serving-after-init.tsv"
```

通过条件：

1. `init` 成功并输出 baseline commit；
2. 本地 `fsck` 退出 0，无 drift；
3. 两个 adoption 都经过双 List + HEAD/必要时流式 GET，输出 `inventory_coverage=complete`；`retained_extra` 必须逐项审阅，但不会被自动删除；
4. 两份 serving-byte TSV 完全相同；唯一新增内容位于被排除且已由 HTTP deny 保护的
   `.sow/` 与 `.pool/` 控制目录；
5. 旧 URL 尚未切换，CF/COS 未被写入；adoption 只读对象存储并只写本地 canonical state。

### Phase 1 回滚

Phase 1 没有服务切换，也没有远端写入。发生问题时先停止 SOW，不要删除或重写旧服务树；失败的 adoption 在双 List/HEAD/GET/local subset 任一门禁失败时不会提交 inventory。成功 adoption 只增加本地 Git 历史，可保留用于诊断或由维护者回退到 adoption 前 commit。恢复旧 Makefile 只读/写入资格前，再跑一次 `serving-after-init.tsv` 对账，证明已有制品未变。

## 4. Phase 2：本地内容纳管与显式结构迁移（可执行）

### 4.1 adoption 前置门禁

再次冻结旧写者，并重新获取服务树基线。配置中的 repo path、APT suite/component/arch、
YUM EL/arch、默认 pool 和 lifecycle 必须与现有树一致。纳管器不会猜包成员：APT 包必须
由 `Packages[.gz|.xz|.zst]` 证明，YUM 包必须由已校验的
`repodata/repomd.xml -> primary` 证明；asset repo 则纳管 baseline manifest 的全部文件。
任何索引缺失、路径逃逸、symlink、size/SHA256 或 DEB/RPM body 身份不一致都会失败。
第 2.3 节 origin/CDN 控制目录拒绝证据也必须仍然有效；`.pool/` 被 byte snapshot 排除是
因为它是 SOW 控制状态，不代表它可以被 HTTP 暴露。

旧写者冻结是整个 `init --adopt-content` 调用的互斥前提，不是一次瞬时检查：紧邻命令前
必须重新运行第 8 节 `writer-fence-preflight.sh` 的三个 live probe，确认
`production_current_host_preflight=pass`，并保持旧 Make/cron/container/cloud writer 已撤销、
服务树对其不可写，直至命令退出。SOW state lock 只串行 SOW 命令，不能假装锁住任意第三方
进程。命令在 Apply 前会再次扫描并拒绝已观察到的 drift；这个扫描是读侧线性化门禁，不是
对违反冻结契约的外部 writer 提供可移植的目录锁。若冻结边界被破坏，立即停止迁移、重跑
`sow fsck` 与 byte snapshot 对账，再从新的 M0 baseline 重试。

```bash
cd "$SOW_SRC"
docs/migration/snapshot-serving-tree.sh \
  "$LEGACY_ROOT" "$EVIDENCE/serving-before-adopt.tsv"

# 默认只建立 latest。每次操作仍可用 --repo/--os/--arch 缩小选择器。
"$SOW_BIN" init --adopt-content \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --view latest --workers 8 \
  | tee "$EVIDENCE/adopt-content-latest.txt"

# 只有业务确认当前存量也属于 append-only Pro stable 时才同时或随后执行：
# "$SOW_BIN" init --adopt-content \
#   --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
#   --view stable --workers 8 \
#   | tee "$EVIDENCE/adopt-content-stable.txt"

docs/migration/snapshot-serving-tree.sh \
  "$LEGACY_ROOT" "$EVIDENCE/serving-after-adopt.tsv"
cmp "$EVIDENCE/serving-before-adopt.tsv" "$EVIDENCE/serving-after-adopt.tsv"
grep -F 'serving_tree_rewritten=false' "$EVIDENCE/adopt-content-latest.txt"
grep -F 'yum_metadata_signature=not-claimed yum_metadata_keyring_sha256=-' \
  "$EVIDENCE/adopt-content-latest.txt"
```

#### 4.1.1 缺体 YUM primary 的审计绑定修复

默认失败输出会给出最多 20 项 `kind=indexed-body-missing` 预览（repo、path、期望
size/SHA-256、name/version/arch）、完整集合的 `confirmation sha256=<digest>`，以及
`exact blocker report count=... sha256=... path=<STATE>/reports/legacy-adoption-blockers-....tsv`。
全集由 SQLite spool 流式写入该私有报告，避免大规模缺体时在 Go heap 和 stderr 中构造
O(N) 字符串；stderr 的 `omitted=N` 不是丢失证据。先复制并保存 path 指向的完整报告，
再从已批准的官方当前站/归档恢复每个仍可获得的精确 body。报告文件 SHA 是整个 TSV 的
完整性摘要；`confirmation sha256` 只绑定其中 `indexed-body-missing` 身份集合，两者用途
不同。下载结果必须与 primary 的 size/SHA-256 同时相等，且不得覆盖已有路径。所有操作
仍只在本地可丢弃副本进行，不能把 CO/COS/Cloudflare 生产仓库、bucket、domain 或 Zone
用作恢复/测试目标。

恢复后重新执行默认 adoption，保存并人工审阅缩小后的完整报告。只有已证明上游当前站
和归档均不再提供的剩余条目，才允许把该次报告中的 exact digest 作为显式确认值：

```bash
# 预期失败；保存 stderr，并按其中 path 复制完整、当前的 blocker TSV，不能只复制 digest。
"$SOW_BIN" init --adopt-content \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --repo reviewed-yum-group --view latest --workers 8 \
  >"$EVIDENCE/yum-missing-preflight.stdout" \
  2>"$EVIDENCE/yum-missing-preflight.stderr"

# 人工核对报告后填入；不要用管道自动提取并立即执行。
CONFIRMED_MISSING_YUM_SHA256='<reviewed-lowercase-sha256>'
"$SOW_BIN" init --adopt-content \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --repo reviewed-yum-group --view latest --workers 8 \
  --adopt-prune-missing-yum-confirm "$CONFIRMED_MISSING_YUM_SHA256" \
  | tee "$EVIDENCE/yum-missing-confirmed.txt"
```

wrong/stale digest、空集合、两次解析之间的 index 变化，或新出现/消失的缺体条目都必须
在 view commit 前失败。成功输出必须含相同 `confirmed_sha256`、精确
`pruned_missing_yum=<count>` 与 `serving_tree_rewritten=false`，并在 canonical Git 中
生成严格有序的 `provenance/legacy-pruned/<repo>.jsonl`。该参数只处理“index 有条目、
M0 无 body”的 YUM 情形；本地存在但无 index 证明的 `.rpm/.deb/.ddeb` 仍必须修复索引
或在配置中显式 quarantine，不能借此删除或猜 membership。账本进入 canonical Git 后
必须在 HEAD 与所有 direct-ref 可达历史中永久、字节不变；删除、替换或改绑非 repo-ref
祖先的 M0 都会被 mutation/fsck 门禁拒绝。

confirmed adoption 仍不改旧 primary。必须随后物化到独立 candidate，使用当前 repo
签名 key 生成与实际 adopted bodies 一致的新 repodata，并执行 L1、真实 dnf 和 serving
byte 对账后才可进入切换评审；即使剩余集合把某个 leaf 修复为空仓库，也必须生成可由
DNF 验证的完整、已签名零包 repodata。完整语义见
[ADR-0030](../adr/0030-audit-bound-legacy-yum-missing-body-prune.md)。

`not-claimed` 是当前 Pigsty-v1 物理树的预期事实：只读 inventory 找到 131 个
`repomd.xml`，没有任何 `repomd.xml.asc`。它不降低 repomd/primary/RPM 的 size 与
SHA-256 校验，也不伪造旧 metadata 的 signer。不得把 `gpg.public_key`（新 metadata
签名身份）或 `yum.package_keyring`（RPM payload signer 集）自动套用到旧 repomd。

只有每个选中 YUM leaf 都真实存在由同一审核 trust bundle 可验证的 `.asc` 时，才使用：

```bash
"$SOW_BIN" init --adopt-content \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --repo reviewed-signed-yum-group --view latest --workers 8 \
  --legacy-metadata-keyring /absolute/path/to/legacy-metadata-public-keys.asc \
  | tee "$EVIDENCE/adopt-content-signed-yum.txt"
grep -F 'yum_metadata_signature=verified yum_metadata_keyring_sha256=' \
  "$EVIDENCE/adopt-content-signed-yum.txt"
```

该 keyring 必须是 bounded、non-symlink、public-only 文件（相对路径按 config 所在目录解析）；
CLI 在 state lock/canonical mutation 之前读取并冻结其 SHA-256。显式提供后，任一选中 YUM
leaf 缺 `.asc`、验签失败或 keyring 含私钥都会 fail closed。不要为了得到 `verified` 补签
旧 metadata；那会把迁移时新生成的签名错误陈述为历史证据。

该 `cmp` 必须逐字节通过。adoption 只会写 `.sow/` canonical/cache、`.pool/sha256/`
CAS 与 legacy receipt，不会生成或覆盖服务索引。失败时 baseline `init` 状态可以保留；
view ref 与 `provenance/legacy/*.jsonl` 不得部分推进，已成功导入的 content-addressed
对象只会成为可由 `sow gc` 报告的 orphan。原命令重放应输出 `changed=false`。

通过条件：

1. 每个选择的 leaf 都建立 `latest`（及明确选择的 `stable`）ref；
2. receipt schema 为 `sow-legacy-adoption/v1`，只声明 legacy migration，不伪造上游签名来源；
3. public view 只含 public pool；gated 默认 pool 纳入 latest 必须失败，不能 force；
4. frozen/EOL repo 可作为历史纳管，但后续 `add`/`sync` 仍拒绝写入；
5. `sow fsck` 与 `sow gc` dry-run 能读取 adoption 后 canonical/CAS 状态。
6. CLI 的 `peak_import_workers` 是导入器实际并发观测值，不是 `--workers` 的回显；大规模
   staging 复核可用 `go test -tags perf ./test/perf -run
   '^TestLegacyAssetAdoptionFiftyThousand$' -count=1 -v -timeout=20m`。该测试只写
   `t.TempDir`，不得把 `LEGACY_ROOT` 或任何生产云资源作为性能夹具。

legacy adoption receipt 只证明索引成员、原字节和迁移来源，不证明 RPM signer 仍受当前
信任策略接受。第一次 `materialize` 或 `publish` 会对所有选中 YUM payload 使用对应 repo
的 `yum.package_keyring` 做密码学验签；独立 `verify --layer L1` 还会逐个验证 indexed RPM。
缺失历史 signer、错 key、header/payload 篡改或未签名 RPM 都必须在服务切换和远端写入前
失败闭锁，不能因字节已进入 CAS 或已有 legacy receipt 而跳过。

### 4.2 frozen cross-EL `yum/infra/{arch}` 的 S0→S3 工作流

`yum/infra/x86_64` 与 `yum/infra/aarch64` 不是普通 EL9 leaf。不得用
`init --adopt-content`、`add`、`sync` 或普通 selector 把其 mixed-EL RPM relabel 成 EL9。
它们必须按 [ADR-0021](../adr/0021-frozen-cross-el-yum-infra-compatibility-projection.md)
逐 architecture 通过专用状态机。以下演练必须在本地完整 clone/staging 根执行；不得把任何
CO/COS/Cloudflare 生产仓库、bucket、domain、Zone 或 CDN 当测试目标，也不得为了“只读确认”
连接这些生产资源。

配置先声明一个 inactive、public、unfiltered、cross-el/0、frozen/gzip carrier，以及独立
enabled EL9/10 zstd policy owner；每个 projection 的 `source.os` 必须是 `cross-el`，初始
`source.commit` 使用 `pin-at-first-freeze`。carrier 与 projection 示例见 ADR-0021。生产配置
所引用的 `yum.package_keyring` 必须是审核过的 public-only RPM signer bundle，不能读取
`/Users/vonng/pgsty/repo/docker/private.asc` 或任何其他私钥作为 package trust。

先在 raw tree byte snapshot 保护下建立完整 S0 carrier baseline。若一个 carrier 同时包含两种
architecture，可以选择 carrier repo，但不能再带 `--arch` 缩小它：

```bash
docs/migration/snapshot-serving-tree.sh \
  "$LEGACY_ROOT" "$EVIDENCE/compat-s0-before.tsv"

"$SOW_BIN" init \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --repo infra-legacy-carrier --workers 8 \
  | tee "$EVIDENCE/compat-s0-init.txt"

docs/migration/snapshot-serving-tree.sh \
  "$LEGACY_ROOT" "$EVIDENCE/compat-s0-after.tsv"
cmp "$EVIDENCE/compat-s0-before.tsv" "$EVIDENCE/compat-s0-after.tsv"
```

S0 接受旧 unsigned seven-record repomd 只是迁移输入：primary/filelists/other XML、三个
sqlite record 与 modules record 都必须有匹配的 compressed/open SHA-256 与 size。sqlite、
modulemd、zchunk 绝不进入新候选输出。

随后逐 projection 建立 S1 adoption。该命令重新验证 S0、逐 RPM 验签、导入 CAS，并固定
`refs/sow/compatibility/yum-source/<id>`；raw tree 仍须逐字节不变：

```bash
export COMPAT_ID=infra-legacy-x86-64

"$SOW_BIN" compatibility yum-adopt \
  --id "$COMPAT_ID" --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --workers 8 \
  | tee "$EVIDENCE/$COMPAT_ID-s1-adopt.txt"

grep -F 'served_tree_rewritten=false' "$EVIDENCE/$COMPAT_ID-s1-adopt.txt"
```

候选必须位于 hosted root 之外。下例使用已在第 1 节证明位于 `LEGACY_ROOT` 外的
`EVIDENCE`；私钥/passphrase file 也必须是 root 外的受保护 regular file。CLI 只把路径写入
本地 transaction，不把候选物理路径写入 canonical receipt：

```bash
umask 077
export COMPAT_CANDIDATE="$EVIDENCE/candidates/$COMPAT_ID"
mkdir -p "$EVIDENCE/candidates"

"$SOW_BIN" compatibility yum-candidate \
  --id "$COMPAT_ID" --output "$COMPAT_CANDIDATE" \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --gpg-private-key-file "$KEY_FILE" \
  --gpg-passphrase-file "$PASS_FILE" \
  --workers 8 \
  | tee "$EVIDENCE/$COMPAT_ID-candidate.txt"

FREEZE_CONFIRM="$(sed -n 's/.* freeze_confirm=\([^ ]*\).*/\1/p' \
  "$EVIDENCE/$COMPAT_ID-candidate.txt")"
[[ "$FREEZE_CONFIRM" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 2
```

候选必须只有 clean signed primary/filelists/other gzip XML、`repomd.xml`/`.asc`、canonical
`Packages/<bucket>/` payload 与 byte-identical flat aliases。任何已有 output/sidecar 只允许
exact replay；中断时用同一 `--id/--output` 加 `--recover`，不得手工拼接或覆盖 sidecar。

用上一步 content-bound token 固定 S2。S2 将 candidate manifest/receipt、projection witness、
repository trust 与 payload closure 固定到 `refs/sow/compatibility/yum/<id>`，但仍不得开放
candidate、generation、mirrorlist 或两条 frozen trust URL：

```bash
"$SOW_BIN" compatibility yum-freeze \
  --id "$COMPAT_ID" --candidate "$COMPAT_CANDIDATE" \
  --confirm "$FREEZE_CONFIRM" \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" --workers 8 \
  | tee "$EVIDENCE/$COMPAT_ID-s2-freeze.txt"

CUTOVER_CONFIRM="$(sed -n 's/.* cutover_confirm=\([^ ]*\).*/\1/p' \
  "$EVIDENCE/$COMPAT_ID-s2-freeze.txt")"
[[ "$CUTOVER_CONFIRM" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 2
grep -F 'served_tree_rewritten=false' "$EVIDENCE/$COMPAT_ID-s2-freeze.txt"
```

S3 是不可与“生成候选”混为一谈的显式切换授权。仅在本地 staging clone 完成真 DNF、
Nginx include 与 rollback 演练后，才能在获批生产维护窗口执行相同动作：

```bash
"$SOW_BIN" compatibility yum-cutover \
  --id "$COMPAT_ID" --confirm "$CUTOVER_CONFIRM" \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" --workers 8 \
  | tee "$EVIDENCE/$COMPAT_ID-s3-cutover.txt"

ROLLBACK_CONFIRM="$(sed -n 's/.* rollback_confirm=\([^ ]*\).*/\1/p' \
  "$EVIDENCE/$COMPAT_ID-s3-cutover.txt")"
[[ "$ROLLBACK_CONFIRM" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 2
grep -F 'raw_tree_rewritten=false' "$EVIDENCE/$COMPAT_ID-s3-cutover.txt"

# S3 只授予 canonical authority；随后 ordinary materialize 才安装 exact
# generation/mirrorlist 与两个 frozen public trust object。
"$SOW_BIN" materialize latest \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" --workers 8
"$SOW_BIN" materialize latest \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --nginx-include "$EVIDENCE/sow-latest.locations.conf"
"$SOW_BIN" fsck \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" --workers 8
```

`yum-cutover` 先写本地 crash journal、再 append canonical event、最后通过 root-bound directory
handle 翻转 `.sow/serving/compatibility/yum/<id>/current`。任一步中断后，所有普通命令（包括
Nginx/edge render-only 与 publish）都必须在输出、state cleanup 或 provider construction 前
失败。恢复只能重跑原动作、原 token 并增加 `--recover`：

```bash
"$SOW_BIN" compatibility yum-cutover \
  --id "$COMPAT_ID" --confirm "$CUTOVER_CONFIRM" --recover \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" --workers 8
```

回滚不是删 commit/ref 或把 ledger 改回去；它 append 一条绑定前序 event 的 rollback，并把
controlled link 切回 exact raw target。随后 ordinary `materialize latest`/`publish` 才会以同一
事务移除 S3-only compatibility mirrorlist、active generation pointer 与两条 frozen trust
public entry point；已验证的 raw bridge 必须继续可消费，历史 immutable generation 与 S1/S2
CAS roots 保留：

```bash
"$SOW_BIN" compatibility yum-rollback \
  --id "$COMPAT_ID" --confirm "$ROLLBACK_CONFIRM" \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" --workers 8 \
  | tee "$EVIDENCE/$COMPAT_ID-s3-rollback.txt"

"$SOW_BIN" materialize latest \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" --workers 8 --recover
"$SOW_BIN" fsck \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" --workers 8
```

真实 CO/COS/Cloudflare 生产资源不属于上述测试流程。需要双云证据时，只能另用编译期 registry
已固定、独立审核且明显 non-production 的专用资源；registry 为空就保持 fail closed。

### 4.3 显式 materialize 到隔离候选树

`init --adopt-content` 不改服务树；以下命令才会原子重建所选 latest 服务布局，并使用
SOW 内建生成器产生 APT Release/InRelease/by-hash 或 YUM repodata pair。它可能改变
metadata 文件、签名、时间戳、压缩正文和新增 by-hash；这些变化不能与 adoption 的
零重写保证混为一谈。迁移期禁止省略 `--target` 直接重写当前服务树；显式候选目录必须是
仓库根下、不与 repo 或 `.sow`/`.pool`/`.git`/`_sow` 控制命名空间重叠的专用目录。
下面固定使用 `.sow-migration-staging/`：它不是 SOW 控制目录，当前 origin 的默认拒绝
allowlist 必须保证它在切换前不能经 HTTP 访问。验证完成后由仓库外的 Nginx root/symlink
原子切换；不要为了把候选塞进 `.sow/materialized/` 而放宽 CLI 的控制目录保护。

```bash
export KEY_FILE=/absolute/protected/path/repository-private.asc
export PASS_FILE=/absolute/protected/path/repository-passphrase
export STAGING_ROOT="$LEGACY_ROOT/.sow-migration-staging/migration-candidate"
# Exact clean base URL that the candidate mirrorlist will use after cutover.
# For latest this is the existing public origin; stable would end in /pro/v1/basic.
export STAGING_SERVING_BASE_URL=https://repo.pigsty.io

docs/migration/snapshot-serving-tree.sh \
  "$LEGACY_ROOT" "$EVIDENCE/serving-before-materialize.tsv"

"$SOW_BIN" materialize latest \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --target "$STAGING_ROOT" \
  --serving-base-url "$STAGING_SERVING_BASE_URL" \
  --gpg-private-key-file "$KEY_FILE" \
  --gpg-passphrase-file "$PASS_FILE" --workers 8 \
  | tee "$EVIDENCE/materialize-latest.txt"

docs/migration/snapshot-serving-tree.sh \
  "$STAGING_ROOT" "$EVIDENCE/serving-after-materialize.tsv"
diff -u "$EVIDENCE/serving-before-materialize.tsv" \
  "$EVIDENCE/serving-after-materialize.tsv" \
  > "$EVIDENCE/materialize-layout.diff" || true

"$SOW_BIN" verify --layer L1 \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" --workers 8 \
  | tee "$EVIDENCE/verify-L1-canonical.txt"
"$SOW_BIN" fsck \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" --limit 200 \
  | tee "$EVIDENCE/fsck-legacy-unchanged.txt"
```

必须审阅 `materialize-layout.diff`：APT package 与 asset 的既有相对路径、所有 payload 的
size/SHA-256 需保持一致。按 [ADR-0027](../adr/0027-legacy-package-adoption-admission-and-canonicalization.md)，
primary 中任何 normalized、index+M0 双重证明的 flat 或 nested RPM href 都迁为 canonical
`Packages/<name 首字母>/<basename>`；legacy receipt 必须保留每个 `source_path` 到
`canonical_path` 的映射。错误的既有 `Packages/` 桶、逃逸、不同字节 collision、未列 RPM/DEB、
缺失的 indexed body 或 checksum 篡改都必须在 CAS/ref/ledger 前失败。其余差异只能来自已批准的 metadata/layout 生成（例如
APT by-hash、Release/签名、YUM repodata 成对翻转）。上面的 L1 验证 canonical view，fsck 证明 legacy 服务树仍与
baseline 一致；二者都不冒充 candidate 检查。candidate 由 materialize 的 exact reconcile、
serving TSV 和随后真实隔离 client 三层验收。对所有已配置 suite/arch 执行
受支持的 apt >= 1.2 执行 `apt update`/目标包 install，以及 EL8/9/10 的
`dnf makecache`/目标包 install，并把命令、
镜像 digest、退出码与安装结果写入 `$EVIDENCE`。未取得这些 client 证据不得切换 origin。
`STAGING_SERVING_BASE_URL` 会进入 YUM generation mirrorlist，不能使用占位域名、带凭据 URL
或 staging 磁盘路径；必须在 materialize 前与待切换的 public/latest（或 stable Basic）客户端
基线逐字节核对。CLI 对任何含 mutable YUM 的显式 `--target` 都强制要求该参数，以免导出树
悄悄继承错误 target/host。

### 4.4 Pigsty YUM consumer 配置的隔离 stage

强 generation tree 可用不等于旧 `baseurl=` consumer 已切换。先对真实 Pigsty source
做只读审计，并把 renderer/config 改动 stage 到 checkout 外；`audit` 和 `stage` 都不得
改源树。当前 allowlist 是两个 renderer、九个配置文件和 22 个 managed definition，任何
未知、漏失或重复定义都会失败闭锁。

```bash
export PIGSTY_SRC=/absolute/path/to/pigsty
export YUM_CONSUMER_STAGE="$EVIDENCE/yum-consumer-stage"
export YUM_CONSUMER_EVIDENCE="$EVIDENCE/yum-consumer-apply"
export YUM_ENDPOINT_RECEIPT="$EVIDENCE/yum-consumer-preflight-$(date -u +%Y%m%dT%H%M%SZ).json"
export RPM_TRUST_BUNDLE=/absolute/path/to/reviewed-public-only-rpm-trust.asc
export SOW_CONFIG=/absolute/path/to/sow.yaml
export SOW_BIN=/absolute/path/to/sow

docs/migration/migrate-pigsty-yum-consumers.sh audit \
  --pigsty-root "$PIGSTY_SRC"
docs/migration/migrate-pigsty-yum-consumers.sh stage \
  --pigsty-root "$PIGSTY_SRC" --output "$YUM_CONSUMER_STAGE"

# 人工审阅 manifest.tsv、全部 staged diff、repo/OS/arch 映射和 key URL。
export YUM_CONSUMER_PLAN_SHA="$(sed -n '1p' "$YUM_CONSUMER_STAGE/plan.sha256")"
```

map v2 对每个定义分别冻结 x86_64/aarch64 的 `repo/os/arch`。`pigsty-infra` 不再伪装成
per-EL repo，而是分别指向 `infra-legacy-x86-64/cross-el/x86_64` 与
`infra-legacy-aarch64/cross-el/aarch64`；renderer 用 `os_arch` 选择嵌套 mirrorlist。
历史 `conf/build/dev.yml` 中 `pigsty-infra` 的国内 raw source 虽指向 beta，但 frozen
compatibility 只有 latest authority，因此 v2 stage 明确把该绑定归一到
`repo.pigsty.cc/.../latest/infra-legacy-*`，不虚构 beta projection。

此时只允许审阅，不允许 `apply`。先把 `RPM_TRUST_BUNDLE` 作为 public asset 的
`pkg/keys/rpm-trust.asc` 纳管，并使用正常 `sow add` / `publish` 事务发布；不能在桶里手工
上传一个不受 aggregate inventory 管理的同名对象。bundle 必须是 public-only，覆盖 SOW
metadata key 与 staged route 可达 RPM 的全部 signer primary key。

随后必须在两个 public origin 上证明每个 mapped
`/_sow/v1/mirrorlist/latest/<repo>/<os>/<arch>.txt` 返回一个精确 immutable generation
base，且 `/pkg/keys/rpm-trust.asc` 包含 fingerprint-reviewed repository key 与所有保留的
RPM source key。先由单一 Go CLI 产生短时、不可覆盖的 endpoint receipt：

```bash
"$SOW_BIN" compatibility yum-consumer-preflight \
  --config "$SOW_CONFIG" \
  --staged "$YUM_CONSUMER_STAGE" \
  --map docs/migration/yum-consumer-map.tsv \
  --inventory docs/migration/yum-consumer-files.tsv \
  --trust-bundle "$RPM_TRUST_BUNDLE" \
  --receipt "$YUM_ENDPOINT_RECEIPT" \
  --confirm "$YUM_CONSUMER_PLAN_SHA" \
  --workers 8 --chunk-entries 4096
```

preflight 会把 22 个定义展开为全部 release × arch × region binding，逐项绑定当前 canonical
generation/checkpoint/plan 与 target aggregate inventory；inventory 中 trust object 的
size/SHA-256、从 CDN 读取的 bytes 和本地 bundle 必须三者完全一致。metadata 与 RPM
验签都使用客户端实际导入的 aggregate certificate/keyring。每个唯一 endpoint 都必须完成 mirrorlist → exact generation →
repomd + `.asc` → primary/filelists/other → RPM embedded signature。receipt 默认 15 分钟
过期，最短 1 秒、最长 1 小时；metadata/RPM 验证与 receipt 使用取得 canonical lock 后的
同一个 UTC 时刻，探测超过所选窗口则不签发。过期或 canonical/input 漂移后必须换一个
新路径重新生成，不能覆盖旧 receipt。
renderer 的外层 release/module/arch selector 与整个 RPM 分支都按精确控制流冻结；四个
canonical consumer 的 module 也必须分别保持 infra/pgsql/percona/mssql。自定义 YAML tag、
多行 description 或通过 meta 覆盖 baseurl/mirrorlist/gpgkey/enabled/TLS 都会失败闭锁。
所有重探测结束后还会轻量重读每个唯一 mirrorlist/trust URL；随后重读 config 引用的
metadata/package keyring 和全部本地输入，并核对 repository/stage/receipt-parent 的目录
inode；任一长窗口漂移或同路径目录替换都不会产生 receipt。

Go 协议门禁通过后，仍要用 stage 后的真实 Jinja renderer 在 EL7/8/9/10 隔离 client 生成
`.repo`，EL7 执行 `yum --refresh makecache`，EL8/9/10 执行
`dnf --refresh makecache`，全部开启 `repo_gpgcheck=1` 并安装选定包。

这些证据全部通过后，才可用审阅过的同一 digest 申请生产 apply：

```bash
docs/migration/migrate-pigsty-yum-consumers.sh apply \
  --pigsty-root "$PIGSTY_SRC" \
  --staged "$YUM_CONSUMER_STAGE" \
  --evidence "$YUM_CONSUMER_EVIDENCE" \
  --confirm "$YUM_CONSUMER_PLAN_SHA" \
  --sow-bin "$SOW_BIN" \
  --sow-config "$SOW_CONFIG" \
  --trust-bundle "$RPM_TRUST_BUNDLE" \
  --preflight-receipt "$YUM_ENDPOINT_RECEIPT"

docs/migration/migrate-pigsty-yum-consumers.sh verify \
  --pigsty-root "$PIGSTY_SRC"
```

apply 在创建 evidence、备份或改写 Pigsty 之前先执行 network-free
`yum-consumer-receipt-check`；它重新推导 stage/map/inventory/config/trust 与 canonical
publication identity，拒绝过期或重放到另一状态的 receipt。脚本再次对比 Go 输出的
receipt digest 与路径；备份完成后、第一字节写入前还会再次执行同一检查，并要求 receipt
digest 不变。因此慢备份期间的过期、配置或 canonical 漂移不会进入 source mutation。
receipt SHA-256，并在任何 source mutation 前将 exact JSON 归档到 evidence；通过后才逐文件接受 manifest
记录的 before/after SHA-256；已混合写入的中断状态可安全重放，foreign drift 会拒绝继续。
apply receipt 同时记录 endpoint receipt SHA-256。`YUM_CONSUMER_EVIDENCE` 是唯一 rollback
authority，必须和 endpoint/deploy 证据一起保留在 checkout 外。

### Phase 2 回滚

若 adoption 尚未 materialize，停止 SOW 即可，旧服务树未变。隔离 materialize 验证失败时
尚未切 origin，删除/保留 candidate 做诊断即可；不要把 candidate 逐文件覆盖进 legacy。
若已切换后才发现问题，保持写者冻结，把外部 Nginx root/symlink 原子切回事先保留的只读
legacy root。失败 candidate 若需保留诊断，先把整个 `.sow-migration-staging/` 移到当前
origin root 之外的受保护证据目录；随后再用 `serving-before-adopt.tsv` 对完整 legacy root
对账。不能一边把 candidate 留在 legacy root 内，一边宣称全树 byte baseline 完全一致；
仅依赖 HTTP deny 也不能替代这个磁盘证据。`.sow`/`.pool` 可保留诊断，但绝不能同时恢复
旧写者和保留 SOW 写者。修复后从同一 canonical ref 重建新的 candidate，再重复 byte/layout
与真实 client 门禁。

若 Pigsty YUM consumer source 已 apply，则在 origin/client 回切后使用同一 plan digest 做
字节级 rollback；命令会拒绝回滚任何 apply 后出现的 foreign drift，并可从混合状态重放：

```bash
docs/migration/migrate-pigsty-yum-consumers.sh rollback \
  --pigsty-root "$PIGSTY_SRC" \
  --evidence "$YUM_CONSUMER_EVIDENCE" \
  --confirm "$YUM_CONSUMER_PLAN_SHA"
```

回滚完成后必须重新执行 `audit`、逐文件 before SHA-256 对账和旧 raw-baseurl 真 dnf；不能只
看到脚本退出 0 就恢复 scheduler/writer。
若曾使用 provisional map/renderer v1，必须用其原 evidence 先执行同一字节回滚，再从 raw
source 生成新的 v2 stage；v2 工具不会把错误的 v1 infra per-EL route 就地解释成 frozen
cross-EL authority。v1 rollback evidence 仍受支持，但新的 apply/rollback receipt 会保留
归档的 endpoint receipt SHA-256。

## 5. Phase 3：本地切换门禁（BLOCKED）

以下每项有可复现证据后，才可把 staging tree 放到 Nginx origin 后：

- Phase 2 adoption/materialize 已保留 package/asset 路径与字节，且 metadata 差异已审阅；
- `sow verify --layer L1 --view latest,stable` 对候选 ref 全部通过，且 L1 机密性闭包不可
  跳过；L2–L4 依赖真实 publish expectation/checkpoint，应在 Phase 4 发布后执行，不能在
  此处用尚未发布的远端伪造通过；
- staging 中真实 apt >= 1.2 `apt update/install` 与 EL8/9/10 `dnf` 消费通过；
- `/pkg/pig/latest` 正文、现有 channel-less APT/YUM URL、签名和缓存头逐项对账；
- YUM `Packages/<首字母>/` 迁移的 URL/hotlink 影响已测；
- EOL 仓库只从 frozen ref 物化；
- `sow promote` 后的 serving tree/index 更新已有 E2E，而不只是 ref 变化；
- 本地故障注入证明中断可恢复、可安全重放。

切换应由仓库外的原子 Nginx root/symlink 变更完成，保留 `LEGACY_ROOT` 只读。SOW 目前没有管理 Nginx 的命令，本文不伪造一个。

### Phase 3 回滚

如果尚未远端发布，原子切回旧 Nginx root/symlink，停止新写者，再用 `serving-before.tsv` 对旧树。不得把 staging 的半生成目录覆盖回旧树，也不得同时恢复旧 Make 写者和保留 SOW 写者。

## 6. Phase 4：双云发布与回滚（真实环境 BLOCKED）

当前 CLI 已有完整调用面；本地 S3 兼容与 provider 契约测试也覆盖 checkpoint/CAS、翻转、
最小 purge、L3/L4、部分失败和幂等重放。生产迁移必须在冻结窗口用真实凭据执行：

```bash
export PRO_TOKEN_FILE=/absolute/protected/path/migration-pro-token

"$SOW_BIN" publish \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --view latest,stable --target cf,cos --workers 8 \
  | tee "$EVIDENCE/publish-latest-stable-cf-cos.txt"

"$SOW_BIN" verify \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --layer all --view latest,stable --target cf,cos \
  --pro-token-file "$PRO_TOKEN_FILE" --workers 8 \
  | tee "$EVIDENCE/verify-latest-stable-cf-cos.txt"
```

不要在首次迁移时省略 `--view` 使用“全部发布”默认值；beta 与保留快照必须分别完成本地
内容/URL 审阅后再显式发布，避免把未纳入冻结窗口的 ref 顺带推到生产。

但当前工作区没有真实 R2/COS/Cloudflare/EdgeOne 凭据、生产 object/URL 基线或获批窗口，
因此上述命令未执行，Phase 4 仍阻断。取得条件前：

- 不得用 rclone 手工补发布后再把迁移标为成功；
- 不得先切一个云、把另一个云留给操作员记忆；
- 不得删除旧远端 object；
- 不得宣称 purge/checkpoint/远端 CAS 已验证。

已提交发布的受支持回滚操作面是前向 restore，而不是 checkpoint 倒退。冻结窗口开始前，
必须从本地 canonical 历史和原发布日志分别选定、复核两个 target 已成功提交的 source
generation；不能假定 CF/COS 代数相同，也不能填任意 Git commit：

```bash
# 示例值必须替换成演练前已经审计的成功代；source intent 由 generation 自身决定。
export CF_ROLLBACK_GENERATION=41
export COS_ROLLBACK_GENERATION=38
export CF_ROLLBACK_VIEW=latest
export COS_ROLLBACK_VIEW=latest

"$SOW_BIN" publish \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --restore-generation "$CF_ROLLBACK_GENERATION" --target cf \
  --gpg-private-key-file "$KEY_FILE" \
  --gpg-passphrase-file "$PASS_FILE" --workers 8 \
  | tee "$EVIDENCE/restore-cf-from-$CF_ROLLBACK_GENERATION.txt"

"$SOW_BIN" verify \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --layer L3,L4 --view "$CF_ROLLBACK_VIEW" --target cf \
  --gpg-public-key-file /absolute/protected/path/repository-public.asc \
  --workers 8 \
  | tee "$EVIDENCE/verify-restored-cf-$CF_ROLLBACK_GENERATION.txt"

"$SOW_BIN" publish \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --restore-generation "$COS_ROLLBACK_GENERATION" --target cos \
  --gpg-private-key-file "$KEY_FILE" \
  --gpg-passphrase-file "$PASS_FILE" --workers 8 \
  | tee "$EVIDENCE/restore-cos-from-$COS_ROLLBACK_GENERATION.txt"

"$SOW_BIN" verify \
  --config "$SOW_CONFIG" --root "$LEGACY_ROOT" \
  --layer L3,L4 --view "$COS_ROLLBACK_VIEW" --target cos \
  --gpg-public-key-file /absolute/protected/path/repository-public.asc \
  --workers 8 \
  | tee "$EVIDENCE/verify-restored-cos-$COS_ROLLBACK_GENERATION.txt"
```

若 source intent 是 stable 或 snapshot，验证时改用对应 `--view stable`/`--snapshot`，并
提供 `--pro-token-file "$PRO_TOKEN_FILE"`。FR-19 禁止从 stable 删除后来版本，因此 stable
source 只有在其完整 ref vector 与 parent 当前 stable vector 完全相同时才允许；真正的历史
钉版/回退必须恢复 immutable snapshot，不能靠 stable regression。命令要求一次恰好一个
显式 target，验证历史 generation/checkpoint/content/ref、同 commit 的 intent plan 投影、
当前相同配置、本地 CAS 与机密性闭包，再以当前 checkpoint 为 parent 创建 `current+1` 代；
其他 intent 和另一个 target 保持当前状态。旧 plan 不会重放，新差异/purge/verify plan 从
历史 ref/CAS 重建。成功日志、当前 generation/checkpoint、包含 source generation/plan 摘要的
`remotes/<target>/restores/<new-generation>.json` 审计记录以及公开 URL 正文/签名/缓存头
必须一同归档；remote transaction ID 中的 `from-<source-generation>` 与冻结的 desired HEAD
用于中断诊断和 COS lock 后的确定性恢复，普通 publish/不同 source 不得接管该事务。

restore 成功后，同一条 publish 命令再执行一次必须报告 `status=unchanged`，不得再次 PUT、
purge 或推进 generation。若中断，先原样重放；只有命令报告本地未完成 journal/lock 时才加
`--recover`，仍不得改 source generation。`verify --layer L2` 默认表达“远端是否等于当前
local desired ref”，所以在有意保持历史代期间会报告 drift；restore 自身已经在 checkpoint
提交前完成 generation/content/head 与 CDN read-back 闭包，随后用上述 L3/L4 和审计文件
验收历史 intent。需要恢复到当前 desired 时再执行普通 `sow publish --view ... --target ...`。

Snapshot retention/restore 演练必须同时归档 plan 的 `Probes` 与 `VerifyAbsent`。删除只在 exact
storage key 的 HEAD 不存在且 exact CDN URL 返回 404/410 时成立；200、任意 3xx（即使最终
跳到 404）、401/403/5xx 都是失败。restore 合法重建 snapshot 后旧 intent negative 不会被
改写，而是依据 current aggregate generation ref 与 canonical sorted inventory 的 exact-key
membership 判断是否已 supersede。若 inventory 缺失、损坏或非排序，先重建/审计 inventory，
不得手工跳过 L2/L3。

restore 对 beta/latest mutable topology removal 开放：asset 逐 path 删除 serving key；APT/YUM
只删除 `dists`、legacy `repodata` 与 public mirrorlist，pool/Packages 与 immutable generation
归档保留。每个删除绑定 parent content、storage key、size/SHA、clean CDN URL 与 verified ETag，
且先用 SOW 自有 probe 判定供应商 DELETE 能力。默认 `storage.delete_mode=conditional` 只有在错误
ETag 被拒且 probe 保留时才执行 matching-ETag DELETE。Cloudflare R2 实测会忽略该条件；若已完成
旧 scheduler/credential/writer 撤权，可在迁移配置中显式设 `checkpoint-fenced`，由 saga 在连续两次
正文证明与 remote publication fence 不变后执行无条件 DELETE，再完成 absence→purge→404。parent-only ref
必须能从 parent `DesiredCommit` 的 canonical config 精确投影，不能从 ref 文本猜路径；任一证据
或围栏/内容证明缺失即不提交。snapshot topology 仍失败闭锁；stable 的任意
非完全相同 ref vector 还会独立按 FR-19 失败闭锁，不得用 rclone 手工删对象绕过。仅恢复
bucket 文件、不执行 mandatory purge 与 read-back 不算回滚。
2026-07-18 已在 owner 指定的空非生产 `pro` 桶验证 R2 conditional PUT/CAS、Copy/GET 以及
DeleteObject 不支持条件头的负事实；运行自有 key 由双次流式正文身份、run lease
前后重验和删除后 absence 证明收敛，桶最终为空。该 storage-only cleanup 没有 publication
checkpoint、purge 或 commit，不能冒充 Publisher checkpoint-fenced 事务，也不是生产回滚。
真实 COS/EdgeOne/双 CDN 与生产 writer 撤权、purge、回滚窗口仍未执行，Phase 4 继续 `BLOCKED`。

### 6.1 单 key 更换是离线迁移，不是 publish 重试

远端 generation 一旦包含 APT/YUM ref，`repository_key_sha256` 就冻结该 target 的
OpenPGP packet identity。不得在原路径原地覆盖 public/private key 后继续普通 publish；
即使只选 asset，SOW 也会在重写本地 metadata 或远端 PUT 前报 repository key drift。
中断与 `--restore-generation` 必须先恢复 generation 记录的旧 key。

schema v1 不提供双签或在线换钥。确需更换时使用独立变更窗口：

1. 冻结所有 writer，使用旧 key 完成/重放全部 journal、checkpoint 与 COS lock；
2. 保存旧 target generation/checkpoint、key fingerprint、URL 清单和客户端验收证据；
3. 用新 key、独立 bucket/CDN hostname 和独立 SOW state 从 canonical serving tree 建立
   新 target；不得删除或原地清空旧 target 来伪装首次发布；
4. 在隔离客户端完成 apt/dnf 签名、钉版、snapshot、Pro 鉴权和缓存验证；
5. 先分发新 `signed-by`/RPM key 与新 URL，再切 client；旧 target 保持只读作为回滚；
6. 观察期结束后才撤销旧 writer/域名。任何希望在同一 target 零停机换钥的需求都需要
   新的多 key/跨 intent 原子迁移协议，属于 [ADR-0010](../adr/0010-repository-signing-identity-and-rotation-boundary.md)
   明确未声称支持的范围。

## 7. Phase 5：Makefile 退役门禁（BLOCKED）

Phase 5 只在 origin 已切到新树、旧 root 不再承担 SOW 写入后执行。以下 preflight 是只读检查：
它不会停止进程、改权限、撤云凭据或删除 Makefile。输入声明必须位于旧 root 之外，schema
闭合且不得夹带 secret；声明中的云撤权结论仍需用 provider IAM 审计日志/面板导出独立佐证。

```bash
export WRITER_ATTESTATION="$EVIDENCE/writer-revocation.attestation"
cat > "$WRITER_ATTESTATION" <<'EOF'
schema=sow-writer-revocation/v1
scheduler_writers_disabled=true
legacy_cloud_credentials_revoked=true
legacy_containers_stopped=true
legacy_make_writers_archived=true
sow_exclusive_writer=true
approved_change=REPLACE-WITH-CHANGE-ID
approved_at=REPLACE-WITH-RFC3339-UTC
EOF
chmod 600 "$WRITER_ATTESTATION"

cd "$SOW_SRC"
docs/migration/writer-fence-preflight.sh \
  --legacy-root "$LEGACY_ROOT" \
  --attestation "$WRITER_ATTESTATION" \
  --output "$EVIDENCE/writer-fence-report.txt"
grep -Fqx 'writer_revoke_preflight=pass' "$EVIDENCE/writer-fence-report.txt"
grep -Fqx 'writable_entries=0' "$EVIDENCE/writer-fence-report.txt"
grep -Fqx 'production_current_host_preflight=pass' "$EVIDENCE/writer-fence-report.txt"
```

脚本以当前有效用户扫描旧树全部普通文件/目录的可写性，探测命令行中显式绑定旧 root、
或 cwd 位于旧 root 下的 Make/rclone/rsync/reprepro/createrepo/rpm/SOW/Docker writer，
并探测 Docker bind mount 和旧 root 下的 writable submount；活跃 writer 候选的 cwd
无法读取、Docker 已安装但 daemon 无法探测时都会失败。报告只保存输入摘要、来源标签、
计数和结论，不复制进程命令或凭据。传入 `--*-snapshot` 只会得到
`production_current_host_preflight=not-proven`，不可重放为当前主机证据；生产退役必须像上例
一样运行三个 live probe 并检查 `production_current_host_preflight=pass`。`ps` 无法跨主机发现 scheduler，当前用户权限也不代表
所有 service account，因此 operator attestation、scheduler 导出、container/runtime 清单、
文件 ACL/ownership 和两家云的 credential revoke 记录必须一并归档。任一证据缺失时 Phase 5
继续 `BLOCKED`。

满足以下全部条件后才能撤销旧写者权限并归档四个 Makefile：

1. `audit-legacy-targets.sh` 对 176/176、固定 source fingerprint、机器处置与当前 CLI
   surface/闭合 enum 全部通过，并保存 177 行（含 header）的规范化 TSV；
2. `family-e2e.tsv` 的 44-family 合同通过：含 `sow-cli` 的每个族均运行真实
   CLI/FS/parser，本地发布协议族覆盖 upload/checkpoint/purge/post-verify；每个 alias 的依赖
   集合另有 selector expansion 黄金测试；非 CLI target 有明确 disposition。生产退役前仍须
   逐 target 补齐真实云、builder handoff 与权限撤销，不能把 family 级本地协议证据升级为现场通过；
3. `cf-yum` 回归只展开 YUM infra+pgsql，不复刻旧 Makefile 的 APT 误依赖；
4. `copy-auth`、sv push/pull、`co-pro-get`、`ext-list`、APT `gen` 按
   [ADR-0005](../adr/0005-legacy-make-target-dispositions.md) 的退役/
   移交/迁移边界落实到权限和 SOP，而不只是表内标签；
5. Docker lifecycle/shell/exec、外部 gpg/rpm 重签、reprepro、createrepo_c、modulemd、rclone、rsync 均不再是 SOW 日常运行时；
6. 外部 builder 的 `copy-bin/copy-beta/ext-list/md5-src/parade/get-d13/get-d13a` handoff
   已按 [digest-bound handoff](builder-handoff.md) 验证到带 `--expected-object` 的
   `sow add`；其中 `.io/.cc` 同 key 双正文已收敛为 canonical 内容；
7. 本地切换与双云回滚各演练一次，旧树和旧 remote checkpoint 保留到观察期结束；
8. 再运行 `audit-legacy-targets.sh`，保存 target 差异为零和 source fingerprints；
9. 独立审计确认真实 apt/dnf、URL、CDN、访问控制和机密性闭包证据；
10. 退役动作先禁写并保留只读归档，不直接删除 Makefile 或应急环境；上述 writer-fence
    报告、scheduler/container/ACL 与云 IAM 撤权证据全部闭合。

当前结论：Phase 0–2 有可重复本地路径，其中 44-family 本地 E2E/disposition contract、
33-repo selector generalization、12-repo synthetic parser/adoption、完整 98-repo/135-row
config/ledger 对 74 APT + 130 ordinary YUM leaf、专用 EL9 policy owner 与双架构 compatibility
projection 的双向集合门禁、零字节 adoption 和本地
symlink 回退夹具已实测。完整存量树 fresh copy 已完成 PGDG 官方恢复、775 个稳定负证、
remainder adoption、真 DNF、full fsck/GC；current `yum/infra` exact copy 已完成 216/216
包验签、双架构 S0→S3 与六组 strong DNF。另一个只读生产源精确副本已把 15 个
23.5GB Pro TGZ 纳入 gated/stable，以 `sow add` 替换零字节 checksum，并通过
materialize/L1/fsck/GC/幂等和机密性负例。见
`docs/evidence/2026-07-16-fresh-full-content-adoption.md`、
`docs/evidence/2026-07-17-yum-infra-current-compatibility-cutover.md` 和
`docs/evidence/2026-07-17-gated-pro-exact-copy-adoption.md`。
这仍不是生产 cutover。Phase 3 仍待完整 staging/client 矩阵与获批 origin 窗口，Phase 4 已有受支持的前向 restore 操作面，
但仍待真实双云条件与两目标回滚演练；snapshot/stable topology removal 保持失败闭锁；Phase 5
待逐生产 target、handoff 与权限退役。因此 G5 仍未通过，不能把本地 family 闭合改写为
“迁移完成”。
