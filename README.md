# sow

`sow` 是 Pigsty 制品仓库的 Git 式管理器：一个纯 Go CLI，以 Git ref
保存 APT、YUM 与 asset 仓库视图，以 SHA-256 CAS 保存制品，并把发布作为
可恢复的双目标事务执行。当前开发版已通过本地真 apt/dnf、真实非生产 R2
storage/publish/fsck 与可复现交付门禁，但真实 Cloudflare Worker/purge/cache-log、
COS/EdgeOne 和生产迁移仍未闭合，因此尚不标记为 production-ready。最低支持
APT 版本已冻结为 1.2；更旧客户端明确不支持，不是待实现的兼容路径。

当前可执行命令面：

```bash
CGO_ENABLED=0 go build -trimpath -o sow ./cmd/sow
./sow help

# 对现有服务树零字节纳管，然后操作制品/视图
./sow init --config sow.yaml
./sow init --adopt-content --view latest --config sow.yaml
./sow add package.rpm --config sow.yaml --repo pgsql-el9-x86-64
# 外部 builder 交付时逐文件绑定其声明的摘要与长度；批量输入按顺序重复该参数
./sow add package.rpm --config sow.yaml --repo pgsql-el9-x86-64 \
  --expected-object sha256:<lowercase-64-hex>:<decimal-size>
# sync 需要显式 upstream 与只读上游 keyring；可加载的 PGDG 范例见下文
./sow sync --config /secure/sow-pgdg.yaml --upstream pgdg-apt,pgdg-yum
./sow promote beta latest --config sow.yaml

# 发布、校验、恢复和离线物化
./sow publish --config sow.yaml --view latest --target cf,cos
./sow verify --config sow.yaml --layer L1
./sow verify --config sow.yaml --layer L2,L3,L4 --view stable --target cf --pro-token-file ./pro-token
./sow fsck --config sow.yaml
./sow fsck --config sow.yaml --recover        # 恢复本地事务/残留并从正典重建 SQLite
./sow fsck --config sow.yaml --target cf --adopt-remote-inventory
./sow fsck --config sow.yaml --target cf --repair-purge-ledger
# fsck 报告 preserved projection audit 后，一次只退休一个当前 inode
./sow fsck --config sow.yaml --retire-preserved-projection <exact-name> \
  --confirm <retire-token>
./sow materialize stable --config sow.yaml --target export/stable \
  --serving-base-url https://repo.example/pro/v1/basic --tgz export/stable.tgz
./sow gc --config sow.yaml                 # dry-run
./sow gc --config sow.yaml --apply --confirm <exact-plan-hash>
```

### 无云凭据的最小可用闭环

下面的 `sow` 生命周期只使用本地文件系统和 `sow.example.yaml`，不会访问上游或
云，也不需要 GPG 私钥或云凭据；若 Go module cache 为空，第一行 `go build`
仍会按 Go 工具链配置下载源码依赖。示例配置声明了三个服务目录；全新根目录必须
先创建它们。显式 materialize 的目标可由 Nginx 直接托管，因此仓库根及其真实祖先必须允许
Nginx worker 穿越（目录至少有 other-execute），且路径不能经过 symlink。

```bash
CGO_ENABLED=0 go build -trimpath -o sow ./cmd/sow

DEMO_ROOT="$(pwd)/sow-demo-root"
DEMO_CONFIG="$(pwd)/sow.demo.yaml"
DEMO_INPUT="$(pwd)/sow-demo.bin"
cp sow.example.yaml "$DEMO_CONFIG"
mkdir -p "$DEMO_ROOT/bin" \
  "$DEMO_ROOT/yum/pgsql/el9.x86_64" \
  "$DEMO_ROOT/apt/pgsql/trixie"
# 仅对尚为空的 demo 目录执行；不要递归 chmod 已初始化的 .sow 私有状态。
chmod -R 0755 "$DEMO_ROOT"
printf 'sow local MVP\n' >"$DEMO_INPUT"

./sow init --config "$DEMO_CONFIG" --root "$DEMO_ROOT"
./sow add "$DEMO_INPUT" --config "$DEMO_CONFIG" --root "$DEMO_ROOT" \
  --repo assets-bin
./sow verify --config "$DEMO_CONFIG" --root "$DEMO_ROOT" \
  --layer L1 --view beta --repo assets-bin
./sow promote beta latest --config "$DEMO_CONFIG" --root "$DEMO_ROOT" \
  --repo assets-bin
./sow materialize latest --config "$DEMO_CONFIG" --root "$DEMO_ROOT" \
  --repo assets-bin --target export/latest
./sow fsck --config "$DEMO_CONFIG" --root "$DEMO_ROOT"
test -f "$DEMO_ROOT/export/latest/bin/sow-demo.bin"

# SQLite 只是派生缓存；显式恢复从 canonical Git 全量重建并继续审计。
rm "$DEMO_ROOT/.sow/cache/state.db"
./sow fsck --recover --config "$DEMO_CONFIG" --root "$DEMO_ROOT"
./sow verify --config "$DEMO_CONFIG" --root "$DEMO_ROOT" \
  --layer L1 --view beta,latest --repo assets-bin

# 从两个可变视图减包；GC 先只读列出精确集合，再用当次摘要确认。
./sow rm sow-demo.bin --view latest --config "$DEMO_CONFIG" \
  --root "$DEMO_ROOT" --repo assets-bin
./sow rm sow-demo.bin --view beta --config "$DEMO_CONFIG" \
  --root "$DEMO_ROOT" --repo assets-bin
# 显式物化是 exact reconcile；视图删除后重放会清掉 Nginx 可见旧文件。
./sow materialize latest --config "$DEMO_CONFIG" --root "$DEMO_ROOT" \
  --repo assets-bin --target export/latest
test ! -e "$DEMO_ROOT/export/latest/bin/sow-demo.bin"
./sow gc --config "$DEMO_CONFIG" --root "$DEMO_ROOT"
```

上面的正式默认值保留最近 32 个 commit，因此刚删除的对象仍是回滚根，dry-run
不会立即给出可删除对象。若要在隔离目录完整演示破坏性的确认阶段，先把另一个
一次性配置的保留窗缩到 1，再初始化；不要对已有仓库临时改这个策略：

```bash
GC_ROOT="$(pwd)/sow-gc-demo-root"
GC_CONFIG="$(pwd)/sow.gc-demo.yaml"
GC_INPUT="$(pwd)/sow-gc-demo.bin"
sed 's/cas_history_commits: 32/cas_history_commits: 1/' \
  sow.example.yaml >"$GC_CONFIG"
mkdir -p "$GC_ROOT/bin" "$GC_ROOT/yum/pgsql/el9.x86_64" \
  "$GC_ROOT/apt/pgsql/trixie"
chmod -R 0755 "$GC_ROOT"
printf 'collectible demo object\n' >"$GC_INPUT"
./sow init --config "$GC_CONFIG" --root "$GC_ROOT"
./sow add "$GC_INPUT" --config "$GC_CONFIG" --root "$GC_ROOT" \
  --repo assets-bin
./sow rm sow-gc-demo.bin --view beta --config "$GC_CONFIG" \
  --root "$GC_ROOT" --repo assets-bin
GC_DRY="$(./sow gc --config "$GC_CONFIG" --root "$GC_ROOT")"
printf '%s\n' "$GC_DRY"
GC_PLAN="$(printf '%s\n' "$GC_DRY" |
  sed -n 's/.*gc_set_sha256=\([0-9a-f]\{64\}\).*/\1/p')"
test -n "$GC_PLAN"
./sow gc --config "$GC_CONFIG" --root "$GC_ROOT" \
  --apply --confirm "$GC_PLAN"
```

`L1` 是纯本地字节、索引、签名与机密性闭包；`L2`–`L4` 需要匹配的已配置
publication target。没有 target 的本地配置执行 `--layer L2` 会以覆盖不完整失败，
这是 fail-closed 行为，不是本地 smoke test 的失败。

普通命令不会静默掩盖无标记的 cache 漂移；`--recover` 是操作者显式选择的昂贵恢复
路径，会在持有本地状态锁时以 manifest/ref/CAS 为输入原子替换
`.sow/cache/state.db`。`gc --apply` 只接受同一当前 CAS+serving 集合算出的
`gc_set_sha256`；集合变化或已成功重放后，旧摘要以冲突退出且不会删除新对象。

旧 `yum/infra/{arch}` 的 mixed-EL 树不是普通 EL9/10 repo，不能用普通
`add`、`sync` 或 selector 重新归类。配置显式的 inactive compatibility carrier 后，
每个 architecture 必须走独立的 S0→S3 状态机：

```bash
./sow compatibility yum-adopt --id infra-legacy-x86-64 --config sow.yaml
./sow compatibility yum-candidate --id infra-legacy-x86-64 \
  --output /outside/hosted-root/infra-legacy-x86-64 \
  --gpg-private-key-file /secure/repository-private.asc --config sow.yaml
./sow compatibility yum-freeze --id infra-legacy-x86-64 \
  --candidate /outside/hosted-root/infra-legacy-x86-64 \
  --confirm 'sha256:<freeze-token>' --config sow.yaml
./sow compatibility yum-cutover --id infra-legacy-x86-64 \
  --confirm 'sha256:<cutover-token>' --config sow.yaml
./sow materialize latest --config sow.yaml
```

`yum-adopt` 固定并验签原始 S0 字节；`yum-candidate` 在 hosted root 外生成干净、
签名且不含 sqlite/modulemd/zchunk 的候选；`yum-freeze` 只建立不可变 S2 证据，
不会开放 generation、mirrorlist 或 compatibility trust URL；只有 append-only
`yum-cutover` 授予 S3 authority，后续普通 `materialize`/`publish` 才安装或发布这些
入口。每一步打印下一步所需的 content-bound `sha256:` token。中断必须以完全相同的
动词、ID、路径和 token 加 `--recover` 重放；不要手工删除 journal。回退使用打印出的
`rollback_confirm` 调用 `yum-rollback`，它追加回滚事件并保留可消费 raw bridge、S1/S2
CAS root 与 immutable generation。完整配置、Nginx/DNF 验证和恢复流程见
[迁移 runbook §4.2](docs/migration/runbook.md#42-frozen-cross-el-yuminfraarch-的-s0s3-工作流)。
任何测试、PoC 或探测都不得使用 CO/COS 或 Cloudflare 生产资源。

外部 builder 仍负责造包、容器收集与兼容 asset 正文生成；最终制品必须通过
`--expected-object` 的摘要/长度绑定进入普通 `sow add`，完整交接、审计和
`.io/.cc` 同 key 异正文边界见
[builder handoff](docs/migration/builder-handoff.md)。

`sow <command> --help` 的参数表直接由该命令实际注册的 FlagSet 生成，包含
选择器、并发/恢复参数以及 GPG、Pro token 等安全文件入口；帮助输出只显示参数
名、用途和安全默认值，不回显调用时提供的文件路径或 secret 内容。

若命令报告 `.sow/materialization-journal/active.json`，不要手工删除它：先恢复原
config/keyring，再用原操作加 `--recover`。中断的 asset add 可直接执行
`sow add --recover --config sow.yaml`，恢复权威来自 frozen ref 与 CAS，不依赖原输入
路径；恢复完成后才会处理同次调用中额外给出的新输入。RPM/DEB 恢复仍需提供 frozen
ref 已精确记录的包条目，以便补回可能丢失的 CAS 对象；跨格式或同格式新条目会在 CAS
安装前被拒绝并保留 journal。

默认 `init` 只扫描声明的服务树；显式 `init --adopt-content` 会从真实 APT/YUM
索引或 asset baseline 校验并导入 CAS，建立 legacy receipt 与 latest（可选 stable）
view。两种模式都不会改动现有发布字节；只有后续显式 `materialize` 才执行结构迁移。
旧 YUM metadata 的信任不会从新仓库签名 key 推断：默认 adoption 校验
`repomd.xml -> primary -> RPM` 的 size/SHA-256 链并报告
`yum_metadata_signature=not-claimed`。只有每个选中 leaf 都有历史 `.asc` 时，才可显式传入
public-only `--legacy-metadata-keyring FILE`；此时缺签名、错签名或私钥材料都会在 state
写入边界上 fail closed，并在成功输出中记录 keyring SHA-256：无效/私钥 keyring 在任何
state mutation 前拒绝；缺失或错误 `.asc` 不推进 view/receipt，但普通 `init` baseline
可能保留供诊断和安全重放。RPM 本体仍由 `yum.package_keyring` 在
materialize/publish/L1 边界独立验签。

若旧 YUM primary 引用了 M0 基线中不存在的 RPM，adoption 默认列出全部路径和
精确 blocker-set SHA-256 后失败。应先从受信上游恢复 size/SHA-256 完全一致的字节；
只有确认已无法恢复的剩余集合才可显式使用
`--adopt-prune-missing-yum-confirm SHA256`。该参数拒绝变化后的集合，写入
`provenance/legacy-pruned/<repo>.jsonl`，不适用于“本地有 body 但无索引”的 orphan，
也不会改写旧服务树。负向账本一旦进入 canonical Git，任何可达历史分支中的删除或
字节替换都会使 mutation/fsck 失败。见
[ADR-0030](docs/adr/0030-audit-bound-legacy-yum-missing-body-prune.md)。
旧 Pro `pro/` 的零拷贝 gated 激活、零字节 checksum 替换与回滚边界见
[ADR-0031](docs/adr/0031-legacy-pro-gated-activation-and-checksum-repair.md)。
Cloudflare 测试资源 `pro`/`pro.pigsty.io`/`beta.pro.pigsty.io` 的精确 tuple 例外、空 registry 默认拒绝与只读预检
边界见 [ADR-0032](docs/adr/0032-owner-designated-cloudflare-test-resource-exception.md)。
first-deployment bootstrap 的 fresh readiness、动态授权、run-bound create-only Worker、R2 CAS
lease、双观察 closure、atomic receipt 与过期租约恢复见
[ADR-0034](docs/adr/0034-cloudflare-nonproduction-worker-bootstrap.md) 和
[离线验证](docs/evidence/2026-07-17-cloudflare-bootstrap-offline-validation.md)；registry 为空时仍会在
读取凭据或联网前拒绝，不能据此宣称真实 Cloudflare POC 已通过。
部署后的 runtime/settings/inventory 双读 attestation、R2 custom-domain TLS 下限与双云日志配置
CAS lease 见 [ADR-0035](docs/adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md) 和
[离线验证](docs/evidence/2026-07-17-cloudflare-provider-attestation-offline-validation.md)；它们同样
没有授权或执行任何真实云写入。

`.sow/state` 是内嵌 Go Git 正典，`.sow/cache/state.db` 可随时重建，
`.pool/sha256` 是不可变 CAS。
公开 latest 继续物化在既有 URL；beta 元数据使用独立 beta 主机；stable
只经 `/pro/v1/...` 边缘鉴权访问。静态 Nginx 必须只允许配置中声明的公开仓库
前缀、`/_sow/` generation 路由和公开签名 key；仓库根下的 `sow.yaml`、secret
provider 文件、`/.sow/`、`/.pool/` 与 `/.git/` 一律不可由 HTTP 到达。

所有仓库命令的 `--repo/--os/--arch` 都是严格作用域。首次带部分选择器执行
`init` 时，只为该作用域建立基线：同一选择器的 `fsck` 应为 clean，而不带选择器
的全量 `fsck` 会把尚未纳管的叶子报告为 `added`，不会悄悄把未知字节当作已覆盖。
随后执行一次无选择器的 `sow init` 即可扩展为完整基线；已有完整基线上的部分
`init` 只替换选中范围，保留其余 manifest 条目。

不要手写或复制仓库 `location`。SOW 从已验证的 `sow.yaml` 生成 canonical、确定性、
原子替换的 default-deny include；`-` 可先输出到 stdout 审阅：

```bash
sow materialize latest --config /etc/sow/sow.yaml --nginx-include -
sow materialize latest --config /etc/sow/sow.yaml \
  --nginx-include /etc/nginx/sow-latest.locations.conf
sow materialize stable --config /etc/sow/sow.yaml \
  --nginx-include /etc/nginx/sow-stable.locations.conf \
  --nginx-auth-user-file /etc/nginx/sow.htpasswd
nginx -t
```

该模式只渲染 include，不修改 manifest/ref/CAS/服务树；先单独执行实际
`sow materialize <view>`，再生成对应 include。输出只含配置拥有的叶子/精确对象、
YUM mirrorlist/generation 和经校验的公开 trust bundle，每条路由限制 GET/HEAD 并禁止
symlink 穿透，最后以 `location / { return 404; }` 关闭未拥有路径。完整接入、reload 与
Basic 回退边界见 [Nginx 直接托管](docs/nginx-hosting.md)。

把私钥、passphrase、云凭据和 Basic Auth 文件放在仓库根之外仍是首选。即便运维
暂时把只含 `env://` 引用的 `sow.yaml` 放在根下，上述 default-deny 也必须保证
`/sow.yaml` 和任意真实存在的 canary secret 返回 404；兼容测试会实际探测这两个路径。

`sow materialize latest` 不带 `--target` 时刷新上述既有 latest 服务树，并在
全部树成功扫描后以一个可恢复事务更新 repo manifest/ref 与 SQLite 缓存；
显式 `--target export/...` 始终只是派生导出，不会移动工作树基线。

## 配置和秘密

配置合同是严格的 `schema: sow/v1`，可从 [sow.example.yaml](sow.example.yaml)
开始。未知字段、明文 secret、错误 provider union、同主机 beta/latest、未确认
的 COS versioning 状态都会失败。配置文件上限为 8 MiB；超限输入在 YAML 解析和
任何仓库状态创建前以配置错误退出。默认展开/规范化后的 canonical YAML 也必须留在
同一上限内；canonical HEAD baseline 与 history 读取会先检查声明大小并最多流式读取
`8 MiB + 1 byte`。生产 target 的关键字段如下：

基础范例故意使用 `upstreams: []`，因此不会在一次误执行中联网。需要 `sync` 时，复制
[完整 PGDG upstream 范例](docs/examples/sow-pgdg.yaml) 到仓库根之外的受保护配置目录，
把仓库自身的公开签名 key 放在 `keys/repository.asc`，把两个**只含公钥**的上游 trust
anchor 放在 `keys/pgdg-apt.asc` 与 `keys/pgdg-yum.asc`，再通过
`SOW_GPG_PRIVATE_KEY`/`SOW_GPG_PASSPHRASE` 注入与 `repository.asc` 配对的私钥。
`keyring` 路径相对配置文件解析，必须是有界 regular non-symlink 文件；APT/YUM upstream
必须分别声明 type、目标 repo、绝对 HTTPS URL、arch，APT 还必须声明目标 repo 已允许的
suite/component。`allow`/`deny` 对 name+arch 过滤，范例有意只同步两个小包；扩大前先审阅
provenance 与容量。需要上游 Bearer 时只设置 `credential: env://NAME`，该环境变量正文是
token，重定向到不同 host 时会自动剥离。

每个 YUM repo 的 `yum.package_keyring` 是另一条显式合同：它是只含公钥的 package signer
bundle，`add`、`sync`、L1、materialize 和 publish 都会用它验证 RPM 嵌入签名。为兼容自建
Pigsty 包，省略时仅默认到 `gpg.public_key`；镜像 PGDG/CentOS 等第三方包必须声明包含相应
signer 的独立 bundle。轮换先加入新 key，且只要 stable/snapshot/history 仍可达旧 key 签名
的包就不能移除旧 key；即使远端 ref-vector unchanged，移除仍在使用的 key 也会让 publish
在网络请求前失败。

当前官方 PGDG 兼容门禁固定验证 APT key
`https://www.postgresql.org/media/keys/ACCC4CF8.asc`（fingerprint
`B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8`）与 YUM key
`https://download.postgresql.org/pub/repos/yum/keys/PGDG-RPM-GPG-KEY-RHEL`
（fingerprint `D4BF08AE67A0B4C7A1DBCCD240BCA2B408B40D20`）。把下载与 fingerprint
核验作为配置供应步骤保存证据；不要把上游 trust anchor 当成 SOW 仓库自己的 signing key，
也不要在 key 漂移时静默接受新正文。可复现实跑边界见
[官方 upstream 证据](docs/evidence/2026-07-12-real-pgdg-upstream-sync.md)。

APT by-hash 默认保留 2 个完整代际（包含 live），可用正整数
`state.apt_by_hash_retention` 调整。代际账本进入 `.sow/state` 的 Git 正典；账本
损坏、live 缺失或 retained 内容校验失败时清理会失败闭锁。

YUM strong-serving 每个 target/repo/OS/arch 默认在 current 之外保留 2 个旧代，
由正整数 `state.yum_generation_retention` 调整。channel lineage 以 target root +
serving base URL 的确定性 ID 分区；显式 export 不会借用默认树或其他 export 的 parent。
retained generation 的 Packages 会作为未索引兼容 hardlink 合入新 generation，避免
DNF 在同一事务中重新解析 mirrorlist 后下载旧 payload 失败；新 repodata 仍只索引
当前 view。该保证按翻转次数而非时间计算，Nginx Basic generation 路径使用
`private, no-store`，不得承诺一年缓存。

```yaml
targets:
  cf:
    storage: {kind: r2, endpoint: "https://ACCOUNT.r2.cloudflarestorage.com", bucket: repo, region: auto, credential: env://SOW_R2, delete_mode: conditional}
    cdn: {kind: cloudflare, base_url: "https://repo.example", beta_base_url: "https://beta.example", zone_id: ZONE, credential: env://SOW_CF}
  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_COS, delete_mode: conditional, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.example", beta_base_url: "https://beta-cn.example", distribution: ZONE, credential: env://SOW_TENCENT}
```

`storage.delete_mode` 省略时也默认为 `conditional`，端点必须通过 SOW 的错误 ETag
DeleteObject 探针，否则在 live key 前失败。Cloudflare R2 实测不提供条件 DeleteObject；只有在
旧 scheduler、发布器与写凭据全部撤销，并确认符合单操作者边界后，才把对应 target 显式改为
`checkpoint-fenced`。该模式仍要求远端发布围栏、连续两次完整正文证明、删除后 absence、mandatory
purge 与验证；它不支持多写者。见 [ADR-0036](docs/adr/0036-provider-delete-capability-and-checkpoint-fenced-fallback.md)。

环境变量值是严格 JSON；不会写入 config snapshot、Git、journal 或日志：

```bash
export SOW_R2='{"access_key_id":"...","secret_access_key":"..."}'
export SOW_CF='{"api_token":"...","basic_username":"verifier","basic_password":"..."}'
export SOW_COS='{"access_key_id":"...","secret_access_key":"..."}'
export SOW_TENCENT='{"secret_id":"...","secret_key":"...","basic_username":"verifier","basic_password":"..."}'
```

`basic_*` 在发布 stable/Pro 及未提供 token 的 stable 校验中使用，并且只会发送到
`/pro/v1/basic/` 路径。`--pro-token-file` 文件必须为 `0600` regular file，内容是
一个 22–256 字符 base64url 路径段；token 仅在运行时内存中把 L3/L4 请求投影到
`/pro/v1/<token>/`，不会写回 plan、Git 或报告。asset 同路径覆盖必须先在
`asset.mutable_paths` 中显式声明；发布会先保存内容寻址历史对象。

## 发布与恢复语义

每个 target 独立维护 generation、checkpoint、内容 manifest 和
`refs/sow/remotes/...`。发布只从本地 remote baseline 计算差异；远端 GET 仅用于
checkpoint/generation 漂移控制。不可变对象、APT/YUM generation、可变指针、
最小 purge、穿 CDN 校验全部成功后，本地 remote refs 才 CAS 前进。一个云失败
时另一个云的成功状态会保留，命令返回 7；重跑会复用相同 generation 和 journal。

已提交代的业务回退使用
`sow publish --restore-generation N --target cf|cos`。`N` 必须是该 target 在本地
canonical 历史中有闭合 generation/checkpoint/content/ref 以及同 commit、同 intent 的
plan 投影证据的成功旧代；旧 plan 只供审计，新 plan 从历史 ref/CAS 重新生成。命令
从历史 ref 和本地 CAS 隔离重建，只恢复该代的 intent，并以当前 checkpoint 为 parent
发布 `current+1`，不会移动当前 local view 或倒退 checkpoint。一次只能显式恢复一个
target；配置/CAS/机密性证据缺失均在远端变更前失败，stable/snapshot 的 pool 分类也只读
历史 commit。beta/latest asset path/leaf 与 APT/YUM topology 可通过绑定 parent content、
storage key、size/SHA 与 clean CDN URL 的条件 DELETE→purge→404 合同收敛；APT/YUM 只撤销
`dists`/`repodata`/mirrorlist 服务入口，包体与 immutable generation 归档保留。parent ref 即使
已不在当前配置中，也只从 parent `DesiredCommit` 的 canonical config 精确投影，绝不从 ref 文本
猜路径。每次真实删除先用 SOW 自有对象证明供应商执行 `If-Match`；忽略条件删除的端点在触碰
服务对象前失败闭锁。snapshot topology 仍不删除。stable 为遵守 FR-19 更严格，
只接受与当前完全相同的 stable ref vector，不能用 restore 从 stable 索引删除后来版本，
历史钉版应使用 snapshot。
restore transaction 同时冻结 source generation 与 desired HEAD；COS 在 generation lock 后
即使另一 target 推进 canonical HEAD，也能重建同一 generation 安全续跑，普通 publish 与
不同 source 不能接管。任何未获上述精确证据授权的删除都会在 checkpoint 前失败，避免
checkpoint 已提交而旧 URL 仍存活。

`sow verify --layer L2 --target cf|cos` 对 checkpoint、immutable generation、
channel bytes 和最近变更计划中的对象做有界 GET/HEAD 对账，绝不调用
ListObjects。`sow fsck --target cf|cos` 才分页全量 ListObjectsV2，并以 canonical
`remotes/<target>/inventory.tsv` 报告 missing、changed、orphan、unknown 和 0-byte
checksum；旧对象没有 `sow-sha256` 元数据时，fsck 会流式 GET 计算 SHA256。
publish 不得通过 List 猜测桶为空，因此 inventory coverage 默认为 `partial`。
只有显式 `fsck --target <cf|cos> --adopt-remote-inventory` 会在 state lock 下执行
双 List 稳定快照、全对象 HEAD、旧对象流式 GET 校验和本地 serving-tree 子集
校验，然后原子写入 complete inventory/content baseline；远端额外对象保留并报告。
普通 fsck 在 partial 状态只会把额外对象标为 unknown，绝不会描述为可安全删除。

`fsck --target <one> --repair-purge-ledger` 是另一条互斥的显式路径，而且严格本地运行：
它不会创建存储/CDN 客户端，也不会 List、GET、purge 或写入云资源。命令只从 embedded
Git 中每一代首次原子发布的 commit 恢复字节完全相同的 purge receipt，并为旧
`sow-checkpoint/v1` 非空 purge plan 写入可复算的 plan-binding attestation；随后重建
绑定 canonical HEAD 的 SQLite cache 并重审整条历史。partial/完整删除/同代改写的
control triplet、缺少原子 receipt 或孤儿证据仍会失败关闭，不能被 repair 掩盖。

L1 与本地 fsck 还会盘点 `.sow` 根控制文件、`generated/**` 和三个 writer journal
目录中的未完成 derived-state。普通检查只报告；`fsck --recover` 依次收敛严格的空目录
stage、durable replacement carrier 和带 128-bit 随机能力的 write/install/removal
临时文件，并在每类变更后重新盘点。旧 16-hex 可预测临时名和
`.tmp-derived-directory-*.preserved-*` 外来替换证据绝不自动删除，必须由操作者检查。
扫描不会进入 canonical Git、cache、CAS、sync/stage/tmp、materialized/origin 或制品树。

中断恢复若发现没有 durable owner 的最终 projection stage，会先把它改名为严格的
`.preserved-<nonce>` 审计副本而不删除。L1 与本地 fsck 流式列出其 name/kind/size/SHA256
和绑定当前 POSIX inode 的 `retire_token`；普通 `--recover` 与 GC 永不隐式删除。
检查完成后只能用 `fsck --retire-preserved-projection <exact-name> --confirm
<retire-token>` 一次退休一个。对象被替换、加硬链接或改变元数据后旧 token 失效；命令
响应丢失后的缺失坐标重放无副作用并报告 `already_absent=true`。

`sow verify --layer L3` 从 canonical
`remotes/<target>/intents/views/<view>/plan.json`（快照使用
`intents/snapshots/<id>/`）重放对应 intent 的完整 Verify
闭包并穿 CDN 流式核对字节；`--layer L4` 以纯 Go 执行 APT
InRelease→by-hash Packages→DEB 和 DNF mirrorlist→repomd+三类 metadata→RPM
协议链，成功报告必须带版本化 transcript 与可安装制品身份。计划/包覆盖缺失会
fail closed；远端字节/签名漂移返回 4，网络或鉴权不可用返回 5。

退出码：`0` 成功、`2` 用法、`3` 配置、`4` 校验、`5` 网络/鉴权、`6`
冲突/漂移、`7` 部分目标发布。

已知硬门禁：受支持的 APT 客户端为 apt >= 1.2，并通过 by-hash 获得发布闭包；
apt < 1.2 明确不受支持，必须在迁移前升级。静态对象存储无法让这类旧客户端同时
观察多个固定 `Packages*` alias 与 `InRelease` 的多键原子替换，真实 apt 1.0 继续作为
负控而不是支持路径。EL8 自 Pigsty v5.0.0 起冻结。Cloudflare service-only R2 origin Worker
与 EdgeOne 直签 COS 的可部署制品和 opt-in GET/HEAD/Range 探针已经就绪，但这两种
direct transport 明确为 cache `BYPASS`。FR-38 使用独立的 main/beta same-host
`https-bearer` 候选、paired client/clean-key exact purge 和双 token gated 验收；真实
R2/COS/Cloudflare/EdgeOne PoC 仍必须在相应凭据可用后另行执行，当前分页/漂移及本地
edge 合同证据不代表供应商真机已经通过。

持续执行账本见 [需求可追踪矩阵](docs/requirements-traceability.md)，核心不变量见
[架构](docs/architecture.md)，客户端配置见
[APT/DNF 安装合同](docs/client-installation.md)，迁移与回滚见
[runbook](docs/migration/runbook.md)。
