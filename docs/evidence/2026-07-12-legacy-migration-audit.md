# 旧 Make 迁移覆盖、零字节纳管与本地回滚证据 — 2026-07-12

> 历史证据：2026-07-14 已将 Docker `default/help` 从 `sow-cli` 修正为 `retire`，并建立
> 44-family 可执行合同；当前处置计数、fixture ID 与验证结果以
> [2026-07-14 报告](2026-07-14-legacy-family-e2e.md)为准。下文 117/31 与旧摘要保留为该次
> 运行的历史观察，不再代表 current-source 结论。

## 环境与边界

- SOW worktree：`/Users/vonng/pgsty/sow`，Darwin arm64，Go 1.26.5
- 旧源只读输入：`/Users/vonng/pgsty/repo`
- 范围：四个 Makefile 的 44-family/176-target 精确分区、当前 SOW CLI/selector surface、
  suite-nested APT + flat-RPM YUM 与 asset 的 adoption/materialize/本地 symlink 回退，
  writer-revoke preflight 的 host/fixture 探针
- 未触碰：任何 Make recipe、rclone/rsync/Docker/reprepro/createrepo、真实 bucket/CDN、
  Nginx 生产配置或公开 URL
- 审计含义：只证明旧输入/账本精确闭合、当前 CLI 动词/flag/闭合 enum 未漂移；不会执行
表内变更命令，也不把“语法/selector 存在”写成业务等价。逐操作等价仍是 G5 生产 E2E 门禁。
flag 存在性直接从各子命令的真实 `FlagSet` 生成帮助面核对；审计不再用“未知 flag +
--help”探测，因为 help 的安全合同要求在任何业务参数、配置读取或副作用之前短路。

本次重跑锁定的迁移审计输入如下；任一摘要变化都必须刷新本证据并重新审查：

```text
20894429a55e24988f3d6b4583d6d41bd4f76f70d27d995da3136dbe914fc3e8  docs/migration/make-target-map.md
ae717db7255cef9f1447dad486e8f4a7fe00437b1d0a8ee5c9dcd12708e69cb2  docs/migration/audit-legacy-targets.sh
ad0c1881af41de1cdbf6664026cb3b3623425f30f2a5ce7ef634f293ab53e56b  docs/migration/test-audit-legacy-targets.sh
2e9ed5f59122362ef783e53805c5f6531abf5f61b067052acd762ad625c14dd1  docs/migration/snapshot-serving-tree.sh
8a8037c04ef61cab59f5a5ae6d4cb047050e72c06317b0e46c2855ce4fb36034  docs/migration/test-local-adoption-rollback.sh
5f616ea75a3e404949ce89accf3ed36859ee9751abc38a47bc2f732cd19de283  docs/migration/writer-fence-preflight.sh
d7724f8824b81c4c6f51df95374485812bab49904dc42314a13a9941621a85c9  docs/migration/test-writer-fence-preflight.sh
0eafef16ac204cbdccbf5861c8bbfb9667ea960e6224aedf6496c455ea381173  docs/migration/runbook.md
d2247799ea1407d76bf15f19d7c8a2ea07cf5aa3e1114c8871073c68f26e7fc4  historical pre-2026-07-14 pigsty-v1 subset (now superseded by pigsty-v1-synthetic.yaml)
168e56d71f7c79a9f24ba32a5b2ccd3aa655dc302631d33b16dde0310d648c32  docs/migration/fixtures/selector-matrix.yaml
be044060447f6cfeebe53c409ced644818c4f813f50a63d2ef207f2ecda1152b  docs/adr/0005-legacy-make-target-dispositions.md
```

## 复现命令

```bash
cd /Users/vonng/pgsty/sow
EVIDENCE=$(mktemp -d /tmp/sow-migration-evidence.XXXXXX)

docs/migration/audit-legacy-targets.sh \
  --legacy-root /Users/vonng/pgsty/repo \
  --emit-tsv "$EVIDENCE/legacy-target-map.tsv"
wc -l "$EVIDENCE/legacy-target-map.tsv"
shasum -a 256 "$EVIDENCE/legacy-target-map.tsv"

docs/migration/test-audit-legacy-targets.sh /Users/vonng/pgsty/repo
docs/migration/test-local-adoption-rollback.sh
docs/migration/test-writer-fence-preflight.sh

go test -count=1 ./internal/config ./internal/provenance ./internal/cli \
  -run 'Migration|Legacy|AdoptContent|PigstyV1'
go test -race -count=1 ./internal/config ./internal/provenance ./internal/cli \
  -run 'Migration|Legacy|AdoptContent|PigstyV1'
go vet ./internal/config ./internal/provenance ./internal/cli
git diff --check
```

2026-07-12 最终重跑全部退出 0。规范化 TSV 共 177 行（header + 176 target），摘要为：

```text
d2b7edf2324fb052376478a7ca0366114de134eee4fae6ebde820cd602df9409
```

## 实测结果

```text
targets root=52 apt=70 yum=14 docker=40 total=176
operation_families=44 partition=exact
cli_identity=sow 0.1.0-dev darwin/arm64 go1.26.5
dispositions sow-cli=117 retire=31 policy-reject=18 external-handoff=8 migration-only=2
machine_map_sha256=d2b7edf2324fb052376478a7ca0366114de134eee4fae6ebde820cd602df9409
ledger coverage: exact
disposition closure: exact
cli surface/enums: current
cli semantic equivalence: not asserted; requires per-operation E2E
```

负例套件实际证明以下任一变化都会非零退出，且不会生成机器 TSV：

```text
PASS baseline-and-machine-map
PASS operation-family-partition-drift
PASS operation-family-id-drift
PASS cf-yum-selector-regression
PASS semantic-non-equivalence-dispositions
PASS source-fingerprint-drift
PASS missing-ledger-row
PASS unparsed-ledger-row
PASS unknown-disposition
PASS reviewed-disposition-drift
PASS stale-cli-flag
PASS invalid-cli-enum
PASS selector-matrix-all-targets-and-aliases
legacy migration audit negative suite: PASS
```

零字节/回退夹具实际输出：

```text
zero_byte_adoption=pass serving_tree_rewritten=false replay_changed=false replay_bytes_unchanged=true
isolated_materialize=pass candidate_bytes=exact
canonical_l1=pass legacy_fsck=pass
local_symlink_rollback=pass legacy_bytes_restored=true
local_symlink_rollback_replay=pass
failed_candidate_preserved_outside_origin=true
snapshot_nonregular_guard=pass
```

该夹具从临时 legacy asset 树建立 before TSV，执行真实
`sow init --adopt-content`，证明服务字节完全不变且重放幂等；随后在
`.sow-migration-staging/rollback-candidate` 构造隔离候选并以 serving TSV 逐字节比对；L1 验证 canonical view，
fsck 证明 legacy root 未漂移，它们不冒充 candidate 校验。随后切换临时 serving-root symlink。候选
被故意删除一个文件后，TSV 检测漂移，再把 symlink 切回从未改写的 legacy root，最终摘要与 before
完全一致；同一回退再次重放仍保持一致。该 symlink fixture 不证明 Nginx reload 或主机崩溃
持久性，生产门禁仍要求独立演练。snapshot 脚本会拒绝 symlink/特殊文件并检测 hash
期间的 size 改变，但多文件全局一致性仍依赖 runbook 要求的外部 writer freeze。

定向 Go E2E 另外使用 schema-valid、非秘密的 Pigsty-v1 fixture，走真实 CLI、DEB/RPM body
parser、签名 metadata、CAS/ref/receipt 和 materialize 路径，证明：

- `apt/pgsql/jammy/dists/jammy` 由 per-suite repo 纳管；
- YUM primary 的 flat `foo.rpm` 从物理 source 导入，canonical view/candidate 只使用
  `Packages/<首字母>/foo.rpm`，receipt 同时锁定 source/canonical；
- nested/escape/wrong-bucket href、unlisted RPM、payload tamper 与 canonical collision 在
  view ref/ledger 提交前失败；
- 真实 package candidate 切换后注入 payload loss，再切回 untouched legacy source；失败
  candidate 移出 origin，源 APT/YUM byte manifest 不变。

writer-fence 套件实际输出：

```text
PASS deterministic-read-only-baseline
PASS live-process-and-mount-probes
PASS suspicious-process
PASS writable-container
PASS writable-container-ancestor
PASS writable-submount
PASS incomplete-attestation
PASS writable-legacy-entry
PASS incomplete-tree-enumeration
PASS nonregular-legacy-entry
PASS no-overwrite
PASS output-inside-root
PASS incomplete-probe
writer fence preflight suite: PASS
```

脚本只读旧 root，报告不复制进程命令或 credential；它证明当前有效用户权限、当前主机
process/mount/container probe 与闭合 operator attestation 一致。测试声明和 fixture 不是云 IAM、
scheduler 或生产 service-account 撤权证据。

真实 DEB/RPM/asset parser、原子性、机密性、frozen 和后续 materialize 证据仍由
`2026-07-12-legacy-content-adoption.md` 承载；本文件不重复冒充生产旧仓全量演练。

## 尚未通过的生产门禁

- 真实旧树的全量 `init --adopt-content`、隔离 materialize、所有 suite/EL/arch 的系统
  apt/dnf 与 origin 切换；
- `/pkg/pig/latest`、channel-less APT/YUM 及全部公开 asset URL 的切换前后 HTTP 证据；
- 生产 Nginx/origin/CDN 对 `/.sow/`、`/.pool/`、`/.git/` 的真实拒绝证据；在此之前不能
  对正在公开托管的 root 执行 adoption；
- R2/COS/Cloudflare/EdgeOne 的真实 publish、purge、漂移、部分失败和回滚；
- 已有 `sow publish --restore-generation N --target cf|cos` 前向恢复操作面，但真实双云回滚
  尚未取得凭据/窗口执行；beta/latest asset/APT/YUM topology 已有条件删除闭包，真实端点
  是否支持并执行 `If-Match` 仍必须现场 probe，snapshot/stable topology 继续失败闭锁；
- `copy-bin`/`copy-beta` 旧 `.io/.cc` 同 key 异正文已在 2026-07-17 由受审 external
  builder 收敛为 canonical 正文并通过本地 SOW handoff；仍缺生产 builder receipt/URL
  回归。其余 `external-handoff` 的真实 builder 交付，以及 `retire`/`policy-reject` 的
  写权限撤销；
- 生产 writer-fence 尚未运行，缺 scheduler 禁用导出、container/runtime 清单、旧树
  ACL/ownership 和 R2/COS credential revoke/IAM 记录。

因此该证据只关闭“迁移映射是否漏项、是否可机读、是否 fail closed、零字节 adoption 与
本地回退是否可复现”四个问题；G5 与生产迁移仍不得标记完成。
