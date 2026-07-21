# 验收证据目录

本目录保存可复现命令、环境与日期化结果摘要；只有明确内嵌或链接日志的报告才包含原始 stdout/stderr。文件只有在实际命令成功运行后才可作为需求矩阵证据；设计说明、资料调研和 Mock-only 测试不得放宽通过标准。

安全冻结（2026-07-14）：任何测试、PoC、探测或 purge 都不得使用 CO/COS 或
Cloudflare 生产仓库、bucket、Zone、domain。既有生产只读基线仅作为冻结的历史迁移前
记录保留，不构成重跑授权。真实云验收只允许独立评审并写入编译期 SHA-256 固定 registry
的专用、可丢弃、明显非生产资源。2026-07-18 provider-readiness registry 已且仅已钉住
`pro`/`pro.pigsty.io`/`beta.pro.pigsty.io` 这一个 Cloudflare tuple。它开放单供应商只读
readiness；owner 另行明确授权了仅命中空 `pro` 桶、带 exact bucket 确认与 run-owned digest
allowlist 的 storage-only 协议测试。destructive/full-POC、Worker/CDN、provider-deployment 与
bootstrap registry 仍保持关闭。
2026-07-19 的 V-25 又把 bootstrap 与 provider log-sink 的 reusable lease key
从 plan/deployment 版本身份中分离：同一资源/专用 raw bucket 始终只有一个稳定 key，历史
idle/expired 版本可 CAS 重放而 live holder 仍阻塞；readiness receipt/seal 的本地半对中断也可
精确续写。该轮只运行本地协议与故障注入，没有写 `pro` 或任何云资源。
2026-07-17 增加的离线 candidate generator 只在仓库外输出评审候选；完整 mutation
仍须命中双云 resource 与 provider-deployment registries，单供应商 read-only readiness 则命中
[ADR-0033](../adr/0033-provider-scoped-readiness-registry.md) 的独立第三 registry。owner 于
2026-07-17 把 R2 bucket `pro` 与
`pro.pigsty.io` namespace 指定为测试资源；[ADR-0032](../adr/0032-owner-designated-cloudflare-test-resource-exception.md)
把 distinct beta 冻结为 `beta.pro.pigsty.io`，且只允许三者 exact tuple 进入离线评审；
任一子集、其他 Pigsty host/bucket 及所有生产仓库仍拒绝。
同日的 [Cloudflare `pro` 只读盘点](2026-07-17-cloudflare-pro-readonly-inventory.md)
已从认证面板确认账号 handle/ID、空 `pro` 桶与 public access，并从公网确认
`pro.pigsty.io` 返回 Cloudflare 404；`beta.pro.pigsty.io` 当前无 DNS。该观察没有
云写入，也不是 signed S3/provider readiness 或 POC-06 通过。
2026-07-18 的[非生产域 readiness 收口](2026-07-18-cloudflare-pro-domain-readiness.md)
随后在 owner 授权边界内新增 beta custom domain、把两个 host 的最低 TLS 冻结到 1.2，
以权威/公共 DNS、TLS 1.0/1.1 拒绝和 1.2/1.3 成功、认证 R2 List 证明真实状态，并把
exact tuple 钉入独立 readiness registry。SOW Go List 已通过；因缺 scoped Cloudflare
read-only API token，signed receipt/控制面摘要与 POC-06 仍未通过。2026-07-19 的
登录面板只读复查又明确显示 `pigsty-entitlements` Worker 不存在；未做任何面板写入，
因此完整 bootstrap 还缺独立评审的 verifier identity。

大仓库 manifest 性能用例通过 `perf` build tag 隔离，默认单测不会意外读取 100GB 级夹具：

```bash
SOW_PERF_ROOT=/path/to/read-only-copy-of-repo \
  /usr/bin/time -l go test -tags perf -run TestLargeRepositoryManifest -v ./test/perf
```

不要把生产 serving root 直接作为写入式测试目标。允许只读盘点时也应先建立可丢弃的
APFS clonefile/普通副本，再让后续性能、迁移和恢复命令只接触副本；2026-07-15 的实跑
边界与结果见 `2026-07-15-legacy-tree-readonly-clone.md`。

正式终验应将完整 stdout/stderr、硬件、源码 revision/工作树摘要与仓库包数保存为日期化日志，并把实测值回写需求矩阵。当前未绑定 revision/工作树摘要或未保存原始日志的报告只能作为该次观察摘要；测试代码存在本身不算通过。

APT 50,000 包流式索引证据可直接复现，不读取外部大仓库：

```bash
SOW_RUN_PERF=1 go test ./internal/aptrepo \
  -run '^TestGenerateStreaming50000Performance$' -count=1 -v
```

实测结果与证据边界见 `2026-07-12-apt-streaming-50k-performance.md`。

远端完整 inventory、双 List 稳定快照、遗留对象 HEAD/流式 GET 纳管、失败零提交
以及首发不重传 payload 的协议级证据见
`2026-07-12-remote-inventory-adoption.md`。该证据明确区分本地 SigV4 协议夹具与
仍需凭据执行的真实 R2/COS PoC。

其余证据报告与验收入口如下；每项是否实跑、源码日期及外部边界以自身正文为准：

- `2026-07-20-yum-compatibility-bound-cutover-recovery.md`：实际 CLI 使用的锁与
  `os.Root` capability-bound YUM cutover recovery 现在覆盖 S2/S3 半写、孤儿、已提交及
  无 canonical authority 的拒绝路径；post-flip 故障恢复原链接或原缺失状态。709 个 CLI
  ordinary/race、全包静态/迁移/性能与双份 clean-delivery 已通过；全程仅临时本地仓库。
- `2026-07-20-dead-code-static-analysis-closure.md`：删除 42 个 `U1000` 不可达声明与
  768 行旧 wrapper/compatibility auditor，保留唯一 CLI 接线路径；默认 Staticcheck
  正确性检查、六片 ordinary/race、非 CLI ordinary/race、四平台静态构建、47 项边缘
  合同、七套迁移和离线 clean-delivery 全绿。全程真实云/上游开关为 0。
- `2026-07-20-config-input-and-rpm-provenance-hardening.md`：所有外部与 canonical-history
  配置入口在 YAML 前统一实施 8 MiB + 1-byte sentinel，覆盖精确边界、空仓/存量仓
  `ExitConfig` 零状态变更与 reachable-history 负例；vendored RPM fixture 恢复固定
  v1.3.0 上游原字节，且 clean-delivery 抽取树以固定 h1、离线可重放方式重跑 provenance
  gate。审查又关闭 canonical 展开自锁、无界 HEAD baseline、sentinel error precedence、
  mutable module-cache 自证和 CRLF 改写路径；697 个 CLI ordinary/race、全部 non-CLI
  ordinary/race、静态/模块与七套迁移门禁已通过。post-document 双份 clean-delivery 身份
  只记录在交付根外 handoff，全程未触云或生产资源。
- `2026-07-20-config-topology-complexity-bound.md`：在任何 upstream arches/components
  序列默认复制和派生叶分配前实施 65,536-work-unit 与 64 MiB derived-string 双预算；
  溢出安全地计入显式成员、default copy、长路径/keyring 重复与 APT/YUM/selector logical
  leaves，包行不计入。成员/路径/edge/Nginx 投影改为索引、一遍 arch 展开或确定性
  `O(n log n)`；第一候选的结果因盲审发现字符串放大和残留二次扫描而作废，修正版经两路
  clean review、707 个 CLI ordinary/race、全部 non-CLI、静态/模块/迁移与 V-43 双份
  clean-delivery 后关闭 V-41。全程仅本地，无云或生产访问。
- `2026-07-20-reachable-history-config-memory-bound.md`：asset 与 package reachable-history
  扫描由 commit→decoded-config 改为 commit→blob identity，并共用 2-entry/16 MiB
  canonical-input LRU；淘汰前置、miss 重验、失败不缓存、owner 冲突证据压缩及真实 Git
  早期违规回归均通过 ordinary/race。只读本地验证，不触云或生产资源。
- `2026-07-19-basic-auth-wire-canonicalization.md`：Cloudflare/EdgeOne 共享
  Basic fallback 收紧为 case-insensitive scheme、literal SP、规范 padded Base64 与最长
  1024 字节 printable US-ASCII `user:password`；alias/CTL/DEL/UTF-8/超长负例均在
  401 前零 origin call，challenge 不再虚报 UTF-8。source/dist、47/47 shared contract、
  双时区与 Go compat bridge 全部通过；仅本地，不替代真 Worker/CDN。
- `2026-07-19-edge-entitlement-expiry-canonicalization.md`：静态 token/Basic
  entitlement 的 expiry 收紧为唯一 whole-second UTC RFC3339 wire form，拒绝无时区、
  offset、fractional、calendar rollover 与 `24:00:00`；畸形 Basic 文档也在两个 adapter
  构造期失败。source/dist、46/46 shared contract、Go deployment/compat focused tests
  全部通过；仅本地，不替代真 Worker/CDN。
- `2026-07-19-confidential-edge-preflight.md`：stable/snapshot/gated publication 在首个
  journal 或远端 mutation 前必须匿名证明 `sow-edge-runtime/v2` 的精确 private 404；
  public-only plan 不联网。raw 404/200/redirect/v1/cache/origin/teardown/cancel 负例、双
  provider HTTP、真实 CLI 零 mutation 和 owner 授权 main/beta raw-domain 只读负证据均
  已实跑。当前两个测试域按设计被拒绝；这不冒充 Worker/private-origin/purge/POC-06 通过。
- `2026-07-19-legacy-migration-review-hardening.md`：迁移 selector 从 synthetic matrix
  收紧到完整 physical Pigsty-v1 contract 与 158-command exact-leaf/compatibility 静态黄金；
  x86_64/aarch64 状态机、缺任一物理架构的第 5 个 family 突变、同数量路径漂移、
  任意进程直接路径及外部 hard-link alias 已打开可写 FD、不可能日期和 Pro 零字节
  empty-SHA 身份负例均已实跑；writer fence 的 macOS `lsof` 与断网 Linux procfs
  分支也都通过。旧仓仅只读，
  用户已有修改保持不动；不冒充生产 writer 撤权或云发布通过。
- `2026-07-19-r2-resource-stable-lease-rotation.md`：bootstrap key 改由 readiness-resource
  SHA 稳定派生，provider log-sink 固定为 dedicated raw bucket 根 key；跨 plan/deployment 的
  idle/expired CAS 接管、live/foreign/stale-holder 拒绝、当时的 recovery receipt v2 与 readiness
  receipt/seal 中断续写均有 ordinary/race 故障注入证据。其 direct recovery 已由下一项替代。
- `2026-07-19-r2-bootstrap-two-phase-recovery.md`：把 expired bootstrap 恢复改为
  `live -> owning pending -> durable receipt -> recovery idle`，覆盖 pending/receipt/final-Put
  三类中断、成功后响应丢失、跨多次恢复保留的 canonical lineage、同 run 幂等、跨
  run/plan/resource/stale ETag/伪造 digest/readiness 负例及零 Delete；ordinary/race/static/
  clean-delivery 均从当前源码复现。未触云，POC-06 不变。
- `2026-07-19-route-safe-caret-url-canonicalization.md`：关闭 Go 接受 RPM 合法 `^`、
  标准 URL 却序列化为 `%5E`、旧 edge 因 blanket percent rejection 永久 404 的协议裂缝；
  Go 的 static/local/dynamic-plan/verify/purge 与两家 adapter 共用唯一 uppercase `%5E` wire
  contract，并在 origin/ownership 比对前恢复同一 literal key。caret YUM root 的
  beta→latest、stable token/Basic CLI E2E、真实 Nginx public/Basic 回环与
  lowercase/double/unreserved/slash 负例通过；
  仅本地/protocol 合同，不冒充真边缘。
- `2026-07-19-state-lock-atomic-publication.md`：本地 state lock 以 boot/start token
  区分 PID 复用，并把完整 v1 记录先写入 leased private inode，再用 create-only hardlink
  单点发布；真实子进程在提交点前后退出、partial unpublished、legacy create collision、
  可见 inode 替换与 permission-reconciliation 前置门禁均通过 ordinary/race/双平台编译。
  全程仅临时目录，无网络或云访问；不替代 FR-28/NFR-09 的真双云验证。
- `2026-07-19-yum-consumer-lock-release.md`：关闭 YUM consumer preflight 准备阶段唯一残留的
  裸 `Lock.Release()`；已有主错误保持原对象/退出分类，真实 durable-record 路径替换的释放
  失败进入 stderr warning，外来锁证据不被删除。ordinary/race、完整 YUM consumer、静态门禁
  与独立盲审通过；仅本地临时锁，不触云且不升级 FR-28/NFR-09 真双云状态。
- `2026-07-17-yum-infra-current-compatibility-cutover.md`：当前生产
  `yum/infra` 只读 234-file 快照的精确可写副本；216/216 RPM 由 Pigsty key
  验签，两个 root `modules.yaml` 只在副本 quarantine，完成双架构
  S0→S1→S2→S3、raw/strong EL8/9/10 DNF、Nginx generation mirrorlist、
  L1/`fsck`/幂等 replay，并记录和修复 carrier-wide manifest 对单 arch route
  的投影缺陷。生产源测试前后 manifest 均为 `b44a86b7…49c7`；repository
  metadata 使用一次性测试 key，不代表生产 key/cutover，也未使用任何生产云。
- `2026-07-17-gated-pro-exact-copy-adoption.md`：只读生产 `pro/` 的 APFS
  精确副本上关闭 gated→latest 失败前 CAS 写入缺陷；15 个 23.5GB TGZ 进入
  stable，零字节 legacy checksum 被排除并以确定性 `sow add` 输入替换；覆盖
  哈希、gzip/tar、重放、hardlink materialize、L1、fsck、GC 与 authenticated
  Nginx route，明确未触碰任何云资源。
- `2026-07-17-real-cloud-safety-entrypoints.md`：provider raw-sink mutation 移入 durable
  ledger/reservation 之后；离线 registry candidate generator 与按 Cloudflare/EdgeOne 独立的
  read-only readiness receipt 已实现并通过本地合同测试。未连接或写入任何云资源。
- `2026-07-17-cloudflare-bootstrap-offline-validation.md`：Cloudflare 首次非生产部署在
  mutation 前强制消费 plan-pinned Ed25519 sealed freshness、逐 run/plan 动态授权与
  provider-visible R2 CAS
  lease；Worker/route create-only、双读稳定闭包、原子私有 receipt、幂等 rollback 与
  expired-lease recovery 的官方 SDK/协议夹具 ordinary/race 均通过。bootstrap registry 仍为空，
  本报告没有联网或写入 R2/Worker/Zone，也不冒充 POC-06。
- `2026-07-17-cloudflare-provider-attestation-offline-validation.md`：provider attestation v3
  把 auth/origin/verifier 的兼容日期、flags、active runtime/settings/schedule/exposure 与完整
  route/domain/Worker inventory 纳入连续双读摘要，并钉住 EdgeOne realtime-log 的不可变 area；R2 custom domain 强制 TLS 1.2+ 与冻结的
  Modern cipher 集，双供应商日志配置用独立 R2 CAS lease 串行。官方 SDK loopback、fake-store
  ordinary/race 通过；未读取凭据、未触云，POC-06 仍受阻。
- `2026-07-17-cloudflare-pro-readonly-inventory.md`：认证 Cloudflare 面板只读确认
  account ID、空 `pro` 桶与 public access；公网只读探针确认主 host 接入 Cloudflare、
  beta host 尚无 DNS。没有上传、配置或 purge；缺 zone ID、scoped credentials 与部署
  身份，所以不冒充 signed readiness/POC-06。
- `2026-07-18-cloudflare-pro-domain-readiness.md`：owner 授权的 `pro` 测试 tuple 已
  配成 exact main+beta、TLS 1.2、active/access-enabled；权威/公共 DNS、HTTPS、
  TLS 1.0–1.3 与认证 R2 空桶实测完成，独立 readiness registry 已钉住。缺 scoped
  Cloudflare API token，故没有 signed receipt，也不冒充完整 POC-06。
- `2026-07-18-cloudflare-bootstrap-rollback-hardening.md`：回滚删除改为 receipt-bound
  checked delete，补齐精确身份探测、附件/完整版本闭包、租约时间预算、provider-success
  响应丢失重放、rollback pre-credential readiness 与 R2-only lease recovery。官方 SDK
  loopback、故障注入、ordinary/race、clean-delivery 和 30 分钟全仓测试通过；未触云，
  不冒充 POC-06。
- `2026-07-18-durability-teardown-audit.md`：本地写入耐久性与收尾错误审计；关闭
  FSCK 最终 Git 复核、APT/upstream/publish/sync/compatibility 锁与能力清理、manifest/
  provenance/evidence 目录 fsync、canonical rollback backup、purge watcher teardown 和
  nil-context panic。记录 676 个 CLI 用例的六分片 PASS、聚焦 ordinary/race、vet 与
  clean-delivery；不包含任何云访问，也不升级真实云或生产迁移状态。
- `2026-07-18-real-r2-storage-protocol.md`：只在 owner 授权的空非生产 `pro` 桶实跑
  create-only、Put CAS 并发单赢家、HEAD/streamed GET、Copy source CAS 与 DeleteObject
  capability probe；确认 R2 忽略删除 `If-Match`，run-owned key 经双次 streamed identity、
  run lease 前后重验与 absence 证明收敛，测试前后及独立 `rclone` 清单均为空。
  它只关闭 R2 storage data-plane 子集，没有实跑 Publisher checkpoint/purge/commit，也不关闭
  Worker/CDN/COS/EdgeOne 或完整 POC-06。
- `2026-07-19-r2-fsck-storage-only-authority.md`：`sow fsck --target` 改为 R2/COS
  concrete storage-only client，CDN secret 缺失或非法仍可完成真实协议路径，且不能转换为
  publisher。owner 授权的空非生产 `pro` 桶真实完成首次采纳、幂等重放、CAS 漂移拒绝且
  Git HEAD 不变、精确恢复与身份绑定清理；测试后独立 `rclone` 清单为空。没有 CDN token、
  control-plane/custom-domain 请求或生产写；不关闭 COS/EdgeOne、purge 或完整 POC-06。
- `2026-07-20-r2-publication-storage-transaction.md`：实际产品 `add/promote/publish/fsck`
  在 owner 授权的空非生产 `pro` 桶完成 R2 checkpoint/generation、物理 no-op 重放、已发布
  inventory adoption、full fsck、CAS 漂移拒绝且 Git HEAD 不变、精确恢复与身份绑定清理；
  测试后独立 `rclone` 清单为空。对象存储与 SigV4/TLS 为真实 R2，purge/CDN 是严格本地
  adapter，明确没有请求真实 Cloudflare control plane/custom domain，也不关闭 COS/EdgeOne
  或完整 POC-06。
- `2026-07-17-builder-handoff.md`：`sow add --expected-object` 把外部 builder
  的 SHA-256/size 声明逐输入绑定到 asset、DEB 与 RPM 的真实 CLI/CAS/Git
  路径；摘要错误在新 CAS/view 写入前拒绝，聚焦 E2E `4.237s` PASS。后续 shared
  ROOT builder 已用这条边界接收 canonical 正文；两者都不冒充生产 builder/cutover。
- `2026-07-17-root-cos-builder-handoff.md`：从只读 Pigsty 源把 `bin/get.cc`、
  `bin/claude`、`bin/ray` 精确绑定为 COS-only `/cc`、`/claude`、`/ray`，在临
  时仓库完成 digest-bound add、promote、hardlink materialize、Nginx、L1、fsck、
  GC 与幂等重放；ordinary/race 均 PASS，20,775 字节，源未变、云访问为零。对应
  physical migration owner 已仅对 `cos` 激活，生产 cutover 仍保持 pending。
- `2026-07-17-root-shared-canonical-builder-handoff.md`：钉住八个 `.io/.cc`
  源正文，确定性生成 mirror-aware `/get`、`/pig`、`/pkg`、`/beta`；global→China
  fallback、strict host override 负例和真实 SOW CLI 本地闭环 ordinary/race 均 PASS，
  源未变、云访问为零。双 target migration owner 已激活，生产 URL/cutover 仍 pending。
- `2026-07-16-fresh-full-content-adoption.md`：新鲜可写副本的当前全量收口。把原
  PGDG 30,274 个 missing path 闭合为 29,499 个官方原字节恢复和 775 个稳定 404
  exact negative-provenance receipt；完成 40,659 APT、44,372 PGDG YUM、16,582
  其他 YUM 与 958 public asset 纳管/幂等，真实 AlmaLinux 10 DNF 在断网、
  `repo_gpgcheck=1`/`gpgcheck=1` 下安装 PGDG 18 文档包，最终 95-repo fsck 与 GC
  为零 drift/orphan/missing/delete。报告还记录 SQLite 多连接 writer 修复、659 项
  ordinary/race 六分片和测试 cancellation barrier 回归。生产源只读，Cloudflare
  `pro` bucket/`pro.pigsty.io` 未被探测或使用。
- `2026-07-16-legacy-tree-full-adoption-copy.md`：历史阶段报告，保留首次发现
  `apt-infra` orphan、PGDG 缺体、DEB control-only RSS 与 asset archive scanner
  问题的审计链；其“恢复未完成”结论已由 fresh-copy 报告取代，不再代表当前状态。
- `2026-07-16-current-source-validation.md`：post-ADR-0030/SQLite/多架构 Nginx 修复后的 660 个 CLI ordinary/race
  六分片、全部非 CLI ordinary/race、vet/mod/provenance、四平台静态构建、两模块
  govulncheck、四个 fuzz、edge 41/41、50k ordinary/race、真 apt/dnf/Nginx、固定 digest
  MinIO、Linux `--network none` archive、官方 PGDG sync/replay/L1/materialize、Pigsty builder
  RPM trust 正负例与七套迁移脚本汇总。大仓扫描仅使用 inode `74638033` 的独立 APFS
  副本；云凭据清空，生产云没有写请求。只读生产输入仅限用户明确允许复制的公开公钥和
  既有副本 RPM。报告保留真非生产云、production raw-YUM cutover、其余 builder/gated
  handoff 和运营指标边界，Goal 仍未完成。
- `2026-07-16-yum-infra-package-signature-inventory.md`：历史只读发现链；
  当日 216 个 RPM 中 22 条（21 个 unique object、627,901,590 path bytes）
  只有 digest、没有嵌入签名，证明 SOW 当时正确 fail closed。文档顶部已标记
  2026-07-17 当前快照 216/216 签名通过并链接 S0→S3 证据；旧逐路径表不得继续
  当作当前 blocker。
- `2026-07-15-current-source-validation.md`：严格清空云凭据、关闭 real-cloud/edge/upstream
  门禁后的历史 current-source ordinary/race 六分片、全 core、静态/四平台构建、真
  Ubuntu apt 与 EL8/9/10 DNF、固定 digest MinIO、edge 41 项，以及 50k
  streaming/materialize/publish/CDN/strong-YUM ordinary+race 汇总。记录并修复两个旧性能
  夹具绕过（重复 YUM pkgid 与 fake canonical catalog identity），产品 fail-closed 校验未
  放宽。所有写入仅在临时目录/本地容器；本地生产树与 CO/COS/Cloudflare 生产资源未成为
  测试目标，且本报告不替代真非生产双云/CDN 或生产迁移。
- `2026-07-15-dual-target-independent-pipelines.md`：同一 publish 调用内按 target-major
  顺序独立执行恢复、beta/latest/stable 与显式/保留快照；协议阻塞测试证明
  `--workers 1` 时 CF checkpoint GET 不阻止 COS 跨多个 view/snapshot 提交，过期的
  中断快照只恢复到持有该 intent 的目标。包含 focused ordinary/race/vet 与完整 publish
  回归命令；全部为严格离线的本地供应商协议夹具，不替代真双云/CDN 证据。
- `2026-07-15-legacy-tree-readonly-clone.md`：只读取存量本地树建立 APFS CoW 副本，
  随后只在副本上完成 176-target/44-family 与 74 APT/131 YUM 物理叶子盘点、敏感文件
  不留 path/size/digest 的 75,034-file serving snapshot，以及 72,310-file/89.862GB、
  18-worker manifest 扫描。原目录与 CO/COS/Cloudflare 生产资源均未成为测试目标；
  该证据不替代写入式完整 adoption、真实 signer、云发布或切换回滚。
- `2026-07-15-physical-owner-route-restoration.md`：current-source、严格离线的 APT/YUM
  physical-owner publication 闭包、canonical route receipt/缺失修复、历史双 alias 共用一份
  YUM generation 的前向恢复、逻辑选择器离线归档，以及 retired generation
  exact-versus-payload 生命周期。聚焦 ordinary 7 项 126.863s，另有两个关键路径的 race、
  publish package 与 vet 证据。配置中的 `cf` target 仅走内存协议 transport；没有访问
  R2、CO/COS、Cloudflare、EdgeOne 或生产仓库，不替代真实云、old APT、完整 current-source
  apt/dnf 矩阵或生产迁移。
- `2026-07-13-rpm-package-trust-closure.md`：当时 330-file 产品集合的历史源码重验证报告；
  其中 product digest 已被后续 selected-set/CAS-admission 修改取代，不复用旧
  `c328…8f20` 或 `70f4…9bd07c`。
  覆盖 packet-preserving primary/subkey 历史 policy、latest-policy-first/no-fallback、
  revocation/cross-cert 语义、binary keyring byte-preservation、RPM embedded-signature/
  provenance v3、present-body exact binding 与 receipt reuse、new-view `pool.Verify`、APT
  exact component coordinate，及 bounded-scope `NO ACTIONABLE FINDINGS` 独立盲审。
  报告同时记录 parser 修复后普通/race 全仓、静态、交叉构建、govulncheck、真
  apt/dnf、官方 PGDG、Pigsty trust、MinIO、隔离 50k/72k 与 fuzz PASS；且不替代真
  双云/边缘/生产迁移。
- `2026-07-13-selected-set-materialization-recovery.md`：direct materialize 与
  publish recovery 的独立盲审闭环；覆盖 suite-wide APT/by-hash、metadata-first
  reconcile、fixed-root ownership 与 explicit-target exact export、asset no-key unit、
  inputless standalone add/离线归档 adoption 的 durable replay、asset path-scoped
  canonical/physical replacement、RPM/DEB frozen-entry pre-CAS admission、snapshot
  `_sow` 漂移清理，以及 mutable/snapshot/historical journal 在远端访问前的 exact
  recovery/identity 门禁。文档区分 2026-07-13 历史基线与 349-file 的 2026-07-14
  日期化 follow-up；后者记录定向 ordinary/race/count、全仓 ordinary/race、
  静态检查、四组 `CGO_ENABLED=0` 构建及当前源码真 apt/dnf/Nginx 矩阵。该矩阵中
  real-cloud、real-upstream、Pigsty package-trust 和 legacy-APT opt-in 门禁为 SKIP，
  因此不替代真实双云/边缘、官方上游复验或生产迁移；本次收尾时 product allowlist 已继续
  扩展，349-file 摘要不再是当前交付身份。
- `2026-07-11-client-compat.md`：2026-07-11 历史运行中的公开 Ubuntu/AlmaLinux
  容器真实 apt/dnf/rpm，并覆盖 Nginx 直接托管树；2026-07-14 current-source 矩阵
  见 selected-set 报告。
- `2026-07-12-apt-legacy-fixed-alias-negative-poc.md`：真 Debian Jessie apt 1.0
  分别消费两个 coherent generation，并以 checksum 失败证明 fixed alias 与
  redirect/cookie 候选无法提供 mutable suite 多键原子性；2026-07-16 的
  [ADR-0029](../adr/0029-client-support-floor-and-el8-freeze-version.md) 据此冻结
  apt>=1.2 支持下限，旧客户端负例继续作为反证。
- `2026-07-11-upstream-50k-streaming.md`：上游候选 SQLite spool 与有界 HTTP
  下载并发。
- `2026-07-11-manifest-72k-performance.md`：真实 72,310 包树的并行 hash 与外排。
- `2026-07-12-yum-streaming-50k-performance.md`：真实 RPM parser 与三类 repodata
  的 50k record 流式生成/回读。
- `2026-07-12-materialize-50k-performance.md`：50k CAS hardlink 与全树 reconcile，
  包含逐文件 fsync 瓶颈的诊断和修复结果。
- `2026-07-18-legacy-adoption-50k-performance.md`：50,000 个路径和正文都唯一的小 asset
  通过真实 `cli.Main init --adopt-content` 完成 baseline→CAS/view/receipt/cache、零 serving
  rewrite 与全量幂等重放；记录实际 8/8 import worker 峰值、5ms sampled heap、OS RSS
  高水位、SQLite provenance 全字段 count+digest 闭包、四路 tuple closure 摘要及
  50,000 CAS 逐对象校验。
- `2026-07-12-strong-yum-serving-50k-performance.md`：4×12.5k strong-YUM 坐标的
  两代 current+Previous activation、replay、L1 verify 与 serving GC preflight；记录
  leaf/inner worker 实际峰值、取消恢复、heap/RSS，并明确与 50k RPM metadata 证据组合。
- `2026-07-12-publish-plan-50k-performance.md`：50k 总条目、单项变化时的 O(变更集)
  upload/verify/purge 计划和内存结果。
- `2026-07-12-verify-l3-l4-protocol.md`：canonical plan 驱动的 L3、纯 Go
  APT/YUM L4、stable token/Basic 路径与负例；明确保留真实客户端和双云证据边界。
- `2026-07-12-l3-bounded-concurrency.md`：发布事务的 L3 CDN 流式校验采用
  1..64/target 有界 worker；50,000 对象闭包、确定性错误、取消与 body close 证据。
- `2026-07-12-minio-s3-compatibility.md`：固定 digest 的真实 MinIO 进程，覆盖
  SigV4、条件写、完整发布事务/重放、List/HEAD/流式 GET、服务端 Copy 与删除。
- `2026-07-12-vendor-sdk-contract.md`：R2/COS 共用 AWS SDK v2 S3、Cloudflare
  与 EdgeOne 各用官方具体 Go SDK 的冻结实现证据；覆盖签名条件头、checksum/
  aws-chunked 负例、CopyObject 200 内嵌错误、精确 purge 和 JobId 轮询，并明确
  不替代真供应商 PoC。
- `2026-07-12-offline-tgz-asset-loop.md`：完整、确定性离线 tgz 在同一命令中
  进入 CAS/asset view/hardlink 树，并以相同 ref 安全重放。
- `2026-07-12-publication-preparation-concurrency.md`：普通 view 发布的
  repo/YUM-leaf 准备和源扫描共享全局 worker 预算，证明有并发且无平方级超额。
- `2026-07-12-legacy-content-adoption.md`：真实 DEB/RPM 与生产 parser 驱动的本地
  baseline→CAS/view/receipt 纳管，覆盖零重写、失败仅 CAS orphan、幂等、机密性、
  frozen 语义及后续 materialize/L1/fsck；50k asset 本命令专项数据另见
  `2026-07-18-legacy-adoption-50k-performance.md`。
- `2026-07-14-legacy-family-e2e.md`：当前 44 个迁移操作族的可执行合同；校准 33-repo
  selector universe 与 12-repo synthetic parser/adoption subset，修正 `pkg-pig` ID 和 Docker
  `default/help` 的 retire 语义，并动态运行 16 个真实 CLI/FS/parser/provider-protocol
  E2E、实际二进制零字节纳管/回滚、审计与 writer-fence 负例及 race。明确不替代逐生产
  target、真实双云/CDN 或旧 writer 撤权证据。
- `2026-07-12-legacy-migration-audit.md`：真实四个旧 Makefile 的 176/176 固定摘要/
  target/机器处置/当前 CLI 审核，含缺行、源漂移、未知处置、陈旧 flag 的 fail-closed
  负例，以及零字节 asset adoption、隔离 materialize 与本地 symlink 回退夹具；其中
  117/31 的旧处置计数为历史观察，当前语义修正见 2026-07-14 报告。
- `2026-07-14-physical-migration-config.md`：以 production config decoder、完整 migration
  ledger 与双向 set equality 精确闭合 98 repo ID/135 row、74 APT index、130 ordinary YUM leaf、
  nested quarantine、7/8 root key/prefix 和 16 gated pro 文件；保留 signer/lifecycle non-claim，
  并证明 12-repo/33-repo synthetic、infra group 泄漏、Percona noarch 回退等突变 fail closed。
  这是原始 discovery 合同的历史证据；Pro inventory carrier 随后由 active owner 替换为
  97/134，2026-07-19 又新增专用 EL9 compatibility policy owner，current 恢复为 98/135，
  但组成不同。两条 physical projection、直接 empty-SHA 与实跑见本日迁移硬化报告。
- `2026-07-14-package-repository-history-continuity.md`：本地 embedded-Git package ownership
  冻结门禁；覆盖 HEAD + `refs/sow/*` DAG、manifest/view/snapshot/YUM generation、matching-HEAD
  漂移、delete/reintroduce/root reuse、active/lifecycle/keyring/upstream 例外、锁内 mutation/GC
  重验和 32 MiB identity-only allocation。仅为本地 focused/race 证据，不替代真 apt/dnf、
  双云/CDN 或生产迁移。
- `2026-07-12-apt-by-hash-retention.md`：真实 CLI 连续生成四代 APT 元数据，证明
  retain=2 自动删旧、live/最近代保留、canonical ledger、重放及损坏账本失败闭锁。
- `2026-07-12-evidence-bound-remote-deletion.md`：production cf/cos target code path
  在本地签名 HTTP/S3/CDN 协议夹具上执行 asset `rm` 直达 URL 删除、stale CDN
  重放/历史恢复，以及真实 APT 制品的三代错峰清理；不代表 R2/COS/Cloudflare/EdgeOne
  已实跑，含 foreign drift 与任意 key 删除负例。
- `2026-07-12-apt-selector-transaction-closure.md`：APT partial publish 的 suite-wide
  arch 闭包、共享 pool 流式 upsert、pending unselected suite 隔离、snapshot 固定根
  selector-owned reconcile，以及 partial/full L1 正负例。
- `2026-07-12-incremental-publish-preflight.md`：发布前以远端控制面、配置摘要和
  ref commit vector 判定 no-op；50k view 的 100 次检查不读取大 manifest。
- `2026-07-12-snapshot-verification.md`：snapshot intent 的 L1–L4、本地物化漂移、
  immutable ref 防篡改，以及后续 latest 推进后旧快照仍可独立验证。
- `2026-07-12-edge-token-verifier-wiring.md`：Go 配置到两家可执行 adapter 的同构
  verifier 部署合同，以及 service-only R2 origin、COS SigV4、direct `BYPASS`、
  main/beta same-host cache candidate、Range/HEAD/SSRF/
  redirect/fallback 的 fail-closed 测试；明确不替代真实供应商 PoC。
- `2026-07-12-portability-and-static-builds.md`：Darwin/Linux × amd64/arm64 的
  `CGO_ENABLED=0` 单二进制构建、产物判型、大小与该报告当时的校验和；当前四组
  构建见 2026-07-14 selected-set 报告。
- `2026-07-12-cas-gc-safety.md`：canonical roots 的引用计数、历史窗、孤儿审计、
  stale plan/missing reference 失败闭锁与精确确认删除。
- `2026-07-12-live-latest-url-baseline.md`：全球/国内生产 `/pkg/pig/latest` 的只读
  迁移前 HTTP、ETag、缓存和本地字节一致性；不代表迁移后兼容通过。
- `2026-07-12-live-bucket-inventory-baseline.md`：真实 R2/COS 生产 bucket 的只读
  对象数/逻辑字节及主要历史前缀 before 基线；不代表 SOW 真云发布通过。
- `2026-07-12-upstream-fuzz-hardening.md`：HTTPS base containment 与 APT Release
  checksum path 的短时 fuzz 边界证据。
- `2026-07-12-real-pgdg-upstream-sync.md`：production CLI 对官方 PGDG APT/YUM
  源的签名、checksum、筛选、原字节 CAS、双 provenance、零下载重放、L1 与
  hardlink 物化；此前日期化复验额外覆盖 present receipt reuse 和 exact-body gate，
  RPM v3 receipt 仍绑定 package-keyring、signer 与 header+payload-digest coverage。
  2026-07-14 current-source Docker 矩阵未设置 `SOW_RUN_REAL_UPSTREAM`，该门禁 SKIP；
  历史运行不替代双云 PoC。
- `2026-07-12-sync-durable-recovery.md`：sync 在 provenance、APT component 与
  canonical view 提交后的持久化阶段记录、真实 APT/YUM 文件系统阻塞、普通重试
  投影修复、SIGKILL advisory-lock/orphan 收敛、精确 config/selector 闭锁，以及
  50k present 候选的 evidence-bound receipt reuse。当前实现对未证 body/rotation/legacy
  receipt 重验，新 view placement 仍做单对象 `pool.Verify`，不把该快路径解释成跳过校验。
- `2026-07-15-offline-archive-durable-recovery.md`：合法长 gzip header 兼容、member/
  CRC/ISIZE 与 tar EOF 后尾流检查、opaque-prefix 负例，以及 receipt 前私有 inode+intent
  fsync、post-receipt/post-link 恢复、mutable ref 推进后仍按 frozen refs 精确收敛；含
  Darwin normal/race 与 Linux `--network none` 的真实 linkat/fsync/进程退出运行证据。
- `2026-07-12-yum-generation-atomicity.md`：YUM generation-pinned mirrorlist 的
  客户端可观察原子性、顺序 raw alias PUT 的混代负例与真实 AlmaLinux 10 安装。
- `2026-07-12-yum-raw-alias-signature-bridge-negative-poc.md`：真实 AlmaLinux
  8/9/10 DNF 对双 armor、双 signature packet 与 repomd redirect 的负验证，证明
  它们无法消除 raw baseurl 的签名混代窗口；这不等于消费者迁移/支持决策已完成。
- `2026-07-14-pigsty-yum-consumer-migration.md`：把两个 renderer、九个配置文件中的
  28 个现有 YUM 定义映射到 architecture-specific generation mirrorlist，提供
  source-read-only audit/stage、plan-digest 确认 apply、字节级 rollback、foreign-drift
  拒绝与混合中断恢复；真实 Ansible 渲染已通过，但双 origin、真 dnf 与生产 cutover
  仍明确开放。
- `2026-07-19-pigsty-yum-consumer-preflight.md`：修正 infra 为两个 frozen cross-EL
  projection，并把 mapped endpoint、canonical channel/aggregate inventory、public trust
  byte identity 与完整 RPM-MD/RPM 签名探测收进短时 no-replace receipt；apply 在任何
  evidence/backup 前做 network-free authority replay，并在第一字节写入前以同一 digest
  再验证一次。真实 provider/生产 consumer 未切换。
- `2026-07-12-forward-only-remote-restore.md`：已提交历史 generation 以前向新代恢复的
  CLI/CAS/canonical Git/APT/YUM/签名/崩溃续跑/双 target 协议证据，含配置、CAS、证据链、
  beta/latest asset 与 APT/YUM topology 的条件删除、purge/404、remote ref/channel 收敛；
  snapshot/stable topology 失败闭锁，且明确不冒充真实双云回滚 PoC。
- `2026-07-12-go-vulnerability-remediation.md`：Go 1.26.5、parser-only RPM 本地快照、
  独立模块回归与固定版本 `govulncheck` 门禁，把 3 条可达漏洞收敛为 0。
- `2026-07-12-final-local-audit.md`：汇总 binary parser 修复后的全仓/race、真 apt/dnf、
  MinIO、官方 PGDG、fuzz 与隔离 50k/72k 证据，并记录 trailing-`0x0b`/armored 定向
  回归；post-fix 本地迁移重跑也全部 PASS。其 330-file product identity
  `70f4d1f5…9bd07c` 仅是历史观察，已被后续源码修改取代。真云、生产迁移、legacy
  policy 与运营指标继续明确 OPEN。
- `2026-07-12-publish-recovery-adversarial-review.md`：以当时 320-file historical
  product-source 摘要绑定的三层发布/恢复审查；覆盖 route/generation/delete/YUM 双向闭包、
  client+clean committed replay purge、50k 全变更 O(N) closure 与全部回归门禁。
- `2026-07-12-real-cloud-acceptance-harness.md`：FR-25/FR-27/NFR-09 的默认离线、强资源确认、
  env-only secrets 双云验收入口；production publish 把最小 client+clean purge 闭包、
  generation/plan/checkpoint 摘要与 Cloudflare/EdgeOne 批次回执保存为 fail-closed sidecar，
  generation 4/5 采集 `sow-real-edge-active/v5`，异步日志到齐后由独立只读门关联
  `sow-real-edge-provider-joined/v3`，两个 artifact 都要求 run-bound seal。夹具要求发布前
  fresh `HIT`/Age/剩余 TTL，EdgeOne geography 只接受 ISO country，并同时核对公开 node IP
  与 node ID；这些合同覆盖 FZ-08、RISK-02、POC-01/06 的本地可执行边界。50 步程序现由
  durable phase ledger、逐 CLI 子日志、运行/源码/二进制/资源身份和 crash recovery 绑定；
  snapshot 恢复还验证 canonical HEAD 与 SQLite membership 一致。generation 5 发布前的独立
  HMAC-bound watcher 已通过三轮父进程 SIGKILL + loopback fake-HTTP 合同测试，证明父测试进程
  死亡后仍能在旧 TTL 内持久化 exact run/resource/body/observer/request/time/cache/clean-URL
  证据及 durable completion seal；恢复只消费 evidence+seal 闭包，并拒绝缺失、过期或篡改。
  provider API raw-export/deployed-bundle attestation collector 已实现，并由 loopback
  官方 SDK/签名协议夹具覆盖分页、逐对象读取与前后 TOCTOU bracket；但当前 exact
  non-production registry 仍为空，且未运行真实云或 provider logs，因此 PoC 仍受阻，
  不能升级为通过。

这些文件分别证明不同层；不得把任一子系统的 50k 结果替代真实双云/CDN PoC。
