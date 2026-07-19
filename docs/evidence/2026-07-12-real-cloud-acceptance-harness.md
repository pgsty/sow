# 专用非生产 R2/Cloudflare + COS/EdgeOne 验收夹具

状态：双云事务夹具、供应商 purge 回执 sidecar、多出口/供应商日志证据合同，以及只读
provider API/raw-export/deployment collector 均已实现并默认跳过；collector 已只在进程内
loopback fake HTTP 上通过官方 SDK/签名对象协议合同测试。完整验收只有在独立评审并分别写入
SHA-256 钉住的双云资源 registry 与 provider-deployment registry 后，配合专用非生产资源、两个
以上独立出口及环境变量凭据，才可能联网。单供应商只读预检另有第三个独立 readiness registry。
destructive 双云 resource 与 provider-deployment registry 仍故意为空；第三个 provider-readiness
registry 已且仅已钉住 owner 指定的 Cloudflare `pro` tuple。因而仍没有完整真实供应商 API 原始
导出、部署身份或运行日志，本文件
不把 POC-01/POC-06 记为通过。**CO/COS/Cloudflare 生产 bucket、domain、zone 或仓库在任何
情况下都不得用于本夹具或 collector。**

2026-07-17 补齐了两个安全入口：`TestRealCloudRegistryOnboardingCandidate` 只在仓库外生成
canonical registry 候选与 digest 回执，不读取凭据或构造 HTTP client；
`TestRealCloudProviderReadinessRegistryOnboardingCandidate` 只为一个供应商生成第三个 registry 的
离线候选；`TestRealCloudProviderScopedReadiness` 每次只读取 Cloudflare 或 EdgeOne 一家的
publisher storage/API 凭据，执行一次空桶 ListObjectsV2 和只读 zone/domain identity 查询并生成
封口回执。它们不能绕过独立评审与编译期 digest。ADR-0032 只允许 owner 指定的 `pro` bucket、
`pro.pigsty.io`、`beta.pro.pigsty.io` exact tuple；其他 Pigsty 资源和全部生产仓库仍被拒绝。
Cloudflare first-deployment 另由 [ADR-0034](../adr/0034-cloudflare-nonproduction-worker-bootstrap.md)
定义独立 bootstrap registry、fresh same-run readiness、动态授权、run-bound create-only Worker、
provider-visible R2 CAS lease、双观察 closure、atomic outcome receipt 与过期租约恢复；
[离线验证](2026-07-17-cloudflare-bootstrap-offline-validation.md)不等于真实 provider POC。
长期 provider observation 与日志 exporter 配置另由
[ADR-0035](../adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md)冻结：三个 Worker 的
runtime/security 与整区相关 inventory 连续双读，日志配置 mutation 由独立 R2 CAS lease 串行；
[离线验证](2026-07-17-cloudflare-provider-attestation-offline-validation.md)同样不等于真实 POC。

入口：`test/compat/real_cloud_test.go` 的 `TestRealCloudAcceptance`。测试直接调用生产
`cli.Main`，没有平行的 fake 发布实现。

## 需求映射与证据边界

| 契约 | 当前状态 | 本地已实现的证据合同 | 仍缺少的最终证据 |
|---|---|---|---|
| FR-25 | 已实现/未验证 | production saga 在 purge 前持久化 `sow-purge-evidence/v1`，把 generation/plan/checkpoint 摘要、精确 URL 集及供应商批次回执绑定；sidecar 失败或批次未全部 `completed` 时不能进入 `purged`，成功后复制到 canonical Git。 | 尚未在真实 R2/Cloudflare 与 COS/EdgeOne 上执行 upload→flip→purge→verify 全事务及故障恢复。 |
| FR-27 | 已实现/未验证 | purge evidence 对排序后的 client+clean URL 闭包取摘要，provider 只接收该精确集合；额外、缺失、重复或任意扩大 URL 都失败闭锁，不存在 Purge Everything 路径。 | 尚无真实 Cloudflare/EdgeOne purge audit log 证明线上执行集合与计划一致。 |
| NFR-09 | 已实现/未验证 | 两个 target 各自持有 checkpoint/journal/sidecar；50 步 acceptance ledger 持久化精确 phase、CLI 子步骤、恢复事实与双目标 reservation；第一步只有在 durable ledger 与 reservation 已持有后才允许幂等校准 provider raw sink。EdgeOne 在 Create 接受后先保存 `JobId`/`RequestId`，恢复时轮询同一 JobId。generation 5 另在发布前启动独立进程 watcher 并确认其持有 liveness lock，父 `go test` 被 SIGKILL 后仍可在旧 TTL 内落盘 post-probe。 | 真实双云错峰中断/重放尚未执行；provider API attestation 与部署 bundle digest 未闭合，因此 ledger 必须保持 `running`。 |
| FZ-08 | 实现中 | Cloudflare Worker 与 EdgeOne 函数共用版本化路由/鉴权/干净 URL 合同；active artifact 为 `sow-real-edge-active/v5`、joined log 为 `sow-real-edge-provider-joined/v3`，两者均要求 run-bound seal。 | 同 host cache candidate、真实 HIT/purge 日志和两端部署仍未闭合。 |
| RISK-02 | 受阻 | generation 5 在发布前要求同 observer 对旧字节取得 fresh `HIT`，保存 `Age`/`max-age`/剩余 TTL；EdgeOne provider evidence 只接受 uppercase ISO 3166-1 alpha-2 country，并同时要求不同 country、公开 node IP 与 node ID。 | 本地合同不能回答 EdgeOne 是 per-node 还是 shared/tiered cache；必须取得真实 provider logs。 |
| POC-01 | 受阻 | token A prime、token B clean-key `HIT`、pre-purge fresh HIT、发布后在旧 TTL 内读到新字节，以及 active v5/provider v3 的 request/parent 因果闭包均已编码。 | 未部署真实 same-host `https-bearer` EdgeOne 路径，也没有 country-only provider evidence；不能记为通过。 |
| POC-06 | 受阻 | opt-in 双云夹具、purge receipt、active/provider seal、双 target 独立推进、故障恢复与只读日志关联入口均已就绪。 | 未注入专用真实资源和凭据，未产生真实运行及供应商日志，不能记为通过。 |

这里的“已实现”只描述可执行代码和本地合同测试，不等于真实云验收通过；上表状态必须在
真实运行日志和供应商证据归档后才可升级。

当前 operator 提供的 joined JSONL 及其同机 seal 只能作为关联材料，不能证明内容来自供应商。
`final-fsck` 现在还要求 `real_cloud_provider_attestation_test.go` 的 in-repo collector 从供应商
控制面与原始对象独立重建同一 joined-v3 闭包，否则以
`provider API raw-export attestation required` 失败并保留最后一步 `Current`。collector 绑定：

- Cloudflare account/zone、配置中钉住且启用的 `http_requests` Logpush job、精确 NDJSON 字段、
  未合并 subrequest、与发布桶不同的 provider-only R2 log bucket/stable raw root，以及供应商动态
  生成的每个对象的 key/size/ETag/字节摘要；共享 zone 中其他启用 job 不能复用该 raw bucket，
  `http_requests` filter 还必须可证明不包含 main/beta host，未知 filter 失败关闭；
- Cloudflare auth Worker、service-only R2 origin Worker 与外部 token verifier 的 active
  deployment/version/ETag/content identity；auth 的 `ORIGIN` 与 `TOKEN_VERIFIER` service
  binding、origin 唯一 `REPOSITORY` R2 binding、main/beta exact routes（共享 zone 的其他 route
  必须可证明不匹配 main/beta host）、account-wide Worker inventory、custom domain 与
  workers.dev/preview exposure；auth
  Worker 的全部 non-secret runtime variables、`SOW_ORIGIN_BEARER` secret 名称及 service binding
  必须精确闭合，`SOW_ORIGIN_MODE` 只能是 `https-bearer`；auth/origin bundle 必须逐字等于仓库
  `edge/dist` 制品，verifier 内容摘要和其 redacted binding inventory 摘要都必须命中独立管理员 registry；
- EdgeOne `DescribeZones` 必须以 exact zone-id filter 返回唯一、active、unpaused 且显式带
  test/ci/sandbox/staging/dev 标记的 full/partial 非生产 zone；随后不加域名 filter 全量分页
  `DescribeAccelerationDomains`，inventory 必须只有 online 的 main+beta 两个 host。该 gate 与
  Cloudflare `Zones.Get` 都在任何 Logpush/realtime-log mutation 前执行；
- EdgeOne 启用且 100% sample 的 L7 realtime-log S3 task、与发布桶不同的 provider-only COS log
  bucket/stable raw root、供应商动态对象 inventory/ETag/摘要、部署函数内容、默认函数域名的
  独立非生产 identity 与 fail-closed 403/404 probe、零 component binding、零 executable replica、
  `DescribeFunctionRuntimeEnvironment` 的完整
  `https-bearer` non-secret/secret-name 闭包，以及 main/beta host 到精确 FunctionID 的 direct trigger
  rules；该模式只允许 `SOW_ORIGIN_BEARER` 与 `SOW_TOKEN_VERIFIER_BEARER`，出现 COS SigV4
  ID/key/session token 即失败；task/function 查询还要求 `TotalCount=1`，不能接受截断页；
- collector source/build/config identity、确定性产品配置摘要、reader/writer 独立身份摘要，以及 Cloudflare `ParentRayID`、EdgeOne
  `ParentRequestID` 对 active request 的完整、无额外、无缺失原始 JSONL 重建；原始 URL 必须
  已去 token/query，最终 ledger 只保存 URL-free/secret-free 摘要与资源身份。

`edgeone_token_verifier_deployment_sha256` 目前是管理员 registry 中的必填部署身份，不是 collector
从通用 HTTPS verifier URL 反查出的供应商 API 事实；collector 不把这个配置摘要伪报为真实部署
查询通过。最终非生产验收还必须从实际 verifier 的部署系统归档 deployment identity/content digest，
并用两枚专用 token 的真实 EdgeOne 请求证明 runtime 正在调用该部署。缺少这份外部证据时，
POC-01/POC-06 与总 Goal 都保持未完成。

本地 loopback 测试覆盖 setup/collector 使用的 Tencent SDK action 精确请求体、Cloudflare 官方
SDK 的完整 SinglePage inventory 遍历、签名 R2/COS provider-side Prefix ListObjectsV2 与逐对象
GET、production-like EO zone、第三个 EO 加速域名、第二个 log task、重叠或复用 raw bucket 的
Logpush job、可证明无关的 shared-zone Logpush job/route、额外 overlapping route/rule/component/
replica、错误 host filter/default function domain/binding/runtime/字段、截断 `TotalCount`、
URL query、重复 JSON key、不完整末行、缺失原始记录、operator 自证不一致、symlink 与读取期间
inode replacement。它证明 collector 可执行，不证明任何真实供应商资源已验证。
资源 registry 在 provider config/credential/client/request 之前执行；资源通过后，第二个
provider-deployment registry 在 config decode 后、任何 credential/client/request 之前执行，且
stable deployment digest 排除供应商动态生成的 raw object key，却绑定资源摘要、log bucket/raw root、
部署 ID、runtime、verifier content/binding digest。不得临时改常量或跳过任一门来“跑一次”。

原先 purge 已提交、generation 5 post-probe 尚未持久化之间的父进程 SIGKILL 窗口，现由
`real_cloud_purge_watcher_test.go` 的独立子进程合同关闭。`interrupt-cf-g5` 在任何 provider
请求前先原子安装 secret-free spec 与 exact expected-body 文件，spec 绑定 run、acceptance
binding、管理员钉住的双云资源摘要、observer topology、workspace、generation、旧 transaction、
新 body/clean URL 摘要及每个 observer 的绝对 `fresh_until`；两枚 run entitlement 只用于派生
HMAC key，不写入文件。子进程再次执行 `validateRealCloudDedicatedTestResources`，取得独占
liveness lock 并原子写入 exact `armed` receipt 后，父进程才允许发布。它独立轮询本地 canonical
committed checkpoint/purge receipt，随后通过现有 `requestRealEdgeMultiPoP` observer/proxy 路径
获取新字节，把 generation/transaction、generation/checkpoint/purge 摘要、observer/request、
request/response time、cache age/max-age/status、body 与 clean URL 摘要原子写入 vendor evidence。
evidence 经 `fsync` 后另以 no-replace 原子安装 durable completion seal，恢复只消费
evidence+seal 闭包；若在 evidence 持久化后、seal 安装前崩溃，只能在原 deadline 前为同一
evidence 补 seal，绝不重发观察请求。恢复只接受同一 spec/run/resource/body 的 HMAC 记录；
已有文件冲突、篡改、自然到期边界或缺失均失败，不会补采 pre-purge 事实。已经在纯本地
loopback fake HTTP 中反复证明父测试进程被
SIGKILL 后孤儿 watcher 继续完成两 vendor/四 observer 证据；这只关闭本地 harness 因果缺口，
不等于真实 Cloudflare/EdgeOne 已验证，provider API raw-export/deployed-bundle attestation 与
专用非生产资源实跑仍是 POC-01/POC-06 blocker。

## 资源安全合同

运行前必须同时满足：

1. 所有资源必须是可丢弃的专用非生产测试资源。除原 destructive confirmation 外，必须
   另行给出固定 non-production 确认和覆盖 R2/COS account endpoint、region、bucket、
   Cloudflare/EdgeOne zone 及四个 CDN base 的 canonical exact allowlist。它还必须逐字段
   命中仓库内 SHA-256 编译期钉住、管理员评审的 exact registry；运行进程不能仅靠同一组
   env 自行声明安全。资源 registry 之外，还必须把 Cloudflare Logpush job、三个 Worker、
   EdgeOne realtime-log task/function/default function domain、不可变 `Area`、完整 runtime、verifier deployment
   digest/binding inventory，以及两个独立 raw-log bucket/raw root 和 reader/writer access-key
   identity digest 写入第二个 SHA-pinned 管理员 registry；供应商动态 object key 因 run 而变化，
   不进入 stable identity。第三个 provider-readiness registry 只钉住一家供应商的 bucket、endpoint、
   zone/name 与 main/beta roots，不授予 Worker/CDN 或完整双云 mutation 权限。当前只有该第三
   registry 包含 exact Cloudflare `pro` tuple；destructive 双云 resource 与 provider-deployment
   registry 仍为空，因此完整真实云入口会在联网前失败。
   离线 onboarding helper 只能在仓库外输出 `.candidate.json` 与
   `sow-real-cloud-registry-candidate-receipt/v1`；它不改 registry、不改编译期 digest、
   不读 credential，也不联网。候选仍须由管理员逐项核对 DNS/account/bucket/zone/IAM 后手工纳入。
   bucket 只接受 `sow-test-`、
   `sow-ci-` 或 `sow-sandbox-` 前缀；CDN host 必须有独立的 `test`/`ci`/`sandbox`/
   `staging`/`dev` label，并显式拒绝已知 Pigsty 生产仓库域名。这个门禁在创建 ledger、
   artifact、observer client 或 provider client 前执行，fresh/recover 都不能绕过。
2. R2 与 COS 都是为本次测试准备的专用空桶；夹具会在任何写入前通过生产
   `fsck --adopt-remote-inventory` 的双 List/逐字节路径证明
   `listed=0 local_expected=0 retained_extra=0 streamed_get=0 pages=2`。非空或双 List
   退化即停止，不会自动清空一个误配桶。
   Logpush/realtime-log 原始导出必须分别落入另外两个专用非生产 log bucket，且配置层强制与
   publisher 的 R2/COS bucket 不同。每次 destructive run 在任何 edge probe 或发布 mutation 前，
   先完成上述 EO/CF zone safety gate，再把两个 exporter 幂等配置为
   `<raw_root>/<same-run-id>/`；跨云只成功一半时不开始 probe，下次以同一 run ID、
   `SOW_REAL_CLOUD_MODE=recover` 和同一配置安全重放。
   exporter 使用各自独立、管理员摘要钉住的 write-only identity；collector 使用另外两个独立的
   read-only identity，只对精确 per-run prefix 执行 SigV4 ListObjectsV2/Get。六个 storage
   publisher/reader/writer access-key identity 两两隔离，control credential 也只绑定对应 provider；
   任一 storage identity 复用即在 client/request 前停止。发布 CLI
   从未得到 log bucket 身份或 credential，因此不能把 operator 写入伪装成 provider-only 原始导出。
   writer/reader IAM policy 仍须在真实专用资源评审时作为外部证据归档；当前空 registry 不把这项
   伪报为通过。
3. COS 桶从未启用过 versioning；“Suspended”不等于从未启用。配置确认之外，
   每次 COS publish 仍会执行生产 `GET ?versioning` 能力探针。
4. 两个 CDN 主域名必须经过已部署的版本化 edge 合同，而不是直接公开桶。真实缓存
   门禁要求两端均以 `SOW_ORIGIN_MODE=https-bearer` 使用 main/beta 同 host global Fetch，
   且 WAF/origin 规则使匿名 `.sow/gated` 请求为 404；`r2-service` 与 `cos-sigv4` 可单独
   验证真实私有读取，但它们都报告 `BYPASS`，不能让本夹具的 FR-38 缓存断言通过。
   Cloudflare 必须保留 `global_fetch_private_origin` 且 zone origin 自行校验独立 origin
   bearer；该 fetch 会绕过 mapped Worker/security rules，不能仅靠 WAF 鉴权。origin
   响应必须显式 shared-cache eligible，且无 private/no-store/Set-Cookie/
   `Vary: Authorization`；夹具拒绝 `BYPASS`、`DYNAMIC` 与 `UNKNOWN`。
   beta 域名必须是独立合法主机名。Cloudflare purge
   token 具备该 zone 的 exact-URL purge 权限，腾讯 CDN 凭据具备 EdgeOne
   `CreatePurgeTask` / `DescribePurgeTasks` 权限；两端 token verifier 都必须认可下面两枚
   彼此不同的专用 Pro token。
5. 测试先生成三代 latest（第二代只改变 APT，第三代同时改变 YUM membership 与
   mutable asset），APT by-hash retention 固定为 100，因此这三代的 plan 均不得含
   DELETE。随后 generation 4 发布完整 stable APT、YUM、public asset 与 gated asset，
   用 token A/B 验证动态 mirrorlist、APT/YUM L3/L4、public/gated asset read-back 与 gated
   clean-cache 收敛。每次有 purge 的 production publish 必须先在私有 publish-journal 目录
   原子保存 `sow-purge-evidence/v1`，把 target/transaction/generation、generation/plan/
   checkpoint SHA 与排序后的精确 URL closure 绑定；Cloudflare 每批记录真实 `CF-Ray`
   （`result.id` 只作为 vendor result，不能冒充 request ID），EdgeOne 则先持久化 Create
   返回的 `JobId`/`RequestId`，再以同一 JobId 轮询并保存 Describe `RequestId`。只有全部
   批次 `completed` 后 journal 才能进入 `purged`，成功后回执复制到 canonical Git 的
   `remotes/<target>/purges/<generation>-<transaction>.json`。generation 4 完成后，夹具还
   从至少两个不同代理出口访问两家 CDN：
   第一个出口用 token A prime，后续出口用 token B 访问同一 clean key 且必须得到 `HIT`；
   request ID、响应 PoP 提示、cache/transport、clean URL/body 摘要与请求时间写到仓库外的
   `0600` active artifact，代理 URL、token、请求 URL 与受保护路径不得进入 artifact；
   generation 5 替换 gated mutable asset。该代先临时把进程内 Cloudflare purge token
   换成确定无权的值，使真实事务停在 `pointer-flipped`；恢复原 credential 后必须沿同一
   transaction 完成 purge、验证与 checkpoint，COS 再独立追平。测试不会改 zone 配置，
   也不会把失权 token 写进配置、参数或 artifact。
6. generation 5 发布前先从 generation 4 的相同 observer/node 采集 `pre-purge` 旧字节
   `HIT`，并记录正 `Age`、`max-age` 与剩余 TTL；发布后必须在同一剩余 TTL（保留一秒安全
   边界）内返回新字节。双目标恢复完成后重复同一组多出口探针，并要求 generation、transaction
   与受保护字节都变化，而 clean URL 摘要保持不变。这一同步阶段只证明主动请求和可关联的
   request ID，不冒充供应商 PoP 证据。Cloudflare/EdgeOne 日志通常异步到达，随后由独立、
   只读的 `TestRealCloudEdgeMultiPoPEvidenceAcceptance` 读取 active artifact 与 collector 归一化
   joined JSONL：Cloudflare 以主请求 `RayID`/`EdgeColoID`/`EdgeColoCode` 关联 Worker 子请求
   `ParentRayID`/`CacheCacheStatus`；EdgeOne 以主请求 `RequestID`/`EdgeServerID`/
   `EdgeServerIP`/`EdgeSeverRegion` 关联函数子请求 `ParentRequestID`/`EdgeCacheStatus`。验收要求
   Cloudflare 不伪造不存在的 edge IP，而由不同 colo/node 证明不同 PoP；EdgeOne evidence
   仅把 `EdgeSeverRegion` 规范化为大写 ISO 3166-1 alpha-2 country，不接受或推断更细粒度
   geography。验收同时要求不同 country、不同公开 `EdgeServerIP` 与不同 `EdgeServerID`，
   不能把“两个不同节点但仍在同一位置”伪报为多 PoP。active artifact 固定为
   `sow-real-edge-active/v5`，完成后由
   `sow-real-edge-active-seal/v1` 绑定 run ID、完整字节 SHA 与 size；joined log 固定为
   `sow-real-edge-provider-joined/v3`，覆盖 `probe_phase=stage|pre-purge`，并由
   `sow-real-edge-provider-log-seal/v1` 完成 exporter seal。只读验收要求四个 active
   generation/vendor 记录及全部 stage/pre-purge child log 精确闭包：不接受额外、未知、重复、
   跨 run、parent/child ID 碰撞或 seal 后追加。两代 joined log 均须逐 request ID、generation、
   transaction、cache status、body/clean digest 与因果时间窗绑定。
   字段依据见 [Cloudflare HTTP request logs](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/zone/http_requests/)、
   [Cloudflare CF-Ray](https://developers.cloudflare.com/fundamentals/reference/http-headers/)、
   [EdgeOne L7 日志字段](https://cloud.tencent.com/document/product/1552/105791)、
   [EdgeOne 实时日志](https://cloud.tencent.com/document/product/1552/96007) 与
   [EdgeOne EO-LOG-UUID](https://cloud.tencent.com/document/product/1552/105788)。
7. generation 6 再替换一次 gated mutable asset，但这次只把进程内 EdgeOne
   `secret_id`/`secret_key` 换成确定无效值，保留 COS storage 与 Basic fallback 字段。
   COS 必须在对象和 generation pointer 已落盘后停于 `pointer-flipped`，本地 committed
   state 仍为 generation 5；恢复原 credential 后沿同一 transaction 完成，Cloudflare
   保持 generation 5，直到它独立追平 generation 6。这证明两家 CDN 故障恢复不是只对
   Cloudflare 特判。
8. generation 7 按需发布一个 7 个月前的 YUM 快照，generation 8 发布当前快照。
   生产 `sow promote stable <snapshot>` 会正确拒绝回填过去日期；测试不能伪造系统时间，
   因此先由真实 CLI 创建今日 immutable snapshot，再以一次可恢复的本地 `state.Apply`
   将完全相同的 YUM leaf 写入 7 个月前的 immutable ref，模拟上线已运行七个月后的合法
   历史状态。该受控 fixture 不写远端、不移动今日 ref，后续 materialize/publish/retention/
   delete 全部仍走 `cli.Main` 与生产 provider。
   generation 7 的 plan 必须声明 `ObjectCopyImmutable.CopySource`；夹具再用同一 source
   ETag/size/digest 对 `.sow/probes/server-side-copy/<target>/...` 发一次真实 R2/COS
   CopyObject，双次 HEAD→streamed GET 校验后只对该 run-bound exact SOW-owned identity 执行明确无条件 cleanup 并确认 absent，从而排除“plan
   写了 CopySource、供应商却只能回退上传”的假阳性。这个 probe 不引用也不删除业务 key。
   `snapshot_materialization_months=6` 使后者只删除前者的
   `.sow/snapshots/<id>.json` 与 `.sow/gated/snapshots/<id>/...` SOW-owned namespace。
   每个目标都必须运行生产 saga 的条件删除能力探针。若错误 ETag 被拒且 probe 仍存在，使用
   matching-ETag DELETE；若供应商明确忽略条件，夹具生成的配置已显式选择
   `checkpoint-fenced`，并依次验证远端 publication fence、连续两次 HEAD→streamed GET 正文
   身份，再执行供应商无条件 DELETE、HEAD absent 与 fence 不变。专用空桶、双云 destructive
   registry 和 writer 隔离是该显式单写者模式的前提，不得用于生产仓库。
   checkpoint 提交后，夹具再用真实 provider 对 plan 中每个 delete key 以及由 transaction ID
   派生的 conditional-delete probe key 逐一 HEAD，全部必须 absent；这一步不依赖本地 inventory
   自证。
   R2、COS 错峰执行；cf 删除后 cos 的旧快照仍在，cos 完成后双方 inventory 才同时消失。
   无论成功或失败，夹具从不清桶、不扫描后删除“额外对象”，也不触碰目标 snapshot
   namespace 外的数据。再次运行必须重新提供专用空桶。
9. 在任何快照删除前，夹具还会对已存在的控制对象做无破坏竞争探针：R2 以错误
   `If-Match` 重写同一 checkpoint 字节，COS 以 create-only 重建同一 generation lock；
   两者都必须返回 conflict 且 body/ETag 不变。这个入口只接受真实供应商服务根：R2 主机必须属于
   `*.r2.cloudflarestorage.com`，COS 主机必须精确等于配置区域的
   `cos.<region>.myqcloud.com`；两者都必须是无凭据、无端口、无 bucket path 的 HTTPS
   根。MinIO 或其他 S3-compatible endpoint 必须使用本地协议夹具，不能由本测试产出
   “真实供应商 PoC”证据。
10. 双目标到 generation 8 后，夹具对真实 R2 和 COS 分别执行
   `publish --restore-generation 4`。restore 不倒退 checkpoint，而是把 historical stable
   intent 以前向 generation 9 重建；快照和其他 intent ref 继续由 parent 保留。cf 先恢复
   时 cos 仍服务第三代 gated 字节，随后 cos 独立恢复第一代字节。两边 exact replay 必须
   同时输出 `status=unchanged`/`status=complete` 且 generation/checkpoint/plan 逐字节不变；
   普通 stable publish 最后把当前第三代 gated ref 推进为 generation 10。每一步都必须穿
   storage、exact purge、CDN read-back 和 target 独立 checkpoint，不能把本地 Git checkout
   冒充远端回滚。

夹具要求一个同时绑定两个存储服务端点、精确桶名、区域、两家 CDN zone 以及四个
main/beta CDN URL 的强确认值：

```bash
export SOW_REAL_CLOUD_NONPRODUCTION_CONFIRM='I-CONFIRM-DEDICATED-DISPOSABLE-NON-PRODUCTION-SOW-TEST-RESOURCES'
# 必须是单行 canonical JSON；下列值必须逐字等于本次 env，不能填生产资源。
export SOW_REAL_CLOUD_TEST_RESOURCE_ALLOWLIST_JSON='{"schema":"sow-real-cloud-test-resource-allowlist/v1","purpose":"dedicated-disposable-non-production-test","cf_r2_endpoint":"https://test-account.r2.cloudflarestorage.com","cf_r2_bucket":"sow-test-r2-example","cf_zone_id":"test-zone-only","cf_cdn_base":"https://sow-test-cf.example.invalid","cf_beta_cdn_base":"https://sow-test-cf-beta.example.invalid","cos_endpoint":"https://cos.ap-shanghai.myqcloud.com","cos_bucket":"sow-test-cos-example","cos_region":"ap-shanghai","edgeone_zone_id":"test-zone-only","cos_cdn_base":"https://sow-test-eo.example.invalid","cos_beta_cdn_base":"https://sow-test-eo-beta.example.invalid"}'
export SOW_REAL_CLOUD_DESTRUCTIVE_CONFIRM="I-CONFIRM-DESTRUCTIVE-SOW-TEST-ON-EMPTY-R2-AND-NEVER-VERSIONED-COS:R2=${SOW_REAL_CF_R2_ENDPOINT}/${SOW_REAL_CF_R2_BUCKET};CF=${SOW_REAL_CF_ZONE_ID}@${SOW_REAL_CF_CDN_BASE_URL},${SOW_REAL_CF_BETA_CDN_BASE_URL};COS=${SOW_REAL_COS_ENDPOINT}/${SOW_REAL_COS_BUCKET}@${SOW_REAL_COS_REGION};EO=${SOW_REAL_EDGEONE_ZONE_ID}@${SOW_REAL_COS_CDN_BASE_URL},${SOW_REAL_COS_BETA_CDN_BASE_URL}"
```

端点、桶名、区域、zone 或 CDN URL 任一改变，旧确认立即失效。

## 离线准入与单供应商只读预检

完整双云 mutation/POC 先注入不含秘密的 canonical
`SOW_REAL_CLOUD_TEST_RESOURCE_ALLOWLIST_JSON` 与
`SOW_REAL_CLOUD_PROVIDER_ATTESTATION_JSON`。输出子目录必须尚不存在且位于仓库外：

```bash
install -d -m 700 /var/tmp/sow-registry-review
export SOW_RUN_REAL_CLOUD_REGISTRY_ONBOARDING=1
export SOW_REAL_CLOUD_REGISTRY_OUTPUT_DIR=/var/tmp/sow-registry-review/candidate-20260717
go test -count=1 ./test/compat -run '^TestRealCloudRegistryOnboardingCandidate$' -v
```

该命令只生成两份 canonical candidate 和一份 digest receipt。管理员必须独立评审 exact bytes，
再把候选纳入两个 registry 并更新对应编译期 SHA-256 常量；直接使用 candidate、临时改常量或
仅设置同值 env 都不能通过进程级门禁。

单供应商只读 readiness 不依赖上面两个完整 registry。先提供只含该供应商身份的 canonical
`SOW_REAL_CLOUD_PROVIDER_READINESS_RESOURCE_JSON`，离线生成第三个 registry 的候选。下面的
Cloudflare 形状中 `REPLACE_WITH_EXACT_ZONE_ID` 必须替换成真实 zone ID，否则校验失败：

```bash
export SOW_REAL_CLOUD_PROVIDER_READINESS_RESOURCE_JSON='{"schema":"sow-real-cloud-provider-readiness-resource/v1","purpose":"dedicated-disposable-non-production-test","provider":"cloudflare","cloudflare":{"account_id":"72cdbd1b54f7add44ecbd3d986399481","r2_endpoint":"https://72cdbd1b54f7add44ecbd3d986399481.r2.cloudflarestorage.com","r2_bucket":"pro","zone_id":"REPLACE_WITH_EXACT_ZONE_ID","zone_name":"pigsty.io","cdn_base":"https://pro.pigsty.io","beta_base":"https://beta.pro.pigsty.io"}}'
export SOW_RUN_REAL_CLOUD_PROVIDER_READINESS_REGISTRY_ONBOARDING=1
export SOW_REAL_CLOUD_REGISTRY_OUTPUT_DIR=/var/tmp/sow-registry-review/readiness-cloudflare-20260717
go test -count=1 ./test/compat -run '^TestRealCloudProviderReadinessRegistryOnboardingCandidate$' -v
```

该 helper 不读取 credential 或联网；它只在仓库外写 canonical candidate 与 resource/registry
digest receipt。管理员独立核对 account、endpoint、bucket、zone、main/beta 后，才可把 exact bytes
纳入第三个 registry 并更新编译期 SHA-256。

readiness entry 评审入库后可只检查一家。下例只读取 Cloudflare 的
`SOW_REAL_CF_STORAGE_JSON` 与 `SOW_REAL_CF_CDN_JSON`；选 `edgeone` 时只读取对应 COS/EdgeOne
两项，不需要另一供应商、完整 deployment config 或 destructive confirmation。它只做 signed
empty-bucket ListObjectsV2 与 zone/domain identity 查询，不做 upload、purge、exporter mutation
或 delete。Cloudflare 还必须从官方 R2 control API 读到该桶恰好两个 enabled、ownership/SSL
均为 active、zone ID/name 精确匹配的 main/beta custom domains；缺 beta 或任何额外 domain 都失败。
readiness 使用的 `SOW_REAL_CF_CDN_JSON` bearer token 因而至少需要 exact account 的
`Workers R2 Storage Read` 与 exact zone 的 `Zone Read`；它不需要写、部署或 purge 权限：

```bash
install -d -m 700 /var/tmp/sow-provider-readiness
export SOW_RUN_REAL_CLOUD_PROVIDER_READINESS=cloudflare
export SOW_REAL_CLOUD_NONPRODUCTION_CONFIRM='I-CONFIRM-DEDICATED-DISPOSABLE-NON-PRODUCTION-SOW-TEST-RESOURCES'
# 继续使用上面已纳入 readiness registry 的 exact canonical resource JSON。
export SOW_REAL_CLOUD_RUN_ID=sow-real-cloud-readiness-20260717-a
export SOW_REAL_CLOUD_PROVIDER_READINESS_RECEIPT=/var/tmp/sow-provider-readiness/cloudflare.json
go test -count=1 ./test/compat -run '^TestRealCloudProviderScopedReadiness$' -v
```

成功会原子写 `sow-real-cloud-provider-readiness/v2` 与同名 `.seal`；回执只含 readiness resource、
bucket/control identity digest 和时间，不含 URL、deployment identity 或 credential。该预检不等于
POC-06，也不代替后续双云故障、purge、cache 与 provider-log 验收。

## 环境合同

非秘密配置：

| 变量 | 含义 |
|---|---|
| `SOW_REAL_CLOUD_NONPRODUCTION_CONFIRM` | 必须逐字等于固定 non-production 确认短语；与 destructive confirmation 相互独立 |
| `SOW_REAL_CLOUD_PROVIDER_READINESS_RESOURCE_JSON` | 单行 canonical JSON，只含所选 Cloudflare 或 EdgeOne 的 endpoint/bucket/zone-name/main/beta；必须命中独立 provider-readiness registry，不能夹带另一供应商字段 |
| `SOW_RUN_REAL_CLOUD_PROVIDER_READINESS` | 只允许 `cloudflare` 或 `edgeone`；启用所选供应商的 read-only empty-bucket + control-plane identity 预检 |
| `SOW_REAL_CLOUD_PROVIDER_READINESS_RECEIPT` | readiness v2 回执的仓库外绝对路径；父目录预先存在且安全，成功时同时写 `.seal` |
| `SOW_REAL_CLOUD_TEST_RESOURCE_ALLOWLIST_JSON` | 单行 canonical JSON，精确列出两个 account endpoint、region、两个测试桶、两个 zone 和四个测试 CDN base；还必须命中编译期 digest 钉住的仓库 registry，任一不一致即在联网前停止 |
| `SOW_REAL_CF_R2_ENDPOINT` | R2 S3 服务根，例如账户级 `https://<account>.r2.cloudflarestorage.com`；不含桶名/路径 |
| `SOW_REAL_CF_R2_BUCKET` | 专用空 R2 桶名 |
| `SOW_REAL_CF_CDN_BASE_URL` | Cloudflare 主 CDN 干净 HTTPS 根 |
| `SOW_REAL_CF_BETA_CDN_BASE_URL` | 与主域名不同的 beta CDN HTTPS 根 |
| `SOW_REAL_CF_ZONE_ID` | Cloudflare zone ID |
| `SOW_REAL_COS_ENDPOINT` | COS S3 服务根，例如 `https://cos.ap-shanghai.myqcloud.com`；不含桶名/路径 |
| `SOW_REAL_COS_BUCKET` | 含 APPID 的专用空 COS 桶名 |
| `SOW_REAL_COS_REGION` | COS 区域，例如 `ap-shanghai` |
| `SOW_REAL_COS_CDN_BASE_URL` | EdgeOne 主 CDN 干净 HTTPS 根 |
| `SOW_REAL_COS_BETA_CDN_BASE_URL` | 与主域名不同的 beta CDN HTTPS 根 |
| `SOW_REAL_EDGEONE_ZONE_ID` | EdgeOne zone ID |
| `SOW_REAL_CLOUD_WORKSPACE` | 本次单一 destructive run 的持久工作区绝对路径；不得位于产品仓库内 |
| `SOW_REAL_CLOUD_RUN_ID` | 绑定本次配置、确认值、公开签名 key 与外部 edge artifact 的稳定 run ID |
| `SOW_REAL_CLOUD_PROVIDER_ATTESTATION_JSON` | 单行 canonical JSON v3；绑定确定性产品配置摘要、CF account/zone/Logpush job/auth+origin+verifier Worker 及逐 Worker compatibility date/flags、verifier 内容与 redacted binding 摘要、EO log task 的不可变 `realtime_log_area`、function/default-domain/verifier deployment、两端 exact `https-bearer` runtime，以及与发布桶分离的两个 raw-log bucket/raw root、reader/writer 和独立 CF log-control identity digest；完整 stable identity 还必须命中独立 provider-deployment registry，未知字段或非 canonical 表示失败 |
| `SOW_REAL_CLOUD_MODE` | `fresh` 或 `recover`；当前 recover 只允许重放已登记的同一 publish 操作，见下方限制 |
| `SOW_REAL_EDGE_OBSERVERS_JSON` | 2–8 个 `{"id":"...","proxy_env":"SOW_REAL_EDGE_PROXY_..."}` observer 的严格 JSON 数组；ID、env 名、代理 endpoint 均不得重复 |
| `SOW_REAL_EDGE_ACTIVE_OBSERVATIONS_JSONL` | 仓库外绝对路径；父目录须预先存在且非 symlink；完成文件使用 `sow-real-edge-active/v5` 并要求同名 `.seal` |
| `SOW_REAL_EDGE_PROVIDER_LOG_JSONL` | destructive run 后由日志 collector 生成并以同名 `.seal` 完成的仓库外 `sow-real-edge-provider-joined/v3` JSONL 路径 |
| `SOW_RUN_REAL_EDGE_EVIDENCE` | provider logs 到齐后仅对只读关联验收设为 `1`；不触发 bucket/CDN mutation |

attestation 配置只含资源身份、access-key identity 摘要、secret 名称以及已独立评审的 verifier
部署/内容/binding 摘要，不含凭据。`product_config_sha256` 必须逐字匹配夹具确定性生成的实际
SOW 产品配置。`raw_bucket` 必须与对应 publisher bucket 不同；`raw_root` 必须位于
`sow-provider-logs/`。运行时派生唯一 `<raw_root><same-run-id>/`，由 exporter 自行生成一个或多个
object key；配置不预言 key。collector 使用 provider-side Prefix ListObjectsV2 全量分页，按 key
排序并逐对象 signed GET，限制对象数与总字节、要求每个 JSONL 文件以换行结束，再把完整 inventory
与控制面前后各读取一次；任一 key/size/ETag/body/control digest 变化即失败。以下仅展示 schema，
占位值不能用于运行，尤其不能替换成任何 CO/COS/Cloudflare 生产资源：

```json
{"schema":"sow-real-cloud-provider-attestation-config/v3","product_config_sha256":"<64-lower-hex-deterministic-product-config-digest>","cloudflare":{"account_id":"dedicated-test-account","zone_id":"dedicated-test-zone","logpush_job_id":1,"worker_script":"sow-test-auth","worker_runtime":{"compatibility_date":"2026-07-17","compatibility_flags":[]},"origin_worker_script":"sow-test-origin","origin_worker_environment":"","origin_worker_runtime":{"compatibility_date":"2026-07-17","compatibility_flags":[]},"token_verifier_service":"sow-test-verifier","token_verifier_environment":"","token_verifier_runtime":{"compatibility_date":"2026-07-17","compatibility_flags":[]},"token_verifier_content_sha256":"<64-lower-hex-reviewed-digest>","token_verifier_bindings_sha256":"<64-lower-hex-reviewed-redacted-binding-digest>","raw_reader_access_key_sha256":"<64-lower-hex-reader-id-digest>","raw_writer_access_key_sha256":"<64-lower-hex-writer-id-digest>","log_control_access_key_sha256":"<64-lower-hex-log-control-id-digest>","raw_bucket":"sow-test-cf-provider-logs","raw_root":"sow-provider-logs/cloudflare/"},"edgeone":{"zone_id":"dedicated-test-zone","realtime_log_task_id":"sow-test-log-task","realtime_log_area":"overseas","function_id":"sow-test-function","function_domain_sha256":"<64-lower-hex-dedicated-default-domain-digest>","raw_reader_access_key_sha256":"<64-lower-hex-reader-id-digest>","raw_writer_access_key_sha256":"<64-lower-hex-writer-id-digest>","raw_bucket":"sow-test-eo-provider-logs-1250000000","raw_root":"sow-provider-logs/edgeone/"},"runtime":{"token_verifier":"provider://sow-test-verifier","public_prefixes":["apt","pkg","yum"],"public_keys":["keys/test.asc"],"edgeone_token_verifier_url":"https://verifier.test.invalid/v1/verify","edgeone_token_verifier_deployment_sha256":"<64-lower-hex-reviewed-deployment-digest>","cloudflare_secret_names":["SOW_ORIGIN_BEARER"],"edgeone_secret_names":["SOW_ORIGIN_BEARER","SOW_TOKEN_VERIFIER_BEARER"]}}
```

秘密必须由当前进程的 secret manager/env 注入，不得写进仓库、临时配置、命令行或
shell 历史。四组 publisher/CDN、两组 provider-log reader、两组 provider-log writer 与一组
CF provider-log lease control 凭据的严格 JSON schema 为：

| 变量 | JSON 字段 |
|---|---|
| `SOW_REAL_CF_STORAGE_JSON` | `access_key_id`, `secret_access_key`, 可选 `session_token` |
| `SOW_REAL_CF_CDN_JSON` | `api_token`, `basic_username`, `basic_password`；Cloudflare readiness 的 token 至少具备 exact account `Workers R2 Storage Read` 与 exact zone `Zone Read`，完整 POC 再另按部署/purge/Logpush 操作收窄授权 |
| `SOW_REAL_COS_STORAGE_JSON` | `access_key_id`, `secret_access_key`, 可选 `session_token` |
| `SOW_REAL_COS_CDN_JSON` | `secret_id`, `secret_key`, 可选 `session_token`, 以及 `basic_username`, `basic_password` |
| `SOW_REAL_CF_LOG_STORAGE_JSON` | provider-only R2 log bucket 的 read-only `access_key_id`, `secret_access_key`, 可选 `session_token`；仅允许 exact per-run prefix List/Get，不得具有 Put/Delete 或 publisher bucket 权限 |
| `SOW_REAL_CF_LOG_WRITER_JSON` | Cloudflare Logpush 专用 write-only `access_key_id`, `secret_access_key`；exporter 配置不能安全携带 session token，因此该字段必须省略；不得 List/Get/Delete 或访问 publisher bucket |
| `SOW_REAL_CF_LOG_CONTROL_JSON` | 独立 R2 lease-control `access_key_id`, `secret_access_key`, 可选 `session_token`；只允许 `<raw_root>.sow/provider-log-sink-lease.json` 的 Get、conditional Put 与 exact delete，不得访问日志正文、publisher bucket 或 CDN/Worker API |
| `SOW_REAL_COS_LOG_STORAGE_JSON` | provider-only COS log bucket 的 read-only `access_key_id`, `secret_access_key`, 可选 `session_token`；仅允许 exact per-run prefix List/Get，不得具有 Put/Delete 或 publisher bucket 权限 |
| `SOW_REAL_COS_LOG_WRITER_JSON` | EdgeOne realtime-log 专用 write-only `access_key_id`, `secret_access_key`；TEO S3 task 不支持 session token，因此该字段必须省略；不得 List/Get/Delete 或访问 publisher bucket |

`SOW_REAL_EDGE_OBSERVERS_JSON` 中每个 `proxy_env` 只保存变量名；对应
`SOW_REAL_EDGE_PROXY_*` 的值属于秘密，只接受带显式端口的 `https`、`socks5` 或
`socks5h` authority URL，可由 secret manager 注入可选 username/password。夹具不把底层
代理错误原文写入日志，避免错误串回显带凭据 URL；每次请求关闭连接，且 provider joined
log 必须证明不同供应商 geography 与节点，不能仅以不同代理 endpoint 代替 PoP 证据。destructive run
开始时会解析全部 observer/proxy，并在 active artifact 父目录完成 `0600` 临时文件的
write/sync/remove 与 directory sync；任何已有 artifact、writer lock、symlink parent 或
不可写目录都在空桶 mutation 前失败。取得 run reservation 后、空桶 mutation 前，还会让每个
observer 分别访问两家 CDN 的匿名 gated clean URL，要求代理认证/CONNECT 或 SOCKS、目标端
TLS 以及精确常量 404 denial envelope 全部成功；这一步不携带 entitlement，也不接触桶写路径。

后置只读验收不再解析或连接原来的代理。它要求 secret manager 注入
`SOW_REAL_EDGE_EVIDENCE_FORBIDDEN_JSON`，即 2–64 个需要在 active/provider artifact 中
禁止出现的敏感片段（至少包括两枚 entitlement token；若组织的 exporter 可能接触其他
credential，也一并加入）。该值本身是秘密，不得写入示例文件或 shell 历史；JSONL 还独立
拒绝任何 URL、受保护路径、symlink、未知字段、超限记录或不完整末行。

两组 publisher storage credential 必须只绑定各自专用发布桶，但在该桶内具备 List/Get/Head/Put/
Copy/Delete；R2 必须保留条件 Put 请求头，COS 还需读取 bucket versioning、接受
`x-cos-forbid-overwrite`。Delete 是否执行条件由 runtime probe 如实判定；只有夹具显式
`checkpoint-fenced` 且 publication fence/连续正文证明通过时才可调用明确的无条件接口。若 IAM
不允许 Delete 或 Copy，夹具会在自有 probe/snapshot namespace 内失败，不会改用未授权 key、
客户端上传或跳过验证。CDN credential
仍只需上述精确 URL purge 与状态查询权限，不需要改 DNS/WAF/zone 配置。

另需以 secret 注入 `SOW_REAL_EDGE_PRO_TOKEN_A` 与
`SOW_REAL_EDGE_PRO_TOKEN_B`：两者必须不同，且各为 22–256 位
`[A-Za-z0-9_-]` token。两枚 token 都必须预先加入 Cloudflare/EdgeOne 共用 entitlement
provider，分别授权两个 `SOW_REAL_*_CDN_BASE_URL` 主机下的
stable APT/YUM、动态 mirrorlist、snapshot 路由以及
`/assets/real-cloud-gated/secret.txt`；授权必须覆盖测试生成的
`/pro/v1/<token>/...` 路径，但不得放开无 token 的 `.sow/gated` clean 路径。测试从不
打印 token；它们与八组 JSON 凭据一起进入输出、响应与持久 artifact 泄漏扫描。
夹具在返回环境配置、解析任何 URL 或创建网络客户端之前即以同一 token validator
校验 A/B 并要求两者不同；默认负例把 endpoint 故意设为畸形值，仍必须首先得到对应
token 环境变量的本地失败。
运行 `sow verify --pro-token-file` 时，夹具把 env 中的 token 写入仓库根之外的随机
`0600` 临时文件，并一直保留原 CreateTemp 文件描述符；清理时对原 inode seek、覆零、
truncate、sync、close，只有路径仍指向同一 inode 才删除。若路径被换成 symlink/其他文件，
夹具会保留替换物、清空原 inode 并报错，绝不沿路径误伤目标。文件名与 CLI 输出均不含
token，仓库、Git 和发布 journal 永不持久化它。`basic_username/basic_password` 仅供
发布事务穿 `/pro/v1/basic/...` 执行 L3 read-back，响应必须是 `private,no-store`，不能由
共享缓存复用。真实 cache POC 的两端 runtime 都固定为 `https-bearer`：Cloudflare auth Worker
只允许名为 `SOW_ORIGIN_BEARER` 的 platform secret，并以 `TOKEN_VERIFIER` service binding 调用
verifier；EdgeOne 只允许 `SOW_ORIGIN_BEARER` 与 `SOW_TOKEN_VERIFIER_BEARER`。这一路明确不注入
`SOW_COS_SECRET_ID`、`SOW_COS_SECRET_KEY` 或 `SOW_COS_SESSION_TOKEN`；它们只属于另行验证、会
报告 `BYPASS` 的 `cos-sigv4` 模式，若出现在本 POC runtime inventory，collector 立即失败。

OpenPGP 私钥必须由 `SOW_REAL_CLOUD_GPG_PRIVATE` 持久注入，使 fresh/recover 使用同一签名
身份；磁盘上只写公开 key。每次 CLI
调用在输出日志前都会检查完整 credential JSON、敏感字段值、私钥 armor marker 与
每个 substantial base64 body line；`basic_username`、`basic_password`、裸
`base64(username:password)` 与标准 `Basic base64(username:password)` 均按秘密片段处理，
任一单独出现也立即停止且不打印泄漏内容。生成的
`sow.yaml` 也执行相同检查，其中只出现 `env://...` 引用。每次生产 CLI 调用后还会流式扫描
临时仓库中的全部 regular artifact（包括 canonical worktree、transaction/publish journal、
配置、CAS、materialized tree 以及 canonical `.git/objects` 原始文件），以重叠窗口覆盖跨
chunk 的秘密；嵌套 `.git/objects` 一律拒绝。Git object database 还通过 go-git 语义枚举
blob/ref/commit/tree/tag，形成原始字节与对象语义双层闭包，同时扫描 artifact 相对路径、Git
ref、commit identity/message 与 tree entry 名；symlink、特殊文件或任何 secret fragment 都
失败闭锁。扫描不会按 artifact 大小跳过持久文件，也不会跳过 canonical `.git/objects`；
journal 位于 Git 外且由普通 artifact 扫描覆盖。即使命令返回了
非预期退出码，持久产物扫描也先于 exit-code 断言执行。故意失权的 Cloudflare credential
也在失败调用前加入同一泄漏集合；直接控制面竞争探针的 provider error 在输出前同样检查。

先配置至少两个独立出口与一个全新的仓库外 artifact 路径；代理 URL 仍由 secret manager
注入到引用的 env，不要把值写入命令历史：

```bash
export SOW_REAL_EDGE_OBSERVERS_JSON='[{"id":"egress-a","proxy_env":"SOW_REAL_EDGE_PROXY_A"},{"id":"egress-b","proxy_env":"SOW_REAL_EDGE_PROXY_B"}]'
export SOW_REAL_EDGE_ACTIVE_OBSERVATIONS_JSONL=/var/tmp/sow-real-edge-active.jsonl
export SOW_REAL_CLOUD_WORKSPACE=/var/tmp/sow-real-cloud-workspace
export SOW_REAL_CLOUD_RUN_ID=sow-real-cloud-20260714-a
export SOW_REAL_CLOUD_MODE=fresh
# SOW_REAL_CLOUD_GPG_PRIVATE 由 secret manager 注入，不在 shell 历史中展开
export SOW_RUN_REAL_CLOUD=1
go test -count=1 -timeout=45m ./test/compat -run '^TestRealCloudAcceptance$' -v
```

这一步成功只产生两代、双供应商的主动请求 artifact，不宣告多 PoP PoC。日志 exporter 完成后，
把 main request 与 cache subrequest 合并为严格 JSONL；每行只能含
`schema,run_id,probe_phase,vendor,request_id,parent_request_id,node_id,node_ip,region,cache_status,clean_url_sha256,body_sha256,generation,transaction_id,observed_at`，
其中 `schema` 固定为 `sow-real-edge-provider-joined/v3`，`probe_phase` 只能是 `stage` 或
`pre-purge`；EdgeOne `region` 必须是大写 ISO 3166-1 alpha-2 country（如 `JP`），并拒绝
TEST-NET、私网、loopback、link-local、benchmark 等 special-use node IP。exporter 完成后须
原子写同名 `.seal`，以 `sow-real-edge-provider-log-seal/v1` 绑定 run ID、JSONL SHA256 与
size。然后复用已由 `sow-real-edge-active-seal/v1` 封口的 active artifact，指向 provider
JSONL，由 secret manager 注入
`SOW_REAL_EDGE_EVIDENCE_FORBIDDEN_JSON`，单独运行只读验收：

```bash
export SOW_REAL_EDGE_PROVIDER_LOG_JSONL=/var/tmp/sow-real-edge-provider-joined.jsonl
export SOW_RUN_REAL_EDGE_EVIDENCE=1
go test -count=1 ./test/compat -run '^TestRealCloudEdgeMultiPoPEvidenceAcceptance$' -v
```

第二条命令不需要原 observer/proxy，也不读取 destructive confirmation，且不会执行任何
bucket/CDN mutation；但它会用已钉住的双供应商 provider config、publisher/log-reader storage
credential 与 CDN/API credential 连接供应商只读 API 和精确 raw-log prefix，独立重建原始闭包。
缺凭据、缺日志、日志仍在投递、任一 request 无唯一关联或两个 observer 落在同一 provider
geography/节点都会失败，不能靠重新跑 destructive test 补写证据。active artifact 与 `.lock` 都是
single-use；若 destructive run 在写 artifact 前失败，可在查明原因后安全处理空 artifact
destination，但一旦 bucket 已发生 mutation 就必须保留该次资源和证据，不得清桶后伪装重跑。

持久 workspace 会以 `sow-real-cloud-run/v1` 绑定 run ID、destructive confirmation、配置与
公开签名 key 摘要；50 个冻结 step ID 及其程序摘要进入
`sow-real-cloud-acceptance/v1` durable phase ledger。每个 CLI 子步骤另有 exact argv、源码/
测试二进制/build identity、开始/完成状态和恢复事实；fresh/recover 都在推进前重新验证资源、
输入与已完成步骤产物。SIGKILL 后只能从同一 ledger 的 `Current` 安全重放，不能跳步或换资源。
snapshot ref 提交后恢复还强制重建 catalog，并验证 SQLite 记录的 canonical HEAD 及 current/
historical snapshot membership。该闭环解决了原先“只恢复一个 publish”的本地 harness 缺口，
generation 5 独立 watcher 也关闭了父进程 SIGKILL 造成的 purge→post-probe 本地 TTL 取证窗口；
但不解决上文 provider API raw-export/deployed-bundle attestation，也没有产生真实供应商运行
证据，故真实 POC 仍保持受阻。

未设置 `SOW_RUN_REAL_CLOUD=1` 时，测试在读取凭据或创建任何网络客户端前跳过；常规
`go test ./...` 因而保持离线。`TestRealCloudStablePlanAssertionContract` 与
`TestRealCloudSnapshotRetentionAssertionContract` 默认运行，分别对完整 stable
APT/YUM/purge closure 与 snapshot CopyObject/delete/absence closure 做纯本地正负例，防止
真实资源尚未注入时断言本身悄然退化。`TestRealCloudGatedAssetMutatesStableWithoutPromotion`
还通过真实本地 CLI 证明 gated add/replace 直接推进 stable ref/hash 且绝不创建 beta ref；
`TestRealCloudHistoricalSnapshotFixturePreservesCurrentRef` 证明历史 fixture 复制精确 canonical
bytes、创建独立 immutable ref 且不移动今日 ref；
`TestRealCloudBasicUsernameIsSecretMaterial` 证明仅泄漏 Basic username、裸 HTTP Basic
编码或标准 Authorization 值也会清空捕获输出并失败闭锁；
`TestRealCloudEnvironmentRejectsUnsafeTokensBeforeEndpointParsing` 与
`TestRealCloudGatedCacheEvidenceContract` 分别固定 pre-network token fail-closed，以及 clean URL
摘要/共享 cache-status allowlist 的正负边界。`TestRealEdgeMultiPoPPreflightContract`、
`TestRealEdgeMultiPoPValidatorContract`、`TestRealEdgeMultiPoPPurgeTransitionContract` 与
artifact/provider-log 文件合同测试则覆盖已有证据/锁、同 endpoint、同 PoP、缺日志、错误
generation/transaction/body/cache/time、秘密或 URL 泄漏、symlink、超限与并发 writer 负例。

2026-07-14 的 watcher 定向证据命令全程显式关闭真实云、真实 edge 与真实 upstream，且没有
注入任何供应商凭据：

```bash
env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  -u CLOUDFLARE_API_TOKEN -u TENCENT_SECRET_ID -u TENCENT_SECRET_KEY \
  -u SOW_REAL_COS_STORAGE_JSON -u SOW_REAL_COS_CDN_JSON \
  SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 SOW_RUN_REAL_UPSTREAM=0 \
  go test ./test/compat \
  -run '^TestRealCloudPurgeWatcher(LocalHTTPContractAndTamperRejection|FailsBeforeNetworkAndAtTTLBoundary|SurvivesParentSIGKILL)$' \
  -count=3 -v
```

结果为三轮全部 PASS；每轮 SIGKILL 测试只访问 `httptest` loopback server，先验证独立 child
持有 lock，再杀父进程，最后才开放本地 publication-ready 门。默认生产 helper 自身仍必须先
通过仓库钉住的 `validateRealCloudDedicatedTestResources`；当前资源与 provider-deployment
registries 都为空，所以这些本地
测试不会让任何 Cloudflare、R2、COS 或 EdgeOne 请求变为可达。

2026-07-13 的对抗收口又把断言从“包含某个 URL”提升为逐目标精确集合：first=5、
YUM+asset update=4、stable=12；snapshot 首发严格为 current client+clean 两项，retention
严格为 current+expired 四项，缺项、重复、额外项或跨 host 均失败。匿名 gated 响应除 404 和
edge contract 外还必须证明正文不含受保护字节；Range 必须同时满足 206、`https-bearer`、
精确 `Content-Range` 和 clean URL/cache evidence。两家 pointer-flipped 故障窗口除
generation/checkpoint 绑定外，还分别从 R2/COS 读回实际 `.sow/gated/.../secret.txt` 并逐字节
比对新代。运行时 Pro token 文件
在 CreateTemp 后、任何 chmod/write 前立即登记 cleanup；chmod、short/write、sync、close 以及
cleanup 自身失败均有 fault-injection，不能静默残留秘密文件。默认合同测试另行固定 cf/cos
target、locked generation 正典字节/摘要/intent 绑定和故障凭据字段保留，真实分支不再是唯一断言面。

本轮本地验证（无真实凭据、无联网）已执行：

```text
$ env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
    -u CLOUDFLARE_API_TOKEN -u TENCENT_SECRET_ID -u TENCENT_SECRET_KEY \
    -u SOW_REAL_COS_STORAGE_JSON -u SOW_REAL_COS_CDN_JSON \
    SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 go test -count=1 ./test/compat
ok github.com/pgsty/sow/test/compat 1.467s

$ go vet ./test/compat
# exit 0

$ env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
    -u CLOUDFLARE_API_TOKEN -u TENCENT_SECRET_ID -u TENCENT_SECRET_KEY \
    -u SOW_REAL_COS_STORAGE_JSON -u SOW_REAL_COS_CDN_JSON \
    SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 \
    go test -count=1 ./test/compat -run '^(TestRealCloud|TestRealEdge)' -v
# 两个 opt-in acceptance 在第一条语句跳过；RealCloud/RealEdge 默认合同测试全部 PASS
ok github.com/pgsty/sow/test/compat 1.594s

$ go test -count=1 ./test/compat/cleandelivery -run '^TestRepositoryPolicyClosure$' -v
PASS
```

2026-07-14 provider raw-attestation 收口后又执行了以下本地证据。每条 `go test` 均显式设置
`SOW_RUN_REAL_CLOUD=0`、`SOW_RUN_REAL_EDGE_EVIDENCE=0`、
`SOW_REAL_CLOUD_PURGE_WATCHER_HELPER=0`、`SOW_RUN_REAL_UPSTREAM=0`，清空八组 `SOW_REAL_*_JSON`
及 AWS/Cloudflare/Tencent ambient credential，并把 `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`
固定为不可达的 `http://127.0.0.1:1`（`NO_PROXY=127.0.0.1,localhost`）。因此这些结果只来自
loopback fake、本地文件系统与编译检查，没有访问任何 CO/COS/Cloudflare 生产资源：

```text
$ go test -count=1 ./internal/publish
ok github.com/pgsty/sow/internal/publish 7.567s

$ go test -count=1 ./test/compat -run '^TestRealCloudProvider'
ok github.com/pgsty/sow/test/compat 0.878s

$ go test -count=1 ./test/compat
ok github.com/pgsty/sow/test/compat 7.469s

$ go test -race -count=1 ./test/compat -run '^TestRealCloudProvider'
ok github.com/pgsty/sow/test/compat 2.994s

$ go vet ./...
# exit 0

$ go test -count=1 ./test/compat/cleandelivery -run '^TestRepositoryPolicyClosure$' -v
PASS
ok github.com/pgsty/sow/test/compat/cleandelivery 1.192s
```

两份 destructive 管理员 registry 仍是 canonical 空集合，且文件摘要与编译期常量一致：resource registry
`bd52ba1da663739b3a5b5a3c8f9d58290d710753d691fcd05c1eb25216ea9cea`，provider-deployment
registry `3eac7304de5472c532fbfcd93f93cc69a5baa778c9c851280e692e0f9d633e52`。所以即使误把任一
opt-in 设为 `1`，`TestMain` 也会在 credential/client/request 之前失败；不能以本地 PASS 解锁真实云。

同日再次按“任何情况下不得用 CO/COS 或 Cloudflare 生产仓库做测试”的硬禁令，清空全部
ambient/provider credential、关闭所有真实云/边缘/上游开关并把外网代理固定到回环黑洞，单独
重跑进程级安全边界：

```text
$ go test -count=1 ./test/compat -run '^(TestRealCloudProductionIsolationGate|TestRealCloudPinnedRegistryCannotApproveProductionResource|TestRealCloudNonProductionConfirmationIsExact|TestRealCloudProcessGateRunsForEveryNetworkCapableOptIn|TestRealCloudDedicatedTestResourceGate)$' -v
PASS
ok github.com/pgsty/sow/test/compat 0.554s
```

负例逐项拒绝 production/prod/live 标记、未获批的 Pigsty 生产域名、COS 存储域名冒充 CDN、
共享 bucket/host、非精确 non-production 确认和任一网络型 opt-in 绕过。ADR-0032 后只允许
桶名 `pro`、`https://pro.pigsty.io` 与 distinct beta
`https://beta.pro.pigsty.io` 作为不可拆分的 owner-designated tuple 进入离线 registry
评审；任一子集或变体仍拒绝，且 destructive 空 registry 继续在完整入口请求前失败关闭。本次
历史运行没有真实供应商请求；2026-07-18 后续只运行了独立 storage-only R2 用例，见对应证据。

共享 `pigsty.io` Zone 可以保留其他业务的 Worker routes，但 provider attestation 会分页读取整区
Worker、embedded route、zone route 与 custom-domain inventory。只有按 Cloudflare 官方 route
pattern 规则确定不可能匹配 `pro.pigsty.io` 或 `beta.pro.pigsty.io` 的无关 route 才允许共存；
任何可能覆盖 reviewed host 的 exact/wildcard/path-specific/negating/malformed route 均拒绝，且
SOW auth Worker 不得有第三条 route。完整 inventory identity 会进入 provider control digest，
连续两次读取必须一致；缺失 custom-domain service/certificate/zone identity 也失败关闭。

共享 Zone 的 Logpush inventory 使用相同的“只绑定相关闭包”原则。钉住的 SOW job 必须精确
覆盖 main+beta；无关 enabled job 仅在 destination 不含 SOW raw bucket 且其 `http_requests`
filter 可证明排除两个 reviewed host 时允许。未知、畸形或不支持的 filter 保守地视为重叠。
无关 job 只有在上述不相交性可证时才允许；完整 Logpush inventory 仍进入 provider control digest。
setup 在两个 provider safety read 都通过后、任何 Logpush/realtime-log mutation 前取得独立 R2
conditional lease，每次 mutation 前续租，全部成功后 exact-ETag 删除。跨供应商部分失败保留租约
至五分钟到期，再由下一次 run CAS 接管并幂等重放；write-only exporter credential 不承担此职责。

## 通过条件

一次通过会依次证明：

- 两个桶的初始 inventory 均为完整且空；
- cf generation 1 成功时 cos 仍无 checkpoint，随后 cos 独立到 generation 1；
- 第二轮仅 cf 前进到 generation 2，cos 保持 generation 1，且 L2 明确报告
  `REF_POINTER_DRIFT`；随后 cos 独立追平；
- 第三轮删除 latest 索引中的 RPM 并替换 mutable asset：仍先让 cf 单独到
  generation 3、证明 cos 保持 generation 2 并报告 drift，再让 cos 独立追平；
- 第一代同时包含 APT InRelease、不可变 YUM generation、公开静态 mirrorlist 和
  mutable asset；两边 canonical generation/checkpoint/plan 都是合法生产 schema，
  checkpoint 为 `checkpoint-committed`，plan 对全部变化对象有 read-back，且最小
  purge 集精确覆盖 APT `InRelease`、YUM mirrorlist、legacy `repomd.xml` + `.asc`
  以及 mutable asset；
- `sow verify --layer L2,L3,L4` 穿两个 CDN 读取对象，并对 APT 与 generation-pinned
  YUM 执行真实协议探针，同时检查 asset 字节闭包；
- 对现有 generation 3 控制对象的无破坏竞争写均失败：R2 checkpoint 的错误
  `If-Match` 与 COS generation lock 的重复 create-only 都返回 conflict，随后读取的
  body/ETag 不变；
- stable generation 4 是完整 Pro APT+YUM+asset publication：plan 同时覆盖 gated APT
  `InRelease`、YUM immutable generation/raw signed pair、stable channel object 与 gated
  metadata、public mutable asset 与 gated asset；两类 asset 都必须进入 plan/verify/exact
  purge closure。token A 穿 cf/cos 对四个 repo 跑 L2/L3/L4 并同时得到 apt/dnf 客户端
  证据，token B 对同一四 repo 独立跑 L3。两端动态 stable mirrorlist 必须只注入当前 token
  并精确钉到 generation 4，匿名
  stable mirrorlist 为 edge 404；
- 对 gated asset，匿名公开 URL 与 exact
  `/.sow/gated/...` clean URL 都必须由版本化 edge 合同返回 404，两枚不同 token
  必须返回同一代字节；夹具在 token B 的任何请求前先以 token A 访问该 gated key，随后
  token B 必须命中相同 key。`X-SOW-Clean-URL-SHA256` 必须是 64 位小写十六进制，且逐端
  等于夹具对 exact `https://<vendor-host>/.sow/gated/assets/real-cloud-gated/secret.txt`
  重新计算的 SHA-256，而不只是两响应彼此相等；token B 的
  `X-SOW-Origin-Cache-Status` 必须为 `HIT`。`X-SOW-Origin-Transport` 必须是
  `https-bearer`；首请求 cache status 只接受明确的 `HIT/MISS/EXPIRED/STALE/UPDATING/REVALIDATED`
  allowlist，空值、未知值、`BYPASS` 与 `DYNAMIC` 均失败，所以 direct R2/COS 不会被误计
  通过；GET、HEAD、
  `Range: bytes=0-2`、private no-store、`206 Content-Range` 与响应凭据剥离全部必须成立；
  token A/B 已把 shared clean cache 暖起后，夹具会再次请求匿名 public 与 exact clean
  URL，两者仍必须由 edge contract 返回 404，防止“鉴权后缓存填充”绕过机密性闭包；
- generation 4/5 各自在至少两个独立代理 endpoint 上采集 Cloudflare 与 EdgeOne 主动请求；
  每端只能有一个 token-A prime，其余 token-B cross-pop 必须为 `HIT`，且两代保持同一 clean
  URL 摘要、推进 generation/transaction/body/published-at。active artifact 必须通过仓库外
  路径、`0600`、inode/body identity lock、atomic replace、fsync、无 URL/secret/protected-path
  扫描，并在四个 generation/vendor 记录完成后以 run-bound SHA/size seal 封口。generation 5
  还必须保存同 observer 的 pre-purge fresh HIT、Age/max-age 与剩余 TTL。该代发布前必须先让
  独立 watcher 持有 liveness lock 并持久化 exact armed receipt；父进程 SIGKILL 后 watcher 仍
  通过原 observer/proxy 路径在各自 `fresh_until` 前保存 generation/transaction/request/time/
  cache/body/clean-URL 的 HMAC-bound vendor evidence 与 durable completion seal，恢复只在二者
  同时有效时把它并入 active artifact。这一层仍
  只叫 active observation，不叫 provider-confirmed multi-PoP；
- 后置只读验收必须把 active request ID 与 collector-normalized provider joined logs 一一绑定。
  Cloudflare 每个 observer 需要不同 `EdgeColoCode`/`EdgeColoID` 且 `node_ip` 为空；EdgeOne
  需要不同 ISO country、公开 `EdgeServerIP` 与 `EdgeServerID`，三项缺一不可。active/provider
  两个 artifact 都必须有匹配 run ID 的完成 seal；provider export 必须精确覆盖所有 stage 与
  pre-purge parent，不能有额外/未知记录、复用 child/parent ID 或 parent-child 碰撞。两家每代的
  cache status、generation、transaction、clean/body digest 和因果时间窗必须一致；缺任一日志
  或日志仍在异步投递时结果只能是失败/未完成，不能把 active artifact 单独升级为 POC-01；
- generation 5 的第一次 cf 发布使用确定无权 purge token，必须在远端 locked checkpoint
  与本地 journal 中停于 `pointer-flipped`；journal 的 generation/transaction 必须与远端
  locked checkpoint 一致，并绑定 generation 4 parent checkpoint 摘要。失败后本地 canonical
  generation/checkpoint/plan 三份逐字节仍是 generation 4；恢复原
  credential 后以同一 transaction ID 继续，不能另起 generation 或跳过 purge/read-back。
  失败窗口还必须留下与 journal generation/plan/checkpoint SHA 一致、但无伪造 completed batch
  的 purge sidecar；恢复成功后 canonical purge evidence 的最新 full attempt 必须逐批完成；
  cos 随后独立完成 generation 5；
- 第一代 gated cache 已被访问后，恢复完成的第二代 exact-URL publication purge 必须使 token 路径立即
  返回新字节，随后另一 token 仍命中同一 clean key。测试日志只记录 vendor、规范化
  cache status、clean URL SHA-256 与 ETag，供 provider cache/purge audit log 对账；
- generation 6 对 COS 重复同一故障协议：无效 EdgeOne signing identity 只能让事务停在
  `pointer-flipped`，不能阻止 COS storage 安装 generation/pointer，也不能推进本地 committed
  state。远端 locked checkpoint、generation、gated 字节和 journal 必须绑定 generation 5
  parent；恢复原 identity 后同 transaction 提交。cf 在此期间严格保持 generation 5，再独立
  发布到 generation 6；双方随后必须返回第三代 gated 字节；
- 第三代不可变 YUM repomd/signature 与 raw compatibility pair 逐字节一致，static
  mirrorlist 与 mutable asset 均进入最小 purge/read-back；双方完整 inventory 同时保留
  YUM generation 1 与 3，证明更新没有暗删旧代；
- generation 7 只发布一个显式请求、已经过期的 YUM snapshot；plan 中 package
  （其历史 ref 由上述本地受控 fixture 从 CLI 创建的今日 immutable ref 复制，未伪报为
  当日可 backdate 的 promote）；plan 中 package
  `ObjectCopyImmutable.CopySource` 必须指向同桶 stable 所引用的 public package，证明 R2/COS 都走
  server-side CopyObject 而非重新上传包体；同源参数的 SOW-owned provider copy probe 还必须
  连续两次 HEAD+streamed GET 证明相同 size/digest/ETag，再以 run-bound identity cleanup 删除并
  HEAD absent。snapshot route 与 package 在双方 inventory 均存在；
- generation 8 发布近期 snapshot 时，先由 cf、再由 cos 分别执行生产 conditional-delete
  capability probe；支持条件删除的端点使用 matching-ETag DELETE，不支持的端点必须由生成配置
  显式选择 ADR-0036 checkpoint-fenced fallback。每份 plan 必须只含 `snapshot-owned` 删除、
  绑定旧 route/package digest、旧 route exact purge/404 与至少一个 retained positive probe；
  每个事务只有在 DELETE 后 HEAD absent 才能提交。cf 完成而 cos 尚未执行时，仅 cos
  inventory 仍保留旧 snapshot；双方完成后旧 route/payload 均消失，近期 snapshot 仍可用
  token A 跑双云 YUM L2/L3/L4；提交后独立 provider HEAD 还必须确认全部 delete key 与
  transaction-scoped capability probe key 均 absent；
- latest generation 3 的双目标无变化 publish 是 `ref-vector` no-op；近期 snapshot
  generation 8 的双目标重放也明确为 `status=unchanged`。两者均不改
  generation/checkpoint/plan，也不重复 DELETE；
- 从 historical stable generation 4 恢复时，cf/cos 各自以前向 generation 9 提交，parent
  固定为 8，gated planned-object SHA 必须回到 generation 4 的第一代摘要；cf 先恢复时 cos
  仍返回第三代字节，随后 cos 独立恢复。exact restore replay 不做 provider side effect；普通
  stable publish 再把双方推进到 generation 10 和第三代字节，证明恢复无需 checkpoint 倒退、
  手工解锁或跳过 purge/read-back；
- 最终四个 repo、双目标的全量 ListObjects `fsck` clean。

这份夹具只把真实验证推进到“资源一旦注入即可复现”的状态；在有真实运行日志之前，
不得把 R2/COS/Cloudflare/EdgeOne PoC 记为已通过。
