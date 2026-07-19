# 2026-07-17 真实云安全入口本地证据

状态：本地合同通过；未连接 Cloudflare、R2、COS 或 EdgeOne，未写任何云资源，POC-01/POC-06
仍未通过。

本轮关闭三个本地缺口：

- provider raw-log sink 不再能在 durable acceptance ledger 与 provider-scoped reservation 之前
  被修改；fresh/recover 都由第一步的精确 receipt 约束，completed ledger 禁止再配置；
- 完整双云的两个空 registry 不再依赖手工拼 JSON。离线 onboarding helper 对 canonical
  resource/deployment 做生产隔离、排序、去重、稳定 identity 与双 registry 自校验，只在仓库外
  写候选和 digest receipt；
- provider readiness 可按 `cloudflare` 或 `edgeone` 独立运行，只加载所选供应商的 storage/API
  credential，做只读空桶 ListObjectsV2 与 zone/domain identity 查询并写 URL-free、secret-free
  receipt + seal。它现在使用第三个独立、SHA-pinned、单供应商 readiness registry，不再要求
  另一供应商或尚未创建的 deployment identity。

owner 后续将 bucket `pro` 与 `pro.pigsty.io` namespace 指定为测试资源；distinct beta
按现有通道合同冻结为 `https://beta.pro.pigsty.io`。[ADR-0032](../adr/0032-owner-designated-cloudflare-test-resource-exception.md)
只允许三者 exact tuple 进入离线 readiness registry 评审；任一子集、变体、其他 Pigsty DNS 名称、
生产仓库和 CO/COS 生产资源仍由结构门禁拒绝。readiness registry 当前为空，仍会在
credential/client/request 前拒绝联网；完整 mutation/POC 还要另行命中双云 resource 与
provider-deployment registries。

后续 [Cloudflare `pro` 外部只读盘点](2026-07-17-cloudflare-pro-readonly-inventory.md)
已确认 account ID、空桶/public access 与主 host Cloudflare 404，并确认 beta host
尚无 DNS；该观察没有使用 CLI/API credential、没有云写入，也没有升级本报告的
本地合同状态。

实际执行：

```text
go test ./test/compat -run 'RealCloudRegistry|RealCloudDedicatedTestResourceGate|RealCloudProviderDeploymentRegistryIsIndependentAndStable' -count=1
ok github.com/pgsty/sow/test/compat 1.208s

go test ./test/compat -run 'RealCloudProviderReadiness|RealCloudRegistry' -count=1
ok github.com/pgsty/sow/test/compat 0.382s

严格清空云凭据并关闭全部联网 opt-in 后：
go test ./test/compat -run 'RealCloud' -count=1
ok github.com/pgsty/sow/test/compat 7.565s

go test -race ./test/compat -run 'RealCloud' -count=1
ok github.com/pgsty/sow/test/compat 12.918s
```

以上仅证明离线生成、进程级 fail-closed、安全选择器、私有文件写入与回执封口。当前三个编译期
registry 均为空，没有真实 provider receipt，不能将真实云验收状态升级。

随后发现并修复原 readiness 入口的循环依赖：它虽选择单供应商，`TestMain` 却仍要求完整双云
resource 与 provider-deployment registry，导致 Cloudflare 预检被无关 COS/EdgeOne 和后续部署身份
阻塞。[ADR-0033](../adr/0033-provider-scoped-readiness-registry.md) 增加单供应商、canonical、编译期
SHA-pinned 的独立 readiness registry。process-gate 负例证明 readiness 分支不会调用完整双云或
deployment validator；destructive 与 evidence 分支仍调用原有两道门。EdgeOne 只读控制面还逐字
比较 live zone name 与 pinned identity，错误名称在 domain inventory 通过前失败。聚焦 ordinary/race
为 1.124s/2.043s；四个联网 opt-in 与两个 onboarding opt-in 全部显式设为 `0` 的完整 `RealCloud`
ordinary/race 为 9.584s/13.651s。没有读取云凭据、构造真实 provider client 或发起网络请求。

后续一致性审计又关闭 Cloudflare domain 归属缺口：readiness 不再只读 Zone 后相信配置中的 URL，
而是调用官方只读 R2 custom-domain list API，要求 `pro` 桶 inventory 恰好为 main+beta，且两项
enabled、ownership/SSL active、zone ID/name 精确命中 pinned identity。缺 beta、额外/重复 host、
disabled、pending、zone drift 与未知 TLS policy 全部失败；响应顺序与 cipher 顺序正规化后进入
provider-control digest。官方 SDK 的 exact GET path/Authorization 由 loopback 合同覆盖。新增后的
focused ordinary/race 为 2.069s/1.960s，完整离线 `RealCloud` ordinary/race 为
9.050s/12.296s；`go vet ./...`、clean-delivery policy 与 `git diff --check` 通过。没有读取真实凭据、
构造真实 provider client 或发起真实请求。

owner-designated tuple 合同在四个联网 opt-in 均显式设为 `0` 时追加实跑：focused
ordinary/race 分别为 1.298s/1.881s；完整 `RealCloud` ordinary/race 为
9.498s/13.478s。覆盖 tuple-only 正例、任一子集/变体负例、其他 Pigsty host 负例、
shared-zone/zone drift、empty-registry 拒绝、离线 candidate 接受及全部既有 fail-closed/recovery 合同；
没有读取云凭据或发起请求。

共享 Zone 的 Worker route inventory 不再要求整区恰好只有两条 route：精确 main/beta
auth route 仍必须各一条，其他 route 只有在按 Cloudflare 官方 leading-host/trailing-path wildcard
规则证明不可能命中两个 reviewed host 时才允许；任一 exact/wildcard/path-specific/negating/
malformed overlap 或 auth Worker 额外暴露均 fail closed。聚焦 ordinary/race SDK collector
为 1.132s/2.211s；无关 route 正例与覆盖 `.sow/*` 负例均通过，仍无网络请求。

共享 Zone 的 Logpush inventory 同样按相关闭包审计，而不再假设整区只有一个 job：配置中钉住的
SOW job 仍必须唯一、启用、100% `http_requests`、精确过滤 main+beta 并写入专用 raw-log bucket；
其他禁用 job 可共存。其他启用 job 只有在不复用 SOW raw bucket，且其 `http_requests` filter
可证明排除两个 reviewed host 时才允许。未知、畸形或不支持的 filter 均按“可能重叠”失败关闭。
新增无关 job 正例、reviewed-host 重叠负例和 raw-bucket 复用负例后，focused ordinary/race 为
1.338s/2.307s；四个联网 opt-in 全部显式关闭的完整 `RealCloud` ordinary/race 为
7.549s/11.065s。全过程未加载凭据、未构造真实云客户端、未发起网络请求。

Cloudflare first-deployment bootstrap 随后的怀疑式审计关闭了跨 run 接管、并发 executor、
absent→upload 覆盖、outcome envelope 崩溃窗、nested compatibility 逃逸、verifier settings 缺口与
trailing-dot production-domain 绕过。apply 现在必须消费同 run 的 fresh readiness receipt；所有权与
动态授权绑定 mode/run/plan/account/zone；auth/origin create 使用 `If-None-Match: *`；R2 上只写一个
`.sow/bootstrap/leases/<readiness-resource-sha>.json` CAS 租约并在 durable receipt 后 CAS 退役为
idle marker；同资源 plan 轮换继续复用该 key，过期租约有单独授权且绑定旧/新 plan 的
`recover-lease`。完整 closure 与 settings/exposure 都要求连续两次观察一致。readiness receipt/seal
各自从完整 inode 做 no-replace 发布，receipt-only 中断可精确续写，seal-only/漂移则失败关闭。详细代码面、
普通/竞态/CLI 六分片实测及尚缺 live POC 见
[Cloudflare bootstrap 离线安全验证](2026-07-17-cloudflare-bootstrap-offline-validation.md)。本轮仍未读取
凭据或触云，registry 仍为空，POC-06 状态不变。

bootstrap 之后的 provider attestation 怀疑式审计又升级到 v3：auth/origin/verifier 的精确
compatibility date/flags、active runtime/settings/schedules/exposure、完整 Worker/route/domain inventory
均连续双读并进入摘要；custom domain 强制 TLS 1.2+ 与冻结 Modern cipher 集，EdgeOne realtime-log
的不可变 `Area` 也必须精确命中配置并进入 deployment/task/raw-ledger 摘要。双供应商 Logpush/
realtime-log setup 在 mutation 前使用独立 `SOW_REAL_CF_LOG_CONTROL_JSON` 身份取得 R2 CAS lease，
部分失败保留租约，write-only exporter credential 不被扩权。ordinary/race 与官方 SDK loopback
结果见 [provider attestation 离线验证](2026-07-17-cloudflare-provider-attestation-offline-validation.md)
和 [ADR-0035](../adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md)；未触云，POC-06 不变。
