# 2026-07-17 Cloudflare provider attestation 离线验证

状态：官方 SDK loopback、R2 CAS fake-store、ordinary/race 均通过；真实
Cloudflare/R2、COS/EdgeOne 未执行，POC-06 仍为受阻。没有读取云凭据，也没有写入
`pro` 或任何 CO/COS/Cloudflare 生产资源。

## 本轮闭包

- provider config/deployment identity 升级为 v3，逐 auth/origin/verifier 钉住
  compatibility date 与 canonical flags。
- active version、settings、schedule、workers.dev/preview 连续双读；usage model、limits、
  placement、cache、Logpush、observability、tags、tail consumers 全部 fail closed。
- raw attestation v3 新增三类 Worker security digest、完整 inventory digest 与独立 log-control
  identity；控制摘要包含 runtime/compatibility，不再只含代码和 bindings。
- EdgeOne realtime-log 的不可变 `Area` 被限制为 `mainland|overseas`，并同时绑定到配置、
  deployment identity、task digest、raw attestation 与 acceptance ledger；缺失、未知或 live
  task 不一致均失败关闭。
- account Worker、embedded route、zone route、custom domain 全量 canonical inventory 连续两次
  必须相同；缺 service/certificate/zone 的 domain、跨读取变化和 schedule/tail 负例均拒绝。
- Logpush 按配置 ID 选择；可证明不覆盖 reviewed hosts/raw bucket 的无关 job 可以共存。
- 双云日志 exporter 更新前取得 R2 conditional lease；每次 mutation 前续租，成功后 exact-ETag
  删除，EdgeOne 注入失败后保留 lease。live conflict、renew、expired CAS takeover、stale holder
  release 均有回归。
- lease 使用新增的独立 `SOW_REAL_CF_LOG_CONTROL_JSON`，不扩大 write-only Logpush writer 权限。
- R2 main/beta custom domain 必须显式 TLS 1.2/1.3，并使用 Cloudflare Modern 的六个 TLS 1.2
  cipher；空策略、TLS 1.0/1.1、legacy/unknown/duplicate cipher 全部拒绝。官方依据：
  [R2 API 默认最低 TLS 1.0](https://developers.cloudflare.com/api/terraform/resources/r2/)；
  [Modern cipher 清单](https://developers.cloudflare.com/ssl/edge-certificates/additional-options/cipher-suites/recommendations/)。

## 实际执行

```text
go test ./test/compat -run 'TestRealCloudProviderCollectorUsesExactSDKAndSignedObjectContracts|TestRealCloudProviderLogSinkLease|TestRealCloudProviderAttestationConfigRequires|TestRealCloudCloudflareReadiness|TestRealCloudCloudflareBootstrapOfficialSDK' -count=1 -v
PASS
ok github.com/pgsty/sow/test/compat 1.796s

go test -race ./test/compat -run 'TestRealCloudProviderCollectorUsesExactSDKAndSignedObjectContracts|TestRealCloudProviderLogSinkLease|TestRealCloudProviderAttestationConfigRequires|TestRealCloudCloudflareReadiness|TestRealCloudCloudflareBootstrapOfficialSDK|TestRealCloudAcceptance' -count=1
ok github.com/pgsty/sow/test/compat 5.993s
```

后续加入独立 log-control identity、部分失败保留 lease 与 safe unrelated Logpush job 回归后又执行：

```text
go test ./test/compat -run 'TestRealCloudProviderCollectorUsesExactSDKAndSignedObjectContracts|TestRealCloudProviderLogSinkLease|TestRealCloudProviderAttestationConfigRequires|TestRealCloudAcceptance' -count=1
ok github.com/pgsty/sow/test/compat 3.518s
```

EdgeOne immutable-area binding 升级到 v3 后执行当前源码聚焦回归：

```text
go test ./test/compat -run 'TestRealCloudProviderCollectorUsesExactSDKAndSignedObjectContracts|TestRealCloudProviderAttestationConfigRequires|TestRealCloudProviderDeploymentRegistryIsIndependentAndStable|TestRealCloudAcceptance' -count=1
ok github.com/pgsty/sow/test/compat 3.225s

go test -race ./test/compat -run 'TestRealCloudProviderCollectorUsesExactSDKAndSignedObjectContracts|TestRealCloudProviderAttestationConfigRequires|TestRealCloudProviderDeploymentRegistryIsIndependentAndStable|TestRealCloudAcceptance' -count=1
ok github.com/pgsty/sow/test/compat 6.403s

env -i <HOME/PATH/TMPDIR/LANG plus every real-cloud/upstream/docker/legacy opt-in=0> go test ./test/compat -count=1
ok github.com/pgsty/sow/test/compat 10.548s

env -i <same sanitized environment> go test -race ./test/compat -count=1
ok github.com/pgsty/sow/test/compat 14.994s
```

## 真实环境剩余条件

live entrypoint 仍会因三个编译期 registry 为空而在联网前失败。真实 POC 还需：独立评审并
钉住 resource/bootstrap/provider-deployment entries；创建 active beta custom domain；配置本 ADR
冻结的 TLS/cipher；提供最小权限 API、publisher、raw reader、两个 exporter writer 与独立
R2 lease-control credential；随后运行 readiness、bootstrap、双云 publish/cache/purge/provider-log、
rollback。任何生产资源不得用于故障或验收测试。
