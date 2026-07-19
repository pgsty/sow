# 2026-07-17 Cloudflare bootstrap 离线安全验证

状态：本地实现与协议合同通过；真实 Cloudflare/R2 bootstrap **未执行**，POC-06 仍未通过。
本轮所有真实云、onboarding 与 evidence opt-in 均显式设为 `0`，没有读取云凭据、构造真实供应商
客户端或写入 `pro`。CO/COS/Cloudflare 生产仓库始终不在测试范围。

## 已关闭的安全缺口

- readiness `.seal` 已从可由本地攻击者重算的 SHA/size envelope 升级为当前 Ed25519 v3：
  私钥 seed 只从环境注入，bootstrap plan/registry 钉住公钥。定向负例证明 receipt 篡改后
  重算 SHA/size，以及用攻击者自有密钥重签，均在读取云凭据前失败关闭。
- apply 必须消费同一 run、15 分钟内、证明精确 R2 空桶及 main/beta custom-domain active 的
  readiness receipt；固定确认短语替换为绑定 mode/run/plan/account/zone 的动态授权。
- auth/origin Worker annotation 同时绑定 plan 与 run；新 Worker 通过官方 SDK 发送
  `If-None-Match: *`，不同 run 不能接管已存在脚本。
- 每次 apply/rollback 先在指定测试桶的 `.sow/bootstrap/leases/<readiness-resource-sha>.json`
  取得 create-only/CAS 租约；每个控制面 mutation 前续租，durable outcome receipt 后把 exact
  live ETag CAS 为 canonical idle marker，不调用 DeleteObject。plan/signer/bundle 轮换仍复用同一
  资源 key；live holder 阻塞，历史 idle才可接管。expired live 只能由 `recover-lease` 先 CAS 为
  owning pending v1；canonical recovery receipt v3 完整落盘并重新读取后，pending 才可 CAS 为
  同时绑定 pending/receipt digest 的 recovery idle v3。live v3 将完成 pair 追加到所有后继状态
  保留的 canonical lineage；任一中断点仅允许 exact run/plan重放。
- readiness 与 bootstrap 之间不再只靠时效窗口：取得租约后以及每次 mutation 前续租后，必须
  完整消费 bounded `ListObjectsV2`，证明桶内唯一对象就是当前 size/ETag 的租约，再以 GET 比对
  canonical lease bytes。同时重新读取 exact zone 与 active main/beta R2 custom-domain/TLS 闭包，
  digest 必须仍等于 readiness receipt；外来对象、缺失/替换租约、分页循环或 provider-control
  漂移都会在 Worker/route 内层写入调用次数为 0 时失败关闭。
- final closure 连续执行两次完整 Worker/route/custom-domain/attachment inventory；两次 closure
  digest 必须相同。Worker settings 与 workers.dev/preview exposure 也连续读取两次，并由 active
  deployment recheck 固定内容观察窗口。
- verifier 不再只验内容与 binding：compatibility date/flags、usage model、limits、placement、
  Logpush、observability、tail consumer、tags 与公开 exposure 全部 fail closed。
- rollback 在删除 route 前按 ID 重新读取 exact pattern/script；删除 Worker 前重新验证
  deployment/version/ETag/content/binding/ownership。Cloudflare 没有文档化的 conditional route/
  script delete，因此只声明“租约串行 SOW executor + 删除前外部漂移复核”，不伪报不存在的 CAS。
- bootstrap outcome receipt 改为一次 `O_EXCL + fsync` 写入的 canonical envelope，消除 receipt 与
  `.seal` 双文件之间的崩溃窗口；读取使用 Lstat/Open/Fstat same-inode 与 bounded exact read。
- `SOW_COMPATIBILITY_ADMISSION` 改用 `internal/config` 的共享语义验证器：nested YUM channel、
  projection、snapshot、raw/active subset、路径、排序、去重与 canonical JSON 都会验证，不再把
  nested JSON 当 opaque bytes。
- CDN safety gate 显式拒绝 trailing-dot hostname，并在 production-domain 判断前正规化 host，
  `beta.pro.pigsty.io.` 不能绕过生产域拦截。
- 官方 SDK loopback 覆盖 auth/origin 两种 multipart upload、create-only header、精确 binding、
  route POST/GET/DELETE、verifier settings/runtime 与 repeated observations。

## 实际执行结果

```text
focused ordinary:
go test ./internal/config ./test/compat -run 'TestValidateEdgeCompatibility|TestRealCloudCloudflareBootstrap|TestRealCloudProviderOptIn|TestRealCloudDedicatedTestResources' -count=1
ok github.com/pgsty/sow/internal/config 1.049s
ok github.com/pgsty/sow/test/compat 0.955s

focused race:
go test -race ./internal/config ./test/compat -run 'TestValidateEdgeCompatibility|TestRealCloudCloudflareBootstrap|TestRealCloudProviderOptIn|TestRealCloudDedicatedTestResources' -count=1
ok github.com/pgsty/sow/internal/config 1.592s
ok github.com/pgsty/sow/test/compat 2.185s

complete compat race, all real-cloud opt-ins forced to 0:
go test -race -timeout 20m -count=1 ./test/compat
ok github.com/pgsty/sow/test/compat 12.519s

go vet ./...
PASS
```

完整 `go test ./...` 的非 CLI 包全部通过；`internal/cli` 有 657 个集成测试，整包串行超过 Go
默认 10 分钟并产生 package-level timeout，不是断言失败。按仓库 CI 的六分片门禁复跑结果：

```text
^Test[A-F]                         355.027s PASS
^Test[G-M]                         656.788s PASS
^Test[N-O]                         163.414s PASS
^Test[P-Q]                         688.946s PASS
^Test[R-V]                         389.770s PASS
^Test([W-Z]|[^A-Z]|$)               66.651s PASS
```

结论：CLI 6/6 分片通过、其他 Go 包通过、compat race 与 vet 通过。默认整包 10 分钟命令不再作为
可判定门禁；CI 已固定 CLI 分片每组 15 分钟。

## 仍需真实环境完成

仓库内 provider-readiness registry 已只钉住 owner-designated `pro` tuple；bootstrap registry
仍故意为空，因此 live mutation entrypoint 会在 credential/client/request 前拒绝。升级 POC-06
至通过至少还需要：生成独立 readiness Ed25519 keypair，把公钥连同 bootstrap plan 一并评审钉住；
用专用最小权限 storage/API credential 与环境注入的 signer seed 生成 fresh readiness receipt；执行一次
apply、真实 main/beta 请求与 provider attestation；执行 rollback 并证明租约、routes、auth/origin
全部消失且 verifier 未变。任何一步不得使用 CO/CF 生产仓库。

部署后的长期 runtime/inventory 观察、custom-domain TLS policy 与 provider-log setup lease 不属于
本 bootstrap receipt；其独立合同和离线结果见
[ADR-0035](../adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md) 与
[provider attestation 离线验证](2026-07-17-cloudflare-provider-attestation-offline-validation.md)。

## 2026-07-19 readiness seal 与中断恢复 follow-up

安全审计发现原 `sow-real-cloud-provider-readiness-seal/v1` 只包含 receipt SHA-256 与
size，本地攻击者可在篡改 receipt 后重算整个 envelope。当前实现已废弃 v1：

- 当前 seal v3 使用 Ed25519 对 `schema + newline + exact canonical receipt bytes` 签名；
- signer seed 只接受环境变量中的严格 lower-hex 32-byte seed，不进入文件或日志；
- bootstrap plan/descriptor 升级为 v2并包含 signer 公钥，plan SHA 再由独立 registry 钉住；
- validator 不信任 seal 自报密钥，只接受 plan 公钥，并在 provider credential 读取前验签；
- key rotation 必须产生新的 plan SHA 与管理员评审的 registry entry，但不产生第二个 R2 lease key；
- receipt 与 `.seal` 的 final path 都从已完整 write/sync 的 inode 以 no-replace 方式发布；若只完成
  receipt，下一次匹配观察对原字节补 seal，seal-only、symlink、stale 或 divergent 半对失败关闭。

本地门禁实跑结果：聚焦 ordinary `0.921s`、race `2.087s`，完整 compat ordinary
`8.691s`、race `11.986s`，`go vet ./test/compat` 与 `git diff --check` 通过。负例精确覆盖
receipt 篡改后重算 SHA/size、攻击者用另一 Ed25519 key 重签、malformed signer seed、错误
plan key 与缺失 readiness。所有 real-cloud opt-in 均关闭；没有读取凭据或访问任何云资源。
