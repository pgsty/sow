# 2026-07-20 真实 R2 发布存储事务证据

## 结论

当前产品 CLI 已在 owner 授权、仓库 registry 精确钉住的非生产 Cloudflare `pro` 空桶
完成一轮真实 R2 发布事务。测试调用实际 `sow add`、`promote`、`publish` 与 `fsck`，而非
直接调用 saga 或内存 provider：首次发布写入当前 asset 指针、内容寻址归档、generation 和
`.sow/manifest.json` checkpoint；同一命令重放返回 `status=unchanged`，没有新增 PUT 或
purge。随后 full remote adoption 对 5 个对象完成两页 List、HEAD 与 streamed GET，报告
`local_expected=1`、`retained_extra=4`、`inventory_coverage=complete`；重放
`changed=false`，普通 full `fsck` 也通过。

测试再用已发布指针的原 ETag 执行 run-owned CAS 篡改。`sow fsck --target cf` 以
verification exit 拒绝，canonical Git HEAD 保持不变；使用篡改 ETag CAS 恢复精确原字节后，
full fsck 再次通过。最终 identity-bound cleanup 删除所有本次精确登记正文，测试内 List 和
退出后的独立 `rclone` 清单都证明 bucket 为空。

R2 对象数据面与 SigV4/TLS 是真实供应商路径；Cloudflare purge 请求在进程内被严格拦截，
只在 zone、Bearer 和唯一指针 URL 全部精确匹配时产生本地协议回执。发布后 CDN GET 指向
两个无端口 `.test` 配置根域，经测试传输改写到本地 TLS server，再由 storage-only 客户端
读取真实 R2 当前对象。测试没有请求 `pro.pigsty.io`、`beta.pro.pigsty.io`、Worker、Zone 或
真实 purge API，因此这是一份“真实 R2 存储 + 本地 CDN/control adapter”的混合事务证据，
不是 Cloudflare 控制面、CDN 或完整 POC-06 通过声明。没有访问或写入 CO/COS、Cloudflare
生产仓库或任何其他 bucket。

## 固定资源与安全门

```text
account_id = 72cdbd1b54f7add44ecbd3d986399481
r2_endpoint = https://72cdbd1b54f7add44ecbd3d986399481.r2.cloudflarestorage.com
bucket = pro
zone_id = da7b5a27e4f9ef6eaa1b00a89c2c77c2
successful_run_id = sow-r2-publication-20260720-06
remote_prefix = acceptance/r2-publication/sow-r2-publication-20260720-06/
local_main = https://r2-publication-main.test
local_beta = https://r2-publication-beta.test
```

首个写请求前依次要求：显式 opt-in、仓库内 SHA-pinned provider-readiness resource、全局
非生产确认、endpoint+bucket 精确确认、22–64 字节 route-safe run ID、严格 storage secret
JSON，以及真实 ListObjectsV2 证明桶为空。测试覆盖的网络闭集只有：

- 精确 `pro.<account>.r2.cloudflarestorage.com`：保留产品 AWS SigV4 与真实 TLS；
- 两个 `.test` CDN host：只允许 GET 受控 asset 指针或 content-addressed archive，内部转发
  到本地 TLS server；
- `api.cloudflare.com`：不建立 socket，只允许精确 zone 的单文件 purge request，返回带
  `CF-Ray` 的本地回执；
- 任意其他 host、未签名请求、lease 前写、非白名单 key、错误 zone/token/URL 全部在调用
  底层 transport 前失败。

Cloudflare API token 环境变量在测试内覆盖为非秘密、本地专用字符串，不读取调用 shell 中
可能存在的真实 token。真实 R2 transport 由标准 Go transport 独立 clone，显式禁用环境代理，
DialContext 只接受精确 R2 authority；URL host 与独立 `request.Host` 必须一致。首次 List 也走
同一受控直连路径。每个非 lease mutation 前都用独立 storage-only 客户端重验 lease body+ETag。

只有供应商明确返回 2xx 后，exact key、size 和 SHA-256 正文才进入 confirmed-success cleanup
allowlist；显式 412 和 ambiguous transport error 的离线负例均证明失败请求不会取得删除权。产品
阶段任何 DELETE 都失败关闭。每个对象删除前做两次 HEAD+streamed GET 身份证明并签发一次性
key/body/ETag capability，底层 transport 在真正 DELETE 前再次直读证明；非 lease 删除前后继续
重验 lease，lease 最后删除，每个 DELETE 后再 HEAD 证明 absent。五个远端 key 与两个 CDN GET
被独立期望集合绑定，事件账本验证 lock→archive/generation→pointer→purge→两个 GET→checkpoint
commit 偏序。输出、错误和本地 artifact 经过 storage secret fragment 扫描。

defer 只保证 Go 测试进程仍存活时的失败收尾。timeout、SIGKILL 或进程崩溃不会执行 defer，当前
ownership map 也不是持久化 crash-recovery ledger；本证据不声称测试 harness 能自动清理这类硬
终止。ambiguous PUT 不获删除权，若供应商实际提交但响应丢失，验收会保留对象并失败报告，而不
冒险删除相同正文的外来对象。产品 publication journal 的中断恢复由其他故障注入证据覆盖。

## 实跑命令

storage credential 从本机已有 `rclone cf:` 配置在同一 shell 内组装成严格 env-only JSON；
没有写入文件或 stdout。资源 JSON逐字取自仓库钉死 registry：

```bash
SOW_RUN_REAL_CLOUD_R2_PUBLICATION_STORAGE=1 \
SOW_REAL_CLOUD_NONPRODUCTION_CONFIRM='I-CONFIRM-DEDICATED-DISPOSABLE-NON-PRODUCTION-SOW-TEST-RESOURCES' \
SOW_REAL_CLOUD_PROVIDER_READINESS_RESOURCE_JSON='<exact registry resource JSON>' \
SOW_REAL_CLOUD_R2_PUBLICATION_STORAGE_CONFIRM='I-CONFIRM-MUTATING-ONLY-THE-PINNED-EMPTY-R2-BUCKET-FOR-PUBLICATION:https://72cdbd1b54f7add44ecbd3d986399481.r2.cloudflarestorage.com/pro' \
SOW_REAL_CLOUD_RUN_ID='sow-r2-publication-20260720-06' \
SOW_REAL_CF_STORAGE_JSON='<strict env-only credential JSON>' \
go test ./test/compat \
  -run '^TestRealCloudR2PublicationStorageTransaction$' \
  -count=1 -v -timeout 8m
```

原始终端结果：

```text
=== RUN   TestRealCloudR2PublicationStorageTransaction
real R2 publication storage transaction PASS run=sow-r2-publication-20260720-06 generation=1 puts=8 purge_adapter_calls=1 local_cdn_gets=2 drift_rejected=true cas_restore=true replay_unchanged=true remote_adoption=true full_fsck=true real_cf_control_plane=false real_custom_domain=false empty_before=true empty_after=true
--- PASS: TestRealCloudR2PublicationStorageTransaction (161.90s)
PASS
ok github.com/pgsty/sow/test/compat 162.380s
```

8 个真实 PUT 包含 lease、checkpoint 的锁定/提交 CAS、asset 指针、内容寻址归档、generation，
以及 drift/restore 两次 CAS。Cloudflare purge adapter 恰好调用 1 次，URL 是唯一当前指针；
两次本地 CDN GET 分别校验当前指针与 immutable archive。幂等 publish 没有增加 PUT/purge。

退出后独立验证：

```bash
rclone lsf cf:pro
```

退出码 `0`、stdout 为空。

## 失败路径与收尾证据

最终加固 run 前有三次测试自身收敛失败，均没有留下远端状态：

1. `...-01` 使用带随机端口且主/β相同的本地 URL，产品 schema 在 `add` 阶段拒绝
   `cdn.beta_base_url`；没有放宽“两个不同、无端口 HTTPS root”契约，defer 清理 lease 后
   独立 `rclone` 为空。
2. `...-02` 已完成真实 publish/adoption，但测试把 retained-extra 误写为 `1`；实际 5 个
   object 中只有当前指针属于 local expected，checkpoint、generation、archive 和 lease 共
   4 个 retained extra。测试断言失败后仍由精确身份 cleanup 收敛，独立清单为空；修正的是
   测试预期，不是产品行为。
3. `...-04` 在补入 lease 后空桶闭包和精确计数后完成真实 drift 检测，但测试错误要求内部
   `REMOTE_OBJECT_CHANGED` 码；CLI 的稳定外部契约实际是精确
   `remote-drift target=cf kind=changed path=<run-owned pointer>`、`changed=1` 汇总和 verification
   exit。测试绑定到这三个外部信号后通过；失败 run 的 defer 与独立清单同样证明桶为空。

`...-05` 曾在精确计数版通过；随后的双重对抗审查发现测试安全层仍可被环境代理、独立 Host、
预注册 ownership 和宽泛 DELETE 破坏，也未绑定两个 CDN key 与事务顺序。上述问题修复后以
`...-06` 重新执行真实供应商路径，因此 `...-06` 是当前权威结果，`...-05` 不再作为当前证据。

普通测试套件始终运行离线负例 `TestRealCloudR2PublicationNetworkBoundary`；真实用例默认
skip，只有上述完整门禁同时存在才可联网写入。

## 需求状态边界

- FR-04：真实产品 publisher 已完成 R2 checkpoint create/CAS/final readback 和 generation 1
  提交；COS checkpoint 与真双云仍未运行，条目总体不升级为全部已验证。
- FR-25/27/31：upload→flip→purge→verify 顺序由真实 R2 数据面加本地 purge/CDN adapter
  闭合；这不证明真实 Cloudflare purge、cache negative verify 或 EdgeOne。
- FR-28/NFR-09：同一 R2 generation 的物理 no-op replay 与 checkpoint CAS 已实跑；真实网络
  中断注入、双云部分失败和 COS 仍未闭合。
- FR-30/NFR-08：已发布 R2 generation/checkpoint 的 adoption、full fsck、正文漂移拒绝、
  Git 不变与 CAS 恢复已验证；真实 COS 和供应商运维报告仍开放。
- G6/MIG-01/POC-06：专用空 R2 的产品发布状态机得到新证据，但生产存量 cf/cos 漂移清零、
  真实 Cloudflare control/CDN、COS/EdgeOne 与生产迁移没有执行，状态保持未完成/受阻。
