# 2026-07-19 真实 R2 remote fsck 最小权限证据

## 结论

`sow fsck --target` 现在为 Cloudflare R2 与 Tencent COS 构造各自的对象审计客户端，
只解析所选 target 的 storage credential。它不解析 CDN credential，也不构造
Cloudflare purge 或 EdgeOne SDK client；storage-only client 不能转换成 publisher。
发布、发布后 CDN 验证与 purge 仍走原来的完整 provider client，不因本次改动降级。

当前源码在 owner 授权、编译期 registry 精确固定的非生产 Cloudflare `pro` 空桶完成了
真实 CLI 闭环：本地 asset 仓库初始化后上传一份相同对象和一份 run lease，首次
`fsck --adopt-remote-inventory` 对全部两对象执行双 List、HEAD 与 bounded streamed GET，
报告 `local_expected=1`、`retained_extra=1` 并提交 complete inventory；第二次重放
`changed=false`。随后用原 ETag CAS 写入本次登记的漂移正文，CLI 以 verification exit
拒绝且 canonical Git HEAD 不变；再用漂移 ETag 精确恢复原正文后，重放仍
`changed=false`。身份绑定 cleanup 和退出后的独立 `rclone` 清单都证明 bucket 为空。

这不是 Cloudflare Worker、Zone、purge、CDN negative verify、COS/EdgeOne 或完整
POC-06 证据，也没有访问或写入任何 CO/COS/Cloudflare 生产仓库。

## 固定资源与安全门

```text
account_id = 72cdbd1b54f7add44ecbd3d986399481
r2_endpoint = https://72cdbd1b54f7add44ecbd3d986399481.r2.cloudflarestorage.com
bucket = pro
run_id = sow-r2-fsck-20260719-02
remote_prefix = acceptance/r2-fsck/sow-r2-fsck-20260719-02/
```

联网前依次要求：exact provider-readiness registry、全局非生产确认、endpoint+bucket
精确绑定确认、route-safe run ID、合法 storage secret，以及首次 ListObjectsV2 必须为空。
Cloudflare CDN 环境变量在测试内显式清空。测试对象仅有 lease 与 payload 两个 exact key；
cleanup 只接受登记过的 size/SHA-256 正文身份，payload 删除前后重验 lease，删除后再 HEAD
确认 absent。所有 CLI 输出、错误和本地 artifact 都经过 storage secret fragment 扫描。

第一轮真实运行还覆盖了本地失败恢复：macOS `t.TempDir()` 的 `/var` symlink 路径被
Nginx-worker traversability 门禁拒绝后，独立超时 cleanup 仍删除两个 run-owned 对象，
随后的 `rclone` 清单为空。夹具随后改为 macOS 的真实 `/private/tmp` 目录，Linux 回退
`/tmp`；这个失败没有放宽产品检查。

## 实跑命令

storage credential 由本机已有 `rclone cf:` 配置在同一 shell 内组装为严格、env-only
JSON；值没有写入文件或 stdout。CDN credential 明确为空：

```bash
SOW_RUN_REAL_CLOUD_R2_FSCK=1 \
SOW_REAL_CLOUD_NONPRODUCTION_CONFIRM='I-CONFIRM-DEDICATED-DISPOSABLE-NON-PRODUCTION-SOW-TEST-RESOURCES' \
SOW_REAL_CLOUD_PROVIDER_READINESS_RESOURCE_JSON='<exact registry resource JSON>' \
SOW_REAL_CLOUD_R2_FSCK_CONFIRM='I-CONFIRM-MUTATING-ONLY-THE-PINNED-EMPTY-R2-BUCKET-FOR-FSCK:https://72cdbd1b54f7add44ecbd3d986399481.r2.cloudflarestorage.com/pro' \
SOW_REAL_CLOUD_RUN_ID='sow-r2-fsck-20260719-02' \
SOW_REAL_CF_STORAGE_JSON='<strict env-only credential JSON>' \
SOW_REAL_CF_CDN_JSON='' \
go test ./test/compat -run '^TestRealCloudR2FSCKStorageOnly$' -count=1 -v -timeout 5m
```

原始终端结果：

```text
=== RUN   TestRealCloudR2FSCKStorageOnly
real R2 fsck PASS run=sow-r2-fsck-20260719-02 adoption=true replay=true drift_rejected=true cas_restore=true cdn_credentials=false control_plane=false custom_domain=false empty_before=true empty_after=true
--- PASS: TestRealCloudR2FSCKStorageOnly (29.09s)
PASS
ok github.com/pgsty/sow/test/compat 29.600s
```

退出后独立验证：

```bash
rclone lsf cf:pro --recursive --max-depth -1
```

退出码 `0`、stdout 为空。

## 2026-07-22 current-source revalidation

Commit `9b481e994265d7b9e623c08a4014cadf8e233bb7` reran the same storage-only
authority gate as `sow-r2-fsck-20260722-020600`. The credential was reconstructed
only inside the shell from the existing `rclone cf:` reference and the CDN
credential remained explicitly empty. The test passed in 29.18s (package
29.891s):

```text
real R2 fsck PASS run=sow-r2-fsck-20260722-020600 adoption=true replay=true drift_rejected=true cas_restore=true cdn_credentials=false control_plane=false custom_domain=false empty_before=true empty_after=true
```

The independent recursive `rclone lsf cf:pro` check returned zero objects. No
other bucket, Cloudflare control plane, CO/COS or production repository was
contacted.

## 2026-07-29 current-source revalidation

The clean `26f29c0` tree reran the storage-only authority gate as
`sow-r2-fsck-20260729-150400`. The storage credential existed only in the test
process environment and the CDN credential remained explicitly absent. The
test passed in `36.22s` (package `37.468s`):

```text
real R2 fsck PASS run=sow-r2-fsck-20260729-150400 adoption=true replay=true drift_rejected=true cas_restore=true cdn_credentials=false control_plane=false custom_domain=false empty_before=true empty_after=true
```

The independent recursive `rclone lsf cf:pro` check again returned exit status
zero and no objects. No Cloudflare control-plane API, custom domain, other
bucket, CO/COS, or production repository was contacted.

## 本地/协议回归

以下门禁覆盖 R2/COS capability separation：

- `TestRemoteAuditTargetClientUsesOnlyStorageAuthority`：Cloudflare CDN secret 缺失、COS
  CDN secret 非法时，两个审计 client 均成功构造；完整 provider 字段为空，调用
  `publisher` 必须失败。
- `TestR2CloudflareControlHTTPNeedsNoCDNAuthority` 与
  `TestCOSControlHTTPNeedsNoEdgeOneAuthority`：真实 SigV4 HTTP 请求只到对象 endpoint。
- Cloudflare/COS CLI adoption 协议夹具在 CDN secret 空或非法时通过；只有中间真实
  `publish` 步骤临时恢复 loopback CDN secret。
- focused ordinary：`internal/publish` `0.568s`、`internal/cli` `28.777s` PASS；focused
  race：`1.620s`/`48.808s` PASS，无 race report。

当前源码的穷尽回归也已闭合：692 个 default CLI test 按 CI 同构六片执行，ordinary
六片为 `564.466/803.168/266.302/911.841/586.986/224.924s`，race 六片为
`602.029/874.101/273.778/1066.818/634.175/267.205s`，全部 PASS 且没有 race report；
全部 non-CLI package 的 ordinary/race 也通过，最长分别为 `28.328s` 与 `33.032s`。
`go vet` 两个 profile、项目 Staticcheck profile、两个 module 的 tidy/verify、嵌套 RPM
module test/vet/provenance 和 `govulncheck@v1.6.0` 均通过；主模块没有可达漏洞，嵌套
module 没有已知漏洞。四个 `CGO_ENABLED=0` build 均成功：

```text
linux/amd64  145ebd2de9b0f2961b3953808555b91ba0c0f0e2bdf922e648b75daae9db348e
linux/arm64  7a7f51c1aebfec23c702bd2c5190982b730f91eda59e75f66355c52f836d071c
darwin/amd64 75f9f6a32c81584e57454f1e895f8db9d352dbf4a7afc98f288f43a97b620397
darwin/arm64 017e0482fd1785788c9fa5546e2921cd0e25911fdb9568f1c9e93d31551c8226
```

当前真实客户端 Docker/Nginx 矩阵 package `95.042s` PASS，真实消费 apt 1.2.35/2.4、
CentOS 7 YUM 3.4.3 与 EL8/9/10 DNF；全部 repo URL 仅指临时 loopback，所有外部 repo
关闭，云 opt-in 关闭。最终 product/delivery/archive identity 不嵌入本交付根以避免
摘要自引用；本报告冻结后的双重 clean reconstruction 只记入外部 V-35 账本。

## 状态边界

- FR-06：真实 R2 的显式全量 remote fsck 已验证；COS 真供应商仍未执行。
- FR-30：真实 R2 首次 manifest 子集对账、全 inventory baseline、漂移拒绝与恢复已验证；
  已发布 generation 的真双云 L2 与 COS 仍未执行。
- MIG-01：`init`→首次 Cloudflare R2 fsck 与 retained-extra 报告已验证；真实 COS 和生产
  存量切换仍未验证。
- NFR-06/NFR-08：证明 remote fsck 不需要 CDN secret、输出不泄密且真实漂移不改 Git；
  不替代两家真实 CDN cache/log、Worker/EdgeOne 或生产运维证据。
