# 远端 inventory 审计与零字节纳管证据（2026-07-12）

## 结论

`sow fsck --target <cf|cos> --adopt-remote-inventory` 已实现为显式、单目标、
持锁的远端基线事务。它在第一次 ListObjectsV2 与第二次 ListObjectsV2 之间对
每个对象执行 HEAD 和有长度上限的流式 GET，正文计算值是唯一的 SHA-256 依据；
已有 `sow-sha256` metadata 只作交叉校验，不能替代读取正文。HEAD 与 GET 的
ETag 必须同时非空且完全相等。只有两次 key/size/ETag 清单完全一致、本地所选服务树
是远端字节的精确子集、既有 canonical inventory 仍是远端子集，而且已知发布
generation/checkpoint/channel/plan 闭包一致时，才会用一次 canonical transaction
提交：

- `remotes/<target>/inventory.tsv`
- `remotes/<target>/inventory.coverage`（`complete`）
- `remotes/<target>/content.tsv`

远端额外对象会保留并逐项报告，不会自动删除，也不会变成 CAS/GC 根。失败时
canonical HEAD 不变。重复执行在桶和本地均未变化时为 `changed=false`。

普通 `publish` 和 L2 verify 均不调用 ListObjectsV2。只有显式远端 fsck 可以
全量 List；因此未纳管的首次 publish 将 coverage 记录为 `partial`，不会把未知
对象误判为可安全删除的 orphan。

## 已实跑的自动化证据

以下定向门禁已在本机实际通过：

```bash
go test -count=1 ./internal/cli \
  -run 'TestFSCKAdoptRemoteInventory|TestGCRemoteInventory' -v

go test -race -count=1 ./internal/cli \
  -run 'TestFSCKAdoptRemoteInventory|TestVerifyL2IsBoundedAndFSCK'

go vet ./internal/cli ./internal/publish
```

覆盖的生产路径和负例包括：

- R2 与 COS 的 SigV4 ListObjectsV2/HEAD/GET 协议路径；
- 两页 opaque continuation-token 分页，以及跨页严格排序；
- List 回包中危险 key、错误 document、错误截断状态的拒绝；
- adoption 必须显式指定唯一 target；
- 每个 listed object 均执行流式 GET+SHA-256，包括已有匹配 metadata 的对象；
- 同尺寸坏正文配伪造 `sow-sha256`、空 HEAD/GET ETag、HEAD/GET ETag 漂移均在
  canonical 提交前失败；取消的正文读取仍严格关闭 response body；
- 第二次 List 发生变化时退出 4，且 canonical HEAD 与 inventory 文件均不变；
- 本地对象远端缺失、同尺寸但内容变化时拒绝提交；
- 远端额外对象保留在完整 inventory，但不进入 source content baseline；
- 重复 adoption 幂等；
- adoption 后第一次 latest publish 不重新上传已纳管 payload，只写 generation 与
  checkpoint 控制对象；
- publish 与 L2 verify 的 List 调用计数保持为零；
- 完整 coverage 下 extra 为 orphan，partial coverage 下 extra 只能是 unknown；
- 遗留 checksum 零字节对象被单独报告；
- inventory digest 永不成为 CAS root；已实际存在于 CAS 的 adopted source digest
  仍受 GC 保护，尚未进入 CAS 的遗留远端字节不会被伪造成 missing CAS object。

在共享工作区的远端审计改动稳定点上，以下门禁曾全部通过：

```bash
go test -count=1 ./...
go test -race -count=1 ./internal/publish ./internal/cli
go vet ./...
```

后续并发开发合入后仍应重跑同一组全量门禁；本文件只记录命令实际执行时的代码
状态，不把并发未完成的改动自动视为已验证。

## 协议边界

测试 transport 运行真实的 SOW HTTP 客户端、URL 构造、SigV4、分页解析、HEAD、
流式 GET 和 provider 方言，但它是进程内协议服务，不是 Cloudflare R2 或腾讯云
COS 的真实账号。因此上述结果证明实现合同和故障语义，不能替代真实云 PoC。

真实云最小验收仍需分别提供一个可清空或专用的 R2 bucket、COS 永未开启 versioning
的 bucket、相应只覆盖测试资源的存储/CDN凭据与测试域名，然后执行：

1. 上传包含缺少 `sow-sha256` metadata 的遗留对象和一个保留 extra；
2. 冻结旧写入方，运行两目标 adoption，保存完整 stdout、对象清单与 provider audit log；
3. 重跑 adoption，证明 `changed=false`；
4. 执行首次 publish，核对 provider 请求日志不存在 payload PUT；
5. 分别注入对象删除、同尺寸改写、分页间变化和鉴权失败，核对退出码 4/5 与零 canonical 提交；
6. 执行普通 remote fsck 与 L2 verify，核对前者分页 List、后者零 List；
7. 验证 CDN purge、发布后 GET 与双目标独立 checkpoint 后再移除测试资源。

在这些真实资源步骤完成前，FR-30/FR-34 与迁移 PoC 只能记为“协议集成通过、真实云
待验证”，不能标为最终通过。
