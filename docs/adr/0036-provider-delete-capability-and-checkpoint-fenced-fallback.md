# ADR-0036：供应商删除能力与 checkpoint-fenced 降级

- 状态：Accepted
- 日期：2026-07-18
- 决策范围：FR-04、FR-07、FR-09、FR-25、FR-27、FR-28、NFR-03、NFR-08、NFR-09、MIG-06、POC-05、POC-06

## 背景

ADR-0011 原先要求所有 live DELETE 都携带刚证明的 ETag，并由供应商拒绝错误的
`If-Match`。这对提供条件 DeleteObject 的端点是最强合同，但它不是 Cloudflare R2 的真实
能力。2026-07-18 在 owner 明确指定的空、非生产 `pro` 桶实测：R2 的 create-only PUT、
`PutObject If-Match`、并发 CAS、HEAD、流式 GET 与带 source ETag 的 CopyObject 均成立；
故意错误 ETag 的 DeleteObject 却成功并删除了测试对象。

该结果与 Cloudflare 官方兼容表一致：条件操作列覆盖 Head/Get/Put，而 DeleteObject 没有
条件操作；Delete Object 文档也只给出无条件删除。R2 扩展提供的是 CopyObject source
条件头，不是 DeleteObject 条件头：

- <https://developers.cloudflare.com/r2/api/s3/api/>
- <https://developers.cloudflare.com/r2/objects/delete-objects/>
- <https://developers.cloudflare.com/r2/api/s3/extensions/>

继续把条件 DELETE 当成 R2 必备能力会让 asset removal、by-hash retention 与前向恢复的
合法删除永久失败；悄悄丢弃 `If-Match` 则会伪造不存在的 CAS 保证。

## 决策

1. `storage.delete_mode` 只有两个值：
   - `conditional`：默认值。端点必须通过错误 ETag 不删除、正确 ETag 才删除的运行时探针；
     不满足则在 live key 前返回 capability error。
   - `checkpoint-fenced`：显式单写者降级。只有 operator 已撤销旧写凭据、停用旧发布器并
     确认没有旁路写者时才可启用。
2. 即使配置了降级，saga 仍先运行确定性的 SOW-owned 条件删除探针。若供应商真的支持条件
   DELETE，继续使用 ETag 条件删除；只有 stale `If-Match` 返回成功且 exact probe 随即 absent
   这一项确定性反证才进入降级。网络错误、HEAD 不确定、probe retained 或 cleanup 失败均不
   能借 `ErrCapability` 进入无条件 live DELETE。该探针在 publication lock 与 mutable write 前完成。
3. 降级删除 live key 前必须连续完成：
   - ADR-0011 的 HEAD + streamed GET 全正文 size/SHA/ETag 身份证明；
   - 远端发布围栏仍与本 transaction 获取的 token 一致：R2 为 locked checkpoint ETag，
     COS 为 create-only generation-lock key + ETag；
   - 第二次独立 HEAD + streamed GET，且两次 size/SHA/ETag 完全相同；紧邻 DELETE 再次读取围栏；
   - 调用供应商明确命名的 unconditional checkpoint-fenced DELETE；
   - HEAD 证明 origin absent，再证明远端发布围栏未变；
   - 原事务继续 mandatory exact purge、negative CDN verify、checkpoint commit 与 remote-ref。
4. 默认路径、计划授权、删除 class 与 key 空间均不扩大。`PlannedDelete` 仍是 ADR-0011 的
   封闭 union；普通 Removed、package payload、immutable generation、checkpoint、CAS archive
   不能借此获得删除权限。
5. 删除已生效但响应丢失时不推测失败。journal 重放先观察 live key；若已 absent，记录完成并
   继续 purge/verify，不发第二次无条件 DELETE。候选或围栏任一漂移均失败闭锁。
6. R2 真实协议已经验证。COS 的 create-only generation fence 有协议/故障注入测试，但
   DeleteObject 真实供应商行为仍未 PoC；在取得专用非生产 COS 资源前不得把 COS 标为通过。

## 安全边界

`checkpoint-fenced` 没有伪装成供应商线性化 DELETE。第二次正文证明与实际无条件 DELETE
之间仍有一个供应商无法封闭的极小窗口；其安全性来自 PRD 已冻结的“单操作者、单开发机”
假设以及切换前撤销所有旧写者。若产品将来支持多写者，必须改为真正的条件删除、版本化对象
或另一个可线性化协调原语，不能继续沿用本模式。

任何生产 CO/COS/Cloudflare 仓库都禁止用于验证本决定。真实 R2 用例仅能命中编译期固定的
非生产 `pro` tuple，第一笔写入前强制证明桶为空，只删除 exact run-owned 且正文摘要在本次
allowlist 内的 key，并在退出时及独立清单中再次证明桶为空。
该 storage-only 用例只验证供应商原语和 identity-bound run-owned cleanup；真实 Publisher 的
checkpoint→DELETE→purge→verify→commit 全事务仍属 POC-06 未完成项。

2026-07-19 同一 exact non-production tuple 又给出 data-plane 反证：main/beta raw R2
custom domain 在当前对象首次匿名读取时命中相同 body/length/ETag；bucket 对象删除并确认空后，
两域仍以 `CF-Cache-Status: HIT` 返回该精确 run-owned 正文，响应 `max-age=1800`。请求端
`Cache-Control: no-store, no-cache, max-age=0` 没有改变该事实。因此 origin absence 只能是
事务中间证据，绝不能推进 checkpoint；只有供应商 exact purge 成功、随后 CDN negative verify
成功，才允许提交删除。测试允许记录 exact stale HIT 只是为了安全描述供应商负能力，不是把
stale cache 当作删除完成。

## 结果

- R2 发布不再依赖不存在的 DeleteObject CAS，也不会把无条件删除伪报成条件删除。
- 安全默认值保持失败闭锁；危险度更高的供应商适配只能由显式、可审计配置启用。
- PRD 单写者假设成为明确运维前提，而不是隐藏在 SDK 行为中的假设。
- ADR-0011 的内容授权、purge、验证、journal 与恢复闭包保持不变。
- raw custom-domain 实测证明 purge 与 negative verify 不是防御性冗余，也不能由对象删除或
  请求端 no-cache 替代。

## 验证

真实供应商命令、结果、空桶前后证明与本地故障注入见
[真实 R2 存储协议证据](../evidence/2026-07-18-real-r2-storage-protocol.md)。
