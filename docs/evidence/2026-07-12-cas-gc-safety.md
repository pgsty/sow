# CAS 引用计数与 GC 安全证据（2026-07-12）

## 结论

生产 `repository.ReferenceSet` 对重复 manifest 引用计数；`sow gc` 自动从 canonical
状态和显式历史窗重建 roots，默认不删除。只有当前孤儿集摘要精确匹配且不存在 missing
reference 时才删除；过期摘要、对象损坏/消失或重新可达都失败闭锁。

## 可复现命令与本轮结果

```bash
go test -count=1 -v ./internal/repository ./internal/cli -run 'GC|Reference'
```

```text
PASS TestReferenceSetCountsDeduplicatedManifestObjects
PASS TestGCIsDryRunByDefaultAndRequiresExactCurrentPlan
PASS TestGCRefusesStalePlanAndMissingReferences
ok   github.com/pgsty/sow/internal/repository 0.707s
PASS TestGCDryRunConfirmationAndHistoryRoots
PASS TestGCRemoteInventoryIsNotACASRoot
PASS TestGCHistoryRetentionIsBoundedAndExplicit
ok   github.com/pgsty/sow/internal/cli 0.938s
```

测试实际创建 reachable 与 orphan CAS 对象：dry-run 后两者都存在；错误 confirmation
返回 conflict；精确摘要只删除 orphan，history root 仍可读。另一组测试证明保留 2 个
commit 时旧对象仍可达，收窄到 1 个 commit 才成为 orphan；remote inventory 中仅存在于
bucket 的摘要不会伪造本地 CAS root。

## 边界

这是本地 canonical/CAS 的真实文件系统测试，不是生产大池回收演练。真实存量树首次
执行应保存 dry-run 报告、人工审阅摘要，再执行同摘要 apply；生产回收量和耗时仍需在
迁移窗口测量。
