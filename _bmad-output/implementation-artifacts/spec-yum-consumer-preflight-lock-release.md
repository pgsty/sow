---
title: 'YUM consumer 预检锁释放失败诊断'
type: 'bugfix'
created: '2026-07-19'
status: 'done'
route: 'one-shot'
---

# YUM consumer 预检锁释放失败诊断

## Intent

**Problem:** YUM consumer preflight 在准备阶段已有主错误时直接忽略 `Lock.Release()`
错误，可能留下 durable `state.lock`，却不告诉操作者随后需要恢复；其余生产 CLI 入口已使用
共享传播器，不应被误报为同一缺陷。

**Approach:** 把 stderr 传入准备边界，并让失败清理复用 `propagateStateLockRelease`：保留原始
错误对象与退出分类，同时输出锁释放诊断并保留被替换的外来锁证据。

## Suggested Review Order

**Failure semantics**

- 保留主错误与退出分类，同时显式诊断 teardown failure。
  [`yum_consumer_preflight.go:1635`](../../internal/cli/yum_consumer_preflight.go#L1635)

- 两个真实命令入口把 stderr 传入准备边界。
  [`yum_consumer_preflight.go:238`](../../internal/cli/yum_consumer_preflight.go#L238)

**Fault evidence**

- 真实路径替换证明 warning、主退出码与外来证据同时保留。
  [`yum_consumer_preflight_test.go:885`](../../internal/cli/yum_consumer_preflight_test.go#L885)
