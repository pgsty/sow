---
title: '将 canonical Apply 与 projection stage 的冻结身份闭合'
type: 'bugfix'
created: '2026-07-22'
status: 'done'
review_loop_iteration: 0
baseline_commit: '5490fb6'
context:
  - '{project-root}/docs/requirements-traceability.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** projection 已把 manifest/config 与 durable intent 绑定为 size+SHA-256，但 `Store.Apply` 写 journal 后仍按 pathname 重新打开 stage；换包可让 canonical Git 接受 intent 未授权的字节，恢复也有 verify→reopen 竞态。

**Approach:** state 层一次性以 no-follow/nonblocking 描述符准入 stage，从同一描述符生成 journal 并安装；Recover 同样一次绑定、一次消费。projection 调用方传入从 intent 推导的完整 canonical path→identity 向量，journal 前验证精确键集与字节。

## Boundaries & Constraints

**Always:** 流式读取且最多消费准入 size+1；拒绝 symlink、special file、增长/截断、原地突变、路径或 inode 变化。journal、copy 与最终校验消费同一描述符。`ExpectedStages != nil` 时与 `staged` 键集完全相同并逐项匹配。当前 Apply 拒绝同字节换 inode；重启后 Recover 可重新绑定 journal 匹配的 regular file，但绑定后任何变化都失败。失败不得改变 HEAD/ref 或删除 replacement，并保留可诊断事务状态。

**Ask First:** 修改 transaction journal schema、破坏 incomplete journal 恢复兼容性，或访问真实云/生产资源。

**Never:** journal 后 reopen stage pathname；以 hash 预检授权后续 reopen；整文件入内存；按 pathname 删除/覆盖 replacement；削弱 intent、机密性校验、Git CAS 或非 projection 调用方；引入外部运行时。

## I/O & Edge-Case Matrix

| 场景 | 状态 | 预期 | 失败闭包 |
|---|---|---|---|
| 正常 Apply | expectation/stage 一致 | 精确字节提交并完成 refs | — |
| expectation 不闭合 | 缺键、多键、非法/错误 identity | journal 前拒绝 | HEAD/ref/stage 不变 |
| journal 后换包 | 不同/同字节 inode 或 FIFO | 不提交且不阻塞 | replacement 保留 |
| 原 inode 突变 | 截断、增长、原地改写 | bounded copy 检出 | 无错误 commit |
| intent 恢复 | stage 匹配 journal | 单次重绑定后幂等重放 | 完成同一 commit/ref |
| recovery 中换包 | bind 后、copy 前替换 | fail closed | journal 不冒充完成 |
| 旧调用方 | `ExpectedStages == nil` | API 兼容但仍 descriptor-bound | 无不受控 reopen |

</frozen-after-approval>

## Code Map

- `internal/state/transaction.go` -- ApplyOptions、journal、Recover/RecoverAborted 和 stage binding。
- `internal/state/store.go` -- descriptor-bound canonical 安装、回滚与 Git commit。
- `internal/cli/{asset,package}_projection_intent.go` 及 add/rm 调用面 -- 从 intent 注入完整 identity 向量。
- `internal/state/transaction_test.go` 与 projection 测试 -- 文件系统竞态和恢复负例。

## Tasks & Acceptance

**Execution:**
- [x] `internal/state/transaction.go` -- 增加 expected-stage 合同与 retained descriptor；journal 由绑定结果生成。
- [x] `internal/state/store.go` -- bounded descriptor copy/校验，Apply/Recover 不 reopen。
- [x] projection intent 与 add/rm -- 普通及 inputless recovery 均注入完整 identity 向量。
- [x] state/CLI 测试 -- 先红测 journal 后不同/同字节换包、FIFO、原 inode 突变和 recovery 换包，再验证幂等闭包。
- [x] 追踪、deferred、clean-delivery 与 evidence -- 记录 review、race、全量、静态分析、跨平台和零云边界。

**Acceptance Criteria:**
- Given durable intent，when stage 在 prepare 或 journal 后被替换，then canonical 不含 replacement，HEAD/ref 不变且 replacement 存活。
- Given intent/stage 匹配，when Apply 或重启 Recover，then journal、Git tree、record 与 intent 的全部 size/SHA-256 一致。
- Given FIFO、增长或原地突变，when 准入/安装，then 有界无阻塞失败且 journal/ref 不错误完成。
- Given nil expectation 的旧调用方，when Apply/Recover，then API 兼容且不经过 pathname reopen。

## Spec Change Log

- 实现审查发现仅冻结 resolved HEAD hash 不足以拒绝同 hash 的 branch/detached 切换；新增可选 `expected_head_raw`，保持 v1 schema 与旧 incomplete journal 兼容。用户已明确要求本地可逆工作不反复请求批准，因此采用该向后兼容安全扩展并在 evidence 中公开记录。
- 原生 `HEAD.lock` 与 target ref lock 保持到 post-commit 校验/回滚结束；late release error 进入 committed recovery boundary。
- Linux root 容器暴露权限型清理失败夹具不确定；改为显式测试 seam，不改变生产 cleanup 语义。

## Design Notes

进程内能力是 descriptor+inode+coordinate+bytes；重启后只能从 journal 重建新 descriptor+bytes。因此当前 Apply 拒绝同字节换 inode，而 Recover 可接受绑定前已存在的同字节 regular file。nil expectation 表示无上层 byte contract；非 nil（含空 map）强制完整闭包，避免只验 manifest 漏掉 config。新 journal 还保存 exact raw HEAD；旧 v1 journal 缺该字段时维持历史 hash-only 恢复兼容。

## Verification

**Commands:**
- `go test ./internal/state ./internal/cli -run 'Stage|Transaction|Projection|IntentWriteFailureReportsStageCleanupDrift' -count=1` -- state `3.918s`、CLI `159.519s`。
- 同一集合 `-race` -- state `4.421s`、CLI `341.077s`，无 race。
- `go test ./... -count=1 -timeout=30m` -- CLI `1478.692s`，全部功能包、compat 与 clean-delivery 通过。
- 文档与 allowlist 更新后 `go test ./test/compat/cleandelivery -count=1` -- 退出 0。
- `go vet ./...`、`staticcheck ./...`、`git diff --check` -- 通过。
- Darwin/Linux amd64/arm64 静态测试构建通过；最终 Linux arm64 二进制在 root、network-none/read-only `debian:13-slim` 容器运行 focused set 通过。
- 完整命令、SHA-256 和边界见 [V-78 evidence](../../docs/evidence/2026-07-22-canonical-apply-stage-identity.md)。

## Review Disposition

- Blind Hunter：`[]`。
- Edge Case Hunter：`[]`。
- 实现中发现并关闭 raw HEAD 同 hash 切换、native ref lock 释放窗、late release recovery 与 CLI materialization scope data race；最终两路独立复核无剩余 finding。
- 未发现 frozen intent gap；`review_loop_iteration: 0`。

## Suggested Review Order

1. [transaction stage binding、journal 与 Apply/Recover](../../internal/state/transaction.go#L30)
2. [raw HEAD/ref capability、manual commit 与 post-commit rollback](../../internal/state/store.go#L642)
3. [asset projection identity vector](../../internal/cli/asset_projection_intent.go#L76) 与 [package projection identity vector](../../internal/cli/package_projection_intent.go#L93)
4. [state adversarial tests](../../internal/state/transaction_test.go#L50) 与 [CLI vector/recovery tests](../../internal/cli/projection_expected_stages_test.go#L10)
5. [V-78 evidence](../../docs/evidence/2026-07-22-canonical-apply-stage-identity.md) 与 [需求追踪](../../docs/requirements-traceability.md)
