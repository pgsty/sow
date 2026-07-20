---
title: 'CLI help 完整展示注册参数'
type: 'bugfix'
created: '2026-07-12'
status: 'done'
review_loop_iteration: 1
baseline_commit: '84800a6743b0d72f3664a45dcf3eca59d1a1e663'
context:
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 每个子命令覆盖 `flag.FlagSet.Usage` 后只输出手写 synopsis，许多已经注册且对真实操作关键的参数（选择器、恢复、GPG/secret 文件、并发和校验限制）无法从 `sow <command> --help` 发现。现有测试只检查 Usage 行存在，因而 FR-42 的“可理解命令面”证据不足。

**Approach:** 提供一个统一 usage helper，在保留各命令 synopsis 和补充说明的同时调用该 FlagSet 的 `PrintDefaults()`；让所有现有 FlagSet 都通过 helper 输出参数，并以真实 CLI 与 VisitAll 驱动的测试证明注册面完整且不会回显传入的敏感值。

## Boundaries & Constraints

**Always:** 顶层 help、退出码、参数解析和现有 synopsis/说明语义保持兼容；参数清单只能从 FlagSet 注册事实生成，不能再维护第二份手写列表；`--help` 必须在读取配置、文件或 secret 前 ExitOK。

**Ask First:** 若修复需要改变任何 flag 名、默认值、命令语义或 stdout/stderr 归属，先请求确认。

**Never:** 不修改 publish plan/restore/provider/delete 逻辑；不在 help、测试日志或文档中放真实 secret；不为测试暴露生产全局 hook；不手写重复的完整 flag 清单。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| 完整帮助 | `sow <cmd> --help`，cmd 为十个 FlagSet 子命令之一 | ExitOK；保留 Usage；展示 Options 及该 FlagSet 全部注册 flag | 不加载配置或执行副作用 |
| 敏感参数 | 在 `--help` 前传入 GPG/passphrase/Pro-token 文件哨兵值 | 展示参数名和描述，但不回显哨兵值 | ExitOK，无 `sow:` 错误前缀 |
| 带说明命令 | `sow publish --help` | 保留 forward restore/stable fail-closed 说明并展示完整 flags | ExitOK |

</frozen-after-approval>

## Code Map

- `internal/cli/app.go` -- 顶层 dispatch、common flags、统一 usage helper、init/fsck。
- `internal/cli/{add,remove,sync,promote,publish,verify,materialize,gc}.go` -- 子命令 FlagSet 与自定义 synopsis。
- `internal/cli/app_test.go` -- help 的退出码、完整注册面和敏感值不泄露回归。
- `README.md`、`docs/requirements-traceability.md` -- 用户入口与 FR-42 证据。

## Tasks & Acceptance

**Execution:**
- [x] `internal/cli/app.go` -- 增加统一 helper，并迁移 init/fsck usage。
- [x] `internal/cli/*.go` -- 将其余八个 FlagSet usage 迁移到 helper，保留命令特有说明。
- [x] `internal/cli/app_test.go` -- 用 VisitAll 验 helper，并遍历真实命令与敏感参数场景。
- [x] `README.md`、`docs/requirements-traceability.md` -- 只补充与实际行为一致的 help 证据。

**Acceptance Criteria:**
- Given 任一现有 FlagSet 子命令，when 执行 `--help`，then ExitOK 且全部已注册 flag 可发现。
- Given help 调用携带敏感文件参数值，when 输出帮助，then 参数名存在但输入值不存在。
- Given 未请求 help 的正常命令，when 解析参数，then 默认值、错误码与执行路径不变。

## Spec Change Log

## Verification

**Commands:**
- `go test -count=1 ./internal/cli -run Help` -- help 与泄露回归通过。
- `go test -race -count=1 ./internal/cli -run Help` -- helper/测试无竞态。
- `go vet ./internal/cli ./cmd/sow` -- 静态检查通过。
- `git diff --check` -- 补丁格式通过。
