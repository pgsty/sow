---
title: '冻结可路由 URL 路径字符契约'
type: 'bugfix'
created: '2026-07-12'
status: 'in-review'
review_loop_iteration: 0
baseline_commit: '84800a60e01aaaf8dc5b189c3ddb1380930f4865'
context:
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Go 配置与 asset `--dest` 当前接受边缘共享路由明确拒绝的字符，因此本地生成和发布可以成功，但标准 URL 编码后会被 Cloudflare Worker 与 EdgeOne 同构契约拒绝，形成永久 404 或 `?/#` URL 语义歧义。

**Approach:** 在 Go 端建立与 `edge/shared/contract.mjs` `SAFE_SEGMENT` 完全同义的单段验证器，并在配置预检与 asset 目标构造时统一调用，使不可路由输入在任何状态变更前失败。

## Boundaries & Constraints

**Always:** 允许字符必须保持为 ASCII `A-Z a-z 0-9 + . _ ~ ^ : -`；路径必须是规范化、相对、非空的 POSIX 段序列；验证 expanded repo paths、APT suite/component、所有 package arch、YUM OS selector 路由值和 asset `--dest`；既有合法 DEB/RPM 文件名、`{arch}` 配置模板及 snapshot/token 契约不得受损。

**Ask First:** 若现有权威配置或真实仓库证明必须公开服务上述集合之外的字符，需先冻结新的 Go/JS 共享编码与缓存键契约。

**Never:** 不放宽 edge 对 `%`、query、fragment、反斜杠或编码别名的拒绝；不引入 URL 自动转义回退；不修改 sync、publish 跨 view 行为或外部协议。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| 合法 repo path | `apt/infra`, `yum/el9/{arch}`, `pkg/tools+debug` | 配置通过，expanded path 每段可路由 | N/A |
| 非法 repo path | 包含空格、`%?#@`、Unicode | Decode 阶段拒绝 | 精确指出字段与不安全 segment |
| 合法维度 | suite `bookworm`, component `non-free-firmware`, arch `x86_64` | 配置通过 | N/A |
| 非法维度 | suite/component/arch 含空格、`%`、Unicode | Decode 阶段拒绝 | 精确指出维度字段 |
| 合法 asset 目标 | `releases/tool+debug_1.0.tgz` | add 目标路径构造成功 | N/A |
| 非法 asset 目标 | 任一 segment 含空格、`@`、Unicode 或为空 | add 在写 CAS/ref 前拒绝 | `unsafe asset destination` |

</frozen-after-approval>

## Code Map

- `internal/config/config.go` -- schema 预检、repo expanded paths 与 URL 维度验证。
- `internal/config/config_test.go` -- 配置正反例。
- `internal/cli/add.go` -- asset 逻辑目标路径验证。
- `internal/cli/add_test.go` -- asset `--dest` CLI 正反例。
- `edge/shared/contract.mjs` -- 字符集合的冻结语义来源，仅对照、不修改。

## Tasks & Acceptance

**Execution:**
- [x] `internal/config/config.go` -- 增加共享 Go route segment/path 验证并接入 expanded repo paths、APT suite/component、arch 与 YUM OS 路由值。
- [x] `internal/config/config_test.go` -- 覆盖全部非法字符类、合法边界字符、YUM `{arch}` 展开和维度字段。
- [x] `internal/cli/add.go` -- 对 asset destination 的每个 segment 应用同一字符契约。
- [x] `internal/cli/add_test.go` -- 证明非法目标在状态变更前失败且合法边界字符仍可添加。

**Acceptance Criteria:**
- Given 任何通过 `sow.yaml` 或 `sow add --dest` 进入公开 key 的路径，when Go 预检成功，then 每个 segment 必须可被 edge `SAFE_SEGMENT` 原样接受且无需百分号编码。
- Given 现有合法示例配置和包路径，when 运行 config/CLI 测试，then 行为保持兼容。
- Given 任一不可路由字符，when Decode 或 add 执行，then 返回配置/用法错误且不创建 CAS、view ref 或 materialized 文件。

## Spec Change Log

## Design Notes

Go 端单一谓词按字节判断 ASCII 白名单，避免正则与 JavaScript 字符类漂移。配置的 `{arch}` 仅在原始 YUM 模板中暂时存在；契约在 `ExpandedPaths()` 后验证实际输出，同时独立验证 arch，使模板仍可用。

## Verification

**Commands:**
- `gofmt -w internal/config/config.go internal/config/config_test.go internal/cli/add.go internal/cli/add_test.go`
- `go test -count=1 ./internal/config ./internal/cli -run '<route-safe focused tests>'`
- `go test -race -count=1 ./internal/config ./internal/cli -run '<route-safe focused tests>'`
- `npm test --prefix edge` -- 共享 edge 字符与路由契约仍全部通过。
