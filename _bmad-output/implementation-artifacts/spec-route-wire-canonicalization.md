---
title: '区分制品 key 与 URL wire canonicalization'
type: 'bugfix'
created: '2026-07-19'
status: 'done'
review_loop_iteration: 2
baseline_commit: '0a1d520fa4ee9a5030cff8a1f9125f01cd45466a'
supersedes: 'spec-route-safe-url-paths.md'
context:
  - '{project-root}/_bmad-output/implementation-artifacts/spec-route-safe-url-paths.md'
  - '{project-root}/docs/adr/0039-caret-url-wire-canonicalization.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md'
---

## Intent

**Problem:** SOW 的 literal object-key alphabet 必须容纳 RPM 4.15+ version 中的 caret，
而 WHATWG `URL`/`Request` 必须把 path caret 序列化为 `%5E`。旧 edge parser blanket-reject
所有 `%`，所以 Go/manifest/publisher 接受的合法 RPM key 会在两家边缘永久 404。旧 Go
channel validator 又拒绝 config 已允许的 caret root，而静态、本地与验证侧 mirrorlist 直接
拼 raw `^`，导致生成正文、发布摘要和边缘动态响应互相漂移。与此同时，dot/backslash raw
request forms 会在标准 `Request.url` 暴露给应用前被规范化，应用代码无法诚实声称自己看见
并拒绝了原始写法。

**Approach:** 把三层身份分开：manifest/origin key 保留 literal `^`；Go 的共享 exact
encoder/decoder、publisher、local serving、remote verifier 与标准客户端统一使用 uppercase
`%5E` wire form；shared edge parser 只恢复这个 exact form，并立即按 literal alphabet、公开
route allowlist 和 normalized entitlement scope 重新验证。
供应商在 Worker 之前的 raw request/cache-key normalization 由真实 POC-06 单列验收，不用
本地 `Request` fixture 冒充。

## Boundaries & Constraints

**Always:** literal segment alphabet 仍为 ASCII
`A-Z a-z 0-9 + . _ ~ ^ : -`；`Request.url` 中 caret 的唯一应用可见 wire form 是 uppercase
`%5E`；decode 后必须重编码并与原 segment byte-equal；canonical final path 无论由何种 raw
写法产生，都必须重新经过 route allowlist、token/Basic entitlement scope 与 closed origin
routing。

**Never:** 不做通用 percent decode；不接受 lowercase `%5e`、encoded unreserved、encoded
separator、double encoding、raw serialized caret、trailing empty segment、query 或 fragment；
不声称应用层能恢复已被 Web API 丢弃的 raw dot/backslash request-target；不把本地 fixture
升级为 provider cache normalization 证据。

**External evidence boundary:** Cloudflare/EdgeOne front door 必须在 POC-06 证明 raw alias
被 provider raw rule 拒绝，或在 Worker/cache/log 前收敛为同一 canonical cache identity。
未取得该真边缘证据前，FR-38/POC-06 状态不升级。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected behavior |
|---|---|---|
| literal caret key | `tool-1.0^git.rpm` | manifest/origin key保留 `^`；Go CDN URL 为 `%5E` |
| canonical caret request | `tool-1.0%5Egit.rpm` | shared parser 恢复 literal key；两 vendor 路由同一 clean origin |
| visible percent aliases | `%5e`、`%255E`、`%41`、`%2F` | 404，零 origin call |
| path spelling aliases | raw caret、末尾 `/` | 404，零 origin call |
| pre-Request normalization | `pkg/%2e%2e/yum/...`、backslash variant | 以 `Request.url` 的 final `/yum/...` 重新做 allowlist 与 entitlement；不冒充 raw rejection |
| normalized escape to unowned target | `pkg/%2e%2e/private/...` | final `/private/...` 404，零 origin call |
| scoped Pro escape | entitlement `/pkg`，raw path 归一到 `/yum/...` | 403，零 origin call |
| dynamic Pro mirrorlist | token/Basic channel 的 `legacy_root` 含 caret | response URL 仅含 uppercase `%5E`，不泄露 raw `^` |
| beta/latest static mirrorlist | config-valid `yum/infra^next/x86_64` | publish body、plan Verify/purge URL 与 L3/L4 expected URL 均为 `infra%5Enext` |
| local/stable mirrorlist | local serving 或 Basic/token Pro | 本地 body、stable transformed digest 与 runtime token expectation byte-identical |
| compatibility closure | frozen route root 含 caret | positive Verify 与 purge 识别 encoded URL，但 manifest/remote key 保持 literal `^` |

## Code Map

- `internal/config/config.go` / `config_test.go` -- literal route alphabet、exact wire encode/decode、
  canonical URL builder 与 256-byte 穷尽属性。
- `internal/publish/model.go` / `saga.go` / `model_plan_test.go` -- channel acceptance、静态 pointer 与
  stable transformed verification digest。
- `internal/serving/model.go` / `serving_test.go` -- 本地 latest/stable mirrorlist 正文。
- `internal/serving/nginx.go` / `nginx_test.go` / `test/compat/nginx_product_include_test.go` --
  frozen literal alphabet 的 Nginx location/alias 渲染，以及 `%5E` 客户端请求到 literal `^`
  origin tree 的真实 public/Basic 回环验证。
- `internal/cli/publish_plan.go` / `verify_remote.go` / `publish_compat_closure.go` -- 真实发布计划、
  token/Basic L3/L4 expectation 与 compatibility Verify/purge 闭包。
- `internal/cli/verify_remote_test.go` -- caret YUM root 的 beta→latest 与 stable token/Basic CLI E2E。
- `edge/shared/contract.mjs` -- exact caret wire decode/re-encode 与 final canonical route gate。
- `edge/test/contract.test.mjs` -- 两 vendor caret、alias、normalization/allowlist/scope 合同。
- `edge/dist/*` -- 由 shared source 机械生成的可部署 bundles。
- `docs/adr/0039-caret-url-wire-canonicalization.md` -- 决策与不可观测 raw boundary。

## Tasks & Acceptance

**Execution:**
- [x] Go route predicate 增加 256-byte 穷尽属性证据，literal alphabet 不变。
- [x] Go 共享 encoder/decoder 只映射 caret↔uppercase `%5E`，拒绝其余 wire aliases。
- [x] ChannelState 接受 frozen literal alphabet；publisher、local serving、plan digest 与 remote
  verifier 全部复用 canonical client URL helper。
- [x] beta/latest/stable、token/Basic、compatibility Verify/purge 的真实 Go 入口覆盖 caret root。
- [x] shared edge parser 只接受 exact `%5E`，拒绝其余 visible aliases 与 trailing empty segment。
- [x] Cloudflare/EdgeOne shared tests 覆盖匿名、token-gated、origin literal key 与零-origin负例。
- [x] Web API 预归一化测试证明 final allowlist 与 entitlement scope 不可绕过。
- [x] Pro 动态 mirrorlist 对 token 与 Basic 均用 exact uppercase `%5E` 序列化 caret root。
- [x] Nginx renderer 复用 frozen literal segment validator；真实 public/Basic include 以 `%5E`
  请求命中 literal caret tree，并保持 traversal/symlink/default-deny 闭包。
- [x] ADR、evidence、traceability 明确本地/真实 provider 证据边界。

**Acceptance Criteria:**
- Given 任一通过 Go 预检的 literal caret key，when publisher 构造 CDN URL 且任一 edge adapter
  处理标准 `Request`，then wire 为 exact `%5E`，origin key 回到同一 literal `^` byte。
- Given 任一应用可见的非 canonical percent/trailing/raw-caret form，when shared handler 处理，
  then 404 且 origin call count 不变。
- Given raw dot/backslash 已被 Web API 归一化，when final canonical target 被处理，then route
  allowlist 与 entitlement 使用 final path；unowned target 404，越出 token scope 403，均零 origin。
- Given channel pointer 的 canonical legacy root 含 caret，when token 或 Basic Pro mirrorlist 在任一
  vendor 生成，then client URL 使用 exact `%5E` 且没有 raw `^`，后续请求恢复同一 literal key。
- Given config-valid `yum/infra^next/x86_64`，when 真实 CLI 发布并 L3/L4 校验 beta、latest 与
  stable，then static/dynamic/local body、plan digest、token/Basic expectation 与 compatibility
  Verify/purge 使用同一 `%5E` wire byte，且 manifest/channel/origin key 仍保存 literal `^`。
- Given config-valid caret root 的真实 Nginx include 与 literal filesystem tree，when public 或
  Basic client 请求 exact `%5E` URL，then Nginx 命中同一 literal origin；未拥有、未认证、
  traversal 与 symlink escape 仍失败关闭。
- Given 仅有本地 Web API fixture，then 不得宣称真供应商 raw cache-key normalization 已通过。

## Review Findings

- 独立盲审指出旧 frozen block 同时要求 caret、无 percent wire 和 blanket percent reject，
  无法自洽；旧 spec 原文保留并标为 superseded，本 spec/ADR 显式承接新合同。
- 独立边界审查指出 `Request.url` 前的 dot/backslash normalization 不可观测；新增 allowed-final、
  unowned-final 和 scoped-Pro 三类合同，文档不再伪称 shared JS 拒绝 raw request-target。
- 独立边界审查还指出动态 Pro mirrorlist 曾直接插入 literal `legacy_root`；共享 encoder 与两
  vendor 的 token/Basic 合同现证明 response URL 只输出 uppercase `%5E`。
- 第二轮两路独立复核共同指出 Go ChannelState、static/local mirrorlist、stable verification
  digest、runtime verifier 与 compatibility closure 仍漂移。现以 config shared helper 收敛全部
  生产入口，并用 caret YUM root 的 beta→latest/stable CLI E2E 与 ordinary/race 回归闭合。
- 第三轮盲审复现 Nginx renderer 仍使用旧 `._-/` 子集，导致 config-valid caret root 无法生成
  可托管 include。renderer 现逐 segment 复用 frozen validator；真实 Nginx public/Basic 回环
  证明 `%5E` 请求由 Nginx 规范化后命中 literal caret location/alias，安全负例保持关闭。
- 修复后 Blind Hunter 与 Edge Case Hunter 最终独立复审均返回 `[]`。

## Design Notes

`%5E` 是 standards-required serialization，不是第二个 object key。decode-and-reencode equality
把可见 wire form 收敛到一个拼写；Go 与 edge 的 exact inverse encoder 用于所有生成的 client
URL，而 filesystem、manifest、checkpoint 与 origin route 继续使用 literal path。
对于 Web API 已经折叠的输入，安全边界不是猜测原始字节，而是对 final canonical path 再执行
ownership 与 authorization。provider 前置缓存是否也使用该 canonical identity 必须由真 POC
的 raw spellings、cache status 和 provider log 证明。

## Verification

- `go test -count=1 ./internal/config ./internal/cli -run 'RouteSegmentContract|NonRoutable|Routable|AssetLogicalPath|AssetAddRejectsNonRoutable'` -- PASS（config 0.608s，CLI 2.160s）。
- `go test -race -count=1 ./internal/config ./internal/cli -run 'RouteSegmentContract|NonRoutable|Routable|AssetLogicalPath|AssetAddRejectsNonRoutable'` -- PASS（config 1.272s，CLI 2.626s）。
- `go test -count=1 ./internal/publish -run '^TestJoinCDNURLUsesCanonicalCaretWireForm$'` -- PASS（0.634s）。
- focused cross-layer ordinary（config/publish/serving/CLI）-- PASS（0.821s/0.794s/0.469s/15.390s），含 beta→latest 与 stable token/Basic caret-root E2E。
- focused cross-layer race -- PASS（1.772s/1.787s/2.980s/25.430s）。
- `SOW_COMPAT_NGINX=1 go test -count=1 ./test/compat -run '^TestProductGeneratedNginxIncludeLoopbackContract$' -v` -- public/Basic PASS（package 10.743s）。
- `npm run build --prefix edge && npm test --prefix edge` -- generated dist fresh，syntax/import 与 45/45 shared contract PASS（128.386292ms）。
- `go test ./... -run '^$'`、`go vet ./...`、`staticcheck -checks='SA*,S1*' ./...`、clean-delivery -- PASS；最终提交前重复。

## Suggested Review Order

**Canonical identity**

- 从 frozen literal alphabet 到唯一 `%5E` wire transform。
  [`config.go:1439`](../../internal/config/config.go#L1439)

- 统一校验 base URL 并构造 client-visible URL。
  [`config.go:1490`](../../internal/config/config.go#L1490)

**Edge trust boundary**

- exact decode/re-encode 在鉴权与 origin 前收敛路径。
  [`contract.mjs:274`](../../edge/shared/contract.mjs#L274)

- 动态 Pro mirrorlist 只生成 canonical client URL。
  [`contract.mjs:335`](../../edge/shared/contract.mjs#L335)

**Publication and verification**

- beta/latest pointer 保留 literal channel、输出 encoded body。
  [`model.go:179`](../../internal/publish/model.go#L179)

- publish plan 与 stable transformed digest 共用 helper。
  [`publish_plan.go:1810`](../../internal/cli/publish_plan.go#L1810)

- compatibility Verify 与 purge 精确往返 wire/literal identity。
  [`publish_compat_closure.go:329`](../../internal/cli/publish_compat_closure.go#L329)

**Direct Nginx hosting**

- renderer 逐 segment 复用 frozen validator，regex 保持 literal。
  [`nginx.go:328`](../../internal/serving/nginx.go#L328)

- 真实 public/Basic 回环证明 `%5E` 命中字面量 tree。
  [`nginx_product_include_test.go:22`](../../test/compat/nginx_product_include_test.go#L22)

**Cross-vendor and CLI evidence**

- 两 adapter 覆盖 canonical caret 与所有 visible aliases。
  [`contract.test.mjs:487`](../../edge/test/contract.test.mjs#L487)

- token/Basic 动态 mirrorlist 保持同一 wire bytes。
  [`contract.test.mjs:1065`](../../edge/test/contract.test.mjs#L1065)

- 真实 CLI beta→latest 与 stable L3/L4 覆盖 caret root。
  [`verify_remote_test.go:414`](../../internal/cli/verify_remote_test.go#L414)
