# 2026-07-20 Cloudflare static entitlement bootstrap

状态：本地实现、官方 SDK wire 合同、普通与 race 测试通过；真实 Cloudflare Worker、route、
purge 和 provider log **未执行**，POC-06 保持 `受阻`。

本轮只修改并运行本地代码与 loopback/fake-provider 测试。没有读取真实云凭据，没有向
`pro` 测试桶、Cloudflare 控制面、CO/COS、EdgeOne 或任何生产仓库发送写请求。

## 关闭的本地阻塞

边缘运行时原本已支持两种冻结的 token verifier 形状：

- `provider://ID`：auth Worker 绑定 `TOKEN_VERIFIER` service，bootstrap 管理 auth/origin，
  但只读审计独立 verifier Worker；
- `env://NAME`：auth Worker 直接读取一个 Cloudflare `secret_text` entitlement 文档。

旧 bootstrap plan 只接受第一种，因此一个 PRD 未要求的预存商业 verifier Worker 被错误地
变成非生产 token PoC 的前置条件。当前 plan/descriptor schema v3 把两种形状冻结为闭合联合类型：

- provider plan 必须有 exact service/runtime/evidence，禁止 static secret；
- static plan 必须只有与 edge contract `env://NAME` 同名的 secret，禁止 provider 字段；
- shared Go contract 与 bootstrap plan 都拒绝 plain variable、required variable、service、secret
  跨类型同名；shared grammar 接受的 leading underscore 同样可部署，而 bootstrap 自身的控制环境
  变量名被保留，不能被误用为 entitlement binding；
- `SOW_BASIC_ENTITLEMENTS` 仍是独立 Basic fallback authority；token verifier 不能复用该名，
  防止同一 digest 文档同时授权 token 与 Basic credential；
- static bootstrap 只管理 auth/origin 两个 Worker 和 main/beta 两条 route，不创建、检查或删除
  verifier Worker；
- rollback 只消费 sealed receipt，不读取 entitlement secret；删除 auth Worker 时 secret binding
  随 Worker 一并消失；
- plan、registry candidate、receipt、日志和错误均不保存 secret 值或 token digest。
- leak detector 除完整 secret JSON 外还登记每个 64-hex token digest，单条 digest 进入错误、
  receipt 或 artifact 也会失败。

production config 生成测试从 `internal/config` 的 `EdgeDeployment("cf")` 直接构造 static plan，
避免只由手写测试 fixture 自证。

## Static secret 门禁

sealed apply replay 只构造只读 R2/API control 并观察 receipt closure，不读取 entitlement。
只有 receipt 不存在时，apply 才在取得 lease、复核 bucket/provider readiness 后读取 exact 环境变量
一次并注入 SDK control。上传前要求：

- JSON 为 canonical compact wire，拒绝 unknown field 与 trailing data；
- 1..10,000 条，但整体不超过 [Cloudflare Workers 每变量 5 KB 上限](https://developers.cloudflare.com/workers/platform/limits/)
  的保守十进制 5,000 bytes；
- token 仅保存 lower-case SHA-256，严格排序且不重复；
- expiry 为 whole-second UTC RFC3339，上传时每条至少还有 15 分钟有效期；
- audience 仅允许 plan 中 exact main/beta host，排序且不重复；
- path prefix 必须 canonical、安全、排序且不重复。

官方 Cloudflare SDK loopback 证明 auth multipart 只有 canonical plain-text variables、一个
`ORIGIN` service binding、一个同名 `secret_text` 和 exact Worker bundle。缺 secret、额外 secret、
provider/static 类型替换都在发出 provider request 前失败。

边界测试构造 exact 5,000-byte canonical secret 正例，并拒绝 5,001 bytes；因此本地计划不会
接受一个必然超过 Cloudflare Worker variable 5 KB 限制的 entitlement 文档。
expiry 同样有 exact 15m 正例与 15m-1s 负例；完成 Worker/route 双观察后、写 durable receipt 前
再次要求仍剩完整 15 分钟，超时状态保持未封存并由下一次 apply 走 checked-reset 恢复。

Cloudflare 的读取接口只返回 `secret_text` 名称与类型，不返回值。若 apply 已有 sealed receipt，
重放只做双次 closure 观察；若上传/建路由后在 receipt 前中断，同 run 的旧 auth 无法证明它仍是
当前环境中的 entitlement。恢复因此在 apply lease 与同一动态授权内，先以 checked-delete 精确
删除 planned routes 和 auth Worker，再用当前 secret 重建；origin 保持不变。route/auth 删除成功但
响应丢失的故障注入均可安全重放。这样无需把 secret 指纹写进 plan、annotation 或 receipt。

## 实际执行结果

```text
gofmt -w internal/config/edge.go internal/config/edge_test.go \
  test/compat/real_cloud_cloudflare_bootstrap_registry_test.go \
  test/compat/real_cloud_cloudflare_bootstrap_test.go

go test ./test/compat -run 'Cloudflare.*Bootstrap' -count=1
ok github.com/pgsty/sow/test/compat 1.073s

go test -race ./test/compat -run 'Cloudflare.*Bootstrap' -count=1
ok github.com/pgsty/sow/test/compat 2.451s

go test ./internal/config ./test/compat -count=1
ok github.com/pgsty/sow/internal/config 1.002s
ok github.com/pgsty/sow/test/compat 14.912s

go test -race ./internal/config ./test/compat -count=1
ok github.com/pgsty/sow/internal/config 11.873s
ok github.com/pgsty/sow/test/compat 18.312s

go test ./... -run '^$' -count=1
PASS (all root-module packages compile)

npm test --prefix edge
PASS (47/47)

go vet ./...
PASS

staticcheck -checks='inherit,-ST1005,-U1000' ./internal/config ./test/compat
PASS

staticcheck -checks='SA*,S1*' ./internal/config ./test/compat
PASS

git diff --check
PASS
```

裸 `staticcheck ./test/compat` 仍报告仓库既有的三个 `U1000`，分别位于
`apt_legacy_alias_test.go` 与 `real_edge_multipop_test.go`；它们不在本轮 diff。上表使用项目
冻结的 profile，并另跑完整 SA/S1 语义检查，不把裸命令伪报为通过。

Blind Hunter 与 Edge Case Hunter 均在无先验对话上下文下复核最终 diff。审查发现的 namespace
碰撞、opaque-secret 中断恢复、单 digest 泄漏、provider size 真边界、shared grammar/control env、
expiry horizon、sealed replay secret 读取和 token/Basic authority alias 均已修复；最终 Edge 返回
空 findings，Blind 仅要求刷新本节计时，现已完成。

## 尚未关闭

这项变更只移除了独立 `pigsty-entitlements` Worker 作为 bounded static-token PoC 的必要前置，
没有把真实 Cloudflare 验收变成本地测试。下一步仍需要 owner-designated `pro` tuple 的 scoped
Cloudflare REST API token，先生成 signed readiness，再执行 bootstrap apply、真实 main/beta
token/anonymous probe、purge/cache/provider-log 观察与 rollback。完整商业 provider 模式仍需要
真实 verifier deployment identity。COS/EdgeOne、双云部分失败/重放和生产迁移也仍未执行。

任何真实执行继续只允许 owner 明确授权的非生产资源；CO/COS/Cloudflare 生产仓库永久禁止测试。
