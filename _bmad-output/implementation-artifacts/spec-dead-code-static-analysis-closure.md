---
title: 'CLI 不可达旧路径与静态分析闭合'
type: 'hardening'
created: '2026-07-20'
status: 'done'
review_loop_iteration: 1
baseline_commit: 'ee467bc'
---

## Intent

默认 `staticcheck ./...` 暴露了 42 个不可达声明。它们包括已被 expected-object、
read-admission、target-bound compatibility workflow 等现行路径取代的旧 wrapper、旧
YUM compatibility materializer/auditor，以及未使用的测试 helper。保留这些代码会让
“实现存在”与“真实 CLI 可达”混淆，也让静态门禁无法作为交付证据。

## Contract

- 删除所有 `U1000` 不可达声明，不改变任何公开 flag、配置 schema、退出码或 wire 合同。
- 保留并验证唯一现行路径；不以 lint ignore 隐藏 dead code。
- `staticcheck` 继续启用全部正确性检查。仅豁免包注释、既有缩写/vendor wire 名和错误
  首字母这四类纯展示规则（`ST1000/ST1003/ST1005/ST1020`）。
- 干净交付白名单必须精确反映删除/新增文件，并继续扫描高置信秘密。
- 全程关闭真实云/真实上游开关，不访问或写入任何云资源。

## Implementation

- 删除 42 个不可达声明和整个旧 `internal/cli/yum_compat_verify.go`。
- 新增 `staticcheck.conf`，保留 `U1000` 与其余正确性检查。
- 将 Cloudflare 测试凭据哨兵改成明确的 fixture/replace-with 值，使交付秘密扫描不需要例外。
- 修正 clean-delivery 产品/交付文件集合，纳入最近两项 Cloudflare spec/evidence。

## Verification

- `staticcheck ./...`
- `go vet ./...`、`go test -run '^$' ./...`、`git diff --check`
- 六个互斥 `internal/cli` ordinary shard 与六个 race shard。
- 非 CLI 全包 ordinary/race、nested RPM module test/vet。
- 四平台 `CGO_ENABLED=0` 静态构建；edge build + 47/47 contract。
- 七套迁移/回滚门禁；clean-delivery 使用空模块缓存和本机 `file://` module proxy。

