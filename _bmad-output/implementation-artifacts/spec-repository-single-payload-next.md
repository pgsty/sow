---
title: 'Repository 单包体 next 实现'
type: 'feature'
created: '2026-08-05'
status: 'in-review'
review_loop_iteration: 0
baseline_commit: '6c84f9e570243c6db2105fc92d7f822cfb5f4fd5'
context:
  - '{project-root}/design/next/specs/SPEC.md'
  - '{project-root}/design/next/architecture/ARCHITECTURE-SPINE.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 当前 v0.2 仍以 C2 为每个 RPM view 建 package hardlink alias；上传对象存储后每个路径都会成为完整副本，而且现有 schema、checker、Generation 与迁移恢复都把 C2 当成正确状态。

**Approach:** 发布 `0.3.0`：根 `pool/` 是唯一 payload data plane；共享纯函数生成/验证 RPM parent-relative href；完整实现 UUID/layout migration、retained/GC、target-scoped static publication 与外置 `sow-rpm-leaf-v1` export。细节以 `design/next/` companions 为准。

## Boundaries & Constraints

**Always:** 每个 Repository/prefix 的 Package Object 恰有一个 canonical payload；公开根只有 `pool/ + dists/`；APT `Filename` 保持 raw path、by-hash 仍可硬链接；RPM href 按实际深度编码并 round-trip；Generation target-neutral，publication/grace target-scoped；旧 C2 经 journal/grace 前滚；校验/回收只依赖 path/size/digest/ref closure。

**Ask First:** 使用真实云/付费资源；操作生产 prefix；缩短 TTL grace；改变 approved `design/next` 或清理无法证明归属的数据。

**Never:** 增加 `release/`、`reposync/` 或 payload alias；用 `/pool/...`、absolute `xml:base`、硬编码深度或 edge rewrite 保正确；为 reposync 恢复 alias；以 inode/link count 定义包；公开控制对象；R2 删除；in-place export replace；接入 V1 Git/CAS ownership。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|---|---|---|---|
| 构建 | 多 Dist/arch 共享包 | 根 Pool 一份，`dists/` 仅 metadata；APT/DNF file+HTTP 可消费 | 非规范 path/href/closure 原子拒绝 |
| C2 升级 | v0.2 tree | `repo migrate` 依 journal/grace/receipt 前滚 | 可重放；transition 时 changes/publish/gc 拒绝 |
| 保留/回收 | live + retained + grace | `retain add|ls|rm` 不复制包；`gc` 只删 closure 外对象 | 证据未知/漂移不删 |
| 发布 | filesystem/R2 target | `publish TARGET` 路径一对一、pointer-last、私有 checkpoint；R2 report-only | overlap/CAS/authority 异常拒绝 |
| 导出 | `export rpm-leaf DIST ARCH DIR [--hardlink]` | 空外部 root、copy 默认、重建 RPM-MD、marker-last；reposync 通过 | foreign/cross-device/unclosed 拒绝 |

</frozen-after-approval>

## Code Map

- `internal/yumrepo/`, `internal/v2/managed/` -- href、metadata-only view、closure、migration/export/GC。
- `internal/v2/state/`, `internal/v2/config/` -- UUID/layout、Generation/retained/target state、`sow/v3`。
- `internal/v2cli/`, `internal/publish/` -- 新命令；仅复用 V1 低层 transport/CAS，另建 V2 plan/state。
- `test/compat/`, `test/poc/`, `design/next/` -- client/target/fault fixtures 与证据。

## Tasks & Acceptance

**Execution:**
- [x] 实现 Pool/RPM href resolver、C2-free renderer/checker/preview，并守住 APT encode-once/by-hash。
- [x] 升级 schema/config/version；实现 UUID、Generation wire、retained wire 与 forward-only transition。
- [x] 实现上述 CLI、export、local GC、filesystem/R2 publish/recovery；R2 delete 固定 disabled。
- [x] 更新 golden 与现行设计/实现证据；历史 v0.2 PoC 保留为历史，不改写成 next PASS。
- [ ] 完成 pinned live-client、completed-export reposync 与获授权真实 R2 release evidence。

**Acceptance Criteria:**
- Given terminal Repository，when `check`/`changes --base 0`，then 与真实 `pool/ + dists/` 精确一致且 `dists/` 无 payload。
- Given mixed APT/RPM、特殊路径与 non-root prefix，when file/HTTP 消费，then encode-once/checksum/install 通过；default reposync 只要求 export 通过。
- Given crash/drift/multi-target/R2，when migrate/publish/gc 重放，then owner、checkpoint、grace、CAS 不串 target且不发生未经证明的删除。
- required next matrix 有可复现证据；无真实凭据的 live target 保持 UNVERIFIED。

## Spec Change Log

## Design Notes

`snapshot/channel` CLI、跨 workspace adoption、default reposync 与 R2 physical GC 是非目标；retained、R2 report-only publication 与 export 不能删减。

## Verification

**Commands:**
- `go test ./internal/aptrepo ./internal/yumrepo ./internal/v2/...`；分片执行全量与 race。
- `go vet ./... && go mod verify && go mod tidy -diff`；四目标 `CGO_ENABLED=0 go build ./cmd/sow`。
- next client、reposync negative/export positive、relocation、migration crash、filesystem/MinIO/获授权 R2 fixtures。
- design linter/clean delivery；自审后以 `claude-code fable-5 max` 至多两轮对抗性 Review。
