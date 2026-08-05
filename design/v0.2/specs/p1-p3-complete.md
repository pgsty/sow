---
title: 'SOW V2 P1 P2 P3 完整落地与验收'
type: 'feature'
created: '2026-08-02'
status: 'complete'
baseline_commit: '50f183cc8125d09199dcdf38eec4fd86eeb338bf'
review_loop_iteration: 1
context:
  - '{project-root}/_bmad-output/specs/spec-sow-v2-p1-p3/SPEC.md'
  - '{project-root}/_bmad-output/specs/spec-sow-v2-p1-p3/acceptance-matrix.md'
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-31/api-contract.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** P0 已能创建简单 RPM/DEB 仓库，但长期 Managed 仓库仍需把 P1 控制面、P2 mutation/recovery 与 P3 verification/handoff 做成同一个封闭、可恢复、真实客户端可消费的产品闭环。仅有命令、元数据文件或旧测试报告不能证明完成。

**Approach:** 以 canonical SPEC、acceptance matrix 和 adopted API contract 为唯一公共契约，在当前 checkout 中补齐实现与缺口测试，并用普通/race/static/clean-delivery、真实 APT/DNF、传统工具语义对照、签名、故障恢复和安全 `repo2` 规模副本逐层验收。

## Boundaries & Constraints

**Always:** 保持 Plain/Managed 隔离；所有公共状态采用 Desired Revision、Built Generation、Operation Journal 和物理 manifest；stage/validate/fsync 后 pointer-last；`changes` 必须可被外部消费者按 payload/metadata/pointer/delete 顺序执行；每项完成声明绑定当前源码 fingerprint、命令、退出码、日志与 retained lab。

**Ask First:** 只有 adopted API 仍无法消解公共行为冲突、真实客户端证明既定布局不可用，或必须扩大到远端发布/GC 等阶段一外能力时暂停。

**Never:** 不写、不挂载、不签名或发布 `/Users/vonng/pgsty/repo`；`/Users/vonng/pgsty/repo2` 只读；不引入 modulemd、route、sync/publish、remote endpoint、GC、SRPM/DSC、服务化多写或 Web UI；未经授权不 commit/push。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|---------------|----------------------------|----------------|
| Managed mutation | 合法/损坏 RPM 或 DEB 混合批次 | 合法项确定性提交并默认形成完整新代 | 部分成功 exit 3，JSON 保留 committed result；全失败拒绝 |
| Build/recovery | dirty Desired 或任一 durable crash point | 公开树只呈现完整旧代或新代，重跑幂等收敛 | 矛盾 journal/stage/identity 进入 integrity error，不猜测修复 |
| Verification/handoff | clean/dirty/recovering/error 与任意保留 base | status 便宜只读；check 全层只读；changes 可重建精确树 | recovering/error 不输出同步计划；prune 不伤恢复或 Generation |
| Repository clients | repo2 只读包副本、file/HTTP、签名开关 | APT/DNF query/download/checksum/install/reposync 与传统工具语义等效 | 客户端或签名失败保留日志并保持旧公开代 |

</frozen-after-approval>

## Code Map

- `internal/v2cli/` -- 封闭 P0–P3 命令树、参数矩阵、退出码与稳定 JSON envelope。
- `internal/v2/{config,state,managed}/` -- strict config、SQLite journal、包/Membership、Generation、查询、校验、签名与恢复。
- `internal/{aptrepo,yumrepo}/` -- DEB/RPM 包事实、metadata 编码与语义校验原语。
- `test/compat/` 与 `test/poc/` -- clean-room、真实客户端、传统工具对照和安全实验。
- `_bmad-output/specs/spec-sow-v2-p1-p3/`、`docs/evidence/` -- canonical contract、traceability 与分层验收报告。

## Tasks & Acceptance

**Execution:**
- [x] `internal/v2cli/`, `internal/v2/config/`, `internal/v2/managed/` -- 闭合 P1 Workspace/Repository/Dist/architecture 与公共 API。
- [x] `internal/v2/state/`, `internal/v2/managed/` -- 实现 P2 immutable objects、Membership/policy/add/rm/pending、partial success 与逐阶段恢复。
- [x] `internal/v2/managed/`, `internal/{aptrepo,yumrepo}/` -- 实现 P3 query/status/build/check/signing/Generation/changes/log，并闭合 Dist lifecycle Changeset。
- [x] `test/compat/`, current checkout -- 完成 ordinary/race/vet/static/clean-delivery/四目标构建与洁净来源复现。
- [x] `/Users/vonng/repo` retained labs -- 完成 repo2 客户端、传统工具、签名、规模、changes consumer 与 prune 验收。
- [x] `_bmad-output/specs/spec-sow-v2-p1-p3/`, `docs/evidence/` -- 写入 source fingerprint、逐层结果、traceability、限制与只读生产观察。

**Acceptance Criteria:**
- Given 任一公开 P1–P3 命令，when 执行 help/negative/API sweep，then 仅 adopted 参数可见且失败前不产生状态。
- Given 任一 durable phase，when 进程被 SIGKILL 并由下一写命令恢复，then 客户端只能观察完整旧代或新代，journal 与 stage 最终清空。
- Given clean Repository，when 外部消费者执行 `changes 0` 或增量 Changeset，then 按四 phase 得到与 `pool/ + dists/` 文件、size、SHA-256 完全相同的树。
- Given 当前只读 repo2 快照，when SOW 与 `createrepo_c`/`dpkg-scanpackages` 分别建库并由真实客户端消费，then normalized package semantics、签名与事务结果一致且 clean rebuild 不超过 120 秒。
- Given全部验收完成，when 比较开发前后生产路径指纹，then生产路径不变，并且没有 commit、push、远端发布或生产签名行为。

## Spec Change Log

- 2026-08-02：完成 P1-P3 实现与一次本地 adversarial review；修复 portable Pool 大小写碰撞、旧 unsigned signing snapshot、空仓库 HTTP 验收与 scale changes 断言；以当前 source fingerprint 的 ordinary/race/fuzz/crash/repo2/scale/clean-delivery 证据封口。

## Design Notes

Dist lifecycle 与 package build 必须共用同一 Generation ledger；任何推进 `built_generation` 的物理变化都同时原子记录 manifest、前代、operation 与 phase-ordered Changeset。`status` 只读便宜状态，`check` 才读取并哈希完整公开树，二者不得互相 impersonate。

## Verification

**Commands:**
- `go test -count=1 -timeout 60m ./...` -- 全部 package PASS，exit 0；最终 log SHA-256 `82537797709f96a0ebf29e9a27296e3a5e2658047d354dc7899900cdece89ec0`。
- V2 race、`go vet ./...`、`staticcheck ./...`、5 个 10 秒 fuzz/property、`gofmt -l` 与 `git diff --check` -- 全部 PASS。
- `test/compat/test-clean-delivery.sh <retained-out>` -- 两次归档 byte-identical；两份解包均完成 tidy/download/verify、clean-room test 与 binary build。
- repo2/传统工具/签名/客户端：`/Users/vonng/repo/sow-v2-repo2-ordinary.o0JiLR`，run log SHA-256 `f4f2731c4f66fde0814c94d735a9a8282ecc541d324be698d09fddd175911f36`。
- SIGKILL/prune/WAL：`/Users/vonng/repo/sow-v2-p1p3-crash-final.ft3pET`，run log SHA-256 `cb3625e32e8070e3cd97f4a7b7575bdd2b743b94e6e29718100d14a603fdd44b`。
- 34,184-package scale：`/Users/vonng/repo/sow-v2-scale-final.lzOCQF`，54/54 rebuild <=120s，worst 101.300s，run log SHA-256 `c05f3cbfe7090cdab41153537d5bdc60c603eb100f2be192f0dbf8acccac1349`。
- 汇总与逐条追踪：`docs/evidence/2026-08-02-sow-v2-p1-p3-{acceptance,traceability}.md`；最终证据索引：`/Users/vonng/repo/sow-v2-p1p3-completion-final.20260802/final-evidence.sha256`。
