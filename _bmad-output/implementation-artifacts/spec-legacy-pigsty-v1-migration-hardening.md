---
title: 'Pigsty-v1 存量仓库迁移硬化'
type: 'feature'
created: '2026-07-12'
status: 'completed'
review_loop_iteration: 2
baseline_commit: '84800a60e01aaaf8dc5b189c3ddb1380930f4865'
context:
  - '{project-root}/_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/prd.md'
  - '{project-root}/docs/migration/make-target-map.md'
  - '{project-root}/docs/migration/runbook.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** 现有迁移账本虽然枚举了 176 个旧 target，但命令模板未绑定 schema-valid 的真实 Pigsty-v1 拓扑；content adoption 只接受 SOW 自己生成的 suite-root APT 与 `Packages/<首字母>/` YUM，无法纳管真实的 suite-nested APT 和 flat-RPM YUM，也缺少逐操作族 selector 与旧 writer 撤权证据。

**Approach:** 增加非秘密 Pigsty-v1 迁移配置与真实旧布局夹具；在已校验 repomd→primary 成员链和 RPM body 的前提下把安全 flat href 映射到 canonical `Packages/<首字母>/`，同时记录 source/canonical 双路径；把 44 操作族、176 target、writer fence 和本地切换/回滚变成 fail-closed 可执行验收。

## Boundaries & Constraints

**Always:** 默认 `sow init` 与 adoption 零服务字节改写语义不变；APT repo 按 suite、YUM repo 按 EL major 使用唯一 ID；source path 与 canonical destination 同时进入确定性 receipt；flat YUM 只接受 basename 或既有 canonical href；所有包必须被已校验索引逐项证明，canonical collision、逃逸、未列 RPM、篡改均在 ref/ledger 提交前失败；旧仓 `/Users/vonng/pgsty/repo` 只读。

**Ask First:** 真实 origin/Nginx 切换、云凭据、旧凭据撤销、生产 writer 停机或任何会修改旧仓/远端的动作。

**Never:** 修改 `materialize_serving*.go`；把 modulemd/sqlite repodata 纳入产品；放宽路径、签名、机密性或 frozen 门禁；用 canonical 测试树冒充 Pigsty-v1；把本地 writer-fence 夹具冒充生产撤权。

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| suite-nested APT | `apt/pgsql/jammy/dists/jammy` + per-suite repo ID | adoption 不改源树，candidate 保持 legacy latest 根并生成标准 metadata | 缺索引、body/hash/path 不一致则 canonical 零推进 |
| flat YUM | primary href=`foo.rpm`，源文件位于 leaf 根 | CAS 从 flat source 导入；view/candidate 使用 `Packages/f/foo.rpm`；receipt 绑定两路径 | slash 变体、逃逸、collision、未列 RPM、篡改全部拒绝 |
| mapping closure | 四 Makefile + 44 family 表 + migration config | 176 target 恰好一次归族；CLI replacement selectors 均解析为预期 leaves；alias 依赖集合有黄金断言 | source/map/config/selector 漂移非零退出且不产证据 |
| writer fence | 冻结声明、进程/container/权限证据 | 只读 preflight 生成无秘密报告并可重放 | 可疑 writer、缺声明或不完整 probe 非零退出 |
| rollback | 零字节 baseline→candidate→坏候选→旧 root | candidate 移出 origin 后全树摘要恢复且重复回滚幂等 | 不允许同时恢复旧 writer 与保留 SOW writer |

</frozen-after-approval>

## Code Map

- `internal/cli/adopt_content.go` -- 区分 physical source 与 canonical view path，实施 flat YUM 规范化与冲突门禁。
- `internal/provenance/legacy.go` -- 向后兼容的 source/canonical 双路径 receipt。
- `internal/cli/adopt_content_test.go` -- suite-nested APT、flat YUM、零改写、candidate 与负例。
- `docs/migration/fixtures/pigsty-v1.yaml` -- 无秘密、schema-valid 的 per-suite/per-major 迁移矩阵。
- `docs/migration/audit-legacy-targets.sh`、`test-audit-legacy-targets.sh` -- 44/176 family 与真实 selector closure。
- `docs/migration/writer-fence-preflight.sh`、对应测试 -- 旧 writer 撤权前置证据。
- `docs/migration/{make-target-map.md,runbook.md}`、`docs/evidence/` -- 可复现命令、批准的 flat→canonical 变换与诚实边界。

## Tasks & Acceptance

**Execution:**
- [x] `internal/cli/adopt_content.go`, `internal/provenance/legacy.go` -- 实现 source/canonical 双身份和 flat YUM 迁移。
- [x] `internal/cli/adopt_content_test.go`, migration fixtures -- 建立真实旧布局 CLI E2E、collision/escape/unlisted/tamper 负例和 rollback。
- [x] migration audit scripts/tests -- 机械闭合 44 family/176 target，绑定 schema-valid config 并验证 alias selector leaves。
- [x] writer-fence script/tests -- 建立 fail-closed、无秘密的撤权 preflight/evidence。
- [x] migration docs/evidence -- 刷新映射、runbook、摘要与当前通过/受阻边界。

**Acceptance Criteria:**
- Given suite-nested APT 与 flat YUM Pigsty-v1 树，when 执行真实 CLI adoption/materialize/verify/fsck，then 源服务树逐字节不变、candidate canonical、receipt 双路径精确且回滚幂等。
- Given 旧 target/map/config 任一漂移，when 运行迁移审计，then 44/176、selector leaves、rollback code 或 writer fence 任一不闭合即失败。

## Spec Change Log

- 2026-07-19: ADR-0027 is the accepted superseding decision for the frozen
  block's flat-only source-href restriction. Safe normalized, index-proven
  nested RPM hrefs are accepted while the final canonical layout and all
  escape/wrong-bucket/collision/unlisted/tamper gates remain unchanged. The
  frozen historical wording above is retained rather than silently rewritten.
- 2026-07-19: review hardening moved the 176-target selector audit from the
  synthetic matrix to the complete physical Pigsty-v1 contract and a static
  158-command exact-leaf golden; added same-count drift, arbitrary open
  writable-FD, impossible timestamp, and zero-byte Pro checksum negatives.
- 2026-07-19: the 44-family E2E gate now expands physical repo groups and
  classifies dedicated `compatibility/yum-*` verbs. Mixed-EL replacement
  families bind executable local x86_64 and aarch64
  adopt/candidate/freeze/cutover/rollback state machines instead of treating
  compatibility as an ordinary selector. The physical contract has a dedicated
  EL9 policy owner and two exact compatibility projections; neither the carrier
  nor policy-only owner can leak into an ordinary repo group. The aarch64
  state machine loads that complete checked-in physical config directly.

## Design Notes

`payload` 以 source path 证明 baseline 成员、以 canonical path 建唯一约束；view entry 只携带 canonical path。RPM body inspector 以 basename/NEVRA/hash 验证制品，不能把 primary 的 flat href误当 canonical destination。旧 receipt 缺 `canonical_path` 时按 source==canonical 解码，新 flat adoption 必须显式写出二者。

## Verification

**Commands:**
- `go test -count=1 ./internal/provenance ./internal/cli -run 'Legacy|AdoptContent|PigstyV1|Migration'` -- 真实布局与负例通过。
- `go test -race -count=1 ./internal/provenance ./internal/cli -run 'Legacy|AdoptContent|PigstyV1|Migration'` -- 并发导入无竞态。
- `docs/migration/test-audit-legacy-targets.sh /Users/vonng/pgsty/repo && docs/migration/test-local-adoption-rollback.sh && docs/migration/test-writer-fence-preflight.sh` -- 迁移脚本通过且旧源未改。
- `go vet ./internal/provenance ./internal/cli && git diff --check` -- 静态与补丁检查通过。

**2026-07-12 result:** normal/race targeted suites、`go vet`、44/176 negative audit、asset/package rollback 与 writer-fence suites 全部退出 0；旧 `/Users/vonng/pgsty/repo` clean，七个固定输入摘要未变。真实生产 IAM/Nginx/双云门禁仍按总 Goal 保持未通过，不属于本 spec 的本地通过声明。

**2026-07-19 review-hardening result:** physical-selector focused and race
suites, 21-case macOS `lsof` / 20-case Linux procfs writer fence, physical
fixture, 176-target audit, 44-family
contract with 16 executable tests, local adoption/rollback, `go vet`, patch
check, full `go test ./...` (`internal/cli` 1202.757s), and clean-delivery
archive all passed. The old repo was read only and
its pre-existing user modification remained untouched. No cloud or production
mutation was performed; those Goal-level gates remain open.
