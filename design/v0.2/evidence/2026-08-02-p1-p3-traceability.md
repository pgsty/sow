# SOW V2 P1/P2/P3 验收追踪

日期：2026-08-02
规范：`_bmad-output/specs/spec-sow-v2-p1-p3/{SPEC.md,acceptance-matrix.md}`
汇总：[`2026-08-02-p1-p3-acceptance.md`](2026-08-02-p1-p3-acceptance.md)
当前 product source fingerprint：`5b9d1b404ea535701ad61648efd55cb713089816e7d1465c9c44655c1cba3aba`

本表按 acceptance matrix 逐行闭合。测试名是当前 checkout 的可执行证明；retained lab 只证明它实际执行时保存的环境和结果，两者不能互相替代。

## P1 — Managed Control Plane

| Gate | 源码与当前自动化 | 外部/retained 证据 | 判定 |
| --- | --- | --- | --- |
| Closed CLI/config | `internal/v2cli/{parse,help}.go`; `TestHelpTreeIsExactlyP0P3`, `TestLeafHelpMatchesClosedOptionMatrix`, `TestParseRejectsUnknownAndDuplicateOptions`; config strict/round-trip tests | completion lab 的 ordinary/clean-room logs | PASS |
| Discovery/selection | `internal/v2/config/discovery.go`; `TestDiscoverPriorityNearestAncestorAndNoChdir`, repository/dist inference/ambiguity、ancestor replacement tests | public CLI lifecycle tests | PASS |
| Repo/Dist lifecycle | `internal/v2/managed/{workspace,repository,lifecycle}.go`; fixed-path/protected-force/symlink tests；Workspace/SQLite journal matrices | crash lab 22 个 lifecycle subprocess points | PASS |
| Architecture | effective/canonical architecture helpers；state reference、neutral fan-out、add/remove dirty tests | repo2 DNF/APT 双 canonical family；C2 client fixture | PASS |
| Empty clients | empty RPM/DEB renderer/validator tests | `/Users/vonng/repo/sow-v2-managed-empty.w4TX1D` file+HTTP 双架构；repo2 C2 install/reposync | PASS |

## P2 — Mutation and Recovery

| Gate | 源码与当前自动化 | 外部/retained 证据 | 判定 |
| --- | --- | --- | --- |
| Immutable ingestion | `ingest.go`, `ingest_facts.go`, `state/objects.go`; regular/no-follow/private snapshot/coordinate/digest/pool-path/collision tests | repo2 6-package managed build；输入 before/after identical | PASS |
| Managed RPM signing | `managed/signing.go`, retained schema v6 key snapshots；never/fill/always、trusted/current key、retry identity、missing key/redaction tests | disposable key；package/repomd 独立 rpm/gpg verify；Plain overwrite | PASS |
| Membership/partial success | whole-set desired mutation、dedup/routing；`TestAddMixedBatchCommitsAcceptedPackagesAndReturnsPartial`, CLI exit-3 tests | repo2 valid+invalid audit；committed JSON preserved | PASS |
| Policy | `policy.go`; classifier golden、exclude truth table、native RPM/Deb ordering、input-order fuzz、edit reconcile tests | forced scale rebuild 18 workspaces uses non-matching policy marker | PASS |
| Remove | exact/name-wide、ambiguity/no-match、check purity、skip/default、recovery tests | ordinary/check/changes suites | PASS |
| Desired/Built/pending | build convergence/no-op/selective/skip/pending/drop-unreferenced tests | scale forced physical generations；repo2 check clean | PASS |
| Recovery | deterministic failpoints plus actual child SIGKILL | crash lab 26 add/rm/build points，old-or-new + idempotent replay | PASS |

## P3 — Verification and Handoff

| Gate | 源码与当前自动化 | 外部/retained 证据 | 判定 |
| --- | --- | --- | --- |
| Query/status | `query.go`, `status.go`; exact/ambiguous/dirty/four-state/hot-WAL/stable snapshot tests | retained public CLI status stress + current race suite | PASS |
| Build | multi-Dist Generation、pointer-last、payload-before-metadata、fingerprint/no-op tests | crash multi-Dist pointer test；scale 54 physical rebuilds | PASS |
| Metadata signing | RPM unsigned/signed/rotation/bad-key tests；APT Release/by-hash/signature tests | repo2 rpm/gpg + DNF gpgcheck + APT signed-by | PASS |
| Check | config/state/pool/pending/package/signature/membership/index/view/manifest layer tests；strict read-only assertions | repo2 post-prune full check；18 Linux scale checks | PASS |
| Generation/Changeset | state generation ledger、manifest equality、net-diff/four-phase/base/recovery refusal tests | repo2 41-file external consumer；scale 18 exact `changes 0` comparisons | PASS |
| Log | list/detail/filter/export/prune/VACUUM/recovery tests | repo2 failed operation export/prune/post-prune check；prune crash lab | PASS |

## Cross-cutting completion gates

| Layer | 证据 | 判定 |
| --- | --- | --- |
| Source | gofmt/diff check；283-item closed dependency graph；source fingerprint；four target hashes | PASS |
| Automated | full ordinary、V2 race、vet、staticcheck、5 fuzz/property、clean-room、clean-delivery；最终清单在 `/Users/vonng/repo/sow-v2-p1p3-completion-final.20260802/final-evidence.sha256` | PASS |
| Crash/security | 26 mutation + 22 lifecycle SIGKILL points；root/no-follow/inode/bounded wire/secret tests | PASS |
| Portability | darwin/linux × amd64/arm64 build；amd64/arm64 APT/DNF runtime clients | PASS |
| Repository semantics | 87 RPM vs `createrepo_c`、181 DEB vs `dpkg-scanpackages`; normalized differences 0 | PASS |
| Real clients | file+HTTP refresh/query/download/checksum/install；C2 reposync；gpgcheck/signed-by | PASS |
| Scale | exact 34,184 / 50.179452850 GiB；54/54 <=120s；worst 101.300s；peak RSS 338,608 KiB | PASS |
| Handoff | `changes 0` 41-file tree SHA `8149d874…`，phase-order consumer exact；no remote action | PASS |
| Safety | repo2 before/after identical；实验只写 retained lab；生产只读观察与既有 `dnfupdate` RW mount 单独披露 | PASS for task actions |

## Review counterexamples closed

| Counterexample | 原问题 | 修复/证明 |
| --- | --- | --- |
| `pool/P` vs `pool/p` | SQLite 可区分、macOS 默认文件系统可能别名 | shard lower-case；case-insensitive collision rejection；State check 与 tests |
| retained signing `{}` | schema v5 unsigned snapshot 被严格 decoder 误拒绝 | 只映射到 RPM package mode `never`；canonical round-trip test |
| empty repository HTTP | 第一版 harness 只测 file client | 当前 harness file+HTTP 双 family，final log SHA `f442597d…` |
| scale `changes` assertion | 第一版脚本检查不存在字段，造成假失败 | 独立比较完整公开树 path/size/SHA 与 phase 顺序；final scale exit 0 |

## Evidence identity

| Evidence | SHA-256 |
| --- | --- |
| crash run log | `cb3625e32e8070e3cd97f4a7b7575bdd2b743b94e6e29718100d14a603fdd44b` |
| repo2 run log | `f4f2731c4f66fde0814c94d735a9a8282ecc541d324be698d09fddd175911f36` |
| traditional comparison JSON | `92ec9766e409451d9acb6e409d3370e74d9629cdca740f0f242e0fad7a9a8c85` |
| scale run log | `c05f3cbfe7090cdab41153537d5bdc60c603eb100f2be192f0dbf8acccac1349` |
| scale summary | `29a4b59f2b47a3157d1cc24c11db1cc8ed7761406541057b3bf1b60a4d1ae0d7` |
| empty client run log | `f442597d3c962e2a6b22d8c09322b88181febd8d70cd9caa38221d734584b607` |
| V2 race log | `285a1ea6e99de28796462883b5dcf6f830172ec482a15d3f8bc569384730b81e` |

`final-evidence.sha256` 是收尾时的唯一最终索引：它包含最终 source manifest、ordinary/clean-room/clean-delivery/static logs、两次生产只读 snapshot 和上述 retained artifacts 的 SHA-256。生成后不再修改产品或验收文档。
