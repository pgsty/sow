# P1–P3 acceptance matrix

每一行都需要绑定最终 checkout 的源码 fingerprint、命令、exit code、日志 hash 和 retained lab；旧报告只能作回归线索。

## P1 — Managed Control Plane

| Gate | Required proof |
| --- | --- |
| Closed CLI/config | help/negative sweep 精确覆盖 API 参数矩阵；未知 flag/config key 不产生状态 |
| Discovery/selection | `-C → cwd → SOW_DIR`、最近祖先、repo/dist 推断与歧义分支全覆盖 |
| Repo/Dist lifecycle | init/repo/dist CRUD、protected/force、固定路径、symlink/escape、workspace/repository journal crash matrix |
| Architecture | canonical aliases、许可上限、Dist 子集、neutral fan-out、移除在用架构拒绝、新增架构 dirty |
| Empty clients | RPM/DEB 双架构空 view 经 file/HTTP DNF/APT refresh/query；C2 fixture 经 native/neutral install 与 reposync |

## P2 — Mutation and Recovery

| Gate | Required proof |
| --- | --- |
| Immutable ingestion | regular-only/recursive scan、private immutable snapshot、RPM/DEB coordinates、SHA-256、pool path、same-coordinate conflict |
| Managed RPM signing | never/fill/always、trusted/current key、signature-neutral retry、same unsigned input across time、missing key/agent failure、secret redaction |
| Membership and partial success | multi-Dist/format/arch routing、same object dedup、mixed valid/invalid batch、exit 3 and complete JSON committed result |
| Policy | closed config, classifier golden, exact/glob truth table, exclude-before-Limit, RPM EVR/Debian version, policy edit reconcile/no resurrection |
| Remove | exact refs/name-wide semantics, ambiguity/no-match, `--check` byte-for-byte purity, default/`--skip` behavior |
| Desired/Built/pending | public tree unchanged under `--skip`, pending durability, dropped-unreferenced cleanup, selective build and no-op Generation |
| Recovery | planned/staged/applied/payload/metadata/pointer/changeset/finalize kill points; old/new client consistency; repeat recovery idempotence |

## P3 — Verification and Handoff

| Gate | Required proof |
| --- | --- |
| Query/status | ls/show/where exact and ambiguous lookup; dirty deltas; status cheap/read-only in all four states |
| Build | multi-Dist single Generation, per-view pointer-last publish, package-before-metadata ordering, config fingerprint/no-op behavior |
| Metadata signing | RPM unsigned/signed repomd behavior; APT Release always and configured InRelease/Release.gpg; key rotation dirty; bad key zero public effect |
| Check | config/DB/pool/pending/package/signature/membership/index/view layers; clean, dirty, recovering, error; no mutation/repair |
| Generation/Changeset | monotonic only on physical change; manifest equals public tree; net diff and all four phases; base validation; recovering/error refusal |
| Log | list/detail/dist filter, deterministic JSONL export, terminal-only prune, VACUUM safety, recovery/state/generation/changeset preservation |

## Cross-cutting completion gates

| Layer | Required proof |
| --- | --- |
| Source | gofmt, diff quality, closed dependency graph, reproducible source fingerprint and binary identity |
| Automated | targeted and full active V2 tests, race, vet/static analysis, fuzz/property where parser/policy/version boundaries warrant it, clean delivery |
| Crash/security | real subprocess SIGKILL plus deterministic failpoints; no-follow/root/inode bounds; bounded files/journals/diagnostics; secret scan |
| Portability | darwin/linux × amd64/arm64 build; runtime client containers on both canonical families where images exist |
| Repository semantics | SOW versus `createrepo_c`/`dpkg-scanpackages` normalized metadata and client-visible result, including changelog/dependencies/signatures |
| Real clients | file and HTTP APT/DNF refresh/query/download/checksum/install; DNF reposync over C2; gpgcheck/repo signature verification where configured |
| Scale | safe 34,184-package, about 50.18 GiB clone; cold/warm and clean rebuild timings; peak memory/disk; clean rebuild median and worst retained run at most 120s |
| Handoff | `changes 0` consumer reconstructs exact public tree in phase order; no remote action is performed by SOW |
| Safety | production path never a write target/mount; lab input/output manifests and final production read-only observation are reported separately |

## Completion rule

P1, P2, or P3 is complete only when every row for that stage and every applicable cross-cutting row has current evidence. A generated file, a passing unit test, an old report, or a browser/terminal observation alone is insufficient. Any failed or skipped required row keeps the goal active unless the user explicitly changes scope.
