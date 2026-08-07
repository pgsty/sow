# SOW V2 P0/P1 requirement traceability

> **历史追踪矩阵，已被后续 P1–P3 工作取代。** 本文只说明 2026-08-01 的 P0/P1 命令与证据身份；它不代表当前 checkout 的 CLI、schema、signing 或 P2/P3 状态。当前完成判定必须引用最终 P1–P3 traceability。

> C2/reposync 行属于 v0.2 证据，不是前向 requirement；下一版矩阵见 [`../../next/specs/acceptance-matrix.md`](../../next/specs/acceptance-matrix.md)。

日期：2026-08-01
状态：当前 checkout 的 P0 Plain 源码与验证证据闭合；整个 P0/P1 目标仍受生产目录零修改证明失效及旧 V1 全包累计测试时限约束。
汇总报告：[`2026-08-01-p0-p1-acceptance.md`](2026-08-01-p0-p1-acceptance.md)

## 1. 证据身份

| 对象 | SHA-256 |
| --- | --- |
| API contract | `ed51f6a278e040e7acd6509870210d318e4a77ac1d0ef2a4e77c7322bbbf69c2` |
| PRD | `4657d0c9f181bb75306644f8fd0acc91b008f4eebbd2e2cc41c38208106f5937` |
| addendum | `7e40308b78b879fa1893c8ccaba3856b296e6b3bf0d91db158782fa803056270` |
| Plain relevant Go source | `f43b9074706c6edee0a5fd8e5719ceaac5bcff64cabc0e8f67ba36ff712804b7` |
| Managed/V2 relevant Go source | `02d27d8a4bbdd94a447c10600b14440fde3fd76cf91f9934eb6f1f529fdf3b53` |
| historical full `go test ./...` PASS log | `950a0f72744b69ab27ee3738f1cc8ad66f937cb3f4b2646970cfdcbb5a5532ec` |
| current P0 targeted log | `8aa039f8ffebad1e72611956e45912203d016740f1cb8fa0036ab8cc8b6211b2` |
| current P0 native race log | `3bd85d826d004cf417aac27fc94eea1f58032ebe6b0ae0f316f648a7a67fc352` |
| current P0 clean-delivery log | `2846621c0cb662eae7f992d47dfb895a7c7f425ed00e10fb8cd4bb8fac1effcc` |
| current legacy V1 10/20-minute timeout logs | `f0a5126e90e7fe89d7016b48d8b3ac292765f331852ea4d535b5eea41854450e`, `22f2ce5bc53f6983da3c2a26d2efd9cad2f1a22ba688edc65d02d79c5e08f233` |
| completion-audit log | `4cc64104d8e4d033d289045b1118ffec0970a5fe0f27e230dcd85eb08e1907dc` |
| clean-room production-binary log | `df0498d03fc15c638ec4b72f1951a5b1e7f75c936989c8d2c2b7ae5ea752da10` |

源 fingerprint 是目标目录下全部 Go 文件的稳定排序 SHA-256 清单再哈希。Git HEAD 为 V1 基础 commit，不能单独标识未提交的 V2 实现。

## 2. 公共 CLI preservation

机器契约由 `internal/v2cli/parse.go` 的 closed `commandSpecs`、`help.go`、`errors.go` 和对应测试共同固定。

| 命令 | 契约参数 | 当前证据 | 判定 |
| --- | --- | --- | --- |
| `create` | `[DIR] -j/--jobs --pigsty -S/--sign-with KEY [--overwrite] -T/-N --json` | `TestParseCreateDefaultsAndOptionsAnywhere`, signing option guards, `TestLeafHelpMatchesClosedOptionMatrix` | exact；`--overwrite` 不能单独出现 |
| `init` | `[DIR] --json` | `TestParseClosedGlobalMatrix`, leaf-help test | exact；不接受 `-T/-N` |
| `config check` | `-C --json` | closed-global 与 leaf-help tests | exact |
| `config show` | `--all -C -r -d... --json` | local-matrix、scope 与 leaf-help tests | exact |
| `repo ls` | `-C --json` | closed-global 与 leaf-help tests | exact |
| `repo new` | `NAME -C -T/-N --json` | local/lock matrix 与 leaf-help tests | exact |
| `repo show` | `[NAME] -C -r --json` | `TestParseRepoShowPreservesNameAndExplicitRepository` | exact |
| `repo rm` | `NAME -f/--force -C -T/-N --json` | local-matrix、leaf-help、lifecycle tests | exact |
| `dist ls` | `-C -r --json` | closed-global 与 leaf-help tests | exact |
| `dist new` | `NAME --format rpm|deb -C -r -T/-N --json` | required-format/cardinality 与 leaf-help tests | exact；无 architecture 参数 |
| `dist show` | `NAME -C -r --json` | local-matrix 与 leaf-help tests | exact |
| `dist rm` | `NAME -f/--force -C -r -T/-N --json` | local/lock matrix、leaf-help、lifecycle tests | exact |
| `help/version` | 封闭 topic/version | help snapshot/tree/version tests | exact |

`TestHelpTreeIsExactlyP0P1` 固定唯一活动 topic 集；`TestMainHelpVersionAndClosedSurface` 通过实际 dispatcher 拒绝 P2/P3 与 V1 topic。root help 实际输出与 golden 字节一致，SHA-256 为 `d125e04ceed5c1c2947186372ea38fdd9ebdf29f017e8a04c36223bbed14eeb6`。

退出码 `0..6`、JSON `sow.cli/v1` envelope、非零退出时保留已提交 partial result 分别由 `errors_test.go`、`output_test.go`、`app_test.go` 固定。未记录的 exit code 会降级为 runtime 1，不能被伪造成成功。

## 3. P0 Plain Create

| # | 要求 | 主要源码/自动化证据 | 外部或结果证据 | 判定 |
| ---: | --- | --- | --- | --- |
| 1 | 只扫描顶层 regular `.rpm/.deb` | `scan.go`; `TestCreateDEBFlatRegularOnlyStable`, `TestCreateRPMFlatAndMixed` | clean offline lab 只 hardlink 顶层 package | 通过 |
| 2 | 不递归、不跟随 symlink、忽略未知文件 | `Lstat` regular gate；APT/RPM symlink negative tests | Plain real-client fixture | 通过 |
| 3 | RPM-only、DEB-only、mixed | `TestCreateRPMFlatAndMixed`; Plain PoC 三目录 | DNF/APT 对三种目录消费 | 通过 |
| 4 | RPM `repodata/` 可消费 | `GenerateFlatUnsigned` 与 validator tests | DNF/YUM makecache/query/download/install | 通过 |
| 5 | DEB `Packages`/`Packages.gz` 可消费 | flat writer/validator/gzip tests | APT update/policy/download/install | 通过 |
| 6 | flat location 只用 basename/`./basename` | RPM/DEB flat validators；`TestPackageLocation` | offline metadata location 零差异 | 通过 |
| 7 | 全部 header 架构与有效版本 | RPM header-only authority tests；DEB parser tests | 1,355 RPM + 978 DEB 全量对照 | 通过 |
| 8 | 同坐标不同内容硬失败 | RPM/DEB coordinate-conflict tests | exit 6 mapping test | 通过 |
| 9 | 默认不改、签、移、删包 | default create tests；无 signing 调用 | input package SHA/byte compare | 通过 |
| 10 | 默认不生成 `repo_complete` | `TestCreateDEBFlatRegularOnlyStable` 等 | Plain PoC assertions | 通过 |
| 11 | 既有 marker 在改索引前失败 | `TestCreateRejectsMarkerBeforeMetadataChange` | exit 6 | 通过 |
| 12 | 不生成/透传/验证 modulemd | 三个 modulemd/opaque-extra tests | output tree inspection | 通过 |
| 13 | `-j` 默认逻辑 CPU，结果确定 | parser default、jobs deterministic、parse-error selection tests | repeat manifest byte stable | 通过 |
| 14 | 同 FS stage 后验证、安全切换 | render/journal/rollback tests | crash matrix | 通过 |
| 15 | 失败保留完整旧索引 | parse/pointer/persistent-failure/preimage tests | crash matrix old-or-new invariant | 通过 |
| 16 | 重跑 no-op 或等价 | deterministic/golden tests | RPM/DEB repeat `noop=true`; manifest diff 0 | 通过 |
| 17 | mixed 是一个 Operation | mixed pointer/process termination/format-removal tests | mixed DNF+APT 同目录消费 | 通过 |
| 18 | `-S/--sign-with KEY` 只补签未签名 RPM | `TestCreateSignWithFillsOnlyUnsignedRPMs`；结构签名检查 | 76 已签名 SHA 不变，11 未签名改变并验签 | 通过 |
| 19 | 与 `--overwrite` 组合重签全部保留 RPM | overwrite unit/CLI tests；生产 adapter 使用 `rpm --resign` | 同 key 87/87 走重签；异 key 3/3 改写并由新 key 验签 | 通过 |
| 20 | key 只接受可选 `0x` + 16/40/64 hex | normalize/usage/DEB-only tests | short ID 与 full fingerprint 均真实执行 | 通过 |
| 21 | 签名只改私有 stage，最终字节先于 rpm-md | signature-neutral digest、NEVRA、完整 mode/UID/GID、duplicate-byte 与 journal v5 tests | 最终 package SHA 进入 rpm-md；DNF 查询与 `createrepo_c` 及当前 repo2 对照一致 | 通过 |
| 22 | signer/stage/commit 失败保留公开旧态 | sign failure、journal input/recovery/fault tests | 不存在 key 的真实失败保持包与 repomd pointer、无 journal | 通过 |

### 3.1 `--pigsty`

| # | 要求 | 主要证据 | 判定 |
| ---: | --- | --- | --- |
| 1 | RPM i386/i486/i586/i686、DEB i386 按 header 删除 | `TestCreatePigstyExactCleanupAndSHA256Marker` | 通过 |
| 2 | 只命中 binary name `patroni` + upstream `3.0.4` | exact-cleanup test | 通过 |
| 3 | RPM 只比较 VERSION | `shouldRemove` + exact fixtures | 通过 |
| 4 | DEB 去 epoch/revision，`3.0.4+foo` 不命中 | `debianUpstreamVersion` fixtures | 通过 |
| 5 | 不用宽泛 filename glob | renamed RPM/header-authority tests | 通过 |
| 6 | package 先同 FS rename 到 recovery trash | journal action validation + process crash tests | 通过 |
| 7 | 新索引不引用删除集 | exact cleanup、all-removed、client validator tests | 通过 |
| 8 | 新 marker 最后原子换入 | marker-before/after fault matrix | 通过 |
| 9 | marker 为稳定 basename 排序 SHA-256 | exact marker test + retained marker hash | 通过 |
| 10 | 成功后才清 trash/journal | completed-journal partial-cleanup tests | 通过 |

`TestCreatePigstyFaultRecoveryMatrix` 与三个真实子进程 termination matrix 覆盖 journal 持久化、旧 marker 撤下、RPM/DEB pointer 前后、每个 package rename、新 marker 前后；重跑只接受完整旧态或完整新态。

## 4. P1 Managed Control Plane

| # | 要求 | 主要源码/自动化证据 | 外部或结果证据 | 判定 |
| ---: | --- | --- | --- | --- |
| 1 | 根级固定 `sow.yml` | config constant、init tests | retained Workspace tree | 通过 |
| 2 | `.sow/` 与 Repository 并列 | fixed-layout/path tests | Managed fixture tree | 通过 |
| 3 | 一个 Workspace 多 Repository | repository lifecycle/selection tests | public CLI lifecycle test | 通过 |
| 4 | 每 Repository 独占 DB/private/pool/dists | fixed path、state/layout tests | `.sow/local.db` + `local/{pool,dists}` | 通过 |
| 5 | 跨 Repository 不去重 | DB/pool 均为 Repository-owned，P1 无跨仓引用表或公共 mutation | dependency/layout audit | 通过 |
| 6 | Repository 路径固定且不可自定义/逃逸 | `RepositoryPath`、adoption/symlink/derived-name tests | 通过 |
| 7 | discovery：workdir → cwd → `SOW_DIR` | discovery priority/fallback/environment tests | CLI fallback test | 通过 |
| 8 | `--workdir` 不改变 cwd 相对语义 | no-chdir 与 inference-start tests | CLI workdir test | 通过 |
| 9 | repo 选择：显式 → cwd → 唯一 → fail | selection priority matrix | dispatcher test | 通过 |
| 10 | 单一 force；protected 不可绕过 | parser duplicate rejection + lifecycle test | 通过 |
| 11 | Dist 是普通可变具名集合 | strict schema 无特殊 state-machine field | list/new/show/rm tests | 通过 |
| 12 | 每 Dist 单一 format | strict config + required-format tests | 通过 |
| 13 | `dist new` 无架构参数，继承有效架构 | closed parser + effective architecture tests | Managed JSON result | 通过 |
| 14 | 空 Dist 有真实可消费索引 | empty renderer/validator tests | DNF/YUM/reposync + APT | 通过 |
| 15 | `dist rm -f` 删 membership/index、不删 Pool | membership gate/pool preservation + crash tests | 通过 |
| 16 | 默认 canonical `x86_64/aarch64` | config default tests | Managed JSON result | 通过 |
| 17 | RPM/DEB alias 正确映射 | config/renderer tests | x86_64/aarch64 与 amd64/arm64 client views | 通过 |
| 18 | `noarch/all` 是 neutral projection | canonical-state and neutral tests | YUM relative-Pool native+noarch | 通过 |
| 19 | 未支持架构不静默扩展 | strict config/render rejection tests | 通过 |
| 20 | 移除被 state 引用架构失败 | every-write/state-reference/membership-reference tests | 通过 |
| 21 | lifecycle 有锁/journal/重跑/路径防逃逸 | lock matrices、Workspace/SQLite crash matrices、symlink/adoption tests | subprocess recovery | 通过 |
| 22 | `config check` 只读且严格 | read-only/scratch/unknown-field/state-aware tests | filesystem no-change assertions | 通过 |
| 23 | `config show --all` 展开且不泄密 | effective-view/no-signing-surface/app scope tests | JSON/human output tests | 通过 |

`init` 的默认创建、已有合法声明补齐、部分初始化续跑、已有有效对象不重置、缺失 built view 不重置等行为由 `TestInitDefaultIsIdempotent`、`TestInitCompletesDeclaredStateWithoutReset`、`TestInitReturnsCommittedProgressOnLaterFailure`、`TestInitRejectsMissingBuiltViewInsteadOfResetting` 固定。

P1 SQLite schema/migration 由 embedded `schema_v1.sql`、完整 migration ledger/DDL 认证与 `TestOpenMigratesAndIsIdempotent`、future/checksum/sidecar/hot-WAL tests 固定。P1 允许的 Dist Operation kind 只有 `dist.new`、`dist.init`、`dist.rm`；`TestDistRecoveryRejectsUnsupportedKindAndConfigForgery` 证明未来或伪造 `dist.arch.add` 在执行 payload 前失败。

## 5. 真实客户端与构建门禁

| 门禁 | 当前 checkout 证据 | 判定 |
| --- | --- | --- |
| Plain RPM/DEB/mixed | `/Users/vonng/repo/sow-v2-plain-clients.IC4VHX`, log SHA `28525cd5c853dc564eef01b8a261bebc1b7ece8415d25d76cb1f3af2f6740bad` | 通过 |
| 全量 RPM vs `createrepo_c` | 1,355/1,355；DNF/YUM query/download/install；SOW log SHA `d3121fd93d3e9b63c7d8f049f0fb87a54207cf101eee9ff15481f2cc3d0e0560` | 通过 |
| 全量 DEB vs `dpkg-scanpackages` | 978/978；APT update/download/install；SOW log SHA `dc56e891bbd56deef9bbb18aa27f8babf1f970a292b61ce424821534f75ebea0` | 通过 |
| RPM 补签/重签 | 当前 binary SHA `ab7905bd25389fd073deb287d5d297445fb6c572dbc4504d96d5ac3ce26267d3`；87/87 `rpm --checksig`；DNF `gpgcheck=1` install；异 key overwrite 3/3 | 通过 |
| 签名后 RPM vs `createrepo_c` | 两边 DNF `NEVRA|location` 87 行逐字节一致，SHA `5cab1fa2e41e7a372eadba31d0707fe8255117f7ff02ccbab8ba9cce58e2fe41` | 通过 |
| 当前 repo2 普通 RPM/DEB | `/Users/vonng/repo/sow-p0-repo2.MnnsY6`；207 RPM 对 `createrepo_c`、92 DEB 对 `dpkg-scanpackages --multiversion` 全字段零差异；file/HTTP DNF/APT 下载安装；重复创建 metadata 不变 | 通过 |
| 当前 repo2 签名/换 key | 未签包补签、已签包保留；Percona key `9334…EFA5` 经 `--overwrite` 换为 Pigsty `E793…8B20`；5/5 `rpm -Kv`，DNF `gpgcheck=1` 安装 | 通过 |
| Managed empty RPM/DEB | `/Users/vonng/repo/sow-v2-managed-empty.cPmqri`, log SHA `d223f06250fba3db3349761bf338aaaa3964038099693899a213357190b64128` | 通过 |
| YUM relative Pool | 原 `../../../pool` 被 reposync 否决；C2 view-local `pool/...` 通过，log SHA `1315965767874fe7af543ad00b2e85c230139b661b0808e961d86874f1fe72b4` | 通过 |
| darwin/linux × amd64/arm64 | 四个最终 binary 均经 `file` 复核；哈希见汇总报告 | 通过 |

## 6. P2/P3 非实现边界

- 活动 CLI、help 和 parser 不注册 `add`、package `rm/ls/show/where`、`status/build/check/changes/log`。
- strict `sow.yml` 拒绝 `limit/exclude/policy/signing/trusted_keys`；CLI 拒绝 `--skip` 与其他 P2/P3 flag。
- `package_objects`/`memberships` 空表、renderer 非空输入能力与 Managed signer source 只是内部扩展点，没有 package mutation 命令、Managed signing 配置或 dispatcher 调用；Plain `create --sign-with` 是单独的 P0 窄入口。
- `go list -deps ./cmd/sow` 共 283 项，SHA-256 `e7967014654dc997cda8ec75dfd16111cfc0a1f3100aee2e440308e492a05caf`；不含 V1 CLI/state/catalog/repository、publish/sync/provider/edge 或远端 SDK。
- 没有 modulemd、Git canonical、CAS/view/snapshot/remote generation、provider、CDN、对象存储或发布 saga 进入 V2 活动路径。

## 7. 证明边界

源码、自动化测试、容器客户端、交叉构建、生产目录和外部发布是独立证据层。当前前六节证明 P0/P1 源码与本地验收闭合；它们不能覆盖汇总报告第 8 节记录的生产目录 metadata 变化，因此整个目标仍不得标为完成。没有执行 commit、push、upload 或 publish；签名只发生在 retained disposable lab，未触及生产仓库。
