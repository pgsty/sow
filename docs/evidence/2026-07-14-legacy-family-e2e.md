# 44-family 本地迁移闭环证据 — 2026-07-14

## 结论与边界

本轮关闭 G5/MIG-02/MIG-05/MIG-08 中仍可在本地完成的第一阶段：迁移账本的 44 个操作族
不再只靠 help/flag/selector 存在性自证。每个含 `sow-cli` 处置的族都绑定到真实
CLI/文件系统/DEB 或 RPM parser/CAS/索引/本地供应商协议测试；其余族必须有明确的
`retire`、`policy-reject`、`external-handoff` 或 `migration-only` contract。

本证据不声称生产逐 target 等价、真实 R2/COS/CDN、builder handoff、旧 writer 撤权、
真实 origin 切换或完整旧树迁移通过。所有执行都在测试临时目录，供应商协议使用内存
transport，上游协议使用 loopback TLS；`GOPROXY=off` 阻止 Go 工具访问模块网络。没有读取
生产 credential，也没有执行旧 Make recipe。

## 修正的合同漂移

1. [`pigsty-v1-synthetic.yaml`](../migration/fixtures/pigsty-v1-synthetic.yaml) 中带错误 asset 前缀的仓库 ID 已
   统一为迁移账本和 33-repo selector 使用的 canonical ID `pkg-pig`，物理路径保持
   `pkg/pig`。
2. [`selector-matrix.yaml`](../migration/fixtures/selector-matrix.yaml) 的 repo ID 集合与 176 行
   替代命令实际引用的 repo ID 集合精确相等，共 33 个。
3. `pigsty-v1-synthetic.yaml` 明确只包含旧的 12-repo parser/adoption 子集：`pkg-pig`、7 个
   per-suite APT pgsql repo、4 个 per-major YUM pgsql repo。其余 21 个 selector repo 仍须在
   生产 byte inventory 后补入，不能用合成 selector path 冒充 physical topology。
4. Docker `default/help` 不再计作 `sow-cli` 业务替代，改为 `retire`。`sow --help` 可以导航，
   但不是旧 Docker wrapper 输出或职责的等价证据。机器处置计数因此从 117/31/18/8/2
   修正为 **115 sow-cli / 33 retire / 18 policy-reject / 8 external-handoff / 2 migration-only**。

更新后的规范化 176-row machine map SHA-256：

```text
e29ceea9facb5a63bbce9fcfb2d17f80d01720c0d47a931101c65adcd3655e52
```

2026-07-17 复核更新 ROOT-02/03 两行的 replacement 证据：COS-only `/cc`、
`/claude`、`/ray` 已取得只读源 exact-copy；shared `/get`、`/pig`、`/pkg`、`/beta`
也已由钉住八个源 identity 的 external builder 收敛并通过真实 SOW 本地 handoff。
target、family、处置、回滚码和命令模板均未改变；审核脚本先按预期拒绝旧摘要，再经逐行
复核冻结为上述新摘要。

## 可执行合同

[`family-e2e.tsv`](../migration/fixtures/family-e2e.tsv) 有 46 行：schema、header 和精确 44 个
family。[`migration_family_e2e_test.go`](../../internal/cli/migration_family_e2e_test.go) 强制：

- family/disposition 与 `make-target-map.md` 逐族一致；
- 每个非 `sow-cli` disposition 都有对应 `contract:<disposition>`；
- 每个 `sow-cli` 命令的 verb 与 repo 类型由至少一个真实 E2E 覆盖；
- `publish` 必须由相同 repo 类型的 provider-protocol 测试覆盖；
- 证据不得使用名称含 `Help` 或 `Selector` 的测试冒充业务等价；
- 14 个许可测试名必须真实存在、均被 family 引用，未知测试/contract 非零失败；
- 33-repo selector universe 与命令引用集合精确相等，12-repo synthetic 子集 ID/path 固定；
  完整物理迁移由独立 `pigsty-v1.yaml` + migration ledger gate 证明，二者不可互换。

[`test-family-e2e.sh`](../migration/test-family-e2e.sh) 从 TSV 动态提取全部测试名，先用
`go test -list` 验证定义存在，再逐一运行并检查每个顶层测试确实输出 PASS；最后运行实际
构建二进制的零字节 adoption/materialize/rollback 脚本。它还在临时目录生成 4 个错误
合同，实际证明缺族、Help 冒充业务证据、错误 disposition 和 publish 缺 provider 均非零失败。

关键输入摘要：

```text
2929564b44245431c5fbda5ba4b0e1d93f80afb34653dd0df9ff98ed505b3c90  docs/migration/fixtures/family-e2e.tsv
2d3a09529a3c35eccfa93b8002f63d519e65025c0064d68462c002538c36b6de  docs/migration/fixtures/pigsty-v1-synthetic.yaml
25abdc1e6880bd0d308ea9e3919d27038f3a8ab4ec6c909ff1dc006eb5d714cf  docs/migration/fixtures/selector-matrix.yaml
ff4a3a12c84ac7682ebd3190c71b1d72d12f552851c9f71125f98e3d34250189  docs/migration/test-family-e2e.sh
2bfb4577f16cc272a1a08101655c80d3150b5c2b61d6c4b2c6d07d39066e9bb7  internal/cli/migration_family_e2e_test.go
```

## 复现与实测

```bash
cd /Users/vonng/pgsty/sow
docs/migration/test-family-e2e.sh
```

2026-07-14 加入合成 33-repo 证据后的最终重跑退出 0。合同/fixture/map 聚焦 package
退出 0，4 个突变负例全部按预期非零失败；动态提取的 14 个真实 E2E package 用时
61.962s，全部顶层测试实际
执行且 PASS：

下列清单采用最终测试名；该轮 harness 日志中的同一测试体仍使用临时名
`TestInitAdoptContentSynthetic33RepoPhysicalMigration`。随后只做了标识符改名以避免被误引为
真实物理迁移，并以 family contract、`go test -list` 和 `git diff --check` 重新验证最终名。

```text
TestDEBAddBuildsSignedByHashRepositoryFromExternalPackage
TestGCDryRunConfirmationAndHistoryRoots
TestInitAdoptContentAssetsIsZeroRewriteAtomicAndIdempotent
TestInitAdoptContentPigstyV1SuiteNestedAPTAndFlatYUM
TestInitAdoptContentRejectsGatedPublicAndAllowsStable
TestInitAdoptContentSynthetic33RepoGeneralization
TestInitAndFSCKEndToEnd
TestMaterializeCLIProducesExactHardlinkTree
TestPublishCLIStableUsesGatedNamespaceAndScopedBasicVerification
TestPublishCLIUploadsRealAPTAndYUMGenerationClosures
TestPublishCLIUsesRealProviderProtocolAndAdvancesRemoteRefLast
TestRPMAddBuildsSignedZstdRepositoryFromExternalPackage
TestSyncAPTEndToEndPreservesCanonicalProvenanceAndNeverDeletes
TestSyncYUMEndToEndPreservesCanonicalProvenanceAndNeverDeletes
```

最终 harness 输出：

```text
zero_byte_adoption=pass serving_tree_rewritten=false replay_changed=false replay_bytes_unchanged=true
isolated_materialize=pass candidate_bytes=exact
canonical_l1=pass legacy_fsck=pass
local_symlink_rollback=pass legacy_bytes_restored=true
local_symlink_rollback_replay=pass
failed_candidate_preserved_outside_origin=true
snapshot_nonregular_guard=pass
migration_family_contract=pass families=44
migration_family_negative_contracts=pass cases=4
migration_family_cli_evidence=pass tests=14
migration_family_external_network=disabled goproxy=off provider_scope=memory_or_loopback
migration_family_production_mutation=none temp_roots_only=true
```

本轮也重新运行机器账本正向审计；结果为 52/70/14/40、176 target、44 family、处置
115/33/18/8/2，输出 TSV 177 行，machine map SHA 与上文一致。其余聚焦门禁也全部退出 0：

- `docs/migration/test-audit-legacy-targets.sh /Users/vonng/pgsty/repo`：13/13 负例 PASS；
- `docs/migration/test-writer-fence-preflight.sh`：13/13 PASS；
- 原 13 个业务 E2E 的 `go test -race -count=1` 继续保持 32.257s PASS；新增的
  33-repo 合成迁移测试另以聚焦 race 命令运行，测试体 63.68s PASS 且无 race report；
- `go vet ./internal/config ./internal/provenance ./internal/cli`：PASS；
- `bash -n docs/migration/test-family-e2e.sh`：PASS。

## 全 selector 合成物理 CLI fixture（非旧生产树）

`TestInitAdoptContentSynthetic33RepoGeneralization` 进一步覆盖了 33 个 selector
配置的通用 CLI 组合，但它严格是 **all-selector synthetic physical CLI fixture**，不是
`/Users/vonng/pgsty/repo`、CO/COS/CF、旧 origin 或任一生产仓的实测。特别是 fixture 中
单-major 的 vendor YUM repo 不能代表旧 Make 树可能存在的多-major 物理拓扑；真实拓扑
拆分仍属于下节未关闭项。

该临时树包含 12 asset、11 APT、10 YUM repo，共 73 个 leaf：

- 53 个真实 payload：12 个 asset、22 个真实可解析 amd64/arm64 DEB、19 个真实签名
  noarch RPM；
- 42 个真实 APT `Packages` index；
- 每个 YUM leaf 都有与配置一致的 gzip 或 zstd primary/filelists/other、`repomd.xml`
  和 `.asc`。EL7 只走 `lifecycle=frozen + gzip` 的 ADR-0019 例外；
- 总计 190 个 source files。一次无 repo filter、显式 `--view latest,stable` 的
  `sow init --adopt-content` 产生 53
  receipts、latest+stable 共 146 个 canonical view entries，SQLite 重建结果为
  files=190、packages=23、memberships=122、relations=8、provenance=53；
- 第二次全量 adoption 为 `changed=false`，HEAD、refs、manifest、CAS、receipt、SQLite
  与全部 source bytes 不变；删除 `state.db` 后从 canonical Git 重建得到相同结果；
- `sow fsck` 覆盖全部 33 repo，随后全部 33 repo/73 leaf materialize 到隔离 candidate。
  APT 的 Release/InRelease/Release.gpg/by-hash、YUM 三类 metadata/repomd/签名和 asset
  payload 均以产品 parser/validator 校验；
- candidate 建立产品 baseline 后删除一个 asset，`sow fsck --repo asset-bin` 必须以
  `removed=1` 和 verification exit code 检出。切换使用同目录临时 symlink + `rename`
  的原子替换，随后回到未改写 source root；相同 rollback 可安全重放。

运行环境显式清空 AWS、Cloudflare、Tencent、COS、raw-log、verifier credential，关闭
所有 real-cloud/edge/upstream/watcher opt-in，设置 `.invalid` URL、空 `NO_PROXY`、失效
`127.0.0.1:1` proxy 和 `GOPROXY=off`。没有连接或测试任何 CO/COS/CF 生产资源。

聚焦普通测试：

```text
同一测试体 PASS 37.76s (family harness；随后仅标识符改名为最终名)
TestLegacyEL7CLIPolicyRejectsUnsafeConfigurations PASS
```

配置和 engine 负例同时证明 active EL7、EL7 zstd、EL1-6、EL11+、隐式 EL7 compression
及 modulemd 均 fail closed；`CompressionForEL(7)` 仍不接受 EL7，只有显式
`CompressionForOptions` 的 frozen+gzip 组合可用。该证据已绑定迁移 family A01、Y02、
Y03 与 D06，但只证明 selector-generalization，不提升为旧生产物理拓扑等价。

## 仍未关闭

- 每个旧 target 的真实生产文件集合、URL、apt/dnf、双云差异/purge/post-verify；
- 其余 external handoff 的真实生产 builder receipt 与逐 target 结果归档；
- 生产 scheduler/container/ACL/cloud IAM 的旧 writer 撤权；
- 真实旧仓全量 staging、origin cutover、失败恢复与双云回滚。

因此 G5、MIG-02、MIG-05、MIG-08 均继续保持 `实现中`，Goal 不可完成。
