# Reality review resolution

> **Historical pre-implementation snapshot.** 本文的“当前源码”均指其声明的
> `HEAD=6c84f9e`；现行 0.3 实现状态由
> [`../../evidence/2026-08-05-implementation.md`](../../evidence/2026-08-05-implementation.md)
> 维护，历史 closure 不构成 live compatibility PASS。

本轮对照 [`review-reality.md`](review-reality.md) 的 24 项原始 finding，审查当前
`HEAD=6c84f9e570243c6db2105fc92d7f822cfb5f4fd5` 工作树中的修订版 `design/next`。
本轮没有联网，也没有把 acceptance requirement 当作运行结果；当前源码、仓库内 retained
PoC 与修订后的前向合同是唯一依据。

这里的 **CLOSED** 只表示原 finding 指出的事实层级错误、范围外推或规范缺口已经在文档中
得到足够修正；它不表示 next renderer、publisher、exporter、GC 或 migrator 已经实现或
PASS。**PARTIAL** 表示修正方向成立，但仍有一处证据或措辞不能闭环。

汇总：22 项 CLOSED，2 项 PARTIAL，0 项完全未处理。当前仍有大量 release gate 未通过，
但修订版已把它们明确写成 approved/unimplemented 或 required/unverified，而不是现实能力。

## Original finding closure

- **F-01 — CLOSED — AD-24 与文档自身的证据分层不一致。**
  [`README.md:3-7,35-36`](../../README.md)、
  [`ARCHITECTURE-SPINE.md:8,32-33`](../ARCHITECTURE-SPINE.md) 和
  [`SPEC.md:20-21,80`](../../specs/SPEC.md) 现在统一声明 next 是 approved/unimplemented；
  [`acceptance-matrix.md:28-31`](../../specs/acceptance-matrix.md) 明确只有 required proof、没有
  next PASS evidence。alternatives 表也已把 parent-relative HTTP/object、export 等分别标为
  unverified 或 future capability，不再以 `yes` 冒充实测结果。

- **F-02 — CLOSED — 单一 AlmaLinux 9/DNF4/`file://` PoC 被外推。**
  [`research:27-41`](../../research/rpm-shared-pool-reposync-compatibility.md) 现在准确限定 PoC
  只证明固定 AlmaLinux 9.8/DNF 4.14.0 fixture 的 ordinary-DNF PASS、default-reposync FAIL
  与 C2 代价；[`compatibility.md:7-16`](../../specs/compatibility.md) 将 HTTP、对象存储、
  whole-root 与其他工具保留为独立未验证单元格。

- **F-03 — CLOSED — computed parent-relative href 被写成已有实现。**
  [`migration.md:3-32`](../../specs/migration.md) 明列当前 C2 行为和 next implementation seams；
  当前源码仍在每个 view 创建 hardlink 并写入 `object.PoolPath`
  （[`render_packages.go:236-275`](../../../../internal/v2/managed/render_packages.go)），checker
  仍要求 alias 与 canonical Pool `SameFile`
  （[`check.go:748-780`](../../../../internal/v2/managed/check.go)）。修订版没有再把 resolver
  说成 current binary capability。

- **F-04 — CLOSED — href escaping/round-trip 合同不能产生唯一实现。**
  [`repository-layout.md:62-84`](../../specs/repository-layout.md) 已冻结 directory-base trailing
  slash、先对未转义 ASCII path 做 POSIX relative 计算、uppercase `%HH`、`%`→`%25`、XML
  escaping 顺序、decode-once round-trip、拒绝条件与 golden vectors；
  [`repository-layout.md:114-126`](../../specs/repository-layout.md) 又版本化 Pool path grammar，
  [`AD-26`](../ARCHITECTURE-SPINE.md) 将两者绑定为同一函数。

- **F-05 — CLOSED — createrepo_c 字段说明被提升为 RPM-MD normative guarantee。**
  [`research:45-50`](../../research/rpm-shared-pool-reposync-compatibility.md) 现在明确称其为生产
  工具 API 而非所有 consumer 的规范保证，并要求 parent segments、`xml:base` 与 escaping
  逐客户端验证。

- **F-06 — PARTIAL — `/pool/...` 的 generic URI、ordinary DNF 与 reposync 语义混写。**
  语义主体已修正：[`repository-layout.md:86-93`](../../specs/repository-layout.md) 和
  [`research:126-133`](../../research/rpm-shared-pool-reposync-compatibility.md) 分别说明 generic
  URI 的 host-root-relative、目标 DNF4 的 `lstrip("/")` 与 reposync local `join`/containment，
  不再断言所有 DNF 都会越过 HTTP publish prefix。但 retained
  [`yum-relative-pool`](../../../../test/poc/yum-relative-pool/README.md) 并未包含 leading-slash
  fixture，当前 [`acceptance-matrix.md:10`](../../specs/acceptance-matrix.md) 也仍要求补该证据；
  因此 [`research:119`](../../research/rpm-shared-pool-reposync-compatibility.md) 把 reposync
  leading-slash 结果写成 `observed DNF4 unsafe local target` 仍比 retained evidence 强。应改为
  inspection-derived/unretained、unverified，或真正保留该 fixture、日志和 hash。

- **F-07 — CLOSED — “默认 EL reposync 不支持”被当成所有 EL 的行为事实。**
  [`research:20-25`](../../research/rpm-shared-pool-reposync-compatibility.md) 与
  [`compatibility.md:12`](../../specs/compatibility.md) 已把 unsupported product contract、pinned
  AlmaLinux 9 observation 和其他 EL/DNF unverified matrix cells 分开；
  [`acceptance-matrix.md:13`](../../specs/acceptance-matrix.md) 禁止再由一个 EL9 fixture 外推。

- **F-08 — CLOSED — `--safe-write-path` 被当作已证明 fallback。**
  [`research:52-65`](../../research/rpm-shared-pool-reposync-compatibility.md) 只保留官方文档存在性
  与 documented/unverified 结论；[`compatibility.md:13`](../../specs/compatibility.md) 明列
  best effort、single-repo 与扩大覆盖权限，且不是 promised fallback；
  [`acceptance-matrix.md:14`](../../specs/acceptance-matrix.md) 仍要求 multi-view、collision 和
  metadata closure 实测。

- **F-09 — CLOSED — standalone export 尚不存在却被写成可用绕行。**
  [`compatibility.md:16`](../../specs/compatibility.md) 直接写明 required future capability / not
  implemented；其后的 `sow-rpm-leaf-v1` marker、manifest、closure、signing、replace 与 copy/
  hardlink 规则是前向要求，且 [`compatibility.md:71-74`](../../specs/compatibility.md) 明确只有
  completed export 通过 default EL reposync 后才可称为 fallback。

- **F-10 — CLOSED — whole-root mirror 被混同为 repository mirror-tool compatibility。**
  [`compatibility.md:90-93`](../../specs/compatibility.md) 现在明确它是 SOW/known-operator 的
  settled-Generation locked handoff，不意味着 reposync 或第三方工具能发现 sibling Pool；支持表
  将其标为 required/unverified，且 [`acceptance-matrix.md:15-16`](../../specs/acceptance-matrix.md)
  分别要求 whole-root relocation 正向门禁和 leaf-only 负向门禁。

- **F-11 — CLOSED — direct static object hosting 被写成已经验证。**
  [`AD-18`](../ARCHITECTURE-SPINE.md) 明写 HTTP/proxy/object compatibility remains unverified；
  [`repository-layout.md:31-34`](../../specs/repository-layout.md) 将 key mapping 标为 approved
  static-target requirement；[`acceptance-matrix.md:17`](../../specs/acceptance-matrix.md) 要求真实
  nonproduction R2，S3/COS 继续分别验收。

- **F-12 — CLOSED — S3 key 文档被当成 SOW one-to-one publisher 的实现证据。**
  [`research:96-111`](../../research/rpm-shared-pool-reposync-compatibility.md) 只从 libcurl/S3
  文档导出 expected mapping 和 key 模型，并明确真实 HTTP/object 日志才能升格 observed PASS；
  one-to-one publish 现在是 AD-18 的设计不变量，真实 target inventory/key-count 是
  [`acceptance-matrix.md:17`](../../specs/acceptance-matrix.md) 的未完成 gate。

- **F-13 — CLOSED — Repository-local 现状与 target-prefix future state 混成同一已实现边界。**
  [`state-publication.md:7-12`](../../specs/state-publication.md) 明确整份 target-state 合同是 approved
  requirement / unverified implementation；[`state-publication.md:33-50`](../../specs/state-publication.md)
  则把 target-neutral Repository state 与 target-scoped Attempt/Checkpoint/Inventory/grace/delete
  分成两个 owner，不再借当前 SQLite/Generation 证明 per-target publisher 已存在。

- **F-14 — CLOSED — consumer base、handoff root 与 authorization unit 混名。**
  [`AD-19`](../ARCHITECTURE-SPINE.md) 现在明确 DNF/APT client entry 是 protocol view/archive base，
  完整 Repository root 才是 locked handoff、relocation、storage 和 authorization unit，并显式禁止
  把 root 误写成含 `repodata/` 的 DNF baseurl。

- **F-15 — CLOSED — ACL 推论被写成已经完成的访问模型。**
  [`publication-retention.md:102-109`](../../specs/publication-retention.md) 已把 mixed visibility
  的 direct-static preflight rejection、拆 Repository/prefix 或统一 private origin + edge auth
  写成要求；真实 R2 auth/ACL 仍在 [`acceptance-matrix.md:17`](../../specs/acceptance-matrix.md)，
  受全局 unimplemented 状态约束，不再是 live-auth PASS。

- **F-16 — CLOSED — hardlink export 与忽略 link count 的完整性模型冲突。**
  [`compatibility.md:60-65`](../../specs/compatibility.md) 已明确 hardlink 共享 inode、`chmod`/同 UID
  hostile writer 可破坏 canonical Pool，并让 opt-in 模式显式退出 hostile-writer 与 independent-
  integrity 保证；copy 是默认值，hardlink 只允许同文件系统、可信只读 disposable tree。因此
  “不以 link count 定义 Repository 正确性”现在是一个明确收窄的威胁模型，而非隐含安全保证。

- **F-17 — CLOSED — hardlink exception 从 C2/本地事实外推。**
  [`compatibility.md:76-88`](../../specs/compatibility.md) 将 private recovery、APT by-hash、external
  export 与 canonical payload alias 分开；[`acceptance-matrix.md:23-24`](../../specs/acceptance-matrix.md)
  为 copy/hardlink export 分设门禁。未实现的 external/recovery 边界没有再被写成 observed。

- **F-18 — CLOSED — retained refset/GC 没有相应 state model却被当成现状。**
  [`state-publication.md:93-107`](../../specs/state-publication.md) 已定义 terminal Generation、exact
  retained metadata bytes 与 canonical payload refset；
  [`publication-retention.md:74-100`](../../specs/publication-retention.md) 定义 local/remote closure
  和 checker obligations。两份文档仍受 approved/unimplemented 状态与
  [`acceptance-matrix.md:21-22`](../../specs/acceptance-matrix.md) 的未完成 gate 约束。

- **F-19 — CLOSED — stale-client grace 没有可执行定义。**
  [`state-publication.md:163-176`](../../specs/state-publication.md) 现在冻结 per-target `verified_at`、
  `not_before`、从 Applied Checkpoint + public endpoint verification 开始、默认 30 天、最大
  metadata/CDN TTL + 24 小时、clock/TTL/witness fail-closed、conditional delete 与 absence receipt。

- **F-20 — CLOSED — pointer-last 被当成多 key 签名原子性。**
  [`state-publication.md:109-136`](../../specs/state-publication.md) 明确 direct-static 没有 Repository
  多 key 原子切换，只承诺 per-view roll-forward 与 bounded mixed generation；
  [`state-publication.md:138-161`](../../specs/state-publication.md) 分别冻结 RPM signature-first/
  `repomd.xml` commit pointer、APT by-hash/Release/InRelease 顺序，并承认严格验签和 non-by-hash
  客户端的短暂 fail-closed 窗口。

- **F-21 — CLOSED — v0.2 local/C2 证据被用来证明 next remote publication。**
  [`state-publication.md:7-12`](../../specs/state-publication.md) 明确历史 C2 PoC 与 V1 publisher
  不能证明 next；[`acceptance-matrix.md:18-20,28-31`](../../specs/acceptance-matrix.md) 将 target
  state、pointer fault matrix 与 Changes 留作 release proof。当前源码仍是 C2 的事实也由 F-03
  所列 renderer/checker 直接确认。

- **F-22 — CLOSED — `xml:base`/URL mapper 的未保留实验被当作 final evidence。**
  [`research:49-50`](../../research/rpm-shared-pool-reposync-compatibility.md) 拒绝从 createrepo_c
  推出 consumer 保证；alternatives 表将 absolute `xml:base` 标为 reported/evidence not retained
  here，edge mapper 只作为 optional external projection；
  [`research:96-98`](../../research/rpm-shared-pool-reposync-compatibility.md) 还明确真实日志才可
  升格 observed PASS。

- **F-23 — CLOSED — migration 顺序草案被写成已实现、已 fault-tested 协议。**
  [`migration.md:3-21`](../../specs/migration.md) 的 truth boundary 明确当前 binary 仍是 C2，文档
  状态不等于代码迁移；transition journal、commit intent、roll-forward 与 alias receipt 是 required
  next behavior，且 [`acceptance-matrix.md:25,28-31`](../../specs/acceptance-matrix.md) 明确 crash matrix
  尚无 PASS evidence。

- **F-24 — PARTIAL — 官方来源没有固定为可长期复核的 revision。**
  [`research:8-11`](../../research/rpm-shared-pool-reposync-compatibility.md) 已补 2026-08-05 访问日期，
  并明确最终实现证据必须固定 client/image/source revision；来源也只支撑 officially documented
  或 design rationale，不再支撑 next PASS。但 DNF4 `latest`、DNF5 `stable`、Debian wiki、Bugzilla
  与厂商文档链接仍可变，尚无 commit permalink、页面 snapshot/hash 或 source package revision。
  因此“证据等级误写”已关闭，“长期可重放 provenance”仍未关闭。

## Remaining blockers

- **仍存在的一处 requirement/observation 层级错误是 leading-slash 表项。** 在保留 fixture 前，
  [`research:119`](../../research/rpm-shared-pool-reposync-compatibility.md) 不能写 `observed DNF4`；
  其正确状态应与 [`acceptance-matrix.md:10`](../../specs/acceptance-matrix.md) 一致，为待验证的
  implementation-specific negative，或附上 exact image/source、命令、输出、exit code 和 artifact hash。

- **官方资料 provenance 仍不耐久。** 访问日期避免了无时间来源，但不能防止 `latest`/`stable`/
  wiki 页面以后变化。它不再造成 capability 误报，却仍阻止 external-evidence finding 完全闭环。

- **safe-write、whole-root handoff、external export、真实 R2/object target、target-scoped state、GC、
  protocol pointer fault recovery 与 migration 仍全部是 release blockers。** 这不是当前文档缺陷：
  [`README.md:35-36`](../../README.md)、[`state-publication.md:7-12`](../../specs/state-publication.md)
  与 [`acceptance-matrix.md:28-31`](../../specs/acceptance-matrix.md) 已准确把它们保留为未实现、无
  next PASS evidence 的要求。在 retained acceptance evidence 出现前，不得因为本 resolution 将其
  对应原 finding 标为 CLOSED 就对外宣称这些能力可用。

- **当前 C2 实现边界清楚且仍然真实。** 文档、renderer 和 checker 一致表明当前 binary 仍要求
  view-local package hardlinks；next 的 metadata-only views、computed href、export、per-target state、
  GC 和 migration 尚未进入代码。不存在“修订文档已经改变当前交付树”的可接受解释。
