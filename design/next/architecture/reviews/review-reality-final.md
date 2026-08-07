# Final reality and evidence review

> **Historical pre-implementation snapshot.** 本文明确绑定 `HEAD=6c84f9e`，所以正文中
> “当前源码仍是 C2”只描述该基线，不描述现在的 0.3 工作树。当前 source/local/mock 事实
> 见 [`../../evidence/2026-08-05-implementation.md`](../../evidence/2026-08-05-implementation.md)；
> live-client/target 单元格仍不得从本历史审查外推。

本审查以当前工作树与 `HEAD=6c84f9e570243c6db2105fc92d7f822cfb5f4fd5`
为对象；`git describe --tags --exact-match HEAD` 返回 `v0.2.0`。审查只判断事实层级是否
准确，不把 approved requirement、待实现设计或 acceptance TODO 当作运行结果。检查范围
包括 current v0.2 与 next 的边界、default reposync、leading slash、APT path、R2
publish/delete、迁移新 prefix，以及历史文档的直接阅读语义。

## Findings

- **当前交付事实与前向设计已经分开。** 当前源码仍由
  [`render_packages.go`](../../../../internal/v2/managed/render_packages.go) 为 RPM view 创建
  C2 hardlink alias，并由
  [`check.go`](../../../../internal/v2/managed/check.go) 用 `os.SameFile` 验证 alias 与 canonical
  Pool 对象；[`README.md`](../../README.md)、[`SPEC.md`](../../specs/SPEC.md) 与
  [`ARCHITECTURE-SPINE.md`](../ARCHITECTURE-SPINE.md) 则统一把 metadata-only view、computed
  parent-relative href、target state、GC 和 migration 标成 approved/unimplemented。这里没有把
  next 误报成当前 binary capability。

- **next 的权威顺序和 evidence 状态能够阻止历史实现反向覆盖。** next README 明确规定
  `design/next` 高于 `design/v0.2`、根 `docs/` 与旧 ADR，且明确写出历史 PoC 不能升格为 next
  PASS；[`acceptance-matrix.md`](../../specs/acceptance-matrix.md) 只有 required proof，没有已通过
  结果，当前也不存在 `design/next/evidence/`。因此“设计已批准”与“实现/验收已完成”没有混写。

- **default reposync 的产品合同与行为观察范围已经拆开。**
  [`compatibility.md`](../../specs/compatibility.md)、
  [`research`](../../research/rpm-shared-pool-reposync-compatibility.md) 和 spine 都只把 default EL
  reposync 设为 unsupported product contract；行为事实只覆盖 pinned AlmaLinux 9/DNF4
  fixture 的拒绝，其他 EL minor、EL8/EL10 与 DNF5 仍是 matrix cells。这里不再把单一 EL9 PoC
  外推成整个 EL 系列的实现事实。

- **reposync 拒绝 parent-relative href 的原因被准确限定为本地目标 containment。** ordinary DNF
  可以按 view base 解析 `../../../pool/...`；default reposync 还需把 href 映射到
  `<download-path>/<repoid>/` 下的本地文件，规范化后目标逃出该目录，于是安全门禁在下载前拒绝。
  文档没有把该失败归因于硬链接、RPM 架构、metadata checksum 或 HTTP；这正好说明 C2 hardlink
  是为满足一个特定 mirror-tool 输出形态而产生的兼容投影，不是 Repository 协议自身要求。

- **leading slash 的三种语义已经分层，先前的 observation 误报已消除。**
  [`repository-layout.md`](../../specs/repository-layout.md) 分开描述 generic URI 的 host-root、目标
  DNF4 的 `lstrip("/")` 与 reposync local join/containment；research 表项也已从 `observed`
  降为 `source-inspected/unretained; fixture pending`。现有 retained PoC 尚未覆盖 `/pool/...`，但
  [`acceptance-matrix.md`](../../specs/acceptance-matrix.md) 明确保留了该 negative gate，所以当前是
  未完成证据，不是能力误报。

- **禁止 `/pool/...` 的设计理由成立，但不是解决 Repository-root 问题的捷径。** root-leading href
  绑定 HTTP origin root，在 non-root publish prefix、`file://` relocation 与不同 consumer
  normalization 下不稳定；目标 DNF4 又可能把它重解释为 base-relative。即使未来 fixture 发现某个
  client 能工作，也只能证明该 client/version 的行为，不能把 leading slash 提升为可移植的
  Repository-root-relative URL。

- **APT 与 RPM 的 path base 差异已被明确接受，而不是无理由的不一致。** APT `Packages` 的
  `Filename` 是 archive-root-relative raw Repository path；RPM-MD `location href` 则相对当前
  metadata/view base 解析。前者可自然写 `pool/...`，后者从深层 view 指向 root Pool 必须使用
  parent-relative reference。两种 metadata 协议的基准不同，强行追求相同字符串才会制造错误；
  单份物理 payload 的不变量应落在 canonical Repository path/object key，而不是两个协议的字段
  spelling 必须一致。

- **APT raw path 与 URI encode-once 合同现在足够明确，也没有被写成完整 next PASS。**
  [`SPEC.md`](../../specs/SPEC.md) 与
  [`repository-layout.md`](../../specs/repository-layout.md) 规定 `Filename` 逐 byte 保存 canonical
  raw `pool/...` path，literal `%3a`/`%3A` 属于 basename spelling；URI 层再把 `%` 编为 `%25`，
  decode once 后回到同一 object key。当前 APT renderer/validator 已有一部分同形实现事实，但
  Ubuntu/Debian、file/HTTP、by-hash 与并发 stale-Release 的 next 矩阵仍正确标为未验证。

- **object key、metadata path 与 HTTP request path 没有再混成一个字段。** next 设计把 canonical
  `pool/...` 定义为 Repository-relative storage key；RPM renderer 从 typed canonical path 计算
  relative href，HTTP 层再解析成 request path。真实 proxy/CDN/object target 的 normalization 仍需
  retained request log 才能 PASS；当前文字只冻结 mapping requirement，没有冒充部署现实。

- **R2 的 publish 与 delete capability 已按 operation 分开。** next 要求真实 nonproduction R2
  验证上传、GET/HEAD/Range、ETag、auth、non-root prefix 与 pointer recovery，但不把 R2 当作
  physical remote-GC PASS；缺少 atomic conditional delete 时必须 retain/report unreachable keys，
  remote delete fail closed。Cloudflare 当前 [S3 compatibility 表](https://developers.cloudflare.com/r2/api/s3/api/)
  只为 Head/Get/Put 等列出条件操作，DeleteObject 行没有条件操作；官方
  [Delete objects](https://developers.cloudflare.com/r2/objects/delete-objects/)
  页面也只展示无条件删除，而 [R2 extensions](https://developers.cloudflare.com/r2/api/s3/extensions/)
  的条件头针对 CopyObject，不是 DeleteObject。文档对 R2 的能力边界没有误报。

- **next 没有继承 V1 的 checkpoint-fenced unconditional delete 降级。**
  [`state-publication.md`](../../specs/state-publication.md) 与
  [`publication-retention.md`](../../specs/publication-retention.md) 要求 target 缺少 atomic conditional
  delete 时只保留并报告；这比历史 V1 的 single-writer/checkpoint-fenced 降级更严格，也与 next
  “不得把未删除对象写成 GC PASS”的 threat model 一致。历史 live R2 证据可以支撑“错误
  `If-Match` 未形成 DeleteObject CAS”的负能力事实，但不能证明 next publisher 已实现。

- **R2 new-prefix migration workaround 的能力边界现在准确。**
  [`migration.md`](../../specs/migration.md) 只允许具备 conditional delete、inventory ownership 与
  cache-absence evidence 的 target 原 prefix 迁移；R2 必须发布到新的、空的、non-overlapping
  prefix，验证后切换外部 route/consumer，旧 prefix 整体作为 legacy 退役。它没有宣称旧字节已被
  回收，也明确承认双 prefix 暂时计费和旧 prefix 清空前不能宣称全 target deduplicated。这是
  approved operational requirement，尚不是已实现迁移能力。

- **migration rollback 已不再承诺互相矛盾的双向恢复。** `commit_intent` 前可以放弃 private
  stage 并保留 C2；`commit_intent` 后只能按 journal roll forward，不能把公开 pointer 恢复到
  v0.2 generation。这个边界与多 view direct-static publication 的可恢复状态机一致，但逐 crash
  point 验收仍在 matrix 中，未被写成 PASS。

- **主要历史目录已经有版本/权威 banner。** 根 README、`design/README.md`、
  `design/v0.2/README.md`、v0.2 的主要 architecture/spec/research/review/evidence index，以及根
  `docs/architecture.md`、`docs/evidence/README.md` 等入口，都说明它们只证明 v0.2 或 V1，不能覆盖
  next。通过这些入口阅读时，事实层级已经清楚。

- **历史 banner 覆盖仍有一个与本次 R2 决策直接冲突的直链反例。**
  [`ADR-0036`](../../../../docs/adr/0036-provider-delete-capability-and-checkpoint-fenced-fallback.md)
  顶部仍只有 `Accepted`，没有“历史 V1、不得覆盖 design/next”的 banner；正文又接受了
  checkpoint-fenced unconditional delete，并用“R2 发布不再依赖……”的当前式措辞。next README
  的权威顺序在目录层面能消歧，但用户从 issue、搜索结果或 permalink 直接打开该 ADR 时，仍可能把
  V1 降级误读为 next 当前决定。这是剩余的事实呈现误报面，应补一个直链自足的历史 banner。

- **v0.2 release evidence 还有一个“current”直读歧义。**
  [`2026-08-05-release.md`](../../../v0.2/evidence/2026-08-05-release.md) 开头写
  `Scope: current codex/release-v0.2.0 checkout` 和 `make release completed`，但该文件自身没有 v0.2
  archive banner。目录与 index 已经把它框定为历史 release evidence，内容也有明确日期；不过脱离
  上下文直链时，“current”可能被误读成当前 dirty checkout 或 next acceptance。它不推翻原始
  v0.2 验收事实，但仍应补一条文件级历史边界说明。

- **来源 permalink/provenance 是独立的非阻塞 residual debt。** research 已有访问日期并要求最终
  fixture 固定 image/source revision，但 DNF4 `latest`、DNF5 `stable`、Debian wiki、Bugzilla 与
  Cloudflare live docs 仍是 mutable URL，没有 commit permalink、页面 snapshot/hash 或 source RPM
  revision。因为这些来源目前只支撑 documented rationale 或待验收结论，不再被拿来冒充 next PASS，
  所以它们不构成新的 capability misreport；但在正式 evidence seal 前仍应固定 provenance。

- **最终判定应分两个层次表达。** authoritative `design/next` 在本次指定范围内已经没有发现
  requirement-as-fact、v0.2-as-next 或 single-fixture-as-all-EL 的误报；leading-slash、APT full
  matrix、真实 R2 publication、GC 和 migration 都仍是明确的 release blockers。Repository-wide
  的直接阅读面还不能称为完全闭合，因为 ADR-0036 与 v0.2 release evidence 缺少文件级历史 banner；
  这是文档 provenance/authority 呈现问题，不是 next 物理布局重新回到 C2 的理由。

## Post-review closure

- **ADR-0036 direct-link ambiguity — CLOSED.** 文件顶部现已明确标为历史 V1 ADR，说明
  checkpoint-fenced unconditional-delete 只解释归档 V1、next 不继承，并直链前向
  `state-publication.md`；脱离目录索引直接阅读也不会再把该降级误认成 next 决定。
- **v0.2 release-evidence `current` ambiguity — CLOSED.** 文件顶部现已把 `current checkout`
  限定为 2026-08-05 封版时的 `codex/release-v0.2.0`，并明确不描述当前工作树、不证明 next
  实现或验收；原始 v0.2 结果与当前事实边界均得到保留。
- **Updated disposition.** 本审查指出的两个 repository-wide 直链 banner 问题均已 CLOSED；
  指定范围内不再存在已知的事实层级误报。未完成的 next acceptance/release gates 与 mutable-source
  permalink/provenance residual debt 不因本 closure 而转为 PASS。
