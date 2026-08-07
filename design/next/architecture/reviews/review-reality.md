# Reality and external-evidence review

> **Historical pre-implementation snapshot.** 以下 finding 审查的是未提交 next 设计与
> `HEAD=6c84f9e` 的 C2 实现；它们不是当前 0.3 source 状态。现状见
> [`../../evidence/2026-08-05-implementation.md`](../../evidence/2026-08-05-implementation.md)。

审查对象是工作树中的 [`ARCHITECTURE-SPINE.md`](../ARCHITECTURE-SPINE.md)，基线
`HEAD=6c84f9e570243c6db2105fc92d7f822cfb5f4fd5`，且 `design/next` 尚未提交。本审查没有联网；
只接受当前源码、仓库内可重放/已保留 PoC，以及
[`design/next/research`](../../research/rpm-shared-pool-reposync-compatibility.md)
列出的官方来源作为依据。设计选择可以先于实现，但不得把选择、推论或 acceptance TODO
写成已验证的现实。

## Findings

- **AD-24 的证据分层规则正确，但 next 文档自己没有遵守。**
  [`acceptance-matrix.md`](../../specs/acceptance-matrix.md) 目前只有 required proof，没有任何
  checkout、命令、exit code、日志或结果；然而 research 的 alternatives 表已经把
  parent-relative href 的 ordinary DNF、static prefix/relocation 和 one payload key 写成
  `yes`，spine 又标为 `status: final`。当前可成立的是“已批准、待验收的设计合同”，不是这些
  matrix cell 已经 PASS。所有没有 retained evidence 的经验性结论应标为 `unverified`，直到
  acceptance matrix 真正填充。

- **AD-13 只有一个固定深度、单客户端、`file://` PoC 的局部依据。**
  [`run-in-container.sh`](../../../../test/poc/yum-relative-pool/run-in-container.sh) 把两个 baseurl
  固定为 `file:///work/repo/dists/el9/{x86_64,aarch64}`，仅验证固定
  `../../../pool/...`、AlmaLinux 9.8、DNF 4.14.0、native/noarch；保留证据确实证明 ordinary
  makecache/query/download/install 通过且 reposync 拒绝。它没有证明 HTTP(S)、不同 view
  深度、不同 Repository prefix、DNF5、代理/WAF、对象存储或真实 renderer 的 computed href。
  因而它支持“这个 fixture 在 DNF4/file 下可消费”，不支持 CAP-3 的完整 required matrix。

- **AD-13 的“computed parent-relative href”目前没有仓库实现证据。** 当前
  [`render_packages.go`](../../../../internal/v2/managed/render_packages.go) 仍创建 C2 hardlink，
  并把 `object.PoolPath` 作为安全的 view-local location；
  [`rpm.go`](../../../../internal/yumrepo/rpm.go) 的 managed validator 仍要求恰好
  `pool/<prefix>/<source>/<basename>`。仓库中没有 spine 要求的共享
  `(viewRoot, poolPath) -> href` resolver，也没有 renderer/checker 共用实现。migration 文档已承认
  这一点，但 spine 的 adopted rule 只能被称为 future invariant，不能被当前源码证明。

- **AD-13 的 URI escaping/round-trip 合同不足以产生唯一实现。** 当前 state path grammar 在
  [`objects.go`](../../../../internal/v2/state/objects.go) 中允许 `%`、`:`、`^` 等字节，而现有 YUM
  location validator 直接拒绝 `%`。next spec 没有冻结“先按 filesystem segment 计算再 escape”
  的顺序、百分号十六进制大小写、UTF-8/Unicode 规范化、一次或两次 decode，以及 `%2e`、`%2f`、
  `%25` 的精确判定。renderer 与 checker 共用同一个未定义纯函数只会共享同一个漏洞，不能替代
  独立 parser/客户端向量。

- **research 把 createrepo_c 字段说明提升成了 RPM-MD 规范结论。** 当前引用的
  createrepo_c Python API 把 `location_href` 描述为 relative location，但它不是 RPM-MD 的
  normative format specification，也没有在引用处证明 parent segments、URI resolution base、
  `xml:base` 优先级或各 consumer 必须采用同一解析方式。AlmaLinux PoC 可以证明一个实现，不能把
  “一个 DNF 实现接受”改写成“RPM 协议保证”。spine 的 compatibility reporting 应保留
  implementation-scoped wording。

- **`/pool/...` 的网络语义说明与目标 DNF4 实现不符。**
  [`repository-layout.md`](../../specs/repository-layout.md) 和 research 把 leading slash 直接写成
  HTTP host-root；但本次对固定 AlmaLinux 9.8 镜像
  `almalinux@sha256:d2515c769e7b73f95c4fde38c0a505336ff38f14990c0b7253b77060a049a743`
  的只读检查显示
  `dnf-4.14.0-34.el9_8.alma.1` 的 `dnf.package.Package.remote_location` 与
  `dnf.repo.Repo.remote_location` 都执行 `location.lstrip("/")` 后再与 package/repo base
  拼接。相反，同镜像 `reposync.py` 使用
  `realpath(join(repo_target, pkg.location))`，leading slash 会丢弃本地 repo target 并被
  containment 拒绝。因此拒绝 `/pool/...` 仍可能正确，但必须分别记录 generic URI、ordinary
  DNF 实际行为和 reposync 本地行为；当前“必然越过 publish prefix”的事实陈述不成立。

- **AD-22 把“默认 EL reposync 不支持”写得比证据覆盖面更宽。** retained PoC 只覆盖一个
  AlmaLinux 9.8/DNF4 镜像；Red Hat Bugzilla 支持 RHEL downstream 的安全/WONTFIX 决策，但不能
  自动代表 Rocky、Oracle、所有 Alma minor、EL8、EL10 或未来默认 DNF5。作为产品合同，SOW 可以
  主动把 default EL reposync 设为 unsupported；作为工具行为事实，应写成“pinned AlmaLinux 9.8
  已失败、RHEL downstream 明确不交付该 escape hatch，其余 EL matrix 未验证”。

- **`--safe-write-path` 的 best-effort 路径只有文档存在性，没有可操作证据。** next research
  引用了上游 DNF4/DNF5 文档，但没有固定版本、命令、输出树或 metadata round-trip PoC。该选项
  只允许单 repo，SOW 却有多个 architecture views；文档没有说明 `--norepopath`、download path、
  safe root 如何组合才能重建同一个 root Pool，重复 view 同步是否碰撞，以及
  `--download-metadata` 最终是否自包含。在这些问题实测前，它只是“上游有一个扩大写权限的 flag”，
  不是已证明的兼容 fallback。

- **AD-22 依赖的 standalone export 目前不存在。** 当前代码、CLI 与 retained acceptance 都只证明
  v0.2 C2；next 的 copy/hardlink export 只有规范文字，没有实现、ownership marker、`--replace`
  防护、失败恢复或真实 client/repo-tool 结果。设计可以把它列为 required future capability，但在
  它通过 [`acceptance-matrix.md`](../../specs/acceptance-matrix.md) 前，不能把它写成已经可用的
  reposync/legacy-tool 绕行路径。

- **“whole-root mirror”只是一个受控文件复制约定，不是 repository mirror-tool 兼容性。** DNF
  client 入口仍是 architecture leaf，metadata 不会告诉 reposync 或第三方镜像工具去发现 sibling
  root Pool；`cp`/rsync/rclone 只有在操作者已知道 enclosing Repository root 时才能复制两棵树。
  现有 `changes 0`/Generation manifest 为精确复制提供了可复用基础，但 next 没有 whole-root
  relocation PoC，也没有规定复制期间的锁、generation snapshot、pointer race 或失败恢复。应把它
  称为 SOW-controlled handoff procedure，而不是默认镜像工具的替代能力。

- **AD-18 的 direct static object-hosting 仍是最关键的未验证假设。** libcurl
  `CURLOPT_PATH_AS_IS` 文档只能说明 curl 的默认 dot-segment 行为，不能证明 DNF/librepo 没有改该
  选项，也不能证明 TLS 前后的 proxy、WAF、signed URL、CDN 和 S3-compatible endpoint 都接收同一
  canonical path。现有 parent-relative PoC 是 `file://`，next 也没有真实 R2/S3/COS 请求日志。
  acceptance matrix 已正确要求真实 target；在其通过前，AD-18 的 object-hosting 应明确标为
  required design target/unverified，而非现实能力。

- **S3 object-key 来源只证明“不同 key 是不同 object”，不证明 SOW 已实现 one-to-one publish。**
  当前 v2 的 public-tree scanner 确实只允许 `pool/` 与 `dists/`，这支持 canonical path 边界；但
  v2 没有 target publish manifest/checkpoint 实现。仓库中现存 V1 YUM snapshot 路径反而使用
  `ObjectCopyImmutable` 生成额外 payload key，v0.2 research 也明确指出这一冲突。AD-18 是对未来
  publisher 的约束，不是当前 publisher 的已验证属性，必须有 next manifest golden 与真实 target
  inventory 才能闭合。

- **AD-17 只有 Repository-local ownership 得到当前源码支持，target-prefix 部分没有。** 一库一
  SQLite、SHA-256 Package Object、唯一 PoolPath、Membership 和 Generation manifest 都有现成
  schema/测试依据；但同一条 rule 又把 remote inventory、checkpoint、authorization 与 GC closure
  一并绑定到 `Repository + target publish prefix`。当前 v2 schema 没有 per-target 状态，现存 remote
  publisher 属于不同的 V1/CAS/gated ownership model。应把已继承的 Repository 边界与新引入的
  per-target 边界拆成两项，后者列出 schema/API/迁移 seam。

- **AD-19 把 consumer unit 与 storage/security unit 混成了一个名字。** ordinary DNF 的 consumer
  baseurl 明确指向 `dists/<dist>/<arch>` leaf；只有 payload storage、copy、ACL 和 GC 需要 enclosing
  Repository root。spine 虽在正文承认 client base URL 可指向 view，标题和“Repository root is the
  consumer unit”仍会误导实现者把 root 当成含 `repodata/` 的 DNF repository。应分别命名 client
  view、handoff root 与 authorization prefix，并给出从每个 baseurl 到其 owner prefix 的明确映射。

- **AD-19 的 ACL 推论合理，但没有完成访问模型。** 同一 canonical Pool key 被 public 与 private
  Dist 引用时，静态 object ACL 无法按来源 metadata view 区分请求；spec 建议拆 Repository 或统一
  private origin + edge authorization，这是正确约束，但没有 migration rule、配置冲突检查或 live
  auth PoC。直到这些门禁存在，“protect entire prefix”只能防止裸 Pool 泄漏，不能证明混合可见性
  Repository 可安全发布。

- **AD-20 允许 hardlink export，却同时取消了防御外部 hardlink 的 link-count 证据。** hardlink
  共享内容、inode owner 和 mode；不能只把 export alias 设为只读，`chmod` 任一路径会改变 canonical
  Pool inode，任何可写 alias 都可原地破坏 canonical bytes。当前 C2 的
  [`pendingLinkTracker`](../../../../internal/v2/managed/render_packages.go) 正是通过精确 link count
  防止未授权 alias；next 又要求 checker 忽略 link count。除非明确一个可信只读 mount/主体边界并
  禁止 chmod/in-place write，否则“hardlink export opt-in”与 canonical payload 防篡改模型冲突；
  更安全的合同是 export 只允许 copy/reflink，或继续审计显式登记的 hardlink closure。

- **AD-20 的 hardlink 例外没有 acceptance 之外的现实依据。** APT by-hash hardlink 有当前代码和
  测试，C2 copy-loses-link PoC 也证明 package correctness不应依赖 inode identity；但 private
  transaction recovery 和 external hardlink export 的允许边界没有统一 ownership/mode/delete
  测试。尤其跨设备失败、部分导出恢复、删除 export 不改变 state、export 不进入 changes/GC 都只是
  matrix TODO，不能由 C2 PoC 外推。

- **AD-21 的 retained refset/GC 模型尚无相应 state model。** 当前 v2 有 physical
  `generation_files` manifest，并为 C2 只保留一个 `prior_built_memberships` 集合；没有 next 所述的
  retained-generation payload refset、snapshot/view root、remote inventory root、grace root 或
  Repository-wide GC API。当前事实最多证明 Generation ledger 可作为迁移基础，不能证明
  “every retained point stores metadata identity plus canonical payload refset”已经成立。

- **AD-21/AD-23 的 stale-client grace 是删除安全性的必要条件，却没有可执行定义。** 文档没有规定
  grace 起点、最短时长、按 metadata generation 还是 CDN TTL 计算、失败/回滚如何延长、如何证明旧
  `repomd.xml`/Release 已不可见，以及 target inventory/clock/cache 漂移时如何 fail closed。没有这些
  规则，“grace 后 evidence-delete”仍是口号，GC 无法得到确定输入。

- **AD-23 的 pointer-last 不能单独解决签名 pointer 的多对象原子性。** RPM 至少有
  `repomd.xml` 与 `repomd.xml.asc`，APT 还有 Release/InRelease/Release.gpg；对象存储不提供多 key
  原子替换。当前 manifest 把这些文件全部归为同一 `pointer` phase，却没有 phase 内顺序或 mixed-pair
  客户端行为。先写任一文件都可能短暂暴露“新 pointer + 旧 signature”或相反。需要 generation-pinned
  route、明确允许/重试语义，或真实并发/fault PoC；仅写“pointer-last”不能证明签名仓库连续可用。

- **AD-23 的现有证据只覆盖 v0.2 local/C2 tree，不能直接证明 next remote publication。** 当前
  Generation/Changeset 已有 payload→metadata→pointer→delete phase validation 和 retained acceptance，
  这是可复用证据；但当前 classifier 会把 `dists/.../pool/...` C2 aliases 也列为 payload，历史 remote
  publisher 又有自己的 object classes/route/checkpoint。只有迁移后 manifest golden 能证明每个 package
  path 在 full/incremental phase 至多一次，真实 target fault matrix 才能证明 pointer-last/delete
  ordering；目前这仍是未来要求。

- **被用来支持 `xml:base` 和 URL-to-object mapper 结论的“Current EL9 Interoperability
  Experiment”不可审计。** 它只出现在 superseded
  [`design/v0.2/research`](../../../v0.2/research/rpm-shared-pool-reposync-compatibility.md)
  的叙述中，没有仓库脚本、完整命令、原始日志、artifact hash 或 retained lab；next research 也没有
  链接该证据。相关结论可能真实，但按 AD-24 自己的规则只能算线索，不能算 final decision evidence。

- **migration 是一份合理顺序草案，不是已证明的迁移协议。** 当前没有 layout-version schema、
  next renderer/checker、旧 binary hard-fail、alias grace ledger、对象存储迁移器或逐 crash-point fixture；
  也没有证明多个 architecture pointer 逐个切换时允许出现怎样的跨-view mixed generation。spine 依赖
  migration 来撤销当前 C2，因此在 fault matrix 完成前不能宣称 AD-13/20/21 已可落地。

- **官方来源虽相关，但没有被固定为可长期复核的证据。** next research 使用 `latest`/`stable` 文档、
  mutable Debian wiki 与未固定 commit 的页面，并且没有访问日期、适用版本或关键源码 permalink；这与
  pinned AlmaLinux PoC 的严谨度不一致。最终 architecture decision 应至少固定 DNF4/DNF5 实现版本、
  RHEL downstream package 状态和所依赖源码 commit，否则未来页面变化会悄悄改变“官方依据”。

## Conclusion

九个 ADOPTED 决策都能找到设计动机，但证据强度不相等：Repository-local ownership、现有
`pool/ + dists/` 扫描、v0.2 C2/hardlink 代价、AlmaLinux 9.8 的 parent-relative ordinary-DNF
PASS/default-reposync FAIL，以及 local Generation phase ledger 有直接依据；computed href、通用 EL
结论、safe-write fallback、whole-root mirror、真实对象存储、external export、retained-refset GC、
remote pointer atomicity和 migration 仍是未实现或未保留证据的承诺。当前最需要修正的不是立刻改回
C2，而是把这些承诺从“事实 yes”降为“approved requirement / unverified”，再用 next acceptance
matrix 逐项升格。
