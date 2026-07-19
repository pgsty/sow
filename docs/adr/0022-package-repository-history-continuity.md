# ADR-0022：包仓库历史连续性与永久物理所有权

- 状态：Accepted
- 日期：2026-07-14
- 决策范围：FZ-09、FR-01、FR-06、NFR-08、NFR-09

## 背景

APT/YUM repo ID 不只是当前配置标签；它同时决定 manifest/ref 身份、物理路径、索引叶、
CAS pool 分类、发布目标和恢复坐标。只比较运行时 YAML 与当前 HEAD 会留下三个绕过面：

1. 已有包体的 repo 可在一次旧版本提交中改路由，随后恢复相同 HEAD；
2. 删除/换 ID/复用物理根的提交可只由 `refs/sow/*` 的 view、snapshot 或 repo ref 保留；
3. 命令读取配置后等待锁时，另一个 writer 可写入并恢复同一配置 blob。

这些状态不能由常规增量发布安全表达，也不能靠 committer time 判断先后。

## 决策

### 所有权建立

aggregate HEAD 或任一 `refs/sow/*` 可达提交中，只要 APT/YUM repo 出现非空的
`manifests/`、`views/`、`snapshots/` 或本地 YUM generation manifest，该 repo 即永久建立
物理所有权。空 repo 在第一条所有权证据前仍可修改。

审计对 HEAD 与全部 SOW ref 的 commit DAG 取并集、按 parent 拓扑传播状态并按 hash 去重；
不使用 author/committer time。任一可达 commit 缺少或无法解码 `config/sow.yaml`、ref 指向
坏 commit、ownership blob 缺失或类型异常时均失败关闭。

### 永久冻结字段

建立所有权后冻结：repo ID/type、规范化 path、`default_pool`、include/exclude 集、OS
family/major/suite、APT arches/suites/逐 suite 有效 component 映射、YUM arches/noarch mode/
compression，以及语义化的 cf/cos target affinity。`active` 省略与 `true` 等价；已占用 repo
不得为 `false`。删除后重引入、换 ID、APT/YUM 改成 asset、物理 root 转交给其它 ID，均需
单独的显式全量迁移，不能作为普通配置变更。

唯一生命周期变更是 `active -> frozen`，包括 APT suite lifecycle；反向恢复失败关闭。
`yum.package_keyring` rotation 不在物理合同中冻结，继续由 ADR-0017 的 selected-set、CAS
admission、materialize/publish trust snapshot 与恢复门禁绑定。upstream allow/deny 也不冻结，
但一次 sync 仍由既有 selection hash/恢复合同绑定其实际选择集。

### 门禁位置

- `loadAndSelect` 在 selector 展开前审计；staged canonical config 再审计。
- 所有使用 canonical config baseline 的命令在持锁边界重验，避免 matching-HEAD 竞态。
- sync 的内部 add、repair、recovery 与 provenance commit 在各自持锁边界显式重验。
- GC 在锁前预检，并在锁内、打开/扫描 CAS 与任何 delete 之前再次显式重验。

审计只读取本地 Git commit/tree/blob metadata；大 manifest 只取 blob identity/size，不解析或
载入正文。

## 结果与边界

旧版本生成的隐蔽漂移、off-HEAD preservation ref、删除/重引入、瞬时 root reuse 和
frozen-to-active 均会阻止真实 CLI 继续。keyring rotation 与 upstream filters 仍保留既定可变
能力。可复现的 focused/race/32 MiB allocation 证据见
[package repository continuity evidence](../evidence/2026-07-14-package-repository-history-continuity.md)。

本 ADR 只证明本地 canonical-state admission 与破坏性 GC 边界；不声称真实 apt/dnf、对象
存储、CDN、生产迁移或云故障恢复在本轮被重新验证。任何情况下不得以 CO/COS/Cloudflare
生产仓库作为测试目标。
