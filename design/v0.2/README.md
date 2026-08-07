# SOW v0.2 design archive

状态：`v0.2.0` 已实现、已验收的历史合同。

本目录保留 v0.2 的 PRD、API、架构、评审和时间戳证据。v0.2 Managed RPM 使用
root Pool + C2 view-local package hardlinks，并把默认 EL `reposync` 作为门禁；这些
陈述仍准确描述 tag `v0.2.0`，不得改写成新布局已经实现。

前向设计已由 [`../next/`](../next/) 取代：Repository 根仍直接是 `pool/ + dists/`，
但 RPM view 改为 metadata-only、href 计算回 root Pool；package hardlinks 不再进入
canonical tree，默认 EL reposync 也不再是兼容承诺。

引用规则：

- 解释当前 `v0.2.0` binary、旧日志或旧 hash：使用本目录。
- 设计下一版实现、迁移、对象存储、快照或 GC：使用 `design/next`。
- 不得用 next 文档给 v0.2 补写不存在的实现证据，也不得用 v0.2 的 C2 PASS 覆盖
  next 的 single-payload contract。
