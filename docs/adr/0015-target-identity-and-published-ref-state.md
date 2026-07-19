# ADR-0015: target 配置只声明身份，published refs 属于 canonical state

- 状态：Accepted
- 日期：2026-07-12
- 决策范围：FR-03、FR-04、FR-41、NFR-08、NFR-09

## 背景

PRD 的配置雏形把 `targets` 概括为“端点、CDN、已发布 ref”。若把动态 ref 写回
`sow.yaml`，同一次发布将同时修改操作者输入与 Git 正典，失败恢复还可能读取到一个
未提交或手工改写的 ref。这会与 FR-03 的每目标跟踪清单、FR-04 的远端 checkpoint CAS
以及“manifest/Git 是正典”冲突。

## 决策

1. `targets.<name>` 只声明稳定目标身份与能力：供应商类型、endpoint/bucket/region、CDN
   host/zone 和 secret reference。每个 publication generation 的 `config_sha256` 不是裸 YAML
   文件哈希，而是域分离的 publication identity：它绑定 canonical YAML 的 SHA-256，再按 repo
   ID 排序绑定该 generation 完整 ref vector 可达的 YUM repo 的 `package_keyring` 文件 SHA-256。
   不可达 YUM repo 的 keyring 不进入该身份，因此 asset-only 或互不相关的发布不会被无关
   keyring 阻断。发布准备只加载一次不可变 trust snapshot；同一份 snapshot 同时提供该身份与
   后续 RPM 验证使用的内存 keyring，不能在两次路径读取之间拼接身份与信任内容。
2. 动态 published ref vector、content baseline、generation、checkpoint、channel state 与
   complete/partial inventory coverage 只写入 `.sow/state/remotes/<target>/...`，由 embedded
   Git 事务提交。`sow.yaml` 不被发布命令改写。
3. 下一次差异仍只用本地 canonical remote refs 计算；远端 checkpoint GET/CAS 只做漂移、
   锁与恢复。只有父代与本代的完整 ref 条目及 publication identity 都相同时，才能继承父代
   的 RPM 信任证明并跳过 manifest/package 读取。同一身份下发生 ref 变化时只流式比较新旧
   manifest，并验证新增或替换的 RPM；第一次发布，或配置/可达 package-keyring 身份变化时，
   必须重新验证本代可达的完整 RPM 闭包。配置身份变化不能伪装成旧 generation 的无变化
   重放；涉及目标身份本身的变化仍必须按迁移/新目标流程建立新基线。
4. 因此 PRD 中“targets 声明已发布 ref”解释为“每个声明目标拥有独立、可审计的已发布
   ref 状态”，而不是“ref 字段必须位于 YAML”。这是 schema 留待架构阶段定案后对雏形
   的具体投影，不削弱 FR-03/04。

## 结果

- secret/config 与运行状态的所有权清晰，恢复不会依赖写回配置的隐藏副作用；
- 两云可独立滞后，且每个 ref advance 与 publication checkpoint 有同一 canonical 证据；
- package-keyring 原地换字节会改变 publication identity 并强制闭包重验，而无关 repo 的
  keyring 不扩大本次发布依赖；
- 配置仍能从干净环境复现目标身份；远端动态状态通过 `init/fsck --adopt-remote-inventory`
  或成功 publish 建立，不能由操作者在 YAML 中伪造。
