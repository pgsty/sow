# ADR-0008：GC 自动判定与显式删除确认

- 状态：Accepted
- 日期：2026-07-12
- 决策范围：FR-06、FR-13、ADR-T03

## 背景

FR-13 要求引用计数、无引用回收和孤儿审计；FR-06 同时要求日常命令保持增量，昂贵
全池扫描只能显式执行。SOW 是单次运行的 CLI，不含常驻守护进程。若每次 add/rm 都
全扫 CAS 并自动删除，不但破坏增量合同，还会在刚提交 canonical ref 后引入不可逆的
隐式 I/O 与失败面。

这里的“自动回收”必须区别于 reprepro 的人工三步操作：操作者不需要手工删除 ref、
目录或推算包体。SOW 应自动枚举所有 preservation root、计算精确引用计数和孤儿集合，
并自动删除经同一计划确认的全部不可达对象；但开始不可逆删除仍必须是显式意图。

## 决策

1. `sow gc` 是唯一昂贵 GC 操作，默认只读审计。它从 canonical Git 的 view、snapshot、
   remote content、provenance 和最近 `state.cas_history_commits` 个 commit 自动重建引用
   计数，再完整校验 CAS，输出 missing/orphan、字节数及排序孤儿集摘要。
2. 删除使用 `sow gc --apply --confirm <orphan_set_sha256>`。命令在持有 state lock 时重新
   计算当前集合；摘要变化、任何引用缺失、对象损坏/消失/重新可达都会失败闭锁。确认的
   含义是“授权这个自动算出的集合”，不是要求操作者手工列对象。
3. `rm` 只移除本地 mutable view 引用；stable、snapshot、provenance、remote ref、保留历史或
   未完成 journal 可达的字节不会被本地 GC。远端 inventory 不是本地 CAS root，远端 content
   只在同摘要本地对象存在时成为 root。asset serving URL 与 APT by-hash retention 的远端
   删除不属于 CAS GC，按 ADR-0011 的证据绑定 publish 事务执行。
4. 不在 add/rm/sync/promote 的成功路径暗中执行全池 GC，也不加入后台 timer。需要周期
   回收时，调度器显式运行上述 dry-run→exact-confirm 流程，并保存两次输出作为审计证据。

## 结果

- FR-13 的自动性落在引用发现、集合计算、校验和批量删除算法，而不是危险的无人确认
  定时删除；不存在 reprepro 式手工 unlink/unreference 步骤。
- 两阶段确认保留了 FR-06 的增量默认路径和可审计性。孤儿集在两步间变化时必须重新
  dry-run，旧摘要不能授权新对象。
- `cas_history_commits` 是明确的本地回滚保留窗，默认 32；缩短它会让更老 commit 独占的
  对象成为 GC 候选，应作为运维变更审阅。
