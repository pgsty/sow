# ADR-0009：远端历史代的前向恢复

- 状态：Accepted
- 日期：2026-07-12
- 决策范围：G3、G5、FR-19、FR-25、FR-27–FR-30、FR-33、FR-42、NFR-05、NFR-06、NFR-09

## 背景

远端发布 checkpoint 是每个 target 独立的单调提交日志。把 checkpoint 直接改回较小代数，
或者从 bucket 中随意复制若干旧文件，会破坏 parent/ETag compare-and-set、双目标独立追踪、
最小 purge 和发布后验证，也无法证明旧 ref 对应的 CAS、配置与 public/gated 闭包仍然有效。
另一方面，只能续跑未完成 saga 不能处理“一个已成功提交的新代需要业务回退”的生产场景。

## 决策

1. 操作面固定为
   `sow publish --restore-generation <N> --target <cf|cos>`。一次只能显式选择一个 target，
   且不能同时使用 view/snapshot/repo/OS/arch 选择器。`N` 是该 target 在本地 canonical
   Git 历史中曾成功提交的 generation，不是任意 Git commit、对象前缀或 checkpoint body。
2. source generation 必须在同一个 canonical commit 中具有可解码且闭合的 generation、
   committed checkpoint、publication plan、content manifest 与 ref vector；generation/
   checkpoint 的 generation、parent、desired commit、intent、content 摘要必须一致，
   target-global generation/checkpoint/plan 必须与同 commit 的 intent-scoped 投影逐字节相同，
   desired/ref commit 必须仍在 canonical HEAD 历史中。source plan 只作为成功发布证据并把
   摘要写入 restore audit；不会重放旧 plan，新的差异/purge/verify plan 必须从重建内容产生。
   当前配置摘要必须与 source generation 相同。
3. restore 只替换 source generation 的 intent（一个 view 或 snapshot）的完整历史 ref vector；
   parent 中其他 intent 的 ref/channel 状态保持当前值。它不会移动当前本地 view/snapshot ref，
   也不会把整个 target 状态回退到旧 checkpoint。FR-19 的 stable append-only 约束优先：
   source stable ref vector 必须与 parent 当前 stable intent vector 完全相同；任何 commit、manifest
   或 ref 集回退均失败闭锁。需要保留历史可安装面时使用 immutable snapshot，不从 stable 删包。
4. checkpoint 永不倒退。restore 以当前 committed checkpoint 为 parent，创建 `current+1`
   generation，并完整执行现有 saga：从本地 historical ref/CAS 隔离重建并校验 APT/YUM/
   asset，上传差异和 immutable closure，翻转 pointer/YUM pair，执行最小 purge，L3 read-back，
   compare-and-set checkpoint，最后才把该 target 的 remote refs 指向历史 commit。隔离重建
   根使用 target/source generation 的确定性路径：正常成功或失败均删除；每次 `publish` 在
   取得独占 publish lock 后、任何新事务或远端动作前，都会用受限 filesystem root 清扫整个
   restore reconstruction namespace。清扫逐级拒绝 symlink/非目录，删除后 fsync parent，并
   输出 recovery evidence；因此 SIGKILL 后即使下一条是普通 publish、不同 target 或不同
   source generation，也不能让隐藏 hardlink 永久绕开 CAS GC。
5. 每个 restore transaction ID 都包含 source generation 和创建 generation 时的 canonical
   desired HEAD；远端 checkpoint/COS lock/journal 在成功 local persist 前也能诊断应重放的
   参数，COS 在 lock 后本地 HEAD 前进仍可重建完全相同的 generation hash。普通 publish 或
   另一个 source generation 不得接管该事务。成功 restore 在
   `remotes/<target>/restores/<new-generation>.json` 记录 source generation、source generation/
   plan 摘要、source state commit、intent、transaction ID 和排序 ref vector。同一命令重放
   沿用 saga journal；完成后的重放不得再次 PUT、purge 或推进 generation。
6. restore 不以旧云端对象为正典。历史 manifest、所有所需 CAS body、签名密钥和当前配置
   必须在本地重新可用；缺失、损坏、配置漂移、机密性闭包失败或远端 checkpoint 漂移均在
   pointer mutation 前失败闭锁。stable/snapshot payload 的 public/gated 分类必须读取同一
   historical ref override，绝不借用 current local ref 的 pool 值。private signing material
   只由 source intent 实际包含的 APT/YUM leaf 决定；纯 asset target 不需要 GPG。若当前
   parent 同时携带其他 intent 的 package ref，asset-only restore 仍必须读取配置的 public
   trust anchor 并证明其 `repository_key_sha256` 连续，但不要求 private key。这样新 generation
   不会在当前配置已信任 B 时继续携带 A 签 package 而伪称发布后验证闭合。
7. retention/asset-serving 删除闭包是 plan-bound 的：storage exact-key HEAD 必须不存在，公开 route purge 后
   只接受 404/410，2xx、任意 3xx（包括同源 302 到 404）、鉴权和服务错误均不算成功；中断
   重放会幂等重删、重 purge 并复验。纯 `asset-serving` deletion-only plan 以 storage absence 与
   exact CDN 404/410 组成完整 negative closure；其他零对象 plan 必须从同 intent 历史携带一个
   未被本 plan 删除的 positive CDN probe。restore 合法重建 snapshot 后，旧 intent
   plan 原文不改；post-hoc L2/L3 只有在 current target-global committed generation 含该 snapshot
   ref 且排序 `inventory.tsv` 精确含对应 route/payload key 时才抑制旧 negative。partial restore
   未重建 key、其他 retired snapshot 与 current-global plan 仍检查；inventory 缺失、损坏或
   非排序均失败闭锁，扫描内存仅随 delete change-set 增长。

## 历史 YUM 物理 owner 投影

历史 generation 中多个逻辑 OS ref 可能共享同一个 `repo+arch` 物理 root。restore 必须先从
历史 config/ref anchor 关闭这个完整物理 owner，只生成一份 repodata/package generation，再为
每个历史 alias 独立生成 channel、mirrorlist 与 ref tracking 条目。两个 alias 的 manifest commit
可以不同；不能因共享路径而丢失任一逻辑 ref，也不能为每个 alias 重复生成互相覆盖的物理 root。

若新的合法历史意图只移除其中一个 alias，删除授权只覆盖该 alias 的 pointer route；仍被 sibling
alias 持有的物理 repodata、Packages、immutable generation 和 payload 不得进入删除计划。配置历史
连续性门禁禁止通过伪造当前 topology 来制造这种恢复，因此没有合法 config anchor 时必须失败闭锁，
不能为了测试或便利放宽 package repository ownership。

当前源码的双 alias 前向恢复、purge 后故障重放、effect-free 再重放及 isolated pointer-removal
planner 证据见 [2026-07-15 physical-owner report](../evidence/2026-07-15-physical-owner-route-restoration.md)。
该证据使用内存 provider protocol，不替代真实云或生产回滚。

## Mutable topology removal 的封闭授权

`beta`/`latest` restore 可把 parent 当前有、历史 intent 没有的 asset serving path 编码为
`DeleteAssetServing`；APT `dists`、YUM legacy `repodata` 与 public mirrorlist 编码为
`DeleteRestoreIndexServing`。授权同时绑定 parent generation 的 `content_manifest_sha256`、旧 manifest
中的精确 source path/size/SHA、frozen classifier 的 remote key 与 clean CDN route。每次 live DELETE
还必须通过 ADR-0011 的能力探针；默认要求 ETag CAS，只有显式 `checkpoint-fenced` 且满足
ADR-0036 的 writer-revocation、远端发布围栏与连续双正文证明时才允许供应商无条件删除。APT pool、YUM Packages、immutable generation、
CAS、Git 历史与 `objects/sha256` archive 均不删。

若 parent 多出整个 leaf/ref，restore 只从 parent `DesiredCommit` 的 canonical `config/sow.yaml`
恢复精确 repo/type/path/OS/arch 投影并增加空 exact-replace scope；不从 ref 字符串猜路径。新的
generation/ref/channel 向历史 intent 收敛，本地 remote refs 在同一 recoverable Git transaction 中
compare-and-delete。parent config 缺失/损坏、snapshot topology 与 stable 的任何非完全相同 ref
vector 仍失败闭锁；本决定不是一般化任意 key、package payload 或 immutable metadata deletion。

## 结果

- 已提交发布的业务回退成为一次新的、可审计、可恢复的前向发布；generation/parent 链与
  target 独立性不被破坏。
- restore 后 remote ref 有意可能落后于当前 local desired view。再次普通 publish 会把它
  前向推进；运维审计必须区分“历史代已按意图恢复”与“remote 等于当前 desired”。
- 真实 R2/Cloudflare 与 COS/EdgeOne 回滚演练仍需要各自凭据和获批窗口；协议夹具不能冒充
  供应商生产 PoC。
