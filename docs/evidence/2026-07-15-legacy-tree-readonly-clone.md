# 存量仓库只读副本盘点与规模证据 — 2026-07-15

## 结论

本轮只读取 `/Users/vonng/pgsty/repo` 以建立 APFS CoW 副本，随后所有盘点、拓扑审计、
serving-byte 快照和规模测试都只针对 `/private/tmp` 下的副本。原目录没有成为任何写入、
纳管、物化、迁移或恢复命令的目标；CO/COS、Cloudflare 生产仓库、bucket、Zone、domain
也没有被访问或用作测试目标。

这份证据证明当前存量本地树可以被完整配置/迁移台账识别，并证明真实 72,310 个 APT/YUM
文件的 manifest 扫描仍是有界并行路径。它不是生产切换、真实 signer、云发布或双 origin
回滚通过声明。

后续没有改变这份只读基线，而是从同一安全快照建立另一个 inode 独立的可写副本，
完成 M0、可证明 APT/YUM/asset 子集 adoption，并 fail-closed 记录源数据缺口；见
[2026-07-16 full-copy evidence](2026-07-16-legacy-tree-full-adoption-copy.md)。本报告以下
“尚未 adoption”均是对 2026-07-15 此次只读运行的历史陈述，不应解释成后续工作未发生。

## 副本边界

源树先以 `cp -cR` 建立 APFS clonefile 副本。扫描前后的只读身份检查为：

| 项目 | 源树 | 副本 |
|---|---:|---:|
| device:root inode | `16777233:5551832` | `16777233:74638033` |
| regular file | 75,353 | 75,353 |
| logical KiB (`du -sk`) | 119,601,412 | 119,601,412 |

两棵树在同一 APFS device 上但根 inode 不同；后续命令中的 `--legacy-root` 与
`SOW_PERF_ROOT` 都只指向副本。副本本身在本轮也只读，尚未用于 adoption 或 materialize。
建立副本时没有取得旧 writer 的全局冻结，因此 `cp -cR` 不是整个 75k-file tree 的原子
时间点；本报告只陈述实际读到的副本，不把它冒充正式 cutover baseline。

## 完整存量布局审计

在严格离线、无云凭据环境中对副本执行：

```sh
docs/migration/audit-legacy-targets.sh \
  --legacy-root /private/tmp/sow-prod-repo-copy.8szcW6/repo

docs/migration/audit-physical-topology.sh \
  --legacy-root /private/tmp/sow-prod-repo-copy.8szcW6/repo
```

实测结果：

- 旧 Makefile 合同：176 targets、44 operation families；machine map SHA-256
  `eb557046…`，冻结的生产来源 fingerprint 全部匹配。
- 物理拓扑：74 APT index、130 ordinary YUM repodata leaf、1 nested quarantine、
  7 root exact key、8 root prefix、16 gated Pro file。
- 审计只读取路径、类型与既有冻结清单要求的非秘密元数据；不把 signer、lifecycle、
  私钥内容或 gated 正文标记为已验证。

## 敏感文件不留痕的 serving-byte 快照

旧快照脚本会把仓库旁的私钥/认证文件也计算 SHA-256。该路径在发现后立即中断，临时文件由
trap 清理；修复后的脚本先进行纯路径预检，并对 reviewed sensitive-path list 中的条目直接
跳过，不打开正文，也不把 path、size 或 digest 写进 TSV。未列入 review 的可疑名称在任何
普通文件开始哈希前失败关闭。

```sh
docs/migration/snapshot-serving-tree.sh \
  /private/tmp/sow-prod-repo-copy.8szcW6/repo \
  /private/tmp/sow-prod-repo-copy.8szcW6/serving-before.tsv
```

current-source 实测输出：

```text
snapshot=/private/tmp/sow-prod-repo-copy.8szcW6/serving-before.tsv files=75034
safe_snapshot=pass files=75034 schema=path_size_sha256 sensitive_paths_persisted=false
```

独立 schema 检查要求每行恰为 `path<TAB>size<TAB>sha256`，并逐项确认默认 reviewed
sensitive paths 均未出现在输出。默认清单只保存路径，不保存秘密值；`.git`、`.sow` 与
`.pool` 控制树仍按既有合同排除。脚本注释与 runbook 继续要求在真实迁移时先冻结所有 writer；
逐文件前后 size 检查不冒充多文件原子快照。

## 真实 72k manifest 性能

```sh
SOW_PERF_ROOT=/private/tmp/sow-prod-repo-copy.8szcW6/repo \
  go test -tags perf ./test/perf \
  -run '^TestLargeRepositoryManifest$' -count=1 -v
```

在 Apple M5 Max、128 GiB、Go 1.26.5 darwin/arm64 上实测 PASS：

| 范围 | 文件 | bytes | elapsed |
|---|---:|---:|---:|
| APT | 40,681 | 47,155,427,190 | 5.012s |
| YUM | 31,629 | 42,707,068,318 | 4.139s |
| 合计 | 72,310 | 89,862,495,508 | 9.151s |

总用时 10.008s，18 workers。结果证明真实近 90GB serving payload 没有被整库读入内存，
也没有退化成单 worker；它不替代 APT/YUM 50k 索引生成、50k hardlink、发布调用数、RSS
以及真云时延的各自证据。

## 仍未闭合

1. 副本尚未进行写入式完整 adoption/materialize/rollback；下一步也只能在该副本的再次可丢弃
   clone 上执行，不能修改源树或本副本基线。
2. 存量私钥、认证文件、gated 正文和未审核 RPM signer 不在本证据读取范围；不得拿它们作为
   测试签名材料。
3. CO/COS 与 Cloudflare 生产资源永久禁止测试；本地副本证据不替代专用非生产云资源 PoC。
4. 工作区基于 Git `84800a60e01aaaf8dc5b189c3ddb1380930f4865`，但有 353 个
   porcelain 条目；本报告是该次 current-source 观察摘要，不是 clean revision 身份。
