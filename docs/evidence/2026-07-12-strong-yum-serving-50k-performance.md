# strong-YUM 50k generation 性能与并行证据

日期：2026-07-12（Asia/Shanghai）
环境：Apple M5 Max，Darwin 25.5.0 arm64，Go 1.26.5，APFS
基线提交：`84800a60e01aaaf8dc5b189c3ddb1380930f4865`（本证据绑定下列未提交源码摘要）

## 覆盖路径与边界

`internal/cli/materialize_serving_perf_test.go` 直接调用生产
`activateLocalYUMServing`，不是通用 CAS benchmark 或只测 YUM metadata。夹具包含 4 个
独立 repo/OS/arch leaf（EL8 x86_64、EL9 aarch64、EL10 x86_64、EL10
aarch64），每 leaf 12,500 个 raw strong-serving coordinate，总计恰好 50,000。
测试连续执行：

1. 第一代扫描、derive、`InstallGeneration`、canonical ledger 与 mirrorlist flip；
2. ref 前进后的第二代，并保留每 leaf 的 `current + Previous`；
3. 同一 ref 的幂等 replay，逐 leaf 恢复/校验 current + Previous；
4. production local strong L1 checks；
5. production serving GC plan 收集与 8 个 protected generation preflight。

为避免夹具本身占用数十 GB，50,000 个坐标循环引用 256 个不同 CAS object；每个
generation 的 50,000 条 manifest、hardlink、权限、inode/CAS 绑定、全树扫描和 ledger
仍是真实文件系统操作。每个 view leaf 只放 1 条、随后 2 条合法 view entry，用来推动
两次 ref commit；因此本测试**不是 50,000 个不同 RPM 包体/50,000 条 view algebra 的
证明**。它必须与 `2026-07-12-yum-streaming-50k-performance.md` 组合解读：后者实际执行
50,000 次真实 RPM header 解析和 50,000 组 primary/filelists/other record 生成/回读。

## 生产改动与恢复不变量

- leaf 按稳定 key 排序后进入有界 worker pool；8 个总 worker 在 4 leaf 时拆为
  `4 outer × 2 inner`，不会平方级放大。
- canonical Git worktree 的读侧由共享 gate 保护；ledger commit 与 mirrorlist flip 在
  独占区内单写、确定性串行。
- 每个 leaf 在 `InstallGeneration` 前先持久化自己的 `install-intent` journal。正常测试
  在并行安装后取消 context，确认 intent journal 存在，再由 production recovery 与
  无 hook 重试收敛且不留 journal。
- fault-injection phase hooks 自动退化为单 worker，既有精确崩溃边界测试语义不变。
- 并发首次创建 `serving-journal/` 接受可信的 `EEXIST` race 后重新 Lstat，并继续拒绝
  symlink/特殊文件。
- CAS 流式校验复用有界 256 KiB buffer pool；第一代累计分配由首次观察的约 21.9 GB
  降至约 9.0 GB。strong L1 的 outer check 与 inner generation scan 也共享总 worker
  预算，最终 verify 峰值 heap 从并发预算修复前的约 238.9 MB 降至约 48.7 MB。

## 可复现命令

```bash
go test -tags=perf ./internal/cli \
  -run '^TestStrongYUMServingFiftyThousand$' -count=1 -v

go test -race ./internal/cli \
  -run '^TestLocalYUMServingRunsIndependentLeafWorkersConcurrently$' \
  -count=1
```

## 实测结果

最终 product-source 摘要
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`
门禁：`PASS`，总测试 wall time `135.23s`（Go package `135.606s`）。该次运行包含
最终的 sorted commit turn、buffer pool 与 bounded verify worker 代码：

| phase | wall | peak Go heap | retained heap | process MaxRSS at phase end | cumulative alloc |
|---|---:|---:|---:|---:|---:|
| generation-1 | 24.226s | 34.79 MB | 3.13 MB | 63.98 MB | 9.00 GB |
| generation-2 current+Previous | 41.455s | 45.69 MB | 3.15 MB | 76.16 MB | 14.24 GB |
| replay current+Previous | 33.776s | 35.92 MB | 3.16 MB | 76.23 MB | 9.82 GB |
| strong L1 verify | 5.782s | 42.83 MB | 3.14 MB | 78.67 MB | 4.25 GB |
| serving GC preflight | 8.557s | 16.31 MB | 3.13 MB | 78.86 MB | 4.32 GB |

三个 activation phase 均实测：

```text
peak_leaf_workers=4
peak_install_workers_per_leaf=2
combined_peak_worker_bound=8
```

正常并发/取消恢复用例在 race detector 下通过：

```text
ok github.com/pgsty/sow/internal/cli 6.580s
```

同一用例用 barrier 强制排序靠后的 `rpm-two` 先完成 prepare，最终 hook 仍观察到
`rpm-test,rpm-two` 的 canonical commit 顺序；随后让首个 sorted leaf 在 commit turn 前
取消，20 秒 deadlock 门禁内确认后序 leaf 没有提交、两个 generation-ready journal 可由
production recovery 清理并由普通重试收敛。read-only replay 也通过同一 turn chain，未
占住或遗漏 turn。

perf 门禁要求每 phase 小于 5 分钟、峰值 Go heap 相对 baseline 小于 512 MiB；实测最慢
phase 约 43.37s，最终有界 verify 的峰值 heap 约 48.7 MB。MaxRSS 使用
`getrusage(RUSAGE_SELF)`，是进程截至该 phase 的高水位，不是隔离子进程的瞬时 RSS。

## 2026-07-15 current-source follow-up

current-source 重跑先发现历史性能夹具直接用 `state.Store.Apply` seed view，未提交 canonical
`config/sow.yaml`、未经过 `applyCanonicalState`/SQLite projection，而且把真实 PGDG RPM
伪装成 `perf-*` name/version。当前 catalog 的 package-body identity gate 正确 fail closed。
修复没有绕过产品校验：首代 seed 现在提交 canonical config，两个 view commit 都走
production catalog mutation/rebuild/advance，entry name/version/hash/size 均来自 production
RPM inspector，第二代使用不同 version/body identity。该合成 successor 只服务性能与状态
投影测试，不作为 package-signature 信任证据。

修复后的严格离线 ordinary/race 都完成两代、current+Previous、重放、L1 与 GC：

| phase | ordinary wall / peak heap | race wall / peak heap |
|---|---:|---:|
| generation 1 | 55.226s / 56,348,536B | 65.328s / 48,726,136B |
| generation 2 + Previous | 90.104s / 51,659,696B | 104.346s / 49,224,232B |
| replay | 75.429s / 49,320,896B | 74.340s / 50,928,880B |
| L1 | 31.962s / 87,174,952B | 30.706s / 80,492,248B |
| GC preflight | 35.498s / 21,279,088B | 47.030s / 21,252,008B |

ordinary test/package 为 `309.94s`/`311.290s`；race 为 `346.78s`/`349.037s`，无 race
report。两个 activation 均观测 `peak_leaf_workers=4`、
`peak_install_workers_per_leaf=2`、combined bound `8`。ordinary/race 的进程 MaxRSS 高水位
分别为 `135,184,384B` 与 `403,013,632B`。每 phase 仍低于 5 分钟与 512 MiB heap 硬门。

完整 current-source 组合见
[`2026-07-15-current-source-validation.md`](2026-07-15-current-source-validation.md)。

## 源码摘要

```text
1048071d9e9b5df7c592b6b2283e56838eb1ec44a50f5ddaeb81baa1f046c33d  internal/cli/materialize_serving.go
c2f04756b4df46846b6dfaeea8ffb6900dca7fb8b503bc01848906039bb05c76  internal/cli/materialize_serving_perf_test.go
8158908e728e8545925b773c1fc7c7dc538937ba36e8a3dbda587b6a2d0a1c45  internal/cli/materialize_serving_payload_closure_test.go
640f80175d7a76039a9107a23e7af669c64448448184a2de99d93d459e3ca532  internal/serving/install.go
e60614ef43a058f47d53d825cb659394469b4ce2a7b2ded8d62898e6e415f09c  internal/repository/cas.go
779da4317a84ac9cc4d5d683d8efdf50663890c1fa7cf99660cfc8d3a7c67e24  internal/cli/verify_serving.go
```

上列摘要绑定本次实跑后的当前工作树；由于尚未形成新提交，复验时仍应同时记录新的
`git rev-parse HEAD`、`shasum -a 256` 与完整命令输出，不能只引用本文代替测试。

## 结论边界

该证据关闭的是 NFR-01/NFR-02 在 strong-YUM `current + Previous` 本地 generation
transaction 上的多 leaf 串行缺口：实际 production activation 达到 leaf 并发，worker
预算有上限，replay/verify/GC 在 50k 坐标下均完成，且中断仍可恢复。它不替代 50,000
个不同大 RPM 的磁盘/网络吞吐、真实 DNF 消费、R2/COS 上传、CDN purge 或供应商 PoC。
