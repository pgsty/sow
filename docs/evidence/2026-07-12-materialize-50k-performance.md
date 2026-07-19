# CAS / hardlink 50k 物化性能证据

日期：2026-07-12（Asia/Shanghai）
环境：Apple M5 Max，Darwin 25.5.0 arm64，Go 1.26.5，APFS

## 验证路径

`test/perf/materialize_50k_test.go` 通过生产 `repository.Store` 建立 CAS object，
流式读取含 50,000 个逻辑路径的 manifest，以 8 个 worker 完成逐对象校验与 hardlink
安装，再运行生产 `ReconcileExact` 的全树并行 hash scan、流式 diff 和 inode 抽样。
所有 50,000 个路径引用同一 4 KiB CAS object，以便把测量集中在 manifest、inode、
目录与 hardlink 扩展性；因此 200 MiB 逻辑字节不是 50,000 个真实包的带宽模型。

实现采用有界 job/result channel，内存与 worker 数和 manifest reader 的小缓冲相关，
不保留全量 entry slice。目录持久化屏障在成功批次末尾对每个真实目录执行一次；
中断留下的部分 hardlink 可由同一 manifest 安全重放。

## 诊断与修复

第一次实跑暴露了真实瓶颈：旧实现每创建一个 hardlink 就对父目录 `fsync`，测试运行
149.03s 后仍未完成，遂主动中断。该结果没有被当作通过。修复为“批量安装后每目录
一次 durability barrier”并保留失败重放语义，随后同一用例完成。

## 可复现命令与结果

```bash
bin=$(mktemp /tmp/sow-materialize-perf.XXXXXX)
go test -tags perf -c -o "$bin" ./test/perf
/usr/bin/time -l "$bin" -test.v \
  -test.run '^TestMaterializeFiftyThousand$' -test.count=1
rm -f "$bin"
```

```text
materialize50k entries=50000 workers=8
materialize=11.323529041s reconcile=2.836211s
baseline_heap=418728 retained_heap=592104 growth=173376
--- PASS: TestMaterializeFiftyThousand (16.41s)
16.83 real, 3.55 user, 35.25 sys
maximum resident set size 21905408
peak memory footprint 18006688
```

测试硬门禁要求 GC 后绝对 heap 小于 64 MiB、增长小于 48 MiB；实测增长约 169 KiB，
独立进程最大 RSS 21,905,408 bytes。抽样的首、中、末路径均与 CAS object 为同一
inode，reconcile 删除数为 0。

最终 product-source 摘要
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`
与 YUM/publish-plan 规模测试在同一进程重跑仍通过：`entries=50000 workers=8
peak_workers=8 materialize=11.036556959s reconcile=2.529256542s
baseline_heap=841800 retained_heap=993176 growth=151376`，测试耗时 15.37s。

增加 worker 峰值仪表后又在两个 `internal/cli` 测试进程同时运行的共享开发机上复跑：

```text
entries=50000 workers=8 peak_workers=8
materialize=54.135296916s reconcile=3.16092825s
retained_heap=839976 growth=165520
PASS (74.70s), maximum RSS 28180480
```

该受争用结果证明实际达到配置上限 8 个并行 job，且在明显 CPU/文件系统竞争下仍于
75.16s wall time 内完成；文档同时保留无该并行测试负载时的 11.32s 结果，不用单次
最好值掩盖环境敏感性。默认单元测试另以 32 个 800 KiB hardlink job 断言峰值必须
在 2..4 worker 之间，并在 race detector 下通过。

## 边界

该证据证明 50k 逻辑文件的本地 CAS/hardlink 物化与全树核对不会因整库内存或逐文件
durability barrier 卡死。它不替代 50,000 个不同大包的磁盘读取量、跨文件系统（产品
明确要求 hardlink，因此会失败关闭）或双云网络发布测量。
