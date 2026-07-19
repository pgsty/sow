# 72,310 包 manifest 扫描性能证据

日期：2026-07-11  
状态：通过 manifest 子系统门禁；不代表尚未实现的 APT/YUM 索引与发布性能已通过。

## 环境与夹具

- 主机：macOS arm64，18 个逻辑 CPU，128 GiB 内存。
- Go：`go1.26.5 darwin/arm64`。
- 只读夹具：`/Users/vonng/pgsty/repo`；测试没有在该目录创建 `.sow` 或修改文件。
- 代码：`test/perf/manifest_large_test.go`，使用 `internal/manifest.Scan` 的 18 个有界 worker、2,048 条目外部排序 run 与流式 k-way merge。
- 扫描范围：`apt/**/*.deb` 与 `yum/**/*.rpm`；因此结果证明大规模包体 manifest 路径，不把非包元数据混入计数。

## 可复现命令

```bash
SOW_PERF_ROOT=/Users/vonng/pgsty/repo GOPROXY=off \
  /usr/bin/time -l go test -tags perf \
  -run TestLargeRepositoryManifest -count=1 -v ./test/perf
```

## 实测结果

| 范围 | 文件数 | 字节数 | 扫描耗时 |
|---|---:|---:|---:|
| APT DEB | 40,681 | 47,155,427,190 | 7.150 s |
| YUM RPM | 31,629 | 42,707,068,318 | 4.012 s |
| 合计 | 72,310 | 89,862,495,508 | 11.164 s |

进程级结果：11.96 s real、30.98 s user、36.16 s sys，最大 resident set size 173,195,264 bytes（约 165.2 MiB）。CPU 时间显著高于 wall time，证明哈希路径实际并行；RSS 仍由 18 worker/2,048-entry run 上限约束，而不是把近 90 GB 包体或 72,310 个文件内容整库载入。

最终 product-source 摘要
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`
重跑：APT 40,681 文件/47,155,427,190 bytes 用时 4.914s，YUM 31,629
文件/42,707,068,318 bytes 用时 3.648s，总计 72,310 文件/89,862,495,508
bytes 用时 8.563s，18 workers，package 8.999s，PASS。

## 结论边界

此证据可支持 FR-01/NFR-02 中 manifest 的确定性、并行与有界内存实现，也证明超过 PRD 约 5 万包门槛的真实本地文件系统路径可运行。APT/YUM 索引、hardlink 物化、repo/component/arch 调度、publish plan 与 L3 由 V-08 的其他独立规模报告承担；本报告不替代那些证据，也不代表真云吞吐。
