# 72,310 包 manifest 扫描性能证据

日期：2026-07-11  
状态：通过 manifest 子系统门禁；不代表尚未实现的 APT/YUM 索引与发布性能已通过。

## 环境与夹具

- 主机：macOS arm64，18 个逻辑 CPU，128 GiB 内存。
- Go：`go1.26.4 darwin/arm64`。
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
| APT DEB | 40,681 | 47,155,427,190 | 4.318 s |
| YUM RPM | 31,629 | 42,707,068,318 | 3.592 s |
| 合计 | 72,310 | 89,862,495,508 | 7.911 s |

进程级结果：8.72 s real、30.47 s user、27.51 s sys，最大 resident set size 92,094,464 bytes（约 87.8 MiB）。CPU 时间显著高于 wall time，证明哈希路径实际并行；RSS 没有随 72,310 个条目线性膨胀，符合有界分块与流式合并设计。

## 结论边界

此证据可支持 FR-01/NFR-02 中 manifest 的确定性、并行与有界内存实现，也证明超过 PRD 约 5 万包门槛的真实本地文件系统路径可运行。NFR-01、NFR-02 与 POC-07 仍不能整体标为通过：APT/YUM 索引生成、hardlink 物化、repo/component/arch 调度和完整 publish 尚需在同一规模补测。
