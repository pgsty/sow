# APT 50,000 包流式索引性能证据

日期：2026-07-12
状态：通过 APT 索引外排、component×arch 并行与有界内存门禁；不代表 CAS hardlink、YUM 或远端 publish 的 5 万包全链路已通过。

## 环境与夹具

- 主机：macOS arm64，Apple M5 Max，128 GiB 内存。
- Go：`go1.26.5 darwin/arm64`。
- 代码：`internal/aptrepo/stream_test.go` 的 `TestGenerateStreaming50000Performance`。
- 夹具：50,000 条由已解析 control paragraph 形态构造的合成 Debian 包记录，分布到 `main/contrib × amd64/arm64/ppc64el/s390x` 共 8 个 Packages 索引；每条记录仍在生成时核对 source size/SHA-256/control 一致性。
- 参数：每个外排 run 最多 256 条，k-way merge fan-in 最多 64，Packages/gzip/xz/by-hash 使用 4 个有界 index worker；Release/InRelease 在 worker 全部完成后确定性签名。

合成记录用于把测试规模固定为 50,000 且避免持有 50,000 个真实包体副本。真实 `.deb` 的解析、两次文件稳定性检查、产物签名与客户端可消费性由 APT fixture/CLI/compat 测试分别覆盖；本证据只衡量索引阶段的驻留内存、磁盘外排和并行上限。

## 可复现命令

```bash
SOW_RUN_PERF=1 go test ./internal/aptrepo \
  -run '^TestGenerateStreaming50000Performance$' -count=1 -v
```

## 实测结果

```text
apt_stream_50k packages=50000 elapsed=3.045724625s retained_heap=207496 heap_after=53355784 maxrss_raw=296943616 spool_disk=32126600 chunk_peak=256 worker_peak=4
```

| 指标 | 实测值 |
|---|---:|
| 包记录 | 50,000 |
| component×arch 索引 | 8 |
| 索引生成耗时 | 3.046 s |
| spool 后 retained heap 增量 | 207,496 bytes（约 0.20 MiB） |
| 生成完成后 HeapAlloc | 53,355,784 bytes（约 50.9 MiB） |
| 进程最大 RSS（Darwin `getrusage` 字节） | 296,943,616 bytes（约 283.2 MiB） |
| 外排磁盘 | 32,126,600 bytes（约 30.6 MiB） |
| 单 run 峰值条目 | 256 |
| index worker 峰值 | 4 |

## 边界与失败面

同一测试文件的默认测试还实际覆盖：乱序输入、Debian `~` 与 epoch 版本排序、跨 run 重复 identity、取消传播、spool checksum 位翻转损坏、130 个单条 run 的分层归并，以及两架构并发生成后的 Packages parser 消费。默认测试不需要 `SOW_RUN_PERF=1`。

结果证明 APT 索引不再把 50,000 个 `Package`/control paragraph 整库保留在 Go heap 中，并且 component×arch 工作实际达到配置的 4 worker 峰值。最大 RSS 包含 4 个并发 xz/gzip writer、OpenPGP 签名和 Go runtime；它受 worker 上限约束，而不是随包数线性保留。

最终 product-source 摘要
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`
重跑：`packages=50000 elapsed=3.039361208s retained_heap=277616
heap_after=53349704 maxrss_raw=242515968 spool_disk=32126600 chunk_peak=256
worker_peak=4`，package `3.688s`，PASS。
