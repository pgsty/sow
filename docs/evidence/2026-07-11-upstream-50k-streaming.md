# 上游同步 50k 候选流式与并发证据

日期：2026-07-11
环境：Apple M5 Max，Darwin 25.5.0 arm64，Go 1.26.5

## 验证对象

该验证针对 `sync` 的生产候选存储和下载执行器，而不是只测一个脱离 CLI 模型的切片：发现阶段把候选与 provenance proof 写入临时 SQLite spool，计划阶段按确定顺序惰性迭代，执行阶段用有界 worker 从真实 HTTP 测试服务流式下载并提交 receipt。内存中不保留 `[]Candidate` 全量副本。

可复现命令：

```bash
bin=$(mktemp /tmp/sow-upstream-test.XXXXXX)
go test -c -o "$bin" ./internal/upstream
/usr/bin/time -l "$bin" -test.v \
  -test.run 'TestStreamingCandidateStoreFiftyThousandBoundedMemory|TestStreamingExecutorBoundsRealHTTPDownloadConcurrency' \
  -test.count=1
rm -f "$bin"
```

## 结果

- 50,000 个 RPM 候选全部进入磁盘 spool；spool 大小 29,265,920 bytes。
- 确定性迭代读取 50,000 项，计划结果为 50,000 个 present、0 个 download，`Discovery.Candidates` 保持 `nil`。
- GC 后基线 heap 2,293,880 bytes，保留 heap 2,270,424 bytes，测得增长为 0；测试硬门禁同时限制绝对 heap 小于 16 MiB、增长小于 24 MiB。
- 独立测试二进制最大 RSS 31,948,800 bytes；`/usr/bin/time` 的 peak memory footprint 为 20,447,808 bytes。
- 24 个真实 HTTPS 下载由 3 个 worker 执行；测试要求观测峰值并发至少 2 且不得超过 3，实际通过。
- 两项测试总 wall time 1.36s，均 PASS。

最终门禁重跑仍为 50,000 项/29,265,920-byte spool：baseline heap 2,296,304，
retained heap 2,278,168，增长 0；两项测试 0.46s/0.40s，总 package 1.539s，均 PASS。

最终 product-source 摘要
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`
重跑仍为 50,000 项/29,265,920-byte spool：baseline heap 2,269,312，
retained heap 2,282,368，增长 13,056 bytes；两项各 0.46s，总 package 1.381s，PASS。

## 边界

这份证据通过 NFR-01/NFR-02 中的上游候选发现、计划与下载部分；它不替代 APT/YUM 索引生成、完整 materialize 或 publish 的独立 50k 性能证据，也不替代真实 PGDG/Percona 网络与签名链验证。
