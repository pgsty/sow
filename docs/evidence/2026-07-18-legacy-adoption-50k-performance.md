# Legacy asset adoption 50k 专项性能证据

日期：2026-07-18（Asia/Shanghai）
环境：macOS 26.5.2（25F84），arm64，Go 1.26.5，APFS
源码基线：`84800a60e01aaaf8dc5b189c3ddb1380930f4865` 上的长期 Goal 工作树（非 clean revision）

## 验证对象与安全边界

[`legacy_adoption_50k_test.go`](../../test/perf/legacy_adoption_50k_test.go) 通过真实
`cli.Main` 调用 `sow init --adopt-content`。夹具在 `t.TempDir` 中创建 50,000 个路径和
正文都不同的小 asset，总正文 1,250,000 bytes；配置没有 target、credential 或网络入口。
测试没有读取或写入 `/Users/vonng/pgsty/repo`，也没有访问 CO/COS/Cloudflare 或任何其他
远端。所有 serving、CAS、Git state、SQLite spool 和证据 manifest 都位于测试临时目录。

本用例与旧 materialize 50k 夹具不同：它真实覆盖 init baseline scan、transaction-wide
SQLite spool、生产并发 CAS import、view/legacy receipt canonical commit、cache rebuild，
以及第二次完整 CLI 幂等重放。每个 payload 都有独立 SHA-256/CAS object，不用一个对象的
50,000 个 hardlink 冒充 adoption I/O。

## 可复现命令

```bash
go test -tags perf ./test/perf \
  -run '^TestLegacyAssetAdoptionFiftyThousand$' \
  -count=1 -v -timeout=35m
```

实际退出 0：

```text
legacy-adoption50k entries=50000 unique_payloads=50000 bytes=1250000
workers=8 peak_import_workers=8
fixture=2.542443s adopt=12m9.369555208s replay=6m12.054509708s
view=50000 receipts=50000 cache=50000 cache_provenance=50000 cas=50000
baseline_heap=3585168 sampled_peak_heap=128682672 sampled_peak_growth=125097504
retained_heap=4139056 retained_growth=553888
baseline_rss=50921472 first_rss=188661760 replay_rss=189906944 rss_growth=138985472
tuple_closure_sha256=845e39df9500dcb804c7c21f89336fd534591b5aabaa15a7bfc214e1d02ca45a
provenance_closure_sha256=1577eccd1c6febec1c4f0e4ad18357a4c20580ba51d12dee92c844ed9271ce57
serving_manifest_unchanged=true replay_changed=false
--- PASS: TestLegacyAssetAdoptionFiftyThousand (1156.07s)
PASS
ok github.com/pgsty/sow/test/perf 1156.737s
```

## 硬门禁与结论

- CLI 总摘要和逐 repo 摘要都报告生产 worker pool 原子观测到的
  `peak_import_workers`，不是把请求的 `--workers=8` 当作实际并发；本轮峰值为 8，且测试
  强制要求 `2..8`。
- 首次运行精确得到 50,000 payload、50,000 CAS object、50,000 view entry、50,000
  `sow-legacy-adoption/v1` receipt 和 50,000 cache manifest row；leaf 为 1。SQLite
  `provenance` 也精确为 50,000，并把 canonical receipt 派生的
  `receipt_id/artifact_sha256/format/kind/repo/source_path/pool/upstream_url/observed_at`
  全字段流与 SQLite 的确定性有序流做 count+SHA-256 对账，摘要同为
  `1577eccd1c6febec1c4f0e4ad18357a4c20580ba51d12dee92c844ed9271ce57`；asset 按 schema 不生成
  package/membership/relation row，三者均精确为 0，而不是拿 files count 冒充 provenance。
- baseline manifest、canonical view、legacy receipt 与 SQLite manifest projection 都按
  `path/size/SHA256/pool` 流式计算同一 tuple closure，摘要均为
  `845e39df9500dcb804c7c21f89336fd534591b5aabaa15a7bfc214e1d02ca45a`；随后逐项
  `pool.Verify` 所有 50,000 个不同 CAS object，不只统计文件名。
- adoption 前、首次提交后、幂等重放后的三份 production manifest scan 字节摘要相同；
  serving tree 没有被修改。
- 第二次完整 CLI 仍扫描、验证并导入同一 50,000 项，但报告 `changed=false`，canonical
  HEAD 不前进，CAS object 数不增长。
- 首轮和 replay 全程以 5 ms 采样 `HeapAlloc`，观测 peak growth 125,097,504 bytes，低于
  384 MiB 硬上限；首轮 GC 后 retained growth 553,888 bytes，低于 96 MiB 硬上限。采样值
  明示为 sampled，不冒充不可漏采的瞬时峰值。
- 同时读取 OS `getrusage(RUSAGE_SELF).ru_maxrss` 进程高水位：fixture 后 baseline
  50,921,472 bytes、首轮后 188,661,760 bytes、replay 后 189,906,944 bytes，增量
  138,985,472 bytes，低于 768 MiB 硬上限。RSS 是进程生命周期高水位，补足 Go heap
  采样无法覆盖 runtime/mmap/SQLite/native allocation 的边界。

## 边界

本夹具刻意使用 50,000 个不同的小正文，证明 metadata/inode/CAS/adoption 扩展性；它不是
50,000 个大包的磁盘带宽模型，也不测 DEB/RPM parser、真实迁移 writer freeze、生产 Nginx
门禁或云发布。首次 adoption 12m09s 是本机、当前受争用工作树的本地观测，不可外推为
ANTI-01 的生产同变更集双云事务指标；完整用例低于 35 分钟 fail-closed 超时，且没有单
  worker 或整库 retained-heap 退化。本报告的 RSS 结论仅是“本次 50k 单点高水位增量低于
  768 MiB 门禁”；单一规模点不证明增长斜率，也不冒充 retained RSS 测量。
