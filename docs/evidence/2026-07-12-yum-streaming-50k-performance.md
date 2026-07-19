# YUM 50k 流式索引证据

日期：2026-07-12（Asia/Shanghai）
环境：Apple M5 Max，Darwin 25.5.0 arm64，Go 1.26.5

## 覆盖路径

`test/perf/yum_streaming_50k_test.go` 调用生产 `yumrepo.Generate` 与
`yumrepo.ValidateDirectory`，覆盖真实 RPM header 解析、primary/filelists/other
三路磁盘 spool、EL10 zstd 压缩、repomd.xml 生成、纯 Go OpenPGP detached
签名以及完整流式回读校验。输入 iterator 每次只提供一个 `PackageInput`，生成器
不接受或保留全量 package slice。

2026-07-12 当时的夹具为一个真实已签名 PGDG noarch RPM，在 50,000 个不同且已排序的
canonical basename 下重复解析。后来加入的 streaming self-validator 正确拒绝同一 package
body 在一个 channel 中出现多次；当前夹具与结果见下方 2026-07-15 follow-up，不能再用本段
历史夹具描述解释当前测试。

## 可复现命令

```bash
bin=$(mktemp /tmp/sow-yum-perf.XXXXXX)
go test -tags perf -c -o "$bin" ./test/perf
/usr/bin/time -l "$bin" -test.v \
  -test.run '^TestYUMStreamingFiftyThousand$' -test.count=1
rm -f "$bin"
```

## 实测结果

```text
yum50k packages=50000 elapsed=3.82773275s
baseline_heap=443968 retained_heap=492496 growth=48528
compressed_metadata=152301
--- PASS: TestYUMStreamingFiftyThousand (5.72s)
6.15 real, 5.17 user, 0.78 sys
maximum resident set size 53149696
peak memory footprint 48464424
```

测试硬门禁要求 GC 后绝对 heap 不超过 128 MiB且相对增长不超过 96 MiB；本轮保留
heap 增长 48,528 bytes，独立测试进程最大 RSS 53,149,696 bytes。生成结果由同一
生产验证器再次确认包数 50,000、repomd SHA-256 一致且签名有效。

最终 product-source 摘要
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`
组合门禁重跑：`packages=50000 elapsed=4.00766275s baseline_heap=1011216
retained_heap=1041120 growth=29904 compressed_metadata=152303`，测试耗时 6.01s，
repomd SHA-256 为 `89d55609f7531de9b645d8f1757598c2da75ae9f030f038ad8d4bd562f4639c8`。

## 2026-07-15 current-source follow-up

当前 self-validator 以完整 RPM SHA-256 作为 `pkgid`，并通过有界外排排序同时校验
primary/filelists/other 的 identity set。最初重跑因此以 `duplicate pkgid` 拒绝了历史性能
夹具；这是产品不变量生效，不是生成器回归。修复只改测试：每次同步 parser 调用前，为
同一真实 RPM header 写入固定长度、随序号变化的测试 trailer，使 50,000 个 package body
checksum 各不相同。另加普通/race 单测，证明不同 basename 不能绕过重复 body 拒绝，且
失败不留下 generation/staging residue。生产校验没有放宽。

严格离线 ordinary 结果：

```text
yum50k packages=50000 elapsed=6.250069667s
baseline_heap=1469784 retained_heap=1490856 growth=21072
compressed_metadata=5893488
--- PASS: TestYUMStreamingFiftyThousand (8.48s)
ok github.com/pgsty/sow/test/perf 28.761s
```

同一 materialize/publish-plan/YUM 组合的 race 结果为 package `104.885s`；YUM phase
`80.84s`，生成 elapsed `48.269957792s`、保留 heap `+19,888B`、compressed metadata
`5,895,861B`，无 race report。重复 body 负例的完整 `internal/yumrepo` 包 ordinary/race
分别 `9.381s`/`12.782s` PASS。

测试 trailer 只构造 parser 可接受、checksum 不同的性能 body；本节不声称 50,000 个
供应商签名各异的可安装 RPM。真实 RPM 签名、DNF 安装与 `rpm -K` 证据由 current-source
Docker 矩阵单独提供。

## 结论边界

该结果证明 YUM 索引核心在 50k record 下不是整库常驻内存路径。它与真实 72,310
包 serving-tree manifest 测量、APT 50k component×arch 测量和 sync 50k spool 测量
共同覆盖 NFR-01/NFR-02 的主要子系统；仍不替代含 50,000 个不同真实 RPM 字节的
端到端 publish 网络带宽、双云时延或 CDN purge 测量。
