# Publish 50k / 单变更规划证据

日期：2026-07-12（Asia/Shanghai）
环境：Apple M5 Max，Darwin 25.5.0 arm64，Go 1.26.5

`test/perf/publish_plan_50k_test.go` 生成两个各含 50,000 项的 canonical manifest，
仅第 25,000 项摘要不同，然后调用生产 `publish.BuildPlan` 的流式 merge-diff 与
`WithCDN` closure。分类器把变化项映射到新的 content-addressed remote key。

```bash
bin=$(mktemp /tmp/sow-publish-plan-perf.XXXXXX)
go test -tags perf -c -o "$bin" ./test/perf
/usr/bin/time -l "$bin" -test.v \
  -test.run '^TestPublishPlanFiftyThousandOneChange$' -test.count=1
rm -f "$bin"
```

```text
publish-plan50k entries=50000 changed=1 objects=1 elapsed=11.739292ms
baseline_heap=675976 retained_heap=716000 growth=40024
--- PASS: TestPublishPlanFiftyThousandOneChange (0.17s)
maximum resident set size 19415040
peak memory footprint 11600400
```

计划精确包含 1 个 upload object、1 个 CDN verify、0 个 purge URL；没有把 49,999
个未变项保留到 plan。GC 后 heap 增长 40,024 bytes，测试硬门禁为绝对 32 MiB、
增长 16 MiB。结合 publish 协议回归中对实际 PUT/HEAD/purge 调用计数的断言，这证明
日常差异计算与请求集合由变更集大小决定，而不是仓库总条目数。

最终源码摘要
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`
上的组合门禁重跑：`entries=50000 changed=1 objects=1 elapsed=12.368833ms
baseline_heap=993448 retained_heap=1033456 growth=40008`，测试耗时 0.17s，仍只产生
一个变更对象。

代码审查另发现旧的 closure 校验会对每条 Verify 再线性扫描全部 Objects，首次全量
发布因而可能退化为 O(N²)。修复为 URL→expectation 索引后，新增 50,000 个全部变化
对象的默认门禁（不是单变更夹具）：

```text
publish-full-change-set objects=50000 elapsed=92.766291ms
--- PASS: TestPlanLargeClosureValidationIsLinearInChangedObjects (0.10s)
```

该门禁同时限制在 5 秒内完成，并与 2,000 个 YUM leaf 的 alias/channel 双向线性闭包
测试组合，防止验证阶段重新引入整集合嵌套扫描。

该证据不代表真实双云的公网时延；provider CAS、purge、恢复与真实云 PoC 仍有各自
证据/门禁。
