# 2026-07-20 reachable-history 配置内存上限

## 结论

asset 与 APT/YUM 物理所有权审计不再按 reachable commit 或唯一 blob 数量长期保存
`*config.Config`。两个扫描器现在只为 commit 保存轻量 `BlobIdentity`，并共用同一实现的
LRU：最多两个已解码配置，按其 canonical 输入大小计费最多 16 MiB。单个配置仍受
8 MiB 声明大小门禁和 `limit+1` 实读门禁约束。

cache miss 在读取、解码新配置前先逐出最旧项；随后按记录的 immutable Git blob identity
重新打开对象，并依次核对对象类型、声明大小、实际读取长度和重新计算的 Git blob hash。
loader、size、hash 或 YAML decode 失败都不会进入缓存，因此下一次访问会重新读取并再次
fail closed。asset/package 历史图也不再保留无界 tree map。等价 owner 合同只保留一份；
一旦历史已经出现差异，每个 repo 最多保留足以生成确定冲突的两份合同证据。保留的
repo 合同深度复制所有 slice、map 与 pointer 字段，不再借浅拷贝把已淘汰 config 的对象图
留在堆中；相同合同的 asset anchors 复用这份 detached 数据，冲突 pair 建立后该 repo 的
anchors 被立即丢弃。

adversarial review 还拒绝了“以反复解码换内存”的实现：asset anchor 在首次扫描中流式
归并，continuity 以 commit 为外层且 reintroduction 只读紧凑 commit hash；package lineage
在一次 parents-first pass 中同时推进全部 populated repo，并在父状态被最后一个 child 使用后
释放 active frontier。presence 只为实际有 anchor 的 asset repo 记录；package 每 repo 只保存
按既有 priority/message 排序会被返回的确定性最佳 finding。因此每阶段每 commit 至多解码
一次，错误证据也不再按 commit×repo 累积。

## 已实跑验证

主代理在当前 review candidate 上独立运行：

```bash
go test -timeout 20m -count=1 ./internal/cli \
  -run 'HistoricalConfigCache|PackageRepository|AssetProjection|GCRejectsRestoredHistoricalPackage|OffHead'
go test -race -timeout 20m -count=1 ./internal/cli \
  -run 'HistoricalConfigCache|PackageRepository|AssetProjection|GCRejectsRestoredHistoricalPackage|OffHead'
go test -timeout 10m -count=1 ./internal/cli \
  -run 'HistoricalConfigCache|AssetProjectionHistoryConfigCache|PackageRepositoryHistoryConfigCache'
go test -race -timeout 10m -count=1 ./internal/cli \
  -run 'HistoricalConfigCache|AssetProjectionHistoryConfigCache|PackageRepositoryHistoryConfigCache'
go test -count=1 ./internal/config ./internal/state
go test -race -count=1 ./internal/config ./internal/state
```

post-review affected broad ordinary/race 分别为 `11.903s` 与 `33.793s`；最终新增 focused
ordinary/race 分别为 `1.643s` 与 `2.651s`。
config/state ordinary 分别为
`1.311s`/`6.281s`，race 分别为 `13.085s`/`14.854s`，全部 PASS 且无 race report。

测试直接观测 current/peak entries、canonical bytes、hit/miss/load/eviction。真实临时 Git
fixture 先清空 ownership evidence 并写入冻结合同漂移，再追加六个唯一 canonical config
blob，强制发生多次淘汰；测试定向载入该违规 identity、用两个后续 blob 将其逐出，再断言
下一次访问 load 计数精确增加且内容仍为原违规合同。asset continuity 与 package lineage
因此是实际发现者，而不是由 populated owner-pair 快速比较代证；canonical HEAD 前后相同。既有
off-HEAD `refs/sow/*`、clock-skew merge、删除/重引入、GC restored-history 与 missing-config
负例也包含在 affected 集合中。独立单元负例证明 loader、声明/实读 size、hash 与 decode
失败均可重试而不被缓存。load 上界断言证明 asset 两阶段总 load 不超过 `2×commits`、
package lineage 单阶段不超过 `commits`；四个相邻 commit 复用同一 config blob 的集成测试还证明缓存
至少产生三次 hit，而每个 commit 的 ownership evidence location 仍精确绑定各自 commit。

## 冻结源码全量门禁

adversarial review 修复完成后，同一冻结源码上的 706 个 CLI tests 以 CI 同构正则分成
六片。普通与 race 均 6/6 PASS，无 race report：

| shard | tests | ordinary | race |
|---|---:|---:|---:|
| `A-F` | 157 | 581.305s | 723.599s |
| `G-M` | 154 | 876.925s | 990.200s |
| `N-O` | 51 | 270.697s | 321.612s |
| `P-Q` | 150 | 991.964s | 1183.151s |
| `R-V` | 123 | 595.499s | 745.218s |
| `W-Z/other` | 71 | 228.679s | 318.654s |

除 `internal/cli` 外的 16 个有测试 package 也分别完成 ordinary/race；`cmd/sow` 无 test
file。`go vet ./...`、perf-tag vet、两个 repository Staticcheck profile、root/nested
`go mod tidy -diff` 与 `go mod verify`、nested RPM tests/vet、fresh-cache RPM upstream
provenance 均退出 0。固定 `govulncheck@v1.6.0` 对主模块报告可达漏洞 0（required module
中一条 advisory 不在调用图），对 nested RPM module 报告 `No vulnerabilities found`。

`CGO_ENABLED=0` 的四个 `-trimpath` 二进制均构建成功：

| target | SHA-256 |
|---|---|
| linux/amd64 | `4972ea7b0b01d8da8baec390ff0ef7365ab5339944670ac7a47d7e03f841c296` |
| linux/arm64 | `b2312d40c1af3722e3cdfcd02ac7798447872975722dafdfee65f3877595b156` |
| darwin/amd64 | `5b4b866bab20f865adba74af2c5db15d07e38772891147cb364f906d6d97578c` |
| darwin/arm64 | `36646e7bf073623240a8eaf3892418d18ca4754e7e4aa3392a0c8fe6af6063eb` |

七个 migration shell suites 全部退出 0；family gate 报告 44 families、5 mutation
negatives 与 16 个真实 CLI E2E，且显式输出 `external_network=disabled`、
`production_mutation=none`。clean-delivery allowlist/policy test 通过；交付文件冻结后的两次
独立 fresh HOME/GOMODCACHE/GOCACHE 重建、归档逐字节比较与最终 identity 记录在交付根外
handoff ledger 的 V-42，因此不会用自引用文档改写其所证明的归档。

## 证据边界

全部命令只读取本地源码、只读本机 module download cache 与临时 fixture，只写本地测试或
`/tmp` 输出。真实云开关均为 0，AWS config/credential 文件指向 `/dev/null`，Cloudflare
API token 为空；未访问或写入 CO/COS、Cloudflare 生产仓库、授权的 `pro` 测试桶、Zone、
Worker、CDN 或 EdgeOne。本轮不升级任何真实云、边缘或生产迁移状态。
