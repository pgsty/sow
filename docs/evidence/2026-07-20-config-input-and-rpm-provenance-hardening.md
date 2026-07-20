# 2026-07-20 配置输入与 RPM vendor 来源闭包

## 结论

所有 `sow/v1` 配置入口现统一在 YAML、schema/default 处理前最多读取
`8 MiB + 1 byte`。恰好 8 MiB 的有效配置仍可解码；多一字节稳定返回
`config exceeds 8388608-byte safety limit`。真实 CLI 的空仓 `init` 负例以
`ExitConfig` 退出且不创建 `.sow/.pool`；已初始化仓负例还证明 canonical HEAD 与
预置在 `.sow/.pool` 的 canary 原字节不变。reachable Git history 中的
`config/sow.yaml` 也由同一 8 MiB 合同预读，不能借历史合同扫描绕过边界。审查补丁
进一步证明：达到 sentinel 的同次 terminal reader error 不会掩盖稳定超限错误；合法的
sub-limit 输入若经 defaults/canonical formatting 展开超过 8 MiB，会在配置加载阶段失败；
命令打开外部 YAML 前读取 canonical HEAD baseline 时，先检查 Git blob 声明大小并把
实际 hash 流限制在 `8 MiB + 1 byte`，不会先无界计算 identity。

vendored `github.com/cavaliergopher/rpm@v1.3.0` 快照的
`testdata/RPM-GPG-KEY-CentOS-5` 已恢复上游末尾空行。`verify-upstream.sh` 继续钉住
原 module version/sum，并只接受既有显式 patch allowlist；本次没有增加 allowlist。
`.gitattributes` 仅对该上游原字节 fixture 设置 `-text` 并关闭 `blank-at-eof` 诊断，
既阻止 `core.autocrlf` 改写固定字节，也使普通 `git diff --check` 不要求篡改快照；其他
空白检查保持默认。
clean-delivery 构建器也已配置为在抽取树内执行该 provenance gate，因此归档缺文件或
非 allowlist 漂移会直接使重建失败。该脚本关闭外部 checksum service，并把源码内固定的
`h1:UHX46sasX8MesUXXQ+UbkFLUX4eUWTlEcX8jcnRBIgI=` 作为权威：只读本地 module proxy
下载的字节仍须先匹配固定 h1，再逐文件比较。每次比较使用 fresh GOMODCACHE extraction，
因此复用缓存中的可变解包目录不能与同样被篡改的 vendor 树互相自证；抽取验证不依赖公网
checksum 请求。

## 已实跑验证

```bash
go test -count=1 ./internal/config ./internal/state ./internal/cli \
  -run 'OversizedConfig|ConfigAtSizeLimit|CanonicalConfig|FileIdentityAtHeadBounded|PackageRepositoryHistoryRejects'
go test -race -count=1 ./internal/config ./internal/state ./internal/cli \
  -run 'OversizedConfig|ConfigAtSizeLimit|CanonicalConfig|FileIdentityAtHeadBounded|PackageRepositoryHistoryRejects'
GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download \
  bash third_party/cavaliergopher-rpm/verify-upstream.sh
(cd third_party/cavaliergopher-rpm && go test -count=1 ./... && go vet ./...)
go test -count=1 ./test/compat/cleandelivery
go vet ./...
go vet -tags perf ./internal/cli ./test/perf
staticcheck -checks='inherit,-ST1005,-U1000' ./...
staticcheck -checks='SA*,S1*' ./...
```

聚焦 ordinary/race 均通过；RPM provenance 输出确认 `upstream=v1.3.0`、固定 module
sum 且 drift 仅来自既有 allowlist；嵌套模块 test/vet 与 clean-delivery policy tests
通过。当前 697 个 CLI tests 的六个互斥 shard 计数为 155/149/51/148/123/71；ordinary
A-F/G-M/N-O/P-Q/R-V/W-Z 为 620.896/855.396/292.746/967.130/637.554/250.621s，race
为 648.794/975.741/269.477/1160.035/669.390/263.359s，全部通过且无 race report。
全部 non-CLI ordinary/race 也通过，最长分别为 state 68.037/60.959s；七套迁移脚本逐项通过，其中 family contract 闭合
44 个 family、5 个突变负例和 16 个真实 CLI E2E，外部网络禁用且只写临时根。两个 vet、
两个 Staticcheck profile、两个 module 的 tidy/verify、全包 compile-only gate 均无诊断。

另一次同日 fuzz 实跑各 20 秒，HTTPS-relative resolver、APT Release path、OpenPGP
packet 与 patched RPM binary-header 分别完成 711,581、692,900、2,750,189、9,083,167
次执行，均通过且未产生 workspace crash corpus。执行数是调度观察，不是阈值。

## 边界

这轮只读取本地源码、Git 对象和 Go module cache，并只写测试临时目录。所有真实云、边缘、
上游与性能 opt-in 均保持关闭；没有访问或写入 CO/COS、Cloudflare 生产仓库、任何 bucket、
Zone、Worker、CDN 或 EdgeOne。本文不声称真云/生产迁移状态升级。

本轮规格与证据已按字节序进入 `delivery-extra-files.txt`。审查前的两次独立 clean-delivery
曾在 fresh HOME/GOMODCACHE/GOCACHE 中仅用只读本地 module proxy 完成并逐字节相同，
且抽取树中的 RPM provenance gate 通过；审查补丁改变了产品源码和 provenance 脚本，故该
identity 只证明旧候选，不能证明当前交付。为避免摘要自引用，本文不记录自身冻结后的
product/delivery/archive digest；当前交付的两次 fresh 重建、`cmp` 与精确身份只写入交付根
之外的 `_bmad-output/implementation-artifacts/validation-selected-set-materialization-2026-07-13.md`
最新 V-40 条目，V-14 以该外部记录为唯一 post-document 权威。
