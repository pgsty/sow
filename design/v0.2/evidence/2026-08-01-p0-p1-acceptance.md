# SOW V2 P0/P1 验收证据

> **历史证据快照，已被后续 P1–P3 工作取代。** 本文只绑定 2026-08-01 当时记录的源码 fingerprint、测试和 P0/P1 范围；其中“P2/P3 未实现”、命令面和当前 checkout fingerprint 均不得用于描述现在的二进制。它仍保留用于追溯早期 P0/P1 证据与当时已知限制。当前完成判定必须引用最终 P1–P3 验收报告和 traceability。

> 本文的 C2/reposync 结果只证明 v0.2 历史布局。下一版已接受默认 EL reposync 限制并采用 metadata-only RPM views；见 [`../../next/`](../../next/)。历史日志、hash 与 PASS 不作改写。

日期：2026-08-01
当前状态：**P0 Plain 建仓/签名的当前 checkout 验证通过；P0/P1 正式完成条件因生产安全事件失败；旧 V1 全包默认测试时限单列**
代码库：`/Users/vonng/pgsty/sow`
基础 commit：`50f183cc8125d09199dcdf38eec4fd86eeb338bf` (`v1`)

> 工作树中的 V2 实现未提交，Git HEAD 不能单独标识被验收源码。本文把源码、自动化测试、真实客户端、交叉构建、生产只读和外部发布分层记录；旧报告或旧二进制不作为当前 checkout 的证明。

逐命令、逐参数及逐条 P0/P1 要求到源码/测试/客户端证据的映射见 [`2026-08-01-p0-p1-traceability.md`](2026-08-01-p0-p1-traceability.md)。

## 1. 范围与规范身份

本轮只实现并验证：

- P0：`create [DIR] [-j N] [--pigsty] [-S/--sign-with KEY [--overwrite]]`，以及适用的 `-T/-N/--json`。
- P1：`init`、`config check/show`、`repo ls/new/show/rm`、`dist ls/new/show/rm`，以及发现/选择、锁、SQLite、journal、架构映射和空 Dist。
- 公共辅助面：封闭的 P0/P1 help/version、JSON envelope、退出码 0–6。

明确未实现：P2 package mutation/Policy/Managed signing/build API 与 P3 query/check/changes/log/performance API。Plain P0 只有显式 `create --sign-with` 的 RPM 包签名；`--skip`、`limit`、`exclude`、`policy`、`signing`、`trusted_keys` 仍被拒绝，不存在空壳命令或假配置。

| 优先级 | 文件 | SHA-256 |
| --- | --- | --- |
| 1 | `_bmad-output/planning-artifacts/prds/prd-sow-2026-07-31/api-contract.md` | `ed51f6a278e040e7acd6509870210d318e4a77ac1d0ef2a4e77c7322bbbf69c2` |
| 2 | `_bmad-output/planning-artifacts/prds/prd-sow-2026-07-31/prd.md` | `4657d0c9f181bb75306644f8fd0acc91b008f4eebbd2e2cc41c38208106f5937` |
| 3 | `_bmad-output/planning-artifacts/prds/prd-sow-2026-07-31/addendum.md` | `7e40308b78b879fa1893c8ccaba3856b296e6b3bf0d91db158782fa803056270` |

API 的 `--skip` 优先于 PRD 漂移的 `--no-build`，但二者属于 P2，本轮都不实现。API 4.1 规定 `init` 只接受 `[DIR]` 与 `--json`；它内部取锁，但不公开 `-T/-N`。

## 2. 当前源码身份与实现

源码 fingerprint 算法：对指定目录下全部 Go 文件逐个 SHA-256，按路径排序，再对清单做 SHA-256。

- Managed/V2 全集（`cmd/sow`, `internal/v2`, `internal/v2cli`, `internal/aptrepo`, `internal/yumrepo`）：`02d27d8a4bbdd94a447c10600b14440fde3fd76cf91f9934eb6f1f529fdf3b53`。
- Plain 客户端子集：`f43b9074706c6edee0a5fd8e5719ceaac5bcff64cabc0e8f67ba36ff712804b7`。
- `go.mod`：`6b00818d0c03ef9bbe37f1e08fab741d2a4635409bebbe6cdecb6c912f0ec79b`。
- `go.sum`：`2ac96d3a2f7da0c5cc0ed474af2c2739c43297176376089b27cb1883ea956d9c`。

| 能力 | 实现位置 | 结果 |
| --- | --- | --- |
| 封闭 CLI | `cmd/sow/main.go`, `internal/v2cli/` | 只注册 P0/P1；逐命令 flag 校验；JSON 和退出码 0–6 |
| Plain Create | `internal/v2/plain/` | 顶层 regular RPM/DEB、确定性 metadata、显式 RPM 补签/重签、统一事务、Pigsty recovery |
| Strict config | `internal/v2/config/` | 严格 YAML、默认/规范化架构、发现/选择、未知字段拒绝 |
| Managed lifecycle | `internal/v2/managed/` | 固定路径、Workspace/Repository 锁、file/SQLite journal、repo/dist/init/rm |
| SQLite | `internal/v2/state/` | 每 Repository 独占 DB、schema v1、完整 ledger/DDL 认证、Operation Journal |
| Parser/renderer | `internal/aptrepo/`, `internal/yumrepo/` | Flat APT/YUM、空 Managed metadata、真实包头、稳定 renderer/validator |
| 架构门禁 | `test/poc/yum-relative-pool/` | 否决 `../../../pool`；采用 C2 root Pool + view-local hardlink alias |

adversarial review 修复全部落地并有测试：DEB ar/control 前进性与资源上限、Plain 稳定父/目标 inode 锁与文件系统根去重锁、force metadata 检查精确收窄到目标 Repository/Dist、legacy RPM `MISSINGOK` weak require、SQLite 完整 ledger/DDL 与 hot-WAL 纯读边界、旧 APT ownership proof 流式化、三类 journal wire-size 上限与 Plain 34,184 包容量回归、RPM header-only source/architecture 权威、默认 mixed 真进程终止恢复矩阵，以及最终真实客户端证据重跑。新增 RPM 签名路径把外部 `rpm` 限制在私有 stage，抑制可能含秘密的子进程输出，验证嵌入签名、signature-neutral digest 与 NEVRA，并保持每个原包各自 mode；主 key 与签名子 key 不用不可靠的 issuer-suffix 比较误判。rpm-md 的 lossy require 规范化仅作为 createrepo-compatible renderer projection，raw header requires 仍独立供 catalog 事实投影。收口还删除了 architecture-add executor 及其 journal kind/payload/recovery/SQLite finalize、无调用 YUM validator wrapper；伪造 `dist.arch.add` 只能完整性失败，不留 P2 暗路径。完整架构见 `docs/architecture-v2.md`，V1 资产处置见 `docs/v1-assets-v2.md`。

## 3. 自动化验证

原 P0/P1 日志根：`/Users/vonng/repo/sow-v2-offline-current.tsU0P8/logs`；RPM 签名验收根：`/Users/vonng/repo/sow-rpm-sign-final3.N42xup`；第二轮 repo2 完整复验根：`/Users/vonng/repo/sow-p0-repo2.MnnsY6`。Plain/Managed 独立客户端 fixture 的原始 `run.log` 保留在各自 lab。

| 类别 | 命令 | 当前结果 | 日志 SHA-256 |
| --- | --- | --- | --- |
| gofmt | `gofmt -l` 检查 `cmd`/`internal`/`test` 下全部 Go 文件 | PASS，空输出 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| P0/P1 targeted | `go test -count=1 -timeout=30m ./internal/aptrepo ./internal/yumrepo ./internal/v2/plain ./internal/v2/config ./internal/v2/state ./internal/v2/managed ./internal/v2cli` | PASS | `576298c94588269460b42a1267aa51cbe10aec41168c5000d033f418ae0e3f01` |
| native race | 同七个关键 package，增加 `-race` | PASS | `dd0ff3b2ab107b152aa072155e37d1e18a638b4d821e45536b6231e8afff7607` |
| compat/clean delivery | 最终 `go test ./...` 中的 `./test/compat` 与 `./test/compat/cleandelivery` | PASS，82.313s / 8.662s | `950a0f72744b69ab27ee3738f1cc8ad66f937cb3f4b2646970cfdcbb5a5532ec` |
| vet | `go vet ./...` | PASS，空输出 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| staticcheck | `staticcheck ./...` | PASS，空输出 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| diff quality | `git diff --check` | PASS，空输出 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 全仓测试 | `go test -count=1 -timeout=60m ./...` | PASS；23 个 package 汇总项全部通过，`internal/cli` 1895.562s | `950a0f72744b69ab27ee3738f1cc8ad66f937cb3f4b2646970cfdcbb5a5532ec` |
| completion audit | `go test -count=1 ./internal/v2cli ./test/compat/cleandelivery` | PASS；最终 spec/docs allowlist closure 与 CLI 契约，4.185s / 3.035s | `4cc64104d8e4d033d289045b1118ffec0970a5fe0f27e230dcd85eb08e1907dc` |
| clean-room binary | `go test -count=1 -run '^TestShippedExampleSupportsCleanRoomLocalMVP$' ./test/compat` | PASS；隔离环境重新 build 并走 P0/P1 公共 CLI，8.451s | `df0498d03fc15c638ec4b72f1951a5b1e7f75c936989c8d2c2b7ae5ea752da10` |
| 第二轮 P0 targeted | `go test -count=1 ./internal/aptrepo ./internal/yumrepo ./internal/v2/plain ./internal/v2cli` | PASS；9.704s / 14.523s / 53.236s / 10.023s | `8aa039f8ffebad1e72611956e45912203d016740f1cb8fa0036ab8cc8b6211b2` |
| 第二轮 P0 race | 同四个当前修改 package，增加 `-race` | PASS；10.762s / 19.601s / 58.529s / 11.221s | `3bd85d826d004cf417aac27fc94eea1f58032ebe6b0ae0f316f648a7a67fc352` |
| 第二轮 vet / clean delivery | 四个当前修改 package 的 `go vet`；`go test ./test/compat/cleandelivery` | PASS；vet 空输出，clean delivery 2.459s | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` / `2846621c0cb662eae7f992d47dfb895a7c7f425ed00e10fb8cd4bb8fac1effcc` |

当前签名增量后的 targeted package 独立重跑耗时：APT 10.048s、YUM 17.219s、Plain 82.487s、config 1.533s、state 5.726s、Managed 61.615s、CLI 13.331s。race 同七包均 exit 0：APT 12.125s、YUM 20.368s、Plain 86.153s、config 3.038s、state 7.236s、Managed 68.683s、CLI 14.369s。

第二轮全仓默认并发命令的所有其他 package 均通过，但旧 V1 `internal/cli` 的 903 项累计 fsync 测试耗尽 Go 默认 10 分钟 package timeout；将该包单独提高到 20 分钟仍推进到后续 publish/serving fsync 测试后耗尽时限。两个超时点分别独立运行 6.854s、16.162s 通过，日志 SHA-256 为 `7578d92ff672204c336ac2ebb089c02d67f107e866ed5370be23d16058bc1ff8` 与 `5c347533efb468469df98a67eead9c57a47f92bde85ed334c67b035dc014f0c0`；10/20 分钟累计超时日志为 `f0a5126e90e7fe89d7016b48d8b3ac292765f331852ea4d535b5eea41854450e` 与 `22f2ce5bc53f6983da3c2a26d2efd9cad2f1a22ba688edc65d02d79c5e08f233`。`cmd/sow` 当前只导入 `internal/v2cli`，故这不计作 P0 PASS，也不冒充 P0 失败；上表第二轮 scoped gate 才是本轮修改的直接测试证据。此前显式 `-timeout=60m` 的完整全仓 PASS 保留为历史回归层，不替代本轮 scoped gate。

收口过程中有一轮完整门禁正确捕获 `TestInitAdoptContentSynthetic33RepoGeneralization` 回归：V1 catalog 的 Relations 从期望 8 变成 3。该失败不计为 PASS；根因是 P0 为对齐 `createrepo_c` 引入的 lossy RPM require 规范化误复用于 raw catalog。修复后新增单元断言证明 catalog 仍读取 header-exact requires，而 rpm-md 继续输出规范化投影；表中的最终全仓结果就是修复后的独立重跑。

删除 Managed P2 暗路径后的第一轮全仓门禁也没有计为 PASS：`test/compat/cleandelivery` 在测试进程启动时发现本轮 Python metadata 对比留下的 `test/poc/plain-clients/__pycache__`，全仓 exit 非零，日志 SHA-256 `8b9cb1597675387629e37e2b7f75a43ec20e1f18074c09a4ac61ae7d911c6afd`。该单一生成缓存被显式删除，随后 `find` 确认不存在 `__pycache__`/`.pyc`/同类缓存，`go test -count=1 ./test/compat/cleandelivery` 独立重跑 2.514s 通过，日志 SHA-256 `4b984af8e2bb7266695a94bb8f48e04f4e843e80098dfd2322558275f28d0ee7`；上表的全仓行只记录再下一轮从干净工作区启动的完整结果。

全仓 PASS 后的 completion audit 只新增本文链接、逐项 traceability 文档及其 delivery allowlist，没有修改任何 Go 源码；Plain/Managed fingerprint 重算未变。表中的 completion-audit 与 clean-room 两行重新覆盖唯一受影响的 clean-delivery/Markdown closure，并从隔离的 HOME/GOCACHE/TMPDIR 重新构建活动 binary、执行 P0/P1 公共 CLI。

P0 tests 覆盖 RPM-only/DEB-only/mixed、non-recursive/regular-only、坐标冲突、jobs/确定性、marker/modulemd、Pigsty 精确筛选、`--sign-with`/`--overwrite` 参数门禁、未签补签/全量重签/重复内容/不同 mode/签名失败零公开副作用、pre-image rollback，以及 journal/marker/RPM pointer/DEB pointer/每个 package rename/new marker 前后的进程终止矩阵。P1 tests 覆盖 init 幂等、发现/选择、strict config、protected/force/逃逸、timeout/no-wait、schema migration/DDL、journal replay、架构 alias/neutral/unknown/state reference 和双架构空索引。

## 4. P0 全量离线包与传统工具对照

实验根：`/Users/vonng/repo/sow-v2-offline-current.tsU0P8`，创建于 2026-08-01 13:27:30 CST。标的是 `~/pigsty/dist/v4.4.0/` 两个离线包的 retained extract：EL9 arm64 archive SHA-256 `41350010f78b3e7d17de7dbfaa51db1e19d725ac5bf8925ec96620f07f8307a7`，U24 arm64 archive SHA-256 `4411b2e287b5c4048536b9fc3d2a414d255dcd0c4aee112ceee139160f97189a`；extract 保存在 `/Users/vonng/repo/sow-v2-deep-review.fgyl0c/sources/{el9,u24}/pigsty`，本轮只把顶层 package regular files hardlink 到干净的 SOW/traditional 对照目录，不复用任何旧 metadata、marker 或 modulemd。生产 `/Users/vonng/pgsty/repo` 未作为输入或 mount。

| 对照 | 客户端镜像（linux/arm64） | 包数 | 生成耗时 real |
| --- | --- | ---: | ---: |
| SOW RPM | `pgsty/el9a:build` / `sha256:b602942464d4527fe15fbcf0d5c68c72b59a39872ffee7e2ea15389ed4b00c89` | 1,355 | 15.434s |
| `createrepo_c` RPM | 同上 | 1,355 | 2.096s |
| SOW DEB | `pgsty/u24a:build` / `sha256:e8ca21fa892a9018e51aac79c3918132b59c9249dbe7a1f31c5acdf92debefba` | 978 | 17.971s |
| `dpkg-scanpackages` + deterministic gzip | 同上 | 978 | 10.418s |

被测 linux/arm64 SOW binary SHA-256：`f5dab7ad51f8925aa083e9f3e121e015e752f3e40f479a867032c2a6c25591d9`。

该 1,355/978 包离线对照绑定的是签名功能加入前的 Plain fingerprint `cc1751f6904760d258c48eca1cf647abc4ea3fb367dca9ede758b98f5a625703`，因此本节保留为历史回归证据，不伪装成当前 checkout 的直接证明。当前签名源码的 87 包 `createrepo_c` 与 DNF 对照在 4.2 节独立记录；自动化与全仓门禁继续覆盖未指定 `--sign-with` 时的默认路径。

核心复核命令（四个目录已保留）：

```text
docker run --rm --pull never --platform linux/arm64 -v <lab>:/lab pgsty/el9a:build bash -c '/lab/bin/sow-linux-arm64 create /lab/el9/sow --json'
docker run --rm --pull never --platform linux/arm64 -v <lab>:/lab pgsty/el9a:build bash -c 'createrepo_c /lab/el9/traditional'
docker run --rm --pull never --platform linux/arm64 -v <lab>:/lab pgsty/u24a:build bash -c '/lab/bin/sow-linux-arm64 create /lab/u24/sow --json'
docker run --rm --pull never --platform linux/arm64 -v <lab>:/lab pgsty/u24a:build bash -c 'cd /lab/u24/traditional && dpkg-scanpackages --multiversion . /dev/null > Packages && gzip -n -9 -c Packages > Packages.gz'
python3 test/poc/plain-clients/compare_offline_metadata.py <lab>
```

生成日志 SHA-256 分别为：SOW RPM `61301928248aab0f3a2b6e1592f98e8a0a797366a3443ce353aa93a558bb9de6`、`createrepo_c` `746b3c34ae65758e489e2d0a384501c8acdf4440770b47c216378dda29952a70`、SOW DEB `45b0567563c3b8af2e96c0c9ed86b95cb2c95224e59a00bed90dfde01e2b8b9b`、`dpkg-scanpackages` `8008968b8f2136bef0b4bf0e68cc47e5190aaf5ff51ae3167d078131847aa2b9`。

逐字段对比报告 `metadata-compare.json` 为 116 行/2,987 bytes，SHA-256 `a635f3ad2539696ccbb432add17286a88c4c0f050af1470459b6b9649d077a8d`，脚本 exit 0：

- RPM 逻辑坐标 1,355/1,355，无单边包；location basename、package SHA-256、filelists 全部零差异；primary file entries 2,708/2,708。
- provides/conflicts/obsoletes/suggests/enhances/recommends/supplements 全部零差异；requires 身份忽略 `pre` 后零差异。唯一差异是 10 个 package 的 `/bin/sh` `pre` 注解（SOW-only 7、traditional-only 8）：容器的 [`createrepo_c 0.20.1`](https://github.com/rpm-software-management/createrepo_c/blob/0.20.1/src/parsehdr.c) 只将 PREREQ/SCRIPT_PRE/SCRIPT_POST 标为 `pre`，而上游当前 [`parsehdr.c`](https://github.com/rpm-software-management/createrepo_c/blob/master/src/parsehdr.c) 还纳入 PRETRANS/POSTTRANS；SOW 与当前上游映射一致。这是传统工具版本的注解策略差异，不是依赖丢失。
- DEB 逻辑坐标 978/978；Filename/Size/SHA256/Package/Version/Architecture 和依赖、关系、section/priority 等比较字段全部零差异。
- 文件名含 literal `%3a` 的 65 个 epoch DEB 全部进入索引。

相同输入再次运行，RPM 与 DEB 均返回 `noop=true, recovered=false`；两套 metadata manifest 的 `diff` 均为 0 bytes。RPM manifest 前后 SHA-256 均为 `cf362df336ce25886a54e3e553c90a56d4e4f2ebc39071031bccb680f8f9fc10`，DEB 均为 `e56cf39500f684fe2c64ab056f3309968474ff1cf188f8a4d82b18701a5cf607`。

### 4.1 真实客户端效果对照

SOW 与传统 RPM 仓库分别运行 DNF/YUM makecache、1,355 包完整 repoquery、native `CUnit` + noarch `basesystem` location/download/byte-compare/install，以及 `docker-ce` legacy weak recommendation。两边都安装成功，下载 SHA-256 完全相同。日志：

- SOW：143 行/9,030 bytes，SHA-256 `d3121fd93d3e9b63c7d8f049f0fb87a54207cf101eee9ff15481f2cc3d0e0560`。
- traditional：142 行/8,950 bytes，SHA-256 `a06e431461bf3df1b1bc6354785d12dce4d1c609619f018241f35511aef45ffb`。

SOW 与传统 DEB 仓库分别运行 APT update、978 包 dumpavail、native `alertmanager`、all `readline-common`、epoch `bind9-dnsutils` 的 policy/download/byte-compare，并实际安装 native+all dependency closure。两边下载 SHA-256 完全相同。日志：

- SOW：128 行/7,497 bytes，SHA-256 `dc56e891bbd56deef9bbb18aa27f8babf1f970a292b61ce424821534f75ebea0`。
- traditional：128 行/7,497 bytes，SHA-256 `d14e62483452828b1ddfd3cd733e9c06ada0062b97de9f1e17877ad0b7852a36`。

性能数据只作为 P0/P1 基础记录；SOW 当前明显慢于传统工具。它不是 P3 的 34,184 包/两分钟门槛，也没有作该声明。

### 4.2 RPM 补签、重签与 `createrepo_c` 当前对照

当前 checkout 的 retained lab 是 `/Users/vonng/repo/sow-rpm-sign-final3.N42xup`；输入只从 `/Users/vonng/pgsty/repo2/yum/infra/x86_64` 的 87 个顶层 RPM 做 APFS clone，生产 `/Users/vonng/pgsty/repo` 未作为输入或 mount。被测 linux/arm64 binary SHA-256 为 `ab7905bd25389fd073deb287d5d297445fb6c572dbc4504d96d5ac3ce26267d3`，执行环境为 `dnfupdate:latest`（image `sha256:38b156544e5c63f80c490d55dcba656dccb44fca1c4ebc57c5d603f23ba8e6ee`，linux/arm64）。

实验完成后重新读取输入目录，87/87 package SHA-256 与 clone 前 manifest 一致、changed 0；所有容器写 mount 都只指向 retained lab。

- 原输入独立统计为已签名 76、未签名 11。`create -S E7935D8DB9BD8B20 --json` 只报告并改写 11 个未签名包，另外 76 个 SHA-256 不变；SOW log SHA-256 `741fa8e0676eaaa9281947d06bdc6b3df2471fc7778a7ab126800bb9dad0f39f`。
- 导出环境中的 public key 后逐包运行 `rpm --checksig`：87 OK、0 BAD、0 wrong signer；DNF repoquery 得到 87 个唯一 NEVRA/location，并以 `gpgcheck=1`、`--forcearch=x86_64` 实际安装新补签的 `asciinema`。独立验证 log SHA-256 `470289973410119387b3e07eaba68abdfd0eca354eadaa1f5ec4cbb5f79ec80e`。
- 同 key 的 `--overwrite` 对 87 个包全部调用 `rpm --resign` 并全部列入 `signed`；RPM 对已有完全相同签名的 76 个包保持字节不变，原 11 个未签名包改变。log SHA-256 `8cd8db6fa10fb454031f2c72753b5cc8ba1535ef0b977f17fe73d8b5a14eb285`。
- 临时生成第二把 GPG key 后，对 3 个已有签名包运行 `--sign-with <fingerprint> --overwrite`：3/3 字节改变、3/3 新 key 验签成功、wrong signer 0。log SHA-256 `d3f8e4c4e3772b9fe30491a761121e66e695d5b324e89891421f0853e0f3e45d`。
- 使用不存在的 key 真实执行返回 exit 1；package SHA 与既有 `repomd.xml` pointer 均不变，stage/recovery/journal residue 为 0。failure log SHA-256 `7933646e1a5bbb40d496a58fbfcf91eb2f6339953f6cdda854f912128c0f706e`。
- 将补签后的相同 87 个最终 RPM 复制给 `createrepo_c`，两仓 DNF `NEVRA|location` 排序结果均为 87 行且字节一致，SHA-256 同为 `5cab1fa2e41e7a372eadba31d0707fe8255117f7ff02ccbab8ba9cce58e2fe41`，对照 log SHA-256 `06c4c714074a722c8a49f8b135800371987c05bdd159fcb2b36ec3cf295ccf75`。SOW 生成 `primary/filelists/other` XML；`createrepo_c` 另有可选 SQLite data types，不影响该客户端结果。

签名 key 的选择边界与 Pigsty `yum/Makefile` 一致：SOW 把规范化 key ID/fingerprint 作为命令行 `%_gpg_name` 交给受信任的 `rpm --addsign/--resign`；GPG home、agent、pinentry、passphrase 与签名子 key 解析由运行环境负责，SOW 不接收、保存或回显秘密。发布前另行验证嵌入签名结构、signature-neutral digest、NEVRA、最终 package SHA-256 与 rpm-md pointer。

### 4.3 第二轮 repo2 普通仓库与签名复验

当前 checkout 的 retained lab 是 `/Users/vonng/repo/sow-p0-repo2.MnnsY6`。普通 RPM 输入来自只读 `/Users/vonng/pgsty/repo2/yum/percona/el9.x86_64` 的 207 个顶层包；普通 DEB 输入来自只读 `/Users/vonng/pgsty/repo2/apt/infra/pool` 的 92 个 amd64/all 包。实验目录均用 APFS clone 创建，生产 `/Users/vonng/pgsty/repo` 没有作为输入或写 mount。普通建仓使用的 darwin/arm64 binary SHA-256 为 `df7fe7295b761692b7096f7aea39496fd4deaf0abd969710d157b4f76514def3`；以相同 `-trimpath`/CGO 参数从最终 Go 源码重建后逐字节得到相同 SHA-256，重建证据 SHA-256 `bd13c83be4c3a61d550d472fb168843b9e4b0a23b9c73ffe6a196ddcc8e0184b`，本次最终收口又现场重建并逐字节匹配。最终 Plain source fingerprint 为 `f43b9074706c6edee0a5fd8e5719ceaac5bcff64cabc0e8f67ba36ff712804b7`。

- `createrepo_c` 对照为 207/207 包：除确定性的 `time.file` 与单独核对的版本差异字段 `entry.pre` 外，primary 中 summary/description/packager/url/time/size/license/vendor/group/buildhost/sourcerpm/header-range、package checksum/location、全部依赖关系和 874/874 file entries 逐项零差异；filelists 也零差异。`other.xml` 为 207/207 包、926/926 changelog entries，逐包零差异。DNF 对 `percona-postgresql18` 的 `repoquery --changelogs` 在两仓各返回相同的最近 10 条，输出 SHA-256 均为 `ba4a8e4c33453d8f8e2f7c4f64dace791f3be216b120d0f619a104a415afa7b1`。`dpkg-scanpackages --multiversion` 对照为 92/92 records，Package/Version/Architecture/Filename/Size/SHA256、Description 及全部关系字段零差异。对照器 SHA-256 为 `61aed9e86be305eb009a8b64640f5367934e92100ba4cb204850a2d82b8e53ec`，完整报告 SHA-256 为 `b415617fe1405ea24db8456e4478c2bdb2c92d49f0a5697366e96bfbd010d4a1`。
- DNF 对 SOW 与 traditional 两仓分别通过 file 与 HTTP 的 makecache、207 包 repoquery、`etcd-3.5.30` download/install；APT 对两仓分别通过 file 与 HTTP 的 update、91 个唯一包名、`rustfs` 两版本、`asciinema-3.2.1` download/install。四类日志 SHA-256：DNF file `2089fbe9d83314e718c81b932c523e1138663020bbc661c3aa6cbdbe8a9800c1`、DNF HTTP `047f3400874bc7b76366a22838c92d4d3e870b166b57f87de493f0f04df0af2b`、APT file `8b6eef9302052eb3bbeba63558a9f3a6b2a433f5bab38ab5d1b6ff0aa480459e`、APT HTTP `48ebdbb59733c647de01408dc5513be0b9de1047ae1b0d53b56e356243537fab`。
- 在 `umask 077` 下首次与重复创建均保持公开 `repodata/` 为 `0755`、所有 rpm-md 与 `Packages{,.gz}` 为 `0644`。207 RPM 与 92 DEB 的重复执行都返回 `noop=true`，metadata manifest 前后逐字节相同；299 个普通实验包的建仓前后 SHA-256 清单相同。
- 真实 `dnfupdate:latest` 环境中，默认 `-S` 只改写未签名 `asciinema`，保留已有 Pigsty 签名的 `agentsview`；`--overwrite` 对全部输入调用 `--resign`。另取 repo2 中由 Percona key `9334…EFA5` 签名的 `percona-pg_gather`，经 `--overwrite -S E793…8B20` 后包字节改变并由 Pigsty key 验签。最终 5/5 副本 `rpm -Kv`、rpm-md 最终 package checksum 和 metadata checksum 均通过，验证日志 SHA-256 `3b45e265227481f14be753743c2ab21c93770e86e236a25959fca92d86836383`。
- 补签与 overwrite 两仓都由 x86_64 EL9 DNF 在 `gpgcheck=1` 下导入 fingerprint `9592 A7BC 7A68 2E73 3337 6E09 E793 5D8D B9BD 8B20`，查询 2 包并实际安装运行 `asciinema 3.2.1`；日志 SHA-256 `8a562b3f80636eacda9f207ef35859a6ec80537b1c6a31e6812c9d41bbc76911`。
- 对已有可用索引的未签 RPM 指定不存在的 `DEADBEEFDEADBEEF`，真实 `rpm --addsign` 返回 exit 1；包与全部 rpm-md 前后 manifest SHA-256 均为 `a1f7b60f0214b723095e44b43debfb543ff11076933bdf7d0d1e70120940c18d`，journal/stage/recovery residue 为 0，且错误输出不含 signer 子进程诊断或秘密。失败日志 SHA-256 `aa9f008565bff8dd9c4d66a99744e7471d3f45d66a03ab5706576ee6e84a1c6a`。

## 5. 独立真实客户端 fixture

### P0 Plain RPM-only / DEB-only / mixed

- 入口：`test/poc/plain-clients/run.sh`，exit 0。
- retained fixture source fingerprint：`cc1751f6904760d258c48eca1cf647abc4ea3fb367dca9ede758b98f5a625703`；这是签名增量前的独立默认路径证据。
- retained lab：`/Users/vonng/repo/sow-v2-plain-clients.IC4VHX`。
- binary SHA-256：`bcb91f9eff5ed45ee059f3a41c372bca0cb251e3d4fbfe16b1712c73d5ac6b68`。
- log：389 行/19,134 bytes，SHA-256 `28525cd5c853dc564eef01b8a261bebc1b7ece8415d25d76cb1f3af2f6740bad`。
- DNF/YUM 对 x86_64+noarch 的 refresh/location/download/install 全通过；APT 对 amd64+all 的 update/policy/download/install 全通过；mixed 的两种客户端同目录消费通过。

### P1 Managed empty Dist

- 入口：`test/poc/managed-empty-clients/run.sh`，exit 0。
- retained fixture source fingerprint：`fc06f274673b362fa68da13761bd87f98c0e673e1a095b6ffeec3d65a419689f`；当前 Managed 回归由自动化/全仓门禁覆盖。
- retained lab：`/Users/vonng/repo/sow-v2-managed-empty.cPmqri`。
- binary SHA-256：`3c0277b0223d43792d9792e4d34c4473bab3e1200e44385be6347387e4f282c2`。
- log：104 行/7,167 bytes，SHA-256 `d223f06250fba3db3349761bf338aaaa3964038099693899a213357190b64128`。
- DNF/YUM 对 x86_64/aarch64 空 view 的 makecache/repoquery/reposync 通过；APT 对 amd64/arm64 empty Packages/Release 的 update/dumpavail 通过。

上述两组使用 `pgsty/el9:build` image ID `sha256:7ae1657642a32d84a5b2bf28403ad7e01b62d5279d253cc63bf36a358bed5292` 和 `pgsty/u24:latest` image ID `sha256:190f49d7960622e40884b17f518e46866aab8fcd8c0ac06e1de0e88ac69191cb`，均为 `--pull never --platform linux/amd64`。

### YUM relative Pool 前置门禁

- 入口：`test/poc/yum-relative-pool/run.sh`，exit 0。
- retained work：`/var/folders/df/bfm8q07d7bv3kpjf1fjchq4m0000gn/T/sow-yum-relative-pool.JrJKRD`。
- log：1,549 行/88,337 bytes，SHA-256 `1315965767874fe7af543ad00b2e85c230139b661b0808e961d86874f1fe72b4`。
- pinned AlmaLinux 9 image：`sha256:d2515c769e7b73f95c4fde38c0a505336ff38f14990c0b7253b77060a049a743`。

原 `../../../pool/...` 在 makecache/query 后被真实 reposync 否决，因此没有冻结。C2 使用 view-local `pool/...` regular hardlink alias；x86_64 native+noarch、forced-aarch64 noarch，以及不保留 hardlink identity 的复制树，均通过 makecache、query/location、download、install、reposync 和源包 byte-compare。

## 6. 四目标构建

命令：`CGO_ENABLED=0 GOOS=<target> GOARCH=<target> go build -trimpath ./cmd/sow`。四个产物均用 `file` 复核为目标 Mach-O/ELF 架构，Linux 产物为静态链接。

| GOOS/GOARCH | bytes | SHA-256 |
| --- | ---: | --- |
| darwin/amd64 | 16,612,880 | `2994111d9c40486c1b4267785ab1a8e4153e32908c0811ad35b0bb8f5d5acc4f` |
| darwin/arm64 | 15,785,890 | `8d1634c548a77c6c37442a79737c066af369f59e23e64b98fdc479f6ac6a7139` |
| linux/amd64 | 16,358,744 | `6c2594ebaecf2a7b016913dd351c527dc7b0b0926abf78da7e39d737a22669b1` |
| linux/arm64 | 15,411,202 | `5df4da97a01ce55f501923308e16a543b33d91f06ae7ad76ec37ea4656d897f0` |

当前产物位于 `/Users/vonng/repo/sow-p0-repo2.MnnsY6/bin`，`file`/hash 证据 SHA-256 为 `9f25f9375ef44fa294236b92d4f09fa1b865c287e7fd1289b02a6ff9d9fd4c3f`。交叉构建只证明可构建，不替代 Linux 客户端证据。

## 7. CLI/API preservation 与活动依赖

- root help 实际快照：26 行/1,056 bytes，SHA-256 `d125e04ceed5c1c2947186372ea38fdd9ebdf29f017e8a04c36223bbed14eeb6`，与 `internal/v2cli/testdata/root-help.golden` 字节一致。
- version 实际输出：`sow 0.2.0-dev darwin/arm64 go1.26.5`。
- 当前树只有 `create`、`init`、`config check/show`、`repo ls/new/show/rm`、`dist ls/new/show/rm`、`help`、`version`。
- `add/rm/ls/show/where/status/build/check/changes/log` 和 V1 `publish/sync/route/snapshot/view/manifest/rejected` 均作为顶层 topic 被拒绝；golden/flag/exit-code preservation tests exit 0。
- `go list -deps ./cmd/sow` 为 283 项，SHA-256 `e7967014654dc997cda8ec75dfd16111cfc0a1f3100aee2e440308e492a05caf`；不含 V1 CLI/state/catalog/repository、publish/sync/provider/edge，也不含 go-git、AWS、Cloudflare provider 或 Tencent SDK。
- Plain P0 的 `create --sign-with` 是唯一活动 RPM 包签名入口，并显式调用环境中的 `rpm`/GPG；Managed signing config、metadata signing 与其他 package mutation 仍不可达。

适用 API 逐项保全结果：

| 命令 | 位置/局部参数 | 允许公共参数 | 对照 |
| --- | --- | --- | --- |
| `create` | `[DIR]`, `-j/--jobs`, `--pigsty`, `-S/--sign-with KEY`, `--overwrite` | `-T/--timeout`, `-N/--no-wait`, `--json` | exact；`--overwrite` 要求 `--sign-with` |
| `init` | `[DIR]` | `--json` | exact |
| `config check` | 无 | `-C/--workdir`, `--json` | exact |
| `config show` | `--all` | `-C`, `-r`, repeatable `-d`, `--json` | exact |
| `repo ls` | 无 | `-C`, `--json` | exact |
| `repo new` | `NAME` | `-C`, `-T`, `-N`, `--json` | exact |
| `repo show` | `[NAME]` | `-C`, `-r`（省略 NAME 时选择）, `--json` | exact |
| `repo rm` | `NAME`, single `-f/--force` | `-C`, `-T`, `-N`, `--json` | exact |
| `dist ls` | 无 | `-C`, `-r`, `--json` | exact |
| `dist new` | `NAME`, required `--format rpm|deb` | `-C`, `-r`, `-T`, `-N`, `--json` | exact；无 architecture 参数 |
| `dist show` | `NAME` | `-C`, `-r`, `--json` | exact |
| `dist rm` | `NAME`, single `-f/--force` | `-C`, `-r`, `-T`, `-N`, `--json` | exact |
| `help/version` | 契约 topic/version | 无数据 mutation 参数 | exact |

表外参数由 parser 以 exit 2 拒绝；`-T` 与 `-N` 的互斥、duration、jobs、必填 format、位置参数 cardinality 和 `repo show NAME`/`-r` 一致性均有 negative tests。

## 8. 生产只读与外部漂移

生产目录：`/Users/vonng/pgsty/repo`。它从未被作为 create/init/rm/fault/performance 目标或容器 mount。

原开发验收窗口的起点与 2026-08-01 06:45:01 CST 终点完全一致：102,650 files，metadata fingerprint `ccb85d842c484e3088de66a7955318cc7b38cd71e3fc90b5b82c4968fb8d7aa3`。

本次深度复核实验根创建于 10:29:46 CST。只读复核发现生产树在两个验收窗口之间发生外部漂移：当前 102,666 files，fingerprint `f4c6cc09f375f4375eae876e2465d02a29061ef7b80ff049997f2578dbd757fe`。新增/变更文件的最新 mtime 为 09:52:43 CST，早于本轮实验开始；其中可见 08:52–08:55 的六个 haproxy RPM、`.git`/IDE 文件和已有工作树修改。不得把这个差异伪装成“原始起点到最终完全一致”。

当前复核 checkpoint 是 2026-08-01 10:50:25 CST。但为归因执行的 `git -C /Users/vonng/pgsty/repo status --short` 不是严格只读：Git 会做可选 index refresh，随后 `.git/index` mtime 变为 11:00:50 CST。11:00:57 CST 还观察到 `ext/.DS_Store` 更新，无法从现有证据可靠归因。无论 index 内容是否语义变化，文件 metadata 已变化，因此不得声称生产树零修改或起终 fingerprint 一致；本任务不会通过 `touch`、checkout 或任何写操作掩盖/恢复该证据，也不再对生产仓库执行 Git 命令。

最终只用 `find/stat` 于 2026-08-01 12:40:58 CST 读取：102,662 files，metadata fingerprint `21e21668f37e6551377fc9f99e73d1751c79d2b44600a63851ad8711b6b57754`。它又不同于 10:50 checkpoint，说明期间仍有外部增删/修改；本轮没有足够证据归因这些变化。最终读操作没有调用生产 Git。

没有对生产目录执行 create、RPM 签名、metadata 构建、upload、publish 或远端 delete，也没有执行 commit/push。本轮新增写入只发生在 `/Users/vonng/repo/sow-p0-repo2.MnnsY6`：普通 repo2 克隆仓库及 3 组小型签名副本。

## 9. 明确未实现的 P2/P3

P2：`add`、package `rm/ls/show/where`、`--skip`、非空 Membership mutation、Policy/limit/exclude、Managed package/RPM signing 配置、非空投影公共事务。Plain P0 `create --sign-with` 不扩展为这些 API。
P3：`status/build/check/changes/log`、Changeset/full query/check、metadata signing 公共配置、34,184 包/两分钟 rebuild 门槛。

数据库中的空 `package_objects`/`memberships` 表、C2 投影设计和 renderer 非空输入只是内部扩展点，不代表上述 API 已实现。

## 10. 最终判定

**P0 Plain 简单仓库与 RPM 补签功能按本轮范围通过。P0/P1 总目标仍未完全完成。** 当前 checkout 的 P0 targeted/race/vet、四目标构建、repo2 全字段传统工具对照、file/HTTP 客户端、真实补签/换 key 与失败原子性均已通过；旧 V1 `internal/cli` 的累计 fsync 测试仍不能在默认/20 分钟 package 时限内跑完整，且生产树发生了上述 metadata 变化、生产 Git 诊断很可能刷新了 `.git/index`。因此可以声明本轮 P0 代码与验证闭环，不能把历史全仓时限或严格“生产目录零修改”伪装为满足，也不能声明整个 P0/P1 项目目标完成。
