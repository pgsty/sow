# SOW V2 P1/P2/P3 验收证据

> **v0.2 历史验收证据。** 本文保留 C2/reposync 的原始 PASS 结论，只用于证明 `v0.2.0`。它不证明 [`../../next/`](../../next/) 已实现；下一版明确撤销 canonical package aliases 并把默认 EL reposync 记为已接受限制。

日期：2026-08-02
代码库：`/Users/vonng/pgsty/sow`
基础 commit：`50f183cc8125d09199dcdf38eec4fd86eeb338bf`
验收状态：**PASS；最终门禁索引为 `/Users/vonng/repo/sow-v2-p1p3-completion-final.20260802/final-evidence.sha256`**

本报告记录 2026-08-02 当时的未提交 checkout，不能单独标识最终 v0.2.0 源码。逐条要求到源码、自动化和外部证据的映射见 [`2026-08-02-p1-p3-traceability.md`](2026-08-02-p1-p3-traceability.md)。

## 1. 规范与源码身份

| 对象 | SHA-256 |
| --- | --- |
| adopted API contract | `1bc75d0bd8e283f8feaa6f7f5a3c1bfc0b9adac44cab32bb2ddeaf0570cc0138` |
| PRD | `7fa1980e519a286373be74f801f991b9b97a641ca25bd74a261372897ffa0705` |
| addendum | `7e40308b78b879fa1893c8ccaba3856b296e6b3bf0d91db158782fa803056270` |
| P1-P3 SPEC | `74f22d6dfcae280eabd16ae99c8636bd056b00e286e5c4a56cc0dc8f9d889b67` |
| acceptance matrix | `19f905262255280015a7798e3b3b9b723264f596056ef6730411cb997a656eab` |
| 当前 product source fingerprint | `5b9d1b404ea535701ad61648efd55cb713089816e7d1465c9c44655c1cba3aba` |

product source fingerprint 由 `test/poc/source-fingerprint.sh` 计算：枚举 `./cmd/sow` 的本仓 build dependency 目录，再加入 `go.mod`、`go.sum` 与 fingerprint 脚本，对稳定排序的逐文件 SHA-256 清单再次哈希。最终门禁保存完整输入清单，避免只凭 dirty tree、二进制时间戳或 Git HEAD 声称身份。

`go list -deps ./cmd/sow` 的 283 项活动依赖清单 SHA-256 为 `9bd59245676b6138c403ad090acd1d6a7b6c53e886f2756028d117549e62ddea`；精确审计未发现 V1 `internal/cli`、`internal/state`、publish/sync/provider/edge 或任何云 provider SDK 进入活动二进制。`github.com/cloudflare/circl` 是传递密码学实现，不是 Cloudflare provider SDK。

## 2. 功能落地结果

| 阶段 | 落地结果 | 主要实现 |
| --- | --- | --- |
| P1 Managed control plane | 封闭 P0-P3 CLI、strict `sow/v2` config、`-C → cwd → SOW_DIR` 发现、Repository/Dist 固定路径与生命周期、canonical architecture、C2 view-local hardlink | `internal/v2cli/`, `internal/v2/config/`, `internal/v2/managed/` |
| P2 mutation/recovery | immutable package facts/object、Membership、add/rm、partial success exit 3、never/fill/always RPM signing、exclude/Limit policy、Desired/Built/pending、SQLite journal 与逐阶段恢复 | `internal/v2/managed/`, `internal/v2/state/` |
| P3 verification/handoff | ls/show/where/status/build/check、signed RPM/APT metadata、Generation/manifest/Changeset、changes、operation log/export/prune | `internal/v2/managed/`, `internal/v2/state/`, `internal/{aptrepo,yumrepo}/` |

公开 CLI 只有 contract 中的命令和 flag；未知/重复/不适用参数在状态创建前拒绝。Managed RPM package signing 的 key、trusted key 和证书 bytes 被解析成 retained authorization snapshot；重试按 signature-neutral payload identity 收敛。RPM metadata 可生成并验证 `repomd.xml.asc`；APT 总有 `Release`，配置签名时同时生成并验证 `InRelease` 与 `Release.gpg`。

一次 Build 对选中 Dist 形成单一物理 Generation：先 stage/validate/fsync payload 与 metadata，再做 per-view pointer-last publication，最后原子写入 Built snapshot、manifest 和 phase-ordered Changeset。无物理变化不推进 Generation；`--skip` 只推进 Desired 并保留公开树。`changes` 在 dirty、recovering、error 或 base 不可验证时拒绝输出可复制计划。

## 3. 当前 checkout 自动化门禁

最终普通测试、clean-room 与 clean-delivery 日志统一保存在 `/Users/vonng/repo/sow-v2-p1p3-completion-final.20260802`；其命令、exit code、日志哈希、source manifest 与 production read-only snapshots 由该目录的 `final-evidence.sha256` 封口。此前同一 product fingerprint 的独立门禁如下：

| 门禁 | 结果 | retained evidence |
| --- | --- | --- |
| 全仓 ordinary | 所有产品/代码 package PASS；唯一失败是新增测试文件未进入 delivery allowlist，随后修复并单独验证 policy closure | `/Users/vonng/repo/sow-v2-p1p3-quality-final.qLzGFH/go-test-all.log`, SHA `c74e0e0a1a8de3a807777ff159b71eb20898044b6bb3478b996e88d63358f380` |
| V2 race | `internal/v2/{config,managed,plain,state}` 与 `internal/v2cli` 全部 PASS | `go-test-race-v2.log`, SHA `285a1ea6e99de28796462883b5dcf6f830172ec482a15d3f8bc569384730b81e` |
| vet/static | `go vet ./...`、`staticcheck ./...` 均 exit 0，空输出 | 两日志均为空文件 SHA `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| formatting/diff | `gofmt -l cmd internal test` 与 `git diff --check` 均为空 | 同上 |
| fuzz/property | 5 个边界 fuzz 各 10 秒 PASS：APT version、RPM EVR、RPM OpenPGP packet、config round-trip、policy input order | `/Users/vonng/repo/sow-v2-p1p3-fuzz-final.0F571x` |
| four-target build | darwin/linux × amd64/arm64 均成功，Linux 为静态 ELF | `/Users/vonng/repo/sow-v2-p1p3-quality-final.qLzGFH/cross-builds.tsv` |
| 最终全仓 ordinary | `go test -count=1 -timeout 60m ./...`，全部 package PASS，exit 0 | completion lab `go-test-all-final.log`, SHA `82537797709f96a0ebf29e9a27296e3a5e2658047d354dc7899900cdece89ec0` |
| 最终 clean-room | 隔离 HOME/cache 重新构建并执行 shipped MVP，exit 0 | completion lab `go-test-clean-room.log`, SHA `50119e5f305cff372fc98e16175f8587f5a4d5af70d9a3d2a28101da3643fe6e` |

四目标二进制：darwin/amd64 `0b14d550…`、darwin/arm64 `34249144…`、linux/amd64 `0b65db7c…`、linux/arm64 `807b9738…`。最终 completion lab 重新覆盖 allowlist、全仓 ordinary、clean-room build/run 和 deterministic clean-delivery，避免把那次已解释的中间 exit 1 冒充最终 PASS。clean-delivery 的第一次隔离下载被 `proxy.golang.org` 网络超时阻断并保留失败日志；通过脚本受支持的 `SOW_CLEAN_GOPROXY=https://goproxy.cn,direct` 与 `SOW_CLEAN_GOSUMDB=sum.golang.google.cn` 重跑后，依赖仍由 checksum DB 验证，完整门禁通过。最终文档状态封口后又以全新输出目录重跑，结果收录于最终门禁索引。

## 4. 故障恢复、并发与安全边界

retained lab：`/Users/vonng/repo/sow-v2-p1p3-crash-final.ft3pET`。完整日志 SHA-256 `cb3625e32e8070e3cd97f4a7b7575bdd2b743b94e6e29718100d14a603fdd44b`，summary SHA-256 `7b9af1431a1292341f6f61d0a415ce4a1355f8e02b27c4a26dbb84532b5c18a4`，exit 0，绑定 source fingerprint `5b9d1b40…`。

- add/rm/build 共 26 个 durable SIGKILL 点覆盖 planned/staged/applied/rendered/payload/pointer/built/finalized；每次只接受完整旧代或完整新代，下一写命令幂等收敛。
- Workspace/Repository/Dist lifecycle 共 22 个真实子进程终止点通过；multi-Dist pointer SIGKILL、stale Workspace journal writer recovery 和跨进程 concurrent init 通过。
- log prune 的 planned/staged/applied/done crash matrix、当前 Generation/changes 保留、nanosecond cutoff、WAL hot read-only 与 generation ledger re-anchor/corrupt rejection通过。
- root-bound/no-follow/inode、symlink/hardlink substitution、bounded package/journal/key/diagnostic、secret redaction 由普通与 race 测试覆盖。

adversarial review 另外修复并回归了四项具体缺口：portable Pool shard 统一小写且 SQLite/State 拒绝大小写碰撞；Pool path 必须由 Source+filename 精确推导；schema v5 的 unsigned `{}` signing snapshot 只解释为 RPM `never`；验收脚本不再把不存在的 `changes` 字段当成证明。

## 5. repo2、传统工具、签名与真实客户端

最终 lab：`/Users/vonng/repo/sow-v2-repo2-ordinary.o0JiLR`。harness SHA-256 `551e45f289dee94516b02986e44c55fe1df3c732388a2846074416303786d406`；完整 `run.log` SHA-256 `f4f2731c4f66fde0814c94d735a9a8282ecc541d324be698d09fddd175911f36`，exit 0。

输入来自 `/Users/vonng/pgsty/repo2` 的 269 个唯一路径，共 10,255,204,101 bytes（9.550903 GiB）。前后逐文件 manifest SHA-256 均为 `dbe1f82671bc16a5b9418987ea1df23a1789368f3018c1219bd3052141f186f4`，证明该输入集字节未变；容器只读挂载 repo2，所有输出和签名均在 retained lab。

### 5.1 traditional-tool semantic comparison

normalized comparison JSON SHA-256 `92ec9766e409451d9acb6e409d3370e74d9629cdca740f0f242e0fad7a9a8c85`：

- RPM：SOW/`createrepo_c` 均 87 包，only-sow/only-traditional/checksum/location/filelists/changelog/primary semantics 均为 0 差异。
- `requires` 原始差异仅 1 个 `entry.pre` 注解；按明确记录的 host/tool-version lossy 字段归一化后为 0，依赖 identity 无丢失。
- DEB：SOW/`dpkg-scanpackages --multiversion` 均 181 包；Package/Version/Architecture/Filename/Size/SHA256 及全部比较的依赖/关系/描述字段为 0 差异。

### 5.2 signing and clients

实验只生成一次性无密码 GPG key，fingerprint `02C145CEB5C681568E3FE83E39F3359DBB6E2E04`。Plain `create --sign-with --overwrite` 的 RPM 均由独立 `rpm` 验签。Managed 的 RPM package signatures、`repomd.xml.asc`、APT `Release`/`InRelease`/`Release.gpg` 均由容器内 `rpm`/`gpg` 独立验证。

- DNF x86_64/aarch64 × file/HTTP：makecache、repoquery、download、checksum、install、C2 reposync 全部通过。
- APT amd64/arm64 × file/HTTP：update、query、download、checksum、install 全部通过。
- native 与 neutral 包都被真实安装；gpgcheck 和 APT `signed-by` 均启用，不以 `trusted=yes` 代替签名证明。

空仓库另由 `/Users/vonng/repo/sow-v2-managed-empty.w4TX1D` 覆盖 RPM x86_64/aarch64 和 APT amd64/arm64 的 file/HTTP refresh/query，以及空 RPM reposync。`run.log` SHA-256 `f442597d3c962e2a6b22d8c09322b88181febd8d70cd9caa38221d734584b607`，exit 0；最终 labelled container/network/volume 均无残留。

## 6. changes、外部 handoff 与 log prune

同一 repo2 lab 的 `changes 0` 产生 41 个文件，phase 顺序为 `payload → metadata → pointer`。独立 consumer 只按公开 JSON 执行后得到与 `pool/ + dists/` 完全相同的 41 文件树，tree SHA-256 `8149d8744bdf5fc689d512040236412fa7429fa3e932e98683800fcd71951a8b`；handoff JSON SHA-256 `a1a23d78d75406e04464637e06fc9f550f30f18e8cc16532fa130f8a99f1f88a`。

随后注入全失败 add 以产生 terminal audit，执行 deterministic JSONL export 和 `log prune`。prune 后 `check` 仍为 clean/ready-to-copy，`changes 0` 与 handoff tree 不变；`check-after-prune.json` SHA-256 `bdf09e17f1feb4d769652d774a0347fe5f78de39697044e465ce249da144e42b`。SOW 只生成本地 copy plan，从未执行 remote sync/publish。

## 7. 规模门禁

最终 lab：`/Users/vonng/repo/sow-v2-scale-final.lzOCQF`。主基线 `/Users/vonng/repo/sow-v2-scale-portable.OnL4IO` 含 17 个从 repo2 manifest 构造的真实 RPM/DEB workspaces、31,811 objects；补充基线 `/Users/vonng/repo/sow-v2-scale-supplement-portable.Jjt2ma` 含 2,373 objects。合计严格为 34,184 packages、53,879,777,230 bytes（50.179452850 GiB）。

run log SHA-256 `c05f3cbfe7090cdab41153537d5bdc60c603eb100f2be192f0dbf8acccac1349`，summary SHA-256 `29a4b59f2b47a3157d1cc24c11db1cc8ed7761406541057b3bf1b60a4d1ae0d7`，timings SHA-256 `e3d591e7c8e188a89ba2116b33379239288449397ec7caf4ff59e187286d1622`，exit 0。

| 条件 | 次数 | median | worst |
| --- | ---: | ---: | ---: |
| Linux guest-cache-cold | 18 | 20.770s | 43.460s |
| macOS host-warm | 36 | 21.085s | 101.300s |
| 合计 | 54 | 20.880s | 101.300s |

54/54 均不超过 120 秒，peak RSS 338,608 KiB。18/18 workspace 在 Linux cold run 后执行 full check，所有 workspace 最终 `changes 0` 与公开树逐 path/size/SHA 精确相等；lab 所有 Docker volume 按运行 token 验证后清理。

边界必须明确：Docker privileged drop-cache 清除的是 Linux guest page cache，macOS APFS host cache 无法由容器清除；因此 host 数据只称 warm。第 18 个 workspace 是为达到精确包数构造的 supplement，不冒充正式 distro 仓库，但每个 package byte 都来自只读 repo2 且经过路径/size 校验。

## 8. 生产与外部副作用边界

本轮所有写入、签名、客户端安装、SIGKILL 和规模实验只发生在 `/Users/vonng/repo/sow-v2-*` 或容器临时层；`/Users/vonng/pgsty/repo2` 仅作只读输入，生产 `/Users/vonng/pgsty/repo` 从未被本任务作为写目标或新容器 mount。

2026-08-02 收尾只读观察记录生产树 102,646 个 regular files、0 symlink、`du -sk` 141,042,764，path/size/mtime/inode manifest 指纹 `9d41e1a81a53bd69d91b19538d1a3617062743b7852b29b8e730c0149d2b4adb`。观察同时发现一个**本任务之前已存在**、创建于 2026-06-21 的运行中容器 `dnfupdate`，以 RW 挂载 `/Users/vonng/pgsty/repo/yum`；本任务没有创建、停止或修改它。最终 completion lab 再次只读采样，若外部容器造成漂移会明确报告，不能归因或冒充为本任务不变证明。

没有 commit、push、upload、publish、production signing 或远端 endpoint 操作。非目标 modulemd/route/sync/publish/remote/GC/SRPM/DSC 仍未进入 P1-P3 产品面。

## 9. 已知限制

- 产品契约是本地 POSIX、单机协作式单写；不承诺 NFS/网络文件系统耐久语义，也不抵御恶意同 UID 或 root 进程。
- 规模 cold 结论只适用于 Linux guest native filesystem；macOS 数字明确标为 warm。
- traditional metadata 对照是客户端语义等效，不要求 gzip bytes、时间字段或 `entry.pre` 等工具版本投影逐字节相同。
- retained labs 是本地验收证据，不等于上传、CDN 或公开可用性。
