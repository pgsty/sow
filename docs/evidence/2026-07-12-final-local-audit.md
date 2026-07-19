# 当前源码本地终审证据（2026-07-13，final clean delivery pending）

> 结论边界：binary OpenPGP parser 修复后的普通/race 全仓、静态、漏洞、交叉构建、
> 真实客户端、官方上游、本地 S3-compatible、隔离规模、fuzz 与本地迁移门禁已
> PASS。本文不把 R2/COS/
> Cloudflare/EdgeOne、生产迁移、legacy policy 或运营指标伪报为通过，长期 Goal
> 仍未完成。

## 源码身份与证据纪律

- Go：`go1.26.5 darwin/arm64`；Docker 使用 Nginx 1.31.2、Ubuntu 22.04 与
  AlmaLinux EL8/EL9/EL10。
- `test/compat/cleandelivery/product-files.txt` 当前精确列举 330 个普通产品文件，包含
  `internal/yumrepo/package_keyring.go`。
- 当前稳定 product-source SHA-256 为
  `70f4d1f50469a2acf4ded5930f9f6d62a3b6ee743cd861bb13d470e36f9bd07c`；不复用已取代的
  329-file `c328bca0…8f20`。
- 一次预备 clean-delivery 已以 330 product files / 406 delivery files PASS；本次
  allowlisted 文档更新已取代其 delivery/content identity，故不记录。仍须两次
  最终独立空缓存 clean-delivery。

## 当前普通/race/静态门禁

> 2026-07-17 执行注：本节下方的整仓普通/race 数字是 2026-07-13 当时源码的历史
> 结果。当前 `internal/cli` 已增长到单包默认 10 分钟超时之外；仓库 CI 因此按测试名
> 六分片执行 CLI，而不是把 `go test ./...` 的包级超时当作产品失败或伪造整包 PASS。
> 2026-07-17 当前源码六个 ordinary 分片均 PASS（355.027s、656.788s、163.414s、
> 688.946s、389.770s、66.651s）；完整 `test/compat` race、focused config/bootstrap
> race、`go vet ./...` 均 PASS。当前可复现入口与边界见
> [Cloudflare bootstrap 离线验证](2026-07-17-cloudflare-bootstrap-offline-validation.md)
> 和 CI workflow；下列历史命令不再作为当前源码的默认一体化入口。

parser 修复后当前源码：

```text
go test -count=1 ./...
  internal/cli 280.274s; all packages including compat/cleandelivery PASS

go test -race -count=1 ./...
  internal/cli 364.215s; all packages including compat/cleandelivery PASS;
  no race report

go vet ./...                         PASS 1.35s
go mod tidy -diff                   PASS, empty diff 0.10s
go mod verify                       PASS, all modules 1.51s
git diff --check                    PASS
(cd third_party/cavaliergopher-rpm && go test -count=1 ./...)
  PASS 1.79s
cd edge && npm test                 PASS 26/26, 0.66s
```

一次较早的 full-race 尝试出现瞬时测试夹具解析失败；同一 focused case 随后连续
20 次 PASS，之后候选与当前两轮完整 full-race 均 PASS。这里保留该波动而不隐藏；
没有 race detector 报告。

其后发现 production `ParseRPMPackageKeyring` 曾对 binary packet stream 无条件
`TrimSpace`，合法末字节 `0x0b` 会被截断。当前修复只对 armored text 接受 outer
whitespace，binary 输入逐字节保留；固定 1333-byte binary key 与 armored whitespace
回归在 yumrepo/CLI publish 定向套件中 PASS；修复后的普通/race 全仓也已 PASS。

修复后固定版本 `govulncheck@v1.6.0` 报告当前调用图可达漏洞 0、vulnerable imported
packages 0。required modules 有 1 条 advisory，但生产调用图不可达。

## 独立怀疑式审查

Blind Hunter 的 bounded audit 覆盖：OpenPGP primary/subkey 历史 packet、
latest-policy-first/no-fallback、outer/self/cross expiry、缺 cross-cert、flags/lifetime/
revocation、present-body receipt reuse、新 view CAS 校验，以及 APT component 坐标。
前序轮次发现的问题均先复现、再修复并固化为永久回归；该 bounded scope 的结论为：

```text
NO ACTIONABLE FINDINGS
```

该结论之后又由独立检查发现 binary trimming 缺陷；缺陷已定向及普通/race 全仓关闭，
同时说明 bounded review 不能替代执行验证。

## 当前信任、增量与坐标闭包

- package-keyring parser 同时保留 primary self-cert/revocation 与每个 signing-subkey
  binding、embedded cross-cert 和 revocation packet，不只使用 library 折叠后的当前
  `Entity`。
- binary OpenPGP keyring 逐字节解析，合法末字节（包括 `0x0b`）不得被 trim；只有
  ASCII-armored 输入接受解码前 outer textual whitespace。
- 以 package signature time 为界，先选当时最新、密码学认证的 policy，再验证 flags、
  primary/subkey lifetime、outer self-cert/binding expiry、cross-cert 存在/expiry 与
  revocation；最新 policy 无效时不得回退旧宽松 policy。
- `KeySuperseded`/`KeyRetired` 从认证的撤销时间起前向生效；compromise 与
  no-reason/unspecified 追溯失效历史签名。
- 新下载或未证明的 present body 用稳定句柄流式绑定 advertised SHA-256/size；RPM 还要
  验 embedded signature。只复用 unchanged first-valid DEB receipt，或相同 package-
  keyring SHA 的 RPM v3 receipt；keyring rotation/legacy receipt 强制重验。对象新进入
  view 前仍执行 `pool.Verify`。
- APT 已存在匹配使用 exact repo-path-relative component/name/version/size；先剥离精确
  `repo.path + "/"`，再只接受 relative `pool/<configured-component>/...`。repo root 中
  的 `pool/main` 子串或 main→contrib 同 digest 移动不能隐藏新 placement。

详见 [RPM package trust closure](2026-07-13-rpm-package-trust-closure.md) 与
[ADR-0017](../adr/0017-rpm-package-keyring-and-cryptographic-verification.md)。

## 静态交叉构建

```text
linux/amd64  static ELF   47,021,598B   SHA-256 ecba281e…
linux/arm64  static ELF   44,641,199B   SHA-256 719721df…
darwin/amd64 Mach-O       48,715,664B   SHA-256 7e5a1b43…
darwin/arm64 Mach-O       46,728,786B   SHA-256 9aa42830…
```

四组均在 parser 修复后使用 `CGO_ENABLED=0`。省略号是已记录摘要前缀，不代表编造了
完整 hash；最终 product identity 仍应由 clean-delivery 记录。

## 真实客户端、S3-compatible 与官方上游

```text
SOW_RUN_DOCKER_COMPAT=1 SOW_COMPAT_NGINX=1 ... go test -v ./test/compat
  Docker client 53.12s; YUM bridge 28.57s
  package 93.128s; wall 93.99s; PASS
```

真实 Nginx 直托树通过 apt install；EL10/EL9 DNF 消费 zstd，EL8 消费 gzip；YUM
signed pair 与 generation-pinned mirrorlist 通过。该门禁是真客户端证据，但未穿过真实
Cloudflare/EdgeOne。

首次调用 PATH 漏 `/usr/local/bin/docker`，11 个 Docker 子测均未启动并报 executable
not found；该无效 harness 运行不计入产品结果。修正 PATH 后完整重跑得到上面的权威 PASS。

Pigsty public RPM/package-key 正负信任门禁 test 2.59s/package 3.246s（wall 4.12s）
PASS；缺 key 拒绝，dnf install + `rpm -K` 正控通过。

```text
SOW_RUN_REAL_UPSTREAM=1 TestOfficialPGDGUpstreamSyncCompatibility
  test 101.94s; package 102.565s; wall 103.44s; PASS
  APT first candidates=3938 download=1 present=0 filtered=3937;
      replay download=0 present=1
  YUM first candidates=1344 download=12 present=0 filtered=1332;
      replay download=0 present=12
  receipts=1 DEB + 12 RPM; CAS=536,434 bytes; evidence=5
  materialize=13 entries / 45 files / 709,543 repository bytes
```

该门禁实际经过 production CLI 的 upstream 发现、筛选、签名/checksum、CAS、receipt、
重放和物化；永久测试另行证明 keyring rotation/legacy receipt 强制重验。

```text
SOW_MINIO_TEST=1 TestMinIOS3Compatibility
  test 0.76s; package 1.284s; wall 2.05s; PASS
```

真 MinIO/SigV4 覆盖 conditional mutation 的安全失败边界。它是本地 S3-compatible
证据，不是 R2/COS 条件删除或供应商 CDN 证据。

## 规模、模糊与迁移门禁

```text
perf package/wall:        32.095s / 37.52s
APT manifest:             40,681 / 47,155,427,190B / 4.224s
YUM manifest:             31,629 / 42,707,068,318B / 3.436s
combined:                 72,310 / 89,862,495,508B / 7.661s / 18 workers
materialize:              50,000 / 11.960s; reconcile 2.793s /
                          workers 8/peak 8 / retained +69,328B
publish plan:             50,000 -> 1 / 16.316ms / one object / +40,008B
YUM streaming:            50,000 / 4.680s / +30,648B / compressed 152,302B
APT streaming:            package 3.693s / wall 3.99s / elapsed 3.012s /
                          workers peak 4 / retained 240,416B /
                          max RSS 300,498,944B / spool 32,126,600B / chunk 256
```

上述 post-fix 性能命令均在空闲条件下隔离重跑并 PASS。

post-fix URL/Release fuzz 各 5 秒，观察 540,487 / 444,076 次 execution（总耗时
6.756/6.368s）；RPM header fuzz 10 秒观察 5,161,146 次（11.396s）；全部 PASS。
execution 数只反映调度，不是阈值。

```text
legacy audit:             176 targets / 44 families / 7.42s
                          root 52 / APT 70 / YUM 14 / Docker 40
                          dispositions 117 / 31 / 18 / 8 / 2
                          TSV 177 lines / SHA-256 d2b7edf2…
audit negatives:          13/13 / 40.59s
zero-byte adopt/rollback: 7 groups / 2.71s
writer fence:             13/13 / 0.97s
targeted ordinary:        28 tests / 0 fail / 0 skip / 17.52s
targeted race:            28 tests / 0 fail / 0 skip / 26.80s
                          identical set SHA-256 f86cf3b6…
total:                    96.01s
```

以上是 parser 修复后的最终本地迁移重跑，运行产物保存在
`/tmp/sow-final-migration-validation.UTQSIC`。这些结果证明本地可执行迁移/回滚
夹具与 fail-closed 检查；不证明生产 writer/IAM 撤权、
真实 bucket/domain 切换或 Makefile 退役。

## 清洁交付门禁

**当前状态：current-source 双跑 PASS。** 2026-07-17 在 ADR-0035/provider-attestation v3
收口后，交付策略固定为 531 个 product source file 与 669 个 delivery file；两次仓库外、
独立 HOME/GOMODCACHE/GOCACHE 使用本机只读 `file://` module download cache 重建，均通过
`go mod tidy -diff`、download/verify、测试、静态构建、CLI smoke、秘密/链接/解包审计并产生
byte-identical archive。为避免 delivery manifest 自引用，最终 product/delivery/archive digest
和两个 archive path 只记录在仓库外交接文件
`_bmad-output/implementation-artifacts/validation-selected-set-materialization-2026-07-13.md`。
默认 `proxy.golang.org` 的一次超时仅是网络条件，不计作产品失败，也未改变工作区。

## 尚未闭合

以下项目保持 **OPEN**：

- R2 与 never-versioned COS 的真实条件 mutation/delete、checkpoint、inventory、失败重放
  与对象读回；
- 两家真实 purge/CDN、部署 Worker/EdgeOne function、双 token 干净 URL cache 归一化、
  匿名/WAF 负例与多 PoP；
- 生产旧树 staging/cutover/rollback、writer freeze/revoke、Makefile 退役与切换后 URL 对比；
- raw YUM alias 的生产 endpoint/trust/origin/client 切换；apt<1.2 已明确不支持，EL8 已冻结为
  Pigsty v5.0.0，不再是开放决策；
- G1、ANTI-01/02/03 的真实运行、成本与时延指标；
- Git release revision 与真正生产切换后的交付签章。

因此本地终审不能支持把长期 Goal 标记为完成。
