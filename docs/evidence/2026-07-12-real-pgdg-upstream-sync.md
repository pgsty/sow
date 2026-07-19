# 官方 PGDG upstream 真实同步证据（2026-07-12）

环境：Darwin/arm64（Darwin 25.5.0）、Go 1.26.5。测试访问 PostgreSQL 官方 APT/YUM
源，构建并调用 production `sow` 二进制；不是 `httptest` 元数据夹具。

## 复现

默认 `go test ./...` 会跳过公网门禁。显式运行：

```bash
SOW_RUN_REAL_UPSTREAM=1 go test -count=1 -v ./test/compat \
  -run '^TestOfficialPGDGUpstreamSyncCompatibility$'
```

入口为 `test/compat/real_upstream_test.go`。门禁固定以下官方输入：

| 格式 | upstream | 范围 | 信任锚 | 主指纹 |
|---|---|---|---|---|
| APT | `https://apt.postgresql.org/pub/repos/apt/` | `bookworm-pgdg/main/amd64`，只允许 `pgbadger` | `ACCC4CF8.asc` | `B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8` |
| YUM | `https://download.postgresql.org/pub/repos/yum/common/redhat/rhel-9-x86_64/` | `x86_64`，只允许 `pgdg-redhat-repo` | `PGDG-RPM-GPG-KEY-RHEL` | `D4BF08AE67A0B4C7A1DBCCD240BCA2B408B40D20` |

公钥单次下载上限 1 MiB、超时 30 秒，并拒绝跨 host redirect。每次 CLI sync
经只允许预期 `host:443` 的 CONNECT proxy，server→client TLS 流量硬上限 32 MiB；
完整测试总超时 6 分钟。公钥轮换、host 漂移、签名/索引/包 checksum 不一致、筛选
结果为空或超过 64 个 RPM、响应超限均失败闭锁，需要显式审核后更新门禁。

## 实测结果

```text
pinned APT key: B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8 (4812 bytes)
pinned YUM key: D4BF08AE67A0B4C7A1DBCCD240BCA2B408B40D20 (2484 bytes)

APT first:  candidates=3930 download=1  present=0  filtered=3929 provenance_changed=true
YUM first:  candidates=1344 download=12 present=0  filtered=1332 provenance_changed=true
APT replay: candidates=3930 download=0  present=1  filtered=3929 provenance_changed=false
YUM replay: candidates=1344 download=0  present=12 filtered=1332 provenance_changed=false

verify outcome=passed exit=0
materialized ref=beta target=export entries=13 bytes=536434 files=27
linked=13 existing=0 relinked=0 apt_suites=1 yum_repos=1

official PGDG gate passed:
  apt_receipts=1 rpm_receipts=12 cas_bytes=536434 evidence=5
  apt_wire_first=1661023 apt_wire_replay=197695
  yum_wire_first=378841 yum_wire_replay=10161

--- PASS: TestOfficialPGDGUpstreamSyncCompatibility (81.06s)
ok github.com/pgsty/sow/test/compat 81.648s
```

最终 320-file product-source 摘要
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`
上又执行一次完整静默门禁，package 40.737s PASS。紧邻的 verbose 门禁因公网波动为
144.67s（APT 首次 114.75s），仍保持 APT/YUM replay 零下载，并使用显式
`--serving-base-url https://export.example.invalid` 生成 mutable YUM strong-serving tree。

门禁还逐条验证：

- APT 官方 `InRelease` 签名与其 SHA-256 约束的 `Packages`，YUM 官方
  `repomd.xml.asc` 与其约束的 `primary.xml.gz` 均由 production parser 验证；
- 每个下载包按上游索引 size/SHA-256 校验后逐字节进入 CAS；13 个 CAS 对象重新
  hash 均与 receipt 一致，总计 536,434 bytes；
- 1 个 DEB receipt 同时引用已保存的 signed Release 与 Packages evidence；12 个
  RPM receipt 的 `original_rpm_sha256 == artifact_sha256` 且策略为
  `preserve-upstream`；canonical evidence 共 5 个对象；
- 第二轮真实公网同步下载为零，receipt 与完整 CAS 文件快照逐字节不变，证明安全
  重放不会删除或改写已纳管对象；
- production `sow verify --layer L1 --view beta` 通过；显式 `materialize beta`
  产出 13 个包文件，全部由 inode 比对证明为 CAS hardlink。

## 实跑发现并修复的生产缺陷

首次真实 YUM 运行在官方单个 armored `repomd.xml.asc` 上失败：OpenPGP armor
reader 在 CRC 行停止，旧代码随后直接读取已被内部 buffer read-ahead 的底层 reader，
把合法 footer 误报为 `trailing data after armored signature`。修复位于
`internal/upstream/signature.go`：严格解析恰好一个 armor envelope、验证可选 CRC-24、
拒绝 envelope 外尾随数据，再把完整 signature packet 交给受信 hash 验签。对应
`internal/upstream/signature_compat_test.go` 覆盖合法 armor、垃圾尾部与坏 CRC。

## 证据边界

该门禁关闭“同步器只对本地 TLS fixture 自证”的 FR-14/FR-16 边界，并与删除上游包
的本地故障夹具共同覆盖只加不删语义。它不替代真实 R2/COS/Cloudflare/EdgeOne PoC，
也不重复证明 apt/dnf 消费 SOW 生成仓库（后者见 `2026-07-11-client-compat.md`）。PGDG
upstream 是可变外部系统，因此该测试不放默认 CI；显式运行结果仅证明上述日期与快照。
candidate 数量只是日期化观察，不能作为可重放的上游快照身份；2026-07-13 的当时源码
复验已把 canonical metadata digest 一并归档如下。

## 2026-07-13 `c328…8f20` 复验（已被后续 P1 修复取代）

> 下述运行对 329-file identity 本身有效；后续盲审修复 RPM sync present-path digest
> verification 的 P1 缺陷后，产品源码已变化。因此这些时长/identity 仅为历史对照，新的
> product digest 上必须重跑本门禁，当前源码状态为 pending。

329-file product-source
`c328bca0bb838fd5b97fdb113b24d60ba7650e758a724c71519bbda480be8f20`
上完整 verbose 门禁 test 54.31s（package 55.079s）PASS。APT 3938 candidates 中下载
1 个，YUM 1344 中下载 12 个；重放分别 present=1/12、download=0。receipt=13、
CAS=536,434 bytes、evidence=5，L1 与 hardlink/strong-serving 物化通过。

12 个 RPM receipt 均为 `sow-provenance/v3`，绑定 package-keyring SHA-256
`a70c9527426017d00fa4e6f9d2941d515357a27a7be82e155248ece53bbe5453`、verified signer
`D4BF08AE67A0B4C7A1DBCCD240BCA2B408B40D20` 和 `header+payload-digest` coverage。
这证明 production sync 在 primary SHA/size 后还对 embedded RPM signature 与 payload
digest 建立受信证据，而不是只依赖 `repomd.xml.asc` 或记录未验证 packet。该轮源码身份、
全仓/race/客户端和性能重验证见
[RPM package trust closure](2026-07-13-rpm-package-trust-closure.md)。

```text
apt_release  e0ce4cda6ea05b096f63c1563636dc323f377eb6b820cac477ec4ee184240d42
apt_packages 13346e8435db13bf0d058d299560520066cad782e89b2ebbce3dc34073b7fafc
yum_repomd   fc6333d7c8ee1a32ebdfbaa1bc7cef7e83a975d7dd31d103b38e274b62459016
yum_repomd_asc 7fd103285984cff083c0d392bcd34dab2949bf7a77ec0156688abcdb53f6f267
yum_primary  d7dde731a1297d524a89fb304e43b11ffc9495043108e5fa9e25f0deec8a1ba4
```

这些五个摘要与前次归档一致，并绑定本轮实际解析和验签的 canonical evidence；上游仍是
可变外部系统，digest 只让本次观察可识别，并不承诺未来 URL 永远返回相同字节。
