# apt < 1.2 fixed-alias 原子性负 PoC

日期：2026-07-12（Asia/Shanghai）
宿主：macOS arm64 + Docker linux/amd64
客户端：`debian/eol:jessie`，apt `1.0.9.8.6`

## 结论

生产 `sow` CLI 生成的两个独立、完整、签名 generation 都能被 Jessie apt 验签、
更新并安装精确 DEB；这证明格式兼容。它不证明 mutable suite 原子。真实客户端随后
稳定复现两种跨代失败：

1. old `InRelease` + new fixed `Packages.gz`：`Hash Sum mismatch`；
2. `InRelease` 302 到 immutable new generation，同时设置 `no-store` 和 generation
   cookie；apt 随后的 fixed Packages 请求既不沿用重定向 generation，也不回传 cookie，
   被路由到 old generation 后仍为 `Hash Sum mismatch`。

因此，标准 apt 1.0 请求没有给静态对象存储/无会话边缘一个可把后续 fixed alias
绑定到已验证 InRelease generation 的输入。多键对象写入的任一顺序都会暴露至少一个
old/new 或 new/old 窗口。测试把这一点作为预期负证据，而不是把“单代可安装”误报成
NFR-05 原子兜底通过。

## 可复现命令

```bash
SOW_RUN_APT_LEGACY_COMPAT=1 \
SOW_COMPAT_LEGACY_APT_IMAGE=debian/eol:jessie \
go test -count=1 -run '^TestLegacyAPTFixedAliasAtomicity$' -v ./test/compat
```

## 当前实测

```text
apt 1.0.9.8.6 for amd64

--- PASS: TestLegacyAPTFixedAliasAtomicity (22.91s)
    --- PASS: .../coherent-old-generation (6.79s)
        GOODSIG / VALIDSIG
        GET .../Packages.gz 200
        Setting up sow-compat-deb (1.2.3-1)
    --- PASS: .../coherent-new-generation (6.78s)
        GOODSIG / VALIDSIG
        GET .../Packages.gz 200
        Setting up sow-compat-deb (2.0.0-1)
    --- PASS: .../publisher-order-old-inrelease-new-alias (2.66s)
        Failed to fetch .../Packages  Hash Sum mismatch
    --- PASS: .../redirect-no-store-cookie-cannot-pin-generation (2.70s)
        GET /_sow-compat/g/new/.../InRelease 200
        GET /apt/.../Packages.gz                 # no Cookie header
        GET /_sow-compat/g/old/.../Packages.gz 200
        Failed to fetch .../Packages  Hash Sum mismatch
PASS
ok  github.com/pgsty/sow/test/compat  23.622s
```

两个 coherent 子测试还实际下载并安装 DEB，不是只运行 `apt-get update`。负例要求
退出 100、包含 `Hash Sum mismatch`、请求日志确切来自不同 generation，且 redirect
候选的 Packages 请求不得携带 generation cookie；任何意外成功都会让测试失败并要求
重新评估协议结论。

## 产品处置边界

apt >= 1.2 继续使用已通过真实客户端验证的 by-hash。apt < 1.2 的 immutable
snapshot/固定 generation 可消费，但 mutable beta/latest 不能据此宣称原子。

2026-07-16 owner 已冻结政策：apt < 1.2 不受 SOW 支持，必须在迁移前升级；见
[ADR-0029](../adr/0029-client-support-floor-and-el8-freeze-version.md)。这关闭 COMP-02/NFR-05
的支持政策缺口，但不把本负 PoC 改写成正向通过，也不允许用旧客户端承诺 mutable
通道原子性。
