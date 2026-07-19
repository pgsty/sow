# 生产 latest URL 迁移前只读基线（2026-07-12）

## 范围

本证据只对现有公开 asset 指针执行 GET，不写 R2/COS/CDN，也不证明 SOW 切换后的
兼容性。它冻结 MIG-03/ANTI-03 的一个关键迁移前事实，供切换后逐字节回归。

## 可复现命令

```bash
for host in repo.pigsty.io repo.pigsty.cc; do
  curl --fail --location --silent --show-error --max-time 20 \
    --dump-header "/tmp/${host}.headers" \
    --output "/tmp/${host}.body" \
    "https://${host}/pkg/pig/latest"
done
shasum -a 256 /tmp/repo.pigsty.{io,cc}.body
cmp /Users/vonng/pgsty/repo/pkg/pig/latest /tmp/repo.pigsty.io.body
cmp /tmp/repo.pigsty.io.body /tmp/repo.pigsty.cc.body
```

随后对两个 URL 重复一次 GET，并比较第二次正文与第一次完全相同。

## 实测结果

| URL | HTTP | server | ETag | bytes | cache（第二次 GET） |
|---|---:|---|---|---:|---|
| `https://repo.pigsty.io/pkg/pig/latest` | 200 | Cloudflare | `3ef04b1c4bad2e221ab8bdb7ce5bb803` | 5 | `cf-cache-status: HIT` |
| `https://repo.pigsty.cc/pkg/pig/latest` | 200 | Tencent COS/CDN | `3ef04b1c4bad2e221ab8bdb7ce5bb803` | 5 | `x-cache-lookup: Cache Hit` |

两个远端正文与本地
`/Users/vonng/pgsty/repo/pkg/pig/latest` 均为同一 5 字节 `1.5.1`（无换行），
SHA-256：

```text
9c50cdf6b7b54ba51e2a2f927862161bccb6f629ca71fa4457c157f9dad55d25
```

## 剩余门禁

APT/YUM channel-less URL 与其他公开 asset 仍需同样保存迁移前 inventory；SOW staging
切换后必须重新执行 GET、ETag/摘要、真实 apt/dnf、缓存与回滚比较。当前基线不能把
MIG-03 或 ANTI-03 升级为通过。
