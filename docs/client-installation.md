# APT / DNF 客户端安装合同

> **历史 V1 客户端合同。** 本文保留 generation-pinned route 的已归档配置；下一版
> `pool/ + dists/` 客户端与兼容矩阵见
> [`../design/next/specs/compatibility.md`](../design/next/specs/compatibility.md)。

本页描述 SOW 仓库的客户端侧配置。它不改变仓库元数据格式，也不让 SOW 生成
modulemd；签名、通道和认证失败时必须修复原因，禁止用 `trusted=yes`、
`gpgcheck=0` 或 `repo_gpgcheck=0` 绕过。

示例中的域名、仓库 ID、suite、组件、EL 版本和 key URL 都是占位值，应替换为
实际部署值。生产只使用 HTTPS。

## DNF：推荐 generation-pinned mirrorlist

latest/stable 客户端应使用 SOW 的 mirrorlist，而不是长期停留在 raw `baseurl`。
mirrorlist 每次解析到一个不可变 generation，因而 `repomd.xml` 与
`repomd.xml.asc`、三类 repodata 和包请求处于同一代。raw latest baseurl 只作为
迁移期兼容 alias；对象存储无法把两个签名对 key 作为一次原子写入。

公开 latest 示例：

```ini
[pigsty-latest]
name=Pigsty latest
mirrorlist=https://repo.example/_sow/v1/mirrorlist/latest/infra/el9/$basearch.txt
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://repo.example/key
       https://repo.example/pkg/keys/PGDG-RPM-GPG-KEY-RHEL-nonfree
metadata_expire=60
skip_if_unavailable=0
```

这里有两条不能混淆的信任链：`repo_gpgcheck` 验证由 SOW 唯一 repository key
签出的 `repomd.xml.asc`；`gpgcheck` 验证 RPM 自身的嵌入签名。Day 1 不重签上游
RPM，因此客户端 trust bundle 必须同时预置 SOW repository key 和所选包来源的
公开 package key。自建包若按 FR-17 使用同一个 Pigsty key，则无需再增加身份；上游
key 只是被保留包的客户端验证材料，不是 SOW 的第二个 metadata signing identity，
也不改变 schema-v1 的单 repository-key 冻结合同。

服务端 `sow.yaml` 也必须在对应 repo 的 `yum.package_keyring` 中声明同一组 package
signer。客户端 bundle 决定 dnf/rpm 是否安装；SOW bundle 决定 add/sync 是否接纳这些
字节，以及 L1、materialize 与 publish 是否允许它们进入可服务闭包。零字节 legacy
adoption 可先把原字节导入 CAS 并写 migration-only receipt，但第一次物化/发布和独立 L1
仍会按当前 bundle 逐包验签，旧 receipt 不能绕过该门禁。两边均不可用 metadata key
冒充 package trust。

所有 package key 必须在启用 repo 前由受信发布清单固定完整 fingerprint，并作为普通
public asset 分发；不能等到安装“仓库 release RPM”后才从包内取 key，因为那会形成
先安装、后验证的循环。key 轮换应先并行部署新 public key、核对 fingerprint，再发布
由它签名的包；旧包仍可达期间，客户端和 SOW package bundle 都必须保留旧 key；不得用
`gpgcheck=0` 跨越轮换。

Pro stable 使用同一路径合同，只在最前面增加认证前缀：

```ini
mirrorlist=https://repo.example/pro/v1/TOKEN/_sow/v1/mirrorlist/stable/infra/el9/$basearch.txt
```

不要把 bearer token 写进镜像、公开仓库、命令输出或工单。生成 `.repo` 文件时应
使用权限受控的 secret provider，并把结果设为 `0600`。Basic Auth 回退保持 URL
干净，并用 DNF 的独立凭据字段：

```ini
mirrorlist=https://repo.example/pro/v1/basic/_sow/v1/mirrorlist/stable/infra/el9/$basearch.txt
username=USER
password=PASSWORD
```

若该路径由 Cloudflare Worker/EdgeOne 边缘函数提供 Basic 鉴权，`USER:PASSWORD`
必须是最长 1024 字节的可打印 US-ASCII：用户名非空且不含冒号，密码可继续包含冒号；
控制字符、DEL、非 ASCII 与非规范/无 padding 的 Base64 均拒绝。entitlement 中保存的是
精确解码后 `USER:PASSWORD` 的 SHA-256，而不是 `Authorization` 头里的 Base64 文本。
边缘挑战因此不宣称 UTF-8。独立 Nginx fallback 的密码字符能力仍由实际 htpasswd/Nginx
实现决定，但客户端配置同样不应依赖含糊的跨编码凭据。

凭据只落在 root-only 配置或客户端 secret provider；不能进入 mirrorlist、canonical
ledger、日志或 URL userinfo。只有边缘层在 cache lookup 前完成 Basic 鉴权并发出干净
子请求时，Authorization 才能从共享缓存键排除；独立 Nginx 回退在源站才鉴权，因此
必须完全不共享缓存。该 fallback 直接托管 `.sow/origin/gated`：mirrorlist 返回 `private, no-store`，immutable
generation 同样返回 `private, no-store`。公开 origin 只允许声明的 APT/YUM/asset
前缀、`_sow` 与公钥；`.sow/.pool/.git`、`sow.yaml` 和其他根文件始终 404。generation
内容不可变，但本地保留窗口按翻转次数而非时间计算，因此 Basic fallback 不得发布
无法由该窗口保证的一年 TTL。

`state.yum_generation_retention: N` 表示每个 serving target/repo/OS/arch 在 current
之外保留最近 N 个 generation（默认 N=2）。同一 DNF 事务若在 payload 阶段再次解析
mirrorlist，新 generation 会继续 hardlink 这些 retained generation 的 Packages 字节，
但 repodata 只描述当前 view。运维必须保证单个客户端事务不跨越超过 N 次通道翻转；
需要更长窗口时应先增大该值并重新物化，再执行高频发布。

### PostgreSQL AppStream module

RHEL/Alma/Rocky 8/9 可能启用发行版自带的 PostgreSQL AppStream module。它会在
客户端侧屏蔽或优先选择模块流中的包；这是 DNF 求解器行为，不是仓库缺少 modulemd。
在安装 Pigsty/PGDG PostgreSQL 包前，仅当主机实际列出该 module 时禁用它：

```bash
if sudo dnf -q module list postgresql >/dev/null 2>&1; then
  sudo dnf -y module disable postgresql
fi
sudo dnf --refresh makecache
sudo dnf install postgresql16-server
```

EL10 不要求 SOW 生成 modulemd，也通常不需要上述命令；条件探测在不支持 module
子命令或没有 PostgreSQL module 时直接跳过。不得为“修复”客户端 module 选择而向
SOW 仓库添加 modulemd、sqlite repodata 或 zchunk。

验证仓库签名和所选来源：

```bash
sudo dnf clean metadata
sudo dnf --refresh makecache
dnf repolist --enabled
dnf repoquery --location postgresql16-server
```

出现 repomd 签名错误时，先确认 `.repo` 已迁到 generation-pinned mirrorlist、系统
时间和 SOW repository key 指纹正确，再重试；包签名错误则核对对应 package key
fingerprint。不得关闭 `repo_gpgcheck` 或 `gpgcheck`。

## APT：by-hash 与标准 suite

将仓库公钥保存为只读 keyring，并使用 `signed-by`：

```text
deb [signed-by=/etc/apt/keyrings/pigsty.gpg] https://repo.example/apt/infra bookworm main
```

SOW 的 `InRelease` 声明 `Acquire-By-Hash: yes`；apt >= 1.2 会按 SHA-256 by-hash
取 Packages。stable 历史版本仍使用原生版本选择：

```bash
sudo apt update
apt-cache madison postgresql-16
sudo apt install postgresql-16=VERSION
```

快照是标准 suite。若快照 ID 为 `bookworm-20260712`，只把 distribution 改为该
suite，不更改 pool URL：

```text
deb [signed-by=/etc/apt/keyrings/pigsty.gpg] https://repo.example/apt/infra bookworm-20260712 main
```

Pro token 仍是 path 前缀，例如
`https://repo.example/pro/v1/TOKEN/apt/infra`。Basic Auth 回退不把凭据写入 source
URI，而放入 root-only `/etc/apt/auth.conf.d/pigsty.conf`：

```text
machine https://repo.example/pro/v1/basic/
login USER
password PASSWORD
```

```bash
sudo chmod 600 /etc/apt/auth.conf.d/pigsty.conf
```

SOW 支持的最低版本是 apt 1.2，并要求 mutable beta/latest/stable 通道使用 by-hash。
apt < 1.2 明确不受支持，必须在迁移前升级；即使旧客户端可以读取一个完整不变的
snapshot，也不能把它当成 mutable 通道的原子兜底。不得用
`Acquire::AllowInsecureRepositories` 或 `[trusted=yes]` 绕过此门禁。该支持政策与
真实 apt 1.0 负 PoC 见 [ADR-0029](adr/0029-client-support-floor-and-el8-freeze-version.md)。

## 安装后验收

每台受支持客户端至少保存以下证据：仓库配置（凭据脱敏）、key 指纹、
`apt update`/`dnf makecache` 退出码、实际下载 URL、安装的精确版本与架构。DNF
还应确认读取 primary/filelists/other，APT 应确认命中 by-hash。生产切换和回滚的
完整门禁见 [迁移 runbook](migration/runbook.md)。
