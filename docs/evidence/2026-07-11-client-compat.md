# APT / DNF 真实客户端兼容证据（2026-07-11）

## 结论

`test/compat/client_compat_test.go` 已在真实 Docker 客户端中通过。测试从生产
`cmd/sow` 构建单一 Go 二进制，执行 `sow init`、零改写遗留纳管、三次
`sow add`、beta→latest/stable promotion 和多视图 `sow materialize`，然后直接托管
完整物化树。容器仅
通过 `host.docker.internal` 访问该树。

- APT 2.4.14 验证纯 Go 生成的 `InRelease`，通过 SHA-256 by-hash 下载
  `Packages`，再下载并安装 `sow-compat-deb=1.2.3-1`；安装后的 dpkg 状态、
  精确版本和落盘文件均通过断言。索引同时含 `1.2.3-1` 与更新的
  `2.0.0-1`；独立 stable 物化树再次由 apt 列出两代，并明确安装旧版，证明
  不是“只有最新版本”的伪钉版。
- 支持下界使用 digest 固定的 `ubuntu:16.04` 原始客户端，实测
  `apt 1.2.35 (amd64)`。它同样验证 `InRelease`，实际请求 SHA-256 by-hash，
  同时列出两代并精确安装 `sow-compat-deb=1.2.3-1`。该测试锁住
  `apt >= 1.2` 的最小支持契约；另有 apt 1.0 固定 alias 负控，不把 `<1.2`
  伪装成支持路径。
- 同一生产 CLI 还执行 `stable → jammy-20260712`，把 immutable snapshot 独立
  物化并由 Nginx 直接托管。另一个干净 Ubuntu 22.04 容器以该 snapshot ID
  作为标准 APT suite，验证 snapshot `InRelease`、实际命中 snapshot
  `by-hash/SHA256`，同时列出两代并安装 `1.2.3-1`。这不是只检查生成文件。
- DNF 4.20.0 在 `repo_gpgcheck=1` 下导入 SOW repository 公钥并验证
  `repomd.xml.asc`，实际消费 primary、filelists、other 三类 zstd 元数据，
  同时从包安装路径之外预置并导入 fingerprint
  `D4BF 08AE 67A0 B4C7 A1DB CCD2 40BC A2B4 08B4 0D20` 的 PGDG package key，
  在 `gpgcheck=1` 下下载并安装
  `pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch`；安装后的 RPM EVR/架构通过
  精确断言，对 DNF 保留的同一下载 RPM 执行 `rpm -K` 结果为
  `digests signatures OK`。独立负例只提供 SOW metadata key，DNF 明确报告
  `Public key ... is not installed` / `GPG check FAILED`，且包未安装。
- AlmaLinux 8 的 DNF 4.7.0 / RPM 4.14.3 先消费由 `sow init
  --adopt-content` 零改写纳管的冻结 EL8 ref，再消费正式 `sow materialize
  latest` 生成的 primary/filelists/other 三类 gzip 元数据；同样验证
  `repomd.xml.asc`、安装精确 RPM，并以 `rpm -K` 验证制品签名。
- 冻结 EL7 兼容叶使用 digest 固定的 CentOS 7、YUM 3.4.3 / RPM 4.11.3。
  它以 `repo_gpgcheck=1` 验证纯 Go 生成的 `repomd.xml.asc`，由真实 YUM
  library 拉取 primary/filelists/other 三类 gzip 元数据，并把镜像内较新
  `centos-release` 降级安装为测试夹具的精确 NEVRA；`rpm -K` 同时验证包签名。
  该路径只允许 `lifecycle: frozen` + gzip，不把 EL7 扩成 active 支持面。
- AlmaLinux 9 的 DNF 4.14.0 / RPM 4.16.1.3 消费 EL9 zstd
  primary/filelists/other，安装相同 noarch RPM 并通过 `rpm -K`；这与 EL10 分开
  执行，避免把“同为 zstd”误当成客户端兼容证据。
- stable YUM 视图包含 `centos-release` 两个历史 NEVRA（含不同 epoch）。
  AlmaLinux 10 的 `dnf repoquery` 同时列出两版，并用精确 NEVRA 下载两个真实
  RPM；请求日志命中两条 `Packages/c/...rpm`，证明不是只在 manifest 中保留。
- 独立 Nginx Basic Auth 回退同时被 Ubuntu apt 和 AlmaLinux 10 dnf 实际安装
  消费；无凭据返回 401、正确凭据返回 200、非 `/pro/v1/basic/` 路径返回 404。
  APT `auth.conf` 显式声明测试所用 HTTP scheme，生产模板要求 HTTPS。
- 生产构建出的 Cloudflare Worker bundle 还由一个本地 file-backed service origin
  实际加载；Ubuntu apt 与 AlmaLinux 10 dnf 都从
  `/pro/v1/{token}/...` 路径完成元数据验签、包验签与精确安装。Worker 在调用
  origin 前验证并剥离 token，origin 只观测到 `/apt/...`、`/yum/...` 与
  `/_sow/...` 干净路径。客户端日志、请求证据和源 key 均不保存原 token；这条
  证据不连接 Cloudflare API、R2 或 CDN，也不冒充真实供应商运行。
- 两个客户端均只启用测试仓库。APT 的系统 source 被替换且
  `sources.list.d` 被清空；每个 DNF 命令都使用
  `--disablerepo='*' --enablerepo=sow-compat`。

## 实测环境

执行时间：2026-07-12（Asia/Shanghai；测试 HTTP Date 为 UTC 2026-07-11）。

| 项目 | 实测值 |
|---|---|
| 宿主 | macOS Darwin 25.5.0, arm64 |
| Go | go1.26.5 darwin/arm64 |
| Docker | client 29.4.1 darwin/arm64；server 29.4.1 linux/arm64 |
| APT 镜像 | `ubuntu:22.04`, linux/amd64, `sha256:0d779ea97881505f5ef0039336ee85edba27519bdba968c284c86ee066a973c8` |
| APT 支持下界镜像 | `ubuntu:16.04`, linux/amd64, `sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6` |
| DNF 镜像 | `almalinux:10`, linux/amd64, `sha256:689dc4a86e288b3f88ced4bf14bef18cdaf5539609608ca4cebc62720740dfa2` |
| EL9 公开镜像 | `almalinux:9`, linux/amd64, `sha256:28db580abb508f7ccbc0ac6d53e1d8da9d42a26c77fa3dcc26ac2726673fbe3e` |
| EL8 公开镜像 | `almalinux:8`, linux/amd64, `sha256:f043b7ac550015e1ed0b5a55a420c61d178bff4357ab9663fe0fbdcf1e6e2d86` |
| 冻结 EL7 镜像 | `centos:7`, linux/amd64, `sha256:be65f488b7764ad3638f236b7b515b3678369a5124c47b8d32916d6487418ea4` |
| APT / dpkg | apt 2.4.14 (amd64), Ubuntu 22.04 容器 |
| APT 支持下界 / dpkg | apt 1.2.35 / dpkg 1.18.4 (amd64), Ubuntu 16.04 容器 |
| DNF / RPM | dnf 4.20.0, RPM 4.19.1.1, EL10 容器 |
| EL9 DNF / RPM | dnf 4.14.0, RPM 4.16.1.3, AlmaLinux 9 容器 |
| EL8 DNF / RPM | dnf 4.7.0, RPM 4.14.3, AlmaLinux 8 容器 |
| EL7 YUM / RPM | yum 3.4.3, RPM 4.11.3, CentOS 7 容器 |

宿主和镜像架构不同，因此测试显式使用 `--platform linux/amd64`；上述镜像在
Docker Desktop 的 arm64 daemon 上运行。

最终 320-file product-source 摘要为
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`。
该摘要上的完整 Nginx/客户端矩阵 package 54.624s PASS；下文保留较早的详细请求日志，
最终静默重跑重新执行了相同 `gpgcheck=1`/`repo_gpgcheck=1`、by-hash、snapshot、
generation mirrorlist 与 default-deny 断言。

## 可复现命令

默认测试不启动 Docker，适合普通单元测试和没有 daemon 的环境：

```bash
go test -count=1 ./test/compat
```

真实客户端门禁必须显式启用：

```bash
SOW_RUN_DOCKER_COMPAT=1 go test -count=1 -v ./test/compat
```

2026-07-12 早期两客户端基线结果（保留作演进记录）：

```text
--- PASS: TestDockerClientCompatibility (5.32s)
    --- PASS: TestDockerClientCompatibility/apt (1.27s)
    --- PASS: TestDockerClientCompatibility/dnf (2.09s)
PASS
ok github.com/pgsty/sow/test/compat 5.958s
```

同一门禁还在 Go race detector 下复跑通过：

```text
$ SOW_RUN_DOCKER_COMPAT=1 go test -race -count=1 ./test/compat
ok github.com/pgsty/sow/test/compat 7.368s
```

测试镜像可由环境覆盖；这使同一个真实客户端门禁可在干净 CI runner 上使用
公开官方镜像，而不是依赖开发机预置镜像：

```bash
SOW_RUN_DOCKER_COMPAT=1 \
SOW_COMPAT_NGINX=1 \
SOW_COMPAT_APT12_IMAGE=ubuntu:16.04@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6 \
SOW_COMPAT_APT_IMAGE=ubuntu:22.04 \
SOW_COMPAT_DNF_IMAGE=almalinux:10 \
SOW_COMPAT_EL9_IMAGE=almalinux:9 \
SOW_COMPAT_EL8_IMAGE=almalinux:8 \
SOW_COMPAT_EL7_IMAGE=centos:7@sha256:be65f488b7764ad3638f236b7b515b3678369a5124c47b8d32916d6487418ea4 \
  go test -count=1 -v ./test/compat
```

该路径也已在本机从 Docker Hub 拉取并实际通过，不是只写入 workflow：Ubuntu
镜像摘要为 `sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982`，
AlmaLinux 10 镜像摘要为
`sha256:cc24bc5b6ac7e284f2f62a07bdaa1b15d3319fdcf46413c6b8fe9fa245068ddd`；
APT 2.4.14、DNF 4.20.0、RPM 4.19.1.1。该次结果为 19.73s PASS
（APT 6.48s，DNF 10.46s），仍命中相同 by-hash、三类 zstd metadata、安装和
`rpm -K` 断言。`.github/workflows/ci.yml` 的 `real-clients` job 使用这一路径；
同时 CI 还执行全量 Go test/vet/race、四目标静态交叉构建和边缘共享契约测试。

本地树直接由 Nginx 托管的合同也单独实跑，而非从 Go 文件服务器作推断：

```bash
PATH="/opt/homebrew/bin:$PATH" \
SOW_RUN_DOCKER_COMPAT=1 SOW_COMPAT_NGINX=1 \
SOW_COMPAT_APT_IMAGE=ubuntu:22.04 \
SOW_COMPAT_DNF_IMAGE=almalinux:10 \
  go test -count=1 -v ./test/compat
```

该模式用临时配置启动 Nginx 1.31.2，`root` 直接指向 SOW 物化目录，不经过
SOW 服务进程或反向代理；同一 apt/dnf 安装、by-hash、三类 repodata、签名和
`rpm -K` 断言在 11.45s 内通过（APT 1.20s，DNF 2.24s）。HTTP 响应实际包含
`Server: nginx/1.31.2`，请求由 Nginx access log 回读并逐项断言。CI 的
`real-clients` job 安装 Nginx 并启用同一模式。

加入 EL9、冻结 EL8、stable 历史钉版、Basic Auth 回退与 generation-pinned
mirrorlist 后，公开镜像 + Nginx 的该次完整门禁实测为：

```text
--- PASS: TestDockerClientCompatibility (36.92s)
    --- PASS: TestDockerClientCompatibility/apt (1.35s)
    --- PASS: TestDockerClientCompatibility/apt-stable-history-pin (1.36s)
    --- PASS: TestDockerClientCompatibility/dnf-stable-history-pin (1.26s)
    --- PASS: TestDockerClientCompatibility/basic-fallback-apt-and-dnf (2.23s)
    --- PASS: TestDockerClientCompatibility/dnf (2.49s)
    --- PASS: TestDockerClientCompatibility/dnf-generation-pinned-mirrorlist (2.01s)
    --- PASS: TestDockerClientCompatibility/dnf-el9-zstd (3.16s)
    --- PASS: TestDockerClientCompatibility/dnf-el8-gzip (3.18s)
PASS
ok  github.com/pgsty/sow/test/compat  37.545s
```

加入 immutable APT snapshot suite 客户端后再次全量实跑：

```text
$ SOW_RUN_DOCKER_COMPAT=1 SOW_COMPAT_NGINX=1 \
    SOW_COMPAT_APT_IMAGE=ubuntu:22.04 SOW_COMPAT_DNF_IMAGE=almalinux:10 \
    SOW_COMPAT_EL9_IMAGE=almalinux:9 SOW_COMPAT_EL8_IMAGE=almalinux:8 \
    go test -count=1 ./test/compat
ok  github.com/pgsty/sow/test/compat  78.891s
```

snapshot 子测试的实测请求为：

```text
GET /apt/test/dists/jammy-20260712/InRelease 200
GET /apt/test/dists/jammy-20260712/main/binary-amd64/by-hash/SHA256/8338... 200
GET /apt/test/pool/main/s/sow-compat-deb/sow-compat-deb_1.2.3-1_amd64.deb 200
Setting up sow-compat-deb (1.2.3-1) ...
```

2026-07-17 对冻结支持下界单独实跑（Nginx 直接托管物化树）：

```text
support-floor client: apt 1.2.35 (amd64)
GET /apt/test/dists/jammy/InRelease 200
GET /apt/test/dists/jammy/main/binary-amd64/by-hash/SHA256/8338a98b... 200
GET /apt/test/pool/main/s/sow-compat-deb/sow-compat-deb_1.2.3-1_amd64.deb 200
Setting up sow-compat-deb (1.2.3-1) ...
--- PASS: TestDockerClientCompatibility/apt-1.2-support-floor (1.36s)
ok github.com/pgsty/sow/test/compat 39.603s
```

随后以相同 Nginx 和公开镜像执行整个 compat package（包括 apt 1.2/2.4、EL8/9/10、
历史、快照、Basic、generation flip、保留代与所有本地合同），`124.095s` PASS；
support-floor 子路径再在 race detector 下 `42.166s` PASS。real-cloud、real-edge、
real-upstream 与 legacy-APT opt-in 均显式关闭，未连接生产或云资源。

同日加入真实系统客户端经 Cloudflare Worker token-in-path 的门禁后，先独立实跑：

```text
--- PASS: TestDockerClientCompatibility (38.23s)
    --- PASS: TestDockerClientCompatibility/cloudflare-token-path-apt-and-dnf (2.86s)
PASS
ok github.com/pgsty/sow/test/compat 38.763s

$ go test -race -run '^TestDockerClientCompatibility/cloudflare-token-path-apt-and-dnf$' ...
ok github.com/pgsty/sow/test/compat 41.202s
```

APT 实际请求 `InRelease`、SHA-256 by-hash 与精确 DEB；DNF 实际请求
`repomd.xml`/`.asc`、三类元数据与精确 RPM，并保持
`repo_gpgcheck=1`/`gpgcheck=1`。边缘 evidence 只保存 credential SHA-256、干净
路径和无凭据 origin key；测试会在 token 出现在客户端输出、evidence 或 origin
namespace 时失败。该门禁加载检入的生产 dist bundle，而不是在 Go 中重写一个
“等价”鉴权 mock；service origin 只用于本地无云消费测试。

同日加入冻结 EL7 的真实 YUM 3 门禁。产品 YUM signer 保持 SHA-256，但关闭
go-crypto 的随机 salt notation，并把 creation-time/key-flags 子包编码为旧客户端可
忽略的 non-critical 形式；固定时间的签名仍逐字节可重放，篡改负例仍失败。聚焦普通
与 race 实跑结果为：

```text
--- PASS: TestDockerClientCompatibility (42.55s)
    --- PASS: TestDockerClientCompatibility/yum-el7-frozen-gzip (5.27s)
PASS
ok github.com/pgsty/sow/test/compat 43.612s

$ SOW_RUN_DOCKER_COMPAT=1 SOW_COMPAT_NGINX=1 \
    go test -race -run '^TestDockerClientCompatibility/yum-el7-frozen-gzip$' ...
ok github.com/pgsty/sow/test/compat 44.439s
```

请求证据包含 `repodata/repomd.xml`、`.asc`、primary/filelists/other 三个 gzip
对象和精确 RPM；所有其他仓库在每个 YUM 命令中显式禁用。`internal/yumrepo`
的确定性/验签回归同源代码上 `8.234s` PASS。整个路径只使用临时目录、本地 Nginx
和 Docker bridge，没有云连接或生产仓库写入。

随后清空全部供应商凭据并显式关闭 real-cloud/real-edge/real-upstream/legacy-APT，
重跑完整 compat package：apt 1.2/2.4、EL7/8/9/10、快照/历史、Basic、生产
Cloudflare Worker bundle 的本地 token path、generation flip 与 Nginx default-deny
全部通过，package `131.021s` PASS。该结果取代此前不含 EL7 的 `129.624s` 基线。

`-v` 输出包含完整 SOW 命令输出、客户端日志和 HTTP 请求日志；失败时相同内容
会直接进入测试错误。测试超时为 10 分钟，不会在 Docker 命令失联时无限等待。

## SOW 生成结果

本次生产 CLI 输出的关键事实：

```text
scanned repo=apt-test files=0 bytes=0
scanned repo=yum-el8 files=6 bytes=15280
scanned repo=yum-el9 files=0 bytes=0
scanned repo=yum-test files=0 bytes=0
adopt-content scanned repo=yum-el8 type=yum payloads=1 bytes=11277 pool=public frozen=true
adopt-content ... leaves=2 receipts=1 serving_tree_rewritten=false
added format=deb packages=2 leaves=1 elapsed=445.592416ms
added format=rpm packages=3 leaves=1 elapsed=316.944708ms
added format=rpm packages=1 leaves=1 elapsed=274.97225ms
promoted source=beta destination=latest leaves=6 entries=12
materialized ref=beta target=export entries=6 files=25 apt_suites=1 yum_repos=2
materialized ref=stable target=export-stable entries=5 files=19 apt_suites=1 yum_repos=1
materialized ref=jammy-20260712 target=export-snapshot entries=2 files=11 apt_suites=1 yum_repos=0
materialized ref=latest target=working-tree repos=4 changed=true
```

三次生产 `sow add` 均远低于 PRD 的单次一分钟反指标门槛；测试会在任一次
达到或超过一分钟时直接失败，而不是只把耗时打印到日志。

测试在启动客户端前还直接检查以下物化闭包：

- APT：`Packages`、`Release`、`InRelease`，以及至少三个
  `by-hash/SHA256/*` 对象；
- YUM：`repomd.xml`、非空 `repomd.xml.asc`，以及恰好一份 primary、
  filelists、other 的 `*.xml.zst`。
- EL9 YUM：同样要求签名与三类 `*.xml.zst`，再由独立 AlmaLinux 9 客户端
  实际查询、安装并读取 filelists/other。
- EL8 YUM：相同签名闭包，但三类 metadata 必须且只能是 `*.xml.gz`；冻结
  配置拒绝 add/sync，存量 payload 由显式 adoption ref 物化。

仓库和签名均由 Go 路径产生。SOW 生成阶段没有调用 Python、Perl、`gpg`、
`createrepo_c` 或 aptly；测试只调用生产 `sow` 二进制。DEB 是测试中用 Go
构造的可安装 Debian 二进制包；RPM 是检入的真实 PGDG noarch fixture。

## 客户端请求与验收点

APT 的成功日志包含：

```text
GET /apt/test/dists/jammy/InRelease 200
GET /apt/test/dists/jammy/main/binary-amd64/by-hash/SHA256/<digest> 200
GET /apt/test/pool/main/s/sow-compat-deb/sow-compat-deb_1.2.3-1_amd64.deb 200
Setting up sow-compat-deb (1.2.3-1) ...
```

测试不会接受回落到固定 `Packages` URL：必须观察到
`/by-hash/SHA256/` 请求才通过。

stable 历史钉版子测试在候选版本为 `2.0.0-1` 时仍执行并验证：

```text
Version table:
   2.0.0-1 500
   1.2.3-1 500
apt-cache madison ... -> 1.2.3-1, 2.0.0-1
Get: ... sow-compat-deb amd64 1.2.3-1
Setting up sow-compat-deb (1.2.3-1) ...
```

该子测试来自 `latest → stable` 的 append-only ref，并单独 materialize/托管，
不是复用 beta 进程内断言。

APT snapshot 子测试则使用不同 suite 和独立 serving root：

```text
deb [arch=amd64 signed-by=/etc/apt/keyrings/sow-compat.gpg] \
  http://host.docker.internal:<port>/apt/test jammy-20260712 main
Get:1 ... jammy-20260712 InRelease
Get:2 ... jammy-20260712/main amd64 Packages
Setting up sow-compat-deb (1.2.3-1) ...
```

DNF 的成功日志包含：

```text
GET /yum/test/x86_64/repodata/repomd.xml 200
GET /yum/test/x86_64/repodata/repomd.xml.asc 200
GET /yum/test/x86_64/repodata/<digest>-primary.xml.zst 200
GET /yum/test/x86_64/repodata/<digest>-filelists.xml.zst 200
GET /yum/test/x86_64/repodata/<digest>-other.xml.zst 200
GET /yum/test/x86_64/Packages/p/pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm 200
Installed: pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch
rpm -K: /var/cache/dnf/.../pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm: digests signatures OK
```

filelists 和 other 不是仅检查文件存在：测试分别执行 `repoquery --list` 与
`repoquery --changelogs` 强制真实 DNF 客户端读取它们，并在宿主 HTTP 请求日志
中逐项断言。`repomd.xml.asc` 同样必须出现实际 200 请求；仅在服务树中存在
签名文件不足以通过测试。RPM 下载使用 `keepcache=True` 保留客户端实际消费的
原始字节；DNF 在安装事务前从独立 trust path 导入 PGDG package key，并在
`gpgcheck=1` 下完成事务，随后对 cache 文件运行 `rpm -K`。任一步未验证签名都立即
失败。因此这轮同时给出 APT `InRelease`、YUM `repomd.xml.asc` 和 RPM 制品签名
三条真实客户端命令证据。

EL8 客户端还必须出现以下请求；任何 `.zst` 替代都不会满足断言：

```text
GET /yum/el8/x86_64/repodata/repomd.xml.asc 200
GET /yum/el8/x86_64/repodata/<digest>-primary.xml.gz 200
GET /yum/el8/x86_64/repodata/<digest>-filelists.xml.gz 200
GET /yum/el8/x86_64/repodata/<digest>-other.xml.gz 200
GET /yum/el8/x86_64/Packages/p/pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm 200
rpm -K: /var/cache/dnf/.../pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm: digests signatures OK
```

EL9 子测试反向约束压缩格式：必须请求三类 `.xml.zst`，出现 `.xml.gz` 即失败。
stable YUM 子测试则要求 `repoquery` 同时返回两个 `centos-release` NEVRA，并
分别观察两个 `Packages/c/*.rpm` 的 200 请求；因此历史钉版覆盖的是客户端可见
对象闭包，而非仅检查本地 ref。Basic Auth 子测试由同一真实 apt/dnf 客户端
访问 Nginx `/pro/v1/basic/`，同时验证匿名 401、错误路径 404 和正确凭据 200。
generation-pinned 子测试先请求静态 mirrorlist，再要求 repomd pair、三类元数据和
RPM 全部落在同一个 `/_sow/v1/g/00000000000000000001/` 前缀；真实 DNF 在
`repo_gpgcheck=1` 和 `gpgcheck=1` 下完成 makecache、filelists/other 查询和安装。

## DNF 双信任链回归（2026-07-12）

客户端合同审计发现旧矩阵虽验证 repomd 和事后 `rpm -K`，实际安装仍设置
`gpgcheck=0`。修复后所有 baseurl、generation mirrorlist、in-flight flip、Basic、
EL8/9/10 和历史配置都显式使用 `gpgcheck=1`；`gpgkey` 同时列出本轮唯一的 SOW
metadata key 和预置 PGDG package key。package key 挂载在 `/run/sow-keys/`，避免
占用 RPM 自己安装的 `/etc/pki/rpm-gpg/...` 目标，因而证明的是正常安装而非只读挂载
造成的伪失败。

同一完整 Nginx 矩阵实跑：

```text
--- PASS: TestDockerClientCompatibility (64.05s)
    --- PASS: .../apt (1.61s)
    --- PASS: .../apt-stable-history-pin (1.77s)
    --- PASS: .../apt-immutable-snapshot-suite (1.65s)
    --- PASS: .../dnf-stable-history-pin (2.17s)
    --- PASS: .../basic-fallback-apt-and-dnf (3.00s)
    --- PASS: .../dnf-package-key-required (2.06s)
    --- PASS: .../dnf (4.23s)
    --- PASS: .../dnf-generation-pinned-mirrorlist (3.51s)
    --- PASS: .../dnf-el9-zstd (5.00s)
    --- PASS: .../dnf-el8-gzip (5.01s)
    --- PASS: .../dnf-generation-flip-keeps-inflight-client-pinned (5.12s)
PASS
ok github.com/pgsty/sow/test/compat 64.734s
```

关键正负证据：

```text
Importing GPG key 0x08B40D20 ... From: /run/sow-keys/PGDG-RPM-GPG-KEY-RHEL-nonfree
Key imported successfully
Installed: pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch
rpm -K: ...: digests signatures OK

Public key for pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm is not installed.
GPG Keys are configured as: file:///etc/pki/rpm-gpg/SOW-COMPAT
Error: GPG check FAILED
missing upstream package key rejected before install
```

这关闭“先安装 release RPM 再从包内导入 key”的循环信任缺口，并验证一份真实
保留上游签名 RPM。Pigsty builder 自建包不由测试临时造包冒充（SOW 明确不造包）；
另一个 opt-in 门禁直接消费现存 builder artifact 与 public key：

```bash
SOW_RUN_PIGSTY_PACKAGE_TRUST=1 \
SOW_COMPAT_DNF_IMAGE=almalinux:10 \
SOW_COMPAT_PIGSTY_RPM=/absolute/path/to/pev2-1.22.0-1.noarch.rpm \
SOW_COMPAT_PIGSTY_PUBLIC_KEY=/absolute/path/to/pigsty-public-key \
  go test -count=1 -run '^TestPigstyBuilderPackageTrustCompatibility$' \
  -v ./test/compat
```

本机以 `/Users/vonng/pgsty/repo` 的真实 313,928-byte
`pev2-1.22.0-1.noarch.rpm` 和 public-only Pigsty key 实跑 3.00s（package 3.308s）
通过。负例只给 SOW repository key，DNF 报 `GPG check FAILED` 且未安装；正例再给
fingerprint `9592 A7BC 7A68 2E73 3337 6E09 E793 5D8D B9BD 8B20` 的 Pigsty package
key，真实请求 `repomd.xml.asc` 与 `Packages/p/pev2...rpm`，安装成功并由 `rpm -K`
返回 `digests signatures OK`。夹具拒绝相对路径、symlink、空/超限文件和含私钥材料
的 key 输入；CI 必须从 builder artifact store 注入，不把私钥或包副本写进 SOW 仓库。

## 审计后 Nginx default-deny 回归（2026-07-12）

仅拒绝 `.sow/.pool/.git` 仍可能让同根的 `sow.yaml` 或 operator 文件被同 UID
worker 读取，因此公开 origin 和独立 Basic fallback 都改为配置仓库前缀、`_sow`
及公钥的显式白名单，default location 一律 404。下列隔离测试使用真实存在文件，
不是用不存在路径的偶然 404 代替访问控制：

```text
$ SOW_COMPAT_NGINX=1 go test -run \
  '^(TestNginxRepositoryAllowlist|TestBasicNginxRepositoryAllowlist)$' \
  -count=1 -v ./test/compat
--- PASS: TestNginxRepositoryAllowlist (5.05s)
--- PASS: TestBasicNginxRepositoryAllowlist (5.03s)
PASS
ok  github.com/pgsty/sow/test/compat  10.572s
```

公开 APT probe 与 public key 返回 200；同一根中真实存在、mode 0600 的
`sow.yaml`、`operator-token`、额外 canary 与未知路径均返回 404。Basic 路径用正确
凭据访问 APT probe 为 200，但根级 operator canary 仍为 404。随后在同一 lifecycle
修复上重新运行完整矩阵，结果如下；因此不再用隔离的 10.572s 代替真实客户端：

```text
--- PASS: TestDockerClientCompatibility (50.04s)
    --- PASS: .../apt (1.31s)
    --- PASS: .../apt-stable-history-pin (1.30s)
    --- PASS: .../apt-immutable-snapshot-suite (1.30s)
    --- PASS: .../dnf-stable-history-pin (1.63s)
    --- PASS: .../basic-fallback-apt-and-dnf (2.17s)
    --- PASS: .../dnf (2.38s)
    --- PASS: .../dnf-generation-pinned-mirrorlist (1.93s)
    --- PASS: .../dnf-el9-zstd (3.00s)
    --- PASS: .../dnf-el8-gzip (3.11s)
    --- PASS: .../dnf-generation-flip-keeps-inflight-client-pinned (3.37s)
PASS
ok  github.com/pgsty/sow/test/compat  50.847s
```

最后一个子测试在 DNF 已读取 G1 metadata 后翻到 G2；同一客户端重新解析
mirrorlist 后从 G2 generation 下载被新索引移除的 G1 RPM 并成功安装，而新启动的
G2 客户端 repoquery 为空。请求日志同时断言 in-flight 客户端没有读取 G2 repodata，
只从 G2 的 retained unindexed payload closure 得到该 RPM。

## 边界

这份证据证明本地直接托管树在 apt 1.2/2.4、EL10 dnf 4.20、EL9 dnf 4.14 与
EL8 dnf 4.7 上可生成/纳管、验签、下载和安装，覆盖 APT by-hash、EL9/10
zstd、冻结 EL8 gzip、APT/YUM 历史钉版、Nginx Basic Auth 回退，以及真实
apt/dnf 对生产 Cloudflare Worker token-in-path bundle 的消费。
这份证据还证明 generation-pinned YUM mirrorlist 的真实客户端可消费性；但它不
替代仍需单独处理的 raw latest YUM baseurl、真实云对象
存储/CDN 发布验证或跨公网故障注入。
