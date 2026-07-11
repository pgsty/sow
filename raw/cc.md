# Cloudflare 缓存配置：repo.pigsty.io 全量缓存方案

> 2026-07-11 制定。策略前提：仓库按月度批次发布，每次发布完成后全量失效（Purge Everything）。
> 目标：**默认缓存所有内容**，让全球用户享受边缘加速，发布靠 purge 保证一致性。

## 一、现状（2026-07-11 实测）

repo.pigsty.io 是 R2 bucket `cf:/repo` 的自定义域名，走 pigsty.io zone 的标准缓存管线。
无任何 Cache Rule 时，Cloudflare 只按「默认扩展名列表」缓存，实测结果：

| 文件类型 | 数量 | 体积 | 当前状态 |
|---|---|---|---|
| `.rpm` | 17,896 | 26.75 GB | ❌ DYNAMIC 直穿 R2 |
| `.deb` | 17,757 | 33.75 GB | ❌ DYNAMIC 直穿 R2 |
| `.gz` / `.bz2`（repodata、Packages.gz） | 1,500 | 5.6 GB | ✅ 已缓存（默认 2h TTL） |
| `repomd.xml` / `InRelease` / `Packages` / `Packages.xz` | ~250 | ~0.1 GB | ❌ DYNAMIC |
| `.tgz` / 无扩展名脚本（get/pig/key）/ 其他 | ~400 | ~0.5 GB | ❌ DYNAMIC |

- **rpm + deb 占 bucket 体积约 90%（60.5 GB / 66.8 GB），全部未缓存**——这是"没有 CDN 加速"体感的主体。
- 隐患：`Packages.gz`（固定文件名）被默认缓存 2h，而 `InRelease` 不缓存永远新鲜，发布后每个边缘节点有最长 2h 的 Hash Sum mismatch 窗口（本方案的元数据规则 + purge SOP 一并解决）。
- ⚠️ 验证缓存必须用 GET（`curl -s -o /dev/null -D - <url>`），**不要用 `curl -I`**——Cloudflare 对 HEAD 请求一律报 DYNAMIC，会误判为零缓存。

## 二、规则设计

> **部署记录（2026-07-11）**：实际采用**单规则方案**——仅部署 Rule 1（`Cache Repo Everything`，
> 浏览器 TTL 用**绕过缓存**），Rule 2 未部署。理由：元数据与包体总是同批发布、发布后必定 purge。
> **代价：发布后 purge 从"建议"升级为"强制步骤"**——元数据边缘 TTL 长达 1 个月，漏 purge 即长期陈旧。
> 已实测验证：rpm / deb / repomd.xml / InRelease / /get 全部 MISS→HIT。

不需要按扩展名逐个枚举——Cache Rule 按 hostname 匹配即可覆盖**所有路径**（包括无扩展名的
`InRelease`、`/get`、`/pig` 等）。原设计用两条规则区分「不可变内容」与「可变元数据」：

| | Rule 1：全站长缓存 | Rule 2：可变元数据短缓存 |
|---|---|---|
| 匹配 | repo.pigsty.io 全部请求 | dists/、repomd.xml、安装脚本、版本指针 |
| Edge TTL | 30 天（忽略源站头） | 10 分钟（忽略源站头） |
| Browser TTL | 1 天 | Bypass（禁止客户端/代理缓存） |
| 摆放顺序 | 在前 | **必须在后**（后匹配的规则覆盖前者设置） |

Rule 2 是安全网：即使某次发布忘了 purge，坏掉的也只是 10 分钟内的元数据视图，
而不是长达 30 天的死仓库。元数据总量不足 100 MB，短 TTL 几乎不损失加速收益
（且能吃掉占请求大头的 InRelease/repomd 轮询流量）。

## 三、Dashboard 配置步骤

前置：repo.pigsty.io 是 R2 custom domain，DNS 记录已自动代理（橙色云），满足 Cache Rules 要求。

### 3.1 Rule 1 —— 全站缓存

> ⚠️ 若使用「Cache Everything」模板，**不要按模板默认值直接部署**，有两个坑：
> ① 模板默认匹配「所有传入请求」——那是整个 pigsty.io zone（含网站等所有子域），必须改为自定义表达式限定 repo 子域；
> ② 模板默认边缘 TTL 是「使用缓存控制标头（如果存在），否则绕过缓存」——R2 不发 cache-control，
> 等于全部绕过缓存，比不配置还糟（连现在默认缓存的 .gz 都会失去缓存）。

1. 登录 [dash.cloudflare.com](https://dash.cloudflare.com)，进入 **pigsty.io** zone。
2. 左侧菜单 **Rules → Overview**（旧版面板为 **Caching → Cache Rules**），点 **创建规则 / Create rule**，选择 **Cache Rule**。
3. 规则名称：`repo-cache-everything`。
4. **如果传入请求匹配**：选 **自定义筛选表达式**（不要选「所有传入请求」），点 Edit expression 粘贴：

   ```
   (http.host eq "repo.pigsty.io")
   ```

5. **缓存资格**：选 **符合缓存条件**。
6. **边缘 TTL**：选第三项 **忽略缓存控制标头，使用此 TTL**，时长填 **2592000 秒**（1 个月）。
7. **状态代码 TTL**：点 **添加状态代码设置**，配置一条：**大于等于 400 → 60 秒**。
   （404/410 属于默认可缓存状态码；不加这条，发布间隙的 404 可能按主 TTL 被缓存最长 1 个月。）
8. **浏览器 TTL**：选 **绕过缓存**（实际部署采用此项：边缘 purge 清不掉客户端/代理侧缓存，
   bypass 保证"purge 即全局一致"；仅当同时部署 Rule 2 时，此处才可放宽为 1 天）。
9. 其余设置全部保持默认：**缓存密钥**不添加；**Vary** 保持「归一化值」；
   **重新验证时提供过时内容**开关保持关闭（即允许在回源更新时先提供过时内容，对不可变包文件安全且提升可用性）；
   **接受强 ETag** 保持关闭；**源服务器错误页面通过** 保持关闭。
10. 放置顺序选 **第一位**，点 **部署 / Deploy**。

### 3.2 Rule 2 —— 可变元数据短缓存（可选安全网，2026-07-11 决定不部署）

1. 再次 **Create rule** → **Cache Rule**，Rule name 填：`repo-mutable-metadata`。
2. Custom filter expression 粘贴：

   ```
   (http.host eq "repo.pigsty.io" and (
     http.request.uri.path contains "/dists/" or
     ends_with(http.request.uri.path, "/repomd.xml") or
     http.request.uri.path in {"/get" "/pig" "/pkg" "/beta" "/key"} or
     ends_with(http.request.uri.path, "/latest") or
     ends_with(http.request.uri.path, "/checksums")
   ))
   ```

   覆盖：apt 全部索引（dists/ 下 InRelease、Release、Packages、Packages.gz/.xz、Translation 等）、
   yum 索引入口 repomd.xml、安装脚本 /get /pig /pkg /beta、GPG 公钥 /key、版本指针 latest/checksums。

3. **缓存资格**：**符合缓存条件**。
4. **边缘 TTL**：选第三项 **忽略缓存控制标头，使用此 TTL**，时长填 **600 秒**（10 分钟）。
5. **状态代码 TTL**：同样加一条 **大于等于 400 → 60 秒**。
6. **浏览器 TTL**：选 **绕过缓存**（模板默认即此项；apt/dnf 自己管元数据过期，禁止客户端/中间代理再缓存一层）。
7. 其余设置保持默认（同 Rule 1 第 9 步）。
8. 放置顺序选 **最后**（规则列表里必须位于 `repo-cache-everything` 之下；同一请求命中多条规则时，靠后的规则覆盖靠前的设置——`repomd.xml` 等会同时命中两条，最终生效 10 分钟 TTL）。
9. 点 **部署 / Deploy**。

### 3.3 开启 Smart Tiered Cache（推荐，免费）

1. 左侧 **Caching → Tiered Cache**。
2. 打开 **Smart Tiered Cache**。

效果：全球边缘 MISS 时统一经由靠近 R2 bucket 的单一上层节点回源，
大幅减少 R2 读请求，并提高其余节点的命中率。R2 官方文档明确推荐此配置。

## 四、发布 SOP：先包体、后索引、再 purge

### 4.1 发布顺序

单趟 `rclone sync` 按字典序上传，`dists/`、`repodata/` 会先于部分包文件上传（顺序是反的）。
月度发布建议拆成两段，Makefile 示例：

```makefile
cf-apt-infra:
	rclone sync -P --transfers=8 apt/infra/pool/  $(CF)/apt/infra/pool/
	rclone sync -P --transfers=8 apt/infra/dists/ $(CF)/apt/infra/dists/

cf-yum-infra:
	rclone sync -P --transfers=8 --exclude 'repodata/**' yum/infra/ $(CF)/yum/infra/
	rclone sync -P --transfers=8 yum/infra/x86_64/repodata/  $(CF)/yum/infra/x86_64/repodata/
	rclone sync -P --transfers=8 yum/infra/aarch64/repodata/ $(CF)/yum/infra/aarch64/repodata/
```

### 4.2 创建 Purge 用 API Token（一次性）

1. Dashboard 右上角头像 → **My Profile → API Tokens → Create Token**。
2. 选 **Create Custom Token**：
    - Permissions：`Zone` / `Cache Purge` / `Purge`
    - Zone Resources：`Include` / `Specific zone` / `pigsty.io`
3. 保存 token。Zone ID 在 pigsty.io zone 的 **Overview** 页右侧栏可查。
4. 存入环境变量（如 `~/.bashrc` 或 CI secret）：

   ```bash
   export CF_ZONE_ID=<pigsty.io 的 Zone ID>
   export CF_PURGE_TOKEN=<刚创建的 token>
   ```

### 4.3 发布后全量失效

```makefile
cf-purge:
	curl -sX POST "https://api.cloudflare.com/client/v4/zones/$$CF_ZONE_ID/purge_cache" \
	  -H "Authorization: Bearer $$CF_PURGE_TOKEN" \
	  -H "Content-Type: application/json" \
	  --data '{"purge_everything":true}'
```

也可以在 Dashboard 手动操作：**Caching → Configuration → Purge Cache → Purge Everything**。

⚠️ **注意**：Purge Everything 清空的是**整个 pigsty.io zone** 的缓存（包括同 zone 其他子域名/站点），
不只是 repo.pigsty.io。按 hostname/前缀 purge 是 Enterprise 专属功能。月度一次、
其余站点冷启动几分钟即可回填，通常可接受；若想精准失效，可用按 URL purge
（免费，每次 30 条），元数据清单可从本地树生成：

```bash
{ find yum -name 'repomd.xml'; find apt -path '*/dists/*' -type f; } \
  | sed 's|^|https://repo.pigsty.io/|' > /tmp/purge-urls.txt
# 之后每 30 条一批 POST {"files":[...]} 到同一 purge_cache 接口
```

由于包文件名含版本号（内容不可变、新版本是新 URL），只 purge 元数据在正确性上
等价于全量 purge——被移除的旧包即使还在缓存中，也不会再被新索引引用。

## 五、部署后验证

发布规则后执行（注意用 GET，不要用 `curl -I`）：

```bash
check() { curl -s -o /dev/null -D - "$1" | grep -iE '^(HTTP/2|cf-cache-status|age|cache-control)'; }

# rpm/deb：第一次 MISS，第二次 HIT；浏览器 TTL bypass → 响应带 cache-control: no-store
check https://repo.pigsty.io/yum/infra/x86_64/asciinema-3.2.1-1.x86_64.rpm
check https://repo.pigsty.io/yum/infra/x86_64/asciinema-3.2.1-1.x86_64.rpm

# 元数据与无扩展名文件同样 MISS→HIT（单规则方案下 age 可长达一个月，直到发布 purge）
check https://repo.pigsty.io/yum/infra/x86_64/repodata/repomd.xml
check https://repo.pigsty.io/apt/infra/dists/generic/InRelease
check https://repo.pigsty.io/get
```

purge 后重测应回到 MISS 再变 HIT。

> ✅ 2026-07-11 实测：以上全部通过——rpm/deb/get MISS→HIT（age=1），repomd.xml/InRelease HIT，
> 所有响应携带 `cache-control: no-store`（浏览器 TTL bypass 生效）。

## 六、已知限制与注意事项

1. **单文件 512 MB 缓存上限**（Free/Pro/Business）。当前 bucket 超限文件仅 3 个，
   均为 percona debuginfo 包，会始终直穿 R2（功能正常，仅无加速）：
    - `yum/percona/el8.x86_64/llvm-debuginfo-16.0.6-3.el8.x86_64.rpm`（810 MB）
    - `yum/percona/el8.x86_64/llvm-libs-debuginfo-16.0.6-3.el8.x86_64.rpm`（785 MB）
    - `yum/percona/el9.x86_64/llvm-static-16.0.6-4.el9.x86_64.rpm`（606 MB）
2. **HEAD 请求永远显示 DYNAMIC**，这是 Cloudflare 行为，不代表未缓存。
3. zone 级 Browser Cache TTL（当前 30 分钟）对命中上述规则的请求不再生效（规则内设置优先）。
4. bucket 卫生：`apt/*/db/`、`apt/*/conf/`、`apt/*/stash/` 是 reprepro 内部目录，
   被整树 sync 上传到了公开 bucket（含 Berkeley DB 与重复的 deb）。建议后续在
   rclone sync 中 `--exclude 'db/**' --exclude 'conf/**' --exclude 'stash/**'`。
5. R2 egress 免费，本方案的收益不在省钱，而在：全球边缘命中的延迟/吞吐、
   发布一致性（元数据短 TTL + purge）、以及对 R2 偶发故障的韧性（命中期间边缘可继续服务）。
6. 中国大陆访问：Cloudflare 免费/Pro 计划在大陆无节点，大陆用户命中境外边缘
   （HKG/NRT/LAX 等），瓶颈在跨境链路而非 R2。缓存能改善 TTFB 与稳定性，
   但几 MB/s 的跨境吞吐量级不会质变——大陆加速的正解是 repo.pigsty.cc（COS + 腾讯 CDN）。













交付物

- 主报告：~/pgsty/pigsty-pro-repo-design-20260710.md（545 行，含实测数据表、四个决策的方案对比、快照/通道设计、Worker 代码、成本表、风险清单、四阶段排期）
- 调研存档：同目录 pigsty-pro-repo-survey-auth-20260710.md（12 家厂商认证机制）与 pigsty-pro-repo-survey-infra-20260710.md（CF/EdgeOne/ICP/PGDG 政策）
- 三个文件都放在 ~/pgsty/ 下（不在任何 git 仓库内，避免被自动提交卷进主分支）

四个决策的结论

1. PGDG 镜像：做，快照式 verbatim 镜像（保 PGDG 原签名）。 实测全量 114 GB、企业口径 67 GB、免费口径 16–20 GB——存储成本无关紧要，重点是同步自动化。建议全球+中国社区侧 v5.0 都默认切自家镜像（我最初倾向中国保持阿里云，但调研翻出了阿里云 2025-05 断档缺 CVE 版本的事故和冻结的 sync_timestamp，改变了判断——你的直觉是对的，现在有数据了）。
2. 域名：pro.pigsty.io / pro.pigsty.cc 子域 + 独立 bucket。 子域免 ICP 备案，新顶级域要 15–20 个工作日、直接威胁 9–10 月排期；.io 后缀根本不能备案。仓库树 = 不可变 snapshot/<id>/ + stable/rolling 通道指针，"慢通道"和"版本锁定"两条产品承诺由布局自带。
3. Token：token-in-path（EDB 就是这么做的——它是 Cloudsmith 白牌）。 我用真实 Rocky9/Debian12 容器把 dnf/apt 端到端跑通了，包括过期订阅 403 续费提示；踩出一个实坑：apt 把 ~ 编码成 %7e，Worker 必须先 decode 再查 R2 key。国内落地用 EdgeOne 边缘函数 + KV——腾讯"远程鉴权"对新账号已封存，不能作为规划依赖。
4. 托管：双云双 bucket + rclone 晋升流水线，不引入 aptly/Pulp。 总成本约 $75–135/月，一个订阅客户的月费就能覆盖。

与任务假设不符/超出的事实（报告 §1 有完整对照表）

- 签名旁路不止 apt：rpm 侧同样 gpgcheck=0（pkg.yml:52）
- repo.pigsty.io 目前 Cloudflare 零缓存（.rpm/.deb/.xml 不在默认缓存扩展名单里），全球用户实际没享受到 CDN 加速——一条 Cache Rule 可修
- repo.pigsty.cc 上的 PGDG 死镜像还在线上（冻结 2025-12，新布局 404）
- PG13 已被 PGDG 整体 410 下架、rsync 通道 2025-05 永久关停——企业版价值主张的两个最硬实证

遗留的开放问题（需要你拍板）

腾讯账号是否在"远程鉴权"存量白名单（影响国内备选路径）；u20/d11 的自建包历史从哪回填（PGDG 侧归档没问题，pigsty 自建扩展的老平台版本只存在于历史 release）；rpm 构建链开 debuginfo 是排期上唯一有分量的工程项。

※ recap: 企业仓库（Pro Repo）改造调研已完成，报告与两份调研存档已写入 ~/pgsty/pigsty-pro-rep件。下一步：请你审阅报告并对遗留开放问题（如 u20/d11 自建包回填）拍板。 (disable recaps in
