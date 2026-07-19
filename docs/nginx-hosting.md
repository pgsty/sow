# Nginx 直接托管

SOW 的服务树可由静态 Nginx 直接托管，但路由正典来自 `sow.yaml` 与已确认的本地发布
状态，不是手写配置。唯一受支持的仓库路由入口是 `sow materialize ...
--nginx-include` 生成的 server-context include。

## 生成与启用

先物化视图，再生成同一物理树的 include：

```bash
sow materialize latest --config /etc/sow/sow.yaml
sow materialize latest --config /etc/sow/sow.yaml \
  --nginx-include /etc/nginx/sow-latest.locations.conf

sow materialize stable --config /etc/sow/sow.yaml
sow materialize stable --config /etc/sow/sow.yaml \
  --nginx-include /etc/nginx/sow-stable.locations.conf \
  --nginx-auth-user-file /etc/nginx/sow.htpasswd

nginx -t
```

生成模式是只读的：它不运行 materialize 写事务、不创建 manifest/ref/CAS、不改服务树；
为证明 compatibility closure 一致性，验证阶段可以短暂获取本地 state lock。
`--nginx-include -` 将可复现正文写到 stdout；绝对文件路径则在解析真实父目录、
排除仓库/服务树/config 重叠后，以 `0644` 临时文件、`fsync` 和同目录 `renameat`
原子替换。父目录或目标在写入期间被 symlink/目录交换会失败关闭。输出路径必须在仓库与
服务树之外。

在自己的 TLS `server` 中只 include 生成文件；不要再设置仓库 `root`、`try_files` 或
更宽的 location：

```nginx
server {
    listen 443 ssl;
    server_name repo.example.com;
    ssl_certificate /etc/nginx/tls/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/private.key;

    include /etc/nginx/sow-latest.locations.conf;
}
```

SOW 不管理证书、Nginx 进程或 reload。只有 `nginx -t` 成功后，才按站点既有的原子
reload 流程启用新文件；失败时保留上一个已加载配置。

## 路由不变量

生成器只投影当前选择集拥有的表面：

- APT 与 ordinary YUM 的精确物理 leaf；
- asset 的精确 root key 或独立 child prefix，`/pkg` 不隐含拥有 `/pkg/`；
- YUM 的精确 mirrorlist、20 位 generation 与 literal repo root；
- 已确认 cutover 的 frozen cross-EL compatibility raw/mirror/generation 闭包；
- 选中包仓库的 repository public key，以及每个 distinct RPM package keyring。

每个 owned location 都只允许 GET/HEAD，启用 `disable_symlinks on`；generation tail
逐 segment 限定并拒绝 `.`/`..`，repo path 中的点按正则 literal 转义。结尾固定为
`location / { return 404; }`。生成器从不创建泛化 `/apt/`、`/yum/`、`/_sow/`、
`/.sow/`、`/.pool/` 或仓库根 fallback，因此控制文件和邻接 canary 即使真实存在也不可达。

latest compatibility 路由必须来自 canonical witness、dedicated immutable cross-EL ref 与
完成的 cutover/generation ledger 的 sealed 只读证明；candidate、adoption staging、temp
或证据不完整的 projection 不会被静默猜测为可服务。生产完整 include 建议不带 selector；
若 selector 或显式 `--target` 不能容纳完整 compatibility closure，命令失败而不是输出半个
allowlist。

## Basic Auth 回退

stable 的 standalone fallback 固定在 `/pro/v1/basic/`，且必须提供一个仓库与服务树之外、
已存在的 regular non-symlink htpasswd 文件：

```bash
sow materialize stable --config /etc/sow/sow.yaml \
  --nginx-include /etc/nginx/sow-stable.locations.conf \
  --nginx-auth-user-file /etc/nginx/sow.htpasswd
```

生成器把 Basic Auth 和 `Cache-Control: private, no-store` 放在每个 owned location 上；没有
匿名 alias。该 standalone origin 不得接入一个忽略 Authorization 的共享缓存键，否则已
认证响应可能被匿名复用。只有 Worker/EdgeOne/WAF 在 cache lookup 前完成认证、剥离凭据并
发起 clean subrequest 时，才可使用共享 clean-URL 缓存；这不属于 Basic fallback 的能力。

参考 server 外壳见 [edge/basic/nginx.conf.example](../edge/basic/nginx.conf.example)。

## 验证与排障

```bash
# 确定性审阅
sow materialize latest --config /etc/sow/sow.yaml --nginx-include - > /tmp/latest.conf
cmp /tmp/latest.conf /etc/nginx/sow-latest.locations.conf

# 配置解析及回环协议测试
nginx -t
SOW_COMPAT_NGINX=1 go test -count=1 ./test/compat \
  -run '^TestProductGeneratedNginxIncludeLoopbackContract$'
```

测试只启动 `127.0.0.1` Nginx，覆盖 GET/HEAD、POST 拒绝、公开与 Basic、普通/兼容 YUM
raw/mirror/generation、两个 trust bundle、plain/encoded traversal、symlink file/dir 逃逸、
点号路径 literal 与 exact asset 边界；不访问任何对象存储、CDN 或外网。
