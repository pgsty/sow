# 2026-07-20 不可达旧路径与静态分析闭合

状态：本地源码、协议、迁移与交付门禁通过；未访问或写入任何云资源。

## 实现结果

- `staticcheck -checks=U1000 ./...` 首轮报告 42 个不可达声明。
- 删除旧 DEB/RPM wrapper、旧 archive/materialize wrapper、旧非 session Nginx wrapper、
  已被 active-state gate 取代的 YUM compatibility helper，以及整份不可达旧 compatibility
  auditor；最终补丁删除 768 行旧代码（写入本证据前统计）。
- `staticcheck.conf` 只豁免 `ST1000/ST1003/ST1005/ST1020` 展示约定；`U1000` 与全部
  正确性检查仍启用，最终 `staticcheck ./...` 退出 0。
- clean-delivery 高置信秘密扫描发现新 Cloudflare fixture 的字段形状像真实 secret；测试值
  改为 `fixture-*` / `replace-with-*` 哨兵，没有放宽扫描器。

## 测试证据

六个 CLI ordinary shard 全过：

| shard | elapsed |
| --- | ---: |
| `A-F` | 332.395s |
| `G-M` | 477.037s |
| `N-O` | 159.378s |
| `P-Q` | 585.390s |
| `R-V` | 338.581s |
| `W-Z/other` | 130.917s |

六个 CLI race shard 全过且无 race report：381.383s、570.275s、158.809s、
750.366s、373.283s、159.205s。非 CLI 全包 ordinary/race、nested RPM module test/vet、
`go vet ./...`、`staticcheck ./...` 与 `git diff --check` 全部退出 0。

Edge bundle 重建后无 diff，47/47 共享合同通过。darwin/linux × amd64/arm64 的
`CGO_ENABLED=0` 静态构建全部通过。七套迁移/回滚门禁全部通过，其中 44 个操作族、
33-selector adoption、YUM 双架构 compatibility state machine、28 个 Pigsty consumer
定义与 writer-fence 正负例均实跑。

干净交付第一次在隔离空 `GOMODCACHE` 下载依赖时遇到 `proxy.golang.org` 网络超时；改用
本机已验证模块缓存的 `file://.../cache/download` Go proxy 后，从空模块缓存完成 tidy、
download、verify、构建、测试和双份确定性归档。加入本 spec/evidence 与最终 allowlist 后
再次重跑通过，最终稳定 product identity 为：

- product: 546 files, SHA-256 `eaa6bdd51b965a83ca1831a1ec60fbcc128706d2fd3065733d869d44e3866fde`
- delivery: 724 files；双份 archive byte-identical。delivery/archive digest 不写回其自身
  收录的证据文件，避免用一次必然改变摘要的自引用编辑伪造“最终身份”。

这关闭本地静态/交付门禁，不提升真实 Cloudflare、COS/EdgeOne、生产迁移或运行指标状态。
