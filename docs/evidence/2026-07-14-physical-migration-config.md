# 完整旧物理迁移配置闭环证据 — 2026-07-14

> 2026-07-19 update: the current contract is again 98 repo IDs / 135 ledger
> rows, but it is not the original discovery composition. The active gated Pro
> owner remains; one dedicated EL9 compatibility policy owner and exact
> aarch64/x86_64 projections were added under ADR-0021. The inactive carrier
> and policy-only owner are excluded from ordinary groups. The legacy empty
> `pro/checksums` row now binds its exact empty SHA directly. See the dated
> migration review-hardening report for current tests and boundaries.
>
> 2026-07-17 update: the current contract is 97 repo IDs / 134 ledger rows.
> Gated Pro, COS-only ROOT and shared ROOT canonical owners have completed
> separate local handoffs and are active with exact target affinity. The
> original 98/135 discovery stages below are retained as historical evidence,
> not current counts. See the dated 2026-07-17 ROOT/Pro evidence reports.

## 结论

`docs/migration/fixtures/pigsty-v1.yaml` 已从 12-repo 局部 parser 夹具升级为无秘密、
schema-valid 的完整本地物理迁移合同；旧夹具保留为 `pigsty-v1-synthetic.yaml`，不再允许
冒充完整迁移证据。生产 config decoder 与独立 machine ledger 的双向集合门禁当前精确闭合：

| 范围 | 精确结果 |
|---|---:|
| config repo ID | 98（11 APT + 74 YUM template + 13 asset） |
| migration ledger row | 135 |
| APT `suite × component × arch` index | 74 |
| ordinary YUM repodata leaf | 130 |
| nested PGDG child | 1，`quarantine-overlap` |
| 根级 exact key | 7 |
| 根级 prefix | 8 |
| gated pro file | 16 |

这是配置、盘点和处置的结构闭环；本报告自身不是 full-tree adoption、真实
signer/lifecycle、Nginx、apt/dnf、对象存储、CDN 或生产迁移通过声明。后续完整树副本
M0、可证明子集 adoption 与源数据 fail-closed 结果见
[2026-07-16 evidence](2026-07-16-legacy-tree-full-adoption-copy.md)。

## 实现合同

- APT ledger 对 27 个 suite 分别冻结 exact component set 与
  `active|frozen-policy-unverified`；展开后必须与 74 个物理 `Packages` leaf 双向相等。PGDG
  stable suite 只有 `main`，testing suite 为 `main,18,19`，不会生成不存在的笛卡尔 index。
- 74 个 YUM path template 展开后必须与 130 个 ordinary repodata leaf 双向相等。Percona
  EL8/9/10 都声明 `noarch_mode: separate`，并各自包含独立 `noarch` leaf。
- 两个 `yum/infra/{arch}` leaf 仅由 `active:false` 的
  `yum-infra-legacy-compat` inventory carrier 表达；ledger 固定
  `quarantine-compat/cross-el-unresolved/targets=none`。它不属于任何 repo group，不进入
  upstream；CLI 明确选择和默认选择均排除它，effective ref/view/publish/upstream unit 均为 0。
- nested `yum/pgdg/17/.../rhel-10.0-aarch64` 不存在于 config repo set，ledger 固定
  `quarantine-overlap`；父 `yum-pgdg-17-el10` 显式 exclude 该子树，禁止父子重叠纳管。
- 根级 `/beta,/get,/pig,/pkg` 绑定双目标 asset owner；初始 ledger 保持
  `external-builder-convergence`，2026-07-17 经 canonical builder/SOW handoff 后已推进为
  `adopted-latest-local-cutover-pending`，且仍不把原 `.io/.cc` bytes 伪装为等价；
  `/cc,/claude,/ray` 与 `/img/`,`/pkg/claude/`,`/pkg/ray/` 保持 COS-only affinity。
- 16 个 `pro/` 文件只按路径/size inventory 映射到 gated rebase owner，正文仍未读取，状态
  `gated-rebase-review-required/content-not-read`。
- 2026-07-15 增补两个 inactive asset inventory carrier：`bin/` 排除 `fileauth.txt`，`pro/`
  保持 gated pool。它们只允许 M0 与 local fsck 读取/校验旧字节，不能 generic-adopt、进入
  view/publish/remote fsck/edge；canonical root/gated owners 在 builder/rebase 审核前保持 inactive。
- fixture 的 `targets` 为空，不含 endpoint、credential、entitlement、private key 或 token。

## 信任与生命周期非声明

只读 physical inventory 无法证明真实业务 lifecycle 或 signer。ledger 因而只允许闭合枚举：

- APT：`release-signature-not-inventory`；
- YUM metadata：`metadata-not-claimed`；
- RPM payload：`payload-keyring-unverified`；
- lifecycle：`active|frozen-policy-unverified`，infra 为 `cross-el-unresolved`；
- gated pro：`stable-gated-policy-unverified/content-not-read`。

任何把这些值改成无依据的 `verified`、解除 quarantine、把 Percona 改回 replicate、让 infra
进入 group，或改变 root target affinity 的突变都会非零失败。

## 可复现验证

从 SOW 根目录执行：

```sh
docs/migration/test-physical-migration-config.sh
SOW_PHYSICAL_MIGRATION_RACE=1 docs/migration/test-physical-migration-config.sh
```

首条脚本会清空 AWS/Cloudflare/Tencent 凭据与全部 real-cloud/upstream opt-in，把外部代理指向
loopback blackhole，并运行一个正例与 8 个 fail-closed 负例：12-repo synthetic、33/73
selector synthetic、缺 APT index、伪造 lifecycle、解除 nested quarantine、Percona noarch
replicate、infra 进入 group、root target drift。全部只读 checked-in fixture 或临时副本。

`SOW_PHYSICAL_MIGRATION_RACE=1` 复用完全相同的凭据清理、黑洞代理和本地 fixture 边界，
只是为全部 Go 门禁加入 race detector。

2026-07-14 原 96/133 合同的 ordinary 与 race hermetic suite 均退出 0。2026-07-15 扩展为
98/135 后，ordinary hermetic suite 再次退出 0；config 正例输出
`apt_indices=74 yum_ordinary=130 yum_nested_quarantine=1 root_keys=7 prefixes=8 gated_pro=16`；
8 个负例及 inactive carrier CLI gate 全部 PASS。全过程未读取/写入/探测任何 CO/COS/CF
生产仓库，也未访问任何网络资源。

## 仍未闭合

1. `yum/infra/{arch}` 的真实跨 EL compatibility projection、ref/selector/restore 语义及消费者
   迁移尚待独立 ADR 和 source-commit 证据，当前 carrier 不得被启用。
2. 真实 RPM signer inventory/public-only keyring、APT Release signer 与业务 lifecycle 仍需审核；
   fixture 中的 `migration-unverified-*` 路径故意不可作为信任通过证据。
3. `.io/.cc` 根脚本与 16 个 gated Pro 文件的本地 builder/adoption 已由 2026-07-17
   证据关闭；真实安全迁移、公开 URL 与 stable/gated 双云回归仍待执行。
4. 后续完整旧树副本已完成 M0/full local fsck 与可证明 APT/YUM/asset 子集 adoption，
   但 `apt-infra` orphan 和 PGDG YUM missing bodies 尚未由 owner 修复；materialize/cutover、
   真实 Nginx/apt/dnf 迁移消费与独立 non-production 云资源验证仍未执行。生产
   CO/COS/CF 资源永久禁止用于测试。
