# SOW V1 → V2 P0–P3 资产清单

日期：2026-08-01
方法：只读源码审计；没有把 V1 测试结果计入 V2 完成证据。

## Reuse：通过窄适配复用

| 资产 | 当前证据 | V2 复用边界 |
| --- | --- | --- |
| DEB 包头、control 与 SHA-256 | `internal/aptrepo/package.go` 的 `InspectPackage*` | 只返回不可变 package facts；补 upstream version helper，不读取 Workspace |
| Debian version | `pault.ag/go/debian/version` 与 `aptrepo` 排序 | 封装 compare/upstream split，覆盖 epoch/revision 与 `3.0.4+foo` |
| APT Packages 编码 | `internal/aptrepo/packages.go` | location 由 V2 renderer 显式注入；P0 为 `./basename` |
| RPM 包头与 SHA-256 | `internal/yumrepo/rpm.go` 的 `InspectPackage*` | 只返回 NEVRA/source/arch/content facts；不采用 V1 placement |
| RPM EVR | patched `third_party/cavaliergopher-rpm` | 提取 compare 接口；不导入 Git/CAS catalog |
| rpm-md XML/压缩 | `internal/yumrepo/xml.go`、generation helpers | location 与 compression 改为显式 V2 输入；Plain 与 Managed 的空/非空 view 共用确定性 renderer |
| RPM signature inspection/neutral digest | `internal/yumrepo/rpm_signature.go` | Plain P0 补签/重签；Managed P2 验证、`never/fill/always`、同 payload 重试与 exact certificate snapshot |
| APT/YUM metadata signing | `internal/aptrepo/sign.go`、`internal/yumrepo/sign.go` | Managed P3 构建时激活；RPM 签 `repomd.xml`，APT 签 `Release`，Built state 保留精确公钥身份供只读校验 |
| metadata validation | APT build closure 与 `internal/yumrepo/validate.go` | 分离 Plain flat、Managed architecture view 与 Built Generation 的验证入口 |
| 安全文件原语 | `internal/manifest/atomic.go`、repository/state 的 path/lock 技法 | 提取 SHA、stable sort、temp、fsync、rename、root-bound、flock；不带产品模型 |

## Replace：整体替换

| V1 资产 | 原因 | V2 替代 |
| --- | --- | --- |
| `internal/cli` dispatcher/help/errors | 暴露 Git/CAS/remote/V1 exit codes，且同 package 编译全部 provider 路径 | 独立 `internal/v2cli` 封闭 P0–P3 command tree 与 0–6 error map |
| `internal/config` schema | 固定 `sow.yaml`/`sow/v1`、views/targets/remote | strict `sow.yml`/`sow/v2` Workspace config |
| `internal/state` | embedded Git refs/transactions 是正典 | 每 Repository SQLite + application Operation Journal |
| `internal/catalog` | SQLite 是 Git/CAS 派生查询 cache | authoritative per-repo schema v6：Desired/Built、Operation、Generation、Changeset 与签名证据 |
| `internal/repository` | `.pool/sha256` CAS/materialize/GC 所有权不符 | Repository-owned `pool/`、Dist Membership 与 C2 view-local hardlink alias |
| APT/YUM `Generate` 公共入口 | 强制 signer、V1 layout/EL 策略、进程内 rollback | V2 caller-owned location + optional signer + durable journal/Generation + pointer-last |
| V1 lock wrapper | 立即失败且耦合 V1 state/process record | timeout/no-wait POSIX lock port |

## Remove：不得进入 V2 活动依赖图

- `internal/publish`：AWS/S3、Cloudflare、Tencent、remote saga/checkpoint。
- `internal/syncer`、`internal/upstream`：远端发现、下载、provenance。
- `internal/views`：View/Snapshot/channel/freeze。
- `internal/serving`：route、Nginx、remote generation pointer。
- V1 `internal/state` Git、`internal/repository` CAS、`internal/catalog` Git-derived state。
- V1 `fsck/sync/publish/gc/verify/promote/materialize/compatibility` 命令。
- V1 `add/rm`；活动二进制使用独立的 V2 Membership `add/rm`，不复用 V1 Git/CAS 语义。
- modulemd、route、manifest、rejected、provider、edge、CDN、remote endpoint。

历史源码与 ADR 可暂留供追溯，但 `cmd/sow` 不得导入 V1 CLI，help 不得注册任何上述命令。

## 审计发现与当前处置

1. `aptrepo.Package` 保留 Debian PoolPath 事实；V2 用 `WriteFlatPackages` 窄适配在编码边界强制 `./basename`，并在写 paragraph 前重新哈希 source bytes。
2. V1 YUM 生成器固定 `Packages/<bucket>/...`；V2 `GenerateFlatUnsigned` 从已解析 `PackageInput` 导出安全 basename location，不继承 V1 placement。
3. 原始 `../../../pool/...` location 候选虽可被 DNF 消费，但 reposync 会拒绝逃出 per-repository download root 的本地落点；活动实现采用 root Pool + view-local regular hardlink + `pool/...` href 的 C2 设计，native 与 neutral 非空投影均由 P2/P3 build 激活。
4. V1 APT/YUM 生成器把 metadata signer 设为必填；V2 renderer 接受显式可选 signer。Plain P0 只签 RPM 包；Managed P2/P3 支持 RPM package policy、RPM metadata 与 DEB metadata 签名，并把 Desired key reference 和 Built public verifier identity 分离。
5. YUM compression 与 EL8/9/10 历史策略绑定，不能作为 P0 或通用空 Dist 的隐式必填产品语义。
6. V1 提交逻辑主要处理进程内错误；V2 Plain 因此重新实现 version 5 `Inputs + Actions(prior ownership/mode) + Dirs + Next + signing authorization` durable journal 和跨 RPM/DEB/签名包替换的单一 Operation：进程终止 forward replay，普通持久失败恢复同文件系统 file/directory/package pre-image 后才返回错误；公开新代已完整提交时只重试私有 cleanup。
7. V1 重复检查不等价于 V2 坐标契约；V2 scan 将 RPM NEVRA 或 DEB package/version/architecture 映射到 SHA-256，只有同坐标不同内容硬拒绝，相同内容重复只渲染一个逻辑条目。

## 活动依赖目标

V2 活动功能的核心依赖目标：patched RPM parser、Debian parser/version、OpenPGP、YAML v3、modernc SQLite、x/sys 与 compression。普通未签名路径仍是单一 Go 二进制；Plain RPM signing 与 Managed 的 GPG-agent/RPM package signing reference 会调用本机 `rpm`/`gpg`，file/env metadata private keys 可走进程内 signer。AWS/S3/Smithy、Cloudflare、Tencent、go-git/go-billy 不得由 `cmd/sow` V2 入口引入；最终活动构建图仍以当前 checkout 的依赖审计为证据。
