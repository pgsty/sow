# Package repository 历史连续性门禁证据（2026-07-14）

## 范围与安全边界

本轮只使用 `t.TempDir()` 下的 embedded Git、文件系统 CAS 和本地 CLI。命令执行时清空
AWS/Cloudflare/Tencent 相关凭据，设置黑洞代理并使用 `GOPROXY=off`；没有网络、对象存储、
CDN 或生产资源访问。尤其没有、也不允许使用 CO/COS/Cloudflare 生产仓库做测试。

实现入口：

- `internal/cli/package_repository_contract.go`
- `internal/cli/package_repository_contract_test.go`
- `internal/cli/app.go` 的 load/stage/lock-held baseline gate
- `internal/cli/gc.go` 的 lock-held pre-CAS/pre-delete gate
- sync internal add/repair/recovery/provenance 的持锁 gate

## 覆盖结果

focused ordinary：

```text
$ go test -count=1 ./internal/cli -run 'PackageRepository|GCRejectsRestoredHistoricalPackage'
ok github.com/pgsty/sow/internal/cli 3.421s
```

focused race：

```text
$ go test -race -count=1 ./internal/cli -run 'PackageRepository|GCRejectsRestoredHistoricalPackage'
ok github.com/pgsty/sow/internal/cli 12.075s
```

覆盖的正负边界包括：

- 冻结 ID/type/path/default pool/include/exclude/OS、APT leaf mapping、YUM noarch/compression
  和 cf/cos target affinity；显式拒绝 APT/YUM -> asset；
- `active: true` 与省略等价，`false` 拒绝；OS/APT suite 只允许 active -> frozen；
- package keyring rotation 与 upstream allow/deny 仍允许；相邻既有 trust-closure tests 通过；
- manifest/view/snapshot/YUM generation 四类非空 ownership；空 manifest 不冻结；
- matching-HEAD 历史漂移、clock-independent parent DAG、HEAD + 全部 `refs/sow/*` 并集、
  off-HEAD 漂移/缺 config/坏 ref；
- delete/reintroduce、同 root 换 ID，以及 root 瞬时转给新 ID 后新 ID 再消失；
- load preflight、锁内 mutation revalidation、GC 已确认 orphan 在门禁失败时字节与 HEAD 均不变。

相邻 asset/YUM/trust 回归：

```text
$ go test -count=1 ./internal/cli -run 'PackageRepository|AssetProjection|YUMCompatibility|SyncSelectionBindsInPlaceUpstreamAndPackageKeyringRotation|MaterializationTrustSnapshotRejectsParallelMixedYUMKeyrings|PublicationTrustRejectsRPMKeyringAtomicReplacementDuringSagaAndRecovers'
ok github.com/pgsty/sow/internal/cli 7.824s
```

## 流式内存证据

测试提交一个 32 MiB 非法正文（只作为 Git blob ownership identity）并扩展 6 个历史 commit；
门禁不得解析或载入该 manifest：

```text
$ go test -v -count=1 ./internal/cli -run '^TestPackageRepositoryContractAuditDoesNotInflateLargeManifest$'
package history audit allocated=856616 manifest=33554432
--- PASS: TestPackageRepositoryContractAuditDoesNotInflateLargeManifest (0.62s)
ok github.com/pgsty/sow/internal/cli 1.246s
```

本次分配约 0.82 MiB，低于测试固定的 manifest/2（16 MiB）上限。它证明该测试历史上的
identity-only 行为，不外推为 50k 包吞吐或任意 commit 数的性能上限。

## 未声称事项

- 本报告不是完整 `go test ./...`、真 apt/dnf 或四平台构建的新基线；这些仍由各自证据项管理。
- 没有真 R2/COS、Cloudflare/EdgeOne、生产 URL、生产 bucket、真实迁移或 purge 运行。
- package keyring 可 rotation 不等于绕过 RPM trust；其密码学/恢复闭包仍由 ADR-0017 与既有
  trust tests 承担。
