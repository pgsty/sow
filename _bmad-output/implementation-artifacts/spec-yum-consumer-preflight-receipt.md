---
status: done
tracking_id: V-27
baseline_commit: ecb5ee136401e09bc080ae6abcd05ae3c7bd4edf
---

# V-27: Pigsty YUM consumer preflight receipt

## Problem

The existing Pigsty migration script could atomically stage, apply, replay and
roll back 28 reviewed YUM definitions, but `apply` trusted an operator reminder
to publish and inspect every mirrorlist and trust URL. It also mapped the
architecture-independent `pigsty-infra` definition to a nonexistent
release-specific repository instead of the two frozen cross-EL projections.
That left a hidden manual release step at the exact boundary intended to retire
raw `baseurl=` consumers.

## Frozen contract

- Consumer map schema v2 carries an exact `repo/os/arch` route per architecture.
  Infra maps to `infra-legacy-x86-64/cross-el/x86_64` and
  `infra-legacy-aarch64/cross-el/aarch64`; ordinary routes retain only the
  explicit `$releasever` substitution.
- The renderer selects `repo.mirrorlist[region][os_arch]`; a reviewed scalar
  mirrorlist and the old baseurl remain fallback-compatible, but mapped v2
  definitions must use the architecture mapping.
- The executable outer `release/module/arch` selector is part of the renderer
  contract. The four canonical names retain their frozen Pigsty modules;
  descriptions must be single-line safe scalars and `meta` cannot override
  route, trust, enablement or TLS policy.
- `sow compatibility yum-consumer-preflight` reads public endpoints only. It
  verifies staged hashes and all expanded definition/release/architecture/
  region bindings, current canonical publication and aggregate inventory,
  exact public trust bytes, one generation-pinned mirrorlist, signed repomd,
  primary/filelists/other and a cryptographically verified RPM per endpoint.
- The aggregate `pkg/keys/rpm-trust.asc` is a public asset, not a second SOW
  signing identity. It must contain every metadata and RPM signer primary key
  required by the staged routes, be present in the target's current aggregate
  inventory, and match the reviewed local file byte-for-byte through the CDN.
- A canonical JSON receipt binds the stage/map/inventory/config/trust digests,
  expanded bindings, intent generation/checkpoint/plan, aggregate generation/
  checkpoint/plan and protocol evidence. It is installed with no-replace
  semantics, is valid for at most one hour, and defaults to fifteen minutes.
- One canonical UTC instant governs metadata/RPM verification and receipt
  validity. The command refuses issuance if probing outlives that window, and
  binds repository, stage and receipt-parent directory identities against
  same-path inode replacement.
- `sow compatibility yum-consumer-receipt-check` performs no network request.
  It re-derives all local and canonical authority and rejects expiry, replay
  against drifted input, missing evidence or changed publication state.
- Migration `apply` invokes receipt-check before it creates its evidence
  directory, copies a backup, or changes a Pigsty byte, then repeats the
  network-free check immediately before the first source write. Both checks
  must name the same receipt. Failure is closed and the accepted preflight
  receipt SHA-256 is retained in the apply receipt.
- Shell evidence handling independently rejects unsafe manifest traversal,
  symlinked or checkout-containing plan/evidence directories, and never writes
  through provisional fixed-name temporary links.

## Safety boundary

The implementation does not write any cloud resource. Tests use an injected
loopback provider protocol and a copied Pigsty tree. CO/COS and Cloudflare
production repositories remain read-only and forbidden test targets. A real
production consumer cutover and dual-origin/real-client acceptance remain open
evidence, so this story does not resolve the overall migration blocker.

## Tasks & Acceptance

- [x] Replace the invalid infra route with explicit frozen cross-EL routes per
  architecture and make the staged renderer architecture-aware.
- [x] Implement online preflight over canonical publication state, aggregate
  trust, signed RPM-MD metadata and a real RPM payload.
- [x] Implement a short-lived, canonical, no-replace receipt and an entirely
  offline receipt-check gate before any Pigsty mutation.
- [x] Revalidate every local input after network probing and accept historical
  RPM signing-key binding records without weakening aggregate trust checks.
- [x] Bind the managed aggregate object identity, use its exact certificates
  for both metadata/RPM probes, recheck remote pointers at issuance, and
  archive the accepted receipt before any recoverable source mutation.
- [x] Complete negative, race, shell, full-suite, static and applicable DNF
  compatibility verification; record exact evidence and finish review.

Acceptance criteria:

- Given a reviewed v2 stage and matching current publication, when preflight
  succeeds, then its receipt binds every local input and every canonical target
  and aggregate generation used by all expanded endpoint probes.
- Given any input, trust byte, target state, receipt time or endpoint evidence
  drift, when preflight or receipt-check runs, then it fails before Pigsty is
  mutated and cannot replace an existing receipt.
- Given an RPM package keyring retaining historical binding renewals, when its
  current primary signing identity is included in the reviewed aggregate
  bundle, then preflight accepts the history while still rejecting private,
  malformed or missing public trust.

## Acceptance evidence

- `go test ./internal/cli -run 'TestYUMConsumer' -count=1`
- `go test -race ./internal/cli ./internal/yumrepo -run 'TestYUMConsumer|TestParseRPMPackageKeyringPreservesHistoricalSigningSubkeyBindings' -count=1`
- `go test ./internal/yumrepo -run 'TestOpenPGPVerifierSelectsExactAggregateCertificate' -count=1`
- `docs/migration/test-migrate-pigsty-yum-consumers.sh`
- `go vet ./...`
- `go test ./internal/cli -timeout 25m -count=1` (688 tests, 1170.620s)
- all non-CLI packages through `go list ./... | ... | xargs go test`
- real local Nginx/Docker APT 1.2 and EL7/8/9/10 YUM/DNF matrix

The Go integration publishes a real signed RPM repository and public trust
asset through the provider protocol fixture, consumes the resulting beta
mirrorlist through the full RPM-MD chain, and proves receipt-check succeeds
with an HTTP transport that rejects every request. Negative cases cover remote
trust/inventory/pointer drift, config keyring drift, reviewed-map drift,
expiry, no-replace receipt install, comment-only renderer checks, failed
outer-selector/module/description/YAML-tag drift, first- and second-gate
failure before Pigsty mutation, unsafe plan containment, foreign drift and
mixed-state recovery.

## Suggested Review Order

**协议门禁**

- 从唯一在线入口理解锁、探测、闭包复核与 no-replace receipt。
  [`yum_consumer_preflight.go:221`](../../internal/cli/yum_consumer_preflight.go#L221)

- 从 canonical state 推导 target、generation、aggregate trust 与 endpoint。
  [`yum_consumer_preflight.go:1266`](../../internal/cli/yum_consumer_preflight.go#L1266)

- 并发执行真实 mirrorlist、RPM-MD、RPM 签名客户端链。
  [`yum_consumer_preflight.go:1849`](../../internal/cli/yum_consumer_preflight.go#L1849)

- 离线重推全部 authority，阻断过期或跨状态重放。
  [`yum_consumer_preflight.go:2014`](../../internal/cli/yum_consumer_preflight.go#L2014)

**Renderer 与输入闭包**

- 精确冻结外层 selector 和完整 RPM Jinja 控制流。
  [`yum_consumer_preflight.go:1038`](../../internal/cli/yum_consumer_preflight.go#L1038)

- 展开 definition，同时冻结 module、route、trust、meta 与 YAML 形状。
  [`yum_consumer_preflight.go:839`](../../internal/cli/yum_consumer_preflight.go#L839)

- v2 map 把 infra 显式绑定到双架构 cross-EL projection。
  [`yum-consumer-map.tsv:1`](../../docs/migration/yum-consumer-map.tsv#L1)

**聚合信任**

- 保留历史 RPM signing-subkey binding 后枚举 primary closure。
  [`package_keyring.go:99`](../../internal/yumrepo/package_keyring.go#L99)

- 从客户端实际导入的多证书 bundle 精确选择 metadata identity。
  [`sign.go:85`](../../internal/yumrepo/sign.go#L85)

**迁移事务**

- 把 receipt-check 封装为可重复、同 digest 的写前门禁。
  [`migrate-pigsty-yum-consumers.sh:407`](../../docs/migration/migrate-pigsty-yum-consumers.sh#L407)

- evidence、备份、二次门禁与逐文件原子改写组成 apply。
  [`migrate-pigsty-yum-consumers.sh:493`](../../docs/migration/migrate-pigsty-yum-consumers.sh#L493)

- rollback 只接受 exact before/after 状态并保留 proof chain。
  [`migrate-pigsty-yum-consumers.sh:607`](../../docs/migration/migrate-pigsty-yum-consumers.sh#L607)

**验证证据**

- 集成测试覆盖真实发布链、漂移、时间、inode 与 offline replay。
  [`yum_consumer_preflight_test.go:54`](../../internal/cli/yum_consumer_preflight_test.go#L54)

- parser 负例集中覆盖 selector、module、tag、description 与 meta bypass。
  [`yum_consumer_preflight_test.go:539`](../../internal/cli/yum_consumer_preflight_test.go#L539)

- copied-tree E2E 覆盖双门禁、中断恢复、路径攻击与 legacy rollback。
  [`test-migrate-pigsty-yum-consumers.sh:140`](../../docs/migration/test-migrate-pigsty-yum-consumers.sh#L140)

- 可复现实测命令、时间与明确未完成的生产边界。
  [`2026-07-19-pigsty-yum-consumer-preflight.md:53`](../../docs/evidence/2026-07-19-pigsty-yum-consumer-preflight.md#L53)
