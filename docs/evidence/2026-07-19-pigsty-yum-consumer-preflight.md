# Pigsty YUM consumer preflight receipt evidence

Date: 2026-07-19
Scope: V-27, FZ-06, FR-08, FR-26 and MIG-04 local/provider-protocol evidence
Result: **local executable gate PASS; production cutover remains open**

## Implemented result

- Map v2 fixes the old infra route: x86_64 and aarch64 now select the two
  frozen `infra-legacy-*` cross-EL projections. Ordinary definitions carry an
  explicit release-aware `repo/os/arch` template. The historical dev-only
  China infra beta raw source is normalized to the only valid frozen authority,
  `repo.pigsty.cc` latest.
- Both Pigsty renderers select a nested regional mirrorlist with `os_arch`,
  while retaining reviewed scalar-mirrorlist and raw-baseurl fallbacks for
  rollback and unrelated user configuration.
- The Go preflight validates all stage hashes and expanded consumer bindings,
  the exact outer release/module/architecture selector and RPM renderer
  control flow, canonical channel/target ownership, current
  aggregate inventory size/SHA-256, public trust coverage and byte identity,
  and the complete RPM-MD client chain using the exact aggregate
  certificate/keyring before issuing an expiring canonical receipt.
- The four shipped definitions freeze their actual Pigsty modules; missing or
  wrong modules, custom YAML tags, multiline renderer descriptions and
  `meta` route/trust overrides are negative-tested rather than silently
  producing an unusable `.repo` file.
- Receipt replay is network-free and is now mandatory before shell `apply`
  creates evidence, copies originals or changes a Pigsty file.
- Receipt issuance reruns every unique mirrorlist/trust read after the heavy
  endpoint probes, then revalidates every local input including config-referenced
  metadata/package keyrings. Transport-triggered remote pointer, stage and
  keyring mutations all passed their earlier phase but were rejected before
  receipt installation. Package trust uses the history-preserving aggregate
  parser; its binding-renewal fixture remains accepted.
- One post-lock UTC instant governs metadata/RPM checks and receipt validity.
  A probe advanced beyond its requested window and a byte-identical same-path
  stage/receipt-parent inode replacement both failed before receipt
  installation; non-UTC receipt timestamps are non-canonical.
- Shell apply compares the Go-validated receipt digest to the path again and
  archives the exact JSON before backups or source mutation. Apply/rollback
  and mixed-state recovery retain that digest rather than losing it in a
  last-step crash window.
- Immediately before the first Pigsty write, shell apply repeats the
  network-free receipt check and requires the same digest. A fixture that
  accepted the first check but rejected the second left every source byte
  unchanged.
- The shell independently rejects non-canonical/traversing manifest paths
  before evidence creation, refuses symlinked or checkout-containing plan and
  evidence directories, and installs marker/final receipts through checked
  process-unique temporary files. Fixed-name stale-symlink sentinels remained
  byte-identical.

## Reproduced commands

```bash
go test ./internal/cli -run 'TestYUMConsumer' -count=1 -v
go test -race ./internal/cli ./internal/yumrepo \
  -run 'TestYUMConsumer|TestParseRPMPackageKeyringPreservesHistoricalSigningSubkeyBindings' \
  -count=1
docs/migration/test-migrate-pigsty-yum-consumers.sh
docker run --rm -v "$PWD:/mnt:ro" koalaman/shellcheck:stable \
  /mnt/docs/migration/migrate-pigsty-yum-consumers.sh \
  /mnt/docs/migration/test-migrate-pigsty-yum-consumers.sh
go vet ./...
staticcheck -checks='SA*,S1*' ./...
go test ./internal/cli -timeout 25m -count=1
go list ./... | rg -v '/internal/cli$' | xargs go test

SOW_RUN_DOCKER_COMPAT=1 SOW_COMPAT_NGINX=1 \
  SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 SOW_RUN_REAL_UPSTREAM=0 \
  go test ./test/compat \
  -run '^(TestDockerClientCompatibility|TestYUMDetachedSignatureBridgeCompatibility)$' \
  -timeout 20m -count=1 -v

SOW_RUN_DOCKER_COMPAT=1 SOW_COMPAT_NGINX=1 \
  SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 SOW_RUN_REAL_UPSTREAM=0 \
  go test ./internal/cli \
  -run '^TestYUMCompatibilityStateMachineWithRealNginxAndDNF$' \
  -timeout 20m -count=1 -v
```

Observed focused Go result:

```text
TestYUMConsumerPreflightClosesPublishedProtocolAndReceiptWithoutNetworkReplay PASS
TestYUMConsumerReceiptInstallIsNoReplaceAndCanonical PASS
TestYUMConsumerReviewParsersRejectUnsafeSurfaces PASS
TestYUMConsumerStageReadRejectsSymlink PASS
TestYUMConsumerRendererRejectsCommentOnlyMarkers PASS
TestYUMConsumerRemoteTrustTreatsCloseFailureAsNetworkFailure PASS
TestYUMConsumerVerbHelpHasDedicatedGateSurface PASS
```

The integration uses a real RPM fixture and the real SOW add/materialize/
publish path. It publishes signed zstd primary/filelists/other metadata,
repomd + detached signature, a generation-pinned beta mirrorlist and a public
`pkg/keys/rpm-trust.asc` asset through the provider protocol fixture. Preflight
then downloads and verifies the referenced RPM. The resulting evidence has
`metadata_objects=6`, `installed_objects=1` and package
`pgdg-redhat-nonfree-repo`.

Receipt-check was rerun with a transport that fails every HTTP request and
still passed, proving that apply-time replay is local/canonical only. Changing
the reviewed map, aggregate inventory identity, config package keyring,
advancing time to expiry, changing remote trust bytes, or flipping a
mirrorlist after its full RPM probe made the gate fail. So did a proof that
outlived its issuance window and an inode-replaced review directory with the
same path and bytes. Failed checks installed no receipt; an existing receipt
could not be replaced.

The final focused run passed in `5.534s`; its race run passed
(`internal/cli` `10.181s`, `internal/yumrepo` `2.750s`). The default aggregate
`go test ./...` invocation reached Go's
10-minute package timeout while the then-685-test CLI package was still making
forward progress. The exact suite was therefore completed as two explicit
partitions rather than hidden or skipped: the final 688-test `internal/cli`
source passed with a 25-minute package budget in `1170.620s`, and every
remaining package (including `test/compat/cleandelivery`) passed in the second
command. `go vet ./...`, correctness-focused Staticcheck, and ShellCheck over
both migration scripts also passed.

The real local Docker/Nginx matrix passed without any real-provider opt-in:

```text
TestDockerClientCompatibility + detached bridge package PASS (129.765s)
  apt 2.4 and apt 1.2 update/install PASS
  DNF EL8 gzip, EL9/EL10 zstd update/install PASS
  stable/history, immutable snapshot, Basic/token and generation flip PASS
  missing package key negative control PASS
TestYUMDetachedSignatureBridgeCompatibility PASS (30.98s)
  EL8, EL9 and EL10 signature-pair/redirect matrix PASS
TestYUMCompatibilityStateMachineWithRealNginxAndDNF PASS (47.84s; package 48.733s)
  S0 -> S2 -> S3 -> rollback across EL8/9/10 PASS
```

That last test initially exposed a stale fixture: current Nginx admission
correctly requires the selected ordinary YUM owner to have a canonical route
receipt before it will expose even the frozen S2 raw bridge. The fixture now
materializes `infra-el9/latest` first; the gate was not bypassed. The corrected
state-machine run passed cutover, signed generation consumption, rollback,
`fsck` and L1 verification.

Observed isolated Pigsty migration result:

```text
pigsty_yum_consumer_audit=pass mapped_definitions=28
pigsty_yum_consumer_stage=pass source_unchanged=true
pigsty_yum_consumer_apply=pass replay_idempotent=true mixed_state_recovered=true
pigsty_yum_consumer_preflight_gate=pass rejected_before_mutation=true revalidated_before_write=true receipt_bound=true unsafe_manifest_rejected=true disjoint_plan_enforced=true stale_symlink_not_followed=true
pigsty_yum_consumer_rollback=pass foreign_drift_rejected=true exact_bytes_restored=true replay_idempotent=true mixed_state_recovered=true legacy_v1_replay=true
```

A fresh read-only stage from `/Users/vonng/pgsty/pigsty` produced:

```text
mapped_definitions=28 already_migrated=
plan_sha256=2568d84b7d712e2a6ae756581bd5e349ab91181805e4b2e511fa6fcfd91cc371
changed=true
```

The test copied only the eleven allow-listed Pigsty files. The source checkout
was never modified. No cloud request or write occurred in this evidence run;
CO/COS and Cloudflare production repositories were not used. Docker clients
talked only to temporary local Nginx listeners.

## Still open

- Publish the reviewed aggregate asset and mapped physical generations first
  to explicitly approved non-production targets; production publication is a
  separate authorized migration action, never a test target.
- Run the same preflight through both approved real public non-production
  origins, then consume the exact staged Pigsty definitions rather than the
  equivalent local route fixtures.
- Perform and rehearse the production source apply/rollback only under explicit
  production-change authority. This evidence does not grant that authority and
  does not resolve the raw-baseurl production migration blocker.
