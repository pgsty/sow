# Dual-target independent publication pipeline evidence

Date: 2026-07-15 (Asia/Shanghai)

Status: current-source local/protocol evidence. This is not real R2, COS,
Cloudflare, or EdgeOne evidence and it did not access any production resource.

## Contract closed

The ordinary publication path gives `cf` and `cos` one independent, strictly
ordered target-major sequence each. Outer target orchestration remains
concurrent even with `--workers 1`; the worker value is the inner
CPU/streaming budget, not permission for one provider observation to serialize
the other provider.

For mutable views, each sequence performs its own interrupted-intent
inspection and then advances beta → latest → stable. Explicit multi-snapshot
publication uses the same shape. Default publication extends the target-local
order to exact interrupted snapshot recovery → interrupted view recovery →
beta → latest → stable → every retained snapshot. A provider that fails one
intent stops only its own later intents; its sibling continues. There is no
cross-target inspection, view, or snapshot join between these steps.

The selected local view/snapshot trees are frozen before ordinary provider
mutation and reused read-only by both sequences. A crashed snapshot intent
older than the retention window is materialized once on demand under the
selected-set barrier. That rare local preparation shares the canonical
persistence coordinator so its frozen-HEAD check cannot race a target-state
commit; provider observation, upload, purge, and verification continue outside
the coordinator. Normal canonical target-state persistence remains the only
shared critical section. Outcomes are buffered per target and emitted in
deterministic target order after both sequences settle, while one failed target
is recorded without rolling back its successful sibling.

Single-target no-change preflight remains an optimization. Multi-target
publication eagerly freezes the local union to avoid turning an optional
provider preflight into a cross-provider barrier; each target's exact builder
still proves unchanged/drift independently and unchanged targets perform no
remote mutation.

Target affinity is applied before desired-manifest, ref, channel, and plan
construction. A target owning the complete prepared union reuses the immutable
union manifest instead of attempting an `O_EXCL` self-copy; a streaming scope
validation still rejects any entry outside the frozen union.

For a zero-object or deletion-only publication, the new plan now carries a
deterministic set of prior committed expectations that closes every frozen
logical leaf. A physical YUM generation URL cannot substitute for the exact
repo/OS/arch mirrorlist. Explicit selectors filter positive sampling but can
never suppress transaction-wide `VerifyAbsent` assertions, so a stale gated
snapshot route remains a critical L3 drift.

## Reproducible local evidence

All commands were run with AWS, Cloudflare, and Tencent credential variables
unset, AWS config/credential files set to `/dev/null`, all real-cloud and
real-upstream opt-ins set to `0`, `GOPROXY=off`, and outbound proxies pointed
at `127.0.0.1:1`.

Focused target-major scheduling and protocol tests, including a requested
worker budget of one and deliberately blocked CF checkpoint reads:

```sh
go test ./internal/cli \
  -run 'Test(TargetPublicationSequencesAdvanceAcrossIntentsWithoutWaitingForSlowSibling|PublishCLIChangedCOSCommitsWhileCFPipelineIsBlocked|PublishCLICOSAdvancesBetaLatestStableWhileCFInspectionIsBlocked|PublishCLICOSAdvancesAcrossSnapshotsWhileCFInspectionIsBlocked|PublishCLIDefaultCOSAdvancesThroughRetainedSnapshotWhileCFInspectionIsBlocked)' \
  -count=3
```

Observed: PASS, package 62.189s. While CF remained blocked, COS reached stable
generation 6 in the changed three-view fixture, explicit snapshot generation 2
in the two-snapshot fixture, and retained-snapshot generation 4 in the default
fixture.

The same concurrency paths plus exact snapshot recovery and sibling-failure
isolation under the race detector:

```sh
go test -race ./internal/cli \
  -run 'Test(TargetPublicationSequencesAdvanceAcrossIntentsWithoutWaitingForSlowSibling|PublishCLIChangedCOSCommitsWhileCFPipelineIsBlocked|PublishCLICOSAdvancesBetaLatestStableWhileCFInspectionIsBlocked|PublishCLICOSAdvancesAcrossSnapshotsWhileCFInspectionIsBlocked|PublishCLIDefaultCOSAdvancesThroughRetainedSnapshotWhileCFInspectionIsBlocked|PublishCLIDefaultSnapshotRecoveryFailureDoesNotBlockSibling|PublishCLIDefaultRecoversExactSnapshotBeforeViewsAndRetainsOthersAfter)' \
  -count=1
```

Observed: PASS, package 48.867s, no race report.

An interrupted snapshot outside the six-month derived-cache window is not
silently dropped and is not broadened to the healthy sibling:

```sh
go test ./internal/cli -run \
  '^TestPublishCLIDefaultRecoversExpiredCFIntentWithoutBlockingCOSViews$' \
  -count=1
go test -race ./internal/cli -run \
  'Test(PublishCLIDefaultRecoversExpiredCFIntentWithoutBlockingCOSViews|PublishCLIPersistsSuccessfulTargetWhenSiblingCredentialIsUnavailable)' \
  -count=1
```

Observed: PASS, ordinary package 6.323s and race package 12.031s. During the
blocked read, CF remained on generation 1, `snapshot/all-20200101`, phase
`locked`; COS reached stable generation 3. After release CF recovered only the
expired intent and reached stable generation 4, while COS never received the
expired snapshot route. The sibling-missing-credential case retained the
existing `failed-before-saga` CLI evidence and the successful target ref.

Production CLI orchestration through signed in-memory R2/COS/CDN protocol
transports:

```sh
go test ./internal/cli -run \
  'TestPublishCLIPersistsSuccessfulTargetWhenSiblingCredentialIsUnavailable|TestPublishCLICommitsBothIndependentTargetsInOneInvocation|TestPublishCLIDefaultViewsStopsFailedTargetAndContinuesSibling|TestPublishCLIDefaultSnapshotRecoveryFailureDoesNotBlockSibling|TestPublishCOSLockedCrashSurvivesOtherTargetCanonicalCommit' \
  -count=1
```

Observed: PASS, package 16.009s.

The broad publication regression surface, including crash recovery, target
trust replacement, restore, retention, target affinity, and publication-plan
validation:

```sh
go test ./internal/cli -run 'TestPublish|TestPublication' -count=1
```

Observed on the current target-major source after the CLI evidence compatibility
fix: PASS, package 345.702s.

The retained-snapshot positive/negative L3 closure and exact YUM selector test:

```sh
go test ./internal/cli -run \
  'TestL3ExplicitYUMSelectorRequiresItsExactChannel|TestPublishCLIYUMSnapshotUsesExactIntentStableRouteAndServerSideCopy' \
  -count=1
```

Observed: PASS, package 13.233s.

`go vet ./internal/cli ./internal/state` also passed after these changes.

## Evidence boundary

These tests use the real CLI, filesystem, canonical Git state, publication
planner/saga, concrete provider protocol code paths, and failure injection,
but the remote endpoints are deterministic local transports. Real
non-production provider latency, conditional-write behavior, CDN purge logs,
and cross-PoP cache convergence remain separate POC evidence. Production
CO/COS/Cloudflare repositories are permanently excluded from testing.
