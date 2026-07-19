# Selected-set materialization and recovery closure — 2026-07-13

## Scope

This report records the local product-path closure performed after an
independent blind review of direct materialization and publication recovery.
It covers APT, YUM and asset selected-set transactions, explicit exports,
snapshot replay, offline archive adoption, and the ordering between durable
local recovery and remote publication. It does not claim a real R2, COS,
Cloudflare or EdgeOne run.

The frozen contract is [ADR-0018](../adr/0018-selected-set-local-materialization-transaction.md).

## Closed defects and invariants

- Direct materialization installs new CAS payloads, then atomically commits
  APT/YUM metadata, and only then performs exact payload reconciliation. A
  metadata failure therefore leaves the previous signed payload closure
  consumable.
- APT direct materialization uses suite-wide selector ownership and persists
  the same canonical by-hash retention ledger as add/publish. Retained
  generations survive direct beta/stable replay.
- Fixed product-owned partial roots merge only the selected ownership scopes.
  An explicit `--target` is an exact selector export and cannot retain gated or
  foreign bytes from an earlier view. Full snapshot replay removes a foreign
  `_sow` namespace; fixed mutable views alone retain delayed-client serving and
  by-hash generations. The explicit target also owns the complete canonical
  serving topology for that physical root: a cross-view or base-URL rewrite
  removes obsolete channels, retires unreferenced generations and removes
  orphan target registries in the same operation instead of deferring known
  drift to GC.
- Every error after selected-set mutation starts retains
  `.sow/materialization-journal/active.json`, including an error after all leaf
  units completed but before the explicit final barrier. Only a successful
  selected-set finish removes the journal.
- Asset repositories are first-class selected units. A pure asset transaction
  records the domain-separated SHA-256 identity of
  `sow-no-repository-signing-key-v1`, while still binding configuration, exact
  refs and target identity. Mutable asset paths may replace canonical entries
  and relink physical files only when each layer independently admits the
  repo-relative path through `asset.mutable_paths`; immutable paths remain
  fail-closed. There is no whole-manifest replacement authority.
- Standalone asset `add` now creates a fresh `add` selected-set before its first
  hostable-tree mutation. `add --recover` replays the frozen ref and CAS before
  interpreting any current positional input as asset, RPM or DEB work. It does
  not reopen or depend on the original pathname, so the inputless form is a
  recovery-only operation; different canonical work remains fenced until that
  recovery succeeds.
- A standalone RPM/DEB add may stage private CAS bytes and commit canonical
  refs before it creates the selected-set, but an already active `add` journal
  is a pre-CAS admission fence. Recovery must match one homogeneous package
  family, the frozen trust/config/HEAD identities, the exact materialization
  unit vector, and complete path/size/SHA-256 entries already present in the
  frozen refs. Cross-family, package-to-asset, mixed-family and same-family
  novel inputs are rejected without installing a CAS object and without
  clearing the journal. An exact frozen entry may restore a missing CAS object
  and then converge the directly hostable tree. RPM and DEB imports use private
  input snapshots; expected-object installation rejects a changed snapshot
  before the candidate can become a persistent CAS object.
- `materialize --tgz --asset-repo` treats archive adoption as a second local
  transaction because the asset ref does not exist until after deterministic
  archive creation. The transaction uses the
  `offline-archive-adoption-v1` scope and `cfg.Root` target identity.
  `materialize --recover` converges that exact CAS/ref projection before it
  plans the caller's current selector. The archive manifest excludes its own
  destination, so replay is byte-identical rather than recursively embedding
  the previous tgz.
- `publish --recover` treats the durable unit vector as recovery authority.
  Mutable-view and multi-snapshot journals are completed and cleared before
  any HTTP request made for the current selector or a requested historical
  restore. A historical restore request first reconstructs the requested
  target/generation unit IDs locally; a mismatch returns conflict with zero
  HTTP calls and preserves the journal. An exact historical request first
  rebuilds its isolated CAS/metadata tree, passes the final barrier and clears
  the journal; only then may it perform the read-only target observation used
  to calculate the real parent topology.
- The zero-HTTP rule applies while an exact durable recovery journal is active.
  An ordinary publish without such a journal may perform its bounded
  O(change-set) GET/HEAD preflight before local preparation; if immutable local
  drift then fails preparation, the verified contract is zero remote mutation,
  not zero read-only observation.

The canonical manifest/ref commit remains the product-truth commit point. A
process stop after that commit but before selected-set creation leaves the
previous complete hostable tree, not a mixed tree. L1 reports the resulting
canonical/filesystem drift and idempotent replay converges it. The durable
selected-set journal is mandatory before the first hostable-tree mutation.

## 2026-07-13 historical focused baseline

The earlier merged focused set contained 13 tests covering:

- direct APT by-hash retention;
- real reconcile failure after metadata completion;
- dedicated public export after a gated export;
- full snapshot `_sow` drift removal;
- asset CAS loss, partial hardlink visibility, writer fencing and exact
  recovery;
- mutable versus immutable asset relink policy;
- standalone asset add conflict/recovery;
- scoped offline archive-adoption conflict/recovery followed by a different
  current selector;
- byte-identical latest/direct tgz replay without self-embedding;
- narrow mutable and multi-snapshot publication journal recovery;
- mutable/snapshot journal recovery before historical restore HTTP;
- historical generation mismatch with zero HTTP and exact reentrant restore.

That dated run completed in 91.806s ordinary and 120.468s under the race
detector on Darwin arm64, Go 1.26.5. It is retained as historical evidence, not
as a command or result for the later 2026-07-14 source identity.

The two new standalone/adoption asset tests also passed focused race,
`-count=3`, the wider Add/Materialize group, and the asset publish/remove and
active-fence groups. The restore-order tests separately passed focused ordinary
and race runs, and the pre-existing exact view/snapshot recovery tests passed
after the change.

The next independent review found two additional P2 ordering/topology
defects and one stale test contract:

- exact historical recovery performed a read-only remote observation before
  clearing its already validated local journal;
- explicit partial target replacement removed physical `_sow` bytes but left
  the old cross-view canonical channel/target ledger;
- the older A→B→A base-URL migration test still expected that deliberately
  known target orphan to remain for later GC.

The merged fixes passed a six-test ordinary/race set in 54.727s/69.675s. After
updating the URL-migration assertion to require immediate target cleanup and
`serving_target_orphans=0`, the historical/dedicated/migration set passed in
21.197s ordinary and 27.893s race. The dedicated cross-view test proves the old
stable channel/target and active generation ledger disappear, a retirement
witness remains, the desired beta channel/target remains, and L1 reports no
`LOCAL_YUM_*` drift.

## 2026-07-13 historical full validation baseline

These commands passed before the 2026-07-14 recovery-admission changes and are
retained only as a dated baseline:

```text
go test -count=1 ./...
ok github.com/pgsty/sow/internal/cli 420.376s
all remaining internal, compat and clean-delivery packages PASS

go test -race -count=1 ./...
ok github.com/pgsty/sow/internal/cli 541.675s
all remaining internal, compat and clean-delivery packages PASS
no race report

go vet ./...                         PASS (1.173s)
go mod tidy -diff                    PASS, empty diff
go mod verify                        PASS (1.681s; all modules verified)
GOPROXY=https://goproxy.cn,direct go run
  golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
                                        PASS, reachable vulnerabilities 0;
                                        imported-package vulnerabilities 0
(cd third_party/cavaliergopher-rpm && go test ./... -count=1)
                                        PASS (rpm package 0.628s)
cd edge && npm test                   PASS (26/26; 0.926s command wall)
gofmt -l internal/cli internal/repository
                                        empty
git diff --check                     PASS
```

A production-source placeholder scan over `cmd`, non-test `internal`, and
non-generated `edge` returned no `TODO`, `FIXME`, `XXX`, `not implemented`,
`unimplemented`, or `panic("TODO` match.

The corresponding historical `CGO_ENABLED=0` cross-builds were:

| Target | Bytes | SHA-256 |
|---|---:|---|
| linux/amd64 | 47,721,581 | `180fd4a10529c52addff4cdac0857da8ad41ba8daa1d086f0874248884e09fd8` |
| linux/arm64 | 45,251,846 | `e138adc6253fe43673ff20a95d1f736f24b38a26257dfb8b50af330dd286f1bb` |
| darwin/amd64 | 49,426,272 | `316f62f0345a1293f829a702b491aff352d7eecf78a7ee9b88783aaf91252b77` |
| darwin/arm64 | 47,341,762 | `74caa1827fbbdd36558cc2b27ce5eae1e7b128495ed0d9f59f33a5915b77d0b1` |

`file` identified both Linux artifacts as statically linked ELF executables and
both Darwin artifacts as Mach-O executables of the requested architecture.

## 2026-07-14 current-source validation

The recovery-admission and path-scoped replacement changes were validated
against the current 349-file product allowlist, not merely against the historical
baseline above. The exact 13-test recovery set covered inputless asset replay,
subtype ordering, exact-envelope rejection, durable failure retention,
path-scoped direct relink, RPM/DEB family and frozen-entry CAS admission, DEB
private-snapshot stability, and the global active-journal writer fence:

```text
RECOVERY_RE='^(TestAssetAddAndPublishReplaceOnlyConfiguredMutablePaths|TestStandaloneAssetAddFailureRetainsDurableSelectedSetAndRecovers|TestAssetAddHelpDocumentsInputlessRecovery|TestAssetAddRecoveryPrecedesCurrentSubtypeDispatch|TestAssetAddRecoveryThenProcessesCurrentNewAsset|TestAssetAddRecoveryRejectsNonExactEnvelopeWithoutClearing|TestAssetAddRecoveryFailureRetainsPreparedJournal|TestDecodeAssetAddMaterializationRequiresExactFrozenAssetUnit|TestDirectAssetMaterializeRelinksOnlyConfiguredMutablePaths|TestPackageAddRecoveryFencesCASByFamilyAndFrozenEntries|TestDEBAddRecoveryFencesCASByFrozenEntriesAndRestoresExactObject|TestDEBAddPrivateSnapshotClosesSourcePathSwapBeforeCAS|TestActiveMaterializationJournalStrictlyFencesWritersAndReportsReadOnlyAudits)$'
go test -count=1 ./internal/cli -run "$RECOVERY_RE"
                                        PASS (27.677s root run;
                                        30.616s independent run)
go test -race -count=1 ./internal/cli -run "$RECOVERY_RE"
                                        PASS (33.786s independent run)
CORE_RE='^(TestAssetAddAndPublishReplaceOnlyConfiguredMutablePaths|TestStandaloneAssetAddFailureRetainsDurableSelectedSetAndRecovers|TestAssetAddRecoveryPrecedesCurrentSubtypeDispatch|TestPackageAddRecoveryFencesCASByFamilyAndFrozenEntries|TestDEBAddRecoveryFencesCASByFrozenEntriesAndRestoresExactObject)$'
go test -count=3 ./internal/cli -run "$CORE_RE"
                                        PASS (43.600s)
go test -count=3 ./internal/repository
                                        PASS (7.872s)
go test -race -count=1 ./internal/repository
                                        PASS (4.989s)
```

The exact recovery expression names these tests:
`TestAssetAddAndPublishReplaceOnlyConfiguredMutablePaths`,
`TestStandaloneAssetAddFailureRetainsDurableSelectedSetAndRecovers`,
`TestAssetAddHelpDocumentsInputlessRecovery`,
`TestAssetAddRecoveryPrecedesCurrentSubtypeDispatch`,
`TestAssetAddRecoveryThenProcessesCurrentNewAsset`,
`TestAssetAddRecoveryRejectsNonExactEnvelopeWithoutClearing`,
`TestAssetAddRecoveryFailureRetainsPreparedJournal`,
`TestDecodeAssetAddMaterializationRequiresExactFrozenAssetUnit`,
`TestDirectAssetMaterializeRelinksOnlyConfiguredMutablePaths`,
`TestPackageAddRecoveryFencesCASByFamilyAndFrozenEntries`,
`TestDEBAddRecoveryFencesCASByFrozenEntriesAndRestoresExactObject`,
`TestDEBAddPrivateSnapshotClosesSourcePathSwapBeforeCAS`, and
`TestActiveMaterializationJournalStrictlyFencesWritersAndReportsReadOnlyAudits`.

Full current-source validation then passed:

```text
go test -count=1 ./...
                                        PASS; internal/cli 489.009s;
                                        all packages PASS
go test -race -count=1 ./...
                                        PASS; internal/cli 556.048s;
                                        all packages PASS; no race report
go vet ./...                           PASS (11.063s independent run)
go mod tidy -diff                      PASS, empty diff
go mod verify                          PASS, all modules verified
(cd third_party/cavaliergopher-rpm && go test ./... -count=1)
                                        PASS (rpm package 0.613s)
(cd edge && npm test)                  PASS (26/26; 143.681ms test duration)
govulncheck@v1.6.0 ./...               PASS; reachable vulnerabilities 0;
                                        imported-package vulnerabilities 0
gofmt -l $(rg --files -g '*.go')       empty
git diff --check                       PASS
```

The production-source placeholder scan over non-test `cmd`, `internal` and
`edge` code again returned no TODO/FIXME/XXX/not-implemented match. The
independent final recovery audit reported `NO ACTIONABLE FINDINGS` after the
focused ordinary/race/count runs, repository stress runs, vet, formatting and
diff checks.

Current `CGO_ENABLED=0`, `-trimpath` cross-builds were:

| Target | Bytes | SHA-256 |
|---|---:|---|
| linux/amd64 | 47,774,486 | `c9dfa92a6254a2c54eae1b57413aeb99e86204a7756aebb19d58904aa4809f9d` |
| linux/arm64 | 45,329,319 | `a4ec9c21aa7f7797af526631bc7aa938c418ff3030ece267fb295a61ee488184` |
| darwin/amd64 | 49,481,232 | `8b3ce90c2143dc7b478254f709b187995b8e52486ea9f0b3e3b6b09eb2bb938c` |
| darwin/arm64 | 47,393,026 | `a721d0f981be748e609dcd87417bb193dff9d597af0b1a9b0a842ac755221b9a` |

`file` identified the Linux binaries as statically linked ELF for x86-64 and
AArch64 and the Darwin binaries as Mach-O for x86_64 and arm64.

The current source was also exercised through the real-client Docker/Nginx
matrix:

```text
PATH=/opt/homebrew/bin:$PATH \
SOW_RUN_DOCKER_COMPAT=1 SOW_COMPAT_NGINX=1 \
SOW_COMPAT_APT_IMAGE=ubuntu:22.04 \
SOW_COMPAT_DNF_IMAGE=almalinux:10 \
SOW_COMPAT_EL9_IMAGE=almalinux:9 \
SOW_COMPAT_EL8_IMAGE=almalinux:8 \
go test -count=1 -v ./test/compat
```

The package passed in 99.123s. `TestDockerClientCompatibility` passed in
58.14s, the two Nginx allowlist tests in 5.03s and 5.04s, and the YUM detached
signature bridge in 29.17s (EL8 11.43s, EL9 11.61s, EL10 5.98s). Real apt
2.4.14 fetched by-hash metadata and installed the package. DNF 4.20/4.14/4.7
installed packages with both metadata and package signature checking; `rpm -K`
passed, and the missing-package-key negative failed as required. The matrix
covered stable history, APT snapshots, Basic fallback, EL8 gzip, EL9/10 zstd,
generation-pinned YUM and an in-flight generation flip.

The opt-in real-cloud, real-upstream, Pigsty package-trust and legacy-APT tests
were deliberately skipped because their corresponding environment gates were
not set. Historical reports remain valid dated observations, but this run does
not promote them to current-source or real-provider evidence.

## Acceptance boundary

These results close the local selected-set implementation defects found in the
blind reviews. They do not upgrade the real-cloud or production-migration
requirements: R2/COS/CDN deployment, two-token/WAF/cache observation,
multi-PoP purge and replay, production cutover/rollback, legacy apt/raw-YUM
policy, the Pigsty EL8 freeze version, and operational success/cost metrics
remain separately tracked blockers. The Goal therefore remains active.
