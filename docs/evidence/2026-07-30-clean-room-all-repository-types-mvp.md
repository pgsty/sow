# Clean-room APT/YUM/asset MVP evidence

Date: 2026-07-30
Scope: local filesystems and disposable process state only
Product baseline: `af72e00d698dff7924e52a3b09e4f2f65c422a1f` plus the reviewed change

## Claim

The release archive's production `cmd/sow` binary can start from the shipped
`sow.example.yaml` and a fresh root, then complete a useful package lifecycle
for all three repository types:

- asset, a real installable DEB, and a real signed RPM are added to `beta`;
- repeated add, promote, materialize, and remove operations converge without
  canonical drift; DEB/RPM add and remove report `physical=no-op`, and package
  materialization reports non-zero `existing` with zero linked/relinked/pruned;
- APT emits `Packages`, `Release`, `InRelease`, SHA-256 by-hash objects, and the
  exact pool payload;
- YUM emits an exact `https://repo.example.invalid` generation-pinned
  mirrorlist, signed `repomd.xml`, primary,
  filelists, and other zstd metadata, plus the exact signed RPM payload;
- `latest` materialization is directly hostable and L1/full fsck pass;
- removing the last DEB/RPM produces valid signed zero-package indexes. APT no
  longer advertises the DEB. The current YUM primary has `packages="0"` and
  does not advertise the RPM; the bounded compatibility generation may retain
  its body so clients holding pre-flip metadata can finish safely;
- SQLite deletion is explicitly rebuilt from canonical Git state; an actual
  production child process is stopped and killed after a durable asset fence,
  then inputless recovery succeeds after the original inputs are deleted.

The human-copyable README example remains asset-only so it needs no signing
material. The automated archive gate generates an ephemeral repository signer
inside its disposable root. Its real RPM fixture retains the independent PGDG
package signature, and the disposable config uses a separate public package
keyring.

## Product defect found and closed

The extended lifecycle first failed after the final DEB/RPM removal:
`APT_POOL_UNSAFE` and `YUM_PACKAGE_TREE_UNSAFE` treated an absent `pool/` or
`Packages/` directory as corruption even when signed indexes proved an empty
closure.

`internal/verify` now permits an absent payload root only as an empty manifest,
including the production snapshot `FilesystemCheck` composed by `sow verify`.
An absence-bound stream rechecks the coordinate at open, read, and close, so a
tree that appears during comparison fails closed. The witness also binds the
repository root and every existing parent directory by inode, and scope/path
patterns are validated before absence can be accepted. Root or parent rename,
replacement, disappearance, symlink, special file, reserved shadow point, or
scan/hash race therefore fails. The signed-index/body comparison still rejects
an absent tree whenever an indexed package exists. The old eager audit was
removed: a present tree performs one shape audit and one hashing scan, not an
extra full walk.

The stronger replay assertion also exposed physical churn for an explicit YUM
export: each replay removed seven valid `_sow` route files before recreating
them. A first attempt carried the entire existing `_sow` tree through exact
reconcile, which could retain unowned bytes. Explicit exports now construct a
keep-set only from canonical target/view/leaf lifecycle records, verify every
retained mirrorlist/generation/trust byte, and preserve those exact inodes.
An injected unowned `_sow` file is pruned and excluded from `--tgz`; the next
clean replay reports `created=false`, `pointer=unchanged`, `pruned=0`, and an
unchanged canonical HEAD.

## Adversarial review defects found and closed

The second review loop found two additional integrity boundaries that the
happy-path lifecycle did not prove:

- exact sub-target reconciliation formerly inherited the repository-root
  exemption for top-level `.sow`, `.pool`, and `.git`. Scan policy is now
  explicit: only the actual canonical root excludes its own operator
  directories; every nested or standalone export includes all shadow points.
  Regular shadow-point files are descriptor-pruned, while symlinks and special
  files fail closed. Isolated serving validation uses the same include-all
  policy.
- YUM validation formerly proved signed metadata and package closure in
  separate pathname reads. `yumrepo.ValidateRootWithProof` now retains an
  `os.Root`, reads `repomd.xml`, its detached signature, and primary/filelists/
  other through bound regular descriptors, and returns a five-file proof.
  L1 parses all three artifacts through that same retained root and re-proves
  identity, size, digest, and public repodata coordinate after validation and
  at completion. Whole-directory, repomd-only, signature-only, and artifact
  swaps therefore fail.

The final proof path also preserves `context.Canceled` and
`context.DeadlineExceeded` through joined hash/close failures instead of
misclassifying cancellation as an integrity finding. Focused ordinary and race
regressions cover the YUM swaps, cancellation, top-level/nested shadow points,
and explicit frozen-compatibility materialization/replay.

## Reproducible verification

The exact prefix below starts every command from an allowlisted environment:
ambient Cloudflare/Tencent/AWS credentials, SOW signing secrets, provider
descriptors, and confirmation variables cannot reach the process. Real cloud,
edge, upstream, Docker, performance, and compatibility opt-ins are explicitly
off.

```bash
SAFE_HOME="$(mktemp -d /tmp/sow-v91-safe-home.XXXXXX)"
SAFE_GOPATH="$(mktemp -d /tmp/sow-v91-safe-gopath.XXXXXX)"
PARENT_GOMODCACHE="$(go env GOMODCACHE)"
PARENT_GOCACHE="$(go env GOCACHE)"
PARENT_GOPROXY="$(go env GOPROXY)"
PARENT_GOSUMDB="$(go env GOSUMDB)"
safe() {
  env -i \
    PATH="$PATH" HOME="$SAFE_HOME" TMPDIR="${TMPDIR:-/tmp}" \
    GOPATH="$SAFE_GOPATH" GOMODCACHE="$PARENT_GOMODCACHE" \
    GOCACHE="$PARENT_GOCACHE" GOPROXY="$PARENT_GOPROXY" \
    GOSUMDB="$PARENT_GOSUMDB" GOENV=off GOWORK=off \
    GOTOOLCHAIN=local GOFLAGS=-mod=readonly LANG=C LC_ALL=C \
    AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    AWS_EC2_METADATA_DISABLED=true \
    SOW_RUN_APT_LEGACY_COMPAT=0 \
    SOW_RUN_AUTHORIZED_CF_RAW_PREFLIGHT_NEGATIVE=0 \
    SOW_RUN_DOCKER_COMPAT=0 SOW_RUN_PERF=0 \
    SOW_RUN_PIGSTY_PACKAGE_TRUST=0 \
    SOW_RUN_PIGSTY_ROOT_BOTH_HANDOFF=0 \
    SOW_RUN_PIGSTY_ROOT_COS_HANDOFF=0 \
    SOW_RUN_REAL_CLOUD=0 \
    SOW_RUN_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP=0 \
    SOW_RUN_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_PLAN_ONBOARDING=0 \
    SOW_RUN_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_REGISTRY_ONBOARDING=0 \
    SOW_RUN_REAL_CLOUD_PROVIDER_READINESS=0 \
    SOW_RUN_REAL_CLOUD_PROVIDER_READINESS_REGISTRY_ONBOARDING=0 \
    SOW_RUN_REAL_CLOUD_R2_FSCK=0 \
    SOW_RUN_REAL_CLOUD_R2_PUBLICATION_STORAGE=0 \
    SOW_RUN_REAL_CLOUD_R2_STORAGE=0 \
    SOW_RUN_REAL_CLOUD_REGISTRY_ONBOARDING=0 \
    SOW_RUN_REAL_EDGE_EVIDENCE=0 SOW_RUN_REAL_UPSTREAM=0 \
    SOW_REAL_CLOUD_PURGE_WATCHER_HELPER=0 \
    SOW_COMPAT_NGINX=0 SOW_MINIO_TEST=0 \
    "$@"
}

safe go test -timeout 15m -count=1 ./internal/manifest ./internal/verify
PASS

safe go test -race -timeout 15m -count=1 ./internal/manifest ./internal/verify
PASS

safe go test -timeout 20m -count=1 ./test/compat \
  -run '^TestShippedExampleSupportsCleanRoomLocalMVP$'
PASS  88.207s

safe go test -race -timeout 20m -count=1 ./test/compat \
  -run '^TestShippedExampleSupportsCleanRoomLocalMVP$'
PASS  76.386s

safe go test -timeout 20m -count=1 ./test/compat
PASS

safe go test -race -timeout 25m -count=1 ./test/compat
PASS

The current CLI package contains 903 tests and cannot fit a single package-wide
wall-clock budget on this host. Ordinary mode was therefore executed as six
mutually exclusive name ranges; the P-Q range was further split into 12 exact
subsets after the original batch exhausted its 30-minute package budget while
its active test had run for only five seconds. Every subset passed:

```text
ordinary A-F   1235.664s
ordinary G-M   1656.494s
ordinary N-O    537.673s
ordinary P-Q     12/12 PASS; slowest 699.258s
ordinary R-V   1119.590s
ordinary W-Z    445.483s
```

Race mode used 12 mutually exclusive round-robin subsets. Ten passed within
their 30-minute budgets. The two remaining batches timed out while their active
tests had run only 17 and 37 seconds; they were split into 12 exact subsets.
Eleven passed. One 12-process overload run hit a test-local 30-second progress
timer, then the exact test passed three consecutive isolated race runs in
32.827 seconds total. Thus every CLI test passed under the race detector, while
the overload timeout is retained as scheduler-budget evidence rather than
misreported as a product deadlock.

All non-CLI product packages passed ordinary and race. Full compatibility
ordinary/race passed in 229.952/247.824 seconds. The clean-room production
binary test is also rerun separately below and by the delivery gate.

safe go test -timeout 5m -count=1 ./test/compat/cleandelivery
PASS

safe go mod tidy -diff
safe go mod verify
safe go vet ./...
safe staticcheck ./...
git diff --check
PASS

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  safe env CGO_ENABLED=0 GOOS="${target%/*}" GOARCH="${target#*/}" \
    go build -trimpath -o "/tmp/sow-${target%/*}-${target#*/}" ./cmd/sow
done
PASS  all four targets
```

The review-loop-1 gate used the host's read-only Go module download cache as a
`file://` proxy after `proxy.golang.org` timed out. It still created fresh
HOME/GOPATH/GOMODCACHE/GOCACHE directories and executed the complete gate in
both independently extracted archive trees:

```text
PRODUCT_SOURCE_SHA256=3c8854e0b98e3d26257ce200727dac1d1f3a43f2b671c8fcf3e6af13cf8eb009
PRODUCT_SOURCE_FILES=595
DELIVERY_CONTENT_SHA256=0bff3f322fa977fcd01c480cf14fe0949ea26f8a4440dc31648a337adcd11090
DELIVERY_FILES=805
ARCHIVE_SHA256=2c7127d7f9f6856005daf7e309f3b4142413dc86773b683c37ecec209d8ed1a0
```

Archives:

- `/tmp/sow-clean-delivery-v91-review-loop1-local-proxy-2/sow-delivery-0bff3f322fa977fc.tgz`

The gate internally generated two archives, compared them byte-for-byte, then
ran all required commands in both extraction trees. These hashes are explicitly
the review-loop-1 candidate, not the post-review delivery. Because this evidence
file is itself inside the archive, the final post-review identity is recorded
by the delivery handoff outside the archive rather than creating a
self-referential hash claim.

## Safety boundary

- No Cloudflare, CO, COS, production repository, production domain, or
  `/Users/vonng/pgsty/repo` write path is used.
- Provider credentials are removed from every test process, and all real
  provider opt-ins are `0`.
- No `gpg`, Python, Perl, package builder, container, or external repository
  tool is used by this gate or the product path. DEB and RPM inputs are
  checked-in real binary fixtures parsed by production code; Go creates only
  the ephemeral repository metadata signing identity.
- This evidence does not upgrade real Cloudflare Worker/CDN, EdgeOne, COS, or
  production migration status.
