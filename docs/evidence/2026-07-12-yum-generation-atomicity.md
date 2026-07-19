# YUM generation-pinned atomicity and legacy-alias boundary (2026-07-12)

## Verdict

- **PASS — strong YUM route:** a client first resolves the public static or Pro
  dynamic mirrorlist, receives one immutable generation base URL, and retrieves
  `repomd.xml`, `repomd.xml.asc`, primary, filelists, other, and RPM payloads
  below that generation. DNF may resolve mirrorlist again during one install,
  so a successor generation also carries retained generations' actually
  indexed `Packages/**` payloads as unindexed CAS hardlinks. Its repodata still
  describes only the current view.
- **GAP — legacy raw baseurl:** R2 and COS cannot replace
  `repomd.xml.asc` and `repomd.xml` as one operation. The compatibility order
  (`asc` then `xml`) has an observable old-XML/new-signature window. The raw URL
  remains available for migration compatibility, but is not strong-atomic.
- **GAP — apt before 1.2:** modern apt is closed by `InRelease` plus immutable
  by-hash indexes. A pre-by-hash client can straddle fixed `Packages*` aliases
  and `InRelease`; static object storage cannot make that multi-key observation
  atomic.

This preserves the frozen latest URL contract without representing the
compatibility aliases as satisfying FR-26/NFR-05. Existing consumers must move
to the standard YUM mirrorlist before the strong pair gate can be marked passed.

## Production fail-closed invariant

`internal/publish/saga.go` rejects any transaction containing a mutable raw YUM
alias pair unless the same transaction also contains:

1. byte-identical `repomd.xml` and `.asc` objects under the current immutable
   generation prefix; and
2. the exact current generation channel plus its static mirrorlist (public) or
   dynamic channel object (stable/Pro).

Validation runs before the remote lock/checkpoint is touched. This prevents a
raw-alias-only plan from becoming a supported publication path. The fault test
also injects a lost response immediately after the alias signature PUT, proves
the mixed raw pair is observable, and proves the generation-pinned mirrorlist
has not advanced.

```text
go test ./internal/publish -run TestYUMAliasCompatibilitySequenceRequiresPinnedRouteAndReplays -count=1 -v
--- PASS: TestYUMAliasCompatibilitySequenceRequiresPinnedRouteAndReplays
```

The full publish and CLI publication suites also passed:

```text
go test ./internal/publish -count=1
ok github.com/pgsty/sow/internal/publish

go test ./internal/cli -run 'Publish|RemoteVerify' -count=1
ok github.com/pgsty/sow/internal/cli
```

## Local serving lineage, retention, and topology evidence

Canonical channels are partitioned by a deterministic identity over target
root + clean base URL. Each target/repo/OS/arch keeps current plus
`state.yum_generation_retention` previous pins (default 2); incomplete journals
pin desired and parent independently. A→B→A deduplicates history, changing the
base URL on one physical root uses the old exact body as a migration parent,
and default/explicit/multiple exports never borrow lineage.

Full-authority materialize/publish removes channels and parent-bound
mirrorlists for leaves removed from view/config topology, including the
zero-YUM-leaf case. Partial repo/OS/arch selection cannot remove siblings.
Expired active generation ledgers atomically become a retired identity plus an
exact TSV deletion witness. The retired TSV is deliberately excluded from CAS
roots: it proves that a partially interrupted directory removal left only a
strict subset, without extending payload reachability. Explicit confirmed GC
binds opened directory inodes, fsyncs absence parents, and removes the paired
witness only after physical and CAS cleanup. Missing explicit exports converge
through confirmed channel+ledger retirement followed by target-registry GC;
legacy unpartitioned channels migrate with `materialize --recover`. Git history
does not silently extend the explicit serving retention window. Basic Nginx generation routes use
`private, no-store`, because a count-based flip window cannot justify a
wall-clock one-year TTL.

The crash contract assumes SOW's repository state lock is the single writer.
Pointer replacement still captures the displaced inode with Linux/macOS atomic
exchange, directory deletion is bound to an opened inode, and GC performs
post-commit rechecks with canonical-witness compensation. A hostile process
that continuously rewrites derived paths outside the lock is detected and
fails closed, but is not treated as a supported concurrent writer.

```text
go test -count=1 ./internal/serving ./internal/config
ok github.com/pgsty/sow/internal/serving
ok github.com/pgsty/sow/internal/config

go test -count=1 ./internal/cli -run '^(TestCanonicalServing|TestFullAuthorityServingTopology|TestServingTopology|TestExplicitServingBaseURLMigration|TestFullMaterializeRemovesYUMTopology|TestMaterializeRetainsRemovedPayload)'
ok github.com/pgsty/sow/internal/cli
```

These local tests include a >16 MiB canonical generation manifest streamed
through validation, journal-temp/recovery boundaries, shared generation IDs
across targets, and a real successor manifest negative check that retained old
RPM bytes are fetchable but absent from fresh primary metadata. The Docker DNF
in-flight gate was rerun after these lifecycle changes; current results follow.

## Cross-vendor channel-flip contract

The shared edge test resolves generation 42, flips the mutable channel to 43,
then requests both signed pair members through the previously returned URL.
Both Cloudflare and EdgeOne routing semantics keep those requests on generation
42; a newly resolved mirrorlist selects 43.

```text
cd edge && npm run build && npm test
tests 18
pass 18
fail 0
```

The test also keeps the verifier deployment contract active; it does not bypass
token verification or reintroduce a manual Cache API.

## Real DNF generation-pinned consumption

The opt-in Docker compatibility test builds the production Go CLI, generates
and signs an EL10 repository, promotes/materializes it, serves one static
mirrorlist whose only URL names generation 1, and runs AlmaLinux 10 DNF 4.20.0
with `repo_gpgcheck=1`.

```text
SOW_RUN_DOCKER_COMPAT=1 \
SOW_COMPAT_APT_IMAGE=ubuntu:22.04 \
SOW_COMPAT_DNF_IMAGE=almalinux:10 \
SOW_COMPAT_EL9_IMAGE=almalinux:9 \
SOW_COMPAT_EL8_IMAGE=almalinux:8 \
go test -count=1 -run TestDockerClientCompatibility/dnf-generation-pinned-mirrorlist -v ./test/compat
```

Observed client requests included:

```text
GET /_sow/v1/mirrorlist/latest/yum-test/el10/x86_64.txt 200
GET /_sow/v1/g/00000000000000000001/yum/test/x86_64/repodata/repomd.xml 200
GET /_sow/v1/g/00000000000000000001/yum/test/x86_64/repodata/repomd.xml.asc 200
GET /_sow/v1/g/00000000000000000001/yum/test/x86_64/repodata/<sha>-primary.xml.zst 200
GET /_sow/v1/g/00000000000000000001/yum/test/x86_64/repodata/<sha>-filelists.xml.zst 200
GET /_sow/v1/g/00000000000000000001/yum/test/x86_64/repodata/<sha>-other.xml.zst 200
GET /_sow/v1/g/00000000000000000001/yum/test/x86_64/Packages/p/pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm 200
```

DNF imported the SOW-generated repository signing key, accepted the detached
signature, created the metadata cache, read filelists and changelogs, and
installed the exact RPM. The targeted run passed in 7.162 seconds on the local
Docker environment.

The complete real-client matrix was then rerun with independent Nginx serving
trees and the Basic Auth fallback enabled:

```text
SOW_RUN_DOCKER_COMPAT=1 SOW_COMPAT_NGINX=1 \
SOW_COMPAT_APT_IMAGE=ubuntu:22.04 \
SOW_COMPAT_DNF_IMAGE=almalinux:10 \
SOW_COMPAT_EL9_IMAGE=almalinux:9 \
SOW_COMPAT_EL8_IMAGE=almalinux:8 \
go test -count=1 -v ./test/compat

--- PASS: TestDockerClientCompatibility (50.04s)
    --- PASS: TestDockerClientCompatibility/apt (1.31s)
    --- PASS: TestDockerClientCompatibility/apt-stable-history-pin (1.30s)
    --- PASS: TestDockerClientCompatibility/apt-immutable-snapshot-suite (1.30s)
    --- PASS: TestDockerClientCompatibility/dnf-stable-history-pin (1.63s)
    --- PASS: TestDockerClientCompatibility/basic-fallback-apt-and-dnf (2.17s)
    --- PASS: TestDockerClientCompatibility/dnf (2.38s)
    --- PASS: TestDockerClientCompatibility/dnf-generation-pinned-mirrorlist (1.93s)
    --- PASS: TestDockerClientCompatibility/dnf-el9-zstd (3.00s)
    --- PASS: TestDockerClientCompatibility/dnf-el8-gzip (3.11s)
    --- PASS: TestDockerClientCompatibility/dnf-generation-flip-keeps-inflight-client-pinned (3.37s)
PASS
ok github.com/pgsty/sow/test/compat 50.847s
```

The in-flight test deliberately pauses DNF after it has fetched G1 repomd,
removes the only indexed RPM, materializes/flips G2, then releases the same
client. DNF re-resolves the mirrorlist and requests the exact removed RPM from
the G2 generation; the request is 200 because G2 carries the retained,
unindexed G1 payload closure. A fresh G2 client reads only G2 repodata and its
repoquery is empty. The request log proves the two generation IDs differ and
contains no G2 repodata request from the in-flight client.

## Remaining release gate

This evidence proves the generation-pinned route and accurately bounds the raw
alias. It does not waive the compatibility migration: the captured Pigsty raw
baseurl inventory still needs an executable move/rollback to mirrorlist. The
apt-before-1.2 support decision also remains unresolved. Therefore the global
FR-26/FZ-06/NFR-05 status must not be reported as unconditionally passed.
