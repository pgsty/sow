# Offline archive durable recovery and admission evidence

Date: 2026-07-15

Scope: local disposable fixtures only. No CO/COS/Cloudflare/EdgeOne production resource was read or written. All Go runs removed cloud credentials and forced proxy failure; the Linux runtime used Docker `--network none`.

## Product boundaries exercised

- legal ordinary gzip with a 900-byte FCOMMENT and a byte-prefixed ordinary gzip remains admissible;
- gzip FHCRC/payload CRC32/ISIZE and member boundaries are parsed as a stream rather than relying on Go's 512-byte header-string implementation limit;
- a SOW marker cannot be hidden in a later gzip member, after a malformed member boundary, after a complete tar EOF inside the same member, or behind an opaque byte prefix;
- the completed archive inode is linked into a `0700` private state directory and that directory is fsynced before the operation intent and canonical taint receipt;
- failure of that private directory fsync leaves no receipt, intent, or visible destination;
- post-receipt, post-link/pre-directory-sync, and post-directory-sync process exits replay to the exact old digest;
- a pending archive intent fences unrelated canonical mutations and is reported by L1 verification;
- `--asset-repo` keeps that intent through the asset ref, CAS import,
  selected-set journal, and directly hostable asset-tree transaction; a
  process stop before adoption replays the frozen archive before an advanced
  selector is allowed to run;
- adoption recovery rejects a rehashed journal whose source, destination,
  policy, or archive identity was changed;
- malformed tar barriers, legal 65535-byte FEXTRA fields, decompression
  budgets, canceled contexts, and a symlink substituted for the private stage
  directory have explicit negative/boundary coverage;
- an existing taint receipt with a newer commit witness is accepted only when
  the semantic ref coordinates, entry digest, counts, and policy are identical;
- after a controlled simulation advances `stable` behind the fence, recovery still installs bytes committed by the frozen old refs, exits, and a subsequent invocation produces the advanced view at a new destination;
- no staging filename appears below the Nginx-served destination tree;
- deterministic archive bytes remain identical across Darwin/arm64 and Linux/arm64 with Go 1.26.5.

Architecture contract: [ADR-0026](../adr/0026-offline-archive-projection-intent.md).

## Darwin runtime

Strict-offline focused normal run:

```text
go test ./internal/cli \
  -run 'OfflineArchive|ArchiveDirectoryCreationSyncsEachParent|ArchiveFilesystemMismatch|ArchiveDestination' \
  -count=1

ok github.com/pgsty/sow/internal/cli 38.454s
```

The identical selector under the race detector:

```text
go test -race ./internal/cli \
  -run 'OfflineArchive|ArchiveDirectoryCreationSyncsEachParent|ArchiveFilesystemMismatch|ArchiveDestination' \
  -count=1

ok github.com/pgsty/sow/internal/cli 52.232s
```

Post-review current-source regression set, including archive adoption,
scanner budgets, intent-directory-sync failure, semantic receipt recovery, and
the existing process-stop suite:

```text
go test ./internal/cli \
  -run 'Test(OfflineArchive|Materialize.*Archive|Archive)' \
  -count=1

ok github.com/pgsty/sow/internal/cli 44.592s

go test -race ./internal/cli \
  -run 'Test(OfflineArchive|Materialize.*Archive|Archive)' \
  -count=1

ok github.com/pgsty/sow/internal/cli 82.880s
```

Projection-intent integration, recovery, and L1 audit regression set:

```text
go test ./internal/cli \
  -run 'ProjectionIntent|ProjectionRecoveryRequired|OfflineArchivePostReceipt' \
  -count=1

ok github.com/pgsty/sow/internal/cli 48.894s
```

Static checks and cross-build:

```text
GOPROXY=off go vet ./internal/cli
GOPROXY=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go test -c ./internal/cli -o /tmp/sow-cli-linux-amd64.test

PASS
```

## Linux runtime

The Linux/arm64 test binary was cross-built from the same source and executed in the already-local `pgsty/u26a:build` image:

```text
docker run --rm --network none \
  -e SOW_RUN_REAL_CLOUD=0 -e SOW_RUN_REAL_UPSTREAM=0 \
  -e AWS_EC2_METADATA_DISABLED=true \
  -v /tmp/sow-cli-linux-arm64.test:/tmp/sow-cli.test:ro \
  pgsty/u26a:build /tmp/sow-cli.test \
  -test.run 'TestDeterministicTGZGoldenBytesAcrossSupportedPlatforms|TestOfflineArchiveDurableStageSyncPrecedesReceipt|TestOfflineArchivePostReceiptCrashNeverStagesBytesInServedTree|TestOfflineArchivePostLinkCrashReplayConverges|TestOfflineArchiveMarkerCannotBeHidden|TestOfflineArchiveMarkerParserLeavesOpaqueGzipUntouched' \
  -test.count=1 -test.v

PASS
```

Every named test and subtest passed on Linux, including real `linkat`, directory fsync, child-process exit/recovery, same-member tar tail rejection, and malformed gzip boundary rejection.

The golden digest on both supported runtime families is:

```text
ecd4e22913198b47f1760991bcf2f3043b4aafa60c5f202d4cf7e23222c0fd74
```

## Safety interpretation

An in-band marker is an integrity tripwire, not an external signature. A party able to unpack and intentionally rebuild an archive can remove it; canonical taint receipts and the managed public/gated closure remain authoritative inside a SOW state root. A destination that cannot support an atomic hard link is never exposed partially: ordinary cross-device paths fail before receipt, while a late platform `EXDEV` retains the durable intent and fails closed.
