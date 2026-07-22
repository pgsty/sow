# Canonical Apply stage identity evidence

Date: 2026-07-22

Scope: V-78, local filesystem and isolated Linux container only

Baseline: `5490fb6`

## Defect and acceptance boundary

Projection intents already froze every manifest/config stage by canonical path,
size and SHA-256, but the canonical state transaction rebuilt its journal and
worktree from stage pathnames. A replacement between projection prepare,
journal durability and installation could therefore authorize one inode and
commit another. The same pathname-reopen boundary existed during restart
recovery.

The accepted implementation closes that boundary without changing the public
journal schema identifier or dropping legacy v1 recovery. It also closes the
adjacent Git coordinate window exposed by an exact stage commit: raw `HEAD`,
its target ref, the index, the complete tree and the canonical worktree must all
remain the frozen transaction vector through post-commit validation and any
rollback.

## Implemented closure

- `ApplyOptions.ExpectedStages` is an exact canonical-path-to-byte-identity
  contract. A non-nil map must have precisely the same keys as the staged map;
  malformed, missing, additional or mismatched identities fail before the
  transaction journal is created.
- Stage admission uses `Lstat` plus a retained `O_NOFOLLOW|O_NONBLOCK`
  descriptor. Hashing and installation stream through that descriptor with a
  256 KiB buffer and a `size+1` bound. Inode, path, type, size, mode,
  modification time and digest are rechecked before and after consumption.
- The journal is built from retained descriptors. `Apply`, `Recover` and
  `RecoverAborted` pass the same bound set into canonical installation; no
  approved stage pathname is reopened after the journal boundary.
- Asset and package projection paths derive the complete manifest plus config
  identity vector from their durable intent. Ordinary add/rm, direct asset
  materialization and inputless recovery all inject that vector.
- New journals preserve exact raw `HEAD` in optional `expected_head_raw` while
  retaining schema `sow-local-transaction/v1`. Existing v1 journals without
  the field continue to recover with the prior hash-only contract; every new
  journal rejects same-hash branch/detached-HEAD switching.
- Native `HEAD.lock` and target `<ref>.lock` capabilities are retained through
  commit/index/tree/worktree verification. Marker creation is create-only,
  fully synced and stale recovery is process-instance bound. Late release
  failures leave a committed journal that `Recover` can finish; rollback
  failures still release both native locks without deleting foreign evidence.
- The manual commit builder validates the exact index/tree vector, rejects
  gitlinks and noncanonical index flags, supports unborn, packed-only and
  detached HEAD, and restores exact raw HEAD while the guard is held.
- The archive cleanup-drift tests now inject cleanup failure explicitly rather
  than relying on `chmod 000`. A root Linux container legitimately bypassed the
  old permission assumption; the deterministic seam preserves the production
  cleanup function and makes root/non-root CI behavior identical.

## Current-source verification

All credential variables and real-cloud/real-edge/real-upstream opt-ins were
blank or disabled. No command below contacted an object store, CDN, provider
control plane, upstream repository or production repository.

```bash
go test ./internal/state ./internal/cli \
  -run 'Stage|Transaction|Projection|IntentWriteFailureReportsStageCleanupDrift' \
  -count=1
# state 3.918s; CLI 159.519s

go test -race ./internal/state ./internal/cli \
  -run 'Stage|Transaction|Projection|IntentWriteFailureReportsStageCleanupDrift' \
  -count=1
# state 4.421s; CLI 341.077s; no race report

go test ./... -count=1 -timeout=30m
# CLI 1478.692s; all packages PASS
# publish 25.462s; repository 16.554s; serving 30.255s; state 58.109s
# upstream 27.703s; verify 15.033s; yumrepo 22.525s
# compat 17.522s; clean-delivery 2.891s

go vet ./...
/Users/vonng/go/bin/staticcheck ./...
git diff --check
# PASS

go test ./test/compat/cleandelivery -count=1
# post-document delivery closure PASS
```

The focused matrix includes different-byte and same-byte inode replacement,
FIFO replacement without blocking, growth/truncation/in-place mutation,
complete-vector revalidation, hardlink-to-canonical rejection, raw HEAD branch
switches before and after intent, detached/unborn/packed-only HEAD, native lock
collision and stale recovery, late lock-release failure, rollback failure,
foreign index/tree/worktree drift, committed and aborted replay, asset/package
intent drift and inputless recovery.

`CGO_ENABLED=0 go test -c -trimpath ./internal/cli` produced the following
current-source test binaries:

| Target | SHA-256 |
|---|---|
| Darwin amd64 | `add3b74eaec4965f664eb5aa865404c3ee2f3c4e7898f567e1b0c6ca87cda00d` |
| Darwin arm64 | `869353ca65a2d12fb6c7fb518ac5dd9311df0fa32e6f95dc3a605f2daf94090a` |
| Linux amd64 | `1732c6d3a1c7f4afb4c86c908abcab81c1d166d06970b919be91071d4ebe5ab3` |
| Linux arm64 | `9626a810dfd74d9e2425b4b7a7027c305bf22a42a8ea840a2b0ca72113b37152` |

The final Linux arm64 binary ran the focused set as root in
`debian:13-slim` with no network, a read-only container, read-only source and
binary mounts, and only `/tmp` as tmpfs:

```bash
docker run --rm --platform linux/arm64 --network none --read-only \
  --mount type=bind,src=/tmp/sow-v78-linux-arm64.test,dst=/sow.test,readonly \
  --mount type=bind,src="$PWD",dst=/workspace,readonly \
  --tmpfs /tmp:rw,exec,nosuid,nodev --workdir /workspace/internal/cli \
  debian:13-slim /sow.test \
  -test.run='Stage|Transaction|Projection|IntentWriteFailureReportsStageCleanupDrift' \
  -test.count=1
# PASS
```

## Review disposition and external boundary

Blind Hunter and Edge Case Hunter independently returned no findings on the
review-final source. The implementation review did identify exact raw-HEAD
freezing as an adjacent correctness requirement; the optional field above is a
backward-compatible v1 extension, so old incomplete journals remain accepted.
No frozen intent gap was found and `review_loop_iteration` remains zero.

All mutations occurred below isolated local temporary roots. This run did not
read or write `pro`, Cloudflare production resources, CO/COS, any object store,
CDN, Worker, EdgeOne function, upstream package repository or production
repository. It strengthens FR-28/NFR-09 local transaction interruption and
replay evidence only; it does not upgrade any real-cloud, provider, CDN or
production-migration status.
