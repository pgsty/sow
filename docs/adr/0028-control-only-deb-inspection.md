# ADR-0028: Control-only DEB inspection

Status: accepted (2026-07-16)

## Context

SOW needs a DEB's control paragraph and exact whole-file identity to build APT
metadata and verify legacy/index membership. It never needs to enumerate the
installed files in `data.tar.*`.

`pault.ag/go/debian/deb.Load` parses the control archive but also constructs a
decoder for `data.tar.*`. Its zstd/xz adapters return a no-op closer. A real
Pigsty-v1 adoption followed by catalog rebuild therefore retained one unused
decoder per package: the process reached a measured 51.6 GiB physical footprint
before it was interrupted. This violates the streaming-memory contract even
though package bytes themselves were never collected into a Go slice.

## Decision

DEB inspection continues to use the frozen `pault.ag/go/debian` parsing stack,
but composes its exported layers directly:

1. `deb.LoadAr` parses the ar container and `deb.ArEntry.Tarfile` opens only the
   unique `control.tar[.*]` member.
2. `control.Unmarshal` decodes the unique regular `control` file. The
   `debian-binary` member must be exactly `2.0\n`; one non-empty
   `data.tar[.*]` member must exist, but its compressor is not instantiated.
   Duplicate structural members fail closed.
3. The caller-owned file descriptor is SHA-256 hashed before control parsing
   and again afterward. Size, digest, inode/mtime checks and index identity bind
   the returned metadata to the complete unchanged DEB bytes.

This is orchestration of the approved parser library, not a new DEB/control
format implementation. SOW does not claim to validate every installed payload
member during metadata inspection; real `apt update/install` compatibility is a
separate acceptance gate.

## Consequences

- Memory is bounded by worker/parser buffers rather than accumulated unused
  data decoders.
- A malformed or duplicate DEB container is rejected, while an irrelevant data
  compressor is never trusted or opened merely to read control metadata.
- Whole-file signed-index/CAS identity remains mandatory. No package body can
  enter a view based only on its filename or control paragraph.
- Regression coverage includes an intentionally unreadable `data.tar.zst`,
  structural-member negatives, ordinary/race tests, and the full disposable
  legacy-tree recovery/replay measurement.
