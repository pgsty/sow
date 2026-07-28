# Preserved projection audit retirement evidence

Date: 2026-07-28

Scope: V-83, local POSIX filesystems only

Baseline: `ac53577`

## Implemented closure

SOW now inventories strict asset/package projection audit quarantines before
canonical recovery in `verify` L1 and `fsck`. Each finding contains the exact
name, kind, streamed content SHA-256, size and an inode-bound retirement token.
Neither ordinary audit nor `--recover` removes the object.

`fsck --retire-preserved-projection NAME --confirm TOKEN` is a separate,
local-only one-object mutation. It recomputes the token from the current held
descriptor and retains that descriptor through exact quarantine, repeated
byte/identity validation, unlink and directory fsync. Missing-coordinate replay
is harmless; replacements, aliases, unsafe metadata and stale tokens retain
evidence and fail closed.

Before retirement, a read-only bounded scanner proves there is no projection
or materialization intent, canonical Git transaction, catalog projection
marker, YUM cutover, serving/topology journal, or derived-state replacement
carrier. This quiescence check never performs recovery or changes directory
timestamps.

## Focused and exhaustive verification

| Gate | Result |
|---|---|
| focused inventory/retirement ordinary | PASS (`2.708s`) |
| focused inventory/retirement race, final source | PASS (`4.030s`) |
| adjacent fsck/verify/projection ordinary | PASS (`106.552s`) |
| adjacent fsck/verify/projection race | PASS (`146.896s`) |
| static analysis | `go vet ./...`, Staticcheck, module verify and diff check PASS |
| clean-delivery allowlist test | PASS (`2.270s`) |

Focused tests use real temporary filesystems and cover two repository kinds,
L1/fsck output, `--recover` non-deletion, wrong and stale tokens, same-byte
inode replacement, a hardlink introduced at the final unlink seam,
one-at-a-time behavior, response-loss replay, unsafe flag combinations,
malformed names and the 1,024-record boundary.

The final 885-test CLI corpus passed in six exhaustive ordinary shards:

| shard | duration |
|---|---:|
| A-F | `428.082s` |
| G-M | `579.014s` |
| N-O | `185.231s` |
| P-Q | `922.832s` |
| R-V | `405.696s` |
| W-Z and other | `128.132s` |

The same six shards passed under the race detector in `490.714s`, `747.932s`,
`195.898s`, `992.817s`, `446.093s` and `196.190s`, with no race report. All 17
non-CLI packages passed ordinary and race serial execution; the longest were
`internal/state` at `21.171s` ordinary and the clean-delivery package at
`35.603s` race.

## Protocol and platform regression

The final-source real local Docker compatibility package passed in `148.236s`.
Digest-pinned Ubuntu 16.04 apt 1.2 and Ubuntu 22.04 apt 2.4 consumed the
generated Packages/Release/InRelease/by-hash repositories. CentOS 7 YUM and
AlmaLinux 8/9/10 DNF consumed primary/filelists/other metadata, gzip for EL7/8,
zstd for EL9/10, repository/package signatures and paired generation flips.
All repositories and package sources were disposable loopback fixtures.

The fixed-digest local MinIO S3/SigV4 compatibility test passed in `0.78s`
(`1.644s` package). Rebuilding the shipped Cloudflare Worker and EdgeOne
bundles produced no diff; all 47 shared authorization, URL normalization,
mirrorlist, token stripping and Basic fallback contracts passed in
`130.650ms`. These are local protocol and executable-contract results, not
provider deployment claims.

Four CGO-free production CLI builds passed:

| target | bytes | SHA-256 | format |
|---|---:|---|---|
| darwin/amd64 | 58,284,064 | `aae3d1767bf7326eb9e13a68366b9d8b256232c579f4d8466d0193064d2eab3b` | Mach-O x86_64 |
| darwin/arm64 | 55,248,818 | `ffb2cf0d7c1df9fee36b2080a317ffcf1fd16376730c768306316ea82573c96a` | Mach-O arm64 |
| linux/amd64 | 56,445,041 | `bde9d5075ae7026fba7f517c34fef939371f0aab48f7f3ca6b1795677cc96054` | static ELF x86-64 |
| linux/arm64 | 52,928,410 | `49badd8bc5e92330abee848039322b4bdeb5b1ac07ccfb0cfdec6f4605db4001` | static ELF arm64 |

## External-state boundary

Every mutation uses a local temporary repository. No provider credential,
network, cloud resource, production repository, `/Users/vonng/pgsty/repo`, or
Pigsty production checkout write path is accessed.

## Terminal gates

All source, regression, static, compatibility and platform gates above passed.
Two final clean-delivery reconstructions from the ledger-bound source are
byte-identical; their product, delivery and archive identities are emitted by
the reconstruction command outside the archive so this evidence does not
create a self-referential digest. V-83 is closed as verified.
