# Generic derived-state residue recovery evidence

Date: 2026-07-28

Scope: V-84, local control-state inventory and recovery only

Baseline: `71dcb5d`

## Defect and authority boundary

The shared derived-state writer creates a random private file before its
durable replacement carrier. A process death in that interval can leave an
unjournaled write temporary. Generated publication sources and root-level
package-completion receipts are outside the specialized materialization and
serving journal cleaners, so L1/fsck did not inventory or recover them.

The recovery authority is intentionally narrower than `.sow/**`. It covers
only immediate `.sow` control files, `.sow/generated/**`, and the
materialization, serving and serving-removal journal directories. Canonical
Git, cache, CAS, sync/stage/tmp, materialized/origin and repository payload
trees are excluded.

## Implemented closure

- The inventory walks the managed surfaces in 128-entry batches and binds the
  state root, every traversed directory and every recoverable regular file
  without following symlinks. Depth, directory, entry, replacement
  transaction, temporary and directory-stage counts are independently
  bounded.
- L1 and local fsck report durable replacement carriers, current random
  write/install/removal temporaries and V-80 empty directory stages as
  critical findings. Malformed related names, unsafe ownership/mode, aliases,
  special objects, replacement races and excess cardinality fail closed.
- `fsck --recover` converges strict V-80 directory stages first, durable
  replacement carriers second and remaining unowned random file temporaries
  last. It performs a fresh bounded inventory between classes and requires a
  final clean inventory.
- File removal retains the admitted inode through random no-replace
  quarantine, repeated root/directory/file security checks, unlink and parent
  fsync. A crash while retiring an existing removal quarantine leaves one
  grammar-closed removal coordinate that the next replay can recover.
- A bare legacy `.tmp-<16hex>` name is the former predictable writer
  coordinate and is not deletion authority. It remains byte-identical,
  ordinary writers do not overwrite or delete it, L1/fsck reports it as
  evidence, and automatic recovery refuses it. A 16-hex base already isolated
  under a random 32-hex removal quarantine is recoverable.
- V-80 `.preserved-<nonce>` directory replacements are likewise reported and
  never auto-deleted. Their presence aborts recovery before any other residue
  is mutated.
- The shared writer reserves temporary-shaped canonical basenames and refuses
  current unjournaled random residue in its exact output directory, directing
  the operator to `sow fsck --recover`. Product commands using `--recover`
  execute the same global convergence before canonical mutation.

## Fault and boundary matrix

Real temporary filesystems cover:

- root and nested generated write, install, removal and directory-stage
  residues;
- a prepared durable replacement transaction whose source temporary must not
  be deleted before transaction replay;
- ordinary L1/fsck no-mutation and explicit CLI recovery;
- hardlink admission and a hardlink inserted at the final unlink seam;
- generated-directory and state-root replacement during removal;
- strict-directory nonempty evidence, preserved directory replacement and
  predictable legacy temporary refusal;
- generated symlink, malformed root/generated names, special mode, excluded
  payload/scratch subtrees and the 4,096-record boundaries;
- subprocess death at the final unlink boundary followed by successful replay;
- destination-name reservation and legacy deterministic sibling preservation.

## Current-source focused verification

```text
focused ordinary                         PASS 1.734s
focused race                             PASS 2.607s; no race report
all DerivedState ordinary                PASS 17.334s
all DerivedState race                    PASS 21.911s; no race report
preserved-projection/derived adjacent    PASS 19.023s
same adjacent race                       PASS 24.453s; no race report
43 fsck/verify adjacent ordinary         PASS 123.942s
43 fsck/verify adjacent race             PASS 169.269s; no race report
go vet ./internal/cli                    PASS
staticcheck ./internal/cli               PASS
git diff --check                         PASS
```

The focused commands include the nine new top-level tests; the complete CLI
corpus now contains 894 top-level tests.

## Exhaustive regression and static gates

The final-source 894-test CLI corpus passed in six exhaustive ordinary shards:

| shard | duration |
|---|---:|
| A-F | `641.459s` |
| G-M | `947.251s` |
| N-O | `256.828s` |
| P-Q | `1231.008s` |
| R-V | `539.566s` |
| W-Z and other | `181.802s` |

The same six shards passed under the race detector in `660.975s`,
`984.604s`, `255.345s`, `1317.880s`, `541.354s` and `240.550s`, with no
race report. Every non-CLI package passed serial ordinary and race execution
in `129.01s` and `200.53s`, including compat and clean-delivery. Full
`go vet ./...`, Staticcheck, `go mod verify` and diff hygiene passed.

## Compatibility, scale and platform evidence

- The fixed local Docker client matrix passed in `61.226s`: Ubuntu 16.04 apt
  1.2 and Ubuntu 22.04 apt 2.4 consumed signed Packages/Release/InRelease and
  by-hash; CentOS 7 YUM plus AlmaLinux 8/9/10 DNF consumed primary/filelists/
  other, gzip for EL7/8, zstd for EL9/10, detached repository signatures,
  package signatures and paired generation flips.
- The digest-pinned local MinIO S3/SigV4 test passed in `1.401s`. Rebuilt
  Cloudflare/EdgeOne bundles were unchanged and all 47 shared edge contracts
  passed in `131.136ms`.
- A read-only scan of `/Users/vonng/pgsty/repo` found 57,399 DEBs
  (`60,072,677,820` bytes) and 34,250 RPMs (`46,254,476,260` bytes):
  91,649 package files / `106,327,154,080` bytes with 18 workers in
  `10.129s`. Manifests and runs were written only below the test temporary
  directory.
- The synthetic 50k unique-content adoption used 8/8 import workers:
  fixture `2.714s`, first adoption `6m15.292s`, effect-free replay
  `2m21.493s`, peak heap growth `124,720,496B`, retained growth `573,280B`
  and RSS growth `141,983,744B`. All 50k CAS objects, view entries,
  provenance receipts and cache rows matched.
- 50k hardlink materialization used 8/8 workers in `15.028s` and exact
  reconciliation in `2.586s`, with `14,208B` retained heap growth. A
  50k/one-change publish plan produced one object in `13.395ms` with
  `77,272B` retained growth. YUM streamed 50k RPM records and signed all
  metadata in `6.382s`, retained growth zero. The same materialize,
  one-change plan and YUM streaming tests passed under the race detector in
  `21.92s`, `0.70s` and `80.93s` respectively, with no race report.
- Four `CGO_ENABLED=0 -trimpath` production builds passed:

| target | bytes | SHA-256 |
|---|---:|---|
| darwin/amd64 | 58,394,336 | `1bb09f14f7abddf90c71b6ce88054b88291d0a3ed51404b81190479eb2b720c4` |
| darwin/arm64 | 55,335,186 | `3a1906b38f238a8913a7c7d3ba99c9e508ce7421a73e1c9aa345fdeef95c3c1e` |
| linux/amd64 | 56,561,578 | `09ee1b84257a640c81f83dc2e531a1dde6f552715348eb454f09f6dfd4fa3c93` |
| linux/arm64 | 53,087,115 | `2ebbd4822ea3c05f21177b031ece0734babfad0ca6b14a7fe4f6473206f405a9` |

## External-state boundary

All mutation occurred below local temporary roots. No credential, network,
cloud resource, production repository, `/Users/vonng/pgsty/repo`, CO/COS or
Cloudflare production path was accessed.

## Terminal gates

All implementation, exhaustive ordinary/race, non-CLI, static, real local
compatibility, scale and platform gates above passed against the final V-84
source. Final post-ledger clean-delivery identities are emitted outside the
archive after the last documentation edit to avoid self-reference.
