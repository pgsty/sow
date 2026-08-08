# YUM shared-pool redesign candidates — 2026-08-01

> **Historical v0.2 candidate matrix.** C2 was selected only because reposync was then mandatory. The released design rejects its object-storage duplication cost and adopts root-Pool parent-relative hrefs with default EL reposync explicitly unsupported; see the maintained [compatibility design](https://sow.pgsty.com/docs/design/compatibility/). The measured rows below remain factual.

## Scope and runtime

This is follow-up evidence after the original `../../../pool/...` href failed
the reposync gate. It uses the same RPMs, x86_64/native + noarch projection,
forced-aarch64/noarch projection, pinned AlmaLinux 9.8 image, and DNF 4.14.0.
No absolute package-location URL or deployment hostname is present in metadata;
no schema change or renderer implementation is involved. The local client
source itself is identified by a normal `file:///work/...` repository baseurl.

Final fresh acceptance-harness run:

```text
status: 0
retained log: /Users/vonng/repo/sow-v2-offline-current.tsU0P8/logs/yum-relative-pool.log
host work: /var/folders/df/bfm8q07d7bv3kpjf1fjchq4m0000gn/T/sow-yum-relative-pool.JrJKRD
log size: 1,549 lines, 88,337 bytes
full log SHA-256: 1315965767874fe7af543ad00b2e85c230139b661b0808e961d86874f1fe72b4
executable fixture-source fingerprint: df0305e916533a346d6660d6fafff5118c58224e492e550ce54ed0db212e6026
image ID: sha256:d2515c769e7b73f95c4fde38c0a505336ff38f14990c0b7253b77060a049a743
image reference: almalinux:9@sha256:d2515c769e7b73f95c4fde38c0a505336ff38f14990c0b7253b77060a049a743
```

The run ended with:

```text
REDESIGN HARNESS PASS: A rejected; B/C/C2 and non-hardlink C2 copy passed.
POC HARNESS PASS: parent-traversal rejected; C2 shared-pool hardlink projection is adoptable.
```

For each candidate and architecture view, the runner executes:

```text
dnf makecache
dnf repoquery --qf '%{name} %{arch} %{location}'
dnf download
dnf install
dnf reposync
```

Successful download and reposync outputs are byte-compared with the source
pool. The aarch64 view must contain the noarch RPM and must not contain the
x86_64 RPM.

## Result matrix

| Candidate/view | makecache | query | download | install | reposync |
| --- | ---: | ---: | ---: | ---: | ---: |
| A x86_64 | 0 | 0 | 1 | 1 | 1 |
| A aarch64 | 0 | 0 | 1 | 1 | 1 |
| B x86_64 | 0 | 0 | 0 | 0 | 0 |
| B aarch64 | 0 | 0 | 0 | 0 | 0 |
| C x86_64 | 0 | 0 | 0 | 0 | 0 |
| C aarch64 | 0 | 0 | 0 | 0 | 0 |
| C2 x86_64 | 0 | 0 | 0 | 0 | 0 |
| C2 aarch64 | 0 | 0 | 0 | 0 | 0 |
| C2 copied x86_64 | 0 | 0 | 0 | 0 | 0 |
| C2 copied aarch64 | 0 | 0 | 0 | 0 | 0 |

Zero is success. The exact compact output is preserved in
[`redesign-matrix.txt`](redesign-matrix.txt).

## A — relative `xml:base`

`createrepo_c --baseurl ../../../` natively produced:

```xml
<location xml:base="../../../" href="pool/s/sow-yum-relative/sow-yum-relative-native-1.0-1.x86_64.rpm"/>
```

Both views passed metadata refresh and query. Query reported `pool/...`, but
download and install failed because DNF interpreted the relative XML base as a
host-like HTTP URL:

```text
Curl error (6): Couldn't resolve host name for http://../pool/... [Could not resolve host: ..]
```

Reposync also returned 1. This option preserves a single regular-file pool and
the whole Repository is a normal static tree, but it is not client-compatible
and still embeds parent traversal in metadata. **Candidate A fails.**

## B — view-local symlink

Each view contains:

```text
pool -> ../../../pool
```

Primary metadata uses only safe-looking view-local locations:

```xml
<location href="pool/s/sow-yum-relative/sow-yum-relative-native-1.0-1.x86_64.rpm"/>
```

Both views passed all five client operations, and the downloaded bytes matched
the shared pool. A POSIX `cp -a` of the whole Repository retained a resolvable
link, so a symlink-preserving copy works.

However, this is not a clean fit for the current product constraints:

- it introduces a symlink in a SOW-controlled architecture view, while current
  path rules reject controlled symlink components;
- a generic static copier/object store does not necessarily preserve symlink
  semantics, so direct rsync/rclone-style portability is conditional on link
  handling;
- the apparent safe href depends on filesystem link resolution outside the
  view.

**Candidate B is client-compatible but does not satisfy the current path-safety
and generic static-copy contract without changing those contracts.**

## C — view-local regular-file hardlinks

Each view uses `Packages/...` hrefs. The x86_64 view hardlinks native + noarch;
the aarch64 view hardlinks noarch only. The pool remains the canonical name:

```text
native: pool inode == x86_64/Packages inode, link count 2
noarch: pool inode == x86_64/Packages inode == aarch64/Packages inode, link count 3
```

Both views passed makecache, query, byte-checked download, install, and
byte-checked reposync. There are no symlinks, parent-traversing hrefs, absolute
paths, or domains. The Repository is a regular-file static tree; copies that do
not preserve hardlink identity still work because every projected path carries
complete package bytes.

Trade-offs remain:

- local creation requires pool and views on the same filesystem;
- tools that do not preserve hardlinks duplicate package bytes at the copied
  destination, so remote/static delivery no longer retains physical dedupe;
- changesets and publication treat each view-local package path as a physical
  path even though local source inodes are shared.

**Candidate C is a passing regular-file/path-safe control, but its
`Packages/...` namespace differs from the desired pool-shaped projection and
changes the delivery-dedupe model.**

## C2 — view-local `pool/...` regular hardlinks (v0.2 choice)

C2 keeps `<repo>/pool/...` as canonical ownership and creates real directories
with regular-file aliases inside each architecture view:

```text
repo/
├── pool/s/sow-yum-relative/*.rpm                 # canonical objects
└── dists/el9/
    ├── x86_64/pool/s/sow-yum-relative/*.rpm      # regular hardlink aliases
    └── aarch64/pool/s/sow-yum-relative/noarch.rpm
```

Metadata contains safe, view-local paths without parent traversal:

```xml
<location href="pool/s/sow-yum-relative/sow-yum-relative-native-1.0-1.x86_64.rpm"/>
<location href="pool/s/sow-yum-relative/sow-yum-relative-neutral-1.0-1.noarch.rpm"/>
```

The canonical native object and x86_64 alias shared one inode with link count
2. The canonical noarch object and both view aliases shared one inode with link
count 3. Both original views passed the complete five-operation matrix,
including byte-checked reposync to view-local `pool/...` paths.

Ownership behavior was verified in isolation: removing the whole aarch64 Dist
alias tree left the root-pool noarch object and x86_64 alias present, on the
same inode with link count reduced from 3 to 2. The intended lifecycle rule is
therefore:

- root pool owns canonical objects;
- architecture views own only regular-file hardlink aliases;
- `dist rm` unlinks that Dist's aliases and metadata, never the root-pool
  canonical object.

The runner then copied the entire repository with:

```text
cp -R --no-preserve=links repo copied-repo
```

Root pool and both aliases became three independent regular files (link count
1 and distinct inodes). The copied x86_64 and aarch64 views still passed all
five client operations and byte checks. Functional static portability is thus
independent of hardlink preservation; capacity dedupe is not.

Hardlink creation uses plain `ln` under `set -e`. An unsupported filesystem or
cross-device projection fails the build; the candidate intentionally has no
copy fallback, because silent fallback would make capacity and generation
semantics environment-dependent.

**C2 was the suggested v0.2 redesign candidate:** it passes every tested client,
keeps safe `pool/...` hrefs, preserves canonical root-pool ownership locally,
and remains functionally copyable as a regular-file tree. Its explicit cost is
that non-hardlink-preserving delivery repeats package bytes per view.

## Decision boundary

The original layout and Candidate A must remain unfrozen. B, C, and C2 are
evidence for architecture selection, not authorization to modify schema,
renderer, or CLI. C2 was the v0.2 candidate; B is only viable if the
product explicitly allows controlled symlinks and defines copy behavior.
