# YUM shared-pool relative location PoC

This fixture gates the candidate managed YUM layout before its physical view
paths or renderer contract are frozen:

```text
repo/
├── pool/s/sow-yum-relative/{native x86_64 RPM,noarch RPM}
└── dists/el9/
    ├── x86_64/repodata/  # native + noarch
    └── aarch64/repodata/ # noarch only
```

Both views use package `location href` values rooted at
`../../../pool/...`. The metadata contains no deployment hostname, absolute
URL, or absolute filesystem path.

## Current result: original rejected, C2 redesign gate passed

AlmaLinux 9.8 with DNF 4.14.0 refreshes, locates, downloads, and installs from
the original views, but `dnf reposync` rejects `../../../pool/...` because it
escapes reposync's per-repo download directory. That parent-traversing renderer
policy is permanently rejected. The C2 redesign uses root-pool canonical
objects plus view-local regular hardlink aliases and safe `pool/...` hrefs; it
passes the full two-view client matrix before and after a copy that discards
hardlink identity. C2 is therefore adoptable. See
[`evidence/2026-08-01-almalinux-9.8.md`](evidence/2026-08-01-almalinux-9.8.md).

## Run

Requirements: Docker with Linux/amd64 container support and network access for
the image's DNF repositories.

```bash
test/poc/yum-relative-pool/run.sh
```

The command is an acceptance harness. It requires the original parent-traversal
candidate and Candidate A to be rejected, then requires B, C, C2, and a
non-hardlink-preserving C2 copy to pass. Expected rejection plus redesign
success exits 0; any result reversal exits non-zero.

The final fresh run exited 0. Its full stdout/stderr log is retained at
`/Users/vonng/repo/sow-v2-offline-current.tsU0P8/logs/yum-relative-pool.log`
(1,549 lines, 88,337 bytes), with SHA-256
`1315965767874fe7af543ad00b2e85c230139b661b0808e961d86874f1fe72b4`.
`KEEP_WORK=1` retained the host fixture at
`/var/folders/df/bfm8q07d7bv3kpjf1fjchq4m0000gn/T/sow-yum-relative-pool.JrJKRD`.
The executable fixture-source fingerprint (all non-evidence files except this
README, sorted per-file SHA-256 records) was
`df0305e916533a346d6660d6fafff5118c58224e492e550ce54ed0db212e6026`.
The run used image ID
`sha256:d2515c769e7b73f95c4fde38c0a505336ff38f14990c0b7253b77060a049a743`.

The default AlmaLinux 9 image is pinned by digest. Override it only when
expanding the compatibility matrix:

```bash
IMAGE=almalinux:9 test/poc/yum-relative-pool/run.sh
```

The script creates a host `mktemp` directory, bind-mounts it at `/work`, and
removes it on exit. Set `KEEP_WORK=1` to retain that isolated directory for
inspection. It never reads or writes `/Users/vonng/pgsty/repo`.

## Gate checks

- The x86_64 primary metadata contains exactly the native and noarch RPMs.
- The aarch64 primary metadata contains exactly the noarch RPM.
- Every package location is `../../../pool/...` and is neither an absolute URL
  nor an absolute path.
- Real DNF performs `makecache`, `repoquery --location`, download, and install
  from each view. The aarch64 view is selected with DNF's `--forcearch` and
  installs the architecture-neutral RPM.
- Real `dnf reposync` must download the native/noarch closure from x86_64 and
  only the noarch closure from aarch64. This check currently fails for both
  views; the harness treats this as the required rejection.

## Redesign matrix

The same run also exercises these non-absolute alternatives. Detailed evidence
is in [`evidence/2026-08-01-redesign-matrix.md`](evidence/2026-08-01-redesign-matrix.md).

| Candidate | Metadata location | DNF download/install | reposync | Main trade-off |
| --- | --- | --- | --- | --- |
| A | `xml:base="../../../"`, `href="pool/..."` | fail | fail | DNF turns the relative XML base into `http://../...` |
| B | view symlink `pool -> ../../../pool`, `href="pool/..."` | pass | pass | controlled symlink conflicts with current path-safety and generic static-copy contract |
| C | view-local hardlinks, `href="Packages/..."` | pass | pass | regular-file projection control |
| C2 | view-local `pool/...` hardlinks, `href="pool/..."` | pass | pass | recommended candidate; copy without links remains functional but duplicates bytes |

B, C, and C2 pass x86_64 native + noarch and forced-aarch64 noarch client
flows. C2 is the suggested candidate because it combines safe `pool/...`
locations, root-pool canonical ownership, and regular-file aliases. The same
two-view matrix also passes after a copy that deliberately discards hardlink
identity. This fixture provides evidence only; it does not implement a
production layout.
