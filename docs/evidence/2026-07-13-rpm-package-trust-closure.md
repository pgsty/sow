# RPM package trust closure and current-source revalidation (2026-07-13)

> This is current-source evidence, not a Goal-completion declaration. Real
> R2/COS/Cloudflare/EdgeOne, production migration, legacy compatibility policy
> and operational metrics remain open.

## Product-source boundary

- `test/compat/cleandelivery/product-files.txt` currently enumerates 330 ordinary
  product files, including `internal/yumrepo/package_keyring.go`.
- The current stable product-source SHA-256 is
  `70f4d1f50469a2acf4ded5930f9f6d62a3b6ee743cd861bb13d470e36f9bd07c`;
  it does not reuse the superseded 329-file `c328bca0…8f20` identity.
- One preliminary clean-delivery run passed with 330 product files and 406
  delivery files. This documentation update supersedes that run's
  delivery/content identities, so they are intentionally omitted. Two final
  independent empty-cache runs remain pending.
- Environment: Go 1.26.5, Darwin/arm64; Docker compatibility uses Nginx 1.31.2,
  Ubuntu 22.04 and AlmaLinux EL8/EL9/EL10 clients.

Evidence below records the post-fix current-source gates, including the final
local migration rerun. The stable product digest above binds the product tree;
final delivery identities require frozen allowlisted documentation.

## Closed implementation gaps

### Packet-preserving RPM package trust

SOW now establishes package trust separately from signed YUM metadata:

- pure-Go RPM v3/v4 RSA/DSA verification covers legacy whole-package signatures
  and modern header signatures plus the signed payload digest;
- the package-keyring loader preserves primary self-certification/revocation
  packets and every signing-subkey binding, embedded primary-key-binding
  cross-signature and revocation packet instead of relying only on a collapsed
  current `Entity` view;
- binary OpenPGP keyrings are parsed byte-for-byte. Generic `TrimSpace` is
  forbidden because a trailing byte such as `0x0b` is valid packet data; only
  ASCII-armored keyrings accept outer textual whitespace before decoding;
- at the package-signature time, verification selects the newest
  cryptographically authenticated primary self-certification or subkey binding
  before checking validity. Signing flags, primary/subkey lifetime, outer
  self-certification/binding expiry, embedded cross-certification presence and
  expiry, and revocation all fail closed;
- an invalid newest policy never falls back to an older permissive policy.
  `KeySuperseded` and `KeyRetired` are prospective; compromise and unspecified/
  no-reason revocations are retroactive;
- provenance v3 binds the exact package-keyring SHA-256, signer/primary
  fingerprint, signature time, coverage, signed byte count and payload evidence;
- add, sync, L1, materialize, publication preparation and L4 all enforce the
  same package trust. Add snapshots its input in a private `0700` directory;
  publication hashes and verifies one stable CAS file descriptor and rechecks
  path/inode/type/size/mtime.

Tests cover a fixed 1333-byte binary public key ending in `0x0b`, armored outer
whitespace, primary and subkey renewal, later restrictive flags/lifetimes,
expired outer self-certifications/bindings, missing or expired cross-
certification, no-fallback from an expired newest cross-certificate, normal and
retroactive revocation, wrong key, future signature time, header/payload tamper,
and real PGDG/CentOS 4/5/7 packages.

### Present-body evidence and APT coordinates

An upstream `present` result no longer trusts pathname or size alone. New or
unproven bodies are opened through a stable handle and streamed to the exact
advertised SHA-256/size; RPM bodies additionally pass embedded-signature
verification. The FR-06 incremental exception is deliberately narrow:

- an unchanged first-valid DEB receipt may be reused;
- an RPM receipt may be reused only at schema v3 and only when its package-
  keyring SHA-256 matches the current immutable keyring;
- keyring rotation or a legacy v1/v2 RPM receipt forces body hash plus signature
  revalidation;
- when an existing CAS object newly enters a selected view, `pool.Verify` runs
  before the hardlink is created.

APT present suppression matches the exact repository-relative component, name,
version and size inside the selected view/architecture. Component extraction
first removes the exact configured `repo.path + "/"` prefix and accepts only the
relative `pool/<configured-component>/...` shape. Regression tests prove that a
repo root containing `pool/main`, or a same-digest main-to-contrib move, cannot
hide a required placement.

## Independent adversarial audit

The bounded Blind Hunter review examined the packet-preserving historical
policy selector, cross-certification and revocation semantics, present-body
receipt reuse, new-view CAS verification and APT component matching. Earlier
review rounds found actionable defects; each was reproduced, fixed and promoted
to a permanent regression. Its final result for that bounded scope was exactly:

```text
NO ACTIONABLE FINDINGS
```

After that bounded result, a separate review found that the production parser
unconditionally trimmed binary OpenPGP input. That defect is now closed with the
fixed binary and armored regressions above. Consequently `NO ACTIONABLE
FINDINGS` must not be misread as proof that the later parser change needs no full
regression. The post-fix ordinary and full-race suites now both pass.

## Current-source validation

After the binary byte-preservation fix, current source produced:

```text
go test -count=1 ./...
  PASS; internal/cli 280.274s; all packages including compat and clean-delivery

go test -race -count=1 ./...
  PASS; internal/cli 364.215s; all packages including compat and clean-delivery;
  no race report

go vet ./...                         PASS 1.35s
go mod tidy -diff                   PASS; empty diff 0.10s
go mod verify                       PASS; all modules 1.51s
git diff --check                    PASS
third_party/cavaliergopher-rpm      PASS 1.79s
edge npm test                       PASS 26/26, 0.66s
```

Current targeted yumrepo and CLI publish suites also pass the fixed 1333-byte
trailing-`0x0b` binary key and armored outer-whitespace regressions.

One earlier full-race attempt reported a transient test-fixture parse failure.
The same focused case then passed 20 consecutive runs, and the subsequent full
race run passed. This report preserves that observation rather than hiding it;
there was no race detector report.

Post-fix `CGO_ENABLED=0` cross-builds passed:

```text
linux/amd64  static ELF   47,021,598B   SHA-256 ecba281e…
linux/arm64  static ELF   44,641,199B   SHA-256 719721df…
darwin/amd64 Mach-O       48,715,664B   SHA-256 7e5a1b43…
darwin/arm64 Mach-O       46,728,786B   SHA-256 9aa42830…
```

The ellipses intentionally denote recorded prefixes, not invented full hashes.
They are not the final product digest. The post-fix `govulncheck@v1.6.0` run
reported zero reachable vulnerabilities and zero vulnerable imported packages;
one required-module advisory is not called by the production graph.

## Real package, client and upstream evidence

The post-fix Docker/Nginx compatibility package passed in 93.128s (wall 93.99s):
the Docker client suite took 53.12s, the public and Basic Nginx allowlists 5.03s
each, and the YUM bridge 28.57s (EL8 11.18s, EL9 11.37s, EL10 5.84s). A real apt
client installed from generated signed APT metadata through Nginx. AlmaLinux
EL10/EL9 consumed zstd and EL8 consumed gzip YUM metadata; signed YUM pair and
generation-pinned mirrorlist checks passed. This is real client evidence, but
it does not traverse Cloudflare or EdgeOne.

The first invocation accidentally omitted `/usr/local/bin` from `PATH`. It
failed with `docker: executable file not found` before any of its 11 Docker
subtests launched; that harness error is not counted as a product run. Adding
the actual Docker location and rerunning the complete package produced the
authoritative PASS above.

The post-fix Pigsty package-trust gate passed in 2.59s (package 3.246s, wall
4.12s), including the missing-key rejection and the trusted-key DNF install plus
`rpm -K` positive path for the public Pigsty RPM fixture.

The post-fix official PGDG opt-in sync gate passed in 101.94s (package 102.565s,
wall 103.44s):

```text
APT first: candidates=3938, download=1, present=0, filtered=3937
APT replay: download=0, present=1
YUM first: candidates=1344, download=12, present=0, filtered=1332
YUM replay: download=0, present=12
receipts: DEB=1, RPM=12; CAS=536,434 bytes; evidence=5
materialize: entries=13, files=45, repository_bytes=709,543, linked=13
serving: apt_suites=1, yum_repos=1, generations=1, pointers=1
```

This run exercises current receipt reuse and exact-body verification while the
permanent suite separately proves that keyring rotation and legacy RPM receipts
force revalidation.

The post-fix fixed-digest real MinIO/SigV4 gate passed in 0.76s (package 1.284s,
wall 2.05s), including conditional-mutation fail-closed behavior. MinIO remains local
S3-compatible evidence and is not R2/COS evidence.

## Scale, fuzz and migration evidence

The post-fix performance commands were rerun under idle conditions and passed:

```text
perf package/wall        32.095s / 37.52s
APT manifest scan        40,681 files / 47,155,427,190 bytes / 4.224s
YUM manifest scan        31,629 files / 42,707,068,318 bytes / 3.436s
combined scan            72,310 files / 89,862,495,508 bytes / 7.661s /
                         18 workers
materialize              50,000 entries / 11.960s; reconcile 2.793s /
                         workers 8, peak 8, retained growth 69,328B
publish plan             50,000 entries -> 1 change / 16.316ms / one object /
                         retained growth 40,008B
YUM streaming            50,000 packages / 4.680s / retained growth 30,648B /
                         compressed 152,302B / repomd SHA-256 103839a4…
APT streaming            package 3.693s / wall 3.99s / elapsed 3.012s /
                         50,000 packages / worker peak 4 /
                         retained 240,416B / max RSS 300,498,944B /
                         spool 32,126,600B / chunk peak 256
```

Post-fix fuzz gates passed: URL resolution observed 540,487 executions in
6.756s, Release parsing 444,076 in 6.368s, and RPM-header parsing 5,161,146 in
11.396s. The configured fuzz windows were five/five/ten seconds; counts are
scheduler observations, not thresholds.

Migration gates passed:

```text
legacy audit             176 targets / 44 families / 7.42s
                         root 52 / APT 70 / YUM 14 / Docker 40
                         dispositions 117 / 31 / 18 / 8 / 2
                         TSV 177 lines / SHA-256 d2b7edf2…
audit negative suite     13/13 / 40.59s
zero-byte adopt/rollback 7 groups / 2.71s
writer-fence preflight   13/13 / 0.97s
targeted Go ordinary     28 tests / 0 fail / 0 skip / 17.52s
targeted Go race         28 tests / 0 fail / 0 skip / 26.80s
                         identical set SHA-256 f86cf3b6…
total                    96.01s
```

These are the post-fix final local migration results; the run artifacts were
captured at `/tmp/sow-final-migration-validation.UTQSIC`. They prove the local
executable migration surface and failure checks. They do not prove production
writer revocation, cutover or rollback.

## Remaining acceptance gates

The long-running Goal remains active. The following are explicitly **OPEN**:

- real R2 and never-versioned COS conditional mutation/deletion, checkpoints,
  inventory, failure replay and object read-back;
- real Cloudflare and EdgeOne purge/CDN behavior, deployed Worker/function,
  two-token clean-cache normalization, anonymous/WAF negatives and multi-PoP
  observation;
- production legacy-tree staging and cutover, writer freeze/revocation, Makefile
  retirement, rollback, and post-cutover URL comparison;
- owner policy for apt < 1.2 fixed aliases, raw-YUM alias migration, and the
  Pigsty release that freezes EL8 commercial support;
- G1 and ANTI-01/02/03 operational, cost and latency measurements;
- two final independent clean-delivery runs with recorded delivery/archive
  identities.

Until those gates are successfully run or explicitly waived in writing, this
report cannot support marking the Goal complete.
