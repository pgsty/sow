# Gated Pro exact-copy adoption and activation evidence (2026-07-17)

## Boundary

This run used only an APFS clone of `/Users/vonng/pgsty/repo/pro` below
`/private/tmp`. The production source was read and hashed, never selected as a
SOW root and never written. No Cloudflare, COS, CDN, DNS, or production origin
was contacted. In particular, the `pro` Cloudflare bucket and
`pro.pigsty.io` were not used because the production-isolation gate rejects
both identities.

The final activation fixture was:

```text
/private/tmp/sow-pro-activation-fixed-20260717.cNshf8
binary_sha256=ef272fe095dd59b547fde003c036f6969e12a9df331621743b06009f75eb6bd0
config_sha256=70252361b705105d9a35ad85e021d8c4a7814331e5eb388850f582b50cdc4741
```

Its active asset owner uses physical `path: pro`, gated pool, remote
`public_path: gated/pro`, and both final target affinities. The zero-byte
legacy `pro/checksums` is excluded from the source baseline and is replaced in
the canonical stable view by a reviewed, non-empty `sow add` input. The source
file remains present and untouched at zero bytes.

## Transactional confidentiality regression

The initial negative run exposed a real defect: `init --adopt-content` rejected
gated content entering `latest`, but only after all 16 objects / 23.5 GB had
already entered CAS. `adoptLegacyContent` now performs a transaction-wide view,
repo-membership, allowed-pool, and public-pool admission before any CAS object
write. The regression test additionally requires zero CAS objects after the
rejection.

On the rebuilt binary, the exact-copy negative run returned exit 4:

```text
scanned repo=asset-pro-gated files=15 bytes=23497439223 scope_full=true
sow: adopt legacy content: confidentiality closure violation:
repo asset-pro-gated default_pool gated cannot enter view latest
```

Immediately afterwards:

```text
find .pool/sha256 -type f | wc -l = 0
du -sk .pool = 0
```

Focused ordinary and race tests passed, followed by the complete
`^TestInitAdoptContent` family in 76.920 seconds ordinary and 125.613 seconds
under the race detector.

## Stable adoption, checksum replacement, and replay

The stable adoption imported the 15 non-empty legacy archives:

```text
payloads=15
bytes=23497439223
pool=gated
receipts=15
commit=fa246c2b115f40e414b61bcd1c11d9183681840b
```

The deterministic checksum input is
`docs/migration/fixtures/pro-v4.4.0-checksums.sha256`:

```text
sha256=cc58dd54ee561c16b1a9728a5d45225690552e600cab0b9ab7122e81413c2fe9
lines=15
bytes=1479
```

`sow add ... --repo asset-pro-gated --dest checksums` committed that file to
stable as an ordinary gated asset:

```text
added files=1 replaced=0 commit=75b4516bea5762082531584895bb4eeddb47ff6b
asset tree entries=16 linked=16 pruned=0
```

The physical source baseline remains 15 entries; the stable view is the
append-only union with the generated checksum object:

```text
source_manifest_sha256=bc4d58d464094ce8752d1c7a1048076e1eda7528672d63cb16c587c14a549ba8
source_manifest_entries=15
stable_view_sha256=b5958778a8669831dee92d4930cdeed7dfd00005748ea81d2ac03b4332acad8b
stable_view_entries=16
stable_view_bytes=23497440702
source_pro/checksums_bytes=0
materialized_checksums_bytes=1479
```

Replaying exact legacy adoption after the generated add preserved the stable
union and returned the same commit with `changed=false`.

## Integrity and operational checks

- `shasum -a 256 -c` validated all 15 TGZ entries against the reviewed
  checksum fixture.
- `gzip -t` and a full `tar -tzf` traversal passed for every TGZ. These are
  evidence-only host tools, not SOW runtime dependencies.
- `sow materialize stable` produced 16 existing hardlinks, 23,497,440,702
  bytes, one exact route receipt, and no prune.
- `sow verify --layer L1 --view stable` passed with zero findings.
- `sow fsck` reported three commits, then four after the generated add and
  route receipt, zero canonical/route/repo drift, and no remote target.
- `sow gc` reported 16 reachable, zero orphan, zero missing, and zero delete.
- Nginx render-only admission emitted only the authenticated
  `/pro/v1/basic/gated/pro/` location, `private, no-store`, an alias rooted at
  `.sow/origin/gated/pro/`, and a catch-all `location / { return 404; }`.

All 15 production-source hashes re-read after the run matched the initial
inventory, including `d7a8ccd4...f6b7` for `pigsty-v4.4.0.tgz`; the empty
source checksum remained `e3b0c442...b855`.

## Remaining boundary

This closes local gated adoption, confidentiality, checksum repair,
materialization, L1, fsck, GC, archive readability, and replay. It does not
claim a provider upload, CDN cache behavior, or production cutover. Those
remain separate non-production-cloud and approved production-migration gates.
