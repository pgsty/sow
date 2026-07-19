# Legacy migration review-hardening evidence

Date: 2026-07-19

Baseline: `1d1746e3d9ac9d18fc803ad20e5bedcad008c34b`

Scope: Pigsty-v1 selector closure, physical migration fixture, and local writer-fence preflight

External mutation: none

## Result

The Pigsty-v1 migration contract now binds every ordinary Make replacement to
the checked-in physical `pigsty-v1.yaml` topology, rather than proving only a
synthetic selector matrix. A static golden freezes 158 command expansions by
the exact APT suite/component/architecture/source/route leaf, YUM OS/component/
architecture/source/route leaf, asset source/public-route/pool leaf, or
compatibility ID/root/carrier/policy-source tuple. The
audit rejects duplicate or empty expansions, command drift, exact-leaf drift,
and same-count physical-path substitution. Its reviewed normalized map digest
is:

```text
54b9e81b837c4010bb16e8a25339375d57043232428a22a8019bb8703253c6ac
```

Compatibility-only `yum-infra` verbs are verified through their actual nested
CLI help and are no longer accepted as ordinary repo selectors. The physical
contract now has one dedicated EL9 policy owner and exact aarch64/x86_64
projections; `<id>` commands expand to both projections, while explicit IDs
resolve to exactly one. Neither the inactive carrier nor policy-only owner is
present in an ordinary repo group. The historical
`yum-ivory` target is explicitly retired because the physical inventory has no
owner for it; the audit does not fabricate one to make the count close.

The older 44-family E2E layer was also moved from synthetic selector lookup to
the physical contract. Repo groups are expanded before capability matching,
and compatibility commands are classified by their dedicated
`compatibility/yum-*` business verbs rather than being mistaken for every repo
type. Families that replace mixed-EL legacy writers now bind the real local
`yum-adopt -> yum-candidate -> yum-freeze -> yum-cutover -> yum-rollback`
state-machine tests for both architectures.

The writer-fence snapshot/report contracts are now v2/v4. In addition to known
writer command classification, the preflight inspects effective-user writable
file descriptors through Linux `/proc` or macOS/system `lsof`, records complete
process and descriptor probe counts, and fails closed on any writable target
whose path is inside the canonical legacy root or whose device/inode identity
belongs to any regular file in that root. This closes external hard-link aliases
whose reported descriptor path is outside the root. Gregorian UTC approval
timestamps are parsed strictly, so syntactically plausible dates such as
2026-02-31 are rejected.

The physical Pro fixture also freezes the legacy `pro/checksums` object as one
and only one gated-metadata entry with byte count zero and the mathematical
empty-file SHA-256 identity:

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Changing its inventory byte count to one or its SHA away from the mathematical
empty identity is a tested failure, so the assertion is bound directly to the
physical topology row rather than a parsed-but-unused field or constant-only
self-test.

## Review findings closed

1. An unrelated process holding an already-open writable descriptor inside the
   legacy root now blocks writer-fence approval even when its command and cwd do
   not identify it as a repository writer.
2. Migration selector closure is evaluated against `pigsty-v1.yaml`, not the
   synthetic selector-only configuration.
3. The golden binds exact physical leaves and includes a same-count path-drift
   negative, so repo-ID/count equality cannot hide suite/component/OS/arch/path
   substitution.
4. The zero-byte Pro checksum row is unique and its bytes and SHA identity are
   asserted.
5. `approved_at` rejects impossible calendar dates and times.
6. The previously separate family E2E gate now consumes the same physical
   selector model and requires executable x86_64 and aarch64 compatibility
   state evidence.

ADR-0027 is recorded as the accepted superseding decision for the older frozen
spec wording that allowed only flat/canonical RPM hrefs: safe normalized,
index-proven nested hrefs are accepted while the canonical destination and all
escape, wrong-bucket, collision, unlisted, and tamper gates remain unchanged.
The historical frozen block itself was not silently edited.

## Reproduced commands

```bash
go test ./internal/config ./internal/cli \
  -run 'PigstyV1PhysicalMigration|LegacyMigrationMap|MigrationSelectorGolden' \
  -count=1
go test -race -count=1 ./internal/provenance ./internal/cli \
  -run 'Legacy|AdoptContent|PigstyV1|Migration'
docs/migration/test-writer-fence-preflight.sh
docker run --rm --network none --user 65534:65534 -e TMPDIR=/tmp \
  -v /Users/vonng/pgsty/sow:/src:ro -w /src pgsty/d13:latest \
  bash docs/migration/test-writer-fence-preflight.sh
docs/migration/test-physical-migration-config.sh
docs/migration/test-audit-legacy-targets.sh /Users/vonng/pgsty/repo
docs/migration/test-family-e2e.sh
docs/migration/test-local-adoption-rollback.sh
SOW_CLEAN_GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download \
  test/compat/test-clean-delivery.sh /tmp/sow-clean-delivery-migration-review
go vet ./internal/config ./internal/cli
git diff --check
go test ./... -count=1 -timeout=30m
```

Observed current-source result: every command exited zero. The native macOS
writer-fence suite reported 21 named PASS outcomes, including direct-path and
external hard-link-alias open-FD negatives, a malformed regular-file `lsof`
identity negative, and the impossible-date negative. The
report binds the complete legacy device/inode set and rejects identity drift
during the probe. The native macOS run exercised the `lsof` branch; a local,
already-present `pgsty/d13:latest` image ran the Linux procfs branch as
unprivileged uid 65534 with `--network none`; its independent procfs path
passed all 20 applicable cases (the `lsof`-only mutation is intentionally not
applicable there). The target audit passed its baseline/map, fixture
guard, output-race, family/ID drift, Cloudflare-YUM selector, disposition,
fingerprint, missing/unparsed row, unknown/known disposition, stale-flag,
invalid-enum, and exact physical-selector golden cases.

The 44-family executable contract passed five fail-closed contract negatives,
including removal of one required physical compatibility architecture, and
16 real CLI/parser/protocol tests, including full local x86_64 and aarch64
YUM compatibility state machines. The aarch64 workflow executes directly from
the checked-in 98-repo physical config and its exact policy-owner/projection
IDs; the x86_64 workflow additionally exercises Nginx and edge admission.
Both rollback workflows preserved the raw legacy carrier bytes. The local
adoption/rollback workflow restored the legacy byte snapshot and replayed
idempotently. Clean delivery used the
already-verified local Go module download cache after the isolated default
`proxy.golang.org` download attempt timed out; the source/archive policy itself
then passed without network or dependency substitution.

```text
race migration plus both compatibility state machines: internal/provenance PASS (4.163s); internal/cli PASS (267.010s)
family contract: 44 families; 5 negative contracts; 16 executable tests PASS
full repository: all packages PASS; internal/cli 1202.757s
```

Delivery/archive digests are intentionally not embedded in a file that is
itself part of those identities. Final clean-delivery identities are recorded
only in the external validation artifact after the delivery tree is frozen.

## Evidence boundary

The migration audit read `/Users/vonng/pgsty/repo` at
`c2f7b5fa967d18d03b424fb7d0ee92fc5eabb6e6`; it did not write that checkout and
preserved the user's pre-existing `ext/data/extension.csv` modification. The
checked-in physical snapshot was refreshed only after two independent
read-only scans produced byte-identical normalized inventories; the refreshed
snapshot then passed a third live read-only audit. All
writer-fence mutations occurred in disposable local fixtures. No network
request, Cloudflare/COS object mutation, CDN purge, production serving-root
change, credential revocation, or old-writer shutdown occurred. Therefore this
closes the local migration-review findings but does not claim production writer
revocation or any real-cloud publication gate.
