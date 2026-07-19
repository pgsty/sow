# External builder handoff

SOW does not build DEB/RPM packages and does not invent the body of generated
bootstrap assets. The external builder owns those bytes; SOW owns admission,
package trust, CAS, repository metadata, views and publication after the final
artifact crosses this boundary.

## Frozen handoff contract

For every artifact, the builder provides a regular file plus its exact SHA-256
and byte size. The operator passes the assertion in the same order as the input
files:

```bash
sow add output.rpm \
  --repo yum-infra-el9 \
  --expected-object sha256:<lowercase-64-hex>:<decimal-size> \
  --gpg-private-key-file /secure/repository-private.asc \
  --config /etc/sow/sow.yaml
```

For a batch, repeat `--expected-object` once per positional input. Duplicate
input paths, a missing/extra assertion, uppercase/non-canonical digests,
negative or non-canonical sizes, and any byte mismatch fail closed. Successful
output contains:

```text
builder handoff verified inputs=<n> receipt_sha256=<sha256>
```

The receipt binds the ordered artifact basenames and immutable object
identities without exposing builder directory names. Preserve the builder's
source revision/toolchain attestation, its artifact digest list, the complete
SOW stdout/stderr and the resulting canonical Git commit/ref together. The SOW
manifest remains the repository truth; the receipt proves which externally
asserted objects were admitted by that invocation.

Package rules remain unchanged:

- self-built RPMs must already carry a signature accepted by the selected
  repository's `yum.package_keyring`; SOW verifies but does not re-sign them;
- DEBs are inspected as existing packages, then SOW builds/signs APT metadata;
- assets enter the configured public or gated pool and obey immutable/mutable
  destination policy;
- a mismatch exits 4 before a novel CAS object or view entry is installed;
  retry with the same artifact/assertion is idempotent, while interrupted
  package projection still follows the normal `sow add --recover` contract.

## Legacy target mapping

| Old target | Builder output admitted by SOW |
|---|---|
| `copy-bin` | one reviewed canonical `get`, `pig` and `pkg` asset; COS-only `cc`/`claude` use a separately targeted repo and have a read-only exact-copy local gate |
| `copy-beta` | one reviewed canonical `beta` asset; COS-only `ray` uses a separately targeted repo and has a read-only exact-copy local gate |
| `ext-list` | a stable externally generated README, only if that URL remains a product contract |
| `md5-src` | the legacy compatibility checksum file generated outside SOW; SOW's own truth remains SHA-256 |
| `parade` | final signed DEBs, grouped by selected suite/repo |
| `get-d13` | final amd64 DEBs for trixie |
| `get-d13a` | final arm64 DEBs for trixie |

The eighth `external-handoff` disposition, old APT `push`, is external
non-production file transport rather than a builder-to-repository admission;
it is intentionally not replaced by `sow add` or counted as builder evidence.

The historical `.io` and `.cc` scripts for `get`/`pig`/`pkg`/`beta` have
different bodies for the same public key. SOW must not silently choose either
variant or encode target-specific content overrides. A product owner/builder
must first produce one canonical Host-aware body (or approve a new explicit
product contract); only that output can cross the digest-bound handoff above.

## Reproducible local gate

```bash
go test -count=1 ./internal/cli -run '^TestBuilderHandoff'
```

The gate uses the real `sow add` dispatcher and filesystem/CAS/Git projection:
one asset mismatch negative, one asset positive, one real DEB add and one
embedded-signature-verified RPM add. It does not invoke a package builder,
external GPG tool, cloud API or production repository.

The three unambiguous COS-only ROOT assets have an additional opt-in exact-copy
gate. It reads but never writes the existing Pigsty repository, performs every
SOW mutation in `/private/tmp`, and does not contact a provider:

```bash
SOW_RUN_PIGSTY_ROOT_COS_HANDOFF=1 \
SOW_PIGSTY_REPO_ROOT=/Users/vonng/pgsty/repo \
go test ./test/compat -run '^TestPigstyRootCOSBuilderHandoff$' -count=1
```

The gate binds `bin/get.cc` to the distinct `/cc` key and binds `bin/claude`
and `bin/ray` to `/claude` and `/ray`. It deliberately does not choose the
shared `/get`, `/pig`, `/pkg` or `/beta` body. See the
[ROOT COS-only evidence](../evidence/2026-07-17-root-cos-builder-handoff.md).
After that gate passed, the physical migration fixture activated only the
dedicated `asset-root-cos` owner; its target affinity remains exactly `cos` and
the ledger still marks production cutover pending.

The shared ROOT assets now have a separate external canonicalizer. It verifies
the exact size/SHA-256 of all eight legacy `.io/.cc` sources, refuses an output
that resolves inside the source tree, and emits four deterministic standalone
scripts with strict global/China mirror selection and fallback:

```bash
docs/migration/build-canonical-root-assets.sh \
  /Users/vonng/pgsty/repo /private/tmp/sow-canonical-root-assets

SOW_RUN_PIGSTY_ROOT_BOTH_HANDOFF=1 \
SOW_PIGSTY_REPO_ROOT=/Users/vonng/pgsty/repo \
go test ./test/compat -run '^TestPigstyRootBothBuilderHandoff$' -count=1
```

The second gate rebuilds twice, exercises mirror selection without network,
and admits `/get`, `/pig`, `/pkg`, `/beta` through the same digest-bound SOW
path. The `asset-root-both` owner is therefore active locally with exact
`cf,cos` affinity; production URL regression and cutover remain pending. See
the [shared ROOT evidence](../evidence/2026-07-17-root-shared-canonical-builder-handoff.md).
