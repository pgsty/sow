# YUM raw-alias detached-signature bridge negative PoC (2026-07-12)

## Verdict

**The proposed transition signature cannot close the raw `baseurl` window.**
AlmaLinux 8, 9, and 10 DNF do not select whichever detached signature matches
the downloaded `repomd.xml`:

- with two concatenated ASCII-armored signatures, DNF effectively verifies the
  first armor block only;
- with two signature packets inside one armor block, DNF 4.7/4.14 effectively
  verifies the first packet only, while DNF 4.20 rejects the multi-packet file
  for both documents; and
- redirecting only `repomd.xml` to an immutable generation does not pin the
  signature request. DNF still requests `repomd.xml.asc` below the configured
  raw base URL.

No production signature-bridge code was added. The immutable generation plus
generation-pinned mirrorlist remains the only proved remote YUM publication
gate. `repo_gpgcheck=1` is never weakened.

## Real-client fixture

`test/compat/yum_signature_bridge_test.go` creates a complete gzip rpm-md
repository with the production pure-Go generator and signer. It then creates
two distinct `repomd.xml` documents, differing only in their revision, and a
valid detached signature for each using the same repository key. Every state
is served over HTTP and checked by a fresh real DNF metadata cache.

The controls prove the test can distinguish a valid from a mismatched pair:

| Served XML | Served signature | EL8 | EL9 | EL10 |
|---|---|---:|---:|---:|
| old | old | pass | pass | pass |
| old | new | fail | fail | fail |
| new | old | fail | fail | fail |
| new | new | pass | pass | pass |

## Transition-signature results

### Concatenated ASCII armor blocks

| Served XML | Signature block order | EL8 DNF 4.7 | EL9 DNF 4.14 | EL10 DNF 4.20 |
|---|---|---:|---:|---:|
| old | old, new | pass | pass | pass |
| new | old, new | **fail** | **fail** | **fail** |
| old | new, old | **fail** | **fail** | **fail** |
| new | new, old | pass | pass | pass |

The trailing signature does not bridge either half of the transition. Ordering
the old signature first preserves the pre-flip state but fails immediately
after the XML flip; ordering the new signature first creates the inverse
window.

### Two binary signature packets in one armor block

| Served XML | Packet order | EL8 | EL9 | EL10 |
|---|---|---:|---:|---:|
| old | old, new | pass | pass | **fail** |
| new | old, new | **fail** | **fail** | **fail** |
| old | new, old | **fail** | **fail** | **fail** |
| new | new, old | pass | pass | **fail** |

This encoding is not a portable bridge either. It also has worse EL10
compatibility than ordinary concatenated armor.

### HTTP redirect probe

For 302, 307, and 308 responses, all three clients failed when the configured
raw `.asc` was the old signature and the redirected XML was new. The recorded
request chain was:

```text
GET /redirect-302/repodata/repomd.xml 302
GET /generation-new/repodata/repomd.xml 200
GET /redirect-302/repodata/repomd.xml.asc 200
```

The 307 and 308 traces were identical apart from the status code. Therefore an
XML redirect cannot turn an unchanged raw `baseurl` into a generation-pinned
signed pair without also changing client configuration or introducing an
unproved stateful request-affinity service.

## Why serial raw-key replacement remains impossible

Let `X0/S0` and `X1/S1` be two distinct valid XML/signature pairs. A static raw
repository exposes two independently replaceable object keys. Replacing the
signature first exposes `X0/S1`; replacing the XML first exposes `X1/S0`.
Avoiding both states requires either one signature representation accepted for
both XML documents, or one client-observable selector that pins both requests.
The real-client probes reject the tested multi-signature representations and
show that a repomd redirect does not pin the `.asc` request.

Deleting a member, serving a maintenance error, relaxing `repo_gpgcheck`, or
assuming clients finish within a grace period would replace an integrity race
with an availability or security failure; none satisfies FR-08/FR-26/NFR-05.

## Reproduction

Images and versions used:

- `almalinux:8` — image
  `sha256:4a87d2615a770506e204c27d6248ac97f4df67f4e41e2e9c47c81f0ed0be98cb`,
  DNF 4.7.0;
- `almalinux:9` — image
  `sha256:d2515c769e7b73f95c4fde38c0a505336ff38f14990c0b7253b77060a049a743`,
  DNF 4.14.0;
- `almalinux:10` — image
  `sha256:cc24bc5b6ac7e284f2f62a07bdaa1b15d3319fdcf46413c6b8fe9fa245068ddd`,
  DNF 4.20.0.

```bash
SOW_RUN_DOCKER_COMPAT=1 \
SOW_COMPAT_EL8_IMAGE=almalinux:8 \
SOW_COMPAT_EL9_IMAGE=almalinux:9 \
SOW_COMPAT_DNF_IMAGE=almalinux:10 \
go test -count=1 -run '^TestYUMDetachedSignatureBridgeCompatibility$' \
  -v ./test/compat

--- PASS: TestYUMDetachedSignatureBridgeCompatibility (30.77s)
    --- PASS: TestYUMDetachedSignatureBridgeCompatibility/el8
    --- PASS: TestYUMDetachedSignatureBridgeCompatibility/el9
    --- PASS: TestYUMDetachedSignatureBridgeCompatibility/el10
```

This is negative compatibility evidence, not a waiver. Existing raw URLs stay
available as compatibility aliases, while strong atomicity requires migration
to the generation-pinned mirrorlist route documented in
`2026-07-12-yum-generation-atomicity.md`.
