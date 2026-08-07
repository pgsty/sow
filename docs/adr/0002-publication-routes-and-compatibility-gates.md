# ADR-0002: Publication routes and compatibility gates

> **Historical V1 ADR.** Its route/CAS decisions are brownfield evidence only;
> next publication is governed by [`../../design/next/`](../../design/next/).

Status: accepted for implementation; external compatibility gates remain open

## Context

The frozen product contract requires one physical bucket per vendor, a distinct
public beta view, legacy latest URLs, gated stable content, generation-pinned
YUM metadata, mandatory CDN verification, and no duplicate package body per
channel. A single CDN base URL cannot identify both latest and beta, and a Pro
verification request cannot carry a bearer token in a persisted plan or log.

The current legacy APT layout also exposes fixed `Packages*` names. An object
store has no multi-key transaction that can replace those files and
`InRelease` simultaneously.

## Decision

1. Every cloud target declares both `cdn.base_url` for latest/Pro and a
   different `cdn.beta_base_url`. Both are clean HTTPS origins. The same vendor
   zone/distribution may serve both hosts.
2. Latest retains every legacy key unchanged. Beta metadata and mutable assets
   use `.sow/beta/<legacy-key>`. The edge selects this namespace only when the
   request origin equals the configured beta origin. Public APT `pool/` and YUM
   `Packages/` requests fall back to the shared legacy public object, so package
   bodies are not copied per channel.
3. Stable metadata and gated bodies use `.sow/gated/`. Public bodies referenced
   by stable continue to use their legacy public key. The classifier resolves
   this from the canonical view entry's pool; it may not guess from a filename.
4. Public YUM metadata lives below
   `.sow/generations/<generation>/yum/<legacy-root>/repodata/`; Pro metadata
   lives below `.sow/gated/generations/...`. A channel pointer is the only
   mutable selector. Its CDN verification is the rendered mirrorlist, not its
   private JSON body.
5. L3 verification for Pro uses `/pro/v1/basic/` with a short-lived or dedicated
   verification credential injected from the target secret. The HTTP provider
   sends `Authorization` only to this exact route. It never serializes the
   credential into a URL, plan, journal, canonical state, error, or log.
6. Object API endpoints are provider-specific. R2 uses region `auto`; COS uses
   the documented virtual-host bucket endpoint
   `<bucket-appid>.cos.<region>.myqcloud.com`. Configuration names the service
   endpoint and bucket separately, and SOW constructs and validates the
   bucket-root URL before signing.
7. For APT, by-hash objects upload create-only, legacy `Packages*`, `Release`,
   and `Release.gpg` aliases install next, and `InRelease` flips last. The
   unavoidable race for apt clients older than 1.2 remains an explicit
   compatibility gate. It is not represented as atomic or passed until a real
   old-client migration/acceptance decision exists. apt >= 1.2 remains coherent
   through the by-hash closure.
8. Every immutable target generation includes an intent view and a complete,
   sorted YUM channel vector. Selector-scoped publication carries unchanged
   mappings from the parent and advances only changed leaves. The exact channel
   body is reproducible from and hash-bound to that vector, and is retained in
   canonical local remote state.
9. Existing raw YUM base URLs remain populated. Generation repodata uploads
   create-only; the raw non-pointer repodata aliases follow; then
   `repomd.xml.asc` and `repomd.xml` install in that order and both URLs are
   purged and verified. This is a compatibility bridge, not a claim that two
   object keys are atomically replaceable. Only generation-pinned mirrorlists
   satisfy the strong pair gate.
10. Edge authorization receives canonical audience and path scope and validates
    expiry before origin access. The edge contract never uses a manual Cache
    API key: credential-free origin subrequests converge in the configured CDN
    hierarchy, whose customer URLs are the same URLs the publish saga purges.
11. Local mutable YUM views use the same public URL vocabulary as remote
    publication: `_sow/v1/mirrorlist/<view>/<repo>/<os>/<arch>.txt` points to
    `_sow/v1/g/<content-derived-id>/<legacy-root>/`. The immutable closure
    contains Packages and all signed repodata. Kernel directory exchange keeps
    the raw bridge crash-safe but is not called pair-atomic for a multi-request
    DNF client.
12. Local serving URLs are an explicit, secret-free configuration contract and
    are never inferred from cf/cos targets. latest/beta use clean origins;
    stable uses the exact clean `/pro/v1/basic` base. HTTP is limited to
    localhost, loopback addresses, and the exact `host.docker.internal` test
    bridge. An explicit mutable-YUM export also requires an explicit
    `--serving-base-url` because its directory may be hosted elsewhere.
13. A local generation manifest and channel JSON are canonical Git state. The
    generation is installed and verified first, canonical desired state commits
    second, and the single mirrorlist flips last. A separate replay journal is
    required because canonical transaction recovery does not replay
    `AfterCommit`; recovery compares the current pointer only with the recorded
    parent or desired digest. Old generations are GC roots and are not removed
    by routine reconciliation.

## Consequences

- A target publication may advance one view generation at a time so each view
  can be verified through its correct origin. The target checkpoint and local
  remote ref vector remain aggregate and are advanced after each successful
  generation; targets remain independently replayable.
- Direct client access to any `/.sow/` path stays forbidden. The edge has the
  only private origin binding capable of resolving beta, gated, channel, and
  generation keys.
- Missing beta routing, Pro verification credentials, a COS never-versioned
  capability proof, or an old-APT compatibility disposition is a fail-closed
  publication/readiness result, not an operator warning.
