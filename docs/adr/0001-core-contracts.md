# ADR-0001: Core Repository and Publication Contracts

Status: accepted  
Date: 2026-07-11  
Scope: contracts whose later migration cost or security impact makes them irreversible

## Context

SOW replaces a mutable Makefile-and-rclone workflow with a single Go CLI. It must preserve existing public repository URLs, add append-only commercial history, publish coherently to two independent object stores/CDNs, and remain recoverable without external git, gpg or repository tooling.

The current Pigsty configuration uses raw YUM base URLs such as **https://repo.pigsty.io/yum/infra/$basearch** and **https://repo.pigsty.io/yum/pgsql/el$releasever.$basearch**. This fact matters because a YUM client obtains **repodata/repomd.xml** and its detached **.asc** in separate HTTP requests.

## Decision

### D1 — State and filesystem

- The repository root contains **.sow**, **.pool**, and the directly hostable APT/YUM/asset tree.
- **.sow/state** is the canonical non-bare Git worktree, accessed by an embedded Go library. The host need not contain a git executable.
- Manifests, refs, object security labels, provenance and configuration hashes are canonical Git content. SQLite is a disposable read-only projection.
- Package bytes live once in the SHA-256 CAS. Published files are hardlinks. A filesystem without hardlink support is rejected.
- Static hosting requires an explicit deny rule for **/.sow/** and **/.pool/**. “Nginx can point at the root” means no SOW application server, not that sensitive dot directories may be exposed.
- The legacy-root tree is the anonymous public projection. Gated local bytes are materialized only below **.sow/origin/gated/**; remote gated keys live below private **.sow/gated/**. Buckets are private and only the edge may read gated/control keys. A direct bucket URL or anonymous Nginx path must never bypass token authorization.

### D2 — Refs and preservation

- Repository, view, snapshot and per-target remote refs use the namespaces in the architecture contract.
- Stable and snapshot refs are append-only. **rm** only removes mutable-view reachability and never deletes a byte still reachable from stable, history, remote refs, provenance or recovery journals.
- GC is exclusively reachability-based and is not part of rm.

### D3 — Configuration and fixed names

- The schema discriminator is **sow/v1**; unknown fields fail closed.
- Public/latest is an alias over every legacy root path, not a new **/latest** path. [The migration ledger §3.2](../migration/make-target-map.md) is the normative captured baseline, including infra/pgsql/pgdg/percona/mssql, all existing asset roots, and the ordinary text-version semantics of **/pkg/pig/latest**. Omission from a short example is not permission to change a URL or its bytes.
- The external Pro prefix is **/pro/v1/{token}/**, followed by the same relative repository path.
- Snapshot IDs are **<suite>-YYYYMMDD** in UTC. Conflicting second snapshots for the same suite/day are rejected.
- Stable plus the most recent six calendar months of snapshots are materialized by default; the positive month count is configurable.
- EL8 is frozen. Existing bytes remain publishable and repairable, new content is rejected, and repodata remains gzip.

### D4 — Publication model

- Local state mutation is a journaled transaction with one Git ref update as its canonical commit point.
- Remote publication is a saga per target. cf and cos never share a commit/rollback boundary; one target succeeding cannot be undone because the other fails.
- Immutable bodies and metadata upload before mutable pointers. Purge and post-publish verification are mandatory saga phases, not operator follow-up.
- Each remote checkpoint names a parent generation and is changed with compare-and-set semantics. The local target remote ref advances last.
- A target generation contains a deterministically encoded, sorted vector of every selected ref and its commit/manifest hash, the aggregate desired-state commit, normalized config hash, content-manifest hash, generation and parent generation. The checkpoint points to the immutable generation-document hash; it never collapses unrelated leaf refs into an ambiguous single commit.

### D5 — YUM pair flip

The two YUM files form one logical publication unit, but local filesystems and object stores need different mechanisms.

**Local:** Build and fsync a complete sibling repodata directory, then exchange the live and staged directory entries atomically. Linux uses **renameat2 with RENAME_EXCHANGE**; macOS uses **renamex_np with RENAME_SWAP**. The old generation remains at the staging name until the journal commits. A plain POSIX rename over a non-empty directory is not equivalent and is forbidden.

**Remote:** Store each complete pair under an immutable generation. Only after read-back verification may one generation pointer or mirrorlist change. Package bodies and old generations remain addressable, so retry and rollback do not require copying bytes.

The remote naming contract is:

~~~text
.sow/generations/<20-digit-generation>/yum/<legacy-root>/repodata/*
.sow/channels/<view>/<repo>/<os>/<arch>.json
~~~

The channel object is the sole mutable selector. A generation-aware edge URL routes repodata to the immutable prefix and package requests to the common legacy package path, so package bodies need not be duplicated per publication generation.

YUM payload location is also frozen: **Packages/<bucket>/<original-basename>**, where bucket is the lowercase first ASCII alphanumeric of RPM Name or underscore. primary metadata uses that exact root-relative href. Leading slashes, dot-dot/cross-repository hrefs, and overwriting a path with different bytes are rejected.

Flat-to-split migration is never in-place: build and verify a full staged generation, switch only after dnf acceptance, and retain the prior manifest/generation as the rollback source. Cleanup waits until all local and remote refs release the old paths.

### D6 — Provenance

- RPM receipt: upstream URL, upstream primary/index SHA-256 and size, plus the original RPM CAS object. Its embedded signature is evidence; mirrored RPMs are not re-signed on Day 1.
- DEB receipt: upstream URL, Packages entry SHA-256 and size, original DEB CAS object, signed upstream InRelease/Release evidence, and the corresponding Packages evidence.
- Evidence hashes are part of canonical Git state; large evidence bytes are CAS objects.

### D7 — Edge contract

Cloudflare Worker and EdgeOne use the same fixtures and observable behavior:

1. Authenticate before origin access.
2. Strip the Pro token segment and fetch a clean public/gated origin path.
3. Keep token, Authorization and secret-derived values out of origin URLs, cache keys and logs.
4. Keep public and gated cache namespaces distinct.
5. Dynamically inject the token only into an authorized Pro mirrorlist; mark that response private and no-store.
6. Support Basic Auth only as the documented fallback.

The token is a bearer secret. TLS, rotation/revocation, minimum 128-bit entropy, constant-time verification, strict single-segment parsing and log redaction are mandatory. Gated origin objects are never anonymously readable.

Both implementations return the same status classes: 404 malformed route, 401 invalid/expired credential, 403 insufficient scope, 405 unsupported method and 503 temporary verifier/origin failure. Authentication failures are private and no-store.

### D8 — Failure recovery

- Every mutation records transaction ID, expected commit/generation, target, phase and content hashes before side effects.
- A retry with the same identity resumes; duplicate immutable uploads and purges are harmless.
- Before a pointer flip, incomplete staging is invisible. After a flip, recovery completes purge, verification, checkpoint and local remote-ref advancement.
- A mismatched transaction, generation, ETag or parent is drift. SOW stops and reports it; it does not overwrite, auto-merge or steal a lock because of elapsed time.
- A command with one completed and one incomplete target exits nonzero and reports both states. The next invocation resumes only the incomplete target.

## Physical and security constraints

### 1. A portable plain directory rename is insufficient

POSIX rename cannot atomically replace a populated directory with another populated directory. The contract therefore means an atomic directory **exchange**, using the platform facilities above. Startup/init must probe the actual production filesystem. If exchange is unavailable, SOW must refuse a live local flip; a two-rename sequence is not an acceptable fallback.

### 2. Static object storage cannot atomically replace two keys

R2/COS do not offer a transaction that makes repomd.xml and repomd.xml.asc visible together. A versioned generation plus one pointer avoids the two-key commit, but strict consistency across a client transaction is possible only when the client first resolves an immutable generation base URL, normally through mirrorlist/metalink.

The existing Pigsty YUM contract is raw **baseurl**, so “unchanged raw URL for both metadata requests” and “mathematically atomic detached-signature pair on static S3” cannot both be guaranteed. An edge function that resolves the current pointer per request still has a race if the pointer changes between the XML and ASC requests.

Therefore:

- Legacy root paths remain valid compatibility aliases and package URLs do not move.
- New signed YUM channel configuration must use a stable mirrorlist/metalink URL whose response selects one immutable generation for that transaction.
- Cloudflare Worker and EdgeOne must also implement the generation-aware public route: metadata resolves to the selected immutable generation while package hrefs resolve to the common legacy root. This behavior is covered by the same cross-vendor contract suite.
- The legacy raw-baseurl path may remain during migration, but it cannot be claimed to satisfy the strong pair-atomicity acceptance gate until a real dnf-compatible generation-pinning mechanism is proven.
- Enabling repo_gpgcheck publication requires an executable migration/rollback map for existing Pigsty baseurl consumers. This is a verification gate, not permission to weaken FR-08/FR-26.

The v1 routes are fixed:

- **/_sow/v1/mirrorlist/latest/<repo>/<os>/<arch>.txt**
- **/pro/v1/{token}/_sow/v1/mirrorlist/<view>/<repo>/<os>/<arch>.txt**
- one returned absolute HTTPS base URL at **/_sow/v1/g/<20-digit-generation>/<legacy-root>/**, with the Pro prefix for gated access

The response contains exactly one base URL, pinning all metadata requests to one generation. Rollback restores the prior repository configuration and channel pointer; it does not rewrite immutable generations.

### 3. Checkpoint CAS differs by provider

Cloudflare documents conditional R2 writes, including If-Match behavior. Tencent COS documents normal overwrite/versioning and a create-only **x-cos-forbid-overwrite** guard, but the reviewed PutObject contract does not establish an equivalent conditional replacement of an existing key.

- R2 may implement checkpoint CAS directly with conditional PutObject.
- COS may use an immutable, deterministic next-generation checkpoint plus create-only acquisition to serialize conforming SOW writers; **.sow/manifest.json** can then be a summary, not the sole lost-update guard.
- The COS adapter must still pass a two-writer race, crash-recovery and foreign-drift conformance test on real COS. Until it does, the target is implemented but not production-validated and the overall Goal remains open.

References: [Cloudflare R2 conditional operations](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/#conditional-operations), [Cloudflare R2 S3 compatibility](https://developers.cloudflare.com/r2/api/s3/api/), [Tencent COS PutObject](https://cloud.tencent.com/document/product/436/7749), [Tencent COS forbid-overwrite condition](https://cloud.tencent.com/document/product/436/71307).

### 4. Token paths and hidden local state need explicit protection

Path tokens otherwise leak through access logs, analytics, referrers and error reporting. Dot directories can also be served by an unsafe static-server configuration. Redaction, clean subrequests, private origins and deny rules are architectural controls, not optional operational advice.

Local **.sow/** and remote **.sow/** are different control planes. Local control files are never uploaded as content. The target adapter alone writes remote **.sow/manifest.json**, generations, channels and gated keys outside the content manifest; edge private bindings may read them, while every client request whose normalized path begins **/.sow/** returns 404.

## Rejected alternatives

- External git/gpg, Python, Perl, aptly, createrepo_c or other runtime tools.
- SQLite or a remote bucket as the canonical local state.
- A generic cloud-provider plugin layer or a cross-cloud all-or-nothing transaction.
- In-place remote overwrite of the YUM pair, purge-everything, or rollback by deleting new package bytes.
- Symlink or two-step directory replacement silently substituted for a verified atomic exchange.
- Token in query/header, token-bearing shared cache entries, or “security by omitting gated packages from an index”.
- Day 1 re-signing of mirrored RPMs.

## Consequences

- Zero-byte adoption can create only hidden SOW state while preserving all published bytes and URLs.
- Desired state, each cloud's published state, and interrupted work are independently observable.
- Immutable generations consume some remote metadata storage; this is intentional and bounded by retention/GC after all refs and checkpoints release them.
- Some external verification remains mandatory: real filesystem exchange, real R2/COS checkpoint races, dnf generation pinning, EdgeOne cache behavior, and apt/dnf signature acceptance. None may be reported as passed from design evidence alone.
- Conformance also requires a 50,000-package run proving bounded repo/component/arch parallelism, streaming/lazy peak memory, and a default publish call count proportional to the changed-object set. Remote listing remains exclusive to explicit fsck.
