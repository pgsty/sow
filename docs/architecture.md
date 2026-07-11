# SOW Architecture Contract

Status: adopted  
Date: 2026-07-11  
Decision record: [ADR-0001](adr/0001-core-contracts.md)

This is the build contract for SOW. The PRD defines scope; the Addendum is the more specific technical ruling. Research is evidence, not acceptance proof. Internal details may evolve, but an invariant here requires a new ADR to change.

## Paradigm

SOW is a Git-backed desired-state controller with a content-addressed data plane and an independent publish saga per remote target.

~~~mermaid
flowchart LR
    C["sow.yaml / sow/v1"] --> X["command transaction"]
    G[".sow/state: embedded Git canonical state"] <--> X
    P[".pool: SHA-256 CAS"] <--> X
    X --> T["directly hostable tree"]
    G --> Q["rebuildable SQLite cache"]
    T --> F["cf saga"]
    T --> O["cos saga"]
    F --> RF["remote ref: cf"]
    O --> RO["remote ref: cos"]
~~~

There is one local writer. Read-only verification may run concurrently. Cloud targets advance independently and may point at different committed generations.

## 1. Local ownership and layout

~~~text
<root>/
├── sow.yaml
├── .sow/
│   ├── state/                 # non-bare embedded Git worktree; canonical
│   │   ├── .git/
│   │   ├── manifests/
│   │   ├── objects/
│   │   └── provenance/
│   ├── cache/state.db         # disposable SQLite projection
│   ├── journal/<txid>.json    # durable recovery journal; no secrets
│   ├── stage/<txid>/          # unpublished staging
│   ├── origin/gated/          # private local projection; never anonymous
│   └── locks/
├── .pool/sha256/<aa>/<hash>   # immutable CAS bytes
└── apt/ yum/ bin/ src/ pkg/ etc/ img/ ...  # published tree
~~~

- **.sow/state** is a normal Git worktree operated through an embedded Go Git library. Calling a git executable is forbidden. Commits and refs are canonical; the checkout is only a materialization.
- Each repository manifest is UTF-8 TSV sorted by unsigned path bytes, with exactly path, size and SHA-256 separated by tabs. Paths are root-relative POSIX paths and reject absolute paths, dot-dot segments, backslashes, tabs, newlines, NUL and duplicate normalized names. Gated local projections use the reserved **.sow/origin/gated/** prefix, so their physical reachability is unambiguous.
- Pool classification, object coordinates, provenance and normalized-configuration hash are canonical files in the same commit; none may exist only in SQLite.
- **.sow/cache/state.db** is ignored by the inner repository. Deleting it and rebuilding from a commit must preserve all query results.
- **.pool** objects are immutable and named by SHA-256. Materialization uses hardlinks, so pool and tree must share a filesystem; preflight fails instead of silently copying.
- The visible legacy-root tree is the final public static repository and needs no SOW runtime. The static server must deny **/.sow/** and **/.pool/**; otherwise state or gated bytes could leak. Local control/cache files never enter a target content manifest. The gated projection enters only the gated target manifest and is remapped to a private origin namespace.
- Remote storage is private. Public bytes retain their legacy object keys; gated bytes map to remote **.sow/gated/<legacy-path>**. The edge is the only public origin and rejects all client **/.sow/** requests. It accesses gated/control keys only through a private binding or signed vendor request.

## 2. Configuration schema v1

The discriminator is exactly **schema: sow/v1**. Unknown fields, duplicate IDs, dangling references and plaintext secret values are errors. URL/layout defaults are normalized and their hash is committed with every state change.

~~~yaml
schema: sow/v1
state:
  snapshot_materialization_months: 6
gpg:
  public_key: ./keys/pigsty.asc
  private_key: env://SOW_GPG_PRIVATE_KEY
  passphrase: env://SOW_GPG_PASSPHRASE
pools:
  public: {}
  gated: {}
repos:
  - id: infra-el9
    type: yum
    path: yum/infra
    os: {family: el, major: 9, lifecycle: active}
    arches: [x86_64, aarch64]
    default_pool: public
    yum: {compression: zstd}
upstreams: []
views:
  beta:   {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://<account>.r2.cloudflarestorage.com", bucket: repo, credential: env://SOW_R2_CREDENTIAL}
    cdn: {kind: cloudflare, base_url: "https://repo.pigsty.io", credential: env://SOW_CF_TOKEN}
  cos:
    storage: {kind: cos, endpoint: "https://cos.<region>.myqcloud.com", bucket: repo, credential: env://SOW_COS_CREDENTIAL}
    cdn: {kind: edgeone, base_url: "https://repo.pigsty.cc", credential: env://SOW_TENCENT_TOKEN}
edge:
  pro_prefix: "/pro/v1/{token}/"
  token_verifier: provider://pigsty-entitlements
~~~

Normative schema rules:

- Top-level keys are **schema, state, gpg, pools, repos, upstreams, views, targets, edge**. Provider unions are closed to R2/Cloudflare and COS/EdgeOne; v1 is not a generic cloud plugin API.
- A repo has a stable ID, type **apt|yum|asset**, legacy-relative path, OS lifecycle, arches and default confidentiality pool. Its apt/yum/asset blocks are mutually exclusive.
- An upstream has an ID, destination repo, HTTPS URL, arch set, ordered allow/deny name filters, debuginfo policy and optional secret reference. Successful sync always writes provenance; this is not configurable off.
- A view declares access, allowed pools, selection rules and append-only behavior. Public views may name only the public pool; stable is always append-only and may name both pools.
- A production profile declares both cf and cos. A local/test profile may omit targets so init, local repository work and verification do not require cloud credentials; publishing an absent target fails. Storage/CDN fields are provider-specific closed unions with endpoint, bucket/zone or service identifiers, public base URL and secret references; config cannot invent a third provider kind.
- Selectors operate on repo, OS, arch and view. An empty match is an error unless that command explicitly defines a no-op.
- Secrets enter only through CLI input, **env://NAME**, or a registered secure-provider reference. References validate at config load, but values resolve only when the selected operation needs them, so init remains offline. Resolved values never enter config snapshots, Git, journals, logs or errors.
- EL8 is always **lifecycle: frozen** with gzip repodata. v1 rejects active or zstd EL8.
- Snapshot materialization defaults to six calendar months and is configurable to a positive value. Stable is always materialized; older refs remain canonical and can be restored on demand.
- The Pro prefix is fixed to **/pro/v1/{token}/**; another v1 shape is invalid.

## 3. Canonical commits, refs and checkpoints

~~~text
refs/sow/repos/<repo>
refs/sow/views/<beta|latest|stable>/<repo>/<os>/<arch>
refs/sow/snapshots/<suite>-YYYYMMDD/<repo>/<os>/<arch>
refs/sow/remotes/<cf|cos>/<view>/<repo>/<os>/<arch>
~~~

- Every ref points to a commit containing everything needed to rebuild that state; it never points to mutable working-tree data.
- Snapshot IDs are **<suite>-YYYYMMDD**, derived from commit time in UTC. One distinct snapshot per suite and UTC day is allowed: the same commit is idempotent; a different commit with the same ID fails.
- Stable and snapshot refs are append-only preservation roots. Normal commands may add a new ref but cannot rewrite or delete an existing one.
- Each target stores **.sow/manifest.json** with schema, target, generation, parent generation, commit, manifest SHA-256, transaction ID, phase and UTC update time.
- Checkpoint mutation is compare-and-set against observed generation/ETag. The local remote ref advances only after the checkpoint is committed and post-publish verification passes. A target that cannot prove conditional-write semantics fails its capability probe and cannot be called production-ready.

One target generation serializes the complete selected ref vector, not one arbitrary leaf commit:

~~~json
{
  "schema": "sow-target-generation/v1",
  "generation": 42,
  "parent_generation": 41,
  "desired_commit": "<aggregate-state-commit>",
  "config_sha256": "<sha256>",
  "refs": [
    {"name": "refs/sow/views/latest/...", "commit": "<git-id>", "manifest_sha256": "<sha256>"}
  ],
  "content_manifest_sha256": "<sha256>"
}
~~~

Refs sort by name and the document uses deterministic encoding. The generation document is immutable; **.sow/manifest.json** records its SHA-256. Local-versus-remote diff and recovery compare this whole vector and content manifest.

## 4. Local mutation and preservation

Every mutation follows: persist intent journal and expected HEAD; stage immutable bytes and metadata; validate hashes, signatures and confidentiality closure; create the canonical commit by ref compare-and-set; atomically materialize; mark the journal complete. Before the commit, recovery may discard staging. After the commit, recovery must finish materialization and never silently roll state back.

- **rm** removes a mutable-view reference, not bytes. It fails if the result removes an object reachable from stable, any snapshot/history ref, a target remote ref or a live journal.
- GC is a separate reachability operation. Roots include every repo/view/snapshot/remote ref, retained commit, materialized generation, provenance evidence and incomplete journal. Only unreachable objects may be deleted.
- Frozen EL8 permits verify, materialize, publish and byte-identical repair. Add, sync, promotion of new content, and non-gzip index regeneration fail.
- RPM provenance records upstream URL, index SHA-256/size and original RPM CAS object; its embedded signature is preserved and Day 1 does not re-sign it.
- DEB provenance records upstream URL, Packages SHA-256/size, DEB CAS object, and CAS hashes for signed InRelease/Release plus corresponding Packages evidence.

## 5. Publish saga and recovery

Each selected target persists these phases independently:

~~~text
planned → locked → immutable-uploaded → generation-ready → pointer-flipped
        → purged → verified → checkpoint-committed → remote-ref-advanced
~~~

- Overall exit is failure if any target is incomplete, but a completed target is never rolled back. Retry resumes each target with the same transaction and generation.
- Bodies, APT by-hash files, YUM generation files and asset hashes upload first. A mutable entry point flips only after its complete closure verifies.
- APT flips one InRelease. YUM treats repomd.xml and repomd.xml.asc as one logical unit.
- YUM package payloads use **Packages/<bucket>/<original-basename>**. Bucket is the lowercase first ASCII alphanumeric of RPM Name, or underscore when none exists. A different hash at an occupied path is an error; the same hash is idempotent. Metadata location href is exactly that root-relative path: no leading slash, dot-dot segment or cross-repository href is allowed.
- Migrating a flat YUM tree builds the complete split tree and repodata in staging, validates it with dnf, then flips the materialized repo. Prior flat bytes remain reachable from the previous manifest/remote generation until rollback retention expires; rollback rematerializes that ref and republishes its pointer.
- Locally, a complete YUM repodata directory is staged and fsynced, then atomically exchanged with the live directory using Linux **renameat2(RENAME_EXCHANGE)** or macOS **renamex_np(RENAME_SWAP)**. Plain rename cannot atomically replace a non-empty directory; unsupported filesystems fail preflight.
- Remotely, a complete YUM pair lives under an immutable generation prefix. A single generation pointer or mirrorlist switches after verification. Strict pair consistency requires an immutable generation base URL; ADR-0001 records the legacy raw-baseurl incompatibility.
- Remote mutable YUM metadata is stored below **.sow/generations/<20-digit-generation>/yum/<legacy-root>/repodata/**. Its only mutable selector is **.sow/channels/<view>/<repo>/<os>/<arch>.json**. Generation-aware mirrorlist URLs include the generation; the edge maps generation metadata to that immutable prefix and package requests to the shared legacy package path.
- Purge is mandatory and limited to mutable entry points: APT InRelease, the YUM channel/generation pointer, and channel aliases. L2/L3 verification must pass before checkpoint commit.

| Last durable phase | Mandatory retry |
|---|---|
| Before pointer flip | Reuse verified immutable uploads; do not expose staging. |
| After flip, before purge | Keep the coherent new generation; purge and verify. |
| After purge, before checkpoint | Read back pointer and hashes; verify; conditionally commit. |
| Checkpoint before local remote ref | Verify checkpoint identity; advance only that target ref. |
| Foreign generation/CAS conflict | Stop with drift diagnostics; never overwrite or auto-steal. |

Timeout alone never authorizes lock stealing. A matching transaction can resume; a foreign or stale owner requires explicit recovery backed by remote inspection.

## 6. URL and edge contract

**latest is a compatibility alias at every existing root path, not a /latest segment.** The normative pre-migration URL/content baseline is [make-target-map.md §3.2](migration/make-target-map.md); migration must capture and compare its HTTP status, redirect, bytes/checksum and cache metadata before switching. The preserved set includes:

- **/apt/infra/**
- **/apt/pgsql/<codename>/**
- **/yum/infra/<arch>/**
- **/yum/pgsql/el<major>.<arch>/**
- existing APT/YUM pgdg, percona and mssql roots
- **/get, /pig, /pkg, /beta, /ray, /cc, /claude**
- **/img/, /ext/, /src/, /etc/, /dba/, /pkg/pig/, /pkg/claude/, /pkg/ray/**

**/pkg/pig/latest** remains an ordinary text object whose body is the selected version, not a repository-channel directory. No URL present in the captured baseline may change merely because it is not listed above.

The existing beta host remains a distinct beta view; it is not silently remapped to latest.

The Pro form prefixes the same relative path, for example **/pro/v1/{token}/yum/infra/<arch>/**. Tokens are opaque URL-safe bearer credentials with at least 128 bits of entropy. Encoded slashes, normalization changes and traversal are rejected before authorization.

Generation-pinned YUM uses these additive URLs:

- public: **/_sow/v1/mirrorlist/latest/<repo>/<os>/<arch>.txt**
- Pro: **/pro/v1/{token}/_sow/v1/mirrorlist/<view>/<repo>/<os>/<arch>.txt**
- selected base URL: **/_sow/v1/g/<20-digit-generation>/<legacy-root>/**, with the Pro prefix when gated

The mirrorlist response contains exactly one absolute HTTPS base URL. The edge routes repodata requests to the immutable generation and package hrefs to the shared public/gated origin key. Legacy raw base URLs remain compatible, but cannot satisfy the strong detached-signature pair gate until migrated to this generation-pinned path.

Cloudflare Worker and EdgeOne share one behavioral contract:

1. Accept GET and HEAD; validate token, expiry, audience and path scope before origin access.
2. Strip the Pro prefix, map authorization to public or gated, and issue a clean origin subrequest. Token material is absent from origin URL, cache key, logs and errors.
3. Keep public and gated cache namespaces distinct. Immutable content caches by clean URL; token-bearing dynamic mirrorlists are **private, no-store**.
4. Template Pro mirrorlists only after authorization. OSS mirrorlists and latest aliases contain no token.
5. Return identical status, error and cache semantics on both vendors. Shared fixtures cover malformed, invalid, expired and under-scoped tokens, normalization, templating and Basic Auth fallback.

Malformed routes return 404, invalid or expired credentials return 401, valid but under-scoped credentials return 403, unsupported methods return 405, and temporary verifier/origin failures return 503. Authentication failures are private and no-store.

Gated origin keys are private. Logs redact the token segment. Basic Auth is the only fallback; it uses the same authorization and clean subrequest and strips Authorization before origin/cache.

## 7. Conformance gates

An implementation does not conform until tests prove:

- SQLite rebuild equivalence and zero external git/gpg/Python/Perl/repository-tool runtime dependencies.
- Crash recovery at every local journal and remote saga boundary.
- Stable/history preservation and unskippable public-to-gated confidentiality failures.
- Independent checkpoint conflict handling for both targets.
- Real apt/dnf acceptance of generated metadata and signatures.
- Remote signed YUM atomicity through the generation-aware path; the legacy migration gate in ADR-0001 cannot be waived silently.
- Production Linux/macOS filesystems pass hardlink and atomic-directory-exchange probes.
- The 50,000-package fixture demonstrates bounded worker parallelism by repo/component/arch, records throughput and proves index/link work is not one global serial loop.
- Manifest, package and XML processing is streaming/lazy; the 50,000-package run records peak RSS and proves no whole-repository in-memory collection.
- Default publish computes its plan from local desired/remote refs, performs a bounded checkpoint read plus O(changed objects) storage/CDN calls, and performs no ListObjects. Only explicit fsck may scale with the remote repository.
