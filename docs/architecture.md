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

There is one local writer. Read-only verification may run concurrently. Cloud targets advance independently and may point at different committed generations. The state lock serializes every conforming local mutation. Generation installation additionally binds the validated serving-root inode, rechecks it before and after each mutation phase, and anchors stage create/rename/cleanup to `os.Root`; an operator rename/replacement between phases fails closed without touching the replacement. A hostile same-UID process racing inside one multi-syscall pathname walk is outside the PRD single-writer threat model and must be excluded with OS ownership/permissions; SOW does not claim a filesystem transaction against such a process.

## 1. Local ownership and layout

~~~text
<root>/
├── sow.yaml
├── .sow/
│   ├── state/                 # non-bare embedded Git worktree; canonical
│   │   ├── .git/
│   │   ├── manifests/
│   │   ├── objects/
│   │   ├── provenance/
│   │   └── retention/apt-by-hash/views/...
│   │                               # sealed per-view/repo/suite ledgers
│   ├── cache/state.db         # disposable SQLite projection
│   ├── journal/<txid>.json    # durable recovery journal; no secrets
│   ├── sync/<upstream>/progress.json
│   │                           # private, secret-free sync phase/commit record
│   ├── sync/<upstream>/replay.jsonl
│   │                           # sealed O(change-set) offline package handoff
│   ├── stage/<txid>/          # unpublished staging
│   ├── origin/gated/          # private local projection; never anonymous
│   └── locks/
├── .pool/sha256/<aa>/<hash>   # immutable CAS bytes
└── apt/ yum/ bin/ src/ pkg/ etc/ img/ ...  # published tree
~~~

- **.sow/state** is a normal Git worktree operated through an embedded Go Git library. Calling a git executable is forbidden. Commits and refs are canonical; the checkout is only a materialization.
- Each repository manifest is UTF-8 TSV sorted by unsigned path bytes, with exactly path, size and SHA-256 separated by tabs. Paths are root-relative POSIX paths and reject absolute paths, dot-dot segments, backslashes, tabs, newlines, NUL and duplicate normalized names. Gated local projections use the reserved **.sow/origin/gated/** prefix, so their physical reachability is unambiguous.
- Pool classification, object coordinates, provenance and normalized-configuration hash are canonical files in the same commit; none may exist only in SQLite.
- **.sow/cache/state.db** is ignored by the inner repository. Deleting it and rebuilding from a commit must preserve all query results. Schema v3 records the exact canonical Git HEAD used for the rebuild; L1 reports `CACHE_HEAD_DRIFT` even when repository-manifest rows happen to be unchanged, so a ref-only snapshot, membership or provenance commit cannot leave a silently stale cache. Every production canonical mutation first fsyncs `.sow/transactions/catalog-projection.pending` and removes it only after the cache reaches the exact resulting HEAD. Projection-neutral commits compare Git blob/ref identities and use a strict SQLite HEAD compare-and-set; config/manifest/view/snapshot/provenance or relevant ref changes rebuild from Git. A kill after the Git commit therefore leaves a durable recovery marker, and both ordinary restart and explicit `--recover` rebuild and verify the exact HEAD before any new mutation; arbitrary unmarked drift is still reported rather than silently healed.
- **.pool** objects are immutable and named by SHA-256. Materialization uses hardlinks, so pool and tree must share a filesystem; preflight fails instead of silently copying.
- Every Nginx-visible APT/YUM/asset owner has a canonical receipt triple under **serving/materializations/&lt;target-sha256&gt;/&lt;view&gt;/routes/**. It binds the normalized absolute target identity, current config and complete ref vector, finite route claims, and frozen exact/payload manifests. The receipt is committed only after exact hostability/CAS validation; Nginx admission reprojects the current canonical view and replays L1 plus a final target/config/trust/Git barrier before emitting authority. Ordinary `fsck` audits every canonical triple, while physical validation remains target-bound because the stored target hash is intentionally not reversible. See [ADR-0024](adr/0024-materialized-route-read-capabilities.md).
- The visible legacy-root tree is the final public static repository and needs no SOW runtime. The static server uses an explicit allowlist containing only configured public repo paths, **/_sow/** generation routes, and the public trust anchor; every other root path is denied. Denying only **/.sow/** and **/.pool/** is insufficient because **sow.yaml** or an operator secret placed beside the serving tree could otherwise be read by a same-UID worker. Local control/cache files never enter a target content manifest. The gated projection enters only the gated target manifest and is remapped to a private origin namespace.
- Legacy Pro activation follows [ADR-0031](adr/0031-legacy-pro-gated-activation-and-checksum-repair.md): the source owner remains physically at **pro/**, its known zero-byte checksum is excluded from the baseline and replaced through gated `sow add`, and stable materializes below **.sow/origin/gated/pro/**. This preserves source bytes while keeping the generated checksum under ordinary CAS/Git/view/recovery controls.
- Remote storage is private. Public bytes retain their legacy object keys; gated bytes map to remote **.sow/gated/<legacy-path>**. The edge is the only public origin and rejects all client **/.sow/** requests. It accesses gated/control keys only through a private binding or signed vendor request.

## 2. Configuration schema v1

The discriminator is exactly **schema: sow/v1**. Unknown fields, duplicate IDs, dangling references and plaintext secret values are errors. URL/layout defaults are normalized and their hash is committed with every state change.

Any operation that signs APT or YUM metadata requires `gpg.public_key` as the
client trust anchor. The injected private key must be the same single OpenPGP
entity and sole signing key; a missing anchor, an unrelated override, or a
public-key file containing private material fails before metadata staging.
Asset-only operations deliberately remain keyless.

Published package generations additionally bind the decoded public OpenPGP
packet stream as `repository_key_sha256`; the generation digest carries that
identity into checkpoints, COS locks and recovery journals. A changed key at
the same path is detected by no-change preflight and L2-L4 verification. Per
[ADR-0010](adr/0010-repository-signing-identity-and-rotation-boundary.md), an
already published schema-v1 target cannot replace that key online: restore the
recorded key for replay, or execute a separate offline target/client migration.
This single identity signs repository metadata. Byte-preserved upstream RPMs
retain their own embedded signatures, so DNF clients also receive a
fingerprint-pinned public package trust bundle and keep both `repo_gpgcheck=1`
and `gpgcheck=1`. Package verification keys are public asset bytes, not extra
SOW signing identities; the optional FR-17 full re-sign phase is the only path
to a genuinely single package signer.

Target-generation `config_sha256` is a separate, domain-separated publication
identity, not the raw YAML digest. It binds the canonical YAML SHA-256 plus the
sorted repo ID/SHA-256 identities of only those YUM `package_keyring` files
reachable from the generation's complete ref vector. Publication loads those
files once into an immutable trust snapshot; the same snapshot supplies both
`config_sha256` and the parsed in-memory keyrings used for RPM verification.
Consequently an unrelated, unreachable YUM keyring is not a dependency of an
asset-only or disjoint publication, while changing bytes at a reachable keyring
path necessarily changes the generation identity.

RPM package-keyring parsing preserves OpenPGP packet history rather than only a
library-normalized current entity: primary self-certifications/revocations and
every signing-subkey binding, embedded cross-certification and revocation remain
available for time-aware verification. At the RPM signature creation time SOW
selects the newest cryptographically authenticated policy packet first, then
enforces its signing flags, key lifetime, self-certification/binding/cross-
certification expiry and revocation. Failure of that newest policy is terminal;
an older permissive packet cannot be used as fallback. `KeySuperseded` and
`KeyRetired` take effect prospectively, while compromise and unspecified
revocations are retroactive.
Binary keyring bytes are identity-bearing packet data and are never passed
through generic whitespace trimming; a trailing byte such as `0x0b` must survive
unchanged. Only ASCII-armored keyrings accept outer textual whitespace before
armor decoding.

~~~yaml
schema: sow/v1
state:
  snapshot_materialization_months: 6
  apt_by_hash_retention: 2
  yum_generation_retention: 2
  cas_history_commits: 32
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
    yum: {compression: zstd, package_keyring: keys/pigsty-and-upstreams.asc}
upstreams: []
views:
  beta:   {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://<account>.r2.cloudflarestorage.com", bucket: repo, region: auto, credential: env://SOW_R2_CREDENTIAL, delete_mode: conditional}
    cdn: {kind: cloudflare, base_url: "https://repo.pigsty.io", beta_base_url: "https://beta.pigsty.io", zone_id: "<zone-id>", credential: env://SOW_CF_TOKEN}
  cos:
    storage: {kind: cos, endpoint: "https://cos.<region>.myqcloud.com", bucket: "repo-<appid>", region: "<region>", credential: env://SOW_COS_CREDENTIAL, delete_mode: conditional, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo.pigsty.cc", beta_base_url: "https://beta.pigsty.cc", distribution: "<zone-id>", credential: env://SOW_TENCENT_TOKEN}
edge:
  pro_prefix: "/pro/v1/{token}/"
  token_verifier: provider://pigsty-entitlements
~~~

`state.apt_by_hash_retention` is a positive total-index-generation count and
defaults to 2. Each successfully installed APT `InRelease` advances the sealed
canonical sequence under `retention/apt-by-hash/views/<view>/<repo>/<suite>.json`;
byte-distinct checkpoints that reference the exact same immutable index path
set share one retention slot, with the newest checkpoint remaining live. Cleanup
first validates every retained immutable object, then removes only paths not
referenced by the live/newest retained generations, and commits all ledgers in
one serial Git transaction after concurrent repository preparation finishes.
An interrupted cleanup is safely replayable: deletion is idempotent and the
old ledger remains sufficient to reproduce the same exact removal set.
Remote cleanup is target-local and history-backed: the old target content
manifest binds size/SHA, the current ledger and live Release prove absence from
the retained closure, and a valid ancestor ledger proves ownership. Therefore a
successful cf commit cannot consume the tombstone required by a lagging cos.

`state.yum_generation_retention` is a positive previous-generation count and
defaults to 2. Every local mutable-YUM channel keeps current plus that many
newest prior pins. Channel state is partitioned below
`serving/yum/targets/<sha256(root,base-url)>/channels/...`; target root and clean
base URL remain in the canonical body, so default serving, explicit exports,
and multiple exports cannot borrow one another's parent lineage. Incomplete
local-serving journals independently pin both desired and parent generations.
Expired generation JSON/TSV pairs are removed from canonical HEAD before they
cease to be CAS roots; historical Git commits do not silently extend this
explicit window. Derived generation directories are removed only by an
explicit, evidence-bound GC after no channel or journal retains them.

Normative schema rules:

- Top-level keys are **schema, state, gpg, pools, repos, upstreams, views, serving, targets, edge**. Provider unions are closed to R2/Cloudflare and COS/EdgeOne; v1 is not a generic cloud plugin API.
- A repo has a stable ID, type **apt|yum|asset**, legacy-relative POSIX path, OS lifecycle, arches and default confidentiality pool. Its apt/yum/asset blocks are mutually exclusive. The first path component is also a routing discriminator: APT roots are exactly **apt** or below **apt/**, YUM roots are exactly **yum** or below **yum/**, and asset roots may use neither namespace. Backslashes and control characters are rejected before any filesystem or edge projection.
- Asset paths are immutable unless they match an explicit
  **asset.mutable_paths** glob. A mutable asset publication also stores the
  selected bytes under **objects/sha256/<digest>** (gated for private content)
  before overwriting and purging the legacy pointer. Canonical `add --replace`
  permission and physical hardlink repair are separate checks: every
  add/rm/publish/adoption materializer evaluates each repository-relative path
  against the glob, and no caller can grant replacement authority to an entire
  asset manifest.
- A legacy asset tree that must be captured before it has a canonical route may
  use **active: false + asset.kind: inventory + asset.inventory_carrier: true**.
  This is a local M0/fsck baseline only: it requires a non-root public path and
  has no root keys or mutable paths; adoption and every mutation/serving/remote
  command exclude it. Reviewed sensitive paths must still be excluded from its
  scan contract. The later canonical repository has a separate ID and root.
- An upstream has an ID, destination repo, HTTPS URL, arch set, ordered allow/deny name filters, debuginfo policy and optional secret reference. Successful sync always writes provenance; this is not configurable off.
- A view declares access, allowed pools, selection rules and append-only behavior. Public views may name only the public pool; stable is always append-only and may name both pools. `views.snapshot` is rejected in schema v1: immutable snapshot refs derive stable's fixed Pro/public+gated/append-only policy, so an accepted but ignored snapshot policy cannot contradict runtime behavior.
- A production profile declares both cf and cos. A local/test profile may omit targets so init, local repository work and verification do not require cloud credentials; publishing an absent target fails. Storage/CDN fields are provider-specific closed unions with endpoint, bucket/zone or service identifiers, public base URL and secret references; config cannot invent a third provider kind.
- The executable provider boundary is frozen by [ADR-0016](adr/0016-frozen-vendor-sdk-boundary.md): R2 and COS share AWS SDK v2 S3, while Cloudflare purge uses `cloudflare-go/v7` and EdgeOne purge uses Tencent TEO `v20220901`. R2/COS-only Smithy middleware may project the vendors' create-only/copy header dialect before the official signer; it is not a generic provider extension point, and no hand-written SigV4/TC3/purge fallback remains.
- COS storage `session_token` is projected to the provider-defined, signed
  **x-cos-security-token** header and never to the AWS header spelling; R2
  retains the standard S3 session-token behavior.
- Target YAML owns only stable provider identity and capability configuration. Dynamic published ref vectors, checkpoints, content baselines, channel state and inventory coverage live under canonical `remotes/<target>/...` and are advanced by embedded-Git transactions; publish never writes state back into operator configuration. [ADR-0015](adr/0015-target-identity-and-published-ref-state.md) records this concrete projection of FR-41's earlier schema sketch.
- Selectors operate on repo, OS, arch and view. An empty match is an error unless that command explicitly defines a no-op.
- Secrets enter only through CLI input, **env://NAME**, or a registered secure-provider reference. References validate at config load, but values resolve only when the selected operation needs them, so init remains offline. Resolved values never enter config snapshots, Git, journals, logs or errors.
- Target secret values use strict JSON. Storage requires
  **access_key_id/secret_access_key** and optional **session_token**.
  Cloudflare CDN requires **api_token**; Tencent CDN requires
  **secret_id/secret_key** and optional **session_token**. Pro publication also
  requires **basic_username/basic_password** in each CDN secret for publication
  verification and the stable Basic fallback. Independent stable L3/L4 may
  instead receive a protected runtime token file; its value is projected onto
  **/pro/v1/<token>/** only in memory and never changes canonical plans.
- EL8 is **lifecycle: frozen** beginning with Pigsty v5.0.0 and uses gzip repodata. v1 rejects active or zstd EL8.
- Snapshot materialization defaults to six calendar months and is configurable to a positive value. Stable is always materialized; older refs remain canonical and can be restored on demand.
- The Pro prefix is fixed to **/pro/v1/{token}/**; another v1 shape is invalid.
- **edge.token_verifier** is a closed non-secret reference, either
  **provider://<lowercase-id>** or **env://<UPPERCASE_BINDING>**. Config preflight
  maps every target to the versioned **sow-edge-runtime/v2** deployment
  variables; a reference that cannot be represented by that target fails config
  loading. Secret values are not part of this mapping.

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
- Each target stores **.sow/manifest.json** as `sow-checkpoint/v2` with target, generation, parent generation, intent view, commit, source-manifest SHA-256, canonical publication-plan SHA-256, transaction ID, phase and UTC update time. Strict v1 decoding is migration-only: purge-free v1 is directly admissible; nonempty v1 remains blocked until local-only `fsck --target <one> --repair-purge-ledger` verifies its atomic Git-anchor receipt and installs a deterministic `sow-legacy-purge-plan-attestation/v1` under `remotes/<target>/purge-migrations/`. The witness binds anchor, target, generation, transaction and generation/checkpoint/plan/receipt SHA-256s without rewriting the historical checkpoint or accessing a provider.
- Checkpoint mutation is compare-and-set against observed generation/ETag. The committed checkpoint ETag is part of canonical local remote state and is the only parent ETag accepted for the next R2 generation; the ETag of a locked or remote-ahead checkpoint cannot replace it. The local remote ref advances only after the checkpoint is committed and post-publish verification passes. A target that cannot prove conditional-write semantics fails its capability probe and cannot be called production-ready.

One target generation serializes the complete selected ref vector, not one arbitrary leaf commit:

~~~json
{
  "schema": "sow-target-generation/v1",
  "generation": 42,
  "parent_generation": 41,
  "desired_commit": "<aggregate-state-commit>",
  "intent_view": "latest",
  "config_sha256": "<sha256>",
  "repository_key_sha256": "<decoded-public-openpgp-packet-sha256>",
  "refs": [
    {"name": "refs/sow/views/latest/...", "commit": "<git-id>", "manifest_sha256": "<sha256>"}
  ],
  "channels": [
    {"view":"latest","repo":"infra","os":"el10","arch":"x86_64","generation":42,"remote_key":".sow/channels/latest/infra/el10/x86_64.json","legacy_root":"yum/infra/x86_64","body_sha256":"<sha256>"}
  ],
  "content_manifest_sha256": "<sha256>"
}
~~~

Refs sort by name, channels sort by remote key, and the document uses deterministic encoding. A channel body is reproducible from its generation and legacy root and is also persisted in canonical per-target state. Selector-scoped publishing carries prior channel mappings and replaces only changed YUM leaves. The generation document is immutable; **.sow/manifest.json** records its SHA-256. Local-versus-remote diff and recovery compare this whole vector and content manifest.

For this document, **config_sha256** means the publication identity defined in
section 2. It covers the canonical YAML and only the package-trust files reachable
from this exact `refs` vector; it must never be populated by hashing YAML alone or
by rereading a keyring independently of the immutable trust snapshot.

## 4. Local mutation and preservation

Every mutation follows: persist intent journal and expected HEAD; stage immutable bytes and metadata; validate hashes, signatures and confidentiality closure; create the canonical commit by ref compare-and-set; atomically materialize; mark the journal complete. Before the commit, recovery may discard staging. After the commit, recovery must finish materialization and never silently roll state back.

- **external builder handoff** is an admission assertion, not a build feature.
  Repeated `--expected-object sha256:<digest>:<size>` values bind one-for-one to
  ordered positional inputs before asset/DEB/RPM admission. Non-canonical or
  mismatched assertions fail before a novel CAS object/view entry; a successful
  command emits a domain-separated receipt over ordered basenames and object
  identities. Canonical manifests/refs remain truth, while builder source and
  toolchain attestations remain external evidence preserved alongside that
  receipt. The migration external builder now pins all eight reviewed
  `.io/.cc` source bodies and emits four deterministic mirror-aware canonical
  root assets; only those generated SHA-256/size identities can cross this
  boundary. Future source drift requires a new builder review and receipt.

- **add RPM** first copies the caller pathname into a private `0700` snapshot
  directory and inspects that snapshot. Embedded-signature verification reads
  a stable descriptor and closes it promptly; CAS `ImportExpected` then reopens
  only that private snapshot and streams it against the exact inspected size and
  digest before installation. A caller-path replacement, snapshot replacement,
  or same-size byte change therefore cannot admit bytes other than those whose
  signature and expected object identity were established, without retaining
  one descriptor per package across a large batch.

- **sync** holds an advisory lock for one upstream across discovery, provenance,
  view ingestion and derived-index installation. Before provenance commit it
  seals and fsyncs an O(change-set) `replay.jsonl` containing only digest, size,
  routing and safe basename, then atomically persists a private
  `sow-sync-progress/v1` record containing upstream/repo identity, exact
  config+selector digests, replay digest/count, phase, canonical commit and
  completed component names. A retry must use the exact original config and
  selectors; `--recover` may reconcile stale canonical transactions but cannot
  rebind that durable intent. Once progress contains a provenance commit, retry
  never rediscovers the mutable upstream or replaces that commit: it verifies
  the sealed replay and recovers from verified download cache/CAS plus canonical
  refs. If a view committed before APT/YUM materialization/signing failed, the
  retry projects canonical beta/stable refs directly into CAS hardlinks and
  signed indexes without re-inspecting/re-importing view-present packages.
  Successful convergence fsyncs/removes exact-prefix abandoned transaction
  directories and only then removes progress. Symlink/special residue fails
  closed.
  A discovery result marked `present` still has to be bound to exact bytes. A
  newly downloaded or unproven present candidate is opened through a stable
  handle, streamed to its advertised SHA-256/size, and, for RPM, verified against
  the immutable package keyring. The incremental exception is evidence-bound:
  an unchanged first-valid DEB receipt may be reused; an RPM receipt may be
  reused only at schema v3 with the same package-keyring SHA-256. Keyring
  rotation and legacy RPM receipts force revalidation, and a CAS object newly
  entering a view passes `pool.Verify` before its hardlink is created. Full
  whole-pool auditing remains the explicit `fsck` path required by FR-06.
  For APT, present suppression additionally requires exact component, package
  name, version and size in the selected view/architecture. Component parsing
  strips the exact configured repository path prefix before accepting only
  relative `pool/<configured-component>/...`; a repo-root substring or a
  same-digest move between components cannot suppress the new placement.
- **rm** removes a mutable-view reference, not bytes. It fails if the result removes an object reachable from stable, any snapshot/history ref, a target remote ref or a live journal.
- GC is a separate, explicit reachability operation so ordinary mutations stay incremental. Roots include every repo/view/snapshot/remote ref, retained commit, materialized generation, provenance evidence and incomplete journal. `sow gc` automatically computes and verifies the complete orphan set; deletion additionally requires that exact set digest via `--apply --confirm`, and a changed/missing/corrupt set fails closed. Only unreachable objects may be deleted; [ADR-0008](adr/0008-gc-reachability-and-confirmation.md) freezes this interpretation of automatic reclamation.
- Frozen EL8 beginning with Pigsty v5.0.0 permits verify, materialize, publish and byte-identical repair. Add, sync, promotion of new content, and non-gzip index regeneration fail.
- RPM provenance records upstream URL, index SHA-256/size and original RPM CAS
  object. New v3 receipts retain bounded packet evidence and additionally bind
  `signature_verification=verified`, the exact package-keyring SHA-256, signature
  creation time, coverage, signed byte count, and verified signer/primary
  fingerprints. RSA/DSA header signatures also require a signed payload digest,
  or a companion trusted whole-package signature for historical RPMs. Existing
  v1/v2 receipts remain byte-identically decodable/replayable without invented
  trust; replay still verifies the current bytes against the current repository
  package keyring before retaining the first canonical observation. URL/index
  rotation and trust-bundle additions do not rewrite artifact-keyed history.
  Historical primary and signing-subkey policy packets are retained. Verification
  selects the latest authenticated self-certification/binding in force at the
  package-signature time before checking expiry, flags, lifetimes, required
  cross-certification and revocation; it never falls back across a failed newest
  policy. Normal supersession/retirement is prospective, whereas compromise/
  no-reason revocation invalidates historical signatures retroactively.
  [ADR-0014](adr/0014-rpm-provenance-signature-evidence-boundary.md),
  [ADR-0017](adr/0017-rpm-package-keyring-and-cryptographic-verification.md)
- DEB provenance records upstream URL, Packages SHA-256/size, DEB CAS object, and CAS hashes for signed InRelease/Release plus corresponding Packages evidence.
- Default `init` commits only the exact serving-tree baseline. Explicit
  `init --adopt-content` may additionally prove local APT membership from Packages,
  YUM membership from repomd→primary, and asset membership from the baseline; it
  hashes and parses each body before CAS import. Before the first CAS write, one
  transaction-wide SQLite spool proves that every selected package body is indexed,
  every index entry resolves to the immutable M0 baseline, and every canonicalized
  legacy YUM collision is byte-identical. Safe flat/nested YUM hrefs normalize to
  `Packages/<name-initial>/<basename>` while provenance retains every physical source
  alias; malformed canonical buckets and missing bodies fail closed by default. A
  missing indexed YUM body may be omitted only through the exact blocker-set digest
  confirmation in
  [ADR-0030](adr/0030-audit-bound-legacy-yum-missing-body-prune.md). That two-pass
  path rejects index drift, commits one negative-provenance entry per omission, and
  never applies to a present but unindexed body. Canonical admission and fsck
  require each ledger to remain byte-identical across every HEAD/direct-ref reachable
  commit, rebind every receipt to the repo ref's ancestor baseline manifest, and
  recompute the complete cross-repo confirmation set. See also
  [ADR-0027](adr/0027-legacy-package-adoption-admission-and-canonicalization.md).
  Adoption never rewrites the serving tree and commits view refs plus
  `provenance/legacy/<repo>.jsonl` receipts, plus any explicitly confirmed
  `provenance/legacy-pruned/<repo>.jsonl` negative receipts, in one canonical
  transaction. Those receipts state legacy migration/repair only, not upstream
  signature provenance or current RPM signer trust. A later body/import failure may leave content-addressed CAS
  orphans, but cannot leave partial view/receipt refs; a later
  explicit materialize is the structural migration that regenerates SOW-owned
  metadata. Legacy YUM repomd signatures are not inferred from the new repository
  signing key: the default validates the repomd-to-primary checksum chain and emits
  `not-claimed`. An explicit public-only `--legacy-metadata-keyring` freezes the exact
  bundle digest before state mutation and makes a valid `repomd.xml.asc` mandatory on
  every selected YUM leaf. For YUM, the first materialize or publish and independent L1 each verify
  every selected/indexed RPM against the repo's current `yum.package_keyring`; an old
  receipt or existing CAS object cannot bypass a removed-key or invalid-signature
  failure.

## 5. Publish saga and recovery

Publish has a local preparation barrier before any target saga: materialize every
selected view, atomically record the real latest serving trees in their repo
manifests/refs, rebuild the derived cache, then freeze one canonical
`desired_commit`. All target/view generations in that invocation use that frozen
commit even when an earlier target success appends remote-tracking state. A local
materialization or scan failure leaves the prior repo baseline in place; an
interruption after its canonical commit is completed by the local journal before
remote recovery. Explicit materialization targets are exports and never advance
the latest working-tree baseline.

The target preparation also loads one immutable RPM trust snapshot for the exact
generation ref vector. If an inherited ref entry and the publication identity are
both unchanged, its prior trust proof is reused without opening either manifest
or package bytes. Under the same identity, a changed ref streams the old/new
manifest delta and verifies only added or replaced RPM objects; removals require
no package read. A first publication, or any publication-identity/package-keyring
policy change, verifies the full reachable RPM closure. Each selected CAS RPM is
hashed and its embedded signature is checked through one file descriptor, after
which SOW rechecks descriptor metadata and canonical path/inode, size and mtime;
any coordinate swap or concurrent mutation fails before remote effects.

Each selected target owns one independent ordered intent sequence. Explicit
multi-view work advances `beta -> latest -> stable`; explicit snapshots advance
in sorted snapshot-ID order; the default sequence is `exact interrupted
snapshot/view recovery -> beta -> latest -> stable -> retained snapshots`.
A failed intent stops later work only for that target. Recovery inspection and
provider work never wait at a sibling view/snapshot barrier, including when the
requested worker count is one. Frozen local publications are shared read-only;
only canonical target-state persistence, plus rare selected-set preparation of
an interrupted snapshot outside retention, uses the cross-target coordinator.

Each selected target persists these phases independently:

~~~text
planned → locked → immutable-uploaded → generation-ready → pointer-flipped
        → purged → verified → checkpoint-committed → remote-ref-advanced
~~~

- Overall exit is failure if any target is incomplete, but a completed target is never rolled back. Retry resumes each target with the same transaction and generation.
- Bodies, APT by-hash files, YUM generation files and asset hashes upload first. A mutable entry point flips only after its complete closure verifies.
- APT flips one InRelease. YUM treats repomd.xml and repomd.xml.asc as one logical unit.
- APT publication ownership is suite-wide, never architecture-wide: `--arch` selects a transaction trigger, then every configured/ref-backed architecture named by that suite's Release enters the preparation, preflight and L1 closure. A partial suite replaces only its `dists/<suite>` subtree; selected shared-pool paths are streamed as exact upserts while unselected-suite and historical pool extras remain. The same predicate merges fixed snapshot materialization roots, so partial snapshot replay cannot prune sibling repos or arches.
- Local payload, metadata, asset and serving flips are coordinated by one durable selected-set transaction described in [ADR-0018](adr/0018-selected-set-local-materialization-transaction.md). It freezes the exact suite/leaf/ref/config/key identities before the first hostable-tree mutation, fences unrelated writers, and requires exact recovery after every started failure, even if all leaf units had completed before a later exact scan or business step failed. Direct partial `materialize` uses ownership merge only for fixed product-owned view and snapshot roots. An explicit `--target` is an exact selector export and exact serving-topology owner for that physical root: it cannot retain content, channel state, active generation ledgers or target registries from a prior view/base URL. Full snapshot replay is exact, while fixed mutable views alone retain product-managed `_sow` and canonical APT by-hash generations for delayed clients. Pure asset transactions use a domain-separated no-repository-key identity while still binding config, refs and target. Asset-add recovery is input-independent and runs before current asset/RPM/DEB subtype dispatch; physical replacement remains path-scoped to `asset.mutable_paths` in add, rm, publish and archive-adoption paths. An active package-add journal admits CAS restoration only after the retry matches one homogeneous family, the exact durable unit vector and complete entries already present in the frozen refs; cross-family, novel-entry and package-to-asset retries fail before CAS. [ADR-0026](adr/0026-offline-archive-projection-intent.md) adds a separate archive visibility bridge: before the taint receipt or public name, the completed inode, frozen ref proof, digest, configuration and exact destination are fsync-bound below private state, so recovery never rebuilds an interrupted archive from an advanced mutable ref. Offline archive adoption is a second scoped transaction because its asset ref exists only after archive creation; recovery closes that frozen CAS/ref projection before planning a new materialize selector. Historical publish recovery similarly closes its isolated local selected set before any remote observation.
- YUM package payloads use **Packages/<bucket>/<original-basename>**. Bucket is the lowercase first ASCII alphanumeric of RPM Name, or underscore when none exists. A different hash at an occupied path is an error; the same hash is idempotent. Metadata location href is exactly that root-relative path: no leading slash, dot-dot segment or cross-repository href is allowed.
- Migrating an ordinary, release-specific flat YUM tree builds the complete split tree and repodata in staging, validates it with dnf, then flips the materialized repo. Prior flat bytes remain reachable from the previous manifest/remote generation until rollback retention expires; rollback rematerializes that ref and republishes its pointer. Frozen mixed-release `yum/infra/{arch}` is deliberately excluded from this shortcut.
- Each frozen cross-EL `yum/infra/{arch}` leaf is owned by an inactive, public, unfiltered carrier and an independent active EL9/10 policy owner. Its dedicated [ADR-0021](adr/0021-frozen-cross-el-yum-infra-compatibility-projection.md) state machine is `S0 raw baseline -> S1 immutable source/CAS adoption -> S2 isolated signed candidate freeze -> S3 append-only cutover authority`. S0 accepts the legacy unsigned seven-record repomd only as fully checksummed migration input; S1 verifies every RPM against a public-only package keyring; S2 stores candidate manifest, dual trust, receipt and witness beneath permanent refs but grants no public candidate/generation/trust route. S3 alone binds a root-relative controlled serving link, independent compatibility channel, exact mirrorlist and two exact trust keys. The local crash journal is written before the canonical event and ordinary commands fail before output or provider construction while either its base or `.next` phase exists. Recovery validates the exact canonical event, converges the root-bound link and removes both durable journal names. Rollback appends a linked event rather than deleting history: it removes only S3 entry points, keeps the raw bridge consumable and retains S1/S2 CAS roots plus immutable generations.
- Locally, a complete raw YUM repodata directory is staged and fsynced, then exchanged with the live compatibility directory using Linux **renameat2(RENAME_EXCHANGE)** or macOS **renamex_np(RENAME_SWAP)**. That exchange is crash-safe for the namespace but is not a client transaction selector: DNF can still issue one GET before and one GET after the swap. Strong local service therefore uses a static mirrorlist at **_sow/v1/mirrorlist/<view>/<repo>/<os>/<arch>.txt**. The one-line pointer atomically selects a content-derived immutable closure at **_sow/v1/g/<20-digit-id>/<legacy-root>/** containing Packages and the complete signed repodata set. Raw baseurl remains only the compatibility bridge.
- Local generation identity domain-separates view/repo/OS/arch, legacy root, canonical view commit, config digest, repository-key digest and the exact serving manifest. Repodata is imported into CAS before the generation tree is hardlinked, so retained `serving/yum/generations/.../*.tsv` files are strict GC roots rather than best-effort adoption records. Occupied IDs are byte-for-byte verified and a projection collision or drift fails closed. Each new generation keeps its own current repodata while hardlinking retained `Packages/**` payloads as an unindexed compatibility closure; a fresh client sees only current packages, while an in-flight DNF retry can still fetch an older payload for the configured flip window.
- Retirement moves the exact TSV to `serving/yum/retired/...` in the same canonical transaction that drops its active ledger. This deletion witness is not a CAS root; it exists so confirmed GC can resume a partial directory removal while rejecting changed or extra paths. Target-channel deletion and the resulting ledger retirement are one canonical transaction. A fixed/default root retains its partial cumulative target semantics, while an exact explicit export removes every now-unclaimed target registry in that same confirmed reconciliation instead of leaving a known orphan for a later GC pass.
- The canonical channel JSON is committed before the mirrorlist flip and binds both desired and parent mirrorlist digests. It also stores newest-first bounded previous pins and a deterministic target identity derived from target root + serving base URL. A separate local-serving journal covers generation-ready, state-committed and pointer-flipped boundaries because `state.ApplyOptions.AfterCommit` is not replayed by canonical recovery. `materialize --recover` and `publish --recover` verify the immutable generation, converge the target-partitioned ledger, compare parent/desired pointer bodies, atomically replace the pointer and read it back; foreign state is never overwritten. latest serves from the repository root, beta from `.sow/materialized/beta`, and stable Basic fallback from `.sow/origin/gated` behind the clean `/pro/v1/basic` URL prefix. Explicit mutable-YUM exports require an explicit `--serving-base-url`.
- Remotely, a complete YUM pair lives under an immutable generation prefix. A single generation pointer or mirrorlist switches after verification. Legacy raw-baseurl aliases are still updated for URL compatibility: non-pointer repodata first, then `repomd.xml.asc`, and `repomd.xml` last, followed by purge and verification of both pair URLs. Object storage cannot make those two legacy keys one atomic write, so strict pair consistency still requires the immutable generation base URL; ADR-0001 records this explicit migration gate.
- Remote mutable YUM metadata is stored below **.sow/generations/<20-digit-generation>/yum/<legacy-root>/repodata/**. Stable uses the private dynamic selector **.sow/channels/stable/<repo>/<os>/<arch>.json**; public beta/latest publish ordinary static **_sow/v1/mirrorlist/<view>/<repo>/<os>/<arch>.txt** objects. Generation-aware mirrorlist URLs include the generation; L2 compares stable channel JSON and reconstructs the exact beta/latest static mirrorlist bytes from the accumulated `ChannelState` vector.
- A persisted plan is recovery input, not an authority. Before a lock or remote mutation, request validation re-derives every APT/YUM generation number, client route, transformed digest and deletion view from the immutable `TargetGeneration`. A current normal YUM leaf is a bidirectional O(objects+channels) closure: exactly one primary, filelists, other, `repomd.xml` and `.asc`; byte-identical compatibility aliases; one current `ChannelState`; and its exact static/dynamic generation pointer. Missing either direction fails before remote state is touched; [ADR-0013](adr/0013-persisted-publication-plans-are-untrusted.md) freezes this trust boundary.
- The canonical Git target state retains `remotes/<target>/purges/<20-digit-generation>-<transaction>.json` for every nonempty purge plan. L2, fsck, remote-inventory adoption and every publish path prove the complete `1..N` generation ledger before network access: each publication anchor must descend from the prior anchor in the Git DAG; its global generation/checkpoint/plan, target `content.tsv`, and intent-local generation/checkpoint/plan must form one exact immutable closure; each receipt must exist in that atomic publication commit, remain byte-identical at HEAD, bind the generation/checkpoint/plan and full URL closure, and contain a latest completed full attempt. Provider/zone binding is evaluated against `config/sow.yaml` in that generation's publication commit, so an audited zone rotation is valid without allowing current configuration to rewrite history. Missing, moved, changed, orphan or semantically incomplete historical evidence blocks later generations instead of being hidden by them. Once a target has published, deletion or rewriting of the global triplet, content, or intent-local triplet without a new generation is permanent drift. The oldest-to-newest scan inflates one envelope and at most one 4 MiB receipt at a time; one `publish` invocation may cache a successful result only for the exact target and canonical HEAD. `fsck --repair-purge-ledger` is additive and network-free: under the state lock it restores only exact anchor receipt bytes plus derived legacy attestations, commits them recoverably, rebuilds the HEAD-bound SQLite cache, re-audits the whole ledger, and refuses sibling anchors, orphan evidence, deleted intent closure, or damaged publication envelopes. Bounded L2 also verifies the exact COS create-only generation lock; full fsck/adoption rejects reserved control objects and any reappearance of a planned deletion before LIST/HEAD/GET.
- Snapshot route JSON has one shared canonical encoder and binds snapshot ID plus target generation. Snapshot-owned payload keys are create-only. Every snapshot YUM `Packages/` leaf must have the same five-object immutable generation metadata closure, so a self-consistent route/package plan cannot publish an unusable DNF snapshot.
- Purge is mandatory and limited to mutable entry points plus explicitly removed serving URLs: APT InRelease, the YUM channel/generation pointer, channel aliases, `asset-serving`, and restore-only `restore-index-serving` deletes. APT by-hash deletion never expands purge. L2/L3 positive or exact-negative verification must pass before checkpoint commit.
- The exact purge set contains both the client-visible URL and any internal `.sow/*` clean-cache key used by the edge adapter. Even when the checkpoint is already committed, recovery reissues that same normalized purge set before L3; checkpoint durability alone cannot prove that a CDN retained a prior invalidation.
- Remote deletion is a closed, evidence-bound union: snapshot-owned retention, selected asset serving paths, expired APT by-hash paths, and beta/latest restore-only APT `dists`/YUM `repodata`/public mirrorlist entry points. Ordinary `Plan.Removed`, package payloads, immutable generation metadata, checkpoint keys and `objects/sha256` archives cannot become DELETE operations. The saga proves size, streams and hashes the live body while binding a stable ETag (custom checksum metadata may reject but never authorize deletion), then runs a deterministic SOW-owned capability probe with a wrong `If-Match`. `storage.delete_mode` defaults to `conditional`: only an endpoint that rejects the wrong condition and retains the probe may issue the live ETag-bound DELETE. Cloudflare R2 really ignores DeleteObject `If-Match`, so an explicit `checkpoint-fenced` mode exists only for the PRD's revoked-legacy-writer/single-operator boundary: it revalidates the R2 checkpoint ETag (or COS create-only generation lock), repeats the complete streamed identity proof, invokes an explicitly unconditional vendor DELETE, and rechecks absence plus the unchanged remote fence. It does not claim to close an external writer racing in the final provider-unfenced window; multiwriter operation is outside this mode. Origin absence, exact purge and CDN 404/410 close every routed deletion; a fully routed deletion-only transaction needs no invented positive probe. See ADR-0036.

| Last durable phase | Mandatory retry |
|---|---|
| Before pointer flip | Reuse verified immutable uploads; do not expose staging. |
| After flip, before purge | Keep the coherent new generation; purge and verify. |
| After purge, before checkpoint | Read back pointer and hashes; verify; conditionally commit. |
| Checkpoint before local remote ref | Verify checkpoint identity; advance only that target ref. |
| Foreign generation/CAS conflict | Stop with drift diagnostics; never overwrite or auto-steal. |

Timeout alone never authorizes lock stealing. A matching transaction can resume; a foreign or stale owner requires explicit recovery backed by remote inspection.

An already committed target generation is restored only through
`sow publish --restore-generation N --target cf|cos`. This is a forward-only
publication, not a checkpoint rewind: the command proves the historical
generation/checkpoint/content/ref closure plus a byte-identical intent-scoped
plan projection in canonical history, rebuilds a new plan and the source intent
from local refs and CAS without moving the current local view,
and commits `current+1` through the complete upload/pointer/purge/verify saga.
The restored intent receives its complete historical ref vector while refs for
other intents remain current; each target is restored independently and records
`remotes/<target>/restores/<new-generation>.json`. Current configuration must
match the historical generation, and missing CAS or confidentiality evidence
fails before remote mutation. Historical stable/snapshot pool classification is
read from those same historical ref commits, never current refs. For beta/latest,
a parent-only ref is projected from the canonical config at the parent
`DesiredCommit`; an absent/invalid mapping fails closed. Asset serving paths are
removed exactly. APT/YUM topology removal deletes only mutable `dists`,
`repodata`, and public mirrorlist entry points while retaining package payloads
and immutable generation archives; the local `refs/sow/remotes/<target>/...`
vector is transactionally compare-and-deleted to match the committed generation.
Stable is stricter and permits restore only when the complete historical/current
stable ref vectors are identical, preserving FR-19 append-only package history;
snapshot topology removal remains fail-closed. Every
transaction ID freezes the generation's desired
canonical HEAD; restore transactions additionally freeze the source generation,
so a COS lock remains reconstructable after another target advances local HEAD
and an ordinary/foreign-source command cannot take it over.
Every publish invocation sweeps the isolated restore reconstruction namespace
while holding the exclusive publish lock and before preparing canonical state or
starting remote work. The sweep uses a filesystem-confined root, rejects symlink
or non-directory namespace components, fsyncs the parent after removal, and
emits recovery evidence; this makes SIGKILL leftovers recoverable even when the
next command targets a different generation or is an ordinary publish.
[ADR-0009](adr/0009-forward-only-remote-generation-restore.md) freezes the
command and residual boundary.

Retention deletion plans bind exact storage keys to exact CDN absence URLs.
Checkpoint commit requires storage HEAD absence and CDN 404/410 without
following redirects; deletion-only plans also carry a prior positive probe.
After a forward restore, intent-scoped historical negatives are suppressed only
when the current aggregate generation has the snapshot ref and the sorted
canonical inventory contains the exact recreated key. Missing/corrupt inventory,
partial restores, other retired snapshots, and current-global deletes fail closed.

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

The executable deployment adapters consume the same non-secret startup tuple:
**SOW_EDGE_SCHEMA=sow-edge-runtime/v2**, the frozen **SOW_PRO_PREFIX**, both
public origins, and **SOW_TOKEN_VERIFIER** copied exactly from `sow.yaml`.
`provider://<id>` is not a label: the ID is included in the versioned digest-only
verification request. Cloudflare carries that request over the fixed
**TOKEN_VERIFIER** service binding; EdgeOne carries the identical JSON over the
HTTPS endpoint in `SOW_TOKEN_VERIFIER_URL`, authenticated by the platform secret
`SOW_TOKEN_VERIFIER_BEARER`. `env://NAME` instead reads strict entitlement JSON
from the named secret binding on either runtime. Missing bindings, malformed
documents, unknown schemes and verifier exceptions fail closed before origin
access. No raw token or verifier secret enters config, generated deployment
contracts, logs or origin requests.

Private-origin transports and their cache boundary are recorded by provisional
[ADR-0012](adr/0012-private-origin-deployment-contract.md). Cloudflare's public auth Worker invokes a second, service-only Worker whose sole
capability is the `REPOSITORY` R2 binding; it has no workers.dev, preview URL or
public route and implements GET/HEAD, conditional and ranged reads. EdgeOne has
no arbitrary bearer gateway: it derives the only allowed COS host from
`SOW_COS_BUCKET` + `SOW_COS_REGION` and signs GET/HEAD directly with S3 SigV4
and Web Crypto. COS redirects are never followed. Both paths validate the same
canonical object-key grammar, preserve gated-to-public 404 fallback and expose
`X-SOW-Edge-Contract: sow-edge-runtime/v2` for the live acceptance harness.
These direct transports deliberately report `BYPASS`: R2 binding reads do not
transit Cloudflare Cache, and cross-host COS reads do not prove EdgeOne node or
tiered-cache use. They are deployable private-read paths, not FR-38 cache proof.

The first Cloudflare deployment is itself a fail-closed transaction
([ADR-0034](adr/0034-cloudflare-nonproduction-worker-bootstrap.md)). Apply consumes a
fresh same-run readiness receipt whose exact canonical bytes carry an Ed25519
seal, a separately SHA-pinned plan that fixes the signer public key, and a
mode/run/plan/account/zone authorization. The readiness receipt and seal are
each no-replace installed from complete synced inodes; an interrupted
receipt-only pair is resumed by sealing those exact bytes after a matching
fresh observation, while seal-only or divergent evidence fails closed.
Auth/origin ownership annotations bind the run; uploads are create-only. A
provider-visible R2 control lease v3 at the readiness-resource-derived key serializes
executors and is renewed before each Worker/route mutation, then CAS-retired
to a canonical release-idle v3 marker only after one atomic local outcome
envelope is durable. The final
Worker/route/settings/exposure closure must match twice. A crash leaves a
bounded lease, whose body also binds that readiness-resource digest, that only
the separately authorized `recover-lease` path for the same readiness resource
may retire after expiry. Recovery first CASes live to an owning pending v1
marker bound to the exact recovery run/plan and recovered lease. Only after a
canonical recovery receipt v3 has been no-replace installed, synced and
reopened may that pending ETag be CASed to recovery-idle v3, which binds both
pending and receipt digests. The same run resumes pending/receipt/committed
response-loss windows; other runs, plans, readiness and ordinary acquisition
remain blocked. Idle replay reconstructs the pending bytes from its embedded
lease, plan and receipt instead of trusting self-reported digests. Completed
pending/receipt pairs append to a bounded canonical lineage carried across
all later live, release and recovery states, so a delayed replay can prove a
later descendant without accepting unrelated bytes; capacity fails before the
live-to-pending CAS. The exact pending plan-registry entry remains pinned until
completion. R2 lacks conditional DeleteObject, so SOW never
deletes this reusable key; the next executor can only replace its idle marker
by ETag CAS. This lease is the sole bootstrap R2 control object;
it never grants permission to alter repository payloads or any production resource.
After acquisition and every renewal, all bounded `ListObjectsV2` pages must
prove that the lease is the bucket's only object; a matching GET binds its
canonical bytes and ETag. The exact zone and active main/beta R2 custom-domain
digest is also re-read against the readiness receipt before each mutation, so
the 15-minute readiness lifetime cannot conceal intervening resource drift.

Long-lived provider attestation is a separate contract
([ADR-0035](adr/0035-cloudflare-provider-attestation-and-log-sink-lease.md)).
The auth, origin and token-verifier Workers pin exact compatibility dates and
canonical flag sets; active version runtime, settings, schedules and exposure
must be observed twice without drift. The provider digest also covers the
complete account Worker, embedded-route, zone-route and custom-domain
inventory, while allowing only unrelated routes whose host-pattern exclusion
is provable. Main and beta R2 custom domains require an explicit TLS 1.2 or 1.3
minimum and the frozen Cloudflare Modern TLS 1.2 cipher set. EdgeOne's
realtime-log task must report the exact immutable `mainland` or `overseas`
area pinned by the deployment contract; that value is bound into the task,
raw-attestation and acceptance-ledger digests. Provider log-sink
configuration is serialized by another five-minute R2 CAS lease at the
dedicated raw bucket's stable `.sow/provider-log-sink-lease.json` key, using an identity distinct from both read-only collectors and
write-only exporters; a partial cross-provider failure retains that lease for
bounded recovery rather than allowing concurrent adoption of uncertain state.
Success CAS-retires it to the same kind of non-owning marker; the control
identity has Get/conditional-Put authority and no Delete requirement.

The separate `https-bearer` candidate strips the customer credential and makes
a same-host global Fetch carrying only an origin-service secret. Main requests
stay on `SOW_PUBLIC_BASE_URL`; an origin group whose first key is under
`.sow/beta/` stays on `SOW_BETA_BASE_URL`, including its shared-package fallback;
beta strong-generation and static-mirrorlist reads also retain that host.
Optional `SOW_ORIGIN_BASE_URL` and `SOW_BETA_ORIGIN_BASE_URL` aliases must match
those two declared origins exactly. The external WAF/origin policy must reject
anonymous `.sow/gated` reads. This mode remains non-conforming until two
distinct entitlements demonstrate the same clean URL digest, a second-token
provider `HIT`, gated anonymous 404, GET/HEAD/Range, and refresh after one exact
paired publication purge. The publisher must invalidate the credential-free clean
cache key as well as the client-visible flip/pointer. `publish.Plan` now derives
that exact pair and rejects a missing or arbitrary extra invalidation; only the
real provider purge/cache observation remains unverified.
Cloudflare additionally pins `global_fetch_private_origin`: same-zone Fetch
bypasses mapped Workers/security settings and therefore cannot recurse through
the public auth route, but the zone origin must itself validate the independent
origin bearer. `global_fetch_strictly_public` is forbidden for this topology.

Malformed routes return 404, invalid or expired credentials return 401, valid but under-scoped credentials return 403, unsupported methods return 405, and temporary verifier/origin failures return 503. Authentication failures are private and no-store.

Gated origin keys are private and logs redact the token segment. Basic Auth is
the only fallback. When Worker/EdgeOne validates Basic before cache lookup, it
uses the same clean-subrequest interface and strips the client Authorization.
The standalone Nginx fallback authenticates only at origin and is therefore
`private,no-store`; it must never share a cache whose key excludes Authorization.

## 7. Conformance gates

An implementation does not conform until tests prove:

- SQLite rebuild equivalence and zero external git/gpg/Python/Perl/repository-tool runtime dependencies.
- Crash recovery at every local journal and remote saga boundary.
- Stable/history preservation and unskippable public-to-gated confidentiality failures.
- Independent checkpoint conflict handling for both targets.
- Real apt/dnf acceptance of generated metadata and signatures.
- L4 YUM evidence includes an RPM selected from signed metadata, downloaded
  through the client route, checksum-validated, and embedded-signature-verified
  against the configured package keyring; valid repomd signatures alone are
  insufficient.
- Remote signed YUM atomicity through the generation-aware path; the legacy migration gate in ADR-0001 cannot be waived silently.
- Production Linux/macOS filesystems pass hardlink and atomic-directory-exchange probes.
- Deployed Cloudflare/EdgeOne paths pass Pro GET, HEAD and Range through their
  private R2/COS origins; the response carries the versioned edge marker and no
  customer or origin Authorization material.
- The 50,000-package fixture demonstrates bounded worker parallelism by repo/component/arch, records throughput and proves index/link work is not one global serial loop.
- Manifest, package and XML processing is streaming/lazy; the 50,000-package run records peak RSS and proves no whole-repository in-memory collection. DEB metadata inspection follows [ADR-0028](adr/0028-control-only-deb-inspection.md): it composes the approved Debian ar/control parser without opening the irrelevant `data.tar.*` decoder, while whole-file double hashing and index/CAS identity still bind the result.
- Default publish computes its plan from local desired/remote refs, performs a bounded checkpoint read plus O(changed objects) storage/CDN calls, and performs no ListObjects. Only explicit fsck may scale with the remote repository.
- `remotes/<target>/content.tsv` remains the source-path publication baseline; it must never be interpreted as a bucket key list. `remotes/<target>/inventory.tsv` is the cumulative sorted remote-key/size/SHA256 closure used by L2/fsck and includes plan objects, the mutable checkpoint, immutable generation documents, and COS generation locks. GC considers only `content.tsv` hashes that already have a local CAS object (zero-byte legacy adoption may precede CAS projection), and never treats `inventory.tsv` or retained remote extras as CAS roots.
- L2 uses bounded checkpoint/generation GET, stable channel JSON GET, beta/latest static mirrorlist GET, plus HEAD for the latest change plan and never lists the bucket. Explicit fsck uses signed, paginated ListObjectsV2 and HEAD; imported legacy objects without SOW checksum metadata fall back to streaming GET+SHA256. Publish cannot prove initial bucket emptiness without violating the no-List contract, so inventory coverage starts partial and unknown keys are not deletion candidates. `fsck --target <one> --adopt-remote-inventory` is the sole transition to complete coverage: it requires two identical key/size/ETag list snapshots around bounded HEAD/GET hashing, proves every selected local serving entry is an exact remote subset, retains and reports remote extras, then commits inventory, coverage and the source baseline in one canonical transaction without fabricating a generation, checkpoint or remote ref.
