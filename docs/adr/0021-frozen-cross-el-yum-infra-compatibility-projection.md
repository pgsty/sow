# ADR-0021: Frozen cross-EL `yum/infra/{arch}` compatibility projection

- Status: Accepted
- Date: 2026-07-14
- Scope: G5, FR-09, FR-15, FR-23, FR-25, FR-26, FR-27, FR-29, FR-32, FR-41, COMP-01, MIG-02

## Context

The Pigsty v1 physical inventory contains the public raw leaves
`yum/infra/x86_64` and `yum/infra/aarch64`. Each leaf is one mixed-release,
flat-RPM compatibility repository. It is not an EL9 repository and must never
be relabelled as an ordinary `EL9/zstd` leaf. Active policy, target affinity and
future package lifecycle remain owned by explicit EL9/EL10 repositories such as
`yum/infra/el9/{arch}` and `yum/infra/el10/{arch}`.

The observed S0 tree is also not the desired generated tree. Its unsigned
`repomd.xml` references seven records: gzip primary/filelists/other XML,
bzip2 sqlite derivatives and module metadata. SOW must verify those bytes as
migration input without reproducing sqlite, modulemd or zchunk in new output.
The clean candidate is exactly three gzip XML records plus a signed
`repomd.xml`/`.asc` pair.

This decision refines [ADR-0020](0020-legacy-physical-topology-and-route-ownership.md)
and the frozen contracts in the
[PRD Addendum](../../_bmad-output/planning-artifacts/prds/prd-sow-2026-07-11/addendum.md).
It does not alter the separate frozen-EL7 policy in
[ADR-0019](0019-frozen-el7-yum-metadata-compatibility.md).

## Decision

### Configuration and physical ownership

Every architecture is one explicit projection. An inactive carrier owns the
whole raw leaf; a separate enabled EL9/10 repository owns policy and target
affinity:

```yaml
repos:
  - id: infra-el9
    type: yum
    path: yum/infra/el9/{arch}
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: keys/infra-packages.pgp}

  - id: infra-legacy-carrier
    type: yum
    path: yum/infra/{arch}
    active: false
    default_pool: public
    arches: [x86_64]
    os: {family: cross-el, major: 0, lifecycle: frozen}
    yum: {compression: gzip, compatibility_carrier: true}

compatibility_projections:
  - id: infra-legacy-x86-64
    root: yum/infra/x86_64
    mode: frozen-cross-el
    carrier: infra-legacy-carrier
    source:
      repo: infra-el9
      view: latest
      os: cross-el
      arch: x86_64
      commit: pin-at-first-freeze
```

The carrier must be inactive, public, unfiltered, cross-EL/0, frozen and gzip.
It cannot enter ordinary repo groups, views, add/rm/sync or publish selection.
The policy owner must be an enabled public EL9/10 zstd repository included by
`latest`; an audited active-to-frozen EOL transition is allowed. `source.os`
is always `cross-el`: the bytes are never claimed to originate in one EL leaf.
`source.commit` is either `pin-at-first-freeze` or the exact immutable S1
commit after an operator has chosen to write it into configuration.

### S0: immutable raw baseline

Ordinary `sow init` is the sole command allowed to include inactive
compatibility carriers. It scans each carrier as one complete leaf, commits its
manifest and creates an immutable `refs/sow/repos/<carrier>` baseline. A later
`init` compares the complete physical tree to that exact baseline and refuses
added, removed or changed bytes. Partial carrier selectors are forbidden.

The S0 validator accepts the observed unsigned seven-record legacy metadata
only as input evidence. Every record must have a safe relative location,
compressed SHA-256/size and open SHA-256/size that match a stable file handle.
All flat RPMs are parsed and verified against the policy owner's public-only
package keyring. No private key is read. S0 does not claim a historical
repository signature and does not activate a generated route.

### S1: zero-rewrite adoption

`sow compatibility yum-adopt --id <id>` revalidates the immutable carrier,
imports the exact RPM bytes into CAS and commits:

- `compatibility/yum/<id>/source.tsv`;
- `compatibility/yum/<id>/adoption.json`;
- `compatibility/yum/<id>/package-trust.pgp`;
- immutable `refs/sow/compatibility/yum-source/<id>`.

The source manifest uses canonical `Packages/<bucket>/<basename>.rpm` paths;
the adoption record binds its SHA-256, Git blob, size, package/byte totals,
carrier baseline and frozen package trust. A separately derived flat-alias
manifest must equal the S0 flat set byte for byte. The raw tree is never
rewritten. Replays are read-only and must reproduce the exact S1 state.

### Isolated candidate and S2 freeze

`sow compatibility yum-candidate` requires a new dedicated directory outside
the hosted repository root. It generates a clean signed gzip repository from
S1 using the configured repository signing identity. The candidate contains
canonical bucketed RPM paths plus byte-identical flat aliases, and only
primary/filelists/other XML metadata, `repomd.xml` and `repomd.xml.asc`.
Legacy sqlite/modulemd records are input-only and never copied forward.

The candidate tree, sidecar manifest and receipt are committed through a local
crash journal. The canonical receipt omits the operator's physical path. It
binds S1 source/adoption/package trust, the complete candidate manifest,
repository public packets, repomd digest, package/byte totals and a
domain-separated `freeze_confirm` token. Existing output is accepted only as
an exact replay; sidecars are never overwritten implicitly.

`sow compatibility yum-freeze --candidate <dir> --confirm <token>` validates
the candidate again through stable handles, imports its closure into CAS and
commits the S2 witness, payload/candidate manifests, path-independent receipt
and frozen repository trust. `refs/sow/compatibility/yum/<id>` permanently pins
that freeze commit. The S1 and S2 refs are independent permanent CAS/GC roots.

S2 is deliberately **pre-cutover**. It does not expose candidate payload,
generation, mirrorlist or either frozen trust URL through materialize, publish,
Nginx or the edge contract. The already-proven raw S0/S1 bridge may remain
routable.

### S3 cutover, rollback and recovery

`sow compatibility yum-cutover --confirm <token>` materializes the exact S2
candidate from CAS below
`.sow/materialized/compatibility/<id>/<candidate-sha256>`, then appends a
content-bound event to `compatibility/yum/<id>/cutover.jsonl`. The canonical
JSONL stores repository-root-relative logical paths only. A separate local
crash journal stores physical paths and makes the sequence recoverable:

1. write and fsync a prepared local journal;
2. append the canonical event;
3. durably mark the journal committed;
4. atomically flip `.sow/serving/compatibility/yum/<id>/current` through a
   root-bound directory handle;
5. verify the root, parent, target and link identities, then remove the journal.

If a process stops after step 2, every ordinary command fails before state
cleanup, materialization or provider construction. Only the matching
`yum-cutover`/`yum-rollback` invocation with its original confirmation and
`--recover` may reconcile that journal; another projection's journal still
blocks it. Parent replacement, symlink substitution and target drift fail
closed without writing outside the repository root.

The append-only ledger alternates `cutover` and `rollback`; every event binds
the prior event, S2 freeze and candidate digest. Rollback appends an event and
flips the controlled link back to the exact raw target. It never deletes S1,
S2, candidate CAS objects or prior events, and the original raw tree is never
rewritten.

Only a validated final `cutover` event admits the strong public compatibility
closure. Ordinary latest materialize/publish then installs the exact frozen
generation and these two exact trust objects:

- `_sow/v1/trust/yum-compat/<id>/packages.pgp`;
- `_sow/v1/trust/yum-compat/<id>/repository.pgp`.

It also admits the cross-EL generation and mirrorlist routes while retaining
the separately verified raw legacy bridge. A final rollback event makes the
immutable carrier manifest plus the verified current carrier bytes the sole
authority for `RouteRoot`: publish writes every differing S0 raw object,
commits the old unsigned `repodata/repomd.xml` only after the other S0
repodata, and deletes every S3-only `Packages/` or `repodata/` candidate extra.
It also removes the mirrorlist/channel and both trust entry points. Immutable
historical generation objects are never deleted and remain available through
their recorded history. S0 writes, raw/trust/mirror deletions, minimal purge,
positive/negative post-verification and checkpoint advancement remain one
ordinary publish saga. The local canonical parent generation, its
content-bound historical plan, the S1 adoption receipt and the current exact
carrier must all validate before provider credentials or clients are touched.

### Namespace-race and capability boundary

Every compatibility writer binds the repository root, `.sow`, lock file and
candidate parent to opened directory identities before admission. It must not
turn a successful identity check back into authority to resolve the configured
pathname. Path-oriented go-git/SQLite work therefore runs in a private `0700`
canonical-state workspace; the resulting authoritative directory is installed
through a parent-FD atomic exchange. CAS imports likewise stage in a private
CAS and enter the repository only through root-bound no-replace links.
Candidate payload and S3 materialization use `linkat` between retained source
and target directory handles, and crash journals plus the serving link are
read, written, reconciled and removed through the retained `.sow`/repository
capabilities.

The CAS commit retains separate capabilities for `.pool`, `sha256`, `.tmp`
and every touched shard; temporary creation, no-replace linking and directory
sync therefore never traverse a replaceable multi-component pathname. The
serving-link transaction retains both old and new target capabilities,
revalidates them immediately before the atomic link rename, and restores the
prior link if a post-rename namespace check fails. Canonical-stage and journal
temporary cleanup is identity-conditional: a nonce coordinate replaced after
creation is reported and preserved, never recursively deleted by name.

If the configured repository pathname is renamed and replaced after admission,
these operations may update only the originally bound inode and must then fail
the post-operation identity check. They must never create a transaction,
journal, CAS shard/object, materialized file or serving pointer in the
replacement tree. Linux `RENAME_EXCHANGE` and macOS `RENAME_SWAP` are the
frozen atomic-directory primitives; unsupported platforms fail closed.

### History, fsck and GC

History admission walks the union of aggregate HEAD and every `refs/sow/*`
reachable DAG, independent of commit timestamps. It rejects S1/S2 removal,
byte-identical reintroduction after a regression, disconnected conflicting
owners, ref recreation, ledger truncation/rewrite and merge histories that do
not preserve every parent prefix. Canonical config at each descendant must
retain the same carrier/root/owner/source contract.

`fsck` reports S0, S1, S2, S3-active or S3-rolled-back explicitly and validates
only the artifacts required at that stage. GC permanently roots both S1 source
and S2 candidate/trust closure even when ordinary bounded HEAD retention would
otherwise age those commits out. Only truly unreachable objects are eligible
for deletion.

## Scope boundary

This ADR covers only the frozen cross-EL `yum/infra/{arch}` bridge. It does not
add generic cloud abstraction, package building, EL7 activation, modulemd,
zchunk, sqlite output or RPM re-signing beyond FR-17.

No CO/COS or Cloudflare production repository, bucket, domain, zone or CDN
resource may be used for tests, probes, baselines, purge exercises or fault
injection. Permitted evidence surfaces are local filesystem/CAS, embedded Git,
loopback HTTP/Nginx, local provider protocols and separately registered,
independently reviewed non-production resources.

## Acceptance consequences

- S0/S1/S2 must leave the existing raw tree byte-identical.
- S2 alone must not make candidate, mirrorlist, generation or trust routes
  public; only S3 can do so.
- L1/fsck must stream manifests and prove RPM trust, candidate metadata,
  canonical/flat/CAS identity and stage/ref/history closure.
- Nginx and both edge implementations must derive raw/active sets from the same
  canonical state machine and reject incomplete or tampered transitions.
- Publish must upload and verify the exact S2 payload and both frozen trust
  objects. Rollback must restore the raw route byte-for-byte to S0, remove all
  S3-only mutable/public candidate extras and entry points, preserve immutable
  generation history, and prove both presence and absence in the same
  evidence-bound saga.
- Crash recovery, provider-call-zero failure tests, true apt/dnf consumers and
  stage-aware GC/history negatives are release gates; mocks alone are not
  sufficient.
