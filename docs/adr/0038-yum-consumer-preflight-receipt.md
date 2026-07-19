# ADR-0038: YUM consumer cutover requires an expiring endpoint receipt

- Status: accepted
- Date: 2026-07-19
- Scope: Pigsty raw-baseurl consumer migration

## Context

Object storage cannot atomically replace `repomd.xml` and its detached
signature. ADR-0001 therefore requires consumers to resolve one immutable
generation through mirrorlist. The original Pigsty migration script already
froze 28 definitions and provided digest-confirmed apply/rollback, but its
last safety gate was prose: operators had to remember that mapped endpoints and
an aggregate trust bundle must be published and reviewed before `apply`.

That was insufficient for two reasons. First, a successful local stage did not
prove that the CDN route was the exact channel committed in canonical state or
that it led to a usable RPM. Second, the v1 map treated `pigsty-infra` like a
per-EL repository even though ADR-0021 freezes it as two architecture-specific
cross-EL compatibility projections.

## Decision

The consumer map is schema v2. Each definition carries exact x86_64 and
aarch64 `repo/os/arch` templates. `pigsty-infra` uses
`infra-legacy-x86-64/cross-el/x86_64` and
`infra-legacy-aarch64/cross-el/aarch64`; the renderer chooses the nested route
with `os_arch`. Its historical dev-only China raw source used
`beta.pigsty.cc`, but ADR-0021 defines no mutable beta compatibility
projection, so that one China binding is deliberately normalized to
`repo.pigsty.cc` `latest`.
The four shipped map names also freeze the Pigsty renderer module selector:
`pigsty-infra=infra`, `pigsty-pgsql=pgsql`, `percona=percona`, and
`wiltondb=mssql`.

`sow compatibility yum-consumer-preflight` is the only authority that may
issue a cutover receipt. Under the canonical state lock it:

1. validates bounded, stable, non-symlink stage/map/inventory/trust inputs and
   the exact confirmed manifest digest;
2. requires the exact executable renderer loop, release/module/architecture
   selector and RPM control flow; parses the staged YAML; rejects custom tags,
   aliases, duplicate or route-overriding security keys, unsafe renderer
   descriptions and every unmapped SOW raw alias; freezes each canonical
   module; requires a safe default mirrorlist fallback; and expands a bounded
   definition/release/architecture/region set;
3. resolves each credential-free HTTPS URL to exactly one configured target,
   committed beta/latest intent and canonical `ChannelState`;
4. validates current config/repository trust, compatibility identity and the
   target-wide generation/checkpoint/plan closure;
5. requires the view-specific trust asset key (`.sow/beta/pkg/...` for beta,
   `pkg/...` for latest) with the exact reviewed size/SHA-256 in current
   aggregate inventory and requires CDN bytes to equal that public-only bundle;
6. proves that bundle covers every required metadata and package signer primary
   key, selects the metadata certificate from those exact aggregate bytes, and
   uses the same packet-preserving aggregate keyring for RPM verification; and
7. follows each mirrorlist to the exact immutable generation, verifies repomd
   and all three metadata streams, downloads a referenced RPM, checks its
   authenticated metadata and verifies its embedded signature.

One UTC time captured after the canonical lock is acquired governs metadata
and RPM verification and receipt validity; the probe must finish inside its
requested window or no receipt is installed. The canonical no-replace receipt
binds all local input digests, expanded
bindings, intent and aggregate publication identities and non-boolean protocol
evidence. Its minimum lifetime is one second, default is fifteen minutes and
maximum is one hour.
After the full probes, issuance rereads every unique mirrorlist pointer and
trust URL to close the long multi-endpoint probe window. It then reopens and
revalidates the config, config-referenced metadata/package keyrings, stage
directory, manifest, plan, every staged file, map, inventory, aggregate trust
bundle and the repository/stage/receipt-parent directory inode identities
before the receipt can be linked into that same parent.
`yum-consumer-receipt-check` never performs network I/O; it re-derives the
same local/canonical authority and rejects an expired or stale receipt.

The shell migration calls receipt-check before evidence creation, backup or
Pigsty mutation, compares the digest printed from the stable Go read to the
path again, then archives the exact receipt under that digest. After backups
it repeats the network-free check immediately before the first Pigsty write,
requiring the same receipt identity so expiry or canonical drift during a slow
backup phase still fails closed.
Its active marker and final apply/rollback receipt retain the endpoint digest,
including across a mixed-state recovery.
It also validates canonical manifest paths before traversing evidence, rejects
symlinked source/stage/evidence parents, requires plan/evidence directories to
be disjoint from the checkout in both directions, and uses checked
process-unique temporary files for evidence authority rather than following
fixed `.tmp` paths.
Rollback continues to use byte-identical originals and does not need a live
endpoint receipt because it restores the old raw consumer contract.

## Consequences

- A reachable but out-of-band trust object is insufficient; it must also be
  owned by SOW's current aggregate publication inventory.
- The aggregate bundle is managed as an ordinary public asset at
  `pkg/keys/rpm-trust.asc`. It is not a metadata signing key and contains no
  private packets.
- Expired receipts are intentionally not refreshed in place. Run preflight
  again with a new destination, then apply that exact receipt.
- A checkout previously changed by the provisional v1 renderer/map must use
  its v1 evidence to byte-roll back first, then create and review a fresh v2
  stage. In-place reinterpretation of the incorrect v1 infra routes is refused.
- The gate is read-only against CDN endpoints and performs no provider control
  or object-storage mutation.
- Local protocol and copied-tree evidence does not authorize production
  cutover. Both real public origins, real EL clients and production rollback
  still require explicit evidence; production CO/COS and Cloudflare resources
  remain forbidden test targets.
