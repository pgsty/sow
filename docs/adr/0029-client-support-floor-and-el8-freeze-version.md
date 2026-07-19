# ADR-0029: APT Client Support Floor and EL8 Freeze Version

Status: accepted
Date: 2026-07-16
Scope: supported client matrix, mutable APT publication, and Pigsty EL8 lifecycle

## Context

The PRD asked for an atomic fallback for APT clients older than 1.2. The real
Debian Jessie apt 1.0 negative PoC proved that two individually valid fixed
`Packages*` aliases and `InRelease` cannot be replaced atomically on static
object storage. Redirect, `no-store`, and generation-cookie variants also fail
because apt does not bind the later fixed-alias request to the generation that
served `InRelease`.

SOW must not describe a protocol-impossible path as supported. The Pigsty
product owner also froze the commercial lifecycle boundary for EL8 on
2026-07-16.

## Decision

1. The minimum supported APT client is **apt 1.2**. Supported mutable channels
   use by-hash indexes. apt older than 1.2 is unsupported and must be upgraded
   before a SOW cutover.
2. A coherent immutable snapshot may remain technically readable by an older
   client, but that does not confer product support and is not a fallback for
   mutable beta/latest/stable channels.
3. SOW never recommends insecure client flags to bridge the support floor.
4. EL8 is frozen beginning with **Pigsty v5.0.0**. Existing EL8 bytes may be
   verified, repaired byte-for-byte, materialized, and published with gzip
   repodata. Adding, syncing, or promoting new EL8 content remains rejected.

This specific, later owner decision supersedes the older PRD wording that
required an apt-before-1.2 mutable fallback. The negative PoC remains required
evidence: the decision closes the support-policy gap; it does not turn the
failed protocol candidate into a passing implementation.

## Consequences

- Client and migration documentation must state `apt >= 1.2` as a hard
  preflight requirement.
- Compatibility tests continue to exercise a real apt 1.0 client as a negative
  control and a supported apt client through by-hash as the positive path.
- EL8 repositories in `sow/v1` remain `lifecycle: frozen` and gzip-only; the
  version constant appears in configuration diagnostics so the commercial
  boundary is visible to operators.

## Evidence

- [apt 1.0 fixed-alias negative PoC](../evidence/2026-07-12-apt-legacy-fixed-alias-negative-poc.md)
- [real client compatibility](../evidence/2026-07-11-client-compat.md)
- Exact support-floor client: digest-pinned Ubuntu 16.04, apt 1.2.35,
  signed InRelease + SHA-256 by-hash + exact package installation.
- [configuration lifecycle enforcement](../../internal/config/config.go)
