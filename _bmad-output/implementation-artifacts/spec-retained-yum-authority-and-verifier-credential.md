---
title: 'Retained YUM authority and verifier credential failure closure'
type: 'hardening'
created: '2026-07-20'
status: 'done'
baseline_commit: '135928a'
---

## Intent

Materialization must not silently reduce a retained YUM package closure when
its canonical generation authority is unavailable. Remote verification must
also tell an operator why L3/L4 could not run without disclosing credentials.

## Contract

- Retained YUM package closure requires both the canonical store and the
  sealed serving channel. Missing authority fails before creating output.
- A channel that yields no canonical generation pins is invalid; the current
  manifest is not an acceptable substitute for retained-generation evidence.
- Missing or invalid CDN verification credentials produce one stable,
  operational finding and the documented network/auth exit code.
- Verification output contains no token, secret-provider name or raw provider
  error. It also does not collapse the condition into a generic check error.
- Selected materialization archives include only the requested logical leaf,
  even when physical-owner metadata contains sibling repositories.
- A manifest-only adopted repository freezes `default_pool`; deleting a view
  cannot permit public-to-gated reclassification.
- Duplicate APT by-hash stages are accepted only when byte-identical.

## Implementation and verification

- `mergeRetainedYUMPackageClosure` now rejects missing authority and an empty
  pin set. Its fail-open manifest-copy branch and unreachable copy helper are
  removed.
- `networkCredentialCheck` records
  `CDN_VERIFICATION_CREDENTIAL_UNAVAILABLE` as a critical operational finding
  while preserving the network/auth exit classification.
- Real CLI tests cover missing L3 and L4 credentials, output redaction and exit
  codes. Filesystem fixtures cover retained closure, selected export,
  manifest-only pool continuity and APT by-hash duplicate identity.
- Focused ordinary/race, affected A-F/G-M/R-V ordinary/race, static and
  migration gates pass. Deterministic clean delivery is recorded externally
  after the delivery-managed source set is frozen.
- No cloud, upstream, Docker or production repository access is involved.
