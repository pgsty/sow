# Upstream proof order determinism — 2026-07-22

## Finding

The disk-backed candidate spool promises deterministic proof selection for a
duplicate package body. APT already preferred the smallest Packages evidence
digest, but RPM always retained the first proof. Equal APT evidence digests
also retained the first otherwise-different proof. The resulting provenance
could therefore depend on metadata discovery order.

The red test inserted the same authenticated RPM candidate with two different
primary-index proofs, then repeated the insertion in reverse order. Before the
fix the retained `IndexSHA256` changed from `ffff...` to `1111...`; the test
failed with `RPM proof depends on discovery order`.

## Resolution

`candidateStore.add` now selects proofs by a total deterministic order:

1. the lexically smallest signed metadata root (`IndexSHA256` for RPM,
   `PackagesEvidenceSHA256` for DEB); then
2. for equal roots, the lexically smallest complete canonical JSON proof.

The first rule preserves the existing APT policy. The second closes ties in
entry, Release, URL and size evidence without retaining repository-sized state.
Both formats still reject a duplicate digest with a different package identity.

## Current-source verification

All commands ran from `/Users/vonng/pgsty/sow` with local temporary directories:

```text
go test ./internal/upstream -run '^TestCandidateStore(ChoosesRPMProofIndependentlyOfDiscoveryOrder|BreaksEqualAPTIndexTiesDeterministically)$' -count=1
PASS 0.457s

go test -race ./internal/upstream -run '^TestCandidateStore(ChoosesRPMProofIndependentlyOfDiscoveryOrder|BreaksEqualAPTIndexTiesDeterministically)$' -count=1
PASS 1.528s

go test ./internal/upstream -count=1
PASS 2.059s

go test -race ./internal/upstream -count=1
PASS 10.585s

go test ./internal/cli -run '^TestSync(APT|YUM)EndToEndPreservesCanonicalProvenanceAndNeverDeletes$' -count=1
PASS 8.375s

go test -race ./internal/cli -run '^TestSync(APT|YUM)EndToEndPreservesCanonicalProvenanceAndNeverDeletes$' -count=1
PASS 12.392s

go vet ./internal/upstream ./internal/cli
staticcheck ./internal/upstream ./internal/cli
PASS
```

The complete upstream package coverage run reported 73.9% statements;
`preferredCandidateProof` reached 89.5% and `proofsEqual` 100%.

## Boundary

This is local synchronization/provenance evidence. No credentials were loaded,
no network or cloud API was used, and no local or cloud production repository
was read or written. It does not upgrade the open Cloudflare control-plane,
COS/EdgeOne, CDN, or production-migration acceptance items.
