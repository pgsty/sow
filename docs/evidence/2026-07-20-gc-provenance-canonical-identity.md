# 2026-07-20 GC provenance canonical identity

Status: final local ordinary/race, static, migration, performance and delivery
gates passed. No cloud or production resource was accessed.

## Finding and correction

`collectCanonicalRoots` previously decoded a provenance receipt and trusted
the identity inside it without proving that identity matched the canonical Git
path that carried the receipt. A file named for artifact A could therefore
claim artifact B: B stayed live while A could become an orphan. Legacy adoption
and prune JSONL filenames had the same unbound repo coordinate.

The correction joins the two labels before a reference is admitted:

- ordinary DEB/RPM receipts must exactly occupy
  `provenance/<format>/<artifact_sha256>.json`;
- legacy adoption and negative-prune receipts must exactly match the repo in
  their `provenance/legacy[-pruned]/<repo>.jsonl` filename;
- negative prune evidence remains validation-only and contributes no CAS root.

## Red evidence

Before the correction, the focused mismatch table accepted all four invalid
states with `err=<nil>`: artifact digest mismatch, artifact format mismatch,
legacy adoption repo mismatch, and legacy prune repo mismatch. This was a
semantic failure, not an uncovered-but-correct branch.

## Current executable evidence

```bash
go test -count=1 ./internal/cli \
  -run '^TestGC(CanonicalProvenanceRootsBindReceiptIdentity|CanonicalProvenanceRootsRejectPathIdentityMismatch|CLIApplyRejectsMismatchedProvenanceBeforeCASPlanning)$'

go test -race -count=1 ./internal/cli \
  -run '^TestGC(CanonicalProvenanceRootsBindReceiptIdentity|CanonicalProvenanceRootsRejectPathIdentityMismatch|CLIApplyRejectsMismatchedProvenanceBeforeCASPlanning)$'

go test -count=1 -covermode=atomic -coverpkg=./internal/cli \
  -coverprofile=/tmp/sow-gc-provenance-path.out ./internal/cli \
  -run '^TestGC(CanonicalProvenanceRootsBindReceiptIdentity|CanonicalProvenanceRootsRejectPathIdentityMismatch|CLIApplyRejectsMismatchedProvenanceBeforeCASPlanning)$'
```

The frozen-source focused ordinary and race suites passed in 1.391s and 2.412s
with no race report; the atomic run passed in 1.247s. Statement coverage on the
identity/root collection cluster is:

| function | focused statement coverage |
| --- | ---: |
| `collectCanonicalRoots` | 62.5% |
| `addLegacyProvenanceRoots` | 76.2% |
| `validateLegacyIndexPruneLedger` | 81.2% |
| `canonicalProvenanceLedgerRepo` | 66.7% |
| `addProvenanceRoot` | 76.5% |

The destructive-path test builds the exact orphan confirmation that the old
path-unbound implementation would accept, invokes real `sow gc --apply`,
expects `ExitVerification`, and verifies both the receipt-named artifact and
the would-be-deleted orphan still exist in the real filesystem CAS.

## Final local gates

All 712 `internal/cli` tests passed in six ordinary shards:

| shard | elapsed |
| --- | ---: |
| A-F | 474.411s |
| G-M | 454.477s |
| N-O | 239.309s |
| P-Q | 745.919s |
| R-V | 494.545s |
| W-Z and other | 229.490s |

The same final source passed all six `-race` shards with no race report:

| shard | elapsed |
| --- | ---: |
| A-F | 530.469s |
| G-M | 643.582s |
| N-O | 263.027s |
| P-Q | 929.855s |
| R-V | 548.473s |
| W-Z and other | 292.430s |

All non-CLI packages passed ordinary/race. The nested RPM module passed
ordinary/race, vet, tidy-diff and module verification. Root compile-only,
`go vet ./...`, repository Staticcheck, root tidy-diff/module verification,
fixed `govulncheck@v1.6.0` for both modules and pinned RPM v1.3.0 h1 plus
bytewise patch-allowlist provenance all passed using the read-only local module
proxy. Both vulnerability scans reported no reachable vulnerability.

Four `CGO_ENABLED=0 -trimpath` builds passed for Darwin/Linux x amd64/arm64;
the Darwin outputs were the expected Mach-O architectures and both Linux
outputs were statically linked ELF. Edge bundles rebuilt without diff and all
47 shared Cloudflare/EdgeOne contracts passed. All seven hermetic migration
suites passed; the family gate reported 44 command families, five mutation
negatives, 16 real CLI E2E flows, external network disabled and production
mutation none.

Current-source 50k gates observed: upstream retained-heap growth 0 with
29,265,920 bytes of spool; APT 4.165s with four workers and a 256-entry peak
chunk; materialization 16.074s with eight workers and 136,192 bytes retained
growth; one-object publish planning 12.036ms; YUM 6.362s with retained growth
0; 100 no-view-read incremental preflights 13.921ms.

One isolated pre-document clean delivery passed with the read-only local module
proxy. After this evidence, its spec, trace row and delivery allowlist were
frozen, two independent clean deliveries were rebuilt and compared bytewise.
Their final non-self-referential identity is recorded in the delivery-external
V-50 section of
`_bmad-output/implementation-artifacts/validation-selected-set-materialization-2026-07-13.md`.

## Evidence boundary

All fixtures use `t.TempDir`, the real filesystem CAS and the real embedded Git
canonical store. Credentials are explicitly absent and real cloud, upstream
and Docker compatibility opt-ins are zero. This closes a local GC authority
defect only; it does not change any real-cloud, production migration, CDN or
operational-success status in the traceability matrix.
