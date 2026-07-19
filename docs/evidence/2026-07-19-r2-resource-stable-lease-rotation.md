# R2 resource-stable lease rotation evidence

Date: 2026-07-19

Status: current-source local/protocol evidence passed; no cloud request or
write was made.

## Defects closed

V-24 correctly replaced unsafe R2 DeleteObject release with conditional Put
CAS retirement, but its bootstrap key still contained the bootstrap plan SHA.
Rotating a Worker bundle, readiness signer or compatibility setting therefore
selected another key while the old idle marker remained. Readiness then saw
multiple control objects and could never recover. The provider log-sink used a
raw-prefix-derived key and required old idle/expired bodies to carry the current
deployment SHA, causing the same failure during normal deployment or raw-root
rotation.

The corrected contracts separate stable resource identity from execution
version identity:

1. bootstrap uses exactly
   `.sow/bootstrap/leases/<readiness-resource-sha>.json`; plan SHA remains in
   each live/idle body, while lease/idle schema v2 also carries the resource
   SHA so a canonical body cannot be relocated between resources;
2. a same-resource historical idle marker or expired live lease may be
   replaced only by exact ETag CAS, but expired live retirement is restricted
   to `recover-lease`; ordinary apply/rollback must consume its idle result;
3. recovery receipt `sow-real-cloud-cloudflare-bootstrap-lease-recovery/v2`
   binds the current plan SHA, recovered historical plan SHA and complete
   recovered canonical lease digest, and replay compares it with the exact
   idle marker;
4. Cloudflare readiness accepts only the one key derived from its current
   pinned resource; legacy plan keys, foreign resources and additional objects
   fail before credentials or Worker clients;
5. provider log-sink setup uses the dedicated raw bucket's single
   `.sow/provider-log-sink-lease.json` key. Deployment and raw-root rotation
   reuse it; lease/idle schema v2 binds the raw bucket in its body, and
   account/zone/bucket drift or live historical holders fail closed;
6. both lease stores expose Get/List/conditional Put only and all rotation
   tests require zero Delete calls;
7. bootstrap recovery and other exclusive real-cloud metadata now use the same
   fully-written-inode/no-replace installer, so their final paths cannot be
   observed as partially written files.

The same audit found that readiness receipt and `.seal` were created with two
direct `O_EXCL` writes. A crash could leave a partial final inode or a complete
receipt without its seal. Each final pathname is now linked with no-replace
semantics only after a temporary inode is fully written and synced. A matching
retry signs the unchanged receipt bytes and completes a receipt-only pair.
Seal-only, symlink, stale, noncanonical or divergent evidence fails closed;
the writer is idempotent and never overwrites completed evidence.

## Focused validation

```text
go test ./test/compat -run 'ProviderReadinessReceiptPair|CloudflareReadiness|CloudflareBootstrap|ProviderLogSinkLease|RealCloudPrivateBootstrapAtomicWindows|RegistryCandidate|PersistentRealCloudWorkspace' -count=1
ok github.com/pgsty/sow/test/compat 0.964s

go test -race ./test/compat -run 'ProviderReadinessReceiptPair|CloudflareReadiness|CloudflareBootstrap|ProviderLogSinkLease|RealCloudPrivateBootstrapAtomicWindows|RegistryCandidate|PersistentRealCloudWorkspace' -count=1
ok github.com/pgsty/sow/test/compat 2.276s
```

The focused suite proves two different bootstrap plans share one exact key;
idle and expired historical plans replay; live old/new plans block each other;
foreign zone/resource and legacy plan-derived marker keys fail; recovery binds
the old plan and every recovered lease field; stale holders cannot release replacements; readiness sees one
marker; and Delete calls remain zero. Equivalent provider-deployment tests
rotate both product configuration and raw root while retaining one key.

Receipt fault injection stops after the complete receipt link and before the
seal link, then resumes with a new matching observation. The original receipt
bytes remain unchanged, their seal validates, a third run is idempotent, and a
divergent observation cannot overwrite either file. Seal-only and symlinked
half-pairs are rejected without modifying their targets.

## Full current-source and delivery validation

All real-cloud opt-ins were explicitly `0` for the current-source runs:

```text
go test ./test/compat -count=1
ok github.com/pgsty/sow/test/compat 7.650s

go test -race ./test/compat -count=1
ok github.com/pgsty/sow/test/compat 11.576s

go vet ./test/compat
PASS (no output)

staticcheck -checks='inherit,-ST1005,-U1000' ./test/compat
PASS (no output)

git diff --check
PASS (no output)
```

The first two clean-delivery attempts used the default `proxy.golang.org` in
fresh module caches and both timed out before validation while downloading
dependencies. A direct 20-second probe reproduced that network timeout;
`https://goproxy.cn` returned the same module metadata immediately. Two
subsequent independent fresh HOME/GOMODCACHE/GOCACHE reconstructions were run
serially with `SOW_CLEAN_GOPROXY=https://goproxy.cn,direct`; their product,
delivery and archive identities were equal and independent `cmp` returned 0.
The final non-self-referential digests and archive paths are recorded in the
external implementation validation ledger. The proxy substitution changed
only the dependency download route; module versions and sums remained the
repository-pinned inputs.

## Boundary

These are local fake-store, official-client protocol and filesystem fault
tests. They do not claim a live Cloudflare Worker bootstrap, API-token
readiness, purge/negative verification, provider logs, COS/EdgeOne or POC-06.
No request was sent to `pro`; no `pro` object, Worker, route, domain, cache or
control-plane setting changed. CO/COS and every Cloudflare production
repository remain forbidden mutation targets.

V-24 never produced a live lease: its bootstrap/provider-deployment registries
were closed and its evidence explicitly made no cloud write. V-25 is the first
live-capable schema, so no supported bucket contains a legacy key. If an
out-of-contract legacy object is present, readiness fails closed and requires
an owner-authorized maintenance decision; SOW does not silently delete or run
two lock namespaces.
