# Cloudflare Workers Paid provider-attestation correction

Date: 2026-07-29

Baseline revision: `f2f34ab`; this report describes the reviewed working tree
on top of that revision.

## Result

The Cloudflare provider-log contract no longer requires the Enterprise-only
zone `http_requests` dataset. The corrected implementation uses the
account-scoped `workers_trace_events` dataset available with Workers Paid:

- only the auth Worker has `logpush=true`; origin and optional verifier Workers
  must have `logpush=false`;
- the account job is enabled, NDJSON, full sample, and filters exact
  `ScriptName` plus `Outcome=ok`;
- exported provider fields are limited to `EventTimestampMs`, `Logs`,
  `Outcome`, `ScriptName`, and `ScriptVersion`;
- the update omits HTTP-only `merge_subrequests` and any timestamp-format
  override, preserving the dataset's documented millisecond integer fields;
- an explicit `X-SOW-Provider-Probe` run ID causes at most one bounded,
  secret-free ten-field console event; the header is never forwarded to the
  origin;
- the parser binds the provider-owned script/version/timestamp envelope to the
  observed `CF-Ray`, colo, clean-URL digest, cache state, freshness, status, and
  acceptance run;
- unrelated successful auth invocations with empty `Logs`, and well-formed
  records for a different run, are ignored rather than treated as evidence;
- every other enabled account job is rejected when it may include the reviewed
  auth Worker or write the dedicated raw bucket;
- the complete zone job inventory remains independently audited so an enabled
  HTTP job cannot capture either reviewed host or write the raw bucket.
- account/zone job and EdgeOne task isolation are read before either provider
  mutation; overlap or wrong immutable task identity therefore has zero
  exporter updates.

This follows Cloudflare's current
[Workers Logpush contract](https://developers.cloudflare.com/workers/observability/logs/logpush/),
[Workers Trace Events dataset](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/workers_trace_events/),
and [account Logpush API](https://developers.cloudflare.com/logs/logpush/logpush-job/api-configuration/).
Cloudflare documents that destination changes can take about 10–15 minutes to
propagate, so the acceptance program now records configuration time and
enforces a 16-minute gate before the first provider probe, including recovery
after reconfiguration.

## Current offline deployment identity

The owner-authorized, disposable `pro` tuple was regenerated from this
corrected Worker bundle in private, create-only directories:

| Artifact | SHA-256 |
|---|---|
| readiness resource canonical bytes | `0af5c47472a59b2c677889d8f2039d469d88ce05f3642b43d54389405aa78a2d` |
| bootstrap plan canonical bytes | `43d936dccecac5d5f3d0afe5e3a85396fa872fb026458224e8aafdf32c496f43` |
| auth Worker bundle | `2d3b5ea7b1cbd9bd6852fe51ba0b91afdf450bb47c642455ac2d69c91bfd6267` |
| origin Worker bundle | `54f9dfe5d124b59cd4c81feb5980f9f8a30f95adb85c8c0f786b27915a646923` |
| current-only bootstrap registry file | `87f7861e0f645d822c1dd237cf4f23a75149b3a90fb10c473295692430bcdf9c` |

The prior plan `12c7410a…025c`, auth bundle `85389273…fa0c`, and registry
`78f400b8…cab0` recorded by V-86 are historical and must not be used for a new
bootstrap. The checked-in registry contains only the corrected plan, so the
stale plan fails before credentials, client construction, or requests.

## Reproducible checks

Every command explicitly removed cloud credentials and disabled every real
cloud, real edge, real upstream, and Docker compatibility opt-in.

```bash
cd edge
npm run build
npm test
```

Result: 48/48 contract tests passed, including the exact event schema,
credential/URL suppression, ray/colo mismatch suppression, uppercase ray
normalization, ordinary-request silence, and origin-header stripping.

```bash
env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  -u CLOUDFLARE_API_TOKEN -u TENCENTCLOUD_SECRET_ID \
  -u TENCENTCLOUD_SECRET_KEY \
  SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 \
  SOW_RUN_REAL_UPSTREAM=0 SOW_RUN_DOCKER_COMPAT=0 \
  go test -timeout 20m -count=1 ./test/compat \
  -run 'RealCloud(Cloudflare|Provider)'
```

Result: PASS, package `1.397s`.

```bash
env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  -u CLOUDFLARE_API_TOKEN -u TENCENTCLOUD_SECRET_ID \
  -u TENCENTCLOUD_SECRET_KEY \
  SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 \
  SOW_RUN_REAL_UPSTREAM=0 SOW_RUN_DOCKER_COMPAT=0 \
  go test -race -timeout 20m -count=1 ./test/compat \
  -run 'RealCloud(Cloudflare|Provider)'
```

Result: PASS, package `3.224s`.

The full compatibility package then passed without the focused selector:

```text
go test -timeout 30m -count=1 ./test/compat
ok github.com/pgsty/sow/test/compat 10.306s

go test -race -timeout 30m -count=1 ./test/compat
ok github.com/pgsty/sow/test/compat 15.268s

go vet ./...
PASS

staticcheck ./...
PASS

git diff --check
PASS
```

These are SDK/HTTP loopback, strict-parser, fake-store, and real filesystem
tests. They deliberately make no provider request and do not upgrade POC-06.

## External evidence still open

Workers Paid is sufficient; an Enterprise zone is no longer a prerequisite.
The remaining live proof requires only dedicated non-production resources and
scoped credentials:

1. create the already prepared short-lived bootstrap token and run the exact
   `pro` Worker/route/purge/cache/rollback program;
2. provide an account-scoped token with `Logs Edit` for the exact Workers Trace
   job, plus pairwise-distinct, prefix-scoped R2 log writer, reader, and lease
   control identities;
3. wait through the automatic 16-minute propagation gate and collect the
   provider-owned Trace envelope twice;
4. run the independent COS/EdgeOne program with its own disposable resources.

No Cloudflare API mutation, remote object write, purge, Worker deployment, or
route change occurred while producing this evidence. No CO/COS or Cloudflare
production repository, bucket, zone, domain, or publication namespace was
readied as a write target.
