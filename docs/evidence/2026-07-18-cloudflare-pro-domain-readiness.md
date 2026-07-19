# 2026-07-18 Cloudflare `pro` non-production domain readiness

Status: live non-production domain configuration and authenticated empty-bucket
evidence passed; the SOW signed provider-readiness receipt is still blocked on
one scoped Cloudflare API token. This is not a POC-06 pass.

## Authorized boundary

The owner explicitly authorized SOW to use the empty R2 bucket `pro`, its S3
endpoint, and `pro.pigsty.io`, while reiterating that no CO/COS/Cloudflare
production repository may be used for testing. The same authorization covers
the reversible beta default already frozen by ADR-0032:
`beta.pro.pigsty.io`.

This run made only two Cloudflare control-plane changes inside that exact test
tuple:

1. connected `beta.pro.pigsty.io` to R2 bucket `pro`, creating the exact
   `beta.pro` CNAME reviewed by the dashboard;
2. raised the existing `pro.pigsty.io` minimum TLS version from 1.0 to 1.2.

It did not upload, overwrite, delete or purge an object; create a Worker;
change a Worker route; touch another bucket/domain; or access a production
repository.

## Provider identity and dashboard result

The exact identity is:

```text
account_id = 72cdbd1b54f7add44ecbd3d986399481
zone_id    = da7b5a27e4f9ef6eaa1b00a89c2c77c2
zone_name  = pigsty.io
r2_bucket  = pro
r2_service = https://72cdbd1b54f7add44ecbd3d986399481.r2.cloudflarestorage.com
main       = https://pro.pigsty.io
beta       = https://beta.pro.pigsty.io
```

Before the change, the authenticated R2 dashboard reported `0 B`, an empty
object table, one active custom domain (`pro.pigsty.io`) and minimum TLS 1.0.
After the change, the same dashboard reported exactly two custom-domain rows:

```text
pro.pigsty.io       min_tls=1.2 status=active access=enabled
beta.pro.pigsty.io  min_tls=1.2 status=active access=enabled
```

The zone ID was independently recovered from the existing local Cloudflare
analytics snapshot's `zoneMap`; no browser credential, cookie, local storage or
secret was inspected.

## Public DNS, HTTPS and TLS evidence

Cloudflare authoritative DNS and both public resolvers returned the same
three anycast IPv4 addresses for the beta host:

```text
dig @rohin.ns.cloudflare.com beta.pro.pigsty.io A
dig @1.1.1.1 beta.pro.pigsty.io A
dig @8.8.8.8 beta.pro.pigsty.io A

104.26.10.24
104.26.11.24
172.67.69.155
```

Both hosts completed certificate verification and returned the expected empty
bucket HTTP/2 404 with `server: cloudflare` and `cf-cache-status: DYNAMIC`.
The beta probe initially used `curl --resolve` because the macOS process-local
resolver still held the pre-creation negative result; authoritative, 1.1.1.1
and 8.8.8.8 were already positive.

OpenSSL 3.6.3 was forced to offer legacy protocols with
`-cipher ALL:@SECLEVEL=0`. Both hosts returned a remote TLS alert 70
(`protocol version`) for TLS 1.0 and 1.1. Both accepted TLS 1.2 and 1.3:

```text
pro.pigsty.io TLS 1.2  ECDHE-ECDSA-CHACHA20-POLY1305  verification OK
pro.pigsty.io TLS 1.3  TLS_AES_256_GCM_SHA384           verification OK
beta.pro.pigsty.io TLS 1.2  ECDHE-ECDSA-CHACHA20-POLY1305  verification OK
beta.pro.pigsty.io TLS 1.3  TLS_AES_256_GCM_SHA384           verification OK
```

## Authenticated storage and SOW gate evidence

The pre-existing local `rclone` Cloudflare remote is pinned to the exact
account R2 endpoint. Only the authorized bucket path was queried:

```text
rclone lsf cf:pro --max-depth 1
# no output

rclone size cf:pro --json
{"count":0,"bytes":0,"sizeless":0}
```

The decrypted credential was passed only through process environment to the
SOW test; it was not printed or persisted. A deliberately invalid, non-secret
Cloudflare API token was supplied so the strictly read-only provider test could
prove ordering. The test completed the product's Go SigV4 `ListObjectsV2`
empty-bucket check and then failed at the next operation:

```text
cloudflare read-only readiness failed: Cloudflare exact zone identity query failed
```

Because the zone query occurs only after a successful empty-bucket list, this
is direct evidence that the SOW storage leg reached and passed the real R2
service. No receipt or seal was written, and the failed run is not reported as
signed readiness.

## Reviewed readiness registry

The offline onboarding command generated a canonical candidate outside the
repository and passed:

```text
resource_sha256=0af5c47472a59b2c677889d8f2039d469d88ce05f3642b43d54389405aa78a2d
registry_sha256=ed06605a86cb84ece865a6ea2eb7280d3094392d144a5841ac257268bc8f3f63
```

The repository-pinned provider-readiness registry now contains exactly this
one Cloudflare tuple. Focused ordinary and race registry tests passed. This
entry authorizes only the read-only readiness path; destructive/full POC,
provider-deployment and bootstrap registries remain separate and closed.

## Remaining exact blocker

The Cloudflare readiness receipt v2 still requires a bearer token with the
harness's two read-only capabilities: exact-account Workers R2 Storage Read
and exact-zone Zone Read. No such token is present in the process environment
or the documented local token file. Its seal is now Ed25519 v2: a future
readiness run must inject a private seed through
`SOW_REAL_CLOUD_PROVIDER_READINESS_SIGNER_JSON`, while the reviewed bootstrap
plan pins only the corresponding public key. Until the token is securely
injected, a keypair/plan is reviewed, and the real test succeeds, the
provider-control digest, signed readiness receipt and POC-06 remain unclaimed.

Full POC-06 additionally requires the independently reviewed Worker/origin/
verifier, purge, provider-log, entitlement, observation and EdgeOne/COS
resources. None of those requirements is weakened by this partial closure.
