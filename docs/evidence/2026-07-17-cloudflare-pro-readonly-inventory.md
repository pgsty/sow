# 2026-07-17 Cloudflare `pro` test resource read-only inventory

Status: external read-only identity partially observed; no cloud mutation; not a
POC-06 pass.

> Historical baseline. The 2026-07-18 owner-authorized non-production follow-up
> connected `beta.pro.pigsty.io`, raised both test hosts to TLS 1.2, authenticated
> the empty R2 bucket and pinned the exact readiness tuple. See
> [2026-07-18-cloudflare-pro-domain-readiness.md](2026-07-18-cloudflare-pro-domain-readiness.md).
> The observations below intentionally remain unchanged as the before-state.

## Owner authorization and hard boundary

The owner designated the exact R2 bucket `pro` and `https://pro.pigsty.io` for
SOW testing. CO/COS and Cloudflare production repositories remain forbidden for
all tests. This observation did not upload, delete, purge, deploy, edit DNS,
inspect secrets, or use a production repository.

## Observed facts

At 2026-07-17 15:36 CST, an authenticated, read-only Cloudflare dashboard
inspection showed:

- account handle `PGSTY`, account ID
  `72cdbd1b54f7add44ecbd3d986399481`;
- R2 bucket `pro` exists under that account;
- storage class `Standard`, public access enabled, reported size `0 B`;
- the object table reports the bucket ready and contains no objects.

Independent public, non-mutating probes showed:

```text
https://pro.pigsty.io/ status=404 tls_verify=0 redirect=<none>
server: cloudflare
cf-cache-status: DYNAMIC

beta.pro.pigsty.io: DNS name did not resolve
```

`pro.pigsty.io` resolved to Cloudflare anycast IPv4 and IPv6 addresses. The
404 is consistent with an enabled custom domain on an empty bucket; it is not
treated as signed S3 inventory evidence.

## Deliberately unclaimed

This observation does **not** prove:

- the account-level R2 S3 endpoint by a signed request;
- the exact `pigsty.io` zone ID;
- `beta.pro.pigsty.io` DNS or routing (it is currently absent);
- scoped R2 storage or Cloudflare API credentials;
- Worker, origin service, token-verifier, route, Logpush, or cache behavior;
- upload, conditional write/delete, purge, recovery, or CLI publication.

All three compiled real-cloud registries therefore remain empty and every
applicable network-capable opt-in still fails before credential decoding or
client construction. The next permitted external step is a signed,
provider-scoped, read-only readiness run after the exact zone ID, an enabled
ownership/SSL-active `beta.pro.pigsty.io` R2 custom domain, the reviewed
readiness entry, a bucket-list S3 credential and an account-R2-read plus
exact-zone-read API token are supplied. Worker/deployment identities are not
needed for this preliminary step; they remain mandatory for the full POC.

## 19:48 CST public revalidation

A second read-only probe after the owner reconfirmed the resource produced the
same boundary: `pro.pigsty.io` resolved to Cloudflare IPv4/IPv6 anycast and a
TLS-verified `HEAD /` returned HTTP/2 404, `server: cloudflare`,
`cf-cache-status: DYNAMIC`, with no redirect. `beta.pro.pigsty.io` still had no
A or AAAA record and HTTPS failed at DNS resolution. No object, DNS, Worker,
route, setting or cache state was changed. The browser control surface had no
authenticated Cloudflare session, and the process environment contained no
Cloudflare/R2 credential or cloud CLI, so signed readiness could not be run.
