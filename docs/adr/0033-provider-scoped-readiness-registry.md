# ADR-0033: Provider-scoped read-only readiness has an independent registry

Status: Accepted (2026-07-17)

## Context

The real-cloud acceptance harness has two deliberately strict, SHA-pinned
registries: one for the complete dual-cloud resource tuple and one for the
deployed edge/logging identity. Requiring both registries for a preliminary
read-only check made the claimed provider-scoped readiness path circular: a
Cloudflare bucket could not be checked until unrelated COS/EdgeOne resources
and every later deployment identity already existed.

Readiness is useful only if it can safely establish one provider's starting
state without granting mutation authority or weakening the full acceptance
gate.

## Decision

1. Add a third, independent, compiled-SHA-pinned provider-readiness registry.
   Each entry names exactly one provider and exactly one non-secret identity:
   - Cloudflare: account ID, account R2 endpoint, bucket, zone ID/name, and
     distinct main/beta HTTPS roots;
   - EdgeOne: regional COS endpoint, bucket, region, zone ID/name, and distinct
     main/beta HTTPS roots.
2. The entry must be canonical JSON, carry the fixed disposable-non-production
   purpose, match the selected provider, and appear byte-for-byte in the
   repository registry. The fixed non-production confirmation is still
   mandatory. These checks run in `TestMain` before credential decoding,
   client construction, or network access.
3. A readiness run loads only the selected provider's storage and control-plane
   credentials. Its permitted operation set is limited to a signed
   `ListObjectsV2` proving the exact publisher bucket empty and read-only
   control-plane identity queries for the pinned zone and domain closure.
   Cloudflare must return exactly the enabled, ownership-active, SSL-active
   main/beta R2 custom domains bound to the pinned bucket/zone; EdgeOne must
   return exactly the online main/beta acceleration domains. It may not upload,
   delete, purge, deploy, configure logging, or inspect the other provider.
4. The exact owner-designated Cloudflare tuple from ADR-0032 is accepted only
   as a whole. Account, endpoint, zone ID/name, bucket, main and beta roots are
   still pinned by the reviewed readiness entry; no arbitrary Pigsty resource
   exception is introduced.
5. Offline onboarding can emit a candidate registry and a digest receipt only
   outside the repository. It does not read credentials, contact a provider,
   modify the compiled registry, or approve its own candidate.
6. A successful readiness receipt uses
   `sow-real-cloud-provider-readiness/v2` and binds the run, selected provider,
   reviewed readiness-resource digest, empty-bucket identity digest and
   provider-control digest. It contains no URL or credential.
7. The complete destructive and evidence-producing POC remains unchanged: it
   still requires the full dual-cloud resource registry, provider-deployment
   registry, destructive confirmation, durable ledger, isolated credentials,
   exact purge and post-publish verification. A readiness receipt is neither
   mutation authorization nor POC-06 evidence.

## Consequences

- Cloudflare readiness no longer waits for COS/EdgeOne or uncreated Worker and
  Logpush identities, while all write paths retain the stronger dual-cloud
  gates.
- The registry starts closed and changes only through an independently reviewed
  canonical candidate plus compiled digest update. On 2026-07-18 it admitted
  exactly the owner-designated Cloudflare `pro` tuple; no EdgeOne or other
  Cloudflare identity is present. This changes only the read-only readiness
  gate, not any write-capable registry.
- The active R2 custom-domain or EdgeOne acceleration-domain binding is proven
  by readiness. Worker/function routes, private-origin deployment, raw-log
  exporters, cache behavior and purge remain explicit later acceptance
  requirements; the narrower readiness receipt cannot be used to claim them.
- No cloud request or mutation is authorized by this ADR alone.
- The separately owner-authorized 2026-07-18 R2 storage-protocol run used this
  registry only to pin the exact nonproduction tuple. ADR-0036 supplied a
  different, run-owned mutation gate; the readiness receipt remains read-only.

## Evidence

`TestRealCloudProviderReadinessRegistryIsIndependentAndPinned`,
`TestRealCloudProviderReadinessRegistryCandidateIsDeterministicAndProviderScoped`,
`TestRealCloudProviderReadinessResourceRejectsPartialOwnerTupleAndCrossProviderFields`,
`TestRealCloudProviderReadinessSelectionDoesNotRequireOtherProviderOrDeployment`,
the process-gate tests, and
`TestRealCloudProviderReadinessContractIsScopedAndRedacted` cover the independent
registry, exact provider selection, offline onboarding, pre-client rejection,
read-only operation set and secret-free sealed receipt.
The live non-production tuple, candidate digests and remaining signed-receipt
boundary are recorded in
[`2026-07-18-cloudflare-pro-domain-readiness.md`](../evidence/2026-07-18-cloudflare-pro-domain-readiness.md).
The storage-only run and its explicit non-claims are recorded in
[`2026-07-18-real-r2-storage-protocol.md`](../evidence/2026-07-18-real-r2-storage-protocol.md).

Cloudflare's official API defines the bucket-scoped custom-domain inventory as
`GET /accounts/{account_id}/r2/buckets/{bucket_name}/domains/custom` and exposes
enabled, ownership/SSL status and zone identity:
<https://developers.cloudflare.com/api/resources/r2/subresources/buckets/subresources/domains/subresources/custom/methods/list/>.
