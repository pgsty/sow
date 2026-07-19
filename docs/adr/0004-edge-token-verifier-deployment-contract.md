# ADR-0004: Versioned edge token-verifier deployment contract

Status: accepted

Date: 2026-07-12

Amended: 2026-07-15

## Context

`sow.yaml` originally accepted `edge.token_verifier: provider://...`, while the
Cloudflare Worker independently selected an optional `ENTITLEMENTS` binding and
the EdgeOne function independently selected static environment data. The Go
reference was therefore validated and persisted but never consumed. A typo or
missing provider could silently select a different verifier path, violating the
frozen dual-vendor interface and fail-closed requirements in FR-38/FR-39.

## Decision

The verifier reference is a closed non-secret union:

- `provider://<lowercase-id>` selects a remote entitlement provider;
- `env://<UPPERCASE_BINDING>` selects strict static entitlement JSON held in a
  platform secret binding.

Go maps each target to versioned edge-runtime variables and binding names during
configuration preflight. Both executable adapters require that version, the
frozen Pro prefix, the two public origins, and an exact `SOW_TOKEN_VERIFIER`
copy. Cloudflare provider mode requires the fixed `TOKEN_VERIFIER` service
binding. EdgeOne provider mode requires `SOW_TOKEN_VERIFIER_URL` and the secret
`SOW_TOKEN_VERIFIER_BEARER`.

Both provider transports send `sow-token-verifier-request/v1` with provider ID,
token SHA-256, canonical audience and canonical path. Raw bearer tokens are not
sent to the provider. Provider 200/401/403 responses map to ok/invalid/forbidden;
all transport, protocol and configuration failures map to unavailable. No
failure may reach the repository origin.

### 2026-07-15 route-admission amendment

The executable runtime contract is now `sow-edge-runtime/v2`. Version 2 is an
intentional fail-closed security upgrade, not a compatible reinterpretation of
version 1. Both adapters reject `sow-edge-runtime/v1`; operators must rerender
each target with `sow materialize latest --edge-contract TARGET` and install the
resulting variables as one indivisible document.

`SOW_COMPATIBILITY_ADMISSION` is the canonical route-admission inventory for
all edge-owned control paths. It contains exact current APT roots, exact YUM
roots and channel coordinates, exact asset roots/keys, compatibility projection
raw/active state, and a separate immutable inventory for every admitted
snapshot. Every ordinary YUM channel coordinate carries its expected literal
repository root; a dynamic channel pointer whose `legacy_root` differs fails
with 503. Compatibility channels use the frozen projection root and apply the
same check.

Snapshot admission is keyed by snapshot ID and derives from the manifest at the
immutable snapshot ref, not from current repository activation. This keeps an
EOL snapshot addressable after its owner leaves current views while preventing
another snapshot ID from borrowing its roots. Both snapshot payload and
`_route.json` require the exact admitted ID before any pointer or origin read.

## Consequences

- Existing `provider://pigsty-entitlements` configuration remains valid, but it
  now requires a real vendor binding and cannot be silently ignored.
- Static deployments must explicitly use `env://NAME`; malformed entitlement
  JSON fails adapter startup instead of becoming an empty allowlist.
- Deployment contracts persist only variable and binding names. Provider bearer,
  entitlement documents, Basic credentials and origin credentials remain in
  vendor secret stores.
- Private repository transport is no longer an unspecified deployment
  dependency: [ADR-0012](0012-private-origin-deployment-contract.md) records the
  service-only R2 origin Worker, EdgeOne's direct COS SigV4 GET/HEAD contract,
  and the still-provisional cache topology boundary.
- The shared local contract suite proves request/status/origin behavior. Real
  Cloudflare and EdgeOne deployment and EdgeOne cache-tier behavior remain an
  external PoC gate; local evidence must not be reported as that PoC.
- No production Cloudflare, R2, EdgeOne or COS repository was used to validate
  the v2 amendment; its evidence is the local generated-contract and shared
  adapter suite only.
