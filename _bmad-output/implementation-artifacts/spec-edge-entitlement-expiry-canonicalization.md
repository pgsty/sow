---
title: 'Canonicalize edge entitlement expiry'
type: 'bugfix'
created: '2026-07-19'
status: 'done'
review_loop_iteration: 0
baseline_commit: '3a0220d44fd8d0bc1ed2359f8881371f563b1235'
context:
  - '{project-root}/docs/adr/0004-edge-token-verifier-deployment-contract.md'
  - '{project-root}/docs/requirements-traceability.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Static token and Basic entitlement expiry used permissive `Date.parse`, so Cloudflare and EdgeOne runtimes could interpret timezone-less or normalized timestamps differently. Malformed Basic documents could also survive adapter construction and fail only after receiving traffic.

**Approach:** Admit one byte-stable wire form (`YYYY-MM-DDTHH:MM:SSZ`), reject calendar normalization and all alternate timezone/fraction forms, and validate both entitlement bindings when either vendor adapter is constructed.

## Boundaries & Constraints

**Always:** Preserve the shared Cloudflare/EdgeOne contract; fail closed before request handling; keep missing bindings equivalent to an empty entitlement list; regenerate committed vendor bundles from shared source; prove timezone independence.

**Ask First:** Any relaxation of the canonical timestamp grammar, compatibility alias, or mutation of a real cloud resource.

**Never:** Use runtime-local timezone behavior, silently normalize malformed dates, defer malformed secret discovery until traffic, write CO/CF production repositories, or claim provider deployment evidence from local tests.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Valid expiry | Whole-second UTC RFC3339 | Both adapters construct and verify identically | Expired value returns invalid authorization |
| Alternate form | Missing zone, numeric offset, or fractional seconds | Both adapters reject construction | Stable strict-entitlement error |
| Invalid calendar | Rollover date or hour 24 | Both adapters reject construction | No `Date` normalization |
| Malformed Basic binding | Valid token document plus malformed Basic document | Both adapters reject construction | Dormant malformed secret cannot deploy |

</frozen-after-approval>

## Code Map

- `edge/shared/contract.mjs` -- shared entitlement parser and verifier used by both vendors.
- `edge/test/contract.test.mjs` -- shared Cloudflare/EdgeOne behavior suite.
- `edge/dist/` -- reproducible generated deployment bundles.
- `edge/README.md` -- operator-visible binding schema.
- `docs/adr/0004-edge-token-verifier-deployment-contract.md` -- frozen edge verifier contract.
- `docs/requirements-traceability.md` -- FR-38, NFR-06, and FZ-08 evidence ledger.

## Tasks & Acceptance

**Execution:**
- [x] `edge/shared/contract.mjs` -- add exact UTC whole-second parsing with calendar round-trip validation and construction-time failure for both documents.
- [x] `edge/test/contract.test.mjs` -- exercise both vendor adapters against valid, alternate, normalized, and malformed Basic inputs.
- [x] `edge/dist/` -- rebuild committed bundles and verify freshness.
- [x] `edge/README.md`, `docs/adr/0004-edge-token-verifier-deployment-contract.md`, and evidence ledgers -- publish the exact wire contract without upgrading real-cloud status.

**Acceptance Criteria:**
- Given identical entitlement JSON, when adapters run under UTC and Asia/Shanghai, then all shared tests produce the same result.
- Given any noncanonical expiry or malformed Basic document, when either adapter is constructed, then construction fails before an origin request can occur.
- Given generated bundles, when freshness and syntax checks run, then committed output is byte-derived from current shared source.
- Given no real provider deployment, when traceability is updated, then FR-38 remains implemented but real-cloud verification remains open.

## Spec Change Log

## Design Notes

Round-tripping `Date.parse(value)` through `toISOString()` is only a validation aid after an exact lexical gate. It rejects JavaScript calendar rollover while keeping expiry comparison in epoch milliseconds.

## Verification

**Commands:**
- `npm test --prefix edge` -- expected: bundle freshness, syntax checks, and all shared contract cases pass.
- `TZ=UTC node --test edge/test/contract.test.mjs` -- expected: shared suite passes.
- `TZ=Asia/Shanghai node --test edge/test/contract.test.mjs` -- expected: identical shared suite passes.
- `go test ./test/compat/cleandelivery -count=1` -- expected: clean-delivery manifest accepts the new evidence and bundles.
- `SOW_CLEAN_GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download ./test/compat/test-clean-delivery.sh <root>` -- expected: two isolated runs have identical product, delivery, and archive digests.

## Suggested Review Order

**Fail-closed validation**

- Validate both static documents before either vendor accepts traffic.
  [`contract.mjs:789`](../../edge/shared/contract.mjs#L789)

- Admit one timezone-independent timestamp and reject calendar normalization.
  [`contract.mjs:1063`](../../edge/shared/contract.mjs#L1063)

**Frozen contract**

- Record the exact cross-vendor wire grammar and deployment failure semantics.
  [`0004-edge-token-verifier-deployment-contract.md:39`](../../docs/adr/0004-edge-token-verifier-deployment-contract.md#L39)

- Give operators the accepted secret shape and rejected alternatives.
  [`README.md:82`](../../edge/README.md#L82)

**Verification**

- Exercise both adapters, timezones, dormant secrets, and zero-call failures.
  [`contract.test.mjs:1585`](../../edge/test/contract.test.mjs#L1585)

- Preserve measured evidence without upgrading real-cloud status.
  [`2026-07-19-edge-entitlement-expiry-canonicalization.md:3`](../../docs/evidence/2026-07-19-edge-entitlement-expiry-canonicalization.md#L3)

- Keep FR-38, NFR-06, and FZ-08 status evidence honest.
  [`requirements-traceability.md:99`](../../docs/requirements-traceability.md#L99)
