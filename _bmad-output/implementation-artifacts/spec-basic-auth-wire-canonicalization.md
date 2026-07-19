---
title: 'Canonicalize Basic fallback authorization wire'
type: 'bugfix'
created: '2026-07-19'
status: 'done'
review_loop_iteration: 0
baseline_commit: 'f93036a'
context:
  - '{project-root}/docs/adr/0004-edge-token-verifier-deployment-contract.md'
  - '{project-root}/edge/README.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** The shared Basic fallback parser accepts only case-exact `Basic`, decodes an unbounded token before enforcing its credential limit, permits ASCII control characters, and advertises UTF-8 although non-ASCII credentials are rejected. Cloudflare and EdgeOne therefore expose a misleading and incompletely bounded RFC 7617 surface.

**Approach:** Freeze a deterministic ASCII-only Basic subset: case-insensitive scheme, one or more literal spaces, canonical padded RFC 4648 Base64, a pre-decode size bound, printable ASCII `user:password`, and a realm-only challenge. Hash the decoded canonical user-pass exactly as before.

## Boundaries & Constraints

**Always:** Preserve current ASCII apt/dnf credentials and entitlement digests; keep password colons valid; reject empty usernames, control/DEL/non-ASCII bytes, aliases and oversized tokens before origin; run the same parser/tests in both vendor adapters; regenerate committed bundles.

**Ask First:** Any Unicode credential support, normalization fallback, entitlement digest migration, or real cloud mutation.

**Never:** Log credentials, hash the Base64 wrapper, accept URL-safe/whitespace/unpadded aliases, advertise unsupported UTF-8, weaken token authentication, or touch CO/CF production resources.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Canonical client | Mixed-case scheme + 1..N spaces + padded Base64 ASCII credentials | Authorized identically on both vendors | Credential stripped before origin |
| Wire alias | Tab separator, whitespace in token, URL-safe or unpadded Base64 | Private 401 | Zero origin calls |
| Invalid user-pass | Empty username, CTL/DEL/non-ASCII byte, or over 1024 decoded bytes | Private 401 | Zero origin calls and no decode-size amplification |
| Challenge | Missing/invalid credentials | `Basic realm="Pigsty Pro"` | No unsupported charset advertisement |

</frozen-after-approval>

## Code Map

- `edge/shared/contract.mjs` -- shared Basic header parser and 401 challenge.
- `edge/test/contract.test.mjs` -- both-vendor authorization and zero-origin boundary suite.
- `edge/dist/` -- generated Cloudflare and EdgeOne deployment bundles.
- `edge/README.md` -- operator contract for credential digest and ASCII wire form.
- `docs/adr/0004-edge-token-verifier-deployment-contract.md` -- frozen cross-vendor verifier decision.
- `docs/requirements-traceability.md` -- FR-40/NFR-06/FZ-08 evidence boundary.

## Tasks & Acceptance

**Execution:**
- [x] `edge/shared/contract.mjs` -- implement bounded canonical ASCII Basic parsing and truthful challenge.
- [x] `edge/test/contract.test.mjs` -- cover case, spacing, Base64 aliases, size, controls, UTF-8 and zero-origin behavior on both adapters.
- [x] `edge/dist/` -- regenerate both affected vendor bundles and prove freshness.
- [x] `edge/README.md`, ADR, evidence and traceability -- freeze the exact digest/wire contract without upgrading real-cloud status.

**Acceptance Criteria:**
- Given supported ASCII credentials, when apt/dnf-style canonical Basic is sent with any scheme casing, then both adapters authorize and strip it before origin.
- Given any forbidden wire/user-pass boundary, when either adapter handles it, then it returns 401, emits the realm-only challenge, and makes zero origin calls.
- Given final source, when build freshness, shared tests, timezone runs and clean-delivery reconstruction execute, then all pass deterministically with no cloud access.

## Spec Change Log

## Design Notes

RFC 7617 requires Base64 credentials and forbids control characters. Its UTF-8 challenge parameter is optional and should only be advertised by a server that implements that credential encoding. SOW deliberately retains the existing ASCII digest domain rather than creating an implicit Unicode normalization migration.

## Verification

**Commands:**
- `npm test --prefix edge` -- expected: generated freshness, syntax and shared contracts pass.
- `TZ=UTC node --test edge/test/contract.test.mjs` -- expected: shared suite passes.
- `TZ=Asia/Shanghai node --test edge/test/contract.test.mjs` -- expected: identical shared suite passes.
- `go test ./test/compat -run 'CloudflareEdge|EdgeContract' -count=1` -- expected: Go deployment/compat bridge passes.
- `go test ./test/compat/cleandelivery -count=1` -- expected: allowlist and clean source assembly pass.

## Suggested Review Order

**Fail-closed parser**

- Check the complete-header/token/decoded bounds, canonical Base64 round trip,
  printable ASCII gate and realm-only challenge.
  [`contract.mjs:566`](../../edge/shared/contract.mjs#L566)

**Cross-vendor boundaries**

- Review the two-adapter positive matrix, password-colon preservation,
  wire aliases, byte classes, exact maximum and zero-origin assertions.
  [`contract.test.mjs:1428`](../../edge/test/contract.test.mjs#L1428)

**Frozen operator contract**

- Confirm digest compatibility and the deliberately ASCII-only RFC 7617
  subset.
  [`0004-edge-token-verifier-deployment-contract.md:47`](../../docs/adr/0004-edge-token-verifier-deployment-contract.md#L47)

- Confirm the deployment-facing secret and credential guidance.
  [`README.md:92`](../../edge/README.md#L92)

**Evidence boundary**

- Reproduce source/dist/timezone/client checks and retain the no-cloud claim.
  [`2026-07-19-basic-auth-wire-canonicalization.md:3`](../../docs/evidence/2026-07-19-basic-auth-wire-canonicalization.md#L3)

- Keep FR-40/NFR-06/FZ-08 real-CDN status open.
  [`requirements-traceability.md:100`](../../docs/requirements-traceability.md#L100)
