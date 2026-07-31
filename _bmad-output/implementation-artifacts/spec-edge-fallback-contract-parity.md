---
title: 'Edge fallback contract parity'
type: 'bugfix'
created: '2026-07-31'
status: 'done'
baseline_commit: '2517d5b24a7523fbea95a7738ee3ad6c5d6caa60'
review_loop_iteration: 0
context:
  - '{project-root}/edge/README.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Cloudflare Worker and EdgeOne top-level failure handlers still emit `X-SOW-Edge-Contract: sow-edge-runtime/v1` even though the only accepted deployment schema is v2. A construction or configuration failure therefore returns misleading, vendor-duplicated evidence and omits the normal private error response hardening.

**Approach:** Make both shipped entrypoints derive their fail-closed response from the shared v2 contract constant, align the response headers with ordinary private errors, and verify source plus generated bundles execute the same fallback behavior.

## Boundaries & Constraints

**Always:** Return 503 without exposing the caught exception, credentials, environment values, or origin details; set `private, no-store`, `nosniff`, plain-text content type, and the current shared contract version; keep Cloudflare and EdgeOne behavior byte-equivalent where their runtime APIs permit.

**Ask First:** Any change to the frozen `sow-edge-runtime/v2` schema or to provider deployment topology.

**Never:** Touch a cloud resource, weaken fail-closed behavior, add a runtime dependency, hand-edit generated `edge/dist` files, or turn this into a broader edge protocol redesign.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Cloudflare construction failure | Invalid or incomplete environment reaches default export | 503, v2 contract header, hardened private headers, stable body | Exception is suppressed |
| EdgeOne construction failure | Invalid or incomplete global `env` reaches fetch listener | Same 503/body/header contract as Cloudflare | Exception is suppressed |
| Generated deployment bundles | Rebuilt standalone artifacts execute without source imports | Their live fallback responses match source entrypoints | Stale bundle check fails before tests |

</frozen-after-approval>

## Code Map

- `edge/shared/contract.mjs` -- owns `EDGE_RUNTIME_SCHEMA` and the common request contract.
- `edge/cloudflare/worker.mjs` -- Cloudflare top-level default export and fallback response.
- `edge/edgeone/index.js` -- EdgeOne fetch-event entrypoint and fallback response.
- `edge/build.mjs` -- produces standalone deployment bundles from source.
- `edge/test/contract.test.mjs` -- source and generated-bundle contract tests.

## Tasks & Acceptance

**Execution:**
- [x] `edge/cloudflare/worker.mjs`, `edge/edgeone/index.js` -- use the shared schema constant and complete hardened fallback headers.
- [x] `edge/test/contract.test.mjs` -- execute both vendor fallback entrypoints and assert exact status, body, and security/contract headers.
- [x] `edge/dist/*` -- regenerate only through `edge/build.mjs`.

**Acceptance Criteria:**
- Given either provider entrypoint cannot construct its handler, when a request is dispatched, then it returns a secret-free 503 carrying `sow-edge-runtime/v2`, `private, no-store, max-age=0`, `text/plain; charset=utf-8`, and `nosniff`.
- Given generated bundles are checked, when edge tests run, then no source/bundle contract drift remains.
- Existing normal auth, routing, cache normalization, mirrorlist, and private-origin tests remain green.

## Spec Change Log

## Verification

**Commands:**
- `cd edge && npm test` -- generated bundles are current and all edge source/bundle contract tests pass.
- `rg -n 'sow-edge-runtime/v1' edge` -- expected: no matches.

## Suggested Review Order

**Shared failure contract**

- Centralizes the secret-free 503 under the frozen runtime schema.
  [`contract.mjs:11`](../../edge/shared/contract.mjs#L11)

**Provider entrypoints**

- Cloudflare construction failures now use the shared hardened response.
  [`worker.mjs:226`](../../edge/cloudflare/worker.mjs#L226)

- EdgeOne construction failures use the identical shared response.
  [`index.js:4`](../../edge/edgeone/index.js#L4)

**Regression proof**

- Executes source and generated entrypoints and compares complete observable responses.
  [`contract.test.mjs:343`](../../edge/test/contract.test.mjs#L343)

- Runs EdgeOne with a present but invalid environment, matching deployment failure shape.
  [`contract.test.mjs:375`](../../edge/test/contract.test.mjs#L375)
