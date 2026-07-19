---
title: 'Remove CDN authority from remote fsck'
type: 'bugfix'
created: '2026-07-19'
status: 'done'
review_loop_iteration: 0
baseline_commit: '93f8a678a5937a81adfc917adfdf9d206efab349'
context:
  - '{project-root}/internal/cli/remote_audit.go'
  - '{project-root}/docs/requirements-traceability.md'
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** `sow fsck --target` performs only object-storage List/HEAD/GET, but constructs the full publication client. It therefore reads CDN credentials and acquires Cloudflare purge or Tencent EdgeOne authority that the operation neither needs nor should possess.

**Approach:** Add provider-specific R2 and COS storage-only clients, route remote inventory adoption/L2 fsck through them, and prove real R2 adoption/drift behavior using only the owner-designated empty non-production `pro` bucket.

## Boundaries & Constraints

**Always:** Resolve only the selected target's storage secret; preserve SigV4, bounded streaming, full inventory and canonical-state semantics; keep Cloudflare and Tencent provider types explicit; require the exact compiled non-production registry, empty-bucket gate, run lease and identity-bound cleanup for real R2.

**Ask First:** Any Worker/Zone/purge API, provider deployment, COS/EdgeOne resource, production repository, or resource outside the pinned `pro` tuple.

**Never:** Read a CDN credential during remote fsck, silently fall back to a full publisher, delete unproven bytes, contact CO/CF production repositories, or claim CDN/POC-06 completion from storage-only evidence.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| R2/COS remote fsck | Valid storage secret; CDN secret absent | List/HEAD/GET through provider-specific storage-only client | No CDN client or credential resolution |
| Existing bucket adoption | Stable full listing plus matching local object | Complete canonical inventory; idempotent replay | Double-list and streamed identity required |
| Remote drift | Same key replaced with different run-owned bytes | Adoption rejected; canonical HEAD unchanged | Restore only with exact CAS and identity proof |
| Real R2 cleanup | Exact run lease and allowlisted bodies | All run objects absent; bucket empty | Foreign/changed bytes retained and failure reported |

</frozen-after-approval>

## Code Map

- `internal/publish/http_tencent.go` -- COS-only signed object client without EdgeOne authority.
- `internal/cli/publish_provider.go` -- storage-only remote-audit client construction.
- `internal/cli/remote_audit.go` -- provider-specific audit transport dispatch.
- `internal/cli/app.go` -- fsck entrypoint selects least-authority client.
- `test/compat/real_cloud_r2_fsck_test.go` -- exact-registry real R2 adoption/drift/cleanup path.
- `docs/requirements-traceability.md` -- FR-06/30, NFR-06 and MIG-01 evidence boundary.

## Tasks & Acceptance

**Execution:**
- [x] Add concrete R2/COS object-audit clients that expose only required read methods.
- [x] Make remote fsck resolve storage credentials only; retain full clients for publish/verify paths.
- [x] Add unit/protocol/CLI tests proving absent or malformed CDN secrets are never consumed.
- [x] Run exact non-production R2 adoption, replay, drift rejection, CAS restore and empty cleanup; record evidence without upgrading CDN status.

**Acceptance Criteria:**
- Given a valid storage secret and absent CDN secret, when `fsck --target cf|cos` runs, then its provider protocol path succeeds without constructing a CDN SDK client.
- Given a stable matching R2 inventory, when adoption runs twice, then the first commits complete coverage and the second is byte-idempotent.
- Given run-owned remote bytes drift, when adoption reruns, then it fails before canonical mutation; exact restore returns the next run to clean.
- Given the test exits, when R2 is independently listed, then the pinned bucket is empty and no Cloudflare control-plane request occurred.

## Spec Change Log

- 2026-07-19: Implemented provider-specific storage-only audit clients, routed `fsck --target`
  through least authority, added capability-separation and real R2 recovery tests, and recorded
  the exact non-production boundary.

## Design Notes

This is capability separation, not a generic cloud abstraction. R2 and COS retain separate concrete types and constructors; only the CLI's read-only audit dispatch is shared.

## Verification

**Commands:**
- `go test ./internal/publish ./internal/cli -run 'ControlHTTP|RemoteAudit|FSCKAdopt' -count=1`.
- `go test -race ./internal/publish ./internal/cli -run 'ControlHTTP|RemoteAudit|FSCKAdopt' -count=1`.
- Exact opt-in `TestRealCloudR2FSCKStorageOnly` command documented in the dated evidence file.
- `go vet ./...`, `staticcheck`, module integrity, clean-delivery policy and two independent clean reconstructions.

**Results:**

- Focused ordinary/race passed; 692 default CLI tests passed in six ordinary and six race
  shards, with no race report; all non-CLI packages passed ordinary/race.
- The real R2 test passed in `29.600s`: adoption, idempotent replay, CAS drift rejection,
  exact restore and identity-bound cleanup all completed with CDN credentials absent.
- Independent `rclone lsf cf:pro --recursive --max-depth -1` returned exit 0 and empty stdout.
- Vet, repository Staticcheck profiles, both module integrity gates, fixed govulncheck,
  four static cross-builds and real apt/YUM/DNF/Nginx compatibility passed.
- Exact clean-delivery identities are recorded outside the delivery root in V-35 after the
  frozen-tree double reconstruction; this spec does not upgrade COS/EdgeOne/CDN status.

## Suggested Review Order

1. `internal/cli/app.go` and `internal/cli/publish_provider.go` for authority selection.
2. `internal/cli/remote_audit.go` and `internal/publish/http_tencent.go` for concrete dispatch.
3. Focused unit/protocol tests, then `test/compat/real_cloud_r2_fsck_test.go` safety gates.
4. The dated evidence, ADR-0016 and V-33/V-35 traceability boundaries.
