# Pigsty ROOT COS-only asset handoff evidence (2026-07-17)

## Result

Three unambiguous COS-only ROOT assets were copied from the existing Pigsty
repository into disposable files and admitted through the production `sow`
CLI with a digest-bound external-builder assertion. The source repository was
opened read-only by the test; all Git state, CAS objects, refs, materialized
files and Nginx output lived below `/private/tmp`. No cloud API or origin was
contacted.

| Public key | Read-only source | Bytes | SHA-256 |
|---|---|---:|---|
| `/cc` | `bin/get.cc` | 5,893 | `a275f2580dbbb6b21cbe228185093cf962919a085d321d2efbc17657269caca7` |
| `/claude` | `bin/claude` | 9,322 | `5f8f3ac25a9cdf15fcb70fb41d70309fc59dde3f33e7c065f24497e94acfd946` |
| `/ray` | `bin/ray` | 5,560 | `d3ff094e5c7d29db72fb792c6d52379043bacd68f32cf400eb0127cf355087ad` |

`get.cc` is intentionally bound to the distinct COS-only `/cc` key. It is not
selected as the body of the shared `/get` key.

The executable gate ran `init`, three authenticated `add` operations,
`promote beta latest`, working-tree `materialize latest`, exact default-deny
Nginx include rendering, `verify --layer L1`, `fsck`, `gc` dry-run and
idempotent `add` replay. It compared every materialized hardlink body with the
source bytes, first required every source size and SHA-256 to match the pinned
table above, required exactly `cc`, `claude` and `ray` at the repository root
asset path, and reopened each source path after the complete workflow to prove
that its file identity, size, modification time and contents were unchanged.

```text
$ SOW_RUN_PIGSTY_ROOT_COS_HANDOFF=1 \
  SOW_PIGSTY_REPO_ROOT=/Users/vonng/pgsty/repo \
  go test ./test/compat -run '^TestPigstyRootCOSBuilderHandoff$' -count=1 -v
root_cos_handoff files=3 bytes=20775 source_read_only=true cloud=false
PASS (test 4.14s; package 5.196s)

$ SOW_RUN_PIGSTY_ROOT_COS_HANDOFF=1 \
  SOW_PIGSTY_REPO_ROOT=/Users/vonng/pgsty/repo \
  go test -race ./test/compat -run '^TestPigstyRootCOSBuilderHandoff$' -count=1 -v
root_cos_handoff files=3 bytes=20775 source_read_only=true cloud=false
PASS (test 6.48s; package 8.341s)
```

## Boundary

This closes the local exact-copy and admission proof for the COS-only
`/cc`, `/claude` and `/ray` objects. The physical migration config now activates
their dedicated `asset-root-cos` owner with `publish_targets: [cos]`, while the
ledger pins the source-hash handoff and keeps production cutover pending. It
does not choose among the divergent `.io` and `.cc` bodies for the shared
`/get`, `/pig`, `/pkg` or `/beta` keys and does not publish to COS. Provider
mutation, CDN purge and URL verification remain gated by an approved migration
window and dedicated credentials; Cloudflare `pro` and `pro.pigsty.io` were
not used.
