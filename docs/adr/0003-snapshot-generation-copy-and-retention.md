# ADR-0003: snapshot generation gate, vendor copy, and inventory-bound retention

Status: accepted for local/protocol implementation; live-cloud PoC remains open.

## Decision

`sow publish --snapshot <suite>-YYYYMMDD` is a distinct, exact publication
intent. The immutable target generation, checkpoint, and COS generation lock
carry both `intent_view=snapshot` and `intent_snapshot=<id>`; beta, latest, and
stable retain their prior canonical JSON because the new field is omitted.

The stable client prefix is
`/pro/v1/{credential}/_sow/v1/snapshots/<id>/`. A mutable
`.sow/snapshots/<id>.json` document selects one immutable generation. The edge
reads and validates this document before routing every Pro request. APT
metadata is served from that generation, while package requests use the shared
public/gated pool. YUM metadata is served from the generation and Packages from
`.sow/gated/snapshots/<id>/yum/...`. Metadata hrefs remain relative, so both
token-in-path and Basic Auth preserve the same repository bytes. Object stores
do not provide a multi-object atomic transaction; the snapshot route document
is therefore the sole strong-consistency entry gate. Existing legacy aliases
remain compatibility paths, not the atomic snapshot contract.

YUM snapshot package bytes use same-bucket server-side copy only after HEAD
proves the source `Content-Length`, provider ETag, and explicit
`sow-sha256`. R2 uses S3 source conditions plus
`cf-copy-destination-if-none-match: *`. Cloudflare documents destination
conditions as **beta** and explicitly says source selection and destination
commit conditions are not mutually atomic. Consequently an unsupported or
ambiguous CopyObject response falls back to a local create-only upload; an
occupied destination is accepted only after a second HEAD proves size and
SHA-256. See the [R2 CopyObject extension](https://developers.cloudflare.com/r2/api/s3/extensions/)
and [R2 S3 compatibility table](https://developers.cloudflare.com/r2/api/s3/api/).

COS uses its native `x-cos-copy-source`,
`x-cos-copy-source-if-match`, `x-cos-metadata-directive: Replaced`, and
`x-cos-forbid-overwrite: true` headers. Tencent documents the source ETag
condition as a 412 gate and documents `x-cos-forbid-overwrite` for
PutObject-Copy, but also states that forbid-overwrite is ineffective when
bucket versioning is enabled. SOW therefore retains the existing mandatory
unversioned-bucket probe. See Tencent's [copy condition documentation](https://cloud.tencent.com/document/product/436/64995),
[PutObject-Copy condition-key example](https://cloud.tencent.com/document/product/436/71307),
and [forbid-overwrite semantics](https://cloud.tencent.com/document/product/436/7749).
COS HTTP 200 responses are parsed as XML and an embedded `Error` document is a
failure, never a successful copy.

APT shared pool entries use HEAD-and-reuse. Matching remote size/SHA skips PUT;
missing entries use the ordinary create-only upload. Snapshot metadata is
always uploaded normally.

Natural-month retention deletes only `.sow/snapshots/<id>.json` and objects
below `.sow/gated/snapshots/<id>/`. A deletion plan can be formed only from a
canonical `inventory.tsv` whose coverage is `complete`. Every deletion is part
of the publish plan and durable journal, is replay-safe, and an exposed route
is purged before checkpoint commit. The plan binds each routed deletion to an
exact `VerifyAbsent` URL: storage HEAD must report absence and the CDN must
return 404 or 410. A stale 2xx, any 3xx (including a same-origin redirect to a
404), authentication failure, or service failure cannot prove deletion. Crash
replay repeats delete/purge safely and rechecks both negative conditions. A
zero-object deletion-only plan additionally carries one prior same-intent
positive CDN probe that is not itself being deleted, so L3 never passes with
an empty check set. Generations, shared pools, channels,
checkpoint/control objects, immutable refs, Git history, and CAS bytes are
never retention-delete candidates. Publishing an old immutable snapshot adds
its exact ref back to the active target vector and reconstructs its route/tree.

Intent-scoped historical plans remain immutable evidence after that restore.
Post-hoc L2/L3 suppresses an old snapshot negative only when the current
target-global committed generation has the snapshot ref and the canonical
sorted `inventory.tsv` contains the exact recreated route/payload key. A
partially rebuilt tree, another retired snapshot, and the current target-global
plan remain fully checked. Missing, malformed, or unsorted inventory fails
closed; inventory membership is streamed with memory bounded by the historical
delete change-set.

## Evidence and remaining gate

Protocol-level HTTP tests exercise the exact R2/COS headers and SigV4 signed
header set, no-retransmit copy, missing-source fallback, ambiguous-response
fallback, independent target sagas, and replay. Shared Worker/EdgeOne contract
tests exercise APT/YUM snapshot routing and credential stripping. These are
local protocol fakes, not a claim of production-cloud validation.

Before marking the cloud PoC complete, run the same fixtures against one real
R2 bucket and one never-versioned COS bucket, confirm destination precondition
behavior and response XML, interrupt after remote copy/delete/purge, replay,
and verify through the configured Cloudflare/EdgeOne host. Until then the R2
beta behavior and COS account/bucket policy remain explicit release gates.
