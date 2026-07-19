package publish

import (
	"context"
	"io"
	"strings"
)

func validPurgeEvidenceIdentifier(value string) bool {
	return value != "" && len(value) <= 2048 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

// ObjectInfo is trusted only when both size and the explicit sow-sha256
// metadata match. Provider ETags are never treated as content hashes.
type ObjectInfo struct {
	Exists bool
	Size   int64
	SHA256 string
	ETag   string
}

type ControlObject struct {
	Exists bool
	Body   []byte
	ETag   string
}

// ListedObject is the bounded metadata exposed by S3 ListObjectsV2. Custom
// sow-sha256 metadata is deliberately absent from list responses and must be
// obtained with HEAD before an object's bytes are considered verified.
type ListedObject struct {
	Key  string
	Size int64
	ETag string
}

// ObjectListPage is one provider page. NextContinuationToken is opaque and
// must only be sent back to the same bucket endpoint.
type ObjectListPage struct {
	Objects               []ListedObject
	NextContinuationToken string
}

// ObjectContent is a streamed GET response. Callers must close Body. Info
// describes the same response and is never inferred from the provider ETag.
type ObjectContent struct {
	Info ObjectInfo
	Body io.ReadCloser
}

type R2PutCondition struct {
	IfMatch     string
	IfNoneMatch bool
}

// R2CloudflareProvider is intentionally vendor-specific. There is no public
// generic cloud storage/CDN plugin interface in SOW v1.
type R2CloudflareProvider interface {
	CloudflarePreflight(ctx context.Context, plan Plan) error
	R2GetControl(ctx context.Context, key string) (ControlObject, error)
	R2Head(ctx context.Context, key string) (ObjectInfo, error)
	R2OpenObject(ctx context.Context, key string) (ObjectContent, error)
	R2Put(ctx context.Context, key string, body io.Reader, size int64, sha256 string, condition R2PutCondition) (etag string, err error)
	CloudflarePurge(ctx context.Context, urls []string) error
	CloudflareOpen(ctx context.Context, url string) (io.ReadCloser, error)
}

// CloudflarePurgeEvidenceProvider is an optional, vendor-specific extension
// used by production publishers to retain one provider receipt for every
// exact-URL purge batch.  The legacy CloudflarePurge method remains part of
// the base interface so existing embedders and test fakes keep their source
// compatibility; callers that require durable operational evidence must fail
// closed when this extension is absent.
type CloudflarePurgeEvidenceProvider interface {
	CloudflarePurgeEvidenceZoneID() string
	CloudflarePurgeBatchEvidence(ctx context.Context, urls []string) (PurgeReceipt, error)
}

type R2CopyDeleteProvider interface {
	R2Copy(ctx context.Context, destinationKey, sourceKey string, size int64, sha256, sourceETag string) (etag string, err error)
	// R2Delete must bind the deletion to the exact currently observed entity.
	// Providers that cannot enforce If-Match must return ErrCapability; silently
	// degrading to an unconditional DELETE would let a concurrent foreign writer
	// lose bytes that SOW never authorized for deletion.
	R2Delete(ctx context.Context, key, ifMatch string) error
}

// R2CheckpointFencedDeleteProvider exposes the deliberately unconditional
// DeleteObject primitive used only by Publisher.WithCheckpointFencedDeletion.
// Cloudflare R2 does not document or enforce If-Match on DeleteObject. The
// publisher therefore admits this method only after the operator explicitly
// enables the single-writer policy, the remote checkpoint ETag still matches,
// and two consecutive streamed identity proofs agree.
type R2CheckpointFencedDeleteProvider interface {
	R2DeleteCheckpointFenced(ctx context.Context, key string) error
}

// COSEdgeOneProvider exposes COS's real create-only primitive separately from
// normal overwrite. COSCreate must use x-cos-forbid-overwrite:true on a bucket
// whose versioning has never been enabled; it must not emulate or advertise
// If-Match.
type COSEdgeOneProvider interface {
	EdgeOnePreflight(ctx context.Context, plan Plan) error
	COSProbeUnversioned(ctx context.Context) error
	COSGetControl(ctx context.Context, key string) (ControlObject, error)
	COSHead(ctx context.Context, key string) (ObjectInfo, error)
	COSOpenObject(ctx context.Context, key string) (ObjectContent, error)
	COSCreate(ctx context.Context, key string, body io.Reader, size int64, sha256 string) (etag string, err error)
	COSPut(ctx context.Context, key string, body io.Reader, size int64, sha256 string) (etag string, err error)
	EdgeOnePurge(ctx context.Context, urls []string) error
	EdgeOneOpen(ctx context.Context, url string) (io.ReadCloser, error)
}

// EdgeOnePurgeEvidenceProvider splits asynchronous EdgeOne purge into its two
// durable boundaries.  A publisher persists the accepted JobId before it
// starts polling and can therefore resume that same job after interruption
// instead of creating an untracked replacement task.
type EdgeOnePurgeEvidenceProvider interface {
	EdgeOnePurgeEvidenceZoneID() string
	EdgeOneAcceptPurgeBatch(ctx context.Context, urls []string) (PurgeReceipt, error)
	EdgeOneCompletePurgeBatch(ctx context.Context, accepted PurgeReceipt) (PurgeReceipt, error)
}

type COSCopyDeleteProvider interface {
	COSCopy(ctx context.Context, destinationKey, sourceKey string, size int64, sha256, sourceETag string) (etag string, err error)
	// COSDelete has the same evidence-bound contract as R2Delete. Runtime
	// capability probing additionally proves that the concrete endpoint honors
	// the condition before any live serving object is removed.
	COSDelete(ctx context.Context, key, ifMatch string) error
}

// COSCheckpointFencedDeleteProvider is the COS counterpart of
// R2CheckpointFencedDeleteProvider. It never advertises an unavailable
// conditional-delete guarantee; all safety admission lives in Publisher.
type COSCheckpointFencedDeleteProvider interface {
	COSDeleteCheckpointFenced(ctx context.Context, key string) error
}
