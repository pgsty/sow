package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

type targetDriver interface {
	preflight(ctx context.Context, plan Plan) error
	acquire(ctx context.Context, request Request, generationSHA string, lockedBody, finalBody []byte) (lockToken string, alreadyCommitted bool, err error)
	getControl(ctx context.Context, key string) (ControlObject, error)
	head(ctx context.Context, key string) (ObjectInfo, error)
	openObject(ctx context.Context, key string) (ObjectContent, error)
	putImmutable(ctx context.Context, key string, body io.Reader, size int64, sha256 string) error
	copyImmutable(ctx context.Context, destinationKey, sourceKey string, size int64, sha256 string) (bool, error)
	hasImmutable(ctx context.Context, key string, size int64, sha256 string) (bool, error)
	requireAdoptedImmutable(ctx context.Context, key string, size int64, sha256 string) error
	putMutable(ctx context.Context, key string, body io.Reader, size int64, sha256 string) error
	delete(ctx context.Context, key, ifMatch string) error
	verifyDeleteFence(ctx context.Context, lockToken string) error
	deleteCheckpointFenced(ctx context.Context, key string) error
	purge(ctx context.Context, urls []string) error
	openCDN(ctx context.Context, url string) (io.ReadCloser, error)
	commit(ctx context.Context, request Request, lockToken string, finalBody []byte) (checkpointETag string, err error)
}

type r2Driver struct{ provider R2CloudflareProvider }

func (d r2Driver) preflight(ctx context.Context, plan Plan) error {
	if d.provider == nil {
		return errors.New("nil R2/Cloudflare provider")
	}
	return d.provider.CloudflarePreflight(ctx, plan)
}

func (d r2Driver) getControl(ctx context.Context, key string) (ControlObject, error) {
	return d.provider.R2GetControl(ctx, key)
}

func (d r2Driver) head(ctx context.Context, key string) (ObjectInfo, error) {
	return d.provider.R2Head(ctx, key)
}

func (d r2Driver) openObject(ctx context.Context, key string) (ObjectContent, error) {
	return d.provider.R2OpenObject(ctx, key)
}

func (d r2Driver) acquire(ctx context.Context, request Request, _ string, lockedBody, finalBody []byte) (string, bool, error) {
	if d.provider == nil {
		return "", false, errors.New("nil R2/Cloudflare provider")
	}
	observed, err := d.provider.R2GetControl(ctx, CheckpointKey)
	if err != nil {
		return "", false, fmt.Errorf("read R2 checkpoint: %w", err)
	}
	if observed.Exists && bytes.Equal(observed.Body, finalBody) {
		return observed.ETag, true, nil
	}
	if observed.Exists && bytes.Equal(observed.Body, lockedBody) {
		if observed.ETag == "" {
			return "", false, fmt.Errorf("%w: locked R2 checkpoint has no ETag", ErrCapability)
		}
		return observed.ETag, false, nil
	}
	if err := matchParent(observed, request.Expected, true, TargetCloudflare); err != nil {
		return "", false, err
	}
	condition := R2PutCondition{}
	if observed.Exists {
		condition.IfMatch = observed.ETag
	} else {
		condition.IfNoneMatch = true
	}
	etag, err := d.provider.R2Put(ctx, CheckpointKey, bytes.NewReader(lockedBody), int64(len(lockedBody)), digestBytes(lockedBody), condition)
	if err != nil {
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrAlreadyExists) {
			return "", false, fmt.Errorf("%w: acquire R2 checkpoint lock", ErrConflict)
		}
		return "", false, err
	}
	if etag == "" {
		return "", false, fmt.Errorf("%w: R2 conditional write returned no ETag", ErrCapability)
	}
	return etag, false, nil
}

func (d r2Driver) putImmutable(ctx context.Context, key string, body io.Reader, size int64, sha string) error {
	_, err := d.provider.R2Put(ctx, key, body, size, sha, R2PutCondition{IfNoneMatch: true})
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrAlreadyExists) && !errors.Is(err, ErrConflict) {
		return err
	}
	if _, drainErr := io.Copy(io.Discard, body); drainErr != nil {
		return drainErr
	}
	info, headErr := d.provider.R2Head(ctx, key)
	if headErr != nil {
		return headErr
	}
	if err := verifyImmutableBody(ctx, key, size, sha, true, info, d.provider.R2OpenObject); err != nil {
		return fmt.Errorf("%w: immutable R2 key %s contains different bytes: %v", ErrConflict, key, err)
	}
	return nil
}

func (d r2Driver) putMutable(ctx context.Context, key string, body io.Reader, size int64, sha string) error {
	_, err := d.provider.R2Put(ctx, key, body, size, sha, R2PutCondition{})
	return err
}

func (d r2Driver) copyImmutable(ctx context.Context, destinationKey, sourceKey string, size int64, sha string) (bool, error) {
	provider, ok := d.provider.(R2CopyDeleteProvider)
	if !ok {
		return false, nil
	}
	source, err := d.provider.R2Head(ctx, sourceKey)
	if err != nil {
		return false, err
	}
	if !source.Exists || source.Size != size || source.SHA256 != sha || source.ETag == "" {
		return false, nil
	}
	// Authenticate the source body once, then bind CopyObject to the exact ETag
	// just verified. This avoids both the forged-metadata poison window and the
	// former source+destination double download. Existing/ambiguous destination
	// conflicts are still streamed below because no successful copy response
	// binds them to this invocation.
	if err := verifyImmutableBody(ctx, sourceKey, size, sha, true, source, d.provider.R2OpenObject); err != nil {
		return false, nil
	}
	copyETag, err := provider.R2Copy(ctx, destinationKey, sourceKey, size, sha, source.ETag)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrCapability) {
		return false, nil
	}
	if errors.Is(err, ErrAlreadyExists) || errors.Is(err, ErrConflict) {
		destination, headErr := d.provider.R2Head(ctx, destinationKey)
		if headErr != nil {
			return false, headErr
		}
		if destination.Exists && destination.Size == size && destination.SHA256 == sha {
			if err := verifyImmutableBody(ctx, destinationKey, size, sha, true, destination, d.provider.R2OpenObject); err != nil {
				return false, fmt.Errorf("%w: immutable R2 copy destination %s contains different bytes: %v", ErrConflict, destinationKey, err)
			}
			return true, nil
		}
		if !destination.Exists {
			return false, nil
		}
		return false, fmt.Errorf("%w: immutable R2 copy destination %s contains different bytes", ErrConflict, destinationKey)
	}
	if err != nil {
		return false, err
	}
	destination, err := d.provider.R2Head(ctx, destinationKey)
	if err != nil || !destination.Exists || destination.Size != size || destination.SHA256 != sha || copyETag == "" || destination.ETag != copyETag {
		return false, errors.Join(err, fmt.Errorf("%w: R2 copy destination %s failed identity read-back", ErrDrift, destinationKey))
	}
	return true, nil
}

func (d r2Driver) hasImmutable(ctx context.Context, key string, size int64, sha string) (bool, error) {
	info, err := d.provider.R2Head(ctx, key)
	if err != nil || !info.Exists {
		return false, err
	}
	if info.Size != size || info.SHA256 != sha {
		return false, fmt.Errorf("%w: reusable R2 key %s contains different bytes", ErrConflict, key)
	}
	if err := verifyImmutableBody(ctx, key, size, sha, true, info, d.provider.R2OpenObject); err != nil {
		return false, fmt.Errorf("%w: reusable R2 key %s contains different bytes: %v", ErrConflict, key, err)
	}
	return true, nil
}

func (d r2Driver) requireAdoptedImmutable(ctx context.Context, key string, size int64, sha string) error {
	return verifyAdoptedImmutable(ctx, key, size, sha, d.provider.R2Head, d.provider.R2OpenObject)
}

func (d r2Driver) delete(ctx context.Context, key, ifMatch string) error {
	provider, ok := d.provider.(R2CopyDeleteProvider)
	if !ok {
		return fmt.Errorf("%w: R2 provider does not implement safe deletion", ErrCapability)
	}
	if ifMatch == "" {
		return fmt.Errorf("%w: R2 conditional deletion requires an ETag", ErrCapability)
	}
	return provider.R2Delete(ctx, key, ifMatch)
}

func (d r2Driver) deleteCheckpointFenced(ctx context.Context, key string) error {
	provider, ok := d.provider.(R2CheckpointFencedDeleteProvider)
	if !ok {
		return fmt.Errorf("%w: R2 provider does not expose checkpoint-fenced deletion", ErrCapability)
	}
	return provider.R2DeleteCheckpointFenced(ctx, key)
}

func (d r2Driver) verifyDeleteFence(ctx context.Context, lockToken string) error {
	if lockToken == "" {
		return fmt.Errorf("%w: R2 checkpoint-fenced deletion requires the acquired checkpoint ETag", ErrCapability)
	}
	checkpoint, err := d.provider.R2GetControl(ctx, CheckpointKey)
	if err != nil {
		return err
	}
	if !checkpoint.Exists || checkpoint.ETag != lockToken {
		return fmt.Errorf("%w: R2 checkpoint changed", ErrConflict)
	}
	return nil
}

func (d r2Driver) purge(ctx context.Context, urls []string) error {
	return d.provider.CloudflarePurge(ctx, append([]string(nil), urls...))
}

func (d r2Driver) openCDN(ctx context.Context, url string) (io.ReadCloser, error) {
	return d.provider.CloudflareOpen(ctx, url)
}

func (d r2Driver) commit(ctx context.Context, _ Request, lockToken string, finalBody []byte) (string, error) {
	etag, err := d.provider.R2Put(ctx, CheckpointKey, bytes.NewReader(finalBody), int64(len(finalBody)), digestBytes(finalBody), R2PutCondition{IfMatch: lockToken})
	if err != nil {
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrAlreadyExists) {
			return "", fmt.Errorf("%w: commit R2 checkpoint", ErrConflict)
		}
		return "", err
	}
	if etag == "" {
		return "", fmt.Errorf("%w: committed R2 checkpoint has no ETag", ErrCapability)
	}
	observed, err := d.provider.R2GetControl(ctx, CheckpointKey)
	if err != nil {
		return "", err
	}
	if !observed.Exists || !bytes.Equal(observed.Body, finalBody) || observed.ETag != etag {
		return "", fmt.Errorf("%w: R2 checkpoint read-after-write mismatch", ErrDrift)
	}
	return etag, nil
}

type cosDriver struct{ provider COSEdgeOneProvider }

func (d cosDriver) preflight(ctx context.Context, plan Plan) error {
	if d.provider == nil {
		return errors.New("nil COS/EdgeOne provider")
	}
	return d.provider.EdgeOnePreflight(ctx, plan)
}

func (d cosDriver) getControl(ctx context.Context, key string) (ControlObject, error) {
	return d.provider.COSGetControl(ctx, key)
}

func (d cosDriver) head(ctx context.Context, key string) (ObjectInfo, error) {
	return d.provider.COSHead(ctx, key)
}

func (d cosDriver) openObject(ctx context.Context, key string) (ObjectContent, error) {
	return d.provider.COSOpenObject(ctx, key)
}

func (d cosDriver) acquire(ctx context.Context, request Request, generationSHA string, _ []byte, finalBody []byte) (string, bool, error) {
	if d.provider == nil {
		return "", false, errors.New("nil COS/EdgeOne provider")
	}
	if err := d.provider.COSProbeUnversioned(ctx); err != nil {
		return "", false, fmt.Errorf("probe COS create-only lock capability: %w", err)
	}
	observed, err := d.provider.COSGetControl(ctx, CheckpointKey)
	if err != nil {
		return "", false, fmt.Errorf("read COS checkpoint: %w", err)
	}
	if observed.Exists && bytes.Equal(observed.Body, finalBody) {
		return observed.ETag, true, nil
	}
	if err := matchParent(observed, request.Expected, false, TargetTencent); err != nil {
		return "", false, err
	}
	lock := GenerationLock{
		Schema: GenerationLockSchema, Target: TargetTencent,
		Generation: request.Generation.Generation, ParentGeneration: request.Generation.ParentGeneration,
		ParentCheckpointSHA256: request.Expected.CheckpointSHA256,
		GenerationSHA256:       generationSHA, TransactionID: request.TransactionID,
		IntentView: request.Generation.IntentView, IntentSnapshot: request.Generation.IntentSnapshot,
		UpdatedAt: request.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	lockBody, err := lock.Canonical()
	if err != nil {
		return "", false, err
	}
	lockKey, _ := GenerationLockKey(request.Generation.Generation)
	etag, err := d.provider.COSCreate(ctx, lockKey, bytes.NewReader(lockBody), int64(len(lockBody)), digestBytes(lockBody))
	if err == nil {
		if etag == "" {
			return "", false, fmt.Errorf("%w: COS create-only lock returned no ETag", ErrCapability)
		}
		return lockKey + "@" + etag, false, nil
	}
	if !errors.Is(err, ErrAlreadyExists) && !errors.Is(err, ErrConflict) {
		return "", false, err
	}
	existing, getErr := d.provider.COSGetControl(ctx, lockKey)
	if getErr != nil {
		return "", false, getErr
	}
	if !existing.Exists || !bytes.Equal(existing.Body, lockBody) || existing.ETag == "" {
		return "", false, fmt.Errorf("%w: COS generation %d is locked by another transaction", ErrConflict, request.Generation.Generation)
	}
	return lockKey + "@" + existing.ETag, false, nil
}

func (d cosDriver) putImmutable(ctx context.Context, key string, body io.Reader, size int64, sha string) error {
	_, err := d.provider.COSCreate(ctx, key, body, size, sha)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrAlreadyExists) && !errors.Is(err, ErrConflict) {
		return err
	}
	if _, drainErr := io.Copy(io.Discard, body); drainErr != nil {
		return drainErr
	}
	info, headErr := d.provider.COSHead(ctx, key)
	if headErr != nil {
		return headErr
	}
	if err := verifyImmutableBody(ctx, key, size, sha, true, info, d.provider.COSOpenObject); err != nil {
		return fmt.Errorf("%w: immutable COS key %s contains different bytes: %v", ErrConflict, key, err)
	}
	return nil
}

func (d cosDriver) putMutable(ctx context.Context, key string, body io.Reader, size int64, sha string) error {
	_, err := d.provider.COSPut(ctx, key, body, size, sha)
	return err
}

func (d cosDriver) copyImmutable(ctx context.Context, destinationKey, sourceKey string, size int64, sha string) (bool, error) {
	provider, ok := d.provider.(COSCopyDeleteProvider)
	if !ok {
		return false, nil
	}
	source, err := d.provider.COSHead(ctx, sourceKey)
	if err != nil {
		return false, err
	}
	if !source.Exists || source.Size != size || source.SHA256 != sha || source.ETag == "" {
		return false, nil
	}
	if err := verifyImmutableBody(ctx, sourceKey, size, sha, true, source, d.provider.COSOpenObject); err != nil {
		return false, nil
	}
	copyETag, err := provider.COSCopy(ctx, destinationKey, sourceKey, size, sha, source.ETag)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrCapability) {
		return false, nil
	}
	if errors.Is(err, ErrAlreadyExists) || errors.Is(err, ErrConflict) {
		destination, headErr := d.provider.COSHead(ctx, destinationKey)
		if headErr != nil {
			return false, headErr
		}
		if destination.Exists && destination.Size == size && destination.SHA256 == sha {
			if err := verifyImmutableBody(ctx, destinationKey, size, sha, true, destination, d.provider.COSOpenObject); err != nil {
				return false, fmt.Errorf("%w: immutable COS copy destination %s contains different bytes: %v", ErrConflict, destinationKey, err)
			}
			return true, nil
		}
		if !destination.Exists {
			return false, nil
		}
		return false, fmt.Errorf("%w: immutable COS copy destination %s contains different bytes", ErrConflict, destinationKey)
	}
	if err != nil {
		return false, err
	}
	destination, err := d.provider.COSHead(ctx, destinationKey)
	if err != nil || !destination.Exists || destination.Size != size || destination.SHA256 != sha || copyETag == "" || destination.ETag != copyETag {
		return false, errors.Join(err, fmt.Errorf("%w: COS copy destination %s failed identity read-back", ErrDrift, destinationKey))
	}
	return true, nil
}

func (d cosDriver) hasImmutable(ctx context.Context, key string, size int64, sha string) (bool, error) {
	info, err := d.provider.COSHead(ctx, key)
	if err != nil || !info.Exists {
		return false, err
	}
	if info.Size != size || info.SHA256 != sha {
		return false, fmt.Errorf("%w: reusable COS key %s contains different bytes", ErrConflict, key)
	}
	if err := verifyImmutableBody(ctx, key, size, sha, true, info, d.provider.COSOpenObject); err != nil {
		return false, fmt.Errorf("%w: reusable COS key %s contains different bytes: %v", ErrConflict, key, err)
	}
	return true, nil
}

func (d cosDriver) requireAdoptedImmutable(ctx context.Context, key string, size int64, sha string) error {
	return verifyAdoptedImmutable(ctx, key, size, sha, d.provider.COSHead, d.provider.COSOpenObject)
}

func verifyAdoptedImmutable(
	ctx context.Context,
	key string,
	size int64,
	sha string,
	head func(context.Context, string) (ObjectInfo, error),
	open func(context.Context, string) (ObjectContent, error),
) error {
	info, err := head(ctx, key)
	if err != nil {
		return fmt.Errorf("verify adopted immutable %s HEAD: %w", key, err)
	}
	if err := verifyImmutableBody(ctx, key, size, sha, false, info, open); err != nil {
		return fmt.Errorf("%w: adopted immutable %s is missing or changed", ErrDrift, key)
	}
	return nil
}

func verifyImmutableBody(
	ctx context.Context,
	key string,
	size int64,
	sha string,
	requireMetadata bool,
	info ObjectInfo,
	open func(context.Context, string) (ObjectContent, error),
) error {
	if !info.Exists || info.Size != size || info.ETag == "" ||
		requireMetadata && info.SHA256 != sha || !requireMetadata && info.SHA256 != "" && info.SHA256 != sha {
		return fmt.Errorf("%w: immutable %s is missing or its HEAD identity changed", ErrDrift, key)
	}
	content, err := open(ctx, key)
	if err != nil {
		return fmt.Errorf("%w: open immutable %s: %v", ErrDrift, key, err)
	}
	if content.Body == nil {
		return fmt.Errorf("%w: immutable %s returned no body", ErrCapability, key)
	}
	limit := size
	if limit != math.MaxInt64 {
		limit++
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, io.LimitReader(content.Body, limit))
	closeErr := content.Body.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	if !content.Info.Exists || content.Info.Size != size || content.Info.ETag == "" || content.Info.ETag != info.ETag ||
		requireMetadata && content.Info.SHA256 != sha || !requireMetadata && content.Info.SHA256 != "" && content.Info.SHA256 != sha ||
		written != size || hex.EncodeToString(hasher.Sum(nil)) != sha {
		return fmt.Errorf("%w: immutable %s changed between HEAD and streamed GET", ErrDrift, key)
	}
	return nil
}

func (d cosDriver) delete(ctx context.Context, key, ifMatch string) error {
	provider, ok := d.provider.(COSCopyDeleteProvider)
	if !ok {
		return fmt.Errorf("%w: COS provider does not implement safe deletion", ErrCapability)
	}
	if ifMatch == "" {
		return fmt.Errorf("%w: COS conditional deletion requires an ETag", ErrCapability)
	}
	return provider.COSDelete(ctx, key, ifMatch)
}

func (d cosDriver) deleteCheckpointFenced(ctx context.Context, key string) error {
	provider, ok := d.provider.(COSCheckpointFencedDeleteProvider)
	if !ok {
		return fmt.Errorf("%w: COS provider does not expose checkpoint-fenced deletion", ErrCapability)
	}
	return provider.COSDeleteCheckpointFenced(ctx, key)
}

func (d cosDriver) verifyDeleteFence(ctx context.Context, lockToken string) error {
	separator := strings.LastIndexByte(lockToken, '@')
	if separator <= 0 || separator == len(lockToken)-1 {
		return fmt.Errorf("%w: COS checkpoint-fenced deletion requires the acquired generation-lock token", ErrCapability)
	}
	lockKey, lockETag := lockToken[:separator], lockToken[separator+1:]
	if !strings.HasPrefix(lockKey, ".sow/locks/") {
		return fmt.Errorf("%w: COS checkpoint-fenced deletion received an invalid generation-lock token", ErrCapability)
	}
	lock, err := d.provider.COSGetControl(ctx, lockKey)
	if err != nil {
		return err
	}
	if !lock.Exists || lock.ETag != lockETag {
		return fmt.Errorf("%w: COS generation lock changed", ErrConflict)
	}
	return nil
}

func (d cosDriver) purge(ctx context.Context, urls []string) error {
	return d.provider.EdgeOnePurge(ctx, append([]string(nil), urls...))
}

func (d cosDriver) openCDN(ctx context.Context, url string) (io.ReadCloser, error) {
	return d.provider.EdgeOneOpen(ctx, url)
}

func (d cosDriver) commit(ctx context.Context, request Request, _ string, finalBody []byte) (string, error) {
	// COS does not support the R2 checkpoint If-Match contract. Re-read the
	// parent under the create-only generation lock, fail closed on drift, write
	// the pointer normally, then require an exact read-after-write match.
	observed, err := d.provider.COSGetControl(ctx, CheckpointKey)
	if err != nil {
		return "", err
	}
	if observed.Exists && bytes.Equal(observed.Body, finalBody) {
		return observed.ETag, nil
	}
	if err := matchParent(observed, request.Expected, false, TargetTencent); err != nil {
		return "", err
	}
	etag, err := d.provider.COSPut(ctx, CheckpointKey, bytes.NewReader(finalBody), int64(len(finalBody)), digestBytes(finalBody))
	if err != nil {
		return "", err
	}
	if etag == "" {
		return "", fmt.Errorf("%w: COS checkpoint write returned no ETag", ErrCapability)
	}
	readBack, err := d.provider.COSGetControl(ctx, CheckpointKey)
	if err != nil {
		return "", err
	}
	if !readBack.Exists || !bytes.Equal(readBack.Body, finalBody) || readBack.ETag != etag {
		return "", fmt.Errorf("%w: COS checkpoint read-after-write mismatch", ErrDrift)
	}
	return etag, nil
}

func matchParent(observed ControlObject, expected ParentExpectation, requireETag bool, target TargetName) error {
	if observed.Exists != expected.Exists {
		return fmt.Errorf("%w: checkpoint existence differs from local remote ref", ErrDrift)
	}
	if !observed.Exists {
		return nil
	}
	checkpoint, err := DecodeCheckpoint(observed.Body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDrift, err)
	}
	if checkpoint.Generation != expected.Generation {
		return fmt.Errorf("%w: remote generation=%d, expected=%d", ErrDrift, checkpoint.Generation, expected.Generation)
	}
	if checkpoint.Target != target || checkpoint.Phase != PhaseCheckpointCommitted {
		return fmt.Errorf("%w: remote checkpoint target or phase is not a committed %s generation", ErrDrift, target)
	}
	digest := digestBytes(observed.Body)
	if digest != expected.CheckpointSHA256 {
		return fmt.Errorf("%w: remote checkpoint digest=%s, expected=%s", ErrDrift, digest, expected.CheckpointSHA256)
	}
	if requireETag && (observed.ETag == "" || observed.ETag != expected.ETag) {
		return fmt.Errorf("%w: remote checkpoint ETag changed", ErrDrift)
	}
	return nil
}
