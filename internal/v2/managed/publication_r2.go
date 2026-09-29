package managed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/r2"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"golang.org/x/sys/unix"
)

const maxR2CredentialBytes = 64 << 10

const (
	r2ImmutableCacheControl = "public, max-age=31536000, immutable"
	r2PointerCacheControl   = "no-cache, must-revalidate"
)

type r2CredentialDocument struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

type r2PublicationObjectClient interface {
	ListObjectsV2Prefix(context.Context, string, string) (r2.ObjectListPage, error)
	Head(context.Context, string) (r2.ObjectInfo, error)
	OpenObject(context.Context, string) (r2.ObjectContent, error)
	Put(context.Context, string, r2.ReadSeekReaderAt, int64, string, r2.PutCondition) (string, error)
}

type managedContextReadSeekAt struct {
	ctx    context.Context
	source r2.ReadSeekReaderAt
}

func (r *managedContextReadSeekAt) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(buffer)
}

func (r *managedContextReadSeekAt) ReadAt(buffer []byte, offset int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.ReadAt(buffer, offset)
}

func (r *managedContextReadSeekAt) Seek(offset int64, whence int) (int64, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Seek(offset, whence)
}

type r2PublicationBackend struct {
	objects               r2PublicationObjectClient
	prefix                string
	publicBase            *url.URL
	publicClient          *http.Client
	maxCacheTTL           time.Duration
	transientRetryWindow  time.Duration
	publicReadIdleTimeout time.Duration
	verificationSleep     func(context.Context, time.Duration) error
	verificationNow       func() time.Time
}

func newR2PublicationBackend(target config.TargetConfig) (*r2PublicationBackend, error) {
	credentials, err := resolveR2Credentials(target.Credential, target.Region)
	if err != nil {
		return nil, err
	}
	// The storage-only client accepts a bucket-root URL. TargetConfig deliberately
	// stores the canonical account endpoint and bucket separately, so use path
	// style here; no public control key is created by this adapter.
	objectBase := strings.TrimSuffix(target.Endpoint, "/") + "/" + target.Bucket
	client, err := r2.NewClient(r2.Config{
		Bucket: target.Bucket, ObjectBaseURL: objectBase, Credentials: credentials,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: initialize R2 storage transport: %v", ErrRejected, err)
	}
	publicBase, err := url.Parse(target.PublicEndpoint)
	if err != nil || publicBase.Scheme != "https" && publicBase.Scheme != "http" {
		return nil, fmt.Errorf("%w: R2 public endpoint must be HTTP(S)", ErrRejected)
	}
	maxCacheTTL := time.Duration(0)
	if target.MaxCacheTTL != "" {
		maxCacheTTL, err = time.ParseDuration(target.MaxCacheTTL)
		if err != nil || maxCacheTTL < 0 {
			return nil, fmt.Errorf("%w: invalid R2 public cache TTL", ErrRejected)
		}
	}
	return &r2PublicationBackend{
		objects: client, prefix: target.Prefix, publicBase: publicBase,
		publicClient: newPublicVerificationClient(), maxCacheTTL: maxCacheTTL,
		transientRetryWindow: publicTransientWindow, publicReadIdleTimeout: publicResponseTimeout,
	}, nil
}

func resolveR2Credentials(reference, region string) (r2.S3Credentials, error) {
	var body []byte
	var err error
	switch {
	case strings.HasPrefix(reference, "env://"):
		name := strings.TrimPrefix(reference, "env://")
		value, ok := os.LookupEnv(name)
		if !ok || value == "" {
			return r2.S3Credentials{}, fmt.Errorf("%w: R2 credential environment reference is unset", ErrNotReady)
		}
		if len(value) > maxR2CredentialBytes {
			return r2.S3Credentials{}, fmt.Errorf("%w: R2 credential document exceeds safety limit", ErrRejected)
		}
		body = []byte(value)
	case strings.HasPrefix(reference, "file://"):
		filename := strings.TrimPrefix(reference, "file://")
		// O_NONBLOCK keeps a FIFO or device from blocking open while the
		// Repository lock is held. Symlinks, such as mounted secrets, still work.
		fd, openErr := unix.Open(filename, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return r2.S3Credentials{}, fmt.Errorf("%w: open R2 credential reference: %v", ErrNotReady, openErr)
		}
		file := os.NewFile(uintptr(fd), filename)
		if info, statErr := file.Stat(); statErr != nil || !info.Mode().IsRegular() {
			return r2.S3Credentials{}, errors.Join(fmt.Errorf("%w: R2 credential reference is not a regular file", ErrRejected), statErr, file.Close())
		}
		body, err = io.ReadAll(io.LimitReader(file, maxR2CredentialBytes+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return r2.S3Credentials{}, errors.Join(fmt.Errorf("%w: read R2 credential reference", ErrNotReady), err, closeErr)
		}
		if len(body) > maxR2CredentialBytes {
			return r2.S3Credentials{}, fmt.Errorf("%w: R2 credential document exceeds safety limit", ErrRejected)
		}
	default:
		return r2.S3Credentials{}, fmt.Errorf("%w: unsupported R2 credential reference", ErrRejected)
	}
	var document r2CredentialDocument
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return r2.S3Credentials{}, fmt.Errorf("%w: decode R2 credential document", ErrRejected)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return r2.S3Credentials{}, fmt.Errorf("%w: R2 credential document has trailing data", ErrRejected)
	}
	return r2.S3Credentials{
		AccessKeyID: document.AccessKeyID, SecretAccessKey: document.SecretAccessKey,
		SessionToken: document.SessionToken, Region: region,
	}, nil
}

func (b *r2PublicationBackend) Provider() string { return "r2" }

func (b *r2PublicationBackend) objectKey(objectPath string) (string, error) {
	if publicFilePhase(objectPath) == "" || !strings.HasPrefix(objectPath, "pool/") && !strings.HasPrefix(objectPath, "dists/") {
		return "", fmt.Errorf("%w: invalid R2 publication path %q", ErrRejected, objectPath)
	}
	if b.prefix == "" {
		return objectPath, nil
	}
	return b.prefix + "/" + objectPath, nil
}

func (b *r2PublicationBackend) relativeKey(key string) (string, error) {
	if b.prefix != "" {
		prefix := b.prefix + "/"
		if !strings.HasPrefix(key, prefix) {
			return "", fmt.Errorf("%w: R2 list escaped configured prefix", ErrIntegrity)
		}
		key = strings.TrimPrefix(key, prefix)
	}
	if _, err := b.objectKey(key); err != nil {
		return "", fmt.Errorf("%w: R2 target contains foreign object %q", ErrIntegrity, key)
	}
	return key, nil
}

func (b *r2PublicationBackend) List(ctx context.Context, _ map[string]struct{}) ([]publicationRemoteObject, error) {
	listPrefix := ""
	if b.prefix != "" {
		listPrefix = b.prefix + "/"
	}
	objects := []publicationRemoteObject{}
	continuation := ""
	seenTokens := map[string]struct{}{}
	previousKey := ""
	for {
		page, err := b.objects.ListObjectsV2Prefix(ctx, listPrefix, continuation)
		if err != nil {
			return nil, err
		}
		for _, listed := range page.Objects {
			if previousKey != "" && listed.Key <= previousKey {
				return nil, fmt.Errorf("%w: R2 inventory is not globally key-sorted", ErrIntegrity)
			}
			previousKey = listed.Key
			relative, err := b.relativeKey(listed.Key)
			if err != nil {
				return nil, err
			}
			info, err := b.objects.Head(ctx, listed.Key)
			if err != nil || !info.Exists || info.Size != listed.Size || info.ETag == "" || info.ETag != listed.ETag || !lowercaseSHA256.MatchString(info.SHA256) {
				return nil, errors.Join(fmt.Errorf("%w: R2 listed object %q lacks exact HEAD evidence", ErrIntegrity, relative), err)
			}
			objects = append(objects, publicationRemoteObject{Path: relative, Size: info.Size, SHA256: info.SHA256, RemoteIdentity: info.ETag})
		}
		if page.NextContinuationToken == "" {
			break
		}
		if _, duplicate := seenTokens[page.NextContinuationToken]; duplicate {
			return nil, fmt.Errorf("%w: R2 listing repeated a continuation token", ErrIntegrity)
		}
		seenTokens[page.NextContinuationToken] = struct{}{}
		continuation = page.NextContinuationToken
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Path < objects[j].Path })
	return objects, nil
}

func (b *r2PublicationBackend) Head(ctx context.Context, objectPath string) (publicationRemoteObject, bool, error) {
	key, err := b.objectKey(objectPath)
	if err != nil {
		return publicationRemoteObject{}, false, err
	}
	info, err := b.objects.Head(ctx, key)
	if err != nil {
		return publicationRemoteObject{}, false, err
	}
	if !info.Exists {
		return publicationRemoteObject{}, false, nil
	}
	if info.Size < 0 || !lowercaseSHA256.MatchString(info.SHA256) || info.ETag == "" || len(info.ETag) > 4096 || strings.ContainsAny(info.ETag, "\x00\r\n") {
		return publicationRemoteObject{}, false, fmt.Errorf("%w: R2 object %q lacks bounded identity metadata", ErrIntegrity, objectPath)
	}
	return publicationRemoteObject{Path: objectPath, Size: info.Size, SHA256: info.SHA256, RemoteIdentity: info.ETag}, true, nil
}

func (b *r2PublicationBackend) Put(ctx context.Context, sourceRoot string, operation state.PublicationPlanOperation, _ string) (string, error) {
	if operation.Operation != "add" && operation.Operation != "update" || operation.Size < 0 || !lowercaseSHA256.MatchString(operation.SHA256) {
		return "", fmt.Errorf("%w: invalid R2 publication write", ErrRejected)
	}
	key, err := b.objectKey(operation.Path)
	if err != nil {
		return "", err
	}
	current, exists, err := b.Head(ctx, operation.Path)
	if err != nil {
		return "", err
	}
	if exists && current.Size == operation.Size && current.SHA256 == operation.SHA256 {
		return current.RemoteIdentity, nil
	}
	if strings.HasPrefix(operation.Path, "pool/") && operation.Operation == "update" {
		return "", fmt.Errorf("%w: immutable payload %q cannot be overwritten", ErrRejected, operation.Path)
	}
	condition := r2.PutCondition{CacheControl: r2ImmutableCacheControl}
	if mutableR2PublicationPath(operation) {
		condition.CacheControl = r2PointerCacheControl
	}
	if operation.Operation == "add" {
		if exists {
			return "", fmt.Errorf("%w: create-only R2 object %q already exists with different identity", ErrIntegrity, operation.Path)
		}
		condition.IfNoneMatch = true
	} else {
		if !exists || operation.ExpectedOldSHA256 == "" || current.SHA256 != operation.ExpectedOldSHA256 {
			return "", fmt.Errorf("%w: R2 CAS precondition failed for %q", ErrIntegrity, operation.Path)
		}
		condition.IfMatch = current.RemoteIdentity
	}
	source, err := openRootedRegular(sourceRoot, filepath.FromSlash(operation.Path))
	if err != nil {
		return "", fmt.Errorf("%w: publication source %q is missing or unsafe: %v", ErrIntegrity, operation.Path, err)
	}
	etag, putErr := b.objects.Put(ctx, key, &managedContextReadSeekAt{ctx: ctx, source: source.file}, operation.Size, operation.SHA256, condition)
	closeErr := source.CloseVerified()
	if putErr != nil || closeErr != nil {
		if putErr != nil {
			if installed, ok, headErr := b.Head(ctx, operation.Path); headErr == nil && ok && installed.Size == operation.Size && installed.SHA256 == operation.SHA256 {
				return installed.RemoteIdentity, closeErr
			}
		}
		return "", errors.Join(putErr, closeErr)
	}
	installed, ok, err := b.Head(ctx, operation.Path)
	if err != nil || !ok || installed.Size != operation.Size || installed.SHA256 != operation.SHA256 || installed.RemoteIdentity != etag {
		return "", errors.Join(fmt.Errorf("%w: R2 write did not install exact object %q", ErrIntegrity, operation.Path), err)
	}
	return installed.RemoteIdentity, nil
}

func mutableR2PublicationPath(operation state.PublicationPlanOperation) bool {
	if operation.Phase == "pointer" {
		return true
	}
	return operation.Phase == "metadata" && strings.HasPrefix(operation.Path, "dists/") &&
		!strings.Contains(operation.Path, "/repodata/") && !strings.Contains(operation.Path, "/by-hash/")
}

func (b *r2PublicationBackend) VerifyPublic(ctx context.Context, expected state.GenerationFile) error {
	return (httpPublicationVerifier{
		client: b.publicClient, base: b.publicBase, maxCacheTTL: b.maxCacheTTL,
		transientRetryWindow: b.transientRetryWindow, readIdleTimeout: b.publicReadIdleTimeout,
		sleep: b.verificationSleep, now: b.verificationNow,
	}).Verify(ctx, expected)
}

func (b *r2PublicationBackend) DeleteConditional(context.Context, state.PublicationCandidate) error {
	return fmt.Errorf("%w: R2 physical deletion is disabled", ErrRejected)
}

func (b *r2PublicationBackend) VerifyPublicAbsent(context.Context, string) error {
	return fmt.Errorf("%w: R2 physical deletion is disabled", ErrRejected)
}
