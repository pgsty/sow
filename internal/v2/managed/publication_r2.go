package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	legacyPublish "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

const maxR2CredentialBytes = 64 << 10

type r2CredentialDocument struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

type r2PublicationObjectClient interface {
	R2ListObjectsV2Prefix(context.Context, string, string) (legacyPublish.ObjectListPage, error)
	R2Head(context.Context, string) (legacyPublish.ObjectInfo, error)
	R2OpenObject(context.Context, string) (legacyPublish.ObjectContent, error)
	R2Put(context.Context, string, io.Reader, int64, string, legacyPublish.R2PutCondition) (string, error)
}

type r2PublicationBackend struct {
	objects    r2PublicationObjectClient
	prefix     string
	publicBase *url.URL
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
	client, err := legacyPublish.NewR2CloudflareControlHTTP(legacyPublish.R2CloudflareControlHTTPConfig{
		Bucket: target.Bucket, ObjectBaseURL: objectBase, Credentials: credentials,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: initialize R2 storage transport: %v", ErrRejected, err)
	}
	publicBase, err := url.Parse(target.PublicEndpoint)
	if err != nil || publicBase.Scheme != "https" && publicBase.Scheme != "http" {
		return nil, fmt.Errorf("%w: R2 public endpoint must be HTTP(S)", ErrRejected)
	}
	return &r2PublicationBackend{objects: client, prefix: target.Prefix, publicBase: publicBase}, nil
}

func resolveR2Credentials(reference, region string) (legacyPublish.S3Credentials, error) {
	var body []byte
	var err error
	switch {
	case strings.HasPrefix(reference, "env://"):
		name := strings.TrimPrefix(reference, "env://")
		value, ok := os.LookupEnv(name)
		if !ok || value == "" {
			return legacyPublish.S3Credentials{}, fmt.Errorf("%w: R2 credential environment reference is unset", ErrNotReady)
		}
		if len(value) > maxR2CredentialBytes {
			return legacyPublish.S3Credentials{}, fmt.Errorf("%w: R2 credential document exceeds safety limit", ErrRejected)
		}
		body = []byte(value)
	case strings.HasPrefix(reference, "file://"):
		filename := strings.TrimPrefix(reference, "file://")
		file, openErr := os.Open(filename)
		if openErr != nil {
			return legacyPublish.S3Credentials{}, fmt.Errorf("%w: open R2 credential reference: %v", ErrNotReady, openErr)
		}
		body, err = io.ReadAll(io.LimitReader(file, maxR2CredentialBytes+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return legacyPublish.S3Credentials{}, errors.Join(fmt.Errorf("%w: read R2 credential reference", ErrNotReady), err, closeErr)
		}
		if len(body) > maxR2CredentialBytes {
			return legacyPublish.S3Credentials{}, fmt.Errorf("%w: R2 credential document exceeds safety limit", ErrRejected)
		}
	default:
		return legacyPublish.S3Credentials{}, fmt.Errorf("%w: unsupported R2 credential reference", ErrRejected)
	}
	var document r2CredentialDocument
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return legacyPublish.S3Credentials{}, fmt.Errorf("%w: decode R2 credential document", ErrRejected)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return legacyPublish.S3Credentials{}, fmt.Errorf("%w: R2 credential document has trailing data", ErrRejected)
	}
	return legacyPublish.S3Credentials{
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
		page, err := b.objects.R2ListObjectsV2Prefix(ctx, listPrefix, continuation)
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
			info, err := b.objects.R2Head(ctx, listed.Key)
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
	info, err := b.objects.R2Head(ctx, key)
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
	condition := legacyPublish.R2PutCondition{}
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
	etag, putErr := b.objects.R2Put(ctx, key, &managedContextReader{ctx: ctx, reader: source.file}, operation.Size, operation.SHA256, condition)
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

func (b *r2PublicationBackend) VerifyPublic(ctx context.Context, expected state.GenerationFile) error {
	return verifyHTTPPublicationObject(ctx, b.publicBase, expected)
}

func (b *r2PublicationBackend) DeleteConditional(context.Context, state.PublicationCandidate) error {
	return fmt.Errorf("%w: R2 physical deletion is disabled", ErrRejected)
}

func (b *r2PublicationBackend) VerifyPublicAbsent(context.Context, string) error {
	return fmt.Errorf("%w: R2 physical deletion is disabled", ErrRejected)
}

func verifyHTTPPublicationObject(ctx context.Context, base *url.URL, expected state.GenerationFile) error {
	u := *base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + expected.Path
	u.RawPath, u.RawQuery, u.Fragment = "", "", ""
	client := &http.Client{
		Timeout:       2 * time.Minute,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: public GET %q returned %s", ErrIntegrity, expected.Path, response.Status)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: io.LimitReader(response.Body, expected.Size+1)})
	if err != nil || size != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return errors.Join(fmt.Errorf("%w: public GET content differs for %q", ErrIntegrity, expected.Path), err)
	}
	return nil
}
