// Package r2 provides the bounded S3 transport used by V2 R2 publication.
// It intentionally contains no CDN, edge-runtime, or provider-control API.
package r2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
)

var (
	ErrAlreadyExists = errors.New("remote object already exists")
	ErrCapability    = errors.New("remote provider lacks required safety capability")
	ErrConflict      = errors.New("remote compare-and-set conflict")
	ErrNotFound      = errors.New("remote object not found")
	hexSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Config struct {
	Bucket        string
	ObjectBaseURL string
	Credentials   S3Credentials
	Client        *http.Client
	AllowInsecure bool
}

// ObjectInfo is trusted only when both size and explicit sow-sha256 metadata
// match. Provider ETags are treated as opaque compare-and-set identities.
type ObjectInfo struct {
	Exists bool
	Size   int64
	SHA256 string
	ETag   string
}

type ListedObject struct {
	Key  string
	Size int64
	ETag string
}

type ObjectListPage struct {
	Objects               []ListedObject
	NextContinuationToken string
}

type ObjectContent struct {
	Info ObjectInfo
	Body io.ReadCloser
}

type PutCondition struct {
	IfMatch     string
	IfNoneMatch bool
}

type Client struct {
	objects *signedObjectHTTP
}

func NewClient(config Config) (*Client, error) {
	objects, err := newSignedObjectHTTP(config.ObjectBaseURL, config.Bucket, config.Credentials, config.Client, config.AllowInsecure)
	if err != nil {
		return nil, err
	}
	return &Client{objects: objects}, nil
}

func (c *Client) ListObjectsV2Prefix(ctx context.Context, prefix, continuationToken string) (ObjectListPage, error) {
	return c.objects.listObjectsV2Prefix(ctx, prefix, continuationToken)
}

func (c *Client) Head(ctx context.Context, key string) (ObjectInfo, error) {
	return c.objects.head(ctx, key)
}

func (c *Client) OpenObject(ctx context.Context, key string) (ObjectContent, error) {
	return c.objects.openObject(ctx, key)
}

func (c *Client) Put(ctx context.Context, key string, body io.Reader, size int64, sha256 string, condition PutCondition) (string, error) {
	if condition.IfMatch != "" && condition.IfNoneMatch {
		return "", errors.New("R2 put cannot combine If-Match and If-None-Match")
	}
	return c.objects.put(ctx, key, body, size, sha256, condition.IfMatch, condition.IfNoneMatch)
}

func validateRemoteKey(value string) error {
	if value == "" || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\\x00\r\n\t") {
		return fmt.Errorf("unsafe remote key %q", value)
	}
	if path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return fmt.Errorf("non-canonical remote key %q", value)
	}
	return nil
}
