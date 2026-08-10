package r2

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/middleware"
)

const (
	maxListResponseSize  = 16 << 20
	maxErrorResponseSize = 1 << 20
	maxListPageKeys      = 1000
)

var (
	credentialIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,256}$`)
	regionPattern       = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	copyBucketPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type S3Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

func (c S3Credentials) validate() error {
	if !credentialIDPattern.MatchString(c.AccessKeyID) || !regionPattern.MatchString(c.Region) || !safeHeaderSecret(c.SecretAccessKey, 4096) ||
		(c.SessionToken != "" && !safeHeaderSecret(c.SessionToken, 16<<10)) {
		return errors.New("S3 access key, secret, and region are required")
	}
	return nil
}

func safeHeaderSecret(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

type signedObjectHTTP struct {
	sdk    *s3.Client
	bucket string
}

func newSignedObjectHTTP(rawBase, configuredBucket string, credentials S3Credentials, client *http.Client, allowInsecure bool) (*signedObjectHTTP, error) {
	if err := credentials.validate(); err != nil {
		return nil, err
	}
	_, endpoint, bucket, usePathStyle, err := splitS3BucketRoot(rawBase, configuredBucket, allowInsecure)
	if err != nil {
		return nil, err
	}
	httpClient := cloneNoRedirectClient(client)
	doer := &s3SDKHTTPClient{client: httpClient}
	provider := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID: credentials.AccessKeyID, SecretAccessKey: credentials.SecretAccessKey,
			SessionToken: credentials.SessionToken, Source: "sow-target-secret",
		}, nil
	})
	awsConfig := aws.Config{
		Region: credentials.Region, Credentials: provider, HTTPClient: doer,
		Retryer: func() aws.Retryer { return aws.NopRetryer{} }, BaseEndpoint: aws.String(endpoint.String()),
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	clientSDK := s3.NewFromConfig(awsConfig, func(options *s3.Options) {
		options.UsePathStyle = usePathStyle
		options.Retryer = aws.NopRetryer{}
		options.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		options.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	return &signedObjectHTTP{sdk: clientSDK, bucket: bucket}, nil
}

func (c *signedObjectHTTP) head(ctx context.Context, key string) (ObjectInfo, error) {
	if err := validateRemoteKey(key); err != nil {
		return ObjectInfo{}, err
	}
	response, err := c.sdk.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if err != nil {
		if s3HTTPStatus(err) == http.StatusNotFound {
			return ObjectInfo{}, nil
		}
		return ObjectInfo{}, err
	}
	return ObjectInfo{
		Exists: true, Size: s3ContentLength(response.ContentLength),
		SHA256: response.Metadata["sow-sha256"], ETag: aws.ToString(response.ETag),
	}, nil
}

func (c *signedObjectHTTP) openObject(ctx context.Context, key string) (ObjectContent, error) {
	if err := validateRemoteKey(key); err != nil {
		return ObjectContent{}, err
	}
	response, err := c.sdk.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if err != nil {
		if s3HTTPStatus(err) == http.StatusNotFound {
			return ObjectContent{}, ErrNotFound
		}
		return ObjectContent{}, err
	}
	return ObjectContent{Info: ObjectInfo{
		Exists: true, Size: s3ContentLength(response.ContentLength),
		SHA256: response.Metadata["sow-sha256"], ETag: aws.ToString(response.ETag),
	}, Body: response.Body}, nil
}

func (c *signedObjectHTTP) listObjectsV2Prefix(ctx context.Context, prefix, continuationToken string) (ObjectListPage, error) {
	if len(continuationToken) > 16<<10 || strings.ContainsAny(continuationToken, "\x00\r\n") {
		return ObjectListPage{}, errors.New("unsafe ListObjectsV2 continuation token")
	}
	if prefix != "" && (!strings.HasSuffix(prefix, "/") || validateRemoteKey(strings.TrimSuffix(prefix, "/")) != nil) {
		return ObjectListPage{}, errors.New("unsafe ListObjectsV2 prefix")
	}
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(c.bucket), EncodingType: types.EncodingTypeUrl,
		MaxKeys: aws.Int32(maxListPageKeys),
	}
	if prefix != "" {
		input.Prefix = aws.String(prefix)
	}
	if continuationToken != "" {
		input.ContinuationToken = aws.String(continuationToken)
	}
	response, err := c.sdk.ListObjectsV2(ctx, input)
	if err != nil {
		return ObjectListPage{}, err
	}
	if response.EncodingType != types.EncodingTypeUrl {
		return ObjectListPage{}, fmt.Errorf("%w: ListObjectsV2 returned an unexpected document", ErrCapability)
	}
	if len(response.Contents) > maxListPageKeys {
		return ObjectListPage{}, fmt.Errorf("%w: ListObjectsV2 exceeded requested max-keys", ErrCapability)
	}
	page := ObjectListPage{Objects: make([]ListedObject, 0, len(response.Contents))}
	lastKey := ""
	for _, object := range response.Contents {
		key, err := url.PathUnescape(aws.ToString(object.Key))
		if err != nil {
			return ObjectListPage{}, fmt.Errorf("decode ListObjectsV2 key: %w", err)
		}
		if len(key) > 1024 {
			return ObjectListPage{}, errors.New("ListObjectsV2 key exceeds S3 safety limit")
		}
		if err := validateRemoteKey(key); err != nil || prefix != "" && !strings.HasPrefix(key, prefix) {
			return ObjectListPage{}, errors.New("ListObjectsV2 returned an unsafe object key")
		}
		if aws.ToInt64(object.Size) < 0 {
			return ObjectListPage{}, errors.New("ListObjectsV2 returned a negative object size")
		}
		if lastKey != "" && key <= lastKey {
			return ObjectListPage{}, errors.New("ListObjectsV2 page is not strictly key-sorted")
		}
		lastKey = key
		page.Objects = append(page.Objects, ListedObject{Key: key, Size: aws.ToInt64(object.Size), ETag: aws.ToString(object.ETag)})
	}
	next := aws.ToString(response.NextContinuationToken)
	if aws.ToBool(response.IsTruncated) {
		if next == "" || len(next) > 16<<10 || strings.ContainsAny(next, "\x00\r\n") {
			return ObjectListPage{}, fmt.Errorf("%w: truncated ListObjectsV2 response has no safe continuation token", ErrCapability)
		}
		page.NextContinuationToken = next
	} else if next != "" {
		return ObjectListPage{}, fmt.Errorf("%w: non-truncated ListObjectsV2 response returned a continuation token", ErrCapability)
	}
	return page, nil
}

func (c *signedObjectHTTP) put(ctx context.Context, key string, body io.Reader, size int64, sha string, ifMatch string, createOnly bool) (string, error) {
	if body == nil || size < 0 || !hexSHA256Pattern.MatchString(sha) || validateRemoteKey(key) != nil {
		return "", errors.New("invalid remote object size or sha256")
	}
	input := &s3.PutObjectInput{
		Bucket: aws.String(c.bucket), Key: aws.String(key), Body: body, ContentLength: aws.Int64(size),
		Metadata: map[string]string{"sow-sha256": sha},
	}
	if ifMatch != "" {
		input.IfMatch = aws.String(ifMatch)
	}
	if createOnly {
		input.IfNoneMatch = aws.String("*")
	}
	response, err := c.sdk.PutObject(ctx, input, withS3RequestContract(sha))
	if err != nil {
		status := s3HTTPStatus(err)
		if status == http.StatusPreconditionFailed || status == http.StatusConflict {
			if createOnly {
				return "", ErrAlreadyExists
			}
			return "", ErrConflict
		}
		if status == http.StatusNotImplemented {
			return "", ErrCapability
		}
		return "", err
	}
	etag := aws.ToString(response.ETag)
	if etag == "" {
		return "", fmt.Errorf("%w: object write response has no ETag", ErrCapability)
	}
	return etag, nil
}

type s3RequestContractMiddleware struct {
	payloadSHA string
}

func (m *s3RequestContractMiddleware) ID() string { return "sowS3VendorContract" }

func (m *s3RequestContractMiddleware) HandleFinalize(ctx context.Context, input middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
	ctx = awsv4.SetPayloadHash(ctx, m.payloadSHA)
	return next.HandleFinalize(ctx, input)
}

func withS3RequestContract(payloadSHA string) func(*s3.Options) {
	return func(options *s3.Options) {
		options.APIOptions = append(options.APIOptions, func(stack *middleware.Stack) error {
			return stack.Finalize.Insert(&s3RequestContractMiddleware{payloadSHA: payloadSHA}, "ComputePayloadHash", middleware.Before)
		})
	}
}

func splitS3BucketRoot(rawBase, configuredBucket string, allowInsecure bool) (*url.URL, *url.URL, string, bool, error) {
	base, err := url.Parse(rawBase)
	if err != nil || base.Host == "" || base.User != nil || base.RawPath != "" ||
		(base.Scheme != "https" && !(allowInsecure && base.Scheme == "http")) || base.RawQuery != "" || base.Fragment != "" {
		return nil, nil, "", false, errors.New("object base URL must be a clean HTTPS bucket-root URL")
	}
	cleanBasePath := strings.TrimSuffix(base.Path, "/")
	if base.Path == "/" {
		cleanBasePath = "/"
	}
	if base.Path != "" && path.Clean(base.Path) != cleanBasePath {
		return nil, nil, "", false, errors.New("object base URL path is not canonical")
	}
	if configuredBucket != "" && !copyBucketPattern.MatchString(configuredBucket) {
		return nil, nil, "", false, errors.New("object bucket must be a DNS-safe label")
	}
	bucketRoot := *base
	endpoint := *base
	trimmedPath := strings.Trim(base.Path, "/")
	if trimmedPath != "" {
		if strings.Contains(trimmedPath, "/") || !copyBucketPattern.MatchString(trimmedPath) {
			return nil, nil, "", false, errors.New("object base URL path must contain exactly one bucket label")
		}
		if configuredBucket != "" && configuredBucket != trimmedPath {
			return nil, nil, "", false, errors.New("object base URL bucket disagrees with configured bucket")
		}
		endpoint.Path = ""
		return &bucketRoot, &endpoint, trimmedPath, true, nil
	}
	bucket := configuredBucket
	hostname := base.Hostname()
	if bucket == "" {
		bucket, hostname, _ = strings.Cut(hostname, ".")
		if hostname == "" || !copyBucketPattern.MatchString(bucket) {
			return nil, nil, "", false, errors.New("object bucket identity is unavailable from bucket-root URL")
		}
	} else {
		prefix := bucket + "."
		if !strings.HasPrefix(strings.ToLower(hostname), prefix) {
			return nil, nil, "", false, errors.New("object base URL host is not bound to the configured bucket")
		}
		hostname = hostname[len(prefix):]
	}
	if base.Port() != "" {
		endpoint.Host = net.JoinHostPort(hostname, base.Port())
	} else {
		endpoint.Host = hostname
	}
	endpoint.Path = ""
	return &bucketRoot, &endpoint, bucket, false, nil
}

type s3SDKHTTPClient struct {
	client *http.Client
}

type s3ResponseLimitError struct {
	statusCode int
	maximum    int64
}

func (e *s3ResponseLimitError) Error() string {
	return fmt.Sprintf("S3 SDK response exceeds safety limit (%d bytes)", e.maximum)
}

func (e *s3ResponseLimitError) HTTPStatusCode() int { return e.statusCode }

func (c *s3SDKHTTPClient) Do(request *http.Request) (*http.Response, error) {
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	// net/http's real transport exposes Content-Length both in the parsed field
	// and header. Preserve that observable wire value for protocol transports
	// before the generated SDK deserializer consumes response headers.
	if response.ContentLength >= 0 && response.Header.Get("Content-Length") == "" {
		response.Header.Set("Content-Length", fmt.Sprintf("%d", response.ContentLength))
	}
	maximum, expectedRoot := int64(0), ""
	switch {
	case request.URL.Query().Has("list-type"):
		maximum, expectedRoot = maxListResponseSize, "ListBucketResult"
	case response.StatusCode < 200 || response.StatusCode >= 300:
		maximum = maxErrorResponseSize
	}
	if maximum == 0 {
		return response, nil
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if int64(len(data)) > maximum {
		return nil, &s3ResponseLimitError{statusCode: response.StatusCode, maximum: maximum}
	}
	if expectedRoot != "" && response.StatusCode >= 200 && response.StatusCode < 300 {
		decoder := xml.NewDecoder(bytes.NewReader(data))
		decoder.Strict = true
		for {
			token, tokenErr := decoder.Token()
			if tokenErr != nil {
				return nil, fmt.Errorf("decode S3 SDK response root: %w", tokenErr)
			}
			if start, ok := token.(xml.StartElement); ok {
				if start.Name.Local != expectedRoot {
					return nil, fmt.Errorf("%w: S3 SDK returned unexpected %s document", ErrCapability, expectedRoot)
				}
				break
			}
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	response.ContentLength = int64(len(data))
	return response, nil
}

func s3HTTPStatus(err error) int {
	for err != nil {
		if responseError, ok := err.(interface{ HTTPStatusCode() int }); ok {
			if status := responseError.HTTPStatusCode(); status != 0 {
				return status
			}
		}
		err = errors.Unwrap(err)
	}
	return 0
}

func s3ContentLength(value *int64) int64 {
	if value == nil {
		return -1
	}
	return *value
}

func cloneNoRedirectClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copyClient
}
