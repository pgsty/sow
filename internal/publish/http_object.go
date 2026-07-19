package publish

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
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/pgsty/sow/internal/config"
)

const maxControlObjectSize = 8 << 20

const (
	maxListResponseSize = 16 << 20
	maxListPageKeys     = 1000
)

var (
	credentialIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,256}$`)
	regionPattern       = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	copyBucketPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type s3VendorDialect uint8

const (
	s3VendorR2 s3VendorDialect = iota + 1
	s3VendorCOS
)

type S3Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

type BasicAuthCredentials struct {
	Username string
	Password string
}

func (c BasicAuthCredentials) validate() error {
	if c.Username == "" || len(c.Username) > 256 || strings.ContainsAny(c.Username, ":\x00\r\n") ||
		c.Password == "" || len(c.Password) > 4096 || strings.ContainsAny(c.Password, "\x00\r\n") {
		return errors.New("invalid CDN Basic verification credentials")
	}
	return nil
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
	base    *url.URL
	client  *http.Client
	sdk     *s3.Client
	bucket  string
	dialect s3VendorDialect
}

func newSignedObjectHTTP(rawBase, configuredBucket string, credentials S3Credentials, client *http.Client, allowInsecure bool, dialect s3VendorDialect) (*signedObjectHTTP, error) {
	if err := credentials.validate(); err != nil {
		return nil, err
	}
	if dialect != s3VendorR2 && dialect != s3VendorCOS {
		return nil, errors.New("unknown S3 vendor dialect")
	}
	bucketRoot, endpoint, bucket, usePathStyle, err := splitS3BucketRoot(rawBase, configuredBucket, allowInsecure)
	if err != nil {
		return nil, err
	}
	httpClient := cloneNoRedirectClient(client)
	doer := &s3SDKHTTPClient{client: httpClient, dialect: dialect}
	sdkSessionToken := credentials.SessionToken
	if dialect == s3VendorCOS {
		// Tencent temporary credentials use x-cos-security-token. Leaving the
		// token on aws.Credentials would make the AWS signer emit the distinct
		// x-amz-security-token header, which COS does not define for its native
		// S3-compatible request contract.
		sdkSessionToken = ""
	}
	provider := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID: credentials.AccessKeyID, SecretAccessKey: credentials.SecretAccessKey,
			SessionToken: sdkSessionToken, Source: "sow-target-secret",
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
		if dialect == s3VendorCOS && credentials.SessionToken != "" {
			options.APIOptions = append(options.APIOptions, withCOSSecurityToken(credentials.SessionToken))
		}
	})
	return &signedObjectHTTP{base: bucketRoot, client: httpClient, sdk: clientSDK, bucket: bucket, dialect: dialect}, nil
}

func (c *signedObjectHTTP) getControl(ctx context.Context, key string) (ControlObject, error) {
	if err := validateRemoteKey(key); err != nil {
		return ControlObject{}, err
	}
	response, err := c.sdk.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if err != nil {
		if s3HTTPStatus(err) == http.StatusNotFound {
			return ControlObject{}, nil
		}
		return ControlObject{}, err
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxControlObjectSize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return ControlObject{}, err
	}
	if len(body) > maxControlObjectSize {
		return ControlObject{}, errors.New("remote control object exceeds safety limit")
	}
	etag := aws.ToString(response.ETag)
	if etag == "" {
		return ControlObject{}, fmt.Errorf("%w: object response has no ETag", ErrCapability)
	}
	return ControlObject{Exists: true, Body: body, ETag: etag}, nil
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

func (c *signedObjectHTTP) listObjectsV2(ctx context.Context, continuationToken string) (ObjectListPage, error) {
	return c.listObjectsV2Prefix(ctx, "", continuationToken)
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
	if createOnly && c.dialect == s3VendorR2 {
		input.IfNoneMatch = aws.String("*")
	}
	response, err := c.sdk.PutObject(ctx, input, withS3RequestContract(sha, c.dialect, createOnly, false))
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

func escapeCopySourceKey(key string) (string, error) {
	if err := validateRemoteKey(key); err != nil {
		return "", err
	}
	segments := strings.Split(key, "/")
	for index := range segments {
		segments[index] = url.PathEscape(segments[index])
	}
	return strings.Join(segments, "/"), nil
}

func (c *signedObjectHTTP) copyObject(ctx context.Context, destinationKey, sourceKey string, size int64, sha, sourceETag string) (string, error) {
	if size < 0 || !hexSHA256Pattern.MatchString(sha) || sourceETag == "" || len(sourceETag) > 1024 || strings.ContainsAny(sourceETag, "\x00\r\n") || validateRemoteKey(destinationKey) != nil {
		return "", errors.New("invalid CopyObject size, digest, or source ETag")
	}
	escapedSource, err := escapeCopySourceKey(sourceKey)
	if err != nil {
		return "", err
	}
	copySource := "/" + c.bucket + "/" + escapedSource
	if c.dialect == s3VendorCOS {
		copySource = c.base.Host + "/" + escapedSource
	}
	response, err := c.sdk.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket: aws.String(c.bucket), Key: aws.String(destinationKey), CopySource: aws.String(copySource),
		CopySourceIfMatch: aws.String(sourceETag), MetadataDirective: types.MetadataDirectiveReplace,
		Metadata: map[string]string{"sow-sha256": sha},
	}, withS3RequestContract(emptySHA256, c.dialect, true, true))
	if err != nil {
		switch s3HTTPStatus(err) {
		case http.StatusNotFound:
			return "", ErrNotFound
		case http.StatusPreconditionFailed, http.StatusConflict:
			return "", ErrConflict
		case http.StatusNotImplemented:
			return "", ErrCapability
		default:
			return "", err
		}
	}
	if response.CopyObjectResult == nil || aws.ToString(response.CopyObjectResult.ETag) == "" {
		return "", fmt.Errorf("%w: CopyObject returned an unexpected success document", ErrCapability)
	}
	return aws.ToString(response.CopyObjectResult.ETag), nil
}

func (c *signedObjectHTTP) deleteObject(ctx context.Context, key, ifMatch string) error {
	if !safeHeaderSecret(ifMatch, 4096) || validateRemoteKey(key) != nil {
		return fmt.Errorf("%w: conditional DeleteObject requires a bounded ETag", ErrCapability)
	}
	_, err := c.sdk.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket), Key: aws.String(key), IfMatch: aws.String(ifMatch),
	})
	if err == nil {
		return nil
	}
	switch s3HTTPStatus(err) {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusPreconditionFailed, http.StatusConflict:
		return ErrConflict
	case http.StatusNotImplemented:
		return ErrCapability
	default:
		return err
	}
}

func (c *signedObjectHTTP) deleteObjectCheckpointFenced(ctx context.Context, key string) error {
	if validateRemoteKey(key) != nil {
		return errors.New("invalid checkpoint-fenced DeleteObject key")
	}
	_, err := c.sdk.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket), Key: aws.String(key),
	})
	if err == nil {
		return nil
	}
	switch s3HTTPStatus(err) {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusPreconditionFailed, http.StatusConflict:
		return ErrConflict
	case http.StatusNotImplemented:
		return ErrCapability
	default:
		return err
	}
}

func (c *signedObjectHTTP) probeCOSUnversioned(ctx context.Context) error {
	response, err := c.sdk.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(c.bucket)})
	if err != nil {
		return err
	}
	switch response.Status {
	case "":
		return nil
	case types.BucketVersioningStatusEnabled, types.BucketVersioningStatusSuspended:
		return fmt.Errorf("%w: COS create-only locks require a bucket that has never enabled versioning", ErrCapability)
	default:
		return fmt.Errorf("%w: COS returned an unknown bucket versioning state", ErrCapability)
	}
}

type s3RequestContractMiddleware struct {
	payloadSHA string
	dialect    s3VendorDialect
	create     bool
	copy       bool
}

type cosSecurityTokenMiddleware struct{ token string }

func (m *cosSecurityTokenMiddleware) ID() string { return "sowCOSSecurityToken" }

func (m *cosSecurityTokenMiddleware) HandleFinalize(ctx context.Context, input middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
	request, ok := input.Request.(*smithyhttp.Request)
	if !ok {
		return middleware.FinalizeOutput{}, middleware.Metadata{}, fmt.Errorf("unexpected S3 transport type %T", input.Request)
	}
	request.Header.Del("X-Amz-Security-Token")
	request.Header.Set("X-Cos-Security-Token", m.token)
	return next.HandleFinalize(ctx, input)
}

func withCOSSecurityToken(token string) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Finalize.Insert(&cosSecurityTokenMiddleware{token: token}, "ComputePayloadHash", middleware.Before)
	}
}

func (m *s3RequestContractMiddleware) ID() string { return "sowS3VendorContract" }

func (m *s3RequestContractMiddleware) HandleFinalize(ctx context.Context, input middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
	request, ok := input.Request.(*smithyhttp.Request)
	if !ok {
		return middleware.FinalizeOutput{}, middleware.Metadata{}, fmt.Errorf("unexpected S3 transport type %T", input.Request)
	}
	if m.payloadSHA != "" {
		ctx = awsv4.SetPayloadHash(ctx, m.payloadSHA)
	}
	if m.copy && m.dialect == s3VendorR2 {
		request.Header.Set("Cf-Copy-Destination-If-None-Match", "*")
	}
	if m.dialect == s3VendorCOS {
		rewriteCOSRequestHeaders(request.Header)
		if m.create {
			request.Header.Del("If-None-Match")
			request.Header.Set("X-Cos-Forbid-Overwrite", "true")
		}
	}
	return next.HandleFinalize(ctx, input)
}

func withS3RequestContract(payloadSHA string, dialect s3VendorDialect, create, copyObject bool) func(*s3.Options) {
	return func(options *s3.Options) {
		options.APIOptions = append(options.APIOptions, func(stack *middleware.Stack) error {
			return stack.Finalize.Insert(&s3RequestContractMiddleware{
				payloadSHA: payloadSHA, dialect: dialect, create: create, copy: copyObject,
			}, "ComputePayloadHash", middleware.Before)
		})
	}
}

func rewriteCOSRequestHeaders(headers http.Header) {
	for name, values := range headers {
		lower := strings.ToLower(name)
		var replacement string
		switch {
		case strings.HasPrefix(lower, "x-amz-meta-"):
			replacement = "X-Cos-Meta-" + name[len("X-Amz-Meta-"):]
		case lower == "x-amz-copy-source":
			replacement = "X-Cos-Copy-Source"
		case lower == "x-amz-copy-source-if-match":
			replacement = "X-Cos-Copy-Source-If-Match"
		case lower == "x-amz-metadata-directive":
			replacement = "X-Cos-Metadata-Directive"
		}
		if replacement == "" {
			continue
		}
		headers.Del(name)
		for _, value := range values {
			if strings.EqualFold(replacement, "X-Cos-Metadata-Directive") {
				value = "Replaced"
			}
			headers.Add(replacement, value)
		}
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
	client  *http.Client
	dialect s3VendorDialect
}

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
	if c.dialect == s3VendorCOS {
		for name, values := range response.Header {
			if !strings.HasPrefix(strings.ToLower(name), "x-cos-meta-") {
				continue
			}
			replacement := "X-Amz-Meta-" + name[len("X-Cos-Meta-"):]
			if response.Header.Get(replacement) == "" {
				response.Header[replacement] = append([]string(nil), values...)
			}
		}
	}
	maximum, expectedRoot, allowErrorRoot := int64(0), "", false
	switch {
	case request.URL.Query().Has("list-type"):
		maximum, expectedRoot = maxListResponseSize, "ListBucketResult"
	case request.URL.Query().Has("versioning"):
		maximum, expectedRoot = 1<<20, "VersioningConfiguration"
	case request.Method == http.MethodPut && (request.Header.Get("X-Amz-Copy-Source") != "" || request.Header.Get("X-Cos-Copy-Source") != ""):
		maximum, expectedRoot, allowErrorRoot = 1<<20, "CopyObjectResult", true
	case response.StatusCode < 200 || response.StatusCode >= 300:
		maximum = 1 << 20
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
		return nil, errors.New("S3 SDK response exceeds safety limit")
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
				if start.Name.Local != expectedRoot && !(allowErrorRoot && start.Name.Local == "Error") {
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
	var responseError interface{ HTTPStatusCode() int }
	if errors.As(err, &responseError) {
		return responseError.HTTPStatusCode()
	}
	return 0
}

func s3ContentLength(value *int64) int64 {
	if value == nil {
		return -1
	}
	return *value
}

type boundedSDKHTTPClient struct {
	client  *http.Client
	maximum int64
}

func (c boundedSDKHTTPClient) Do(request *http.Request) (*http.Response, error) {
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	return bufferBoundedHTTPResponse(response, c.maximum)
}

func bufferBoundedHTTPResponse(response *http.Response, maximum int64) (*http.Response, error) {
	if response == nil || response.Body == nil || maximum <= 0 {
		return response, nil
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("vendor SDK response exceeds safety limit")
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	response.ContentLength = int64(len(data))
	return response, nil
}

func cloneNoRedirectClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copyClient
}

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type httpStatusError struct {
	Method string
	URL    string
	Status int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("%s %s returned HTTP %d", e.Method, e.URL, e.Status)
}

func httpResponseError(response *http.Response) error {
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return &httpStatusError{Method: response.Request.Method, URL: redactSensitiveURL(response.Request.URL), Status: response.StatusCode}
}

func openCDN(ctx context.Context, client *http.Client, base *url.URL, rawURL string, basic *BasicAuthCredentials) (io.ReadCloser, error) {
	u, err := validateCDNTarget(base, rawURL)
	if err != nil {
		return nil, errors.New("invalid CDN verification URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if isBasicVerificationPath(u.Path) {
		if basic == nil || basic.validate() != nil {
			return nil, errors.New("Basic CDN verification route requires configured credentials")
		}
		request.SetBasicAuth(basic.Username, basic.Password)
	}
	// CDN verification admits only the explicit Basic credential above. An
	// ambient client cookie jar must not create a second authentication channel.
	response, err := doNoRedirect(clientWithoutCookieJar(client), request)
	if err != nil {
		return nil, fmt.Errorf("CDN verification request failed: %w", unwrapURLError(err))
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		return nil, httpResponseError(response)
	}
	return response.Body, nil
}

func isBasicVerificationPath(value string) bool {
	parts := strings.Split(value, "/")
	for index := 0; index+2 < len(parts); index++ {
		if parts[index] == "pro" && parts[index+1] == "v1" && parts[index+2] == "basic" {
			return true
		}
	}
	return false
}

func unwrapURLError(err error) error {
	var requestError *url.Error
	if errors.As(err, &requestError) && requestError.Err != nil {
		return requestError.Err
	}
	return errors.New("HTTP request failed")
}

func redactURLString(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "<invalid-url>"
	}
	return redactSensitiveURL(parsed)
}

func validateCDNTarget(base *url.URL, rawURL string) (*url.URL, error) {
	if base == nil {
		return nil, errors.New("CDN base URL is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || path.Clean(u.Path) != u.Path ||
		u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) || !strings.HasPrefix(u.Path, base.Path) || containsBearerCredential(u.Path) {
		return nil, errors.New("URL is outside the configured CDN base")
	}
	canonical := *u
	canonical.RawPath = ""
	if canonical.String() != rawURL {
		return nil, errors.New("CDN URL is not canonically encoded")
	}
	return u, nil
}

func validateProviderCDNPlan(base *url.URL, basic *BasicAuthCredentials, plan Plan) error {
	for _, rawURL := range plan.PurgeURLs {
		if _, err := validateCDNTarget(base, rawURL); err != nil {
			return errors.New("purge URL is outside the configured CDN base")
		}
	}
	positive := make([]VerifyObject, 0, len(plan.Verify)+len(plan.Probes))
	positive = append(positive, plan.Verify...)
	positive = append(positive, plan.Probes...)
	for _, expectation := range positive {
		target, err := validateCDNTarget(base, expectation.URL)
		if err != nil {
			return errors.New("verification URL is outside the configured CDN base")
		}
		if isBasicVerificationPath(target.Path) && (basic == nil || basic.validate() != nil) {
			return errors.New("Basic CDN verification route requires configured credentials")
		}
	}
	for _, expectation := range plan.VerifyAbsent {
		target, err := validateCDNTarget(base, expectation.URL)
		if err != nil {
			return errors.New("absence verification URL is outside the configured CDN base")
		}
		if isBasicVerificationPath(target.Path) && (basic == nil || basic.validate() != nil) {
			return errors.New("Basic CDN absence verification route requires configured credentials")
		}
	}
	return nil
}

const (
	confidentialEdgeCanaryKey     = ".sow/gated/.sow-confidentiality-preflight"
	confidentialEdgeCanaryBody    = "not_found\n"
	maxConfidentialEdgeCanaryBody = 64
)

// preflightProviderCDNPlan is the last no-mutation boundary before a publish
// journal, remote lock, checkpoint, or payload can be created. Public-only
// plans retain their local validation path. A plan that can introduce or
// expose confidential bytes additionally has to prove that the configured
// front door is the versioned SOW edge runtime, rather than a raw public
// object-store custom domain that happens to return a generic 404.
func preflightProviderCDNPlan(ctx context.Context, client *http.Client, base *url.URL, basic *BasicAuthCredentials, plan Plan) error {
	if ctx == nil {
		return errors.New("provider preflight requires a context")
	}
	if err := validateProviderCDNPlan(base, basic, plan); err != nil {
		return err
	}
	if !planRequiresConfidentialEdge(plan) {
		return nil
	}
	return attestConfidentialEdgeDenial(ctx, client, base)
}

func planRequiresConfidentialEdge(plan Plan) bool {
	for _, object := range plan.Objects {
		if strings.HasPrefix(object.RemoteKey, ".sow/gated/") || isBasicCDNPath(object.CDNPath) {
			return true
		}
	}
	for _, deletion := range plan.Deletes {
		if strings.HasPrefix(deletion.RemoteKey, ".sow/gated/") || isBasicCDNPath(deletion.CDNPath) {
			return true
		}
	}
	for _, rawURL := range plan.PurgeURLs {
		if isBasicCDNURL(rawURL) {
			return true
		}
	}
	positive := make([]VerifyObject, 0, len(plan.Verify)+len(plan.Probes))
	positive = append(positive, plan.Verify...)
	positive = append(positive, plan.Probes...)
	for _, expectation := range positive {
		if isBasicCDNURL(expectation.URL) {
			return true
		}
	}
	for _, expectation := range plan.VerifyAbsent {
		if isBasicCDNURL(expectation.URL) {
			return true
		}
	}
	return false
}

func isBasicCDNPath(value string) bool {
	if value == "" {
		return false
	}
	return isBasicVerificationPath("/" + strings.TrimPrefix(value, "/"))
}

func isBasicCDNURL(rawURL string) bool {
	target, err := url.Parse(rawURL)
	return err == nil && isBasicVerificationPath(target.Path)
}

func attestConfidentialEdgeDenial(ctx context.Context, client *http.Client, base *url.URL) error {
	rawURL := joinCDNURL(base, confidentialEdgeCanaryKey)
	target, err := validateCDNTarget(base, rawURL)
	if err != nil {
		return fmt.Errorf("%w: derive confidential edge denial canary", ErrCapability)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return fmt.Errorf("%w: construct confidential edge denial canary: %w", ErrCapability, err)
	}
	// This request is deliberately anonymous. Supplying the verification Basic
	// credentials here would prove only that an origin is readable, not that an
	// unauthenticated client is denied before gated bytes can be uploaded.
	request.Header.Set("Accept", "text/plain")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-store, no-cache, max-age=0")
	request.Header.Set("Pragma", "no-cache")

	// A caller-supplied client may carry a cookie jar. net/http injects those
	// cookies only inside Client.Do, after the request header checks above, so a
	// shallow client copy with Jar=nil is required to make anonymity a product
	// property rather than a convention of the default CLI client.
	response, err := doNoRedirect(clientWithoutCookieJar(client), request)
	if err != nil {
		return fmt.Errorf("%w: confidential edge denial canary request failed: %w", ErrCapability, unwrapURLError(err))
	}
	if response == nil || response.Body == nil {
		return fmt.Errorf("%w: confidential edge denial canary returned no response body", ErrCapability)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxConfidentialEdgeCanaryBody+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return fmt.Errorf("%w: read confidential edge denial canary: %w", ErrCapability, errors.Join(readErr, closeErr))
	}
	if len(body) > maxConfidentialEdgeCanaryBody {
		return fmt.Errorf("%w: confidential edge denial canary body exceeds safety limit", ErrCapability)
	}
	if response.StatusCode != http.StatusNotFound {
		return fmt.Errorf("%w: confidential edge denial canary returned HTTP %d", ErrCapability, response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != int64(len(body)) {
		return fmt.Errorf("%w: confidential edge denial canary length mismatch", ErrCapability)
	}
	if string(body) != confidentialEdgeCanaryBody {
		return fmt.Errorf("%w: confidential edge denial canary body does not match the runtime contract", ErrCapability)
	}
	if !hasSingleExactHeader(response.Header, "X-SOW-Edge-Contract", config.EdgeRuntimeSchema) {
		return fmt.Errorf("%w: confidential edge denial canary lacks runtime contract %s", ErrCapability, config.EdgeRuntimeSchema)
	}
	if !hasSingleExactHeader(response.Header, "Content-Type", "text/plain; charset=utf-8") ||
		!hasSingleExactHeader(response.Header, "X-Content-Type-Options", "nosniff") {
		return fmt.Errorf("%w: confidential edge denial canary has invalid content headers", ErrCapability)
	}
	if !hasExactPrivateDenialCacheControl(response.Header) {
		return fmt.Errorf("%w: confidential edge denial canary is not private and non-cacheable", ErrCapability)
	}
	if len(response.Trailer) != 0 || hasForbiddenEdgeDenialHeader(response.Header) {
		return fmt.Errorf("%w: confidential edge denial canary exposes a redirect, credential, encoding, or origin marker", ErrCapability)
	}
	return nil
}

func hasSingleExactHeader(header http.Header, name, wanted string) bool {
	values := headerValuesFold(header, name)
	return len(values) == 1 && values[0] == wanted
}

func headerValuesFold(header http.Header, name string) []string {
	var values []string
	for candidate, candidateValues := range header {
		if strings.EqualFold(candidate, name) {
			values = append(values, candidateValues...)
		}
	}
	return values
}

func hasExactPrivateDenialCacheControl(header http.Header) bool {
	values := headerValuesFold(header, "Cache-Control")
	if len(values) != 1 {
		return false
	}
	wanted := map[string]bool{"private": false, "no-store": false, "max-age=0": false}
	directives := strings.Split(values[0], ",")
	if len(directives) != len(wanted) {
		return false
	}
	for _, rawDirective := range directives {
		directive := strings.ToLower(strings.TrimSpace(rawDirective))
		seen, exists := wanted[directive]
		if !exists || seen {
			return false
		}
		wanted[directive] = true
	}
	return wanted["private"] && wanted["no-store"] && wanted["max-age=0"]
}

func hasForbiddenEdgeDenialHeader(header http.Header) bool {
	for name := range header {
		lower := strings.ToLower(name)
		switch lower {
		case "location", "set-cookie", "www-authenticate", "content-encoding", "x-sow-clean-url-sha256":
			return true
		}
		if strings.HasPrefix(lower, "x-sow-origin-") {
			return true
		}
	}
	return false
}

func clientWithoutCookieJar(client *http.Client) *http.Client {
	if client == nil {
		return nil
	}
	copyClient := *client
	copyClient.Jar = nil
	return &copyClient
}

func doNoRedirect(client *http.Client, request *http.Request) (*http.Response, error) {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return copyClient.Do(request)
}

func redactSensitiveURL(value *url.URL) string {
	if value == nil {
		return "<invalid-url>"
	}
	redacted := *value
	redacted.User = nil
	if redacted.RawQuery != "" {
		redacted.RawQuery = "REDACTED"
	}
	parts := strings.Split(redacted.Path, "/")
	for i := 1; i+2 < len(parts); i++ {
		if parts[i] == "pro" && parts[i+1] == "v1" && parts[i+2] != "basic" {
			parts[i+2] = "REDACTED"
		}
	}
	redacted.Path = strings.Join(parts, "/")
	redacted.RawPath = ""
	return redacted.String()
}
