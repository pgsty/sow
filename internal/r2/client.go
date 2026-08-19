package r2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsretry "github.com/aws/aws-sdk-go-v2/aws/retry"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/middleware"
)

const (
	maxListResponseSize  = 16 << 20
	maxErrorResponseSize = 1 << 20
	maxListPageKeys      = 1000
	defaultMultipartAt   = 100 << 20
	defaultPartSize      = 64 << 20
	minimumPartSize      = 5 << 20
	maximumPartSize      = 5 << 30
	maximumMultipartSize = (5 << 40) - (5 << 30)
	maximumParts         = 10000
	responseHeaderLimit  = 2 * time.Minute
	uploadProgressLimit  = 2 * time.Minute
)

var (
	credentialIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,256}$`)
	regionPattern       = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	copyBucketPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	errUploadNoProgress = errors.New("R2 upload made no progress before its idle deadline")
	// ErrReadNoProgress reports a response body that stopped delivering bytes
	// while its request remained otherwise live.
	ErrReadNoProgress = errors.New("R2 response made no progress before its idle deadline")
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
	sdk                  *s3.Client
	bucket               string
	multipartThreshold   int64
	multipartMinPartSize int64
	noProgressTimeout    time.Duration
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
	doer := &s3SDKHTTPClient{client: httpClient, readIdleTimeout: uploadProgressLimit}
	provider := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID: credentials.AccessKeyID, SecretAccessKey: credentials.SecretAccessKey,
			SessionToken: credentials.SessionToken, Source: "sow-target-secret",
		}, nil
	})
	awsConfig := aws.Config{
		Region: credentials.Region, Credentials: provider, HTTPClient: doer,
		Retryer: func() aws.Retryer { return awsretry.NewStandard() }, BaseEndpoint: aws.String(endpoint.String()),
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	clientSDK := s3.NewFromConfig(awsConfig, func(options *s3.Options) {
		options.UsePathStyle = usePathStyle
		options.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		options.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	return &signedObjectHTTP{
		sdk: clientSDK, bucket: bucket, multipartThreshold: defaultMultipartAt,
		multipartMinPartSize: defaultPartSize, noProgressTimeout: uploadProgressLimit,
	}, nil
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

func (c *signedObjectHTTP) put(ctx context.Context, key string, body ReadSeekReaderAt, size int64, sha string, ifMatch string, createOnly bool, cacheControl string) (string, error) {
	if body == nil || size < 0 || !hexSHA256Pattern.MatchString(sha) || validateRemoteKey(key) != nil {
		return "", errors.New("invalid remote object size or sha256")
	}
	if position, err := body.Seek(0, io.SeekStart); err != nil || position != 0 {
		return "", errors.Join(errors.New("rewind R2 upload source"), err)
	}
	if size > maximumMultipartSize {
		return "", fmt.Errorf("%w: object size %d exceeds the R2 multipart limit", ErrCapability, size)
	}
	if size > c.multipartThreshold {
		return c.putMultipart(ctx, key, body, size, sha, ifMatch, createOnly, cacheControl)
	}
	return c.putSingle(ctx, key, body, size, sha, ifMatch, createOnly, cacheControl)
}

func (c *signedObjectHTTP) putSingle(ctx context.Context, key string, body ReadSeekReaderAt, size int64, sha, ifMatch string, createOnly bool, cacheControl string) (string, error) {
	requestCtx, monitored, finish := monitorUploadProgress(ctx, body, c.noProgressTimeout)
	input := &s3.PutObjectInput{
		Bucket: aws.String(c.bucket), Key: aws.String(key), Body: monitored, ContentLength: aws.Int64(size),
		Metadata: map[string]string{"sow-sha256": sha},
	}
	if cacheControl != "" {
		input.CacheControl = aws.String(cacheControl)
	}
	if ifMatch != "" {
		input.IfMatch = aws.String(ifMatch)
	}
	if createOnly {
		input.IfNoneMatch = aws.String("*")
	}
	response, err := c.sdk.PutObject(requestCtx, input, withS3RequestContract(sha))
	if finishErr := finish(); finishErr != nil {
		err = errors.Join(err, finishErr)
	}
	if err != nil {
		return "", classifyPutError(err, createOnly)
	}
	etag := aws.ToString(response.ETag)
	if etag == "" {
		return "", fmt.Errorf("%w: object write response has no ETag", ErrCapability)
	}
	return etag, nil
}

func (c *signedObjectHTTP) putMultipart(ctx context.Context, key string, body ReadSeekReaderAt, size int64, sha, ifMatch string, createOnly bool, cacheControl string) (string, error) {
	partSize, err := multipartPartSize(size, c.multipartMinPartSize)
	if err != nil {
		return "", err
	}
	createInput := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(c.bucket), Key: aws.String(key), Metadata: map[string]string{"sow-sha256": sha},
	}
	if cacheControl != "" {
		createInput.CacheControl = aws.String(cacheControl)
	}
	created, err := c.sdk.CreateMultipartUpload(ctx, createInput)
	if err != nil {
		return "", err
	}
	uploadID := aws.ToString(created.UploadId)
	if uploadID == "" || len(uploadID) > 16<<10 || strings.ContainsAny(uploadID, "\x00\r\n") {
		return "", errors.Join(fmt.Errorf("%w: multipart create returned no bounded upload identity", ErrCapability), c.abortMultipart(key, uploadID))
	}
	abort := func(result error) (string, error) {
		return "", errors.Join(result, c.abortMultipart(key, uploadID))
	}
	parts := make([]types.CompletedPart, 0, (size+partSize-1)/partSize)
	for offset, partNumber := int64(0), int32(1); offset < size; offset, partNumber = offset+partSize, partNumber+1 {
		length := min(partSize, size-offset)
		section := io.NewSectionReader(body, offset, length)
		partHash := sha256.New()
		read, hashErr := io.Copy(partHash, section)
		if hashErr != nil || read != length {
			return abort(errors.Join(fmt.Errorf("hash multipart part %d: read %d of %d bytes", partNumber, read, length), hashErr))
		}
		partSHA := hex.EncodeToString(partHash.Sum(nil))
		if _, err := section.Seek(0, io.SeekStart); err != nil {
			return abort(err)
		}
		requestCtx, monitored, finish := monitorUploadProgress(ctx, section, c.noProgressTimeout)
		uploaded, uploadErr := c.sdk.UploadPart(requestCtx, &s3.UploadPartInput{
			Bucket: aws.String(c.bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
			PartNumber: aws.Int32(partNumber), Body: monitored, ContentLength: aws.Int64(length),
		}, withS3RequestContract(partSHA))
		if finishErr := finish(); finishErr != nil {
			uploadErr = errors.Join(uploadErr, finishErr)
		}
		if uploadErr != nil {
			return abort(uploadErr)
		}
		etag := aws.ToString(uploaded.ETag)
		if etag == "" {
			return abort(fmt.Errorf("%w: multipart part %d returned no ETag", ErrCapability, partNumber))
		}
		parts = append(parts, types.CompletedPart{ETag: aws.String(etag), PartNumber: aws.Int32(partNumber)})
	}
	input := &s3.CompleteMultipartUploadInput{
		Bucket: aws.String(c.bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	}
	if ifMatch != "" {
		input.IfMatch = aws.String(ifMatch)
	}
	if createOnly {
		input.IfNoneMatch = aws.String("*")
	}
	completed, err := c.sdk.CompleteMultipartUpload(ctx, input)
	if err != nil {
		return abort(classifyPutError(err, createOnly))
	}
	etag := aws.ToString(completed.ETag)
	if etag == "" {
		return "", fmt.Errorf("%w: multipart completion returned no ETag", ErrCapability)
	}
	return etag, nil
}

func (c *signedObjectHTTP) abortMultipart(key, uploadID string) error {
	if uploadID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := c.sdk.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket: aws.String(c.bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
	})
	return err
}

func multipartPartSize(size, preferred int64) (int64, error) {
	if size <= 0 || size > maximumMultipartSize {
		return 0, fmt.Errorf("%w: invalid multipart object size %d", ErrCapability, size)
	}
	if preferred <= 0 {
		preferred = defaultPartSize
	}
	required := (size + maximumParts - 1) / maximumParts
	partSize := max(preferred, required)
	if partSize >= minimumPartSize {
		const alignment = int64(1 << 20)
		partSize = (partSize + alignment - 1) / alignment * alignment
	}
	if partSize > maximumPartSize || (size+partSize-1)/partSize > maximumParts {
		return 0, fmt.Errorf("%w: object size %d cannot fit the R2 multipart limits", ErrCapability, size)
	}
	return partSize, nil
}

func classifyPutError(err error, createOnly bool) error {
	status := s3HTTPStatus(err)
	if status == http.StatusPreconditionFailed || status == http.StatusConflict {
		if createOnly {
			return ErrAlreadyExists
		}
		return ErrConflict
	}
	if status == http.StatusNotImplemented {
		return ErrCapability
	}
	return err
}

type uploadProgressReadSeekAt struct {
	source   ReadSeekReaderAt
	progress chan<- struct{}
}

func (r *uploadProgressReadSeekAt) observed(count int) {
	if count <= 0 {
		return
	}
	select {
	case r.progress <- struct{}{}:
	default:
	}
}

func (r *uploadProgressReadSeekAt) Read(buffer []byte) (int, error) {
	count, err := r.source.Read(buffer)
	r.observed(count)
	return count, err
}

func (r *uploadProgressReadSeekAt) ReadAt(buffer []byte, offset int64) (int, error) {
	count, err := r.source.ReadAt(buffer, offset)
	r.observed(count)
	return count, err
}

func (r *uploadProgressReadSeekAt) Seek(offset int64, whence int) (int64, error) {
	position, err := r.source.Seek(offset, whence)
	if err == nil {
		r.observed(1)
	}
	return position, err
}

func monitorUploadProgress(ctx context.Context, source ReadSeekReaderAt, timeout time.Duration) (context.Context, ReadSeekReaderAt, func() error) {
	if timeout <= 0 {
		return ctx, source, func() error { return nil }
	}
	requestCtx, cancel := context.WithCancel(ctx)
	progress := make(chan struct{}, 1)
	done := make(chan struct{})
	var stalled atomic.Bool
	var finished atomic.Bool
	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		for {
			select {
			case <-progress:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(timeout)
			case <-timer.C:
				stalled.Store(true)
				cancel()
				return
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	finish := func() error {
		if finished.CompareAndSwap(false, true) {
			close(done)
			cancel()
		}
		if stalled.Load() {
			return errUploadNoProgress
		}
		return nil
	}
	return requestCtx, &uploadProgressReadSeekAt{source: source, progress: progress}, finish
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
	client          *http.Client
	readIdleTimeout time.Duration
}

type s3ResponseLimitError struct {
	statusCode int
	maximum    int64
}

func (e *s3ResponseLimitError) Error() string {
	return fmt.Sprintf("S3 SDK response exceeds safety limit (%d bytes)", e.maximum)
}

func (e *s3ResponseLimitError) HTTPStatusCode() int  { return e.statusCode }
func (e *s3ResponseLimitError) RetryableError() bool { return false }

func (c *s3SDKHTTPClient) Do(request *http.Request) (*http.Response, error) {
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.Body != nil && c.readIdleTimeout > 0 {
		response.Body = NewIdleReadCloser(request.Context(), response.Body, c.readIdleTimeout)
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

type idleReadCloser struct {
	ctx       context.Context
	source    io.ReadCloser
	progress  chan struct{}
	done      chan struct{}
	stalled   atomic.Bool
	doneOnce  sync.Once
	closeOnce sync.Once
	closeErr  error
}

// NewIdleReadCloser cancels a response body by closing it when no bytes arrive
// within timeout. It limits inactivity rather than total transfer duration, so
// large healthy downloads remain unbounded by object size.
func NewIdleReadCloser(ctx context.Context, source io.ReadCloser, timeout time.Duration) io.ReadCloser {
	if source == nil || timeout <= 0 {
		return source
	}
	if ctx == nil {
		ctx = context.Background()
	}
	reader := &idleReadCloser{
		ctx: ctx, source: source, progress: make(chan struct{}, 1), done: make(chan struct{}),
	}
	go reader.monitor(timeout)
	return reader
}

func (r *idleReadCloser) monitor(timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-r.progress:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(timeout)
		case <-timer.C:
			r.stalled.Store(true)
			_ = r.closeSource()
			return
		case <-r.ctx.Done():
			_ = r.closeSource()
			return
		case <-r.done:
			return
		}
	}
}

func (r *idleReadCloser) observed(count int) {
	if count <= 0 {
		return
	}
	select {
	case r.progress <- struct{}{}:
	default:
	}
}

func (r *idleReadCloser) stop() {
	r.doneOnce.Do(func() { close(r.done) })
}

func (r *idleReadCloser) closeSource() error {
	r.closeOnce.Do(func() { r.closeErr = r.source.Close() })
	return r.closeErr
}

func (r *idleReadCloser) Read(buffer []byte) (int, error) {
	count, err := r.source.Read(buffer)
	r.observed(count)
	if err != nil {
		r.stop()
	}
	if r.stalled.Load() {
		return count, errors.Join(err, ErrReadNoProgress)
	}
	if err != nil && r.ctx.Err() != nil {
		return count, errors.Join(err, r.ctx.Err())
	}
	return count, err
}

func (r *idleReadCloser) Close() error {
	r.stop()
	err := r.closeSource()
	if r.stalled.Load() {
		return errors.Join(err, ErrReadNoProgress)
	}
	return err
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
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.ResponseHeaderTimeout = responseHeaderLimit
		client = &http.Client{Transport: transport}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copyClient
}
