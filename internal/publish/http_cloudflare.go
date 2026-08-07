package publish

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	cloudflareapi "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/cache"
	"github.com/cloudflare/cloudflare-go/v7/option"
)

type R2CloudflareHTTPConfig struct {
	Bucket            string
	ObjectBaseURL     string
	CDNBaseURL        string
	Credentials       S3Credentials
	ZoneID            string
	APIToken          string
	CloudflareAPIURL  string
	Client            *http.Client
	AllowInsecure     bool
	VerificationBasic *BasicAuthCredentials
}

// R2CloudflareControlHTTPConfig configures the R2-only control-object surface.
// It deliberately has no CDN identity or API token: callers that only manage a
// provider-visible lease/checkpoint must not acquire unrelated CDN authority.
type R2CloudflareControlHTTPConfig struct {
	Bucket        string
	ObjectBaseURL string
	Credentials   S3Credentials
	Client        *http.Client
	AllowInsecure bool
}

// R2CloudflareControlHTTP is the R2 object-control subset used by recovery and
// coordination paths that must not be able to purge or mutate Cloudflare CDN
// configuration.
type R2CloudflareControlHTTP struct {
	objects *signedObjectHTTP
}

func NewR2CloudflareControlHTTP(config R2CloudflareControlHTTPConfig) (*R2CloudflareControlHTTP, error) {
	objects, err := newSignedObjectHTTP(config.ObjectBaseURL, config.Bucket, config.Credentials, config.Client, config.AllowInsecure, s3VendorR2)
	if err != nil {
		return nil, err
	}
	return &R2CloudflareControlHTTP{objects: objects}, nil
}

func (c *R2CloudflareControlHTTP) R2GetControl(ctx context.Context, key string) (ControlObject, error) {
	return c.objects.getControl(ctx, key)
}

func (c *R2CloudflareControlHTTP) R2ListObjectsV2(ctx context.Context, continuationToken string) (ObjectListPage, error) {
	return c.objects.listObjectsV2(ctx, continuationToken)
}

// R2ListObjectsV2Prefix is the storage-only, exact-prefix audit surface used by
// the V2 publisher. It acquires no CDN authority and revalidates every returned
// key inside signedObjectHTTP.
func (c *R2CloudflareControlHTTP) R2ListObjectsV2Prefix(ctx context.Context, prefix, continuationToken string) (ObjectListPage, error) {
	return c.objects.listObjectsV2Prefix(ctx, prefix, continuationToken)
}

// R2Head, R2OpenObject, and R2Copy keep storage-only callers on the same
// least-authority client used for leases and checkpoints. They deliberately do
// not acquire a Cloudflare API token or any CDN/Worker control capability.
func (c *R2CloudflareControlHTTP) R2Head(ctx context.Context, key string) (ObjectInfo, error) {
	return c.objects.head(ctx, key)
}

func (c *R2CloudflareControlHTTP) R2OpenObject(ctx context.Context, key string) (ObjectContent, error) {
	return c.objects.openObject(ctx, key)
}

func (c *R2CloudflareControlHTTP) R2Copy(ctx context.Context, destinationKey, sourceKey string, size int64, sha, sourceETag string) (string, error) {
	return c.objects.copyObject(ctx, destinationKey, sourceKey, size, sha, sourceETag)
}

func (c *R2CloudflareControlHTTP) R2Put(ctx context.Context, key string, body io.Reader, size int64, sha string, condition R2PutCondition) (string, error) {
	if condition.IfMatch != "" && condition.IfNoneMatch {
		return "", errors.New("R2 put cannot combine If-Match and If-None-Match")
	}
	return c.objects.put(ctx, key, body, size, sha, condition.IfMatch, condition.IfNoneMatch)
}

func (c *R2CloudflareControlHTTP) R2Delete(ctx context.Context, key, ifMatch string) error {
	return c.objects.deleteObject(ctx, key, ifMatch)
}

func (c *R2CloudflareControlHTTP) R2DeleteCheckpointFenced(ctx context.Context, key string) error {
	return c.objects.deleteObjectCheckpointFenced(ctx, key)
}

type R2CloudflareHTTP struct {
	objects    *signedObjectHTTP
	client     *http.Client
	cloudflare *cloudflareapi.Client
	zoneID     string
	cdnBase    *url.URL
	basic      *BasicAuthCredentials
}

func NewR2CloudflareHTTP(config R2CloudflareHTTPConfig) (*R2CloudflareHTTP, error) {
	objects, err := newSignedObjectHTTP(config.ObjectBaseURL, config.Bucket, config.Credentials, config.Client, config.AllowInsecure, s3VendorR2)
	if err != nil {
		return nil, err
	}
	if !credentialIDPattern.MatchString(config.ZoneID) || !safeHeaderSecret(config.APIToken, 16<<10) {
		return nil, errors.New("Cloudflare zone ID and API token are required")
	}
	cdnBase, _, err := parseCDNBaseURL(config.CDNBaseURL, config.AllowInsecure)
	if err != nil {
		return nil, err
	}
	var basic *BasicAuthCredentials
	if config.VerificationBasic != nil {
		copyCredentials := *config.VerificationBasic
		if err := copyCredentials.validate(); err != nil {
			return nil, err
		}
		basic = &copyCredentials
	}
	apiBase := config.CloudflareAPIURL
	if apiBase == "" {
		apiBase = "https://api.cloudflare.com/client/v4"
	}
	u, err := url.Parse(apiBase)
	if err != nil || u.Host == "" || u.User != nil || u.RawPath != "" || (u.Scheme != "https" && !(config.AllowInsecure && u.Scheme == "http")) || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid Cloudflare API URL")
	}
	cleanAPIPath := strings.TrimSuffix(u.Path, "/")
	if u.Path == "/" {
		cleanAPIPath = "/"
	}
	if u.Path != "" && path.Clean(u.Path) != cleanAPIPath {
		return nil, errors.New("Cloudflare API URL path is not canonical")
	}
	cloudflareClient := cloudflareapi.NewClient(
		option.WithBaseURL(strings.TrimSuffix(apiBase, "/")+"/"),
		option.WithAPIToken(config.APIToken),
		option.WithHTTPClient(boundedSDKHTTPClient{client: objects.client, maximum: 1 << 20}),
		option.WithMaxRetries(0),
	)
	return &R2CloudflareHTTP{objects: objects, client: objects.client, cloudflare: cloudflareClient, zoneID: config.ZoneID, cdnBase: cdnBase, basic: basic}, nil
}

func (c *R2CloudflareHTTP) R2GetControl(ctx context.Context, key string) (ControlObject, error) {
	return c.objects.getControl(ctx, key)
}

func (c *R2CloudflareHTTP) CloudflarePreflight(ctx context.Context, plan Plan) error {
	return preflightProviderCDNPlan(ctx, c.client, c.cdnBase, c.basic, plan)
}

func (c *R2CloudflareHTTP) R2Head(ctx context.Context, key string) (ObjectInfo, error) {
	return c.objects.head(ctx, key)
}

// R2ListObjectsV2 is intentionally absent from R2CloudflareProvider. Only the
// explicit fsck path calls this concrete audit method; publish cannot issue a
// repository-wide list through its provider interface.
func (c *R2CloudflareHTTP) R2ListObjectsV2(ctx context.Context, continuationToken string) (ObjectListPage, error) {
	return c.objects.listObjectsV2(ctx, continuationToken)
}

// R2ListObjectsV2Prefix is the provider-attestation audit surface. Prefix is
// signed into the S3 request and every returned key is rechecked against it;
// it is deliberately absent from the publication provider interface.
func (c *R2CloudflareHTTP) R2ListObjectsV2Prefix(ctx context.Context, prefix, continuationToken string) (ObjectListPage, error) {
	return c.objects.listObjectsV2Prefix(ctx, prefix, continuationToken)
}

func (c *R2CloudflareHTTP) R2OpenObject(ctx context.Context, key string) (ObjectContent, error) {
	return c.objects.openObject(ctx, key)
}

func (c *R2CloudflareHTTP) R2Put(ctx context.Context, key string, body io.Reader, size int64, sha string, condition R2PutCondition) (string, error) {
	if condition.IfMatch != "" && condition.IfNoneMatch {
		return "", errors.New("R2 put cannot combine If-Match and If-None-Match")
	}
	return c.objects.put(ctx, key, body, size, sha, condition.IfMatch, condition.IfNoneMatch)
}

func (c *R2CloudflareHTTP) R2Copy(ctx context.Context, destinationKey, sourceKey string, size int64, sha, sourceETag string) (string, error) {
	return c.objects.copyObject(ctx, destinationKey, sourceKey, size, sha, sourceETag)
}

func (c *R2CloudflareHTTP) R2Delete(ctx context.Context, key, ifMatch string) error {
	return c.objects.deleteObject(ctx, key, ifMatch)
}

func (c *R2CloudflareHTTP) R2DeleteCheckpointFenced(ctx context.Context, key string) error {
	return c.objects.deleteObjectCheckpointFenced(ctx, key)
}

func (c *R2CloudflareHTTP) CloudflarePurge(ctx context.Context, urls []string) error {
	if err := c.validateCloudflarePurgeURLs(urls, 0); err != nil {
		return err
	}
	// Cloudflare's documented single-file purge ceiling is 100 URLs on every
	// plan (500 only on Enterprise). Batches are independently idempotent; if a
	// later batch fails the saga safely repeats earlier batches.
	for start := 0; start < len(urls); start += 100 {
		end := min(start+100, len(urls))
		if _, err := c.cloudflarePurgeBatch(ctx, urls[start:end], false); err != nil {
			return err
		}
	}
	return nil
}

// CloudflarePurgeBatchEvidence executes exactly one documented-size batch and
// returns the provider trace needed by the durable publication sidecar.  It is
// deliberately separate from CloudflarePurge so old callers retain their API
// while the production CLI can require receipt-bearing providers.
func (c *R2CloudflareHTTP) CloudflarePurgeBatchEvidence(ctx context.Context, urls []string) (PurgeReceipt, error) {
	if err := c.validateCloudflarePurgeURLs(urls, 100); err != nil {
		return PurgeReceipt{}, err
	}
	return c.cloudflarePurgeBatch(ctx, urls, true)
}

func (c *R2CloudflareHTTP) CloudflarePurgeEvidenceZoneID() string { return c.zoneID }

func (c *R2CloudflareHTTP) validateCloudflarePurgeURLs(urls []string, maximum int) error {
	if len(urls) == 0 {
		return errors.New("Cloudflare purge requires explicit URLs")
	}
	if maximum != 0 && len(urls) > maximum {
		return errors.New("Cloudflare purge evidence batch exceeds 100 URLs")
	}
	for _, value := range urls {
		if _, err := validateCDNTarget(c.cdnBase, value); err != nil {
			return errors.New("Cloudflare purge URL is outside the configured CDN base")
		}
	}
	return nil
}

func (c *R2CloudflareHTTP) cloudflarePurgeBatch(ctx context.Context, urls []string, requireEvidence bool) (PurgeReceipt, error) {
	// cloudflare-go returns nil error for any HTTP 2xx response, even when the
	// Cloudflare envelope says success=false. Decode the public envelope here so
	// a business-level rejection cannot advance the publication saga.
	var envelope cache.CachePurgeResponseEnvelope
	var rawResponse *http.Response
	_, err := c.cloudflare.Cache.Purge(ctx, cache.CachePurgeParams{
		ZoneID: cloudflareapi.F(c.zoneID),
		Body: cache.CachePurgeParamsBodyCachePurgeSingleFile{
			Files: cloudflareapi.F(append([]string(nil), urls...)),
		},
	}, option.WithResponseBodyInto(&envelope), option.WithResponseInto(&rawResponse))
	if err != nil {
		return PurgeReceipt{}, err
	}
	if !envelope.Success || len(envelope.Errors) != 0 || strings.TrimSpace(envelope.Result.ID) == "" {
		return PurgeReceipt{}, errors.New("Cloudflare purge API did not confirm successful completion")
	}
	rayID := ""
	if rawResponse != nil {
		rayID = strings.TrimSpace(rawResponse.Header.Get("CF-Ray"))
	}
	if requireEvidence && !validPurgeEvidenceIdentifier(rayID) {
		return PurgeReceipt{}, errors.New("Cloudflare purge response has no safe CF-Ray receipt")
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	digest, err := PurgeURLsDigest(urls)
	if err != nil {
		return PurgeReceipt{}, err
	}
	return PurgeReceipt{
		URLCount: len(urls), URLsSHA256: digest,
		Vendor: PurgeVendorCloudflare, ZoneID: c.zoneID, Status: PurgeReceiptCompleted,
		AcceptedRequestID: rayID, AcceptedObservedAt: stamp,
		CompletedRequestID: rayID, CompletedObservedAt: stamp,
		VendorResultID: strings.TrimSpace(envelope.Result.ID),
	}, nil
}

func (c *R2CloudflareHTTP) CloudflareOpen(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	return openCDN(ctx, c.client, c.cdnBase, rawURL, c.basic)
}
