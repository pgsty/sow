package publish

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	teo "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/teo/v20220901"
)

type TencentCredentials struct {
	SecretID  string
	SecretKey string
	Token     string
}

func (c TencentCredentials) validate() error {
	if !credentialIDPattern.MatchString(c.SecretID) || !safeHeaderSecret(c.SecretKey, 4096) ||
		(c.Token != "" && !safeHeaderSecret(c.Token, 16<<10)) {
		return errors.New("invalid Tencent credentials")
	}
	return nil
}

type COSEdgeOneHTTPConfig struct {
	Bucket                     string
	ObjectBaseURL              string
	CDNBaseURL                 string
	ObjectCredentials          S3Credentials
	TencentCredentials         TencentCredentials
	ZoneID                     string
	EdgeOneAPIURL              string
	Client                     *http.Client
	AllowInsecure              bool
	UnversionedBucketConfirmed bool
	VerificationBasic          *BasicAuthCredentials
}

// COSControlHTTPConfig configures the COS object-only surface used by remote
// audit and recovery paths. It intentionally has no EdgeOne identity, zone, or
// credential, so callers cannot accidentally acquire CDN control authority.
type COSControlHTTPConfig struct {
	Bucket        string
	ObjectBaseURL string
	Credentials   S3Credentials
	Client        *http.Client
	AllowInsecure bool
}

// COSControlHTTP exposes only the signed COS object operations required by
// remote audits. Publication continues to use COSEdgeOneHTTP, whose distinct
// type makes the stronger CDN capability explicit at construction time.
type COSControlHTTP struct {
	objects *signedObjectHTTP
}

func NewCOSControlHTTP(config COSControlHTTPConfig) (*COSControlHTTP, error) {
	objects, err := newSignedObjectHTTP(config.ObjectBaseURL, config.Bucket, config.Credentials, config.Client, config.AllowInsecure, s3VendorCOS)
	if err != nil {
		return nil, err
	}
	return &COSControlHTTP{objects: objects}, nil
}

func (c *COSControlHTTP) COSGetControl(ctx context.Context, key string) (ControlObject, error) {
	return c.objects.getControl(ctx, key)
}

func (c *COSControlHTTP) COSHead(ctx context.Context, key string) (ObjectInfo, error) {
	return c.objects.head(ctx, key)
}

func (c *COSControlHTTP) COSListObjectsV2(ctx context.Context, continuationToken string) (ObjectListPage, error) {
	return c.objects.listObjectsV2(ctx, continuationToken)
}

func (c *COSControlHTTP) COSOpenObject(ctx context.Context, key string) (ObjectContent, error) {
	return c.objects.openObject(ctx, key)
}

type COSEdgeOneHTTP struct {
	objects           *signedObjectHTTP
	client            *http.Client
	edgeOne           *teo.Client
	zoneID            string
	cdnBase           *url.URL
	basic             *BasicAuthCredentials
	purgePollInterval time.Duration
	purgeWaitTimeout  time.Duration
	purgeMissingGrace time.Duration
}

func NewCOSEdgeOneHTTP(config COSEdgeOneHTTPConfig) (*COSEdgeOneHTTP, error) {
	if !config.UnversionedBucketConfirmed {
		return nil, fmt.Errorf("%w: COS create-only locks require a bucket that has never enabled versioning", ErrCapability)
	}
	objects, err := newSignedObjectHTTP(config.ObjectBaseURL, config.Bucket, config.ObjectCredentials, config.Client, config.AllowInsecure, s3VendorCOS)
	if err != nil {
		return nil, err
	}
	if config.TencentCredentials.validate() != nil || !credentialIDPattern.MatchString(config.ZoneID) {
		return nil, errors.New("Tencent secret ID, secret key, and EdgeOne zone ID are required")
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
	apiURL := config.EdgeOneAPIURL
	if apiURL == "" {
		apiURL = "https://teo.tencentcloudapi.com"
	}
	u, err := url.Parse(apiURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawPath != "" || (u.Scheme != "https" && !(config.AllowInsecure && u.Scheme == "http")) || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid EdgeOne API URL")
	}
	clientProfile := profile.NewClientProfile()
	clientProfile.DisableRegionBreaker = true
	clientProfile.NetworkFailureMaxRetries = 0
	clientProfile.RateLimitExceededMaxRetries = 0
	clientProfile.HttpProfile.Scheme = strings.ToUpper(u.Scheme)
	clientProfile.HttpProfile.Endpoint = u.Host
	timeout := objects.client.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	clientProfile.HttpProfile.ReqTimeout = max(1, int((timeout+time.Second-1)/time.Second))
	credential := common.NewTokenCredential(config.TencentCredentials.SecretID, config.TencentCredentials.SecretKey, config.TencentCredentials.Token)
	edgeOneClient, err := teo.NewClient(credential, "", clientProfile)
	if err != nil {
		return nil, fmt.Errorf("construct Tencent EdgeOne SDK client: %w", err)
	}
	transport := objects.client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	edgeOneClient.WithHttpTransport(rejectRedirectRoundTripper{base: transport})
	return &COSEdgeOneHTTP{
		objects: objects, client: objects.client, edgeOne: edgeOneClient, zoneID: config.ZoneID, cdnBase: cdnBase, basic: basic,
		purgePollInterval: 250 * time.Millisecond, purgeWaitTimeout: 2 * time.Minute, purgeMissingGrace: 5 * time.Minute,
	}, nil
}

func (c *COSEdgeOneHTTP) COSProbeUnversioned(ctx context.Context) error {
	// Probe every publication. Bucket versioning is mutable provider state; a
	// process-lifetime cache could keep using create-only locks after an
	// operator enables or suspends versioning out of band.
	return c.objects.probeCOSUnversioned(ctx)
}

func (c *COSEdgeOneHTTP) EdgeOnePreflight(ctx context.Context, plan Plan) error {
	return preflightProviderCDNPlan(ctx, c.client, c.cdnBase, c.basic, plan)
}

func (c *COSEdgeOneHTTP) COSGetControl(ctx context.Context, key string) (ControlObject, error) {
	return c.objects.getControl(ctx, key)
}

func (c *COSEdgeOneHTTP) COSHead(ctx context.Context, key string) (ObjectInfo, error) {
	return c.objects.head(ctx, key)
}

// COSListObjectsV2 is an audit-only concrete method. Publication uses the
// narrower COSEdgeOneProvider interface and therefore cannot list the bucket.
func (c *COSEdgeOneHTTP) COSListObjectsV2(ctx context.Context, continuationToken string) (ObjectListPage, error) {
	return c.objects.listObjectsV2(ctx, continuationToken)
}

// COSListObjectsV2Prefix is the provider-attestation audit surface. Prefix is
// signed into the S3 request and every returned key is rechecked against it;
// it is deliberately absent from the publication provider interface.
func (c *COSEdgeOneHTTP) COSListObjectsV2Prefix(ctx context.Context, prefix, continuationToken string) (ObjectListPage, error) {
	return c.objects.listObjectsV2Prefix(ctx, prefix, continuationToken)
}

func (c *COSEdgeOneHTTP) COSOpenObject(ctx context.Context, key string) (ObjectContent, error) {
	return c.objects.openObject(ctx, key)
}

func (c *COSEdgeOneHTTP) COSCreate(ctx context.Context, key string, body io.Reader, size int64, sha string) (string, error) {
	return c.objects.put(ctx, key, body, size, sha, "", true)
}

func (c *COSEdgeOneHTTP) COSPut(ctx context.Context, key string, body io.Reader, size int64, sha string) (string, error) {
	return c.objects.put(ctx, key, body, size, sha, "", false)
}

func (c *COSEdgeOneHTTP) COSCopy(ctx context.Context, destinationKey, sourceKey string, size int64, sha, sourceETag string) (string, error) {
	return c.objects.copyObject(ctx, destinationKey, sourceKey, size, sha, sourceETag)
}

func (c *COSEdgeOneHTTP) COSDelete(ctx context.Context, key, ifMatch string) error {
	return c.objects.deleteObject(ctx, key, ifMatch)
}

func (c *COSEdgeOneHTTP) COSDeleteCheckpointFenced(ctx context.Context, key string) error {
	return c.objects.deleteObjectCheckpointFenced(ctx, key)
}

func (c *COSEdgeOneHTTP) EdgeOnePurge(ctx context.Context, urls []string) error {
	if err := c.validateEdgeOnePurgeURLs(urls, 0); err != nil {
		return err
	}
	// EdgeOne quotas vary by plan. A conservative bounded batch avoids an
	// unbounded request while preserving exact-URL purge semantics.
	for start := 0; start < len(urls); start += 100 {
		end := min(start+100, len(urls))
		jobID, err := c.createEdgeOnePurge(ctx, urls[start:end])
		if err != nil {
			return err
		}
		if err := c.waitEdgeOnePurge(ctx, jobID); err != nil {
			return err
		}
	}
	return nil
}

func (c *COSEdgeOneHTTP) createEdgeOnePurge(ctx context.Context, urls []string) (string, error) {
	receipt, err := c.createEdgeOnePurgeReceipt(ctx, urls, false)
	return receipt.JobID, err
}

// EdgeOneAcceptPurgeBatch exposes the asynchronous provider acceptance
// boundary.  Its receipt is persisted before polling, which lets a later
// process continue the exact accepted JobId after a timeout or crash.
func (c *COSEdgeOneHTTP) EdgeOneAcceptPurgeBatch(ctx context.Context, urls []string) (PurgeReceipt, error) {
	if err := c.validateEdgeOnePurgeURLs(urls, 100); err != nil {
		return PurgeReceipt{}, err
	}
	return c.createEdgeOnePurgeReceipt(ctx, urls, true)
}

func (c *COSEdgeOneHTTP) EdgeOnePurgeEvidenceZoneID() string { return c.zoneID }

func (c *COSEdgeOneHTTP) validateEdgeOnePurgeURLs(urls []string, maximum int) error {
	if len(urls) == 0 {
		return errors.New("EdgeOne purge requires explicit URLs")
	}
	if maximum != 0 && len(urls) > maximum {
		return errors.New("EdgeOne purge evidence batch exceeds 100 URLs")
	}
	for _, value := range urls {
		if _, err := validateCDNTarget(c.cdnBase, value); err != nil {
			return errors.New("EdgeOne purge URL is outside the configured CDN base")
		}
	}
	return nil
}

func (c *COSEdgeOneHTTP) createEdgeOnePurgeReceipt(ctx context.Context, urls []string, requireEvidence bool) (PurgeReceipt, error) {
	request := teo.NewCreatePurgeTaskRequest()
	request.ZoneId = stringPointer(c.zoneID)
	request.Type = stringPointer("purge_url")
	request.Targets = stringPointers(urls)
	response, err := c.edgeOne.CreatePurgeTaskWithContext(ctx, request)
	if err != nil {
		return PurgeReceipt{}, err
	}
	if response == nil || response.Response == nil || response.Response.JobId == nil || *response.Response.JobId == "" || len(response.Response.FailedList) != 0 {
		return PurgeReceipt{}, errors.New("EdgeOne purge did not accept every URL")
	}
	requestID := ""
	if response.Response.RequestId != nil {
		requestID = strings.TrimSpace(*response.Response.RequestId)
	}
	jobID := strings.TrimSpace(*response.Response.JobId)
	if requireEvidence && (!validPurgeEvidenceIdentifier(jobID) || !validPurgeEvidenceIdentifier(requestID)) {
		return PurgeReceipt{}, errors.New("EdgeOne purge acceptance has no safe job/request receipt")
	}
	digest, err := PurgeURLsDigest(urls)
	if err != nil {
		return PurgeReceipt{}, err
	}
	return PurgeReceipt{
		URLCount: len(urls), URLsSHA256: digest,
		Vendor: PurgeVendorEdgeOne, ZoneID: c.zoneID, Status: PurgeReceiptAccepted,
		JobID: jobID, AcceptedRequestID: requestID,
		AcceptedObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (c *COSEdgeOneHTTP) waitEdgeOnePurge(ctx context.Context, jobID string) error {
	_, err := c.waitEdgeOnePurgeReceipt(ctx, PurgeReceipt{JobID: jobID}, false)
	return err
}

// EdgeOneCompletePurgeBatch polls exactly the previously accepted job.  It
// never creates a replacement task. Transport errors leave the accepted
// receipt resumable; repeated cross-call exact-query absence becomes an
// auditable indeterminate receipt so the saga may start a new exact attempt;
// terminal provider failures are returned as failed receipts.
func (c *COSEdgeOneHTTP) EdgeOneCompletePurgeBatch(ctx context.Context, accepted PurgeReceipt) (PurgeReceipt, error) {
	if accepted.Vendor != PurgeVendorEdgeOne || accepted.ZoneID != c.zoneID || accepted.Status != PurgeReceiptAccepted ||
		accepted.URLCount < 1 || accepted.URLCount > 100 || !hexSHA256Pattern.MatchString(accepted.URLsSHA256) ||
		!validPurgeEvidenceIdentifier(accepted.JobID) || !validPurgeEvidenceIdentifier(accepted.AcceptedRequestID) || !isCanonicalUTCTime(accepted.AcceptedObservedAt) {
		return accepted, errors.New("invalid accepted EdgeOne purge receipt")
	}
	acceptedAt, _ := time.Parse(time.RFC3339Nano, accepted.AcceptedObservedAt)
	if err := validatePurgeNotFoundEvidence(accepted, acceptedAt); err != nil || accepted.IndeterminateRequestID != "" || accepted.IndeterminateObservedAt != "" {
		return accepted, errors.New("invalid accepted EdgeOne purge not-found history")
	}
	return c.waitEdgeOnePurgeReceipt(ctx, accepted, true)
}

func (c *COSEdgeOneHTTP) waitEdgeOnePurgeReceipt(ctx context.Context, accepted PurgeReceipt, requireEvidence bool) (PurgeReceipt, error) {
	jobID := accepted.JobID
	waitTimeout := c.purgeWaitTimeout
	if waitTimeout <= 0 {
		waitTimeout = 2 * time.Minute
	}
	pollInterval := c.purgePollInterval
	if pollInterval <= 0 {
		pollInterval = 250 * time.Millisecond
	}
	waitCtx, cancel := context.WithTimeout(ctx, waitTimeout)
	defer cancel()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	onlyNotFound := true
	lastNotFoundRequestID := ""
	lastNotFoundObservedAt := ""
	for {
		request := teo.NewDescribePurgeTasksRequest()
		request.ZoneId = stringPointer(c.zoneID)
		request.Limit = int64Pointer(1)
		request.Filters = []*teo.AdvancedFilter{{Name: stringPointer("job-id"), Values: stringPointers([]string{jobID})}}
		response, err := c.edgeOne.DescribePurgeTasksWithContext(waitCtx, request)
		if err != nil {
			if waitCtx.Err() != nil && requireEvidence && onlyNotFound && lastNotFoundRequestID != "" {
				return c.edgeOneMissingJobOutcome(accepted, lastNotFoundRequestID, lastNotFoundObservedAt)
			}
			return accepted, err
		}
		if response == nil || response.Response == nil {
			return accepted, errors.New("EdgeOne purge status API returned an empty response")
		}
		requestID := ""
		if response.Response.RequestId != nil {
			requestID = strings.TrimSpace(*response.Response.RequestId)
		}
		if requireEvidence && !validPurgeEvidenceIdentifier(requestID) {
			return accepted, errors.New("EdgeOne purge status response has no safe request receipt")
		}
		tasks := response.Response.Tasks
		if len(tasks) > 1 || len(tasks) == 1 && (tasks[0] == nil || tasks[0].JobId == nil || *tasks[0].JobId != jobID) {
			return accepted, errors.New("EdgeOne purge status returned a mismatched task")
		}
		if len(tasks) == 1 {
			onlyNotFound = false
			status := ""
			if tasks[0].Status != nil {
				status = strings.ToLower(*tasks[0].Status)
			}
			switch status {
			case "success":
				completed := accepted
				completed.Status = PurgeReceiptCompleted
				completed.CompletedRequestID = requestID
				completed.CompletedObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
				if err := copyEdgeOneProviderTimes(&completed, tasks[0]); err != nil {
					return accepted, err
				}
				return completed, nil
			case "failed", "timeout", "canceled":
				failed := accepted
				failed.Status = PurgeReceiptFailed
				failed.FailedRequestID = requestID
				failed.FailedObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
				if err := copyEdgeOneProviderTimes(&failed, tasks[0]); err != nil {
					return accepted, err
				}
				return failed, fmt.Errorf("EdgeOne purge task ended with status %s", status)
			case "processing", "":
			default:
				return accepted, errors.New("EdgeOne purge task returned an unknown status")
			}
		} else if requireEvidence {
			lastNotFoundRequestID = requestID
			lastNotFoundObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		select {
		case <-waitCtx.Done():
			if requireEvidence && onlyNotFound && lastNotFoundRequestID != "" {
				return c.edgeOneMissingJobOutcome(accepted, lastNotFoundRequestID, lastNotFoundObservedAt)
			}
			return accepted, fmt.Errorf("wait for EdgeOne purge completion: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (c *COSEdgeOneHTTP) edgeOneMissingJobOutcome(accepted PurgeReceipt, requestID, observedAt string) (PurgeReceipt, error) {
	missing, terminal := c.recordEdgeOneMissingJob(accepted, requestID, observedAt)
	if terminal {
		return missing, errors.New("EdgeOne accepted purge job remained absent from repeated exact job-id queries; exact URL closure requires a new auditable attempt")
	}
	return missing, errors.New("EdgeOne accepted purge job is not yet visible to an exact job-id query")
}

func (c *COSEdgeOneHTTP) recordEdgeOneMissingJob(accepted PurgeReceipt, requestID, observedAt string) (PurgeReceipt, bool) {
	updated := accepted
	updated.NotFoundConfirmations++
	if updated.NotFoundConfirmations == 1 {
		updated.FirstNotFoundRequestID = requestID
		updated.FirstNotFoundObservedAt = observedAt
	}
	updated.LastNotFoundRequestID = requestID
	updated.LastNotFoundObservedAt = observedAt
	acceptedAt, err := time.Parse(time.RFC3339Nano, accepted.AcceptedObservedAt)
	grace := c.purgeMissingGrace
	if grace < 0 {
		grace = 5 * time.Minute
	}
	terminal := err == nil && updated.NotFoundConfirmations >= 2 && !time.Now().UTC().Before(acceptedAt.Add(grace))
	if terminal {
		updated.Status = PurgeReceiptIndeterminate
		updated.IndeterminateRequestID = requestID
		updated.IndeterminateObservedAt = observedAt
	}
	return updated, terminal
}

func copyEdgeOneProviderTimes(receipt *PurgeReceipt, task *teo.Task) error {
	if task.CreateTime != nil {
		receipt.ProviderCreatedAt = strings.TrimSpace(*task.CreateTime)
	}
	if task.UpdateTime != nil {
		receipt.ProviderUpdatedAt = strings.TrimSpace(*task.UpdateTime)
	}
	for _, value := range []string{receipt.ProviderCreatedAt, receipt.ProviderUpdatedAt} {
		if value != "" && (len(value) > 256 || strings.ContainsAny(value, "\x00\r\n\t")) {
			return errors.New("EdgeOne purge task returned an unsafe provider time")
		}
	}
	return nil
}

func (c *COSEdgeOneHTTP) EdgeOneOpen(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	return openCDN(ctx, c.client, c.cdnBase, rawURL, c.basic)
}

type rejectRedirectRoundTripper struct{ base http.RoundTripper }

func (t rejectRedirectRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		response.Body.Close()
		return nil, errors.New("Tencent SDK redirect refused")
	}
	return bufferBoundedHTTPResponse(response, 1<<20)
}

func stringPointer(value string) *string { return &value }

func int64Pointer(value int64) *int64 { return &value }

func stringPointers(values []string) []*string {
	result := make([]*string, len(values))
	for index := range values {
		result[index] = stringPointer(values[index])
	}
	return result
}
