package compat_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/publish"
)

const (
	realCloudR2StorageOptInEnv       = "SOW_RUN_REAL_CLOUD_R2_STORAGE"
	realCloudR2StorageConfirmEnv     = "SOW_REAL_CLOUD_R2_STORAGE_CONFIRM"
	realCloudR2StorageConfirmPrefix  = "I-CONFIRM-MUTATING-ONLY-THE-PINNED-EMPTY-R2-BUCKET"
	realCloudR2StorageOperationLabel = "create-only+cas-race+head+stream-get+main-beta-custom-domain+copy-source-cas+delete-capability-probe+identity-bound-unconditional-cleanup+custom-domain-post-delete-observation"
)

// TestRealCloudR2StorageProtocol is the storage and anonymous raw custom-domain
// portion of POC-06. It intentionally does not construct a Cloudflare
// control-plane, Worker, or purge client. The exact provider-readiness registry
// entry, an exact bucket-bound confirmation, and an empty-bucket observation
// are all required before the first mutation. Cleanup is deliberately
// unconditional because R2 does not expose conditional DeleteObject; it is
// restricted to exact run-owned keys whose current bodies match the run's
// digest allowlist. Foreign bytes are never removed. Post-delete custom-domain
// HITs are accepted only as bounded negative capability evidence when their
// bytes, ETag, length, Age and max-age still bind the exact run-owned object.
func TestRealCloudR2StorageProtocol(t *testing.T) {
	if os.Getenv(realCloudR2StorageOptInEnv) != "1" {
		t.Skip("set SOW_RUN_REAL_CLOUD_R2_STORAGE=1 to test the pinned empty non-production R2 bucket")
	}
	resource, environment, err := loadRealCloudProviderReadinessSelection("cloudflare", os.Getenv)
	if err != nil {
		t.Fatalf("R2 storage resource gate failed before credentials or networking: %v", err)
	}
	if resource.Cloudflare == nil {
		t.Fatal("R2 storage resource gate selected no Cloudflare identity")
	}
	expectedConfirmation := realCloudR2StorageConfirmation(*resource.Cloudflare)
	if os.Getenv(realCloudR2StorageConfirmEnv) != expectedConfirmation {
		t.Fatalf("%s must exactly bind the pinned R2 endpoint and bucket", realCloudR2StorageConfirmEnv)
	}
	runID := strings.TrimSpace(os.Getenv(realCloudRunIDEnv))
	if !validRealCloudRunID(runID) {
		t.Fatalf("%s must be a 22-64 character route-safe nonsecret identifier", realCloudRunIDEnv)
	}
	storageRaw := os.Getenv(realCloudStorageCredentialCF)
	secretFragments := realCloudScopedSecretFragments(storageRaw)
	storage, err := decodeRealCloudProviderSecret[realCloudStorageSecret](storageRaw)
	if err != nil || strings.TrimSpace(storage.AccessKeyID) == "" || strings.TrimSpace(storage.SecretAccessKey) == "" {
		t.Fatal("Cloudflare R2 storage credential is absent or invalid")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	result, err := exerciseRealCloudR2StorageProtocol(ctx, environment, storage, runID)
	if err != nil {
		assertNoRealCloudSecret(t, "real R2 storage protocol error", []byte(err.Error()), secretFragments)
		t.Fatalf("real R2 storage protocol failed: %v", err)
	}
	assertNoRealCloudSecret(t, "real R2 storage protocol evidence", []byte(result), secretFragments)
	t.Log(result)
}

func realCloudR2StorageConfirmation(resource realCloudCloudflareReadinessResource) string {
	return realCloudR2StorageConfirmPrefix + ":" + resource.R2Endpoint + "/" + resource.R2Bucket
}

type realCloudR2OwnedIdentity struct {
	Size   int64
	SHA256 string
}

type realCloudR2OwnedObjects map[string]map[realCloudR2OwnedIdentity]struct{}

func (owned realCloudR2OwnedObjects) allow(key string, body []byte) {
	if owned[key] == nil {
		owned[key] = make(map[realCloudR2OwnedIdentity]struct{})
	}
	owned[key][realCloudR2OwnedIdentity{Size: int64(len(body)), SHA256: realCloudLowerSHA256(body)}] = struct{}{}
}

func exerciseRealCloudR2StorageProtocol(
	ctx context.Context,
	environment realCloudEnvironment,
	storage realCloudStorageSecret,
	runID string,
) (evidence string, resultErr error) {
	client, err := publish.NewR2CloudflareControlHTTP(publish.R2CloudflareControlHTTPConfig{
		Bucket: environment.CFR2Bucket, ObjectBaseURL: realCloudProviderBucketBaseURL(environment.CFR2Endpoint, environment.CFR2Bucket),
		Credentials: publish.S3Credentials{
			AccessKeyID: storage.AccessKeyID, SecretAccessKey: storage.SecretAccessKey,
			SessionToken: storage.SessionToken, Region: "auto",
		},
		Client: realCloudProviderHTTPClient(),
	})
	if err != nil {
		return "", errors.New("construct R2 storage-only client")
	}
	before, err := listAllRealCloudR2Objects(ctx, client)
	if err != nil {
		return "", fmt.Errorf("list pinned R2 bucket before mutation: %w", err)
	}
	if len(before) != 0 {
		return "", fmt.Errorf("pinned R2 bucket is not empty before mutation: observed %d objects", len(before))
	}

	prefix := ".sow/acceptance/r2-storage/" + runID + "/"
	leaseKey := prefix + "lease.json"
	objectKey := prefix + "object.bin"
	copyKey := prefix + "copy.bin"
	staleCopyKey := prefix + "stale-copy.bin"
	owned := make(realCloudR2OwnedObjects)
	defer func() {
		// Cleanup must survive the protocol deadline or caller cancellation. It
		// receives no broader authority: the exact run-owned identity allowlist
		// and lease fence are still enforced for every unconditional DELETE.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		cleanupErr := cleanupRealCloudR2OwnedObjects(cleanupCtx, client, owned, leaseKey)
		remaining, listErr := listAllRealCloudR2Objects(cleanupCtx, client)
		if listErr == nil && len(remaining) != 0 {
			listErr = fmt.Errorf("pinned R2 bucket is not empty after cleanup: observed %d objects", len(remaining))
		}
		resultErr = errors.Join(resultErr, cleanupErr, listErr)
	}()

	leaseBody := []byte(`{"schema":"sow-real-r2-storage-lease/v1","run_id":"` + runID + `"}`)
	owned.allow(leaseKey, leaseBody)
	leaseETag, err := client.R2Put(ctx, leaseKey, bytes.NewReader(leaseBody), int64(len(leaseBody)), realCloudLowerSHA256(leaseBody), publish.R2PutCondition{IfNoneMatch: true})
	if err != nil {
		return "", fmt.Errorf("create R2 storage acceptance lease: %w", err)
	}
	if strings.TrimSpace(leaseETag) == "" {
		return "", errors.New("R2 storage acceptance lease returned no ETag")
	}

	firstBody := []byte("sow-real-r2-storage-first\n" + runID + "\n")
	secondBody := []byte("sow-real-r2-storage-second\n" + runID + "\n")
	thirdBody := []byte("sow-real-r2-storage-third\n" + runID + "\n")
	owned.allow(objectKey, firstBody)
	owned.allow(objectKey, secondBody)
	owned.allow(objectKey, thirdBody)
	firstETag, err := client.R2Put(ctx, objectKey, bytes.NewReader(firstBody), int64(len(firstBody)), realCloudLowerSHA256(firstBody), publish.R2PutCondition{IfNoneMatch: true})
	if err != nil {
		return "", fmt.Errorf("R2 create-only object: %w", err)
	}
	if _, err := client.R2Put(ctx, objectKey, bytes.NewReader(secondBody), int64(len(secondBody)), realCloudLowerSHA256(secondBody), publish.R2PutCondition{IfNoneMatch: true}); !errors.Is(err, publish.ErrAlreadyExists) {
		return "", fmt.Errorf("R2 duplicate create-only result = %v, want ErrAlreadyExists", err)
	}
	if _, err := client.R2Put(ctx, objectKey, bytes.NewReader(secondBody), int64(len(secondBody)), realCloudLowerSHA256(secondBody), publish.R2PutCondition{IfMatch: `"sow-intentionally-stale-etag"`}); !errors.Is(err, publish.ErrConflict) {
		return "", fmt.Errorf("R2 stale If-Match update result = %v, want ErrConflict", err)
	}
	if err := requireRealCloudR2Object(ctx, client, objectKey, firstBody, firstETag); err != nil {
		return "", fmt.Errorf("R2 create/stale-write preservation: %w", err)
	}

	type casResult struct {
		body []byte
		etag string
		err  error
	}
	start := make(chan struct{})
	results := make(chan casResult, 2)
	for _, body := range [][]byte{secondBody, thirdBody} {
		body := append([]byte(nil), body...)
		go func() {
			<-start
			etag, putErr := client.R2Put(ctx, objectKey, bytes.NewReader(body), int64(len(body)), realCloudLowerSHA256(body), publish.R2PutCondition{IfMatch: firstETag})
			results <- casResult{body: body, etag: etag, err: putErr}
		}()
	}
	close(start)
	firstRace := <-results
	secondRace := <-results
	race := []casResult{firstRace, secondRace}
	var winner casResult
	successes, conflicts := 0, 0
	for _, result := range race {
		switch {
		case result.err == nil:
			successes++
			winner = result
		case errors.Is(result.err, publish.ErrConflict):
			conflicts++
		default:
			return "", fmt.Errorf("R2 concurrent CAS returned unexpected result: %w", result.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		return "", fmt.Errorf("R2 concurrent CAS successes=%d conflicts=%d, want 1/1", successes, conflicts)
	}
	if err := requireRealCloudR2Object(ctx, client, objectKey, winner.body, winner.etag); err != nil {
		return "", fmt.Errorf("R2 concurrent CAS winner: %w", err)
	}
	customDomainPresent, err := exerciseRealCloudR2CustomDomainDataPlane(ctx, realCloudProviderHTTPClient(), environment, objectKey, winner.body, winner.etag, true)
	if err != nil {
		return "", fmt.Errorf("R2 main/beta custom-domain current object: %w", err)
	}

	owned.allow(staleCopyKey, winner.body)
	if _, err := client.R2Copy(ctx, staleCopyKey, objectKey, int64(len(winner.body)), realCloudLowerSHA256(winner.body), `"sow-intentionally-stale-source-etag"`); !errors.Is(err, publish.ErrConflict) {
		return "", fmt.Errorf("R2 stale source CopyObject result = %v, want ErrConflict", err)
	}
	staleCopy, err := client.R2GetControl(ctx, staleCopyKey)
	if err != nil || staleCopy.Exists {
		return "", errors.New("R2 stale source CopyObject created a destination")
	}

	owned.allow(copyKey, winner.body)
	copyETag, err := client.R2Copy(ctx, copyKey, objectKey, int64(len(winner.body)), realCloudLowerSHA256(winner.body), winner.etag)
	if err != nil {
		return "", fmt.Errorf("R2 conditional server-side copy: %w", err)
	}
	if err := requireRealCloudR2Object(ctx, client, copyKey, winner.body, copyETag); err != nil {
		return "", fmt.Errorf("R2 copied object: %w", err)
	}
	conditionalDeleteSupported := false
	staleDeleteErr := client.R2Delete(ctx, copyKey, `"sow-intentionally-stale-delete-etag"`)
	afterStaleDelete, getErr := client.R2GetControl(ctx, copyKey)
	switch {
	case errors.Is(staleDeleteErr, publish.ErrConflict) && getErr == nil && afterStaleDelete.Exists:
		conditionalDeleteSupported = true
		if err := requireRealCloudR2Object(ctx, client, copyKey, winner.body, copyETag); err != nil {
			return "", fmt.Errorf("R2 stale-delete preservation: %w", err)
		}
		if err := client.R2Delete(ctx, copyKey, copyETag); err != nil {
			return "", fmt.Errorf("R2 exact conditional delete: %w", err)
		}
	case staleDeleteErr == nil && getErr == nil && !afterStaleDelete.Exists:
		// Cloudflare's S3 compatibility contract does not advertise conditional
		// DeleteObject. This is the expected negative capability evidence: the
		// deliberately wrong ETag removed only this run-owned probe object.
	default:
		return "", errors.Join(staleDeleteErr, getErr, errors.New("R2 conditional-delete probe returned an indeterminate result"))
	}

	if err := cleanupRealCloudR2OwnedObject(ctx, client, owned, leaseKey, objectKey); err != nil {
		return "", fmt.Errorf("R2 identity-bound unconditional cleanup of CAS winner: %w", err)
	}
	customDomainAfterDelete, err := exerciseRealCloudR2CustomDomainDataPlane(ctx, realCloudProviderHTTPClient(), environment, objectKey, winner.body, winner.etag, false)
	if err != nil {
		return "", fmt.Errorf("R2 main/beta custom-domain post-delete observation: %w", err)
	}
	if err := cleanupRealCloudR2OwnedObject(ctx, client, owned, leaseKey, leaseKey); err != nil {
		return "", fmt.Errorf("R2 identity-bound unconditional cleanup of acceptance lease: %w", err)
	}

	return fmt.Sprintf("real R2 storage PASS run=%s operations=%s conditional_delete=%t custom_domain_present=%s custom_domain_after_delete=%s empty_before=true empty_after=true", runID, realCloudR2StorageOperationLabel, conditionalDeleteSupported, customDomainPresent, customDomainAfterDelete), nil
}

type realCloudR2CustomDomainObservation struct {
	State       string
	CacheStatus string
	Colo        string
	MaxAge      int64
}

type realCloudR2RoundTripFunc func(*http.Request) (*http.Response, error)

func (function realCloudR2RoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestRealCloudR2CustomDomainProbeContract(t *testing.T) {
	body := []byte("real-r2-custom-domain-probe\n")
	etag := `"real-r2-custom-domain-etag"`
	mode := "present"
	hosts := make(map[string]int)
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport: realCloudR2RoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodGet || request.Header.Get("Accept-Encoding") != "identity" ||
				request.Header.Get("Cache-Control") != "no-store, no-cache, max-age=0" ||
				request.Header.Get("Pragma") != "no-cache" || request.Header.Get("Authorization") != "" ||
				request.URL.Path != "/.sow/acceptance/r2-storage/sow-r2-contract-20260719-01/object.bin" {
				return nil, errors.New("custom-domain request contract differs")
			}
			hosts[request.URL.Host]++
			header := make(http.Header)
			header.Set("CF-Ray", "0123456789abcdef-SJC")
			header.Set("CF-Cache-Status", "DYNAMIC")
			status := http.StatusOK
			responseBody := body
			contentLength := int64(len(body))
			switch mode {
			case "present":
				header.Set("ETag", etag)
			case "absent":
				status = http.StatusNotFound
				responseBody = []byte("not found")
				contentLength = int64(len(responseBody))
			case "stale":
				header.Set("CF-Cache-Status", "HIT")
				header.Set("Cache-Control", "max-age=1800")
				header.Set("Age", "60")
				header.Set("ETag", etag)
			}
			return &http.Response{
				StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(responseBody)),
				ContentLength: contentLength, Request: request,
			}, nil
		}),
	}
	environment := realCloudEnvironment{
		CFCDNBase:     realCloudOwnerDesignatedCFCDNBase,
		CFBetaCDNBase: realCloudOwnerDesignatedCFBetaBase,
	}
	key := ".sow/acceptance/r2-storage/sow-r2-contract-20260719-01/object.bin"
	evidence, err := exerciseRealCloudR2CustomDomainDataPlane(t.Context(), client, environment, key, body, etag, true)
	if err != nil || evidence != "main=CURRENT-DYNAMIC/SJC,beta=CURRENT-DYNAMIC/SJC" || hosts["pro.pigsty.io"] != 1 || hosts["beta.pro.pigsty.io"] != 1 {
		t.Fatalf("present custom-domain contract evidence=%q hosts=%v err=%v", evidence, hosts, err)
	}
	mode = "absent"
	evidence, err = exerciseRealCloudR2CustomDomainDataPlane(t.Context(), client, environment, key, body, etag, false)
	if err != nil || evidence != "main=ABSENT-DYNAMIC/SJC,beta=ABSENT-DYNAMIC/SJC" || hosts["pro.pigsty.io"] != 2 || hosts["beta.pro.pigsty.io"] != 2 {
		t.Fatalf("absent custom-domain contract evidence=%q hosts=%v err=%v", evidence, hosts, err)
	}
	mode = "stale"
	evidence, err = exerciseRealCloudR2CustomDomainDataPlane(t.Context(), client, environment, key, body, etag, false)
	if err != nil || evidence != "main=STALE-HIT/SJC/max-age=1800,beta=STALE-HIT/SJC/max-age=1800" || hosts["pro.pigsty.io"] != 3 || hosts["beta.pro.pigsty.io"] != 3 {
		t.Fatalf("stale custom-domain contract evidence=%q hosts=%v err=%v", evidence, hosts, err)
	}

	networkCalls := 0
	refusingClient := &http.Client{Transport: realCloudR2RoundTripFunc(func(*http.Request) (*http.Response, error) {
		networkCalls++
		return nil, errors.New("must not be called")
	})}
	mutated := environment
	mutated.CFCDNBase = "https://repo.pigsty.io"
	if _, err := exerciseRealCloudR2CustomDomainDataPlane(t.Context(), refusingClient, mutated, key, body, etag, true); err == nil || networkCalls != 0 {
		t.Fatalf("unpinned custom-domain tuple reached networking calls=%d err=%v", networkCalls, err)
	}
}

func TestRealCloudR2CustomDomainProbeRejectsCachedOrRedirectedResponse(t *testing.T) {
	body := []byte("real-r2-custom-domain-probe\n")
	etag := `"real-r2-custom-domain-etag"`
	for _, testCase := range []struct {
		name   string
		status int
		cache  string
	}{
		{name: "shared cache hit", status: http.StatusOK, cache: "HIT"},
		{name: "redirect", status: http.StatusFound, cache: "DYNAMIC"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			client := &http.Client{
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
				Transport: realCloudR2RoundTripFunc(func(request *http.Request) (*http.Response, error) {
					header := make(http.Header)
					header.Set("CF-Ray", "0123456789abcdef-SJC")
					header.Set("CF-Cache-Status", testCase.cache)
					header.Set("ETag", etag)
					if testCase.status >= 300 && testCase.status < 400 {
						header.Set("Location", "https://other.example.invalid/object.bin")
					}
					return &http.Response{
						StatusCode: testCase.status, Header: header, Body: io.NopCloser(bytes.NewReader(body)),
						ContentLength: int64(len(body)), Request: request,
					}, nil
				}),
			}
			if _, err := probeRealCloudR2CustomDomain(t.Context(), client, "https://pro.pigsty.io", "object.bin", body, etag, true); err == nil {
				t.Fatal("unsafe custom-domain response was accepted")
			}
		})
	}
}

func exerciseRealCloudR2CustomDomainDataPlane(
	ctx context.Context,
	client *http.Client,
	environment realCloudEnvironment,
	key string,
	expected []byte,
	expectedETag string,
	present bool,
) (string, error) {
	if environment.CFCDNBase != realCloudOwnerDesignatedCFCDNBase || environment.CFBetaCDNBase != realCloudOwnerDesignatedCFBetaBase {
		return "", errors.New("R2 custom-domain probe is outside the exact owner-designated main/beta tuple")
	}
	if client == nil || !validRealCloudR2CustomDomainProbeKey(key) {
		return "", errors.New("R2 custom-domain probe input is invalid")
	}
	if len(expected) == 0 || strings.TrimSpace(expectedETag) == "" {
		return "", errors.New("R2 custom-domain expected identity is inconsistent")
	}

	results := make([]string, 0, 2)
	for _, target := range []struct {
		label string
		base  string
	}{{label: "main", base: environment.CFCDNBase}, {label: "beta", base: environment.CFBetaCDNBase}} {
		observation, err := waitRealCloudR2CustomDomain(ctx, client, target.base, key, expected, expectedETag, present)
		if err != nil {
			return "", fmt.Errorf("%s: %w", target.label, err)
		}
		value := observation.State + "-" + observation.CacheStatus + "/" + observation.Colo
		if observation.MaxAge > 0 {
			value += "/max-age=" + strconv.FormatInt(observation.MaxAge, 10)
		}
		results = append(results, target.label+"="+value)
	}
	return strings.Join(results, ","), nil
}

func validRealCloudR2CustomDomainProbeKey(key string) bool {
	const prefix = ".sow/acceptance/r2-storage/"
	const suffix = "/object.bin"
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
		return false
	}
	runID := strings.TrimSuffix(strings.TrimPrefix(key, prefix), suffix)
	return validRealCloudRunID(runID) && key == prefix+runID+suffix
}

func waitRealCloudR2CustomDomain(
	ctx context.Context,
	client *http.Client,
	base, key string,
	expected []byte,
	expectedETag string,
	present bool,
) (realCloudR2CustomDomainObservation, error) {
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for {
		observation, err := probeRealCloudR2CustomDomain(ctx, client, base, key, expected, expectedETag, present)
		if err == nil {
			return observation, nil
		}
		lastErr = err
		if !time.Now().Before(deadline) {
			return realCloudR2CustomDomainObservation{}, lastErr
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return realCloudR2CustomDomainObservation{}, errors.Join(lastErr, context.Cause(ctx))
		case <-timer.C:
		}
	}
}

func probeRealCloudR2CustomDomain(
	ctx context.Context,
	client *http.Client,
	base, key string,
	expected []byte,
	expectedETag string,
	present bool,
) (realCloudR2CustomDomainObservation, error) {
	rawURL := strings.TrimSuffix(base, "/") + "/" + key
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return realCloudR2CustomDomainObservation{}, errors.New("construct anonymous custom-domain request")
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-store, no-cache, max-age=0")
	request.Header.Set("Pragma", "no-cache")
	response, err := client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return realCloudR2CustomDomainObservation{}, errors.Join(err, errors.New("anonymous custom-domain request failed"))
	}
	maximum := int64(64<<10 + 1)
	if present && int64(len(expected))+1 < maximum {
		maximum = int64(len(expected)) + 1
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximum))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return realCloudR2CustomDomainObservation{}, errors.Join(readErr, closeErr)
	}
	if response.Request == nil || response.Request.URL.String() != rawURL || response.Header.Get("Location") != "" ||
		response.StatusCode >= 300 && response.StatusCode < 400 || response.Header.Get("Set-Cookie") != "" ||
		response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" ||
		response.Header.Get("X-SOW-Edge-Contract") != "" {
		return realCloudR2CustomDomainObservation{}, errors.New("anonymous custom-domain response changed route, encoding, cookie, or raw-R2 boundary")
	}
	_, colo, err := realEdgeResponseRequestID("cloudflare", response.Header)
	if err != nil {
		return realCloudR2CustomDomainObservation{}, err
	}
	cacheStatus := strings.TrimSpace(response.Header.Get("CF-Cache-Status"))
	if present {
		switch cacheStatus {
		case "DYNAMIC", "BYPASS", "MISS", "EXPIRED", "REVALIDATED":
		default:
			return realCloudR2CustomDomainObservation{}, fmt.Errorf("anonymous current-object no-store response has unsafe cache status %q", cacheStatus)
		}
		if response.StatusCode != http.StatusOK || !bytes.Equal(body, expected) || response.Header.Get("ETag") != expectedETag ||
			response.ContentLength >= 0 && response.ContentLength != int64(len(expected)) {
			return realCloudR2CustomDomainObservation{}, errors.New("anonymous custom-domain body, status, length, or ETag differs from current R2 identity")
		}
		return realCloudR2CustomDomainObservation{State: "CURRENT", CacheStatus: cacheStatus, Colo: colo}, nil
	}
	if len(body) > 64<<10 {
		return realCloudR2CustomDomainObservation{}, errors.New("anonymous custom-domain post-delete response exceeds the bounded audit size")
	}
	if response.StatusCode == http.StatusNotFound {
		switch cacheStatus {
		case "DYNAMIC", "BYPASS", "MISS", "EXPIRED", "REVALIDATED":
			return realCloudR2CustomDomainObservation{State: "ABSENT", CacheStatus: cacheStatus, Colo: colo}, nil
		case "HIT", "STALE", "UPDATING":
			maxAge, err := realCloudR2CacheMaxAge(response.Header)
			if err != nil {
				return realCloudR2CustomDomainObservation{}, err
			}
			return realCloudR2CustomDomainObservation{State: "ABSENT", CacheStatus: cacheStatus, Colo: colo, MaxAge: maxAge}, nil
		default:
			return realCloudR2CustomDomainObservation{}, fmt.Errorf("anonymous post-delete 404 has unsafe cache status %q", cacheStatus)
		}
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, expected) || response.Header.Get("ETag") != expectedETag ||
		response.ContentLength >= 0 && response.ContentLength != int64(len(expected)) {
		return realCloudR2CustomDomainObservation{}, errors.New("anonymous post-delete response is neither absent nor the exact run-owned stale object")
	}
	if cacheStatus != "HIT" && cacheStatus != "STALE" && cacheStatus != "UPDATING" {
		return realCloudR2CustomDomainObservation{}, fmt.Errorf("anonymous exact post-delete object has non-cache status %q", cacheStatus)
	}
	maxAge, err := realCloudR2CacheMaxAge(response.Header)
	if err != nil {
		return realCloudR2CustomDomainObservation{}, err
	}
	return realCloudR2CustomDomainObservation{State: "STALE", CacheStatus: cacheStatus, Colo: colo, MaxAge: maxAge}, nil
}

func realCloudR2CacheMaxAge(header http.Header) (int64, error) {
	ageValues := header.Values("Age")
	if len(ageValues) != 1 || strings.TrimSpace(ageValues[0]) != ageValues[0] {
		return 0, errors.New("cached custom-domain response has no canonical Age")
	}
	age, err := strconv.ParseInt(ageValues[0], 10, 64)
	if err != nil || age < 0 || age > 24*60*60 {
		return 0, errors.New("cached custom-domain response Age is invalid")
	}
	cacheControlValues := header.Values("Cache-Control")
	if len(cacheControlValues) == 0 {
		return 0, errors.New("cached custom-domain response has no Cache-Control lifetime")
	}
	maxAge := int64(-1)
	for _, directive := range strings.Split(strings.ToLower(strings.Join(cacheControlValues, ",")), ",") {
		directive = strings.TrimSpace(directive)
		if directive == "private" || directive == "no-store" || directive == "no-cache" {
			return 0, errors.New("cached custom-domain response has a non-cacheable directive")
		}
		if !strings.HasPrefix(directive, "max-age=") {
			continue
		}
		if maxAge >= 0 {
			return 0, errors.New("cached custom-domain response has duplicate max-age")
		}
		maxAge, err = strconv.ParseInt(strings.TrimPrefix(directive, "max-age="), 10, 64)
		if err != nil {
			return 0, errors.New("cached custom-domain response max-age is invalid")
		}
	}
	if maxAge <= 0 || maxAge > 24*60*60 || age > maxAge {
		return 0, errors.New("cached custom-domain response lifetime is absent, expired, or unbounded")
	}
	return maxAge, nil
}

func requireRealCloudR2Object(ctx context.Context, client *publish.R2CloudflareControlHTTP, key string, expected []byte, expectedETag string) error {
	control, err := client.R2GetControl(ctx, key)
	if err != nil {
		return err
	}
	if !control.Exists || control.ETag != expectedETag || !bytes.Equal(control.Body, expected) {
		return errors.New("control GET differs from the expected object bytes or ETag")
	}
	info, err := client.R2Head(ctx, key)
	if err != nil {
		return err
	}
	if !info.Exists || info.ETag != expectedETag || info.Size != int64(len(expected)) || info.SHA256 != realCloudLowerSHA256(expected) {
		return errors.New("HEAD differs from the expected size, digest, or ETag")
	}
	content, err := client.R2OpenObject(ctx, key)
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(io.LimitReader(content.Body, int64(len(expected))+1))
	closeErr := content.Body.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if content.Info != info || !bytes.Equal(body, expected) {
		return errors.New("stream GET differs from HEAD or expected bytes")
	}
	return nil
}

func listAllRealCloudR2Objects(ctx context.Context, client *publish.R2CloudflareControlHTTP) ([]publish.ListedObject, error) {
	var result []publish.ListedObject
	continuation := ""
	seen := make(map[string]struct{})
	for pageNumber := 0; pageNumber < 4096; pageNumber++ {
		page, err := client.R2ListObjectsV2(ctx, continuation)
		if err != nil {
			return nil, err
		}
		result = append(result, page.Objects...)
		if len(result) > 1_000_000 {
			return nil, errors.New("R2 acceptance inventory exceeds the safety limit")
		}
		if page.NextContinuationToken == "" {
			sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
			return result, nil
		}
		if _, duplicate := seen[page.NextContinuationToken]; duplicate {
			return nil, errors.New("R2 acceptance inventory continuation loop")
		}
		seen[page.NextContinuationToken] = struct{}{}
		continuation = page.NextContinuationToken
	}
	return nil, errors.New("R2 acceptance inventory exceeded the page limit")
}

func proveRealCloudR2OwnedObject(
	ctx context.Context,
	client *publish.R2CloudflareControlHTTP,
	owned realCloudR2OwnedObjects,
	key string,
) (publish.ObjectInfo, bool, error) {
	allowed := owned[key]
	if len(allowed) == 0 {
		return publish.ObjectInfo{}, false, fmt.Errorf("key %s is outside the run-owned cleanup allowlist", key)
	}
	maximumSize := int64(0)
	for identity := range allowed {
		if identity.Size > maximumSize {
			maximumSize = identity.Size
		}
	}
	first, firstSHA, exists, err := readRealCloudObjectIdentity(ctx, key, maximumSize, client.R2Head, client.R2OpenObject)
	if err != nil || !exists {
		return first, exists, err
	}
	if _, ok := allowed[realCloudR2OwnedIdentity{Size: first.Size, SHA256: firstSHA}]; !ok {
		return publish.ObjectInfo{}, false, fmt.Errorf("refuse to delete foreign bytes at %s", key)
	}
	second, secondSHA, exists, err := readRealCloudObjectIdentity(ctx, key, maximumSize, client.R2Head, client.R2OpenObject)
	if err != nil || !exists || second != first || secondSHA != firstSHA {
		return publish.ObjectInfo{}, false, errors.Join(err, fmt.Errorf("run-owned object %s changed between consecutive identity proofs", key))
	}
	return second, true, nil
}

func cleanupRealCloudR2OwnedObject(
	ctx context.Context,
	client *publish.R2CloudflareControlHTTP,
	owned realCloudR2OwnedObjects,
	leaseKey, key string,
) error {
	first, exists, err := proveRealCloudR2OwnedObject(ctx, client, owned, key)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if key != leaseKey {
		if _, exists, err := proveRealCloudR2OwnedObject(ctx, client, owned, leaseKey); err != nil || !exists {
			return errors.Join(err, errors.New("run-owned cleanup lease is absent or changed before deletion"))
		}
		current, exists, err := proveRealCloudR2OwnedObject(ctx, client, owned, key)
		if err != nil || !exists || current != first {
			return errors.Join(err, fmt.Errorf("run-owned object %s changed across its lease proof", key))
		}
	}
	removeErr := client.R2DeleteCheckpointFenced(ctx, key)
	after, headErr := client.R2Head(ctx, key)
	if headErr != nil || after.Exists {
		return errors.Join(removeErr, headErr, fmt.Errorf("identity-bound cleanup did not prove %s absent", key))
	}
	if key != leaseKey {
		if _, exists, err := proveRealCloudR2OwnedObject(ctx, client, owned, leaseKey); err != nil || !exists {
			return errors.Join(err, errors.New("run-owned cleanup lease is absent or changed after deletion"))
		}
	}
	return nil
}

func cleanupRealCloudR2OwnedObjects(ctx context.Context, client *publish.R2CloudflareControlHTTP, owned realCloudR2OwnedObjects, leaseKey string) error {
	keys := make([]string, 0, len(owned))
	for key := range owned {
		if key != leaseKey {
			keys = append(keys, key)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	var resultErr error
	for _, key := range keys {
		if err := cleanupRealCloudR2OwnedObject(ctx, client, owned, leaseKey, key); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("cleanup %s: %w", key, err))
		}
	}
	// Retain the lease whenever any owned payload could not be proven absent;
	// it is the durable signal that this run still owns cleanup work.
	if resultErr != nil {
		return resultErr
	}
	if err := cleanupRealCloudR2OwnedObject(ctx, client, owned, leaseKey, leaseKey); err != nil {
		return fmt.Errorf("cleanup lease %s: %w", leaseKey, err)
	}
	return resultErr
}
