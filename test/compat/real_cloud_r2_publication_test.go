package compat_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/cli"
	"github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

const (
	realCloudR2PublicationOptInEnv      = "SOW_RUN_REAL_CLOUD_R2_PUBLICATION_STORAGE"
	realCloudR2PublicationConfirmEnv    = "SOW_REAL_CLOUD_R2_PUBLICATION_STORAGE_CONFIRM"
	realCloudR2PublicationConfirmPrefix = "I-CONFIRM-MUTATING-ONLY-THE-PINNED-EMPTY-R2-BUCKET-FOR-PUBLICATION"
	realCloudR2PublicationRepositoryID  = "r2-publication-acceptance"
	realCloudR2PublicationLocalToken    = "sow-local-purge-adapter-token"
	realCloudR2PublicationMainBase      = "https://r2-publication-main.test"
	realCloudR2PublicationBetaBase      = "https://r2-publication-beta.test"
)

var realCloudR2PublicationDefaultTransportMu sync.Mutex

// TestRealCloudR2PublicationStorageTransaction runs the actual product CLI and
// the actual R2 data plane while replacing only the CDN read and Cloudflare
// purge control plane with process-local protocol adapters. It is intentionally
// not evidence for a real Cloudflare purge, custom domain, Worker, or Zone PoC.
func TestRealCloudR2PublicationStorageTransaction(t *testing.T) {
	if os.Getenv(realCloudR2PublicationOptInEnv) != "1" {
		t.Skip("set SOW_RUN_REAL_CLOUD_R2_PUBLICATION_STORAGE=1 to test the product publication transaction against the pinned empty non-production R2 bucket")
	}
	realCloudR2PublicationDefaultTransportMu.Lock()
	defer realCloudR2PublicationDefaultTransportMu.Unlock()
	resource, environment, err := loadRealCloudProviderReadinessSelection("cloudflare", os.Getenv)
	if err != nil {
		t.Fatalf("R2 publication resource gate failed before credentials or networking: %v", err)
	}
	if resource.Cloudflare == nil {
		t.Fatal("R2 publication resource gate selected no Cloudflare identity")
	}
	if os.Getenv(realCloudNonProductionEnv) != realCloudNonProductionPhrase {
		t.Fatalf("%s must exactly confirm dedicated disposable non-production resources", realCloudNonProductionEnv)
	}
	expectedConfirmation := realCloudR2PublicationConfirmPrefix + ":" + resource.Cloudflare.R2Endpoint + "/" + resource.Cloudflare.R2Bucket
	if os.Getenv(realCloudR2PublicationConfirmEnv) != expectedConfirmation {
		t.Fatalf("%s must exactly bind the pinned R2 endpoint and bucket", realCloudR2PublicationConfirmEnv)
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

	// Never inherit a real Cloudflare API token. The production CLI resolves a
	// syntactically valid local-only value, and the network firewall below
	// consumes the corresponding request without opening a socket.
	t.Setenv(realCloudCDNCredentialCF, `{"api_token":"`+realCloudR2PublicationLocalToken+`"}`)
	t.Setenv(realCloudEnvironmentNames["CFZoneID"], environment.CFZoneID)

	objectBaseURL := realCloudProviderBucketBaseURL(environment.CFR2Endpoint, environment.CFR2Bucket)
	r2URL, err := url.Parse(objectBaseURL)
	if err != nil {
		t.Fatal("parse R2 publication bucket URL")
	}
	directTransport, err := newRealCloudR2PublicationDirectTransport(r2URL)
	if err != nil {
		t.Fatalf("construct proxy-free R2 publication transport: %v", err)
	}
	defer directTransport.CloseIdleConnections()
	credentials := publish.S3Credentials{
		AccessKeyID: storage.AccessKeyID, SecretAccessKey: storage.SecretAccessKey,
		SessionToken: storage.SessionToken, Region: "auto",
	}
	directClient := realCloudProviderHTTPClient()
	directClient.Transport = directTransport
	rawControl, err := publish.NewR2CloudflareControlHTTP(publish.R2CloudflareControlHTTPConfig{
		Bucket: environment.CFR2Bucket, ObjectBaseURL: objectBaseURL, Credentials: credentials, Client: directClient,
	})
	if err != nil {
		t.Fatal("construct direct R2 publication storage client")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	before, err := listAllRealCloudR2Objects(ctx, rawControl)
	if err != nil {
		assertNoRealCloudSecret(t, "real R2 publication preflight error", []byte(err.Error()), secretFragments)
		t.Fatalf("list pinned R2 bucket before publication: %v", err)
	}
	if len(before) != 0 {
		t.Fatalf("pinned R2 bucket is not empty before publication: observed %d objects", len(before))
	}

	prefix := "acceptance/r2-publication/" + runID + "/"
	leaseKey := prefix + "lease.json"
	payloadKey := prefix + "latest"
	leaseBody := []byte(`{"schema":"sow-real-r2-publication-lease/v1","run_id":"` + runID + `"}`)
	payload := []byte("sow-real-r2-publication-original\n" + runID + "\n")
	tampered := []byte("sow-real-r2-publication-tampered\n" + runID + "\n")
	owned := make(realCloudR2OwnedObjects)

	localHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.RawQuery != "" || request.Header.Get("Authorization") != "" {
			http.Error(writer, "invalid local CDN verification request", http.StatusBadRequest)
			return
		}
		key := strings.TrimPrefix(request.URL.Path, "/")
		if !validRealCloudR2PublicationCDNKey(key, payloadKey) {
			http.NotFound(writer, request)
			return
		}
		observed, getErr := rawControl.R2GetControl(request.Context(), key)
		if getErr != nil {
			http.Error(writer, "local CDN origin read failed", http.StatusBadGateway)
			return
		}
		if !observed.Exists {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.Header().Set("ETag", observed.ETag)
		writer.Header().Set("Content-Length", strconv.Itoa(len(observed.Body)))
		_, _ = writer.Write(observed.Body)
	})
	localCDN := httptest.NewTLSServer(localHandler)
	defer localCDN.Close()
	localOrigin, err := url.Parse(localCDN.URL)
	if err != nil {
		t.Fatal(err)
	}
	previousDefaultTransport := http.DefaultTransport
	transport := &realCloudR2PublicationTransport{
		r2Host: strings.ToLower(r2URL.Host), zoneID: environment.CFZoneID,
		localHosts: map[string]struct{}{
			strings.TrimPrefix(realCloudR2PublicationMainBase, "https://"): {},
			strings.TrimPrefix(realCloudR2PublicationBetaBase, "https://"): {},
		},
		localBaseURL: realCloudR2PublicationMainBase, localOrigin: localOrigin,
		leaseKey: leaseKey, payloadKey: payloadKey, bucket: environment.CFR2Bucket,
		r2Transport: directTransport, localTransport: localCDN.Client().Transport, r2Probe: rawControl,
		owned: owned, knownBodies: make(map[string][]byte), cleanupCapabilities: make(map[string]realCloudR2PublicationCleanupCapability),
	}
	interceptedClient := realCloudProviderHTTPClient()
	interceptedClient.Transport = transport
	control, err := publish.NewR2CloudflareControlHTTP(publish.R2CloudflareControlHTTPConfig{
		Bucket: environment.CFR2Bucket, ObjectBaseURL: objectBaseURL, Credentials: credentials, Client: interceptedClient,
	})
	if err != nil {
		t.Fatal("construct intercepted R2 publication storage client")
	}
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = previousDefaultTransport }()

	cleanupComplete := false
	defer func() {
		if cleanupComplete {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		var cleanupErr error
		if len(owned[leaseKey]) != 0 {
			cleanupErr = cleanupRealCloudR2OwnedObjectsWithAuthorizer(cleanupCtx, control, owned, leaseKey, transport.authorizeCleanupDelete)
		}
		remaining, listErr := listAllRealCloudR2Objects(cleanupCtx, control)
		if listErr == nil && len(remaining) != 0 {
			listErr = fmt.Errorf("pinned R2 bucket is not empty after deferred publication cleanup: observed %d objects", len(remaining))
		}
		if joined := errors.Join(cleanupErr, listErr); joined != nil {
			assertNoRealCloudSecret(t, "real R2 publication deferred cleanup error", []byte(joined.Error()), secretFragments)
			t.Errorf("real R2 publication deferred cleanup: %v", joined)
		}
	}()

	leaseETag, err := control.R2Put(ctx, leaseKey, bytes.NewReader(leaseBody), int64(len(leaseBody)), realCloudLowerSHA256(leaseBody), publish.R2PutCondition{IfNoneMatch: true})
	if err != nil || strings.TrimSpace(leaseETag) == "" {
		t.Fatalf("create R2 publication acceptance lease: %v", err)
	}
	transport.bindLease(leaseBody, leaseETag)
	leased, err := listAllRealCloudR2Objects(ctx, control)
	if err != nil || len(leased) != 1 || leased[0].Key != leaseKey {
		t.Fatalf("pinned R2 bucket changed while acquiring the publication lease: objects=%v err=%v", leased, err)
	}
	if _, exists, err := proveRealCloudR2OwnedObject(ctx, control, owned, leaseKey); err != nil || !exists {
		t.Fatalf("publication lease lacks exact run-owned identity after acquisition: exists=%t err=%v", exists, err)
	}

	root := realCloudR2FSCKWorkerRoot(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, realCloudR2PublicationConfig(environment, runID, realCloudR2PublicationMainBase, realCloudR2PublicationBetaBase), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "publication-input.bin")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	runCLI := func(expected int, arguments ...string) string {
		t.Helper()
		result, runErr := executeCheckedRealCloudCLI(cli.Main, root, expected, secretFragments, arguments...)
		if runErr != nil {
			t.Fatalf("real R2 publication CLI %v failed: %v output=%q", arguments, runErr, result.output)
		}
		return string(result.output)
	}
	for _, command := range [][]string{
		{"add", input, "--config", configPath, "--repo", realCloudR2PublicationRepositoryID, "--dest", "latest", "--workers", "2"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", realCloudR2PublicationRepositoryID},
	} {
		runCLI(cli.ExitOK, command...)
	}
	publishArguments := []string{"publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", realCloudR2PublicationRepositoryID, "--workers", "2", "--chunk-entries", "2"}
	first := runCLI(cli.ExitOK, publishArguments...)
	if !strings.Contains(first, "target=cf") || !strings.Contains(first, "status=published") {
		t.Fatalf("first R2 publication did not report a committed target: %s", first)
	}
	putsBeforeReplay, purgesBeforeReplay, _, _, unexpectedBeforeReplay := transport.counts()
	replay := runCLI(cli.ExitOK, publishArguments...)
	putsAfterReplay, purgesAfterReplay, _, _, unexpectedAfterReplay := transport.counts()
	if !strings.Contains(replay, "status=unchanged") || putsAfterReplay != putsBeforeReplay || purgesAfterReplay != purgesBeforeReplay {
		t.Fatalf("R2 publication replay was not a physical no-op: puts=%d/%d purges=%d/%d output=%s", putsBeforeReplay, putsAfterReplay, purgesBeforeReplay, purgesAfterReplay, replay)
	}
	if unexpectedBeforeReplay != 0 || unexpectedAfterReplay != 0 {
		t.Fatalf("R2 publication reached an unapproved network host: before=%d after=%d", unexpectedBeforeReplay, unexpectedAfterReplay)
	}

	publication := readRealCloudPublication(t, root, string(publish.TargetCloudflare))
	generationKey, err := publish.GenerationKey(publication.generation.Generation)
	if err != nil {
		t.Fatal(err)
	}
	generationObserved, err := control.R2GetControl(ctx, generationKey)
	if err != nil || !generationObserved.Exists || strings.TrimSpace(generationObserved.ETag) == "" {
		t.Fatalf("read real R2 generation identity: exists=%t etag_present=%t err=%v", generationObserved.Exists, strings.TrimSpace(generationObserved.ETag) != "", err)
	}
	if err := requireRealCloudR2Object(ctx, control, generationKey, publication.generationBody, generationObserved.ETag); err != nil {
		t.Fatalf("real R2 generation object: %v", err)
	}
	checkpointETagBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "checkpoint.etag"))
	if err != nil {
		t.Fatal(err)
	}
	checkpointETag := string(checkpointETagBody)
	if err := requireRealCloudR2Object(ctx, control, publish.CheckpointKey, publication.checkpointBody, checkpointETag); err != nil {
		t.Fatalf("real R2 checkpoint object: %v", err)
	}
	purgeURLs := transport.purgeURLSnapshot()
	if purgesAfterReplay != 1 || !slices.Equal(purgeURLs, publication.plan.PurgeURLs) || len(purgeURLs) != 1 || purgeURLs[0] != realCloudR2PublicationMainBase+"/"+payloadKey {
		t.Fatalf("local purge adapter did not receive the exact minimal pointer set: calls=%d got=%v plan=%v", purgesAfterReplay, purgeURLs, publication.plan.PurgeURLs)
	}
	archiveKey := "objects/sha256/" + realCloudLowerSHA256(payload)
	localKeys, events := transport.networkEvidenceSnapshot()
	slices.Sort(localKeys)
	expectedLocalKeys := []string{archiveKey, payloadKey}
	slices.Sort(expectedLocalKeys)
	if !slices.Equal(localKeys, expectedLocalKeys) {
		t.Fatalf("local CDN verification did not cover the pointer and immutable archive exactly once: got=%v want=%v", localKeys, expectedLocalKeys)
	}
	if err := requireRealCloudR2PublicationEventOrder(events, leaseKey, publish.CheckpointKey, archiveKey, generationKey, payloadKey); err != nil {
		t.Fatalf("R2 publication transaction order: %v events=%v", err, events)
	}

	remoteObjects, err := listAllRealCloudR2Objects(ctx, control)
	if err != nil {
		t.Fatal(err)
	}
	remoteKeys := make([]string, len(remoteObjects))
	for index, object := range remoteObjects {
		remoteKeys[index] = object.Key
	}
	expectedRemoteKeys := []string{leaseKey, payloadKey, archiveKey, generationKey, publish.CheckpointKey}
	slices.Sort(expectedRemoteKeys)
	if !slices.Equal(remoteKeys, expectedRemoteKeys) {
		t.Fatalf("real R2 publication wrote an unexpected object set: got=%v want=%v", remoteKeys, expectedRemoteKeys)
	}
	for _, object := range remoteObjects {
		if _, exists, proveErr := proveRealCloudR2OwnedObject(ctx, control, owned, object.Key); proveErr != nil || !exists {
			t.Fatalf("real R2 publication object %s lacks exact run-owned identity: exists=%t err=%v", object.Key, exists, proveErr)
		}
	}

	adoptArguments := []string{"fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", realCloudR2PublicationRepositoryID, "--workers", "2", "--limit", "20"}
	adopted := runCLI(cli.ExitOK, adoptArguments...)
	for _, required := range []string{"fsck-adopt target=cf", "listed=5", "local_expected=1", "retained_extra=4", "streamed_get=5", "changed=true", "inventory_coverage=complete"} {
		if !strings.Contains(adopted, required) {
			t.Fatalf("published-generation adoption omitted %q: %s", required, adopted)
		}
	}
	adoptReplay := runCLI(cli.ExitOK, adoptArguments...)
	if !strings.Contains(adoptReplay, "changed=false") || !strings.Contains(adoptReplay, "inventory_coverage=complete") {
		t.Fatalf("published-generation adoption replay was not idempotent: %s", adoptReplay)
	}
	fsckArguments := []string{"fsck", "--target", "cf", "--config", configPath, "--repo", realCloudR2PublicationRepositoryID, "--workers", "2", "--limit", "20"}
	clean := runCLI(cli.ExitOK, fsckArguments...)
	if !strings.Contains(clean, "fsck target=cf") || !strings.Contains(clean, "inventory_coverage=complete") {
		t.Fatalf("published-generation full fsck was not clean: %s", clean)
	}

	original, err := control.R2GetControl(ctx, payloadKey)
	if err != nil || !original.Exists || !bytes.Equal(original.Body, payload) || strings.TrimSpace(original.ETag) == "" {
		t.Fatalf("read published R2 pointer before drift: exists=%t etag_present=%t err=%v", original.Exists, strings.TrimSpace(original.ETag) != "", err)
	}
	tamperedETag, err := control.R2Put(ctx, payloadKey, bytes.NewReader(tampered), int64(len(tampered)), realCloudLowerSHA256(tampered), publish.R2PutCondition{IfMatch: original.ETag})
	if err != nil || strings.TrimSpace(tamperedETag) == "" {
		t.Fatalf("install run-owned R2 publication drift: etag_present=%t err=%v", strings.TrimSpace(tamperedETag) != "", err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	headBeforeDrift, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	drift := runCLI(cli.ExitVerification, fsckArguments...)
	expectedDrift := "remote-drift target=cf kind=changed path=" + payloadKey
	if !strings.Contains(drift, expectedDrift) || !strings.Contains(drift, "fsck target=cf listed=5 expected=5 missing=0 changed=1 orphan=0 unknown=0") || !strings.Contains(drift, "sow: repository or remote drift detected") {
		t.Fatalf("real R2 publication drift was rejected for the wrong reason: %s", drift)
	}
	headAfterDrift, err := canonical.HeadHash()
	if err != nil || headAfterDrift != headBeforeDrift {
		t.Fatalf("rejected real R2 publication drift changed canonical HEAD: before=%s after=%s err=%v", headBeforeDrift, headAfterDrift, err)
	}
	restoredETag, err := control.R2Put(ctx, payloadKey, bytes.NewReader(payload), int64(len(payload)), realCloudLowerSHA256(payload), publish.R2PutCondition{IfMatch: tamperedETag})
	if err != nil || strings.TrimSpace(restoredETag) == "" {
		t.Fatalf("restore exact run-owned R2 publication pointer: etag_present=%t err=%v", strings.TrimSpace(restoredETag) != "", err)
	}
	if err := requireRealCloudR2Object(ctx, control, payloadKey, payload, restoredETag); err != nil {
		t.Fatalf("restored R2 publication pointer: %v", err)
	}
	restored := runCLI(cli.ExitOK, fsckArguments...)
	if !strings.Contains(restored, "fsck target=cf") || !strings.Contains(restored, "inventory_coverage=complete") {
		t.Fatalf("restored real R2 publication fsck was not clean: %s", restored)
	}

	if err := cleanupRealCloudR2OwnedObjectsWithAuthorizer(ctx, control, owned, leaseKey, transport.authorizeCleanupDelete); err != nil {
		assertNoRealCloudSecret(t, "real R2 publication cleanup error", []byte(err.Error()), secretFragments)
		t.Fatalf("identity-bound real R2 publication cleanup: %v", err)
	}
	after, err := listAllRealCloudR2Objects(ctx, control)
	if err != nil || len(after) != 0 {
		t.Fatalf("pinned R2 bucket is not empty after publication cleanup: objects=%d err=%v", len(after), err)
	}
	cleanupComplete = true
	puts, purges, deletes, localGets, unexpected := transport.counts()
	if puts != 8 || purges != 1 || deletes != 5 || localGets != 2 || unexpected != 0 {
		t.Fatalf("publication network evidence is incomplete: puts=%d purges=%d deletes=%d local_gets=%d unexpected=%d", puts, purges, deletes, localGets, unexpected)
	}
	assertNoRealCloudSecret(t, "real R2 publication bounded evidence", []byte(first+replay+adopted+adoptReplay+clean+drift+restored), secretFragments)
	t.Logf("real R2 publication storage transaction PASS run=%s generation=%d puts=%d purge_adapter_calls=%d local_cdn_gets=%d drift_rejected=true cas_restore=true replay_unchanged=true remote_adoption=true full_fsck=true real_cf_control_plane=false real_custom_domain=false empty_before=true empty_after=true", runID, publication.generation.Generation, puts, purges, localGets)
}

// TestRealCloudR2PublicationNetworkBoundary is always offline. It keeps the
// opt-in acceptance's fail-closed routing and mutation lease rules under the
// ordinary test suite instead of trusting an unexercised safety wrapper.
func TestRealCloudR2PublicationNetworkBoundary(t *testing.T) {
	const (
		r2Host     = "pro.72cdbd1b54f7add44ecbd3d986399481.r2.cloudflarestorage.com"
		localHost  = "r2-publication-main.test"
		zoneID     = "da7b5a27e4f9ef6eaa1b00a89c2c77c2"
		leaseKey   = "acceptance/r2-publication/sow-r2-publication-contract-01/lease.json"
		payloadKey = "acceptance/r2-publication/sow-r2-publication-contract-01/latest"
	)
	baseCalls := 0
	base := realCloudR2PublicationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		baseCalls++
		return realCloudR2PublicationHTTPResponse(request, http.StatusOK, "", map[string]string{"ETag": `"offline-etag"`}), nil
	})
	owned := make(realCloudR2OwnedObjects)
	transport := &realCloudR2PublicationTransport{
		r2Host: r2Host, localHosts: map[string]struct{}{localHost: {}, "r2-publication-beta.test": {}}, zoneID: zoneID, localBaseURL: "https://" + localHost,
		localOrigin: &url.URL{Scheme: "https", Host: "127.0.0.1:18443"},
		leaseKey:    leaseKey, payloadKey: payloadKey, bucket: "pro", r2Transport: base, localTransport: base,
		owned: owned, knownBodies: make(map[string][]byte),
		cleanupCapabilities: make(map[string]realCloudR2PublicationCleanupCapability),
	}
	direct, err := newRealCloudR2PublicationDirectTransport(&url.URL{Scheme: "https", Host: r2Host})
	if err != nil || direct.Proxy != nil {
		t.Fatalf("proxy-free direct transport rejected: proxy=%v err=%v", direct != nil && direct.Proxy != nil, err)
	}
	defer direct.CloseIdleConnections()
	if _, err := direct.DialContext(t.Context(), "tcp", "production.example:443"); err == nil {
		t.Fatal("proxy-free direct transport accepted a foreign dial authority")
	}
	for _, testCase := range []struct {
		name string
		base realCloudR2PublicationRoundTripFunc
	}{
		{name: "explicit-rejection", base: func(request *http.Request) (*http.Response, error) {
			return realCloudR2PublicationHTTPResponse(request, http.StatusPreconditionFailed, "", nil), nil
		}},
		{name: "ambiguous-transport-error", base: func(*http.Request) (*http.Response, error) {
			return nil, errors.New("offline ambiguous outcome")
		}},
	} {
		t.Run(testCase.name+"-does-not-grant-cleanup-authority", func(t *testing.T) {
			rejectedOwned := make(realCloudR2OwnedObjects)
			rejected := &realCloudR2PublicationTransport{
				r2Host: r2Host, leaseKey: leaseKey, payloadKey: payloadKey, bucket: "pro", r2Transport: testCase.base,
				owned: rejectedOwned, knownBodies: make(map[string][]byte), cleanupCapabilities: make(map[string]realCloudR2PublicationCleanupCapability),
			}
			request, _ := http.NewRequest(http.MethodPut, "https://"+r2Host+"/"+leaseKey, strings.NewReader("lease"))
			request.Header.Set("Authorization", "AWS4-HMAC-SHA256 offline-contract")
			response, _ := rejected.RoundTrip(request)
			if response != nil {
				_ = response.Body.Close()
			}
			puts, _, _, _, _ := rejected.counts()
			if puts != 0 || len(rejectedOwned) != 0 || len(rejected.knownBodies) != 0 {
				t.Fatalf("failed PUT granted cleanup authority: puts=%d owned=%v known=%v", puts, rejectedOwned, rejected.knownBodies)
			}
		})
	}
	foreign, _ := http.NewRequest(http.MethodGet, "https://repo.pigsty.io/production", nil)
	if _, err := transport.RoundTrip(foreign); err == nil || baseCalls != 0 {
		t.Fatalf("foreign host reached transport: calls=%d err=%v", baseCalls, err)
	}
	authorityOverride, _ := http.NewRequest(http.MethodGet, "https://"+r2Host+"/", nil)
	authorityOverride.Host = "production.example"
	authorityOverride.Header.Set("Authorization", "AWS4-HMAC-SHA256 offline-contract")
	if _, err := transport.RoundTrip(authorityOverride); err == nil || baseCalls != 0 {
		t.Fatalf("independent Host authority reached transport: calls=%d err=%v", baseCalls, err)
	}
	unsigned, _ := http.NewRequest(http.MethodPut, "https://"+r2Host+"/"+payloadKey, strings.NewReader("payload"))
	if _, err := transport.RoundTrip(unsigned); err == nil || baseCalls != 0 {
		t.Fatalf("unsigned or unleased R2 mutation reached network: calls=%d err=%v", baseCalls, err)
	}
	lease, _ := http.NewRequest(http.MethodPut, "https://"+r2Host+"/"+leaseKey, strings.NewReader("lease"))
	lease.Header.Set("Authorization", "AWS4-HMAC-SHA256 offline-contract")
	response, err := transport.RoundTrip(lease)
	if err != nil || response.StatusCode != http.StatusOK || baseCalls != 1 {
		t.Fatalf("exact signed lease rejected: calls=%d response=%v err=%v", baseCalls, response, err)
	}
	_ = response.Body.Close()
	deleteLease, _ := http.NewRequest(http.MethodDelete, "https://"+r2Host+"/"+leaseKey, nil)
	deleteLease.Header.Set("Authorization", "AWS4-HMAC-SHA256 offline-contract")
	if _, err := transport.RoundTrip(deleteLease); err == nil || baseCalls != 1 {
		t.Fatalf("DELETE without a one-shot cleanup capability reached network: calls=%d err=%v", baseCalls, err)
	}
	outside, _ := http.NewRequest(http.MethodPut, "https://"+r2Host+"/production/latest", strings.NewReader("foreign"))
	outside.Header.Set("Authorization", "AWS4-HMAC-SHA256 offline-contract")
	if _, err := transport.RoundTrip(outside); err == nil || baseCalls != 1 {
		t.Fatalf("outside-key R2 mutation reached network: calls=%d err=%v", baseCalls, err)
	}
	wrongPurge, _ := http.NewRequest(http.MethodPost, "https://api.cloudflare.com/client/v4/zones/production/purge_cache", strings.NewReader(`{"files":["https://`+localHost+`/`+payloadKey+`"]}`))
	wrongPurge.Header.Set("Authorization", "Bearer "+realCloudR2PublicationLocalToken)
	if _, err := transport.RoundTrip(wrongPurge); err == nil || baseCalls != 1 {
		t.Fatalf("wrong-zone purge was accepted: calls=%d err=%v", baseCalls, err)
	}
	goodPurge, _ := http.NewRequest(http.MethodPost, "https://api.cloudflare.com/client/v4/zones/"+zoneID+"/purge_cache", strings.NewReader(`{"files":["https://`+localHost+`/`+payloadKey+`"]}`))
	goodPurge.Header.Set("Authorization", "Bearer "+realCloudR2PublicationLocalToken)
	response, err = transport.RoundTrip(goodPurge)
	if err != nil || response.StatusCode != http.StatusOK || baseCalls != 1 {
		t.Fatalf("exact local purge adapter request rejected: calls=%d response=%v err=%v", baseCalls, response, err)
	}
	_ = response.Body.Close()
	puts, purges, _, _, unexpected := transport.counts()
	if puts != 1 || purges != 1 || unexpected != 2 || len(owned[leaseKey]) != 1 {
		t.Fatalf("offline boundary evidence differs: puts=%d purges=%d unexpected=%d owned=%v", puts, purges, unexpected, owned)
	}
}

type realCloudR2PublicationRoundTripFunc func(*http.Request) (*http.Response, error)

func (function realCloudR2PublicationRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type realCloudR2PublicationCleanupCapability struct {
	etag string
	body []byte
}

type realCloudR2PublicationTransport struct {
	mutex               sync.Mutex
	r2Host              string
	localHosts          map[string]struct{}
	zoneID              string
	localBaseURL        string
	localOrigin         *url.URL
	leaseKey            string
	payloadKey          string
	bucket              string
	r2Transport         http.RoundTripper
	localTransport      http.RoundTripper
	r2Probe             *publish.R2CloudflareControlHTTP
	owned               realCloudR2OwnedObjects
	knownBodies         map[string][]byte
	cleanupCapabilities map[string]realCloudR2PublicationCleanupCapability
	leaseReady          bool
	leaseBody           []byte
	leaseETag           string
	puts                int
	purges              int
	deletes             int
	localGets           int
	unexpected          int
	purgeURLs           []string
	localKeys           []string
	events              []string
}

func (transport *realCloudR2PublicationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, errors.New("R2 publication transport received an empty request")
	}
	host := strings.ToLower(request.URL.Host)
	if request.Host != "" && !strings.EqualFold(request.Host, request.URL.Host) {
		transport.mutex.Lock()
		transport.unexpected++
		transport.mutex.Unlock()
		return nil, fmt.Errorf("R2 publication refused authority override %s for %s", request.Host, request.URL.Host)
	}
	_, isLocalHost := transport.localHosts[host]
	switch {
	case host == transport.r2Host:
		return transport.roundTripR2(request)
	case isLocalHost:
		if request.URL.Scheme != "https" || request.Method != http.MethodGet || !validRealCloudR2PublicationCDNKey(strings.TrimPrefix(request.URL.Path, "/"), transport.payloadKey) {
			return nil, errors.New("R2 publication local CDN request is outside the exact verification route")
		}
		if transport.localOrigin == nil || transport.localOrigin.Scheme != "https" || transport.localOrigin.Host == "" {
			return nil, errors.New("R2 publication local CDN origin is invalid")
		}
		key := strings.TrimPrefix(request.URL.Path, "/")
		forwarded := request.Clone(request.Context())
		forwardedURL := *request.URL
		forwardedURL.Scheme = transport.localOrigin.Scheme
		forwardedURL.Host = transport.localOrigin.Host
		forwarded.URL = &forwardedURL
		forwarded.Host = transport.localOrigin.Host
		response, err := transport.localTransport.RoundTrip(forwarded)
		if response != nil {
			response.Request = request
		}
		if err == nil && response != nil && response.StatusCode >= 200 && response.StatusCode < 300 {
			transport.mutex.Lock()
			transport.localGets++
			transport.localKeys = append(transport.localKeys, key)
			transport.events = append(transport.events, "cdn-get:"+key)
			transport.mutex.Unlock()
		}
		return response, err
	case host == "api.cloudflare.com":
		return transport.roundTripCloudflarePurge(request)
	default:
		transport.mutex.Lock()
		transport.unexpected++
		transport.mutex.Unlock()
		return nil, fmt.Errorf("R2 publication refused unapproved network host %s", host)
	}
}

func (transport *realCloudR2PublicationTransport) roundTripR2(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		return nil, errors.New("R2 publication refused a non-TLS or unsigned object request")
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodPut && request.Method != http.MethodDelete {
		return nil, errors.New("R2 publication refused an unexpected object-store method")
	}
	escapedKey := strings.TrimPrefix(request.URL.EscapedPath(), "/")
	key, err := url.PathUnescape(escapedKey)
	if err != nil {
		return nil, errors.New("R2 publication object key is not canonical")
	}
	mutating := request.Method == http.MethodPut || request.Method == http.MethodDelete
	if mutating && !validRealCloudR2PublicationWriteKey(key, transport.leaseKey, transport.payloadKey) {
		return nil, fmt.Errorf("R2 publication refused write outside its exact key set: %s", key)
	}
	if mutating && key != transport.leaseKey {
		if err := transport.requireLiveLease(request.Context()); err != nil {
			return nil, err
		}
	}

	var candidateBody []byte
	if request.Method == http.MethodPut {
		copySource := request.Header.Get("X-Amz-Copy-Source")
		if copySource == "" {
			if request.Body == nil {
				return nil, errors.New("R2 publication PUT has no body")
			}
			body, readErr := io.ReadAll(io.LimitReader(request.Body, 8<<20+1))
			closeErr := request.Body.Close()
			if readErr != nil || closeErr != nil {
				return nil, errors.Join(readErr, closeErr)
			}
			if len(body) > 8<<20 {
				return nil, errors.New("R2 publication PUT exceeds the acceptance identity limit")
			}
			request.Body = io.NopCloser(bytes.NewReader(body))
			request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
			candidateBody = body
		} else {
			source, sourceErr := realCloudR2PublicationCopySource(copySource, transport.bucket)
			if sourceErr != nil {
				return nil, sourceErr
			}
			transport.mutex.Lock()
			body, exists := transport.knownBodies[source]
			transport.mutex.Unlock()
			if !exists {
				return nil, errors.New("R2 publication refused CopyObject from an untracked source identity")
			}
			candidateBody = append([]byte(nil), body...)
		}
	} else if request.Method == http.MethodDelete {
		capability, err := transport.takeCleanupCapability(key)
		if err != nil {
			return nil, err
		}
		if transport.r2Probe == nil {
			return nil, errors.New("R2 publication cleanup has no direct identity probe")
		}
		if err := requireRealCloudR2Object(request.Context(), transport.r2Probe, key, capability.body, capability.etag); err != nil {
			return nil, fmt.Errorf("R2 publication cleanup identity changed before DELETE: %w", err)
		}
	}
	response, err := transport.r2Transport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		transport.mutex.Lock()
		switch request.Method {
		case http.MethodPut:
			transport.owned.allow(key, candidateBody)
			transport.knownBodies[key] = append([]byte(nil), candidateBody...)
			transport.puts++
			transport.events = append(transport.events, "put:"+key)
			if key == transport.leaseKey {
				transport.leaseReady = true
			}
		case http.MethodDelete:
			transport.deletes++
			transport.events = append(transport.events, "delete:"+key)
			delete(transport.knownBodies, key)
			if key == transport.leaseKey {
				transport.leaseReady = false
			}
		}
		transport.mutex.Unlock()
	}
	return response, nil
}

func (transport *realCloudR2PublicationTransport) roundTripCloudflarePurge(request *http.Request) (*http.Response, error) {
	expectedPath := "/client/v4/zones/" + transport.zoneID + "/purge_cache"
	if request.URL.Scheme != "https" || request.Method != http.MethodPost || request.URL.Path != expectedPath || request.URL.RawQuery != "" || request.Header.Get("Authorization") != "Bearer "+realCloudR2PublicationLocalToken {
		return nil, errors.New("R2 publication refused a non-local or incorrectly bound Cloudflare purge request")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		return nil, errors.New("R2 publication purge request is absent or oversized")
	}
	_ = request.Body.Close()
	var payload struct {
		Files []string `json:"files"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return nil, errors.New("decode local Cloudflare purge request")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("local Cloudflare purge request contains trailing JSON")
	}
	if len(payload.Files) != 1 || payload.Files[0] != transport.localBaseURL+"/"+transport.payloadKey {
		return nil, fmt.Errorf("R2 publication purge is not the exact minimal pointer set: %v", payload.Files)
	}
	transport.mutex.Lock()
	transport.purges++
	transport.purgeURLs = append(transport.purgeURLs, payload.Files...)
	transport.events = append(transport.events, "purge:"+payload.Files[0])
	serial := transport.purges
	transport.mutex.Unlock()
	return realCloudR2PublicationHTTPResponse(request, http.StatusOK, `{"success":true,"errors":[],"messages":[],"result":{"id":"local-r2-publication-`+strconv.Itoa(serial)+`"}}`, map[string]string{
		"Content-Type": "application/json", "CF-Ray": "cf-ray-local-r2-publication-" + strconv.Itoa(serial),
	}), nil
}

func (transport *realCloudR2PublicationTransport) counts() (puts, purges, deletes, localGets, unexpected int) {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	return transport.puts, transport.purges, transport.deletes, transport.localGets, transport.unexpected
}

func (transport *realCloudR2PublicationTransport) purgeURLSnapshot() []string {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	return append([]string(nil), transport.purgeURLs...)
}

func (transport *realCloudR2PublicationTransport) networkEvidenceSnapshot() (localKeys, events []string) {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	return append([]string(nil), transport.localKeys...), append([]string(nil), transport.events...)
}

func (transport *realCloudR2PublicationTransport) bindLease(body []byte, etag string) {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	transport.leaseBody = append([]byte(nil), body...)
	transport.leaseETag = etag
}

func (transport *realCloudR2PublicationTransport) requireLiveLease(ctx context.Context) error {
	transport.mutex.Lock()
	ready := transport.leaseReady
	body := append([]byte(nil), transport.leaseBody...)
	etag := transport.leaseETag
	probe := transport.r2Probe
	transport.mutex.Unlock()
	if !ready || len(body) == 0 || strings.TrimSpace(etag) == "" || probe == nil {
		return errors.New("R2 publication refused mutation without a bound run-owned lease")
	}
	if err := requireRealCloudR2Object(ctx, probe, transport.leaseKey, body, etag); err != nil {
		return fmt.Errorf("R2 publication refused mutation after the run-owned lease changed: %w", err)
	}
	return nil
}

func (transport *realCloudR2PublicationTransport) authorizeCleanupDelete(key string, identity publish.ObjectInfo) error {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	body, exists := transport.knownBodies[key]
	if !exists || identity.ETag == "" || identity.Size != int64(len(body)) {
		return errors.New("cleanup identity is absent from the confirmed-success body ledger")
	}
	allowed := transport.owned[key]
	if _, exists := allowed[realCloudR2OwnedIdentity{Size: int64(len(body)), SHA256: realCloudLowerSHA256(body)}]; !exists {
		return errors.New("cleanup body is absent from the confirmed-success ownership ledger")
	}
	transport.cleanupCapabilities[key] = realCloudR2PublicationCleanupCapability{
		etag: identity.ETag,
		body: append([]byte(nil), body...),
	}
	return nil
}

func (transport *realCloudR2PublicationTransport) takeCleanupCapability(key string) (realCloudR2PublicationCleanupCapability, error) {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	capability, exists := transport.cleanupCapabilities[key]
	delete(transport.cleanupCapabilities, key)
	if !exists || capability.etag == "" || len(capability.body) == 0 {
		return realCloudR2PublicationCleanupCapability{}, errors.New("R2 publication refused DELETE without a one-shot exact-identity cleanup capability")
	}
	return capability, nil
}

func newRealCloudR2PublicationDirectTransport(r2URL *url.URL) (*http.Transport, error) {
	if r2URL == nil || r2URL.Scheme != "https" || r2URL.User != nil || r2URL.Hostname() == "" || r2URL.Port() != "" {
		return nil, errors.New("R2 publication direct transport requires one clean HTTPS authority")
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok || base == nil {
		return nil, errors.New("R2 publication requires the standard Go HTTP transport before installing its firewall")
	}
	direct := base.Clone()
	direct.Proxy = nil
	direct.ProxyConnectHeader = nil
	direct.GetProxyConnectHeader = nil
	direct.DialTLSContext = nil
	dial := direct.DialContext
	if dial == nil {
		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		dial = dialer.DialContext
	}
	allowedHost := strings.ToLower(r2URL.Hostname())
	direct.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || !strings.HasPrefix(network, "tcp") || !strings.EqualFold(host, allowedHost) || port != "443" {
			return nil, fmt.Errorf("R2 publication refused direct dial network=%s address=%s", network, address)
		}
		return dial(ctx, network, address)
	}
	return direct, nil
}

func requireRealCloudR2PublicationEventOrder(events []string, leaseKey, checkpointKey, archiveKey, generationKey, payloadKey string) error {
	if len(events) != 9 {
		return fmt.Errorf("expected 9 successful transaction events, got %d", len(events))
	}
	positions := func(event string) []int {
		var result []int
		for index, observed := range events {
			if observed == event {
				result = append(result, index)
			}
		}
		return result
	}
	lease := positions("put:" + leaseKey)
	checkpoints := positions("put:" + checkpointKey)
	archive := positions("put:" + archiveKey)
	generation := positions("put:" + generationKey)
	pointer := positions("put:" + payloadKey)
	purge := positions("purge:" + realCloudR2PublicationMainBase + "/" + payloadKey)
	cdnPointer := positions("cdn-get:" + payloadKey)
	cdnArchive := positions("cdn-get:" + archiveKey)
	if len(lease) != 1 || lease[0] != 0 || len(checkpoints) != 2 || len(archive) != 1 || len(generation) != 1 || len(pointer) != 1 || len(purge) != 1 || len(cdnPointer) != 1 || len(cdnArchive) != 1 {
		return errors.New("transaction event identities or cardinalities differ")
	}
	lock, commit := checkpoints[0], checkpoints[1]
	if !(lock < archive[0] && lock < generation[0] && archive[0] < pointer[0] && generation[0] < pointer[0] && pointer[0] < purge[0] && purge[0] < cdnPointer[0] && purge[0] < cdnArchive[0] && cdnPointer[0] < commit && cdnArchive[0] < commit) {
		return errors.New("upload, pointer flip, purge, verification, and checkpoint commit order differs")
	}
	return nil
}

func validRealCloudR2PublicationWriteKey(key, leaseKey, payloadKey string) bool {
	if key == leaseKey || key == payloadKey || key == publish.CheckpointKey {
		return true
	}
	if strings.HasPrefix(key, "objects/sha256/") {
		return validRealCloudLowerSHA256(strings.TrimPrefix(key, "objects/sha256/"))
	}
	const generationPrefix = ".sow/generations/"
	if !strings.HasPrefix(key, generationPrefix) {
		return false
	}
	generation, tail, found := strings.Cut(strings.TrimPrefix(key, generationPrefix), "/")
	if !found || len(generation) != 20 || tail != "generation.json" {
		return false
	}
	for _, character := range generation {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validRealCloudR2PublicationCDNKey(key, payloadKey string) bool {
	return key == payloadKey || strings.HasPrefix(key, "objects/sha256/") && validRealCloudLowerSHA256(strings.TrimPrefix(key, "objects/sha256/"))
}

func realCloudR2PublicationCopySource(raw, bucket string) (string, error) {
	decoded, err := url.PathUnescape(strings.TrimPrefix(raw, "/"))
	if err != nil {
		return "", errors.New("R2 publication CopyObject source is not canonical")
	}
	prefix := bucket + "/"
	if !strings.HasPrefix(decoded, prefix) || strings.TrimPrefix(decoded, prefix) == "" {
		return "", errors.New("R2 publication CopyObject source is outside the exact bucket")
	}
	return strings.TrimPrefix(decoded, prefix), nil
}

func realCloudR2PublicationHTTPResponse(request *http.Request, status int, body string, headers map[string]string) *http.Response {
	header := make(http.Header)
	for name, value := range headers {
		header.Set(name, value)
	}
	return &http.Response{
		StatusCode: status, Status: strconv.Itoa(status) + " " + http.StatusText(status), Header: header,
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request,
	}
}

func realCloudR2PublicationConfig(environment realCloudEnvironment, runID, localCDNBase, localBetaBase string) []byte {
	return []byte(fmt.Sprintf(`schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: %s
    type: asset
    path: acceptance/r2-publication/%s
    default_pool: public
    asset:
      kind: release
      mutable_paths: [latest]
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: %q}
  beta: {base_url: %q}
  stable: {base_url: %q}
targets:
  cf:
    storage: {kind: r2, endpoint: %q, bucket: %s, region: auto, credential: env://SOW_REAL_CF_STORAGE_JSON, delete_mode: checkpoint-fenced}
    cdn: {kind: cloudflare, base_url: %q, beta_base_url: %q, zone_id: %s, credential: env://SOW_REAL_CF_CDN_JSON}
edge:
  token_verifier: provider://test
`, realCloudR2PublicationRepositoryID, runID, localCDNBase, localBetaBase, localCDNBase+"/pro/v1/basic",
		environment.CFR2Endpoint, environment.CFR2Bucket, localCDNBase, localBetaBase, environment.CFZoneID))
}
