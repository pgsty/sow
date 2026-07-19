package compat_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/cli"
	"github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

const (
	realCloudR2FSCKOptInEnv      = "SOW_RUN_REAL_CLOUD_R2_FSCK"
	realCloudR2FSCKConfirmEnv    = "SOW_REAL_CLOUD_R2_FSCK_CONFIRM"
	realCloudR2FSCKConfirmPrefix = "I-CONFIRM-MUTATING-ONLY-THE-PINNED-EMPTY-R2-BUCKET-FOR-FSCK"
	realCloudR2FSCKRepositoryID  = "r2-fsck-acceptance"
)

// TestRealCloudR2FSCKStorageOnly proves that the product CLI can adopt and
// re-audit a real R2 inventory using only the storage credential. It never
// resolves a Cloudflare API token, requests a custom domain, or contacts the
// Zone/Worker/purge control plane.
func TestRealCloudR2FSCKStorageOnly(t *testing.T) {
	if os.Getenv(realCloudR2FSCKOptInEnv) != "1" {
		t.Skip("set SOW_RUN_REAL_CLOUD_R2_FSCK=1 to test storage-only fsck against the pinned empty non-production R2 bucket")
	}
	resource, environment, err := loadRealCloudProviderReadinessSelection("cloudflare", os.Getenv)
	if err != nil {
		t.Fatalf("R2 fsck resource gate failed before credentials or networking: %v", err)
	}
	if resource.Cloudflare == nil {
		t.Fatal("R2 fsck resource gate selected no Cloudflare identity")
	}
	if os.Getenv(realCloudNonProductionEnv) != realCloudNonProductionPhrase {
		t.Fatalf("%s must exactly confirm dedicated disposable non-production resources", realCloudNonProductionEnv)
	}
	expectedConfirmation := realCloudR2FSCKConfirmPrefix + ":" + resource.Cloudflare.R2Endpoint + "/" + resource.Cloudflare.R2Bucket
	if os.Getenv(realCloudR2FSCKConfirmEnv) != expectedConfirmation {
		t.Fatalf("%s must exactly bind the pinned R2 endpoint and bucket", realCloudR2FSCKConfirmEnv)
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
	// A token inherited from the invoking shell must not accidentally grant the
	// product path more authority than this test intends to exercise.
	t.Setenv(realCloudCDNCredentialCF, "")

	client, err := publish.NewR2CloudflareControlHTTP(publish.R2CloudflareControlHTTPConfig{
		Bucket:        environment.CFR2Bucket,
		ObjectBaseURL: realCloudProviderBucketBaseURL(environment.CFR2Endpoint, environment.CFR2Bucket),
		Credentials: publish.S3Credentials{
			AccessKeyID: storage.AccessKeyID, SecretAccessKey: storage.SecretAccessKey,
			SessionToken: storage.SessionToken, Region: "auto",
		},
		Client: realCloudProviderHTTPClient(),
	})
	if err != nil {
		t.Fatal("construct R2 storage-only client")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	before, err := listAllRealCloudR2Objects(ctx, client)
	if err != nil {
		assertNoRealCloudSecret(t, "real R2 fsck preflight error", []byte(err.Error()), secretFragments)
		t.Fatalf("list pinned R2 bucket before mutation: %v", err)
	}
	if len(before) != 0 {
		t.Fatalf("pinned R2 bucket is not empty before mutation: observed %d objects", len(before))
	}

	prefix := "acceptance/r2-fsck/" + runID + "/"
	leaseKey := prefix + "lease.json"
	remoteKey := prefix + "release.bin"
	leaseBody := []byte(`{"schema":"sow-real-r2-fsck-lease/v1","run_id":"` + runID + `"}`)
	payload := []byte("sow-real-r2-fsck-original\n" + runID + "\n")
	tampered := []byte("sow-real-r2-fsck-tampered\n" + runID + "\n")
	owned := make(realCloudR2OwnedObjects)
	owned.allow(leaseKey, leaseBody)
	owned.allow(remoteKey, payload)
	owned.allow(remoteKey, tampered)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		cleanupErr := cleanupRealCloudR2OwnedObjects(cleanupCtx, client, owned, leaseKey)
		remaining, listErr := listAllRealCloudR2Objects(cleanupCtx, client)
		if listErr == nil && len(remaining) != 0 {
			listErr = fmt.Errorf("pinned R2 bucket is not empty after cleanup: observed %d objects", len(remaining))
		}
		if err := errors.Join(cleanupErr, listErr); err != nil {
			assertNoRealCloudSecret(t, "real R2 fsck deferred cleanup error", []byte(err.Error()), secretFragments)
			t.Errorf("real R2 fsck deferred cleanup: %v", err)
		}
	}()

	if _, err := client.R2Put(ctx, leaseKey, bytes.NewReader(leaseBody), int64(len(leaseBody)), realCloudLowerSHA256(leaseBody), publish.R2PutCondition{IfNoneMatch: true}); err != nil {
		t.Fatalf("create R2 fsck acceptance lease: %v", err)
	}
	originalETag, err := client.R2Put(ctx, remoteKey, bytes.NewReader(payload), int64(len(payload)), realCloudLowerSHA256(payload), publish.R2PutCondition{IfNoneMatch: true})
	if err != nil || strings.TrimSpace(originalETag) == "" {
		t.Fatalf("create R2 fsck payload: etag_present=%t err=%v", strings.TrimSpace(originalETag) != "", err)
	}

	root := realCloudR2FSCKWorkerRoot(t)
	configPath := filepath.Join(root, "sow.yaml")
	configBody := realCloudR2FSCKConfig(environment, runID)
	if err := os.WriteFile(configPath, configBody, 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "input-release.bin")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	runCLI := func(expected int, arguments ...string) string {
		t.Helper()
		result, runErr := executeCheckedRealCloudCLI(cli.Main, root, expected, secretFragments, arguments...)
		if runErr != nil {
			t.Fatalf("real R2 fsck CLI %v failed: %v output=%q", arguments, runErr, result.output)
		}
		return string(result.output)
	}
	for _, command := range [][]string{
		{"add", input, "--config", configPath, "--repo", realCloudR2FSCKRepositoryID, "--dest", "release.bin"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", realCloudR2FSCKRepositoryID},
		{"materialize", "latest", "--config", configPath, "--repo", realCloudR2FSCKRepositoryID, "--workers", "2"},
		{"init", "--config", configPath, "--repo", realCloudR2FSCKRepositoryID, "--workers", "2"},
	} {
		runCLI(cli.ExitOK, command...)
	}
	localPayload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(remoteKey)))
	if err != nil || !bytes.Equal(localPayload, payload) {
		t.Fatalf("local serving payload differs before remote adoption: err=%v", err)
	}

	fsckArgs := []string{"fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", realCloudR2FSCKRepositoryID, "--workers", "2", "--limit", "20"}
	first := runCLI(cli.ExitOK, fsckArgs...)
	for _, required := range []string{"target=cf", "listed=2", "local_expected=1", "retained_extra=1", "streamed_get=2", "changed=true", "inventory_coverage=complete"} {
		if !strings.Contains(first, required) {
			t.Fatalf("first real R2 adoption omitted %q: %s", required, first)
		}
	}
	replay := runCLI(cli.ExitOK, fsckArgs...)
	if !strings.Contains(replay, "changed=false") {
		t.Fatalf("real R2 adoption replay was not idempotent: %s", replay)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	headBeforeDrift, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}

	tamperedETag, err := client.R2Put(ctx, remoteKey, bytes.NewReader(tampered), int64(len(tampered)), realCloudLowerSHA256(tampered), publish.R2PutCondition{IfMatch: originalETag})
	if err != nil || strings.TrimSpace(tamperedETag) == "" {
		t.Fatalf("install run-owned R2 drift fixture: etag_present=%t err=%v", strings.TrimSpace(tamperedETag) != "", err)
	}
	drift := runCLI(cli.ExitVerification, fsckArgs...)
	if !strings.Contains(drift, "remote inventory adoption evidence drifted") {
		t.Fatalf("real R2 drift was rejected for the wrong reason: %s", drift)
	}
	headAfterDrift, err := canonical.HeadHash()
	if err != nil || headAfterDrift != headBeforeDrift {
		t.Fatalf("rejected real R2 drift changed canonical HEAD: before=%s after=%s err=%v", headBeforeDrift, headAfterDrift, err)
	}
	restoredETag, err := client.R2Put(ctx, remoteKey, bytes.NewReader(payload), int64(len(payload)), realCloudLowerSHA256(payload), publish.R2PutCondition{IfMatch: tamperedETag})
	if err != nil || strings.TrimSpace(restoredETag) == "" {
		t.Fatalf("restore exact run-owned R2 payload: etag_present=%t err=%v", strings.TrimSpace(restoredETag) != "", err)
	}
	restored := runCLI(cli.ExitOK, fsckArgs...)
	if !strings.Contains(restored, "changed=false") {
		t.Fatalf("restored real R2 adoption was not idempotent: %s", restored)
	}

	if err := cleanupRealCloudR2OwnedObjects(ctx, client, owned, leaseKey); err != nil {
		assertNoRealCloudSecret(t, "real R2 fsck cleanup error", []byte(err.Error()), secretFragments)
		t.Fatalf("identity-bound real R2 fsck cleanup: %v", err)
	}
	after, err := listAllRealCloudR2Objects(ctx, client)
	if err != nil || len(after) != 0 {
		t.Fatalf("pinned R2 bucket is not empty after fsck cleanup: objects=%d err=%v", len(after), err)
	}
	assertNoRealCloudSecret(t, "real R2 fsck bounded evidence", []byte(first+replay+drift+restored), secretFragments)
	t.Logf("real R2 fsck PASS run=%s adoption=true replay=true drift_rejected=true cas_restore=true cdn_credentials=false control_plane=false custom_domain=false empty_before=true empty_after=true", runID)
}

func realCloudR2FSCKWorkerRoot(t *testing.T) string {
	t.Helper()
	base := "/private/tmp"
	if info, err := os.Lstat(base); err != nil || !info.IsDir() {
		base = "/tmp"
	}
	root, err := os.MkdirTemp(base, "sow-real-r2-fsck-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		_ = os.RemoveAll(root)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(root, 0o755)
		_ = os.RemoveAll(root)
	})
	return root
}

func realCloudR2FSCKConfig(environment realCloudEnvironment, runID string) []byte {
	return []byte(fmt.Sprintf(`schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: %s
    type: asset
    path: acceptance/r2-fsck/%s
    default_pool: public
    asset:
      kind: release
      mutable_paths: [release.bin]
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
`, realCloudR2FSCKRepositoryID, runID, environment.CFCDNBase, environment.CFBetaCDNBase, environment.CFCDNBase+"/pro/v1/basic", environment.CFR2Endpoint, environment.CFR2Bucket, environment.CFCDNBase, environment.CFBetaCDNBase, environment.CFZoneID))
}
