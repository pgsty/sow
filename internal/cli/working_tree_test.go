package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

func TestMaterializeLatestDefaultRefreshesWorkingBaselineButExportDoesNot(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "asset"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("init", "--config", configPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	first := filepath.Join(root, "first.bin")
	if err := os.WriteFile(first, []byte("first-working-version"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", first, "--config", configPath, "--repo", "asset", "--dest", "first.bin"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "asset"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("materialize", "latest", "--config", configPath, "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "target=working-tree") {
		t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if body, err := os.ReadFile(filepath.Join(root, "asset", "first.bin")); err != nil || string(body) != "first-working-version" {
		t.Fatalf("legacy materialization body=%q err=%v", body, err)
	}
	if code, stdout, stderr := run("fsck", "--config", configPath, "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "fsck clean") {
		t.Fatalf("fsck after materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	canonical := state.New(filepath.Join(root, ".sow"))
	repoRef, _ := state.RepoRef("asset")
	baselineRef, exists, err := canonical.Ref(repoRef)
	if err != nil || !exists {
		t.Fatalf("baseline ref exists=%v err=%v", exists, err)
	}
	baselineBody, err := os.ReadFile(canonical.ManifestPath("asset"))
	if err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(root, "second.bin")
	if err := os.WriteFile(second, []byte("export-only-version"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", second, "--config", configPath, "--repo", "asset", "--dest", "second.bin"); code != ExitOK {
		t.Fatalf("second add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "asset"); code != ExitOK {
		t.Fatalf("second promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("materialize", "latest", "--config", configPath, "--target", "export", "--workers", "2"); code != ExitOK {
		t.Fatalf("export code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	afterRef, _, err := canonical.Ref(repoRef)
	afterBody, readErr := os.ReadFile(canonical.ManifestPath("asset"))
	if err != nil || readErr != nil || afterRef != baselineRef || !bytes.Equal(afterBody, baselineBody) {
		t.Fatalf("explicit export changed working baseline ref=%s/%s read_err=%v ref_err=%v", baselineRef, afterRef, readErr, err)
	}
	if _, err := os.Stat(filepath.Join(root, "asset", "second.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit export unexpectedly changed legacy tree: %v", err)
	}
	if body, err := os.ReadFile(filepath.Join(root, "export", "asset", "second.bin")); err != nil || string(body) != "export-only-version" {
		t.Fatalf("exported body=%q err=%v", body, err)
	}
	if code, stdout, stderr := run("fsck", "--config", configPath, "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "fsck clean") {
		t.Fatalf("fsck after export code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestRefreshWorkingTreeBaselineStagesAtomicallyAndRecoversCommit(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "asset"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath, "--workers", "2"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	cfg, repos, err := loadAndSelect(commonFlags{configPath: configPath, workers: 2, chunk: 2})
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	repoRef, _ := state.RepoRef("asset")
	beforeHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	beforeRef, _, err := canonical.Ref(repoRef)
	if err != nil {
		t.Fatal(err)
	}
	beforeManifest, err := os.ReadFile(canonical.ManifestPath("asset"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "asset", "new.bin"), []byte("new working bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	txDir, err := newTransactionDir(cfg.StatePath(), "working-cancelled-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	if _, _, err := refreshWorkingTreeBaselines(cancelled, cfg, canonical, repos, txDir, commonFlags{workers: 2, chunk: 2}, "working-cancelled-test", state.ApplyOptions{}, &stdout); err == nil {
		t.Fatal("cancelled scan unexpectedly committed a baseline")
	}
	afterCancelledHead, _ := canonical.HeadHash()
	afterCancelledRef, _, _ := canonical.Ref(repoRef)
	afterCancelledManifest, _ := os.ReadFile(canonical.ManifestPath("asset"))
	if afterCancelledHead != beforeHead || afterCancelledRef != beforeRef || !bytes.Equal(afterCancelledManifest, beforeManifest) {
		t.Fatal("scan failure changed canonical head, repo ref, or manifest")
	}

	injected := errors.New("injected stop after canonical commit")
	txDir, err = newTransactionDir(cfg.StatePath(), "working-recovery-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	commit, changed, err := refreshWorkingTreeBaselines(t.Context(), cfg, canonical, repos, txDir, commonFlags{workers: 2, chunk: 2}, "working-recovery-test", state.ApplyOptions{AfterCommit: func() error { return injected }}, &stdout)
	if !errors.Is(err, injected) || !changed || commit == "" {
		t.Fatalf("interrupted commit=%s changed=%v err=%v", commit, changed, err)
	}
	committedHead, _ := canonical.HeadHash()
	interruptedRef, _, _ := canonical.Ref(repoRef)
	if committedHead.String() != commit || interruptedRef != beforeRef {
		t.Fatalf("durable commit/ref boundary head=%s commit=%s ref=%s before=%s", committedHead, commit, interruptedRef, beforeRef)
	}
	if err := canonical.RequireNoIncompleteTransactions(); !errors.Is(err, state.ErrRecoveryRequired) {
		t.Fatalf("interrupted transaction was not detectable: %v", err)
	}
	stdout.Reset()
	if err := prepareCanonicalState(t.Context(), canonical, true, &stdout); err != nil || !strings.Contains(stdout.String(), "cache rebuilt after recovery") {
		t.Fatalf("recover output=%s err=%v", stdout.String(), err)
	}
	recoveredRef, _, err := canonical.Ref(repoRef)
	if err != nil || recoveredRef != committedHead {
		t.Fatalf("recovered ref=%s head=%s err=%v", recoveredRef, committedHead, err)
	}

	retryDir, err := newTransactionDir(cfg.StatePath(), "working-retry-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(retryDir)
	retryCommit, retryChanged, err := refreshWorkingTreeBaselines(t.Context(), cfg, canonical, repos, retryDir, commonFlags{workers: 2, chunk: 2}, "working-retry-test", state.ApplyOptions{}, &stdout)
	if err != nil || retryChanged || retryCommit != committedHead.String() {
		t.Fatalf("idempotent retry commit=%s changed=%v err=%v", retryCommit, retryChanged, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"fsck", "--config", configPath, "--workers", "2"}, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "fsck clean") {
		t.Fatalf("fsck after recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestRemoveLatestRefreshesWorkingBaselineAndLeavesFSCKClean(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "asset"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("init", "--config", configPath); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, name := range []string{"keep.bin", "remove.bin"} {
		input := filepath.Join(root, "input-"+name)
		if err := os.WriteFile(input, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "asset", "--dest", name); code != ExitOK {
			t.Fatalf("add %s code=%d stdout=%s stderr=%s", name, code, stdout, stderr)
		}
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "asset"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("materialize", "latest", "--config", configPath); code != ExitOK {
		t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("rm", "remove.bin", "--view", "latest", "--config", configPath, "--repo", "asset"); code != ExitOK {
		t.Fatalf("rm code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, "asset", "remove.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed legacy file remains: %v", err)
	}
	if body, err := os.ReadFile(filepath.Join(root, "asset", "keep.bin")); err != nil || string(body) != "keep.bin" {
		t.Fatalf("retained legacy body=%q err=%v", body, err)
	}
	if code, stdout, stderr := run("fsck", "--config", configPath); code != ExitOK || !strings.Contains(stdout, "fsck clean") {
		t.Fatalf("fsck after rm code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

type switchableCDNFailureTransport struct {
	base *cloudProtocolTransport
	fail atomic.Bool
}

func (transport *switchableCDNFailureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.fail.Load() && (request.URL.Host == "repo.test" || request.URL.Host == "beta.test") {
		return nil, errors.New("injected CDN verification interruption")
	}
	return transport.base.RoundTrip(request)
}

func TestPublishLatestFreezesWorkingBaselineBeforeRemoteAndReusesItAfterFailure(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	base := newCloudProtocolTransport()
	transport := &switchableCDNFailureTransport{base: base}
	transport.fail.Store(true)
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("init", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	input := filepath.Join(root, "release.txt")
	if err := os.WriteFile(input, []byte("release-after-baseline"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code == ExitOK || !strings.Contains(stderr, "injected CDN verification interruption") {
		t.Fatalf("interrupted publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	repoRef, _ := state.RepoRef("assets")
	baselineCommit, exists, err := canonical.Ref(repoRef)
	if err != nil || !exists {
		t.Fatalf("working ref exists=%v err=%v", exists, err)
	}
	remoteRef, _ := state.RemoteRef("cf", "latest", "assets", "all", "all")
	if _, exists, err := canonical.Ref(remoteRef); err != nil || exists {
		t.Fatalf("remote ref advanced across failed verification exists=%v err=%v", exists, err)
	}
	base.mutex.Lock()
	checkpointObject, exists := base.objects[pub.CheckpointKey]
	base.mutex.Unlock()
	if !exists {
		t.Fatal("failed remote transaction did not leave a detectable checkpoint")
	}
	checkpoint, err := pub.DecodeCheckpoint(checkpointObject.body)
	if err != nil || checkpoint.DesiredCommit == "" || checkpoint.DesiredCommit == baselineCommit.String() {
		t.Fatalf("checkpoint desired=%s baseline=%s err=%v", checkpoint.DesiredCommit, baselineCommit, err)
	}
	if ancestor, err := canonical.IsAncestor(baselineCommit, plumbing.NewHash(checkpoint.DesiredCommit)); err != nil || !ancestor {
		t.Fatalf("route-capability checkpoint does not descend from frozen working baseline: ancestor=%t err=%v", ancestor, err)
	}

	transport.fail.Store(false)
	code, stdout, stderr = run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("recovered publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	generation, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || generation.DesiredCommit != checkpoint.DesiredCommit {
		t.Fatalf("generation desired=%s checkpoint=%s baseline=%s exists=%v err=%v", generation.DesiredCommit, checkpoint.DesiredCommit, baselineCommit, exists, err)
	}

	localConfigPath := filepath.Join(root, "local-sow.yaml")
	if err := os.WriteFile(localConfigPath, []byte(publishAssetLocalConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("fsck", "--config", localConfigPath, "--repo", "assets", "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "fsck clean") {
		t.Fatalf("local fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

const publishAssetLocalConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: assets
    type: asset
    path: pkg
    default_pool: public
    asset:
      kind: release
      mutable_paths: [latest]
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
