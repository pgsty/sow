package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
	"github.com/pgsty/sow/internal/yumrepo"
)

type failingCLIWriter struct{ err error }

func (writer failingCLIWriter) Write([]byte) (int, error) { return 0, writer.err }

type shortCLIWriter struct{}

func (shortCLIWriter) Write(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, nil
	}
	return len(body) - 1, nil
}

func TestCLIOutputFailureCannotReportSuccessOrEraseExitClass(t *testing.T) {
	injected := errors.New("injected CLI output failure")
	t.Run("successful command becomes internal failure", func(t *testing.T) {
		var stderr bytes.Buffer
		err := Run(context.Background(), []string{"version"}, failingCLIWriter{err: injected}, &stderr)
		if exitCode(err) != ExitInternal || !errors.Is(err, injected) {
			t.Fatalf("output failure was discarded: exit=%d err=%v", exitCode(err), err)
		}
	})

	t.Run("short write becomes internal failure", func(t *testing.T) {
		var stderr bytes.Buffer
		err := Run(context.Background(), []string{"help"}, shortCLIWriter{}, &stderr)
		if exitCode(err) != ExitInternal || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short output write was discarded: exit=%d err=%v", exitCode(err), err)
		}
	})

	t.Run("nil output sink becomes internal failure", func(t *testing.T) {
		var stderr bytes.Buffer
		err := Run(context.Background(), []string{"help"}, nil, &stderr)
		if exitCode(err) != ExitInternal || !strings.Contains(err.Error(), "stdout writer is nil") {
			t.Fatalf("nil output sink was not rejected: exit=%d err=%v", exitCode(err), err)
		}
	})

	t.Run("existing usage class is retained", func(t *testing.T) {
		var stdout bytes.Buffer
		err := Run(context.Background(), []string{"init", "--definitely-unknown"}, &stdout, failingCLIWriter{err: injected})
		if exitCode(err) != ExitUsage || !errors.Is(err, injected) {
			t.Fatalf("output failure erased the usage result: exit=%d err=%v", exitCode(err), err)
		}
	})
}

func TestPublicationRecoveryRepoNarrowingDoesNotMutateCanonicalConfig(t *testing.T) {
	configured := config.Repo{
		ID: "yum-audit", Type: "yum", Arches: []string{"aarch64", "x86_64"}, YUM: &config.YUMConfig{},
	}
	cfg := &config.Config{Repos: []config.Repo{configured}}
	leaves := []viewLeaf{{repo: configured, os: "el9", arch: "x86_64"}}
	recovered, err := publicationRecoveryRepos(cfg, leaves)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 1 || len(recovered[0].Arches) != 1 || recovered[0].Arches[0] != "x86_64" {
		t.Fatalf("unexpected narrowed recovery repository: %+v", recovered)
	}
	if got := strings.Join(cfg.Repos[0].Arches, ","); got != "aarch64,x86_64" {
		t.Fatalf("recovery narrowing mutated canonical configuration: %s", got)
	}
	recovered[0].Arches[0] = "mutated-after-return"
	if got := strings.Join(cfg.Repos[0].Arches, ","); got != "aarch64,x86_64" {
		t.Fatalf("returned recovery repository aliases canonical configuration: %s", got)
	}
}

func initializeRepoBaselineForTest(t *testing.T, root, configPath string, repoPaths ...string) {
	t.Helper()
	for _, repoPath := range repoPaths {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(repoPath)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("initialize repository baseline code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestLoadAndSelectRejectsEveryUnknownDimensionValue(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(multiSuiteAPTInitConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	base := commonFlags{configPath: configPath, workers: 1, chunk: 1, repos: csvFlag{items: []string{"apt-test"}}}

	withUnknownOS := base
	withUnknownOS.oses = csvFlag{items: []string{"bookworm", "bookwrom"}}
	if _, _, err := loadAndSelect(withUnknownOS); exitCode(err) != ExitConfig || !strings.Contains(err.Error(), "unknown os selector(s): bookwrom") {
		t.Fatalf("mixed valid/unknown OS selector was accepted: %v", err)
	}

	withUnknownArch := base
	withUnknownArch.arches = csvFlag{items: []string{"amd64", "am64"}}
	if _, _, err := loadAndSelect(withUnknownArch); exitCode(err) != ExitConfig || !strings.Contains(err.Error(), "unknown arch selector(s): am64") {
		t.Fatalf("mixed valid/unknown arch selector was accepted: %v", err)
	}

	valid := base
	valid.oses = csvFlag{items: []string{"bookworm", "trixie"}}
	valid.arches = csvFlag{items: []string{"amd64", "arm64"}}
	if _, repos, err := loadAndSelect(valid); err != nil || len(repos) != 1 {
		t.Fatalf("valid multi-value selectors failed: repos=%d err=%v", len(repos), err)
	}
}

func TestPublishPreparedViewReturnsEveryFailedTargetIdentity(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{Root: root, Views: map[string]config.View{"beta": {Access: "public"}}}
	canonical := state.New(filepath.Join(root, ".sow"))
	var stdout bytes.Buffer
	failures, err := publishPreparedView(
		context.Background(), cfg, canonical, nil,
		preparedPublication{view: "beta"}, []string{"cf", "cos"}, plumbing.ZeroHash,
		t.TempDir(), commonFlags{workers: 1, chunk: 1}, &stdout,
	)
	if err != nil || len(failures) != 2 || failures["cf"] == nil || failures["cos"] == nil {
		t.Fatalf("per-target failures were not exposed: failures=%v err=%v output=%s", failures, err, stdout.String())
	}
	if strings.Count(stdout.String(), "status=failed-before-saga") != 2 {
		t.Fatalf("per-target failure evidence is incomplete: %s", stdout.String())
	}
}

func TestSnapshotAPTSuiteWideningRejectsMissingSiblingRef(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	repo := config.Repo{
		ID: "apt-test", Type: "apt", Path: "apt/test", DefaultPool: "public",
		Arches: []string{"amd64", "arm64"},
		OS:     config.OSConfig{Family: "ubuntu", Suite: "jammy", Lifecycle: "active"},
		APT: &config.APTConfig{
			Suites: []string{"jammy"}, Components: []string{"main"},
			SuiteComponents: map[string][]string{"jammy": {"main"}}, SuiteLifecycle: map[string]string{"jammy": "frozen"},
		},
	}
	cfg := &config.Config{Root: root, Repos: []config.Repo{repo}}
	const snapshotID = "jammy-20260712"
	canonicalPath, err := state.SnapshotPath(snapshotID, repo.ID, "jammy", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "amd64.tsv")
	if err := os.WriteFile(stage, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	commit, _, err := canonical.InstallPaths(map[string]string{canonicalPath: stage}, "seed incomplete APT snapshot")
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := state.SnapshotRef(snapshotID, repo.ID, "jammy", "amd64")
	if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, commit, true); err != nil {
		t.Fatal(err)
	}
	values := commonFlags{workers: 1, chunk: 1, arches: csvFlag{items: []string{"amd64"}}}
	if _, err := selectedSnapshotPublicationLeaves(canonical, cfg, []config.Repo{repo}, snapshotID, values); err == nil || !strings.Contains(err.Error(), "arm64") || !strings.Contains(err.Error(), "configured sibling ref") {
		t.Fatalf("incomplete widened APT snapshot was accepted: %v", err)
	}
	armPath, _ := state.SnapshotPath(snapshotID, repo.ID, "jammy", "arm64")
	armCommit, _, err := canonical.InstallPaths(map[string]string{armPath: stage}, "complete APT snapshot")
	if err != nil {
		t.Fatal(err)
	}
	armRef, _ := state.SnapshotRef(snapshotID, repo.ID, "jammy", "arm64")
	if err := canonical.AdvanceRef(armRef, plumbing.ZeroHash, armCommit, true); err != nil {
		t.Fatal(err)
	}
	leaves, err := selectedSnapshotPublicationLeaves(canonical, cfg, []config.Repo{repo}, snapshotID, values)
	if err != nil || len(leaves) != 2 || strings.Join(leaves[0].repo.APT.ComponentsForSuite("jammy"), ",") != "main" || leaves[0].repo.LifecycleForSuite("jammy") != "frozen" {
		t.Fatalf("complete sparse snapshot leaves=%+v err=%v", leaves, err)
	}
	leaves[0].repo.APT.SuiteComponents["jammy"][0] = "mutated"
	leaves[0].repo.APT.SuiteLifecycle["jammy"] = "active"
	if repo.APT.SuiteComponents["jammy"][0] != "main" || repo.APT.SuiteLifecycle["jammy"] != "frozen" {
		t.Fatal("snapshot suite maps alias canonical configuration")
	}
}

func TestBuildL1ReportsMissingCanonicalRepositoryBaseline(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	stage := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(stage, []byte("schema: sow/v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": stage}, "initialize state without repo baseline"); err != nil {
		t.Fatal(err)
	}
	repo := config.Repo{ID: "assets", Type: "asset", Path: "assets", DefaultPool: "public", Asset: &config.AssetConfig{Kind: "test"}}
	cfg := &config.Config{Root: root, State: config.StateConfig{CASHistoryCommits: config.DefaultCASHistory}}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	checks, err := buildL1Checks(context.Background(), cfg, canonical, pool, []config.Repo{repo}, nil, commonFlags{workers: 1, chunk: 1}, "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	report := verify.Run(context.Background(), verify.Request{Layers: []verify.Layer{verify.LayerL1}, Checks: checks, Workers: 1})
	found := false
	for _, finding := range report.Findings {
		found = found || finding.Code == "REPO_REF_MISSING" && strings.Contains(finding.Subject, "refs/sow/repos/assets")
	}
	if !found || report.Exit == verify.ExitSuccess {
		t.Fatalf("missing canonical baseline was not an L1 failure: %+v", report)
	}
}

func TestYUMGenerationIdentityGuardFailsClosedOnNil(t *testing.T) {
	expected := &yumrepo.Generation{RepomdSHA256: strings.Repeat("a", 64), Packages: 7}
	if yumGenerationMatches(nil, expected.RepomdSHA256, expected.Packages) || yumGenerationMatchesExpected(nil, expected, expected.Packages) || yumGenerationMatchesExpected(expected, nil, expected.Packages) {
		t.Fatal("nil YUM validator result was accepted")
	}
	if !yumGenerationMatches(expected, expected.RepomdSHA256, expected.Packages) || !yumGenerationMatchesExpected(expected, expected, expected.Packages) {
		t.Fatal("exact YUM generation identity was rejected")
	}
	if yumGenerationMatches(expected, expected.RepomdSHA256, expected.Packages+1) || yumGenerationMatches(expected, strings.Repeat("b", 64), expected.Packages) {
		t.Fatal("mismatched YUM generation identity was accepted")
	}
}

type gateWriter struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

type failingStateLockReleaser struct {
	err   error
	calls int
}

func (lock *failingStateLockReleaser) Release() error {
	lock.calls++
	return lock.err
}

func TestStateLockReleaseFailureChangesOnlySuccessfulCommandResult(t *testing.T) {
	releaseErr := fmt.Errorf("durable lock record changed")
	lock := &failingStateLockReleaser{err: releaseErr}
	var resultErr error
	var stderr bytes.Buffer
	propagateStateLockRelease(lock, &resultErr, &stderr)
	if lock.calls != 1 || exitCode(resultErr) != ExitInternal || !strings.Contains(resultErr.Error(), releaseErr.Error()) {
		t.Fatalf("successful command ignored lock release failure: calls=%d err=%v", lock.calls, resultErr)
	}
	if stderr.Len() != 0 {
		t.Fatalf("successful command duplicated returned release error on stderr: %q", stderr.String())
	}

	primary := withExitCode(ExitConfig, "primary command failure")
	resultErr = primary
	propagateStateLockRelease(lock, &resultErr, &stderr)
	if lock.calls != 2 || resultErr != primary || exitCode(resultErr) != ExitConfig {
		t.Fatalf("release failure replaced primary result: calls=%d err=%v", lock.calls, resultErr)
	}
	if !strings.Contains(stderr.String(), "warning: release state lock") || !strings.Contains(stderr.String(), releaseErr.Error()) {
		t.Fatalf("release failure beside primary error was not diagnosed: %q", stderr.String())
	}
}

type failingSyncOperationCloser struct {
	err   error
	calls int
}

func (operation *failingSyncOperationCloser) Close() error {
	operation.calls++
	return operation.err
}

func TestSyncOperationCloseFailureChangesOnlySuccessfulCommandResult(t *testing.T) {
	closeErr := fmt.Errorf("operation lease descriptor changed")
	operation := &failingSyncOperationCloser{err: closeErr}
	var resultErr error
	var stderr bytes.Buffer
	propagateSyncOperationClose(operation, "pgdg", &resultErr, &stderr)
	if operation.calls != 1 || exitCode(resultErr) != ExitInternal || !strings.Contains(resultErr.Error(), closeErr.Error()) {
		t.Fatalf("successful sync ignored operation close failure: calls=%d err=%v", operation.calls, resultErr)
	}
	if stderr.Len() != 0 {
		t.Fatalf("successful sync duplicated returned close error on stderr: %q", stderr.String())
	}

	primary := withExitCode(ExitVerification, "primary sync failure")
	resultErr = primary
	propagateSyncOperationClose(operation, "pgdg", &resultErr, &stderr)
	if operation.calls != 2 || resultErr != primary || exitCode(resultErr) != ExitVerification {
		t.Fatalf("operation close failure replaced primary result: calls=%d err=%v", operation.calls, resultErr)
	}
	if !strings.Contains(stderr.String(), "warning: close upstream pgdg sync operation") || !strings.Contains(stderr.String(), closeErr.Error()) {
		t.Fatalf("operation close failure beside primary error was not diagnosed: %q", stderr.String())
	}
}

func TestCanonicalFSCKFinalizerFailureIsNeverDiscarded(t *testing.T) {
	finalizeErr := fmt.Errorf("canonical worktree changed after scan")
	calls := 0
	finalize := func() error {
		calls++
		return finalizeErr
	}

	var resultErr error
	propagateCanonicalFSCKFinalizer(finalize, "canonical Git audit", &resultErr)
	if calls != 1 || exitCode(resultErr) != ExitVerification || !strings.Contains(resultErr.Error(), finalizeErr.Error()) {
		t.Fatalf("successful fsck ignored final integrity failure: calls=%d err=%v", calls, resultErr)
	}

	primary := withExitCode(ExitNetworkAuth, "remote inventory request failed")
	resultErr = primary
	propagateCanonicalFSCKFinalizer(finalize, "canonical Git topology", &resultErr)
	if calls != 2 || exitCode(resultErr) != ExitNetworkAuth {
		t.Fatalf("final topology failure replaced the primary exit class: calls=%d err=%v", calls, resultErr)
	}
	if !strings.Contains(resultErr.Error(), primary.Error()) || !strings.Contains(resultErr.Error(), finalizeErr.Error()) {
		t.Fatalf("joined fsck failure does not expose both causes: %v", resultErr)
	}
}

func TestYUMCompatibilityCleanupFailureChangesOnlySuccessfulCommandResult(t *testing.T) {
	cleanupErr := fmt.Errorf("bound directory descriptor changed")
	calls := 0
	cleanup := func() error {
		calls++
		return cleanupErr
	}
	var resultErr error
	var stderr bytes.Buffer
	propagateYUMCompatibilityCleanup("close compatibility root binding", cleanup, &resultErr, &stderr)
	if calls != 1 || exitCode(resultErr) != ExitInternal || !strings.Contains(resultErr.Error(), cleanupErr.Error()) {
		t.Fatalf("successful compatibility command ignored cleanup failure: calls=%d err=%v", calls, resultErr)
	}
	if stderr.Len() != 0 {
		t.Fatalf("successful compatibility command duplicated cleanup error: %q", stderr.String())
	}

	primary := withExitCode(ExitConflict, "candidate identity changed")
	resultErr = primary
	propagateYUMCompatibilityCleanup("close compatibility root binding", cleanup, &resultErr, &stderr)
	if calls != 2 || resultErr != primary || exitCode(resultErr) != ExitConflict {
		t.Fatalf("cleanup failure replaced primary compatibility result: calls=%d err=%v", calls, resultErr)
	}
	if !strings.Contains(stderr.String(), "warning: close compatibility root binding") || !strings.Contains(stderr.String(), cleanupErr.Error()) {
		t.Fatalf("cleanup failure beside primary error was not diagnosed: %q", stderr.String())
	}
}

func (writer *gateWriter) Write(body []byte) (int, error) {
	writer.once.Do(func() { close(writer.entered) })
	<-writer.release
	return len(body), nil
}

func TestVerifyHoldsStateOperationLockThroughReportEmission(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "asset"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "asset", "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var initOut, initErr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath, "--workers", "1", "--chunk-entries", "1"}, &initOut, &initErr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, initOut.String(), initErr.String())
	}

	output := &gateWriter{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		var stderr bytes.Buffer
		done <- runVerify(context.Background(), []string{"--layer", "L1", "--config", configPath, "--repo", "asset", "--workers", "1", "--chunk-entries", "1"}, output, &stderr)
	}()
	select {
	case <-output.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("verify did not reach report emission")
	}
	competing, err := state.AcquireLock(filepath.Join(root, ".sow"), "competing-test", false)
	if err == nil {
		_ = competing.Release()
		close(output.release)
		t.Fatal("a competing state operation acquired the lock while verify was emitting its report")
	}
	if !strings.Contains(err.Error(), "running verify") && !strings.Contains(err.Error(), "active process instance holding the persistent lease") {
		close(output.release)
		t.Fatalf("unexpected competing lock error: %v", err)
	}
	close(output.release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("verify did not finish after report writer was released")
	}
	if lock, err := state.AcquireLock(filepath.Join(root, ".sow"), "after-verify", false); err != nil {
		t.Fatalf("verify did not release the state lock: %v", err)
	} else if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}
