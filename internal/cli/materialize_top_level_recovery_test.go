package cli

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
)

type topLevelPackageFixture struct {
	root       string
	configPath string
	keyPath    string
	cfg        *config.Config
	canonical  *state.Store
}

func setupTopLevelPackageFixture(t *testing.T, promoteAll bool) topLevelPackageFixture {
	t.Helper()
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishMultiLeafPackageAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "yum", "test", "x86_64"), 0o755); err != nil {
		t.Fatal(err)
	}
	keyPath := writePublishTestPrivateKey(t, root)
	rpmPath := writeRestoreRPMFixture(t, root, "1.0.0")
	if code, stdout, stderr := runTopLevelRecoveryCLI(t, "add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--arch", "x86_64", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("seed RPM code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := runTopLevelRecoveryCLI(t, "init", "--config", configPath, "--repo", "rpm-test", "--arch", "x86_64", "--workers", "1", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("seed repository baseline code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if promoteAll {
		for _, pair := range [][2]string{{"beta", "latest"}, {"latest", "stable"}} {
			if code, stdout, stderr := runTopLevelRecoveryCLI(t, "promote", pair[0], pair[1], "--config", configPath, "--repo", "rpm-test", "--arch", "x86_64"); code != ExitOK {
				t.Fatalf("promote %s/%s code=%d stdout=%s stderr=%s", pair[0], pair[1], code, stdout, stderr)
			}
		}
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	return topLevelPackageFixture{root: root, configPath: configPath, keyPath: keyPath, cfg: cfg, canonical: state.New(cfg.StatePath())}
}

func leaveMutablePublishMaterializationJournal(t *testing.T, fixture topLevelPackageFixture, viewName string) materializationSelectionJournal {
	t.Helper()
	values := commonFlags{
		configPath: fixture.configPath,
		repos:      csvFlag{items: []string{"rpm-test"}},
		arches:     csvFlag{items: []string{"x86_64"}},
		workers:    1,
		chunk:      2,
	}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := os.ReadFile(fixture.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	repositoryKeySHA, err := repositorySigningKeyIdentity(cfg, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaves := selectedLeaves(repos, values)
	snapshot, err := captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	values.materializeTrust = snapshot
	values.materializeOperation = "publish"
	target, err := defaultMutableServingTarget(cfg, viewName)
	if err != nil {
		t.Fatal(err)
	}
	source := materializeCanonicalSource{ID: viewName, Public: cfg.Views[viewName].Access == "public"}
	requests := []materializationSelectionRequest{
		{Source: source, Leaves: leaves, TargetRoot: cfg.Root, IncludeMetadata: true, ExpandAPT: true},
		{Source: source, Leaves: leaves, TargetRoot: target, IncludeServing: true},
	}
	values, owner, err := beginMaterializationSelectionForRequests(cfg, fixture.canonical, values, "publish", requests)
	if err != nil || !owner {
		t.Fatalf("leave publication materialization owner=%t err=%v", owner, err)
	}
	values.materializeTrust.resetMaterializationSelection()
	journal, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists {
		t.Fatalf("read publication materialization journal exists=%t err=%v", exists, err)
	}
	for _, unit := range journal.Units {
		if unit.Source != viewName {
			t.Fatalf("durable publication expanded source=%s want=%s", unit.Source, viewName)
		}
	}
	return journal
}

func runTopLevelRecoveryCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Main(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

type journalGuardTransport struct {
	stateRoot string
	delegate  http.RoundTripper

	mu               sync.Mutex
	calls            int
	callsWithJournal int
	journalErr       error
}

func (transport *journalGuardTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	_, active, err := readMaterializationSelectionJournal(transport.stateRoot)
	transport.mu.Lock()
	transport.calls++
	if active {
		transport.callsWithJournal++
	}
	if err != nil && transport.journalErr == nil {
		transport.journalErr = err
	}
	transport.mu.Unlock()
	return transport.delegate.RoundTrip(request)
}

func (transport *journalGuardTransport) counts() (calls, callsWithJournal int, err error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.calls, transport.callsWithJournal, transport.journalErr
}

func TestPublishRecoverClosesDurableSingleViewBeforeDefaultOrMultiViewRemoteWork(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "default", args: nil},
		{name: "multi-view", args: []string{"--view", "beta", "--view", "latest"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := setupTopLevelPackageFixture(t, true)
			journal := leaveMutablePublishMaterializationJournal(t, fixture, "beta")
			if len(journal.Units) != 2 {
				t.Fatalf("durable beta selected set units=%d want=2", len(journal.Units))
			}
			t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
			t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
			protocol := newCloudProtocolTransport()
			guard := &journalGuardTransport{stateRoot: fixture.cfg.StatePath(), delegate: protocol}
			previousClient := publishProviderHTTPClient
			publishProviderHTTPClient = &http.Client{Transport: guard}
			t.Cleanup(func() { publishProviderHTTPClient = previousClient })

			args := []string{"publish", "--target", "cf", "--config", fixture.configPath, "--repo", "rpm-test", "--arch", "x86_64", "--gpg-private-key-file", fixture.keyPath, "--workers", "1", "--chunk-entries", "2", "--recover"}
			args = append(args, test.args...)
			code, stdout, stderr := runTopLevelRecoveryCLI(t, args...)
			if code != ExitOK {
				t.Fatalf("publish recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			calls, callsWithJournal, journalErr := guard.counts()
			if journalErr != nil || calls == 0 || callsWithJournal != 0 {
				t.Fatalf("remote ordering calls=%d while_journal=%d journal_err=%v stdout=%s", calls, callsWithJournal, journalErr, stdout)
			}
			if _, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath()); err != nil || exists {
				t.Fatalf("publish recovery retained durable single-view journal exists=%t err=%v", exists, err)
			}
		})
	}
}

func TestActiveMaterializationJournalStrictlyFencesWritersAndReportsReadOnlyAudits(t *testing.T) {
	fixture := setupTopLevelPackageFixture(t, true)
	journal := leaveMutablePublishMaterializationJournal(t, fixture, "beta")
	asset := filepath.Join(fixture.root, "blocked-asset.txt")
	if err := os.WriteFile(asset, []byte("must-not-be-added\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)

	commands := []struct {
		name string
		args []string
	}{
		{name: "init", args: []string{"init", "--config", fixture.configPath}},
		{name: "promote", args: []string{"promote", "beta", "latest", "--config", fixture.configPath, "--repo", "rpm-test", "--arch", "x86_64"}},
		{name: "gc", args: []string{"gc", "--config", fixture.configPath}},
		{name: "asset-add", args: []string{"add", asset, "--config", fixture.configPath, "--repo", "assets", "--dest", "blocked"}},
		{name: "verify-recover", args: []string{"verify", "--layer", "L1", "--view", "beta", "--config", fixture.configPath, "--repo", "rpm-test", "--arch", "x86_64", "--recover"}},
		{name: "fsck-adopt", args: []string{"fsck", "--config", fixture.configPath, "--target", "cf", "--adopt-remote-inventory"}},
	}
	for _, command := range commands {
		code, stdout, stderr := runTopLevelRecoveryCLI(t, command.args...)
		if code != ExitConflict || !strings.Contains(stderr, "durable materialization intent") {
			t.Fatalf("%s was not strictly fenced code=%d stdout=%s stderr=%s", command.name, code, stdout, stderr)
		}
		current, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath())
		if err != nil || !exists || current.ID != journal.ID {
			t.Fatalf("%s changed durable fence journal=%+v exists=%t err=%v", command.name, current, exists, err)
		}
	}

	code, stdout, stderr := runTopLevelRecoveryCLI(t, "verify", "--layer", "L1", "--view", "beta", "--config", fixture.configPath, "--repo", "rpm-test", "--arch", "x86_64", "--gpg-public-key-file", fixture.keyPath+".pub", "--workers", "1")
	if code == ExitOK || !strings.Contains(stdout, "code=MATERIALIZATION_RECOVERY_REQUIRED") || !strings.Contains(stdout, `operation="publish"`) {
		t.Fatalf("ordinary verify did not report durable fence code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runTopLevelRecoveryCLI(t, "fsck", "--config", fixture.configPath, "--repo", "rpm-test", "--arch", "x86_64", "--limit", "0")
	if code != ExitVerification || !strings.Contains(stdout, "drift materialization_operation=publish") || !strings.Contains(stdout, "recovery_required=true") {
		t.Fatalf("ordinary fsck did not report durable fence code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if current, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath()); err != nil || !exists || current.ID != journal.ID {
		t.Fatalf("read-only audits changed durable fence journal=%+v exists=%t err=%v", current, exists, err)
	}
}

func TestSyncMaterializationScopeSeparatesSameRepoUpstreams(t *testing.T) {
	fixture := setupMaterializationSelectionFixture(t)
	selectionSHA := strings.Repeat("1", 64)
	fixture.snapshot.operationScope = syncMaterializationScope("upstream-a", selectionSHA)
	owner, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "sync", false, fixture.units)
	if err != nil || !owner {
		t.Fatalf("begin scoped sync selection owner=%t err=%v", owner, err)
	}
	fixture.snapshot.resetMaterializationSelection()
	journalA, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath())
	if err != nil || !exists {
		t.Fatalf("read scoped sync journal exists=%t err=%v", exists, err)
	}
	upstreamID, parsedSelection, err := parseSyncMaterializationScope(journalA.OperationScope)
	if err != nil || upstreamID != "upstream-a" || parsedSelection != selectionSHA {
		t.Fatalf("parse scoped sync journal upstream=%s selection=%s err=%v", upstreamID, parsedSelection, err)
	}

	snapshotB := recaptureMaterializationSelectionTrust(t, fixture)
	snapshotB.operationScope = syncMaterializationScope("upstream-b", selectionSHA)
	configSHA, parentConfigSHA, expectedHead, err := currentMaterializationCanonicalIdentity(fixture.cfg, fixture.canonical)
	if err != nil {
		t.Fatal(err)
	}
	journalB, err := newMaterializationSelectionJournal("sync", configSHA, parentConfigSHA, expectedHead, snapshotB, fixture.units)
	if err != nil {
		t.Fatal(err)
	}
	if journalA.ID == journalB.ID || journalA.OperationScope == journalB.OperationScope {
		t.Fatalf("same-repo upstream scopes were not identity-bound a=%+v b=%+v", journalA, journalB)
	}
	if owner, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, snapshotB, "sync", true, fixture.units); err == nil || owner || !strings.Contains(err.Error(), "frozen trust differs") {
		t.Fatalf("different upstream rebound durable sync selection owner=%t err=%v", owner, err)
	}

	wrongUpstream := config.Upstream{ID: "upstream-b", Repo: "deb-test", Type: "apt", Arches: []string{"arm64"}, Suite: "jammy"}
	if recovered, err := checkSyncRecovery(t.Context(), fixture.cfg, fixture.canonical, false, []config.Upstream{wrongUpstream}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || recovered || !strings.Contains(err.Error(), "exact upstream upstream-a") {
		t.Fatalf("same-repo wrong upstream admitted recovered=%t err=%v", recovered, err)
	}
	if current, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath()); err != nil || !exists || current.ID != journalA.ID {
		t.Fatalf("wrong upstream changed durable sync journal=%+v exists=%t err=%v", current, exists, err)
	}
}

func TestSyncJournalTempCleanupOccursOnlyAfterStateLockAcquisition(t *testing.T) {
	fixture := setupMaterializationSelectionFixture(t)
	directory, _, err := materializationSelectionJournalDirectory(fixture.cfg.StatePath(), true)
	if err != nil {
		t.Fatal(err)
	}
	tempPath := filepath.Join(directory, "active.json.tmp-0123456789abcdef")
	if err := os.WriteFile(tempPath, []byte("interrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	holder, err := state.AcquireLock(fixture.cfg.StatePath(), "test-holder", false)
	if err != nil {
		t.Fatal(err)
	}
	upstream := config.Upstream{ID: "upstream-a", Repo: "deb-test", Type: "apt", Arches: []string{"arm64"}, Suite: "jammy"}
	if recovered, err := checkSyncRecovery(t.Context(), fixture.cfg, fixture.canonical, false, []config.Upstream{upstream}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || recovered {
		_ = holder.Release()
		t.Fatalf("sync recovery entered held state lock recovered=%t err=%v", recovered, err)
	}
	if _, err := os.Lstat(tempPath); err != nil {
		_ = holder.Release()
		t.Fatalf("failed lock acquisition cleaned journal temp: %v", err)
	}
	if err := holder.Release(); err != nil {
		t.Fatal(err)
	}
	if recovered, err := checkSyncRecovery(t.Context(), fixture.cfg, fixture.canonical, false, []config.Upstream{upstream}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil || recovered {
		t.Fatalf("locked temp cleanup recovered=%t err=%v", recovered, err)
	}
	if _, err := os.Lstat(tempPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state-lock-owned sync recovery retained temp: %v", err)
	}
}

func TestRestorePackageMaterializationJournalExactRecoverIsReentrantAndClears(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishRestorePackageConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := writePublishTestPrivateKey(t, root)
	debOne := writeRetentionDEB(t, root, "1.0.0")
	debTwo := writeRetentionDEB(t, root, "2.0.0")
	rpmOne := writeRestoreRPMFixture(t, root, "1.0.0")
	rpmTwo := writeRestoreRPMFixture(t, root, "2.0.0")
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })

	for _, generation := range [][]struct{ path, repo string }{
		{{debOne, "deb-restore"}, {rpmOne, "rpm-restore"}},
		{{debTwo, "deb-restore"}, {rpmTwo, "rpm-restore"}},
	} {
		for _, artifact := range generation {
			if code, stdout, stderr := runTopLevelRecoveryCLI(t, "add", artifact.path, "--config", configPath, "--repo", artifact.repo, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "2"); code != ExitOK {
				t.Fatalf("seed restore add repo=%s code=%d stdout=%s stderr=%s", artifact.repo, code, stdout, stderr)
			}
		}
		if code, stdout, stderr := runTopLevelRecoveryCLI(t, "publish", "--view", "beta", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("seed restore publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	}

	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	historical, err := loadHistoricalTargetPublication(canonical, "cf", 1)
	if err != nil {
		t.Fatal(err)
	}
	historicalLeaves, err := configuredHistoricalLeaves(cfg, historical.Generation)
	if err != nil {
		t.Fatal(err)
	}
	leaves := make([]viewLeaf, 0, len(historicalLeaves))
	refCommits := make(map[string]plumbing.Hash, len(historicalLeaves))
	for name, historicalLeaf := range historicalLeaves {
		leaves = append(leaves, historicalLeaf.leaf)
		refCommits[name] = plumbing.NewHash(historicalLeaf.ref.Commit)
	}
	privateKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	repositoryKeySHA, err := repositorySigningKeyIdentity(cfg, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	restoreRoot := filepath.Join(root, ".sow", "materialized", "restores", "cf", fmt.Sprintf("%020d", historical.Generation.Generation), historical.Generation.IntentView)
	values := commonFlags{workers: 1, chunk: 2, materializeTrust: snapshot, materializeOperation: "publish"}
	source := materializeCanonicalSource{ID: historical.Generation.IntentView, Public: true, RefCommits: refCommits}
	values, owner, err := beginMaterializationSelectionForSource(cfg, canonical, values, "publish", source, leaves, restoreRoot, true, false)
	if err != nil || !owner {
		t.Fatalf("leave historical package materialization owner=%t err=%v", owner, err)
	}
	values.materializeTrust.resetMaterializationSelection()
	journal, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists || len(journal.Units) != 2 {
		t.Fatalf("historical package journal=%+v exists=%t err=%v", journal, exists, err)
	}
	for _, unit := range journal.Units {
		if !unit.Historical || unit.Source != "beta" {
			t.Fatalf("restore journal contains non-historical unit: %+v", unit)
		}
	}

	guard := &journalGuardTransport{stateRoot: cfg.StatePath(), delegate: transport}
	publishProviderHTTPClient = &http.Client{Transport: guard}
	code, stdout, stderr := runTopLevelRecoveryCLI(t, "publish", "--restore-generation", "2", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "2", "--recover")
	if code != ExitConflict || !strings.Contains(stderr, "does not match --restore-generation 2 --target cf") {
		t.Fatalf("mismatched historical recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if calls, callsWithJournal, journalErr := guard.counts(); journalErr != nil || calls != 0 || callsWithJournal != 0 {
		t.Fatalf("mismatched historical recovery accessed remote calls=%d while_journal=%d journal_err=%v", calls, callsWithJournal, journalErr)
	}
	if current, exists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || !exists || current.ID != journal.ID {
		t.Fatalf("mismatched historical recovery changed durable journal=%+v exists=%t err=%v", current, exists, err)
	}

	code, stdout, stderr = runTopLevelRecoveryCLI(t, "publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "2", "--recover")
	if code != ExitOK || !strings.Contains(stdout, "source_generation=1") || !strings.Contains(stdout, "status=complete") {
		t.Fatalf("exact package restore recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if calls, callsWithJournal, journalErr := guard.counts(); journalErr != nil || calls == 0 || callsWithJournal != 0 {
		t.Fatalf("exact historical recovery remote ordering calls=%d while_journal=%d journal_err=%v stdout=%s", calls, callsWithJournal, journalErr, stdout)
	}
	if _, exists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || exists {
		t.Fatalf("exact package restore retained journal exists=%t err=%v", exists, err)
	}
	transport.mutex.Lock()
	puts, purges, cdnGets := transport.puts, transport.purges, transport.cdnGets
	transport.mutex.Unlock()
	code, stdout, stderr = runTopLevelRecoveryCLI(t, "publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "2", "--recover")
	if code != ExitOK || !strings.Contains(stdout, "status=unchanged") || !strings.Contains(stdout, "status=complete") {
		t.Fatalf("reentrant exact package restore code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	if transport.puts != puts || transport.purges != purges || transport.cdnGets != cdnGets {
		t.Fatalf("reentrant package restore repeated remote effects puts=%d/%d purges=%d/%d cdn=%d/%d", puts, transport.puts, purges, transport.purges, cdnGets, transport.cdnGets)
	}
}
