package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/catalog"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
)

func TestBuildL1WiresCanonicalSQLiteCacheCheck(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, ".sow")
	manifestPath := filepath.Join(t.TempDir(), "assets-bin.tsv")
	data := "bin/tool\t1\tca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\n"
	if err := os.WriteFile(manifestPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(stateDir)
	commit, _, err := canonical.InstallPaths(map[string]string{
		"manifests/assets-bin.tsv": manifestPath,
		"config/sow.yaml":          filepath.Join("..", "..", "sow.example.yaml"),
	}, "cache verify fixture")
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := state.RepoRef("assets-bin")
	if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Rebuild(stateDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(catalog.Path(stateDir), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", catalog.Path(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	_, updateErr := db.Exec(`UPDATE meta SET value=CASE key WHEN 'schema_version' THEN '999' WHEN 'canonical_head' THEN '0000000000000000000000000000000000000000' ELSE value END WHERE key IN ('schema_version','canonical_head')`)
	closeErr := db.Close()
	if updateErr != nil || closeErr != nil {
		t.Fatalf("inject schema drift: %v / %v", updateErr, closeErr)
	}

	cfg := &config.Config{Root: root, State: config.StateConfig{CASHistoryCommits: config.DefaultCASHistory}}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	checks, err := buildL1Checks(context.Background(), cfg, canonical, pool, []config.Repo{{ID: "assets-bin", Type: "asset", Path: "bin"}}, nil, commonFlags{workers: 1, chunk: 2}, "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var cacheChecks []verify.Check
	for _, check := range checks {
		if _, ok := check.(verify.CacheCheck); ok {
			cacheChecks = append(cacheChecks, check)
		}
	}
	if len(cacheChecks) != 1 {
		t.Fatalf("L1 cache checks=%d, all checks=%d", len(cacheChecks), len(checks))
	}
	report := verify.Run(context.Background(), verify.Request{Layers: []verify.Layer{verify.LayerL1}, Checks: cacheChecks, Workers: 1})
	foundSchema, foundHead := false, false
	for _, finding := range report.Findings {
		foundSchema = foundSchema || finding.Code == "CACHE_SCHEMA_DRIFT"
		foundHead = foundHead || finding.Code == "CACHE_HEAD_DRIFT"
	}
	if !foundSchema || !foundHead || report.Exit != verify.ExitVerification {
		t.Fatalf("cache schema drift was not a verification failure: %+v", report)
	}
}

func TestCanonicalApplyKeepsCatalogExactAcrossNeutralAndRelevantMutations(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	stateDir := filepath.Join(root, ".sow")
	canonical := state.New(stateDir)
	baseline, err := canonical.HeadHash()
	if err != nil || baseline.IsZero() {
		t.Fatalf("baseline head=%s err=%v", baseline, err)
	}
	before, err := catalog.Statistics(t.Context(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	stageDir, err := os.MkdirTemp(stateDir, "catalog-apply-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stageDir)
	neutralStage := filepath.Join(stageDir, "serving.json")
	if err := os.WriteFile(neutralStage, []byte("{\"phase\":\"complete\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	neutralHead, changed, err := applyCanonicalState(t.Context(), canonical, "catalog-neutral-test", "test: projection-neutral ledger", map[string]string{
		"serving/test/ledger.json": neutralStage,
	}, nil, state.ApplyOptions{})
	if err != nil || !changed {
		t.Fatalf("neutral apply head=%s changed=%t err=%v", neutralHead, changed, err)
	}
	cacheHead, err := catalog.CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != neutralHead {
		t.Fatalf("neutral cache head=%s want=%s err=%v", cacheHead, neutralHead, err)
	}
	afterNeutral, err := catalog.Statistics(t.Context(), stateDir)
	if err != nil || afterNeutral != before {
		t.Fatalf("neutral mutation changed projection before=%+v after=%+v err=%v", before, afterNeutral, err)
	}

	manifestStage := filepath.Join(stageDir, "asset.tsv")
	const digest = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	if err := os.WriteFile(manifestStage, []byte("asset/tool.bin\t1\t"+digest+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repoRef, err := state.RepoRef("asset")
	if err != nil {
		t.Fatal(err)
	}
	expected, exists, err := canonical.Ref(repoRef)
	if err != nil || !exists {
		t.Fatalf("repo ref=%s exists=%t err=%v", expected, exists, err)
	}
	relevantHead, changed, err := applyCanonicalState(t.Context(), canonical, "catalog-relevant-test", "test: projection-relevant manifest", map[string]string{
		"manifests/asset.tsv": manifestStage,
	}, []state.RefUpdate{{Name: repoRef, Expected: expected}}, state.ApplyOptions{})
	if err != nil || !changed {
		t.Fatalf("relevant apply head=%s changed=%t err=%v", relevantHead, changed, err)
	}
	cacheHead, err = catalog.CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != relevantHead {
		t.Fatalf("relevant cache head=%s want=%s err=%v", cacheHead, relevantHead, err)
	}
	afterRelevant, err := catalog.Statistics(t.Context(), stateDir)
	if err != nil || afterRelevant.Files != before.Files+1 {
		t.Fatalf("relevant projection files=%d want=%d stats=%+v err=%v", afterRelevant.Files, before.Files+1, afterRelevant, err)
	}
}

func TestCanonicalApplyNoopRefUpdateDoesNotRebuildCatalog(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	stateDir := filepath.Join(root, ".sow")
	canonical := state.New(stateDir)
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		t.Fatalf("baseline head=%s err=%v", head, err)
	}
	manifest, err := canonical.OpenPath("manifests/asset.tsv")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(manifest)
	closeErr := manifest.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal(errors.Join(readErr, closeErr))
	}
	stageDir, err := os.MkdirTemp(stateDir, "catalog-noop-ref-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stageDir)
	stage := filepath.Join(stageDir, "asset.tsv")
	if err := os.WriteFile(stage, body, 0o600); err != nil {
		t.Fatal(err)
	}
	repoRef, _ := state.RepoRef("asset")
	expected, exists, err := canonical.Ref(repoRef)
	if err != nil || !exists {
		t.Fatalf("repo ref=%s exists=%t err=%v", expected, exists, err)
	}
	cacheBefore, err := os.Stat(catalog.Path(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	result, changed, err := applyCanonicalState(t.Context(), canonical, "catalog-noop-ref-test", "test: exact no-op ref replay",
		map[string]string{"manifests/asset.tsv": stage}, []state.RefUpdate{{Name: repoRef, Expected: expected}}, state.ApplyOptions{})
	if err != nil || changed || result != head {
		t.Fatalf("no-op ref apply head=%s want=%s changed=%t err=%v", result, head, changed, err)
	}
	cacheAfter, err := os.Stat(catalog.Path(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(cacheBefore, cacheAfter) {
		t.Fatal("no-op ref update replaced the SQLite cache instead of validating its exact HEAD")
	}
	cacheHead, err := catalog.CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != head {
		t.Fatalf("no-op cache head=%s want=%s err=%v", cacheHead, head, err)
	}
}

func TestPendingCatalogProjectionRecoversOnNormalRestart(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	stateDir := filepath.Join(root, ".sow")
	canonical := state.New(stateDir)
	before, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	if err := beginCatalogProjectionMutation(stateDir, before); err != nil {
		t.Fatal(err)
	}
	stageDir, err := os.MkdirTemp(stateDir, "catalog-crash-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stageDir)
	stage := filepath.Join(stageDir, "ledger.json")
	if err := os.WriteFile(stage, []byte("{\"complete\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, changed, err := canonical.Apply(t.Context(), "catalog-crash-test", "test: complete canonical commit before projection", map[string]string{
		"serving/test/crash.json": stage,
	}, nil, state.ApplyOptions{})
	if err != nil || !changed {
		t.Fatalf("canonical crash fixture head=%s changed=%t err=%v", after, changed, err)
	}
	cacheHead, err := catalog.CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != before {
		t.Fatalf("fixture cache head=%s want stale=%s err=%v", cacheHead, before, err)
	}
	var output bytes.Buffer
	if err := prepareCanonicalStateCore(t.Context(), canonical, false, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "cache rebuilt after pending projection") {
		t.Fatalf("normal restart omitted projection recovery evidence: %s", output.String())
	}
	cacheHead, err = catalog.CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != after {
		t.Fatalf("recovered cache head=%s want=%s err=%v", cacheHead, after, err)
	}
	if pending, err := pendingCatalogProjectionMutation(stateDir); err != nil || pending {
		t.Fatalf("pending marker after recovery=%t err=%v", pending, err)
	}
}

func TestPendingCatalogProjectionRebuildsEvenWhenMetadataHeadMatches(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "asset"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "asset", "tool.bin"), []byte("catalog projection fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	stateDir := filepath.Join(root, ".sow")
	canonical := state.New(stateDir)
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		t.Fatalf("canonical head=%s err=%v", head, err)
	}
	if err := beginCatalogProjectionMutation(stateDir, head); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(catalog.Path(stateDir), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", catalog.Path(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	_, deleteErr := db.Exec(`DELETE FROM files`)
	closeErr := db.Close()
	if deleteErr != nil || closeErr != nil {
		t.Fatalf("inject row drift with matching metadata head: %v / %v", deleteErr, closeErr)
	}
	if count, err := catalog.Count(stateDir); err != nil || count != 0 {
		t.Fatalf("fixture cache count=%d err=%v", count, err)
	}
	var output bytes.Buffer
	if err := prepareCanonicalStateCore(t.Context(), canonical, false, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "cache rebuilt after pending projection") {
		t.Fatalf("pending recovery omitted rebuild evidence: %s", output.String())
	}
	if count, err := catalog.Count(stateDir); err != nil || count == 0 {
		t.Fatalf("pending recovery trusted matching metadata over canonical rows: count=%d err=%v", count, err)
	}
	if pending, err := pendingCatalogProjectionMutation(stateDir); err != nil || pending {
		t.Fatalf("pending marker after exact rebuild=%t err=%v", pending, err)
	}
}

func TestExplicitRecoveryRebuildsMissingCatalogWithoutPendingMarker(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	stateDir := filepath.Join(root, ".sow")
	canonical := state.New(stateDir)
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		t.Fatalf("canonical head=%s err=%v", head, err)
	}
	if err := os.Remove(catalog.Path(stateDir)); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := prepareCanonicalStateCore(t.Context(), canonical, true, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "cache rebuilt after recovery") {
		t.Fatalf("explicit cache recovery omitted evidence: %s", output.String())
	}
	cacheHead, err := catalog.CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != head {
		t.Fatalf("recovered cache head=%s want=%s err=%v", cacheHead, head, err)
	}
	if version, err := catalog.Version(t.Context(), stateDir); err != nil || version != catalog.SchemaVersion {
		t.Fatalf("recovered cache schema=%d want=%d err=%v", version, catalog.SchemaVersion, err)
	}
}

func TestExplicitRecoveryRebuildsUnmarkedCatalogMetadataDrift(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	stateDir := filepath.Join(root, ".sow")
	canonical := state.New(stateDir)
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		t.Fatalf("canonical head=%s err=%v", head, err)
	}
	if err := os.Chmod(catalog.Path(stateDir), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", catalog.Path(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	_, updateErr := db.Exec(`UPDATE meta SET value=CASE key WHEN 'schema_version' THEN '999' WHEN 'canonical_head' THEN '0000000000000000000000000000000000000000' ELSE value END WHERE key IN ('schema_version','canonical_head')`)
	closeErr := db.Close()
	if updateErr != nil || closeErr != nil {
		t.Fatalf("inject unmarked metadata drift: %v / %v", updateErr, closeErr)
	}

	var output bytes.Buffer
	if err := prepareCanonicalStateCore(t.Context(), canonical, true, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "cache rebuilt after recovery") {
		t.Fatalf("explicit metadata recovery omitted evidence: %s", output.String())
	}
	cacheHead, err := catalog.CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != head {
		t.Fatalf("recovered cache head=%s want=%s err=%v", cacheHead, head, err)
	}
	if version, err := catalog.Version(t.Context(), stateDir); err != nil || version != catalog.SchemaVersion {
		t.Fatalf("recovered cache schema=%d want=%d err=%v", version, catalog.SchemaVersion, err)
	}
}

func TestExplicitRecoveryRebuildsUnmarkedCatalogRowDrift(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "asset"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "asset", "tool.bin"), []byte("explicit catalog recovery fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	stateDir := filepath.Join(root, ".sow")
	canonical := state.New(stateDir)
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		t.Fatalf("canonical head=%s err=%v", head, err)
	}
	if err := os.Chmod(catalog.Path(stateDir), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", catalog.Path(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	_, deleteErr := db.Exec(`DELETE FROM files`)
	closeErr := db.Close()
	if deleteErr != nil || closeErr != nil {
		t.Fatalf("inject unmarked row drift: %v / %v", deleteErr, closeErr)
	}
	if count, err := catalog.Count(stateDir); err != nil || count != 0 {
		t.Fatalf("drifted cache count=%d err=%v", count, err)
	}

	var output bytes.Buffer
	if err := prepareCanonicalStateCore(t.Context(), canonical, true, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "cache rebuilt after recovery") {
		t.Fatalf("explicit row recovery omitted evidence: %s", output.String())
	}
	if count, err := catalog.Count(stateDir); err != nil || count != 1 {
		t.Fatalf("recovered cache count=%d want=1 err=%v", count, err)
	}
	cacheHead, err := catalog.CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != head {
		t.Fatalf("recovered cache head=%s want=%s err=%v", cacheHead, head, err)
	}
}

func TestInterruptedCatalogRebuildResidueRequiresExplicitRecovery(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	stateDir := filepath.Join(root, ".sow")
	canonical := state.New(stateDir)
	cacheDir := filepath.Join(stateDir, "cache")
	for _, name := range []string{"state-crash.db", "state-crash.db-journal"} {
		if err := os.WriteFile(filepath.Join(cacheDir, name), []byte("interrupted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := prepareCanonicalStateCore(t.Context(), canonical, false, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "requires explicit --recover") {
		t.Fatalf("ordinary restart accepted interrupted cache rebuild residue: %v", err)
	}
	for _, name := range []string{"state-crash.db", "state-crash.db-journal"} {
		if _, err := os.Lstat(filepath.Join(cacheDir, name)); err != nil {
			t.Fatalf("ordinary restart changed %s: %v", name, err)
		}
	}

	var output bytes.Buffer
	if err := prepareCanonicalStateCore(t.Context(), canonical, true, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "recovered cache_rebuild_residues=2") ||
		!strings.Contains(output.String(), "cache rebuilt after recovery") {
		t.Fatalf("explicit recovery omitted cache residue evidence: %s", output.String())
	}
	if residues, err := catalog.InterruptedRebuildResidues(stateDir); err != nil || len(residues) != 0 {
		t.Fatalf("explicit recovery retained rebuild residues=%v err=%v", residues, err)
	}
	if info, err := os.Stat(catalog.Path(stateDir)); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("explicit recovery did not leave a usable cache: info=%v err=%v", info, err)
	}
}

func TestCatalogProjectionMarkerCoversCommitFailureUntilExplicitRecovery(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	stateDir := filepath.Join(root, ".sow")
	canonical := state.New(stateDir)
	before, err := canonical.HeadHash()
	if err != nil || before.IsZero() {
		t.Fatalf("baseline head=%s err=%v", before, err)
	}
	stageDir, err := os.MkdirTemp(stateDir, "catalog-after-commit-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stageDir)
	stage := filepath.Join(stageDir, "ledger.json")
	if err := os.WriteFile(stage, []byte("{\"committed\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("stop after durable canonical commit")
	after, changed, err := applyCanonicalState(t.Context(), canonical, "catalog-after-commit-test", "test: stop before projection", map[string]string{
		"serving/test/after-commit.json": stage,
	}, nil, state.ApplyOptions{AfterCommit: func() error { return injected }})
	if !errors.Is(err, injected) || !changed || after.IsZero() || after == before {
		t.Fatalf("injected apply head=%s changed=%t err=%v", after, changed, err)
	}
	if pending, err := pendingCatalogProjectionMutation(stateDir); err != nil || !pending {
		t.Fatalf("durable commit did not retain pending projection marker: pending=%t err=%v", pending, err)
	}
	cacheHead, err := catalog.CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != before {
		t.Fatalf("cache advanced across injected stop head=%s want=%s err=%v", cacheHead, before, err)
	}
	if err := prepareCanonicalStateCore(t.Context(), canonical, false, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "retry with --recover") {
		t.Fatalf("normal restart accepted incomplete canonical journal: %v", err)
	}
	if pending, err := pendingCatalogProjectionMutation(stateDir); err != nil || !pending {
		t.Fatalf("failed normal restart consumed marker: pending=%t err=%v", pending, err)
	}
	var output bytes.Buffer
	if err := prepareCanonicalStateCore(t.Context(), canonical, true, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "recovered transaction=") || !strings.Contains(output.String(), "cache rebuilt after recovery") {
		t.Fatalf("explicit recovery omitted evidence: %s", output.String())
	}
	cacheHead, err = catalog.CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != after {
		t.Fatalf("recovered cache head=%s want=%s err=%v", cacheHead, after, err)
	}
	if pending, err := pendingCatalogProjectionMutation(stateDir); err != nil || pending {
		t.Fatalf("explicit recovery retained marker: pending=%t err=%v", pending, err)
	}
}

func TestCatalogProjectionMarkerIsRemovedAfterPreCommitFailure(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	stateDir := filepath.Join(root, ".sow")
	canonical := state.New(stateDir)
	before, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	commit, changed, err := applyCanonicalState(ctx, canonical, "catalog-precommit-test", "test: canceled before apply", map[string]string{
		"serving/test/never.json": filepath.Join(t.TempDir(), "never.json"),
	}, nil, state.ApplyOptions{})
	if !errors.Is(err, context.Canceled) || changed || !commit.IsZero() {
		t.Fatalf("precommit result head=%s changed=%t err=%v", commit, changed, err)
	}
	after, err := canonical.HeadHash()
	if err != nil || after != before {
		t.Fatalf("precommit failure changed canonical head=%s want=%s err=%v", after, before, err)
	}
	if pending, err := pendingCatalogProjectionMutation(stateDir); err != nil || pending {
		t.Fatalf("precommit failure retained marker: pending=%t err=%v", pending, err)
	}
	cacheHead, err := catalog.CanonicalHead(t.Context(), stateDir)
	if err != nil || cacheHead != before {
		t.Fatalf("precommit failure changed cache head=%s want=%s err=%v", cacheHead, before, err)
	}
}

func TestCatalogProjectionMarkerRejectsSymlinkWithoutCanonicalMutation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	stateDir := filepath.Join(root, ".sow")
	canonical := state.New(stateDir)
	before, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	marker := catalogProjectionMutationPath(stateDir)
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "marker-target")
	if err := os.WriteFile(target, []byte(catalogProjectionMutationSchema+"\n"+before.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, marker); err != nil {
		t.Fatal(err)
	}
	if pending, err := pendingCatalogProjectionMutation(stateDir); err == nil || pending || !strings.Contains(err.Error(), "not a bounded regular file") {
		t.Fatalf("symlink marker pending=%t err=%v", pending, err)
	}
	stage := filepath.Join(t.TempDir(), "ledger.json")
	if err := os.WriteFile(stage, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	commit, changed, err := applyCanonicalState(t.Context(), canonical, "catalog-symlink-test", "test: reject symlink marker", map[string]string{
		"serving/test/symlink.json": stage,
	}, nil, state.ApplyOptions{})
	if err == nil || changed || !commit.IsZero() || !errors.Is(err, state.ErrRecoveryRequired) {
		t.Fatalf("symlink marker apply head=%s changed=%t err=%v", commit, changed, err)
	}
	after, err := canonical.HeadHash()
	if err != nil || after != before {
		t.Fatalf("symlink marker changed canonical head=%s want=%s err=%v", after, before, err)
	}
}
