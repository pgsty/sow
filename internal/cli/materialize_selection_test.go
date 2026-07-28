package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
)

type materializationSelectionFixture struct {
	cfg       *config.Config
	canonical *state.Store
	snapshot  *materializationTrustSnapshot
	units     []materializationSelectedUnit
	refName   string
	refCommit string
	private   []byte
}

func setupMaterializationSelectionFixture(t *testing.T) materializationSelectionFixture {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(snapshotAPTConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "apt", "test"), 0o755); err != nil {
		t.Fatal(err)
	}
	private, _ := writeMaterializeSigningKey(t, root)
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	values := commonFlags{configPath: configPath, workers: 1, chunk: 2}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	ref, err := state.ViewRef("latest", "deb-test", "jammy", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	marker := writeMaterializationSelectionStage(t, cfg.StatePath(), "initial")
	commit, _, err := canonical.Apply(t.Context(), "test", "selection fixture", map[string]string{"tests/selection.txt": marker}, []state.RefUpdate{{Name: ref}}, state.ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	repositoryKeySHA, err := repositorySigningKeyIdentity(cfg, private)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureMaterializationTrust(cfg, selectedLeaves(repos, values), private, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	targetSHA, err := materializationTargetSHA256(root)
	if err != nil {
		t.Fatal(err)
	}
	refVector := []materializationSelectionRef{{Name: ref.String(), Commit: commit.String()}}
	first, err := newMaterializationSelectedUnit("apt", "latest", false, targetSHA, "deb-test", "jammy", "", refVector)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newMaterializationSelectedUnit("apt", "latest", false, targetSHA, "deb-test", "noble", "", refVector)
	if err != nil {
		t.Fatal(err)
	}
	return materializationSelectionFixture{
		cfg: cfg, canonical: canonical, snapshot: snapshot, units: []materializationSelectedUnit{first, second},
		refName: ref.String(), refCommit: commit.String(), private: private,
	}
}

func writeMaterializationSelectionStage(t *testing.T, root, body string) string {
	t.Helper()
	file, err := os.CreateTemp(root, "selection-stage-")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(body); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		t.Fatal(err)
	}
	return file.Name()
}

func TestSimultaneousProjectionBridgesFailClosedWithoutCleanup(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	privateKey, _ := writeMaterializeSigningKey(t, root)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	repo := cfg.Repos[0]
	assetPath, err := state.ViewPath("beta", repo.ID, "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	assetRef, err := state.ViewRef("beta", repo.ID, "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	assetStage := writeMaterializationSelectionStage(t, cfg.StatePath(), "asset projection\n")
	assetIntent, _, err := prepareAssetProjectionIntent(cfg, canonical, "add", "", repo, "beta", assetPath, assetRef, plumbing.ZeroHash, assetStage, nil)
	if err != nil {
		t.Fatal(err)
	}
	packagePath, err := state.ViewPath("beta", repo.ID, "jammy", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	packageRef, err := state.ViewRef("beta", repo.ID, "jammy", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	packageStage := writeMaterializationSelectionStage(t, cfg.StatePath(), "package projection\n")
	packageIntent, _, err := preparePackageProjectionIntent(cfg, canonical, "add", "apt", []packageProjectionMutation{{
		leaf: viewLeaf{repo: repo, os: "jammy", arch: "amd64"}, view: "beta", viewPath: packagePath,
		viewRef: packageRef.String(), expected: plumbing.ZeroHash.String(),
	}}, map[string]string{packagePath: packageStage}, &materializationTrustSnapshot{
		repositoryKeySHA256: strings.Repeat("a", 64), yum: make(map[string]materializationYUMTrust),
		verificationTime: time.Now().UTC().Truncate(time.Second),
	}, privateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"add", "--config", configPath, "--repo", repo.ID, "--recover", "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code == ExitOK || !strings.Contains(stderr.String(), "simultaneous pending asset and package projections") {
		t.Fatalf("dual projection recovery code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	headAfter, err := canonical.HeadHash()
	if err != nil || headAfter != headBefore {
		t.Fatalf("dual projection admission mutated HEAD before=%s after=%s err=%v", headBefore, headAfter, err)
	}
	currentAsset, assetExists, assetErr := readAssetProjectionIntent(filepath.Join(root, ".sow"))
	currentPackage, packageExists, packageErr := readPackageProjectionIntent(filepath.Join(root, ".sow"))
	if assetErr != nil || !assetExists || currentAsset.ID != assetIntent.ID || packageErr != nil || !packageExists || currentPackage.ID != packageIntent.ID {
		t.Fatalf("dual projection admission cleared or changed evidence asset=%+v/%t/%v package=%+v/%t/%v", currentAsset, assetExists, assetErr, currentPackage, packageExists, packageErr)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", assetIntent.StageRelative)); err != nil {
		t.Fatalf("dual projection admission removed asset stage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", packageIntent.Units[0].StageRelative)); err != nil {
		t.Fatalf("dual projection admission removed package stage: %v", err)
	}
}

func recaptureMaterializationSelectionTrust(t *testing.T, fixture materializationSelectionFixture) *materializationTrustSnapshot {
	t.Helper()
	repositoryKeySHA, err := repositorySigningKeyIdentity(fixture.cfg, fixture.private)
	if err != nil {
		t.Fatal(err)
	}
	repos := fixture.cfg.Repos
	snapshot, err := captureMaterializationTrust(fixture.cfg, selectedLeaves(repos, commonFlags{}), fixture.private, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestMaterializationSelectionJournalBindsSchemaConfigAndHead(t *testing.T) {
	fixture := setupMaterializationSelectionFixture(t)
	owner, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units)
	if err != nil || !owner {
		t.Fatalf("begin owner=%t err=%v", owner, err)
	}
	journal, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath())
	if err != nil || !exists {
		t.Fatalf("read journal exists=%t err=%v", exists, err)
	}
	configSHA, parentConfigSHA, head, err := currentMaterializationCanonicalIdentity(fixture.cfg, fixture.canonical)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Schema != materializationSelectionJournalSchema || journal.ConfigSHA256 != configSHA || journal.ParentConfigSHA256 != parentConfigSHA || journal.ExpectedHead != head || len(journal.Units) != 2 {
		t.Fatalf("journal identity not frozen: %+v", journal)
	}
	corrupt := journal
	corrupt.ConfigSHA256 = strings.Repeat("0", 64)
	if err := corrupt.validate(); err == nil || !strings.Contains(err.Error(), "ID mismatch") {
		t.Fatalf("config identity mutation retained a valid journal ID: %v", err)
	}
	corrupt = journal
	corrupt.ExpectedHead = strings.Repeat("0", 40)
	if err := corrupt.validate(); err == nil || !strings.Contains(err.Error(), "ID mismatch") {
		t.Fatalf("HEAD identity mutation retained a valid journal ID: %v", err)
	}
	if err := finishMaterializationSelectedSet(fixture.cfg, fixture.snapshot, owner, errors.New("prepared failure")); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath()); err != nil || exists {
		t.Fatalf("prepared-only failure did not abort empty fence: exists=%t err=%v", exists, err)
	}
}

func TestMaterializationSelectionJournalRejectsUnknownSchemaAndPublicPermissions(t *testing.T) {
	t.Run("unknown-field", func(t *testing.T) {
		fixture := setupMaterializationSelectionFixture(t)
		if _, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units); err != nil {
			t.Fatal(err)
		}
		journal, _, err := readMaterializationSelectionJournal(fixture.cfg.StatePath())
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(journal)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(body, &document); err != nil {
			t.Fatal(err)
		}
		document["unexpected"] = true
		body, err = json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeDerivedStateFile(fixture.cfg.StatePath(), filepath.FromSlash(materializationSelectionJournalRelative), body); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readMaterializationSelectionJournal(fixture.cfg.StatePath()); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("unknown materialization journal field was accepted: %v", err)
		}
	})

	t.Run("public-mode", func(t *testing.T) {
		fixture := setupMaterializationSelectionFixture(t)
		if _, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units); err != nil {
			t.Fatal(err)
		}
		active := filepath.Join(fixture.cfg.StatePath(), filepath.FromSlash(materializationSelectionJournalRelative))
		if err := os.Chmod(active, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readMaterializationSelectionJournal(fixture.cfg.StatePath()); err == nil || !strings.Contains(err.Error(), "private exact regular file") {
			t.Fatalf("public materialization journal mode was accepted: %v", err)
		}
	})
}

func TestMaterializationSelectionNestedBeginRequiresDurableSubsetAndIdentity(t *testing.T) {
	fixture := setupMaterializationSelectionFixture(t)
	owner, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units)
	if err != nil || !owner {
		t.Fatalf("begin owner=%t err=%v", owner, err)
	}
	if nestedOwner, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units[:1]); err != nil || nestedOwner {
		t.Fatalf("valid nested subset owner=%t err=%v", nestedOwner, err)
	}
	values := commonFlags{materializeTrust: fixture.snapshot}
	_, nestedOwner, err := beginMaterializationSelectionForRequests(fixture.cfg, fixture.canonical, values, "materialize", []materializationSelectionRequest{{
		Source: materializeCanonicalSource{ID: "latest", Public: true},
		Leaves: []viewLeaf{{repo: fixture.cfg.Repos[0], os: "jammy", arch: "arm64"}}, TargetRoot: fixture.cfg.Root, IncludeMetadata: true,
	}})
	if err != nil || nestedOwner {
		t.Fatalf("planned nested subset owner=%t err=%v", nestedOwner, err)
	}
	targetSHA, _ := materializationTargetSHA256(fixture.cfg.Root)
	unknown, err := newMaterializationSelectedUnit("apt", "latest", false, targetSHA, "deb-test", "oracular", "", []materializationSelectionRef{{Name: fixture.refName, Commit: fixture.refCommit}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, []materializationSelectedUnit{unknown}); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("nested unit expansion was not rejected: %v", err)
	}
	marker := writeMaterializationSelectionStage(t, fixture.cfg.StatePath(), "derived")
	if _, _, err := fixture.canonical.Apply(t.Context(), "test", "derived ledger", map[string]string{"tests/derived.txt": marker}, nil, state.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units[:1]); err != nil {
		t.Fatalf("descendant HEAD with unchanged config/ref vector was rejected: %v", err)
	}
	if err := fixture.snapshot.handleMaterializationTrustResult(fixture.cfg, fixture.units[0].ID, materializeTrustPayloadBefore, nil); err != nil {
		t.Fatal(err)
	}
	if err := finishMaterializationSelectedSet(fixture.cfg, fixture.snapshot, owner, errors.New("started failure")); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath()); err != nil || !exists {
		t.Fatalf("started partial fence was not retained: exists=%t err=%v", exists, err)
	}
}

func TestMaterializationSelectionRecoveryAcceptsDescendantButRejectsIntentDrift(t *testing.T) {
	t.Run("descendant-and-exact-set", func(t *testing.T) {
		fixture := setupMaterializationSelectionFixture(t)
		owner, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units)
		if err != nil || !owner {
			t.Fatalf("begin owner=%t err=%v", owner, err)
		}
		fixture.snapshot.resetMaterializationSelection() // simulate process loss; journal remains durable
		marker := writeMaterializationSelectionStage(t, fixture.cfg.StatePath(), "descendant")
		if _, _, err := fixture.canonical.Apply(t.Context(), "test", "derived descendant", map[string]string{"tests/descendant.txt": marker}, nil, state.ApplyOptions{}); err != nil {
			t.Fatal(err)
		}
		recovered := recaptureMaterializationSelectionTrust(t, fixture)
		if _, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, recovered, "materialize", true, fixture.units[:1]); err == nil || !strings.Contains(err.Error(), "unit set differs") {
			t.Fatalf("subset recovery was not rejected: %v", err)
		}
		owner, err = beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, recovered, "materialize", true, fixture.units)
		if err != nil || !owner {
			t.Fatalf("exact descendant recovery owner=%t err=%v", owner, err)
		}
		if err := finishMaterializationSelectedSet(fixture.cfg, recovered, owner, errors.New("prepared recovery abort")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("canonical-config", func(t *testing.T) {
		fixture := setupMaterializationSelectionFixture(t)
		owner, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units)
		if err != nil || !owner {
			t.Fatalf("begin owner=%t err=%v", owner, err)
		}
		body, err := os.ReadFile(fixture.cfg.Path)
		if err != nil {
			t.Fatal(err)
		}
		stage := writeMaterializationSelectionStage(t, fixture.cfg.StatePath(), string(body)+"\n# canonical drift\n")
		if _, _, err := fixture.canonical.Apply(t.Context(), "test", "config drift", map[string]string{"config/sow.yaml": stage}, nil, state.ApplyOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units[:1]); err == nil || !strings.Contains(err.Error(), "canonical config") {
			t.Fatalf("nested begin accepted canonical config drift: %v", err)
		}
	})

	t.Run("frozen-ref", func(t *testing.T) {
		fixture := setupMaterializationSelectionFixture(t)
		owner, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units)
		if err != nil || !owner {
			t.Fatalf("begin owner=%t err=%v", owner, err)
		}
		marker := writeMaterializationSelectionStage(t, fixture.cfg.StatePath(), "ref drift")
		ref, _ := state.ViewRef("latest", "deb-test", "jammy", "arm64")
		if _, _, err := fixture.canonical.Apply(t.Context(), "test", "ref drift", map[string]string{"tests/ref-drift.txt": marker}, []state.RefUpdate{{Name: ref, Expected: plumbing.NewHash(fixture.refCommit)}}, state.ApplyOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units[:1]); err == nil || !strings.Contains(err.Error(), "changed from frozen commit") {
			t.Fatalf("nested begin accepted frozen ref drift: %v", err)
		}
	})
}

func TestMaterializationSelectionFinishRetainsEveryStartedErrorUntilExplicitSuccess(t *testing.T) {
	fixture := setupMaterializationSelectionFixture(t)
	owner, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units[:1])
	if err != nil || !owner {
		t.Fatalf("begin owner=%t err=%v", owner, err)
	}
	if err := fixture.snapshot.handleMaterializationTrustResult(fixture.cfg, fixture.units[0].ID, materializeTrustPayloadBefore, nil); err != nil {
		t.Fatal(err)
	}
	if err := finishMaterializationSelectedSet(fixture.cfg, fixture.snapshot, owner, errors.New("payload failure")); err != nil {
		t.Fatal(err)
	}
	journal, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath())
	if err != nil || !exists || journal.Phase != materializationSelectionMaterializing || len(journal.CompletedUnits) != 0 {
		t.Fatalf("started zero-complete fence was not retained: journal=%+v exists=%t err=%v", journal, exists, err)
	}
	fixture.snapshot.resetMaterializationSelection()
	recovered := recaptureMaterializationSelectionTrust(t, fixture)
	owner, err = beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, recovered, "materialize", true, fixture.units[:1])
	if err != nil || !owner {
		t.Fatalf("recover owner=%t err=%v", owner, err)
	}
	if err := recovered.handleMaterializationTrustResult(fixture.cfg, fixture.units[0].ID, materializeTrustAPTCommitAfter, nil); err != nil {
		t.Fatal(err)
	}
	if err := finishMaterializationSelectedSet(fixture.cfg, recovered, owner, errors.New("archive failure after complete materialization")); err != nil {
		t.Fatalf("retain completed set after later failure: %v", err)
	}
	journal, exists, err = readMaterializationSelectionJournal(fixture.cfg.StatePath())
	if err != nil || !exists || len(journal.CompletedUnits) != 1 {
		t.Fatalf("completed fence was cleared by a failed owner: journal=%+v exists=%t err=%v", journal, exists, err)
	}
	if err := finishMaterializationSelectedSet(fixture.cfg, recovered, owner, nil); err != nil {
		t.Fatalf("explicit successful finish did not clear completed set: %v", err)
	}
	if _, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath()); err != nil || exists {
		t.Fatalf("completed fence survived explicit success: exists=%t err=%v", exists, err)
	}
}

func TestMaterializationSelectionStopsWhenCompletedUnitJournalWriteFails(t *testing.T) {
	fixture := setupMaterializationSelectionFixture(t)
	owner, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units)
	if err != nil || !owner {
		t.Fatalf("begin owner=%t err=%v", owner, err)
	}
	if err := fixture.snapshot.handleMaterializationTrustResult(fixture.cfg, fixture.units[0].ID, materializeTrustPayloadBefore, nil); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected completed-unit journal sync failure")
	previous := derivedStateReplacementParentSync
	fired := false
	derivedStateReplacementParentSync = func(parent *os.File, phase string) error {
		if phase == "prepared" && !fired {
			fired = true
			return injected
		}
		return parent.Sync()
	}
	t.Cleanup(func() { derivedStateReplacementParentSync = previous })
	handleErr := fixture.snapshot.handleMaterializationTrustResult(fixture.cfg, fixture.units[0].ID, materializeTrustAPTCommitAfter, nil)
	derivedStateReplacementParentSync = previous
	if !fired || !errors.Is(handleErr, injected) || !strings.Contains(handleErr.Error(), "before continuing the selected set") {
		t.Fatalf("completed-unit journal failure fired=%t err=%v", fired, handleErr)
	}

	journal, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath())
	if err != nil || !exists || journal.Phase != materializationSelectionMaterializing || len(journal.CompletedUnits) != 0 {
		t.Fatalf("failed journal replacement changed the durable selected set: journal=%+v exists=%t err=%v", journal, exists, err)
	}
	if fixture.snapshot.firstDrift == nil || !errors.Is(fixture.snapshot.firstDrift, injected) {
		t.Fatalf("journal failure was not retained as the first drift: %v", fixture.snapshot.firstDrift)
	}
	if err := finishMaterializationSelectedSet(fixture.cfg, fixture.snapshot, owner, handleErr); err != nil {
		t.Fatalf("retain failed selected set: %v", err)
	}
	if _, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath()); err != nil || !exists {
		t.Fatalf("failed selected set lost its recovery fence: exists=%t err=%v", exists, err)
	}
}

func TestMaterializationSelectionRetainsTrustAndJournalFailuresTogether(t *testing.T) {
	fixture := setupMaterializationSelectionFixture(t)
	owner, err := beginMaterializationSelectedSet(fixture.cfg, fixture.canonical, fixture.snapshot, "materialize", false, fixture.units)
	if err != nil || !owner {
		t.Fatalf("begin owner=%t err=%v", owner, err)
	}
	if err := fixture.snapshot.handleMaterializationTrustResult(fixture.cfg, fixture.units[0].ID, materializeTrustPayloadBefore, nil); err != nil {
		t.Fatal(err)
	}
	if err := fixture.snapshot.handleMaterializationTrustResult(fixture.cfg, fixture.units[0].ID, materializeTrustAPTCommitAfter, nil); err != nil {
		t.Fatal(err)
	}

	trustErr := errors.New("injected post-boundary trust change")
	journalErr := errors.New("injected drift-journal sync failure")
	previous := derivedStateReplacementParentSync
	fired := false
	derivedStateReplacementParentSync = func(parent *os.File, phase string) error {
		if phase == "prepared" && !fired {
			fired = true
			return journalErr
		}
		return parent.Sync()
	}
	t.Cleanup(func() { derivedStateReplacementParentSync = previous })
	handleErr := fixture.snapshot.handleMaterializationTrustResult(
		fixture.cfg,
		fixture.units[1].ID,
		materializeTrustAPTCommitAfter,
		trustErr,
	)
	derivedStateReplacementParentSync = previous
	if !fired || !errors.Is(handleErr, trustErr) || !errors.Is(handleErr, journalErr) {
		t.Fatalf("combined trust/journal failure fired=%t err=%v", fired, handleErr)
	}
	if fixture.snapshot.firstDrift == nil ||
		!errors.Is(fixture.snapshot.firstDrift, trustErr) ||
		!errors.Is(fixture.snapshot.firstDrift, journalErr) {
		t.Fatalf("combined failure was not retained as first drift: %v", fixture.snapshot.firstDrift)
	}
	journal, exists, err := readMaterializationSelectionJournal(fixture.cfg.StatePath())
	if err != nil || !exists || len(journal.CompletedUnits) != 1 || journal.CompletedUnits[0] != fixture.units[0].ID {
		t.Fatalf("failed second-unit update changed durable completed set: journal=%+v exists=%t err=%v", journal, exists, err)
	}
	if err := finishMaterializationSelectedSet(fixture.cfg, fixture.snapshot, owner, handleErr); err != nil {
		t.Fatalf("retain combined-failure selected set: %v", err)
	}
}
