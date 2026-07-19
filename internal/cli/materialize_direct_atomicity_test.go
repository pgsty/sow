package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestDirectMaterializeBetaRetainsCanonicalAPTByHashGenerations(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(aptByHashCLIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	_, keyPath := writeMaterializeSigningKey(t, root)
	for _, version := range []string{"1.0.0", "2.0.0", "3.0.0"} {
		packagePath := writeRetentionDEB(t, root, version)
		if code, stdout, stderr := runServingCLI(t, "add", packagePath, "--config", configPath, "--repo", "deb-retention", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("add %s code=%d stdout=%s stderr=%s", version, code, stdout, stderr)
		}
		if code, stdout, stderr := runServingCLI(t, "materialize", "beta", "--config", configPath, "--repo", "deb-retention", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("materialize %s code=%d stdout=%s stderr=%s", version, code, stdout, stderr)
		}
	}

	canonical := state.New(filepath.Join(root, ".sow"))
	canonicalPath, err := state.APTByHashLedgerPath("views", "beta", "deb-retention", "jammy")
	if err != nil {
		t.Fatal(err)
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		t.Fatalf("canonical HEAD=%s err=%v", head, err)
	}
	reader, err := canonical.OpenPathAt(head, canonicalPath)
	if err != nil {
		t.Fatalf("open committed by-hash ledger: %v", err)
	}
	var committed bytes.Buffer
	if _, err := committed.ReadFrom(reader); err != nil {
		reader.Close()
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := aptrepo.DecodeByHashLedger(bytes.NewReader(committed.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Generations) != 2 || ledger.LiveGeneration == "" {
		t.Fatalf("retention ledger=%+v, want exactly live+previous", ledger)
	}
	derivedPath := filepath.Join(root, ".sow", "state", filepath.FromSlash(canonicalPath))
	derived, err := os.ReadFile(derivedPath)
	if err != nil || !bytes.Equal(derived, committed.Bytes()) {
		t.Fatalf("canonical/derived by-hash ledger differ err=%v", err)
	}

	archiveRoot := filepath.Join(root, ".sow", "materialized", "beta", "apt", "retention")
	expected := make(map[string]struct{})
	live := make(map[string]struct{})
	for _, generation := range ledger.Generations {
		for _, relative := range generation.Paths {
			expected[relative] = struct{}{}
			if generation.ID == ledger.LiveGeneration {
				live[relative] = struct{}{}
			}
			if _, err := os.Stat(filepath.Join(archiveRoot, filepath.FromSlash(relative))); err != nil {
				t.Fatalf("ledger-retained by-hash object %s is missing: %v", relative, err)
			}
		}
	}
	previousUnique := ""
	for _, generation := range ledger.Generations {
		if generation.ID == ledger.LiveGeneration {
			continue
		}
		for _, relative := range generation.Paths {
			if _, shared := live[relative]; !shared {
				previousUnique = relative
				break
			}
		}
	}
	if previousUnique == "" {
		t.Fatalf("fixture did not retain a physical previous-generation-only by-hash object: %+v", ledger)
	}

	actual := make(map[string]struct{})
	if err := filepath.WalkDir(archiveRoot, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(archiveRoot, current)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if strings.Contains(relative, "/by-hash/SHA256/") {
			actual[relative] = struct{}{}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(actual) != len(expected) {
		t.Fatalf("physical by-hash object count=%d canonical=%d actual=%v expected=%v", len(actual), len(expected), actual, expected)
	}
	for relative := range expected {
		if _, exists := actual[relative]; !exists {
			t.Fatalf("canonical retained path absent from physical tree: %s", relative)
		}
	}
	for relative := range actual {
		if _, exists := expected[relative]; !exists {
			t.Fatalf("physical by-hash orphan absent from canonical ledger: %s", relative)
		}
	}
}

func TestDirectMaterializeRecoveryKeepsCompletedMetadataUnitAfterRealReconcileFailure(t *testing.T) {
	t.Run("apt", func(t *testing.T) {
		root := nginxWorkerTempDir(t)
		configPath := filepath.Join(root, "sow.yaml")
		if err := os.WriteFile(configPath, []byte(aptByHashCLIConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		_, keyPath := writeMaterializeSigningKey(t, root)
		packagePath := writeRetentionDEB(t, root, "1.0.0")
		if code, stdout, stderr := runServingCLI(t, "add", packagePath, "--config", configPath, "--repo", "deb-retention", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}

		target := "recover-apt"
		targetRoot := filepath.Join(root, target)
		arguments := []string{"materialize", "beta", "--config", configPath, "--repo", "deb-retention", "--target", target, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
		if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
			t.Fatalf("baseline APT materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		rogue := installReconcileFailureSymlink(t, targetRoot)
		code, stdout, stderr := runServingCLI(t, arguments...)
		if code != ExitVerification || !strings.Contains(stderr, "reconcile materialized beta") || !strings.Contains(stderr, "symlink") {
			t.Fatalf("real APT reconcile fault code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		assertCompletedMetadataSelectionJournal(t, root, "apt")
		if _, err := os.Stat(filepath.Join(targetRoot, "apt", "retention", "dists", "jammy", "Release")); err != nil {
			t.Fatalf("APT metadata was not committed before reconcile fault: %v", err)
		}
		if err := os.Remove(rogue); err != nil {
			t.Fatal(err)
		}
		arguments = append(arguments, "--recover")
		if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
			t.Fatalf("APT exact recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		assertNoMaterializationSelectionJournal(t, root)
	})

	t.Run("yum", func(t *testing.T) {
		root := nginxWorkerTempDir(t)
		configPath := filepath.Join(root, "sow.yaml")
		if err := os.WriteFile(configPath, []byte(snapshotYUMConfig), 0o600); err != nil {
			t.Fatal(err)
		}
		rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
		_, keyPath := writeMaterializeSigningKey(t, root)
		if code, stdout, stderr := runServingCLI(t, "add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if code, stdout, stderr := runServingCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "rpm-test"); code != ExitOK {
			t.Fatalf("promote latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		snapshotID, err := views.SnapshotID("el10", time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if code, stdout, stderr := runServingCLI(t, "promote", "stable", snapshotID, "--config", configPath, "--repo", "rpm-test"); code != ExitOK {
			t.Fatalf("create snapshot code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}

		target := "recover-yum"
		targetRoot := filepath.Join(root, target)
		arguments := []string{"materialize", snapshotID, "--config", configPath, "--repo", "rpm-test", "--target", target, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
		if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
			t.Fatalf("baseline YUM materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		rogue := installReconcileFailureSymlink(t, targetRoot)
		code, stdout, stderr := runServingCLI(t, arguments...)
		if code != ExitVerification || !strings.Contains(stderr, "reconcile materialized "+snapshotID) || !strings.Contains(stderr, "symlink") {
			t.Fatalf("real YUM reconcile fault code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		assertCompletedMetadataSelectionJournal(t, root, "yum")
		if _, err := os.Stat(filepath.Join(targetRoot, "yum", "test", "x86_64", "repodata", "repomd.xml")); err != nil {
			t.Fatalf("YUM metadata was not committed before reconcile fault: %v", err)
		}
		if err := os.Remove(rogue); err != nil {
			t.Fatal(err)
		}
		arguments = append(arguments, "--recover")
		if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
			t.Fatalf("YUM exact recovery code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		assertNoMaterializationSelectionJournal(t, root)
	})
}

func TestDedicatedPartialPublicMaterializeDropsOutOfScopeGatedServingTree(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(directMaterializeDualYUMConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	_, keyPath := writeMaterializeSigningKey(t, root)
	for _, repo := range []string{"rpm-gated", "rpm-public"} {
		if err := os.MkdirAll(filepath.Join(root, "yum", strings.TrimPrefix(repo, "rpm-"), "x86_64"), 0o755); err != nil {
			t.Fatal(err)
		}
		if code, stdout, stderr := runServingCLI(t, "add", rpmPath, "--config", configPath, "--repo", repo, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("add %s code=%d stdout=%s stderr=%s", repo, code, stdout, stderr)
		}
		if code, stdout, stderr := runServingCLI(t, "init", "--config", configPath, "--repo", repo, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("init %s code=%d stdout=%s stderr=%s", repo, code, stdout, stderr)
		}
	}
	info, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	target := "shared-export"
	targetRoot := filepath.Join(root, target)
	stableArguments := []string{"materialize", "stable", "--config", configPath, "--repo", "rpm-gated", "--target", target, "--serving-base-url", "https://export.example.invalid/pro/v1/basic", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	if code, stdout, stderr := runServingCLI(t, stableArguments...); code != ExitOK {
		t.Fatalf("stable gated materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	stableMirror := "_sow/v1/mirrorlist/stable/rpm-gated/el10/x86_64.txt"
	stableGeneration := mirrorGenerationID(t, targetRoot, stableMirror)
	if _, err := os.Stat(filepath.Join(targetRoot, "yum", "gated", "x86_64", filepath.FromSlash(info.Location))); err != nil {
		t.Fatalf("stable gated payload missing: %v", err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	stableTarget, err := localServingTargetIdentity(cfg, "stable", targetRoot, "https://export.example.invalid/pro/v1/basic")
	if err != nil {
		t.Fatal(err)
	}
	stableCoordinate := serving.Generation{ID: stableGeneration, View: "stable", Repo: "rpm-gated", OS: "el10", Arch: "x86_64"}
	if reader, err := canonical.OpenPath(serving.TargetStatePath(stableTarget)); err != nil {
		t.Fatalf("stable target registry was not committed before replacement: %v", err)
	} else if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	stableChannelPath := serving.ChannelStatePath(serving.Channel{TargetID: stableTarget.ID, View: "stable", Repo: "rpm-gated", OS: "el10", Arch: "x86_64"})
	if reader, err := canonical.OpenPath(stableChannelPath); err != nil {
		t.Fatalf("stable channel was not committed before replacement: %v", err)
	} else if err := reader.Close(); err != nil {
		t.Fatal(err)
	}

	betaArguments := []string{"materialize", "beta", "--config", configPath, "--repo", "rpm-public", "--target", target, "--serving-base-url", "https://export.example.invalid", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	if code, stdout, stderr := runServingCLI(t, betaArguments...); code != ExitOK {
		t.Fatalf("partial beta public materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(targetRoot, "yum", "public", "x86_64", filepath.FromSlash(info.Location))); err != nil {
		t.Fatalf("selected public payload missing: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(targetRoot, "yum", "gated")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("out-of-scope gated payload survived explicit target replay: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(targetRoot, filepath.FromSlash(stableMirror))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("out-of-scope stable mirrorlist survived explicit target replay: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(targetRoot, "_sow", "v1", "g", stableGeneration)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("out-of-scope stable generation survived explicit target replay: %v", err)
	}
	betaMirror := "_sow/v1/mirrorlist/beta/rpm-public/el10/x86_64.txt"
	betaGeneration := mirrorGenerationID(t, targetRoot, betaMirror)
	entries, err := os.ReadDir(filepath.Join(targetRoot, "_sow", "v1", "g"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != betaGeneration {
		t.Fatalf("explicit target retained scope-external serving generations: entries=%v beta=%s", entries, betaGeneration)
	}

	lifecycle, err := loadCanonicalServingLifecycle(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := lifecycle.Targets[stableTarget.ID]; exists {
		t.Fatalf("explicit target replacement retained obsolete stable target registry %s", stableTarget.ID)
	}
	if reader, err := canonical.OpenPath(stableChannelPath); err == nil {
		_ = reader.Close()
		t.Fatalf("explicit target replacement retained obsolete stable channel %s", stableChannelPath)
	}
	stableManifestPath := serving.GenerationManifestStatePath(stableCoordinate)
	if _, exists := lifecycle.Generations[stableManifestPath]; exists {
		t.Fatalf("explicit target replacement retained active stable generation ledger %s", stableManifestPath)
	}
	if _, exists := lifecycle.Retired[serving.RetiredGenerationStatePath(stableCoordinate)]; !exists {
		t.Fatalf("explicit target replacement omitted stable generation retirement witness %s", stableGeneration)
	}
	betaTarget, err := localServingTargetIdentity(cfg, "beta", targetRoot, "https://export.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := lifecycle.Targets[betaTarget.ID]; !exists {
		t.Fatalf("explicit target replacement removed desired beta target registry %s", betaTarget.ID)
	}
	wantedBetaChannel := serving.ChannelStatePath(serving.Channel{TargetID: betaTarget.ID, View: "beta", Repo: "rpm-public", OS: "el10", Arch: "x86_64"})
	if reader, err := canonical.OpenPath(wantedBetaChannel); err != nil {
		t.Fatalf("explicit target replacement omitted desired beta channel %s: %v", wantedBetaChannel, err)
	} else if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runServingCLI(t, "verify", "--layer", "L1", "--view", "beta", "--view", "stable", "--config", configPath, "--repo", "rpm-public", "--repo", "rpm-gated", "--workers", "2", "--chunk-entries", "2"); strings.Contains(stdout, "LOCAL_YUM_") || (code != ExitOK && !(code == ExitVerification && strings.Contains(stdout, "outcome=warning") && strings.Contains(stdout, "critical=0") && strings.Contains(stdout, "operational=0"))) {
		t.Fatalf("exact explicit target left canonical serving drift code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestFullSnapshotReplayRemovesManualServingNamespaceDrift(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(snapshotAPTConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	debPath := decodeMaterializeFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(root, "package.deb"))
	_, keyPath := writeMaterializeSigningKey(t, root)
	if code, stdout, stderr := runServingCLI(t, "add", debPath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := runServingCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "deb-test"); code != ExitOK {
		t.Fatalf("promote latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotID, err := views.SnapshotID("jammy", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runServingCLI(t, "promote", "stable", snapshotID, "--config", configPath, "--repo", "deb-test"); code != ExitOK {
		t.Fatalf("create snapshot code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	arguments := []string{"materialize", snapshotID, "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("first full snapshot materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	targetRoot := filepath.Join(root, ".sow", "materialized", "snapshots", snapshotID)
	rogue := filepath.Join(targetRoot, "_sow", "rogue")
	if err := os.MkdirAll(filepath.Dir(rogue), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rogue, []byte("manual drift\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK || !strings.Contains(stdout, "pruned=1") {
		t.Fatalf("full snapshot exact replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Lstat(filepath.Join(targetRoot, "_sow")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("full snapshot retained manual _sow drift: %v", err)
	}
}

func installReconcileFailureSymlink(t *testing.T, targetRoot string) string {
	t.Helper()
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	rogue := filepath.Join(targetRoot, "rogue-symlink")
	if err := os.Symlink(t.TempDir(), rogue); err != nil {
		t.Fatal(err)
	}
	return rogue
}

func assertCompletedMetadataSelectionJournal(t *testing.T, root, kind string) {
	t.Helper()
	journal, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || !exists {
		t.Fatalf("active selected-set journal exists=%t err=%v", exists, err)
	}
	if journal.Phase != materializationSelectionMaterializing || len(journal.Units) != 1 || journal.Units[0].Kind != kind || len(journal.CompletedUnits) != 1 || journal.CompletedUnits[0] != journal.Units[0].ID {
		t.Fatalf("completed %s metadata unit was not durably fenced: %+v", kind, journal)
	}
}

func assertNoMaterializationSelectionJournal(t *testing.T, root string) {
	t.Helper()
	journal, exists, err := readMaterializationSelectionJournal(filepath.Join(root, ".sow"))
	if err != nil || exists {
		t.Fatalf("exact recovery retained selected-set journal exists=%t journal=%+v err=%v", exists, journal, err)
	}
}

const directMaterializeDualYUMConfig = `schema: sow/v1
state: {snapshot_materialization_months: 6}
gpg:
  public_key: repository-public.pgp
pools:
  public: {}
  gated: {}
repos:
  - id: rpm-public
    type: yum
    path: yum/public/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
  - id: rpm-gated
    type: yum
    path: yum/gated/x86_64
    default_pool: gated
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false, repos: [rpm-public]}
  latest: {access: public, allowed_pools: [public], append_only: false, repos: [rpm-public]}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true, repos: [rpm-gated]}
serving:
  latest: {base_url: "https://repo.example.invalid"}
  beta: {base_url: "https://beta.example.invalid"}
  stable: {base_url: "https://repo.example.invalid/pro/v1/basic"}
targets: {}
edge:
  token_verifier: provider://test
`
