package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
)

func TestAssetProjectionCompletionPreservesConcurrentIntentReplacement(t *testing.T) {
	stateRoot, intent := writeTestAssetProjectionIntent(t)
	assertProjectionIntentReplacementPreserved(t, stateRoot, assetProjectionIntentRelative, func() error {
		return removeAssetProjectionIntent(stateRoot, intent)
	})
}

func TestAssetProjectionCompletionRemovesExactIntentAndStages(t *testing.T) {
	stateRoot, intent := writeTestAssetProjectionIntent(t)
	if err := removeAssetProjectionIntent(stateRoot, intent); err != nil {
		t.Fatalf("remove exact asset projection intent: %v", err)
	}
	for _, relative := range []string{assetProjectionIntentRelative, intent.StageRelative, intent.ConfigStage} {
		if _, err := os.Lstat(filepath.Join(stateRoot, relative)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("completed asset projection residue %s remains: %v", relative, err)
		}
	}
}

func TestAssetProjectionCompletionPreservesConcurrentStageReplacement(t *testing.T) {
	stateRoot, intent := writeTestAssetProjectionIntent(t)
	stage := filepath.Join(stateRoot, intent.StageRelative)
	assertProjectionStageReplacementPreserved(t, stage, func() error {
		previous := projectionStageCleanupHook
		projectionStageCleanupHook = func(relative string) error {
			if relative != intent.StageRelative {
				return nil
			}
			return replaceProjectionStageWithCanary(stage)
		}
		t.Cleanup(func() { projectionStageCleanupHook = previous })
		return removeAssetProjectionIntent(stateRoot, intent)
	})
	projectionStageCleanupHook = nil
}

func TestAssetProjectionCompletionRemovesEmptyExactStage(t *testing.T) {
	stateRoot, intent := writeTestAssetProjectionIntentWithStage(t, nil)
	if intent.ManifestSize != 0 {
		t.Fatalf("empty manifest size=%d", intent.ManifestSize)
	}
	if err := removeAssetProjectionIntent(stateRoot, intent); err != nil {
		t.Fatalf("remove empty exact asset stage: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, intent.StageRelative)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty exact asset stage remains: %v", err)
	}
}

func TestAssetProjectionCompletionPreservesDigestMismatchedStage(t *testing.T) {
	stateRoot, intent := writeTestAssetProjectionIntent(t)
	stage := filepath.Join(stateRoot, intent.StageRelative)
	corrupt := bytes.Repeat([]byte("x"), int(intent.ManifestSize))
	if err := os.WriteFile(stage, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeAssetProjectionIntent(stateRoot, intent); err != nil {
		t.Fatalf("post-commit mismatched stage cleanup leaked an error: %v", err)
	}
	body, err := os.ReadFile(stage)
	if err != nil || !bytes.Equal(body, corrupt) {
		t.Fatalf("digest-mismatched stage was deleted or changed body=%q err=%v", body, err)
	}
}

func writeTestAssetProjectionIntent(t *testing.T) (string, assetProjectionIntent) {
	return writeTestAssetProjectionIntentWithStage(t, []byte("owned projection stage"))
}

func writeTestAssetProjectionIntentWithStage(t *testing.T, stageBody []byte) (string, assetProjectionIntent) {
	t.Helper()
	stateRoot := t.TempDir()
	transactionID := strings.Repeat("1", 32)
	viewPath, err := state.ViewPath("beta", "asset-test", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	viewRef, err := state.ViewRef("beta", "asset-test", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	intent := assetProjectionIntent{
		Schema: assetProjectionIntentSchema, Operation: "add", TransactionID: transactionID,
		Message:      assetProjectionIntentMessage("add", "", "asset-test", transactionID, nil),
		ConfigSHA256: strings.Repeat("2", 64), ConfigSize: 1,
		ConfigStage:  assetProjectionStagePrefix + transactionID + "-config.yaml",
		ExpectedHead: strings.Repeat("3", 40), ExpectedRef: strings.Repeat("4", 40),
		Repo: "asset-test", View: "beta", ViewPath: viewPath, ViewRef: viewRef.String(),
		TargetSHA256: strings.Repeat("5", 64), ManifestSHA256: strings.Repeat("6", 64),
		StageRelative: assetProjectionStagePrefix + transactionID + ".tsv",
	}
	configBody := []byte("frozen projection config")
	stageDigest := sha256.Sum256(stageBody)
	configDigest := sha256.Sum256(configBody)
	intent.ManifestSHA256 = hex.EncodeToString(stageDigest[:])
	intent.ManifestSize = int64(len(stageBody))
	intent.ConfigSHA256 = hex.EncodeToString(configDigest[:])
	intent.ConfigSize = int64(len(configBody))
	intent.ID, err = assetProjectionIntentID(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAssetProjectionIntent(stateRoot, intent); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateRoot, intent.StageRelative), stageBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateRoot, intent.ConfigStage), configBody, 0o600); err != nil {
		t.Fatal(err)
	}
	return stateRoot, intent
}

func TestPackageProjectionCompletionPreservesConcurrentIntentReplacement(t *testing.T) {
	stateRoot, intent := writeTestCompletedPackageProjection(t)
	assertProjectionIntentReplacementPreserved(t, stateRoot, packageProjectionIntentRelative, func() error {
		return removePackageProjectionIntent(stateRoot, intent)
	})
}

func TestPackageProjectionCompletionPreservesConcurrentStageReplacement(t *testing.T) {
	stateRoot, intent := writeTestCompletedPackageProjection(t)
	if len(intent.Units) != 1 {
		t.Fatalf("package projection units=%d", len(intent.Units))
	}
	stage := filepath.Join(stateRoot, intent.Units[0].StageRelative)
	previous := projectionStageCleanupHook
	projectionStageCleanupHook = func(relative string) error {
		if relative != intent.Units[0].StageRelative {
			return nil
		}
		return replaceProjectionStageWithCanary(stage)
	}
	t.Cleanup(func() { projectionStageCleanupHook = previous })
	assertProjectionStageReplacementPreserved(t, stage, func() error {
		return removePackageProjectionIntent(stateRoot, intent)
	})
	projectionStageCleanupHook = nil
}

func writeTestCompletedPackageProjection(t *testing.T) (string, packageProjectionIntent) {
	t.Helper()
	root, configPath, packagePath, keyPath := preparePackageNoopDEB(t)
	previousMutation := packageProjectionMutationHook
	packageProjectionMutationHook = func(phase string) error {
		if phase == "after-fence-before-apply" {
			return errors.New("seed package bridge for intent replacement")
		}
		return nil
	}
	t.Cleanup(func() { packageProjectionMutationHook = previousMutation })
	var stdout, stderr bytes.Buffer
	if err := runAdd(t.Context(), []string{packagePath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); err == nil {
		t.Fatal("package replacement bridge seed unexpectedly succeeded")
	}
	packageProjectionMutationHook = nil
	stateRoot := filepath.Join(root, ".sow")
	intent, exists, err := readPackageProjectionIntent(stateRoot)
	if err != nil || !exists {
		t.Fatalf("replacement package bridge exists=%t err=%v", exists, err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ensurePackageProjectionCanonical(t.Context(), cfg, state.New(stateRoot), intent); err != nil {
		t.Fatalf("complete replacement-boundary canonical transaction: %v", err)
	}
	return stateRoot, intent
}

func assertProjectionIntentReplacementPreserved(t *testing.T, stateRoot, relative string, remove func() error) {
	t.Helper()
	path := filepath.Join(stateRoot, relative)
	backup := path + ".test-original"
	canary := []byte("foreign replacement must survive")
	previous := projectionIntentRemovalHook
	projectionIntentRemovalHook = func(current string) error {
		if current != relative {
			return nil
		}
		if err := os.Rename(path, backup); err != nil {
			return err
		}
		return os.WriteFile(path, canary, 0o600)
	}
	t.Cleanup(func() { projectionIntentRemovalHook = previous })
	err := remove()
	if err == nil {
		t.Fatal("intent completion accepted a replacement pathname")
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(body, canary) {
		t.Fatalf("intent completion deleted or changed replacement body=%q err=%v", body, readErr)
	}
	if info, statErr := os.Stat(backup); statErr != nil || !info.Mode().IsRegular() {
		t.Fatalf("test did not retain the original intent: %v", statErr)
	}
	projectionIntentRemovalHook = nil
}

func replaceProjectionStageWithCanary(path string) error {
	if err := os.Rename(path, path+".test-original"); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("foreign stage replacement must survive"), 0o600)
}

func assertProjectionStageReplacementPreserved(t *testing.T, path string, remove func() error) {
	t.Helper()
	if err := remove(); err != nil {
		t.Fatalf("post-commit projection cleanup leaked an error: %v", err)
	}
	want := []byte("foreign stage replacement must survive")
	body, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(body, want) {
		t.Fatalf("projection cleanup deleted or changed replacement body=%q err=%v", body, err)
	}
	if _, err := os.Lstat(path + ".test-original"); err != nil {
		t.Fatalf("test did not retain original projection stage: %v", err)
	}
}

func TestAssetProjectionRecoveryPreservesConcurrentResidueReplacement(t *testing.T) {
	stateRoot := t.TempDir()
	name := assetProjectionStagePrefix + strings.Repeat("7", 32) + ".tsv"
	assertProjectionResidueReplacementPreserved(t, stateRoot, name, func() error {
		return cleanupAssetProjectionIntentResidue(stateRoot, true)
	})
}

func TestPackageProjectionRecoveryPreservesConcurrentResidueReplacement(t *testing.T) {
	stateRoot := t.TempDir()
	name := packageProjectionStagePrefix + strings.Repeat("8", 32) + "-000.tsv"
	assertProjectionResidueReplacementPreserved(t, stateRoot, name, func() error {
		return cleanupPackageProjectionIntentResidue(stateRoot, true)
	})
}

func TestProjectionRecoveryPreservesExactOrphanResidues(t *testing.T) {
	for _, tc := range []struct {
		name     string
		relative string
		cleanup  func(string) error
	}{
		{
			name: "asset", relative: assetProjectionStagePrefix + strings.Repeat("9", 32) + ".tsv",
			cleanup: func(root string) error { return cleanupAssetProjectionIntentResidue(root, true) },
		},
		{
			name: "package", relative: packageProjectionStagePrefix + strings.Repeat("a", 32) + "-000.tsv",
			cleanup: func(root string) error { return cleanupPackageProjectionIntentResidue(root, true) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateRoot := t.TempDir()
			path := filepath.Join(stateRoot, tc.relative)
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tc.cleanup(stateRoot); err == nil || !strings.Contains(err.Error(), "preserved orphan") {
				t.Fatalf("orphan projection residue was not preserved for audit: %v", err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("orphan projection residue remains in the live coordinate: %v", err)
			}
			entries, err := os.ReadDir(stateRoot)
			if err != nil {
				t.Fatal(err)
			}
			preserved := ""
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), tc.relative+".preserved-") {
					preserved = filepath.Join(stateRoot, entry.Name())
				}
			}
			if preserved == "" {
				t.Fatal("orphan projection residue has no preserved audit coordinate")
			}
			if body, err := os.ReadFile(preserved); err != nil || len(body) != 0 {
				t.Fatalf("preserved empty projection residue changed body=%q err=%v", body, err)
			}
			if err := tc.cleanup(stateRoot); err != nil {
				t.Fatalf("second recovery did not ignore preserved audit residue: %v", err)
			}
		})
	}
}

func TestProjectionRecoveryRejectsUnknownStageSuffixes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		relative string
		cleanup  func(string) error
	}{
		{
			name: "asset", relative: assetProjectionStagePrefix + strings.Repeat("b", 32) + ".tsv.test-original",
			cleanup: func(root string) error { return cleanupAssetProjectionIntentResidue(root, true) },
		},
		{
			name: "package", relative: packageProjectionStagePrefix + strings.Repeat("c", 32) + "-000.tsv.test-original",
			cleanup: func(root string) error { return cleanupPackageProjectionIntentResidue(root, true) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateRoot := t.TempDir()
			path := filepath.Join(stateRoot, tc.relative)
			body := []byte("unknown projection residue")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tc.cleanup(stateRoot); err == nil || !strings.Contains(err.Error(), "unsafe") {
				t.Fatalf("unknown projection residue suffix was not rejected: %v", err)
			}
			if current, err := os.ReadFile(path); err != nil || !bytes.Equal(current, body) {
				t.Fatalf("unknown projection residue changed body=%q err=%v", current, err)
			}
		})
	}
}

func TestProjectionStageNameClassificationIsExact(t *testing.T) {
	assetID := strings.Repeat("1", 32)
	packageID := strings.Repeat("2", 32)
	for _, tc := range []struct {
		name  string
		valid bool
		check func(string) bool
	}{
		{name: assetProjectionStagePrefix + assetID + ".tsv", valid: true, check: isAssetProjectionStageFinalName},
		{name: assetProjectionStagePrefix + assetID + "-config.yaml", valid: true, check: isAssetProjectionStageFinalName},
		{name: assetProjectionStagePrefix + assetID + ".tsv.test-original", check: isAssetProjectionStageFinalName},
		{name: packageProjectionStagePrefix + packageID + "-000.tsv", valid: true, check: isPackageProjectionStageFinalName},
		{name: packageProjectionStagePrefix + packageID + "-1000.tsv", valid: true, check: isPackageProjectionStageFinalName},
		{name: packageProjectionStagePrefix + packageID + "-0000.tsv", check: isPackageProjectionStageFinalName},
		{name: packageProjectionStagePrefix + packageID + "-00x.tsv", check: isPackageProjectionStageFinalName},
	} {
		if actual := tc.check(tc.name); actual != tc.valid {
			t.Errorf("projection stage classification name=%q actual=%t want=%t", tc.name, actual, tc.valid)
		}
	}
	final := packageProjectionStagePrefix + packageID + "-000.tsv"
	for _, tc := range []struct {
		name      string
		temporary bool
		preserved bool
	}{
		{name: final + ".tmp-" + strings.Repeat("a", 32), temporary: true},
		{name: final + ".tmp-install-" + strings.Repeat("b", 32) + ".tmp-remove-" + strings.Repeat("c", 32), temporary: true},
		{name: final + ".preserved-" + strings.Repeat("d", 32), preserved: true},
		{name: final + ".tmp", temporary: false},
		{name: final + ".preserved-not-hex", preserved: false},
	} {
		if actual := isProjectionStageTemporaryName(tc.name, isPackageProjectionStageFinalName); actual != tc.temporary {
			t.Errorf("temporary classification name=%q actual=%t want=%t", tc.name, actual, tc.temporary)
		}
		if actual := isProjectionStagePreservedName(tc.name, isPackageProjectionStageFinalName); actual != tc.preserved {
			t.Errorf("preserved classification name=%q actual=%t want=%t", tc.name, actual, tc.preserved)
		}
	}
}

func TestExactPrivateStateRemovalRevalidatesLastUnlinkBoundary(t *testing.T) {
	stateRoot := t.TempDir()
	name := "owned.tmp-" + strings.Repeat("d", 32)
	path := filepath.Join(stateRoot, name)
	if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, identity, err := bindExactProjectionResidue(root, name, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	directory, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	canary := []byte("last-boundary replacement")
	var quarantine string
	previous := projectionStateBeforeUnlinkHook
	projectionStateBeforeUnlinkHook = func(relative string) error {
		quarantine = filepath.Join(stateRoot, relative)
		if err := os.Rename(quarantine, quarantine+".test-original"); err != nil {
			return err
		}
		return os.WriteFile(quarantine, canary, 0o600)
	}
	t.Cleanup(func() { projectionStateBeforeUnlinkHook = previous })
	err = commitExactPrivateStateFileRemoval(root, directory, file, identity, name, func() error { return nil })
	if err == nil {
		t.Fatal("exact removal accepted a replacement at the last unlink boundary")
	}
	preserved := false
	for _, candidate := range []string{path, quarantine} {
		body, readErr := os.ReadFile(candidate)
		if readErr == nil && bytes.Equal(body, canary) {
			preserved = true
		}
	}
	if !preserved {
		t.Fatal("last-boundary replacement bytes did not survive")
	}
	projectionStateBeforeUnlinkHook = previous
}

func assertProjectionResidueReplacementPreserved(t *testing.T, stateRoot, name string, cleanup func() error) {
	t.Helper()
	path := filepath.Join(stateRoot, name)
	if err := os.WriteFile(path, []byte("owned orphan residue"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := projectionResidueCleanupHook
	projectionResidueCleanupHook = func(relative string) error {
		if relative != name {
			return nil
		}
		return replaceProjectionStageWithCanary(path)
	}
	t.Cleanup(func() { projectionResidueCleanupHook = previous })
	err := cleanup()
	if err == nil {
		t.Fatal("projection recovery accepted a replacement residue pathname")
	}
	want := []byte("foreign stage replacement must survive")
	body, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(body, want) {
		t.Fatalf("projection recovery deleted or changed replacement body=%q err=%v", body, readErr)
	}
	projectionResidueCleanupHook = nil
}
