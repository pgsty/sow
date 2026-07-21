package cli

import (
	"bytes"
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
	for _, relative := range []string{intent.StageRelative, intent.ConfigStage} {
		if err := os.WriteFile(filepath.Join(stateRoot, relative), []byte("frozen"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeAssetProjectionIntent(stateRoot, intent); err != nil {
		t.Fatalf("remove exact asset projection intent: %v", err)
	}
	for _, relative := range []string{assetProjectionIntentRelative, intent.StageRelative, intent.ConfigStage} {
		if _, err := os.Lstat(filepath.Join(stateRoot, relative)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("completed asset projection residue %s remains: %v", relative, err)
		}
	}
}

func writeTestAssetProjectionIntent(t *testing.T) (string, assetProjectionIntent) {
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
	intent.ID, err = assetProjectionIntentID(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAssetProjectionIntent(stateRoot, intent); err != nil {
		t.Fatal(err)
	}
	return stateRoot, intent
}

func TestPackageProjectionCompletionPreservesConcurrentIntentReplacement(t *testing.T) {
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
	assertProjectionIntentReplacementPreserved(t, stateRoot, packageProjectionIntentRelative, func() error {
		return removePackageProjectionIntent(stateRoot, intent)
	})
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
