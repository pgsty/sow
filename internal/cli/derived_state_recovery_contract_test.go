package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDerivedStateRecoveryRecognizesCurrentTemporaryNames(t *testing.T) {
	tests := []struct {
		name      string
		canonical string
		directory func(string) (string, bool, error)
		cleanup   func(string) error
	}{
		{
			name: "materialization-selection", canonical: "active.json",
			directory: func(root string) (string, bool, error) {
				return materializationSelectionJournalDirectory(root, true)
			},
			cleanup: cleanupMaterializationSelectionJournalTemps,
		},
		{
			name: "local-serving", canonical: strings.Repeat("a", 32) + ".json",
			directory: func(root string) (string, bool, error) {
				return localServingJournalDirectory(root, true)
			},
			cleanup: cleanupLocalServingJournalTemps,
		},
		{
			name: "local-serving-removal", canonical: strings.Repeat("b", 32) + ".json",
			directory: func(root string) (string, bool, error) {
				return localServingRemovalDirectory(root, true)
			},
			cleanup: cleanupLocalServingRemovalTemps,
		},
	}
	for _, tc := range tests {
		for _, residue := range []struct {
			name   string
			suffix string
		}{
			{name: "write", suffix: ".tmp-" + strings.Repeat("c", 32)},
			{name: "install", suffix: ".tmp-install-" + strings.Repeat("d", 32)},
			{name: "write-removal", suffix: ".tmp-" + strings.Repeat("c", 32) + ".tmp-remove-" + strings.Repeat("4", 32)},
			{name: "install-removal", suffix: ".tmp-install-" + strings.Repeat("d", 32) + ".tmp-remove-" + strings.Repeat("5", 32)},
		} {
			t.Run(tc.name+"-"+residue.name, func(t *testing.T) {
				stateRoot := t.TempDir()
				directory, _, err := tc.directory(stateRoot)
				if err != nil {
					t.Fatal(err)
				}
				temporary := filepath.Join(directory, tc.canonical+residue.suffix)
				if err := os.WriteFile(temporary, []byte("interrupted"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := tc.cleanup(stateRoot); err != nil {
					t.Fatalf("clean current derived-state residue: %v", err)
				}
				if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("current derived-state residue remains: %v", err)
				}
			})
		}
	}
}

func TestExactPrivateStateRemovalReportsQuarantineUnlinkFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can unlink from a non-writable test directory")
	}
	stateRoot := t.TempDir()
	name := "owned.tmp-" + strings.Repeat("6", 32)
	if err := os.WriteFile(filepath.Join(stateRoot, name), []byte("owned"), 0o600); err != nil {
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
	err = commitExactPrivateStateFileRemoval(root, directory, file, identity, name, func() error {
		return os.Chmod(stateRoot, 0o500)
	})
	if chmodErr := os.Chmod(stateRoot, 0o700); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	if err == nil {
		t.Fatal("exact removal hid quarantine unlink failure")
	}
}

func TestDerivedStateRecoveryPreservesConcurrentTemporaryReplacement(t *testing.T) {
	tests := []struct {
		name      string
		canonical string
		directory func(string) (string, bool, error)
		cleanup   func(string) error
	}{
		{
			name: "materialization-selection", canonical: "active.json",
			directory: func(root string) (string, bool, error) {
				return materializationSelectionJournalDirectory(root, true)
			},
			cleanup: cleanupMaterializationSelectionJournalTemps,
		},
		{
			name: "local-serving", canonical: strings.Repeat("e", 32) + ".json",
			directory: func(root string) (string, bool, error) {
				return localServingJournalDirectory(root, true)
			},
			cleanup: cleanupLocalServingJournalTemps,
		},
		{
			name: "local-serving-removal", canonical: strings.Repeat("f", 32) + ".json",
			directory: func(root string) (string, bool, error) {
				return localServingRemovalDirectory(root, true)
			},
			cleanup: cleanupLocalServingRemovalTemps,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stateRoot := t.TempDir()
			directory, _, err := tc.directory(stateRoot)
			if err != nil {
				t.Fatal(err)
			}
			name := tc.canonical + ".tmp-" + strings.Repeat("1", 16)
			path := filepath.Join(directory, name)
			if err := os.WriteFile(path, []byte("owned residue"), 0o600); err != nil {
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
			err = tc.cleanup(stateRoot)
			if err == nil {
				t.Fatal("derived-state recovery accepted a replacement temporary")
			}
			want := []byte("foreign stage replacement must survive")
			body, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(body, want) {
				t.Fatalf("derived-state recovery deleted replacement body=%q err=%v", body, readErr)
			}
			projectionResidueCleanupHook = nil
		})
	}
}

func TestExactPrivateStateRemovalRevalidatesQuarantineAfterCallback(t *testing.T) {
	stateRoot := t.TempDir()
	name := "owned.tmp-" + strings.Repeat("2", 32)
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
	canary := []byte("foreign quarantine replacement")
	var quarantine string
	err = commitExactPrivateStateFileRemoval(root, directory, file, identity, name, func() error {
		entries, err := os.ReadDir(stateRoot)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), name+".tmp-remove-") {
				quarantine = filepath.Join(stateRoot, entry.Name())
				break
			}
		}
		if quarantine == "" {
			return errors.New("test did not find removal quarantine")
		}
		if err := os.Rename(quarantine, quarantine+".test-original"); err != nil {
			return err
		}
		return os.WriteFile(quarantine, canary, 0o600)
	})
	if err == nil {
		t.Fatal("exact removal deleted a replacement quarantine")
	}
	preserved := false
	for _, candidate := range []string{path, quarantine} {
		body, readErr := os.ReadFile(candidate)
		if readErr == nil && bytes.Equal(body, canary) {
			preserved = true
		}
	}
	if !preserved {
		t.Fatal("replacement quarantine bytes did not survive")
	}
}

func TestDerivedStateWriteRevalidatesIsolationAfterFinalHash(t *testing.T) {
	stateRoot := t.TempDir()
	directory := filepath.Join(stateRoot, "generated")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "channel.json")
	prior := []byte("prior canonical state")
	if err := os.WriteFile(destination, prior, 0o600); err != nil {
		t.Fatal(err)
	}
	canary := []byte("foreign post-hash replacement")
	previous := derivedStateAfterVerifyHook
	derivedStateAfterVerifyHook = func(name string) error {
		isolation := filepath.Join(directory, name)
		if err := os.Rename(isolation, isolation+".test-original"); err != nil {
			return err
		}
		return os.WriteFile(isolation, canary, 0o600)
	}
	t.Cleanup(func() { derivedStateAfterVerifyHook = previous })
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "channel.json"), []byte("new canonical state")); err == nil {
		t.Fatal("derived-state writer installed a post-hash replacement")
	}
	body, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(body, prior) {
		t.Fatalf("post-hash replacement changed canonical state body=%q err=%v", body, err)
	}
	derivedStateAfterVerifyHook = nil
}

func TestProjectionRecoveryRejectsReplacedStateRootAfterResidueBind(t *testing.T) {
	parent := t.TempDir()
	stateRoot := filepath.Join(parent, "state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := assetProjectionStagePrefix + strings.Repeat("3", 32) + ".tsv"
	path := filepath.Join(stateRoot, name)
	if err := os.WriteFile(path, []byte("owned orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	canary := []byte("replacement root residue")
	previous := projectionResidueCleanupHook
	projectionResidueCleanupHook = func(relative string) error {
		if relative != name {
			return nil
		}
		if err := os.Rename(stateRoot, stateRoot+".test-original"); err != nil {
			return err
		}
		if err := os.Mkdir(stateRoot, 0o700); err != nil {
			return err
		}
		return os.WriteFile(path, canary, 0o600)
	}
	t.Cleanup(func() { projectionResidueCleanupHook = previous })
	if err := cleanupAssetProjectionIntentResidue(stateRoot, true); err == nil {
		t.Fatal("projection recovery accepted a replaced state-root coordinate")
	}
	body, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(body, canary) {
		t.Fatalf("projection recovery changed replacement root body=%q err=%v", body, err)
	}
	projectionResidueCleanupHook = nil
}

func TestProjectionRecoveryTreatsConcurrentResidueDisappearanceAsIdempotent(t *testing.T) {
	stateRoot := t.TempDir()
	name := assetProjectionStagePrefix + strings.Repeat("7", 32) + ".tsv"
	path := filepath.Join(stateRoot, name)
	if err := os.WriteFile(path, []byte("owned orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := projectionResidueCleanupHook
	projectionResidueCleanupHook = func(relative string) error {
		if relative != name {
			return nil
		}
		return os.Remove(path)
	}
	t.Cleanup(func() { projectionResidueCleanupHook = previous })
	if err := cleanupAssetProjectionIntentResidue(stateRoot, true); err != nil {
		t.Fatalf("concurrent exact residue disappearance was not idempotent: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("concurrently removed residue reappeared: %v", err)
	}
	projectionResidueCleanupHook = nil
}
