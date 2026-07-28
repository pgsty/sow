package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDerivedStateWriterStopsAtFailedAncestorDirectorySync(t *testing.T) {
	stateRoot := t.TempDir()
	relative := filepath.Join("generated", "channels", "cf", "latest", "state.json")
	injected := errors.New("injected ancestor directory sync failure")
	previous := derivedStateDirectorySync
	seen := make([]string, 0, 4)
	failOnce := true
	derivedStateDirectorySync = func(parent *os.Root, created string) error {
		seen = append(seen, created)
		if created == filepath.Join("generated", "channels") && failOnce {
			failOnce = false
			return injected
		}
		return previous(parent, created)
	}
	t.Cleanup(func() { derivedStateDirectorySync = previous })
	err := writeDerivedStateFile(stateRoot, relative, []byte("durable state\n"))
	if !errors.Is(err, injected) {
		t.Fatalf("ancestor sync failure error=%v", err)
	}
	wantSeen := []string{"generated", filepath.Join("generated", "channels")}
	if !reflect.DeepEqual(seen, wantSeen) {
		t.Fatalf("directory sync order=%v want=%v", seen, wantSeen)
	}
	if _, statErr := os.Stat(filepath.Join(stateRoot, "generated", "channels")); statErr != nil {
		t.Fatalf("failed but created level is unavailable: %v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(stateRoot, "generated", "channels", "cf")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("writer descended after failed parent sync: %v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(stateRoot, relative)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("writer published after failed ancestor sync: %v", statErr)
	}
	if err := writeDerivedStateFile(stateRoot, relative, []byte("durable state\n")); err != nil {
		t.Fatalf("replay after ancestor sync failure: %v", err)
	}
	derivedStateDirectorySync = previous
	wantSeen = append(wantSeen,
		"generated",
		filepath.Join("generated", "channels"),
		filepath.Join("generated", "channels", "cf"),
		filepath.Join("generated", "channels", "cf", "latest"),
	)
	if !reflect.DeepEqual(seen, wantSeen) {
		t.Fatalf("directory replay sync order=%v want=%v", seen, wantSeen)
	}
}

func TestDerivedStateWriterRejectsNewDirectoryReplacementAfterParentSync(t *testing.T) {
	parent := t.TempDir()
	stateRoot := filepath.Join(parent, "state")
	displaced := filepath.Join(parent, "admitted-generated")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	relative := filepath.Join("generated", "deep", "state.json")
	previous := derivedStateDirectoryAfterSyncHook
	derivedStateDirectoryAfterSyncHook = func(created string) error {
		if created != "generated" {
			return nil
		}
		if err := os.Rename(filepath.Join(stateRoot, "generated"), displaced); err != nil {
			return err
		}
		return os.Mkdir(filepath.Join(stateRoot, "generated"), 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryAfterSyncHook = previous })
	err := writeDerivedStateFile(stateRoot, relative, []byte("must not publish\n"))
	derivedStateDirectoryAfterSyncHook = previous
	if err == nil || !strings.Contains(err.Error(), "directory coordinate changed") {
		t.Fatalf("new directory replacement error=%v", err)
	}
	for _, path := range []string{
		filepath.Join(stateRoot, relative),
		filepath.Join(displaced, "deep", "state.json"),
	} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("directory replacement received state at %s: %v", path, statErr)
		}
	}
}

func TestDerivedStateWriterAdmitsConcurrentWinnerOnlyAfterParentSync(t *testing.T) {
	stateRoot := t.TempDir()
	previousHook := derivedStateDirectoryBeforeCreateHook
	derivedStateDirectoryBeforeCreateHook = func(created string) error {
		if created != "generated" {
			return nil
		}
		return os.Mkdir(filepath.Join(stateRoot, created), 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeCreateHook = previousHook })
	previousSync := derivedStateDirectorySync
	seen := make([]string, 0, 2)
	derivedStateDirectorySync = func(parent *os.Root, relative string) error {
		seen = append(seen, relative)
		return previousSync(parent, relative)
	}
	t.Cleanup(func() { derivedStateDirectorySync = previousSync })
	relative := filepath.Join("generated", "deep", "state.json")
	if err := writeDerivedStateFile(stateRoot, relative, []byte("converged\n")); err != nil {
		t.Fatalf("concurrent directory winner did not converge: %v", err)
	}
	derivedStateDirectoryBeforeCreateHook = previousHook
	derivedStateDirectorySync = previousSync
	if want := []string{"generated", filepath.Join("generated", "deep")}; !reflect.DeepEqual(seen, want) {
		t.Fatalf("concurrent winner sync order=%v want=%v", seen, want)
	}
	body, err := os.ReadFile(filepath.Join(stateRoot, relative))
	if err != nil || string(body) != "converged\n" {
		t.Fatalf("concurrent winner state=%q err=%v", body, err)
	}
	entries, err := os.ReadDir(stateRoot)
	if err != nil || len(entries) != 1 || entries[0].Name() != "generated" {
		t.Fatalf("concurrent winner left stage residue entries=%v err=%v", entries, err)
	}
}

func TestDerivedStateWriterRejectsNewDirectoryReplacementBeforeBind(t *testing.T) {
	parent := t.TempDir()
	stateRoot := filepath.Join(parent, "state")
	displaced := filepath.Join(parent, "admitted-generated")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := derivedStateDirectoryBeforeBindHook
	derivedStateDirectoryBeforeBindHook = func(created string) error {
		if created != "generated" {
			return nil
		}
		if err := os.Rename(filepath.Join(stateRoot, "generated"), displaced); err != nil {
			return err
		}
		return os.Mkdir(filepath.Join(stateRoot, "generated"), 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeBindHook = previous })
	err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "deep", "state.json"), []byte("must not publish\n"))
	derivedStateDirectoryBeforeBindHook = previous
	if err == nil || !strings.Contains(err.Error(), "changed while") {
		t.Fatalf("pre-bind directory replacement error=%v", err)
	}
	for _, path := range []string{
		filepath.Join(stateRoot, "generated", "deep", "state.json"),
		filepath.Join(displaced, "deep", "state.json"),
	} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("pre-bind replacement received state at %s: %v", path, statErr)
		}
	}
}

func TestDerivedStateWriterRejectsStageModeMutationBeforeInstall(t *testing.T) {
	stateRoot := t.TempDir()
	previous := derivedStateDirectoryBeforeStageInstallHook
	derivedStateDirectoryBeforeStageInstallHook = func(stage string) error {
		return os.Chmod(filepath.Join(stateRoot, stage), 0o755)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeStageInstallHook = previous })
	err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("must not publish\n"))
	derivedStateDirectoryBeforeStageInstallHook = previous
	if err == nil || !strings.Contains(err.Error(), "coordinate changed") {
		t.Fatalf("stage mode mutation error=%v", err)
	}
	entries, readErr := os.ReadDir(stateRoot)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("mode-mutated stage was not cleaned entries=%v err=%v", entries, readErr)
	}
}

func TestDerivedStateWriterPreservesStageReplacementBeforeInstall(t *testing.T) {
	stateRoot := t.TempDir()
	displaced := filepath.Join(t.TempDir(), "admitted-stage")
	var replacement string
	previous := derivedStateDirectoryBeforeStageInstallHook
	derivedStateDirectoryBeforeStageInstallHook = func(stage string) error {
		replacement = filepath.Join(stateRoot, stage)
		if err := os.Rename(replacement, displaced); err != nil {
			return err
		}
		return os.Mkdir(replacement, 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeStageInstallHook = previous })
	err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("must not publish\n"))
	derivedStateDirectoryBeforeStageInstallHook = previous
	if err == nil || !strings.Contains(err.Error(), "stage changed before removal") {
		t.Fatalf("stage replacement error=%v", err)
	}
	entries, readErr := os.ReadDir(stateRoot)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var preservedReplacement string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), filepath.Base(replacement)+derivedStateDirectoryStagePreservedMarker) {
			preservedReplacement = filepath.Join(stateRoot, entry.Name())
		}
	}
	if preservedReplacement == "" {
		t.Fatalf("stage replacement was not moved outside recovery namespace entries=%v", entries)
	}
	for _, path := range []string{preservedReplacement, displaced} {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.IsDir() {
			t.Fatalf("stage replacement evidence missing at %s: %v", path, statErr)
		}
	}
	if _, statErr := os.Lstat(filepath.Join(stateRoot, "generated")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("stage replacement reached canonical directory: %v", statErr)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("safe replay\n")); err != nil {
		t.Fatalf("replay after preserving pre-install replacement: %v", err)
	}
	if info, statErr := os.Lstat(preservedReplacement); statErr != nil || !info.IsDir() {
		t.Fatalf("replay removed pre-install replacement evidence: %v", statErr)
	}
}

func TestDerivedStateWriterRollsBackNewDirectoryModeMutationBeforeBind(t *testing.T) {
	stateRoot := t.TempDir()
	previous := derivedStateDirectoryBeforeBindHook
	derivedStateDirectoryBeforeBindHook = func(relative string) error {
		if relative != "generated" {
			return nil
		}
		return os.Chmod(filepath.Join(stateRoot, relative), 0o755)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeBindHook = previous })
	err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("must not publish\n"))
	derivedStateDirectoryBeforeBindHook = previous
	if err == nil || !strings.Contains(err.Error(), "changed while installing") {
		t.Fatalf("new directory mode mutation error=%v", err)
	}
	entries, readErr := os.ReadDir(stateRoot)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("mode-mutated canonical directory was not rolled back entries=%v err=%v", entries, readErr)
	}
}

func TestDerivedStateWriterPreservesReplacementAtDirectoryRemovalBoundary(t *testing.T) {
	parent := t.TempDir()
	stateRoot := filepath.Join(parent, "state")
	displaced := filepath.Join(parent, "admitted-quarantine")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	previousCreate := derivedStateDirectoryBeforeCreateHook
	derivedStateDirectoryBeforeCreateHook = func(relative string) error {
		if relative != "generated" {
			return nil
		}
		return os.Mkdir(filepath.Join(stateRoot, relative), 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeCreateHook = previousCreate })
	previousRemoval := derivedStateDirectoryBeforeRemovalHook
	var replacement string
	derivedStateDirectoryBeforeRemovalHook = func(quarantine string) error {
		replacement = filepath.Join(stateRoot, quarantine)
		if err := os.Rename(replacement, displaced); err != nil {
			return err
		}
		return os.Mkdir(replacement, 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeRemovalHook = previousRemoval })
	err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("must not publish\n"))
	derivedStateDirectoryBeforeCreateHook = previousCreate
	derivedStateDirectoryBeforeRemovalHook = previousRemoval
	if err == nil || !strings.Contains(err.Error(), "stage changed before removal") {
		t.Fatalf("directory removal replacement error=%v", err)
	}
	base := strings.TrimSuffix(replacement, derivedStateDirectoryStageQuarantineSuffix)
	entries, readErr := os.ReadDir(stateRoot)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var preservedReplacement string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), filepath.Base(base)+derivedStateDirectoryStagePreservedMarker) {
			preservedReplacement = filepath.Join(stateRoot, entry.Name())
			if _, recoverable := derivedStateDirectoryStageBase(entry.Name()); recoverable {
				t.Fatalf("preserved replacement remained recoverable as %s", entry.Name())
			}
		}
	}
	if preservedReplacement == "" {
		t.Fatalf("directory removal replacement was not preserved outside recovery namespace entries=%v", entries)
	}
	for _, path := range []string{preservedReplacement, displaced} {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.IsDir() {
			t.Fatalf("directory removal evidence missing at %s: %v", path, statErr)
		}
	}
	if _, statErr := os.Lstat(filepath.Join(stateRoot, "generated", "state.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("directory removal replacement received state: %v", statErr)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("safe replay\n")); err != nil {
		t.Fatalf("replay after preserving directory replacement: %v", err)
	}
	if info, statErr := os.Lstat(preservedReplacement); statErr != nil || !info.IsDir() {
		t.Fatalf("replay removed preserved replacement at %s: %v", preservedReplacement, statErr)
	}
}

func TestDerivedStateWriterPreservesCanonicalReoccupationBeforeRestoringQuarantine(t *testing.T) {
	stateRoot := t.TempDir()
	injected := errors.New("injected cleanup interruption")
	previousBind := derivedStateDirectoryBeforeBindHook
	derivedStateDirectoryBeforeBindHook = func(relative string) error {
		if relative != "generated" {
			return nil
		}
		return os.Chmod(filepath.Join(stateRoot, relative), 0o755)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeBindHook = previousBind })
	previousRemoval := derivedStateDirectoryBeforeRemovalHook
	derivedStateDirectoryBeforeRemovalHook = func(quarantine string) error {
		if err := os.Chmod(filepath.Join(stateRoot, quarantine), 0o700); err != nil {
			return err
		}
		if err := os.Mkdir(filepath.Join(stateRoot, "generated"), 0o700); err != nil {
			return err
		}
		return injected
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeRemovalHook = previousRemoval })
	err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("must not publish\n"))
	derivedStateDirectoryBeforeBindHook = previousBind
	derivedStateDirectoryBeforeRemovalHook = previousRemoval
	if !errors.Is(err, injected) {
		t.Fatalf("canonical reoccupation error=%v", err)
	}
	var preserved string
	entries, readErr := os.ReadDir(stateRoot)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), derivedStateDirectoryStagePreservedMarker) {
			preserved = filepath.Join(stateRoot, entry.Name())
		}
	}
	if preserved == "" {
		t.Fatalf("canonical reoccupation was not preserved entries=%v", entries)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("replayed\n")); err != nil {
		t.Fatalf("replay after canonical reoccupation: %v", err)
	}
	if info, statErr := os.Lstat(preserved); statErr != nil || !info.IsDir() {
		t.Fatalf("replay removed preserved canonical reoccupation: %v", statErr)
	}
}

func TestDerivedStateWriterRecoversRepeatedDirectoryStageCrashes(t *testing.T) {
	if stateRoot := os.Getenv("SOW_DERIVED_DIRECTORY_CRASH_ROOT"); stateRoot != "" {
		switch os.Getenv("SOW_DERIVED_DIRECTORY_CRASH_MODE") {
		case "stage":
			derivedStateDirectoryBeforeStageInstallHook = func(string) error {
				os.Exit(93)
				return nil
			}
		case "remove":
			derivedStateDirectoryBeforeRemovalHook = func(string) error {
				os.Exit(94)
				return nil
			}
		default:
			os.Exit(95)
		}
		_ = writeDerivedStateFile(stateRoot, filepath.Join("generated", "deep", "state.json"), []byte("recovered\n"))
		os.Exit(96)
	}

	stateRoot := t.TempDir()
	runCrash := func(mode string, wantExit int) {
		t.Helper()
		command := exec.Command(os.Args[0], "-test.run=^TestDerivedStateWriterRecoversRepeatedDirectoryStageCrashes$")
		command.Env = append(os.Environ(),
			"SOW_DERIVED_DIRECTORY_CRASH_ROOT="+stateRoot,
			"SOW_DERIVED_DIRECTORY_CRASH_MODE="+mode,
		)
		err := command.Run()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != wantExit {
			t.Fatalf("%s crash err=%v want exit=%d", mode, err, wantExit)
		}
	}
	stageResidues := func() []string {
		t.Helper()
		var residues []string
		err := filepath.WalkDir(stateRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if _, ok := derivedStateDirectoryStageBase(entry.Name()); ok {
				residues = append(residues, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(residues)
		return residues
	}

	runCrash("stage", 93)
	first := stageResidues()
	if len(first) != 1 || strings.HasSuffix(first[0], derivedStateDirectoryStageQuarantineSuffix) {
		t.Fatalf("after stage crash residues=%v", first)
	}
	runCrash("remove", 94)
	second := stageResidues()
	if len(second) != 1 || !strings.HasSuffix(second[0], derivedStateDirectoryStageQuarantineSuffix) {
		t.Fatalf("after removal crash residues=%v", second)
	}
	runCrash("remove", 94)
	third := stageResidues()
	if !reflect.DeepEqual(third, second) {
		t.Fatalf("repeated removal crash changed stable quarantine first=%v second=%v", second, third)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "deep", "state.json"), []byte("recovered\n")); err != nil {
		t.Fatalf("replay after repeated stage crashes: %v", err)
	}
	if residues := stageResidues(); len(residues) != 0 {
		t.Fatalf("replay retained directory stage residues=%v", residues)
	}
	body, err := os.ReadFile(filepath.Join(stateRoot, "generated", "deep", "state.json"))
	if err != nil || string(body) != "recovered\n" {
		t.Fatalf("recovered state=%q err=%v", body, err)
	}
}

func TestDerivedStateWriterClearsAbsentDirtyStageAfterDurableRescan(t *testing.T) {
	stateRoot := t.TempDir()
	residue := filepath.Join(stateRoot, derivedStateDirectoryStagePrefix+strings.Repeat("c", 32))
	if err := os.Mkdir(residue, 0o700); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected post-remove directory sync failure")
	previousSync := derivedStateDirectoryParentSync
	syncCalls := 0
	derivedStateDirectoryParentSync = func(parent *os.File) error {
		syncCalls++
		if syncCalls == 2 {
			return injected
		}
		return previousSync(parent)
	}
	t.Cleanup(func() { derivedStateDirectoryParentSync = previousSync })
	err := writeDerivedStateFile(stateRoot, "first.json", []byte("first\n"))
	derivedStateDirectoryParentSync = previousSync
	if !errors.Is(err, injected) {
		t.Fatalf("post-remove sync error=%v", err)
	}
	if _, statErr := os.Lstat(residue); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("removed stage coordinate reappeared: %v", statErr)
	}
	previousScan := derivedStateDirectoryRecoveryScanHook
	rootScans := 0
	derivedStateDirectoryRecoveryScanHook = func(relative string) {
		if relative == "." {
			rootScans++
		}
	}
	t.Cleanup(func() { derivedStateDirectoryRecoveryScanHook = previousScan })
	if err := writeDerivedStateFile(stateRoot, "second.json", []byte("second\n")); err != nil {
		t.Fatalf("durable rescan after post-remove sync failure: %v", err)
	}
	if err := writeDerivedStateFile(stateRoot, "third.json", []byte("third\n")); err != nil {
		t.Fatalf("write after clearing absent dirty stage: %v", err)
	}
	derivedStateDirectoryRecoveryScanHook = previousScan
	if rootScans != 1 {
		t.Fatalf("root recovery scans=%d want=1 after clearing absent dirty stage", rootScans)
	}
}

func TestDerivedStateWriterPreservesReoccupationAfterDirectoryUnlink(t *testing.T) {
	stateRoot := t.TempDir()
	residue := filepath.Join(stateRoot, derivedStateDirectoryStagePrefix+strings.Repeat("d", 32))
	if err := os.Mkdir(residue, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := derivedStateDirectoryAfterRemovalHook
	derivedStateDirectoryAfterRemovalHook = func(quarantine string) error {
		return os.Mkdir(filepath.Join(stateRoot, quarantine), 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryAfterRemovalHook = previous })
	injected := errors.New("injected post-unlink parent sync failure")
	previousSync := derivedStateDirectoryParentSync
	syncCalls := 0
	derivedStateDirectoryParentSync = func(parent *os.File) error {
		syncCalls++
		if syncCalls == 2 {
			return injected
		}
		return previousSync(parent)
	}
	t.Cleanup(func() { derivedStateDirectoryParentSync = previousSync })
	err := writeDerivedStateFile(stateRoot, "first.json", []byte("must not publish\n"))
	derivedStateDirectoryAfterRemovalHook = previous
	derivedStateDirectoryParentSync = previousSync
	if !errors.Is(err, errDerivedStateDirectoryStagePreserved) || !errors.Is(err, injected) {
		t.Fatalf("post-unlink reoccupation error=%v", err)
	}
	entries, readErr := os.ReadDir(stateRoot)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var preserved string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), derivedStateDirectoryStagePreservedMarker) {
			preserved = filepath.Join(stateRoot, entry.Name())
		}
		if _, recoverable := derivedStateDirectoryStageBase(entry.Name()); recoverable {
			t.Fatalf("post-unlink replacement remains recoverable as %s", entry.Name())
		}
	}
	if preserved == "" {
		t.Fatalf("post-unlink replacement was not preserved entries=%v", entries)
	}
	if err := writeDerivedStateFile(stateRoot, "second.json", []byte("replayed\n")); err != nil {
		t.Fatalf("replay after post-unlink replacement: %v", err)
	}
	if info, statErr := os.Lstat(preserved); statErr != nil || !info.IsDir() {
		t.Fatalf("replay removed post-unlink replacement evidence: %v", statErr)
	}
}

func TestDerivedStateWriterPreservesRecoveryReplacementAfterInitialLstat(t *testing.T) {
	container := t.TempDir()
	stateRoot := filepath.Join(container, "state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := derivedStateDirectoryStagePrefix + strings.Repeat("9", 32)
	residue := filepath.Join(stateRoot, name)
	if err := os.Mkdir(residue, 0o700); err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(container, "admitted-residue")
	previous := derivedStateDirectoryRecoveryAfterLstatHook
	derivedStateDirectoryRecoveryAfterLstatHook = func(relative string) error {
		if filepath.Base(relative) != name {
			return nil
		}
		if err := os.Rename(residue, displaced); err != nil {
			return err
		}
		return os.Mkdir(residue, 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryRecoveryAfterLstatHook = previous })
	err := writeDerivedStateFile(stateRoot, "first.json", []byte("must not publish\n"))
	derivedStateDirectoryRecoveryAfterLstatHook = previous
	if !errors.Is(err, errDerivedStateDirectoryStagePreserved) {
		t.Fatalf("recovery replacement error=%v", err)
	}
	entries, readErr := os.ReadDir(stateRoot)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var preserved string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), derivedStateDirectoryStagePreservedMarker) {
			preserved = filepath.Join(stateRoot, entry.Name())
		}
		if _, recoverable := derivedStateDirectoryStageBase(entry.Name()); recoverable {
			t.Fatalf("recovery replacement remained recoverable as %s", entry.Name())
		}
	}
	if preserved == "" {
		t.Fatalf("recovery replacement was not preserved entries=%v", entries)
	}
	if err := writeDerivedStateFile(stateRoot, "second.json", []byte("replayed\n")); err != nil {
		t.Fatalf("replay after recovery replacement: %v", err)
	}
	for _, path := range []string{preserved, displaced} {
		if info, statErr := os.Lstat(path); statErr != nil || !info.IsDir() {
			t.Fatalf("replay removed recovery replacement evidence at %s: %v", path, statErr)
		}
	}
}

func TestDerivedStateWriterPreservesCanonicalReplacementWhenQuarantineDisappears(t *testing.T) {
	container := t.TempDir()
	stateRoot := filepath.Join(container, "state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := derivedStateDirectoryStagePrefix + strings.Repeat("8", 32)
	if err := os.Mkdir(filepath.Join(stateRoot, name), 0o700); err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(container, "admitted-quarantine")
	previous := derivedStateDirectoryBeforeRemovalHook
	derivedStateDirectoryBeforeRemovalHook = func(quarantine string) error {
		if err := os.Rename(filepath.Join(stateRoot, quarantine), displaced); err != nil {
			return err
		}
		return os.Mkdir(filepath.Join(stateRoot, name), 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeRemovalHook = previous })
	err := writeDerivedStateFile(stateRoot, "first.json", []byte("must not publish\n"))
	derivedStateDirectoryBeforeRemovalHook = previous
	if !errors.Is(err, errDerivedStateDirectoryStagePreserved) {
		t.Fatalf("quarantine disappearance error=%v", err)
	}
	entries, readErr := os.ReadDir(stateRoot)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var preserved string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), derivedStateDirectoryStagePreservedMarker) {
			preserved = filepath.Join(stateRoot, entry.Name())
		}
		if _, recoverable := derivedStateDirectoryStageBase(entry.Name()); recoverable {
			t.Fatalf("quarantine-disappearance replacement remained recoverable as %s", entry.Name())
		}
	}
	if preserved == "" {
		t.Fatalf("quarantine-disappearance replacement was not preserved entries=%v", entries)
	}
	if err := writeDerivedStateFile(stateRoot, "second.json", []byte("replayed\n")); err != nil {
		t.Fatalf("replay after quarantine disappearance: %v", err)
	}
	for _, path := range []string{preserved, displaced} {
		if info, statErr := os.Lstat(path); statErr != nil || !info.IsDir() {
			t.Fatalf("replay removed quarantine-disappearance evidence at %s: %v", path, statErr)
		}
	}
}

func TestDerivedStateWriterDrainsBothForeignCoordinatesAfterFirstPreserveSyncFailure(t *testing.T) {
	container := t.TempDir()
	stateRoot := filepath.Join(container, "state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := derivedStateDirectoryStagePrefix + strings.Repeat("6", 32)
	if err := os.Mkdir(filepath.Join(stateRoot, name), 0o700); err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(container, "admitted-quarantine")
	previousRemoval := derivedStateDirectoryBeforeRemovalHook
	derivedStateDirectoryBeforeRemovalHook = func(quarantine string) error {
		if err := os.Rename(filepath.Join(stateRoot, quarantine), displaced); err != nil {
			return err
		}
		if err := os.Mkdir(filepath.Join(stateRoot, quarantine), 0o700); err != nil {
			return err
		}
		return os.Mkdir(filepath.Join(stateRoot, name), 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeRemovalHook = previousRemoval })
	injected := errors.New("injected first preservation sync failure")
	previousSync := derivedStateDirectoryParentSync
	syncCalls := 0
	derivedStateDirectoryParentSync = func(parent *os.File) error {
		syncCalls++
		if syncCalls == 2 {
			return injected
		}
		return previousSync(parent)
	}
	t.Cleanup(func() { derivedStateDirectoryParentSync = previousSync })
	err := writeDerivedStateFile(stateRoot, "first.json", []byte("must not publish\n"))
	derivedStateDirectoryBeforeRemovalHook = previousRemoval
	derivedStateDirectoryParentSync = previousSync
	if !errors.Is(err, errDerivedStateDirectoryStagePreserved) {
		t.Fatalf("dual-coordinate preservation error=%v", err)
	}
	entries, readErr := os.ReadDir(stateRoot)
	if readErr != nil {
		t.Fatal(readErr)
	}
	preserved := 0
	for _, entry := range entries {
		if strings.Contains(entry.Name(), derivedStateDirectoryStagePreservedMarker) {
			preserved++
		}
		if _, recoverable := derivedStateDirectoryStageBase(entry.Name()); recoverable {
			t.Fatalf("dual-coordinate replacement remained recoverable as %s", entry.Name())
		}
	}
	if preserved != 2 {
		t.Fatalf("preserved replacements=%d want=2 entries=%v", preserved, entries)
	}
	if err := writeDerivedStateFile(stateRoot, "second.json", []byte("replayed\n")); err != nil {
		t.Fatalf("replay after dual-coordinate preservation: %v", err)
	}
}

func TestDerivedStateWriterDurablyCreatesEveryMissingAncestorInOrder(t *testing.T) {
	stateRoot := t.TempDir()
	relative := filepath.Join("generated", "channels", "cf", "latest", "state.json")
	previous := derivedStateDirectorySync
	seen := make([]string, 0, 4)
	derivedStateDirectorySync = func(parent *os.Root, created string) error {
		seen = append(seen, created)
		return previous(parent, created)
	}
	t.Cleanup(func() { derivedStateDirectorySync = previous })
	if err := writeDerivedStateFile(stateRoot, relative, []byte("durable state\n")); err != nil {
		t.Fatal(err)
	}
	derivedStateDirectorySync = previous
	wantSeen := []string{
		"generated",
		filepath.Join("generated", "channels"),
		filepath.Join("generated", "channels", "cf"),
		filepath.Join("generated", "channels", "cf", "latest"),
	}
	if !reflect.DeepEqual(seen, wantSeen) {
		t.Fatalf("directory sync order=%v want=%v", seen, wantSeen)
	}
	for _, directory := range wantSeen {
		info, err := os.Lstat(filepath.Join(stateRoot, directory))
		if err != nil || info.Mode() != os.ModeDir|0o700 {
			t.Fatalf("new directory %s mode=%v err=%v", directory, infoMode(info), err)
		}
	}
	body, err := os.ReadFile(filepath.Join(stateRoot, relative))
	if err != nil || string(body) != "durable state\n" {
		t.Fatalf("durable state body=%q err=%v", body, err)
	}
}

func TestDerivedStateWriterResyncsExistingAncestorsForCrashRecovery(t *testing.T) {
	stateRoot := t.TempDir()
	directory := filepath.Join(stateRoot, "generated", "channels", "cf")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := derivedStateDirectorySync
	seen := make([]string, 0, 3)
	derivedStateDirectorySync = func(parent *os.Root, relative string) error {
		seen = append(seen, relative)
		return previous(parent, relative)
	}
	t.Cleanup(func() { derivedStateDirectorySync = previous })
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "channels", "cf", "state.json"), []byte("existing tree\n")); err != nil {
		t.Fatal(err)
	}
	derivedStateDirectorySync = previous
	want := []string{"generated", filepath.Join("generated", "channels"), filepath.Join("generated", "channels", "cf")}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("existing ancestor sync order=%v want=%v", seen, want)
	}
}

func TestDerivedStateWriterConvergesConcurrentFirstWrites(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		stateRoot := t.TempDir()
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, name := range []string{"cf.json", "cos.json"} {
			name := name
			go func() {
				<-start
				results <- writeDerivedStateFile(stateRoot, filepath.Join("generated", "channels", "latest", name), []byte(name+"\n"))
			}()
		}
		close(start)
		for writer := 0; writer < 2; writer++ {
			if err := <-results; err != nil {
				t.Fatalf("iteration %d concurrent writer: %v", iteration, err)
			}
		}
		for _, name := range []string{"cf.json", "cos.json"} {
			body, err := os.ReadFile(filepath.Join(stateRoot, "generated", "channels", "latest", name))
			if err != nil || string(body) != name+"\n" {
				t.Fatalf("iteration %d state %s=%q err=%v", iteration, name, body, err)
			}
		}
		err := filepath.WalkDir(stateRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if strings.HasPrefix(entry.Name(), ".tmp-derived-directory-") {
				return fmt.Errorf("stage residue at %s", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("iteration %d: %v", iteration, err)
		}
	}
}

func TestDerivedStateWriterConcurrentlyRecoversOneStaleDirectoryStage(t *testing.T) {
	stateRoot := t.TempDir()
	parent := filepath.Join(stateRoot, "generated", "channels")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	residue := filepath.Join(parent, derivedStateDirectoryStagePrefix+strings.Repeat("a", 32))
	if err := os.Mkdir(residue, 0o700); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, name := range []string{"cf.json", "cos.json"} {
		name := name
		go func() {
			<-start
			results <- writeDerivedStateFile(stateRoot, filepath.Join("generated", "channels", name), []byte(name+"\n"))
		}()
	}
	close(start)
	for writer := 0; writer < 2; writer++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent stale-stage recovery writer %d: %v", writer, err)
		}
	}
	if _, err := os.Lstat(residue); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale directory stage remains after concurrent recovery: %v", err)
	}
	for _, name := range []string{"cf.json", "cos.json"} {
		body, err := os.ReadFile(filepath.Join(parent, name))
		if err != nil || string(body) != name+"\n" {
			t.Fatalf("concurrent recovery state %s=%q err=%v", name, body, err)
		}
	}
}

func TestDerivedStateWriterRecoversRootLevelDirectoryStageForRootFile(t *testing.T) {
	stateRoot := t.TempDir()
	residue := filepath.Join(stateRoot, derivedStateDirectoryStagePrefix+strings.Repeat("b", 32))
	if err := os.Mkdir(residue, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeDerivedStateFile(stateRoot, "root-state.json", []byte("root\n")); err != nil {
		t.Fatalf("root-file write did not recover root-level directory stage: %v", err)
	}
	if _, err := os.Lstat(residue); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root-level directory stage remains: %v", err)
	}
}

func TestDerivedStateWriterInvalidatesCleanCacheWhenParentInodeChanges(t *testing.T) {
	container := t.TempDir()
	stateRoot := filepath.Join(container, "state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "first.json"), []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(container, "old-generated")
	if err := os.Rename(filepath.Join(stateRoot, "generated"), displaced); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(stateRoot, "generated")
	if err := os.Mkdir(replacement, 0o700); err != nil {
		t.Fatal(err)
	}
	residue := filepath.Join(replacement, derivedStateDirectoryStagePrefix+strings.Repeat("e", 32))
	if err := os.Mkdir(residue, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "second.json"), []byte("second\n")); err != nil {
		t.Fatalf("write through replaced parent inode: %v", err)
	}
	if _, err := os.Lstat(residue); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement-parent residue survived stale clean cache: %v", err)
	}
}

func TestDerivedStateWriterDoesNotLaunderLateStageIntoCleanCache(t *testing.T) {
	stateRoot := t.TempDir()
	parent := filepath.Join(stateRoot, "generated")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	name := derivedStateDirectoryStagePrefix + strings.Repeat("7", 32)
	residue := filepath.Join(parent, name)
	previous := derivedStateBeforeInstallHook
	derivedStateBeforeInstallHook = func(string) error {
		return os.Mkdir(residue, 0o700)
	}
	t.Cleanup(func() { derivedStateBeforeInstallHook = previous })
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "first.json"), []byte("first\n")); err != nil {
		t.Fatalf("write with late directory stage: %v", err)
	}
	derivedStateBeforeInstallHook = previous
	if _, err := os.Lstat(residue); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("late directory stage was admitted to clean cache: %v", err)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "second.json"), []byte("second\n")); err != nil {
		t.Fatalf("replay after late directory stage: %v", err)
	}
}

func TestDerivedStateWriterDetectsBalancedLateDirectoryStageMutation(t *testing.T) {
	stateRoot := t.TempDir()
	parent := filepath.Join(stateRoot, "generated")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(parent, "sibling")
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	name := derivedStateDirectoryStagePrefix + strings.Repeat("5", 32)
	residue := filepath.Join(parent, name)
	previous := derivedStateBeforeInstallHook
	derivedStateBeforeInstallHook = func(string) error {
		if err := os.Remove(sibling); err != nil {
			return err
		}
		return os.Mkdir(residue, 0o700)
	}
	t.Cleanup(func() { derivedStateBeforeInstallHook = previous })
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("second\n")); err != nil {
		t.Fatalf("write across balanced late directory mutation: %v", err)
	}
	derivedStateBeforeInstallHook = previous
	if _, err := os.Lstat(residue); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("balanced late directory stage was admitted to clean cache: %v", err)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("third\n")); err != nil {
		t.Fatalf("second replay after balanced mutation: %v", err)
	}
}

func TestDerivedStateWriterRejectsStateRootReplacementBeforeFinalCacheAdmission(t *testing.T) {
	container := t.TempDir()
	stateRoot := filepath.Join(container, "state")
	displaced := filepath.Join(container, "admitted-state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := derivedStateDirectoryBeforeFinalCacheHook
	derivedStateDirectoryBeforeFinalCacheHook = func(string) error {
		if err := os.Rename(stateRoot, displaced); err != nil {
			return err
		}
		return os.Mkdir(stateRoot, 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeFinalCacheHook = previous })
	relative := filepath.Join("generated", "state.json")
	err := writeDerivedStateFile(stateRoot, relative, []byte("committed but detached\n"))
	derivedStateDirectoryBeforeFinalCacheHook = previous
	if err == nil || !strings.Contains(err.Error(), "derived state root coordinate changed") {
		t.Fatalf("final state-root replacement error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(stateRoot, relative)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("replacement state root received detached write: %v", statErr)
	}
	body, readErr := os.ReadFile(filepath.Join(displaced, relative))
	if readErr != nil || string(body) != "committed but detached\n" {
		t.Fatalf("admitted detached state evidence=%q err=%v", body, readErr)
	}
}

func TestDerivedStateWriterDoesNotLaunderBalancedMutationBeforeFinalCacheAdmission(t *testing.T) {
	stateRoot := t.TempDir()
	parent := filepath.Join(stateRoot, "generated")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(parent, "sibling")
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	residue := filepath.Join(parent, derivedStateDirectoryStagePrefix+strings.Repeat("6", 32))
	previous := derivedStateDirectoryBeforeFinalCacheHook
	derivedStateDirectoryBeforeFinalCacheHook = func(string) error {
		if err := os.Remove(sibling); err != nil {
			return err
		}
		return os.Mkdir(residue, 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeFinalCacheHook = previous })
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("state\n")); err != nil {
		t.Fatalf("write across final balanced mutation: %v", err)
	}
	derivedStateDirectoryBeforeFinalCacheHook = previous
	if _, err := os.Lstat(residue); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final balanced directory stage was admitted to clean cache: %v", err)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "second.json"), []byte("replay\n")); err != nil {
		t.Fatalf("replay after final balanced mutation: %v", err)
	}
}

func TestDerivedStateWriterFallsBackToUncachedRecoveryWhenMutationSealUnavailable(t *testing.T) {
	stateRoot := t.TempDir()
	parent := filepath.Join(stateRoot, "generated")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	previousSealer := derivedStateDirectoryMutationSealer
	derivedStateDirectoryMutationSealer = func(*os.File, uint64) (derivedStateDirectoryMutationEpoch, error) {
		return derivedStateDirectoryMutationEpoch{}, nil
	}
	t.Cleanup(func() { derivedStateDirectoryMutationSealer = previousSealer })
	residue := filepath.Join(parent, derivedStateDirectoryStagePrefix+strings.Repeat("8", 32))
	previousFinalHook := derivedStateDirectoryBeforeFinalCacheHook
	derivedStateDirectoryBeforeFinalCacheHook = func(string) error {
		return os.Mkdir(residue, 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeFinalCacheHook = previousFinalHook })
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("uncached\n")); err != nil {
		t.Fatalf("unavailable mutation seal rejected an otherwise writable repository: %v", err)
	}
	derivedStateDirectoryBeforeFinalCacheHook = previousFinalHook
	if _, err := os.Lstat(residue); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncached fallback laundered a late stage: %v", err)
	}
	parentKey := filepath.Join(stateRoot, "generated")
	derivedStateDirectoryStageState.Lock()
	_, cached := derivedStateDirectoryStageState.cleanParents[parentKey]
	derivedStateDirectoryStageState.Unlock()
	if cached {
		t.Fatal("unsupported mutation seal admitted a clean-cache entry")
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "second.json"), []byte("replay\n")); err != nil {
		t.Fatalf("uncached fallback replay: %v", err)
	}
}

func TestDerivedStateWriterInvalidatesExistingCleanCacheWhenMutationSealBecomesUnavailable(t *testing.T) {
	stateRoot := t.TempDir()
	parentRelative := "generated"
	parent := filepath.Join(stateRoot, parentRelative)
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join(parentRelative, "first.json"), []byte("cached\n")); err != nil {
		t.Fatal(err)
	}
	parentKey := filepath.Join(stateRoot, parentRelative)
	derivedStateDirectoryStageState.Lock()
	cached, cachePresent := derivedStateDirectoryStageState.cleanParents[parentKey]
	derivedStateDirectoryStageState.Unlock()
	if !cachePresent || cached.validUntil.IsZero() || !time.Now().Before(cached.validUntil) {
		t.Fatalf("first write did not establish a live clean-cache lease: %#v", cached)
	}

	previousScan := derivedStateDirectoryRecoveryScanHook
	scans := 0
	derivedStateDirectoryRecoveryScanHook = func(relative string) {
		if relative == parentRelative {
			scans++
		}
	}
	t.Cleanup(func() { derivedStateDirectoryRecoveryScanHook = previousScan })
	previousSealer := derivedStateDirectoryMutationSealer
	derivedStateDirectoryMutationSealer = func(*os.File, uint64) (derivedStateDirectoryMutationEpoch, error) {
		return derivedStateDirectoryMutationEpoch{}, nil
	}
	t.Cleanup(func() { derivedStateDirectoryMutationSealer = previousSealer })

	if err := writeDerivedStateFile(stateRoot, filepath.Join(parentRelative, "second.json"), []byte("uncached\n")); err != nil {
		t.Fatalf("write after mutation-seal downgrade: %v", err)
	}
	derivedStateDirectoryMutationSealer = previousSealer
	derivedStateDirectoryRecoveryScanHook = previousScan
	if scans == 0 {
		t.Fatal("mutation-seal downgrade reused the existing clean cache without a recovery scan")
	}
	derivedStateDirectoryStageState.Lock()
	_, cachePresent = derivedStateDirectoryStageState.cleanParents[parentKey]
	derivedStateDirectoryStageState.Unlock()
	if cachePresent {
		t.Fatal("mutation-seal downgrade retained a clean-cache entry")
	}
}

func TestDerivedStateWriterRejectsStateRootReplacementAfterLinkCountRecovery(t *testing.T) {
	container := t.TempDir()
	stateRoot := filepath.Join(container, "state")
	displaced := filepath.Join(container, "admitted-state")
	parent := filepath.Join(stateRoot, "generated")
	sibling := filepath.Join(parent, "sibling")
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	residue := filepath.Join(parent, derivedStateDirectoryStagePrefix+strings.Repeat("9", 32))
	previousFinalHook := derivedStateDirectoryBeforeFinalCacheHook
	derivedStateDirectoryBeforeFinalCacheHook = func(string) error {
		if err := os.Remove(sibling); err != nil {
			return err
		}
		return os.Mkdir(residue, 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryBeforeFinalCacheHook = previousFinalHook })

	previousSealer := derivedStateDirectoryMutationSealer
	postRecoverySeals := 0
	replaced := false
	derivedStateDirectoryMutationSealer = func(directory *os.File, sequence uint64) (derivedStateDirectoryMutationEpoch, error) {
		if !replaced {
			_, siblingErr := os.Lstat(sibling)
			_, residueErr := os.Lstat(residue)
			if errors.Is(siblingErr, os.ErrNotExist) && errors.Is(residueErr, os.ErrNotExist) {
				postRecoverySeals++
				if postRecoverySeals == 2 {
					if err := os.Rename(stateRoot, displaced); err != nil {
						return derivedStateDirectoryMutationEpoch{}, err
					}
					if err := os.Mkdir(stateRoot, 0o700); err != nil {
						return derivedStateDirectoryMutationEpoch{}, err
					}
					replaced = true
				}
			}
		}
		return previousSealer(directory, sequence)
	}
	t.Cleanup(func() { derivedStateDirectoryMutationSealer = previousSealer })

	relative := filepath.Join("generated", "state.json")
	err := writeDerivedStateFile(stateRoot, relative, []byte("committed before final fence\n"))
	derivedStateDirectoryBeforeFinalCacheHook = previousFinalHook
	derivedStateDirectoryMutationSealer = previousSealer
	if !replaced || postRecoverySeals < 2 {
		t.Fatalf("test did not reach link-count recovery reseal: replaced=%t seals=%d", replaced, postRecoverySeals)
	}
	if err == nil || !strings.Contains(err.Error(), "derived state root coordinate changed") {
		t.Fatalf("final root replacement error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(stateRoot, relative)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("replacement state root received detached write: %v", statErr)
	}
	body, readErr := os.ReadFile(filepath.Join(displaced, relative))
	if readErr != nil || string(body) != "committed before final fence\n" {
		t.Fatalf("displaced committed state=%q err=%v", body, readErr)
	}
}

func TestDerivedStateWriterMutationSealDoesNotBackdateDirectory(t *testing.T) {
	stateRoot := t.TempDir()
	parent := filepath.Join(stateRoot, "generated")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "state.json"), []byte("current epoch\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info.ModTime().Before(started.Add(-time.Second)) || info.ModTime().After(time.Now().Add(4*time.Second)) {
		t.Fatalf("derived state directory mutation seal left a stale or far-future mtime: %s", info.ModTime())
	}
}

func TestDerivedStateWriterRescansAfterCleanCacheLeaseExpires(t *testing.T) {
	stateRoot := t.TempDir()
	parentRelative := filepath.Join("generated", "channels")
	parent := filepath.Join(stateRoot, parentRelative)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	previousScan := derivedStateDirectoryRecoveryScanHook
	scans := 0
	derivedStateDirectoryRecoveryScanHook = func(relative string) {
		if relative == parentRelative {
			scans++
		}
	}
	t.Cleanup(func() { derivedStateDirectoryRecoveryScanHook = previousScan })
	if err := writeDerivedStateFile(stateRoot, filepath.Join(parentRelative, "first.json"), []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	parentKey := filepath.Join(stateRoot, parentRelative)
	derivedStateDirectoryStageState.Lock()
	cached, ok := derivedStateDirectoryStageState.cleanParents[parentKey]
	if ok {
		cached.validUntil = time.Now().Add(-time.Second)
		derivedStateDirectoryStageState.cleanParents[parentKey] = cached
	}
	derivedStateDirectoryStageState.Unlock()
	if !ok {
		t.Fatal("first write did not establish a clean-cache lease")
	}
	if err := writeDerivedStateFile(stateRoot, filepath.Join(parentRelative, "second.json"), []byte("second\n")); err != nil {
		t.Fatal(err)
	}
	derivedStateDirectoryRecoveryScanHook = previousScan
	if scans != 2 {
		t.Fatalf("recovery scans after forced lease expiry=%d want=2", scans)
	}
}

func TestDerivedStateWriterRepairsSetgidCrashResidueBeforeRecovery(t *testing.T) {
	stateRoot := t.TempDir()
	residue := filepath.Join(stateRoot, derivedStateDirectoryStagePrefix+strings.Repeat("f", 32))
	if err := os.Mkdir(residue, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(residue, os.ModeSetgid|0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(residue)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Skip("filesystem did not retain setgid on test directory")
	}
	if err := writeDerivedStateFile(stateRoot, "state.json", []byte("recovered\n")); err != nil {
		t.Fatalf("recover setgid crash residue: %v", err)
	}
	if _, err := os.Lstat(residue); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("setgid crash residue remains: %v", err)
	}
}

func TestDerivedStateWriterCachesCleanLargeDirectoryRecoveryScan(t *testing.T) {
	stateRoot := t.TempDir()
	parentRelative := filepath.Join("generated", "channels")
	parent := filepath.Join(stateRoot, parentRelative)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 5000; index++ {
		name := fmt.Sprintf("ordinary-%05d", index)
		if err := os.WriteFile(filepath.Join(parent, name), []byte("ordinary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previous := derivedStateDirectoryRecoveryScanHook
	scans := make(map[string]int)
	derivedStateDirectoryRecoveryScanHook = func(relative string) {
		scans[relative]++
	}
	t.Cleanup(func() { derivedStateDirectoryRecoveryScanHook = previous })
	for index := 0; index < 50; index++ {
		relative := filepath.Join(parentRelative, fmt.Sprintf("state-%02d.json", index))
		if err := writeDerivedStateFile(stateRoot, relative, []byte("{}\n")); err != nil {
			t.Fatalf("write %d under large sibling set: %v", index, err)
		}
	}
	derivedStateDirectoryRecoveryScanHook = previous
	if scans[parentRelative] != 1 {
		t.Fatalf("large directory recovery scans=%d want=1 all=%v", scans[parentRelative], scans)
	}
}

func TestDerivedStateWriterRepairsRestrictiveUmaskForMissingAncestors(t *testing.T) {
	if stateRoot := os.Getenv("SOW_DERIVED_DIRECTORY_UMASK_ROOT"); stateRoot != "" {
		if err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "channels", "state.json"), []byte("private ancestors\n")); err != nil {
			t.Fatal(err)
		}
		return
	}
	stateRoot := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestDerivedStateWriterRepairsRestrictiveUmaskForMissingAncestors$")
	command.Env = append(os.Environ(), "SOW_DERIVED_DIRECTORY_UMASK_ROOT="+stateRoot)
	previous := syscall.Umask(0o400)
	output, runErr := command.CombinedOutput()
	syscall.Umask(previous)
	if runErr != nil {
		t.Fatalf("subprocess write under restrictive inherited umask: %v\n%s", runErr, output)
	}
	for _, relativeDirectory := range []string{"generated", filepath.Join("generated", "channels")} {
		info, statErr := os.Lstat(filepath.Join(stateRoot, relativeDirectory))
		if statErr != nil || info.Mode() != os.ModeDir|0o700 {
			t.Fatalf("derived state directory %s mode=%v err=%v want=0700", relativeDirectory, infoMode(info), statErr)
		}
	}
}

func TestDerivedStateWriterRejectsAncestorReplacementDuringRecursiveCreate(t *testing.T) {
	stateRoot := t.TempDir()
	displaced := filepath.Join(t.TempDir(), "admitted-generated")
	previous := derivedStateDirectoryAfterSyncHook
	derivedStateDirectoryAfterSyncHook = func(created string) error {
		if created != filepath.Join("generated", "channels") {
			return nil
		}
		if err := os.Rename(filepath.Join(stateRoot, "generated"), displaced); err != nil {
			return err
		}
		return os.Mkdir(filepath.Join(stateRoot, "generated"), 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryAfterSyncHook = previous })
	err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "channels", "cf", "state.json"), []byte("must not publish\n"))
	derivedStateDirectoryAfterSyncHook = previous
	if err == nil || !strings.Contains(err.Error(), "directory coordinate changed") {
		t.Fatalf("ancestor replacement error=%v", err)
	}
	for _, path := range []string{
		filepath.Join(stateRoot, "generated", "channels", "cf", "state.json"),
		filepath.Join(displaced, "channels", "cf", "state.json"),
	} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("ancestor replacement received state at %s: %v", path, statErr)
		}
	}
}

func TestDerivedStateWriterRejectsStateRootReplacementDuringRecursiveCreate(t *testing.T) {
	parent := t.TempDir()
	stateRoot := filepath.Join(parent, "state")
	displaced := filepath.Join(parent, "admitted-state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := derivedStateDirectoryAfterSyncHook
	derivedStateDirectoryAfterSyncHook = func(created string) error {
		if created != "generated" {
			return nil
		}
		if err := os.Rename(stateRoot, displaced); err != nil {
			return err
		}
		return os.Mkdir(stateRoot, 0o700)
	}
	t.Cleanup(func() { derivedStateDirectoryAfterSyncHook = previous })
	err := writeDerivedStateFile(stateRoot, filepath.Join("generated", "deep", "state.json"), []byte("must not publish\n"))
	derivedStateDirectoryAfterSyncHook = previous
	if err == nil || !strings.Contains(err.Error(), "root coordinate changed") {
		t.Fatalf("state-root replacement error=%v", err)
	}
	for _, path := range []string{
		filepath.Join(stateRoot, "generated", "deep", "state.json"),
		filepath.Join(displaced, "generated", "deep", "state.json"),
	} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("state-root replacement received state at %s: %v", path, statErr)
		}
	}
}

func TestDerivedStateWriterRejectsInvalidRecursiveDirectoryComponents(t *testing.T) {
	for _, kind := range []string{"file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			stateRoot := t.TempDir()
			outside := t.TempDir()
			coordinate := filepath.Join(stateRoot, "generated")
			var err error
			switch kind {
			case "file":
				err = os.WriteFile(coordinate, []byte("not a directory\n"), 0o600)
			case "symlink":
				err = os.Symlink(outside, coordinate)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = writeDerivedStateFile(stateRoot, filepath.Join("generated", "deep", "state.json"), []byte("must not publish\n"))
			if err == nil || !strings.Contains(err.Error(), "not a real directory") {
				t.Fatalf("%s component error=%v", kind, err)
			}
			if _, statErr := os.Lstat(filepath.Join(outside, "deep", "state.json")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s component escaped state root: %v", kind, statErr)
			}
		})
	}
}

func infoMode(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode()
}

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
