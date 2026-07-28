package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDerivedStateSecurityAdmissionRejectsWritableDirectoryAndHardlink(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "control")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitDerivedStateDirectory(info, "control directory"); err != nil {
		t.Fatalf("admit private directory: %v", err)
	}
	if err := os.Chmod(directory, 0o720); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitDerivedStateDirectory(info, "control directory"); err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("expected writable-directory rejection, got %v", err)
	}

	control := filepath.Join(root, "control.json")
	alias := filepath.Join(root, "control.alias")
	if err := os.WriteFile(control, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(control)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitDerivedStateControlFile(info, "control file"); err != nil {
		t.Fatalf("admit singly-linked control: %v", err)
	}
	if err := os.Link(control, alias); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(control)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitDerivedStateControlFile(info, "control file"); err == nil || !strings.Contains(err.Error(), "link count 2") {
		t.Fatalf("expected hardlink rejection, got %v", err)
	}
}

func TestDerivedStateWriterRejectsUnsafeDirectoryBeforeFileMutation(t *testing.T) {
	t.Run("writable immediate parent", func(t *testing.T) {
		parent := t.TempDir()
		stateRoot := filepath.Join(parent, ".sow")
		if err := os.Mkdir(stateRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
		result, err := writeDerivedStateFileOutcome(stateRoot, filepath.Join("generated", "state.json"), []byte("{}\n"))
		if err == nil || !strings.Contains(err.Error(), "immediate parent") || !strings.Contains(err.Error(), "group/other writable") {
			t.Fatalf("writable immediate parent was accepted: result=%+v err=%v", result, err)
		}
		if _, err := os.Lstat(filepath.Join(stateRoot, "generated")); !os.IsNotExist(err) {
			t.Fatalf("unsafe-parent rejection mutated derived state: %v", err)
		}
	})

	t.Run("writable intermediate", func(t *testing.T) {
		stateRoot := filepath.Join(t.TempDir(), ".sow")
		intermediate := filepath.Join(stateRoot, "generated")
		if err := os.MkdirAll(intermediate, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(intermediate, 0o720); err != nil {
			t.Fatal(err)
		}
		result, err := writeDerivedStateFileOutcome(stateRoot, filepath.Join("generated", "state.json"), []byte("{}\n"))
		if err == nil || !strings.Contains(err.Error(), "group/other writable") {
			t.Fatalf("writable intermediate was accepted: result=%+v err=%v", result, err)
		}
		if _, err := os.Lstat(filepath.Join(intermediate, "state.json")); !os.IsNotExist(err) {
			t.Fatalf("unsafe-intermediate rejection installed a control file: %v", err)
		}
	})
}

func TestDerivedStateWriterRejectsAliasedControlAndPreservesEvidence(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	directory := filepath.Join(stateRoot, "generated")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "state.json")
	alias := filepath.Join(directory, "state.alias")
	prior := []byte("prior\n")
	if err := os.WriteFile(destination, prior, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(destination, alias); err != nil {
		t.Fatal(err)
	}
	result, err := writeDerivedStateFileOutcome(stateRoot, filepath.Join("generated", "state.json"), []byte("new\n"))
	if err == nil || !strings.Contains(err.Error(), "link count 2") {
		t.Fatalf("aliased destination was accepted: result=%+v err=%v", result, err)
	}
	for _, path := range []string{destination, alias} {
		body, readErr := os.ReadFile(path)
		if readErr != nil || string(body) != string(prior) {
			t.Fatalf("aliased evidence changed at %s: body=%q err=%v", path, body, readErr)
		}
	}
}

func TestDerivedStateWriterRejectsCandidateAliasAtInstallBoundary(t *testing.T) {
	stateRoot := t.TempDir()
	alias := filepath.Join(t.TempDir(), "candidate.alias")
	var candidate string
	previous := derivedStateBeforeInstallHook
	derivedStateBeforeInstallHook = func(relative string) error {
		candidate = filepath.Join(stateRoot, relative)
		return os.Link(candidate, alias)
	}
	t.Cleanup(func() { derivedStateBeforeInstallHook = previous })

	result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
	derivedStateBeforeInstallHook = previous
	if err == nil || !strings.Contains(err.Error(), "link count 2") {
		t.Fatalf("candidate alias was accepted: result=%+v err=%v", result, err)
	}
	if result.Outcome != derivedStateReplacementNotCommitted {
		t.Fatalf("pre-transaction alias outcome=%v want not-committed", result.Outcome)
	}
	if _, statErr := os.Lstat(filepath.Join(stateRoot, "state.json")); !os.IsNotExist(statErr) {
		t.Fatalf("aliased candidate was published: %v", statErr)
	}
	candidateInfo, candidateErr := os.Lstat(candidate)
	aliasInfo, aliasErr := os.Lstat(alias)
	if candidateErr != nil || aliasErr != nil || !os.SameFile(candidateInfo, aliasInfo) {
		t.Fatalf("candidate alias evidence was not preserved: candidate=%v alias=%v errors=%v/%v", candidateInfo, aliasInfo, candidateErr, aliasErr)
	}
}

func TestDerivedStateWriterRejectsPreparedCarrierAlias(t *testing.T) {
	stateRoot := t.TempDir()
	alias := filepath.Join(t.TempDir(), "prepared-carrier.alias")
	previous := derivedStateReplacementPhaseHook
	derivedStateReplacementPhaseHook = func(phase string) error {
		if phase != "prepared-carrier" {
			return nil
		}
		entries, err := os.ReadDir(stateRoot)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), derivedStateReplacementIntentPrefix) &&
				strings.HasSuffix(entry.Name(), ".json.new") {
				return os.Link(filepath.Join(stateRoot, entry.Name()), alias)
			}
		}
		return os.ErrNotExist
	}
	t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })

	result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
	derivedStateReplacementPhaseHook = previous
	if err == nil || !strings.Contains(err.Error(), "link count 2") {
		t.Fatalf("prepared carrier alias was accepted: result=%+v err=%v", result, err)
	}
	if result.Outcome != derivedStateReplacementRecoveryRequired {
		t.Fatalf("published aliased carrier outcome=%v want recovery-required", result.Outcome)
	}
	if _, statErr := os.Lstat(filepath.Join(stateRoot, "state.json")); !os.IsNotExist(statErr) {
		t.Fatalf("aliased prepared carrier allowed destination publication: %v", statErr)
	}
	carriers, globErr := filepath.Glob(filepath.Join(stateRoot, derivedStateReplacementIntentPrefix+"*.json"))
	if globErr != nil || len(carriers) != 1 {
		t.Fatalf("prepared carrier evidence=%v err=%v", carriers, globErr)
	}
	carrierInfo, carrierErr := os.Lstat(carriers[0])
	aliasInfo, aliasErr := os.Lstat(alias)
	if carrierErr != nil || aliasErr != nil || !os.SameFile(carrierInfo, aliasInfo) {
		t.Fatalf("prepared carrier alias evidence was not preserved: carrier=%v alias=%v errors=%v/%v", carrierInfo, aliasInfo, carrierErr, aliasErr)
	}
}

func TestDerivedStateWriterRejectsDirectoryModeDriftAndRecovers(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	directory := filepath.Join(stateRoot, "generated")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := derivedStateDirectoryBeforeFinalCacheHook
	derivedStateDirectoryBeforeFinalCacheHook = func(relative string) error {
		if relative != "generated" {
			return nil
		}
		return os.Chmod(directory, 0o720)
	}
	t.Cleanup(func() {
		derivedStateDirectoryBeforeFinalCacheHook = previous
		_ = os.Chmod(directory, 0o700)
	})

	result, err := writeDerivedStateFileOutcome(stateRoot, filepath.Join("generated", "state.json"), []byte("candidate\n"))
	derivedStateDirectoryBeforeFinalCacheHook = previous
	if err == nil || !strings.Contains(err.Error(), "directory coordinate changed") ||
		result.Outcome != derivedStateReplacementRecoveryRequired {
		t.Fatalf("directory mode drift was accepted: result=%+v err=%v", result, err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	replayed, replayErr := writeDerivedStateFileOutcomeWithRecovery(
		stateRoot,
		filepath.Join("generated", "state.json"),
		[]byte("candidate\n"),
		true,
	)
	if replayErr != nil || replayed.Outcome != derivedStateReplacementCommitted {
		t.Fatalf("safe replay after directory-mode restoration did not converge: result=%+v err=%v", replayed, replayErr)
	}
}
