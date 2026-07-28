package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDerivedStateResidueInventoryAndRecovery(t *testing.T) {
	stateRoot := t.TempDir()
	generated := filepath.Join(stateRoot, "generated", "channels", "cf")
	if err := os.MkdirAll(generated, 0o700); err != nil {
		t.Fatal(err)
	}
	records := []string{
		filepath.Join(stateRoot, "package-projection-complete-"+strings.Repeat("a", 64)+".json.tmp-"+strings.Repeat("1", 32)),
		filepath.Join(generated, "latest.json.tmp-"+strings.Repeat("2", 32)),
		filepath.Join(generated, "beta.json.tmp-install-"+strings.Repeat("3", 32)),
		filepath.Join(generated, "stable.json.tmp-"+strings.Repeat("4", 16)+".tmp-remove-"+strings.Repeat("5", 32)),
	}
	for _, path := range records {
		if err := os.WriteFile(path, []byte("interrupted derived state\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	audit, err := inspectDerivedStateResidues(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit.temporaries) != len(records) || len(audit.replacements) != 0 ||
		strings.Count(derivedStateResidueAuditOutput(audit), "DERIVED_STATE_TEMPORARY_RESIDUE") != len(records) {
		t.Fatalf("derived residue inventory=%+v findings=%s", audit, derivedStateResidueAuditOutput(audit))
	}
	stats, err := recoverDerivedStateResidues(stateRoot, audit)
	if err != nil {
		t.Fatalf("recover strict derived state residue: %v", err)
	}
	if stats.Transactions != 0 || stats.Temporaries != len(records) {
		t.Fatalf("recovery stats=%+v", stats)
	}
	for _, path := range records {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("derived state residue survived at %s: %v", path, err)
		}
	}
	clean, err := inspectDerivedStateResidues(stateRoot)
	if err != nil || clean.pending() {
		t.Fatalf("post-recovery inventory=%+v err=%v", clean, err)
	}
	if _, err := recoverDerivedStateResidues(t.TempDir(), audit); err == nil ||
		!strings.Contains(err.Error(), "another state root") {
		t.Fatalf("cross-root inventory capability was accepted: %v", err)
	}
	replayed, err := recoverDerivedStateResidues(stateRoot, clean)
	if err != nil || replayed != (derivedStateResidueRecoveryStats{}) {
		t.Fatalf("clean recovery replay=%+v err=%v", replayed, err)
	}
}

func TestDerivedStateDirectoryResidueInventoryRecoveryAndPreservation(t *testing.T) {
	t.Run("root and nested strict stages", func(t *testing.T) {
		stateRoot := t.TempDir()
		nested := filepath.Join(stateRoot, "generated", "routes", "cf")
		if err := os.MkdirAll(nested, 0o700); err != nil {
			t.Fatal(err)
		}
		stages := []string{
			filepath.Join(stateRoot, derivedStateDirectoryStagePrefix+strings.Repeat("1", 32)),
			filepath.Join(nested, derivedStateDirectoryStagePrefix+strings.Repeat("2", 32)+derivedStateDirectoryStageQuarantineSuffix),
		}
		for _, stage := range stages {
			if err := os.Mkdir(stage, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		audit, err := inspectDerivedStateResidues(stateRoot)
		if err != nil {
			t.Fatal(err)
		}
		if len(audit.directoryStages) != len(stages) || len(audit.directoryEvidence) != 0 ||
			strings.Count(derivedStateResidueAuditOutput(audit), "DERIVED_STATE_DIRECTORY_STAGE_PENDING") != len(stages) {
			t.Fatalf("directory stage audit=%+v findings=%s", audit, derivedStateResidueAuditOutput(audit))
		}
		if err := requireNoDerivedStateReplacementTransactionsReadOnly(stateRoot); err == nil {
			t.Fatal("directory stages did not block preserved-projection retirement")
		}
		stats, err := recoverDerivedStateResidues(stateRoot, audit)
		if err != nil {
			t.Fatalf("recover strict directory stages: %v", err)
		}
		if stats.DirectoryStages != len(stages) || stats.Transactions != 0 || stats.Temporaries != 0 {
			t.Fatalf("directory recovery stats=%+v", stats)
		}
		for _, stage := range stages {
			if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("directory stage survived at %s: %v", stage, err)
			}
		}
	})

	t.Run("preserved evidence blocks every automatic mutation", func(t *testing.T) {
		stateRoot := t.TempDir()
		generated := filepath.Join(stateRoot, "generated")
		if err := os.Mkdir(generated, 0o700); err != nil {
			t.Fatal(err)
		}
		stage := filepath.Join(stateRoot, derivedStateDirectoryStagePrefix+strings.Repeat("3", 32))
		preserved := filepath.Join(
			generated,
			derivedStateDirectoryStagePrefix+strings.Repeat("4", 32)+
				derivedStateDirectoryStagePreservedMarker+strings.Repeat("5", 32),
		)
		if err := os.Mkdir(stage, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(preserved, 0o700); err != nil {
			t.Fatal(err)
		}
		canary := filepath.Join(preserved, "foreign")
		if err := os.WriteFile(canary, []byte("operator evidence\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		audit, err := inspectDerivedStateResidues(stateRoot)
		if err != nil {
			t.Fatal(err)
		}
		if len(audit.directoryStages) != 1 || len(audit.directoryEvidence) != 1 ||
			!strings.Contains(derivedStateResidueAuditOutput(audit), "DERIVED_STATE_DIRECTORY_EVIDENCE") {
			t.Fatalf("preserved directory audit=%+v findings=%s", audit, derivedStateResidueAuditOutput(audit))
		}
		if _, err := recoverDerivedStateResidues(stateRoot, audit); err == nil ||
			!strings.Contains(err.Error(), "cannot be auto-recovered") {
			t.Fatalf("preserved directory evidence was auto-recovered: %v", err)
		}
		if _, err := os.Lstat(stage); err != nil {
			t.Fatalf("recovery mutated an unrelated strict stage before refusing evidence: %v", err)
		}
		if body, err := os.ReadFile(canary); err != nil || string(body) != "operator evidence\n" {
			t.Fatalf("preserved directory evidence changed body=%q err=%v", body, err)
		}
	})

	t.Run("predictable legacy temporary is visible but never auto-deleted", func(t *testing.T) {
		stateRoot := t.TempDir()
		name := "state.json.tmp-" + strings.Repeat("6", 16)
		path := filepath.Join(stateRoot, name)
		if err := os.WriteFile(path, []byte("legacy or foreign\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		audit, err := inspectDerivedStateResidues(stateRoot)
		if err != nil {
			t.Fatal(err)
		}
		if len(audit.temporaries) != 0 || len(audit.legacyEvidence) != 1 ||
			!strings.Contains(derivedStateResidueAuditOutput(audit), "DERIVED_STATE_LEGACY_TEMPORARY_EVIDENCE") {
			t.Fatalf("legacy temporary audit=%+v findings=%s", audit, derivedStateResidueAuditOutput(audit))
		}
		if _, err := recoverDerivedStateResidues(stateRoot, audit); err == nil ||
			!strings.Contains(err.Error(), "cannot be auto-recovered") {
			t.Fatalf("predictable legacy temporary was auto-recovered: %v", err)
		}
		if removed, err := removeManagedDerivedStateTemporary(stateRoot, ".", name); err == nil || removed {
			t.Fatalf("direct removal accepted predictable legacy temporary removed=%t err=%v", removed, err)
		}
		if body, err := os.ReadFile(path); err != nil || string(body) != "legacy or foreign\n" {
			t.Fatalf("legacy temporary evidence changed body=%q err=%v", body, err)
		}
	})

	t.Run("nonempty strict directory stage fails without deleting evidence", func(t *testing.T) {
		stateRoot := t.TempDir()
		stage := filepath.Join(stateRoot, derivedStateDirectoryStagePrefix+strings.Repeat("7", 32))
		if err := os.Mkdir(stage, 0o700); err != nil {
			t.Fatal(err)
		}
		canary := filepath.Join(stage, "foreign")
		if err := os.WriteFile(canary, []byte("must survive\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		audit, err := inspectDerivedStateResidues(stateRoot)
		if err != nil || len(audit.directoryStages) != 1 {
			t.Fatalf("nonempty directory-stage audit=%+v err=%v", audit, err)
		}
		if _, err := recoverDerivedStateResidues(stateRoot, audit); err == nil ||
			!strings.Contains(err.Error(), "not empty") {
			t.Fatalf("nonempty directory stage was accepted: %v", err)
		}
		if body, err := os.ReadFile(canary); err != nil || string(body) != "must survive\n" {
			t.Fatalf("nonempty directory evidence changed body=%q err=%v", body, err)
		}
	})
}

func TestVerifyAndFSCKExposeAndRecoverDerivedStateResidue(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	stateRoot := filepath.Join(root, ".sow")
	generated := filepath.Join(stateRoot, "generated", "snapshot-routes", "cf")
	if err := os.MkdirAll(generated, 0o700); err != nil {
		t.Fatal(err)
	}
	rootResidue := filepath.Join(stateRoot, "package-projection-complete-"+strings.Repeat("b", 64)+".json.tmp-"+strings.Repeat("6", 32))
	generatedResidue := filepath.Join(generated, "snapshot.json.tmp-install-"+strings.Repeat("7", 32))
	directoryStage := filepath.Join(stateRoot, derivedStateDirectoryStagePrefix+strings.Repeat("8", 32))
	for _, path := range []string{rootResidue, generatedResidue} {
		if err := os.WriteFile(path, []byte("cli-visible residue\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(directoryStage, 0o700); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runAssetMaterializeHardeningCLI(t,
		"verify", "--layer", "L1", "--config", configPath, "--workers", "1",
	)
	if code != ExitVerification || strings.Count(stdout, "DERIVED_STATE_TEMPORARY_RESIDUE") != 2 ||
		strings.Count(stdout, "DERIVED_STATE_DIRECTORY_STAGE_PENDING") != 1 {
		t.Fatalf("verify derived residue code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"fsck", "--config", configPath, "--workers", "1", "--limit", "0",
	)
	if code != ExitVerification || strings.Count(stdout, "code=DERIVED_STATE_TEMPORARY_RESIDUE") != 2 ||
		strings.Count(stdout, "code=DERIVED_STATE_DIRECTORY_STAGE_PENDING") != 1 {
		t.Fatalf("ordinary fsck derived residue code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, path := range []string{rootResidue, generatedResidue, directoryStage} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("ordinary audit changed %s: %v", path, err)
		}
	}
	code, stdout, stderr = runAssetMaterializeHardeningCLI(t,
		"fsck", "--recover", "--config", configPath, "--workers", "1", "--limit", "0",
	)
	if code != ExitOK || !strings.Contains(stdout, "fsck-recover-derived-state directory_stages=1 transactions=0 temporaries=2 clean=true") {
		t.Fatalf("recovering fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, path := range []string{rootResidue, generatedResidue, directoryStage} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovering fsck left %s: %v", path, err)
		}
	}
}

func TestDerivedStateResidueRecoveryConvergesDurableTransactionBeforeTemporary(t *testing.T) {
	stateRoot := t.TempDir()
	relative := filepath.Join("generated", "routes", "state.json")
	previous := derivedStateReplacementPhaseHook
	derivedStateReplacementPhaseHook = func(phase string) error {
		if phase == "prepared" {
			return errDerivedStateReplacementTestCrash
		}
		return nil
	}
	t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
	result, writeErr := writeDerivedStateFileOutcome(stateRoot, relative, []byte("candidate\n"))
	derivedStateReplacementPhaseHook = previous
	if result.Outcome != derivedStateReplacementRecoveryRequired ||
		!errors.Is(writeErr, errDerivedStateReplacementRecoveryRequired) {
		t.Fatalf("crash result=%+v err=%v", result, writeErr)
	}
	audit, err := inspectDerivedStateResidues(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit.replacements) != 1 || len(audit.temporaries) != 1 {
		t.Fatalf("transaction audit=%+v", audit)
	}
	if err := requireNoDerivedStateReplacementTransactionsReadOnly(stateRoot); err == nil {
		t.Fatal("nested replacement did not block preserved-projection retirement")
	}
	stats, err := recoverDerivedStateResidues(stateRoot, audit)
	if err != nil {
		t.Fatalf("recover durable transaction before source: %v", err)
	}
	if stats.Transactions != 1 || stats.Temporaries != 0 {
		t.Fatalf("transaction recovery stats=%+v", stats)
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, relative)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prepared transaction did not restore absent destination: %v", err)
	}
}

func TestDerivedStateResidueRecoveryRejectsAliasAndFinalUnlinkRace(t *testing.T) {
	stateRoot := t.TempDir()
	generated := filepath.Join(stateRoot, "generated")
	if err := os.Mkdir(generated, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "state.json.tmp-" + strings.Repeat("8", 32)
	path := filepath.Join(generated, name)
	alias := filepath.Join(generated, "foreign.alias")
	if err := os.WriteFile(path, []byte("retained evidence\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectDerivedStateResidues(stateRoot); err == nil || !strings.Contains(err.Error(), "link count") {
		t.Fatalf("hardlinked residue inventory was accepted: %v", err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	audit, err := inspectDerivedStateResidues(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	previous := projectionStateBeforeUnlinkHook
	projectionStateBeforeUnlinkHook = func(quarantine string) error {
		return os.Link(filepath.Join(generated, quarantine), alias)
	}
	t.Cleanup(func() { projectionStateBeforeUnlinkHook = previous })
	if _, err := recoverDerivedStateResidues(stateRoot, audit); err == nil || !strings.Contains(err.Error(), "link count") {
		t.Fatalf("final-unlink alias was accepted: %v", err)
	}
	projectionStateBeforeUnlinkHook = previous
	for _, current := range []string{path, alias} {
		if body, err := os.ReadFile(current); err != nil || string(body) != "retained evidence\n" {
			t.Fatalf("unlink race changed %s body=%q err=%v", current, body, err)
		}
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	audit, err = inspectDerivedStateResidues(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recoverDerivedStateResidues(stateRoot, audit); err != nil {
		t.Fatalf("retry after alias removal: %v", err)
	}
}

func TestDerivedStateResidueRecoveryRejectsDirectoryAndRootReplacement(t *testing.T) {
	for _, replaceRoot := range []bool{false, true} {
		name := "directory"
		if replaceRoot {
			name = "root"
		}
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			stateRoot := filepath.Join(parent, ".sow")
			generated := filepath.Join(stateRoot, "generated")
			if err := os.MkdirAll(generated, 0o700); err != nil {
				t.Fatal(err)
			}
			residueName := "state.json.tmp-" + strings.Repeat("c", 32)
			if err := os.WriteFile(filepath.Join(generated, residueName), []byte("original evidence\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			audit, err := inspectDerivedStateResidues(stateRoot)
			if err != nil {
				t.Fatal(err)
			}
			displaced := generated + ".displaced"
			replacement := generated
			if replaceRoot {
				displaced = stateRoot + ".displaced"
				replacement = stateRoot
			}
			previous := projectionStateBeforeUnlinkHook
			projectionStateBeforeUnlinkHook = func(string) error {
				if err := os.Rename(func() string {
					if replaceRoot {
						return stateRoot
					}
					return generated
				}(), displaced); err != nil {
					return err
				}
				if err := os.MkdirAll(func() string {
					if replaceRoot {
						return filepath.Join(replacement, "generated")
					}
					return replacement
				}(), 0o700); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(replacement, "canary"), []byte("replacement\n"), 0o600)
			}
			t.Cleanup(func() { projectionStateBeforeUnlinkHook = previous })
			if _, err := recoverDerivedStateResidues(stateRoot, audit); err == nil ||
				(!strings.Contains(err.Error(), "coordinate changed") &&
					!strings.Contains(err.Error(), "root changed")) {
				t.Fatalf("%s replacement was accepted: %v", name, err)
			}
			projectionStateBeforeUnlinkHook = previous
			if body, err := os.ReadFile(filepath.Join(replacement, "canary")); err != nil || string(body) != "replacement\n" {
				t.Fatalf("replacement canary changed body=%q err=%v", body, err)
			}
			evidenceRoot := displaced
			if replaceRoot {
				evidenceRoot = filepath.Join(displaced, "generated")
			}
			if body, err := os.ReadFile(filepath.Join(evidenceRoot, residueName)); err != nil ||
				string(body) != "original evidence\n" {
				t.Fatalf("displaced evidence changed body=%q err=%v", body, err)
			}
		})
	}
}

func TestDerivedStateResidueInventoryScopeAndMalformedBoundaries(t *testing.T) {
	t.Run("excluded payload and canonical trees", func(t *testing.T) {
		stateRoot := t.TempDir()
		for _, directory := range []string{"state", "cache", "tmp", "materialized", "origin", "sync", "stage"} {
			path := filepath.Join(stateRoot, directory)
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "legitimate.tmp-"+strings.Repeat("9", 32)), []byte("not managed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		audit, err := inspectDerivedStateResidues(stateRoot)
		if err != nil || audit.pending() {
			t.Fatalf("excluded subtree became deletion scope audit=%+v err=%v", audit, err)
		}
	})
	t.Run("malformed generated coordinate", func(t *testing.T) {
		stateRoot := t.TempDir()
		generated := filepath.Join(stateRoot, "generated")
		if err := os.Mkdir(generated, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(generated, "state.json.tmp-not-hex")
		if err := os.WriteFile(path, []byte("ambiguous\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectDerivedStateResidues(stateRoot); err == nil || !strings.Contains(err.Error(), "malformed reserved") {
			t.Fatalf("malformed generated residue was accepted: %v", err)
		}
		if body, err := os.ReadFile(path); err != nil || string(body) != "ambiguous\n" {
			t.Fatalf("malformed evidence changed body=%q err=%v", body, err)
		}
	})
	t.Run("malformed root directory stage", func(t *testing.T) {
		stateRoot := t.TempDir()
		path := filepath.Join(stateRoot, derivedStateDirectoryStagePrefix+"not-hex")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectDerivedStateResidues(stateRoot); err == nil ||
			!strings.Contains(err.Error(), "malformed reserved derived state directory") {
			t.Fatalf("malformed root directory stage was accepted: %v", err)
		}
		if info, err := os.Lstat(path); err != nil || !info.IsDir() {
			t.Fatalf("malformed root evidence changed: info=%v err=%v", info, err)
		}
	})
	t.Run("temporary marker in a directory component", func(t *testing.T) {
		stateRoot := t.TempDir()
		directory := filepath.Join(stateRoot, "generated", "repo.tmp-not-a-file-residue")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		audit, err := inspectDerivedStateResidues(stateRoot)
		if err != nil || audit.pending() {
			t.Fatalf("directory component was confused with a file residue audit=%+v err=%v", audit, err)
		}
	})
	t.Run("generated symlink", func(t *testing.T) {
		stateRoot := t.TempDir()
		generated := filepath.Join(stateRoot, "generated")
		outside := t.TempDir()
		if err := os.Mkdir(generated, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(generated, "escape")); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectDerivedStateResidues(stateRoot); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("generated symlink was accepted: %v", err)
		}
	})
	t.Run("bounded temporary records", func(t *testing.T) {
		stateRoot := t.TempDir()
		generated := filepath.Join(stateRoot, "generated")
		if err := os.Mkdir(generated, 0o700); err != nil {
			t.Fatal(err)
		}
		for index := 0; index <= derivedStateResidueMaximumTemporaries; index++ {
			name := "state-" + formatProjectionAuditHex(index) + ".json.tmp-" + strings.Repeat("f", 32)
			if err := os.WriteFile(filepath.Join(generated, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := inspectDerivedStateResidues(stateRoot); err == nil ||
			!strings.Contains(err.Error(), "count exceeds 4096") {
			t.Fatalf("unbounded temporary inventory was accepted: %v", err)
		}
	})
	t.Run("bounded directory stage records", func(t *testing.T) {
		stateRoot := t.TempDir()
		for index := 0; index <= derivedStateResidueMaximumDirectoryStages; index++ {
			name := derivedStateDirectoryStagePrefix + formatProjectionAuditHex(index) + strings.Repeat("0", 28)
			if err := os.Mkdir(filepath.Join(stateRoot, name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := inspectDerivedStateResidues(stateRoot); err == nil ||
			!strings.Contains(err.Error(), "directory residue count exceeds 4096") {
			t.Fatalf("unbounded directory-stage inventory was accepted: %v", err)
		}
	})
}

func TestDerivedStateRemovalQuarantineCrashRemainsRecoverable(t *testing.T) {
	if stateRoot := os.Getenv("SOW_TEST_DERIVED_RESIDUE_CRASH_ROOT"); stateRoot != "" {
		audit, err := inspectDerivedStateResidues(stateRoot)
		if err != nil {
			os.Exit(89)
		}
		projectionStateBeforeUnlinkHook = func(string) error {
			os.Exit(91)
			return nil
		}
		_, _ = recoverDerivedStateResidues(stateRoot, audit)
		os.Exit(92)
	}
	stateRoot := t.TempDir()
	generated := filepath.Join(stateRoot, "generated")
	if err := os.Mkdir(generated, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "state.json.tmp-" + strings.Repeat("1", 32) + ".tmp-remove-" + strings.Repeat("2", 32)
	if err := os.WriteFile(filepath.Join(generated, name), []byte("crash durable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestDerivedStateRemovalQuarantineCrashRemainsRecoverable$")
	command.Env = append(os.Environ(), "SOW_TEST_DERIVED_RESIDUE_CRASH_ROOT="+stateRoot)
	err := command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 91 {
		t.Fatalf("crash helper error=%v", err)
	}
	audit, err := inspectDerivedStateResidues(stateRoot)
	if err != nil || len(audit.temporaries) != 1 {
		t.Fatalf("post-crash removal inventory=%+v err=%v", audit, err)
	}
	recoveredName := audit.temporaries[0].Name
	if strings.Count(recoveredName, ".tmp-remove-") != 1 {
		t.Fatalf("removal crash produced a non-closed grammar %q", recoveredName)
	}
	if _, err := recoverDerivedStateResidues(stateRoot, audit); err != nil {
		t.Fatalf("recover crash-stable removal quarantine: %v", err)
	}
}

func TestDerivedStateWriterReservesTemporaryNamesAndBlocksUnjournaledResidue(t *testing.T) {
	stateRoot := t.TempDir()
	reserved := "state.json.tmp-" + strings.Repeat("a", 32)
	if result, err := writeDerivedStateFileOutcome(stateRoot, reserved, []byte("must not publish\n")); err == nil ||
		result.Outcome != derivedStateReplacementRecoveryRequired ||
		!strings.Contains(err.Error(), "reserved temporary-name") {
		t.Fatalf("temporary-shaped destination result=%+v err=%v", result, err)
	}
	residue := filepath.Join(stateRoot, "state.json.tmp-"+strings.Repeat("b", 32))
	if err := os.WriteFile(residue, []byte("orphan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n")); err == nil ||
		result.Outcome != derivedStateReplacementRecoveryRequired ||
		!strings.Contains(err.Error(), "sow fsck --recover") {
		t.Fatalf("writer ignored unjournaled residue result=%+v err=%v", result, err)
	}
	audit, err := inspectDerivedStateResidues(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recoverDerivedStateResidues(stateRoot, audit); err != nil {
		t.Fatal(err)
	}
	result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
	if err != nil || result.Outcome != derivedStateReplacementCommitted {
		t.Fatalf("writer after explicit cleanup result=%+v err=%v", result, err)
	}
}

func derivedStateResidueAuditOutput(audit derivedStateResidueAudit) string {
	var output strings.Builder
	audit.writeFSCKDrift(&output)
	return output.String()
}
