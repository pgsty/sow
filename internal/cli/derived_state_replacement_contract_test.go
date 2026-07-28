package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/config"
)

func TestDerivedStateReplacementZeroValueFailsClosed(t *testing.T) {
	var result derivedStateReplacementResult
	err := consumeDerivedStateReplacement(result, nil)
	if !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
		t.Fatalf("zero-value outcome did not fail closed: %v", err)
	}
}

func TestPublishedDerivedStateSourceRequiresExplicitRecovery(t *testing.T) {
	cfg := &config.Config{Root: t.TempDir()}
	if err := os.Mkdir(cfg.StatePath(), 0o700); err != nil {
		t.Fatal(err)
	}

	previous := derivedStateReplacementPhaseHook
	derivedStateReplacementPhaseHook = func(phase string) error {
		if phase == "prepared" {
			return errDerivedStateReplacementTestCrash
		}
		return nil
	}
	t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
	if _, _, err := writeSnapshotRouteSource(cfg, "cf", "jammy-20260728", 1, false); !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
		t.Fatalf("interrupted generated source did not require recovery: %v", err)
	}
	derivedStateReplacementPhaseHook = previous

	if _, _, err := writeSnapshotRouteSource(cfg, "cf", "jammy-20260728", 2, false); err == nil ||
		!strings.Contains(err.Error(), "requires --recover") ||
		!errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
		t.Fatalf("ordinary publish replay was not blocked: %v", err)
	}

	source, body, err := writeSnapshotRouteSource(cfg, "cf", "jammy-20260728", 2, true)
	if err != nil {
		t.Fatalf("explicit generated-source recovery: %v", err)
	}
	if source != ".sow/generated/snapshot-routes/cf/jammy-20260728.json" {
		t.Fatalf("generated source path=%q", source)
	}
	persisted, err := os.ReadFile(filepath.Join(cfg.Root, filepath.FromSlash(source)))
	if err != nil || !bytes.Equal(persisted, body) {
		t.Fatalf("generated source body=%q want=%q err=%v", persisted, body, err)
	}
	assertNoDerivedStateReplacementResidue(t, filepath.Dir(filepath.Join(cfg.Root, filepath.FromSlash(source))))
}

func TestDerivedStateReplacementPrecommitFaultRestoresExactPrior(t *testing.T) {
	stateRoot := t.TempDir()
	destination := filepath.Join(stateRoot, "state.json")
	priorBody := []byte("exact prior\n")
	if err := os.WriteFile(destination, priorBody, 0o640); err != nil {
		t.Fatal(err)
	}
	prior, err := os.Lstat(destination)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected post-mutation fault")
	previous := derivedStateReplacementPhaseHook
	derivedStateReplacementPhaseHook = func(phase string) error {
		if phase == "destination-mutated" {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
	result, writeErr := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
	derivedStateReplacementPhaseHook = previous
	if result.Outcome != derivedStateReplacementNotCommitted || !errors.Is(writeErr, injected) {
		t.Fatalf("replacement result=%+v err=%v", result, writeErr)
	}
	current, err := os.Lstat(destination)
	if err != nil || !os.SameFile(prior, current) || current.Mode() != prior.Mode() {
		t.Fatalf("prior inode was not restored exactly current=%+v err=%v", current, err)
	}
	body, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(body, priorBody) {
		t.Fatalf("prior body=%q err=%v", body, err)
	}
	assertNoDerivedStateReplacementResidue(t, stateRoot)
}

func TestDerivedStateReplacementCommittedCleanupFaultReplaysForward(t *testing.T) {
	stateRoot := t.TempDir()
	destination := filepath.Join(stateRoot, "state.json")
	if err := os.WriteFile(destination, []byte("prior\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected committed cleanup fault")
	previous := derivedStateReplacementPhaseHook
	derivedStateReplacementPhaseHook = func(phase string) error {
		if phase == "committed-prior-cleanup-quarantine" {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
	result, writeErr := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
	derivedStateReplacementPhaseHook = previous
	if result.Outcome != derivedStateReplacementCommitted || !errors.Is(writeErr, injected) {
		t.Fatalf("replacement result=%+v err=%v", result, writeErr)
	}
	body, err := os.ReadFile(destination)
	if err != nil || string(body) != "candidate\n" {
		t.Fatalf("committed body=%q err=%v", body, err)
	}
	if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true); err != nil {
		t.Fatalf("forward recovery: %v", err)
	}
	body, err = os.ReadFile(destination)
	if err != nil || string(body) != "candidate\n" {
		t.Fatalf("replayed committed body=%q err=%v", body, err)
	}
	assertNoDerivedStateReplacementResidue(t, stateRoot)
}

func TestDerivedStateReplacementCrashReplayMatrix(t *testing.T) {
	if phase := os.Getenv("SOW_DERIVED_STATE_CRASH_PHASE"); phase != "" {
		stateRoot := os.Getenv("SOW_DERIVED_STATE_CRASH_ROOT")
		derivedStateReplacementPhaseHook = func(current string) error {
			if current == phase {
				os.Exit(91)
			}
			return nil
		}
		_, _ = writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
		os.Exit(92)
	}
	cases := []struct {
		phase      string
		committed  bool
		priorOnly  bool
		absentOnly bool
	}{
		{phase: "prepared-carrier"},
		{phase: "prepared"},
		{phase: "candidate-isolated"},
		{phase: "destination-mutated"},
		{phase: "committed-carrier"},
		{phase: "committed", committed: true},
		{phase: "committed-observed", committed: true},
		{phase: "committed-prior-cleanup-quarantine", committed: true, priorOnly: true},
		{phase: "committed-prior-cleanup-remove", committed: true, priorOnly: true},
		{phase: "committed-new-absence", committed: true, absentOnly: true},
		{phase: "replacement-intent-cleanup-quarantine", committed: true},
		{phase: "replacement-intent-cleanup-remove", committed: true},
	}
	for _, priorPresent := range []bool{false, true} {
		mode := "absent"
		if priorPresent {
			mode = "prior"
		}
		for _, tc := range cases {
			if tc.priorOnly && !priorPresent || tc.absentOnly && priorPresent {
				continue
			}
			t.Run(mode+"/"+tc.phase, func(t *testing.T) {
				stateRoot := t.TempDir()
				destination := filepath.Join(stateRoot, "state.json")
				var prior os.FileInfo
				if priorPresent {
					if err := os.WriteFile(destination, []byte("prior\n"), 0o640); err != nil {
						t.Fatal(err)
					}
					var err error
					prior, err = os.Lstat(destination)
					if err != nil {
						t.Fatal(err)
					}
				}
				cmd := exec.Command(os.Args[0], "-test.run=^TestDerivedStateReplacementCrashReplayMatrix$")
				cmd.Env = append(os.Environ(),
					"SOW_DERIVED_STATE_CRASH_PHASE="+tc.phase,
					"SOW_DERIVED_STATE_CRASH_ROOT="+stateRoot,
				)
				err := cmd.Run()
				exitErr, ok := err.(*exec.ExitError)
				if !ok || exitErr.ExitCode() != 91 {
					t.Fatalf("crash phase %s exit=%v", tc.phase, err)
				}
				if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true); err != nil {
					t.Fatalf("recover phase %s: %v", tc.phase, err)
				}
				if tc.committed {
					body, err := os.ReadFile(destination)
					if err != nil || string(body) != "candidate\n" {
						t.Fatalf("phase %s committed body=%q err=%v", tc.phase, body, err)
					}
				} else if priorPresent {
					current, err := os.Lstat(destination)
					if err != nil || !os.SameFile(prior, current) || current.Mode() != prior.Mode() {
						t.Fatalf("phase %s prior identity=%+v err=%v", tc.phase, current, err)
					}
					body, err := os.ReadFile(destination)
					if err != nil || string(body) != "prior\n" {
						t.Fatalf("phase %s prior body=%q err=%v", tc.phase, body, err)
					}
				} else if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("phase %s did not restore durable absence: %v", tc.phase, err)
				}
				assertNoDerivedStateReplacementResidue(t, stateRoot)
			})
		}
	}
}

func TestDerivedStateReplacementRecoveryRefusesThirdIdentity(t *testing.T) {
	stateRoot := t.TempDir()
	destination := filepath.Join(stateRoot, "state.json")
	if err := os.WriteFile(destination, []byte("prior\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := derivedStateReplacementPhaseHook
	derivedStateReplacementPhaseHook = func(phase string) error {
		if phase == "destination-mutated" {
			return errDerivedStateReplacementTestCrash
		}
		return nil
	}
	t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
	result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
	derivedStateReplacementPhaseHook = previous
	if result.Outcome != derivedStateReplacementRecoveryRequired || !errors.Is(err, errDerivedStateReplacementTestCrash) {
		t.Fatalf("crash result=%+v err=%v", result, err)
	}
	if err := os.Rename(destination, destination+".displaced"); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("foreign\n")
	if err := os.WriteFile(destination, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true); !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
		t.Fatalf("third-identity recovery error=%v", err)
	}
	body, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(body, foreign) {
		t.Fatalf("foreign destination changed body=%q err=%v", body, err)
	}
	if residues := derivedStateReplacementResidues(t, stateRoot); len(residues) < 2 {
		t.Fatalf("third-identity evidence was not retained: %v", residues)
	}
}

func TestDerivedStateReplacementScannerArbitratesBeforeLegacyCleanup(t *testing.T) {
	cases := []struct {
		name        string
		destination string
		cleanup     func(string, bool) error
	}{
		{name: "asset", destination: assetProjectionIntentRelative, cleanup: cleanupAssetProjectionIntentResidue},
		{name: "package", destination: packageProjectionIntentRelative, cleanup: cleanupPackageProjectionIntentResidue},
		{name: "offline-archive", destination: offlineArchiveProjectionIntentRelative, cleanup: cleanupOfflineArchiveProjectionResidue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stateRoot := t.TempDir()
			legacy := tc.destination + ".tmp-" + strings.Repeat("b", 32)
			if err := os.WriteFile(filepath.Join(stateRoot, legacy), []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			previous := derivedStateReplacementPhaseHook
			derivedStateReplacementPhaseHook = func(phase string) error {
				if phase == "destination-mutated" {
					return errDerivedStateReplacementTestCrash
				}
				return nil
			}
			t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
			result, err := writeDerivedStateFileOutcome(stateRoot, tc.destination, []byte("{}\n"))
			derivedStateReplacementPhaseHook = previous
			if result.Outcome != derivedStateReplacementRecoveryRequired || err == nil {
				t.Fatalf("crash result=%+v err=%v", result, err)
			}
			if err := tc.cleanup(stateRoot, false); err == nil || !strings.Contains(err.Error(), "--recover") {
				t.Fatalf("ordinary scanner did not block transaction: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(stateRoot, legacy)); err != nil {
				t.Fatalf("legacy residue changed before transaction arbitration: %v", err)
			}
			if err := tc.cleanup(stateRoot, true); err != nil {
				t.Fatalf("recovering scanner: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(stateRoot, tc.destination)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("prepared first install was not rolled back to absence: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(stateRoot, legacy)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("legacy residue was not cleaned after arbitration: %v", err)
			}
			assertNoDerivedStateReplacementResidue(t, stateRoot)
		})
	}
}

func TestDerivedStateReplacementNestedScannersArbitrateBeforeLegacyCleanup(t *testing.T) {
	cases := []struct {
		name        string
		directory   string
		destination string
		cleanup     func(string) error
	}{
		{
			name: "selection", directory: "materialization-journal", destination: "active.json",
			cleanup: cleanupMaterializationSelectionJournalTemps,
		},
		{
			name: "serving", directory: "serving-journal", destination: strings.Repeat("a", 32) + ".json",
			cleanup: cleanupLocalServingJournalTemps,
		},
		{
			name: "serving-removal", directory: "serving-removal-journal", destination: strings.Repeat("c", 32) + ".json",
			cleanup: cleanupLocalServingRemovalTemps,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stateRoot := t.TempDir()
			previous := derivedStateReplacementPhaseHook
			derivedStateReplacementPhaseHook = func(phase string) error {
				if phase == "destination-mutated" {
					return errDerivedStateReplacementTestCrash
				}
				return nil
			}
			t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
			relative := filepath.Join(tc.directory, tc.destination)
			result, err := writeDerivedStateFileOutcome(stateRoot, relative, []byte("{}\n"))
			derivedStateReplacementPhaseHook = previous
			if result.Outcome != derivedStateReplacementRecoveryRequired || err == nil {
				t.Fatalf("crash result=%+v err=%v", result, err)
			}
			legacy := tc.destination + ".tmp-" + strings.Repeat("d", 32)
			legacyPath := filepath.Join(stateRoot, tc.directory, legacy)
			if err := os.WriteFile(legacyPath, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tc.cleanup(stateRoot); err != nil {
				t.Fatalf("recovering nested scanner: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(stateRoot, relative)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("prepared nested install was not rolled back: %v", err)
			}
			if _, err := os.Lstat(legacyPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("legacy nested residue was not cleaned: %v", err)
			}
			assertNoDerivedStateReplacementResidue(t, filepath.Join(stateRoot, tc.directory))
		})
	}
}

func TestDerivedStateReplacementAcceptsEpochMtimePrior(t *testing.T) {
	stateRoot := t.TempDir()
	destination := filepath.Join(stateRoot, "state.json")
	if err := os.WriteFile(destination, []byte("epoch prior\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	epoch := time.Unix(0, 0)
	if err := os.Chtimes(destination, epoch, epoch); err != nil {
		t.Fatal(err)
	}
	prior, err := os.Lstat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if prior.ModTime().UnixNano() != 0 {
		t.Skipf("filesystem did not retain an epoch mtime: %s", prior.ModTime())
	}
	injected := errors.New("rollback epoch prior")
	previous := derivedStateReplacementPhaseHook
	derivedStateReplacementPhaseHook = func(phase string) error {
		if phase == "destination-mutated" {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
	result, writeErr := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
	derivedStateReplacementPhaseHook = previous
	if result.Outcome != derivedStateReplacementNotCommitted || !errors.Is(writeErr, injected) {
		t.Fatalf("replacement result=%+v err=%v", result, writeErr)
	}
	current, err := os.Lstat(destination)
	if err != nil || !os.SameFile(prior, current) || current.ModTime().UnixNano() != 0 {
		t.Fatalf("epoch prior was not restored exactly current=%+v err=%v", current, err)
	}
	assertNoDerivedStateReplacementResidue(t, stateRoot)
}

func TestDerivedStateReplacementRejectsReservedDestination(t *testing.T) {
	for _, destination := range []string{
		derivedStateReplacementIntentName(strings.Repeat("a", 32)),
		derivedStateReplacementIsolationName(strings.Repeat("b", 32)),
		derivedStateReplacementSourceTrashName(strings.Repeat("c", 32)),
	} {
		t.Run(destination, func(t *testing.T) {
			stateRoot := t.TempDir()
			result, err := writeDerivedStateFileOutcome(stateRoot, destination, []byte("must not publish\n"))
			if result.Outcome != derivedStateReplacementNotCommitted || err == nil ||
				!strings.Contains(err.Error(), "reserved replacement coordinate") {
				t.Fatalf("reserved destination result=%+v err=%v", result, err)
			}
			if _, err := os.Lstat(filepath.Join(stateRoot, destination)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("reserved destination was created: %v", err)
			}
			assertNoDerivedStateReplacementResidue(t, stateRoot)
		})
	}
}

func TestDerivedStateReplacementLongDestinationRecoveryUsesShortTrash(t *testing.T) {
	stateRoot := t.TempDir()
	destination := strings.Repeat("a", 175)
	previous := derivedStateReplacementPhaseHook
	derivedStateReplacementPhaseHook = func(phase string) error {
		if phase == "prepared" {
			return errDerivedStateReplacementTestCrash
		}
		return nil
	}
	t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
	result, err := writeDerivedStateFileOutcome(stateRoot, destination, []byte("candidate\n"))
	derivedStateReplacementPhaseHook = previous
	if result.Outcome != derivedStateReplacementRecoveryRequired || !errors.Is(err, errDerivedStateReplacementTestCrash) {
		t.Fatalf("long destination result=%+v err=%v", result, err)
	}
	if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true); err != nil {
		t.Fatalf("recover long destination: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, destination)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("long destination did not restore absence: %v", err)
	}
	assertNoDerivedStateReplacementResidue(t, stateRoot)
}

func TestDerivedStateReplacementParentSyncFailureOutcomes(t *testing.T) {
	t.Run("one-shot-precommit-rolls-back", func(t *testing.T) {
		for _, target := range []string{"prepared", "destination-mutated"} {
			t.Run(target, func(t *testing.T) {
				stateRoot := t.TempDir()
				destination := filepath.Join(stateRoot, "state.json")
				if err := os.WriteFile(destination, []byte("prior\n"), 0o640); err != nil {
					t.Fatal(err)
				}
				prior, err := os.Lstat(destination)
				if err != nil {
					t.Fatal(err)
				}
				injected := errors.New("injected one-shot parent sync failure")
				previous := derivedStateReplacementParentSync
				fired := false
				derivedStateReplacementParentSync = func(parent *os.File, phase string) error {
					if phase == target && !fired {
						fired = true
						return injected
					}
					return parent.Sync()
				}
				t.Cleanup(func() { derivedStateReplacementParentSync = previous })
				result, writeErr := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
				derivedStateReplacementParentSync = previous
				if !fired || result.Outcome != derivedStateReplacementNotCommitted || !errors.Is(writeErr, injected) {
					t.Fatalf("target=%s result=%+v fired=%v err=%v", target, result, fired, writeErr)
				}
				current, err := os.Lstat(destination)
				if err != nil || !os.SameFile(prior, current) || current.Mode() != prior.Mode() {
					t.Fatalf("target=%s prior=%+v err=%v", target, current, err)
				}
				assertNoDerivedStateReplacementResidue(t, stateRoot)
			})
		}
	})

	t.Run("one-shot-commit-barrier-is-made-durable-by-replay", func(t *testing.T) {
		stateRoot := t.TempDir()
		if err := os.WriteFile(filepath.Join(stateRoot, "state.json"), []byte("prior\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		injected := errors.New("injected commit parent sync failure")
		previous := derivedStateReplacementParentSync
		fired := false
		derivedStateReplacementParentSync = func(parent *os.File, phase string) error {
			if phase == "committed" && !fired {
				fired = true
				return injected
			}
			return parent.Sync()
		}
		t.Cleanup(func() { derivedStateReplacementParentSync = previous })
		result, writeErr := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
		derivedStateReplacementParentSync = previous
		if !fired || result.Outcome != derivedStateReplacementCommitted || !errors.Is(writeErr, injected) {
			t.Fatalf("commit barrier result=%+v fired=%v err=%v", result, fired, writeErr)
		}
		body, err := os.ReadFile(filepath.Join(stateRoot, "state.json"))
		if err != nil || string(body) != "candidate\n" {
			t.Fatalf("commit barrier body=%q err=%v", body, err)
		}
		assertNoDerivedStateReplacementResidue(t, stateRoot)
	})

	t.Run("persistent-commit-barrier-requires-recovery", func(t *testing.T) {
		stateRoot := t.TempDir()
		destination := filepath.Join(stateRoot, "state.json")
		if err := os.WriteFile(destination, []byte("prior\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		injected := errors.New("persistent commit parent sync failure")
		previous := derivedStateReplacementParentSync
		derivedStateReplacementParentSync = func(parent *os.File, phase string) error {
			if phase == "committed" || phase == "committed-observed" {
				return injected
			}
			return parent.Sync()
		}
		t.Cleanup(func() { derivedStateReplacementParentSync = previous })
		result, writeErr := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
		if result.Outcome != derivedStateReplacementRecoveryRequired || !errors.Is(writeErr, injected) ||
			!errors.Is(writeErr, errDerivedStateReplacementRecoveryRequired) {
			t.Fatalf("persistent commit barrier result=%+v err=%v", result, writeErr)
		}
		if residues := derivedStateReplacementResidues(t, stateRoot); len(residues) < 2 {
			t.Fatalf("persistent commit evidence=%v", residues)
		}
		derivedStateReplacementParentSync = previous
		if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true); err != nil {
			t.Fatalf("recover persistent commit barrier: %v", err)
		}
		body, err := os.ReadFile(destination)
		if err != nil || string(body) != "candidate\n" {
			t.Fatalf("persistent commit replay body=%q err=%v", body, err)
		}
		assertNoDerivedStateReplacementResidue(t, stateRoot)
	})

	for _, target := range []string{
		"committed-prior-cleanup-quarantine",
		"replacement-intent-cleanup-quarantine",
	} {
		t.Run("one-shot-cleanup/"+target, func(t *testing.T) {
			stateRoot := t.TempDir()
			destination := filepath.Join(stateRoot, "state.json")
			if err := os.WriteFile(destination, []byte("prior\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected cleanup parent sync failure")
			previous := derivedStateReplacementParentSync
			fired := false
			derivedStateReplacementParentSync = func(parent *os.File, phase string) error {
				if phase == target && !fired {
					fired = true
					return injected
				}
				return parent.Sync()
			}
			t.Cleanup(func() { derivedStateReplacementParentSync = previous })
			result, writeErr := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
			derivedStateReplacementParentSync = previous
			if !fired || result.Outcome != derivedStateReplacementCommitted || !errors.Is(writeErr, injected) {
				t.Fatalf("target=%s result=%+v fired=%v err=%v", target, result, fired, writeErr)
			}
			if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true); err != nil {
				t.Fatalf("target=%s replay: %v", target, err)
			}
			body, err := os.ReadFile(destination)
			if err != nil || string(body) != "candidate\n" {
				t.Fatalf("target=%s body=%q err=%v", target, body, err)
			}
			assertNoDerivedStateReplacementResidue(t, stateRoot)
		})
	}
}

func TestDerivedStateReplacementRejectsMalformedReservedCoordinates(t *testing.T) {
	for _, name := range []string{
		derivedStateReplacementIntentPrefix + "not-a-transaction.json",
		derivedStateReplacementIsolationPrefix + "not-a-transaction",
	} {
		t.Run(name, func(t *testing.T) {
			stateRoot := t.TempDir()
			path := filepath.Join(stateRoot, name)
			if err := os.WriteFile(path, []byte("evidence\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true)
			if !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
				t.Fatalf("malformed reserved coordinate error=%v", err)
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil || string(body) != "evidence\n" {
				t.Fatalf("malformed evidence changed body=%q err=%v", body, readErr)
			}
		})
	}
}

func TestDerivedStateReplacementRejectsOrphanIsolationWithoutCarrier(t *testing.T) {
	stateRoot := t.TempDir()
	transactionID := strings.Repeat("a", 32)
	isolation := filepath.Join(stateRoot, derivedStateReplacementIsolationName(transactionID))
	if err := os.WriteFile(isolation, []byte("exact prior evidence\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", false); err == nil || !strings.Contains(err.Error(), "--recover") {
		t.Fatalf("ordinary recovery did not stop for orphan isolation: %v", err)
	}
	if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true); !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
		t.Fatalf("orphan isolation recovery error=%v", err)
	}
	body, err := os.ReadFile(isolation)
	if err != nil || string(body) != "exact prior evidence\n" {
		t.Fatalf("orphan isolation evidence changed body=%q err=%v", body, err)
	}
}

func TestDerivedStateReplacementRejectsImpossibleCarrierTopologyWithoutMutation(t *testing.T) {
	t.Run("committed-staged-only", func(t *testing.T) {
		stateRoot := t.TempDir()
		previous := derivedStateReplacementPhaseHook
		derivedStateReplacementPhaseHook = func(phase string) error {
			if phase == "prepared-carrier" {
				return errDerivedStateReplacementTestCrash
			}
			return nil
		}
		t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
		result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
		derivedStateReplacementPhaseHook = previous
		if result.Outcome != derivedStateReplacementRecoveryRequired || !errors.Is(err, errDerivedStateReplacementTestCrash) {
			t.Fatalf("staged-only setup result=%+v err=%v", result, err)
		}
		staged := findDerivedStateReplacementCarrierForTest(t, stateRoot, "staged")
		rewriteDerivedStateReplacementCarrierPhaseForTest(t, filepath.Join(stateRoot, staged), derivedStateReplacementCommittedPhase)
		before, err := os.ReadFile(filepath.Join(stateRoot, staged))
		if err != nil {
			t.Fatal(err)
		}
		if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true); !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
			t.Fatalf("committed staged-only topology error=%v", err)
		}
		after, err := os.ReadFile(filepath.Join(stateRoot, staged))
		if err != nil || !bytes.Equal(after, before) {
			t.Fatalf("impossible staged carrier moved or changed body=%q err=%v", after, err)
		}
		if _, err := os.Lstat(filepath.Join(stateRoot, strings.TrimSuffix(staged, ".new"))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("impossible staged carrier was published as main: %v", err)
		}
	})

	t.Run("prepared-main-and-next", func(t *testing.T) {
		stateRoot := t.TempDir()
		if err := os.WriteFile(filepath.Join(stateRoot, "state.json"), []byte("prior\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		previous := derivedStateReplacementPhaseHook
		derivedStateReplacementPhaseHook = func(phase string) error {
			if phase == "committed-carrier" {
				return errDerivedStateReplacementTestCrash
			}
			return nil
		}
		t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
		result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
		derivedStateReplacementPhaseHook = previous
		if result.Outcome != derivedStateReplacementRecoveryRequired || !errors.Is(err, errDerivedStateReplacementTestCrash) {
			t.Fatalf("main-next setup result=%+v err=%v", result, err)
		}
		main := findDerivedStateReplacementCarrierForTest(t, stateRoot, "main")
		next := findDerivedStateReplacementCarrierForTest(t, stateRoot, "next")
		rewriteDerivedStateReplacementCarrierPhaseForTest(t, filepath.Join(stateRoot, next), derivedStateReplacementPrepared)
		if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true); !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
			t.Fatalf("prepared main+next topology error=%v", err)
		}
		for _, name := range []string{main, next} {
			if _, err := os.Lstat(filepath.Join(stateRoot, name)); err != nil {
				t.Fatalf("impossible topology carrier %s was moved: %v", name, err)
			}
		}
	})
}

func TestDerivedStateReplacementValidatesCarrierTrashBeforeRestore(t *testing.T) {
	stateRoot := t.TempDir()
	transactionID := strings.Repeat("a", 32)
	trash := derivedStateReplacementIntentName(transactionID) + ".remove"
	path := filepath.Join(stateRoot, trash)
	body := []byte("foreign cleanup evidence\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true); !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
		t.Fatalf("malformed carrier trash error=%v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, body) {
		t.Fatalf("malformed carrier trash moved or changed body=%q err=%v", after, err)
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, derivedStateReplacementIntentName(transactionID))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("malformed carrier trash was restored before validation: %v", err)
	}
}

func TestDerivedStateReplacementBoundsTransactionInventory(t *testing.T) {
	stateRoot := t.TempDir()
	for index := 0; index <= derivedStateReplacementMaxTransactions; index++ {
		transactionID := fmt.Sprintf("%032x", index)
		name := filepath.Join(stateRoot, derivedStateReplacementIsolationName(transactionID))
		if err := os.WriteFile(name, []byte("evidence\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true)
	if !errors.Is(err, errDerivedStateReplacementRecoveryRequired) ||
		!strings.Contains(err.Error(), "transaction count exceeds") {
		t.Fatalf("unbounded transaction inventory error=%v", err)
	}
	for _, index := range []int{0, derivedStateReplacementMaxTransactions} {
		transactionID := fmt.Sprintf("%032x", index)
		if _, err := os.Lstat(filepath.Join(stateRoot, derivedStateReplacementIsolationName(transactionID))); err != nil {
			t.Fatalf("bounded inventory changed evidence %d: %v", index, err)
		}
	}
}

func TestDerivedStateReplacementOrdinaryWriteCannotReplayInterruptedTransaction(t *testing.T) {
	stateRoot := t.TempDir()
	previous := derivedStateReplacementPhaseHook
	derivedStateReplacementPhaseHook = func(phase string) error {
		if phase == "prepared" {
			return errDerivedStateReplacementTestCrash
		}
		return nil
	}
	t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
	result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("first\n"))
	derivedStateReplacementPhaseHook = previous
	if result.Outcome != derivedStateReplacementRecoveryRequired || !errors.Is(err, errDerivedStateReplacementTestCrash) {
		t.Fatalf("interrupted setup result=%+v err=%v", result, err)
	}
	before := derivedStateReplacementResidues(t, stateRoot)
	result, err = writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("ordinary retry\n"))
	if result.Outcome != derivedStateReplacementRecoveryRequired || !errors.Is(err, errDerivedStateReplacementRecoveryRequired) ||
		!strings.Contains(err.Error(), "--recover") {
		t.Fatalf("ordinary retry result=%+v err=%v", result, err)
	}
	after := derivedStateReplacementResidues(t, stateRoot)
	if strings.Join(after, "\x00") != strings.Join(before, "\x00") {
		t.Fatalf("ordinary retry changed recovery evidence before=%v after=%v", before, after)
	}
	result, err = writeDerivedStateFileOutcomeWithRecovery(stateRoot, "state.json", []byte("recovered retry\n"), true)
	if result.Outcome != derivedStateReplacementCommitted || err != nil {
		t.Fatalf("explicit recovery result=%+v err=%v", result, err)
	}
	body, err := os.ReadFile(filepath.Join(stateRoot, "state.json"))
	if err != nil || string(body) != "recovered retry\n" {
		t.Fatalf("explicit recovery body=%q err=%v", body, err)
	}
	assertNoDerivedStateReplacementResidue(t, stateRoot)
}

func TestDerivedStateReplacementIdentityRejectsMtimeChange(t *testing.T) {
	stateRoot := t.TempDir()
	path := filepath.Join(stateRoot, "candidate")
	body := []byte("candidate\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if _, err := replacementIdentityFromFile(file, before, &digest); err == nil || !strings.Contains(err.Error(), "changed before identity capture") {
		t.Fatalf("mtime mutation retained a valid identity: %v", err)
	}
}

func TestDerivedStateReplacementCarrierReadRejectsMtimeChange(t *testing.T) {
	stateRoot := t.TempDir()
	previousPhase := derivedStateReplacementPhaseHook
	derivedStateReplacementPhaseHook = func(phase string) error {
		if phase == "prepared" {
			return errDerivedStateReplacementTestCrash
		}
		return nil
	}
	t.Cleanup(func() { derivedStateReplacementPhaseHook = previousPhase })
	result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
	derivedStateReplacementPhaseHook = previousPhase
	if result.Outcome != derivedStateReplacementRecoveryRequired || !errors.Is(err, errDerivedStateReplacementTestCrash) {
		t.Fatalf("carrier-read setup result=%+v err=%v", result, err)
	}
	main := findDerivedStateReplacementCarrierForTest(t, stateRoot, "main")
	previousRead := derivedStateReplacementAfterCarrierReadHook
	fired := false
	derivedStateReplacementAfterCarrierReadHook = func(name string) error {
		if fired || name != main {
			return nil
		}
		fired = true
		path := filepath.Join(stateRoot, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		return os.Chtimes(path, info.ModTime(), info.ModTime().Add(2*time.Second))
	}
	t.Cleanup(func() { derivedStateReplacementAfterCarrierReadHook = previousRead })
	err = recoverDerivedStateReplacementTransactions(stateRoot, ".", true)
	derivedStateReplacementAfterCarrierReadHook = previousRead
	if !fired || !errors.Is(err, errDerivedStateReplacementRecoveryRequired) ||
		!strings.Contains(err.Error(), "changed while reading") {
		t.Fatalf("carrier mtime mutation fired=%t err=%v", fired, err)
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, main)); err != nil {
		t.Fatalf("mtime-mutated carrier was removed: %v", err)
	}
}

func TestDerivedStateReplacementStreamsLargeSiblingDirectory(t *testing.T) {
	stateRoot := t.TempDir()
	for index := 0; index < 4097; index++ {
		name := filepath.Join(stateRoot, fmt.Sprintf("ordinary-%05d", index))
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", true); err != nil {
		t.Fatalf("large sibling scan: %v", err)
	}
}

func findDerivedStateReplacementCarrierForTest(t *testing.T, directory, wantedKind string) string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		_, kind, ok := parseDerivedStateReplacementCarrierName(entry.Name())
		if ok && kind == wantedKind {
			return entry.Name()
		}
	}
	t.Fatalf("derived state replacement carrier kind %s is missing", wantedKind)
	return ""
}

func rewriteDerivedStateReplacementCarrierPhaseForTest(t *testing.T, path, phase string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var intent derivedStateReplacementIntent
	if err := json.Unmarshal(body, &intent); err != nil {
		t.Fatal(err)
	}
	intent.Phase = phase
	body, err = json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		t.Fatal(err)
	}
}

func TestDerivedStateReplacementRecoveryRequiredPreservesOwnedSource(t *testing.T) {
	container := t.TempDir()
	stateRoot := filepath.Join(container, "state")
	displaced := filepath.Join(container, "displaced")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("replace state root after prepared barrier")
	previous := derivedStateReplacementPhaseHook
	derivedStateReplacementPhaseHook = func(phase string) error {
		if phase != "prepared" {
			return nil
		}
		if err := os.Rename(stateRoot, displaced); err != nil {
			return err
		}
		if err := os.Mkdir(stateRoot, 0o700); err != nil {
			return err
		}
		return injected
	}
	t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
	result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
	derivedStateReplacementPhaseHook = previous
	if result.Outcome != derivedStateReplacementRecoveryRequired ||
		!errors.Is(err, injected) || !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
		t.Fatalf("prepared root replacement result=%+v err=%v", result, err)
	}
	if residues := derivedStateReplacementResidues(t, displaced); len(residues) < 2 {
		t.Fatalf("prepared source or carrier was not retained: %v", residues)
	}
}

func TestDerivedStateReplacementReplayRevalidatesDestination(t *testing.T) {
	t.Run("prepared-cleanup", func(t *testing.T) {
		stateRoot := t.TempDir()
		destination := filepath.Join(stateRoot, "state.json")
		if err := os.WriteFile(destination, []byte("prior\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		previous := derivedStateReplacementPhaseHook
		derivedStateReplacementPhaseHook = func(phase string) error {
			if phase == "destination-mutated" {
				return errDerivedStateReplacementTestCrash
			}
			return nil
		}
		t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
		result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
		derivedStateReplacementPhaseHook = previous
		if result.Outcome != derivedStateReplacementRecoveryRequired || err == nil {
			t.Fatalf("prepared setup result=%+v err=%v", result, err)
		}
		foreign := []byte("foreign\n")
		fired := false
		derivedStateReplacementPhaseHook = func(phase string) error {
			if phase != "prepared-candidate-cleanup-quarantine" || fired {
				return nil
			}
			fired = true
			if err := os.Rename(destination, destination+".displaced"); err != nil {
				return err
			}
			return os.WriteFile(destination, foreign, 0o600)
		}
		err = recoverDerivedStateReplacementTransactions(stateRoot, ".", true)
		derivedStateReplacementPhaseHook = previous
		if !fired || !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
			t.Fatalf("prepared final proof fired=%v err=%v", fired, err)
		}
		body, readErr := os.ReadFile(destination)
		if readErr != nil || !bytes.Equal(body, foreign) {
			t.Fatalf("prepared foreign destination changed body=%q err=%v", body, readErr)
		}
		if residues := derivedStateReplacementResidues(t, stateRoot); len(residues) == 0 {
			t.Fatal("prepared final proof removed all transaction evidence")
		}
	})

	t.Run("committed-carrier-cleanup", func(t *testing.T) {
		stateRoot := t.TempDir()
		destination := filepath.Join(stateRoot, "state.json")
		if err := os.WriteFile(destination, []byte("prior\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		foreign := []byte("foreign\n")
		previous := derivedStateReplacementPhaseHook
		fired := false
		derivedStateReplacementPhaseHook = func(phase string) error {
			if phase != "replacement-intent-cleanup-quarantine" || fired {
				return nil
			}
			fired = true
			if err := os.Rename(destination, destination+".displaced"); err != nil {
				return err
			}
			return os.WriteFile(destination, foreign, 0o600)
		}
		t.Cleanup(func() { derivedStateReplacementPhaseHook = previous })
		result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
		derivedStateReplacementPhaseHook = previous
		if !fired || result.Outcome != derivedStateReplacementRecoveryRequired ||
			!errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
			t.Fatalf("committed final proof result=%+v fired=%v err=%v", result, fired, err)
		}
		body, readErr := os.ReadFile(destination)
		if readErr != nil || !bytes.Equal(body, foreign) {
			t.Fatalf("committed foreign destination changed body=%q err=%v", body, readErr)
		}
		if residues := derivedStateReplacementResidues(t, stateRoot); len(residues) == 0 {
			t.Fatal("committed final proof removed every carrier")
		}
	})
}

func TestDerivedStateReplacementFinalCoordinateOutcome(t *testing.T) {
	t.Run("root-replaced", func(t *testing.T) {
		container := t.TempDir()
		stateRoot := filepath.Join(container, "state")
		displaced := filepath.Join(container, "displaced")
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
		result, err := writeDerivedStateFileOutcome(stateRoot, filepath.Join("generated", "state.json"), []byte("candidate\n"))
		derivedStateDirectoryBeforeFinalCacheHook = previous
		if result.Outcome != derivedStateReplacementRecoveryRequired || !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
			t.Fatalf("root replacement result=%+v err=%v", result, err)
		}
		body, readErr := os.ReadFile(filepath.Join(displaced, "generated", "state.json"))
		if readErr != nil || string(body) != "candidate\n" {
			t.Fatalf("detached committed evidence=%q err=%v", body, readErr)
		}
		if residues := derivedStateReplacementResidues(t, filepath.Join(displaced, "generated")); len(residues) == 0 {
			t.Fatal("detached committed transaction carrier was not retained")
		}
	})

	t.Run("prior-retained-until-final-coordinate-proof", func(t *testing.T) {
		container := t.TempDir()
		stateRoot := filepath.Join(container, "state")
		displaced := filepath.Join(container, "displaced")
		if err := os.Mkdir(stateRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(stateRoot, "state.json")
		if err := os.WriteFile(destination, []byte("prior\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		prior, err := os.Lstat(destination)
		if err != nil {
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
		result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
		derivedStateDirectoryBeforeFinalCacheHook = previous
		if result.Outcome != derivedStateReplacementRecoveryRequired ||
			!errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
			t.Fatalf("prior-retention result=%+v err=%v", result, err)
		}
		entries, err := os.ReadDir(displaced)
		if err != nil {
			t.Fatal(err)
		}
		foundPrior := false
		foundCarrier := false
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasPrefix(name, derivedStateReplacementIsolationPrefix) &&
				!strings.HasSuffix(name, ".remove") && !strings.HasSuffix(name, ".source.remove") {
				current, statErr := os.Lstat(filepath.Join(displaced, name))
				if statErr == nil && os.SameFile(prior, current) {
					foundPrior = true
				}
			}
			if strings.HasPrefix(name, derivedStateReplacementIntentPrefix) {
				foundCarrier = true
			}
		}
		if !foundPrior || !foundCarrier {
			t.Fatalf("final coordinate failure prior=%v carrier=%v entries=%v", foundPrior, foundCarrier, entries)
		}
	})

	t.Run("parent-replaced", func(t *testing.T) {
		stateRoot := t.TempDir()
		parent := filepath.Join(stateRoot, "generated")
		displaced := filepath.Join(stateRoot, "generated-displaced")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		previous := derivedStateDirectoryBeforeFinalCacheHook
		derivedStateDirectoryBeforeFinalCacheHook = func(string) error {
			if err := os.Rename(parent, displaced); err != nil {
				return err
			}
			return os.Mkdir(parent, 0o700)
		}
		t.Cleanup(func() { derivedStateDirectoryBeforeFinalCacheHook = previous })
		result, err := writeDerivedStateFileOutcome(stateRoot, filepath.Join("generated", "state.json"), []byte("candidate\n"))
		derivedStateDirectoryBeforeFinalCacheHook = previous
		if result.Outcome != derivedStateReplacementRecoveryRequired || !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
			t.Fatalf("parent replacement result=%+v err=%v", result, err)
		}
		body, readErr := os.ReadFile(filepath.Join(displaced, "state.json"))
		if readErr != nil || string(body) != "candidate\n" {
			t.Fatalf("detached parent evidence=%q err=%v", body, readErr)
		}
	})

	t.Run("same-bytes-foreign-destination", func(t *testing.T) {
		stateRoot := t.TempDir()
		destination := filepath.Join(stateRoot, "state.json")
		displaced := destination + ".displaced"
		candidate := []byte("candidate\n")
		previous := derivedStateDirectoryBeforeFinalCacheHook
		derivedStateDirectoryBeforeFinalCacheHook = func(string) error {
			if err := os.Rename(destination, displaced); err != nil {
				return err
			}
			return os.WriteFile(destination, candidate, 0o600)
		}
		t.Cleanup(func() { derivedStateDirectoryBeforeFinalCacheHook = previous })
		result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", candidate)
		derivedStateDirectoryBeforeFinalCacheHook = previous
		if result.Outcome != derivedStateReplacementRecoveryRequired || !errors.Is(err, errDerivedStateReplacementRecoveryRequired) {
			t.Fatalf("destination replacement result=%+v err=%v", result, err)
		}
		foreign, foreignErr := os.ReadFile(destination)
		evidence, evidenceErr := os.ReadFile(displaced)
		if foreignErr != nil || evidenceErr != nil || !bytes.Equal(foreign, candidate) || !bytes.Equal(evidence, candidate) {
			t.Fatalf("destination evidence foreign=%q displaced=%q errors=%v/%v", foreign, evidence, foreignErr, evidenceErr)
		}
	})

	t.Run("post-commit-hook-error", func(t *testing.T) {
		stateRoot := t.TempDir()
		injected := errors.New("post-commit bookkeeping failed")
		previous := derivedStateDirectoryBeforeFinalCacheHook
		derivedStateDirectoryBeforeFinalCacheHook = func(string) error { return injected }
		t.Cleanup(func() { derivedStateDirectoryBeforeFinalCacheHook = previous })
		result, err := writeDerivedStateFileOutcome(stateRoot, "state.json", []byte("candidate\n"))
		derivedStateDirectoryBeforeFinalCacheHook = previous
		if result.Outcome != derivedStateReplacementCommitted || !errors.Is(err, injected) {
			t.Fatalf("committed hook error result=%+v err=%v", result, err)
		}
	})
}

func derivedStateReplacementResidues(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var residues []string
	for _, entry := range entries {
		name := entry.Name()
		if _, _, ok := parseDerivedStateReplacementCarrierName(name); ok ||
			strings.HasPrefix(name, derivedStateReplacementIsolationPrefix) ||
			strings.Contains(name, ".tmp-install-") ||
			strings.Contains(name, ".tmp-remove-") ||
			strings.Contains(name, ".tmp-") {
			residues = append(residues, name)
		}
	}
	return residues
}

func assertNoDerivedStateReplacementResidue(t *testing.T, directory string) {
	t.Helper()
	if residues := derivedStateReplacementResidues(t, directory); len(residues) != 0 {
		t.Fatalf("derived state replacement residues=%v", residues)
	}
}
