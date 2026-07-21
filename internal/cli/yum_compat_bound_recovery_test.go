package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
)

func bindYUMCompatibilityRecoveryFixture(t *testing.T, fixture yumCompatibilityContractFixture) yumCompatibilityWorkflow {
	t.Helper()
	lock, err := state.AcquireLock(fixture.cfg.StatePath(), "test-bound-yum-compatibility-recovery", false)
	if err != nil {
		t.Fatal(err)
	}
	workflow := yumCompatibilityWorkflow{cfg: fixture.cfg}
	if err := workflow.bindMutationRoots(lock); err != nil {
		_ = lock.Release()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := workflow.closeMutationRoots(); err != nil {
			t.Errorf("close bound YUM compatibility roots: %v", err)
		}
		if err := lock.Release(); err != nil {
			t.Errorf("release bound YUM compatibility lock: %v", err)
		}
	})
	return workflow
}

func fixtureYUMCompatibilityCutover(t *testing.T, fixture yumCompatibilityContractFixture, commit bool) (yumCompatibilityCutoverEvent, yumCompatibilityCutoverJournal) {
	t.Helper()
	id := fixture.cfg.CompatibilityProjections[0].ID
	frozen, err := loadYUMCompatibilityFrozenStateAt(fixture.canonical, plumbing.ZeroHash, id)
	if err != nil {
		t.Fatal(err)
	}
	stateAtHead, err := loadYUMCompatibilityCutoverStateAt(fixture.canonical, plumbing.ZeroHash, id)
	if err != nil {
		t.Fatal(err)
	}
	event, err := buildNextYUMCompatibilityCutoverEvent(frozen, stateAtHead, "cutover")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := physicalYUMCompatibilityCutoverJournal(fixture.cfg, event)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{journal.FromTarget, journal.ToTarget} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if commit {
		transaction, err := newTransactionDir(fixture.cfg.StatePath(), "test-bound-cutover-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(transaction) })
		commitHash, err := appendYUMCompatibilityCutoverEvent(t.Context(), fixture.canonical, event, transaction)
		if err != nil || commitHash.IsZero() {
			t.Fatalf("append canonical cutover event commit=%s err=%v", commitHash, err)
		}
	}
	return event, journal
}

func writeYUMCompatibilityCrashJournal(t *testing.T, filename string, journal yumCompatibilityCutoverJournal) {
	t.Helper()
	body, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertYUMCompatibilityCutoverJournalAbsent(t *testing.T, cfg *config.Config, id string) {
	t.Helper()
	base := yumCompatibilityCutoverJournalPath(cfg, id)
	for _, filename := range []string{base, base + ".next"} {
		if _, err := os.Lstat(filename); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovered cutover journal remains at %s: %v", filename, err)
		}
	}
}

func assertYUMCompatibilityCrashJournalPreserved(t *testing.T, filename string, before []byte) {
	t.Helper()
	after, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("fail-closed recovery changed forensic journal %s: before=%q after=%q err=%v", filename, before, after, err)
	}
}

func TestYUMCompatibilityBoundCutoverRecoveryConvergesCrashStates(t *testing.T) {
	t.Run("prepared-event-requires-explicit-recovery", func(t *testing.T) {
		fixture := newYUMCompatibilityContractFixture(t, "")
		id := fixture.cfg.CompatibilityProjections[0].ID
		_, journal := fixtureYUMCompatibilityCutover(t, fixture, false)
		workflow := bindYUMCompatibilityRecoveryFixture(t, fixture)
		if err := writeYUMCompatibilityCutoverJournalBound(workflow, journal, true); err != nil {
			t.Fatal(err)
		}
		err := recoverYUMCompatibilityCutoverJournalBound(workflow, fixture.canonical, id, false)
		if err == nil || !strings.Contains(err.Error(), "--recover") {
			t.Fatalf("prepared transaction was recovered implicitly: %v", err)
		}
		if _, err := os.Lstat(yumCompatibilityCutoverJournalPath(fixture.cfg, id)); err != nil {
			t.Fatalf("implicit recovery discarded prepared journal: %v", err)
		}
		if err := recoverYUMCompatibilityCutoverJournalBound(workflow, fixture.canonical, id, true); err != nil {
			t.Fatalf("explicitly discard pre-canonical prepared event: %v", err)
		}
		assertYUMCompatibilityCutoverJournalAbsent(t, fixture.cfg, id)
	})

	t.Run("orphan-partial-before-canonical-event", func(t *testing.T) {
		fixture := newYUMCompatibilityContractFixture(t, "")
		id := fixture.cfg.CompatibilityProjections[0].ID
		workflow := bindYUMCompatibilityRecoveryFixture(t, fixture)
		next := yumCompatibilityCutoverJournalPath(fixture.cfg, id) + ".next"
		if err := os.WriteFile(next, []byte("{\"phase\":"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := recoverYUMCompatibilityCutoverJournalBound(workflow, fixture.canonical, id, true); err != nil {
			t.Fatalf("recover orphan partial journal: %v", err)
		}
		assertYUMCompatibilityCutoverJournalAbsent(t, fixture.cfg, id)
		stateAtHead, err := loadYUMCompatibilityCutoverStateAt(fixture.canonical, plumbing.ZeroHash, id)
		if err != nil || stateAtHead.Stage != yumCompatibilityStageS2 || len(stateAtHead.Events) != 0 {
			t.Fatalf("orphan partial recovery changed canonical S2 state: state=%+v err=%v", stateAtHead, err)
		}
	})

	t.Run("orphan-partial-after-canonical-event", func(t *testing.T) {
		fixture := newYUMCompatibilityContractFixture(t, "")
		id := fixture.cfg.CompatibilityProjections[0].ID
		_, journal := fixtureYUMCompatibilityCutover(t, fixture, true)
		workflow := bindYUMCompatibilityRecoveryFixture(t, fixture)
		if err := os.WriteFile(yumCompatibilityCutoverJournalPath(fixture.cfg, id)+".next", []byte("{\"phase\":"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := recoverYUMCompatibilityCutoverJournalBound(workflow, fixture.canonical, id, true); err != nil {
			t.Fatalf("recover orphan partial journal from canonical event: %v", err)
		}
		assertYUMCompatibilityServingLinkTarget(t, journal.ServingLink, journal.ToTarget)
		assertYUMCompatibilityCutoverJournalAbsent(t, fixture.cfg, id)
	})

	t.Run("prepared-base-and-partial-commit-after-canonical-event", func(t *testing.T) {
		fixture := newYUMCompatibilityContractFixture(t, "")
		id := fixture.cfg.CompatibilityProjections[0].ID
		_, journal := fixtureYUMCompatibilityCutover(t, fixture, true)
		workflow := bindYUMCompatibilityRecoveryFixture(t, fixture)
		if err := writeYUMCompatibilityCutoverJournalBound(workflow, journal, true); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(yumCompatibilityCutoverJournalPath(fixture.cfg, id)+".next", []byte("{\"phase\":"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := recoverYUMCompatibilityCutoverJournalBound(workflow, fixture.canonical, id, true); err != nil {
			t.Fatalf("recover partial committed phase: %v", err)
		}
		assertYUMCompatibilityServingLinkTarget(t, journal.ServingLink, journal.ToTarget)
		assertYUMCompatibilityCutoverJournalAbsent(t, fixture.cfg, id)
	})

	t.Run("committed-main-after-canonical-event", func(t *testing.T) {
		fixture := newYUMCompatibilityContractFixture(t, "")
		id := fixture.cfg.CompatibilityProjections[0].ID
		_, journal := fixtureYUMCompatibilityCutover(t, fixture, true)
		workflow := bindYUMCompatibilityRecoveryFixture(t, fixture)
		if err := writeYUMCompatibilityCutoverJournalBound(workflow, journal, true); err != nil {
			t.Fatal(err)
		}
		journal.Phase = yumCompatibilityCutoverCommitted
		if err := writeYUMCompatibilityCutoverJournalBound(workflow, journal, false); err != nil {
			t.Fatal(err)
		}
		if err := recoverYUMCompatibilityCutoverJournalBound(workflow, fixture.canonical, id, true); err != nil {
			t.Fatalf("recover committed main journal: %v", err)
		}
		assertYUMCompatibilityServingLinkTarget(t, journal.ServingLink, journal.ToTarget)
		assertYUMCompatibilityCutoverJournalAbsent(t, fixture.cfg, id)
	})

	t.Run("committed-main-without-canonical-event-fails-closed", func(t *testing.T) {
		fixture := newYUMCompatibilityContractFixture(t, "")
		id := fixture.cfg.CompatibilityProjections[0].ID
		_, journal := fixtureYUMCompatibilityCutover(t, fixture, false)
		workflow := bindYUMCompatibilityRecoveryFixture(t, fixture)
		if err := writeYUMCompatibilityCutoverJournalBound(workflow, journal, true); err != nil {
			t.Fatal(err)
		}
		journal.Phase = yumCompatibilityCutoverCommitted
		if err := writeYUMCompatibilityCutoverJournalBound(workflow, journal, false); err != nil {
			t.Fatal(err)
		}
		journalPath := yumCompatibilityCutoverJournalPath(fixture.cfg, id)
		before, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		err = recoverYUMCompatibilityCutoverJournalBound(workflow, fixture.canonical, id, true)
		if err == nil || !strings.Contains(err.Error(), "absent from canonical state") {
			t.Fatalf("committed main journal without authority was accepted: %v", err)
		}
		assertYUMCompatibilityCrashJournalPreserved(t, journalPath, before)
		if _, err := os.Lstat(journal.ServingLink); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unauthorized committed main journal changed serving link: %v", err)
		}
	})

	t.Run("prepared-and-committed-pair-without-canonical-event-fails-closed", func(t *testing.T) {
		fixture := newYUMCompatibilityContractFixture(t, "")
		id := fixture.cfg.CompatibilityProjections[0].ID
		_, journal := fixtureYUMCompatibilityCutover(t, fixture, false)
		workflow := bindYUMCompatibilityRecoveryFixture(t, fixture)
		if err := writeYUMCompatibilityCutoverJournalBound(workflow, journal, true); err != nil {
			t.Fatal(err)
		}
		committed := journal
		committed.Phase = yumCompatibilityCutoverCommitted
		base := yumCompatibilityCutoverJournalPath(fixture.cfg, id)
		next := base + ".next"
		writeYUMCompatibilityCrashJournal(t, next, committed)
		before := make(map[string][]byte, 2)
		for _, filename := range []string{base, next} {
			body, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			before[filename] = body
		}
		err := recoverYUMCompatibilityCutoverJournalBound(workflow, fixture.canonical, id, true)
		if err == nil || !strings.Contains(err.Error(), "no exact canonical event") {
			t.Fatalf("dual-phase journal without authority was accepted: %v", err)
		}
		for _, filename := range []string{base, next} {
			assertYUMCompatibilityCrashJournalPreserved(t, filename, before[filename])
		}
		if _, err := os.Lstat(journal.ServingLink); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unauthorized dual-phase journal changed serving link: %v", err)
		}
	})

	t.Run("orphan-committed-phase-after-canonical-event", func(t *testing.T) {
		fixture := newYUMCompatibilityContractFixture(t, "")
		id := fixture.cfg.CompatibilityProjections[0].ID
		_, journal := fixtureYUMCompatibilityCutover(t, fixture, true)
		journal.Phase = yumCompatibilityCutoverCommitted
		writeYUMCompatibilityCrashJournal(t, yumCompatibilityCutoverJournalPath(fixture.cfg, id)+".next", journal)
		workflow := bindYUMCompatibilityRecoveryFixture(t, fixture)
		if err := recoverYUMCompatibilityCutoverJournalBound(workflow, fixture.canonical, id, true); err != nil {
			t.Fatalf("recover orphan committed phase: %v", err)
		}
		assertYUMCompatibilityServingLinkTarget(t, journal.ServingLink, journal.ToTarget)
		assertYUMCompatibilityCutoverJournalAbsent(t, fixture.cfg, id)
	})

	t.Run("orphan-committed-phase-without-canonical-event-fails-closed", func(t *testing.T) {
		fixture := newYUMCompatibilityContractFixture(t, "")
		id := fixture.cfg.CompatibilityProjections[0].ID
		_, journal := fixtureYUMCompatibilityCutover(t, fixture, false)
		journal.Phase = yumCompatibilityCutoverCommitted
		next := yumCompatibilityCutoverJournalPath(fixture.cfg, id) + ".next"
		writeYUMCompatibilityCrashJournal(t, next, journal)
		before, err := os.ReadFile(next)
		if err != nil {
			t.Fatal(err)
		}
		workflow := bindYUMCompatibilityRecoveryFixture(t, fixture)
		err = recoverYUMCompatibilityCutoverJournalBound(workflow, fixture.canonical, id, true)
		if err == nil || !strings.Contains(err.Error(), "no exact canonical event") {
			t.Fatalf("orphan committed phase without authority was accepted: %v", err)
		}
		assertYUMCompatibilityCrashJournalPreserved(t, next, before)
		if _, err := os.Lstat(journal.ServingLink); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unauthorized orphan journal changed serving link: %v", err)
		}
	})
}

func TestYUMCompatibilityBoundServingLinkPostFlipFailureRestoresPriorState(t *testing.T) {
	for _, previousExists := range []bool{false, true} {
		name := "previous-absent"
		if previousExists {
			name = "previous-link"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "repository")
			raw := filepath.Join(root, "raw")
			candidate := filepath.Join(root, "candidate")
			servingParent := filepath.Join(root, config.StateDirectory, "serving", "compatibility", "yum", "infra-legacy-x86-64")
			for _, directory := range []string{raw, candidate, servingParent} {
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			servingLink := filepath.Join(servingParent, "current")
			if previousExists {
				relative, err := filepath.Rel(servingParent, raw)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(relative, servingLink); err != nil {
					t.Fatal(err)
				}
			}
			lock, err := state.AcquireLock(filepath.Join(root, config.StateDirectory), "test-yum-link-post-flip-rollback", false)
			if err != nil {
				t.Fatal(err)
			}
			workflow := yumCompatibilityWorkflow{cfg: &config.Config{Root: root}}
			if err := workflow.bindMutationRoots(lock); err != nil {
				_ = lock.Release()
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := workflow.closeMutationRoots(); err != nil {
					t.Errorf("close bound YUM compatibility roots: %v", err)
				}
				if err := lock.Release(); err != nil {
					t.Errorf("release bound YUM compatibility lock: %v", err)
				}
			})
			workflow.mutationHook = func(phase string) error {
				switch phase {
				case "flip controlled compatibility serving link":
					return nil
				case "verify controlled compatibility serving link after flip":
					return errors.New("injected post-flip failure")
				default:
					return errors.New("unexpected mutation phase: " + phase)
				}
			}
			journal := yumCompatibilityCutoverJournal{ServingLink: servingLink, FromTarget: raw, ToTarget: candidate}
			err = reconcileYUMCompatibilityServingLinkBound(workflow, journal)
			if err == nil || !strings.Contains(err.Error(), "injected post-flip failure") {
				t.Fatalf("post-flip fault was not surfaced: %v", err)
			}
			if previousExists {
				assertYUMCompatibilityServingLinkTarget(t, servingLink, raw)
			} else if _, err := os.Lstat(servingLink); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("new serving link survived rollback: %v", err)
			}
		})
	}
}
