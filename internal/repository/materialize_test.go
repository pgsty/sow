package repository

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
)

func TestMaterializeCreatesOnlyHardlinksAndIsIdempotent(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	alpha := putString(t, store, "alpha")
	beta := putString(t, store, "beta")
	copyPath := filepath.Join(store.Root(), "apt", "copy.pkg")
	if err := os.MkdirAll(filepath.Dir(copyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}

	content := manifestBytes(t,
		manifest.Entry{Path: "apt/alpha.pkg", Size: alpha.Size, SHA256: [32]byte(alpha.SHA256)},
		manifest.Entry{Path: "apt/copy.pkg", Size: alpha.Size, SHA256: [32]byte(alpha.SHA256)},
		manifest.Entry{Path: "yum/beta.rpm", Size: beta.Size, SHA256: [32]byte(beta.SHA256)},
	)
	stats, err := store.Materialize(context.Background(), bytes.NewReader(content), "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Entries != 3 || stats.Linked != 2 || stats.Relinked != 1 || stats.Existing != 0 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	assertSameFile(t, store.ObjectPath(alpha.SHA256), filepath.Join(store.Root(), "apt", "alpha.pkg"))
	assertSameFile(t, store.ObjectPath(alpha.SHA256), copyPath)
	assertSameFile(t, store.ObjectPath(beta.SHA256), filepath.Join(store.Root(), "yum", "beta.rpm"))

	stats, err = store.Materialize(context.Background(), bytes.NewReader(content), "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Entries != 3 || stats.Existing != 3 || stats.Linked != 0 || stats.Relinked != 0 {
		t.Fatalf("idempotent stats: %#v", stats)
	}
}

func TestMaterializeRejectsDifferentExistingContent(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	destination := filepath.Join(store.Root(), "repo", "package")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("wrong!"), 0o644); err != nil {
		t.Fatal(err)
	}
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})
	_, err := store.Materialize(context.Background(), bytes.NewReader(content), "")
	if !errors.Is(err, ErrMaterializeConflict) {
		t.Fatalf("wanted conflict, got %v", err)
	}
	body, readErr := os.ReadFile(destination)
	if readErr != nil || string(body) != "wrong!" {
		t.Fatalf("conflicting destination changed: body=%q err=%v", body, readErr)
	}
}

func TestMaterializeRejectsTraversalReservedAndSymlinkPaths(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "x")
	hash := object.HashString()
	unsafeManifests := []string{
		fmt.Sprintf("../escape\t1\t%s\n", hash),
		fmt.Sprintf("/absolute\t1\t%s\n", hash),
		fmt.Sprintf(".pool/replace\t1\t%s\n", hash),
		fmt.Sprintf(".sow/replace\t1\t%s\n", hash),
	}
	for _, content := range unsafeManifests {
		if _, err := store.Materialize(context.Background(), strings.NewReader(content), ""); err == nil {
			t.Fatalf("unsafe manifest accepted: %q", content)
		}
	}
	if _, err := os.Stat(filepath.Join(store.Root(), "..", "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("traversal created an outside file: %v", err)
	}

	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(store.Root(), "repo")); err != nil {
		t.Fatal(err)
	}
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})
	if _, err := store.Materialize(context.Background(), bytes.NewReader(content), ""); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted symlink rejection, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "package")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink traversal wrote outside root: %v", err)
	}
}

func TestMaterializeRejectsSpecialDestinationAndOutsideTarget(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "x")
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})
	if err := os.MkdirAll(filepath.Join(store.Root(), "repo", "package"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Materialize(context.Background(), bytes.NewReader(content), ""); !errors.Is(err, ErrMaterializeConflict) {
		t.Fatalf("wanted special-file conflict, got %v", err)
	}
	if _, err := store.Materialize(context.Background(), bytes.NewReader(content), t.TempDir()); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted outside target rejection, got %v", err)
	}
	if _, err := store.Materialize(context.Background(), bytes.NewReader(content), filepath.Join(".pool", "target")); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted pool target rejection, got %v", err)
	}
}

func TestMaterializeBoundsAndUsesParallelWorkers(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	body := bytes.Repeat([]byte("parallel-materialization\n"), 32*1024)
	object, err := store.Put(context.Background(), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]manifest.Entry, 32)
	for index := range entries {
		entries[index] = manifest.Entry{
			Path: fmt.Sprintf("repo/%02d/package.rpm", index), Size: object.Size,
			SHA256: [32]byte(object.SHA256),
		}
	}
	stats, err := store.MaterializeWithOptions(context.Background(), bytes.NewReader(manifestBytes(t, entries...)), "export", MaterializeOptions{Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Entries != int64(len(entries)) || stats.Linked != int64(len(entries)) || stats.PeakWorkers < 2 || stats.PeakWorkers > 4 {
		t.Fatalf("parallel materialization stats=%+v", stats)
	}
	if _, err := store.MaterializeWithOptions(context.Background(), bytes.NewReader(manifestBytes(t, entries...)), "other", MaterializeOptions{Workers: 1025}); err == nil {
		t.Fatal("unbounded worker count was accepted")
	}
}

func TestMaterializePropagatesFinalDescriptorFailures(t *testing.T) {
	for _, fixture := range []struct {
		name  string
		phase materializeTestPhase
	}{
		{name: "parent-cache", phase: materializeTestAfterParentCacheClose},
		{name: "binding", phase: materializeTestAfterBindingClose},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			store := newTestStore(t, t.TempDir())
			object := putString(t, store, "durable")
			content := manifestBytes(t, manifest.Entry{
				Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256),
			})
			injected := errors.New("injected final descriptor failure")
			stats, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{Workers: 1},
				func(phase materializeTestPhase, _, _ string) error {
					if phase == fixture.phase {
						return injected
					}
					return nil
				},
			)
			if !errors.Is(err, injected) {
				t.Fatalf("materialization swallowed final descriptor failure: stats=%+v err=%v", stats, err)
			}
			if stats.Entries != 1 || stats.Linked != 1 {
				t.Fatalf("final descriptor failure lost completed work accounting: %+v", stats)
			}
			assertSameFile(t, store.ObjectPath(object.SHA256), filepath.Join(store.Root(), "repo", "package"))
		})
	}
}

func TestMaterializePreservesPrimaryAndFinalDescriptorFailures(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	destination := filepath.Join(store.Root(), "repo", "package")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("wrong!"), 0o644); err != nil {
		t.Fatal(err)
	}
	content := manifestBytes(t, manifest.Entry{
		Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256),
	})
	injected := errors.New("injected parent-cache close failure")
	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{Workers: 1},
		func(phase materializeTestPhase, _, _ string) error {
			if phase == materializeTestAfterParentCacheClose {
				return injected
			}
			return nil
		},
	)
	if !errors.Is(err, ErrMaterializeConflict) || !errors.Is(err, injected) {
		t.Fatalf("materialization did not preserve primary and teardown failures: %v", err)
	}
}

func TestMaterializeRejectsCASCoordinateSwapBeforeNewDestinationLink(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	source := store.ObjectPath(object.SHA256)
	backup := source + ".verified-backup"
	canary := filepath.Join(store.Root(), "same-size-canary")
	if err := os.WriteFile(canary, []byte("CANARY"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(store.Root(), "repo", "package")
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})

	swapped := false
	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{Workers: 1},
		func(phase materializeTestPhase, hookSource, hookDestination string) error {
			if phase != materializeTestBeforeDirectLink || swapped {
				return nil
			}
			swapped = true
			if hookSource != source || hookDestination != destination {
				return fmt.Errorf("unexpected hook paths source=%q destination=%q", hookSource, hookDestination)
			}
			return swapCASCoordinateForMaterializeTest(source, backup, canary)
		},
	)
	if !errors.Is(err, ErrObjectCorrupt) {
		t.Fatalf("wanted fail-closed CAS corruption error, got %v", err)
	}
	if !swapped {
		t.Fatal("CAS coordinate swap hook was not invoked")
	}
	if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unauthorized new destination link remains: %v", statErr)
	}
	assertMaterializeCanaryAndNoTemporaryLinks(t, canary, filepath.Dir(destination))
}

func TestMaterializeRejectsCASCoordinateSwapBeforeReplacementLink(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	source := store.ObjectPath(object.SHA256)
	backup := source + ".verified-backup"
	canary := filepath.Join(store.Root(), "same-size-canary")
	if err := os.WriteFile(canary, []byte("CANARY"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(store.Root(), "repo", "package")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("legacy"), 0o644); err != nil {
		t.Fatal(err)
	}
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})

	swapped := false
	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{
		Workers:          1,
		AllowReplacePath: func(string) bool { return true },
	}, func(phase materializeTestPhase, hookSource, hookDestination string) error {
		if phase != materializeTestBeforeReplacementLink || swapped {
			return nil
		}
		swapped = true
		if hookSource != source || hookDestination != destination {
			return fmt.Errorf("unexpected hook paths source=%q destination=%q", hookSource, hookDestination)
		}
		return swapCASCoordinateForMaterializeTest(source, backup, canary)
	},
	)
	if !errors.Is(err, ErrObjectCorrupt) {
		t.Fatalf("wanted fail-closed CAS corruption error, got %v", err)
	}
	if !swapped {
		t.Fatal("CAS coordinate swap hook was not invoked")
	}
	body, readErr := os.ReadFile(destination)
	if readErr != nil || string(body) != "legacy" {
		t.Fatalf("replacement destination changed after rejected CAS swap: body=%q err=%v", body, readErr)
	}
	assertMaterializeCanaryAndNoTemporaryLinks(t, canary, filepath.Dir(destination))
}

func TestMaterializeRejectsBoundParentReplacementWithoutWritingEitherTree(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	destination := filepath.Join(store.Root(), "repo", "package")
	parent := filepath.Dir(destination)
	boundParent := parent + ".bound-aside"
	canary := filepath.Join(parent, "CANARY")
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})

	swapped := false
	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{Workers: 1},
		func(phase materializeTestPhase, _, hookDestination string) error {
			if phase != materializeTestBeforeDirectLink || swapped {
				return nil
			}
			swapped = true
			if hookDestination != destination {
				return fmt.Errorf("unexpected destination %q", hookDestination)
			}
			if err := os.Rename(parent, boundParent); err != nil {
				return err
			}
			if err := os.Mkdir(parent, 0o755); err != nil {
				return err
			}
			return os.WriteFile(canary, []byte("CANARY"), 0o600)
		},
	)
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted bound-parent replacement rejection, got %v", err)
	}
	if !swapped {
		t.Fatal("parent replacement hook was not invoked")
	}
	for _, name := range []string{destination, filepath.Join(boundParent, "package")} {
		if _, statErr := os.Lstat(name); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("parent race left destination %q: %v", name, statErr)
		}
	}
	body, readErr := os.ReadFile(canary)
	if readErr != nil || string(body) != "CANARY" {
		t.Fatalf("replacement-parent canary changed: body=%q err=%v", body, readErr)
	}
	assertNoMaterializeTransactionNames(t, parent)
	assertNoMaterializeTransactionNames(t, boundParent)
}

func TestMaterializeExchangePreservesConcurrentDestinationReplacement(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	destination := filepath.Join(store.Root(), "repo", "package")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("legacy"), 0o644); err != nil {
		t.Fatal(err)
	}
	legacyBackup := filepath.Join(store.Root(), "legacy-destination-backup")
	canary := filepath.Join(store.Root(), "destination-race-canary")
	if err := os.WriteFile(canary, []byte("CANARY"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})

	swapped := false
	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{
		Workers: 1, AllowReplacePath: func(string) bool { return true },
	}, func(phase materializeTestPhase, _, hookDestination string) error {
		if phase != materializeTestBeforeReplacementExchange || swapped {
			return nil
		}
		swapped = true
		if hookDestination != destination {
			return fmt.Errorf("unexpected destination %q", hookDestination)
		}
		if err := os.Rename(destination, legacyBackup); err != nil {
			return err
		}
		return os.Link(canary, destination)
	})
	if !errors.Is(err, ErrMaterializeConflict) {
		t.Fatalf("wanted concurrent destination conflict, got %v", err)
	}
	if !swapped {
		t.Fatal("destination replacement hook was not invoked")
	}
	assertSameFile(t, canary, destination)
	body, readErr := os.ReadFile(legacyBackup)
	if readErr != nil || string(body) != "legacy" {
		t.Fatalf("original destination was not preserved: body=%q err=%v", body, readErr)
	}
	assertMaterializeCanaryAndNoTemporaryLinks(t, canary, filepath.Dir(destination))
}

func TestMaterializeFailureCleanupRemovesOwnedTemporary(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	destination := filepath.Join(store.Root(), "repo", "package")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("legacy"), 0o644); err != nil {
		t.Fatal(err)
	}
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})
	injected := errors.New("injected failure after replacement proof")

	var temporary string
	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{
		Workers: 1, AllowReplacePath: func(string) bool { return true },
	}, func(phase materializeTestPhase, source, _ string) error {
		if phase != materializeTestAfterReplacementTempProof {
			return nil
		}
		temporary = source
		return injected
	})
	if !errors.Is(err, injected) || errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted primary failure with successful owned cleanup, got %v", err)
	}
	if temporary == "" {
		t.Fatal("post-proof failure hook was not invoked")
	}
	if _, statErr := os.Lstat(temporary); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("owned replacement temporary survived failure cleanup: %v", statErr)
	}
	body, readErr := os.ReadFile(destination)
	if readErr != nil || string(body) != "legacy" {
		t.Fatalf("destination changed before failed replacement: body=%q err=%v", body, readErr)
	}
	assertNoMaterializeTransactionNames(t, filepath.Dir(destination))
}

func TestMaterializeFailureCleanupPreservesConcurrentTemporaryReplacement(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	destination := filepath.Join(store.Root(), "repo", "package")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("legacy"), 0o644); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(store.Root(), "temporary-cleanup-canary")
	if err := os.WriteFile(canary, []byte("CANARY"), 0o600); err != nil {
		t.Fatal(err)
	}
	savedVerifiedLink := filepath.Join(store.Root(), "saved-cleanup-verified-link")
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})
	injected := errors.New("injected failure after replacement proof")

	var replacedTemporary string
	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{
		Workers: 1, AllowReplacePath: func(string) bool { return true },
	}, func(phase materializeTestPhase, temporary, _ string) error {
		if phase != materializeTestAfterReplacementTempProof || replacedTemporary != "" {
			return nil
		}
		replacedTemporary = temporary
		if err := os.Rename(temporary, savedVerifiedLink); err != nil {
			return err
		}
		if err := os.Link(canary, temporary); err != nil {
			return err
		}
		return injected
	})
	if !errors.Is(err, injected) || !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted primary failure plus inode-safe cleanup rejection, got %v", err)
	}
	if replacedTemporary == "" {
		t.Fatal("post-proof temporary replacement hook was not invoked")
	}
	assertSameFile(t, canary, replacedTemporary)
	assertSameFile(t, store.ObjectPath(object.SHA256), savedVerifiedLink)
	body, readErr := os.ReadFile(destination)
	if readErr != nil || string(body) != "legacy" {
		t.Fatalf("destination changed before rejected cleanup: body=%q err=%v", body, readErr)
	}
}

func TestMaterializeExchangeRejectsTemporaryReplacementBeforeInstall(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	destination := filepath.Join(store.Root(), "repo", "package")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("legacy"), 0o644); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(store.Root(), "temporary-race-canary")
	if err := os.WriteFile(canary, []byte("CANARY"), 0o600); err != nil {
		t.Fatal(err)
	}
	savedVerifiedLink := filepath.Join(store.Root(), "saved-verified-temporary")
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})

	swapped := false
	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{
		Workers: 1, AllowReplacePath: func(string) bool { return true },
	}, func(phase materializeTestPhase, temporary, _ string) error {
		if phase != materializeTestBeforeReplacementExchange || swapped {
			return nil
		}
		swapped = true
		if err := os.Rename(temporary, savedVerifiedLink); err != nil {
			return err
		}
		return os.Link(canary, temporary)
	})
	if !errors.Is(err, ErrMaterializeConflict) {
		t.Fatalf("wanted temporary replacement conflict, got %v", err)
	}
	if !swapped {
		t.Fatal("temporary replacement hook was not invoked")
	}
	body, readErr := os.ReadFile(destination)
	if readErr != nil || string(body) != "legacy" {
		t.Fatalf("destination changed after rejected temporary swap: body=%q err=%v", body, readErr)
	}
	body, readErr = os.ReadFile(canary)
	if readErr != nil || string(body) != "CANARY" {
		t.Fatalf("temporary replacement canary changed: body=%q err=%v", body, readErr)
	}
	assertNoMaterializeTransactionNames(t, filepath.Dir(destination))
}

func TestMaterializeExchangeRollsBackSymlinkTemporaryWithoutFollowingIt(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	destination := filepath.Join(store.Root(), "repo", "package")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("legacy"), 0o644); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(store.Root(), "symlink-target-canary")
	if err := os.WriteFile(canary, []byte("CANARY"), 0o600); err != nil {
		t.Fatal(err)
	}
	savedVerifiedLink := filepath.Join(store.Root(), "saved-symlink-race-link")
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})

	swapped := false
	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{
		Workers: 1, AllowReplacePath: func(string) bool { return true },
	}, func(phase materializeTestPhase, temporary, _ string) error {
		if phase != materializeTestBeforeReplacementExchange || swapped {
			return nil
		}
		swapped = true
		if err := os.Rename(temporary, savedVerifiedLink); err != nil {
			return err
		}
		return os.Symlink(canary, temporary)
	})
	if !errors.Is(err, ErrMaterializeConflict) {
		t.Fatalf("wanted symlink temporary conflict, got %v", err)
	}
	body, readErr := os.ReadFile(destination)
	if readErr != nil || string(body) != "legacy" {
		t.Fatalf("destination changed after symlink temporary race: body=%q err=%v", body, readErr)
	}
	body, readErr = os.ReadFile(canary)
	if readErr != nil || string(body) != "CANARY" {
		t.Fatalf("symlink target canary changed: body=%q err=%v", body, readErr)
	}
	assertNoMaterializeTransactionNames(t, filepath.Dir(destination))
}

func TestMaterializeCleanupDoesNotDeleteConcurrentDestinationReplacement(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	destination := filepath.Join(store.Root(), "repo", "package")
	createdBackup := filepath.Join(store.Root(), "created-link-backup")
	canary := filepath.Join(store.Root(), "cleanup-race-canary")
	if err := os.WriteFile(canary, []byte("CANARY"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})

	swapped := false
	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{Workers: 1},
		func(phase materializeTestPhase, _, hookDestination string) error {
			if phase != materializeTestAfterDirectLink || swapped {
				return nil
			}
			swapped = true
			if hookDestination != destination {
				return fmt.Errorf("unexpected destination %q", hookDestination)
			}
			if err := os.Rename(destination, createdBackup); err != nil {
				return err
			}
			return os.Link(canary, destination)
		},
	)
	if !errors.Is(err, ErrObjectCorrupt) || !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted corruption plus inode-safe cleanup rejection, got %v", err)
	}
	assertSameFile(t, canary, destination)
	assertSameFile(t, store.ObjectPath(object.SHA256), createdBackup)
	assertMaterializeCanaryAndNoTemporaryLinks(t, canary, filepath.Dir(destination))
}

func TestMaterializeDetectsInPlaceCASRewriteAndRemovesItsNewLink(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	source := store.ObjectPath(object.SHA256)
	destination := filepath.Join(store.Root(), "repo", "package")
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})

	rewritten := false
	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{Workers: 1},
		func(phase materializeTestPhase, hookSource, _ string) error {
			if phase != materializeTestBeforeDirectLink || rewritten {
				return nil
			}
			rewritten = true
			if hookSource != source {
				return fmt.Errorf("unexpected source %q", hookSource)
			}
			if err := os.Chmod(source, 0o644); err != nil {
				return err
			}
			return os.WriteFile(source, []byte("RACED!"), 0o644)
		},
	)
	if !errors.Is(err, ErrObjectCorrupt) {
		t.Fatalf("wanted in-place CAS corruption rejection, got %v", err)
	}
	if !rewritten {
		t.Fatal("in-place rewrite hook was not invoked")
	}
	if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("link to rewritten CAS inode remains: %v", statErr)
	}
	assertNoMaterializeTransactionNames(t, filepath.Dir(destination))
}

func TestMaterializeClassifiesDisappearedCASCoordinateAsCorrupt(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	source := store.ObjectPath(object.SHA256)
	backup := source + ".disappeared"
	destination := filepath.Join(store.Root(), "repo", "package")
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})

	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{Workers: 1},
		func(phase materializeTestPhase, _, _ string) error {
			if phase != materializeTestBeforeDirectLink {
				return nil
			}
			return os.Rename(source, backup)
		},
	)
	if !errors.Is(err, ErrObjectCorrupt) {
		t.Fatalf("wanted disappeared CAS coordinate to be corrupt, got %v", err)
	}
	if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination exists after disappeared CAS coordinate: %v", statErr)
	}
	body, readErr := os.ReadFile(backup)
	if readErr != nil || string(body) != "wanted" {
		t.Fatalf("retained CAS inode was not preserved: body=%q err=%v", body, readErr)
	}
	assertNoMaterializeTransactionNames(t, filepath.Dir(destination))
}

func TestMaterializeClassifiesReplacedCASShardAsCorrupt(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object := putString(t, store, "wanted")
	source := store.ObjectPath(object.SHA256)
	shard := filepath.Dir(source)
	boundShard := shard + ".bound-aside"
	canary := filepath.Join(store.Root(), "same-size-shard-canary")
	if err := os.WriteFile(canary, []byte("CANARY"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(store.Root(), "repo", "package")
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})

	replaced := false
	_, err := store.materializeWithOptions(context.Background(), bytes.NewReader(content), "", MaterializeOptions{Workers: 1},
		func(phase materializeTestPhase, _, _ string) error {
			if phase != materializeTestBeforeDirectLink || replaced {
				return nil
			}
			replaced = true
			if err := os.Rename(shard, boundShard); err != nil {
				return err
			}
			if err := os.Mkdir(shard, 0o755); err != nil {
				return err
			}
			return os.Link(canary, source)
		},
	)
	if !errors.Is(err, ErrObjectCorrupt) {
		t.Fatalf("wanted replaced CAS shard to be corrupt, got %v", err)
	}
	if !replaced {
		t.Fatal("CAS shard replacement hook was not invoked")
	}
	if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination exists after CAS shard replacement: %v", statErr)
	}
	assertSameFile(t, canary, source)
	body, readErr := os.ReadFile(filepath.Join(boundShard, object.HashString()))
	if readErr != nil || string(body) != "wanted" {
		t.Fatalf("bound verified shard was not preserved: body=%q err=%v", body, readErr)
	}
	assertNoMaterializeTransactionNames(t, filepath.Dir(destination))
}

func TestMaterializeReadOnlyStoreDoesNotCreateTarget(t *testing.T) {
	root := t.TempDir()
	writable := newTestStore(t, root)
	object := putString(t, writable, "wanted")
	readOnly, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = readOnly.Close() })
	content := manifestBytes(t, manifest.Entry{Path: "repo/package", Size: object.Size, SHA256: [32]byte(object.SHA256)})
	target := filepath.Join(root, "export")
	if _, err := readOnly.Materialize(context.Background(), bytes.NewReader(content), "export"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted read-only materialization rejection, got %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only materialization created target %q: %v", target, err)
	}
}

func swapCASCoordinateForMaterializeTest(source, backup, canary string) error {
	if err := os.Rename(source, backup); err != nil {
		return fmt.Errorf("move verified CAS inode aside: %w", err)
	}
	if err := os.Link(canary, source); err != nil {
		return fmt.Errorf("install same-size replacement CAS coordinate: %w", err)
	}
	return nil
}

func assertMaterializeCanaryAndNoTemporaryLinks(t *testing.T, canary, directory string) {
	t.Helper()
	body, err := os.ReadFile(canary)
	if err != nil || string(body) != "CANARY" {
		t.Fatalf("canary changed: body=%q err=%v", body, err)
	}
	assertNoMaterializeTransactionNames(t, directory)
}

func assertNoMaterializeTransactionNames(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".sow-materialize-") {
			t.Fatalf("materialization transaction residue remains: %q", filepath.Join(directory, entry.Name()))
		}
	}
}

func putString(t *testing.T, store *Store, body string) Object {
	t.Helper()
	object, err := store.Put(context.Background(), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func manifestBytes(t *testing.T, entries ...manifest.Entry) []byte {
	t.Helper()
	var result bytes.Buffer
	for _, entry := range entries {
		if err := manifest.WriteEntry(&result, entry); err != nil {
			t.Fatal(err)
		}
	}
	return result.Bytes()
}

func assertSameFile(t *testing.T, left, right string) {
	t.Helper()
	leftInfo, err := os.Stat(left)
	if err != nil {
		t.Fatal(err)
	}
	rightInfo, err := os.Stat(right)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(leftInfo, rightInfo) {
		t.Fatalf("%q and %q are not the same inode", left, right)
	}
}
