package repository

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestCASPutOpenVerifyAndDeduplicate(t *testing.T) {
	root := t.TempDir()
	store := newTestStore(t, root)
	object, err := store.Put(context.Background(), strings.NewReader("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(store.Root(), ".pool", "sha256", object.HashString()[:2], object.HashString())
	if store.ObjectPath(object.SHA256) != wantPath {
		t.Fatalf("path=%q want=%q", store.ObjectPath(object.SHA256), wantPath)
	}
	if err := store.Verify(context.Background(), object); err != nil {
		t.Fatal(err)
	}
	file, err := store.Open(object.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || string(body) != "alpha" {
		t.Fatalf("body=%q readErr=%v closeErr=%v", body, readErr, closeErr)
	}

	again, err := store.Put(context.Background(), strings.NewReader("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if again != object {
		t.Fatalf("second put=%#v want=%#v", again, object)
	}
	if count := countPoolObjects(t, store); count != 1 {
		t.Fatalf("pool objects=%d want=1", count)
	}
}

func TestCASConcurrentPutIsAtomicAndIdempotent(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	const workers = 32
	objects := make(chan Object, workers)
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			object, err := store.Put(context.Background(), strings.NewReader(strings.Repeat("concurrent-data", 1024)))
			if err != nil {
				errorsFound <- err
				return
			}
			objects <- object
		}()
	}
	wait.Wait()
	close(objects)
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
	var first Object
	for object := range objects {
		if first.Size == 0 {
			first = object
		} else if object != first {
			t.Fatalf("objects differ: %#v %#v", first, object)
		}
	}
	if err := store.Verify(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if count := countPoolObjects(t, store); count != 1 {
		t.Fatalf("pool objects=%d want=1", count)
	}
}

func TestCASNeverOverwritesOccupiedCoordinate(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	object, err := store.Put(context.Background(), strings.NewReader("good"))
	if err != nil {
		t.Fatal(err)
	}
	path := store.ObjectPath(object.SHA256)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("evil"), 0o444); err != nil {
		t.Fatal(err)
	}
	_, err = store.Put(context.Background(), strings.NewReader("good"))
	if !errors.Is(err, ErrObjectConflict) {
		t.Fatalf("wanted object conflict, got %v", err)
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil || string(body) != "evil" {
		t.Fatalf("occupied coordinate was changed: body=%q err=%v", body, readErr)
	}
	if err := store.Verify(context.Background(), object); !errors.Is(err, ErrObjectCorrupt) {
		t.Fatalf("wanted corruption error, got %v", err)
	}
}

func TestCASFailedStreamLeavesNoObject(t *testing.T) {
	store := newTestStore(t, t.TempDir())
	_, err := store.Put(context.Background(), failingReader{})
	if err == nil || !strings.Contains(err.Error(), "injected read failure") {
		t.Fatalf("wanted injected error, got %v", err)
	}
	if count := countPoolObjects(t, store); count != 0 {
		t.Fatalf("pool objects=%d want=0", count)
	}
}

func TestCASImportRejectsSymlinkAndImportsRegularFile(t *testing.T) {
	root := t.TempDir()
	store := newTestStore(t, root)
	source := filepath.Join(root, "source.rpm")
	if err := os.WriteFile(source, []byte("package"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "source-link.rpm")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Import(context.Background(), link); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted unsafe path error, got %v", err)
	}
	if _, err := store.Import(context.Background(), root); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted special-file rejection, got %v", err)
	}
	object, err := store.Import(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Verify(context.Background(), object); err != nil {
		t.Fatal(err)
	}
}

func TestCASImportExpectedRejectsWrongIdentityBeforeInstallation(t *testing.T) {
	root := t.TempDir()
	store := newTestStore(t, root)
	body := []byte("authenticated-package")
	source := filepath.Join(root, "source.deb")
	if err := os.WriteFile(source, body, 0o644); err != nil {
		t.Fatal(err)
	}
	wrongSum := sha256.Sum256([]byte("substituted-package-"))
	wrong := Object{SHA256: Digest(wrongSum), Size: int64(len(body))}
	if _, err := store.ImportExpected(context.Background(), source, wrong); !errors.Is(err, ErrObjectCorrupt) {
		t.Fatalf("wrong authenticated identity error=%v", err)
	}
	if count := countPoolObjects(t, store); count != 0 {
		t.Fatalf("rejected source installed %d orphan CAS objects", count)
	}
	wantedSum := sha256.Sum256(body)
	wanted := Object{SHA256: Digest(wantedSum), Size: int64(len(body))}
	object, err := store.ImportExpected(context.Background(), source, wanted)
	if err != nil || object != wanted {
		t.Fatalf("expected import object=%#v err=%v", object, err)
	}
	if err := store.Verify(context.Background(), wanted); err != nil {
		t.Fatal(err)
	}
}

func TestCASImportExpectedReusesVerifiedObjectWithoutStaging(t *testing.T) {
	root := t.TempDir()
	store := newTestStore(t, root)
	body := []byte("already-imported-package")
	source := filepath.Join(root, "source.rpm")
	if err := os.WriteFile(source, body, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	expected := Object{SHA256: Digest(sum), Size: int64(len(body))}
	if _, err := store.ImportExpected(context.Background(), source, expected); err != nil {
		t.Fatal(err)
	}

	// A replay of a verified object must not need a throwaway CAS staging file.
	// Keep the directory searchable but make ordinary writes fail on Linux and
	// macOS; the entry-count assertion also catches staging on privileged runs.
	if err := os.Chmod(store.tempRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(store.tempRoot, 0o700) })
	entriesBefore, err := os.ReadDir(store.tempRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportExpected(context.Background(), source, expected); err != nil {
		t.Fatalf("idempotent import required staging: %v", err)
	}
	entriesAfter, err := os.ReadDir(store.tempRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entriesAfter) != len(entriesBefore) {
		t.Fatalf("idempotent import changed staging entries: before=%d after=%d", len(entriesBefore), len(entriesAfter))
	}

	changed := []byte("already-imported-packagf")
	if len(changed) != len(body) {
		t.Fatalf("test fixture changed size: %d != %d", len(changed), len(body))
	}
	if err := os.WriteFile(source, changed, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportExpected(context.Background(), source, expected); !errors.Is(err, ErrObjectCorrupt) {
		t.Fatalf("changed source error=%v", err)
	}

	if err := os.Chmod(store.ObjectPath(expected.SHA256), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.ObjectPath(expected.SHA256), body[:len(body)-1], 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportExpected(context.Background(), source, expected); !errors.Is(err, ErrObjectCorrupt) {
		t.Fatalf("corrupt occupied coordinate error=%v", err)
	}
}

func TestCASRejectsSymlinkedPool(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".pool")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(root); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted unsafe pool error, got %v", err)
	}
}

func TestOpenStoreIsReadOnlyAndRejectsPoolReplacement(t *testing.T) {
	root := t.TempDir()
	if opened, err := OpenStore(root); err == nil {
		_ = opened.Close()
		t.Fatal("read-only open accepted a missing CAS")
	}
	if _, err := os.Lstat(filepath.Join(root, ".pool")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only open created a pool: %v", err)
	}

	writable := newTestStore(t, root)
	object, err := writable.Put(context.Background(), strings.NewReader("read-only object"))
	if err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(writable.PoolRoot(), ".tmp")
	if err := os.Remove(temp); err != nil {
		t.Fatal(err)
	}
	readOnly, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = readOnly.Close() })
	if err := readOnly.Verify(context.Background(), object); err != nil {
		t.Fatalf("read-only verification: %v", err)
	}
	if _, err := os.Lstat(temp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only verification recreated .tmp: %v", err)
	}
	if _, err := readOnly.Put(context.Background(), strings.NewReader("forbidden")); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("read-only store accepted mutation: %v", err)
	}

	poolRoot := writable.PoolRoot()
	displaced := poolRoot + "-displaced"
	if err := os.Rename(poolRoot, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(poolRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := readOnly.Verify(context.Background(), object); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("read-only store accepted replaced pool: %v", err)
	}
}

func TestOpenStoreRejectsSymlinkedExistingComponents(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".pool")); err != nil {
		t.Fatal(err)
	}
	if opened, err := OpenStore(root); !errors.Is(err, ErrUnsafePath) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("read-only open accepted symlinked pool parent: %v", err)
	}
}

type failingReader struct{ sent bool }

func (r failingReader) Read(buffer []byte) (int, error) {
	if !r.sent {
		copy(buffer, "partial")
		return len("partial"), fmt.Errorf("injected read failure")
	}
	return 0, io.EOF
}

func newTestStore(t *testing.T, root string) *Store {
	t.Helper()
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func countPoolObjects(t *testing.T, store *Store) int {
	t.Helper()
	count := 0
	entries, err := os.ReadDir(store.PoolRoot())
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range entries {
		if shard.Name() == ".tmp" {
			continue
		}
		objects, err := os.ReadDir(filepath.Join(store.PoolRoot(), shard.Name()))
		if err != nil {
			t.Fatal(err)
		}
		count += len(objects)
	}
	return count
}
