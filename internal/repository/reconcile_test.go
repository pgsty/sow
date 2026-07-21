package repository

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
)

func TestReconcileExactPrunesStaleFilesAndKeepsHardlinks(t *testing.T) {
	root := t.TempDir()
	store, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	object, err := store.Put(context.Background(), bytes.NewReader([]byte("wanted")))
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "desired.tsv")
	manifestFile, err := os.Create(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.WriteEntry(manifestFile, manifest.Entry{Path: "pkg/wanted", Size: object.Size, SHA256: object.SHA256}); err != nil {
		t.Fatal(err)
	}
	if err := manifestFile.Close(); err != nil {
		t.Fatal(err)
	}
	desired, err := os.Open(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Materialize(context.Background(), desired, "export"); err != nil {
		t.Fatal(err)
	}
	desired.Close()
	stale := filepath.Join(root, "export", "old", "stale")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := store.ReconcileExact(context.Background(), manifestPath, "export", 2, 2)
	if err != nil || result.RemovedFiles != 1 {
		t.Fatalf("reconcile removed=%d err=%v", result.RemovedFiles, err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale path remains: %v", err)
	}
	poolInfo, _ := os.Stat(store.ObjectPath(object.SHA256))
	targetInfo, _ := os.Stat(filepath.Join(root, "export", "pkg", "wanted"))
	if !os.SameFile(poolInfo, targetInfo) {
		t.Fatal("desired file is not a CAS hardlink")
	}
}

func TestReconcilePrunePreservesConcurrentPathReplacement(t *testing.T) {
	root := t.TempDir()
	stale := filepath.Join(root, "stale")
	if err := os.WriteFile(stale, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(root, "stale-scanned-backup")
	canary := filepath.Join(root, "reconcile-canary")
	if err := os.WriteFile(canary, []byte("CANARY"), 0o600); err != nil {
		t.Fatal(err)
	}

	replaced := false
	err := removeMaterializedPathWithHook(root, "stale", func(path string) error {
		replaced = true
		if path != stale {
			return errors.New("unexpected prune path")
		}
		if err := os.Rename(stale, backup); err != nil {
			return err
		}
		return os.Link(canary, stale)
	})
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("wanted inode-safe stale-path conflict, got %v", err)
	}
	if !replaced {
		t.Fatal("stale-path replacement hook was not invoked")
	}
	assertSameFile(t, canary, stale)
	body, readErr := os.ReadFile(backup)
	if readErr != nil || string(body) != "old" {
		t.Fatalf("scanned stale inode was not preserved: body=%q err=%v", body, readErr)
	}
}
