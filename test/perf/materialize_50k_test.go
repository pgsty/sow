//go:build perf

package perf_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
)

// TestMaterializeFiftyThousand exercises the production CAS verifier,
// parallel hardlink installer, full-tree scan, and exact reconciliation. One
// content object is intentionally referenced at 50,000 logical paths so the
// fixture measures metadata/link scalability without consuming package-sized
// disk space.
func TestMaterializeFiftyThousand(t *testing.T) {
	const (
		entries = 50_000
		workers = 8
	)
	root := t.TempDir()
	store, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	object, err := store.Put(context.Background(), bytes.NewReader(make([]byte, 4096)))
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(t.TempDir(), "desired.tsv")
	file, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < entries; index++ {
		entry := manifest.Entry{
			Path: fmt.Sprintf("repo/%03d/package-%05d.rpm", index/1000, index),
			Size: object.Size, SHA256: [32]byte(object.SHA256),
		}
		if err := manifest.WriteEntry(file, entry); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	input, err := os.Open(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	stats, materializeErr := store.MaterializeWithOptions(context.Background(), input, "export", repository.MaterializeOptions{Workers: workers})
	closeErr := input.Close()
	if materializeErr != nil || closeErr != nil {
		t.Fatalf("materialize=%v close=%v", materializeErr, closeErr)
	}
	materializeElapsed := time.Since(started)
	if stats.Entries != entries || stats.Linked != entries || stats.PeakWorkers < 2 || stats.PeakWorkers > workers {
		t.Fatalf("materialize stats=%+v", stats)
	}
	started = time.Now()
	reconciled, err := store.ReconcileExact(context.Background(), manifestPath, "export", workers, 1024)
	if err != nil || reconciled.RemovedFiles != 0 {
		t.Fatalf("reconcile=%+v err=%v", reconciled, err)
	}
	reconcileElapsed := time.Since(started)
	objectInfo, err := os.Stat(store.ObjectPath(object.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, entries / 2, entries - 1} {
		linked, err := os.Stat(filepath.Join(root, "export", fmt.Sprintf("repo/%03d/package-%05d.rpm", index/1000, index)))
		if err != nil || !os.SameFile(objectInfo, linked) {
			t.Fatalf("sample %d is not the CAS inode: %v", index, err)
		}
	}
	runtime.GC()
	var retained runtime.MemStats
	runtime.ReadMemStats(&retained)
	growth := uint64(0)
	if retained.HeapAlloc > baseline.HeapAlloc {
		growth = retained.HeapAlloc - baseline.HeapAlloc
	}
	t.Logf("materialize50k entries=%d workers=%d peak_workers=%d materialize=%s reconcile=%s baseline_heap=%d retained_heap=%d growth=%d",
		entries, workers, stats.PeakWorkers, materializeElapsed, reconcileElapsed, baseline.HeapAlloc, retained.HeapAlloc, growth)
	if retained.HeapAlloc > 64<<20 || growth > 48<<20 {
		t.Fatalf("50k materialization retained unbounded heap: baseline=%d retained=%d growth=%d", baseline.HeapAlloc, retained.HeapAlloc, growth)
	}
}
