//go:build perf

package perf_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/publish"
)

func TestPublishPlanFiftyThousandOneChange(t *testing.T) {
	const entries = 50_000
	directory := t.TempDir()
	oldPath, newPath := directory+"/old.tsv", directory+"/new.tsv"
	oldFile, err := os.OpenFile(oldPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	newFile, err := os.OpenFile(newPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		oldFile.Close()
		t.Fatal(err)
	}
	for index := 0; index < entries; index++ {
		oldDigest := sha256.Sum256([]byte(fmt.Sprintf("old-%05d", index)))
		newDigest := oldDigest
		if index == entries/2 {
			newDigest = sha256.Sum256([]byte("the-only-changed-object"))
		}
		path := fmt.Sprintf("asset/%05d.bin", index)
		if err := manifest.WriteEntry(oldFile, manifest.Entry{Path: path, Size: 4096, SHA256: oldDigest}); err != nil {
			t.Fatal(err)
		}
		if err := manifest.WriteEntry(newFile, manifest.Entry{Path: path, Size: 4096, SHA256: newDigest}); err != nil {
			t.Fatal(err)
		}
	}
	if err := oldFile.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := newFile.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := oldFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := newFile.Close(); err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	oldReader, err := os.Open(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	newReader, err := os.Open(newPath)
	if err != nil {
		oldReader.Close()
		t.Fatal(err)
	}
	started := time.Now()
	plan, planErr := publish.BuildPlan(oldReader, newReader, func(entry manifest.Entry) (string, publish.ObjectClass, error) {
		return "objects/sha256/" + entry.HashString(), publish.ObjectImmutable, nil
	})
	closeErr := oldReader.Close()
	if err := newReader.Close(); closeErr == nil {
		closeErr = err
	}
	if planErr != nil || closeErr != nil {
		t.Fatalf("plan=%v close=%v", planErr, closeErr)
	}
	plan, err = plan.WithCDN("https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if len(plan.Objects) != 1 || len(plan.Verify) != 1 || len(plan.PurgeURLs) != 0 || plan.Stats.Changed != 1 || plan.Stats.Added != 0 || plan.Stats.Removed != 0 {
		t.Fatalf("plan is not O(change-set): objects=%d verify=%d purge=%d stats=%+v", len(plan.Objects), len(plan.Verify), len(plan.PurgeURLs), plan.Stats)
	}
	runtime.GC()
	var retained runtime.MemStats
	runtime.ReadMemStats(&retained)
	growth := uint64(0)
	if retained.HeapAlloc > baseline.HeapAlloc {
		growth = retained.HeapAlloc - baseline.HeapAlloc
	}
	t.Logf("publish-plan50k entries=%d changed=%d objects=%d elapsed=%s baseline_heap=%d retained_heap=%d growth=%d",
		entries, plan.Stats.Changed, len(plan.Objects), elapsed, baseline.HeapAlloc, retained.HeapAlloc, growth)
	if retained.HeapAlloc > 32<<20 || growth > 16<<20 {
		t.Fatalf("50k one-change plan retained unbounded heap: baseline=%d retained=%d growth=%d", baseline.HeapAlloc, retained.HeapAlloc, growth)
	}
}
