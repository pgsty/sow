//go:build perf

package perf_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/manifest"
)

func TestLargeRepositoryManifest(t *testing.T) {
	root := os.Getenv("SOW_PERF_ROOT")
	if root == "" {
		t.Fatal("SOW_PERF_ROOT must name the read-only large repository fixture")
	}
	workers := runtime.NumCPU()
	type fixture struct {
		name    string
		path    string
		include string
	}
	fixtures := []fixture{
		{name: "apt-deb", path: "apt", include: "**/*.deb"},
		{name: "yum-rpm", path: "yum", include: "**/*.rpm"},
	}
	var totalFiles, totalBytes int64
	start := time.Now()
	for _, fixture := range fixtures {
		dst := filepath.Join(t.TempDir(), fixture.name+".tsv")
		began := time.Now()
		stats, err := manifest.Scan(context.Background(), root, manifest.Scope{
			Path: fixture.path, Include: []string{fixture.include},
		}, dst, manifest.ScanOptions{
			Workers: workers, ChunkEntries: 2048, TempDir: t.TempDir(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("fixture=%s files=%d bytes=%d workers=%d elapsed=%s manifest=%s", fixture.name, stats.Files, stats.Bytes, workers, time.Since(began), dst)
		totalFiles += stats.Files
		totalBytes += stats.Bytes
	}
	if totalFiles < 50_000 {
		t.Fatalf("fixture has %d package files; need at least 50000", totalFiles)
	}
	t.Logf("total files=%d bytes=%d workers=%d elapsed=%s", totalFiles, totalBytes, workers, time.Since(start))
}
