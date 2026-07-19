//go:build perf

package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func TestIncrementalPublishPreflightFiftyThousandEntriesDoesNotReadView(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, "latest.tsv")
	file, err := os.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	buffer := bufio.NewWriterSize(file, 256*1024)
	digest := sha256.Sum256([]byte("payload"))
	for index := 0; index < 50_000; index++ {
		entry := views.Entry{
			Repo: "assets", OS: "all", Arch: "all", Name: fmt.Sprintf("asset-%05d", index), Version: "1",
			Path: fmt.Sprintf("pkg/%05d.bin", index), Size: 7, SHA256: hex.EncodeToString(digest[:]), Pool: "public",
		}
		if err := views.WriteEntry(buffer, entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := buffer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	viewPath, _ := state.ViewPath("latest", "assets", "all", "all")
	commit, _, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "50k latest")
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := state.ViewRef("latest", "assets", "all", "all")
	if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}
	parent := &pub.TargetGeneration{Refs: []pub.RefState{{Name: ref.String(), Commit: commit.String(), ManifestSHA256: strings.Repeat("a", 64)}}}
	repo := config.Repo{ID: "assets", Type: "asset", Path: "pkg", Asset: &config.AssetConfig{Kind: "test"}}
	cfg := &config.Config{Repos: []config.Repo{repo}}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	for range 100 {
		current, err := selectedPublicationRefCommitsCurrent(canonical, cfg, []config.Repo{repo}, "latest", "cf", config.View{}, commonFlags{}, parent)
		if err != nil || !current {
			t.Fatalf("preflight current=%v err=%v", current, err)
		}
	}
	elapsed := time.Since(started)
	runtime.GC()
	runtime.ReadMemStats(&after)
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("incremental-preflight entries=50000 iterations=100 elapsed=%s retained_heap_growth=%d", elapsed, growth)
	if elapsed > time.Second {
		t.Fatalf("50k ref-vector preflight took %s", elapsed)
	}
	if growth > 4<<20 {
		t.Fatalf("50k ref-vector preflight retained %d bytes", growth)
	}
}
