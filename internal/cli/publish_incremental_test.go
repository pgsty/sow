package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

func TestIncrementalPublishPreflightRequiresExactRefCommit(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	viewPath, err := state.ViewPath("latest", "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "view.tsv")
	if err := os.WriteFile(stage, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, _, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "first")
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := state.ViewRef("latest", "assets", "all", "all")
	if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, first, false); err != nil {
		t.Fatal(err)
	}
	repo := config.Repo{ID: "assets", Type: "asset", Path: "pkg", Asset: &config.AssetConfig{Kind: "test"}}
	cfg := &config.Config{Repos: []config.Repo{repo}}
	parent := &pub.TargetGeneration{Refs: []pub.RefState{{Name: ref.String(), Commit: first.String(), ManifestSHA256: strings.Repeat("a", 64)}}}
	current, err := selectedPublicationRefCommitsCurrent(canonical, cfg, []config.Repo{repo}, "latest", "cf", config.View{}, commonFlags{}, parent)
	if err != nil || !current {
		t.Fatalf("matching ref current=%v err=%v", current, err)
	}

	if err := os.WriteFile(stage, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, _, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "second")
	if err != nil {
		t.Fatal(err)
	}
	if err := canonical.AdvanceRef(ref, first, second, false); err != nil {
		t.Fatal(err)
	}
	current, err = selectedPublicationRefCommitsCurrent(canonical, cfg, []config.Repo{repo}, "latest", "cf", config.View{}, commonFlags{}, parent)
	if err != nil || current {
		t.Fatalf("moved ref current=%v err=%v", current, err)
	}
}

func TestIncrementalStablePreflightFallsBackWhenSnapshotExpires(t *testing.T) {
	now := time.Date(2026, time.July, 12, 0, 0, 0, 0, time.UTC)
	parent := &pub.TargetGeneration{Refs: []pub.RefState{{
		Name: "refs/sow/snapshots/jammy-20260711/repo/el9/x86_64",
	}}}
	current, err := publishedSnapshotRetentionCurrent(parent, now, 6)
	if err != nil || !current {
		t.Fatalf("recent snapshot current=%v err=%v", current, err)
	}
	parent.Refs[0].Name = "refs/sow/snapshots/jammy-20250101/repo/el9/x86_64"
	current, err = publishedSnapshotRetentionCurrent(parent, now, 6)
	if err != nil || current {
		t.Fatalf("expired snapshot current=%v err=%v", current, err)
	}
}
