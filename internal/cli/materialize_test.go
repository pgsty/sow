package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func TestMaterializeCLIProducesExactHardlinkTree(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonicalConfig, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	canonicalConfigPath := filepath.Join(root, "canonical-sow.yaml")
	if err := os.WriteFile(canonicalConfigPath, canonicalConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	object, err := pool.Put(context.Background(), strings.NewReader("asset bytes"))
	if err != nil {
		t.Fatal(err)
	}
	entry := views.Entry{
		Repo: "asset", OS: "all", Arch: "all", Name: "tool", Version: "1",
		Path: "asset/pkg/tool", Size: object.Size, SHA256: object.HashString(), Pool: "public",
	}
	var encoded bytes.Buffer
	if err := views.WriteEntry(&encoded, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "view.tsv")
	if err := os.WriteFile(stage, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	viewPath, _ := state.ViewPath("latest", "asset", "all", "all")
	commit, _, err := canonical.InstallPaths(map[string]string{viewPath: stage, "config/sow.yaml": canonicalConfigPath}, "seed latest")
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := state.ViewRef("latest", "asset", "all", "all")
	if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	materializeArgs := []string{"materialize", "latest", "--config", configPath, "--target", "export", "--tgz", "offline/pigsty-pkg-test.tgz", "--asset-repo", "asset", "--asset-dest", "src/pigsty-pkg-test.tgz", "--workers", "2", "--chunk-entries", "2"}
	code := Main(materializeArgs, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "entries=1") || !strings.Contains(stdout.String(), "archive path=") || !strings.Contains(stdout.String(), "archive adopted repo=asset") {
		t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	archivePath := filepath.Join(root, "offline", "pigsty-pkg-test.tgz")
	firstArchive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	poolInfo, err := os.Stat(pool.ObjectPath(object.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(root, "export", "asset", "pkg", "tool")
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(poolInfo, targetInfo) {
		t.Fatal("materialized path is not a CAS hardlink")
	}
	assetRef, _ := state.ViewRef("beta", "asset", "all", "all")
	assetCommit, exists, err := canonical.Ref(assetRef)
	if err != nil || !exists {
		t.Fatalf("offline asset ref missing: commit=%s exists=%v err=%v", assetCommit, exists, err)
	}
	assetViewPath, _ := state.ViewPath("beta", "asset", "all", "all")
	assetView, err := canonical.OpenPathAt(assetCommit, assetViewPath)
	if err != nil {
		t.Fatal(err)
	}
	assetEntry, err := views.NewReader(assetView).Next()
	if closeErr := assetView.Close(); err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	if assetEntry.Path != "asset/src/pigsty-pkg-test.tgz" {
		t.Fatalf("offline archive adopted at %q", assetEntry.Path)
	}
	assetDigest, err := repository.ParseDigest(assetEntry.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	assetPoolInfo, err := os.Stat(pool.ObjectPath(assetDigest))
	if err != nil {
		t.Fatal(err)
	}
	assetTreeInfo, err := os.Stat(filepath.Join(root, ".sow", "materialized", "beta", "asset", "src", "pigsty-pkg-test.tgz"))
	if err != nil || !os.SameFile(assetPoolInfo, assetTreeInfo) {
		t.Fatalf("offline archive is not a CAS-backed asset hardlink: %v", err)
	}
	stale := filepath.Join(root, "export", "stale")
	if err := os.WriteFile(stale, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main(materializeArgs, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "pruned=1") || !strings.Contains(stdout.String(), "add unchanged repo=asset") {
		t.Fatalf("reconcile code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale file remains: %v", err)
	}
	secondArchive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstArchive, secondArchive) {
		t.Fatal("offline tgz is not deterministic across identical materializations")
	}
}

func TestMaterializeCLIRejectsLiveRepoOverlap(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"materialize", "latest", "--config", configPath, "--target", "asset"}, &stdout, &stderr)
	if code != ExitUsage || !strings.Contains(stderr.String(), "overlaps configured repo") {
		t.Fatalf("overlap code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, test := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{name: "asset repo needs archive", args: []string{"materialize", "latest", "--config", configPath, "--asset-repo", "asset"}, code: ExitUsage, want: "--asset-repo requires --tgz"},
		{name: "asset destination needs repo", args: []string{"materialize", "latest", "--config", configPath, "--asset-dest", "src/offline.tgz"}, code: ExitUsage, want: "--asset-dest requires --asset-repo"},
		{name: "asset repo is typed", args: []string{"materialize", "latest", "--config", configPath, "--tgz", "offline/out.tgz", "--asset-repo", "missing"}, code: ExitConfig, want: "is not a configured asset repository"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()
			got := Main(test.args, &stdout, &stderr)
			if got != test.code || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("code=%d stdout=%s stderr=%s", got, stdout.String(), stderr.String())
			}
		})
	}
}
