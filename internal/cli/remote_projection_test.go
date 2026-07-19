package cli

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
)

func TestProjectLatestSourceManifestSeparatesPhysicalAndRemoteNamespaces(t *testing.T) {
	repos := []config.Repo{
		{
			ID: "apt", Type: "apt", Path: "apt/test", Arches: []string{"amd64"},
			APT: &config.APTConfig{Suites: []string{"jammy"}, Components: []string{"main"}},
		},
		{
			ID: "bootstrap", Type: "asset", Path: "asset/bootstrap",
			Asset: &config.AssetConfig{PublicPath: ".", RootKeys: []string{"pkg"}},
		},
		{
			ID: "images", Type: "asset", Path: "asset/images",
			Asset: &config.AssetConfig{PublicPath: "img"},
		},
	}
	source := writeProjectionManifest(t, []manifest.Entry{
		projectionEntry("apt/test/dists/jammy/InRelease", "apt"),
		projectionEntry("asset/bootstrap/pkg", "bootstrap"),
		projectionEntry("asset/images/logo.png", "logo"),
	})
	destination := filepath.Join(t.TempDir(), "remote.tsv")
	stage := t.TempDir()
	if err := projectLatestSourceManifest(repos, source, destination, stage); err != nil {
		t.Fatal(err)
	}
	got := readProjectionManifest(t, destination)
	for sourcePath, remotePath := range map[string]string{
		"apt/test/dists/jammy/InRelease": "apt/test/dists/jammy/InRelease",
		"asset/bootstrap/pkg":            "pkg",
		"asset/images/logo.png":          "img/logo.png",
	} {
		if got[remotePath] == "" {
			t.Fatalf("physical %s was not projected to %s: %v", sourcePath, remotePath, got)
		}
		if sourcePath != remotePath && got[sourcePath] != "" {
			t.Fatalf("physical asset path leaked into remote manifest: %s", sourcePath)
		}
	}
}

func TestProjectLatestSourceManifestRejectsRootKeyWideningAndCollisions(t *testing.T) {
	rootRepo := config.Repo{
		ID: "bootstrap", Type: "asset", Path: "asset/bootstrap",
		Asset: &config.AssetConfig{PublicPath: ".", RootKeys: []string{"pkg"}},
	}
	nested := writeProjectionManifest(t, []manifest.Entry{projectionEntry("asset/bootstrap/pkg/child", "nested")})
	if err := projectLatestSourceManifest([]config.Repo{rootRepo}, nested, filepath.Join(t.TempDir(), "nested.tsv"), t.TempDir()); err == nil || !strings.Contains(err.Error(), "one exact key") {
		t.Fatalf("root exact-key widening accepted: %v", err)
	}

	colliding := []config.Repo{
		{ID: "one", Type: "asset", Path: "asset/one", Asset: &config.AssetConfig{PublicPath: "pkg"}},
		{ID: "two", Type: "asset", Path: "asset/two", Asset: &config.AssetConfig{PublicPath: "pkg"}},
	}
	source := writeProjectionManifest(t, []manifest.Entry{
		projectionEntry("asset/one/same", "one"),
		projectionEntry("asset/two/same", "two"),
	})
	if err := projectLatestSourceManifest(colliding, source, filepath.Join(t.TempDir(), "collision.tsv"), t.TempDir()); err == nil || !strings.Contains(err.Error(), "duplicate") || !strings.Contains(err.Error(), "manifest path") {
		t.Fatalf("remote-key collision accepted: %v", err)
	}
}

func writeProjectionManifest(t *testing.T, entries []manifest.Entry) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "source.tsv")
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := manifest.WriteEntry(file, entry); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return filename
}

func projectionEntry(path, body string) manifest.Entry {
	return manifest.Entry{Path: path, Size: int64(len(body)), SHA256: sha256.Sum256([]byte(body))}
}

func readProjectionManifest(t *testing.T, filename string) map[string]string {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result := make(map[string]string)
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return result
		}
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Path] = entry.HashString()
	}
}
