package manifest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanRootMatchesPathScan(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"repo/a.txt":        "alpha\n",
		"repo/nested/b.txt": "bravo\n",
		"repo/skip.tmp":     "ignored\n",
	} {
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want := filepath.Join(t.TempDir(), "path.tsv")
	options := ScanOptions{Workers: 2, ChunkEntries: 1, TempDir: t.TempDir()}
	pathStats, err := Scan(context.Background(), root, Scope{Path: "repo", Exclude: []string{"*.tmp"}}, want, options)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	got := filepath.Join(t.TempDir(), "root.tsv")
	rootStats, err := ScanRoot(context.Background(), bound, Scope{Path: "repo", Exclude: []string{"*.tmp"}}, got, options)
	if err != nil {
		t.Fatal(err)
	}
	wantBody, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	gotBody, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if pathStats != rootStats || string(wantBody) != string(gotBody) {
		t.Fatalf("bound scan differs: path=%+v root=%+v\nwant=%s\ngot=%s", pathStats, rootStats, wantBody, gotBody)
	}
}

func TestScanRootRepositoryReplacementReadsRetainedRoot(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "repo")
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "identity"), []byte("retained A\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bound, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	displaced := rootPath + "-displaced"
	if err := os.Rename(rootPath, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rootPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "identity"), []byte("replacement B\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "bound.tsv")
	if _, err := ScanRoot(context.Background(), bound, Scope{Path: "."}, destination, ScanOptions{Workers: 1, ChunkEntries: 1, TempDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	reader := NewReader(file)
	entry, err := reader.Next()
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read bound manifest: %v %v", err, closeErr)
	}
	want := digestScanRootTestBytes([]byte("retained A\n"))
	if entry.Path != "identity" || entry.HashString() != want {
		t.Fatalf("replacement root was read: entry=%+v want_sha=%s", entry, want)
	}
}

func TestScanRootRejectsIntermediateScopeSymlink(t *testing.T) {
	rootPath := t.TempDir()
	replacement := filepath.Join(rootPath, "replacement", "v1")
	if err := os.MkdirAll(replacement, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(replacement, "identity"), []byte("replacement B\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("replacement", filepath.Join(rootPath, "_sow")); err != nil {
		t.Fatal(err)
	}
	bound, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	destination := filepath.Join(t.TempDir(), "manifest.tsv")
	_, err = ScanRoot(context.Background(), bound, Scope{Path: "_sow/v1"}, destination, ScanOptions{
		Workers:      2,
		ChunkEntries: 1,
		TempDir:      t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("intermediate scope symlink was not rejected: %v", err)
	}
	if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
		t.Fatalf("failed scan unexpectedly installed a manifest: %v", statErr)
	}
}

func TestScanRootRejectsIntermediateEntrySymlink(t *testing.T) {
	rootPath := t.TempDir()
	for name, body := range map[string]string{
		"replacement/identity": "replacement B\n",
		"ordinary/identity":    "retained A\n",
	} {
		filename := filepath.Join(rootPath, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../replacement", filepath.Join(rootPath, "ordinary", "redirect")); err != nil {
		t.Fatal(err)
	}
	bound, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	_, err = ScanRoot(context.Background(), bound, Scope{Path: "ordinary"}, filepath.Join(t.TempDir(), "manifest.tsv"), ScanOptions{
		Workers:      4,
		ChunkEntries: 1,
		TempDir:      t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "repo contains symlink") {
		t.Fatalf("entry symlink was not rejected: %v", err)
	}
}

func TestScanRootIntermediateScopeReplacementFailsClosed(t *testing.T) {
	rootPath := t.TempDir()
	retainedPath := filepath.Join(rootPath, "_sow", "v1")
	replacementPath := filepath.Join(rootPath, "replacement", "v1")
	for filename, body := range map[string]string{
		filepath.Join(retainedPath, "identity"):    "retained A\n",
		filepath.Join(replacementPath, "identity"): "replacement B\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bound, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	binding, err := openBoundScanScope(bound, "_sow/v1")
	if err != nil {
		t.Fatal(err)
	}
	defer binding.close()
	job, err := openBoundRootFile(binding.root, "identity", "_sow/v1/identity")
	if err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(rootPath, "_sow-retained")
	if err := os.Rename(filepath.Join(rootPath, "_sow"), displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("replacement", filepath.Join(rootPath, "_sow")); err != nil {
		t.Fatal(err)
	}
	entry, hashErr := hashRootFile(context.Background(), job, make([]byte, 32*1024))
	closeErr := job.close()
	if hashErr != nil || closeErr != nil {
		t.Fatalf("hash retained scope: %v; close: %v", hashErr, closeErr)
	}
	if got, want := entry.HashString(), digestScanRootTestBytes([]byte("retained A\n")); got != want {
		t.Fatalf("replacement scope was read: got %s want retained %s (replacement %s)", got, want, digestScanRootTestBytes([]byte("replacement B\n")))
	}
	if err := binding.verify(bound); err == nil || !strings.Contains(err.Error(), "replaced during scan") {
		t.Fatalf("intermediate scope replacement was not rejected: %v", err)
	}
}

func TestScanRootIntermediateEntryReplacementKeepsOriginalCapability(t *testing.T) {
	rootPath := t.TempDir()
	retainedPath := filepath.Join(rootPath, "nested")
	replacementPath := filepath.Join(rootPath, "replacement")
	for filename, body := range map[string]string{
		filepath.Join(retainedPath, "identity"):    "retained A\n",
		filepath.Join(replacementPath, "identity"): "replacement B\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bound, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	retained, identity, err := openBoundRootDirectory(bound, "nested")
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	job, err := openBoundRootFile(retained, "identity", "nested/identity")
	if err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(rootPath, "nested-retained")
	if err := os.Rename(filepath.Join(rootPath, "nested"), displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("replacement", filepath.Join(rootPath, "nested")); err != nil {
		t.Fatal(err)
	}
	entry, hashErr := hashRootFile(context.Background(), job, make([]byte, 32*1024))
	closeErr := job.close()
	if hashErr != nil || closeErr != nil {
		t.Fatalf("hash retained entry: %v; close: %v", hashErr, closeErr)
	}
	if got, want := entry.HashString(), digestScanRootTestBytes([]byte("retained A\n")); got != want {
		t.Fatalf("replacement entry was read: got %s want retained %s (replacement %s)", got, want, digestScanRootTestBytes([]byte("replacement B\n")))
	}
	if err := verifyBoundRootDirectory(bound, "nested", identity, "nested"); err == nil || !strings.Contains(err.Error(), "replaced during scan") {
		t.Fatalf("intermediate entry replacement was not rejected: %v", err)
	}
}

func TestScanRootCanceledContextDoesNotInstallManifest(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "identity"), []byte("retained A\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bound, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	destination := filepath.Join(t.TempDir(), "manifest.tsv")
	if _, err := ScanRoot(ctx, bound, Scope{Path: "."}, destination, ScanOptions{
		Workers:      8,
		ChunkEntries: 1,
		TempDir:      t.TempDir(),
	}); err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("canceled scan did not fail closed: %v", err)
	}
	if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
		t.Fatalf("canceled scan unexpectedly installed a manifest: %v", statErr)
	}
}

func digestScanRootTestBytes(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
