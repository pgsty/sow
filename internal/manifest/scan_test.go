package manifest

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestScanIsDeterministicBoundedAndHonorsExcludes(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "repo", "z.txt"), "z")
	writeTestFile(t, filepath.Join(root, "repo", "a.txt"), "a")
	writeTestFile(t, filepath.Join(root, "repo", "nested", "b.txt"), "b")
	writeTestFile(t, filepath.Join(root, "repo", "conf", "secret"), "do-not-scan")
	writeTestFile(t, filepath.Join(root, "repo", ".sow", "hidden"), "shadow")
	writeTestFile(t, filepath.Join(root, "repo", ".git", "index"), "shadow")

	first := filepath.Join(root, "one.tsv")
	second := filepath.Join(root, "two.tsv")
	scope := Scope{Path: "repo", Include: []string{"**/*.txt", "*.txt"}, Exclude: []string{"conf/**"}}
	stats, err := Scan(context.Background(), root, scope, first, ScanOptions{Workers: 4, ChunkEntries: 1, TempDir: filepath.Join(root, ".sow", "tmp")})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Files != 3 || stats.Bytes != 3 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	if _, err := Scan(context.Background(), root, scope, second, ScanOptions{Workers: 2, ChunkEntries: 2, TempDir: filepath.Join(root, ".sow", "tmp")}); err != nil {
		t.Fatal(err)
	}
	one, _ := os.ReadFile(first)
	two, _ := os.ReadFile(second)
	if !reflect.DeepEqual(one, two) {
		t.Fatalf("scan is not deterministic:\n%s\n%s", one, two)
	}
	paths := readPaths(t, first)
	want := []string{"repo/a.txt", "repo/nested/b.txt", "repo/z.txt"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths=%v want=%v", paths, want)
	}
}

func TestScanRejectsUnrepresentablePathAndSymlink(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "repo", "bad\tname"), "x")
	err := scanError(root)
	if err == nil || !strings.Contains(err.Error(), "cannot be represented") {
		t.Fatalf("wanted TSV path error, got %v", err)
	}
	if err := os.Remove(filepath.Join(root, "repo", "bad\tname")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "outside"), "x")
	if err := os.Symlink(filepath.Join(root, "outside"), filepath.Join(root, "repo", "link")); err != nil {
		t.Fatal(err)
	}
	err = scanError(root)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("wanted symlink error, got %v", err)
	}
}

func scanError(root string) error {
	_, err := Scan(context.Background(), root, Scope{Path: "repo"}, filepath.Join(root, "manifest.tsv"), ScanOptions{Workers: 2, ChunkEntries: 1, TempDir: filepath.Join(root, ".sow", "tmp")})
	return err
}

func readPaths(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader := NewReader(f)
	var paths []string
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return paths
		}
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, entry.Path)
	}
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
