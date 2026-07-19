package cli

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/views"
)

func TestValidateRetainedYUMPayloadPathsConfinesCanonicalRPMs(t *testing.T) {
	encode := func(path string) []byte {
		t.Helper()
		var body bytes.Buffer
		digest := sha256.Sum256([]byte(path))
		if err := views.WriteEntry(&body, views.Entry{
			Repo: "rpm-test", OS: "el10", Arch: "x86_64", Name: "package", Version: "1-1",
			Path: path, Size: 1, SHA256: stringHex(digest[:]), Pool: "public",
		}); err != nil {
			t.Fatal(err)
		}
		return body.Bytes()
	}
	valid := "yum/test/x86_64/Packages/p/package-1-1.x86_64.rpm"
	if err := validateRetainedYUMPayloadPaths(bytes.NewReader(encode(valid)), "yum/test/x86_64"); err != nil {
		t.Fatalf("valid retained RPM rejected: %v", err)
	}
	for name, invalid := range map[string]string{
		"other-leaf": "yum/other/x86_64/Packages/p/package.rpm",
		"metadata":   "yum/test/x86_64/repodata/repomd.xml",
		"nested":     "yum/test/x86_64/Packages/p/nested/package.rpm",
		"not-rpm":    "yum/test/x86_64/Packages/p/package.txt",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRetainedYUMPayloadPaths(bytes.NewReader(encode(invalid)), "yum/test/x86_64"); err == nil {
				t.Fatalf("unsafe retained payload accepted: %s", invalid)
			}
		})
	}
}

func TestMergeCompatibleManifestFilesDeduplicatesAndFailsClosed(t *testing.T) {
	root := t.TempDir()
	entry := func(path, content string) manifest.Entry {
		return manifest.Entry{Path: path, Size: int64(len(content)), SHA256: sha256.Sum256([]byte(content))}
	}
	left := filepath.Join(root, "left.tsv")
	right := filepath.Join(root, "right.tsv")
	writeServingCompatManifest(t, left, entry("a", "a"), entry("c", "same"))
	writeServingCompatManifest(t, right, entry("b", "b"), entry("c", "same"))
	merged := filepath.Join(root, "merged.tsv")
	if err := mergeCompatibleManifestFiles(left, right, merged); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(merged)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(string(body)), "\n"); len(lines) != 3 || !strings.HasPrefix(lines[0], "a\t") || !strings.HasPrefix(lines[1], "b\t") || !strings.HasPrefix(lines[2], "c\t") {
		t.Fatalf("unexpected merged manifest:\n%s", body)
	}

	conflict := filepath.Join(root, "conflict.tsv")
	writeServingCompatManifest(t, conflict, entry("c", "changed"))
	rejected := filepath.Join(root, "rejected.tsv")
	if err := mergeCompatibleManifestFiles(left, conflict, rejected); err == nil || !strings.Contains(err.Error(), "changed bytes") {
		t.Fatalf("manifest path collision was not rejected: %v", err)
	}
	if _, err := os.Lstat(rejected); !os.IsNotExist(err) {
		t.Fatalf("failed merge left a destination behind: %v", err)
	}
}

func TestYUMCompatibilityGenerationManifestExcludesFlatAliases(t *testing.T) {
	root := t.TempDir()
	entry := func(name string) manifest.Entry {
		body := []byte(name)
		return manifest.Entry{Path: name, Size: int64(len(body)), SHA256: sha256.Sum256(body)}
	}
	candidate := filepath.Join(root, "candidate.tsv")
	writeServingCompatManifest(t, candidate,
		entry("Packages/p/pkg-1.x86_64.rpm"),
		entry("pkg-1.x86_64.rpm"),
		entry("repodata/repomd.xml"),
		entry("repodata/repomd.xml.asc"),
	)
	generation := filepath.Join(root, "generation.tsv")
	if err := buildYUMCompatibilityGenerationManifest(candidate, generation, "yum/infra/x86_64"); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(generation)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	var paths []string
	for {
		value, readErr := reader.Next()
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			t.Fatal(readErr)
		}
		paths = append(paths, value.Path)
	}
	want := []string{
		"yum/infra/x86_64/Packages/p/pkg-1.x86_64.rpm",
		"yum/infra/x86_64/repodata/repomd.xml",
		"yum/infra/x86_64/repodata/repomd.xml.asc",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("generation paths=%v want=%v", paths, want)
	}

	unsafe := filepath.Join(root, "unsafe.tsv")
	writeServingCompatManifest(t, unsafe, entry("operator-secret"), entry("repodata/repomd.xml"))
	rejected := filepath.Join(root, "rejected.tsv")
	if err := buildYUMCompatibilityGenerationManifest(unsafe, rejected, "yum/infra/x86_64"); err == nil || !strings.Contains(err.Error(), "unsupported path") {
		t.Fatalf("unsupported candidate path accepted: %v", err)
	}
	if _, err := os.Lstat(rejected); !os.IsNotExist(err) {
		t.Fatalf("failed generation projection survived: %v", err)
	}
}

func writeServingCompatManifest(t *testing.T, filename string, entries ...manifest.Entry) {
	t.Helper()
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := manifest.WriteEntry(file, entry); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func stringHex(data []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for index, value := range data {
		result[index*2] = digits[value>>4]
		result[index*2+1] = digits[value&0x0f]
	}
	return string(result)
}
