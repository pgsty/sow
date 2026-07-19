package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestFrozenYUMMetadataManifestRejectsExtraPrivateGenerationEntry(t *testing.T) {
	generationDir := t.TempDir()
	generation := &yumrepo.Generation{}
	for index, kind := range []string{"primary", "filelists", "other"} {
		name := kind + ".xml.gz"
		body := []byte(kind + " metadata\n")
		writeFrozenYUMFixtureFile(t, generationDir, name, body)
		digest := sha256.Sum256(body)
		generation.Artifacts[index] = yumrepo.Artifact{
			Type: kind, Path: "repodata/" + name, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(body)),
		}
	}
	repomd := []byte("repomd\n")
	writeFrozenYUMFixtureFile(t, generationDir, "repomd.xml", repomd)
	repomdDigest := sha256.Sum256(repomd)
	generation.RepomdSHA256 = hex.EncodeToString(repomdDigest[:])
	writeFrozenYUMFixtureFile(t, generationDir, "repomd.xml.asc", []byte("signature\n"))
	writeFrozenYUMFixtureFile(t, generationDir, "same-uid-injection", []byte("stray\n"))

	destination := filepath.Join(t.TempDir(), "metadata.tsv")
	if err := writeFrozenYUMMetadataManifest(t.Context(), generationDir, destination, "yum/test/x86_64/repodata", generation); err == nil || !strings.Contains(err.Error(), "contains 6 entries") {
		t.Fatalf("extra private YUM generation entry was accepted: %v", err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected private generation left an exact manifest: %v", err)
	}
	if err := os.Remove(filepath.Join(generationDir, "same-uid-injection")); err != nil {
		t.Fatal(err)
	}
	if err := writeFrozenYUMMetadataManifest(t.Context(), generationDir, destination, "yum/test/x86_64/repodata", generation); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	reader := manifest.NewReader(file)
	count := 0
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		if !strings.HasPrefix(entry.Path, "yum/test/x86_64/repodata/") {
			file.Close()
			t.Fatalf("unprefixed frozen YUM metadata entry %q", entry.Path)
		}
		count++
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("frozen YUM exact manifest entries=%d, want 5", count)
	}
}

func writeFrozenYUMFixtureFile(t *testing.T, root, name string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), body, 0o444); err != nil {
		t.Fatal(err)
	}
}
