package cli

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
)

// This digest is intentionally toolchain-sensitive. go.mod pins the supported
// Go patch release and CI runs this test on Linux and macOS; a compressor/tar
// encoding change must therefore be reviewed as an archive compatibility event
// instead of silently causing no-clobber conflicts with an existing tgz.
func TestDeterministicTGZGoldenBytesAcrossSupportedPlatforms(t *testing.T) {
	materialized := t.TempDir()
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	entries := []struct {
		name string
		body []byte
	}{
		{name: "a.txt", body: []byte("archive golden alpha\n")},
		{name: "nested/b.bin", body: []byte{0, 1, 2, 3, 0xfe, 0xff}},
	}
	var encoded bytes.Buffer
	for _, entry := range entries {
		filename := filepath.Join(materialized, filepath.FromSlash(entry.name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, entry.body, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := manifest.WriteEntry(&encoded, manifest.Entry{Path: entry.name, Size: int64(len(entry.body)), SHA256: sha256.Sum256(entry.body)}); err != nil {
			t.Fatal(err)
		}
	}
	manifestPath := filepath.Join(private, "golden.tsv")
	if err := os.WriteFile(manifestPath, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "golden.tgz")
	result, err := writeDeterministicTGZWithPrecommit(t.Context(), materialized, manifestPath, destination, false, private, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	const want = "ecd4e22913198b47f1760991bcf2f3043b4aafa60c5f202d4cf7e23222c0fd74"
	if result.SHA256 != want {
		t.Fatalf("deterministic tgz golden changed go=%s os=%s arch=%s sha256=%s want=%s", runtime.Version(), runtime.GOOS, runtime.GOARCH, result.SHA256, want)
	}
}
