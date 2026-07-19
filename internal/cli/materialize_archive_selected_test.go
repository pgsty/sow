package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
)

func TestLatestWorkingTreeAPTArchiveRetainsLogicalSuiteSelector(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	configBody := strings.Replace(snapshotAPTConfig, "apt: {suites: [jammy], components: [main]}", "apt: {suites: [jammy, noble], components: [main]}", 1)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	jammyDEB := writeSelectorDEB(t, root, "jammy-only", "1.0-1", "arm64")
	nobleDEB := writeSelectorDEB(t, root, "noble-only", "2.0-1", "arm64")
	jammyInfo, err := aptrepo.InspectPackage(t.Context(), jammyDEB, "main")
	if err != nil {
		t.Fatal(err)
	}
	nobleInfo, err := aptrepo.InspectPackage(t.Context(), nobleDEB, "main")
	if err != nil {
		t.Fatal(err)
	}
	private, keyPath := writeMaterializeSigningKey(t, root)
	for _, input := range []struct {
		path  string
		suite string
	}{{jammyDEB, "jammy"}, {nobleDEB, "noble"}} {
		if code, stdout, stderr := runServingCLI(t, "add", input.path, "--config", configPath, "--repo", "deb-test", "--os", input.suite, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("add %s code=%d stdout=%s stderr=%s", input.suite, code, stdout, stderr)
		}
	}
	if code, stdout, stderr := runServingCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "deb-test"); code != ExitOK {
		t.Fatalf("promote APT suites code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	archivePath := filepath.Join(root, "offline", "jammy-only.tgz")
	args := []string{"materialize", "latest", "--config", configPath, "--repo", "deb-test", "--os", "jammy", "--gpg-private-key-file", keyPath, "--tgz", archivePath, "--workers", "2", "--chunk-entries", "2"}
	code, stdout, stderr := runServingCLI(t, args...)
	if code != ExitOK || !strings.Contains(stdout, "archive path=") {
		t.Fatalf("partial APT archive code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, relative := range []string{
		"apt/test/dists/jammy/InRelease", "apt/test/" + jammyInfo.PoolPath,
		"apt/test/dists/noble/InRelease", "apt/test/" + nobleInfo.PoolPath,
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("physical APT owner did not retain %s: %v", relative, err)
		}
	}
	encoded, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"apt/test/dists/jammy/InRelease", "apt/test/dists/jammy/main/binary-arm64/Packages", "apt/test/" + jammyInfo.PoolPath} {
		if !archiveHasPath(t, encoded, wanted) {
			t.Fatalf("partial APT archive omitted %s", wanted)
		}
	}
	for _, forbidden := range []string{"apt/test/dists/noble/InRelease", "apt/test/dists/noble/main/binary-arm64/Packages", "apt/test/" + nobleInfo.PoolPath} {
		if archiveHasPath(t, encoded, forbidden) {
			t.Fatalf("partial APT archive leaked sibling suite path %s", forbidden)
		}
	}
	extracted := extractMaterializeArchive(t, encoded)
	verifier, err := verify.NewAPTVerifier(bytes.NewReader(private))
	if err != nil {
		t.Fatal(err)
	}
	report := verify.Run(context.Background(), verify.Request{Layers: []verify.Layer{verify.LayerL1}, Checks: []verify.Check{verify.APTCheck{
		CheckID: "selected-jammy-archive", Root: filepath.Join(extracted, "apt", "test"), ExpectedSuites: []string{"jammy"},
		Verifier: verifier, VerifyAt: time.Now().UTC().Add(time.Hour), Workers: 2, ChunkEntries: 2,
	}}})
	if report.Outcome != verify.OutcomePassed {
		t.Fatalf("partial APT archive is not consumable: %+v", report)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr = runServingCLI(t, args...); code != ExitOK {
		t.Fatalf("partial APT archive replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	replayed, err := os.ReadFile(archivePath)
	if err != nil || !bytes.Equal(encoded, replayed) {
		t.Fatalf("partial APT archive replay changed bytes: err=%v", err)
	}
	if after, err := canonical.HeadHash(); err != nil || after != head {
		t.Fatalf("partial APT archive replay advanced canonical HEAD before=%s after=%s err=%v manifest_diff=%v stdout=%s stderr=%s", head, after, err, canonicalManifestDiff(t, canonical, head, after, "manifests/deb-test.tsv"), stdout, stderr)
	}
}

func canonicalManifestDiff(t *testing.T, canonical *state.Store, left, right plumbing.Hash, canonicalPath string) []string {
	t.Helper()
	read := func(commit plumbing.Hash) map[string]manifest.Entry {
		file, err := canonical.OpenPathAt(commit, canonicalPath)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		result := make(map[string]manifest.Entry)
		reader := manifest.NewReader(file)
		for {
			entry, err := reader.Next()
			if errors.Is(err, io.EOF) {
				return result
			}
			if err != nil {
				t.Fatal(err)
			}
			result[entry.Path] = entry
		}
	}
	leftEntries, rightEntries := read(left), read(right)
	var result []string
	for path, entry := range leftEntries {
		other, exists := rightEntries[path]
		if !exists {
			result = append(result, "-"+path)
		} else if other != entry {
			result = append(result, path+":"+entry.HashString()+"->"+other.HashString())
		}
	}
	for path := range rightEntries {
		if _, exists := leftEntries[path]; !exists {
			result = append(result, "+"+path)
		}
	}
	sort.Strings(result)
	return result
}

func extractMaterializeArchive(t *testing.T, encoded []byte) string {
	t.Helper()
	root := t.TempDir()
	compressed, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg || header.Name == "" || filepath.IsAbs(header.Name) || filepath.Clean(header.Name) != filepath.FromSlash(header.Name) || header.Name == ".." || strings.HasPrefix(header.Name, "../") {
			t.Fatalf("unsafe archive test entry %q type=%d", header.Name, header.Typeflag)
		}
		destination := filepath.Join(root, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
		if err != nil {
			t.Fatal(err)
		}
		written, copyErr := io.Copy(file, reader)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != header.Size {
			t.Fatal(errors.Join(copyErr, closeErr))
		}
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return root
}
