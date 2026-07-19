package serving

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
)

func testIdentity() Identity {
	return Identity{
		View: "latest", Repo: "rpm-test", OS: "el10", Arch: "x86_64", LegacyRoot: "yum/test/x86_64",
		RefCommit: strings.Repeat("1", 40), ConfigSHA256: strings.Repeat("2", 64), RepositoryKeySHA256: strings.Repeat("3", 64),
	}
}

func writeServingFixture(t *testing.T, root string) string {
	t.Helper()
	files := map[string]string{
		"yum/test/x86_64/Packages/p/pkg.rpm":       "rpm-payload\n",
		"yum/test/x86_64/repodata/primary.xml.zst": "primary\n",
		"yum/test/x86_64/repodata/repomd.xml":      "repomd\n",
		"yum/test/x86_64/repodata/repomd.xml.asc":  "signature\n",
	}
	for relative, body := range files {
		filename := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifestPath := filepath.Join(root, ".sow", "fixture.tsv")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Scan(t.Context(), root, manifest.Scope{Path: "yum/test/x86_64"}, manifestPath, manifest.ScanOptions{Workers: 2, ChunkEntries: 2, TempDir: filepath.Join(root, ".sow")}); err != nil {
		t.Fatal(err)
	}
	return manifestPath
}

func deriveFixtureGeneration(t *testing.T, manifestPath string) Generation {
	t.Helper()
	file, err := os.Open(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	generation, deriveErr := DeriveGeneration(testIdentity(), file)
	closeErr := file.Close()
	if deriveErr != nil || closeErr != nil {
		t.Fatal(errors.Join(deriveErr, closeErr))
	}
	return generation
}

func TestContentDerivedGenerationAndChannelAreCanonical(t *testing.T) {
	root := t.TempDir()
	manifestPath := writeServingFixture(t, root)
	first := deriveFixtureGeneration(t, manifestPath)
	second := deriveFixtureGeneration(t, manifestPath)
	if first != second || len(first.ID) != 20 || first.ID == "00000000000000000000" {
		t.Fatalf("non-deterministic generation first=%#v second=%#v", first, second)
	}
	body, err := first.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGeneration(body)
	if err != nil || decoded != first {
		t.Fatalf("generation round trip=%#v err=%v", decoded, err)
	}
	channel, err := NewChannel(first, "https://repo.example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	mirrorlist, err := channel.MirrorlistBody()
	if err != nil {
		t.Fatal(err)
	}
	want := "https://repo.example.invalid/_sow/v1/g/" + first.ID + "/yum/test/x86_64/\n"
	if string(mirrorlist) != want {
		t.Fatalf("mirrorlist=%q want=%q", mirrorlist, want)
	}
	channelBody, _ := channel.Canonical()
	if decoded, err := DecodeChannel(channelBody); err != nil || !reflect.DeepEqual(decoded, channel) {
		t.Fatalf("channel round trip=%#v err=%v", decoded, err)
	}
}

func TestInstallGenerationImportsCASHardlinksAndRejectsDrift(t *testing.T) {
	root := t.TempDir()
	manifestPath := writeServingFixture(t, root)
	generation := deriveFixtureGeneration(t, manifestPath)
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	options := InstallOptions{Workers: 2, ChunkEntries: 2, TempDir: filepath.Join(root, ".sow")}
	installed, err := InstallGeneration(t.Context(), pool, root, generation, manifestPath, options)
	if err != nil || !installed.Created || installed.Entries != 4 {
		t.Fatalf("install=%#v err=%v", installed, err)
	}
	installed, err = InstallGeneration(t.Context(), pool, root, generation, manifestPath, options)
	if err != nil || installed.Created {
		t.Fatalf("idempotent install=%#v err=%v", installed, err)
	}

	manifestFile, err := os.Open(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	reader := manifest.NewReader(manifestFile)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		generationPath := filepath.Join(root, "_sow", "v1", "g", generation.ID, filepath.FromSlash(entry.Path))
		generationInfo, err := os.Stat(generationPath)
		if err != nil {
			t.Fatal(err)
		}
		objectInfo, err := os.Stat(pool.ObjectPath(repository.Digest(entry.SHA256)))
		if err != nil || !os.SameFile(generationInfo, objectInfo) {
			t.Fatalf("generation path %s is not the CAS hardlink: %v", entry.Path, err)
		}
	}
	_ = manifestFile.Close()

	repomd := filepath.Join(root, "_sow", "v1", "g", generation.ID, "yum", "test", "x86_64", "repodata", "repomd.xml")
	if err := os.Chmod(repomd, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repomd, []byte("foreign bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallGeneration(t.Context(), pool, root, generation, manifestPath, options); err == nil {
		t.Fatalf("drifted generation accepted: %v", err)
	}
}

func TestMirrorlistFlipIsParentBoundAndRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	manifestPath := writeServingFixture(t, root)
	first := deriveFixtureGeneration(t, manifestPath)
	channel, err := NewChannel(first, "https://repo.example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ReconcileMirrorlist(root, channel)
	if err != nil || !changed {
		t.Fatalf("first flip changed=%v err=%v", changed, err)
	}
	if changed, err := ReconcileMirrorlist(root, channel); err != nil || changed {
		t.Fatalf("idempotent flip changed=%v err=%v", changed, err)
	}

	// Construct the next channel from a valid, differently-derived record.
	changedManifest, err := os.Open(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity()
	identity.RefCommit = strings.Repeat("4", 40)
	second, err := DeriveGeneration(identity, changedManifest)
	_ = changedManifest.Close()
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewChannel(second, "https://repo.example.invalid", &channel)
	if err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(root, filepath.FromSlash(channel.MirrorlistPath))
	if err := os.Chmod(pointer, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pointer, []byte("https://foreign.invalid/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileMirrorlist(root, next); err == nil || !strings.Contains(err.Error(), "differs from both") {
		t.Fatalf("foreign pointer accepted: %v", err)
	}

	symlinkRoot := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(symlinkRoot, "_sow"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(symlinkRoot, "_sow", "v1")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileMirrorlist(symlinkRoot, channel); err == nil {
		t.Fatal("symlinked mirrorlist parent was accepted")
	}
}

func TestMirrorlistConcurrentReadersSeeOnlyWholeParentOrDesiredBody(t *testing.T) {
	root := t.TempDir()
	manifestPath := writeServingFixture(t, root)
	first := deriveFixtureGeneration(t, manifestPath)
	parent, err := NewChannel(first, "https://repo.example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileMirrorlist(root, parent); err != nil {
		t.Fatal(err)
	}
	manifestFile, err := os.Open(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := testIdentity()
	identity.RefCommit = strings.Repeat("5", 40)
	second, err := DeriveGeneration(identity, manifestFile)
	_ = manifestFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	desired, err := NewChannel(second, "https://repo.example.invalid", &parent)
	if err != nil {
		t.Fatal(err)
	}
	oldBody, _ := parent.MirrorlistBody()
	newBody, _ := desired.MirrorlistBody()

	start := make(chan struct{})
	errorsByReader := make(chan error, 8)
	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for range 500 {
				body, exists, err := ReadMirrorlist(root, parent.MirrorlistPath)
				if err != nil || !exists {
					errorsByReader <- errors.Join(err, errors.New("mirrorlist disappeared during flip"))
					return
				}
				if !bytes.Equal(body, oldBody) && !bytes.Equal(body, newBody) {
					errorsByReader <- errors.New("reader observed a partial mirrorlist body")
					return
				}
			}
		}()
	}
	close(start)
	if _, err := ReconcileMirrorlist(root, desired); err != nil {
		t.Fatal(err)
	}
	readers.Wait()
	close(errorsByReader)
	for err := range errorsByReader {
		if err != nil {
			t.Fatal(err)
		}
	}
	final, exists, err := ReadMirrorlist(root, desired.MirrorlistPath)
	if err != nil || !exists || !bytes.Equal(final, newBody) {
		t.Fatalf("final mirrorlist=%q exists=%v err=%v", final, exists, err)
	}
}
