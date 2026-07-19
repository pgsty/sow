package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"golang.org/x/sys/unix"
)

func TestLatestWorkingTreeTGZContainsActivatedStrongYUMRoutesAndNoTemps(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	generationTemp := filepath.Join(root, "_sow", "v1", "g", ".stage-12345678901234567890-"+strings.Repeat("a", 32))
	mirrorTemp := filepath.Join(root, "_sow", "v1", "mirrorlist", "latest", "rpm-test", "el10", ".mirrorlist-"+strings.Repeat("b", 32))
	if err := os.MkdirAll(generationTemp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(mirrorTemp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mirrorTemp, []byte("partial\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(root, "offline", "latest.tgz")
	arguments := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--tgz", archivePath, "--workers", "2", "--chunk-entries", "2"}
	code, stdout, stderr := runServingCLI(t, arguments...)
	if code != ExitOK || !strings.Contains(stdout, "archive path=") {
		t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	mirror := "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"
	generation := mirrorGenerationID(t, root, mirror)
	encoded, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	assertArchiveNames(t, encoded,
		mirror,
		"_sow/v1/g/"+generation+"/yum/test/x86_64/repodata/repomd.xml",
		"_sow/v1/g/"+generation+"/yum/test/x86_64/repodata/repomd.xml.asc",
	)
	for _, forbidden := range []string{
		"_sow/v1/g/" + filepath.Base(generationTemp),
		"_sow/v1/mirrorlist/latest/rpm-test/el10/" + filepath.Base(mirrorTemp),
		"offline/latest.tgz",
	} {
		if archiveHasPath(t, encoded, forbidden) {
			t.Fatalf("archive contains forbidden temporary/self path %s", forbidden)
		}
	}
	for _, temporary := range []string{generationTemp, mirrorTemp} {
		if _, err := os.Lstat(temporary); !os.IsNotExist(err) {
			t.Fatalf("temporary coordinate survived materialize: %s err=%v", temporary, err)
		}
	}

	// An existing exact regular destination is replaced deterministically and
	// still cannot become an input entry.
	code, _, stderr = runServingCLI(t, arguments...)
	if code != ExitOK {
		t.Fatalf("existing regular archive replay code=%d stderr=%s", code, stderr)
	}
}

func archiveHasPath(t *testing.T, encoded []byte, wanted string) bool {
	t.Helper()
	gzipReader, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	reader := tar.NewReader(gzipReader)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == wanted {
			return true
		}
	}
}

func TestMaterializeTGZDestinationRejectsReservedRepoConfigAndSymlinkCoordinates(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "existing-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(root, "existing.tgz")
	if err := os.WriteFile(regular, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkDestination := filepath.Join(root, "symlink.tgz")
	if err := os.Symlink(regular, symlinkDestination); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{
		".sow/archive.tgz",
		".pool/archive.tgz",
		".git/archive.tgz",
		"_sow/archive.tgz",
		"yum/test/x86_64/archive.tgz",
		configPath,
		"linked/archive.tgz",
		"existing-dir",
		symlinkDestination,
	} {
		t.Run(strings.ReplaceAll(destination, "/", "_"), func(t *testing.T) {
			code, stdout, stderr := runServingCLI(t, "materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--tgz", destination, "--workers", "2", "--chunk-entries", "2")
			if code != ExitUsage || !strings.Contains(stderr, "offline archive destination") {
				t.Fatalf("destination=%s code=%d stdout=%s stderr=%s", destination, code, stdout, stderr)
			}
		})
	}
}

func TestExplicitMaterializeTargetCannotClaimAnyInternalDefaultRoot(t *testing.T) {
	_, configPath, _, keyPath, _ := setupServingYUMView(t)
	for _, target := range []string{
		".sow/materialized/beta",
		".sow/materialized/stable",
		".sow/origin/gated",
		".sow/origin/gated/nested",
		"_sow/v1/g/export",
	} {
		t.Run(strings.ReplaceAll(target, "/", "_"), func(t *testing.T) {
			code, stdout, stderr := runServingCLI(t, "materialize", "beta", "--config", configPath, "--repo", "rpm-test", "--target", target, "--serving-base-url", "https://export.example.invalid", "--gpg-private-key-file", keyPath)
			if code != ExitUsage || !strings.Contains(stderr, "reserved control directory") {
				t.Fatalf("target=%s code=%d stdout=%s stderr=%s", target, code, stdout, stderr)
			}
		})
	}
}

func TestLocalServingJournalRecoveryCleansOnlyExactTempsAndBoundsReaders(t *testing.T) {
	t.Run("recover exact temp", func(t *testing.T) {
		root, configPath, _, _, _ := setupServingYUMView(t)
		cfg, _, err := loadAndSelect(commonFlags{configPath: configPath, workers: 2, chunk: 2})
		if err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(cfg.StatePath(), "serving-journal")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		temporary := filepath.Join(directory, strings.Repeat("a", 32)+".json.tmp-"+strings.Repeat("b", 16))
		if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		canonical := state.New(filepath.Join(root, ".sow"))
		if err := prepareLocalServingState(t.Context(), cfg, canonical, true, commonFlags{workers: 2, chunk: 2}, io.Discard); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(temporary); !os.IsNotExist(err) {
			t.Fatalf("interrupted write temp survived --recover: %v", err)
		}
	})

	t.Run("malformed temp is never broadly removed", func(t *testing.T) {
		stateRoot := filepath.Join(t.TempDir(), ".sow")
		directory := filepath.Join(stateRoot, "serving-journal")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		malformed := filepath.Join(directory, strings.Repeat("a", 32)+".json.tmp-not-owned")
		if err := os.WriteFile(malformed, []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := cleanupLocalServingJournalTemps(stateRoot); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(malformed); err != nil {
			t.Fatalf("strict cleanup removed malformed coordinate: %v", err)
		}
		if _, err := listLocalServingJournals(stateRoot); err == nil || !strings.Contains(err.Error(), "unsafe local serving journal entry") {
			t.Fatalf("malformed journal temp was silently accepted: %v", err)
		}
	})

	for _, test := range []struct {
		name   string
		create func(*testing.T, string)
		want   string
	}{
		{
			name: "fifo",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := unix.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "exact regular file",
		},
		{
			name: "oversize",
			create: func(t *testing.T, path string) {
				t.Helper()
				file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Truncate(localServingJournalMaxBytes + 1); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
			want: "byte limit",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateRoot := filepath.Join(t.TempDir(), ".sow")
			directory := filepath.Join(stateRoot, "serving-journal")
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			test.create(t, filepath.Join(directory, strings.Repeat("c", 32)+".json"))
			if _, err := listLocalServingJournals(stateRoot); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsafe journal reader accepted %s: %v", test.name, err)
			}
		})
	}

	t.Run("symlink parent", func(t *testing.T) {
		stateRoot := filepath.Join(t.TempDir(), ".sow")
		if err := os.MkdirAll(stateRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), filepath.Join(stateRoot, "serving-journal")); err != nil {
			t.Fatal(err)
		}
		if _, err := listLocalServingJournals(stateRoot); err == nil || !strings.Contains(err.Error(), "not a real directory") {
			t.Fatalf("symlinked journal parent accepted: %v", err)
		}
	})

	t.Run("symlink state-root parent", func(t *testing.T) {
		realRoot := t.TempDir()
		if err := os.MkdirAll(filepath.Join(realRoot, ".sow", "serving-journal"), 0o700); err != nil {
			t.Fatal(err)
		}
		aliasParent := filepath.Join(t.TempDir(), "repository")
		if err := os.Symlink(realRoot, aliasParent); err != nil {
			t.Fatal(err)
		}
		if _, err := listLocalServingJournals(filepath.Join(aliasParent, ".sow")); err == nil || !strings.Contains(err.Error(), "state root parent") {
			t.Fatalf("symlinked state-root parent accepted: %v", err)
		}
	})
}

func TestLocalYUMServingReadyValidatesCanonicalManifestAgainstExactGenerationTree(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	arguments := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	cfg, repos, err := loadAndSelect(commonFlags{configPath: configPath, workers: 2, chunk: 2})
	if err != nil {
		t.Fatal(err)
	}
	privateKey, passphrase, keySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, selectedLeaves(repos, commonFlags{}), keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	canonical := state.New(cfg.StatePath())
	ready, err := localYUMServingReady(cfg, canonical, repos, "latest", keySHA, commonFlags{workers: 2, chunk: 2})
	if err != nil || !ready {
		t.Fatalf("baseline ready=%v err=%v", ready, err)
	}
	mirror := "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"
	generation := mirrorGenerationID(t, root, mirror)
	extra := filepath.Join(root, "_sow", "v1", "g", generation, "extra")
	if err := os.WriteFile(extra, []byte("drift\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ready, err = localYUMServingReady(cfg, canonical, repos, "latest", keySHA, commonFlags{workers: 2, chunk: 2})
	if err == nil || ready || !strings.Contains(err.Error(), "manifest drift") {
		t.Fatalf("extra generation file accepted ready=%v err=%v", ready, err)
	}
	if matches, err := filepath.Glob(filepath.Join(cfg.StatePath(), "transactions", "serving-ready-*")); err != nil || len(matches) != 0 {
		t.Fatalf("bounded canonical TSV transaction leaked matches=%v err=%v", matches, err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pool.PoolRoot()); err != nil {
		t.Fatalf("CAS root changed during readiness validation: %v", err)
	}
}
