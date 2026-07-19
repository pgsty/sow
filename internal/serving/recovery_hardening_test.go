package serving

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
)

func installedServingFixture(t *testing.T) (string, string, Generation, *repository.Store, InstallOptions) {
	t.Helper()
	root := t.TempDir()
	manifestPath := writeServingFixture(t, root)
	generation := deriveFixtureGeneration(t, manifestPath)
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	options := InstallOptions{Workers: 2, ChunkEntries: 2, TempDir: filepath.Join(root, ".sow")}
	if _, err := InstallGeneration(t.Context(), pool, root, generation, manifestPath, options); err != nil {
		t.Fatal(err)
	}
	return root, manifestPath, generation, pool, options
}

func TestValidateAndScanInstalledGenerationAreConfinedAndExact(t *testing.T) {
	t.Run("baseline", func(t *testing.T) {
		root, manifestPath, generation, pool, options := installedServingFixture(t)
		if err := ValidateInstalledGeneration(t.Context(), pool, root, generation, manifestPath, options); err != nil {
			t.Fatal(err)
		}
		assertServingTreeHostable(t, filepath.Join(root, "_sow", "v1", "g", generation.ID))
		scanned := filepath.Join(root, ".sow", "scanned.tsv")
		if err := ScanInstalledGeneration(t.Context(), pool, root, generation, scanned, options); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("permission drift is rejected and replay repairs it", func(t *testing.T) {
		root, manifestPath, generation, pool, options := installedServingFixture(t)
		generationRoot := filepath.Join(root, "_sow", "v1", "g", generation.ID)
		privateDirectory := filepath.Join(generationRoot, "yum", "test")
		if err := os.Chmod(generationRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(privateDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := ValidateInstalledGeneration(t.Context(), pool, root, generation, manifestPath, options); err == nil || !strings.Contains(err.Error(), "mode=") {
			t.Fatalf("non-hostable generation accepted: %v", err)
		}
		installed, err := InstallGeneration(t.Context(), pool, root, generation, manifestPath, options)
		if err != nil || installed.Created {
			t.Fatalf("permission repair result=%+v err=%v", installed, err)
		}
		assertServingTreeHostable(t, generationRoot)
	})

	t.Run("same-byte copy is rejected and replay restores CAS hardlink", func(t *testing.T) {
		root, manifestPath, generation, pool, options := installedServingFixture(t)
		generationRoot := filepath.Join(root, "_sow", "v1", "g", generation.ID)
		filename := filepath.Join(generationRoot, "yum", "test", "x86_64", "repodata", "repomd.xml")
		body, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		replacement := filename + ".copy"
		if err := os.WriteFile(replacement, body, 0o444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(replacement, 0o444); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, filename); err != nil {
			t.Fatal(err)
		}
		if err := ValidateInstalledGeneration(t.Context(), pool, root, generation, manifestPath, options); err == nil || !strings.Contains(err.Error(), "canonical CAS hardlink") {
			t.Fatalf("same-byte non-CAS copy accepted: %v", err)
		}
		if _, err := InstallGeneration(t.Context(), pool, root, generation, manifestPath, options); err != nil {
			t.Fatal(err)
		}
		targetInfo, err := os.Stat(filename)
		if err != nil {
			t.Fatal(err)
		}
		digest := repository.Digest(sha256.Sum256(body))
		object, err := pool.Open(digest)
		if err != nil {
			t.Fatal(err)
		}
		objectInfo, statErr := object.Stat()
		closeErr := object.Close()
		if statErr != nil || closeErr != nil || !os.SameFile(targetInfo, objectInfo) {
			t.Fatalf("replay did not restore CAS hardlink stat=%v close=%v", statErr, closeErr)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string, Generation)
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, root string, generation Generation) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, "_sow", "v1", "g", generation.ID, "yum", "test", "x86_64", "repodata", "repomd.xml")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "changed",
			mutate: func(t *testing.T, root string, generation Generation) {
				t.Helper()
				path := filepath.Join(root, "_sow", "v1", "g", generation.ID, "yum", "test", "x86_64", "repodata", "repomd.xml")
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("changed\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "extra",
			mutate: func(t *testing.T, root string, generation Generation) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, "_sow", "v1", "g", generation.ID, "extra"), []byte("extra\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, manifestPath, generation, pool, options := installedServingFixture(t)
			test.mutate(t, root, generation)
			if err := ValidateInstalledGeneration(t.Context(), pool, root, generation, manifestPath, options); err == nil || !strings.Contains(err.Error(), "manifest drift") {
				t.Fatalf("drift accepted: %v", err)
			}
		})
	}

	t.Run("parent symlink", func(t *testing.T) {
		root, manifestPath, generation, pool, options := installedServingFixture(t)
		generationBase := filepath.Join(root, "_sow", "v1", "g")
		realBase := generationBase + "-real"
		if err := os.Rename(generationBase, realBase); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realBase, generationBase); err != nil {
			t.Fatal(err)
		}
		if err := ValidateInstalledGeneration(t.Context(), pool, root, generation, manifestPath, options); err == nil || !strings.Contains(err.Error(), "generation parent") {
			t.Fatalf("symlinked parent accepted: %v", err)
		}
		if err := ScanInstalledGeneration(t.Context(), pool, root, generation, filepath.Join(root, ".sow", "scan.tsv"), options); err == nil || !strings.Contains(err.Error(), "generation parent") {
			t.Fatalf("scan accepted symlinked parent: %v", err)
		}
	})

	t.Run("target symlink", func(t *testing.T) {
		root, manifestPath, generation, pool, options := installedServingFixture(t)
		alias := filepath.Join(root, "alias")
		if err := os.Symlink(root, alias); err != nil {
			t.Fatal(err)
		}
		if err := ValidateInstalledGeneration(t.Context(), pool, alias, generation, manifestPath, options); err == nil || !strings.Contains(err.Error(), "not a real directory") {
			t.Fatalf("symlinked target accepted: %v", err)
		}
	})

	t.Run("target parent symlink", func(t *testing.T) {
		root := t.TempDir()
		realParent := filepath.Join(root, "real")
		target := filepath.Join(realParent, "target")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(root, "alias")
		if err := os.Symlink(realParent, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := validateTargetRoot(root, filepath.Join(alias, "target")); err == nil || !strings.Contains(err.Error(), "not a real directory") {
			t.Fatalf("symlinked target parent accepted: %v", err)
		}
	})

	t.Run("manifest identity", func(t *testing.T) {
		root, _, generation, pool, options := installedServingFixture(t)
		file, err := os.OpenFile(filepath.Join(root, "yum", "test", "x86_64", "extra"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString("extra\n"); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		// Re-scan a manifest that no longer derives the occupied generation.
		wrong := filepath.Join(root, ".sow", "wrong.tsv")
		if _, err := manifest.Scan(t.Context(), root, manifest.Scope{Path: "yum/test/x86_64"}, wrong, manifest.ScanOptions{Workers: 2, ChunkEntries: 2, TempDir: filepath.Join(root, ".sow")}); err != nil {
			t.Fatal(err)
		}
		if err := ValidateInstalledGeneration(t.Context(), pool, root, generation, wrong, options); err == nil || !strings.Contains(err.Error(), "does not match exact manifest") {
			t.Fatalf("wrong canonical manifest accepted: %v", err)
		}
	})
}

func assertServingTreeHostable(t *testing.T, root string) {
	t.Helper()
	if err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.IsDir() && info.Mode().Perm() != 0o755 {
			t.Errorf("directory %s mode=%#o want=0755", current, info.Mode().Perm())
		}
		if !info.IsDir() && (!info.Mode().IsRegular() || info.Mode().Perm() != 0o444) {
			t.Errorf("file %s mode=%#o want=0444", current, info.Mode().Perm())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupTransactionTempsUsesStrictOwnedPatterns(t *testing.T) {
	root := t.TempDir()
	if _, err := repository.NewStore(root); err != nil {
		t.Fatal(err)
	}
	generationBase := filepath.Join(root, "_sow", "v1", "g")
	mirrorBase := filepath.Join(root, "_sow", "v1", "mirrorlist", "latest", "rpm-test", "el10")
	if err := os.MkdirAll(generationBase, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mirrorBase, 0o755); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(generationBase, ".stage-12345678901234567890-"+strings.Repeat("a", 32))
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	mirror := filepath.Join(mirrorBase, ".mirrorlist-"+strings.Repeat("b", 32))
	if err := os.WriteFile(mirror, []byte("partial\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := CleanupTransactionTemps(root, root)
	if err != nil || removed != 2 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	for _, path := range []string{stage, mirror} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("temporary coordinate survived %s: %v", path, err)
		}
	}

	malformed := filepath.Join(generationBase, ".stage-not-owned")
	if err := os.Mkdir(malformed, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupTransactionTemps(root, root); err == nil || !strings.Contains(err.Error(), "unsafe generation stage") {
		t.Fatalf("malformed reserved stage accepted: %v", err)
	}
	if _, err := os.Stat(malformed); err != nil {
		t.Fatalf("strict cleanup removed malformed coordinate: %v", err)
	}
}
