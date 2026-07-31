package serving

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/repository"
)

func TestValidateInstalledGenerationRootRejectsNilDependencies(t *testing.T) {
	if err := ValidateInstalledGenerationRoot(context.Background(), nil, nil, Generation{}, "", InstallOptions{}); err == nil || !strings.Contains(err.Error(), "dependencies are unavailable") {
		t.Fatalf("nil pool/root validation dependencies were accepted: %v", err)
	}
}

func TestValidateInstalledGenerationCanonicalSubsetAllowsOnlyPrunableExtras(t *testing.T) {
	t.Run("extra regular file", func(t *testing.T) {
		root, manifestPath, generation, pool, options := installedServingFixture(t)
		extra := filepath.Join(root, "_sow", "v1", "g", generation.ID, "unowned-private.bin")
		if err := os.WriteFile(extra, []byte("prune me\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ValidateInstalledGenerationCanonicalSubset(t.Context(), pool, root, generation, manifestPath, options); err != nil {
			t.Fatalf("prunable extra regular file rejected: %v", err)
		}
		if err := ValidateInstalledGeneration(t.Context(), pool, root, generation, manifestPath, options); err == nil || !strings.Contains(err.Error(), "added=1") {
			t.Fatalf("ordinary exact validator accepted extra file: %v", err)
		}
	})

	t.Run("shadow-point extra regular file", func(t *testing.T) {
		root, manifestPath, generation, pool, options := installedServingFixture(t)
		extra := filepath.Join(root, "_sow", "v1", "g", generation.ID, ".sow", "private.bin")
		if err := os.MkdirAll(filepath.Dir(extra), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(extra, []byte("prune me\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ValidateInstalledGenerationCanonicalSubset(t.Context(), pool, root, generation, manifestPath, options); err != nil {
			t.Fatalf("prunable shadow-point regular file rejected: %v", err)
		}
		if err := ValidateInstalledGeneration(t.Context(), pool, root, generation, manifestPath, options); err == nil || !strings.Contains(err.Error(), "added=1") {
			t.Fatalf("ordinary exact validator accepted shadow-point extra file: %v", err)
		}
	})

	t.Run("changed canonical file", func(t *testing.T) {
		root, manifestPath, generation, pool, options := installedServingFixture(t)
		target := filepath.Join(root, "_sow", "v1", "g", generation.ID, "yum", "test", "x86_64", "repodata", "repomd.xml")
		body, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		body[0] ^= 0x7f
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, body, 0o444); err != nil {
			t.Fatal(err)
		}
		if err := ValidateInstalledGenerationCanonicalSubset(t.Context(), pool, root, generation, manifestPath, options); err == nil || !strings.Contains(err.Error(), "changed=1") {
			t.Fatalf("changed canonical generation file accepted: %v", err)
		}
	})

	t.Run("unsafe extra symlink", func(t *testing.T) {
		root, manifestPath, generation, pool, options := installedServingFixture(t)
		extra := filepath.Join(root, "_sow", "v1", "g", generation.ID, "unowned-link")
		if err := os.Symlink(t.TempDir(), extra); err != nil {
			t.Fatal(err)
		}
		if err := ValidateInstalledGenerationCanonicalSubset(t.Context(), pool, root, generation, manifestPath, options); err == nil {
			t.Fatal("unsafe extra symlink accepted")
		}
	})

	t.Run("unsafe shadow-point symlink", func(t *testing.T) {
		root, manifestPath, generation, pool, options := installedServingFixture(t)
		extra := filepath.Join(root, "_sow", "v1", "g", generation.ID, ".sow")
		if err := os.Symlink(t.TempDir(), extra); err != nil {
			t.Fatal(err)
		}
		if err := ValidateInstalledGenerationCanonicalSubset(t.Context(), pool, root, generation, manifestPath, options); err == nil {
			t.Fatal("unsafe shadow-point symlink accepted")
		}
	})
}

func TestValidateInstalledGenerationPathAndBoundRejectPermissionDrift(t *testing.T) {
	validators := []struct {
		name     string
		validate func(*testing.T, string, string, Generation, *repository.Store, InstallOptions) error
	}{
		{
			name: "ordinary",
			validate: func(t *testing.T, root, manifestPath string, generation Generation, pool *repository.Store, options InstallOptions) error {
				return ValidateInstalledGeneration(t.Context(), pool, root, generation, manifestPath, options)
			},
		},
		{
			name: "bound",
			validate: func(t *testing.T, root, manifestPath string, generation Generation, pool *repository.Store, options InstallOptions) error {
				handle, err := os.OpenRoot(root)
				if err != nil {
					return err
				}
				defer handle.Close()
				return ValidateInstalledGenerationRoot(t.Context(), pool, handle, generation, manifestPath, options)
			},
		},
	}
	for _, validator := range validators {
		validator := validator
		t.Run(validator.name+"/mode-0600-file", func(t *testing.T) {
			root, manifestPath, generation, pool, options := installedServingFixture(t)
			file := filepath.Join(root, "_sow", "v1", "g", generation.ID, "yum", "test", "x86_64", "repodata", "repomd.xml")
			if err := os.Chmod(file, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validator.validate(t, root, manifestPath, generation, pool, options); err == nil || !strings.Contains(err.Error(), "0444") {
				t.Fatalf("private generation file accepted: %v", err)
			}
		})
		t.Run(validator.name+"/mode-0700-parent", func(t *testing.T) {
			root, manifestPath, generation, pool, options := installedServingFixture(t)
			parent := filepath.Join(root, "_sow", "v1", "g")
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := validator.validate(t, root, manifestPath, generation, pool, options); err == nil || !strings.Contains(err.Error(), "0755") {
				t.Fatalf("private generation parent accepted: %v", err)
			}
		})
	}
}

func TestValidateInstalledGenerationRootReverifiesCASAfterManifestScan(t *testing.T) {
	root, manifestPath, generation, pool, options := installedServingFixture(t)
	target := filepath.Join(root, "_sow", "v1", "g", generation.ID, "yum", "test", "x86_64", "repodata", "repomd.xml")
	original, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	malicious := append([]byte(nil), original...)
	for index := range malicious {
		if malicious[index] != '\n' {
			malicious[index] ^= 0x5a
		}
	}
	if string(malicious) == string(original) {
		t.Fatal("fault body did not change")
	}
	mutated := false
	ctx := withGenerationValidationHook(t.Context(), func(phase, _ string) error {
		if phase != generationValidationAfterManifestScan || mutated {
			return nil
		}
		mutated = true
		if err := os.Chmod(target, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(target, malicious, 0o644); err != nil {
			return err
		}
		return os.Chmod(target, 0o444)
	})
	handle, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	err = ValidateInstalledGenerationRoot(ctx, pool, handle, generation, manifestPath, options)
	if !mutated {
		t.Fatal("after-scan fault hook did not run")
	}
	if err == nil || !errors.Is(err, repository.ErrObjectCorrupt) {
		t.Fatalf("same-length CAS/hardlink rewrite after scan was accepted: %v", err)
	}
}

func TestValidateInstalledGenerationRootReverifiesRetainedCASAfterIdentityCheck(t *testing.T) {
	root, manifestPath, generation, pool, options := installedServingFixture(t)
	relative := filepath.ToSlash(filepath.Join("yum", "test", "x86_64", "repodata", "repomd.xml"))
	target := filepath.Join(root, "_sow", "v1", "g", generation.ID, filepath.FromSlash(relative))
	original, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	malicious := append([]byte(nil), original...)
	malicious[0] ^= 0x7f
	mutated := false
	ctx := withGenerationValidationHook(t.Context(), func(phase, entry string) error {
		if phase != generationValidationAfterCASVerified || entry != relative || mutated {
			return nil
		}
		mutated = true
		if err := os.Chmod(target, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(target, malicious, 0o644); err != nil {
			return err
		}
		return os.Chmod(target, 0o444)
	})
	handle, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	err = ValidateInstalledGenerationRoot(ctx, pool, handle, generation, manifestPath, options)
	if !mutated {
		t.Fatal("after-CAS-verified fault hook did not run")
	}
	if err == nil || !errors.Is(err, repository.ErrObjectCorrupt) {
		t.Fatalf("same-length retained CAS/hardlink rewrite after first verification was accepted: %v", err)
	}
}
