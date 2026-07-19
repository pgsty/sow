package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
)

func installedCompatibilityTrustFixture(t *testing.T) (string, *repository.Store, frozenYUMCompatibilityServingEvidence) {
	t.Helper()
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	evidence := frozenYUMCompatibilityServingEvidence{
		projection:      config.YUMCompatibilityProjection{ID: "infra-legacy-x86-64"},
		packageTrust:    []byte("package trust bytes\n"),
		repositoryTrust: []byte("repository trust bytes\n"),
	}
	for relative, body := range map[string][]byte{
		config.YUMCompatibilityPackageTrustRoute(evidence.projection.ID):    evidence.packageTrust,
		config.YUMCompatibilityRepositoryTrustRoute(evidence.projection.ID): evidence.repositoryTrust,
	} {
		object, err := pool.Put(t.Context(), bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		physical := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(physical), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(pool.ObjectPath(object.SHA256), physical); err != nil {
			t.Fatal(err)
		}
	}
	return root, pool, evidence
}

func TestCompatibilityTrustPermissionClosureIsPathBoundIsomorphic(t *testing.T) {
	validators := []struct {
		name     string
		validate func(*testing.T, string, *repository.Store, frozenYUMCompatibilityServingEvidence) error
	}{
		{
			name: "ordinary",
			validate: func(t *testing.T, root string, pool *repository.Store, evidence frozenYUMCompatibilityServingEvidence) error {
				return validateInstalledFrozenYUMCompatibilityTrust(t.Context(), pool, root, evidence)
			},
		},
		{
			name: "bound",
			validate: func(t *testing.T, root string, pool *repository.Store, evidence frozenYUMCompatibilityServingEvidence) error {
				handle, err := os.OpenRoot(root)
				if err != nil {
					return err
				}
				defer handle.Close()
				return validateInstalledFrozenYUMCompatibilityTrustAtRoot(t.Context(), pool, handle, evidence)
			},
		},
	}
	for _, validator := range validators {
		validator := validator
		t.Run(validator.name+"/baseline", func(t *testing.T) {
			root, pool, evidence := installedCompatibilityTrustFixture(t)
			if err := validator.validate(t, root, pool, evidence); err != nil {
				t.Fatal(err)
			}
		})
		t.Run(validator.name+"/mode-0600-file", func(t *testing.T) {
			root, pool, evidence := installedCompatibilityTrustFixture(t)
			file := filepath.Join(root, filepath.FromSlash(config.YUMCompatibilityPackageTrustRoute(evidence.projection.ID)))
			if err := os.Chmod(file, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validator.validate(t, root, pool, evidence); err == nil || !strings.Contains(err.Error(), "0444") {
				t.Fatalf("private trust file accepted: %v", err)
			}
		})
		t.Run(validator.name+"/mode-0700-parent", func(t *testing.T) {
			root, pool, evidence := installedCompatibilityTrustFixture(t)
			parent := filepath.Join(root, "_sow", "v1", "trust")
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := validator.validate(t, root, pool, evidence); err == nil || !strings.Contains(err.Error(), "0755") {
				t.Fatalf("private trust parent accepted: %v", err)
			}
		})
	}
}

func TestCompatibilityTrustReverifiesRetainedCASAfterPublicInodeComparison(t *testing.T) {
	root, pool, evidence := installedCompatibilityTrustFixture(t)
	relative := config.YUMCompatibilityPackageTrustRoute(evidence.projection.ID)
	physical := filepath.Join(root, filepath.FromSlash(relative))
	malicious := append([]byte(nil), evidence.packageTrust...)
	malicious[0] ^= 0x7f
	mutated := false
	err := validateInstalledFrozenYUMCompatibilityTrustWithHook(t.Context(), pool, root, evidence, func(observed string) error {
		if observed != relative || mutated {
			return nil
		}
		mutated = true
		if err := os.Chmod(physical, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(physical, malicious, 0o644); err != nil {
			return err
		}
		return os.Chmod(physical, 0o444)
	})
	if !mutated {
		t.Fatal("post-CAS verification trust hook did not run")
	}
	if err == nil || !errors.Is(err, repository.ErrObjectCorrupt) {
		t.Fatalf("same-length in-place trust/CAS rewrite was accepted: %v", err)
	}
}
