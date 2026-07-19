package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
)

func writeCompatibilityCandidateHostabilityFixture(t *testing.T) (*config.Config, string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".sow"), 0o711); err != nil {
		t.Fatal(err)
	}
	relative := filepath.ToSlash(filepath.Join(".sow", "materialized", "compatibility", "infra-legacy-x86-64", strings.Repeat("a", 64)))
	tree := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Join(tree, "repodata"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(tree, "repodata", "repomd.xml")
	if err := os.WriteFile(file, []byte("repomd\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o444); err != nil {
		t.Fatal(err)
	}
	return &config.Config{Root: root}, relative, file
}

func TestYUMCompatibilityCandidateHostabilityRejectsPrivateClosureInBothModes(t *testing.T) {
	validators := []struct {
		name     string
		validate func(*testing.T, *config.Config, string) error
	}{
		{
			name: "ordinary",
			validate: func(_ *testing.T, cfg *config.Config, relative string) error {
				return validateYUMCompatibilityCandidateHostability(cfg, relative, nil)
			},
		},
		{
			name: "bound",
			validate: func(t *testing.T, cfg *config.Config, relative string) error {
				handle, err := os.OpenRoot(cfg.Root)
				if err != nil {
					return err
				}
				defer handle.Close()
				return validateYUMCompatibilityCandidateHostability(cfg, relative, &yumCompatibilityReadBinding{repositoryRoot: handle})
			},
		},
	}
	for _, validator := range validators {
		validator := validator
		t.Run(validator.name+"/baseline-0711-corridor", func(t *testing.T) {
			cfg, relative, _ := writeCompatibilityCandidateHostabilityFixture(t)
			if err := validator.validate(t, cfg, relative); err != nil {
				t.Fatal(err)
			}
		})
		t.Run(validator.name+"/mode-0600-file", func(t *testing.T) {
			cfg, relative, file := writeCompatibilityCandidateHostabilityFixture(t)
			if err := os.Chmod(file, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validator.validate(t, cfg, relative); err == nil || !strings.Contains(err.Error(), "0444") {
				t.Fatalf("private candidate file accepted: %v", err)
			}
		})
		t.Run(validator.name+"/mode-0700-parent", func(t *testing.T) {
			cfg, relative, _ := writeCompatibilityCandidateHostabilityFixture(t)
			if err := os.Chmod(filepath.Join(cfg.Root, ".sow", "materialized", "compatibility"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := validator.validate(t, cfg, relative); err == nil || !strings.Contains(err.Error(), "0755") {
				t.Fatalf("private candidate parent accepted: %v", err)
			}
		})
	}
}
