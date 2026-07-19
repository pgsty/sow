package serving

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/repository"
)

func TestInstallGenerationRejectsTargetRootReplacementBeforeMutation(t *testing.T) {
	for _, phase := range []string{"materialize-generation-stage", "install-generation-stage"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			manifestPath := writeServingFixture(t, root)
			generation := deriveFixtureGeneration(t, manifestPath)
			pool, err := repository.NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			options := InstallOptions{Workers: 2, ChunkEntries: 2, TempDir: filepath.Join(root, ".sow")}
			moved := root + "-bound-inode"
			var swapped bool
			var stageName string
			ctx := withInstallMutationHook(t.Context(), func(observed string) error {
				if observed != phase || swapped {
					return nil
				}
				entries, err := os.ReadDir(filepath.Join(root, "_sow", "v1", "g"))
				if err != nil {
					return err
				}
				for _, entry := range entries {
					if entry.IsDir() && strings.HasPrefix(entry.Name(), ".stage-"+generation.ID+"-") {
						stageName = entry.Name()
						break
					}
				}
				if stageName == "" {
					return errors.New("fault hook could not find the owned generation stage")
				}
				if err := os.Rename(root, moved); err != nil {
					return err
				}
				swapped = true
				replacementBase := filepath.Join(root, "_sow", "v1", "g")
				if err := os.MkdirAll(filepath.Join(replacementBase, stageName), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(replacementBase, stageName, "operator-sentinel"), []byte("keep\n"), 0o600); err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Join(replacementBase, generation.ID), 0o755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(replacementBase, generation.ID, "operator-sentinel"), []byte("keep\n"), 0o600)
			})

			_, installErr := InstallGeneration(ctx, pool, root, generation, manifestPath, options)
			if !swapped {
				t.Fatal("fault hook did not replace the target root")
			}
			if installErr == nil || !strings.Contains(installErr.Error(), "serving target root identity changed immediately before "+phase) {
				t.Fatalf("target replacement was not rejected before %s: %v", phase, installErr)
			}
			for _, sentinel := range []string{
				filepath.Join(root, "_sow", "v1", "g", stageName, "operator-sentinel"),
				filepath.Join(root, "_sow", "v1", "g", generation.ID, "operator-sentinel"),
			} {
				body, err := os.ReadFile(sentinel)
				if err != nil || string(body) != "keep\n" {
					t.Fatalf("replacement root was mutated at %s: body=%q err=%v", sentinel, body, err)
				}
			}
			if _, err := os.Lstat(filepath.Join(moved, "_sow", "v1", "g", stageName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("bound stage cleanup did not remove the original stage: %v", err)
			}

			// Restore the t.TempDir namespace so the test framework can remove
			// the original repository and no sibling directory leaks.
			if err := os.RemoveAll(root); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(moved, root); err != nil {
				t.Fatal(err)
			}
		})
	}
}
