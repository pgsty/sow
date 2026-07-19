package serving

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeHostableFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	tree := filepath.Join(root, "served", "tree")
	file := filepath.Join(tree, "payload")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("payload\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o444); err != nil {
		t.Fatal(err)
	}
	return root, filepath.ToSlash(filepath.Join("served", "tree")), filepath.ToSlash(filepath.Join("served", "tree", "payload"))
}

func TestHostableValidationPathAndBoundRootAreIsomorphic(t *testing.T) {
	type validator struct {
		name string
		tree func(string, string) error
		file func(string, string) error
	}
	validators := []validator{
		{name: "ordinary", tree: ValidateHostableTree, file: ValidateHostableFile},
		{
			name: "bound",
			tree: func(root, relative string) error {
				handle, err := os.OpenRoot(root)
				if err != nil {
					return err
				}
				defer handle.Close()
				return ValidateHostableTreeRoot(handle, relative)
			},
			file: func(root, relative string) error {
				handle, err := os.OpenRoot(root)
				if err != nil {
					return err
				}
				defer handle.Close()
				return ValidateHostableFileRoot(handle, relative)
			},
		},
	}
	for _, validate := range validators {
		validate := validate
		t.Run(validate.name+"/baseline", func(t *testing.T) {
			root, tree, file := writeHostableFixture(t)
			if err := validate.tree(root, tree); err != nil {
				t.Fatalf("tree: %v", err)
			}
			if err := validate.file(root, file); err != nil {
				t.Fatalf("file: %v", err)
			}
		})
		t.Run(validate.name+"/mode-0600-file", func(t *testing.T) {
			root, tree, file := writeHostableFixture(t)
			if err := os.Chmod(filepath.Join(root, filepath.FromSlash(file)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validate.tree(root, tree); err == nil || !strings.Contains(err.Error(), "0444") {
				t.Fatalf("private tree file accepted: %v", err)
			}
			if err := validate.file(root, file); err == nil || !strings.Contains(err.Error(), "0444") {
				t.Fatalf("private served file accepted: %v", err)
			}
		})
		t.Run(validate.name+"/mode-0700-parent", func(t *testing.T) {
			root, tree, file := writeHostableFixture(t)
			if err := os.Chmod(filepath.Join(root, "served"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := validate.tree(root, tree); err == nil || !strings.Contains(err.Error(), "0755") {
				t.Fatalf("private tree parent accepted: %v", err)
			}
			if err := validate.file(root, file); err == nil || !strings.Contains(err.Error(), "0755") {
				t.Fatalf("private file parent accepted: %v", err)
			}
		})
	}
}
