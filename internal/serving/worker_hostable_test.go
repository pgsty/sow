package serving

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeWorkerHostabilityFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "keys", "public")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "repository.pgp")
	if err := os.WriteFile(file, []byte("public trust\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, "keys/public", "keys/public/repository.pgp"
}

func TestWorkerHostabilityPathAndBoundRootAreIsomorphic(t *testing.T) {
	type validator struct {
		name      string
		directory func(string, string) error
		file      func(string, string) error
	}
	validators := []validator{
		{name: "ordinary", directory: ValidateWorkerTraversableDirectory, file: ValidateWorkerReadableFile},
		{
			name: "bound",
			directory: func(root, relative string) error {
				handle, err := os.OpenRoot(root)
				if err != nil {
					return err
				}
				defer handle.Close()
				return ValidateWorkerTraversableDirectoryRoot(handle, relative)
			},
			file: func(root, relative string) error {
				handle, err := os.OpenRoot(root)
				if err != nil {
					return err
				}
				defer handle.Close()
				return ValidateWorkerReadableFileRoot(handle, relative)
			},
		},
	}
	for _, validate := range validators {
		validate := validate
		t.Run(validate.name+"/baseline", func(t *testing.T) {
			root, directory, file := writeWorkerHostabilityFixture(t)
			if err := validate.directory(root, directory); err != nil {
				t.Fatalf("directory: %v", err)
			}
			if err := validate.file(root, file); err != nil {
				t.Fatalf("file: %v", err)
			}
		})
		t.Run(validate.name+"/mode-0600-file", func(t *testing.T) {
			root, _, file := writeWorkerHostabilityFixture(t)
			if err := os.Chmod(filepath.Join(root, filepath.FromSlash(file)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validate.file(root, file); err == nil || !strings.Contains(err.Error(), "other-read") {
				t.Fatalf("private file accepted: %v", err)
			}
		})
		t.Run(validate.name+"/mode-0700-parent", func(t *testing.T) {
			root, directory, file := writeWorkerHostabilityFixture(t)
			if err := os.Chmod(filepath.Join(root, "keys"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := validate.directory(root, directory); err == nil || !strings.Contains(err.Error(), "other-execute") {
				t.Fatalf("private directory accepted: %v", err)
			}
			if err := validate.file(root, file); err == nil || !strings.Contains(err.Error(), "other-execute") {
				t.Fatalf("private file parent accepted: %v", err)
			}
		})
		t.Run(validate.name+"/symlink-file", func(t *testing.T) {
			root, _, file := writeWorkerHostabilityFixture(t)
			absolute := filepath.Join(root, filepath.FromSlash(file))
			if err := os.Rename(absolute, absolute+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(absolute)+".real", absolute); err != nil {
				t.Fatal(err)
			}
			if err := validate.file(root, file); err == nil || !strings.Contains(err.Error(), "non-symlink") {
				t.Fatalf("symlink file accepted: %v", err)
			}
		})
		t.Run(validate.name+"/symlink-parent", func(t *testing.T) {
			root, directory, file := writeWorkerHostabilityFixture(t)
			if err := os.Rename(filepath.Join(root, "keys"), filepath.Join(root, "real-keys")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real-keys", filepath.Join(root, "keys")); err != nil {
				t.Fatal(err)
			}
			if err := validate.directory(root, directory); err == nil || !strings.Contains(err.Error(), "real directory") {
				t.Fatalf("symlink directory accepted: %v", err)
			}
			if err := validate.file(root, file); err == nil || !strings.Contains(err.Error(), "real directory") {
				t.Fatalf("symlink file parent accepted: %v", err)
			}
		})
	}
}

func TestWorkerAbsoluteHostabilityRejectsPrivateAncestorAboveSuppliedRoot(t *testing.T) {
	base := "/private/tmp"
	if info, err := os.Lstat(base); err != nil || !info.IsDir() {
		base = "/tmp"
	}
	parent, err := os.MkdirTemp(base, "sow-worker-absolute-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(parent, 0o755)
		_ = os.RemoveAll(parent)
	})
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(parent, "operator", "repo")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWorkerTraversableAbsoluteDirectory(leaf); err != nil {
		t.Fatalf("worker-readable absolute baseline: %v", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWorkerTraversableAbsoluteDirectory(leaf); err == nil || !strings.Contains(err.Error(), "other-execute") {
		t.Fatalf("private ancestor above supplied root was accepted: %v", err)
	}
}
