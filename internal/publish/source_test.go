package publish

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectorySourceRejectsSymlinksAndEscapes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "file-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "dir-link")); err != nil {
		t.Fatal(err)
	}
	source := DirectorySource{Root: root}
	if _, err := source.Open("file-link"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("final symlink was not rejected: %v", err)
	}
	if _, err := source.Open("dir-link/secret"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("parent symlink escape was not rejected: %v", err)
	}
}
