package compat_test

import (
	"os"
	"testing"
)

// hostableCompatTempDir places end-to-end repository fixtures below a real,
// other-traversable ancestor chain. Go's default test temp root is 0700 and is
// reached through /var symlinks on macOS, so it cannot model a tree that the
// production Nginx route receipt is allowed to advertise.
func hostableCompatTempDir(t *testing.T) string {
	t.Helper()
	base := "/private/tmp"
	if info, err := os.Lstat(base); err != nil || !info.IsDir() {
		base = "/tmp"
	}
	root, err := os.MkdirTemp(base, "sow-compat-hostable-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		_ = os.RemoveAll(root)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(root, 0o755)
		_ = os.RemoveAll(root)
	})
	return root
}
