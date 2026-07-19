package cli

import (
	"os"
	"testing"
)

// nginxWorkerTempDir places Nginx permission fixtures below a path whose full
// absolute ancestor chain is other-traversable. Go's platform test temp root is
// intentionally 0700 on macOS and therefore cannot model a different worker
// UID resolving an alias.
func nginxWorkerTempDir(t *testing.T) string {
	t.Helper()
	base := "/private/tmp"
	if info, err := os.Lstat(base); err != nil || !info.IsDir() {
		base = "/tmp"
	}
	root, err := os.MkdirTemp(base, "sow-nginx-worker-")
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
