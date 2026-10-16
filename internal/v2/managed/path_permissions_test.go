package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
)

func TestManagedSearchOnlyAncestor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks require an unprivileged user")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Join(base, "search-only")
	root := filepath.Join(ancestor, "Workspace")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ancestor, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ancestor, 0o700) })
	if _, err := os.ReadDir(ancestor); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("ancestor must be unlistable, got %v", err)
	}
	if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
		t.Fatalf("init beneath searchable ancestor: %v", err)
	}
	data, err := readBoundedRegularNoFollow(filepath.Join(root, config.ConfigFilename), 1<<20)
	if err != nil || len(data) == 0 {
		t.Fatalf("bound config read: data=%q err=%v", data, err)
	}
	handle, binding, err := openBoundRootDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := handle.ReadDir(-1)
	if err := errors.Join(readErr, handle.Sync(), verifyBoundRootDirectory(handle, binding), handle.Close()); err != nil {
		t.Fatalf("owner must retain a readable, syncable descriptor: %v", err)
	}
	physical, exists, err := prospectiveRealDirectory(root)
	if err != nil || !exists || physical != root {
		t.Fatalf("physical directory=%q exists=%t err=%v", physical, exists, err)
	}
	missing := filepath.Join(root, "new", "child")
	physical, exists, err = prospectiveRealDirectory(missing)
	if err != nil || exists || physical != missing {
		t.Fatalf("prospective directory=%q exists=%t err=%v", physical, exists, err)
	}
	// The nearest existing ancestor can itself be search-only.
	physical, exists, err = prospectiveRealDirectory(filepath.Join(ancestor, "new"))
	if err != nil || exists || physical != filepath.Join(ancestor, "new") {
		t.Fatalf("search-only prospective ancestor=%q exists=%t err=%v", physical, exists, err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(ancestor, alias); err != nil {
		t.Fatal(err)
	}
	workspace, err := config.Discover(config.DiscoverOptions{Workdir: filepath.Join(alias, "Workspace")})
	if err != nil {
		t.Fatal(err)
	}
	guard, err := bindDiscoveredWorkspaceRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	t.Chdir(base)
	guard, err = bindCurrentWorkspaceRoot(filepath.Join("search-only", "Workspace"))
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedSearchOnlyAncestorPreservesTargetPermissions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks require an unprivileged user")
	}
	ancestor := filepath.Join(t.TempDir(), "search-only")
	root := filepath.Join(ancestor, "workspace")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(root, "known")
	if err := os.WriteFile(filename, []byte("private"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ancestor, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ancestor, 0o700); _ = os.Chmod(root, 0o700) })
	if _, err := os.ReadFile(filename); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("ordinary read must fail: %v", err)
	}
	if data, err := readBoundedRegularNoFollow(filename, 64); err == nil || data != nil {
		t.Fatalf("unreadable file accepted: data=%q err=%v", data, err)
	}
	if err := os.Chmod(root, 0o111); err != nil {
		t.Fatal(err)
	}
	if handle, _, err := openBoundRootDirectory(root); err == nil {
		_ = handle.Close()
		t.Fatal("unreadable owner accepted for directory I/O")
	}
	if err := os.Chmod(ancestor, 0); err != nil {
		t.Fatal(err)
	}
	if handle, _, err := openBoundRootDirectory(root); err == nil {
		_ = handle.Close()
		t.Fatal("non-searchable ancestor accepted")
	}
	if _, err := canonicalDirectoryEntrySpelling(root); err == nil {
		t.Fatal("canonical spelling accepted a non-searchable ancestor")
	}
}

func TestCanonicalDirectorySpellingSearchOnlyCaseAlias(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks require an unprivileged user")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Join(base, "search-only")
	root := filepath.Join(ancestor, "MixedCase")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(ancestor, "mixedcase")
	if _, err := os.Stat(alias); errors.Is(err, os.ErrNotExist) {
		t.Skip("filesystem is case-sensitive")
	} else if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ancestor, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ancestor, 0o700) })
	physical, exists, err := prospectiveRealDirectory(filepath.Join(alias, "new"))
	if err != nil || exists || physical != filepath.Join(root, "new") {
		t.Fatalf("case alias=%q exists=%t err=%v", physical, exists, err)
	}
}

func TestCanonicalDirectorySpellingReadableAncestor(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "Parent", "Directory")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	physical, exists, err := prospectiveRealDirectory(filepath.Join(root, "new"))
	if err != nil || exists || physical != filepath.Join(root, "new") {
		t.Fatalf("physical directory=%q exists=%t err=%v", physical, exists, err)
	}
}

func TestManagedSearchOnlyAncestorReplacementAfterBinding(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks require an unprivileged user")
	}
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "directory", true: "symlink"}[symlink], func(t *testing.T) {
			base := t.TempDir()
			live := filepath.Join(base, "live")
			root := filepath.Join(live, "workspace")
			moved := filepath.Join(base, "moved")
			external := filepath.Join(base, "external")
			for _, parent := range []string{root, filepath.Join(external, "workspace")} {
				if err := os.MkdirAll(parent, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(parent, "known"), []byte("contents"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(live, 0o111); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(live, 0o700); _ = os.Chmod(moved, 0o700) })
			hooked := false
			data, err := readBoundedRegularNoFollowWithHook(filepath.Join(root, "known"), 64, func() error {
				hooked = true
				if err := os.Rename(live, moved); err != nil {
					return err
				}
				if symlink {
					return os.Symlink(external, live)
				}
				return os.Rename(external, live)
			})
			if !hooked || err == nil || data != nil {
				t.Fatalf("ancestor replacement: hook=%t data=%q err=%v", hooked, data, err)
			}
		})
	}
}
