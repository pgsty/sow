package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadWorkspaceSearchOnlyAncestors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks require an unprivileged user")
	}
	base := t.TempDir()
	ancestor := filepath.Join(base, "search-only")
	root := filepath.Join(ancestor, "workspace")
	writeConfigFixture(t, root)
	if err := os.Chmod(ancestor, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ancestor, 0o700); _ = os.Chmod(root, 0o700) })
	if _, err := os.ReadDir(ancestor); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("ancestor must be unlistable, got %v", err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(ancestor, alias); err != nil {
		t.Fatal(err)
	}
	t.Chdir(base)
	for _, start := range []string{root, filepath.Join("search-only", "workspace"), filepath.Join(alias, "workspace")} {
		workspace, err := Discover(DiscoverOptions{Workdir: start})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := LoadWorkspace(workspace); err != nil {
			t.Fatalf("load through %q: %v", start, err)
		}
	}
	// Reading a known file needs search permission, not a directory listing.
	if err := os.Chmod(root, 0o111); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(root, ConfigFilename)
	if _, err := os.ReadFile(filename); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filename); err != nil {
		t.Fatalf("config parent needs only search permission: %v", err)
	}
	if err := os.Chmod(filename, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filename); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("unreadable config must fail with permission error: %v", err)
	}
	if err := os.Chmod(ancestor, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filename); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("non-searchable ancestor must fail with permission error: %v", err)
	}
}

func TestSearchOnlyConfigAncestorReplacementAfterBinding(t *testing.T) {
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
			writeConfigFixture(t, root)
			writeConfigFixture(t, filepath.Join(external, "workspace"))
			if err := os.Chmod(live, 0o111); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(live, 0o700); _ = os.Chmod(moved, 0o700) })
			workspace, err := Discover(DiscoverOptions{Workdir: root})
			if err != nil {
				t.Fatal(err)
			}
			hooked := false
			data, _, err := readConfigFileBound(workspace.ConfigPath, workspace.rootDevice, workspace.rootInode, func() error {
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
