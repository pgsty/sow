package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfigFixture(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ConfigFilename), []byte("schema: sow/v3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverPriorityNearestAncestorAndNoChdir(t *testing.T) {
	base := t.TempDir()
	cwdRoot := filepath.Join(base, "cwd-ws")
	workRoot := filepath.Join(base, "work-ws")
	envRoot := filepath.Join(base, "env-ws")
	writeConfigFixture(t, cwdRoot)
	writeConfigFixture(t, workRoot)
	writeConfigFixture(t, envRoot)
	cwd := filepath.Join(cwdRoot, "a", "b")
	work := filepath.Join(workRoot, "c", "d")
	env := filepath.Join(envRoot, "e", "f")
	for _, dir := range []string{cwd, work, env} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	before, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	ws, err := Discover(DiscoverOptions{Workdir: work, CWD: cwd, SOWDir: env})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if ws.Root != realPath(t, workRoot) || ws.StartDir != realPath(t, work) || ws.CWD != realPath(t, cwd) || ws.Source != DiscoveryWorkdir {
		t.Fatalf("workdir discovery = %#v", ws)
	}
	after, _ := os.Getwd()
	if after != before {
		t.Fatalf("Discover changed cwd from %q to %q", before, after)
	}

	inner := filepath.Join(workRoot, "c")
	writeConfigFixture(t, inner)
	ws, err = Discover(DiscoverOptions{Workdir: work, CWD: cwd, SOWDir: env})
	if err != nil {
		t.Fatal(err)
	}
	if ws.Root != realPath(t, inner) {
		t.Fatalf("nearest root = %q, want %q", ws.Root, realPath(t, inner))
	}
}

func TestDiscoverFallbackMatrix(t *testing.T) {
	base := t.TempDir()
	cwdRoot := filepath.Join(base, "cwd-ws")
	envRoot := filepath.Join(base, "env-ws")
	writeConfigFixture(t, cwdRoot)
	writeConfigFixture(t, envRoot)
	cwd := filepath.Join(cwdRoot, "deep")
	env := filepath.Join(envRoot, "deep")
	none := filepath.Join(base, "none", "deep")
	for _, dir := range []string{cwd, env, none} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name string
		opts DiscoverOptions
		root string
		src  DiscoverySource
	}{
		{"workdir misses then env", DiscoverOptions{Workdir: none, CWD: cwd, SOWDir: env}, envRoot, DiscoveryEnvironment},
		{"cwd", DiscoverOptions{CWD: cwd, SOWDir: env}, cwdRoot, DiscoveryCWD},
		{"env fallback", DiscoverOptions{CWD: none, SOWDir: env}, envRoot, DiscoveryEnvironment},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws, err := Discover(tt.opts)
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			if ws.Root != realPath(t, tt.root) || ws.Source != tt.src {
				t.Fatalf("workspace = %#v, want root %q source %q", ws, tt.root, tt.src)
			}
		})
	}
}

func TestDiscoverExplicitWorkdirNeverFallsBackToCWD(t *testing.T) {
	base := t.TempDir()
	cwdRoot := filepath.Join(base, "cwd-ws")
	writeConfigFixture(t, cwdRoot)
	cwd := filepath.Join(cwdRoot, "deep")
	missingWorkdir := filepath.Join(base, "missing-workdir")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(missingWorkdir, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := Discover(DiscoverOptions{Workdir: missingWorkdir, CWD: cwd})
	if err == nil {
		t.Fatal("explicit workdir unexpectedly fell back to cwd workspace")
	}
	if !strings.Contains(err.Error(), "workdir") || strings.Contains(err.Error(), "cwd=") {
		t.Fatalf("discovery error = %v, want only explicit workdir evidence", err)
	}
}

func TestDiscoverEnvironmentAndFailures(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "ws")
	writeConfigFixture(t, root)
	start := filepath.Join(root, "deep")
	if err := os.MkdirAll(start, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_DIR", start)
	ws, err := Discover(DiscoverOptions{CWD: filepath.Join(base, "missing")})
	if err != nil {
		t.Fatalf("Discover using env: %v", err)
	}
	if ws.Source != DiscoveryEnvironment || ws.Root != realPath(t, root) {
		t.Fatalf("workspace = %#v", ws)
	}

	if _, err := Discover(DiscoverOptions{CWD: filepath.Join(base, "missing"), SOWDir: filepath.Join(base, "also-missing")}); err == nil || !strings.Contains(err.Error(), "workspace") {
		t.Fatalf("missing workspace error = %v", err)
	}

	symlinkRoot := filepath.Join(base, "symlink-ws")
	if err := os.MkdirAll(symlinkRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, ConfigFilename), filepath.Join(symlinkRoot, ConfigFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(DiscoverOptions{Workdir: symlinkRoot, CWD: filepath.Join(base, "missing"), SOWDir: filepath.Join(base, "also-missing")}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink config error = %v", err)
	}
}

func TestLoadWorkspaceRejectsAncestorReplacementAfterDiscovery(t *testing.T) {
	base := t.TempDir()
	live := filepath.Join(base, "live")
	workspaceRoot := filepath.Join(live, "workspace")
	external := filepath.Join(base, "external")
	externalWorkspace := filepath.Join(external, "workspace")
	writeConfigFixture(t, workspaceRoot)
	writeConfigFixture(t, externalWorkspace)

	workspace, err := Discover(DiscoverOptions{Workdir: workspaceRoot, CWD: workspaceRoot})
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(base, "original")
	if err := os.Rename(live, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, live); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(workspace.ConfigPath); err == nil {
		t.Fatal("generic config load followed a replaced ancestor symlink")
	}
	if _, err := LoadWorkspace(workspace); err == nil {
		t.Fatalf("workspace ancestor replacement accepted: %v", err)
	}
}

func TestWorkspaceConfigReadDetectsAncestorReplacementAfterParentBinding(t *testing.T) {
	base := t.TempDir()
	live := filepath.Join(base, "live")
	workspaceRoot := filepath.Join(live, "workspace")
	external := filepath.Join(base, "external")
	writeConfigFixture(t, workspaceRoot)
	writeConfigFixture(t, filepath.Join(external, "workspace"))
	workspace, err := Discover(DiscoverOptions{Workdir: workspaceRoot, CWD: workspaceRoot})
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(base, "original")
	data, _, err := readConfigFileBound(workspace.ConfigPath, workspace.rootDevice, workspace.rootInode, func() error {
		if err := os.Rename(live, original); err != nil {
			return err
		}
		return os.Symlink(external, live)
	})
	if err == nil {
		t.Fatalf("workspace ancestor replacement accepted with data %q", data)
	}
}

func realPath(t *testing.T, path string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	real, err = filepath.Abs(real)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(real)
}
