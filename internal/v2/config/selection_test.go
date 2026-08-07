package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelectRepositoryPriorityMatrix(t *testing.T) {
	root := t.TempDir()
	writeConfigFixture(t, root)
	for _, name := range []string{"infra", "pgsql"} {
		if err := os.MkdirAll(filepath.Join(root, name, "nested"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := Parse([]byte("schema: sow/v3\nrepos:\n  infra: {}\n  pgsql: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ws, err := Discover(DiscoverOptions{CWD: filepath.Join(root, "pgsql", "nested")})
	if err != nil {
		t.Fatal(err)
	}

	sel, err := SelectRepository(ws, cfg, SelectRepositoryOptions{Explicit: "infra", StartDir: filepath.Join(root, "pgsql", "nested")})
	if err != nil {
		t.Fatalf("explicit selection: %v", err)
	}
	if sel.Name != "infra" || sel.Source != RepositoryExplicit {
		t.Fatalf("explicit selection = %#v", sel)
	}

	sel, err = SelectRepository(ws, cfg, SelectRepositoryOptions{StartDir: filepath.Join(root, "pgsql", "nested")})
	if err != nil {
		t.Fatalf("cwd selection: %v", err)
	}
	if sel.Name != "pgsql" || sel.Source != RepositoryCWD {
		t.Fatalf("cwd selection = %#v", sel)
	}

	if _, err := SelectRepository(ws, cfg, SelectRepositoryOptions{StartDir: root}); err == nil || !strings.Contains(err.Error(), "multiple repositories") || !strings.Contains(err.Error(), "infra, pgsql") {
		t.Fatalf("ambiguous selection error = %v", err)
	}

	one, err := Parse([]byte("schema: sow/v3\nrepos:\n  pgsql: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	sel, err = SelectRepository(ws, one, SelectRepositoryOptions{StartDir: root})
	if err != nil {
		t.Fatalf("unique selection: %v", err)
	}
	if sel.Name != "pgsql" || sel.Source != RepositoryUnique {
		t.Fatalf("unique selection = %#v", sel)
	}

	if _, err := SelectRepository(ws, cfg, SelectRepositoryOptions{Explicit: "missing", StartDir: root}); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unknown explicit selection error = %v", err)
	}
}

func TestWorkdirChangesRepositoryInferenceStart(t *testing.T) {
	root := t.TempDir()
	writeConfigFixture(t, root)
	for _, name := range []string{"infra", "pgsql"} {
		if err := os.MkdirAll(filepath.Join(root, name, "nested"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := Parse([]byte("schema: sow/v3\nrepos:\n  infra: {}\n  pgsql: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ws, err := Discover(DiscoverOptions{
		Workdir: filepath.Join(root, "infra", "nested"),
		CWD:     filepath.Join(root, "pgsql", "nested"),
	})
	if err != nil {
		t.Fatal(err)
	}
	sel, err := SelectRepository(ws, cfg, SelectRepositoryOptions{})
	if err != nil {
		t.Fatalf("SelectRepository: %v", err)
	}
	if sel.Name != "infra" || sel.Source != RepositoryCWD {
		t.Fatalf("selection = %#v; workdir did not affect inference", sel)
	}

	outside := t.TempDir()
	ws, err = Discover(DiscoverOptions{Workdir: filepath.Join(root, "infra"), CWD: outside})
	if err != nil {
		t.Fatal(err)
	}
	sel, err = SelectRepository(ws, cfg, SelectRepositoryOptions{})
	if err != nil {
		t.Fatalf("workdir repository selection: %v", err)
	}
	if sel.Name != "infra" || sel.Source != RepositoryCWD {
		t.Fatalf("workdir repository selection = %#v", sel)
	}
	one, err := Parse([]byte("schema: sow/v3\nrepos:\n  infra: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	sel, err = SelectRepository(ws, one, SelectRepositoryOptions{})
	if err != nil {
		t.Fatalf("workdir selection with one repository: %v", err)
	}
	if sel.Name != "infra" || sel.Source != RepositoryCWD {
		t.Fatalf("workdir selection with one repository = %#v", sel)
	}
}

func TestRepositoryPathRejectsSymlinkAndEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "pgsql")); err != nil {
		t.Fatal(err)
	}
	if _, err := RepositoryPath(root, "pgsql"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("RepositoryPath symlink error = %v", err)
	}
	for _, name := range []string{"../escape", ".sow", "dists", "sow.yml"} {
		if _, err := RepositoryPath(root, name); err == nil {
			t.Errorf("RepositoryPath(%q) unexpectedly succeeded", name)
		}
	}
}

func TestSelectRepositoryRejectsSymlinkedStartComponent(t *testing.T) {
	root := t.TempDir()
	writeConfigFixture(t, root)
	if err := os.MkdirAll(filepath.Join(root, "pgsql", "real", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "pgsql", "real"), filepath.Join(root, "pgsql", "link")); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]byte("schema: sow/v3\nrepos:\n  pgsql: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ws, err := Discover(DiscoverOptions{CWD: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SelectRepository(ws, cfg, SelectRepositoryOptions{StartDir: filepath.Join(root, "pgsql", "link")}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked start selection error = %v", err)
	}
}

func TestDiscoveredWorkdirRetainsSymlinkEvidenceForSelection(t *testing.T) {
	root := t.TempDir()
	writeConfigFixture(t, root)
	if err := os.MkdirAll(filepath.Join(root, "pgsql", "real", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "pgsql", "link")
	if err := os.Symlink(filepath.Join(root, "pgsql", "real"), link); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]byte("schema: sow/v3\nrepos:\n  pgsql: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	workdir := filepath.Join(link, "nested")
	ws, err := Discover(DiscoverOptions{Workdir: workdir, CWD: root})
	if err != nil {
		t.Fatal(err)
	}
	if ws.StartDir != realPath(t, workdir) {
		t.Fatalf("physical start = %q", ws.StartDir)
	}
	if _, err := SelectRepository(ws, cfg, SelectRepositoryOptions{}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("discovered symlinked workdir selection error = %v", err)
	}
}

func TestDistContainingCWDUsesPhysicalSelectedRepositoryScope(t *testing.T) {
	root := t.TempDir()
	writeConfigFixture(t, root)
	for _, directory := range []string{
		filepath.Join(root, "pgsql", "dists", "el9", "x86_64"),
		filepath.Join(root, "pgsql", "dists", "noble"),
		filepath.Join(root, "infra", "dists", "el9"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := Parse([]byte(`
schema: sow/v3
repos:
  infra:
    dists:
      el9: {format: rpm}
  pgsql:
    dists:
      el9: {format: rpm}
      noble: {format: deb}
`))
	if err != nil {
		t.Fatal(err)
	}
	ws, err := Discover(DiscoverOptions{CWD: filepath.Join(root, "pgsql", "dists", "el9", "x86_64")})
	if err != nil {
		t.Fatal(err)
	}
	dist, inside, err := DistContainingCWD(ws, cfg, "pgsql")
	if err != nil || !inside || dist != "el9" {
		t.Fatalf("dist cwd selection = %q, %t, %v", dist, inside, err)
	}
	if dist, inside, err := DistContainingCWD(ws, cfg, "infra"); err != nil || inside || dist != "" {
		t.Fatalf("explicit other repository must suppress cwd dist selection = %q, %t, %v", dist, inside, err)
	}

	if err := os.MkdirAll(filepath.Join(root, "pgsql", "dists", "noble", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "pgsql", "dists", "el9", "linked")
	if err := os.Symlink(filepath.Join(root, "pgsql", "dists", "noble"), link); err != nil {
		t.Fatal(err)
	}
	ws, err = Discover(DiscoverOptions{Workdir: filepath.Join(link, "nested"), CWD: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DistContainingCWD(ws, cfg, "pgsql"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked dist cwd error = %v", err)
	}
}
