package managed

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/yumrepo"
)

func TestRenderEmptyRPMDistViews(t *testing.T) {
	root := t.TempDir()
	result, err := RenderEmptyDist(context.Background(), root, EmptyDistSpec{Name: "el9", Format: "rpm", Architectures: []string{"x86_64", "aarch64"}, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	if result.Files != 8 || len(result.TreeSHA256) != 64 {
		t.Fatalf("result=%#v", result)
	}
	for _, family := range []string{"x86_64", "aarch64"} {
		view := filepath.Join(root, "dists", "el9", family, "repodata")
		validated, err := yumrepo.ValidateFlatUnsignedDirectory(context.Background(), view, yumrepo.CompressionGzip)
		if err != nil {
			t.Fatalf("validate %s: %v", family, err)
		}
		if validated.Packages != 0 || validated.Revision != 1 {
			t.Fatalf("empty %s view=%#v", family, validated)
		}
	}
}

func TestRenderEmptyDEBDistViews(t *testing.T) {
	root := t.TempDir()
	result, err := RenderEmptyDist(context.Background(), root, EmptyDistSpec{Name: "noble", Format: "deb", Architectures: []string{"x86_64", "aarch64"}, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	if result.Files != 9 || len(result.TreeSHA256) != 64 {
		t.Fatalf("result=%#v", result)
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		for _, name := range []string{"Packages", "Packages.gz"} {
			path := filepath.Join(root, "dists", "noble", "main", "binary-"+architecture, name)
			if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
				t.Fatalf("missing %s/%s: info=%v err=%v", architecture, name, info, err)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(root, "dists", "noble", "Release")); err != nil {
		t.Fatal(err)
	}
	release, err := os.ReadFile(filepath.Join(root, "dists", "noble", "Release"))
	if err != nil {
		t.Fatal(err)
	}
	if generation, present, err := parseReleaseGeneration(release); err != nil || !present || generation != 1 {
		t.Fatalf("Release generation=%d present=%t err=%v", generation, present, err)
	}
}

func TestRenderEmptyDistRejectsUnknownNeutralAndDuplicateFamilies(t *testing.T) {
	for _, architectures := range [][]string{{"all"}, {"noarch"}, {"riscv64"}, {"x86_64", "x86_64"}} {
		if _, err := RenderEmptyDist(context.Background(), t.TempDir(), EmptyDistSpec{Name: "test", Format: "rpm", Architectures: architectures, Generation: 1}); err == nil {
			t.Fatalf("architectures %v succeeded", architectures)
		}
	}
}
