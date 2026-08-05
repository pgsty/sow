package aptrepo

import (
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateEmptyUnsignedAPTDistribution(t *testing.T) {
	root := t.TempDir()
	cfg := RepositoryConfig{
		Origin: "SOW", Label: "noble", Suite: "noble", Codename: "noble",
		Description: "SOW empty distribution", Components: []string{"main"},
		Architectures: []string{"amd64", "arm64"}, Date: time.Unix(0, 0).UTC(),
	}
	result, err := GenerateEmptyUnsigned(context.Background(), root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Artifacts) != 5 || result.ReleasePath != "dists/noble/Release" {
		t.Fatalf("result=%#v", result)
	}
	release, err := os.ReadFile(filepath.Join(root, "dists", "noble", "Release"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(release)
	for _, want := range []string{"Suite: noble\n", "Architectures: amd64 arm64\n", "Components: main\n", "main/binary-amd64/Packages", "main/binary-arm64/Packages.gz"} {
		if !strings.Contains(text, want) {
			t.Errorf("Release missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Acquire-By-Hash") {
		t.Fatalf("empty distribution advertised absent by-hash objects:\n%s", text)
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		packages := filepath.Join(root, "dists", "noble", "main", "binary-"+architecture, "Packages")
		info, err := os.Stat(packages)
		if err != nil || info.Size() != 0 {
			t.Fatalf("empty Packages %s: info=%v err=%v", architecture, info, err)
		}
		compressed, err := os.Open(packages + ".gz")
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(compressed)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		if err := zr.Close(); err != nil {
			t.Fatal(err)
		}
		if err := compressed.Close(); err != nil {
			t.Fatal(err)
		}
		if len(body) != 0 {
			t.Fatalf("compressed Packages %s is not empty", architecture)
		}
	}
	if err := ValidateEmptyUnsigned(context.Background(), root, "noble", []string{"amd64", "arm64"}); err != nil {
		t.Fatalf("ValidateEmptyUnsigned: %v", err)
	}
}

func TestValidateEmptyUnsignedRejectsBrokenClosure(t *testing.T) {
	newFixture := func(t *testing.T) string {
		t.Helper()
		root := t.TempDir()
		_, err := GenerateEmptyUnsigned(context.Background(), root, RepositoryConfig{
			Origin: "SOW", Label: "noble", Suite: "noble", Codename: "noble",
			Components: []string{"main"}, Architectures: []string{"amd64", "arm64"},
			Date: time.Unix(0, 0).UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return root
	}
	validate := func(root string) error {
		return ValidateEmptyUnsigned(context.Background(), root, "noble", []string{"amd64", "arm64"})
	}

	t.Run("packages checksum", func(t *testing.T) {
		root := newFixture(t)
		filename := filepath.Join(root, "dists", "noble", "main", "binary-amd64", "Packages")
		if err := os.Chmod(filename, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte("not empty\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := validate(root); err == nil {
			t.Fatal("tampered Packages accepted")
		}
	})

	t.Run("release dimensions", func(t *testing.T) {
		root := newFixture(t)
		filename := filepath.Join(root, "dists", "noble", "Release")
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.Replace(string(data), "Architectures: amd64 arm64", "Architectures: amd64", 1))
		if err := os.Chmod(filename, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := validate(root); err == nil {
			t.Fatal("Release architecture drift accepted")
		}
	})

	t.Run("unexpected signature", func(t *testing.T) {
		root := newFixture(t)
		if err := os.WriteFile(filepath.Join(root, "dists", "noble", "InRelease"), []byte("forged"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := validate(root); err == nil {
			t.Fatal("unexpected file accepted")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		root := newFixture(t)
		filename := filepath.Join(root, "dists", "noble", "main", "binary-amd64", "Packages")
		if err := os.Remove(filename); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "dists", "noble", "Release"), filename); err != nil {
			t.Fatal(err)
		}
		if err := validate(root); err == nil {
			t.Fatal("symlink Packages accepted")
		}
	})
}
