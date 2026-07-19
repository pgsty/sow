package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
)

func writeCandidateHardlinkFixture(t *testing.T) (root string, pool *repository.Store, candidate *os.Root, manifestPath, target string, object repository.Object) {
	t.Helper()
	root = t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	source := filepath.Join(t.TempDir(), "repomd.xml")
	if err := os.WriteFile(source, []byte("immutable candidate bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	object, err = pool.Import(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath = filepath.Join(t.TempDir(), "candidate.tsv")
	manifestFile, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	entry := manifest.Entry{Path: "repodata/repomd.xml", Size: object.Size, SHA256: [32]byte(object.SHA256)}
	if err := errors.Join(manifest.WriteEntry(manifestFile, entry), manifestFile.Close()); err != nil {
		t.Fatal(err)
	}
	manifestFile, err = os.Open(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.MaterializeWithOptions(t.Context(), manifestFile, "candidate", repository.MaterializeOptions{Workers: 1}); err != nil {
		_ = manifestFile.Close()
		t.Fatal(err)
	}
	if err := manifestFile.Close(); err != nil {
		t.Fatal(err)
	}
	candidate, err = os.OpenRoot(filepath.Join(root, "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = candidate.Close() })
	target = filepath.Join(root, "candidate", "repodata", "repomd.xml")
	return root, pool, candidate, manifestPath, target, object
}

func TestYUMCompatibilityCandidateHardlinkValidationRejectsCopiedTreeAndFinalRewrite(t *testing.T) {
	_, pool, candidate, manifestPath, target, object := writeCandidateHardlinkFixture(t)
	if err := validateYUMCompatibilityCandidateHardlinks(t.Context(), pool, candidate, manifestPath); err != nil {
		t.Fatalf("canonical hardlink baseline: %v", err)
	}

	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, body, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := validateYUMCompatibilityCandidateHardlinks(t.Context(), pool, candidate, manifestPath); err == nil || !strings.Contains(err.Error(), "byte-identical copy") {
		t.Fatalf("copied candidate tree was accepted: %v", err)
	}

	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(pool.ObjectPath(object.SHA256), target); err != nil {
		t.Fatal(err)
	}
	malicious := append([]byte(nil), body...)
	malicious[0] ^= 0x5a
	mutated := false
	ctx := withYUMCompatibilityCandidateHardlinkHook(context.Background(), func(relative string) error {
		if relative != "repodata/repomd.xml" || mutated {
			return nil
		}
		mutated = true
		if err := os.Chmod(target, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(target, malicious, 0o644); err != nil {
			return err
		}
		return os.Chmod(target, 0o444)
	})
	err = validateYUMCompatibilityCandidateHardlinks(ctx, pool, candidate, manifestPath)
	if !mutated {
		t.Fatal("candidate final-rehash fault hook did not run")
	}
	if err == nil || !errors.Is(err, repository.ErrObjectCorrupt) {
		t.Fatalf("same-size in-place candidate/CAS rewrite was accepted: %v", err)
	}
}
