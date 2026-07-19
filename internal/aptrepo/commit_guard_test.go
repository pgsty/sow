package aptrepo

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCommitPostGuardFailureRestoresExactPublishedTree(t *testing.T) {
	created := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
	signer, _, _ := testSigningMaterial(t, created.Add(-time.Hour))
	packages := testBuildPackages(t)
	cfg := RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "beta", Codename: "bookworm",
		Components: []string{"main"}, Architectures: []string{"amd64"}, Date: created,
	}
	root := t.TempDir()
	if _, err := Generate(t.Context(), root, cfg, []Index{{Component: "main", Architecture: "amd64", Packages: packages[:1]}}, signer); err != nil {
		t.Fatal(err)
	}
	before := readTree(t, root)
	stage := t.TempDir()
	cfg.Date = cfg.Date.Add(time.Hour)
	result, err := generateTree(t.Context(), stage, cfg, []Index{{Component: "main", Architecture: "amd64", Packages: packages}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	rotated := errors.New("repository trust rotated")
	err = commitStagedBuildGuarded(t.Context(), stage, root, result, func(phase CommitPhase) error {
		if phase == CommitAfterMutation {
			return rotated
		}
		return nil
	})
	if !errors.Is(err, rotated) {
		t.Fatalf("guarded commit error = %v", err)
	}
	if after := readTree(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("post-commit guard failure did not restore the exact published tree")
	}
}

func TestCommitPreGuardFailureDoesNotOverwriteConcurrentLiveChange(t *testing.T) {
	created := time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC)
	signer, _, _ := testSigningMaterial(t, created.Add(-time.Hour))
	packages := testBuildPackages(t)
	cfg := RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "beta", Codename: "bookworm",
		Components: []string{"main"}, Architectures: []string{"amd64"}, Date: created,
	}
	root := t.TempDir()
	initial, err := Generate(t.Context(), root, cfg, []Index{{Component: "main", Architecture: "amd64", Packages: packages[:1]}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	cfg.Date = cfg.Date.Add(time.Hour)
	result, err := generateTree(t.Context(), stage, cfg, []Index{{Component: "main", Architecture: "amd64", Packages: packages}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	external := []byte("concurrent external checkpoint\n")
	rotated := errors.New("repository trust rotated")
	err = commitStagedBuildGuarded(context.Background(), stage, root, result, func(phase CommitPhase) error {
		if phase != CommitBeforeMutation {
			return nil
		}
		destination := filepath.Join(root, filepath.FromSlash(initial.InReleasePath))
		temporary := destination + ".external"
		if err := os.WriteFile(temporary, external, 0o444); err != nil {
			return err
		}
		if err := os.Rename(temporary, destination); err != nil {
			return err
		}
		return rotated
	})
	if !errors.Is(err, rotated) {
		t.Fatalf("guarded commit error = %v", err)
	}
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(initial.InReleasePath)))
	if err != nil || !bytes.Equal(body, external) {
		t.Fatalf("pre-guard failure overwrote concurrent live change: body=%q err=%v", body, err)
	}
}

func TestStagedTransformMayChangeOnlySignatureCheckpoints(t *testing.T) {
	before := BuildResult{
		ReleasePath: "dists/beta/Release", InReleasePath: "dists/beta/InRelease", DetachedSignaturePath: "dists/beta/Release.gpg",
		Artifacts: []Artifact{
			{Path: "dists/beta/InRelease", Size: 10, SHA256: strings.Repeat("a", 64)},
			{Path: "dists/beta/Release", Size: 20, SHA256: strings.Repeat("b", 64)},
			{Path: "dists/beta/Release.gpg", Size: 30, SHA256: strings.Repeat("c", 64)},
		},
	}
	after := before
	after.Artifacts = append([]Artifact(nil), before.Artifacts...)
	after.Artifacts[0].SHA256 = strings.Repeat("d", 64)
	after.Artifacts[2].SHA256 = strings.Repeat("e", 64)
	if err := validateStagedSignatureTransform(before, after); err != nil {
		t.Fatalf("signature-only transform rejected: %v", err)
	}
	after.Artifacts[1].SHA256 = strings.Repeat("f", 64)
	if err := validateStagedSignatureTransform(before, after); err == nil {
		t.Fatal("Release mutation was accepted as a staged signature transform")
	}
}
