package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestGenerationSignerProjectionCoversUnchangedAndLifecycleViews(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	opts := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9":  {Format: "rpm", Architectures: []string{"x86_64"}},
		"el10": {Format: "rpm", Architectures: []string{"x86_64"}},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	assertCurrent := func(t *testing.T, views ...string) state.GenerationID {
		t.Helper()
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		summary, err := store.Summary(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, view := range views {
			signer, err := store.GenerationViewSigner(ctx, summary.BuiltGeneration, view)
			if err != nil || signer.SignerIdentity != "none" {
				t.Fatalf("Generation %s view %s signer=%#v err=%v", summary.BuiltGeneration, view, signer, err)
			}
		}
		if renderer, signer, err := store.GenerationRetentionIdentity(ctx, summary.BuiltGeneration); err != nil || renderer == "" || signer != "none" {
			t.Fatalf("Generation %s retention identity renderer=%q signer=%q err=%v", summary.BuiltGeneration, renderer, signer, err)
		}
		return summary.BuiltGeneration
	}
	assertCurrent(t, "dists/el9/x86_64", "dists/el10/x86_64")

	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	partialGeneration := assertCurrent(t, "dists/el9/x86_64", "dists/el10/x86_64")

	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: opts, Repository: "repo", Name: "el11", Format: "rpm"}); err != nil {
		t.Fatal(err)
	}
	lifecycleGeneration := assertCurrent(t, "dists/el9/x86_64", "dists/el10/x86_64", "dists/el11/x86_64", "dists/el11/aarch64")
	if lifecycleGeneration == partialGeneration {
		t.Fatal("Dist addition did not advance Generation")
	}
	if _, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: opts, Repository: "repo", Name: "el11", Force: true}); err != nil {
		t.Fatal(err)
	}
	removedGeneration := assertCurrent(t, "dists/el9/x86_64", "dists/el10/x86_64")
	if removedGeneration == lifecycleGeneration {
		t.Fatal("Dist removal did not advance Generation")
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, signerErr := store.GenerationViewSigner(ctx, removedGeneration, "dists/el11/x86_64")
	closeErr := store.Close()
	if !errors.Is(signerErr, state.ErrNotFound) || closeErr != nil {
		t.Fatalf("removed view signer remains: err=%v close=%v", signerErr, closeErr)
	}
}

func TestPartialMetadataKeyRotationRetainsHeterogeneousSignerEvidence(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	opts := WorkspaceOptions{Workdir: root, CWD: root}
	firstKey, _ := managedTestPrivateKey(t, "generation-signer-first")
	secondKey, _ := managedTestPrivateKey(t, "generation-signer-second")
	t.Setenv("SOW_TEST_GENERATION_SIGNER_FIRST", string(firstKey))
	t.Setenv("SOW_TEST_GENERATION_SIGNER_SECOND", string(secondKey))
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{
		Signing: config.SigningConfig{RPM: config.RPMSigningConfig{Metadata: config.MetadataSigningConfig{Key: "env://SOW_TEST_GENERATION_SIGNER_FIRST"}}},
		Dists: map[string]config.DistConfig{
			"el9":  {Format: "rpm", Architectures: []string{"x86_64"}},
			"el10": {Format: "rpm", Architectures: []string{"x86_64"}},
		},
	}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	repository := cfg.Repositories["repo"]
	repository.Signing.RPM.Metadata.Key = "env://SOW_TEST_GENERATION_SIGNER_SECOND"
	cfg.Repositories["repo"] = repository
	writeManagedConfig(t, root, cfg)
	built, err := Build(ctx, BuildOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9"}, Jobs: 1})
	if err != nil || built.Noop || !built.Dirty {
		t.Fatalf("partial signer rotation build=%#v err=%v", built, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	el9, el9Err := store.GenerationViewSigner(ctx, built.Generation, "dists/el9/x86_64")
	el10, el10Err := store.GenerationViewSigner(ctx, built.Generation, "dists/el10/x86_64")
	if err := errors.Join(el9Err, el10Err); err != nil || el9.SignerIdentity == "none" || el10.SignerIdentity == "none" || el9.SignerIdentity == el10.SignerIdentity {
		t.Fatalf("heterogeneous signer rows el9=%#v el10=%#v err=%v", el9, el10, err)
	}
	if _, _, err := store.GenerationRetentionIdentity(ctx, built.Generation); !errors.Is(err, state.ErrConflict) {
		t.Fatalf("heterogeneous Generation retention identity error=%v", err)
	}
	if err := store.ValidateGenerationLedger(ctx); err != nil {
		t.Fatalf("heterogeneous but complete signer ledger is invalid: %v", err)
	}
}
