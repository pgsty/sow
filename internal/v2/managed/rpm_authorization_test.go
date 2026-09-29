package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
)

func TestRPMBuildAuthorizationReusesVerifiedBytesAndInvalidatesProof(t *testing.T) {
	ctx := context.Background()
	root, ws := newRejectionWorkspace(t)
	cfg, err := config.Load(filepath.Join(root, "sow.yml"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile("../../testdata/PGDG-RPM-GPG-KEY-RHEL-nonfree.asc")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pgdg.asc"), key, 0600); err != nil {
		t.Fatal(err)
	}
	fixture := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(root, "package.rpm"))
	// Build under never first: the stored issuer key ID is not authentication.
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{fixture}, Jobs: 3}); err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repositories["repo"]
	repo.Signing.RPM.Packages = config.RPMPackageSigningConfig{Mode: "fill", Key: "file://pgdg.asc"}
	cfg.Repositories["repo"] = repo
	tools := t.TempDir()
	if err := os.WriteFile(filepath.Join(tools, "gpg"), []byte("#!/bin/sh\nlast=\nfor arg in \"$@\"; do last=\"$arg\"; done\ncase \" $* \" in\n *\" --list-secret-keys \"*) printf 'sec::::::::::\\nfpr:::::::::%s:\\n' \"$last\";;\nesac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "rpm"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	writeManagedConfig(t, root, cfg)
	cold, coldMetrics := workmetrics.Ensure(ctx)
	if _, err := Build(cold, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 3}); err != nil {
		t.Fatal(err)
	}
	if got := coldMetrics.Snapshot(); got.SignatureStreams != 1 {
		t.Fatalf("cold policy transition must verify once, including rendering: %+v", got)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow/repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	objects, err := store.ListPackageObjects(ctx, []string{"el9"}, false)
	if err != nil || len(objects) != 1 {
		t.Fatalf("objects=%v err=%v", objects, err)
	}
	object := objects[0]
	manifest := mutationManifest{Version: mutationOperationVersion, Objects: []state.PackageObject{}, Desired: map[string][]string{"el9": {object.SHA256}}}
	snapshot, err := validateCurrentPublicGenerationSnapshot(ctx, root, "repo", store)
	if err != nil {
		t.Fatal(err)
	}
	hot, hotMetrics := workmetrics.Ensure(ctx)
	preflight, err := prepareMutationBuildPreflight(hot, root, "repo", cfg, []string{"el9"}, manifest, store, nil, snapshot, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizeBuildRPMObjects(hot, root, "repo", objects, preflight.rpmPolicy, 3, preflight.rpmAuthorizations); err != nil {
		t.Fatal(err)
	}
	if got := hotMetrics.Snapshot(); got.SignatureStreams != 0 || got.SignatureBytesRead != 0 {
		t.Fatalf("unchanged Built bytes were reverified: %+v", got)
	}
	// A changed file identity invalidates the cheap proof, even with equal bytes.
	path := filepath.Join(root, "repo", filepath.FromSlash(object.PoolPath))
	at := time.Now().Add(time.Second)
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
	changed, changedMetrics := workmetrics.Ensure(ctx)
	proofs, err := authorizeBuildRPMObjects(changed, root, "repo", objects, preflight.rpmPolicy, 3, preflight.rpmAuthorizations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizeBuildRPMObjects(changed, root, "repo", objects, preflight.rpmPolicy, 3, proofs); err != nil {
		t.Fatal(err)
	}
	if got := changedMetrics.Snapshot(); got.SignatureStreams != 1 {
		t.Fatalf("changed identity must verify exactly once: %+v", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := authorizeBuildRPMObjects(ctx, root, "repo", objects, preflight.rpmPolicy, 3, proofs); !errors.Is(err, errImmutableRPMSigningPolicy) {
		t.Fatalf("tampered bytes accepted: %v", err)
	}
	t.Logf("signature streams: cold=%d hot=%d changed=%d", coldMetrics.Snapshot().SignatureStreams, hotMetrics.Snapshot().SignatureStreams, changedMetrics.Snapshot().SignatureStreams)
}
