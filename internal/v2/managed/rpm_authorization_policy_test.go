package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
)

func rpmPolicyCacheFixture(t *testing.T, mode string) (string, WorkspaceOptions, config.Config) {
	t.Helper()
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
	private, _ := managedTestPrivateKey(t, "policy-cache-wrong-current")
	public, err := publicOpenPGPKeyMaterial(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "wrong.asc"), public, 0600); err != nil {
		t.Fatal(err)
	}
	fixture := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(root, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{fixture}, Jobs: 2}); err != nil {
		t.Fatal(err)
	}
	tools := t.TempDir()
	if err := os.WriteFile(filepath.Join(tools, "gpg"), []byte("#!/bin/sh\nlast=\nfor arg in \"$@\"; do last=\"$arg\"; done\ncase \" $* \" in\n *\" --list-secret-keys \"*) printf 'sec::::::::::\\nfpr:::::::::%s:\\n' \"$last\";;\nesac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "rpm"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	repo := cfg.Repositories["repo"]
	repo.Signing.RPM.Packages = config.RPMPackageSigningConfig{Mode: mode, Key: "file://pgdg.asc"}
	if mode == "fill" {
		repo.Signing.RPM.Packages.Key = "file://wrong.asc"
		repo.Signing.RPM.Packages.TrustedKeys = []string{"file://pgdg.asc"}
	}
	cfg.Repositories["repo"] = repo
	writeManagedConfig(t, root, cfg)
	cold, metrics := workmetrics.Ensure(ctx)
	if _, err := Build(cold, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 2}); err != nil {
		t.Fatal(err)
	}
	if got := metrics.Snapshot(); got.SignatureStreams != 1 {
		t.Fatalf("cold %s must authenticate once: %+v", mode, got)
	}
	return root, ws, cfg
}

func TestRPMPolicyCacheAlwaysHotAndTrustContraction(t *testing.T) {
	for _, mode := range []string{"always", "fill"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			root, ws, cfg := rpmPolicyCacheFixture(t, mode)
			store, err := state.OpenExisting(filepath.Join(root, ".sow/repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			objects, err := store.ListPackageObjects(ctx, []string{"el9"}, false)
			if err != nil || len(objects) != 1 {
				t.Fatalf("objects=%v err=%v", objects, err)
			}
			manifest := mutationManifest{Version: mutationOperationVersion, Objects: []state.PackageObject{}, Desired: map[string][]string{"el9": {objects[0].SHA256}}}
			snapshot, err := validateCurrentPublicGenerationSnapshot(ctx, root, "repo", store)
			if err != nil {
				t.Fatal(err)
			}
			hot, metrics := workmetrics.Ensure(ctx)
			preflight, err := prepareMutationBuildPreflight(hot, root, "repo", cfg, []string{"el9"}, manifest, store, nil, snapshot, 2)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authorizeBuildRPMObjects(hot, root, "repo", objects, preflight.rpmPolicy, 2, preflight.rpmAuthorizations); err != nil {
				t.Fatal(err)
			}
			if got := metrics.Snapshot(); got.SignatureStreams != 0 || got.SignatureBytesRead != 0 {
				t.Fatalf("hot %s repeated verification: %+v", mode, got)
			}
			before, err := store.Summary(ctx)
			if err != nil {
				t.Fatal(err)
			}
			store.Close()
			repo := cfg.Repositories["repo"]
			repo.Signing.RPM.Packages.Key = "file://wrong.asc"
			if mode == "fill" {
				repo.Signing.RPM.Packages.TrustedKeys = nil
			} else {
				repo.Signing.RPM.Packages.TrustedKeys = []string{"file://pgdg.asc"}
			}
			cfg.Repositories["repo"] = repo
			writeManagedConfig(t, root, cfg)
			result, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 2})
			if !errors.Is(err, errImmutableRPMSigningPolicy) || result.Operation != "" {
				t.Fatalf("changed %s policy reused old Built proof: %+v %v", mode, result, err)
			}
			after := managedTestSummary(t, root)
			if before.DesiredRevision != after.DesiredRevision || before.BuiltGeneration != after.BuiltGeneration {
				t.Fatalf("rejected policy applied changes: %+v -> %+v", before, after)
			}
		})
	}
}

func TestUnfrozenMutationCertificateReplacementCanFinish(t *testing.T) {
	for _, point := range []string{"build.command.staged", "build.command.applied"} {
		t.Run(point, func(t *testing.T) {
			ctx := context.Background()
			root, ws, cfg := rpmPolicyCacheFixture(t, "fill")
			repo := cfg.Repositories["repo"]
			dist := repo.Dists["el9"]
			dist.Limit = 2
			repo.Dists["el9"] = dist
			cfg.Repositories["repo"] = repo
			writeManagedConfig(t, root, cfg)
			crash := errors.New("stop before frozen build")
			result, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 2, Fault: func(got string) error {
				if got == point {
					return crash
				}
				return nil
			}})
			if !errors.Is(err, crash) {
				t.Fatal(err)
			}
			before := managedTestSummary(t, root)
			original, err := os.ReadFile(filepath.Join(root, "pgdg.asc"))
			if err != nil {
				t.Fatal(err)
			}
			replacementPrivate, _ := managedTestPrivateKey(t, "replacement-trusted-certificate")
			replacement, err := publicOpenPGPKeyMaterial(replacementPrivate)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "pgdg.asc"), replacement, 0600); err != nil {
				t.Fatal(err)
			}
			// The YAML is unchanged, but the retained policy snapshot is not.
			if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 2}); !errors.Is(err, errImmutableRPMSigningPolicy) {
				t.Fatalf("new build should reject changed policy: %v", err)
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow/repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			operation, err := store.GetOperation(ctx, result.Operation)
			if err != nil {
				t.Fatal(err)
			}
			want := state.OperationFailed
			if point == "build.command.applied" {
				want = state.OperationDoneDirty
			}
			if operation.Operation.State != want {
				t.Fatalf("old operation stuck after certificate replacement: %+v", operation.Operation)
			}
			members, err := store.MembershipDigests(ctx, "el9", false)
			if err != nil || len(members) != 1 {
				t.Fatalf("Desired lost: %v %v", members, err)
			}
			store.Close()
			after := managedTestSummary(t, root)
			if before.DesiredRevision != after.DesiredRevision || before.BuiltGeneration != after.BuiltGeneration {
				t.Fatalf("recovery changed committed data: %+v -> %+v", before, after)
			}
			if err := os.WriteFile(filepath.Join(root, "pgdg.asc"), original, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 2}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
