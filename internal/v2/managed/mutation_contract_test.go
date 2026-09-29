package managed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func oldContractWorkspace(t *testing.T) (string, WorkspaceOptions, config.Config) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}, "stable": {Format: "deb"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow/repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	previous, _, err := effectiveDistConfigContract(ctx, root, cfg, "repo", "stable", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE dists SET effective_config_sha256=?, built_config_sha256=? WHERE name='stable'`, previous, previous); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return root, WorkspaceOptions{Workdir: root, CWD: root}, cfg
}

func TestUnfrozenPreviousContractScopeCanFinishWithoutWidening(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		for _, applied := range []bool{false, true} {
			t.Run(fmt.Sprintf("mixed=%t/applied=%t", mixed, applied), func(t *testing.T) {
				ctx := context.Background()
				root, ws, _ := oldContractWorkspace(t)
				crash := errors.New("old command interruption")
				var id string
				if mixed {
					input := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(root, "package.rpm"))
					point := "add.staged"
					if applied {
						point = "add.applied"
					}
					result, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9", "stable"}, Paths: []string{input}, Jobs: 1, Fault: func(got string) error {
						if got == point {
							return crash
						}
						return nil
					}})
					if !errors.Is(err, crash) {
						t.Fatal(err)
					}
					id = result.Operation
				} else {
					point := "build.command.staged"
					if applied {
						point = "build.command.applied"
					}
					result, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1, Fault: func(got string) error {
						if got == point {
							return crash
						}
						return nil
					}})
					if !errors.Is(err, crash) {
						t.Fatal(err)
					}
					id = result.Operation
				}
				store, err := state.OpenExisting(filepath.Join(root, ".sow/repo.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				_, payload, manifest, err := loadMutationOperation(ctx, store, root, "repo", id)
				if err != nil {
					t.Fatal(err)
				}
				if manifest.Build != nil {
					t.Fatal("fixture unexpectedly frozen")
				}
				payload.BuildDists = []string{}
				payload.Noop = !mixed
				if mixed {
					payload.BuildDists = []string{"el9"}
				}
				wire, _ := json.Marshal(payload)
				if err := store.UpdateOperationPayload(ctx, id, string(wire)); err != nil {
					t.Fatal(err)
				}
				if err := recoverDistOperations(ctx, root, "repo", store); err != nil {
					t.Fatal(err)
				}
				detail, err := store.GetOperation(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if detail.Operation.State != state.OperationFailed && detail.Operation.State != state.OperationDoneDirty {
					t.Fatalf("not terminal: %+v", detail.Operation)
				}
				objects, err := store.ListPackageObjects(ctx, []string{"el9"}, false)
				if err != nil {
					t.Fatal(err)
				}
				expected := 0
				if mixed && applied {
					expected = 1
				}
				if len(objects) != expected {
					t.Fatalf("Desired changed: got=%d want=%d", len(objects), expected)
				}
				store.Close()
				if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
					t.Fatalf("retry: %v", err)
				}
			})
		}
	}
}

func TestFrozenPreviousContractFinishesWithOriginalHash(t *testing.T) {
	ctx := context.Background()
	root, ws, cfg := oldContractWorkspace(t)
	crash := errors.New("frozen old tree")
	input := decodeManagedFixture(t, "../../aptrepo/testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64", filepath.Join(root, "package.deb"))
	result, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"stable"}, Paths: []string{input}, Jobs: 1, Fault: func(point string) error {
		if point == "build.staged" {
			return crash
		}
		return nil
	}})
	if !errors.Is(err, crash) {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow/repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, payload, manifest, err := loadMutationOperation(ctx, store, root, "repo", result.Operation)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Build == nil || len(manifest.Build.Dists) != 1 {
		t.Fatal("missing frozen fixture")
	}
	previous, _, err := effectiveDistConfigFrozenPrevious(cfg, "repo", "stable", manifest.Build.Dists[0].EffectiveSigning)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Build.Dists[0].EffectiveConfigSHA256 = previous
	wire, err := marshalMutationManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	payload.ManifestSHA256 = bytesSHA(wire)
	if err := writeAtomic(mutationManifestPath(root, "repo", result.Operation, payload.ManifestSHA256), wire, 0600); err != nil {
		t.Fatal(err)
	}
	payloadWire, _ := json.Marshal(payload)
	if err := store.UpdateOperationPayload(ctx, result.Operation, string(payloadWire)); err != nil {
		t.Fatal(err)
	}
	if err := recoverDistOperations(ctx, root, "repo", store); err != nil {
		t.Fatal(err)
	}
	built, err := store.GetDist(ctx, "stable")
	if err != nil {
		t.Fatal(err)
	}
	if built.EffectiveConfigSHA256 != previous {
		t.Fatal("old frozen bytes were mislabeled as new authentication contract")
	}
	store.Close()
	if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil || !checked.ReadyToCopy {
		t.Fatalf("rebuilt check=%+v err=%v", checked, err)
	}
}
