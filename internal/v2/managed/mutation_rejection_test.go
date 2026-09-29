package managed

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func newRejectionWorkspace(t *testing.T) (string, WorkspaceOptions) {
	t.Helper()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	return root, WorkspaceOptions{Workdir: root, CWD: root}
}

func collidingRPMInputs(t *testing.T, root string) []string {
	t.Helper()
	paths := []string{}
	for i, name := range []string{"centos-release-6-0.el6.centos.5.x86_64.rpm", "centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm"} {
		dir := filepath.Join(root, []string{"one", "two"}[i])
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join("../../../third_party/cavaliergopher-rpm/testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(dir, "centos-release-latest.rpm")
		if err := os.WriteFile(dest, data, 0644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, dest)
	}
	return paths
}

func TestAddPoolPathConflictIsPerInput(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "batch", true: "existing"}[existing], func(t *testing.T) {
			ctx := context.Background()
			root, ws := newRejectionWorkspace(t)
			paths := collidingRPMInputs(t, root)
			if existing {
				if _, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: paths[:1], Skip: true, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				paths = paths[1:]
			}
			epel, err := filepath.Abs("../../../third_party/cavaliergopher-rpm/testdata/epel-release-7-5.noarch.rpm")
			if err != nil {
				t.Fatal(err)
			}
			paths = append(paths, epel)
			result, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: paths, Skip: true, Jobs: 1})
			var partial *PartialError
			if !errors.As(err, &partial) || result.Failed != 1 || result.Accepted != len(paths)-1 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLegacyStagedPoolConflictRollsBack(t *testing.T) {
	ctx := context.Background()
	root, ws := newRejectionWorkspace(t)
	paths := collidingRPMInputs(t, root)
	crash := errors.New("staged crash")
	added, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: paths[:1], Skip: true, Jobs: 1, Fault: func(p string) error {
		if p == "add.staged" {
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
	_, payload, manifest, err := loadMutationOperation(ctx, store, root, "repo", added.Operation)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate a valid old-version staged journal containing two different RPM
	// versions with the same pool path; new Add now rejects this before staging.
	object, err := inspectRPMSnapshot(ctx, paths[1], filepath.Base(paths[1]))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(paths[1])
	if err != nil {
		t.Fatal(err)
	}
	if err = writeAtomic(filepath.Join(mutationStageRoot(root, "repo", added.Operation), "objects", object.SHA256), data, managedPayloadFileMode); err != nil {
		t.Fatal(err)
	}
	manifest.Objects = append(manifest.Objects, object)
	manifest.Desired["el9"] = append(manifest.Desired["el9"], object.SHA256)
	manifest.Result["accepted"] = 2
	wire, err := marshalMutationManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	payload.ManifestSHA256 = bytesSHA(wire)
	if err = writeAtomic(mutationManifestPath(root, "repo", added.Operation, payload.ManifestSHA256), wire, 0600); err != nil {
		t.Fatal(err)
	}
	pw, _ := json.Marshal(payload)
	if err = store.UpdateOperationPayload(ctx, added.Operation, string(pw)); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
			t.Fatal(err)
		}
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow/repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	detail, err := store.GetOperation(ctx, added.Operation)
	if err != nil || detail.Operation.State != state.OperationFailed {
		t.Fatalf("journal=%+v err=%v", detail.Operation, err)
	}
	objects, err := store.ListPackageObjects(ctx, nil, false)
	if err != nil || len(objects) != 0 {
		t.Fatalf("objects=%+v err=%v", objects, err)
	}
}

func TestLegacyUnbuiltSigningRejectionRecovery(t *testing.T) {
	for _, scenario := range []string{"same-config", "restored-config", "public-tamper", "pending-tamper"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			root, ws := newRejectionWorkspace(t)
			input := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(root, "package.rpm"))
			if _, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Skip: true, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(filepath.Join(root, "sow.yml"))
			if err != nil {
				t.Fatal(err)
			}
			key, _ := managedTestPrivateKey(t, "rejected-policy")
			public, err := publicOpenPGPKeyMaterial(key)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("SOW_REJECTION_KEY", string(public))
			tools := t.TempDir()
			for name, body := range map[string]string{"rpm": "#!/bin/sh\nexit 0\n", "gpg": "#!/bin/sh\nlast=\nfor arg in \"$@\"; do last=\"$arg\"; done\nprintf 'sec::::::::::\\nfpr:::::::::%s:\\n' \"$last\"\n"} {
				if err := os.WriteFile(filepath.Join(tools, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
			cfg, err := config.Load(filepath.Join(root, "sow.yml"))
			if err != nil {
				t.Fatal(err)
			}
			repo := cfg.Repositories["repo"]
			repo.Signing.RPM.Packages = config.RPMPackageSigningConfig{Mode: "fill", Key: "env://SOW_REJECTION_KEY"}
			cfg.Repositories["repo"] = repo
			writeManagedConfig(t, root, cfg)
			policy, err := loadRPMSigningPolicy(ctx, root, repo.Signing.RPM.Packages)
			if err != nil {
				t.Fatal(err)
			}
			store, err := state.OpenExisting(filepath.Join(root, ".sow/repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			objects, err := store.ListPackageObjects(ctx, []string{"el9"}, false)
			if err != nil || len(objects) != 1 {
				t.Fatal(err)
			}
			manifest := mutationManifest{Version: mutationOperationVersion, Objects: []state.PackageObject{}, Desired: map[string][]string{"el9": {objects[0].SHA256}}, Result: map[string]int{"dists": 1}, RPMSigningKeys: policy.retainedKeys}
			wire, err := marshalMutationManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			id, err := operationID()
			if err != nil {
				t.Fatal(err)
			}
			sha, err := config.FileSHA(filepath.Join(root, "sow.yml"))
			if err != nil {
				t.Fatal(err)
			}
			payload := mutationOperationPayload{Version: mutationOperationVersion, Repository: "repo", Kind: "build", ConfigSHA256: sha, ManifestSHA256: bytesSHA(wire), Jobs: 1, Dists: []string{"el9"}, BuildDists: []string{"el9"}}
			pw, _ := json.Marshal(payload)
			if err = store.BeginOperation(ctx, state.Operation{ID: id, Kind: "build", State: state.OperationPlanned, PayloadJSON: string(pw)}); err != nil {
				t.Fatal(err)
			}
			if err = durableMkdir(mutationStageRoot(root, "repo", id), 0700); err != nil {
				t.Fatal(err)
			}
			if err = writeAtomic(mutationManifestPath(root, "repo", id, payload.ManifestSHA256), wire, 0600); err != nil {
				t.Fatal(err)
			}
			if err = store.SetOperationState(ctx, id, state.OperationStaged, ""); err != nil {
				t.Fatal(err)
			}
			if _, err = store.ApplyDesiredMutation(ctx, id, nil, manifest.Desired, `{"dists":1}`); err != nil {
				t.Fatal(err)
			}
			if err = recordBuildProgress(ctx, store, id, "rendering", 0, 1, 1); err != nil {
				t.Fatal(err)
			}
			// Old versions overwrite applied with recovering on the first retry.
			if err = store.SetOperationState(ctx, id, state.OperationRecovering, ""); err != nil {
				t.Fatal(err)
			}
			if err = store.Close(); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "restored-config":
				if err = os.WriteFile(filepath.Join(root, "sow.yml"), original, 0600); err != nil {
					t.Fatal(err)
				}
			case "public-tamper":
				if err = os.WriteFile(filepath.Join(root, "repo/dists/el9/x86_64/repodata/repomd.xml"), []byte("tampered"), 0644); err != nil {
					t.Fatal(err)
				}
			case "pending-tamper":
				if err = os.WriteFile(filepath.Join(root, ".sow/repo/pending", objects[0].SHA256), []byte("tampered"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			_, err = Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1})
			if scenario == "public-tamper" || scenario == "pending-tamper" {
				if !errors.Is(err, ErrIntegrity) {
					t.Fatalf("tampering error=%v", err)
				}
				return
			}
			if scenario == "same-config" && !errors.Is(err, ErrRejected) {
				t.Fatalf("policy error=%v", err)
			}
			if scenario == "restored-config" && err != nil {
				t.Fatal(err)
			}
			store, err = state.OpenReadOnly(filepath.Join(root, ".sow/repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			detail, err := store.GetOperation(ctx, id)
			if err != nil || detail.Operation.State != state.OperationDoneDirty {
				t.Fatalf("old journal=%+v err=%v", detail.Operation, err)
			}
			store.Close()
			if err = os.WriteFile(filepath.Join(root, "sow.yml"), original, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			checked, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1})
			if err != nil || !checked.ReadyToCopy {
				t.Fatalf("check=%+v err=%v", checked, err)
			}
		})
	}
}

func TestRejectedMutationTerminalCleanupSurvivesInterruption(t *testing.T) {
	ctx := context.Background()
	root, ws := newRejectionWorkspace(t)
	paths := collidingRPMInputs(t, root)
	crash := errors.New("staged crash")
	added, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: paths[:1], Skip: true, Jobs: 1, Fault: func(point string) error {
		if point == "add.staged" {
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
	op, _, _, err := loadMutationOperation(ctx, store, root, "repo", added.Operation)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate interruption after the terminal record but before cleanup.
	// Pending/staged bytes must still exist at this point.
	if err := store.FailOperation(ctx, op.ID, "rejected", "legacy conflict", `{}`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	stage := mutationStageRoot(root, "repo", op.ID)
	if _, err := os.Stat(stage); err != nil {
		t.Fatalf("recovery evidence disappeared before terminal state: %v", err)
	}
	for range 2 {
		if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("terminal stage was not removed: %v", err)
	}
	if _, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
		t.Fatal(err)
	}
}
