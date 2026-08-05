package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestCheckCleanDirtyAndIntegrityWithoutMutation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	beforeTree, _ := publicTreeSnapshot(root, "repo")
	beforeDB, _ := os.ReadFile(filepath.Join(root, ".sow", "repo.db"))
	clean, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if err != nil || !clean.ReadyToCopy || clean.Status != "clean" {
		t.Fatalf("clean=%#v err=%v", clean, err)
	}
	afterTree, _ := publicTreeSnapshot(root, "repo")
	afterDB, _ := os.ReadFile(filepath.Join(root, ".sow", "repo.db"))
	if !reflect.DeepEqual(beforeTree, afterTree) || string(beforeDB) != string(afterDB) {
		t.Fatal("check changed repository state")
	}
	if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Skip: true, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	dirty, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrNotReady) || dirty.ReadyToCopy || dirty.Status != "dirty" {
		t.Fatalf("dirty=%#v err=%v", dirty, err)
	}
	// Pool bytes deliberately remain after Membership removal; corrupting that
	// retained object must still be detected by the full byte layer.
	for path := range beforeTree {
		if len(path) > 5 && path[:5] == "pool/" {
			if err := os.WriteFile(filepath.Join(root, "repo", filepath.FromSlash(path)), []byte("tampered"), 0o644); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	broken, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrIntegrity) || broken.Status != "error" {
		t.Fatalf("broken=%#v err=%v", broken, err)
	}
}

func TestCheckConfigurationLayerRejectsRemovedBuiltArchitectureAndHonorsScope(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Architectures = []string{"x86_64", "aarch64"}
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9":   {Format: "rpm"},
		"noble": {Format: "deb"},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	dist := cfg.Repositories["repo"].Dists["el9"]
	dist.Architectures = []string{"aarch64"}
	repo := cfg.Repositories["repo"]
	repo.Dists["el9"] = dist
	cfg.Repositories["repo"] = repo
	writeManagedConfig(t, root, cfg)

	options := WorkspaceOptions{Workdir: root, CWD: root}
	beforeTree := persistentWorkspaceSnapshot(t, root)
	scoped, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Jobs: 1})
	if err != nil || scoped.Status != "clean" || !scoped.ReadyToCopy {
		t.Fatalf("unaffected scoped check=%#v err=%v", scoped, err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrIntegrity) || checked.Status != "error" || checked.ReadyToCopy {
		t.Fatalf("repo check=%#v err=%v", checked, err)
	}
	layers := make(map[string]CheckLayer, len(checked.Layers))
	for _, layer := range checked.Layers {
		layers[layer.Name] = layer
	}
	configuration, ok := layers["config"]
	if !ok || configuration.OK || !strings.Contains(strings.Join(configuration.Issues, "\n"), "removed") || !layers["index"].OK || !layers["signature"].OK {
		t.Fatalf("check layers do not isolate configuration failure: %#v", checked.Layers)
	}
	afterTree := persistentWorkspaceSnapshot(t, root)
	if !reflect.DeepEqual(beforeTree, afterTree) {
		t.Fatalf("check changed invalid-config persistent state: before=%#v after=%#v", beforeTree, afterTree)
	}

	cfg.Architectures = []string{"x86_64", "aarch64"}
	repo = cfg.Repositories["repo"]
	delete(repo.Dists, "el9")
	cfg.Repositories["repo"] = repo
	writeManagedConfig(t, root, cfg)
	if scoped, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Jobs: 1}); err != nil || !scoped.ReadyToCopy {
		t.Fatalf("unaffected scoped check after config removal=%#v err=%v", scoped, err)
	}
	checked, err = Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	layers = make(map[string]CheckLayer, len(checked.Layers))
	for _, layer := range checked.Layers {
		layers[layer.Name] = layer
	}
	if !errors.Is(err, ErrIntegrity) || layers["config"].OK || !strings.Contains(strings.Join(layers["config"].Issues, "\n"), "absent") {
		t.Fatalf("repo check omitted built Dist removed from config: checked=%#v err=%v", checked, err)
	}
}

func TestCheckAPTIndexLayerValidatesCompleteReleaseProjection(t *testing.T) {
	mutations := map[string]func(string) string{
		"origin":   func(value string) string { return strings.Replace(value, "Origin: SOW", "Origin: Other", 1) },
		"label":    func(value string) string { return strings.Replace(value, "Label: noble", "Label: other", 1) },
		"suite":    func(value string) string { return strings.Replace(value, "Suite: noble", "Suite: other", 1) },
		"codename": func(value string) string { return strings.Replace(value, "Codename: noble", "Codename: other", 1) },
		"architectures": func(value string) string {
			return strings.Replace(value, "Architectures: amd64", "Architectures: arm64", 1)
		},
		"components": func(value string) string { return strings.Replace(value, "Components: main", "Components: contrib", 1) },
		"by-hash": func(value string) string {
			return strings.Replace(value, "Acquire-By-Hash: yes", "Acquire-By-Hash: no", 1)
		},
		"description": func(value string) string {
			return strings.Replace(value, "Description: SOW managed distribution", "Description: other", 1)
		},
		"date": func(value string) string { return strings.Replace(value, "Date: ", "Date: invalid-", 1) },
		"unexpected": func(value string) string {
			return strings.Replace(value, "SHA256:\n", "Unexpected: value\nSHA256:\n", 1)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			options := WorkspaceOptions{Workdir: root, CWD: root}
			cfg := config.Default()
			cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"noble": {Format: "deb", Architectures: []string{"x86_64"}}}}
			writeManagedConfig(t, root, cfg)
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			release := filepath.Join(root, "repo", "dists", "noble", "Release")
			data, err := os.ReadFile(release)
			if err != nil {
				t.Fatal(err)
			}
			changed := mutate(string(data))
			if changed == string(data) {
				t.Fatal("test mutation did not change Release")
			}
			if err := os.WriteFile(release, []byte(changed), 0o644); err != nil {
				t.Fatal(err)
			}
			checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
			if !errors.Is(err, ErrIntegrity) || checked.Status != "error" {
				t.Fatalf("mutated Release check=%#v err=%v", checked, err)
			}
			indexOK := true
			for _, layer := range checked.Layers {
				if layer.Name == "index" {
					indexOK = layer.OK
				}
			}
			if indexOK {
				t.Fatalf("APT Release %s defect was not attributed to index layer: %#v", name, checked.Layers)
			}
		})
	}
}

func TestCheckRejectsStoredPackageSignatureIdentityDrift(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE package_objects SET signature_key = ?`, "0000000000000000000000000000000000000000"); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrIntegrity) || checked.Status != "error" {
		t.Fatalf("check=%#v err=%v", checked, err)
	}
	layers := make(map[string]CheckLayer, len(checked.Layers))
	for _, layer := range checked.Layers {
		layers[layer.Name] = layer
	}
	if layers["signature"].OK || !layers["package-bytes"].OK || !layers["index"].OK {
		t.Fatalf("stored signature drift was not isolated to signature layer: %#v", checked.Layers)
	}
}

func TestCheckCoversUnreferencedPublicPoolObjectsAndRequiresObjectBijection(t *testing.T) {
	makeOrphan := func(t *testing.T) (string, WorkspaceOptions, state.PackageObject) {
		t.Helper()
		ctx := context.Background()
		root := t.TempDir()
		options := WorkspaceOptions{Workdir: root, CWD: root}
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
		writeManagedConfig(t, root, cfg)
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		inputs := filepath.Join(root, "inputs")
		if err := os.Mkdir(inputs, 0o755); err != nil {
			t.Fatal(err)
		}
		rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
		if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		// A later config-only build advances the Dist and intentionally clears
		// the one-generation C2 membership projection. The immutable Pool
		// object and its Generation payload remain retained.
		dist := cfg.Repositories["repo"].Dists["el9"]
		dist.Limit = 1
		repository := cfg.Repositories["repo"]
		repository.Dists["el9"] = dist
		cfg.Repositories["repo"] = repository
		writeManagedConfig(t, root, cfg)
		if _, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		objects, err := store.ListPackageObjects(ctx, nil, false)
		var desired, built, prior int
		countErr := store.DB().QueryRowContext(ctx, `SELECT (SELECT count(*) FROM memberships), (SELECT count(*) FROM built_memberships), (SELECT count(*) FROM prior_built_memberships)`).Scan(&desired, &built, &prior)
		closeErr := store.Close()
		if err := errors.Join(err, countErr, closeErr); err != nil || len(objects) != 1 || desired != 0 || built != 0 || prior != 0 || objects[0].Storage != "pool" {
			t.Fatalf("orphan setup objects=%#v memberships=%d/%d/%d err=%v", objects, desired, built, prior, err)
		}
		return root, options, objects[0]
	}
	layer := func(result CheckResult, name string) CheckLayer {
		for _, candidate := range result.Layers {
			if candidate.Name == name {
				return candidate
			}
		}
		return CheckLayer{}
	}

	t.Run("facts", func(t *testing.T) {
		ctx := context.Background()
		root, options, object := makeOrphan(t)
		clean, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
		if err != nil || !clean.ReadyToCopy || layer(clean, "package-bytes").Checked != 1 {
			t.Fatalf("orphan baseline check=%#v err=%v", clean, err)
		}
		store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		_, updateErr := store.DB().ExecContext(ctx, `UPDATE package_objects SET name = 'tampered-orphan-name' WHERE sha256 = ?`, object.SHA256)
		closeErr := store.Close()
		if err := errors.Join(updateErr, closeErr); err != nil {
			t.Fatal(err)
		}
		checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
		if !errors.Is(err, ErrIntegrity) || checked.Status != "error" || layer(checked, "package-bytes").OK {
			t.Fatalf("orphan fact tamper check=%#v err=%v", checked, err)
		}
	})

	t.Run("missing object row", func(t *testing.T) {
		ctx := context.Background()
		root, options, object := makeOrphan(t)
		store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		_, deleteErr := store.DB().ExecContext(ctx, `DELETE FROM package_objects WHERE sha256 = ?`, object.SHA256)
		closeErr := store.Close()
		if err := errors.Join(deleteErr, closeErr); err != nil {
			t.Fatal(err)
		}
		checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
		if !errors.Is(err, ErrIntegrity) || checked.Status != "error" || layer(checked, "package-bytes").OK {
			t.Fatalf("missing Pool object row check=%#v err=%v", checked, err)
		}
	})
}

func TestCheckRejectsByteIdenticalNonHardlinkC2Alias(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	objects, err := store.ListPackageObjects(ctx, []string{"el9"}, true)
	closeErr := store.Close()
	if err := errors.Join(err, closeErr); err != nil || len(objects) != 1 {
		t.Fatalf("objects=%#v err=%v", objects, err)
	}
	canonical := filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath))
	alias := filepath.Join(root, "repo", "dists", "el9", "x86_64", filepath.FromSlash(objects[0].PoolPath))
	data, err := os.ReadFile(alias)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alias, data, 0o644); err != nil {
		t.Fatal(err)
	}
	canonicalInfo, err := os.Stat(canonical)
	if err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Stat(alias)
	if err != nil || os.SameFile(canonicalInfo, aliasInfo) {
		t.Fatalf("test did not replace hardlink with independent bytes: %v", err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrIntegrity) || checked.Status != "error" {
		t.Fatalf("check accepted byte-identical non-hardlink alias: checked=%#v err=%v", checked, err)
	}
}

func TestCheckReportsWorkspaceRecoveryWithoutMutation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	configData, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	journal := workspaceJournal{
		Version: workspaceJournalVersion, ID: "456", Kind: "repo.init", Repository: "repo",
		OldConfigSHA: bytesSHA(configData), OldConfig: configData,
		NewConfigSHA: bytesSHA(configData), NewConfig: configData, Phase: "applied",
	}
	if err := persistWorkspaceJournal(root, journal); err != nil {
		t.Fatal(err)
	}
	before := persistentWorkspaceSnapshot(t, root)
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrNotReady) || checked.Status != "recovering" || checked.ReadyToCopy {
		t.Fatalf("check=%#v err=%v", checked, err)
	}
	after := persistentWorkspaceSnapshot(t, root)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("check mutated recovering persistent state: before=%#v after=%#v", before, after)
	}
}

func TestCheckRejectsOrphanPendingPayload(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(root, ".sow", "repo", "pending", strings.Repeat("0", 64))
	if err := os.WriteFile(orphan, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrIntegrity) || checked.Status != "error" {
		t.Fatalf("check=%#v err=%v", checked, err)
	}
}

func TestCheckStateLayerValidatesCrossTableSemanticRelations(t *testing.T) {
	mutations := map[string]string{
		"built membership generation": `UPDATE built_memberships SET generation = 999`,
		"prior membership generation": `UPDATE prior_built_memberships SET generation = 999`,
		"architecture generation":     `UPDATE dist_architectures SET built_generation = 999`,
		"dist generation":             `UPDATE dists SET built_generation = 999`,
		"object revision":             `UPDATE package_objects SET created_revision = 999`,
		"membership revision":         `UPDATE memberships SET created_revision = 999`,
		"built object storage":        `UPDATE package_objects SET storage = 'pending'`,
		"repository status":           `UPDATE repository_state SET status = 'dirty', dirty_reason = 'synthetic mismatch'`,
	}
	for name, statement := range mutations {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			options := WorkspaceOptions{Workdir: root, CWD: root}
			cfg := config.Default()
			cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
			writeManagedConfig(t, root, cfg)
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			inputs := filepath.Join(root, "inputs")
			if err := os.Mkdir(inputs, 0o755); err != nil {
				t.Fatal(err)
			}
			rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
			if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			// Advance once more without changing membership so both current and
			// prior-Built relation tables contain evidence.
			dist := cfg.Repositories["repo"].Dists["el9"]
			dist.Limit = 1
			repository := cfg.Repositories["repo"]
			repository.Dists["el9"] = dist
			cfg.Repositories["repo"] = repository
			writeManagedConfig(t, root, cfg)
			if _, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			_, mutationErr := store.DB().ExecContext(ctx, statement)
			closeErr := store.Close()
			if err := errors.Join(mutationErr, closeErr); err != nil {
				t.Fatal(err)
			}
			checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
			if !errors.Is(err, ErrIntegrity) || checked.Status != "error" {
				t.Fatalf("semantic tamper check=%#v err=%v", checked, err)
			}
			stateOK := true
			for _, layer := range checked.Layers {
				if layer.Name == "state" {
					stateOK = layer.OK
				}
			}
			if stateOK {
				t.Fatalf("semantic defect %s was not attributed to state layer: %#v", name, checked.Layers)
			}
		})
	}
}

func TestGenerationZeroRequiresEmptyPublicDeliveryTree(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	options := WorkspaceOptions{Workdir: root, CWD: root}
	clean, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || !clean.ReadyToCopy || clean.Generation != 0 {
		t.Fatalf("clean Generation 0=%#v err=%v", clean, err)
	}
	zero := int64(0)
	if changes, err := Changes(ctx, ChangesOptions{WorkspaceOptions: options, Repository: "repo", Base: &zero}); err != nil || len(changes.Changes) != 0 {
		t.Fatalf("clean Generation 0 changes=%#v err=%v", changes, err)
	}
	if err := os.WriteFile(filepath.Join(root, "repo", "pool", "unexpected"), []byte("unexpected"), 0o644); err != nil {
		t.Fatal(err)
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1}); !errors.Is(err, ErrIntegrity) || checked.Status != "error" {
		t.Fatalf("tampered Generation 0 check=%#v err=%v", checked, err)
	}
	if changes, err := Changes(ctx, ChangesOptions{WorkspaceOptions: options, Repository: "repo", Base: &zero}); !errors.Is(err, ErrIntegrity) || len(changes.Changes) != 0 {
		t.Fatalf("tampered Generation 0 changes=%#v err=%v", changes, err)
	}
}
