package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestBuildRejectsOversizedRPMCertificateSnapshotsBeforeOperation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}

	keysDir := filepath.Join(root, "keys")
	if err := os.Mkdir(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	currentPrivate, currentFingerprint := managedTestPrivateKey(t, "manifest-current")
	currentPublic, err := publicOpenPGPKeyMaterial(currentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	currentPath := filepath.Join(keysDir, "current.asc")
	if err := os.WriteFile(currentPath, currentPublic, 0o600); err != nil {
		t.Fatal(err)
	}
	trusted := make([]string, 0, 4)
	for index := 0; index < 4; index++ {
		// Each certificate is valid under the per-key 16 MiB limit, while the
		// exact snapshots together exceed the recovery artifact's 64 MiB limit.
		privateKey, _ := managedTestPrivateKey(t, strings.Repeat(string(rune('A'+index)), 5<<20))
		publicKey, err := publicOpenPGPKeyMaterial(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		if len(publicKey) >= maxManagedKeyBytes {
			t.Fatalf("certificate %d size=%d exceeds individual bound", index, len(publicKey))
		}
		name := filepath.Join(keysDir, "trusted-"+string(rune('0'+index))+".asc")
		if err := os.WriteFile(name, publicKey, 0o600); err != nil {
			t.Fatal(err)
		}
		trusted = append(trusted, "file://"+name)
	}
	tools := t.TempDir()
	gpg := "#!/bin/sh\ncase \" $* \" in\n  *\" --list-secret-keys \"*) printf 'sec::::::::::\\nfpr:::::::::" + currentFingerprint + ":\\n'; exit 0;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(tools, "gpg"), []byte(gpg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "rpm"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	repository := cfg.Repositories["repo"]
	repository.Signing.RPM.Packages = config.RPMPackageSigningConfig{Mode: "fill", Key: "file://" + currentPath, TrustedKeys: trusted}
	cfg.Repositories["repo"] = repository
	writeManagedConfig(t, root, cfg)

	result, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Jobs: 1})
	if !errors.Is(err, ErrRejected) || result.Operation != "" {
		t.Fatalf("oversized manifest preflight result=%#v err=%v", result, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	pending, pendingErr := store.PendingOperations(ctx)
	keys, keysErr := store.ListRPMSigningKeys(ctx)
	closeErr := store.Close()
	if err := errors.Join(pendingErr, keysErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 || len(keys) != 0 {
		t.Fatalf("pending=%v keys=%v", pending, keys)
	}
	stageEntries, err := os.ReadDir(filepath.Join(root, ".sow", "repo", "stage"))
	if err != nil || len(stageEntries) != 0 {
		t.Fatalf("stage entries=%v err=%v", stageEntries, err)
	}

	repository.Signing.RPM.Packages.TrustedKeys = nil
	cfg.Repositories["repo"] = repository
	writeManagedConfig(t, root, cfg)
	second, secondErr := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Jobs: 1})
	if secondErr != nil || second.Operation == "" || second.Generation == 0 {
		t.Fatalf("bounded follow-up build result=%#v err=%v", second, secondErr)
	}
	checked, checkErr := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Jobs: 1})
	if checkErr != nil || !checked.ReadyToCopy || checked.Status != "clean" {
		t.Fatalf("follow-up check=%#v err=%v", checked, checkErr)
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	keys, keysErr = store.ListRPMSigningKeys(ctx)
	closeErr = store.Close()
	if err := errors.Join(keysErr, closeErr); err != nil || len(keys) != 1 {
		t.Fatalf("follow-up retained keys=%v err=%v", keys, err)
	}
}

func TestBuildRejectsRepeatedOversizedMetadataCertificateBeforeOperation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	dists := make(map[string]config.DistConfig)
	for index := 0; index < 8; index++ {
		dists["el"+string(rune('0'+index))] = config.DistConfig{Format: "rpm"}
	}
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: dists}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}

	keysDir := filepath.Join(root, "keys")
	if err := os.Mkdir(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey, _ := managedTestPrivateKey(t, strings.Repeat("metadata-certificate-user-id", 200_000))
	if len(privateKey) >= maxManagedKeyBytes {
		t.Fatalf("private metadata key size=%d exceeds individual bound", len(privateKey))
	}
	keyPath := filepath.Join(keysDir, "metadata.asc")
	if err := os.WriteFile(keyPath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	repository := cfg.Repositories["repo"]
	repository.Signing.RPM.Metadata = config.MetadataSigningConfig{Key: "file://" + keyPath}
	cfg.Repositories["repo"] = repository
	writeManagedConfig(t, root, cfg)

	result, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrRejected) || result.Operation != "" {
		t.Fatalf("oversized repeated metadata preflight result=%#v err=%v", result, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	pending, pendingErr := store.PendingOperations(ctx)
	closeErr := store.Close()
	if err := errors.Join(pendingErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending operations=%v", pending)
	}
	stageEntries, err := os.ReadDir(filepath.Join(root, ".sow", "repo", "stage"))
	if err != nil || len(stageEntries) != 0 {
		t.Fatalf("stage entries=%v err=%v", stageEntries, err)
	}

	smallPrivate, _ := managedTestPrivateKey(t, "metadata-small")
	if err := os.WriteFile(keyPath, smallPrivate, 0o600); err != nil {
		t.Fatal(err)
	}
	second, secondErr := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if secondErr != nil || second.Operation == "" || second.Generation == 0 {
		t.Fatalf("bounded metadata follow-up result=%#v err=%v", second, secondErr)
	}
	checked, checkErr := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if checkErr != nil || checked.Status != "clean" || !checked.ReadyToCopy {
		t.Fatalf("bounded metadata follow-up check=%#v err=%v", checked, checkErr)
	}
}

func TestAddAndRemoveRejectOversizedSignerProjectionBeforeDesiredWrites(t *testing.T) {
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

	keysDir := filepath.Join(root, "keys")
	if err := os.Mkdir(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	currentPublic, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "compat", "testdata", "PGDG-RPM-GPG-KEY-RHEL-nonfree.asc"))
	if err != nil {
		t.Fatal(err)
	}
	currentPath := filepath.Join(keysDir, "current.asc")
	if err := os.WriteFile(currentPath, currentPublic, 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprints, err := resolveReferenceFingerprints(ctx, root, "file://"+currentPath)
	if err != nil || len(fingerprints) != 1 {
		t.Fatalf("current fingerprints=%v err=%v", fingerprints, err)
	}
	trusted := make([]string, 0, 4)
	for index := 0; index < 4; index++ {
		privateKey, _ := managedTestPrivateKey(t, strings.Repeat(string(rune('Q'+index)), 5<<20))
		publicKey, err := publicOpenPGPKeyMaterial(privateKey)
		if err != nil || len(publicKey) >= maxManagedKeyBytes {
			t.Fatalf("trusted cert %d bytes=%d err=%v", index, len(publicKey), err)
		}
		keyPath := filepath.Join(keysDir, "large-"+string(rune('0'+index))+".asc")
		if err := os.WriteFile(keyPath, publicKey, 0o600); err != nil {
			t.Fatal(err)
		}
		trusted = append(trusted, "file://"+keyPath)
	}
	tools := t.TempDir()
	gpg := "#!/bin/sh\nlast=\nfor arg in \"$@\"; do last=\"$arg\"; done\ncase \" $* \" in\n  *\" --list-secret-keys \"*) printf 'sec::::::::::\\nfpr:::::::::%s:\\n' \"$last\"; exit 0;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(tools, "gpg"), []byte(gpg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "rpm"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))

	setPolicy := func(policy config.RPMPackageSigningConfig) {
		repository := cfg.Repositories["repo"]
		repository.Signing.RPM.Packages = policy
		cfg.Repositories["repo"] = repository
		writeManagedConfig(t, root, cfg)
	}
	hugePolicy := config.RPMPackageSigningConfig{Mode: "fill", Key: "file://" + currentPath, TrustedKeys: trusted}
	setPolicy(hugePolicy)
	beforeAdd, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	addResult, addErr := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1})
	if !errors.Is(addErr, ErrRejected) || addResult.Operation == "" {
		t.Fatalf("oversized add result=%#v err=%v", addResult, addErr)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	detail, detailErr := store.GetOperation(ctx, addResult.Operation)
	objects, objectsErr := store.ListPackageObjects(ctx, nil, false)
	keys, keysErr := store.ListRPMSigningKeys(ctx)
	closeErr := store.Close()
	if err := errors.Join(detailErr, objectsErr, keysErr, closeErr); err != nil {
		t.Fatal(err)
	}
	afterAdd, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	if detail.Operation.State != state.OperationFailed || len(objects) != 0 || len(keys) != 0 || !sameGenerationManifest(beforeAdd, afterAdd) {
		t.Fatalf("failed add operation=%s objects=%d keys=%d public_changed=%v", detail.Operation.State, len(objects), len(keys), !sameGenerationManifest(beforeAdd, afterAdd))
	}
	stageEntries, err := os.ReadDir(filepath.Join(root, ".sow", "repo", "stage"))
	if err != nil || len(stageEntries) != 0 {
		t.Fatalf("failed add stage=%v err=%v", stageEntries, err)
	}

	setPolicy(config.RPMPackageSigningConfig{Mode: "never"})
	added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1})
	if err != nil || added.Accepted != 1 || len(added.Items) != 1 {
		t.Fatalf("bounded add=%#v err=%v", added, err)
	}
	beforeRemove, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	setPolicy(hugePolicy)
	removed, removeErr := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"sha256:" + added.Items[0].SHA256}, Jobs: 1})
	if !errors.Is(removeErr, ErrRejected) || removed.Operation != "" {
		t.Fatalf("oversized remove result=%#v err=%v", removed, removeErr)
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	memberships, membershipsErr := store.MembershipDigests(ctx, "el9", false)
	pending, pendingErr := store.PendingOperations(ctx)
	keys, keysErr = store.ListRPMSigningKeys(ctx)
	closeErr = store.Close()
	if err := errors.Join(membershipsErr, pendingErr, keysErr, closeErr); err != nil {
		t.Fatal(err)
	}
	afterRemove, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	if len(memberships) != 1 || memberships[0] != added.Items[0].SHA256 || len(pending) != 0 || len(keys) != 0 || !sameGenerationManifest(beforeRemove, afterRemove) {
		t.Fatalf("failed remove memberships=%v pending=%v keys=%v public_changed=%v", memberships, pending, keys, !sameGenerationManifest(beforeRemove, afterRemove))
	}
	setPolicy(config.RPMPackageSigningConfig{Mode: "never"})
	final, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"sha256:" + added.Items[0].SHA256}, Jobs: 1})
	if err != nil || final.Operation == "" {
		t.Fatalf("bounded remove=%#v err=%v", final, err)
	}
}
