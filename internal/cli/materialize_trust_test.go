package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestMaterializeAPTKeyRotationDuringCommitRestoresPublishedSuite(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(snapshotAPTConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	debPath := decodeMaterializeFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(root, "package.deb"))
	private, keyPath := writeMaterializeSigningKey(t, root)
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"add", debPath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"promote", "beta", "latest", "--config", configPath, "--repo", "deb-test"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	values := commonFlags{configPath: configPath, repos: csvFlag{items: []string{"deb-test"}}, workers: 2, chunk: 2}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	leaves := selectedLeaves(repos, values)
	privateKey, passphrase, repositoryKeySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, leaves, keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	if !bytes.Equal(private, privateKey) {
		t.Fatal("loaded materialization private key changed")
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	firstTx, err := newTransactionDir(cfg.StatePath(), "apt-trust-first-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(firstTx)
	if _, err := materializeAPTRepo(t.Context(), cfg, canonical, pool, repos[0], "latest", firstTx, values, privateKey, passphrase); err != nil {
		t.Fatalf("initial APT materialization: %v", err)
	}
	publishedRoot := filepath.Join(root, filepath.FromSlash(repos[0].Path))
	before := readMaterializationTree(t, publishedRoot)

	snapshot, err := captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	rotatedRoot := t.TempDir()
	writeMaterializeSigningKey(t, rotatedRoot)
	rotatedPublic, err := os.ReadFile(filepath.Join(rotatedRoot, "repository-public.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	var rotateOnce sync.Once
	snapshot.beforeCheck = func(boundary materializationTrustBoundary) {
		if boundary == materializeTrustAPTCommitAfter {
			rotateOnce.Do(func() {
				atomicReplaceTestFile(t, filepath.Join(root, "repository-public.pgp"), rotatedPublic, 0o644)
			})
		}
	}
	values.materializeTrust = snapshot
	secondTx, err := newTransactionDir(cfg.StatePath(), "apt-trust-second-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(secondTx)
	if _, err := materializeAPTRepo(t.Context(), cfg, canonical, pool, repos[0], "latest", secondTx, values, privateKey, passphrase); err == nil || !strings.Contains(err.Error(), "materialization trust changed") {
		t.Fatalf("in-place repository key rotation was not rejected: %v", err)
	}
	if after := readMaterializationTree(t, publishedRoot); !reflect.DeepEqual(before, after) {
		t.Fatal("APT key rotation left a partially committed or newly signed live suite")
	}
}

func TestMaterializeYUMPackageKeyRotationDuringExchangeRestoresOldGeneration(t *testing.T) {
	root, configPath, rpmPath, keyPath, private := setupServingYUMView(t)
	values := commonFlags{configPath: configPath, repos: csvFlag{items: []string{"rpm-test"}}, workers: 2, chunk: 2}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	leaves := selectedLeaves(repos, values)
	if len(leaves) != 1 {
		t.Fatalf("selected YUM leaves=%d, want 1", len(leaves))
	}
	privateKey, passphrase, repositoryKeySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, leaves, keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	firstTx, err := newTransactionDir(cfg.StatePath(), "yum-trust-first-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(firstTx)
	if _, err := materializeYUMLeaf(t.Context(), cfg, canonical, pool, repos[0], leaves[0], "latest", firstTx, values, privateKey, passphrase); err != nil {
		t.Fatalf("initial YUM materialization: %v", err)
	}
	ref, err := state.ViewRef("latest", repos[0].ID, leaves[0].os, leaves[0].arch)
	if err != nil {
		t.Fatal(err)
	}
	commit, exists, err := canonical.Ref(ref)
	if err != nil || !exists {
		t.Fatalf("latest YUM ref missing: commit=%s exists=%t err=%v", commit, exists, err)
	}
	commitTime, err := canonical.CommitTime(commit)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(private), nil, commitTime)
	if err != nil {
		t.Fatal(err)
	}
	effectiveRoot, err := repos[0].PathForArch(leaves[0].arch)
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := filepath.Join(root, filepath.FromSlash(effectiveRoot))
	live := filepath.Join(repoRoot, "repodata")
	if err := os.RemoveAll(live); err != nil {
		t.Fatal(err)
	}
	info, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	oldGeneration, err := yumrepo.Generate(t.Context(), live, yumrepo.Options{ELMajor: repos[0].OS.Major, Revision: commitTime.Unix() - 1, Signer: signer}, &yumrepo.SliceIterator{Inputs: []yumrepo.PackageInput{{Path: filepath.Join(repoRoot, filepath.FromSlash(info.Location))}}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	rotatedTrust, err := os.ReadFile(filepath.Join(root, "repository-public.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	var rotateOnce sync.Once
	snapshot.beforeCheck = func(boundary materializationTrustBoundary) {
		if boundary == materializeTrustYUMActivationAfter {
			rotateOnce.Do(func() {
				atomicReplaceTestFile(t, filepath.Join(root, "package-trust.asc"), rotatedTrust, 0o644)
			})
		}
	}
	values.materializeTrust = snapshot
	secondTx, err := newTransactionDir(cfg.StatePath(), "yum-trust-second-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(secondTx)
	if _, err := materializeYUMLeaf(t.Context(), cfg, canonical, pool, repos[0], leaves[0], "latest", secondTx, values, privateKey, passphrase); err == nil || !strings.Contains(err.Error(), "package keyring") {
		t.Fatalf("in-place RPM package keyring rotation was not rejected: %v", err)
	}
	active, err := yumrepo.ValidateDirectory(t.Context(), live, yumrepo.CompressionZstd, signer)
	if err != nil {
		t.Fatalf("validate restored YUM generation: %v", err)
	}
	if active.RepomdSHA256 != oldGeneration.RepomdSHA256 || active.Revision != oldGeneration.Revision {
		t.Fatalf("YUM key rotation left the rejected generation live: active=%+v old=%+v", active, oldGeneration)
	}
}

func TestMaterializationTrustSnapshotRejectsParallelMixedYUMKeyrings(t *testing.T) {
	root := t.TempDir()
	secondRepo := `  - id: rpm-two
    type: yum
    path: yum/two/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
`
	configBody := strings.Replace(servingYUMConfig(), "upstreams: []\n", secondRepo+"upstreams: []\n", 1)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	private, _ := writeMaterializeSigningKey(t, root)
	values := commonFlags{configPath: configPath, workers: 2, chunk: 2}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	leaves := selectedLeaves(repos, values)
	repositoryKeySHA, err := repositorySigningKeyIdentity(cfg, private)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureMaterializationTrust(cfg, leaves, private, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.yum) != 2 || snapshot.yum["rpm-test"].digest != snapshot.yum["rpm-two"].digest {
		t.Fatalf("parallel YUM trust snapshot is not one frozen bundle: %+v", snapshot.yum)
	}
	rotatedTrust, err := os.ReadFile(filepath.Join(root, "repository-public.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	atomicReplaceTestFile(t, filepath.Join(root, "package-trust.asc"), rotatedTrust, 0o644)

	errorsByRepo := make(chan error, 2)
	var group sync.WaitGroup
	for _, repo := range repos {
		if repo.Type != "yum" {
			continue
		}
		repo := repo
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := snapshot.requireYUM(cfg, repo, private, materializeTrustPayloadBefore)
			errorsByRepo <- err
		}()
	}
	group.Wait()
	close(errorsByRepo)
	for err := range errorsByRepo {
		if err == nil || !strings.Contains(err.Error(), "package keyring") {
			t.Fatalf("parallel leaf accepted a keyring outside the frozen digest: %v", err)
		}
	}
}

func TestMaterializeAPTSelectedSetForwardsFrozenTrustAcrossSuitesAndRecovers(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	configBody := strings.Replace(snapshotAPTConfig, "suites: [jammy]", "suites: [jammy, noble]", 1)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	debPath := decodeMaterializeFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(root, "package.deb"))
	_, keyPath := writeMaterializeSigningKey(t, root)
	for _, suite := range []string{"jammy", "noble"} {
		var stdout, stderr bytes.Buffer
		arguments := []string{"add", debPath, "--config", configPath, "--repo", "deb-test", "--os", suite, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "2"}
		if code := Main(arguments, &stdout, &stderr); code != ExitOK {
			t.Fatalf("add suite=%s code=%d stdout=%s stderr=%s", suite, code, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"promote", "beta", "latest", "--config", configPath, "--repo", "deb-test"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	values := commonFlags{configPath: configPath, repos: csvFlag{items: []string{"deb-test"}}, workers: 1, chunk: 2, materializeOperation: "materialize"}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	leaves := selectedLeaves(repos, values)
	if len(leaves) != 2 {
		t.Fatalf("APT selected leaves=%d, want 2", len(leaves))
	}
	privateKey, passphrase, repositoryKeySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, leaves, keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	baselineTx, err := newTransactionDir(cfg.StatePath(), "apt-selected-baseline-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baselineTx)
	if _, err := materializeAPTRepo(t.Context(), cfg, canonical, pool, repos[0], "latest", baselineTx, values, privateKey, passphrase); err != nil {
		t.Fatalf("baseline APT selected set: %v", err)
	}
	originalPublic, err := os.ReadFile(filepath.Join(root, "repository-public.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	rotatedRoot := t.TempDir()
	writeMaterializeSigningKey(t, rotatedRoot)
	rotatedPublic, err := os.ReadFile(filepath.Join(rotatedRoot, "repository-public.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	completedPosts := 0
	var rotateOnce sync.Once
	snapshot.beforeCheck = func(boundary materializationTrustBoundary) {
		if boundary == materializeTrustAPTCommitBefore && completedPosts == 1 {
			rotateOnce.Do(func() {
				atomicReplaceTestFile(t, filepath.Join(root, "repository-public.pgp"), rotatedPublic, 0o644)
			})
		}
		if boundary == materializeTrustAPTCommitAfter {
			completedPosts++
		}
	}
	values.materializeTrust = snapshot
	failedTx, err := newTransactionDir(cfg.StatePath(), "apt-selected-drift-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(failedTx)
	if _, err := materializeAPTRepo(t.Context(), cfg, canonical, pool, repos[0], "latest", failedTx, values, privateKey, passphrase); err == nil || !strings.Contains(err.Error(), "selected-set trust barrier failed") {
		t.Fatalf("APT selected-set drift was not failed by the final barrier: %v", err)
	}
	journal, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists || journal.Phase != materializationSelectionDrifted || len(journal.Units) != 2 || len(journal.CompletedUnits) != 2 {
		t.Fatalf("APT selected set was not durably forward-converged: journal=%+v exists=%t err=%v", journal, exists, err)
	}
	aptSigner, err := aptrepo.NewSigner(bytes.NewReader(privateKey), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	for _, suite := range []string{"jammy", "noble"} {
		suiteRoot := filepath.Join(root, "apt", "test", "dists", suite)
		release, readErr := os.ReadFile(filepath.Join(suiteRoot, "Release"))
		inRelease, inReleaseErr := os.ReadFile(filepath.Join(suiteRoot, "InRelease"))
		detached, detachedErr := os.ReadFile(filepath.Join(suiteRoot, "Release.gpg"))
		if err := errors.Join(readErr, inReleaseErr, detachedErr); err != nil {
			t.Fatal(err)
		}
		if err := aptSigner.Verify(release, inRelease, detached, time.Now().UTC()); err != nil {
			t.Fatalf("suite %s did not converge under frozen K1: %v", suite, err)
		}
	}

	// Even after every unit is complete, a rotation exactly at the final
	// barrier must retain the durable fence. A final exact K1 recovery clears it.
	atomicReplaceTestFile(t, filepath.Join(root, "repository-public.pgp"), originalPublic, 0o644)
	finalSnapshot, err := captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	var finalRotate sync.Once
	finalSnapshot.beforeCheck = func(boundary materializationTrustBoundary) {
		if boundary == materializeTrustSelectedSetFinal {
			finalRotate.Do(func() {
				atomicReplaceTestFile(t, filepath.Join(root, "repository-public.pgp"), rotatedPublic, 0o644)
			})
		}
	}
	recoveryValues := values
	recoveryValues.recover = true
	recoveryValues.materializeTrust = finalSnapshot
	finalTx, err := newTransactionDir(cfg.StatePath(), "apt-selected-final-drift-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(finalTx)
	if _, err := materializeAPTRepo(t.Context(), cfg, canonical, pool, repos[0], "latest", finalTx, recoveryValues, privateKey, passphrase); err == nil || !strings.Contains(err.Error(), "selected-set trust barrier failed") {
		t.Fatalf("final-barrier APT rotation was not rejected: %v", err)
	}
	if _, exists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || !exists {
		t.Fatalf("final-barrier drift cleared the APT journal: exists=%t err=%v", exists, err)
	}
	atomicReplaceTestFile(t, filepath.Join(root, "repository-public.pgp"), originalPublic, 0o644)
	recoveredSnapshot, err := captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	recoveryValues.materializeTrust = recoveredSnapshot
	recoveredTx, err := newTransactionDir(cfg.StatePath(), "apt-selected-recovered-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(recoveredTx)
	if _, err := materializeAPTRepo(t.Context(), cfg, canonical, pool, repos[0], "latest", recoveredTx, recoveryValues, privateKey, passphrase); err != nil {
		t.Fatalf("exact K1 APT recovery did not converge: %v", err)
	}
	if _, exists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || exists {
		t.Fatalf("exact K1 APT recovery did not clear journal: exists=%t err=%v", exists, err)
	}
}

func TestMaterializeYUMSelectedSetForwardsFrozenTrustAcrossLeavesAndRecovers(t *testing.T) {
	root := t.TempDir()
	secondRepo := `  - id: rpm-two
    type: yum
    path: yum/two/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
`
	configBody := strings.Replace(snapshotYUMConfig, "upstreams: []\n", secondRepo+"upstreams: []\n", 1)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	_, keyPath := writeMaterializeSigningKey(t, root)
	for _, repoID := range []string{"rpm-test", "rpm-two"} {
		if code, stdout, stderr := runServingCLI(t, "add", rpmPath, "--config", configPath, "--repo", repoID, "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "2"); code != ExitOK {
			t.Fatalf("add repo=%s code=%d stdout=%s stderr=%s", repoID, code, stdout, stderr)
		}
	}
	if code, stdout, stderr := runServingCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "rpm-test,rpm-two"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	values := commonFlags{configPath: configPath, workers: 1, chunk: 2, materializeOperation: "materialize"}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	leaves := selectedLeaves(repos, values)
	if len(leaves) != 2 {
		t.Fatalf("YUM selected leaves=%d, want 2", len(leaves))
	}
	privateKey, passphrase, repositoryKeySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, leaves, keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	baselineTx, err := newTransactionDir(cfg.StatePath(), "yum-selected-baseline-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baselineTx)
	var baselineOutput bytes.Buffer
	if _, err := preparePublicationViewWithVerb(t.Context(), cfg, canonical, pool, repos, "latest", baselineTx, values, privateKey, passphrase, "materialize", &baselineOutput); err != nil {
		t.Fatalf("baseline YUM selected set: %v output=%s", err, baselineOutput.String())
	}
	originalPackageTrust, err := os.ReadFile(filepath.Join(root, "package-trust.asc"))
	if err != nil {
		t.Fatal(err)
	}
	rotatedPackageTrust, err := os.ReadFile(filepath.Join(root, "repository-public.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	completedPosts := 0
	var rotateOnce sync.Once
	snapshot.beforeCheck = func(boundary materializationTrustBoundary) {
		if boundary == materializeTrustYUMActivationBefore && completedPosts == 1 {
			rotateOnce.Do(func() {
				atomicReplaceTestFile(t, filepath.Join(root, "package-trust.asc"), rotatedPackageTrust, 0o644)
			})
		}
		if boundary == materializeTrustYUMActivationAfter {
			completedPosts++
		}
	}
	values.materializeTrust = snapshot
	failedTx, err := newTransactionDir(cfg.StatePath(), "yum-selected-drift-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(failedTx)
	var failedOutput bytes.Buffer
	if _, err := preparePublicationViewWithVerb(t.Context(), cfg, canonical, pool, repos, "latest", failedTx, values, privateKey, passphrase, "materialize", &failedOutput); err == nil || !strings.Contains(err.Error(), "selected-set trust barrier failed") {
		t.Fatalf("YUM selected-set drift was not failed by final barrier: err=%v output=%s", err, failedOutput.String())
	}
	journal, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists || journal.Phase != materializationSelectionDrifted || len(journal.Units) != 2 || len(journal.CompletedUnits) != 2 {
		t.Fatalf("YUM selected set was not durably forward-converged: journal=%+v exists=%t err=%v", journal, exists, err)
	}
	for _, leaf := range leaves {
		ref, err := state.ViewRef("latest", leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			t.Fatal(err)
		}
		commit, exists, err := canonical.Ref(ref)
		if err != nil || !exists {
			t.Fatalf("read %s: commit=%s exists=%t err=%v", ref, commit, exists, err)
		}
		commitTime, err := canonical.CommitTime(commit)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateKey), passphrase, commitTime)
		if err != nil {
			t.Fatal(err)
		}
		effectiveRoot, err := leaf.repo.PathForArch(leaf.arch)
		if err != nil {
			t.Fatal(err)
		}
		compression, err := yumrepo.CompressionForEL(leaf.repo.OS.Major)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := yumrepo.ValidateDirectory(t.Context(), filepath.Join(root, filepath.FromSlash(effectiveRoot), "repodata"), compression, signer); err != nil {
			t.Fatalf("leaf %s did not converge under frozen K1: %v", leaf.repo.ID, err)
		}
	}
	atomicReplaceTestFile(t, filepath.Join(root, "package-trust.asc"), originalPackageTrust, 0o644)
	recoveredSnapshot, err := captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	recoveryValues := values
	recoveryValues.recover = true
	recoveryValues.materializeTrust = recoveredSnapshot
	recoveredTx, err := newTransactionDir(cfg.StatePath(), "yum-selected-recovered-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(recoveredTx)
	var recoveredOutput bytes.Buffer
	if _, err := preparePublicationViewWithVerb(t.Context(), cfg, canonical, pool, repos, "latest", recoveredTx, recoveryValues, privateKey, passphrase, "materialize", &recoveredOutput); err != nil {
		t.Fatalf("exact K1 YUM recovery did not converge: %v output=%s", err, recoveredOutput.String())
	}
	if _, exists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || exists {
		t.Fatalf("exact K1 YUM recovery did not clear journal: exists=%t err=%v", exists, err)
	}
}

func TestLocalServingKeyRotationBeforeLeafCommitLeavesPointerUnchanged(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	values := commonFlags{configPath: configPath, repos: csvFlag{items: []string{"rpm-test"}}, workers: 2, chunk: 2}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	leaves := selectedLeaves(repos, values)
	privateKey, passphrase, repositoryKeySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, leaves, keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	values.materializeTrust, err = captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "serving-trust-commit-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	if _, err := materializeYUMLeaf(t.Context(), cfg, canonical, pool, repos[0], leaves[0], "latest", txDir, values, privateKey, passphrase); err != nil {
		t.Fatalf("materialize raw latest YUM tree: %v", err)
	}
	rotatedTrust, err := os.ReadFile(filepath.Join(root, "repository-public.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	var rotateOnce sync.Once
	var output bytes.Buffer
	_, err = activateLocalYUMServing(t.Context(), cfg, canonical, pool,
		materializeCanonicalSource{ID: "latest", Public: true}, root, "https://repo.example.invalid", repositoryKeySHA, txDir,
		localServingLeavesFromViewLeaves(leaves), values, localServingActivationOptions{
			BeforeLeafCommitTurn: func(localYUMServingLeaf) error {
				rotateOnce.Do(func() {
					atomicReplaceTestFile(t, filepath.Join(root, "package-trust.asc"), rotatedTrust, 0o644)
				})
				return nil
			},
		}, &output)
	if err == nil || !strings.Contains(err.Error(), "package keyring") {
		t.Fatalf("local serving leaf commit accepted rotated trust: err=%v output=%s", err, output.String())
	}
	mirrorPath := serving.MirrorlistPath("latest", "rpm-test", "el10", "x86_64")
	if _, exists, err := serving.ReadMirrorlist(root, mirrorPath); err != nil || exists {
		t.Fatalf("rejected local serving generation became reachable: exists=%t err=%v", exists, err)
	}
	target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	channelPath := serving.ChannelStatePath(serving.Channel{TargetID: target.ID, View: "latest", Repo: "rpm-test", OS: "el10", Arch: "x86_64"})
	if reader, err := canonical.OpenPath(channelPath); err == nil {
		reader.Close()
		t.Fatal("rejected local serving channel was committed canonically")
	}
}

func TestLocalServingRestorePostGuardRemovesOldTrustPointer(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	arguments := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("initial materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	values := commonFlags{configPath: configPath, repos: csvFlag{items: []string{"rpm-test"}}, workers: 2, chunk: 2}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	leaves := selectedLeaves(repos, values)
	privateKey, passphrase, repositoryKeySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, leaves, keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	values.materializeTrust, err = captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	channelPath := serving.ChannelStatePath(serving.Channel{TargetID: target.ID, View: "latest", Repo: "rpm-test", OS: "el10", Arch: "x86_64"})
	channelBody, exists, err := readOptionalCanonical(canonical, channelPath)
	if err != nil || !exists {
		t.Fatalf("canonical local serving channel missing: exists=%t err=%v", exists, err)
	}
	channel, err := serving.DecodeChannel(channelBody)
	if err != nil {
		t.Fatal(err)
	}
	if removed, err := serving.RemoveMirrorlist(root, channel); err != nil || !removed {
		t.Fatalf("remove committed mirrorlist for restore test: removed=%t err=%v", removed, err)
	}
	rotatedTrust, err := os.ReadFile(filepath.Join(root, "repository-public.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	var rotateOnce sync.Once
	values.materializeTrust.beforeCheck = func(boundary materializationTrustBoundary) {
		if boundary == materializeTrustServingRestoreAfter {
			rotateOnce.Do(func() {
				atomicReplaceTestFile(t, filepath.Join(root, "package-trust.asc"), rotatedTrust, 0o644)
			})
		}
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "serving-trust-restore-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	var output bytes.Buffer
	_, err = activateLocalYUMServing(t.Context(), cfg, canonical, pool,
		materializeCanonicalSource{ID: "latest", Public: true}, root, "https://repo.example.invalid", repositoryKeySHA, txDir,
		localServingLeavesFromViewLeaves(leaves), values, localServingActivationOptions{}, &output)
	if err == nil || !strings.Contains(err.Error(), "package keyring") {
		t.Fatalf("restored pointer accepted rotated trust: err=%v output=%s", err, output.String())
	}
	if _, exists, err := serving.ReadMirrorlist(root, channel.MirrorlistPath); err != nil || exists {
		t.Fatalf("post-guard failure left restored old-trust pointer reachable: exists=%t err=%v", exists, err)
	}
}

func TestLocalServingPostLedgerTrustFailureBlocksRecoveryUntilTrustRestored(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	values := commonFlags{configPath: configPath, repos: csvFlag{items: []string{"rpm-test"}}, workers: 2, chunk: 2}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		t.Fatal(err)
	}
	leaves := selectedLeaves(repos, values)
	privateKey, passphrase, repositoryKeySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, leaves, keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	values.materializeTrust, err = captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "serving-trust-ledger-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	if _, err := materializeYUMLeaf(t.Context(), cfg, canonical, pool, repos[0], leaves[0], "latest", txDir, values, privateKey, passphrase); err != nil {
		t.Fatalf("materialize raw latest YUM tree: %v", err)
	}
	originalTrust, err := os.ReadFile(filepath.Join(root, "package-trust.asc"))
	if err != nil {
		t.Fatal(err)
	}
	rotatedTrust, err := os.ReadFile(filepath.Join(root, "repository-public.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	var rotateOnce sync.Once
	var output bytes.Buffer
	_, err = activateLocalYUMServing(t.Context(), cfg, canonical, pool,
		materializeCanonicalSource{ID: "latest", Public: true}, root, "https://repo.example.invalid", repositoryKeySHA, txDir,
		localServingLeavesFromViewLeaves(leaves), values, localServingActivationOptions{
			AfterPhase: func(phase localServingPhase) error {
				if phase == localServingStateCommitted {
					rotateOnce.Do(func() {
						atomicReplaceTestFile(t, filepath.Join(root, "package-trust.asc"), rotatedTrust, 0o644)
					})
				}
				return nil
			},
		}, &output)
	if err == nil || !strings.Contains(err.Error(), "package keyring") {
		t.Fatalf("post-ledger trust rotation was not rejected: err=%v output=%s", err, output.String())
	}
	mirrorPath := serving.MirrorlistPath("latest", "rpm-test", "el10", "x86_64")
	if _, exists, err := serving.ReadMirrorlist(root, mirrorPath); err != nil || exists {
		t.Fatalf("post-ledger trust failure exposed a pointer: exists=%t err=%v", exists, err)
	}
	journals, err := listLocalServingJournals(cfg.StatePath())
	if err != nil || len(journals) != 1 || journals[0].Phase != localServingStateCommitted || !validMaterializationTrustSHA256(journals[0].PackageKeyringSHA256) {
		t.Fatalf("post-ledger failure is not recoverably journaled: journals=%+v err=%v", journals, err)
	}
	output.Reset()
	if err := prepareLocalServingState(t.Context(), cfg, canonical, true, values, &output); err == nil || !strings.Contains(err.Error(), "recovery trust changed") {
		t.Fatalf("recovery accepted rotated package trust: err=%v output=%s", err, output.String())
	}
	if _, exists, err := serving.ReadMirrorlist(root, mirrorPath); err != nil || exists {
		t.Fatalf("blocked recovery exposed a pointer: exists=%t err=%v", exists, err)
	}
	atomicReplaceTestFile(t, filepath.Join(root, "package-trust.asc"), originalTrust, 0o644)
	var recoveryRotateOnce sync.Once
	values.localServingRecoveryTrustHook = func(boundary localServingRecoveryTrustBoundary) {
		if boundary == localServingRecoveryTrustAfterPointer {
			recoveryRotateOnce.Do(func() {
				atomicReplaceTestFile(t, filepath.Join(root, "package-trust.asc"), rotatedTrust, 0o644)
			})
		}
	}
	output.Reset()
	if err := prepareLocalServingState(t.Context(), cfg, canonical, true, values, &output); err == nil || !strings.Contains(err.Error(), "after pointer activation") {
		t.Fatalf("post-pointer recovery trust rotation was not rejected: err=%v output=%s", err, output.String())
	}
	if _, exists, err := serving.ReadMirrorlist(root, mirrorPath); err != nil || exists {
		t.Fatalf("post-pointer recovery trust failure was not rolled back: exists=%t err=%v", exists, err)
	}
	if journals, err := listLocalServingJournals(cfg.StatePath()); err != nil || len(journals) != 1 {
		t.Fatalf("rolled-back recovery lost its durable journal: journals=%+v err=%v", journals, err)
	}
	atomicReplaceTestFile(t, filepath.Join(root, "package-trust.asc"), originalTrust, 0o644)
	values.localServingRecoveryTrustHook = nil
	output.Reset()
	if err := prepareLocalServingState(t.Context(), cfg, canonical, true, values, &output); err != nil {
		t.Fatalf("recovery after restoring frozen trust: %v output=%s", err, output.String())
	}
	if _, exists, err := serving.ReadMirrorlist(root, mirrorPath); err != nil || !exists {
		t.Fatalf("restored-trust recovery did not complete the pointer: exists=%t err=%v", exists, err)
	}
}

func atomicReplaceTestFile(t *testing.T, destination string, body []byte, mode os.FileMode) {
	t.Helper()
	temporary := destination + ".rotation"
	if err := os.WriteFile(temporary, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, destination); err != nil {
		t.Fatal(err)
	}
}

func readMaterializationTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	if err := filepath.WalkDir(root, func(filename string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(relative)] = body
		return nil
	}); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return result
}
