package compat_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/state"
)

// TestShippedExampleSupportsCleanRoomLocalMVP executes the documented local
// path plus all three repository types with the production binary and shipped
// configuration. Repository signing material is generated only in the
// disposable test root; provider credentials and network opt-ins stay absent.
func TestShippedExampleSupportsCleanRoomLocalMVP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	moduleRoot := findModuleRoot(t)
	work := hostableCompatTempDir(t)
	cleanRoomEnvironment := cleanRoomSubprocessEnvironment(t, work)
	// Scope every existing build and successful CLI call site to the same
	// allowlisted environment; expected-failure execs set it explicitly below.
	buildCLI := func(ctx context.Context, t *testing.T, moduleRoot, work string) string {
		return buildCleanRoomCLI(ctx, t, moduleRoot, work, cleanRoomEnvironment)
	}
	runCLI := func(
		ctx context.Context,
		t *testing.T,
		moduleRoot string,
		executable string,
		arguments ...string,
	) string {
		return runCleanRoomCLI(ctx, t, moduleRoot, executable, cleanRoomEnvironment, arguments...)
	}
	repositoryRoot := filepath.Join(work, "repository")
	for _, directory := range []string{
		repositoryRoot,
		filepath.Join(repositoryRoot, "bin"),
		filepath.Join(repositoryRoot, "keys"),
		filepath.Join(repositoryRoot, "yum", "pgsql", "el9.x86_64"),
		filepath.Join(repositoryRoot, "apt", "pgsql", "trixie"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	example, err := os.ReadFile(filepath.Join(moduleRoot, "sow.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	const debFixtureName = "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb"
	debPath := decodeBase64Fixture(t,
		filepath.Join(moduleRoot, "internal", "aptrepo", "testdata", debFixtureName+".b64"),
		filepath.Join(work, debFixtureName),
	)
	debMetadata, err := aptrepo.InspectPackage(ctx, debPath, "main")
	if err != nil {
		t.Fatalf("inspect checked-in external DEB fixture: %v", err)
	}

	const shippedAPTRepoID = "pgsql-trixie-amd64"
	aptRepoID := "pgsql-trixie-" + debMetadata.Architecture
	configuredExample := cleanRoomReplaceExactlyOnce(
		t,
		example,
		"id: "+shippedAPTRepoID,
		"id: "+aptRepoID,
	)
	configuredExample = cleanRoomReplaceExactlyOnce(
		t,
		configuredExample,
		"arches: [amd64]",
		"arches: ["+debMetadata.Architecture+"]",
	)
	const shippedPackageKeyring = "yum: {compression: zstd, package_keyring: keys/pigsty.asc}"
	const separatedPackageKeyring = "yum: {compression: zstd, package_keyring: keys/rpm-signers.asc}"
	configuredExample = cleanRoomReplaceExactlyOnce(
		t,
		configuredExample,
		shippedPackageKeyring,
		separatedPackageKeyring,
	)
	configPath := filepath.Join(work, "sow.yaml")
	writeFile(t, configPath, configuredExample, 0o600)
	privateKey, _ := writeSigningKey(t, work)
	passphrasePath := filepath.Join(work, "signing-passphrase")
	writeFile(t, passphrasePath, []byte("clean-room-test-passphrase\n"), 0o600)
	if err := os.Mkdir(filepath.Join(work, "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	repositoryPublicKey, err := os.ReadFile(filepath.Join(work, "signing-public.asc"))
	if err != nil {
		t.Fatal(err)
	}
	rpmPackageKey, err := os.ReadFile(filepath.Join(moduleRoot, "test", "compat", "testdata", "PGDG-RPM-GPG-KEY-RHEL-nonfree.asc"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []struct {
		relative string
		body     []byte
	}{
		{relative: "keys/pigsty.asc", body: repositoryPublicKey},
		{relative: "keys/rpm-signers.asc", body: rpmPackageKey},
	} {
		writeFile(t, filepath.Join(work, filepath.FromSlash(key.relative)), key.body, 0o644)
		writeFile(t, filepath.Join(repositoryRoot, filepath.FromSlash(key.relative)), key.body, 0o644)
	}
	inputBody := []byte("sow local MVP\n")
	inputPath := filepath.Join(work, "sow-demo.bin")
	writeFile(t, inputPath, inputBody, 0o644)
	rpmPath := decodeBase64Fixture(t,
		filepath.Join(moduleRoot, "internal", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"),
		filepath.Join(work, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm"),
	)

	cliPath := buildCLI(ctx, t, moduleRoot, work)
	runCLI(ctx, t, moduleRoot, cliPath,
		"init", "--config", configPath, "--root", repositoryRoot)
	runCLI(ctx, t, moduleRoot, cliPath,
		"add", inputPath, "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin")
	assetAddHEAD := cleanRoomCanonicalHEAD(t, repositoryRoot)
	addReplayOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"add", inputPath, "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin")
	if !strings.Contains(addReplayOutput, "add unchanged repo=assets-bin view=beta") {
		t.Fatalf("asset add replay was not idempotent:\n%s", addReplayOutput)
	}
	assertCleanRoomHEAD(t, repositoryRoot, assetAddHEAD, "asset add replay")
	runCLI(ctx, t, moduleRoot, cliPath,
		"add", debPath, "--config", configPath, "--root", repositoryRoot,
		"--repo", aptRepoID, "--component", "main",
		"--gpg-private-key-file", privateKey, "--gpg-passphrase-file", passphrasePath)
	debAddHEAD := cleanRoomCanonicalHEAD(t, repositoryRoot)
	debReplayOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"add", debPath, "--config", configPath, "--root", repositoryRoot,
		"--repo", aptRepoID, "--component", "main",
		"--gpg-private-key-file", privateKey, "--gpg-passphrase-file", passphrasePath)
	if !strings.Contains(debReplayOutput, "add unchanged format=deb") ||
		!strings.Contains(debReplayOutput, "physical=no-op") ||
		strings.Contains(debReplayOutput, "repair=materialization") {
		t.Fatalf("DEB add replay was not idempotent:\n%s", debReplayOutput)
	}
	assertCleanRoomHEAD(t, repositoryRoot, debAddHEAD, "DEB add replay")
	runCLI(ctx, t, moduleRoot, cliPath,
		"add", rpmPath, "--config", configPath, "--root", repositoryRoot,
		"--repo", "pgsql-el9-x86-64", "--gpg-private-key-file", privateKey,
		"--gpg-passphrase-file", passphrasePath)
	rpmAddHEAD := cleanRoomCanonicalHEAD(t, repositoryRoot)
	rpmReplayOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"add", rpmPath, "--config", configPath, "--root", repositoryRoot,
		"--repo", "pgsql-el9-x86-64", "--gpg-private-key-file", privateKey,
		"--gpg-passphrase-file", passphrasePath)
	if !strings.Contains(rpmReplayOutput, "add unchanged format=rpm") ||
		!strings.Contains(rpmReplayOutput, "physical=no-op") ||
		strings.Contains(rpmReplayOutput, "repair=materialization") {
		t.Fatalf("RPM add replay was not idempotent:\n%s", rpmReplayOutput)
	}
	assertCleanRoomHEAD(t, repositoryRoot, rpmAddHEAD, "RPM add replay")
	verifyOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"verify", "--config", configPath, "--root", repositoryRoot,
		"--layer", "L1", "--view", "beta", "--repo", "assets-bin")
	if !strings.Contains(verifyOutput, "verify outcome=passed") {
		t.Fatalf("local L1 verification did not pass:\n%s", verifyOutput)
	}
	runCLI(ctx, t, moduleRoot, cliPath,
		"promote", "beta", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin")
	assetPromoteHEAD := cleanRoomCanonicalHEAD(t, repositoryRoot)
	promoteReplayOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"promote", "beta", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin")
	if !strings.Contains(promoteReplayOutput, "promote unchanged source=beta destination=latest") {
		t.Fatalf("promote replay was not idempotent:\n%s", promoteReplayOutput)
	}
	assertCleanRoomHEAD(t, repositoryRoot, assetPromoteHEAD, "asset promote replay")
	runCLI(ctx, t, moduleRoot, cliPath,
		"verify", "--config", configPath, "--root", repositoryRoot,
		"--layer", "L1", "--view", "beta",
		"--repo", aptRepoID, "--repo", "pgsql-el9-x86-64")
	runCLI(ctx, t, moduleRoot, cliPath,
		"promote", "beta", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", aptRepoID, "--repo", "pgsql-el9-x86-64")
	packagePromoteHEAD := cleanRoomCanonicalHEAD(t, repositoryRoot)
	packagePromoteReplay := runCLI(ctx, t, moduleRoot, cliPath,
		"promote", "beta", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", aptRepoID, "--repo", "pgsql-el9-x86-64")
	if !strings.Contains(packagePromoteReplay, "promote unchanged source=beta destination=latest") {
		t.Fatalf("package promote replay was not idempotent:\n%s", packagePromoteReplay)
	}
	assertCleanRoomHEAD(t, repositoryRoot, packagePromoteHEAD, "package promote replay")
	runCLI(ctx, t, moduleRoot, cliPath,
		"materialize", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin", "--target", "export/latest")
	assetMaterializeHEAD := cleanRoomCanonicalHEAD(t, repositoryRoot)
	materializeReplayOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"materialize", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin", "--target", "export/latest")
	if !strings.Contains(materializeReplayOutput, "route_receipt_changed=false") ||
		!strings.Contains(materializeReplayOutput, "existing=1") {
		t.Fatalf("materialize replay was not idempotent:\n%s", materializeReplayOutput)
	}
	assertCleanRoomHEAD(t, repositoryRoot, assetMaterializeHEAD, "asset materialize replay")
	runCLI(ctx, t, moduleRoot, cliPath,
		"materialize", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", aptRepoID, "--repo", "pgsql-el9-x86-64",
		"--target", "export/packages", "--gpg-private-key-file", privateKey,
		"--gpg-passphrase-file", passphrasePath,
		"--serving-base-url", "https://repo.example.invalid")
	packageMaterializeHEAD := cleanRoomCanonicalHEAD(t, repositoryRoot)
	exportRoot := filepath.Join(repositoryRoot, "export", "packages")
	firstYUMGeneration := assertCleanRoomPackageRepositories(t, exportRoot, debMetadata)
	yumGenerationRoot := filepath.Join(
		exportRoot, "_sow", "v1", "g", firstYUMGeneration, "yum", "pgsql", "el9.x86_64",
	)
	packageReplayIdentities := captureCleanRoomFileIdentities(
		t,
		filepath.Join(
			exportRoot, "_sow", "v1", "mirrorlist", "latest",
			"pgsql-el9-x86-64", "el9", "x86_64.txt",
		),
		filepath.Join(yumGenerationRoot, "repodata", "repomd.xml"),
		filepath.Join(yumGenerationRoot, "Packages", "p", rpmPackage+"-"+rpmVersionArch+".rpm"),
	)
	packageMaterializeReplay := runCLI(ctx, t, moduleRoot, cliPath,
		"materialize", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", aptRepoID, "--repo", "pgsql-el9-x86-64",
		"--target", "export/packages", "--gpg-private-key-file", privateKey,
		"--gpg-passphrase-file", passphrasePath,
		"--serving-base-url", "https://repo.example.invalid")
	wantServingReplay := "serving view=latest repo=pgsql-el9-x86-64 os=el9 arch=x86_64 generation=" +
		firstYUMGeneration + " created=false pointer=unchanged"
	if !strings.Contains(packageMaterializeReplay, wantServingReplay) ||
		cleanRoomSummaryField(t, packageMaterializeReplay, "serving_created") != "0" ||
		cleanRoomSummaryField(t, packageMaterializeReplay, "serving_pointers") != "0" ||
		cleanRoomSummaryField(t, packageMaterializeReplay, "route_receipt_changed") != "false" ||
		cleanRoomSummaryField(t, packageMaterializeReplay, "existing") == "0" ||
		cleanRoomSummaryField(t, packageMaterializeReplay, "linked") != "0" ||
		cleanRoomSummaryField(t, packageMaterializeReplay, "relinked") != "0" ||
		cleanRoomSummaryField(t, packageMaterializeReplay, "pruned") != "0" {
		t.Fatalf("package materialize replay was not idempotent:\n%s", packageMaterializeReplay)
	}
	assertCleanRoomHEAD(t, repositoryRoot, packageMaterializeHEAD, "package materialize replay")
	assertCleanRoomFileIdentities(t, packageReplayIdentities)
	if got := assertCleanRoomPackageRepositories(t, exportRoot, debMetadata); got != firstYUMGeneration {
		t.Fatalf("package materialize replay changed YUM generation: got=%s want=%s", got, firstYUMGeneration)
	}
	fsckOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"fsck", "--config", configPath, "--root", repositoryRoot)
	if !strings.Contains(fsckOutput, "fsck clean repos=3 targets=0") {
		t.Fatalf("clean-room fsck did not close all shipped repositories:\n%s", fsckOutput)
	}

	materialized, err := os.ReadFile(filepath.Join(repositoryRoot, "export", "latest", "bin", filepath.Base(inputPath)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(materialized, inputBody) {
		t.Fatalf("materialized asset=%q want=%q", materialized, inputBody)
	}

	// Close the asset removal and two-phase GC lifecycle without weakening the
	// shipped rollback default. This disposable copy uses one retained commit
	// only to make one unexported asset deterministically collectible.
	const defaultHistory = "cas_history_commits: 32"
	const testHistory = "cas_history_commits: 1"
	if bytes.Count(example, []byte(defaultHistory)) != 1 {
		t.Fatalf("shipped example must contain exactly one %q", defaultHistory)
	}
	writeFile(t, configPath, bytes.Replace(configuredExample, []byte(defaultHistory), []byte(testHistory), 1), 0o600)
	gcInputBody := []byte("sow local GC lifecycle\n")
	gcInputPath := filepath.Join(work, "sow-gc-demo.bin")
	writeFile(t, gcInputPath, gcInputBody, 0o644)
	runCLI(ctx, t, moduleRoot, cliPath,
		"add", gcInputPath, "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin")
	runCLI(ctx, t, moduleRoot, cliPath,
		"rm", filepath.Base(gcInputPath), "--view", "beta",
		"--config", configPath, "--root", repositoryRoot, "--repo", "assets-bin")

	gcDigest := fmt.Sprintf("%x", sha256.Sum256(gcInputBody))
	gcObjectPath := filepath.Join(repositoryRoot, ".pool", "sha256", gcDigest[:2], gcDigest)
	if _, err := os.Stat(gcObjectPath); err != nil {
		t.Fatalf("collectible CAS object missing before GC: %v", err)
	}
	gcDryRun := runCLI(ctx, t, moduleRoot, cliPath,
		"gc", "--config", configPath, "--root", repositoryRoot, "--limit", "20")
	if cleanRoomSummaryField(t, gcDryRun, "dry_run") != "true" ||
		cleanRoomSummaryField(t, gcDryRun, "orphans") != "1" {
		t.Fatalf("GC dry run did not identify exactly one orphan:\n%s", gcDryRun)
	}
	gcPlan := cleanRoomSummaryField(t, gcDryRun, "gc_set_sha256")
	gcApply := runCLI(ctx, t, moduleRoot, cliPath,
		"gc", "--config", configPath, "--root", repositoryRoot,
		"--apply", "--confirm", gcPlan, "--limit", "20")
	if cleanRoomSummaryField(t, gcApply, "dry_run") != "false" ||
		cleanRoomSummaryField(t, gcApply, "deleted") != "1" {
		t.Fatalf("confirmed GC did not delete the exact orphan:\n%s", gcApply)
	}
	if _, err := os.Stat(gcObjectPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("confirmed GC retained orphan %s: %v", gcObjectPath, err)
	}

	// Change the current non-empty deletion set after confirmation. Reusing the
	// old digest must preserve the newly orphaned object, not merely reject an
	// already-empty replay.
	changedGCBody := []byte("sow GC set changed after confirmation\n")
	changedGCInput := filepath.Join(work, "sow-gc-changed.bin")
	writeFile(t, changedGCInput, changedGCBody, 0o644)
	runCLI(ctx, t, moduleRoot, cliPath,
		"add", changedGCInput, "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin")
	runCLI(ctx, t, moduleRoot, cliPath,
		"rm", filepath.Base(changedGCInput), "--view", "beta",
		"--config", configPath, "--root", repositoryRoot, "--repo", "assets-bin")
	changedGCDigest := fmt.Sprintf("%x", sha256.Sum256(changedGCBody))
	changedGCObjectPath := filepath.Join(repositoryRoot, ".pool", "sha256", changedGCDigest[:2], changedGCDigest)

	staleGC := exec.CommandContext(ctx, cliPath,
		"gc", "--config", configPath, "--root", repositoryRoot,
		"--apply", "--confirm", gcPlan, "--limit", "20")
	staleGC.Dir = moduleRoot
	staleGC.Env = cleanRoomEnvironment
	staleGCOutput, staleGCErr := staleGC.CombinedOutput()
	var staleGCExit *exec.ExitError
	if !errors.As(staleGCErr, &staleGCExit) || staleGCExit.ExitCode() != 6 ||
		!strings.Contains(string(staleGCOutput), "confirmation differs from current") {
		t.Fatalf("stale GC confirmation did not fail closed: err=%v\n%s", staleGCErr, staleGCOutput)
	}
	if _, err := os.Stat(changedGCObjectPath); err != nil {
		t.Fatalf("stale GC confirmation deleted a newly orphaned object: %v", err)
	}
	changedGCDryRun := runCLI(ctx, t, moduleRoot, cliPath,
		"gc", "--config", configPath, "--root", repositoryRoot, "--limit", "20")
	if cleanRoomSummaryField(t, changedGCDryRun, "orphans") != "1" {
		t.Fatalf("changed GC set did not retain exactly one orphan:\n%s", changedGCDryRun)
	}
	changedGCPlan := cleanRoomSummaryField(t, changedGCDryRun, "gc_set_sha256")
	runCLI(ctx, t, moduleRoot, cliPath,
		"gc", "--config", configPath, "--root", repositoryRoot,
		"--apply", "--confirm", changedGCPlan, "--limit", "20")
	if _, err := os.Stat(changedGCObjectPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fresh GC confirmation retained changed orphan: %v", err)
	}
	gcReplay := runCLI(ctx, t, moduleRoot, cliPath,
		"gc", "--config", configPath, "--root", repositoryRoot, "--limit", "20")
	if cleanRoomSummaryField(t, gcReplay, "orphans") != "0" ||
		cleanRoomSummaryField(t, gcReplay, "deleted") != "0" {
		t.Fatalf("GC replay did not converge:\n%s", gcReplay)
	}

	runCLI(ctx, t, moduleRoot, cliPath,
		"rm", filepath.Base(inputPath), "--view", "latest",
		"--config", configPath, "--root", repositoryRoot, "--repo", "assets-bin")
	assetRemoveHEAD := cleanRoomCanonicalHEAD(t, repositoryRoot)
	rmReplayOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"rm", filepath.Base(inputPath), "--view", "latest",
		"--config", configPath, "--root", repositoryRoot, "--repo", "assets-bin")
	if !strings.Contains(rmReplayOutput, "rm unchanged view=latest") {
		t.Fatalf("asset rm replay was not idempotent:\n%s", rmReplayOutput)
	}
	assertCleanRoomHEAD(t, repositoryRoot, assetRemoveHEAD, "asset rm replay")
	runCLI(ctx, t, moduleRoot, cliPath,
		"rm", filepath.Base(inputPath), "--view", "beta",
		"--config", configPath, "--root", repositoryRoot, "--repo", "assets-bin")
	materializeRemoval := runCLI(ctx, t, moduleRoot, cliPath,
		"materialize", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin", "--target", "export/latest")
	if !strings.Contains(materializeRemoval, "pruned=1") {
		t.Fatalf("materialized export did not report deleted asset pruning:\n%s", materializeRemoval)
	}
	if _, err := os.Stat(filepath.Join(repositoryRoot, "export", "latest", "bin", filepath.Base(inputPath))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted asset remains in Nginx-hostable export: %v", err)
	}

	for _, view := range []string{"latest", "beta"} {
		runCLI(ctx, t, moduleRoot, cliPath,
			"rm", debMetadata.Name, "--view", view, "--config", configPath, "--root", repositoryRoot,
			"--repo", aptRepoID, "--gpg-private-key-file", privateKey,
			"--gpg-passphrase-file", passphrasePath)
		runCLI(ctx, t, moduleRoot, cliPath,
			"rm", rpmPackage, "--view", view, "--config", configPath, "--root", repositoryRoot,
			"--repo", "pgsql-el9-x86-64", "--gpg-private-key-file", privateKey,
			"--gpg-passphrase-file", passphrasePath)
	}
	packageRemoveHEAD := cleanRoomCanonicalHEAD(t, repositoryRoot)
	debRemoveReplay := runCLI(ctx, t, moduleRoot, cliPath,
		"rm", debMetadata.Name, "--view", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", aptRepoID, "--gpg-private-key-file", privateKey,
		"--gpg-passphrase-file", passphrasePath)
	if !strings.Contains(debRemoveReplay, "rm unchanged view=latest") ||
		!strings.Contains(debRemoveReplay, "physical=no-op") ||
		strings.Contains(debRemoveReplay, "repair=materialization") {
		t.Fatalf("DEB rm replay was not idempotent:\n%s", debRemoveReplay)
	}
	assertCleanRoomHEAD(t, repositoryRoot, packageRemoveHEAD, "DEB rm replay")
	rpmRemoveReplay := runCLI(ctx, t, moduleRoot, cliPath,
		"rm", rpmPackage, "--view", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", "pgsql-el9-x86-64", "--gpg-private-key-file", privateKey,
		"--gpg-passphrase-file", passphrasePath)
	if !strings.Contains(rpmRemoveReplay, "rm unchanged view=latest") ||
		!strings.Contains(rpmRemoveReplay, "physical=no-op") ||
		strings.Contains(rpmRemoveReplay, "repair=materialization") {
		t.Fatalf("RPM rm replay was not idempotent:\n%s", rpmRemoveReplay)
	}
	assertCleanRoomHEAD(t, repositoryRoot, packageRemoveHEAD, "RPM rm replay")
	runCLI(ctx, t, moduleRoot, cliPath,
		"materialize", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", aptRepoID, "--repo", "pgsql-el9-x86-64",
		"--target", "export/packages", "--gpg-private-key-file", privateKey,
		"--gpg-passphrase-file", passphrasePath,
		"--serving-base-url", "https://repo.example.invalid")
	assertCleanRoomPackageRemoval(t, exportRoot, firstYUMGeneration, debMetadata)
	runCLI(ctx, t, moduleRoot, cliPath,
		"verify", "--config", configPath, "--root", repositoryRoot,
		"--layer", "L1", "--view", "beta,latest",
		"--repo", aptRepoID, "--repo", "pgsql-el9-x86-64")

	cachePath := filepath.Join(repositoryRoot, ".sow", "cache", "state.db")
	if err := os.Remove(cachePath); err != nil {
		t.Fatal(err)
	}
	cacheRecoveryOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"fsck", "--recover", "--config", configPath, "--root", repositoryRoot)
	if !strings.Contains(cacheRecoveryOutput, "cache rebuilt after recovery") ||
		!strings.Contains(cacheRecoveryOutput, "fsck clean repos=3 targets=0") {
		t.Fatalf("explicit cache recovery did not rebuild and audit canonical state:\n%s", cacheRecoveryOutput)
	}
	if info, err := os.Stat(cachePath); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("recovered SQLite cache is not a non-empty regular file: info=%v err=%v", info, err)
	}
	runCLI(ctx, t, moduleRoot, cliPath,
		"verify", "--config", configPath, "--root", repositoryRoot,
		"--layer", "L1", "--view", "beta,latest", "--repo", "assets-bin")

	readme, err := os.ReadFile(filepath.Join(moduleRoot, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"### 无云凭据的最小可用闭环",
		`mkdir -p "$DEMO_ROOT/bin"`,
		"--layer L1 --view beta --repo assets-bin",
		"--repo assets-bin --target export/latest",
		"fsck --recover",
		"gc --config",
		"发行归档的强制 clean-room 门禁",
		"`L2`–`L4` 需要匹配的已配置",
	} {
		if !bytes.Contains(readme, []byte(required)) {
			t.Fatalf("README clean-room contract omitted %q", required)
		}
	}

	// Exercise the documented inputless asset recovery with the production
	// binary and a real SIGKILL, not an in-process fault hook. A sufficiently
	// wide selected set keeps the post-intent materialization window open long
	// enough to stop the child immediately after its durable fence appears.
	const recoveryFiles = 1024
	recoveryInputRoot := filepath.Join(work, "recovery-input")
	if err := os.Mkdir(recoveryInputRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	recoveryArguments := []string{"add"}
	var recoverySampleName string
	var recoverySampleBody []byte
	for index := 0; index < recoveryFiles; index++ {
		name := fmt.Sprintf("recovery-%04d.bin", index)
		body := []byte(fmt.Sprintf("durable recovery asset %04d\n", index))
		path := filepath.Join(recoveryInputRoot, name)
		writeFile(t, path, body, 0o644)
		recoveryArguments = append(recoveryArguments, path)
		if index == recoveryFiles-1 {
			recoverySampleName = name
			recoverySampleBody = body
		}
	}
	recoveryArguments = append(recoveryArguments,
		"--config", configPath, "--root", repositoryRoot, "--repo", "assets-bin",
		"--workers", "4", "--chunk-entries", "128")

	var interruptedOutput bytes.Buffer
	interrupted := exec.CommandContext(ctx, cliPath, recoveryArguments...)
	interrupted.Dir = moduleRoot
	interrupted.Env = cleanRoomEnvironment
	interrupted.Stdout = &interruptedOutput
	interrupted.Stderr = &interruptedOutput
	if err := interrupted.Start(); err != nil {
		t.Fatal(err)
	}
	interruptedDone := make(chan error, 1)
	go func() { interruptedDone <- interrupted.Wait() }()
	intentPaths := []string{
		filepath.Join(repositoryRoot, ".sow", "asset-projection-intent.json"),
		filepath.Join(repositoryRoot, ".sow", "materialization-journal", "active.json"),
	}
	ticker := time.NewTicker(200 * time.Microsecond)
	defer ticker.Stop()
	killDeadline := time.NewTimer(90 * time.Second)
	defer killDeadline.Stop()
	interruptedAtFence := false
	for !interruptedAtFence {
		select {
		case err := <-interruptedDone:
			t.Fatalf("asset add exited before SIGKILL fence observation: %v\n%s", err, interruptedOutput.String())
		case <-killDeadline.C:
			_ = interrupted.Process.Kill()
			<-interruptedDone
			t.Fatalf("timed out observing durable asset recovery fence:\n%s", interruptedOutput.String())
		case <-ticker.C:
			for _, intentPath := range intentPaths {
				if _, err := os.Lstat(intentPath); err == nil {
					if err := syscall.Kill(interrupted.Process.Pid, syscall.SIGSTOP); err != nil {
						t.Fatalf("stop interrupted asset add: %v", err)
					}
					if err := interrupted.Process.Kill(); err != nil {
						t.Fatalf("SIGKILL interrupted asset add: %v", err)
					}
					if err := <-interruptedDone; err == nil {
						t.Fatal("SIGKILL asset add unexpectedly returned success")
					}
					interruptedAtFence = true
					break
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("inspect durable recovery fence %s: %v", intentPath, err)
				}
			}
		}
	}

	diagnostic := exec.CommandContext(ctx, cliPath,
		"fsck", "--config", configPath, "--root", repositoryRoot)
	diagnostic.Dir = moduleRoot
	diagnostic.Env = cleanRoomEnvironment
	diagnosticOutput, diagnosticErr := diagnostic.CombinedOutput()
	var diagnosticExit *exec.ExitError
	if !errors.As(diagnosticErr, &diagnosticExit) || !strings.Contains(strings.ToLower(string(diagnosticOutput)), "recover") {
		t.Fatalf("plain fsck did not diagnose interrupted recovery: err=%v\n%s", diagnosticErr, diagnosticOutput)
	}
	if err := os.RemoveAll(recoveryInputRoot); err != nil {
		t.Fatal(err)
	}
	recoveryOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"add", "--recover", "--config", configPath, "--root", repositoryRoot)
	if !strings.Contains(recoveryOutput, "recovered") || !strings.Contains(recoveryOutput, "asset") {
		t.Fatalf("inputless asset recovery omitted its receipt:\n%s", recoveryOutput)
	}
	runCLI(ctx, t, moduleRoot, cliPath,
		"verify", "--config", configPath, "--root", repositoryRoot,
		"--layer", "L1", "--view", "beta", "--repo", "assets-bin")
	runCLI(ctx, t, moduleRoot, cliPath,
		"fsck", "--config", configPath, "--root", repositoryRoot)

	recoveredSample, err := os.ReadFile(filepath.Join(repositoryRoot, ".sow", "materialized", "beta", "bin", recoverySampleName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recoveredSample, recoverySampleBody) {
		t.Fatalf("recovered asset=%q want=%q", recoveredSample, recoverySampleBody)
	}
	for _, residue := range intentPaths {
		if _, err := os.Lstat(residue); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovery residue remains at %s: %v", residue, err)
		}
	}
}

func assertCleanRoomPackageRepositories(t *testing.T, exportRoot string, debMetadata aptrepo.Package) string {
	t.Helper()
	aptRoot := filepath.Join(exportRoot, "apt", "pgsql", "trixie")
	binaryDirectory := "binary-" + debMetadata.Architecture
	packagesPath := filepath.Join(aptRoot, "dists", "trixie", "main", binaryDirectory, "Packages")
	packages, err := os.ReadFile(packagesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(packages, []byte("Package: "+debMetadata.Name+"\n")) ||
		!bytes.Contains(packages, []byte("Version: "+debMetadata.Version+"\n")) ||
		!bytes.Contains(packages, []byte("Architecture: "+debMetadata.Architecture+"\n")) {
		t.Fatalf("clean-room APT Packages omitted the added DEB:\n%s", packages)
	}
	for _, path := range []string{
		filepath.Join(aptRoot, "dists", "trixie", "Release"),
		filepath.Join(aptRoot, "dists", "trixie", "InRelease"),
		filepath.Join(aptRoot, filepath.FromSlash(debMetadata.PoolPath)),
	} {
		assertCleanRoomRegularFile(t, path, true)
	}
	byHash, err := filepath.Glob(filepath.Join(
		aptRoot, "dists", "trixie", "main", binaryDirectory, "by-hash", "SHA256", "*"))
	if err != nil || len(byHash) < 3 {
		t.Fatalf("clean-room APT by-hash closure has %d objects: %v", len(byHash), err)
	}

	generation := readStaticYUMGeneration(t, exportRoot, "latest", "pgsql-el9-x86-64", "el9", "x86_64")
	mirrorlistPath := filepath.Join(
		exportRoot, "_sow", "v1", "mirrorlist", "latest",
		"pgsql-el9-x86-64", "el9", "x86_64.txt",
	)
	mirrorlist, err := os.ReadFile(mirrorlistPath)
	if err != nil {
		t.Fatal(err)
	}
	wantMirrorlist := "https://repo.example.invalid/_sow/v1/g/" + generation + "/yum/pgsql/el9.x86_64/\n"
	if string(mirrorlist) != wantMirrorlist {
		t.Fatalf("clean-room YUM mirrorlist=%q want=%q", mirrorlist, wantMirrorlist)
	}
	yumRoot := filepath.Join(exportRoot, "_sow", "v1", "g", generation, "yum", "pgsql", "el9.x86_64")
	for _, path := range []string{
		filepath.Join(yumRoot, "repodata", "repomd.xml"),
		filepath.Join(yumRoot, "repodata", "repomd.xml.asc"),
		filepath.Join(yumRoot, "Packages", "p", rpmPackage+"-"+rpmVersionArch+".rpm"),
	} {
		assertCleanRoomRegularFile(t, path, true)
	}
	for _, kind := range []string{"primary", "filelists", "other"} {
		matches, err := filepath.Glob(filepath.Join(yumRoot, "repodata", "*-"+kind+".xml.zst"))
		if err != nil || len(matches) != 1 {
			t.Fatalf("clean-room YUM %s zstd metadata matches=%d err=%v", kind, len(matches), err)
		}
	}
	return generation
}

func assertCleanRoomPackageRemoval(
	t *testing.T,
	exportRoot string,
	previousYUMGeneration string,
	debMetadata aptrepo.Package,
) {
	t.Helper()
	packagesPath := filepath.Join(
		exportRoot,
		"apt",
		"pgsql",
		"trixie",
		"dists",
		"trixie",
		"main",
		"binary-"+debMetadata.Architecture,
		"Packages",
	)
	packages, err := os.ReadFile(packagesPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(packages, []byte("Package: "+debMetadata.Name+"\n")) {
		t.Fatalf("removed DEB remains in current clean-room APT index:\n%s", packages)
	}

	current := readStaticYUMGeneration(t, exportRoot, "latest", "pgsql-el9-x86-64", "el9", "x86_64")
	if current == previousYUMGeneration {
		t.Fatalf("clean-room YUM generation did not advance after package removal: %s", current)
	}
	packageRelative := filepath.Join("Packages", "p", rpmPackage+"-"+rpmVersionArch+".rpm")
	currentRoot := filepath.Join(exportRoot, "_sow", "v1", "g", current, "yum", "pgsql", "el9.x86_64")
	// SOW intentionally carries a removed payload through bounded successor
	// generations so a client holding old metadata can finish after a pointer
	// flip. The current primary index must not advertise it.
	assertCleanRoomRegularFile(t, filepath.Join(currentRoot, packageRelative), true)
	assertCleanRoomRegularFile(t, filepath.Join(currentRoot, "repodata", "repomd.xml"), true)
	assertCleanRoomRegularFile(t, filepath.Join(currentRoot, "repodata", "repomd.xml.asc"), true)
	primaryMatches, err := filepath.Glob(filepath.Join(currentRoot, "repodata", "*-primary.xml.zst"))
	if err != nil || len(primaryMatches) != 1 {
		t.Fatalf("current empty YUM primary matches=%d err=%v", len(primaryMatches), err)
	}
	primaryCompressed, err := os.ReadFile(primaryMatches[0])
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	primary, err := decoder.DecodeAll(primaryCompressed, nil)
	decoder.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(primary, []byte("<name>"+rpmPackage+"</name>")) ||
		!bytes.Contains(primary, []byte(`packages="0"`)) {
		t.Fatalf("removed RPM remains in current clean-room YUM primary:\n%s", primary)
	}

	previousRoot := filepath.Join(exportRoot, "_sow", "v1", "g", previousYUMGeneration, "yum", "pgsql", "el9.x86_64")
	assertCleanRoomRegularFile(t, filepath.Join(previousRoot, packageRelative), true)
}

func assertCleanRoomRegularFile(t *testing.T, path string, nonEmpty bool) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || (nonEmpty && info.Size() == 0) {
		t.Fatalf("required clean-room artifact %s is absent, unsafe, or empty: info=%v err=%v", path, info, err)
	}
}

type cleanRoomFileIdentity struct {
	path   string
	info   os.FileInfo
	sha256 [sha256.Size]byte
}

func captureCleanRoomFileIdentities(t *testing.T, paths ...string) []cleanRoomFileIdentity {
	t.Helper()
	identities := make([]cleanRoomFileIdentity, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("capture clean-room file identity %s: info=%v err=%v", path, info, err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("hash clean-room file identity %s: %v", path, err)
		}
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(info, after) || after.Size() != info.Size() || after.Mode() != info.Mode() || !after.ModTime().Equal(info.ModTime()) {
			t.Fatalf("clean-room file changed while capturing identity %s: before=%v after=%v err=%v", path, info, after, err)
		}
		identities = append(identities, cleanRoomFileIdentity{path: path, info: after, sha256: sha256.Sum256(body)})
	}
	return identities
}

func assertCleanRoomFileIdentities(t *testing.T, identities []cleanRoomFileIdentity) {
	t.Helper()
	for _, identity := range identities {
		current, err := os.Lstat(identity.path)
		if err != nil || !current.Mode().IsRegular() || !os.SameFile(identity.info, current) ||
			current.Size() != identity.info.Size() || current.Mode() != identity.info.Mode() ||
			!current.ModTime().Equal(identity.info.ModTime()) {
			t.Fatalf(
				"clean-room materialize replay changed canonical file identity or metadata %s: before=%v after=%v err=%v",
				identity.path,
				identity.info,
				current,
				err,
			)
		}
		body, err := os.ReadFile(identity.path)
		if err != nil || sha256.Sum256(body) != identity.sha256 {
			t.Fatalf("clean-room materialize replay changed canonical file bytes %s: err=%v", identity.path, err)
		}
		after, err := os.Lstat(identity.path)
		if err != nil || !os.SameFile(current, after) || after.Size() != current.Size() ||
			after.Mode() != current.Mode() || !after.ModTime().Equal(current.ModTime()) {
			t.Fatalf("clean-room file changed while verifying identity %s: before=%v after=%v err=%v", identity.path, current, after, err)
		}
	}
}

func cleanRoomSummaryField(t *testing.T, output, key string) string {
	t.Helper()
	prefix := key + "="
	for _, field := range strings.Fields(output) {
		if strings.HasPrefix(field, prefix) {
			value := strings.TrimPrefix(field, prefix)
			if value == "" {
				t.Fatalf("summary field %s is empty in:\n%s", key, output)
			}
			return value
		}
	}
	t.Fatalf("summary field %s is missing from:\n%s", key, output)
	return ""
}

func cleanRoomCanonicalHEAD(t *testing.T, root string) string {
	t.Helper()
	head, err := state.New(filepath.Join(root, ".sow")).HeadHash()
	if err != nil {
		t.Fatalf("read clean-room canonical HEAD: %v", err)
	}
	if head.IsZero() {
		t.Fatal("clean-room canonical HEAD is zero")
	}
	return head.String()
}

func assertCleanRoomHEAD(t *testing.T, root, want, operation string) {
	t.Helper()
	if got := cleanRoomCanonicalHEAD(t, root); got != want {
		t.Fatalf("%s changed canonical HEAD: got=%s want=%s", operation, got, want)
	}
}

func cleanRoomReplaceExactlyOnce(t *testing.T, body []byte, old, replacement string) []byte {
	t.Helper()
	if count := bytes.Count(body, []byte(old)); count != 1 {
		t.Fatalf("shipped example contains %d copies of %q, want exactly one", count, old)
	}
	return bytes.Replace(body, []byte(old), []byte(replacement), 1)
}

func cleanRoomSubprocessEnvironment(t *testing.T, work string) []string {
	t.Helper()
	home := filepath.Join(work, "subprocess-home")
	goPath := filepath.Join(work, "subprocess-gopath")
	goCache := filepath.Join(work, "subprocess-gocache")
	temp := filepath.Join(work, "subprocess-tmp")
	for _, directory := range []string{home, goPath, goCache, temp} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("create clean-room subprocess directory %s: %v", directory, err)
		}
	}

	goModCache := strings.TrimSpace(os.Getenv("GOMODCACHE"))
	if goModCache == "" {
		parentGoPath := strings.TrimSpace(os.Getenv("GOPATH"))
		if parentGoPath != "" {
			goModCache = filepath.Join(filepath.SplitList(parentGoPath)[0], "pkg", "mod")
		} else {
			parentHome, err := os.UserHomeDir()
			if err != nil {
				t.Fatalf("resolve existing Go module cache: %v", err)
			}
			goModCache = filepath.Join(parentHome, "go", "pkg", "mod")
		}
	}
	if !filepath.IsAbs(goModCache) {
		t.Fatalf("clean-room GOMODCACHE must be absolute: %s", goModCache)
	}

	goProxy := strings.TrimSpace(os.Getenv("GOPROXY"))
	if goProxy == "" {
		goProxy = "https://proxy.golang.org,direct"
	}
	goSumDB := strings.TrimSpace(os.Getenv("GOSUMDB"))
	if goSumDB == "" {
		goSumDB = "sum.golang.org"
	}
	environment := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GOPATH=" + goPath,
		"GOMODCACHE=" + goModCache,
		"GOCACHE=" + goCache,
		"TMPDIR=" + temp,
		"GOENV=off",
		"GOWORK=off",
		"GOTOOLCHAIN=local",
		"GOFLAGS=-mod=readonly",
		"CGO_ENABLED=0",
		"GOPRIVATE=",
		"GONOPROXY=",
		"GONOSUMDB=",
		"GOPROXY=" + goProxy,
		"GOSUMDB=" + goSumDB,
		"LANG=C",
		"LC_ALL=C",
		"AWS_CONFIG_FILE=/dev/null",
		"AWS_SHARED_CREDENTIALS_FILE=/dev/null",
		"AWS_EC2_METADATA_DISABLED=true",
	}
	for _, name := range []string{
		"SOW_RUN_APT_LEGACY_COMPAT",
		"SOW_RUN_AUTHORIZED_CF_RAW_PREFLIGHT_NEGATIVE",
		"SOW_RUN_DOCKER_COMPAT",
		"SOW_RUN_PERF",
		"SOW_RUN_PIGSTY_PACKAGE_TRUST",
		"SOW_RUN_PIGSTY_ROOT_BOTH_HANDOFF",
		"SOW_RUN_PIGSTY_ROOT_COS_HANDOFF",
		"SOW_RUN_REAL_CLOUD",
		"SOW_RUN_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP",
		"SOW_RUN_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_PLAN_ONBOARDING",
		"SOW_RUN_REAL_CLOUD_CLOUDFLARE_BOOTSTRAP_REGISTRY_ONBOARDING",
		"SOW_RUN_REAL_CLOUD_PROVIDER_READINESS",
		"SOW_RUN_REAL_CLOUD_PROVIDER_READINESS_REGISTRY_ONBOARDING",
		"SOW_RUN_REAL_CLOUD_R2_FSCK",
		"SOW_RUN_REAL_CLOUD_R2_PUBLICATION_STORAGE",
		"SOW_RUN_REAL_CLOUD_R2_STORAGE",
		"SOW_RUN_REAL_CLOUD_REGISTRY_ONBOARDING",
		"SOW_RUN_REAL_EDGE_EVIDENCE",
		"SOW_RUN_REAL_UPSTREAM",
		"SOW_REAL_CLOUD_PURGE_WATCHER_HELPER",
		"SOW_COMPAT_NGINX",
		"SOW_MINIO_TEST",
	} {
		environment = append(environment, name+"=0")
	}
	return environment
}

func buildCleanRoomCLI(
	ctx context.Context,
	t *testing.T,
	moduleRoot string,
	work string,
	environment []string,
) string {
	t.Helper()
	output := filepath.Join(work, "sow")
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", output, "./cmd/sow")
	command.Dir = moduleRoot
	command.Env = environment
	combined, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build production CLI in clean-room environment: %v\n%s", err, combined)
	}
	return output
}

func runCleanRoomCLI(
	ctx context.Context,
	t *testing.T,
	moduleRoot string,
	executable string,
	environment []string,
	arguments ...string,
) string {
	t.Helper()
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = moduleRoot
	command.Env = environment
	started := time.Now()
	output, err := command.CombinedOutput()
	elapsed := time.Since(started)
	t.Logf("sow %s elapsed=%s\n%s", strings.Join(arguments, " "), elapsed, output)
	if len(arguments) != 0 && arguments[0] == "add" && elapsed >= time.Minute {
		t.Fatalf("single-command add exceeded the PRD one-minute assumption: %s", elapsed)
	}
	if err != nil {
		t.Fatalf("sow %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}
