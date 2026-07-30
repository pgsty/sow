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
)

// TestShippedExampleSupportsCleanRoomLocalMVP executes the documented
// credential-free path with the production binary and shipped configuration.
// It guards against a README that only parses while omitting required serving
// directories, selectors, or the local-vs-remote verification boundary.
func TestShippedExampleSupportsCleanRoomLocalMVP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	moduleRoot := findModuleRoot(t)
	work := hostableCompatTempDir(t)
	repositoryRoot := filepath.Join(work, "repository")
	for _, directory := range []string{
		repositoryRoot,
		filepath.Join(repositoryRoot, "bin"),
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
	configPath := filepath.Join(work, "sow.yaml")
	writeFile(t, configPath, example, 0o600)
	inputBody := []byte("sow local MVP\n")
	inputPath := filepath.Join(work, "sow-demo.bin")
	writeFile(t, inputPath, inputBody, 0o644)

	cliPath := buildCLI(ctx, t, moduleRoot, work)
	runCLI(ctx, t, moduleRoot, cliPath,
		"init", "--config", configPath, "--root", repositoryRoot)
	runCLI(ctx, t, moduleRoot, cliPath,
		"add", inputPath, "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin")
	addReplayOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"add", inputPath, "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin")
	if !strings.Contains(addReplayOutput, "add unchanged repo=assets-bin view=beta") {
		t.Fatalf("asset add replay was not idempotent:\n%s", addReplayOutput)
	}
	verifyOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"verify", "--config", configPath, "--root", repositoryRoot,
		"--layer", "L1", "--view", "beta", "--repo", "assets-bin")
	if !strings.Contains(verifyOutput, "verify outcome=passed") {
		t.Fatalf("local L1 verification did not pass:\n%s", verifyOutput)
	}
	runCLI(ctx, t, moduleRoot, cliPath,
		"promote", "beta", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin")
	promoteReplayOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"promote", "beta", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin")
	if !strings.Contains(promoteReplayOutput, "promote unchanged source=beta destination=latest") {
		t.Fatalf("promote replay was not idempotent:\n%s", promoteReplayOutput)
	}
	runCLI(ctx, t, moduleRoot, cliPath,
		"materialize", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin", "--target", "export/latest")
	materializeReplayOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"materialize", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin", "--target", "export/latest")
	if !strings.Contains(materializeReplayOutput, "route_receipt_changed=false") ||
		!strings.Contains(materializeReplayOutput, "existing=1") {
		t.Fatalf("materialize replay was not idempotent:\n%s", materializeReplayOutput)
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
	writeFile(t, configPath, bytes.Replace(example, []byte(defaultHistory), []byte(testHistory), 1), 0o600)
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
	rmReplayOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"rm", filepath.Base(inputPath), "--view", "latest",
		"--config", configPath, "--root", repositoryRoot, "--repo", "assets-bin")
	if !strings.Contains(rmReplayOutput, "rm unchanged view=latest") {
		t.Fatalf("asset rm replay was not idempotent:\n%s", rmReplayOutput)
	}
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
