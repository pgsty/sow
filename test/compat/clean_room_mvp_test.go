package compat_test

import (
	"bytes"
	"context"
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
	verifyOutput := runCLI(ctx, t, moduleRoot, cliPath,
		"verify", "--config", configPath, "--root", repositoryRoot,
		"--layer", "L1", "--view", "beta", "--repo", "assets-bin")
	if !strings.Contains(verifyOutput, "verify outcome=passed") {
		t.Fatalf("local L1 verification did not pass:\n%s", verifyOutput)
	}
	runCLI(ctx, t, moduleRoot, cliPath,
		"promote", "beta", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin")
	runCLI(ctx, t, moduleRoot, cliPath,
		"materialize", "latest", "--config", configPath, "--root", repositoryRoot,
		"--repo", "assets-bin", "--target", "export/latest")
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

	readme, err := os.ReadFile(filepath.Join(moduleRoot, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"### 无云凭据的最小可用闭环",
		`mkdir -p "$DEMO_ROOT/bin"`,
		"--layer L1 --view beta --repo assets-bin",
		"--repo assets-bin --target export/latest",
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
