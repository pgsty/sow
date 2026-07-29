package compat_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestShippedExampleSupportsCleanRoomLocalMVP executes the documented
// credential-free path with the production binary and shipped configuration.
// It guards against a README that only parses while omitting required serving
// directories, selectors, or the local-vs-remote verification boundary.
func TestShippedExampleSupportsCleanRoomLocalMVP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
}
