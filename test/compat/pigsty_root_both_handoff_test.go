package compat_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const pigstyRootBothHandoffOptInEnv = "SOW_RUN_PIGSTY_ROOT_BOTH_HANDOFF"

// TestPigstyRootBothBuilderHandoff converts the eight reviewed legacy .io/.cc
// scripts into four deterministic mirror-aware bodies outside the read-only
// source tree, then admits those exact bytes through the production SOW CLI.
func TestPigstyRootBothBuilderHandoff(t *testing.T) {
	if os.Getenv(pigstyRootBothHandoffOptInEnv) != "1" {
		t.Skip("set SOW_RUN_PIGSTY_ROOT_BOTH_HANDOFF=1 with SOW_PIGSTY_REPO_ROOT pointing at a read-only Pigsty repository")
	}
	sourceRoot := requirePigstyRootCOSHandoffSource(t, os.Getenv(pigstyRootCOSHandoffSource))
	sourceNames := []string{"beta.cc", "beta.io", "get.cc", "get.io", "pig.cc", "pig.io", "pkg.cc", "pkg.io"}
	sourceBodies := make(map[string][]byte, len(sourceNames))
	for _, name := range sourceNames {
		sourceBodies[name] = readStablePigstyRootAsset(t, filepath.Join(sourceRoot, "bin", name))
	}

	work := pigstyRootCOSWorkerTempDir(t)
	assertCanonicalRootBuilderSeparatesSourceAndOutput(t, work, sourceBodies)
	firstOutput := filepath.Join(work, "canonical-a")
	secondOutput := filepath.Join(work, "canonical-b")
	firstReceipt := runPigstyCanonicalRootBuilder(t, sourceRoot, firstOutput)
	secondReceipt := runPigstyCanonicalRootBuilder(t, sourceRoot, secondOutput)
	if firstReceipt != secondReceipt || !strings.Contains(firstReceipt, "CANONICAL_ROOT_ASSET kind=get") {
		t.Fatalf("canonical builder receipt was not deterministic:\nfirst:\n%s\nsecond:\n%s", firstReceipt, secondReceipt)
	}

	type artifact struct {
		destination string
		body        []byte
		digest      [sha256.Size]byte
	}
	artifacts := make([]artifact, 0, 4)
	for _, destination := range []string{"beta", "get", "pig", "pkg"} {
		first := readStablePigstyRootAsset(t, filepath.Join(firstOutput, destination))
		second := readStablePigstyRootAsset(t, filepath.Join(secondOutput, destination))
		if !bytes.Equal(first, second) {
			t.Fatalf("canonical %s differs across independent builds", destination)
		}
		for _, marker := range []string{
			"readonly ASSET_KIND='" + destination + "'",
			"https://repo.pigsty.io",
			"https://repo.pigsty.cc",
			"PIGSTY_REPO_URL",
			"PIGSTY_REPO_FALLBACK_URL",
		} {
			if !bytes.Contains(first, []byte(marker)) {
				t.Fatalf("canonical %s omitted mirror contract %q", destination, marker)
			}
		}
		if bytes.Contains(first, []byte("@ASSET_KIND@")) {
			t.Fatalf("canonical %s retained a template token", destination)
		}
		artifacts = append(artifacts, artifact{destination: destination, body: first, digest: sha256.Sum256(first)})
	}

	assertCanonicalRootMirrorRuntime(t, firstOutput)

	repositoryRoot := filepath.Join(work, "repository")
	if err := os.MkdirAll(filepath.Join(repositoryRoot, "assets", "root-both"), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(work, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(pigstyRootBothHandoffConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	runPigstyRootCOSHandoffCLI(t, "init", "--config", configPath, "--root", repositoryRoot, "--repo", "asset-root-both")
	for _, artifact := range artifacts {
		output := runPigstyRootCOSHandoffCLI(t,
			"add", filepath.Join(firstOutput, artifact.destination),
			"--config", configPath, "--root", repositoryRoot,
			"--repo", "asset-root-both", "--dest", artifact.destination,
			"--expected-object", fmt.Sprintf("sha256:%x:%d", artifact.digest, len(artifact.body)),
			"--workers", "2", "--chunk-entries", "2",
		)
		if !strings.Contains(output, "builder handoff verified inputs=1 receipt_sha256=") {
			t.Fatalf("%s add omitted digest-bound receipt:\n%s", artifact.destination, output)
		}
	}
	runPigstyRootCOSHandoffCLI(t, "promote", "beta", "latest", "--config", configPath, "--root", repositoryRoot, "--repo", "asset-root-both")
	runPigstyRootCOSHandoffCLI(t, "materialize", "latest", "--config", configPath, "--root", repositoryRoot, "--repo", "asset-root-both")

	exportRoot := filepath.Join(repositoryRoot, "assets", "root-both")
	for _, artifact := range artifacts {
		actual, err := os.ReadFile(filepath.Join(exportRoot, artifact.destination))
		if err != nil || !bytes.Equal(actual, artifact.body) {
			t.Fatalf("materialized canonical root key %s mismatch: %v", artifact.destination, err)
		}
	}
	assertPigstyRootCOSExportKeys(t, exportRoot, []string{"beta", "get", "pig", "pkg"})

	nginxInclude := filepath.Join(work, "root-both.locations.conf")
	runPigstyRootCOSHandoffCLI(t, "materialize", "latest", "--config", configPath, "--root", repositoryRoot, "--repo", "asset-root-both", "--nginx-include", nginxInclude)
	nginx, err := os.ReadFile(nginxInclude)
	if err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"beta", "get", "pig", "pkg"} {
		if !bytes.Contains(nginx, []byte("location = /"+destination+" ")) {
			t.Fatalf("Nginx include omitted exact root key %s", destination)
		}
	}
	if !bytes.Contains(nginx, []byte("location / { return 404; }")) {
		t.Fatal("Nginx include omitted default deny")
	}

	runPigstyRootCOSHandoffCLI(t, "verify", "--layer", "L1", "--view", "latest", "--config", configPath, "--root", repositoryRoot, "--repo", "asset-root-both")
	runPigstyRootCOSHandoffCLI(t, "fsck", "--config", configPath, "--root", repositoryRoot, "--repo", "asset-root-both")
	runPigstyRootCOSHandoffCLI(t, "gc", "--config", configPath, "--root", repositoryRoot)
	for _, artifact := range artifacts {
		output := runPigstyRootCOSHandoffCLI(t,
			"add", filepath.Join(firstOutput, artifact.destination),
			"--config", configPath, "--root", repositoryRoot,
			"--repo", "asset-root-both", "--dest", artifact.destination,
			"--expected-object", fmt.Sprintf("sha256:%x:%d", artifact.digest, len(artifact.body)),
		)
		if !strings.Contains(output, "add unchanged") || !strings.Contains(output, "builder handoff verified inputs=1") {
			t.Fatalf("%s canonical replay was not idempotent:\n%s", artifact.destination, output)
		}
	}
	for _, name := range sourceNames {
		if after := readStablePigstyRootAsset(t, filepath.Join(sourceRoot, "bin", name)); !bytes.Equal(after, sourceBodies[name]) {
			t.Fatalf("read-only source %s changed during canonical handoff", name)
		}
	}
	t.Logf("root_both_handoff files=4 bytes=%d source_read_only=true cloud=false", len(artifacts[0].body)+len(artifacts[1].body)+len(artifacts[2].body)+len(artifacts[3].body))
}

func assertCanonicalRootBuilderSeparatesSourceAndOutput(t *testing.T, work string, sourceBodies map[string][]byte) {
	t.Helper()
	sourceCopy := filepath.Join(work, "source-copy")
	if err := os.MkdirAll(filepath.Join(sourceCopy, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range sourceBodies {
		if err := os.WriteFile(filepath.Join(sourceCopy, "bin", name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	repositoryRoot, err := realEdgeRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	builder := filepath.Join(repositoryRoot, "docs", "migration", "build-canonical-root-assets.sh")
	assertRejected := func(output string) {
		t.Helper()
		command := exec.Command(builder, sourceCopy, output)
		command.Env = append(filteredCanonicalRootEnvironment(), "PATH="+os.Getenv("PATH"))
		body, runErr := command.CombinedOutput()
		if runErr == nil || !strings.Contains(string(body), "must not resolve inside the read-only source tree") {
			t.Fatalf("builder accepted output inside its source: err=%v\n%s", runErr, body)
		}
		if _, statErr := os.Lstat(filepath.Join(sourceCopy, "generated")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("rejected builder wrote inside its source: %v", statErr)
		}
	}
	assertRejected(filepath.Join(sourceCopy, "generated"))
	alias := filepath.Join(work, "source-alias")
	if err := os.Symlink(sourceCopy, alias); err != nil {
		t.Fatal(err)
	}
	assertRejected(filepath.Join(alias, "generated"))
}

func runPigstyCanonicalRootBuilder(t *testing.T, sourceRoot, outputRoot string) string {
	t.Helper()
	repositoryRoot, err := realEdgeRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(filepath.Join(repositoryRoot, "docs", "migration", "build-canonical-root-assets.sh"), sourceRoot, outputRoot)
	command.Env = append(filteredCanonicalRootEnvironment(), "PATH="+os.Getenv("PATH"))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("canonical root builder failed: %v\n%s", err, output)
	}
	return string(output)
}

func filteredCanonicalRootEnvironment() []string {
	blocked := map[string]struct{}{
		"PIGSTY_REPO_URL": {}, "PIGSTY_REGION": {}, "PATH": {}, "HOME": {}, "TMPDIR": {},
	}
	result := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, found := blocked[key]; !found {
			result = append(result, entry)
		}
	}
	return result
}

func assertCanonicalRootMirrorRuntime(t *testing.T, outputRoot string) {
	t.Helper()
	fixture := t.TempDir()
	bin := filepath.Join(fixture, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(fixture, "calls.log")
	writeExecutableFixture := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutableFixture("curl", `#!/bin/sh
out=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) out=$2; shift 2 ;;
    http*) url=$1; shift ;;
    *) shift ;;
  esac
done
printf 'curl %s\n' "$url" >>"$CANONICAL_FAKE_LOG"
case "$url" in
  *repo.pigsty.io*) [ "${CANONICAL_FAIL_GLOBAL:-0}" = 1 ] && exit 22 ;;
esac
printf 'fixture payload\n' >"$out"
`)
	writeExecutableFixture("tar", `#!/bin/sh
parent=
while [ "$#" -gt 0 ]; do
  if [ "$1" = -C ]; then parent=$2; shift 2; else shift; fi
done
mkdir -p "$parent/pigsty/bin"
printf '#!/bin/sh\nprintf "get-pkg %%s\\n" "$*" >>"$CANONICAL_FAKE_LOG"\n' >"$parent/pigsty/bin/get-pkg"
printf '#!/bin/sh\nprintf "bootstrap\\n" >>"$CANONICAL_FAKE_LOG"\n' >"$parent/pigsty/bootstrap"
chmod 700 "$parent/pigsty/bin/get-pkg" "$parent/pigsty/bootstrap"
`)
	writeExecutableFixture("uname", `#!/bin/sh
case "${1:-}" in -s) echo Linux ;; -m) echo x86_64 ;; *) echo Linux ;; esac
`)
	writeExecutableFixture("dpkg", `#!/bin/sh
printf 'dpkg %s\n' "$*" >>"$CANONICAL_FAKE_LOG"
`)
	writeExecutableFixture("sudo", `#!/bin/sh
printf 'sudo %s\n' "$*" >>"$CANONICAL_FAKE_LOG"
"$@"
`)
	writeExecutableFixture("ansible-playbook", "#!/bin/sh\nexit 0\n")

	runSequence := 0
	run := func(asset string, arguments []string, extra ...string) (string, error) {
		t.Helper()
		runSequence++
		home := filepath.Join(fixture, "home-"+asset+fmt.Sprint(runSequence))
		if err := os.Mkdir(home, 0o700); err != nil {
			t.Fatal(err)
		}
		downloads := filepath.Join(fixture, "downloads-"+asset+fmt.Sprint(runSequence))
		if err := os.Mkdir(downloads, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(logPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(filepath.Join(outputRoot, asset), arguments...)
		command.Env = append(filteredCanonicalRootEnvironment(),
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"HOME="+home,
			"TMPDIR="+downloads,
			"CANONICAL_FAKE_LOG="+logPath,
		)
		command.Env = append(command.Env, extra...)
		output, err := command.CombinedOutput()
		calls, readErr := os.ReadFile(logPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		return string(calls) + "\n" + string(output), err
	}

	calls, err := run("get", nil, "CANONICAL_FAIL_GLOBAL=1")
	if err != nil || !orderedCanonicalRootCalls(calls, "https://repo.pigsty.io/src/", "https://repo.pigsty.cc/src/") {
		t.Fatalf("global-to-China fallback failed: err=%v\n%s", err, calls)
	}
	calls, err = run("pkg", nil, "PIGSTY_REGION=cn")
	if err != nil || !strings.Contains(calls, "https://repo.pigsty.cc/src/") || strings.Contains(calls, "https://repo.pigsty.io/src/") || !strings.Contains(calls, "get-pkg -c") {
		t.Fatalf("China-first pkg behavior failed: err=%v\n%s", err, calls)
	}
	calls, err = run("pig", nil, "CANONICAL_FAIL_GLOBAL=1")
	if err != nil || !orderedCanonicalRootCalls(calls, "https://repo.pigsty.io/pkg/pig/", "https://repo.pigsty.cc/pkg/pig/") || !strings.Contains(calls, "dpkg -i ") || !strings.Contains(calls, "pig_1.5.1-1_amd64.deb") {
		t.Fatalf("pig mirror fallback/install behavior failed: err=%v\n%s", err, calls)
	}
	calls, err = run("beta", nil, "PIGSTY_REPO_URL=https://unreviewed.example.invalid")
	var exitErr *exec.ExitError
	if err == nil || !errors.As(err, &exitErr) || exitErr.ExitCode() != 64 || strings.Contains(calls, "curl ") {
		t.Fatalf("unreviewed mirror override was not rejected before download: err=%v\n%s", err, calls)
	}
	calls, err = run("get", []string{"../../escape"})
	exitErr = nil
	if err == nil || !errors.As(err, &exitErr) || exitErr.ExitCode() != 64 || strings.Contains(calls, "curl ") {
		t.Fatalf("unsafe version was not rejected before download: err=%v\n%s", err, calls)
	}
}

func orderedCanonicalRootCalls(body, first, second string) bool {
	firstIndex := strings.Index(body, first)
	secondIndex := strings.Index(body, second)
	return firstIndex >= 0 && secondIndex > firstIndex
}

const pigstyRootBothHandoffConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: asset-root-both
    type: asset
    path: assets/root-both
    default_pool: public
    asset:
      kind: bootstrap
      mutable_paths: [beta, get, pig, pkg]
      public_path: .
      root_keys: [beta, get, pig, pkg]
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
