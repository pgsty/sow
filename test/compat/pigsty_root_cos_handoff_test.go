package compat_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/cli"
)

const (
	pigstyRootCOSHandoffOptInEnv = "SOW_RUN_PIGSTY_ROOT_COS_HANDOFF"
	pigstyRootCOSHandoffSource   = "SOW_PIGSTY_REPO_ROOT"
)

// TestPigstyRootCOSBuilderHandoff proves the three unambiguous COS-only root
// assets on a read-only source tree. get.cc intentionally becomes the distinct
// /cc key; it is never selected as the shared /get canonical body. All SOW
// state, CAS, materialization and retries live under disposable directories.
func TestPigstyRootCOSBuilderHandoff(t *testing.T) {
	if os.Getenv(pigstyRootCOSHandoffOptInEnv) != "1" {
		t.Skip("set SOW_RUN_PIGSTY_ROOT_COS_HANDOFF=1 with a read-only Pigsty repository root")
	}
	sourceRoot := requirePigstyRootCOSHandoffSource(t, os.Getenv(pigstyRootCOSHandoffSource))
	sources := []struct {
		destination string
		path        string
		size        int
		sha256      string
	}{
		{destination: "cc", path: filepath.Join(sourceRoot, "bin", "get.cc"), size: 5893, sha256: "a275f2580dbbb6b21cbe228185093cf962919a085d321d2efbc17657269caca7"},
		{destination: "claude", path: filepath.Join(sourceRoot, "bin", "claude"), size: 9322, sha256: "5f8f3ac25a9cdf15fcb70fb41d70309fc59dde3f33e7c065f24497e94acfd946"},
		{destination: "ray", path: filepath.Join(sourceRoot, "bin", "ray"), size: 5560, sha256: "d3ff094e5c7d29db72fb792c6d52379043bacd68f32cf400eb0127cf355087ad"},
	}

	type artifact struct {
		destination string
		source      string
		body        []byte
		digest      [sha256.Size]byte
	}
	artifacts := make([]artifact, 0, len(sources))
	for _, source := range sources {
		body := readStablePigstyRootAsset(t, source.path)
		digest := sha256.Sum256(body)
		if len(body) != source.size || fmt.Sprintf("%x", digest) != source.sha256 {
			t.Fatalf("root asset %s drifted from the audited migration baseline: bytes=%d sha256=%x", source.path, len(body), digest)
		}
		artifacts = append(artifacts, artifact{destination: source.destination, source: source.path, body: body, digest: digest})
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].destination < artifacts[j].destination })

	work := pigstyRootCOSWorkerTempDir(t)
	repositoryRoot := filepath.Join(work, "repository")
	if err := os.MkdirAll(filepath.Join(repositoryRoot, "assets", "root-cos"), 0o755); err != nil {
		t.Fatal(err)
	}
	inputRoot := filepath.Join(work, "inputs")
	if err := os.Mkdir(inputRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(work, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(pigstyRootCOSHandoffConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	runPigstyRootCOSHandoffCLI(t, "init", "--config", configPath, "--root", repositoryRoot, "--repo", "asset-root-cos")
	for index := range artifacts {
		artifact := &artifacts[index]
		input := filepath.Join(inputRoot, artifact.destination)
		if err := os.WriteFile(input, artifact.body, 0o600); err != nil {
			t.Fatal(err)
		}
		output := runPigstyRootCOSHandoffCLI(t,
			"add", input, "--config", configPath, "--root", repositoryRoot,
			"--repo", "asset-root-cos", "--dest", artifact.destination,
			"--expected-object", fmt.Sprintf("sha256:%x:%d", artifact.digest, len(artifact.body)),
			"--workers", "2", "--chunk-entries", "2",
		)
		if !strings.Contains(output, "builder handoff verified inputs=1 receipt_sha256=") {
			t.Fatalf("%s add omitted digest-bound receipt:\n%s", artifact.destination, output)
		}
	}
	runPigstyRootCOSHandoffCLI(t, "promote", "beta", "latest", "--config", configPath, "--root", repositoryRoot, "--repo", "asset-root-cos")

	runPigstyRootCOSHandoffCLI(t, "materialize", "latest", "--config", configPath, "--root", repositoryRoot, "--repo", "asset-root-cos")
	exportPayloadRoot := filepath.Join(repositoryRoot, "assets", "root-cos")
	for _, artifact := range artifacts {
		actual, err := os.ReadFile(filepath.Join(exportPayloadRoot, artifact.destination))
		if err != nil || !bytes.Equal(actual, artifact.body) {
			t.Fatalf("exported root key %s differs from read-only source: err=%v", artifact.destination, err)
		}
	}
	assertPigstyRootCOSExportKeys(t, exportPayloadRoot, []string{"cc", "claude", "ray"})

	nginxInclude := filepath.Join(work, "root-cos.locations.conf")
	runPigstyRootCOSHandoffCLI(t, "materialize", "latest", "--config", configPath, "--root", repositoryRoot, "--repo", "asset-root-cos", "--nginx-include", nginxInclude)
	nginx, err := os.ReadFile(nginxInclude)
	if err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"cc", "claude", "ray"} {
		if !bytes.Contains(nginx, []byte("location = /"+destination+" ")) {
			t.Fatalf("Nginx include omitted exact root key %s", destination)
		}
	}
	if !bytes.Contains(nginx, []byte("location / { return 404; }")) {
		t.Fatal("Nginx include omitted default deny")
	}

	runPigstyRootCOSHandoffCLI(t, "verify", "--layer", "L1", "--view", "latest", "--config", configPath, "--root", repositoryRoot, "--repo", "asset-root-cos")
	runPigstyRootCOSHandoffCLI(t, "fsck", "--config", configPath, "--root", repositoryRoot, "--repo", "asset-root-cos")
	runPigstyRootCOSHandoffCLI(t, "gc", "--config", configPath, "--root", repositoryRoot)

	for _, artifact := range artifacts {
		input := filepath.Join(inputRoot, artifact.destination)
		output := runPigstyRootCOSHandoffCLI(t,
			"add", input, "--config", configPath, "--root", repositoryRoot,
			"--repo", "asset-root-cos", "--dest", artifact.destination,
			"--expected-object", fmt.Sprintf("sha256:%x:%d", artifact.digest, len(artifact.body)),
		)
		if !strings.Contains(output, "add unchanged") || !strings.Contains(output, "builder handoff verified inputs=1") {
			t.Fatalf("%s replay was not idempotent:\n%s", artifact.destination, output)
		}
		if after := readStablePigstyRootAsset(t, artifact.source); !bytes.Equal(after, artifact.body) {
			t.Fatalf("read-only Pigsty source %s changed during handoff", artifact.source)
		}
	}
	t.Logf("root_cos_handoff files=3 bytes=%d source_read_only=true cloud=false", len(artifacts[0].body)+len(artifacts[1].body)+len(artifacts[2].body))
}

func requirePigstyRootCOSHandoffSource(t *testing.T, raw string) string {
	t.Helper()
	if raw == "" || raw != strings.TrimSpace(raw) || !filepath.IsAbs(raw) || filepath.Clean(raw) != raw {
		t.Fatalf("%s must be one clean absolute directory", pigstyRootCOSHandoffSource)
	}
	info, err := os.Lstat(raw)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		t.Fatalf("%s is not a non-symlink directory: %v", pigstyRootCOSHandoffSource, err)
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil || resolved != raw {
		t.Fatalf("%s must already be its resolved path: resolved=%q err=%v", pigstyRootCOSHandoffSource, resolved, err)
	}
	return raw
}

func pigstyRootCOSWorkerTempDir(t *testing.T) string {
	t.Helper()
	base := "/private/tmp"
	if info, err := os.Lstat(base); err != nil || !info.IsDir() {
		base = "/tmp"
	}
	root, err := os.MkdirTemp(base, "sow-root-cos-handoff-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		_ = os.RemoveAll(root)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(root, 0o755)
		_ = os.RemoveAll(root)
	})
	return root
}

func readStablePigstyRootAsset(t *testing.T, filename string) []byte {
	t.Helper()
	before, err := os.Lstat(filename)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 1<<20 {
		t.Fatalf("root asset %s is not a bounded regular non-symlink file: %v", filename, err)
	}
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		t.Fatalf("root asset %s changed while opening: %v", filename, err)
	}
	body, readErr := io.ReadAll(io.LimitReader(file, 1<<20+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	current, pathErr := os.Lstat(filename)
	if readErr != nil || statErr != nil || closeErr != nil || pathErr != nil || len(body) > 1<<20 ||
		!os.SameFile(before, after) || !os.SameFile(before, current) || before.Size() != int64(len(body)) ||
		!before.ModTime().Equal(after.ModTime()) || current.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("root asset %s changed while reading: %v", filename, errors.Join(readErr, statErr, closeErr, pathErr))
	}
	return body
}

func runPigstyRootCOSHandoffCLI(t *testing.T, arguments ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := cli.Main(arguments, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("sow %s code=%d\nstdout:\n%s\nstderr:\n%s", strings.Join(arguments, " "), code, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func assertPigstyRootCOSExportKeys(t *testing.T, root string, wanted []string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var regular []string
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().IsRegular() {
			regular = append(regular, entry.Name())
		}
	}
	sort.Strings(regular)
	if !reflect.DeepEqual(regular, wanted) {
		t.Fatalf("exported root regular keys=%v want=%v", regular, wanted)
	}
}

const pigstyRootCOSHandoffConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: asset-root-cos
    type: asset
    path: assets/root-cos
    default_pool: public
    asset:
      kind: bootstrap
      mutable_paths: [cc, claude, ray]
      public_path: .
      root_keys: [cc, claude, ray]
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
