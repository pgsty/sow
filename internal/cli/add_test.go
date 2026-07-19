package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func TestAssetAddIsCASBackedMaterializedAndReplayable(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	input := filepath.Join(root, "tool.bin")
	if err := os.WriteFile(input, []byte("version-one"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(extra ...string) (int, string, string) {
		args := []string{input, "--config", configPath, "--repo", "asset", "--dest", "tool.bin", "--workers", "2", "--chunk-entries", "2"}
		args = append(args, extra...)
		var stdout, stderr bytes.Buffer
		err := runAdd(context.Background(), args, &stdout, &stderr)
		if err != nil {
			stderr.WriteString("sow: " + err.Error())
		}
		return exitCode(err), stdout.String(), stderr.String()
	}
	code, stdout, stderr := run()
	if code != ExitOK || !strings.Contains(stdout, "added repo=asset") {
		t.Fatalf("asset add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	ref, _ := state.ViewRef("beta", "asset", "all", "all")
	commit, exists, err := canonical.Ref(ref)
	if err != nil || !exists {
		t.Fatalf("beta ref=%s exists=%v err=%v", commit, exists, err)
	}
	viewPath, _ := state.ViewPath("beta", "asset", "all", "all")
	reader, err := canonical.OpenPathAt(commit, viewPath)
	if err != nil {
		t.Fatal(err)
	}
	viewReader := views.NewReader(reader)
	entry, err := viewReader.Next()
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := repository.ParseDigest(entry.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	poolInfo, err := os.Stat(pool.ObjectPath(digest))
	if err != nil {
		t.Fatal(err)
	}
	materializedPath := filepath.Join(root, ".sow", "materialized", "beta", "asset", "tool.bin")
	materializedInfo, err := os.Stat(materializedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(poolInfo, materializedInfo) {
		t.Fatal("asset beta tree is not a CAS hardlink")
	}
	code, stdout, stderr = run()
	if code != ExitOK || !strings.Contains(stdout, "add unchanged") {
		t.Fatalf("asset replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	var verifyOut, verifyErr bytes.Buffer
	if code := Main([]string{"verify", "--layer", "L1", "--view", "beta", "--config", configPath, "--repo", "asset", "--workers", "2", "--chunk-entries", "2"}, &verifyOut, &verifyErr); code != ExitOK || !strings.Contains(verifyOut.String(), "outcome=passed") {
		t.Fatalf("asset CLI verify code=%d stdout=%s stderr=%s", code, verifyOut.String(), verifyErr.String())
	}

	if err := os.WriteFile(input, []byte("version-two"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = run()
	if code != ExitConflict || !strings.Contains(stderr, "path conflict") {
		t.Fatalf("unexpected implicit replace code=%d stderr=%s", code, stderr)
	}
	code, stdout, stderr = run("--replace")
	if code != ExitOK || !strings.Contains(stdout, "replaced=1") {
		t.Fatalf("explicit replace code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	contents, err := os.ReadFile(materializedPath)
	if err != nil || string(contents) != "version-two" {
		t.Fatalf("replaced materialization=%q err=%v", contents, err)
	}

	immutableInput := filepath.Join(root, "immutable.bin")
	if err := os.WriteFile(immutableInput, []byte("immutable-one"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdoutBuffer, stderrBuffer := bytes.Buffer{}, bytes.Buffer{}
	immutableArgs := []string{"add", immutableInput, "--config", configPath, "--repo", "asset", "--dest", "immutable.bin", "--workers", "2"}
	if code := Main(immutableArgs, &stdoutBuffer, &stderrBuffer); code != ExitOK {
		t.Fatalf("initial immutable add code=%d stdout=%s stderr=%s", code, stdoutBuffer.String(), stderrBuffer.String())
	}
	if err := os.WriteFile(immutableInput, []byte("immutable-two"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdoutBuffer.Reset()
	stderrBuffer.Reset()
	if code := Main(append(immutableArgs, "--replace"), &stdoutBuffer, &stderrBuffer); code != ExitConflict || !strings.Contains(stderrBuffer.String(), "asset.mutable_paths") {
		t.Fatalf("immutable replace code=%d stdout=%s stderr=%s", code, stdoutBuffer.String(), stderrBuffer.String())
	}
}

func TestAssetLogicalPathRequiresEdgeSafeSegments(t *testing.T) {
	const relative = "releases/tool+debug_1.0~rc^2:amd64.tgz"
	if got, err := assetLogicalPath("pkg/tools", relative); err != nil || got != "pkg/tools/"+relative {
		t.Fatalf("edge-safe asset path=%q err=%v", got, err)
	}
	for _, value := range []string{
		"release bad/tool.tgz", "releases/tool@latest.tgz", "releases/工具.tgz",
		"releases/percent%.tgz", "releases/query?.tgz", "releases/fragment#.tgz",
	} {
		if _, err := assetLogicalPath("pkg/tools", value); err == nil || !strings.Contains(err.Error(), "unsafe asset destination") {
			t.Fatalf("non-routable asset destination %q accepted or misclassified: %v", value, err)
		}
	}
}

func TestAssetAddRejectsNonRoutableDestinationBeforeCASMutation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	casBefore := readMaterializationTree(t, filepath.Join(root, ".pool"))
	input := filepath.Join(root, "tool.bin")
	if err := os.WriteFile(input, []byte("route-safe asset"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := runAdd(context.Background(), []string{
		input, "--config", configPath, "--repo", "asset", "--dest", "releases/bad name.tgz",
	}, &stdout, &stderr)
	if exitCode(err) != ExitUsage || !strings.Contains(err.Error(), "not edge-routable") {
		t.Fatalf("non-routable add err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if casAfter := readMaterializationTree(t, filepath.Join(root, ".pool")); !reflect.DeepEqual(casBefore, casAfter) {
		t.Fatalf("invalid destination mutated initialized CAS: before=%v after=%v", casBefore, casAfter)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	ref, _ := state.ViewRef("beta", "asset", "all", "all")
	if _, exists, err := canonical.Ref(ref); err != nil || exists {
		t.Fatalf("invalid destination advanced beta ref exists=%v err=%v", exists, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", "materialized", "beta", "asset")); !os.IsNotExist(err) {
		t.Fatalf("invalid destination materialized an asset tree: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	const safeDestination = "releases/tool+debug_1.0~rc^2:amd64.tgz"
	err = runAdd(context.Background(), []string{
		input, "--config", configPath, "--repo", "asset", "--dest", safeDestination,
	}, &stdout, &stderr)
	if err != nil || !strings.Contains(stdout.String(), "added repo=asset") {
		t.Fatalf("edge-safe add err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", "materialized", "beta", "asset", filepath.FromSlash(safeDestination))); err != nil {
		t.Fatalf("edge-safe destination was not materialized: %v", err)
	}
}

func TestGatedAssetMutablePointerCanAdvanceInsideAppendOnlyStable(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(gatedAssetTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "input.bin")
	run := func(replace bool) (int, string, string) {
		args := []string{"add", input, "--config", configPath, "--repo", "private-assets", "--dest", "channel/tool.bin", "--workers", "2"}
		if replace {
			args = append(args, "--replace")
		}
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if err := os.WriteFile(input, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run(false); code != ExitOK || !strings.Contains(stdout, "view=stable") {
		t.Fatalf("initial gated add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.WriteFile(input, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run(true); code != ExitOK || !strings.Contains(stdout, "replaced=1") {
		t.Fatalf("gated mutable replacement code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	materialized := filepath.Join(root, ".sow", "origin", "gated", "assets", "private", "channel", "tool.bin")
	contents, err := os.ReadFile(materialized)
	if err != nil || string(contents) != "v2" {
		t.Fatalf("gated mutable materialization=%q err=%v", contents, err)
	}
}

func TestDefaultPoolCannotReclassifyHistoricalPublicEntry(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	publicConfig := strings.Replace(gatedAssetTestConfig, "default_pool: gated", "default_pool: public", 1)
	if err := os.WriteFile(configPath, []byte(publicConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(root, "first.bin")
	if err := os.WriteFile(first, []byte("public bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"add", first, "--config", configPath, "--repo", "private-assets", "--dest", "releases/first.bin"}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "view=beta") {
		t.Fatalf("seed public entry code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if err := os.WriteFile(configPath, []byte(gatedAssetTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(root, "second.bin")
	if err := os.WriteFile(second, []byte("gated bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"add", second, "--config", configPath, "--repo", "private-assets", "--dest", "releases/second.bin"}, &stdout, &stderr)
	if code != ExitConflict || !strings.Contains(stderr.String(), "default_pool is frozen as public") || !strings.Contains(stderr.String(), "use a new repo ID") {
		t.Fatalf("historical pool reclassification code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(root, ".sow", "origin", "gated", "assets", "private", "releases", "second.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected reclassification mutated gated origin: %v", err)
	}
}

func TestDebugPackagesRouteOnlyToStableView(t *testing.T) {
	public := config.Repo{DefaultPool: "public"}
	gated := config.Repo{DefaultPool: "gated"}
	if got := packageDestinationView(public, false); got != "beta" {
		t.Fatalf("ordinary public package routed to %s", got)
	}
	if got := packageDestinationView(public, true); got != "stable" {
		t.Fatalf("public debuginfo routed to %s", got)
	}
	if got := packageDestinationView(gated, false); got != "stable" {
		t.Fatalf("gated package routed to %s", got)
	}
	for _, name := range []string{"postgresql16-debuginfo", "postgresql16-debugsource"} {
		if !isDebugRPM(name) {
			t.Fatalf("RPM debuginfo name %s was not classified", name)
		}
	}
	for _, name := range []string{"postgresql-16-dbgsym", "libpq-dbg"} {
		if !isDebugDEB(name) {
			t.Fatalf("DEB debuginfo name %s was not classified", name)
		}
	}
}

const gatedAssetTestConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: private-assets
    type: asset
    path: assets/private
    default_pool: gated
    asset: {kind: private, mutable_paths: [channel/*.bin]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
