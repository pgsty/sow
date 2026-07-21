package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

const rootMappedAssetConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: bootstrap
    type: asset
    path: asset/bootstrap
    default_pool: public
    asset:
      kind: bootstrap
      public_path: .
      root_keys: [get, pkg]
      mutable_paths: [get, pkg]
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`

func TestRootMappedAssetProjectionAdmitsOnlyExactDeclaredKeys(t *testing.T) {
	repo := config.Repo{
		ID: "bootstrap", Type: "asset", Path: "asset/bootstrap",
		Asset: &config.AssetConfig{PublicPath: ".", RootKeys: []string{"get", "pkg"}},
	}
	for _, logical := range []string{"asset/bootstrap/get", "asset/bootstrap/pkg"} {
		if err := validateAssetProjectionPath(repo, logical); err != nil {
			t.Fatalf("declared exact key %q rejected: %v", logical, err)
		}
	}
	for _, logical := range []string{
		"asset/bootstrap/other",
		"asset/bootstrap/pkg/child",
		"asset/other/pkg",
	} {
		if err := validateAssetProjectionPath(repo, logical); err == nil {
			t.Fatalf("non-owned root projection %q accepted", logical)
		}
	}

	prefixed := repo
	prefixed.Asset = &config.AssetConfig{PublicPath: "pkg/bootstrap"}
	if err := validateAssetProjectionPath(prefixed, "asset/bootstrap/releases/tool.tgz"); err != nil {
		t.Fatalf("bounded public prefix rejected nested asset: %v", err)
	}
}

func TestRootMappedAssetAddRejectsBeforeCASMutation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(rootMappedAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset/bootstrap")
	casBefore := readMaterializationTree(t, filepath.Join(root, ".pool"))
	input := filepath.Join(root, "input.bin")
	if err := os.WriteFile(input, []byte("must not enter CAS"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := runAdd(context.Background(), []string{
		input, "--config", configPath, "--repo", "bootstrap", "--dest", "pkg/child",
	}, &stdout, &stderr)
	if exitCode(err) != ExitUsage || !strings.Contains(err.Error(), "one exact key") {
		t.Fatalf("root projection add code=%d stdout=%s stderr=%s err=%v", exitCode(err), stdout.String(), stderr.String(), err)
	}
	if casAfter := readMaterializationTree(t, filepath.Join(root, ".pool")); !reflect.DeepEqual(casBefore, casAfter) {
		t.Fatalf("invalid root projection mutated initialized CAS: before=%v after=%v", casBefore, casAfter)
	}
}

func TestRootMappedAssetScanRejectsUndeclaredPhysicalKey(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(rootMappedAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "asset", "bootstrap"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "asset", "bootstrap", "not-owned"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, exists := cfg.RepoByName("bootstrap")
	if !exists {
		t.Fatal("bootstrap repo missing")
	}
	destination := filepath.Join(root, "scan.tsv")
	_, err = scanRepoManifest(context.Background(), cfg, repo, destination, manifest.ScanOptions{
		Workers: 1, ChunkEntries: 1, TempDir: filepath.Join(root, ".sow", "tmp"),
	})
	if err == nil || !strings.Contains(err.Error(), "not declared by asset.root_keys") {
		t.Fatalf("undeclared physical root key accepted: %v", err)
	}
	if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
		t.Fatalf("rejected scan manifest was retained: %v", statErr)
	}
}

func TestRootMappedOfflineArchiveDestinationRejectsBeforeAnyMutation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(rootMappedAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset/bootstrap")
	input := filepath.Join(root, "seed.bin")
	if err := os.WriteFile(input, []byte("seed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(arguments ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "bootstrap", "--dest", "pkg"); code != ExitOK {
		t.Fatalf("seed add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "bootstrap"); code != ExitOK {
		t.Fatalf("seed promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	canonical := state.New(filepath.Join(root, ".sow"))
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	poolBefore := readMaterializationTree(t, filepath.Join(root, ".pool"))
	outputRoot := filepath.Join(root, ".sow", "materialized", "latest")
	outputBefore := readMaterializationTree(t, outputRoot)
	archivePath := filepath.Join(root, "offline", "bundle.tgz")

	code, stdout, stderr := run(
		"materialize", "latest", "--config", configPath,
		"--tgz", "offline/bundle.tgz", "--asset-repo", "bootstrap", "--asset-dest", "pkg/child",
	)
	if code != ExitUsage || !strings.Contains(stderr, "one exact key") || stdout != "" {
		t.Fatalf("invalid archive projection code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	headAfter, err := canonical.HeadHash()
	if err != nil || headAfter != headBefore {
		t.Fatalf("invalid archive projection changed canonical HEAD before=%s after=%s err=%v", headBefore, headAfter, err)
	}
	assertByteTreeEqual(t, "CAS", poolBefore, readMaterializationTree(t, filepath.Join(root, ".pool")))
	assertByteTreeEqual(t, "materialized output", outputBefore, readMaterializationTree(t, outputRoot))
	if _, err := os.Stat(archivePath); !os.IsNotExist(err) {
		t.Fatalf("invalid archive projection created tgz: %v", err)
	}
}

func TestInitRejectsUnsafeNonRootAssetPathWithoutCanonicalCommit(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "asset"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "asset", "bad name.bin"), []byte("unsafe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"init", "--config", configPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitVerification || !strings.Contains(stderr.String(), "not edge-routable") {
		t.Fatalf("unsafe init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	head, err := canonical.HeadHash()
	if err != nil || !head.IsZero() {
		t.Fatalf("unsafe init created a canonical commit head=%s err=%v", head, err)
	}
	if _, err := os.Stat(canonical.ManifestPath("asset")); !os.IsNotExist(err) {
		t.Fatalf("unsafe init retained a canonical manifest: %v", err)
	}
}

func TestFSCKReportsUnsafeNonRootAssetPathAsVerificationDrift(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset")
	canonical := state.New(filepath.Join(root, ".sow"))
	headBefore, err := canonical.HeadHash()
	if err != nil || headBefore.IsZero() {
		t.Fatalf("baseline head=%s err=%v", headBefore, err)
	}
	if err := os.WriteFile(filepath.Join(root, "asset", "bad name.bin"), []byte("unsafe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"fsck", "--config", configPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitVerification || !strings.Contains(stdout.String(), "kind=scan_error") || !strings.Contains(stderr.String(), "not edge-routable") {
		t.Fatalf("unsafe fsck code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	headAfter, err := canonical.HeadHash()
	if err != nil || headAfter != headBefore {
		t.Fatalf("unsafe fsck changed canonical HEAD before=%s after=%s err=%v", headBefore, headAfter, err)
	}
}

func TestForgedRootMappedAssetViewFailsMaterializeAndPublishBeforeNetwork(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	configText := strings.Replace(publishAssetConfig,
		"    path: pkg\n    default_pool: public\n    asset:\n      kind: release\n      mutable_paths: [latest]",
		"    path: asset/bootstrap\n    default_pool: public\n    asset:\n      kind: bootstrap\n      public_path: .\n      root_keys: [pkg]\n      mutable_paths: [pkg]", 1)
	if configText == publishAssetConfig {
		t.Fatal("root projection publish fixture replacement did not match")
	}
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset/bootstrap")
	input := filepath.Join(root, "seed.bin")
	if err := os.WriteFile(input, []byte("seed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(arguments ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "pkg"); code != ExitOK {
		t.Fatalf("seed add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	canonical := state.New(filepath.Join(root, ".sow"))
	viewRef, err := state.ViewRef("beta", "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	viewPath, err := state.ViewPath("beta", "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	before, exists, err := canonical.Ref(viewRef)
	if err != nil || !exists {
		t.Fatalf("beta ref exists=%v err=%v", exists, err)
	}
	reader, err := canonical.OpenPathAt(before, viewPath)
	if err != nil {
		t.Fatal(err)
	}
	entry, readErr := views.NewReader(reader).Next()
	if closeErr := reader.Close(); readErr != nil || closeErr != nil {
		t.Fatal(errors.Join(readErr, closeErr))
	}
	entry.Path = "asset/bootstrap/pkg/child"
	var forged bytes.Buffer
	if err := views.WriteEntry(&forged, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "forged-beta.tsv")
	if err := os.WriteFile(stage, forged.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	after, changed, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "inject invalid root asset view")
	if err != nil || !changed {
		t.Fatalf("inject forged view commit=%s changed=%v err=%v", after, changed, err)
	}
	if err := canonical.AdvanceRef(viewRef, before, after, false); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run("fsck", "--config", configPath, "--repo", "assets", "--workers", "1", "--chunk-entries", "1")
	if code != ExitVerification || !strings.Contains(stdout, "kind=canonical_asset_projection") {
		t.Fatalf("forged fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = run("verify", "--layer", "L1", "--view", "beta", "--config", configPath, "--repo", "assets", "--workers", "1", "--chunk-entries", "1")
	if code != ExitVerification || !strings.Contains(stdout, "VIEW_ASSET_PROJECTION_INVALID") {
		t.Fatalf("forged verify code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	code, stdout, stderr = run("materialize", "beta", "--config", configPath, "--repo", "assets", "--target", "export")
	if code != ExitVerification || !strings.Contains(stderr, "one exact key") {
		t.Fatalf("forged materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, "export")); !os.IsNotExist(err) {
		t.Fatalf("forged materialize created output: %v", err)
	}

	t.Setenv("SOW_TEST_R2", `{"access_key_id":"fake","secret_access_key":"fake"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"fake"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	code, stdout, stderr = run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets")
	if code != ExitVerification || !strings.Contains(stderr, "one exact key") {
		t.Fatalf("forged publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	remoteCalls := transport.puts + transport.copies + transport.deletes + transport.purges + transport.cdnGets + transport.listCalls + transport.objectGets + transport.headCalls
	transport.mutex.Unlock()
	if remoteCalls != 0 {
		t.Fatalf("forged canonical view reached provider transport calls=%d", remoteCalls)
	}
}

func TestPublicationClassifierRejectsInvalidRootMappedAssetPath(t *testing.T) {
	repo := config.Repo{
		ID: "bootstrap", Type: "asset", Path: "asset/bootstrap",
		Asset: &config.AssetConfig{Kind: "bootstrap", PublicPath: ".", RootKeys: []string{"pkg"}},
	}
	projection := publicationProjection{
		view: "beta", repo: repo, sourceRoot: ".sow/materialized/beta/asset/bootstrap",
		canonicalRoot: repo.Path, remoteRoot: repo.AssetPublicRoot(), legacyRoot: repo.Path,
	}
	classifier := publicationClassifier{view: "beta", projections: []publicationProjection{projection}}
	if _, _, err := classifier.classify(manifest.Entry{Path: projection.sourceRoot + "/pkg/child", Size: 1}); err == nil || !strings.Contains(err.Error(), "one exact key") {
		t.Fatalf("classifier accepted forged root path: %v", err)
	}
}

func TestAssetRemoveRejectsInvalidResidualViewBeforeCanonicalMutation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(rootMappedAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "asset/bootstrap")
	run := func(arguments ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	for _, key := range []string{"get", "pkg"} {
		input := filepath.Join(root, key+".bin")
		if err := os.WriteFile(input, []byte(key+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "bootstrap", "--dest", key); code != ExitOK {
			t.Fatalf("add %s code=%d stdout=%s stderr=%s", key, code, stdout, stderr)
		}
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	viewRef, _ := state.ViewRef("beta", "bootstrap", "all", "all")
	viewPath, _ := state.ViewPath("beta", "bootstrap", "all", "all")
	validCommit, exists, err := canonical.Ref(viewRef)
	if err != nil || !exists {
		t.Fatalf("beta ref exists=%v err=%v", exists, err)
	}
	reader, err := canonical.OpenPathAt(validCommit, viewPath)
	if err != nil {
		t.Fatal(err)
	}
	viewReader := views.NewReader(reader)
	var entries []views.Entry
	for {
		entry, nextErr := viewReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			reader.Close()
			t.Fatal(nextErr)
		}
		if entry.Path == "asset/bootstrap/pkg" {
			entry.Path = "asset/bootstrap/pkg/child"
		}
		entries = append(entries, entry)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	var forged bytes.Buffer
	for _, entry := range entries {
		if err := views.WriteEntry(&forged, entry); err != nil {
			t.Fatal(err)
		}
	}
	stage := filepath.Join(root, "forged-rm-beta.tsv")
	if err := os.WriteFile(stage, forged.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	forgedCommit, changed, err := canonical.InstallPaths(map[string]string{viewPath: stage}, "inject invalid residual asset view")
	if err != nil || !changed {
		t.Fatalf("inject forged removal view changed=%v err=%v", changed, err)
	}
	if err := canonical.AdvanceRef(viewRef, validCommit, forgedCommit, false); err != nil {
		t.Fatal(err)
	}
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	physicalBefore := readMaterializationTree(t, filepath.Join(root, "asset", "bootstrap"))
	materializedRoot := filepath.Join(root, ".sow", "materialized", "beta", "asset", "bootstrap")
	materializedBefore := readMaterializationTree(t, materializedRoot)
	code, stdout, stderr := run("rm", "get", "--view", "beta", "--config", configPath, "--repo", "bootstrap")
	if code != ExitVerification || !strings.Contains(stderr, "one exact key") {
		t.Fatalf("rm invalid residual code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	headAfter, err := canonical.HeadHash()
	if err != nil || headAfter != headBefore {
		t.Fatalf("rejected rm changed HEAD before=%s after=%s err=%v", headBefore, headAfter, err)
	}
	refAfter, exists, err := canonical.Ref(viewRef)
	if err != nil || !exists || refAfter != forgedCommit {
		t.Fatalf("rejected rm moved ref before=%s after=%s exists=%v err=%v", forgedCommit, refAfter, exists, err)
	}
	assertByteTreeEqual(t, "physical asset", physicalBefore, readMaterializationTree(t, filepath.Join(root, "asset", "bootstrap")))
	assertByteTreeEqual(t, "materialized asset", materializedBefore, readMaterializationTree(t, materializedRoot))
}

func assertByteTreeEqual(t *testing.T, label string, before, after map[string][]byte) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("%s tree changed entry count before=%d after=%d", label, len(before), len(after))
	}
	for name, want := range before {
		got, exists := after[name]
		if !exists || !bytes.Equal(got, want) {
			t.Fatalf("%s tree changed at %q exists=%v", label, name, exists)
		}
	}
}
