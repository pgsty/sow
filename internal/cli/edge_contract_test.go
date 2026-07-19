package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func TestMaterializeEdgeContractConfigOnlyIsReadOnlyAndFailClosed(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(nginxCompatibilityConfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	render := func() (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main([]string{"materialize", "latest", "--config", configPath, "--edge-contract", "cf", "--workers", "1", "--chunk-entries", "2"}, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	firstCode, first, firstErr := render()
	secondCode, second, secondErr := render()
	if firstCode != ExitOK || secondCode != ExitOK || firstErr != "" || secondErr != "" {
		t.Fatalf("first=(%d,%q) second=(%d,%q)", firstCode, firstErr, secondCode, secondErr)
	}
	if first != second {
		t.Fatal("identical edge contract renders produced different stdout")
	}
	var contract config.EdgeDeploymentContract
	if err := json.Unmarshal([]byte(first), &contract); err != nil {
		t.Fatal(err)
	}
	compatibility := contract.Variables[config.EdgeRuntimeCompatibilityVariable]
	if !strings.Contains(compatibility, `"id":"infra-legacy-x86-64"`) || !strings.Contains(compatibility, `"root":"yum/infra/x86_64"`) ||
		!strings.Contains(compatibility, `"raw":[]`) || !strings.Contains(compatibility, `"active":[]`) {
		t.Fatalf("config-only compatibility admission=%s", compatibility)
	}
	if strings.Contains(contract.Variables[config.EdgeRuntimePublicPrefixesVariable], "yum/infra/x86_64") ||
		strings.Contains(contract.Variables[config.EdgeRuntimePublicKeysVariable], "trust/yum-compat") {
		t.Fatalf("config-only compatibility routes were admitted: %v", contract.Variables)
	}
	if _, err := os.Lstat(filepath.Join(root, ".sow")); !os.IsNotExist(err) {
		t.Fatalf("edge contract render created canonical state: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".pool")); !os.IsNotExist(err) {
		t.Fatalf("edge contract render created CAS: %v", err)
	}
}

func TestMaterializeEdgeContractRejectsUnsafeModesBeforeMutation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(nginxCompatibilityConfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{name: "unknown target", args: []string{"materialize", "latest", "--config", configPath, "--edge-contract", "missing"}, code: ExitConfig, want: "is not configured"},
		{name: "stable view", args: []string{"materialize", "stable", "--config", configPath, "--edge-contract", "cf"}, code: ExitUsage, want: "must be rendered from latest"},
		{name: "snapshot", args: []string{"materialize", "trixie-20260715", "--config", configPath, "--edge-contract", "cf"}, code: ExitUsage, want: "must be rendered from latest"},
		{name: "repo selector", args: []string{"materialize", "latest", "--config", configPath, "--edge-contract", "cf", "--repo", "infra-el9"}, code: ExitUsage, want: "full-target render-only mode"},
		{name: "os selector", args: []string{"materialize", "latest", "--config", configPath, "--edge-contract", "cf", "--os", "el9"}, code: ExitUsage, want: "full-target render-only mode"},
		{name: "arch selector", args: []string{"materialize", "latest", "--config", configPath, "--edge-contract", "cf", "--arch", "x86_64"}, code: ExitUsage, want: "full-target render-only mode"},
		{name: "export target", args: []string{"materialize", "latest", "--config", configPath, "--edge-contract", "cf", "--target", filepath.Join(root, "export")}, code: ExitUsage, want: "full-target render-only mode"},
		{name: "archive", args: []string{"materialize", "latest", "--config", configPath, "--edge-contract", "cf", "--tgz", "offline.tgz"}, code: ExitUsage, want: "full-target render-only mode"},
		{name: "recovery", args: []string{"materialize", "latest", "--config", configPath, "--edge-contract", "cf", "--recover"}, code: ExitUsage, want: "full-target render-only mode"},
		{name: "nginx renderer", args: []string{"materialize", "latest", "--config", configPath, "--edge-contract", "cf", "--nginx-include", "-"}, code: ExitUsage, want: "separate render-only modes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Main(test.args, &stdout, &stderr)
			if code != test.code || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("code=%d stdout=%s stderr=%s want code=%d fragment=%q", code, stdout.String(), stderr.String(), test.code, test.want)
			}
			if _, err := os.Lstat(filepath.Join(root, ".sow")); !os.IsNotExist(err) {
				t.Fatalf("rejected edge renderer created canonical state: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(root, ".pool")); !os.IsNotExist(err) {
				t.Fatalf("rejected edge renderer created CAS: %v", err)
			}
		})
	}
}

func TestEdgeReadAdmissionRejectsCanonicalGitAppearingMidRender(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(edgeSnapshotAdmissionConfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	created := false
	ctx := withNginxCompatibilityAdmissionHook(t.Context(), func(phase, _ string) error {
		if phase != "after-snapshot-admission" || created {
			return nil
		}
		created = true
		stage := filepath.Join(root, "appeared.txt")
		if err := os.WriteFile(stage, []byte("appeared\n"), 0o600); err != nil {
			return err
		}
		_, _, err := state.New(filepath.Join(root, ".sow")).InstallPaths(map[string]string{"proof/appeared.txt": stage}, "appeared during admission")
		return err
	})
	var stdout bytes.Buffer
	err = renderMaterializeEdgeContract(ctx, cfg, "cf", commonFlags{workers: 1, chunk: 2}, &stdout)
	if !created || err == nil || stdout.Len() != 0 || !strings.Contains(err.Error(), "Git metadata appeared") {
		t.Fatalf("created=%t stdout=%s err=%v", created, stdout.String(), err)
	}
}

func TestEdgeSnapshotAdmissionRetainsHistoricalOwnerAndValidatesRefManifest(t *testing.T) {
	for _, test := range []struct {
		name         string
		manifestMode string
		wantError    string
	}{
		{name: "valid EOL snapshot", manifestMode: "valid"},
		{name: "missing manifest", manifestMode: "missing", wantError: "manifest"},
		{name: "wrong manifest ownership", manifestMode: "wrong", wantError: "outside physical repository root"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "sow.yaml")
			if err := os.MkdirAll(filepath.Join(root, "asset", "eol"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, []byte(edgeSnapshotAdmissionConfigYAML), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if code := Main([]string{"init", "--config", configPath, "--workers", "1", "--chunk-entries", "2"}, &stdout, &stderr); code != ExitOK {
				t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			snapshotID := "eol-20260712"
			snapshotPath, err := state.SnapshotPath(snapshotID, "eol", "all", "all")
			if err != nil {
				t.Fatal(err)
			}
			commit, err := canonical.HeadHash()
			if err != nil {
				t.Fatal(err)
			}
			if test.manifestMode != "missing" {
				path := "asset/eol/tool.tgz"
				if test.manifestMode == "wrong" {
					path = "asset/sibling/tool.tgz"
				}
				var body bytes.Buffer
				if err := views.WriteEntry(&body, views.Entry{
					Repo: "eol", OS: "all", Arch: "all", Name: "tool", Version: "1", Path: path,
					Size: 1, SHA256: strings.Repeat("a", 64), Pool: "public",
				}); err != nil {
					t.Fatal(err)
				}
				stage := filepath.Join(root, "snapshot-stage.tsv")
				if err := os.WriteFile(stage, body.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
				var changed bool
				commit, changed, err = canonical.InstallPaths(map[string]string{snapshotPath: stage}, "test: immutable EOL snapshot")
				if err != nil || !changed {
					t.Fatalf("snapshot commit=%s changed=%t err=%v", commit, changed, err)
				}
			}
			ref, err := state.SnapshotRef(snapshotID, "eol", "all", "all")
			if err != nil {
				t.Fatal(err)
			}
			if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, commit, true); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(configPath, "")
			if err != nil {
				t.Fatal(err)
			}
			inactive := false
			cfg.Repos[0].Active = &inactive
			before := readMaterializationTree(t, root)
			snapshots, err := admittedEdgeSnapshots(cfg, "cf")
			after := readMaterializationTree(t, root)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("edge snapshot read admission mutated repository\nbefore=%v\nafter=%v", before, after)
			}
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("wanted %q, snapshots=%+v err=%v", test.wantError, snapshots, err)
				}
				return
			}
			if err != nil || len(snapshots) != 1 || snapshots[0].ID != snapshotID || len(snapshots[0].AssetRoots) != 1 || snapshots[0].AssetRoots[0] != "archive/eol" {
				t.Fatalf("historical snapshot admission=%+v err=%v", snapshots, err)
			}
			contract, err := cfg.EdgeDeployment("cf", config.EdgeCompatibilityAdmission{Snapshots: snapshots})
			if err != nil {
				t.Fatal(err)
			}
			if contract.Variables[config.EdgeRuntimePublicPrefixesVariable] != `[]` ||
				!strings.Contains(contract.Variables[config.EdgeRuntimeCompatibilityVariable], `"snapshots":[{"id":"eol-20260712","apt_roots":[],"yum_roots":[],"asset_roots":["archive/eol"],"asset_keys":[]}]`) {
				t.Fatalf("inactive current repo widened or historical snapshot vanished: %v", contract.Variables)
			}
		})
	}
}

const edgeSnapshotAdmissionConfigYAML = `schema: sow/v1
state: {}
gpg: {}
pools: {public: {}, gated: {}}
repos:
  - id: eol
    type: asset
    path: asset/eol
    default_pool: public
    asset: {kind: release, public_path: archive/eol}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false, repos: [eol]}
  latest: {access: public, allowed_pools: [public], append_only: false, repos: [eol]}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true, repos: [eol]}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.example.invalid", bucket: test-repo, credential: env://SOW_TEST_STORAGE}
    cdn: {kind: cloudflare, base_url: "https://repo.example.invalid", beta_base_url: "https://beta.example.invalid", zone_id: test-zone, credential: env://SOW_TEST_CDN}
edge: {token_verifier: provider://test}
`
