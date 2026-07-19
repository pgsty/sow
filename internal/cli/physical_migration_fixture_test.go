package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/state"
)

func TestPhysicalMigrationCompatibilityCarrierIsNotCLISelectable(t *testing.T) {
	configPath := filepath.Join("..", "..", "docs", "migration", "fixtures", "pigsty-v1.yaml")
	values := commonFlags{
		configPath: configPath,
		// loadAndSelect performs read-only canonical continuity checks. Keep the
		// fixture source immutable and route any empty-state observation to an
		// isolated root so this test can never create docs/.../.sow.
		root:    t.TempDir(),
		repos:   csvFlag{items: []string{"yum-infra-legacy-compat"}},
		workers: 1,
		chunk:   1,
	}
	_, _, err := loadAndSelect(values)
	if exitCode(err) != ExitConfig || !strings.Contains(err.Error(), "selectors matched no active repositories") {
		t.Fatalf("inactive compatibility carrier was not rejected by CLI selection: %v", err)
	}

	values.repos = csvFlag{}
	_, selected, err := loadAndSelect(values)
	if err != nil {
		t.Fatalf("select active physical migration repositories: %v", err)
	}
	active := len(selected)
	for _, repo := range selected {
		if repo.ID == "yum-infra-legacy-compat" || repo.Asset != nil && repo.Asset.InventoryCarrier {
			t.Fatalf("inactive migration carrier leaked into default CLI selection: %s", repo.ID)
		}
	}
	values.includeCompatibilityCarriers = true
	values.includeAssetInventoryCarriers = true
	_, initialized, err := loadAndSelect(values)
	if err != nil {
		t.Fatalf("select init migration repositories: %v", err)
	}
	if len(initialized) != active+2 {
		t.Fatalf("init migration repositories=%d active=%d want two inactive carriers", len(initialized), active)
	}
	wantCarriers := map[string]bool{"yum-infra-legacy-compat": false, "asset-legacy-bin-inventory": false}
	for _, repo := range initialized {
		if _, exists := wantCarriers[repo.ID]; exists {
			wantCarriers[repo.ID] = true
		}
	}
	for id, found := range wantCarriers {
		if !found {
			t.Fatalf("init did not select inactive migration carrier %s", id)
		}
	}
}

func TestInitAndLocalFSCKOwnAssetInventoryCarrierWithoutAdoptingIt(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	configBody := `schema: sow/v1
state: {}
gpg: {}
pools: {public: {}, gated: {}}
repos:
  - id: public-assets
    type: asset
    path: public
    default_pool: public
    asset: {kind: release, public_path: public}
  - id: legacy-bin
    type: asset
    path: bin
    active: false
    exclude: [fileauth.txt]
    default_pool: public
    asset: {kind: inventory, public_path: migration/bin, inventory_carrier: true}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Join(root, "public"), filepath.Join(root, "bin")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	legacyPath := filepath.Join(root, "bin", "get.io")
	if err := os.WriteFile(legacyPath, []byte("legacy public script\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "fileauth.txt"), []byte("synthetic secret must stay outside canonical state\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	code, stdout, stderr := run("init", "--config", configPath, "--workers", "2", "--chunk-entries", "1")
	if code != ExitOK || !strings.Contains(stdout, "scanned repo=legacy-bin files=1") {
		t.Fatalf("inventory init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	manifestBody, err := os.ReadFile(state.New(filepath.Join(root, ".sow")).ManifestPath("legacy-bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(manifestBody, []byte("bin/get.io\t")) || bytes.Contains(manifestBody, []byte("fileauth")) || bytes.Contains(manifestBody, []byte("synthetic secret")) {
		t.Fatalf("inventory manifest crossed its reviewed exclusion boundary: %q", manifestBody)
	}

	code, stdout, stderr = run("init", "--adopt-content", "--config", configPath, "--repo", "legacy-bin", "--workers", "1", "--chunk-entries", "1")
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "cannot adopt an inventory carrier") {
		t.Fatalf("inventory adoption was not rejected before work code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = run("fsck", "--config", configPath, "--workers", "2", "--chunk-entries", "1")
	if code != ExitOK || !strings.Contains(stdout, "fsck clean") {
		t.Fatalf("clean inventory fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.WriteFile(legacyPath, []byte("drifted public script\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run("init", "--config", configPath, "--workers", "2", "--chunk-entries", "1")
	if code != ExitVerification || !strings.Contains(stderr, "differs from immutable baseline") {
		t.Fatalf("inventory drift reset its baseline code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	manifestAfterRejectedInit, err := os.ReadFile(state.New(filepath.Join(root, ".sow")).ManifestPath("legacy-bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifestBody, manifestAfterRejectedInit) {
		t.Fatalf("rejected inventory init changed the canonical baseline\nbefore=%q\nafter=%q", manifestBody, manifestAfterRejectedInit)
	}
	code, stdout, stderr = run("fsck", "--config", configPath, "--workers", "2", "--chunk-entries", "1")
	if code != ExitVerification || !strings.Contains(stdout, "fsck repo=legacy-bin") || !strings.Contains(stdout, "changed=1") {
		t.Fatalf("inventory drift escaped local fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}
