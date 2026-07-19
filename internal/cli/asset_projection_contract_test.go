package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

const assetProjectionTransitionConfig = `schema: sow/v1
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
    asset: {kind: bootstrap}
  - id: other
    type: asset
    path: asset/other
    default_pool: public
    asset: {kind: other}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`

func TestPopulatedAssetProjectionContractCannotChangeThroughUnrelatedSelector(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"asset/bootstrap", "asset/other"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "asset", "bootstrap", "pkg"), []byte("root bootstrap\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	changed := strings.Replace(assetProjectionTransitionConfig,
		"    asset: {kind: bootstrap}",
		"    asset: {kind: bootstrap, public_path: '.', root_keys: [pkg], mutable_paths: [pkg]}", 1)
	if err := os.WriteFile(configPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "explicit full re-projection migration") {
		t.Fatalf("unrelated selector accepted populated projection change: %v", err)
	}
}

func TestEmptyAssetProjectionContractCanBeDefinedBeforeFirstEntry(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"asset/bootstrap", "asset/other"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	changed := strings.Replace(assetProjectionTransitionConfig,
		"    asset: {kind: bootstrap}",
		"    asset: {kind: bootstrap, public_path: '.', root_keys: [pkg], mutable_paths: [pkg]}", 1)
	if err := os.WriteFile(configPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1}); err != nil {
		t.Fatalf("empty projection contract could not be defined: %v", err)
	}
}

func TestPopulatedAssetProjectionCannotBeDeactivated(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	deactivated := assetProjectionConfigWithBootstrapLines(t, "    active: false\n")
	if err := os.WriteFile(configPath, []byte(deactivated), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "active/path/include/exclude") {
		t.Fatalf("populated asset deactivation was accepted: %v", err)
	}
	headAfter, headErr := canonical.HeadHash()
	if headErr != nil || headAfter != headBefore {
		t.Fatalf("rejected asset deactivation changed canonical HEAD before=%s after=%s err=%v", headBefore, headAfter, headErr)
	}
}

func TestSameAssetProjectionContractCanonicalizesPatternSets(t *testing.T) {
	active := true
	left := config.Repo{
		ID: "bootstrap", Type: "asset", Path: "asset/bootstrap", Active: nil,
		Include: []string{"README", "pkg/**"}, Exclude: []string{"pkg/private/**", "tmp/**"},
		Asset: &config.AssetConfig{Kind: "bootstrap"},
	}
	right := left
	right.Active = &active
	right.Include = []string{"pkg/**", "README"}
	right.Exclude = []string{"tmp/**", "pkg/private/**"}
	if !sameAssetProjectionContract(left, right) {
		t.Fatal("equivalent reordered include/exclude sets changed asset projection contract")
	}
	right.Exclude = []string{"tmp/**"}
	if sameAssetProjectionContract(left, right) {
		t.Fatal("different exclude set did not change asset projection contract")
	}
}

func TestHistoricalEmptyAssetManifestDoesNotFreezeTemporaryContractChanges(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"asset/bootstrap", "asset/other"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	changedContract := strings.Replace(assetProjectionTransitionConfig,
		"    asset: {kind: bootstrap}",
		"    asset: {kind: bootstrap, public_path: '.', root_keys: [pkg], mutable_paths: [pkg]}", 1)
	canonical := state.New(filepath.Join(root, ".sow"))
	changedPath := filepath.Join(root, "empty-changed-sow.yaml")
	if err := os.WriteFile(changedPath, []byte(changedContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": changedPath}, "temporarily change empty asset contract"); err != nil || !changed {
		t.Fatalf("install empty contract change changed=%v err=%v", changed, err)
	}
	restoredPath := filepath.Join(root, "empty-restored-sow.yaml")
	if err := os.WriteFile(restoredPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": restoredPath}, "restore empty asset contract"); err != nil || !changed {
		t.Fatalf("restore empty contract changed=%v err=%v", changed, err)
	}
	if err := os.WriteFile(configPath, []byte(changedContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1}); err != nil {
		t.Fatalf("empty manifest history froze a never-populated contract: %v", err)
	}
}

func TestPopulatedAssetProjectionOwnerCannotBeRemoved(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	removed := assetProjectionConfigWithoutBootstrap(t)
	if err := os.WriteFile(configPath, []byte(removed), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "cannot be removed") || !strings.Contains(err.Error(), "explicit full re-projection migration") {
		t.Fatalf("populated asset removal was accepted: %v", err)
	}
	headAfter, headErr := canonical.HeadHash()
	if headErr != nil || headAfter != headBefore {
		t.Fatalf("rejected removal changed canonical HEAD before=%s after=%s err=%v", headBefore, headAfter, headErr)
	}
}

func TestPopulatedAssetProjectionCannotBeReintroducedAfterHistoricalRemoval(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	removedPath := filepath.Join(root, "removed-sow.yaml")
	if err := os.WriteFile(removedPath, []byte(assetProjectionConfigWithoutBootstrap(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": removedPath}, "simulate legacy unsafe asset removal"); err != nil || !changed {
		t.Fatalf("install historical removal changed=%v err=%v", changed, err)
	}
	if err := os.WriteFile(configPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"bootstrap"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "cannot be reintroduced") {
		t.Fatalf("historically removed asset repo was reintroduced: %v", err)
	}
	headAfter, headErr := canonical.HeadHash()
	if headErr != nil || headAfter != headBefore {
		t.Fatalf("rejected reintroduction changed canonical HEAD before=%s after=%s err=%v", headBefore, headAfter, headErr)
	}
}

func TestNewAssetIDCannotReuseHistoricalPhysicalRootWithZeroSourceDiff(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	manifestBefore, exists, err := canonical.FileIdentityAtHead("manifests/bootstrap.tsv")
	if err != nil || !exists || manifestBefore.Size == 0 {
		t.Fatalf("populated manifest identity=%#v exists=%v err=%v", manifestBefore, exists, err)
	}
	removedPath := filepath.Join(root, "removed-sow.yaml")
	if err := os.WriteFile(removedPath, []byte(assetProjectionConfigWithoutBootstrap(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": removedPath}, "simulate legacy unsafe asset removal before rename"); err != nil || !changed {
		t.Fatalf("install historical removal changed=%v err=%v", changed, err)
	}
	renamed := strings.Replace(assetProjectionTransitionConfig, "  - id: bootstrap\n", "  - id: bootstrap-v2\n", 1)
	if renamed == assetProjectionTransitionConfig {
		t.Fatal("asset rename fixture replacement did not match")
	}
	if err := os.WriteFile(configPath, []byte(renamed), 0o600); err != nil {
		t.Fatal(err)
	}
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"bootstrap-v2"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "cannot reuse physical asset root") || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("new asset ID reused historical physical root: %v", err)
	}
	headAfter, headErr := canonical.HeadHash()
	if headErr != nil || headAfter != headBefore {
		t.Fatalf("rejected physical-root reuse changed canonical HEAD before=%s after=%s err=%v", headBefore, headAfter, headErr)
	}
	manifestAfter, exists, err := canonical.FileIdentityAtHead("manifests/bootstrap.tsv")
	if err != nil || !exists || manifestAfter != manifestBefore {
		t.Fatalf("zero-diff source manifest changed before=%#v after=%#v exists=%v err=%v", manifestBefore, manifestAfter, exists, err)
	}
}

func TestHistoricalPopulatedProjectionDriftCannotHideBehindMatchingHead(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	changedContract := strings.Replace(assetProjectionTransitionConfig,
		"    asset: {kind: bootstrap}",
		"    asset: {kind: bootstrap, public_path: '.', root_keys: [pkg], mutable_paths: [pkg]}", 1)
	if changedContract == assetProjectionTransitionConfig {
		t.Fatal("asset projection fixture replacement did not match")
	}
	legacyPath := filepath.Join(root, "legacy-unsafe-sow.yaml")
	if err := os.WriteFile(legacyPath, []byte(changedContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, committed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": legacyPath}, "simulate legacy unsafe projection change"); err != nil || !committed {
		t.Fatalf("install legacy unsafe projection changed=%v err=%v", committed, err)
	}
	if err := os.WriteFile(configPath, []byte(changedContract), 0o600); err != nil {
		t.Fatal(err)
	}
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "canonical history contains incompatible populated asset contracts") {
		t.Fatalf("matching HEAD hid historical populated projection drift: %v", err)
	}
	headAfter, headErr := canonical.HeadHash()
	if headErr != nil || headAfter != headBefore {
		t.Fatalf("rejected historical drift changed canonical HEAD before=%s after=%s err=%v", headBefore, headAfter, headErr)
	}
}

func TestHistoricalAssetOwnershipFilterAndActiveDriftCannotHideBehindRestore(t *testing.T) {
	tests := []struct {
		name  string
		lines string
	}{
		{name: "include-exclude", lines: "    include: ['README', 'pkg/**']\n    exclude: ['pkg/private/**']\n"},
		{name: "inactive", lines: "    active: false\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, configPath := newPopulatedAssetProjectionFixture(t)
			canonical := state.New(filepath.Join(root, ".sow"))
			changedContract := assetProjectionConfigWithBootstrapLines(t, test.lines)
			changedPath := filepath.Join(root, "legacy-"+test.name+"-sow.yaml")
			if err := os.WriteFile(changedPath, []byte(changedContract), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, committed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": changedPath}, "simulate legacy unsafe asset "+test.name+" drift"); err != nil || !committed {
				t.Fatalf("install legacy %s drift changed=%v err=%v", test.name, committed, err)
			}
			restoredPath := filepath.Join(root, "restored-"+test.name+"-sow.yaml")
			if err := os.WriteFile(restoredPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, committed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": restoredPath}, "restore asset contract after "+test.name+" drift"); err != nil || !committed {
				t.Fatalf("restore legacy %s drift changed=%v err=%v", test.name, committed, err)
			}
			headBefore, err := canonical.HeadHash()
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
			if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "incompatible populated asset contracts") {
				t.Fatalf("restored HEAD hid historical %s drift: %v", test.name, err)
			}
			headAfter, headErr := canonical.HeadHash()
			if headErr != nil || headAfter != headBefore {
				t.Fatalf("rejected %s drift changed canonical HEAD before=%s after=%s err=%v", test.name, headBefore, headAfter, headErr)
			}
		})
	}
}

func TestOffHeadSOWRefAssetHistoryCannotHideOwnershipViolations(t *testing.T) {
	tests := []struct {
		name           string
		config         func(*testing.T) string
		want           string
		continuityWant string
	}{
		{
			name: "contract-drift",
			config: func(t *testing.T) string {
				return assetProjectionConfigWithBootstrapLines(t, "    include: ['pkg/**']\n")
			},
			want: "incompatible populated asset contracts",
		},
		{
			name:   "removal",
			config: assetProjectionConfigWithoutBootstrap,
			want:   "was removed",
		},
		{
			name: "physical-root-reuse",
			config: func(t *testing.T) string {
				changed := strings.Replace(assetProjectionTransitionConfig, "  - id: bootstrap\n", "  - id: bootstrap-v2\n", 1)
				if changed == assetProjectionTransitionConfig {
					t.Fatal("asset projection rename marker did not match")
				}
				return changed
			},
			want:           "was removed",
			continuityWant: "later reused",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, configPath := newPopulatedAssetProjectionFixture(t)
			canonical := state.New(filepath.Join(root, ".sow"))
			base, err := canonical.HeadHash()
			if err != nil {
				t.Fatal(err)
			}
			unsafe := commitAssetProjectionState(t, root, []plumbing.Hash{base}, time.Now().UTC().Add(-time.Hour), "off-HEAD asset "+test.name, map[string][]byte{
				"config/sow.yaml": []byte(test.config(t)),
			})
			safe := commitAssetProjectionState(t, root, []plumbing.Hash{base}, time.Now().UTC(), "restore safe HEAD beside "+test.name, map[string][]byte{
				"tests/off-head-" + test.name: []byte("safe\n"),
			})
			preserved := plumbing.ReferenceName("refs/sow/imported/asset-" + test.name)
			if err := canonical.AdvanceRef(preserved, plumbing.ZeroHash, unsafe, true); err != nil {
				t.Fatal(err)
			}
			if descendant, err := canonical.IsAncestor(unsafe, safe); err != nil || descendant {
				t.Fatalf("unsafe ref target remained on HEAD ancestry descendant=%v err=%v", descendant, err)
			}

			_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
			if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("off-HEAD refs/sow history hid %s: %v", test.name, err)
			}
			if test.continuityWant != "" {
				registry, registryErr := historicalAssetProjectionOwners(canonical)
				if registryErr != nil {
					t.Fatal(registryErr)
				}
				found := false
				for _, finding := range registry.continuity {
					found = found || strings.Contains(finding, test.continuityWant)
				}
				if !found {
					t.Fatalf("off-HEAD %s did not retain explicit continuity evidence %q: %v", test.name, test.continuityWant, registry.continuity)
				}
			}
			headAfter, headErr := canonical.HeadHash()
			if headErr != nil || headAfter != safe {
				t.Fatalf("rejected off-HEAD %s changed HEAD=%s want=%s err=%v", test.name, headAfter, safe, headErr)
			}
			refAfter, exists, refErr := canonical.Ref(preserved)
			if refErr != nil || !exists || refAfter != unsafe {
				t.Fatalf("rejected off-HEAD %s changed preservation ref=%s exists=%v err=%v", test.name, refAfter, exists, refErr)
			}
		})
	}
}

func TestHistoricalAssetRemovalAndReintroductionCannotHideBehindMatchingHead(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	removedPath := filepath.Join(root, "legacy-removed-sow.yaml")
	if err := os.WriteFile(removedPath, []byte(assetProjectionConfigWithoutBootstrap(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, committed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": removedPath}, "simulate legacy unsafe asset removal"); err != nil || !committed {
		t.Fatalf("install legacy removal changed=%v err=%v", committed, err)
	}
	reintroducedPath := filepath.Join(root, "legacy-reintroduced-sow.yaml")
	if err := os.WriteFile(reintroducedPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, committed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": reintroducedPath}, "simulate legacy unsafe asset reintroduction"); err != nil || !committed {
		t.Fatalf("install legacy reintroduction changed=%v err=%v", committed, err)
	}
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "was removed") || !strings.Contains(err.Error(), "later reintroduced") {
		t.Fatalf("matching HEAD hid historical asset removal/reintroduction: %v", err)
	}
	headAfter, headErr := canonical.HeadHash()
	if headErr != nil || headAfter != headBefore {
		t.Fatalf("rejected historical reintroduction changed canonical HEAD before=%s after=%s err=%v", headBefore, headAfter, headErr)
	}
}

func TestHistoricalAssetContractChangeWhileManifestEmptyCannotHide(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	changedContract := strings.Replace(assetProjectionTransitionConfig,
		"    asset: {kind: bootstrap}",
		"    asset: {kind: bootstrap, public_path: '.', root_keys: [pkg], mutable_paths: [pkg]}", 1)
	legacyPath := filepath.Join(root, "legacy-empty-changed-sow.yaml")
	emptyManifest := filepath.Join(root, "empty-bootstrap.tsv")
	if err := os.WriteFile(legacyPath, []byte(changedContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(emptyManifest, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, committed, err := canonical.InstallPaths(map[string]string{
		"config/sow.yaml":         legacyPath,
		"manifests/bootstrap.tsv": emptyManifest,
	}, "simulate legacy contract drift after manifest emptied"); err != nil || !committed {
		t.Fatalf("install empty-manifest contract drift changed=%v err=%v", committed, err)
	}
	restoredPath := filepath.Join(root, "legacy-restored-sow.yaml")
	if err := os.WriteFile(restoredPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, committed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": restoredPath}, "simulate legacy contract restoration"); err != nil || !committed {
		t.Fatalf("restore legacy contract changed=%v err=%v", committed, err)
	}
	_, _, err := loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "contract owned") || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("empty manifest hid historical contract drift: %v", err)
	}
}

func TestHistoricalAssetContinuityUsesAncestryAcrossClockSkewedMerge(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	base, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	changedContract := strings.Replace(assetProjectionTransitionConfig,
		"    asset: {kind: bootstrap}",
		"    asset: {kind: bootstrap, public_path: '.', root_keys: [pkg], mutable_paths: [pkg]}", 1)
	unsafe := commitAssetProjectionState(t, root, []plumbing.Hash{base}, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), "clock-skewed unsafe branch", map[string][]byte{
		"config/sow.yaml":         []byte(changedContract),
		"manifests/bootstrap.tsv": {},
	})
	safe := commitAssetProjectionState(t, root, []plumbing.Hash{base}, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), "safe branch", map[string][]byte{
		"tests/safe": []byte("safe\n"),
	})
	merge := commitAssetProjectionState(t, root, []plumbing.Hash{safe, unsafe}, time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), "merge safe tree", map[string][]byte{
		"tests/merge": []byte("merged\n"),
	})
	history, err := canonical.History()
	if err != nil {
		t.Fatal(err)
	}
	positions := make(map[plumbing.Hash]int, len(history))
	for index, commit := range history {
		positions[commit] = index
	}
	if positions[merge] != 0 || positions[base] >= positions[unsafe] {
		t.Fatalf("fixture did not expose committer-time/non-topological history: merge=%d base=%d unsafe=%d history=%v", positions[merge], positions[base], positions[unsafe], history)
	}

	_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "contract owned") || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("clock-skewed merge hid descendant asset contract drift: %v", err)
	}
}

func TestHistoricalAssetContinuityRejectsClockSkewedConfigDeletion(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	base, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	deleted := commitAssetProjectionState(t, root, []plumbing.Hash{base}, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), "clock-skewed config deletion", nil, "config/sow.yaml")
	safe := commitAssetProjectionState(t, root, []plumbing.Hash{base}, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), "safe branch", map[string][]byte{
		"tests/safe-config": []byte("safe\n"),
	})
	commitAssetProjectionState(t, root, []plumbing.Hash{safe, deleted}, time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), "merge after config deletion", map[string][]byte{
		"tests/merge-config": []byte("merged\n"),
	})

	_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "lost canonical config") {
		t.Fatalf("clock-skewed descendant config deletion did not fail closed: %v", err)
	}
}

func TestCurrentHeadAssetConfigDeletionFailsClosedForLoadAndGC(t *testing.T) {
	root, configPath, canonical, pool, orphan, confirm := confirmedAssetProjectionGCOrphan(t)
	parent, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	deleted := commitAssetProjectionState(t, root, []plumbing.Hash{parent}, time.Now().UTC(), "simulate deleted canonical config at HEAD", nil, "config/sow.yaml")
	if deleted.IsZero() || deleted == parent {
		t.Fatalf("config deletion did not advance HEAD parent=%s deleted=%s", parent, deleted)
	}

	_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "missing config/sow.yaml") {
		t.Fatalf("load accepted non-zero HEAD without canonical config: %v", err)
	}
	assertAssetProjectionGCRejectedWithoutMutation(t, configPath, canonical, pool, orphan, confirm, "missing config/sow.yaml")
}

func TestOffHeadOnlyAssetHistoryMissingConfigFailsClosed(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	commit, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	preserved := plumbing.ReferenceName("refs/sow/imported/asset-without-head")
	if err := canonical.AdvanceRef(preserved, plumbing.ZeroHash, commit, true); err != nil {
		t.Fatal(err)
	}
	repository, err := git.PlainOpen(filepath.Join(root, ".sow", "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.ReferenceName("refs/heads/unborn-import"))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, ".sow", "state", "config", "sow.yaml")); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	err = validateCanonicalAssetProjectionContracts(cfg)
	if err == nil || !strings.Contains(err.Error(), "preservation history is missing config/sow.yaml") {
		t.Fatalf("off-HEAD-only asset history bypassed missing canonical config: %v", err)
	}
	refAfter, exists, refErr := canonical.Ref(preserved)
	if refErr != nil || !exists || refAfter != commit {
		t.Fatalf("failed audit changed off-HEAD preservation ref=%s exists=%v err=%v", refAfter, exists, refErr)
	}
}

func TestGCRejectsRestoredHistoricalAssetDriftBeforeCASApply(t *testing.T) {
	root, configPath, canonical, pool, orphan, confirm := confirmedAssetProjectionGCOrphan(t)
	changedContract := assetProjectionConfigWithBootstrapLines(t, "    include: ['pkg/**']\n    exclude: ['pkg/private/**']\n")
	changedPath := filepath.Join(root, "legacy-gc-unsafe-sow.yaml")
	if err := os.WriteFile(changedPath, []byte(changedContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, committed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": changedPath}, "simulate legacy GC projection drift"); err != nil || !committed {
		t.Fatalf("install legacy GC drift changed=%v err=%v", committed, err)
	}
	restoredPath := filepath.Join(root, "legacy-gc-restored-sow.yaml")
	if err := os.WriteFile(restoredPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, committed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": restoredPath}, "restore config after legacy GC projection drift"); err != nil || !committed {
		t.Fatalf("restore legacy GC drift changed=%v err=%v", committed, err)
	}
	assertAssetProjectionGCRejectedWithoutMutation(t, configPath, canonical, pool, orphan, confirm, "incompatible populated asset contracts")
}

func TestCanonicalMutationBoundaryReauditsOffHeadAssetDriftAfterMatchingHeadRestore(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	baseline, err := readCanonicalConfigBaseline(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	setCanonicalConfigBaseline(cfg, baseline)
	canonical := state.New(filepath.Join(root, ".sow"))
	safeHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	changed := assetProjectionConfigWithBootstrapLines(t, "    include: ['pkg/**']\n")
	unsafe := commitAssetProjectionState(t, root, []plumbing.Hash{safeHead}, time.Now().UTC(), "unsafe drift while command waits for lock", map[string][]byte{
		"config/sow.yaml": []byte(changed),
	})
	resetAssetProjectionHead(t, root, safeHead)
	preserved := plumbing.ReferenceName("refs/sow/imported/asset-lock-window")
	if err := canonical.AdvanceRef(preserved, plumbing.ZeroHash, unsafe, true); err != nil {
		t.Fatal(err)
	}
	if restored, err := canonical.HeadHash(); err != nil || restored != safeHead {
		t.Fatalf("fixture did not restore exact pre-lock HEAD=%s want=%s err=%v", restored, safeHead, err)
	}
	identity, exists, err := canonical.FileIdentityAtHead("config/sow.yaml")
	if err != nil || !exists || identity.SHA256 != baseline.identity.SHA256 || identity.Size != baseline.identity.Size {
		t.Fatalf("fixture did not restore exact pre-lock config identity=%#v baseline=%#v exists=%v err=%v", identity, baseline.identity, exists, err)
	}

	lock, err := state.AcquireLock(cfg.StatePath(), "asset-contract-lock-window-test", false)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	err = requireCanonicalConfigBaseline(cfg, canonical)
	if err == nil || !strings.Contains(err.Error(), "incompatible populated asset contracts") {
		t.Fatalf("shared locked mutation boundary accepted off-HEAD drift behind matching HEAD/config: %v", err)
	}
}

func TestHistoricalAssetViewFreezesProjectionWhenManifestWasAlwaysEmpty(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"asset/bootstrap", "asset/other"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	viewPath, err := state.ViewPath("beta", "bootstrap", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	viewStage := filepath.Join(root, "legacy-view.tsv")
	writeAssetProjectionOwnershipLeaf(t, viewStage)
	canonical := state.New(filepath.Join(root, ".sow"))
	if _, committed, err := canonical.InstallPaths(map[string]string{viewPath: viewStage}, "simulate imported asset view without working manifest"); err != nil || !committed {
		t.Fatalf("install view-only ownership changed=%v err=%v", committed, err)
	}
	changedContract := strings.Replace(assetProjectionTransitionConfig,
		"    asset: {kind: bootstrap}",
		"    asset: {kind: bootstrap, public_path: '.', root_keys: [pkg], mutable_paths: [pkg]}", 1)
	legacyPath := filepath.Join(root, "legacy-view-changed-sow.yaml")
	if err := os.WriteFile(legacyPath, []byte(changedContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, committed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": legacyPath}, "simulate legacy view-owned projection drift"); err != nil || !committed {
		t.Fatalf("install view-owned projection drift changed=%v err=%v", committed, err)
	}
	if err := os.WriteFile(configPath, []byte(changedContract), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "incompatible populated asset contracts") || !strings.Contains(err.Error(), viewPath) {
		t.Fatalf("view-only ownership did not freeze asset projection: %v", err)
	}
}

func TestHistoricalAssetSnapshotFreezesProjectionWhenManifestWasAlwaysEmpty(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"asset/bootstrap", "asset/other"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	snapshotPath, err := state.SnapshotPath("snapshot-20260715", "bootstrap", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	snapshotStage := filepath.Join(root, "legacy-snapshot.tsv")
	writeAssetProjectionOwnershipLeaf(t, snapshotStage)
	canonical := state.New(filepath.Join(root, ".sow"))
	if _, committed, err := canonical.InstallPaths(map[string]string{snapshotPath: snapshotStage}, "simulate imported asset snapshot without working manifest"); err != nil || !committed {
		t.Fatalf("install snapshot-only ownership changed=%v err=%v", committed, err)
	}
	changedContract := strings.Replace(assetProjectionTransitionConfig,
		"    asset: {kind: bootstrap}",
		"    asset: {kind: bootstrap, public_path: '.', root_keys: [pkg], mutable_paths: [pkg]}", 1)
	legacyPath := filepath.Join(root, "legacy-snapshot-changed-sow.yaml")
	if err := os.WriteFile(legacyPath, []byte(changedContract), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, committed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": legacyPath}, "simulate legacy snapshot-owned projection drift"); err != nil || !committed {
		t.Fatalf("install snapshot-owned projection drift changed=%v err=%v", committed, err)
	}
	if err := os.WriteFile(configPath, []byte(changedContract), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = loadAndSelect(commonFlags{configPath: configPath, repos: csvFlag{items: []string{"other"}}, workers: 1, chunk: 1})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "incompatible populated asset contracts") || !strings.Contains(err.Error(), snapshotPath) {
		t.Fatalf("snapshot-only ownership did not freeze asset projection: %v", err)
	}
}

func TestAssetProjectionHistoryReadErrorFailsClosed(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	identity, exists, err := canonical.BlobIdentityAt(head, "manifests/bootstrap.tsv")
	if err != nil || !exists || identity.Hash.IsZero() {
		t.Fatalf("manifest identity=%#v exists=%v err=%v", identity, exists, err)
	}
	hash := identity.Hash.String()
	objectPath := filepath.Join(root, ".sow", "state", ".git", "objects", hash[:2], hash[2:])
	if err := os.Remove(objectPath); err != nil {
		t.Fatalf("remove historical blob object %s: %v", hash, err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	err = validateCanonicalAssetProjectionContracts(cfg)
	if err == nil || !strings.Contains(err.Error(), "audit historical asset projection ownership") {
		t.Fatalf("missing historical manifest blob did not fail closed: %v", err)
	}
}

func TestAssetProjectionHistorySymlinkFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name     string
		relative string
		target   func(t *testing.T, root, configPath string) string
	}{
		{
			name:     "config",
			relative: "config/sow.yaml",
			target:   func(_ *testing.T, _, configPath string) string { return configPath },
		},
		{
			name:     "manifest",
			relative: "manifests/bootstrap.tsv",
			target: func(t *testing.T, root, _ string) string {
				filename := filepath.Join(root, "external-bootstrap.tsv")
				if err := os.WriteFile(filename, []byte("symlink ownership bytes\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return filename
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, configPath := newPopulatedAssetProjectionFixture(t)
			canonical := state.New(filepath.Join(root, ".sow"))
			parent, err := canonical.HeadHash()
			if err != nil {
				t.Fatal(err)
			}
			commitAssetProjectionSymlink(t, root, parent, test.relative, test.target(t, root, configPath))
			cfg, err := config.Load(configPath, "")
			if err != nil {
				t.Fatal(err)
			}
			err = validateCanonicalAssetProjectionContracts(cfg)
			if err == nil || !strings.Contains(err.Error(), test.relative) || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("historical %s symlink did not fail closed: %v", test.relative, err)
			}
		})
	}
}

func TestAssetProjectionContractAuditDoesNotInflateLargeManifest(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"asset/bootstrap", "asset/other"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	const manifestSize = int64(32 << 20)
	largeManifest := filepath.Join(root, "large-invalid-manifest.tsv")
	file, err := os.OpenFile(largeManifest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	truncateErr := file.Truncate(manifestSize)
	closeErr := file.Close()
	if truncateErr != nil || closeErr != nil {
		t.Fatalf("create large manifest truncate=%v close=%v", truncateErr, closeErr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	if _, changed, err := canonical.InstallPaths(map[string]string{"manifests/bootstrap.tsv": largeManifest}, "install large identity-only asset manifest"); err != nil || !changed {
		t.Fatalf("install large manifest changed=%v err=%v", changed, err)
	}
	for index := 0; index < 8; index++ {
		marker := filepath.Join(root, fmt.Sprintf("history-marker-%02d", index))
		if err := os.WriteFile(marker, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("tests/history-%02d", index)
		if _, changed, err := canonical.InstallPaths(map[string]string{name: marker}, "extend large manifest history"); err != nil || !changed {
			t.Fatalf("install history marker %d changed=%v err=%v", index, changed, err)
		}
	}
	history, err := canonical.History()
	if err != nil || len(history) < 10 {
		t.Fatalf("large manifest history commits=%d err=%v", len(history), err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	err = validateCanonicalAssetProjectionContracts(cfg)
	elapsed := time.Since(started)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("identity-only audit parsed invalid manifest contents: %v", err)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("identity-only history audit allocated=%d elapsed=%s manifest=%d commits=%d", allocated, elapsed, manifestSize, len(history))
	if allocated >= uint64(manifestSize/2) {
		t.Fatalf("asset projection audit inflated large manifest: allocated=%d manifest=%d", allocated, manifestSize)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("asset projection history metadata audit took %s", elapsed)
	}
}

func confirmedAssetProjectionGCOrphan(t *testing.T) (string, string, *state.Store, *repository.Store, repository.Object, string) {
	t.Helper()
	root, configPath := newPopulatedAssetProjectionFixture(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := pool.Put(t.Context(), strings.NewReader("asset-projection-gc-orphan\n"))
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runGCTestCLI(t, "gc", "--config", configPath, "--limit", "0", "--workers", "1", "--chunk-entries", "1")
	if code != ExitOK {
		t.Fatalf("prepare confirmed GC plan code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	return root, configPath, canonical, pool, orphan, gcDigest(t, stdout, "gc_set_sha256")
}

func assertAssetProjectionGCRejectedWithoutMutation(t *testing.T, configPath string, canonical *state.Store, pool *repository.Store, orphan repository.Object, confirm, message string) {
	t.Helper()
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	objectPath := pool.ObjectPath(orphan.SHA256)
	objectBefore, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatalf("read GC orphan before rejection: %v", err)
	}
	code, stdout, stderr := runGCTestCLI(t, "gc", "--config", configPath, "--apply", "--confirm", confirm, "--limit", "0", "--workers", "1", "--chunk-entries", "1")
	if code != ExitConflict || !strings.Contains(stderr, message) {
		t.Fatalf("unsafe asset projection reached GC code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if stdout != "" {
		t.Fatalf("rejected GC emitted a CAS/serving plan: %s", stdout)
	}
	headAfter, headErr := canonical.HeadHash()
	if headErr != nil || headAfter != headBefore {
		t.Fatalf("rejected GC changed canonical HEAD before=%s after=%s err=%v", headBefore, headAfter, headErr)
	}
	objectAfter, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatalf("rejected GC removed its confirmed orphan: %v", err)
	}
	if !bytes.Equal(objectAfter, objectBefore) {
		t.Fatal("rejected GC changed its confirmed orphan bytes")
	}
}

func newPopulatedAssetProjectionFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(assetProjectionTransitionConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"asset/bootstrap", "asset/other"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(directory)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "asset", "bootstrap", "pkg"), []byte("root bootstrap\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	return root, configPath
}

func assetProjectionConfigWithBootstrapLines(t *testing.T, lines string) string {
	t.Helper()
	marker := "    default_pool: public\n    asset: {kind: bootstrap}"
	replacement := "    default_pool: public\n" + lines + "    asset: {kind: bootstrap}"
	changed := strings.Replace(assetProjectionTransitionConfig, marker, replacement, 1)
	if changed == assetProjectionTransitionConfig {
		t.Fatal("asset projection bootstrap marker did not match")
	}
	return changed
}

func assetProjectionConfigWithoutBootstrap(t *testing.T) string {
	t.Helper()
	start := strings.Index(assetProjectionTransitionConfig, "  - id: bootstrap\n")
	end := strings.Index(assetProjectionTransitionConfig, "  - id: other\n")
	if start < 0 || end <= start {
		t.Fatal("asset projection fixture repo boundaries not found")
	}
	return assetProjectionTransitionConfig[:start] + assetProjectionTransitionConfig[end:]
}

func writeAssetProjectionOwnershipLeaf(t *testing.T, filename string) {
	t.Helper()
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writeErr := views.WriteEntry(file, views.Entry{
		Repo: "bootstrap", OS: "all", Arch: "all", Name: "pkg", Version: "1",
		Path: "pkg", Size: 1, SHA256: strings.Repeat("a", 64), Pool: "public",
	})
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("write asset ownership leaf=%v close=%v", writeErr, closeErr)
	}
}

func commitAssetProjectionState(t *testing.T, root string, parents []plumbing.Hash, when time.Time, message string, files map[string][]byte, deleted ...string) plumbing.Hash {
	t.Helper()
	if len(parents) == 0 {
		t.Fatal("asset projection test commit requires a parent")
	}
	stateRoot := filepath.Join(root, ".sow", "state")
	repository, err := git.PlainOpen(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := worktree.Reset(&git.ResetOptions{Mode: git.HardReset, Commit: parents[0]}); err != nil {
		t.Fatal(err)
	}
	for relative, body := range files {
		filename := filepath.Join(stateRoot, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := worktree.Add(relative); err != nil {
			t.Fatal(err)
		}
	}
	for _, relative := range deleted {
		filename := filepath.Join(stateRoot, filepath.FromSlash(relative))
		if err := os.Remove(filename); err != nil {
			t.Fatal(err)
		}
		if _, err := worktree.Remove(relative); err != nil {
			t.Fatal(err)
		}
	}
	signature := &object.Signature{Name: "sow-test", Email: "sow-test@localhost", When: when}
	hash, err := worktree.Commit(message, &git.CommitOptions{Author: signature, Committer: signature, Parents: parents})
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func resetAssetProjectionHead(t *testing.T, root string, commit plumbing.Hash) {
	t.Helper()
	repository, err := git.PlainOpen(filepath.Join(root, ".sow", "state"))
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := worktree.Reset(&git.ResetOptions{Mode: git.HardReset, Commit: commit}); err != nil {
		t.Fatal(err)
	}
}

func commitAssetProjectionSymlink(t *testing.T, root string, parent plumbing.Hash, relative, target string) plumbing.Hash {
	t.Helper()
	stateRoot := filepath.Join(root, ".sow", "state")
	repository, err := git.PlainOpen(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := worktree.Reset(&git.ResetOptions{Mode: git.HardReset, Commit: parent}); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(stateRoot, filepath.FromSlash(relative))
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filename); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add(relative); err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC()
	signature := &object.Signature{Name: "sow-test", Email: "sow-test@localhost", When: when}
	hash, err := worktree.Commit("install corrupted canonical symlink", &git.CommitOptions{Author: signature, Committer: signature, Parents: []plumbing.Hash{parent}})
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
