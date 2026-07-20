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
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

const packageRepositoryContractConfig = `schema: sow/v1
state: {}
gpg: {public_key: keys/repository.asc}
pools:
  public: {}
  gated: {}
repos:
  - id: apt-test
    type: apt
    path: apt/test
    default_pool: public
    active: true
    include: [pool/**]
    exclude: [pool/private/**]
    publish_targets: [cf, cos]
    arches: [amd64, arm64]
    os: {family: debian, major: 12, suite: bookworm, lifecycle: active}
    apt:
      suites: [bookworm, trixie]
      components: [main, contrib]
      suite_components: {bookworm: [main], trixie: [main, contrib]}
      suite_lifecycle: {bookworm: active, trixie: active}
  - id: yum-test
    type: yum
    path: yum/test/el9/{arch}
    default_pool: public
    arches: [x86_64, aarch64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: keys/rpm-a.asc, noarch_mode: replicate}
upstreams:
  - id: apt-source
    type: apt
    repo: apt-test
    url: https://upstream.example.invalid/debian
    suite: bookworm
    components: [main]
    arches: [amd64]
    allow: [pigsty-*]
    deny: [pigsty-secret-*]
    keyring: keys/upstream.asc
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`

type packageRepositoryContractFixture struct {
	root       string
	configPath string
	canonical  *state.Store
	cfg        *config.Config
	head       plumbing.Hash
}

func TestPackageRepositoryHistoryRejectsOversizedCanonicalConfig(t *testing.T) {
	fixture := newPackageRepositoryContractFixture(t, "manifests")
	commitPackageRepositoryState(t, fixture, "oversized historical config", map[string][]byte{
		"config/sow.yaml": bytes.Repeat([]byte{'#'}, config.MaxConfigBytes+1),
	})
	if _, err := loadReachablePackageRepositoryHistory(fixture.canonical); err == nil || !strings.Contains(err.Error(), "maximum 8388608") {
		t.Fatalf("oversized package history config error = %v", err)
	}
}

func TestPackageRepositoryContractFrozenFieldMatrix(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		allowed bool
	}{
		{name: "active-omitted-equals-true", allowed: true, mutate: func(cfg *config.Config) { cfg.Repos[0].Active = nil }},
		{name: "inactive", mutate: func(cfg *config.Config) { value := false; cfg.Repos[0].Active = &value }},
		{name: "path", mutate: func(cfg *config.Config) { cfg.Repos[0].Path = "apt/moved" }},
		{name: "default-pool", mutate: func(cfg *config.Config) { cfg.Repos[0].DefaultPool = "gated" }},
		{name: "include", mutate: func(cfg *config.Config) { cfg.Repos[0].Include = []string{"pool/**", "extra/**"} }},
		{name: "exclude", mutate: func(cfg *config.Config) { cfg.Repos[0].Exclude = nil }},
		{name: "os-family", mutate: func(cfg *config.Config) { cfg.Repos[0].OS.Family = "ubuntu" }},
		{name: "os-major", mutate: func(cfg *config.Config) { cfg.Repos[0].OS.Major = 13 }},
		{name: "os-suite", mutate: func(cfg *config.Config) { cfg.Repos[0].OS.Suite = "trixie" }},
		{name: "apt-arches", mutate: func(cfg *config.Config) { cfg.Repos[0].Arches = []string{"amd64"} }},
		{name: "apt-suites", mutate: func(cfg *config.Config) { cfg.Repos[0].APT.Suites = []string{"bookworm"} }},
		{name: "apt-suite-components", mutate: func(cfg *config.Config) { cfg.Repos[0].APT.SuiteComponents["bookworm"] = []string{"main", "contrib"} }},
		{name: "target-affinity", mutate: func(cfg *config.Config) { cfg.Repos[0].PublishTargets = []string{"cf"} }},
		{name: "yum-arches", mutate: func(cfg *config.Config) { cfg.Repos[1].Arches = []string{"x86_64"} }},
		{name: "yum-noarch", mutate: func(cfg *config.Config) {
			cfg.Repos[1].Arches = append(cfg.Repos[1].Arches, "noarch")
			cfg.Repos[1].YUM.NoarchMode = config.YUMNoarchSeparate
		}},
		{name: "yum-compression", mutate: func(cfg *config.Config) { cfg.Repos[1].YUM.Compression = "gzip" }},
		{name: "package-keyring-rotation", allowed: true, mutate: func(cfg *config.Config) { cfg.Repos[1].YUM.PackageKeyring = "keys/rpm-b.asc" }},
		{name: "lifecycle-forward", allowed: true, mutate: func(cfg *config.Config) {
			cfg.Repos[0].OS.Lifecycle = "frozen"
			cfg.Repos[0].APT.SuiteLifecycle["bookworm"] = "frozen"
			cfg.Repos[0].APT.SuiteLifecycle["trixie"] = "frozen"
			cfg.Repos[1].OS.Lifecycle = "frozen"
		}},
		{name: "upstream-filters", allowed: true, mutate: func(cfg *config.Config) {
			cfg.Upstreams[0].Allow = []string{"postgresql-*"}
			cfg.Upstreams[0].Deny = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPackageRepositoryContractFixture(t, "manifests")
			current := cloneRootedPackageConfig(t, fixture.cfg)
			test.mutate(current)
			err := validateCanonicalPackageRepositoryContracts(current)
			if test.allowed && err != nil {
				t.Fatalf("permitted package contract change rejected: %v", err)
			}
			if !test.allowed && (err == nil || !strings.Contains(err.Error(), "package repository")) {
				t.Fatalf("frozen package contract change accepted or misclassified: %v", err)
			}
		})
	}
}

func TestPackageRepositoryContractRejectsFrozenLifecycleReactivation(t *testing.T) {
	fixture := newPackageRepositoryContractFixture(t, "manifests")
	frozen := cloneRootedPackageConfig(t, fixture.cfg)
	frozen.Repos[0].OS.Lifecycle = "frozen"
	frozen.Repos[0].APT.SuiteLifecycle["bookworm"] = "frozen"
	frozen.Repos[0].APT.SuiteLifecycle["trixie"] = "frozen"
	body, err := frozen.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	commitPackageRepositoryState(t, fixture, "freeze package lifecycle", map[string][]byte{"config/sow.yaml": body})
	current := cloneRootedPackageConfig(t, fixture.cfg)
	if err := validateCanonicalPackageRepositoryContracts(current); err == nil || !strings.Contains(err.Error(), "lifecycle") {
		t.Fatalf("frozen lifecycle was reactivated: %v", err)
	}
}

func TestEmptyPackageRepositoryContractRemainsEditable(t *testing.T) {
	fixture := newPackageRepositoryContractFixture(t, "empty")
	current := cloneRootedPackageConfig(t, fixture.cfg)
	current.Repos[0].Path = "apt/renamed-before-population"
	current.Repos[0].DefaultPool = "gated"
	current.Repos[0].APT.Suites = []string{"sid"}
	current.Repos[0].APT.SuiteComponents = map[string][]string{"sid": {"main"}}
	current.Repos[0].APT.SuiteLifecycle = map[string]string{"sid": "active"}
	if err := validateCanonicalPackageRepositoryContracts(current); err != nil {
		t.Fatalf("empty package repository was frozen: %v", err)
	}
}

func TestPackageRepositoryOwnershipEvidenceFreezesManifestViewSnapshotAndGeneration(t *testing.T) {
	tests := []struct {
		name string
		kind string
	}{
		{name: "manifest", kind: "manifests"},
		{name: "view", kind: "view"},
		{name: "snapshot", kind: "snapshot"},
		{name: "yum-generation", kind: "generation"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPackageRepositoryContractFixture(t, test.kind)
			current := cloneRootedPackageConfig(t, fixture.cfg)
			if test.kind == "generation" {
				current.Repos[1].Path = "yum/moved/el9/{arch}"
			} else {
				current.Repos[0].Path = "apt/moved"
			}
			if err := validateCanonicalPackageRepositoryContracts(current); err == nil || !strings.Contains(err.Error(), testKindLocationFragment(test.kind)) {
				t.Fatalf("%s ownership did not freeze contract: %v", test.kind, err)
			}
		})
	}
}

func TestPackageRepositoryHistoricalDriftCannotHideBehindMatchingHead(t *testing.T) {
	fixture := newPackageRepositoryContractFixture(t, "manifests")
	unsafe := cloneRootedPackageConfig(t, fixture.cfg)
	unsafe.Repos[0].Include = []string{"pool/**", "legacy-drift/**"}
	body, err := unsafe.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	commitPackageRepositoryState(t, fixture, "legacy unsafe package drift", map[string][]byte{"config/sow.yaml": body})
	safeBody, _ := fixture.cfg.Canonical()
	commitPackageRepositoryState(t, fixture, "restore package contract", map[string][]byte{"config/sow.yaml": safeBody})
	if err := validateCanonicalPackageRepositoryContracts(fixture.cfg); err == nil || !strings.Contains(err.Error(), "historical") {
		t.Fatalf("matching HEAD hid package repository drift: %v", err)
	}
}

func TestPackageRepositoryDeleteReintroduceAndRootReuseAreRejected(t *testing.T) {
	tests := []struct {
		name      string
		reintroID string
		want      string
	}{
		{name: "same-id", reintroID: "apt-test", want: "reintroduced"},
		{name: "new-id-root-reuse", reintroID: "apt-v2", want: "root"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPackageRepositoryContractFixture(t, "manifests")
			removed := cloneRootedPackageConfig(t, fixture.cfg)
			removed.Repos = append([]config.Repo(nil), removed.Repos[1:]...)
			removed.Upstreams = nil
			removedBody, _ := removed.Canonical()
			commitPackageRepositoryState(t, fixture, "remove populated package repository", map[string][]byte{"config/sow.yaml": removedBody})
			reintroduced := cloneRootedPackageConfig(t, fixture.cfg)
			reintroduced.Repos[0].ID = test.reintroID
			if test.reintroID != "apt-test" {
				reintroduced.Upstreams = nil
			}
			reintroducedBody, _ := reintroduced.Canonical()
			commitPackageRepositoryState(t, fixture, "reintroduce package repository", map[string][]byte{"config/sow.yaml": reintroducedBody})
			if err := validateCanonicalPackageRepositoryContracts(reintroduced); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("package continuity violation accepted: %v", err)
			}
		})
	}
}

func TestPackageRepositoryTransientHistoricalRootReuseCannotDisappear(t *testing.T) {
	fixture := newPackageRepositoryContractFixture(t, "manifests")
	replacement := cloneRootedPackageConfig(t, fixture.cfg)
	replacement.Repos[0].ID = "apt-v2"
	replacement.Upstreams = nil
	replacementBody, err := replacement.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	commitPackageRepositoryState(t, fixture, "transiently transfer populated package root", map[string][]byte{"config/sow.yaml": replacementBody})
	removed := cloneRootedPackageConfig(t, fixture.cfg)
	removed.Repos = append([]config.Repo(nil), removed.Repos[1:]...)
	removed.Upstreams = nil
	removedBody, err := removed.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	commitPackageRepositoryState(t, fixture, "remove transient package root replacement", map[string][]byte{"config/sow.yaml": removedBody})
	if err := validateCanonicalPackageRepositoryContracts(removed); err == nil || !strings.Contains(err.Error(), "root") || !strings.Contains(err.Error(), "apt-v2") {
		t.Fatalf("transient historical root reuse disappeared behind later removal: %v", err)
	}
}

func TestPackageRepositoryHistoricalAPTAndYUMTypeMutationToAssetIsRejected(t *testing.T) {
	for _, test := range []struct {
		name  string
		index int
	}{
		{name: "apt-to-asset", index: 0},
		{name: "yum-to-asset", index: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPackageRepositoryContractFixture(t, "manifests")
			mutated := cloneRootedPackageConfig(t, fixture.cfg)
			repo := &mutated.Repos[test.index]
			repo.Type = "asset"
			repo.Path = "archive/" + repo.ID
			repo.OS = config.OSConfig{}
			repo.Arches = nil
			repo.APT = nil
			repo.YUM = nil
			repo.Asset = &config.AssetConfig{Kind: "legacy-package-archive"}
			mutated.Upstreams = nil
			body, err := mutated.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			commitPackageRepositoryState(t, fixture, "mutate populated package repository to asset", map[string][]byte{"config/sow.yaml": body})
			if err := validateCanonicalPackageRepositoryContracts(mutated); err == nil || !strings.Contains(err.Error(), "type") || !strings.Contains(err.Error(), "package repository") {
				t.Fatalf("historical %s mutation escaped package gate: %v", test.name, err)
			}
		})
	}
}

func TestPackageRepositoryOffHeadSOWRefAndMissingConfigFailClosed(t *testing.T) {
	tests := []struct {
		name         string
		deleteConfig bool
		want         string
	}{
		{name: "off-head-drift", want: "historical"},
		{name: "off-head-missing-config", deleteConfig: true, want: "missing config/sow.yaml"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPackageRepositoryContractFixture(t, "manifests")
			var offHead plumbing.Hash
			if test.deleteConfig {
				offHead = commitAssetProjectionState(t, fixture.root, []plumbing.Hash{fixture.head}, time.Now().Add(-24*time.Hour), "off-head config deletion", nil, "config/sow.yaml")
			} else {
				unsafe := cloneRootedPackageConfig(t, fixture.cfg)
				unsafe.Repos[0].Path = "apt/off-head-moved"
				body, _ := unsafe.Canonical()
				offHead = commitAssetProjectionState(t, fixture.root, []plumbing.Hash{fixture.head}, time.Now().Add(-24*time.Hour), "off-head package drift", map[string][]byte{"config/sow.yaml": body})
			}
			pinPackageRepositoryOffHead(t, fixture, offHead, "refs/sow/tests/off-head")
			if err := validateCanonicalPackageRepositoryContracts(fixture.cfg); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("off-HEAD package history escaped gate: %v", err)
			}
		})
	}
}

func TestPackageRepositoryLoadAndLockedMutationRevalidateHistory(t *testing.T) {
	fixture := newPackageRepositoryContractFixture(t, "manifests")
	unsafe := cloneRootedPackageConfig(t, fixture.cfg)
	unsafe.Repos[0].Exclude = nil
	body, _ := unsafe.Canonical()
	commitPackageRepositoryState(t, fixture, "unsafe historical package exclude drift", map[string][]byte{"config/sow.yaml": body})
	safeBody, _ := fixture.cfg.Canonical()
	commitPackageRepositoryState(t, fixture, "restore package exclude contract", map[string][]byte{"config/sow.yaml": safeBody})
	if _, _, err := loadAndSelect(commonFlags{configPath: fixture.configPath, repos: csvFlag{items: []string{"yum-test"}}, workers: 1, chunk: 1}); exitCode(err) != ExitConflict {
		t.Fatalf("load preflight accepted historical package drift: %v", err)
	}
	lock, err := state.AcquireLock(fixture.cfg.StatePath(), "package-contract-test", false)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	if err := requireCanonicalConfigBaseline(fixture.cfg, fixture.canonical); err == nil || !strings.Contains(err.Error(), "package repository") {
		t.Fatalf("lock-held mutation boundary accepted matching-HEAD drift: %v", err)
	}
}

func TestGCRejectsRestoredHistoricalPackageDriftBeforeCASApply(t *testing.T) {
	root, configPath, canonical, pool, orphan, _ := confirmedAssetProjectionGCOrphan(t)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Repos = append(cfg.Repos, config.Repo{
		ID: "apt-gc", Type: "apt", Path: "apt/gc", DefaultPool: "public",
		Arches: []string{"amd64"}, OS: config.OSConfig{Family: "debian", Suite: "bookworm", Lifecycle: "active"},
		APT: &config.APTConfig{Suites: []string{"bookworm"}, Components: []string{"main"}},
	})
	owned, err := pool.Put(t.Context(), strings.NewReader("package-contract-owned-object\n"))
	if err != nil {
		t.Fatal(err)
	}
	safeBody, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	manifestBody := []byte(fmt.Sprintf("pool/main/p/pkg.deb\t%d\t%s\n", owned.Size, owned.HashString()))
	if _, changed, err := canonical.InstallPaths(map[string]string{
		"config/sow.yaml":      writePackageRepositoryStage(t, root, "gc-package-safe.yaml", safeBody),
		"manifests/apt-gc.tsv": writePackageRepositoryStage(t, root, "gc-package-manifest.tsv", manifestBody),
	}, "freeze GC package repository contract"); err != nil || !changed {
		t.Fatalf("freeze GC package contract changed=%v err=%v", changed, err)
	}
	if err := os.WriteFile(configPath, safeBody, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runGCTestCLI(t, "gc", "--config", configPath, "--limit", "0", "--workers", "1", "--chunk-entries", "1")
	if code != ExitOK {
		t.Fatalf("confirm package GC plan code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	confirm := gcDigest(t, stdout, "gc_set_sha256")
	unsafe := cloneRootedPackageConfig(t, cfg)
	unsafe.Repos[len(unsafe.Repos)-1].Include = []string{"pool/**"}
	unsafeBody, _ := unsafe.Canonical()
	commitPackageRepositoryState(t, packageRepositoryContractFixture{root: root, canonical: canonical}, "unsafe package drift before GC", map[string][]byte{"config/sow.yaml": unsafeBody})
	commitPackageRepositoryState(t, packageRepositoryContractFixture{root: root, canonical: canonical}, "restore package contract before GC", map[string][]byte{"config/sow.yaml": safeBody})
	assertAssetProjectionGCRejectedWithoutMutation(t, configPath, canonical, pool, orphan, confirm, "historical package repository")
}

func TestPackageRepositoryHistoryAuditRejectsBrokenSOWRef(t *testing.T) {
	fixture := newPackageRepositoryContractFixture(t, "manifests")
	repositoryPath := filepath.Join(fixture.root, ".sow", "state")
	repositoryGit, err := git.PlainOpen(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}
	broken := plumbing.NewHashReference(plumbing.ReferenceName("refs/sow/tests/broken"), plumbing.NewHash(strings.Repeat("f", 40)))
	if err := repositoryGit.Storer.SetReference(broken); err != nil {
		t.Fatal(err)
	}
	if err := validateCanonicalPackageRepositoryContracts(fixture.cfg); err == nil || !strings.Contains(err.Error(), "invalid commit") {
		t.Fatalf("broken SOW ref did not fail package history closed: %v", err)
	}
}

func TestPackageRepositoryContractAuditDoesNotInflateLargeManifest(t *testing.T) {
	fixture := newPackageRepositoryContractFixture(t, "empty")
	const manifestSize = int64(32 << 20)
	manifestPath := filepath.Join(fixture.root, "large-package-manifest.tsv")
	file, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(manifestSize); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := fixture.canonical.InstallPaths(map[string]string{"manifests/apt-test.tsv": manifestPath}, "large package ownership manifest"); err != nil || !changed {
		t.Fatalf("install large manifest changed=%v err=%v", changed, err)
	}
	for index := 0; index < 6; index++ {
		marker := filepath.Join(fixture.root, fmt.Sprintf("marker-%d", index))
		if err := os.WriteFile(marker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, changed, err := fixture.canonical.InstallPaths(map[string]string{fmt.Sprintf("tests/package-marker-%d", index): marker}, "extend package history"); err != nil || !changed {
			t.Fatalf("extend history changed=%v err=%v", changed, err)
		}
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err = validateCanonicalPackageRepositoryContracts(fixture.cfg)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("package history audit allocated=%d manifest=%d", allocated, manifestSize)
	if allocated >= uint64(manifestSize/2) {
		t.Fatalf("package contract audit inflated manifest: allocated=%d manifest=%d", allocated, manifestSize)
	}
}

func newPackageRepositoryContractFixture(t *testing.T, evidence string) packageRepositoryContractFixture {
	t.Helper()
	root := t.TempDir()
	cfg, err := config.Decode(strings.NewReader(packageRepositoryContractConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Root = root
	cfg.Path = filepath.Join(root, "sow.yaml")
	body, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	staged := map[string]string{"config/sow.yaml": writePackageRepositoryStage(t, root, "canonical-config.yaml", body)}
	manifestBody := []byte("pool/main/p/pkg.deb\t1\t" + strings.Repeat("a", 64) + "\n")
	switch evidence {
	case "manifests":
		staged["manifests/apt-test.tsv"] = writePackageRepositoryStage(t, root, "apt-manifest.tsv", manifestBody)
		staged["manifests/yum-test.tsv"] = writePackageRepositoryStage(t, root, "yum-manifest.tsv", []byte("Packages/p/pkg.rpm\t1\t"+strings.Repeat("b", 64)+"\n"))
	case "view":
		staged["views/latest/apt-test/bookworm/amd64.tsv"] = writePackageRepositoryStage(t, root, "apt-view.tsv", []byte("owned\n"))
	case "snapshot":
		staged["snapshots/bookworm-20260714/apt-test/bookworm/amd64.tsv"] = writePackageRepositoryStage(t, root, "apt-snapshot.tsv", []byte("owned\n"))
	case "generation":
		generationPath := serving.GenerationManifestStatePathFor("00000000000000000001", "latest", "yum-test", "el9", "x86_64")
		staged[generationPath] = writePackageRepositoryStage(t, root, "yum-generation.tsv", []byte("owned\n"))
	case "empty":
		staged["manifests/apt-test.tsv"] = writePackageRepositoryStage(t, root, "empty-apt.tsv", nil)
		staged["manifests/yum-test.tsv"] = writePackageRepositoryStage(t, root, "empty-yum.tsv", nil)
	default:
		t.Fatalf("unknown package ownership evidence %q", evidence)
	}
	canonical := state.New(cfg.StatePath())
	head, changed, err := canonical.InstallPaths(staged, "package repository contract fixture")
	if err != nil || !changed {
		t.Fatalf("install package fixture changed=%v err=%v", changed, err)
	}
	baseline, err := readCanonicalConfigBaseline(cfg.Path, cfg.Root)
	if err != nil {
		t.Fatal(err)
	}
	setCanonicalConfigBaseline(cfg, baseline)
	return packageRepositoryContractFixture{root: root, configPath: cfg.Path, canonical: canonical, cfg: cfg, head: head}
}

func cloneRootedPackageConfig(t *testing.T, cfg *config.Config) *config.Config {
	t.Helper()
	body, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	clone, err := config.Decode(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	clone.Root = cfg.Root
	clone.Path = cfg.Path
	clone.CanonicalBaselineKnown = cfg.CanonicalBaselineKnown
	clone.CanonicalBaselineExists = cfg.CanonicalBaselineExists
	clone.CanonicalBaselineSHA256 = cfg.CanonicalBaselineSHA256
	clone.CanonicalBaselineSize = cfg.CanonicalBaselineSize
	return clone
}

func writePackageRepositoryStage(t *testing.T, root, name string, body []byte) string {
	t.Helper()
	filename := filepath.Join(root, name)
	if err := os.WriteFile(filename, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return filename
}

func commitPackageRepositoryState(t *testing.T, fixture packageRepositoryContractFixture, message string, files map[string][]byte, deleted ...string) plumbing.Hash {
	t.Helper()
	parent, err := fixture.canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	return commitAssetProjectionState(t, fixture.root, []plumbing.Hash{parent}, time.Now().UTC(), message, files, deleted...)
}

func pinPackageRepositoryOffHead(t *testing.T, fixture packageRepositoryContractFixture, offHead plumbing.Hash, refName string) {
	t.Helper()
	ref := plumbing.ReferenceName(refName)
	if err := fixture.canonical.AdvanceRef(ref, plumbing.ZeroHash, offHead, true); err != nil {
		t.Fatal(err)
	}
	repository, err := git.PlainOpen(filepath.Join(fixture.root, ".sow", "state"))
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := worktree.Reset(&git.ResetOptions{Mode: git.HardReset, Commit: fixture.head}); err != nil {
		t.Fatal(err)
	}
}

func testKindLocationFragment(kind string) string {
	switch kind {
	case "manifests":
		return "manifests/apt-test.tsv"
	case "view":
		return "views/latest/apt-test"
	case "snapshot":
		return "snapshots/bookworm-20260714/apt-test"
	case "generation":
		return "serving/yum/generations"
	default:
		return kind
	}
}
