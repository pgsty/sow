package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
)

func TestHistoricalConfigCacheHitLRUAndBounds(t *testing.T) {
	bodies := [][]byte{
		historicalConfigFixture(0),
		historicalConfigFixture(1),
		historicalConfigFixture(2),
	}
	identities := make([]state.BlobIdentity, len(bodies))
	loads := make([]int, len(bodies))
	for index, body := range bodies {
		identities[index] = historicalConfigIdentity(body)
	}
	cache := newHistoricalConfigCache()
	get := func(index int) *config.Config {
		t.Helper()
		decoded, err := cache.get(identities[index], func() ([]byte, error) {
			loads[index]++
			return append([]byte(nil), bodies[index]...), nil
		})
		if err != nil {
			t.Fatalf("get config %d: %v", index, err)
		}
		return decoded
	}

	first := get(0)
	get(1)
	if again := get(0); again != first {
		t.Fatal("cache hit did not reuse the decoded config")
	}
	get(2) // config 0 was most recently used, so config 1 is evicted.
	get(1)
	if loads[0] != 1 || loads[1] != 2 || loads[2] != 1 {
		t.Fatalf("unexpected LRU loads: %v", loads)
	}
	stats := cache.snapshot()
	if stats.PeakEntries > historicalConfigCacheMaxEntries || stats.PeakBytes > historicalConfigCacheMaxCanonicalBytes {
		t.Fatalf("cache exceeded production bounds: %+v", stats)
	}
	if stats.Entries != 2 || stats.Hits != 1 || stats.Loads != 4 || stats.Evictions != 2 {
		t.Fatalf("unexpected cache stats: %+v", stats)
	}
}

func TestHistoricalConfigCacheByteBoundEvictsBeforeDecode(t *testing.T) {
	left := historicalConfigFixture(10)
	right := historicalConfigFixture(11)
	maxBytes := int64(len(left) + len(right) - 1)
	cache := newHistoricalConfigCacheWithLimits(3, maxBytes)
	for _, body := range [][]byte{left, right} {
		identity := historicalConfigIdentity(body)
		if _, err := cache.get(identity, func() ([]byte, error) { return body, nil }); err != nil {
			t.Fatal(err)
		}
	}
	stats := cache.snapshot()
	if stats.PeakEntries != 1 || stats.Evictions != 1 || stats.PeakBytes > maxBytes {
		t.Fatalf("byte budget was not enforced before the second decode: %+v", stats)
	}
}

func TestHistoricalConfigCacheFailuresAreNotCached(t *testing.T) {
	valid := historicalConfigFixture(20)
	identity := historicalConfigIdentity(valid)
	cache := newHistoricalConfigCache()
	loads := 0
	if _, err := cache.get(identity, func() ([]byte, error) {
		loads++
		return nil, errors.New("injected read failure")
	}); err == nil || !strings.Contains(err.Error(), "injected read failure") {
		t.Fatalf("loader failure = %v", err)
	}
	if _, err := cache.get(identity, func() ([]byte, error) {
		loads++
		return valid, nil
	}); err != nil {
		t.Fatalf("retry after loader failure: %v", err)
	}
	if loads != 2 || cache.snapshot().Loads != 1 {
		t.Fatalf("loader failure was cached: loads=%d stats=%+v", loads, cache.snapshot())
	}

	malformed := []byte("schema: [not valid\n")
	malformedIdentity := historicalConfigIdentity(malformed)
	decodeLoads := 0
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := cache.get(malformedIdentity, func() ([]byte, error) {
			decodeLoads++
			return malformed, nil
		}); err == nil {
			t.Fatal("malformed config unexpectedly decoded")
		}
	}
	if decodeLoads != 2 {
		t.Fatalf("decode failure was cached: loads=%d", decodeLoads)
	}
}

func TestHistoricalConfigCacheIdentityMismatchIsRetryable(t *testing.T) {
	want := historicalConfigFixture(30)
	wrong := historicalConfigFixture(31)
	identity := historicalConfigIdentity(want)
	cache := newHistoricalConfigCache()
	loads := 0
	if _, err := cache.get(identity, func() ([]byte, error) {
		loads++
		return wrong, nil
	}); err == nil || (!strings.Contains(err.Error(), "hash mismatch") && !strings.Contains(err.Error(), "expected")) {
		t.Fatalf("identity mismatch = %v", err)
	}
	if _, err := cache.get(identity, func() ([]byte, error) {
		loads++
		return want, nil
	}); err != nil {
		t.Fatalf("retry after identity mismatch: %v", err)
	}
	if loads != 2 || cache.snapshot().Loads != 1 {
		t.Fatalf("identity mismatch was cached: loads=%d stats=%+v", loads, cache.snapshot())
	}

	sizeCache := newHistoricalConfigCache()
	sizeLoads := 0
	if _, err := sizeCache.get(identity, func() ([]byte, error) {
		sizeLoads++
		return want[:len(want)-1], nil
	}); err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("size mismatch = %v", err)
	}
	if _, err := sizeCache.get(identity, func() ([]byte, error) {
		sizeLoads++
		return want, nil
	}); err != nil {
		t.Fatalf("retry after size mismatch: %v", err)
	}
	if sizeLoads != 2 || sizeCache.snapshot().Loads != 1 {
		t.Fatalf("size mismatch was cached: loads=%d stats=%+v", sizeLoads, sizeCache.snapshot())
	}
}

func TestHistoricalConfigCacheSizeMismatchIsRetryable(t *testing.T) {
	body := historicalConfigFixture(32)
	identity := historicalConfigIdentity(body)
	identity.Size++
	cache := newHistoricalConfigCache()
	loads := 0
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := cache.get(identity, func() ([]byte, error) {
			loads++
			return body, nil
		}); err == nil || !strings.Contains(err.Error(), "expected") {
			t.Fatalf("size mismatch attempt %d = %v", attempt, err)
		}
	}
	if loads != 2 || cache.snapshot().Loads != 0 {
		t.Fatalf("size mismatch was cached: loads=%d stats=%+v", loads, cache.snapshot())
	}
}

func TestAssetProjectionHistoryConfigCacheBoundAndEvictedViolation(t *testing.T) {
	root, configPath := newPopulatedAssetProjectionFixture(t)
	canonical := state.New(root + "/.sow")
	unsafe := assetProjectionConfigWithBootstrapLines(t, "    include: ['pkg/**']\n")
	unsafeCommit := commitAssetProjectionState(t, root, []plumbing.Hash{mustCanonicalHead(t, canonical)}, time.Now().UTC(), "early empty-evidence unsafe bounded-history asset contract", map[string][]byte{
		"config/sow.yaml":         []byte(unsafe),
		"manifests/bootstrap.tsv": {},
	})
	var laterCommits []plumbing.Hash
	for index := 0; index < 6; index++ {
		body := []byte(fmt.Sprintf("%s\n# bounded asset history %d\n", assetProjectionTransitionConfig, index))
		if index == 0 {
			body = []byte(assetProjectionConfigWithBootstrapLines(t, "    include: ['second-unsafe/**']\n"))
		}
		laterCommits = append(laterCommits, commitAssetProjectionState(t, root, []plumbing.Hash{mustCanonicalHead(t, canonical)}, time.Now().UTC().Add(time.Duration(index+1)*time.Second), fmt.Sprintf("unique asset config %d", index), map[string][]byte{
			"config/sow.yaml": body,
		}))
	}
	headBefore := mustCanonicalHead(t, canonical)
	registry, err := historicalAssetProjectionOwners(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if registry.configCache.PeakEntries > historicalConfigCacheMaxEntries || registry.configCache.PeakBytes > historicalConfigCacheMaxCanonicalBytes || registry.configCache.Evictions == 0 {
		t.Fatalf("asset historical config cache was not bounded: %+v", registry.configCache)
	}
	gitHistory, err := openHistoricalAssetProjectionGit(canonical)
	if err != nil {
		t.Fatal(err)
	}
	targeted := &historicalAssetProjectionConfigIndex{
		gitHistory: gitHistory,
		identities: make(map[plumbing.Hash]state.BlobIdentity),
		cache:      newHistoricalConfigCache(),
	}
	for _, commit := range append([]plumbing.Hash{unsafeCommit}, laterCommits[len(laterCommits)-2:]...) {
		identity, exists, identityErr := gitHistory.blobIdentityAt(commit, "config/sow.yaml")
		if identityErr != nil || !exists {
			t.Fatalf("config identity at %s exists=%v err=%v", commit, exists, identityErr)
		}
		targeted.identities[commit] = identity
	}
	if _, _, err := targeted.configAt(unsafeCommit); err != nil {
		t.Fatal(err)
	}
	for _, commit := range laterCommits[len(laterCommits)-2:] {
		if _, _, err := targeted.configAt(commit); err != nil {
			t.Fatal(err)
		}
	}
	loadsBeforeReload := targeted.cache.snapshot().Loads
	reloadedUnsafe, exists, err := targeted.configAt(unsafeCommit)
	if err != nil || !exists {
		t.Fatalf("reload evicted unsafe asset config exists=%v err=%v", exists, err)
	}
	if loadsAfterReload := targeted.cache.snapshot().Loads; loadsAfterReload != loadsBeforeReload+1 {
		t.Fatalf("evicted unsafe asset blob was not reloaded: before=%d after=%d", loadsBeforeReload, loadsAfterReload)
	}
	if include := assetReposByID(reloadedUnsafe)["bootstrap"].Include; len(include) != 1 || include[0] != "pkg/**" {
		t.Fatalf("reloaded unsafe asset contract include = %v", include)
	}
	history, err := gitHistory.reachableCanonicalCommits()
	if err != nil {
		t.Fatal(err)
	}
	if registry.configCache.Loads <= uint64(len(history)) {
		t.Fatalf("asset continuity did not reload evicted configs: history=%d stats=%+v", len(history), registry.configCache)
	}
	if registry.configCache.Loads > uint64(2*len(history)) {
		t.Fatalf("asset continuity decoded configs superlinearly: history=%d stats=%+v", len(history), registry.configCache)
	}
	if records := registry.byID["bootstrap"]; len(records) != 1 {
		t.Fatalf("empty-evidence drift created %d ownership records, want only the established baseline", len(records))
	}
	if len(registry.continuity) == 0 || !strings.Contains(registry.continuity[0], "contract owned") || !strings.Contains(registry.continuity[0], "changed") {
		t.Fatalf("evicted empty-evidence asset drift escaped continuity audit: %v", registry.continuity)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCanonicalAssetProjectionContracts(cfg); err == nil || !strings.Contains(err.Error(), "contract owned") || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("evicted historical asset violation escaped audit: %v", err)
	}
	if headAfter := mustCanonicalHead(t, canonical); headAfter != headBefore {
		t.Fatalf("asset audit mutated HEAD: before=%s after=%s", headBefore, headAfter)
	}
}

func TestPackageRepositoryHistoryConfigCacheBoundAndEvictedViolation(t *testing.T) {
	fixture := newPackageRepositoryContractFixture(t, "manifests")
	unsafe := cloneRootedPackageConfig(t, fixture.cfg)
	unsafe.Repos[0].Include = []string{"pool/**", "early-unsafe/**"}
	unsafeBody, err := unsafe.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	unsafeCommit := commitPackageRepositoryState(t, fixture, "early empty-evidence unsafe bounded-history package contract", map[string][]byte{
		"config/sow.yaml":        unsafeBody,
		"manifests/apt-test.tsv": {},
	})
	safeBody, err := fixture.cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	secondUnsafe := cloneRootedPackageConfig(t, fixture.cfg)
	secondUnsafe.Repos[0].Include = []string{"pool/**", "second-unsafe/**"}
	secondUnsafeBody, err := secondUnsafe.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	var laterCommits []plumbing.Hash
	for index := 0; index < 6; index++ {
		body := []byte(fmt.Sprintf("%s\n# bounded package history %d\n", safeBody, index))
		if index == 0 {
			body = secondUnsafeBody
		}
		laterCommits = append(laterCommits, commitPackageRepositoryState(t, fixture, fmt.Sprintf("unique package config %d", index), map[string][]byte{"config/sow.yaml": body}))
	}
	headBefore := mustCanonicalHead(t, fixture.canonical)
	graph, err := loadReachablePackageRepositoryHistory(fixture.canonical)
	if err != nil {
		t.Fatal(err)
	}
	stats := graph.configCache.snapshot()
	if stats.PeakEntries > historicalConfigCacheMaxEntries || stats.PeakBytes > historicalConfigCacheMaxCanonicalBytes || stats.Evictions == 0 {
		t.Fatalf("package historical config cache was not bounded: %+v", stats)
	}
	if _, err := graph.configAt(unsafeCommit); err != nil {
		t.Fatal(err)
	}
	for _, commit := range laterCommits[len(laterCommits)-2:] {
		if _, err := graph.configAt(commit); err != nil {
			t.Fatal(err)
		}
	}
	loadsBeforeReload := graph.configCache.snapshot().Loads
	reloadedUnsafe, err := graph.configAt(unsafeCommit)
	if err != nil {
		t.Fatal(err)
	}
	if loadsAfterReload := graph.configCache.snapshot().Loads; loadsAfterReload != loadsBeforeReload+1 {
		t.Fatalf("evicted unsafe package blob was not reloaded: before=%d after=%d", loadsBeforeReload, loadsAfterReload)
	}
	if field := packageRepositoryImmutableDifference(fixture.cfg.Repos[0], reloadedUnsafe.Repos[0]); field != "include" {
		t.Fatalf("reloaded unsafe package contract difference = %q, want include", field)
	}
	records := []packageRepositoryOwner{{repo: fixture.cfg.Repos[0]}}
	records = retainPackageRepositoryImmutableContract(records, packageRepositoryOwner{repo: unsafe.Repos[0]})
	records = retainPackageRepositoryImmutableContract(records, packageRepositoryOwner{repo: secondUnsafe.Repos[0]})
	if len(records) != 2 {
		t.Fatalf("package ownership retained %d records instead of the sufficient conflicting pair", len(records))
	}
	owner := packageRepositoryOwner{commit: fixture.head, repo: detachHistoricalRepository(fixture.cfg.Repos[0]), location: graph.evidence[fixture.head]["apt-test"]}
	loadsBeforeLineage := graph.configCache.snapshot().Loads
	lineages, err := auditPackageRepositoryLineages(graph, []string{"apt-test"}, map[string][]packageRepositoryOwner{"apt-test": {owner}})
	if err != nil {
		t.Fatal(err)
	}
	if lineageLoads := graph.configCache.snapshot().Loads - loadsBeforeLineage; lineageLoads > uint64(len(graph.order)) {
		t.Fatalf("package lineage decoded configs superlinearly: commits=%d loads=%d", len(graph.order), lineageLoads)
	}
	foundLineageDrift := false
	for _, finding := range lineages["apt-test"].findings {
		foundLineageDrift = foundLineageDrift || strings.Contains(finding.message, "include contract")
	}
	if !foundLineageDrift {
		t.Fatalf("evicted empty-evidence package drift escaped lineage audit: %+v", lineages["apt-test"].findings)
	}
	if err := validateCanonicalPackageRepositoryContracts(fixture.cfg); err == nil || !strings.Contains(err.Error(), "include contract") {
		t.Fatalf("evicted historical package violation escaped audit: %v", err)
	}
	if headAfter := mustCanonicalHead(t, fixture.canonical); headAfter != headBefore {
		t.Fatalf("package audit mutated HEAD: before=%s after=%s", headBefore, headAfter)
	}
}

func TestDetachHistoricalRepositoryOwnsNestedContractData(t *testing.T) {
	active := true
	source := config.Repo{
		ID: "detached", Type: "apt", Path: "apt/detached", Active: &active,
		Arches: []string{"amd64"}, Include: []string{"pool/**"}, Exclude: []string{"debug/**"}, PublishTargets: []string{"cf"},
		APT: &config.APTConfig{
			Suites:          []string{"bookworm"},
			Components:      []string{"main"},
			SuiteComponents: map[string][]string{"bookworm": {"main"}},
			SuiteLifecycle:  map[string]string{"bookworm": "active"},
		},
		YUM:   &config.YUMConfig{Compression: "zstd"},
		Asset: &config.AssetConfig{MutablePaths: []string{"latest"}, RootKeys: []string{"pkg"}},
	}
	detached := detachHistoricalRepository(source)
	*source.Active = false
	source.Arches[0] = "changed"
	source.Include[0] = "changed"
	source.Exclude[0] = "changed"
	source.PublishTargets[0] = "changed"
	source.APT.Suites[0] = "changed"
	source.APT.Components[0] = "changed"
	source.APT.SuiteComponents["bookworm"][0] = "changed"
	source.APT.SuiteLifecycle["bookworm"] = "frozen"
	source.YUM.Compression = "gzip"
	source.Asset.MutablePaths[0] = "changed"
	source.Asset.RootKeys[0] = "changed"
	if !detached.IsActive() || detached.Arches[0] != "amd64" || detached.Include[0] != "pool/**" || detached.Exclude[0] != "debug/**" || detached.PublishTargets[0] != "cf" {
		t.Fatalf("detached top-level contract aliases source: %+v", detached)
	}
	if detached.APT.Suites[0] != "bookworm" || detached.APT.Components[0] != "main" || detached.APT.SuiteComponents["bookworm"][0] != "main" || detached.APT.SuiteLifecycle["bookworm"] != "active" {
		t.Fatalf("detached APT contract aliases source: %+v", detached.APT)
	}
	if detached.YUM.Compression != "zstd" || detached.Asset.MutablePaths[0] != "latest" || detached.Asset.RootKeys[0] != "pkg" {
		t.Fatalf("detached nested contract aliases source: yum=%+v asset=%+v", detached.YUM, detached.Asset)
	}
}

func TestPackageRepositoryHistoryReusesBlobAndAuditsEveryCommitEvidence(t *testing.T) {
	fixture := newPackageRepositoryContractFixture(t, "manifests")
	body, err := fixture.cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	commits := make([]plumbing.Hash, 0, 4)
	for index := 0; index < 4; index++ {
		commits = append(commits, commitPackageRepositoryState(t, fixture, fmt.Sprintf("repeat canonical config %d", index), map[string][]byte{
			"config/sow.yaml":                     body,
			fmt.Sprintf("tests/repeat-%d", index): []byte("evidence\n"),
		}))
	}
	graph, err := loadReachablePackageRepositoryHistory(fixture.canonical)
	if err != nil {
		t.Fatal(err)
	}
	identity := graph.configIdentities[commits[0]]
	if identity.Hash.IsZero() {
		t.Fatal("repeated canonical config has no blob identity")
	}
	for _, commit := range commits {
		if got := graph.configIdentities[commit]; got != identity {
			t.Fatalf("commit %s config identity = %+v, want %+v", commit, got, identity)
		}
		wantLocation := commit.String() + ":manifests/apt-test.tsv"
		if got := graph.evidence[commit]["apt-test"]; got != wantLocation {
			t.Fatalf("commit %s evidence = %q, want %q", commit, got, wantLocation)
		}
	}
	stats := graph.configCache.snapshot()
	if stats.Hits < uint64(len(commits)-1) {
		t.Fatalf("repeated blob was decoded instead of reused: %+v", stats)
	}
}

func historicalConfigFixture(index int) []byte {
	return []byte(fmt.Sprintf("%s\n# historical config cache fixture %d\n", assetProjectionTransitionConfig, index))
}

func historicalConfigIdentity(body []byte) state.BlobIdentity {
	return state.BlobIdentity{Hash: plumbing.ComputeHash(plumbing.BlobObject, body), Size: int64(len(body))}
}

func mustCanonicalHead(t *testing.T, canonical *state.Store) plumbing.Hash {
	t.Helper()
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	return head
}
