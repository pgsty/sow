package config

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"testing"
)

func TestConfigComplexityBudgetsAcceptExactLimitsAndRejectOneMore(t *testing.T) {
	structural := newConfigStructuralBudget()
	if err := structural.add(MaxConfigTopologyUnits, "exact structural boundary"); err != nil {
		t.Fatalf("exact structural limit rejected: %v", err)
	}
	if structural.used != MaxConfigTopologyUnits {
		t.Fatalf("structural usage=%d want=%d", structural.used, MaxConfigTopologyUnits)
	}
	if err := structural.add(1, "structural limit plus one"); err == nil || err.Error() != "configuration topology exceeds 65536-work-unit safety limit while accounting for structural limit plus one" {
		t.Fatalf("structural limit+1 error=%v", err)
	}

	derived := newConfigDerivedStringBudget()
	if err := derived.add(MaxConfigDerivedStringBytes, "exact derived boundary"); err != nil {
		t.Fatalf("exact derived byte limit rejected: %v", err)
	}
	if derived.used != MaxConfigDerivedStringBytes {
		t.Fatalf("derived usage=%d want=%d", derived.used, MaxConfigDerivedStringBytes)
	}
	if err := derived.add(1, "derived limit plus one"); err == nil || err.Error() != "configuration derived strings exceeds 67108864-byte safety limit while accounting for derived limit plus one" {
		t.Fatalf("derived limit+1 error=%v", err)
	}
}

func TestConfigComplexityProductArithmeticIsOverflowSafe(t *testing.T) {
	budget := newConfigStructuralBudget()
	if err := budget.addProduct("exact 256-square", 256, 256); err != nil {
		t.Fatalf("exact product rejected: %v", err)
	}
	if budget.used != MaxConfigTopologyUnits {
		t.Fatalf("product usage=%d want=%d", budget.used, MaxConfigTopologyUnits)
	}

	zero := newConfigStructuralBudget()
	if err := zero.addProduct("zero product", math.MaxUint64, 0, math.MaxUint64); err != nil || zero.used != 0 {
		t.Fatalf("zero product err=%v usage=%d", err, zero.used)
	}

	overflow := configComplexityBudget{limit: math.MaxUint64, kind: "test complexity", unit: "unit"}
	if err := overflow.addProduct("overflow product", math.MaxUint64, 2); err == nil || !strings.Contains(err.Error(), "overflow product") {
		t.Fatalf("overflowing product accepted or misclassified: %v", err)
	}
	alreadyOver := configComplexityBudget{used: 2, limit: 1, kind: "test complexity", unit: "unit"}
	if err := alreadyOver.add(0, "corrupt prior usage"); err == nil || !strings.Contains(err.Error(), "corrupt prior usage") {
		t.Fatalf("over-limit prior usage underflowed or was accepted: %v", err)
	}
}

func TestConfigDerivedStringAccountingAcceptsExactLimitAndRejectsOneMore(t *testing.T) {
	arches := makeRouteValues("arch", 15)
	cfg := &Config{Repos: []Repo{{
		ID: "yum-boundary", Type: "yum", Path: "yum/" + strings.Repeat("p", 2<<20) + "/{arch}", Arches: arches,
		OS:  OSConfig{Family: "el", Major: 9},
		YUM: &YUMConfig{PackageKeyring: "keys/packages.asc", NoarchMode: YUMNoarchReplicate, noarchModePresent: true},
	}}}
	usage, err := configComplexityUsageFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if usage.DerivedStringBytes >= MaxConfigDerivedStringBytes {
		t.Fatalf("boundary fixture base=%d want below %d", usage.DerivedStringBytes, MaxConfigDerivedStringBytes)
	}
	remaining := MaxConfigDerivedStringBytes - usage.DerivedStringBytes
	cfg.Edge.ProPrefix = strings.Repeat("x", int(remaining))
	usage, err = configComplexityUsageFor(cfg)
	if err != nil {
		t.Fatalf("exact derived accounting rejected: %v", err)
	}
	if usage.DerivedStringBytes != MaxConfigDerivedStringBytes {
		t.Fatalf("derived usage=%d want=%d", usage.DerivedStringBytes, MaxConfigDerivedStringBytes)
	}
	cfg.Edge.ProPrefix += "x"
	if _, err := configComplexityUsageFor(cfg); err == nil || !strings.Contains(err.Error(), "edge.pro_prefix") {
		t.Fatalf("derived limit+1 accepted or misclassified: %v", err)
	}
}

func TestConfigStructuralAccountingAcceptsExactLimit(t *testing.T) {
	members := make([]string, MaxConfigTopologyUnits-1)
	cfg := &Config{RepoGroups: map[string][]string{"boundary": members}}
	usage, err := configComplexityUsageFor(cfg)
	if err != nil {
		t.Fatalf("exact topology rejected: %v", err)
	}
	if usage.StructuralUnits != MaxConfigTopologyUnits {
		t.Fatalf("structural usage=%d want=%d", usage.StructuralUnits, MaxConfigTopologyUnits)
	}
	cfg.RepoGroups["boundary"] = append(cfg.RepoGroups["boundary"], "one-more")
	if _, err := configComplexityUsageFor(cfg); err == nil || !strings.Contains(err.Error(), "repo_groups.boundary") {
		t.Fatalf("limit+1 topology accepted or misclassified: %v", err)
	}
}

func TestConfigComplexityRejectsAPTMetadataProduct(t *testing.T) {
	arches := makeRouteValues("arch", 257)
	components := makeRouteValues("component", 257)
	cfg := &Config{
		Schema: Schema,
		Repos: []Repo{{
			ID: "apt-wide", Type: "apt", Path: "apt/wide", Arches: arches,
			APT: &APTConfig{Suites: []string{"suite"}, Components: components},
		}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "65536-work-unit") || !strings.Contains(err.Error(), "apt metadata leaves") {
		t.Fatalf("257x257 metadata topology accepted or misclassified: %v", err)
	}
}

func TestConfigComplexityRejectsLongPathExpansionBelowInputLimit(t *testing.T) {
	arches := makeRouteValues("arch", 20)
	repo := fmt.Sprintf(`
  - id: yum-wide
    type: yum
    path: yum/%s/{arch}
    default_pool: public
    arches: [%s]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: keys/packages.asc}`,
		strings.Repeat("p", 2<<20), strings.Join(arches, ", "))
	input := validYAML(repo)
	if len(input) >= MaxConfigBytes {
		t.Fatalf("long-path adversary is not sub-limit: %d", len(input))
	}
	if _, err := Decode(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), "67108864-byte") || !strings.Contains(err.Error(), "repos[0]") {
		t.Fatalf("long path expansion accepted or misclassified: %v", err)
	}
}

func TestConfigComplexityRejectsDefaultStringAmplificationWithoutMutation(t *testing.T) {
	longArch := strings.Repeat("a", 4<<20)
	upstreams := make([]Upstream, 8)
	for index := range upstreams {
		upstreams[index] = Upstream{ID: fmt.Sprintf("upstream-%02d", index), Type: "yum", Repo: "yum-wide"}
	}
	cfg := &Config{
		Schema: Schema,
		Repos: []Repo{{
			ID: "yum-wide", Type: "yum", Path: "yum/wide", Arches: []string{longArch},
			YUM: &YUMConfig{},
		}},
		Upstreams: upstreams,
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "67108864-byte") || !strings.Contains(err.Error(), "upstreams[") {
		t.Fatalf("default string amplification accepted or misclassified: %v", err)
	}
	for index, upstream := range cfg.Upstreams {
		if upstream.Arches != nil || upstream.Components != nil || upstream.DebugInfo != "" || upstream.Suite != "" {
			t.Fatalf("upstream %d mutated before preflight rejection: %#v", index, upstream)
		}
	}
	if cfg.Repos[0].Arches[0] != longArch || cfg.Repos[0].YUM.NoarchMode != "" {
		t.Fatal("repository mutated before preflight rejection")
	}
}

func TestConfigComplexityChargesRepeatedPackageKeyringDefault(t *testing.T) {
	const repos = 17
	cfg := &Config{GPG: GPGConfig{PublicKey: strings.Repeat("k", 4<<20)}}
	for index := 0; index < repos; index++ {
		cfg.Repos = append(cfg.Repos, Repo{
			ID: fmt.Sprintf("yum-%02d", index), Type: "yum", Path: fmt.Sprintf("yum/r%02d", index),
			Arches: []string{"x86_64"}, OS: OSConfig{Family: "el", Major: 9}, YUM: &YUMConfig{},
		})
	}
	cfg.applyDefaults()
	for index := range cfg.Repos {
		if !cfg.Repos[index].YUM.packageKeyringDefaulted {
			t.Fatalf("repo %d lost package-keyring default provenance", index)
		}
	}
	if _, err := configComplexityUsageFor(cfg); err == nil || !strings.Contains(err.Error(), "package_keyring default") {
		t.Fatalf("repeated package-keyring default accepted or misclassified: %v", err)
	}
}

func TestConfigComplexityChargesInvalidDefaultViewRepoPairs(t *testing.T) {
	const dimension = 257
	cfg := &Config{Views: make(map[string]View, dimension)}
	for index := 0; index < dimension; index++ {
		cfg.Repos = append(cfg.Repos, Repo{ID: fmt.Sprintf("repo-%03d", index), Type: "apt", APT: &APTConfig{}})
		cfg.Views[fmt.Sprintf("view-%03d", index)] = View{}
	}
	if _, err := configComplexityUsageFor(cfg); err == nil || !strings.Contains(err.Error(), "default expansion") {
		t.Fatalf("uncharged invalid view/repo cross-product was accepted: %v", err)
	}
}

func TestConfigComplexityCountsEveryYUMOSSelector(t *testing.T) {
	cfg := &Config{Repos: []Repo{{
		ID: "yum-dual-os", Type: "yum", Arches: []string{"x86_64", "aarch64"},
		OS: OSConfig{Suite: "custom", Family: "el", Major: 9}, YUM: &YUMConfig{},
	}}}
	usage, err := configComplexityUsageFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// One repo, two decoded arches, and two OS values by two arches.
	if usage.StructuralUnits != 7 {
		t.Fatalf("structural usage=%d want=7", usage.StructuralUnits)
	}
}

func TestConfigComplexityPredictsDirectAssetPublicPathDefault(t *testing.T) {
	cfg := &Config{Repos: []Repo{{
		ID: "asset-default", Type: "asset", Path: "assets/releases", Asset: &AssetConfig{},
	}}}
	usage, err := configComplexityUsageFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(len("asset-default") + 3*len("assets/releases"))
	if usage.DerivedStringBytes != want {
		t.Fatalf("derived usage=%d want=%d", usage.DerivedStringBytes, want)
	}
}

func TestConfigComplexityHandlesRectangularAPTWithZeroArchesLinearly(t *testing.T) {
	const dimension = 32700
	cfg := &Config{Repos: []Repo{{
		ID: "apt-invalid", Type: "apt",
		APT: &APTConfig{Suites: makeRouteValues("suite", dimension), Components: makeRouteValues("component", dimension)},
	}}}
	usage, err := configComplexityUsageFor(cfg)
	if err != nil {
		t.Fatalf("invalid zero-arch fixture should reach the ordinary schema error within the preflight budget: %v", err)
	}
	if usage.StructuralUnits >= MaxConfigTopologyUnits {
		t.Fatalf("structural usage=%d want below %d", usage.StructuralUnits, MaxConfigTopologyUnits)
	}
}

func TestConfigComplexityPrecomputesInvalidDefaultViewCoordinates(t *testing.T) {
	const dimension = 16000
	tests := []struct {
		name string
		repo Repo
	}{
		{
			name: "APT suites with zero arches",
			repo: Repo{ID: "apt-invalid", Type: "apt", APT: &APTConfig{Suites: makeRouteValues("suite", dimension)}},
		},
		{
			name: "YUM arches with zero OS selectors",
			repo: Repo{ID: "yum-invalid", Type: "yum", Arches: makeRouteValues("arch", dimension), YUM: &YUMConfig{}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &Config{Repos: []Repo{test.repo}, Views: make(map[string]View, dimension)}
			for index := 0; index < dimension; index++ {
				cfg.Views[fmt.Sprintf("view-%05d", index)] = View{}
			}
			usage, err := configComplexityUsageFor(cfg)
			if err != nil {
				t.Fatalf("invalid coordinate fixture should reach ordinary validation within the preflight budget: %v", err)
			}
			if usage.StructuralUnits >= MaxConfigTopologyUnits {
				t.Fatalf("structural usage=%d want below %d", usage.StructuralUnits, MaxConfigTopologyUnits)
			}
		})
	}
}

func TestExpandedPathsHandlesManyConfiguredArchesInOnePass(t *testing.T) {
	arches := makeRouteValues("arch", 8192)
	repo := Repo{ID: "many-arches", Type: "yum", Path: "yum/many/{arch}", Arches: arches}
	paths, err := repo.ExpandedPaths()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != len(arches) || paths[0] != "yum/many/arch0000" || paths[len(paths)-1] != "yum/many/arch8191" {
		t.Fatalf("expanded paths have wrong boundaries: count=%d first=%q last=%q", len(paths), paths[0], paths[len(paths)-1])
	}
	if _, err := repo.PathForArch("missing"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("external membership check was weakened: %v", err)
	}
}

func TestSparseAPTSuiteNormalizationUsesGlobalOrderIndex(t *testing.T) {
	const suites = 2048
	components := makeRouteValues("component", suites)
	components = append([]string{"common"}, components...)
	apt := &APTConfig{
		Suites:                 makeRouteValues("suite", suites),
		Components:             components,
		SuiteComponents:        make(map[string][]string, suites),
		suiteComponentsPresent: true,
	}
	for index, suite := range apt.Suites {
		apt.SuiteComponents[suite] = []string{components[index+1], "common"}
	}
	cfg := &Config{Repos: []Repo{{ID: "apt-sparse", Type: "apt", Path: "apt/sparse", Arches: []string{"amd64"}, APT: apt}}}
	usage, err := configComplexityUsageFor(cfg)
	if err != nil {
		t.Fatalf("sparse topology unexpectedly exceeds budget: %v", err)
	}
	if usage.StructuralUnits >= MaxConfigTopologyUnits {
		t.Fatalf("sparse topology units=%d", usage.StructuralUnits)
	}
	if err := validateAPTSuiteContracts(0, apt); err != nil {
		t.Fatal(err)
	}
	for _, suite := range apt.Suites {
		got := apt.SuiteComponents[suite]
		if len(got) != 2 || got[0] != "common" || !strings.HasPrefix(got[1], "component") {
			t.Fatalf("suite %s was not normalized by global order: %v", suite, got)
		}
	}
}

func TestPathConflictIndexesMatchQuadraticOracle(t *testing.T) {
	random := rand.New(rand.NewSource(20260720))
	for iteration := 0; iteration < 500; iteration++ {
		count := 1 + random.Intn(80)
		paths := make([]string, count)
		for index := range paths {
			segments := 1 + random.Intn(4)
			parts := make([]string, segments)
			for segment := range parts {
				parts[segment] = fmt.Sprintf("p%d", random.Intn(24))
			}
			paths[index] = strings.Join(parts, "/")
		}
		want := quadraticNonOverlappingOracle(append([]string(nil), paths...))
		got := validateNonOverlapping(append([]string(nil), paths...))
		if errorText(got) != errorText(want) {
			t.Fatalf("iteration %d mismatch\npaths=%v\ngot=%v\nwant=%v", iteration, paths, got, want)
		}
		if replay := validateNonOverlapping(append([]string(nil), paths...)); errorText(replay) != errorText(got) {
			t.Fatalf("iteration %d was nondeterministic: first=%v replay=%v", iteration, got, replay)
		}
	}
}

func TestPublicOwnershipIndexMatchesQuadraticOracle(t *testing.T) {
	random := rand.New(rand.NewSource(41041))
	for iteration := 0; iteration < 300; iteration++ {
		count := 1 + random.Intn(70)
		prefixes := make([]publicPrefixOwner, count)
		for index := range prefixes {
			segments := 1 + random.Intn(4)
			parts := make([]string, segments)
			for segment := range parts {
				parts[segment] = fmt.Sprintf("p%d", random.Intn(20))
			}
			prefixes[index] = publicPrefixOwner{path: strings.Join(parts, "/"), repo: fmt.Sprintf("repo-%03d", index)}
		}
		want := quadraticPublicOwnershipOracle(append([]publicPrefixOwner(nil), prefixes...), nil)
		got := validatePublicOwnership(append([]publicPrefixOwner(nil), prefixes...), nil)
		if errorText(got) != errorText(want) {
			t.Fatalf("iteration %d mismatch\nprefixes=%v\ngot=%v\nwant=%v", iteration, prefixes, got, want)
		}
	}

	prefixes := []publicPrefixOwner{{path: "pkg", repo: "prefix-owner"}, {path: "src/tool", repo: "other"}}
	keys := map[string]string{"src": "root-src", "pkg": "root-pkg"}
	want := quadraticPublicOwnershipOracle(append([]publicPrefixOwner(nil), prefixes...), keys)
	got := validatePublicOwnership(append([]publicPrefixOwner(nil), prefixes...), keys)
	if errorText(got) != errorText(want) {
		t.Fatalf("root-key conflict mismatch: got=%v want=%v", got, want)
	}
}

func TestCurrentConfigurationFixturesStayBelowComplexityBounds(t *testing.T) {
	fixtures := []struct {
		path      string
		wantUnits uint64
	}{
		{path: "../../sow.example.yaml", wantUnits: 33},
		{path: "../../docs/examples/sow-pgdg.yaml", wantUnits: 200},
		{path: "../../docs/migration/fixtures/pigsty-v1.yaml", wantUnits: 1785},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.path, func(t *testing.T) {
			file, err := os.Open(fixture.path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			cfg, err := Decode(file)
			if err != nil {
				t.Fatal(err)
			}
			usage, err := configComplexityUsageFor(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if usage.StructuralUnits != fixture.wantUnits {
				t.Fatalf("units=%d want=%d", usage.StructuralUnits, fixture.wantUnits)
			}
			t.Logf("structural=%d/%d derived-bytes=%d/%d", usage.StructuralUnits, MaxConfigTopologyUnits, usage.DerivedStringBytes, MaxConfigDerivedStringBytes)
		})
	}
}

func makeRouteValues(prefix string, count int) []string {
	values := make([]string, count)
	width := len(fmt.Sprintf("%d", max(0, count-1)))
	for index := range values {
		values[index] = fmt.Sprintf("%s%0*d", prefix, width, index)
	}
	return values
}

func quadraticNonOverlappingOracle(paths []string) error {
	sort.Strings(paths)
	for left := range paths {
		for right := left + 1; right < len(paths); right++ {
			leftPath := strings.TrimSuffix(paths[left], "/")
			rightPath := strings.TrimSuffix(paths[right], "/")
			if leftPath == rightPath || strings.HasPrefix(leftPath, rightPath+"/") || strings.HasPrefix(rightPath, leftPath+"/") {
				return fmt.Errorf("repo paths overlap: %q and %q", paths[left], paths[right])
			}
		}
	}
	return nil
}

func quadraticPublicOwnershipOracle(prefixes []publicPrefixOwner, rootKeyOwners map[string]string) error {
	sort.Slice(prefixes, func(left, right int) bool {
		if prefixes[left].path == prefixes[right].path {
			return prefixes[left].repo < prefixes[right].repo
		}
		return prefixes[left].path < prefixes[right].path
	})
	for left := range prefixes {
		for right := left + 1; right < len(prefixes); right++ {
			if prefixes[left].path == prefixes[right].path || strings.HasPrefix(prefixes[left].path, prefixes[right].path+"/") || strings.HasPrefix(prefixes[right].path, prefixes[left].path+"/") {
				return fmt.Errorf("public repo prefixes overlap: repo %q owns %q and repo %q owns %q", prefixes[left].repo, prefixes[left].path, prefixes[right].repo, prefixes[right].path)
			}
		}
	}
	for _, key := range sortedStringMapKeys(rootKeyOwners) {
		for _, prefix := range prefixes {
			if key == prefix.path || strings.HasPrefix(key, prefix.path+"/") {
				return fmt.Errorf("public root exact key %q from repo %q conflicts with prefix %q from repo %q", key, rootKeyOwners[key], prefix.path, prefix.repo)
			}
		}
	}
	return nil
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
