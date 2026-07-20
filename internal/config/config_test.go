package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestExampleConfigMatchesSchema(t *testing.T) {
	f, err := os.Open("../../sow.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := Decode(f); err != nil {
		t.Fatalf("example config is invalid: %v", err)
	}
}

func TestDecodeRejectsOversizedConfigBeforeYAMLParsing(t *testing.T) {
	input := strings.NewReader(strings.Repeat("#", MaxConfigBytes+4096))
	if _, err := Decode(input); err == nil || !strings.Contains(err.Error(), "config exceeds 8388608-byte safety limit") {
		t.Fatalf("oversized configuration error = %v", err)
	}
	if want := 4095; input.Len() != want {
		t.Fatalf("oversized configuration consumed %d bytes; want exactly limit+1", MaxConfigBytes+4096-input.Len())
	}
}

func TestDecodePrefersOversizeErrorWhenSentinelReadAlsoFails(t *testing.T) {
	input := &terminalErrorReader{remaining: MaxConfigBytes + 1, terminal: errors.New("terminal read failure")}
	if _, err := Decode(input); err == nil || err.Error() != "config exceeds 8388608-byte safety limit" {
		t.Fatalf("sentinel read error precedence = %v", err)
	}
}

func TestDecodeRejectsCanonicalExpansionBeyondLimit(t *testing.T) {
	input := strings.Replace(validYAML(""), "    asset: {kind: bin}", "    include: []\n    asset: {kind: bin}", 1)
	padding := MaxConfigBytes - len(input)
	if padding <= 0 {
		t.Fatalf("canonical expansion fixture base=%d", len(input))
	}
	input = strings.Replace(input, "include: []", "include: ["+strings.Repeat("a", padding)+"]", 1)
	if len(input) != MaxConfigBytes {
		t.Fatalf("canonical expansion fixture size=%d want=%d", len(input), MaxConfigBytes)
	}
	if _, err := Decode(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), "canonical config exceeds 8388608-byte safety limit") {
		t.Fatalf("canonical expansion error = %v", err)
	}
}

func TestDecodeAcceptsValidConfigAtSizeLimit(t *testing.T) {
	input := []byte(validYAML(""))
	padding := MaxConfigBytes - len(input)
	if padding < 2 {
		t.Fatalf("test config unexpectedly exceeds boundary: %d bytes", len(input))
	}
	input = append(input, '\n', '#')
	input = append(input, bytes.Repeat([]byte{'x'}, padding-2)...)
	if len(input) != MaxConfigBytes {
		t.Fatalf("boundary fixture size=%d want=%d", len(input), MaxConfigBytes)
	}
	if _, err := Decode(bytes.NewReader(input)); err != nil {
		t.Fatalf("valid configuration at size limit was rejected: %v", err)
	}
}

type terminalErrorReader struct {
	remaining int
	terminal  error
}

func (r *terminalErrorReader) Read(destination []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	count := min(len(destination), r.remaining)
	for index := 0; index < count; index++ {
		destination[index] = '#'
	}
	r.remaining -= count
	if r.remaining == 0 {
		return count, r.terminal
	}
	return count, nil
}

func TestShippedPGDGUpstreamExampleMatchesSchema(t *testing.T) {
	f, err := os.Open("../../docs/examples/sow-pgdg.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cfg, err := Decode(f)
	if err != nil {
		t.Fatalf("PGDG upstream example is invalid: %v", err)
	}
	if len(cfg.Upstreams) != 2 || len(cfg.Targets) != 0 {
		t.Fatalf("PGDG example upstreams=%d targets=%d", len(cfg.Upstreams), len(cfg.Targets))
	}
	want := map[string]struct {
		typeName string
		repo     string
		keyring  string
	}{
		"pgdg-apt": {typeName: "apt", repo: "apt-pgdg", keyring: "keys/pgdg-apt.asc"},
		"pgdg-yum": {typeName: "yum", repo: "yum-pgdg", keyring: "keys/pgdg-yum.asc"},
	}
	for _, upstream := range cfg.Upstreams {
		expected, exists := want[upstream.ID]
		if !exists || upstream.Type != expected.typeName || upstream.Repo != expected.repo || upstream.Keyring != expected.keyring || !strings.HasPrefix(upstream.URL, "https://") {
			t.Fatalf("unexpected PGDG upstream: %#v", upstream)
		}
		delete(want, upstream.ID)
	}
	if len(want) != 0 {
		t.Fatalf("PGDG example omitted upstreams: %v", want)
	}
	aptRepo, exists := cfg.RepoByName("apt-pgdg")
	if !exists || len(aptRepo.APT.Suites) != 10 {
		t.Fatalf("PGDG sparse APT fixture suites=%d exists=%v", len(aptRepo.APT.Suites), exists)
	}
	for _, suite := range aptRepo.APT.Suites {
		components := strings.Join(aptRepo.APT.ComponentsForSuite(suite), ",")
		if strings.HasSuffix(suite, "-testing") {
			if components != "main,18,19" {
				t.Fatalf("testing suite %s components=%q", suite, components)
			}
		} else if components != "main" {
			t.Fatalf("stable suite %s components=%q", suite, components)
		}
		wantLifecycle := "active"
		if strings.HasPrefix(suite, "bullseye-") {
			wantLifecycle = "frozen"
		}
		if got := aptRepo.LifecycleForSuite(suite); got != wantLifecycle {
			t.Fatalf("suite %s lifecycle=%q want=%q", suite, got, wantLifecycle)
		}
	}
}

func TestRepoGroupsAreFlatCanonicalPhysicalSets(t *testing.T) {
	repos := `
  - {id: asset-a, type: asset, path: a, default_pool: public, asset: {kind: test}}
  - {id: asset-b, type: asset, path: b, default_pool: public, asset: {kind: test}}`
	withGroups := func(groups string) string {
		return strings.Replace(validYAML(repos), "upstreams: []", "repo_groups:\n"+groups+"\nupstreams: []", 1)
	}
	cfg, err := Decode(strings.NewReader(withGroups("  all-assets: [asset-b, asset-a]")))
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := cfg.ExpandRepoSelectors([]string{"all-assets", "asset-b"})
	if err != nil || strings.Join(expanded, ",") != "asset-a,asset-b" {
		t.Fatalf("expanded=%v err=%v", expanded, err)
	}
	if strings.Join(cfg.RepoGroups["all-assets"], ",") != "asset-a,asset-b" {
		t.Fatalf("group was not canonicalized: %v", cfg.RepoGroups)
	}
	baseSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		t.Fatal(err)
	}
	changed, err := Decode(strings.NewReader(withGroups("  all-assets: [asset-a]")))
	if err != nil {
		t.Fatal(err)
	}
	changedSHA, err := changed.CanonicalSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if baseSHA == changedSHA {
		t.Fatal("canonical config SHA did not bind repo group membership")
	}
	if _, err := cfg.ExpandRepoSelectors([]string{"missing"}); err == nil {
		t.Fatal("unknown runtime repo selector was accepted")
	}

	tests := []struct {
		name   string
		groups string
		want   string
	}{
		{name: "empty", groups: "  empty: []", want: "at least one"},
		{name: "duplicate", groups: "  dup: [asset-a, asset-a]", want: "duplicate"},
		{name: "unknown", groups: "  unknown: [asset-c]", want: "unknown physical repo"},
		{name: "collision", groups: "  asset-a: [asset-b]", want: "collides"},
		{name: "nested", groups: "  inner: [asset-a]\n  outer: [inner]", want: "nested group"},
		{name: "invalid name", groups: "  BadGroup: [asset-a]", want: "must match"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(withGroups(test.groups)))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid groups accepted or misclassified: %v", err)
			}
		})
	}
}

func TestAPTSuiteComponentsAndLifecycleAreExact(t *testing.T) {
	repo := `
  - id: apt-pgdg
    type: apt
    path: apt/pgdg
    os: {family: debian, lifecycle: active}
    arches: [amd64]
    default_pool: public
    apt:
      suites: [bookworm-pgdg, bookworm-pgdg-testing]
      components: [main, "18", "19"]
      suite_components:
        bookworm-pgdg: [main]
        bookworm-pgdg-testing: [main, "18", "19"]
      suite_lifecycle:
        bookworm-pgdg: frozen
        bookworm-pgdg-testing: active`
	cfg, err := Decode(strings.NewReader(validYAML(repo)))
	if err != nil {
		t.Fatal(err)
	}
	apt := cfg.Repos[0].APT
	if apt.HasComponent("bookworm-pgdg", "18") || !apt.HasComponent("bookworm-pgdg-testing", "18") {
		t.Fatalf("suite component closure is not exact: %#v", apt.SuiteComponents)
	}
	if got := cfg.Repos[0].LifecycleForSuite("bookworm-pgdg"); got != "frozen" {
		t.Fatalf("suite lifecycle=%q", got)
	}
	narrow := apt.NarrowSuites([]string{"bookworm-pgdg"})
	if strings.Join(narrow.Components, ",") != "main" || len(narrow.SuiteComponents) != 1 || len(narrow.SuiteLifecycle) != 1 {
		t.Fatalf("narrow suite contract widened or aliased: %#v", narrow)
	}
	narrow.SuiteComponents["bookworm-pgdg"][0] = "mutated"
	if apt.SuiteComponents["bookworm-pgdg"][0] != "main" {
		t.Fatal("narrow suite component map aliases canonical config")
	}
	withUpstreams := strings.Replace(validYAML(repo), "upstreams: []", `upstreams:
  - {id: stable, type: apt, repo: apt-pgdg, url: "https://apt.example.invalid/", suite: bookworm-pgdg, arches: [amd64], debuginfo: drop, keyring: keys/pgdg.asc}
  - {id: testing, type: apt, repo: apt-pgdg, url: "https://apt.example.invalid/", suite: bookworm-pgdg-testing, arches: [amd64], debuginfo: drop, keyring: keys/pgdg.asc}`, 1)
	upstreamConfig, err := Decode(strings.NewReader(withUpstreams))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(upstreamConfig.Upstreams[0].Components, ",") != "main" || strings.Join(upstreamConfig.Upstreams[1].Components, ",") != "main,18,19" {
		t.Fatalf("upstream defaults ignored suite matrix: %+v", upstreamConfig.Upstreams)
	}
	invalidUpstream := strings.Replace(withUpstreams, "suite: bookworm-pgdg, arches:", "suite: bookworm-pgdg, components: [\"18\"], arches:", 1)
	if _, err := Decode(strings.NewReader(invalidUpstream)); err == nil || !strings.Contains(err.Error(), "suite bookworm-pgdg") {
		t.Fatalf("stable upstream accepted testing-only component: %v", err)
	}

	replace := func(old, replacement string) string {
		return strings.Replace(repo, old, replacement, 1)
	}
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "missing component suite", yaml: replace("        bookworm-pgdg-testing: [main, \"18\", \"19\"]\n", ""), want: "cover every configured suite"},
		{name: "empty component map", yaml: strings.Replace(repo, "      suite_components:\n        bookworm-pgdg: [main]\n        bookworm-pgdg-testing: [main, \"18\", \"19\"]", "      suite_components: {}", 1), want: "cover every configured suite"},
		{name: "null component map", yaml: strings.Replace(repo, "      suite_components:\n        bookworm-pgdg: [main]\n        bookworm-pgdg-testing: [main, \"18\", \"19\"]", "      suite_components: null", 1), want: "cover every configured suite"},
		{name: "extra component suite", yaml: strings.Replace(repo, "        bookworm-pgdg-testing: [main, \"18\", \"19\"]", "        bookworm-pgdg-testing: [main, \"18\", \"19\"]\n        trixie-pgdg: [main]", 1), want: "cover every configured suite"},
		{name: "empty component suite", yaml: replace("bookworm-pgdg: [main]", "bookworm-pgdg: []"), want: "at least one component"},
		{name: "duplicate component", yaml: replace("bookworm-pgdg: [main]", "bookworm-pgdg: [main, main]"), want: "duplicate"},
		{name: "component outside union", yaml: replace("bookworm-pgdg: [main]", "bookworm-pgdg: [contrib]"), want: "outside apt.components"},
		{name: "union mismatch", yaml: replace("bookworm-pgdg-testing: [main, \"18\", \"19\"]", "bookworm-pgdg-testing: [main, \"18\"]"), want: "union must equal"},
		{name: "missing lifecycle", yaml: replace("        bookworm-pgdg-testing: active", ""), want: "cover every configured suite"},
		{name: "empty lifecycle map", yaml: strings.Replace(repo, "      suite_lifecycle:\n        bookworm-pgdg: frozen\n        bookworm-pgdg-testing: active", "      suite_lifecycle: {}", 1), want: "cover every configured suite"},
		{name: "null lifecycle map", yaml: strings.Replace(repo, "      suite_lifecycle:\n        bookworm-pgdg: frozen\n        bookworm-pgdg-testing: active", "      suite_lifecycle: null", 1), want: "cover every configured suite"},
		{name: "extra lifecycle", yaml: strings.Replace(repo, "        bookworm-pgdg-testing: active", "        bookworm-pgdg-testing: active\n        trixie-pgdg: active", 1), want: "cover every configured suite"},
		{name: "invalid lifecycle", yaml: replace("bookworm-pgdg: frozen", "bookworm-pgdg: retired"), want: "must be active or frozen"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(validYAML(test.yaml)))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid suite contract accepted or misclassified: %v", err)
			}
		})
	}
}

func TestPigstyV1MigrationFixtureRetainsLegacyPGSQLPartitions(t *testing.T) {
	f, err := os.Open("../../docs/migration/fixtures/pigsty-v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cfg, err := Decode(f)
	if err != nil {
		t.Fatalf("Pigsty-v1 migration fixture is invalid: %v", err)
	}
	if len(cfg.Targets) != 0 || cfg.GPG.PrivateKey != "" || cfg.GPG.Passphrase != "" {
		t.Fatal("migration fixture contains a cloud target or signing secret")
	}
	wantAPT := map[string]string{
		"apt-pgsql-focal": "focal", "apt-pgsql-jammy": "jammy", "apt-pgsql-noble": "noble",
		"apt-pgsql-resolute": "resolute", "apt-pgsql-bullseye": "bullseye",
		"apt-pgsql-bookworm": "bookworm", "apt-pgsql-trixie": "trixie",
	}
	wantYUM := map[string]int{"yum-pgsql-el7": 7, "yum-pgsql-el8": 8, "yum-pgsql-el9": 9, "yum-pgsql-el10": 10}
	for id, suite := range wantAPT {
		repo, exists := cfg.RepoByName(id)
		if !exists || repo.Type != "apt" || len(repo.APT.Suites) != 1 || repo.APT.Suites[0] != suite || repo.Path != "apt/pgsql/"+suite {
			t.Fatalf("APT partition %s=%+v exists=%v", id, repo, exists)
		}
	}
	for id, major := range wantYUM {
		repo, exists := cfg.RepoByName(id)
		if !exists || repo.Type != "yum" || repo.OS.Major != major || repo.Path != "yum/pgsql/el"+strconv.Itoa(major)+".{arch}" {
			t.Fatalf("YUM partition %s=%+v exists=%v", id, repo, exists)
		}
	}
}

func TestLegacySelectorMatrixFixtureMatchesSchema(t *testing.T) {
	f, err := os.Open("../../docs/migration/fixtures/selector-matrix.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cfg, err := Decode(f)
	if err != nil {
		t.Fatalf("legacy selector matrix is invalid: %v", err)
	}
	if len(cfg.Repos) != 33 || len(cfg.Targets) != 2 {
		t.Fatalf("selector matrix repos=%d targets=%d", len(cfg.Repos), len(cfg.Targets))
	}
}

func TestAssetPublicProjectionAndTargetAffinityAreCanonical(t *testing.T) {
	repos := `
  - id: root-compat
    type: asset
    path: compatibility/root
    default_pool: public
    publish_targets: [cf]
    asset:
      kind: bootstrap
      public_path: .
      root_keys: [pkg, get]
      mutable_paths: [pkg]
  - id: pig-release
    type: asset
    path: compatibility/pig
    default_pool: public
    publish_targets: [cos]
    asset: {kind: release, public_path: pkg/pig}`
	cfg, err := Decode(strings.NewReader(withProjectionTargets(validYAML(repos))))
	if err != nil {
		t.Fatal(err)
	}
	root := cfg.Repos[0]
	child := cfg.Repos[1]
	if root.AssetPublicRoot() != "." || strings.Join(root.Asset.RootKeys, ",") != "get,pkg" || strings.Join(root.Asset.MutablePaths, ",") != "pkg" {
		t.Fatalf("root projection was not canonicalized: %#v", root.Asset)
	}
	if !root.PublishesToTarget("cf") || root.PublishesToTarget("cos") || child.PublishesToTarget("cf") || !child.PublishesToTarget("cos") {
		t.Fatalf("target affinity mismatch: root=%v child=%v", root.PublishTargets, child.PublishTargets)
	}
	if child.AssetPublicRoot() != "pkg/pig" {
		t.Fatalf("child public root=%q", child.AssetPublicRoot())
	}

	canonical, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonical, []byte("public_path: .")) || !bytes.Contains(canonical, []byte("publish_targets:")) || !bytes.Contains(canonical, []byte("root_keys:")) {
		t.Fatalf("canonical YAML omitted projection/affinity contract:\n%s", canonical)
	}
	roundTrip, err := Decode(bytes.NewReader(canonical))
	if err != nil {
		t.Fatalf("canonical projection did not round-trip: %v\n%s", err, canonical)
	}
	firstSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		t.Fatal(err)
	}
	roundTripSHA, err := roundTrip.CanonicalSHA256()
	if err != nil || firstSHA != roundTripSHA {
		t.Fatalf("round-trip SHA=%q want=%q err=%v", roundTripSHA, firstSHA, err)
	}

	mapped, err := Decode(strings.NewReader(strings.Replace(withProjectionTargets(validYAML(repos)), "public_path: pkg/pig", "public_path: pkg/tool", 1)))
	if err != nil {
		t.Fatal(err)
	}
	mappedSHA, _ := mapped.CanonicalSHA256()
	if firstSHA == mappedSHA {
		t.Fatal("canonical SHA did not bind asset public_path")
	}
	affinity, err := Decode(strings.NewReader(strings.Replace(withProjectionTargets(validYAML(repos)), "publish_targets: [cf]", "publish_targets: [cos]", 1)))
	if err != nil {
		t.Fatal(err)
	}
	affinitySHA, _ := affinity.CanonicalSHA256()
	if firstSHA == affinitySHA {
		t.Fatal("canonical SHA did not bind repo publish_targets")
	}

	defaultCfg, err := Decode(strings.NewReader(withProjectionTargets(validYAML(""))))
	if err != nil {
		t.Fatal(err)
	}
	defaultRepo := defaultCfg.Repos[0]
	if defaultRepo.AssetPublicRoot() != "bin" || !defaultRepo.PublishesToTarget("cf") || !defaultRepo.PublishesToTarget("cos") {
		t.Fatalf("compatibility defaults changed: public=%q targets=%v", defaultRepo.AssetPublicRoot(), defaultRepo.PublishTargets)
	}
	explicitDefault, err := Decode(strings.NewReader(withProjectionTargets(strings.Replace(validYAML(""), "asset: {kind: bin}", "asset: {kind: bin, public_path: bin}", 1))))
	if err != nil {
		t.Fatal(err)
	}
	defaultSHA, _ := defaultCfg.CanonicalSHA256()
	explicitDefaultSHA, _ := explicitDefault.CanonicalSHA256()
	if defaultSHA != explicitDefaultSHA {
		t.Fatal("omitted public_path and its repo.path default have different canonical identities")
	}

	orderedA, err := Decode(strings.NewReader(withProjectionTargets(strings.Replace(validYAML(""), "default_pool: public", "default_pool: public\n    publish_targets: [cos, cf]", 1))))
	if err != nil {
		t.Fatal(err)
	}
	orderedB, err := Decode(strings.NewReader(withProjectionTargets(strings.Replace(validYAML(""), "default_pool: public", "default_pool: public\n    publish_targets: [cf, cos]", 1))))
	if err != nil {
		t.Fatal(err)
	}
	orderedASHA, _ := orderedA.CanonicalSHA256()
	orderedBSHA, _ := orderedB.CanonicalSHA256()
	if orderedASHA != orderedBSHA || strings.Join(orderedA.Repos[0].PublishTargets, ",") != "cf,cos" {
		t.Fatal("publish target set was not canonicalized")
	}
}

func TestAssetPublicProjectionRejectsAmbiguousOrUnsafeOwnership(t *testing.T) {
	rootRepo := `
  - id: root-compat
    type: asset
    path: compatibility/root
    default_pool: public
    asset: {kind: bootstrap, public_path: ., root_keys: [pkg], mutable_paths: [pkg]}`
	tests := []struct {
		name  string
		repos string
		want  string
	}{
		{name: "empty public path", repos: strings.Replace(rootRepo, "public_path: ., root_keys: [pkg], mutable_paths: [pkg]", `public_path: ""`, 1), want: "public_path"},
		{name: "null public path", repos: strings.Replace(rootRepo, "public_path: ., root_keys: [pkg], mutable_paths: [pkg]", "public_path: null", 1), want: "public_path"},
		{name: "unsafe public path", repos: strings.Replace(rootRepo, "public_path: ., root_keys: [pkg], mutable_paths: [pkg]", `public_path: "bad path"`, 1), want: "outside"},
		{name: "glob public path", repos: strings.Replace(rootRepo, "public_path: ., root_keys: [pkg], mutable_paths: [pkg]", `public_path: "pkg/*"`, 1), want: "outside"},
		{name: "non-normal public path", repos: strings.Replace(rootRepo, "public_path: ., root_keys: [pkg], mutable_paths: [pkg]", `public_path: "pkg/../bin"`, 1), want: "normalized"},
		{name: "empty root keys", repos: strings.Replace(rootRepo, "root_keys: [pkg]", "root_keys: []", 1), want: "at least one"},
		{name: "null root keys", repos: strings.Replace(rootRepo, "root_keys: [pkg]", "root_keys: null", 1), want: "at least one"},
		{name: "duplicate root key", repos: strings.Replace(rootRepo, "root_keys: [pkg]", "root_keys: [pkg, pkg]", 1), want: "duplicate"},
		{name: "root key slash", repos: strings.Replace(rootRepo, "root_keys: [pkg]", "root_keys: [pkg/pig]", 1), want: "non-routable"},
		{name: "root key glob", repos: strings.Replace(rootRepo, "root_keys: [pkg]", `root_keys: ["pkg*"]`, 1), want: "non-routable"},
		{name: "root key unsafe", repos: strings.Replace(rootRepo, "root_keys: [pkg]", `root_keys: ["bad key"]`, 1), want: "non-routable"},
		{name: "root key reserved apt", repos: strings.Replace(rootRepo, "root_keys: [pkg]", "root_keys: [apt]", 1), want: "reserved public namespace"},
		{name: "root key reserved control", repos: strings.Replace(rootRepo, "root_keys: [pkg]", "root_keys: [_sow]", 1), want: "reserved public namespace"},
		{name: "root mutable glob", repos: strings.Replace(rootRepo, "mutable_paths: [pkg]", `mutable_paths: ["*"]`, 1), want: "exact route-safe"},
		{name: "root mutable slash", repos: strings.Replace(rootRepo, "mutable_paths: [pkg]", "mutable_paths: [pkg/pig]", 1), want: "exact route-safe"},
		{name: "root mutable outside allowlist", repos: strings.Replace(rootRepo, "mutable_paths: [pkg]", "mutable_paths: [get]", 1), want: "not declared"},
		{name: "root keys on non-root", repos: strings.Replace(rootRepo, "public_path: .", "public_path: compatibility/public", 1), want: "only when public_path is ."},
		{name: "empty root keys on non-root", repos: strings.Replace(strings.Replace(rootRepo, "public_path: .", "public_path: compatibility/public", 1), "root_keys: [pkg]", "root_keys: []", 1), want: "only when public_path is ."},
		{name: "reserved package public path", repos: strings.Replace(rootRepo, "public_path: ., root_keys: [pkg], mutable_paths: [pkg]", "public_path: apt/assets", 1), want: "reserved public namespace"},
		{name: "duplicate root owner", repos: rootRepo + `
  - {id: root-other, type: asset, path: compatibility/other, default_pool: public, asset: {kind: bootstrap, public_path: ., root_keys: [pkg]}}`, want: "owned by both"},
		{name: "same exact and prefix", repos: rootRepo + `
  - {id: pkg-prefix, type: asset, path: compatibility/prefix, default_pool: public, asset: {kind: release, public_path: pkg}}`, want: "conflicts with prefix"},
		{name: "overlapping prefixes", repos: `
  - {id: parent, type: asset, path: physical/parent, default_pool: public, asset: {kind: release, public_path: pkg}}
  - {id: child, type: asset, path: physical/child, default_pool: public, asset: {kind: release, public_path: pkg/pig}}`, want: "public repo prefixes overlap"},
		{name: "target disjoint ownership still conflicts", repos: `
  - {id: cf-owner, type: asset, path: physical/cf, default_pool: public, publish_targets: [cf], asset: {kind: release, public_path: shared}}
  - {id: cos-owner, type: asset, path: physical/cos, default_pool: public, publish_targets: [cos], asset: {kind: release, public_path: shared/child}}`, want: "public repo prefixes overlap"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(withProjectionTargets(validYAML(test.repos))))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid public ownership accepted or misclassified: %v", err)
			}
		})
	}

	for _, misplaced := range []string{
		strings.Replace(validYAML(""), "default_pool: public", "default_pool: public\n    public_path: pkg", 1),
		strings.Replace(validYAML(""), "default_pool: public", "default_pool: public\n    root_keys: [pkg]", 1),
	} {
		if _, err := Decode(strings.NewReader(misplaced)); err == nil || !strings.Contains(err.Error(), "field") {
			t.Fatalf("non-asset projection field was accepted: %v", err)
		}
	}
}

func TestAssetInventoryCarrierIsExplicitInactiveAndNonRoutable(t *testing.T) {
	valid := `
  - id: legacy-bin
    type: asset
    path: bin
    active: false
    default_pool: public
    exclude: [fileauth.txt]
    asset: {kind: inventory, public_path: migration/bin, inventory_carrier: true}`
	cfg, err := Decode(strings.NewReader(withProjectionTargets(validYAML(valid))))
	if err != nil {
		t.Fatalf("decode inventory carrier: %v", err)
	}
	carrier, exists := cfg.RepoByName("legacy-bin")
	if !exists || carrier.IsActive() || carrier.Asset == nil || !carrier.Asset.InventoryCarrier {
		t.Fatalf("inventory carrier lost its explicit boundary: %+v", carrier)
	}

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "active", yaml: strings.Replace(valid, "active: false", "active: true", 1), want: "requires active=false"},
		{name: "wrong kind", yaml: strings.Replace(valid, "kind: inventory", "kind: release", 1), want: "requires kind=inventory"},
		{name: "root projection", yaml: strings.Replace(valid, "public_path: migration/bin, inventory_carrier: true", "public_path: ., root_keys: [get], inventory_carrier: true", 1), want: "must use a non-root public_path"},
		{name: "mutable", yaml: strings.Replace(valid, "inventory_carrier: true", "mutable_paths: [latest], inventory_carrier: true", 1), want: "may not declare root_keys or mutable_paths"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(withProjectionTargets(validYAML(test.yaml))))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid inventory carrier accepted or misclassified: %v", err)
			}
		})
	}
}

func TestRepoPublishTargetsRejectEmptyUnknownAndDuplicateLists(t *testing.T) {
	base := withProjectionTargets(validYAML(""))
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty", value: "[]", want: "at least one"},
		{name: "null", value: "null", want: "at least one"},
		{name: "duplicate", value: "[cf, cf]", want: "duplicate"},
		{name: "unknown", value: "[missing]", want: "must be cf or cos"},
		{name: "unsafe", value: `["cf*"]`, want: "must be cf or cos"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			yaml := strings.Replace(base, "default_pool: public", "default_pool: public\n    publish_targets: "+test.value, 1)
			_, err := Decode(strings.NewReader(yaml))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid target affinity accepted or misclassified: %v", err)
			}
		})
	}
	for _, target := range []string{"cf", "cos"} {
		yaml := strings.Replace(validYAML(""), "default_pool: public", "default_pool: public\n    publish_targets: ["+target+"]", 1)
		cfg, err := Decode(strings.NewReader(yaml))
		if err != nil || len(cfg.Targets) != 0 || !cfg.Repos[0].PublishesToTarget(target) {
			t.Fatalf("frozen affinity %s with targets:{} cfg=%#v err=%v", target, cfg, err)
		}
	}

	aptRepo := `
  - id: apt-main
    type: apt
    path: apt/main
    os: {family: debian, lifecycle: active}
    arches: [amd64]
    default_pool: public
    publish_targets: [cos]
    apt: {suites: [bookworm], components: [main]}`
	cfg, err := Decode(strings.NewReader(withProjectionTargets(validYAML(aptRepo))))
	if err != nil {
		t.Fatalf("repo-level target affinity was rejected for non-asset repo: %v", err)
	}
	if cfg.Repos[0].PublishesToTarget("cf") || !cfg.Repos[0].PublishesToTarget("cos") {
		t.Fatalf("APT target affinity mismatch: %v", cfg.Repos[0].PublishTargets)
	}
}

func TestDecodeRejectsAliasesAndMergeKeysBeforePresenceDefaults(t *testing.T) {
	base := validYAML("")
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "merged null publish targets",
			yaml: strings.Replace(base, "    default_pool: public", "    <<: {publish_targets: null}\n    default_pool: public", 1),
			want: "YAML merge keys (<<) are not allowed",
		},
		{
			name: "aliased empty publish targets",
			yaml: strings.Replace(base, "    default_pool: public", "    include: &empty_targets []\n    default_pool: public\n    publish_targets: *empty_targets", 1),
			want: "YAML aliases are not allowed",
		},
		{
			name: "merged null public path",
			yaml: strings.Replace(base, "    asset: {kind: bin}", "    asset:\n      <<: {public_path: null}\n      kind: bin", 1),
			want: "YAML merge keys (<<) are not allowed",
		},
		{
			name: "aliased null public path",
			yaml: strings.Replace(
				strings.Replace(base, "    default_pool: public", "    active: &null_public_path null\n    default_pool: public", 1),
				"    asset: {kind: bin}", "    asset: {kind: bin, public_path: *null_public_path}", 1,
			),
			want: "YAML aliases are not allowed",
		},
		{
			name: "merged empty root keys",
			yaml: strings.Replace(base, "    asset: {kind: bin}", "    asset:\n      <<: {root_keys: []}\n      kind: bin", 1),
			want: "YAML merge keys (<<) are not allowed",
		},
		{
			name: "aliased empty root keys",
			yaml: strings.Replace(base, "    asset: {kind: bin}", "    include: &empty_root_keys []\n    asset: {kind: bin, public_path: ., root_keys: *empty_root_keys}", 1),
			want: "YAML aliases are not allowed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(test.yaml))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("alias/merge presence fallback accepted or misclassified: %v", err)
			}
		})
	}
}

func withProjectionTargets(yaml string) string {
	return strings.Replace(yaml, "targets: {}", `targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage-cf.example.invalid", bucket: repo-cf, credential: env://CF_STORAGE}
    cdn: {kind: cloudflare, base_url: "https://repo-cf.example.invalid", beta_base_url: "https://beta-cf.example.invalid", zone_id: zone-cf, credential: env://CF_CDN}
  cos:
    storage: {kind: cos, endpoint: "https://storage-cos.example.invalid", bucket: repo-cos-1250000000, region: ap-shanghai, credential: env://COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cos.example.invalid", beta_base_url: "https://beta-cos.example.invalid", distribution: zone-cos, credential: env://COS_CDN}`, 1)
}

func validYAML(repoBlock string) string {
	if repoBlock == "" {
		repoBlock = `
  - id: asset-bin
    type: asset
    path: bin
    default_pool: public
    asset: {kind: bin}`
	}
	return `schema: sow/v1
state: {}
gpg: {public_key: keys/test-package-trust.asc}
pools:
  public: {}
  gated: {}
repos:` + repoBlock + `
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://pigsty-entitlements
`
}

func TestDecodeAppliesFrozenDefaults(t *testing.T) {
	cfg, err := Decode(strings.NewReader(validYAML("")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Edge.ProPrefix != DefaultProPrefix || cfg.State.SnapshotMaterializationMonths != DefaultSnapshotAge || cfg.State.APTByHashRetention != DefaultAPTByHashRetention || cfg.State.YUMGenerationRetention != DefaultYUMGenerationRetention {
		t.Fatalf("frozen defaults not applied: %#v %#v", cfg.Edge, cfg.State)
	}
}

func TestDecodeRejectsConfigurableSnapshotView(t *testing.T) {
	snapshot := strings.Replace(validYAML(""),
		"  stable: {access: pro, allowed_pools: [public, gated], append_only: true}\n",
		"  stable: {access: pro, allowed_pools: [public, gated], append_only: true}\n  snapshot: {access: public, debuginfo: drop, allowed_pools: [public], append_only: false}\n", 1)
	if _, err := Decode(strings.NewReader(snapshot)); err == nil ||
		!strings.Contains(err.Error(), "views.snapshot is not configurable") ||
		!strings.Contains(err.Error(), "derive") || !strings.Contains(err.Error(), "stable") {
		t.Fatalf("configurable snapshot policy was accepted or misclassified: %v", err)
	}
}

func TestYUMPackageTrustBundleDefaultsAndRejectsUnsafePaths(t *testing.T) {
	repoBlock := `
  - id: yum-main
    type: yum
    path: yum/main
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd}`
	cfg, err := Decode(strings.NewReader(validYAML(repoBlock)))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Repos[0].YUM.PackageKeyring; got != "keys/test-package-trust.asc" {
		t.Fatalf("default package keyring=%q", got)
	}
	explicitEmpty := strings.Replace(validYAML(repoBlock), "yum: {compression: zstd}", "yum: {compression: zstd, package_keyring: ''}", 1)
	cfg, err = Decode(strings.NewReader(explicitEmpty))
	if err != nil || cfg.Repos[0].YUM.PackageKeyring != "keys/test-package-trust.asc" || !cfg.Repos[0].YUM.packageKeyringDefaulted {
		t.Fatalf("explicit-empty package keyring did not preserve default provenance: value=%q defaulted=%t err=%v", cfg.Repos[0].YUM.PackageKeyring, cfg.Repos[0].YUM.packageKeyringDefaulted, err)
	}
	explicit := strings.Replace(validYAML(repoBlock), "yum: {compression: zstd}", "yum: {compression: zstd, package_keyring: keys/vendor-and-pigsty.asc}", 1)
	cfg, err = Decode(strings.NewReader(explicit))
	if err != nil || cfg.Repos[0].YUM.PackageKeyring != "keys/vendor-and-pigsty.asc" {
		t.Fatalf("explicit package keyring=%q err=%v", cfg.Repos[0].YUM.PackageKeyring, err)
	}
	for _, unsafe := range []string{"../outside.asc", "/absolute.asc", `keys\\alternate.asc`} {
		bad := strings.Replace(validYAML(repoBlock), "yum: {compression: zstd}", "yum: {compression: zstd, package_keyring: '"+unsafe+"'}", 1)
		if _, err := Decode(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "package_keyring") {
			t.Errorf("unsafe package keyring %q accepted: %v", unsafe, err)
		}
	}
	missing := strings.Replace(validYAML(repoBlock), "gpg: {public_key: keys/test-package-trust.asc}", "gpg: {}", 1)
	if _, err := Decode(strings.NewReader(missing)); err == nil || !strings.Contains(err.Error(), "package_keyring is required") {
		t.Fatalf("missing package keyring accepted: %v", err)
	}
}

func TestRepositoryPublicTrustRouteRejectsAbsoluteAndEscapingPathsForAPTOnly(t *testing.T) {
	for _, unsafe := range []string{"/etc/pigsty/repository.asc", "../repository.asc", "keys/../repository.asc", "keys/public trust.asc"} {
		unsafe := unsafe
		t.Run(strings.NewReplacer("/", "-", " ", "-").Replace(unsafe), func(t *testing.T) {
			document := strings.Replace(validYAML(`
  - id: apt-main
    type: apt
    path: apt
    default_pool: public
    arches: [amd64]
    os: {family: ubuntu, major: 22, lifecycle: active}
    apt: {suites: [jammy], components: [main]}`), "keys/test-package-trust.asc", unsafe, 1)
			if _, err := Decode(strings.NewReader(document)); err == nil || !strings.Contains(err.Error(), "gpg.public_key") {
				t.Fatalf("unsafe APT-only repository public trust route %q accepted: %v", unsafe, err)
			}
		})
	}
}

func TestYUMNoarchModeDefaultsValidatesAndBindsCanonicalIdentity(t *testing.T) {
	repoBlock := `
  - id: yum-percona-el10
    type: yum
    path: yum/percona/el10.{arch}
    default_pool: public
    arches: [x86_64, aarch64, noarch]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd}`
	implicit, err := Decode(strings.NewReader(validYAML(repoBlock)))
	if err != nil {
		t.Fatal(err)
	}
	if got := implicit.Repos[0].YUM.NoarchMode; got != YUMNoarchReplicate {
		t.Fatalf("implicit noarch mode=%q", got)
	}
	implicitCanonical, err := implicit.Canonical()
	if err != nil || !bytes.Contains(implicitCanonical, []byte("noarch_mode: replicate")) {
		t.Fatalf("canonical default missing noarch mode err=%v\n%s", err, implicitCanonical)
	}

	explicitYAML := strings.Replace(validYAML(repoBlock), "yum: {compression: zstd}", "yum: {compression: zstd, noarch_mode: replicate}", 1)
	explicit, err := Decode(strings.NewReader(explicitYAML))
	if err != nil {
		t.Fatal(err)
	}
	explicitCanonical, err := explicit.Canonical()
	if err != nil || !bytes.Equal(implicitCanonical, explicitCanonical) {
		t.Fatalf("implicit and explicit replicate canonical forms differ err=%v\nimplicit:\n%s\nexplicit:\n%s", err, implicitCanonical, explicitCanonical)
	}
	implicitSHA, _ := implicit.CanonicalSHA256()
	explicitSHA, _ := explicit.CanonicalSHA256()
	if implicitSHA != explicitSHA {
		t.Fatalf("implicit SHA=%s explicit SHA=%s", implicitSHA, explicitSHA)
	}

	separateYAML := strings.Replace(validYAML(repoBlock), "yum: {compression: zstd}", "yum: {compression: zstd, noarch_mode: separate}", 1)
	separate, err := Decode(strings.NewReader(separateYAML))
	if err != nil {
		t.Fatal(err)
	}
	if separate.Repos[0].YUM.NoarchMode != YUMNoarchSeparate {
		t.Fatalf("separate mode=%q", separate.Repos[0].YUM.NoarchMode)
	}
	separateSHA, _ := separate.CanonicalSHA256()
	if separateSHA == implicitSHA {
		t.Fatal("canonical config SHA did not bind YUM noarch routing mode")
	}

	for _, test := range []struct {
		name string
		yaml string
		want string
	}{
		{name: "separate without noarch leaf", yaml: strings.Replace(separateYAML, "[x86_64, aarch64, noarch]", "[x86_64, aarch64]", 1), want: "contain noarch"},
		{name: "unknown mode", yaml: strings.Replace(explicitYAML, "noarch_mode: replicate", "noarch_mode: shared", 1), want: "replicate or separate"},
		{name: "empty mode", yaml: strings.Replace(explicitYAML, "noarch_mode: replicate", `noarch_mode: ""`, 1), want: "replicate or separate"},
		{name: "null mode", yaml: strings.Replace(explicitYAML, "noarch_mode: replicate", "noarch_mode: null", 1), want: "replicate or separate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(test.yaml)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid noarch mode accepted or misclassified: %v", err)
			}
		})
	}
}

func TestServingURLsAreStrictAllOrNothingAndSecretFree(t *testing.T) {
	serving := `serving:
  latest: {base_url: "https://repo.example.invalid/"}
  beta: {base_url: "https://beta.example.invalid/"}
  stable: {base_url: "https://repo.example.invalid/pro/v1/basic/"}
`
	configured := strings.Replace(validYAML(""), "targets: {}\n", serving+"targets: {}\n", 1)
	cfg, err := Decode(strings.NewReader(configured))
	if err != nil {
		t.Fatal(err)
	}
	if latest, _ := cfg.ServingBaseURL("latest"); latest != "https://repo.example.invalid" {
		t.Fatalf("normalized latest serving URL = %q", latest)
	}
	if stable, _ := cfg.ServingBaseURL("stable"); stable != "https://repo.example.invalid/pro/v1/basic" {
		t.Fatalf("normalized stable serving URL = %q", stable)
	}

	partial := strings.Replace(configured, "  beta: {base_url: \"https://beta.example.invalid/\"}\n", "", 1)
	if _, err := Decode(strings.NewReader(partial)); err == nil || !strings.Contains(err.Error(), "configure latest, beta, and stable") {
		t.Fatalf("partial serving contract accepted: %v", err)
	}

	tests := []struct {
		name string
		old  string
		new  string
	}{
		{"userinfo", "https://repo.example.invalid/", "https://token@repo.example.invalid/"},
		{"query", "https://repo.example.invalid/", "https://repo.example.invalid/?token=secret"},
		{"latest path", "https://repo.example.invalid/", "https://repo.example.invalid/token/"},
		{"stable token path", "https://repo.example.invalid/pro/v1/basic/", "https://repo.example.invalid/pro/v1/secret/"},
		{"public plain HTTP", "https://beta.example.invalid/", "http://beta.example.invalid/"},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			candidate := strings.Replace(configured, item.old, item.new, 1)
			if _, err := Decode(strings.NewReader(candidate)); err == nil {
				t.Fatalf("unsafe serving URL accepted: %s", item.new)
			}
		})
	}
}

func TestServingAllowsLoopbackHTTPForRealClientTests(t *testing.T) {
	serving := `serving:
  latest: {base_url: "http://127.0.0.1:18080"}
  beta: {base_url: "http://host.docker.internal:18081"}
  stable: {base_url: "http://[::1]:18082/pro/v1/basic"}
`
	configured := strings.Replace(validYAML(""), "targets: {}\n", serving+"targets: {}\n", 1)
	if _, err := Decode(strings.NewReader(configured)); err != nil {
		t.Fatalf("loopback serving URLs rejected: %v", err)
	}
	evil := strings.Replace(configured, "host.docker.internal:18081", "host.docker.internal.evil:18081", 1)
	if _, err := Decode(strings.NewReader(evil)); err == nil {
		t.Fatal("lookalike Docker bridge HTTP hostname was accepted")
	}
}

func TestDecodeRejectsInvalidAPTByHashRetention(t *testing.T) {
	for _, value := range []string{"0", "-1"} {
		yaml := strings.Replace(validYAML(""), "state: {}", "state: {apt_by_hash_retention: "+value+"}", 1)
		_, err := Decode(strings.NewReader(yaml))
		if err == nil || !strings.Contains(err.Error(), "apt_by_hash_retention must be positive") {
			t.Fatalf("wanted positive APT by-hash retention error for %s, got %v", value, err)
		}
	}
}

func TestDecodeRejectsInvalidYUMGenerationRetention(t *testing.T) {
	for _, value := range []string{"0", "-1"} {
		yaml := strings.Replace(validYAML(""), "state: {}", "state: {yum_generation_retention: "+value+"}", 1)
		_, err := Decode(strings.NewReader(yaml))
		if err == nil || !strings.Contains(err.Error(), "yum_generation_retention must be positive") {
			t.Fatalf("wanted positive YUM generation retention error for %s, got %v", value, err)
		}
	}
}

func TestDecodeRejectsUnknownField(t *testing.T) {
	_, err := Decode(strings.NewReader(validYAML("") + "mystery: true\n"))
	if err == nil || !strings.Contains(err.Error(), "field mystery") {
		t.Fatalf("wanted unknown-field error, got %v", err)
	}
}

func TestDecodeRequiresContractBlocks(t *testing.T) {
	yaml := strings.Replace(validYAML(""), "upstreams: []\n", "", 1)
	_, err := Decode(strings.NewReader(yaml))
	if err == nil {
		t.Fatal("missing upstreams block was accepted")
	}
}

func TestDecodeRejectsLiteralSecretAndOverlap(t *testing.T) {
	yaml := strings.Replace(validYAML(""), "gpg: {public_key: keys/test-package-trust.asc}", "gpg: {public_key: keys/test-package-trust.asc, passphrase: literal-secret}", 1)
	_, err := Decode(strings.NewReader(yaml))
	if err == nil || !strings.Contains(err.Error(), "env://") {
		t.Fatalf("wanted secret-reference error, got %v", err)
	}

	overlap := `
  - id: apt-all
    type: apt
    path: apt
    default_pool: public
    arches: [amd64]
    os: {family: debian, major: 13, suite: trixie, lifecycle: active}
    apt: {suites: [trixie], components: [main]}
  - id: apt-infra
    type: apt
    path: apt/infra
    default_pool: public
    arches: [amd64]
    os: {family: debian, major: 13, suite: trixie, lifecycle: active}
    apt: {suites: [trixie], components: [main]}`
	_, err = Decode(strings.NewReader(validYAML(overlap)))
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("wanted overlap error, got %v", err)
	}
}

func TestDecodeRejectsReservedRepoPathAndChangedPrefix(t *testing.T) {
	reserved := `
  - id: state
    type: asset
    path: data/.sow/files
    default_pool: public
    asset: {kind: data}`
	_, err := Decode(strings.NewReader(validYAML(reserved)))
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("wanted reserved path error, got %v", err)
	}
	servingNamespace := strings.Replace(validYAML(""), "path: bin", "path: _sow/private", 1)
	if _, err := Decode(strings.NewReader(servingNamespace)); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved local serving namespace accepted: %v", err)
	}

	yaml := strings.Replace(validYAML(""), "token_verifier: provider://", "pro_prefix: /other/{token}/\n  token_verifier: provider://", 1)
	_, err = Decode(strings.NewReader(yaml))
	if err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("wanted frozen prefix error, got %v", err)
	}
}

func TestDecodeRejectsNonPOSIXRepoPathAndControlCharacters(t *testing.T) {
	backslash := strings.Replace(validYAML(""), "path: bin", `path: 'bin\escape'`, 1)
	if _, err := Decode(strings.NewReader(backslash)); err == nil || !strings.Contains(err.Error(), "backslash") {
		t.Fatalf("backslash repo path accepted: %v", err)
	}
	for _, value := range []string{"bin/\x00escape", "bin/\x1fescape", "bin/\x7fescape", "bin/\u0085escape"} {
		if err := validateRelativePath(value); err == nil || !strings.Contains(err.Error(), "control") {
			t.Fatalf("control-bearing path %q accepted: %v", value, err)
		}
	}
}

func TestRouteSegmentContractMatchesEdgeSafeVocabulary(t *testing.T) {
	for _, value := range []string{
		"apt", "non-free-firmware", "x86_64", "tool+debug_1.0~rc^2:amd64",
	} {
		if err := ValidateRouteSegment(value); err != nil {
			t.Fatalf("edge-safe segment %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{
		"", ".", "..", "has space", "percent%", "query?", "fragment#",
		"at@", "slash/value", `back\value`, "工具", "line\nbreak",
	} {
		if err := ValidateRouteSegment(value); err == nil {
			t.Fatalf("non-routable segment %q accepted", value)
		}
	}
}

func TestRouteSegmentContractExhaustiveBytes(t *testing.T) {
	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+._~^:-"
	for value := 0; value <= 0xff; value++ {
		candidate := string([]byte{'x', byte(value), 'x'})
		wantSafe := value < 0x80 && strings.ContainsRune(allowed, rune(value))
		err := ValidateRouteSegment(candidate)
		if wantSafe && err != nil {
			t.Fatalf("allowed byte 0x%02x rejected: %v", value, err)
		}
		if !wantSafe && err == nil {
			t.Fatalf("byte 0x%02x outside the frozen edge alphabet accepted", value)
		}
	}
}

func TestCanonicalRouteWirePathAndURL(t *testing.T) {
	t.Parallel()
	const literal = "_sow/v1/g/00000000000000000042/yum/infra^next/x86_64"
	wire, err := EncodeRouteWirePath(literal)
	if err != nil || wire != "_sow/v1/g/00000000000000000042/yum/infra%5Enext/x86_64" {
		t.Fatalf("wire=%q err=%v", wire, err)
	}
	decoded, err := DecodeRouteWirePath(wire)
	if err != nil || decoded != literal {
		t.Fatalf("decoded=%q err=%v", decoded, err)
	}
	for _, alias := range []string{
		"_sow/v1/g/00000000000000000042/yum/infra^next/x86_64",
		"_sow/v1/g/00000000000000000042/yum/infra%5enext/x86_64",
		"_sow/v1/g/00000000000000000042/yum/infra%255Enext/x86_64",
		"_sow/v1/g/00000000000000000042/yum/infra%41next/x86_64",
		"_sow/v1/g/00000000000000000042/yum/infra%2Fnext/x86_64",
		"_sow/v1/g/00000000000000000042/yum/infra%5Enext/x86_64/",
	} {
		if _, err := DecodeRouteWirePath(alias); err == nil {
			t.Fatalf("non-canonical wire path %q was accepted", alias)
		}
	}
	for _, tc := range []struct {
		base, want string
	}{
		{"https://repo.example", "https://repo.example/" + wire + "/"},
		{"https://repo.example/", "https://repo.example/" + wire + "/"},
		{"https://repo.example/pro/v1/basic", "https://repo.example/pro/v1/basic/" + wire + "/"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080/" + wire + "/"},
	} {
		got, err := CanonicalRouteURL(tc.base, literal, true)
		if err != nil || got != tc.want {
			t.Fatalf("base=%q got=%q want=%q err=%v", tc.base, got, tc.want, err)
		}
	}
	for _, unsafe := range []string{"https://user@example.com", "https://repo.example/a/../b", "https://repo.example?x=1"} {
		if _, err := CanonicalRouteURL(unsafe, literal, true); err == nil {
			t.Fatalf("unsafe base %q was accepted", unsafe)
		}
	}
	for _, unsafe := range []string{"_sow/v1/../private", "_sow/v1//private", "_sow/v1/private/", "_sow/v1/%5E"} {
		if _, err := CanonicalRouteURL("https://repo.example", unsafe, true); err == nil {
			t.Fatalf("unsafe literal route %q was accepted", unsafe)
		}
	}
}

func TestDecodeRejectsNonRoutableRepositoryDimensions(t *testing.T) {
	aptRepo := `
  - id: apt-main
    type: apt
    path: apt/main
    default_pool: public
    arches: [amd64]
    os: {family: debian, major: 13, suite: trixie, lifecycle: active}
    apt: {suites: [trixie], components: [main]}`
	yumRepo := `
  - id: yum-main
    type: yum
    path: yum/el9/{arch}
    default_pool: public
    arches: [x86_64, aarch64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd}`
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "expanded repo path",
			yaml: strings.Replace(validYAML(""), "path: bin", `path: "pkg/bad path"`, 1),
			want: "expanded path",
		},
		{
			name: "apt suite",
			yaml: strings.Replace(validYAML(aptRepo), "suites: [trixie]", `suites: ["tri%xie"]`, 1),
			want: "apt.suites",
		},
		{
			name: "apt component",
			yaml: strings.Replace(validYAML(aptRepo), "components: [main]", `components: ["main@debug"]`, 1),
			want: "apt.components",
		},
		{
			name: "package arch",
			yaml: strings.Replace(validYAML(yumRepo), "aarch64]", `"aar ch64"]`, 1),
			want: "arches",
		},
		{
			name: "yum os route",
			yaml: strings.Replace(validYAML(yumRepo), "major: 9, lifecycle", `major: 9, suite: "el@9", lifecycle`, 1),
			want: "repos[0].os",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(test.yaml))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("non-routable configuration accepted or misclassified: %v", err)
			}
		})
	}
}

func TestDecodeAcceptsEdgeSafeRepositoryPathsAndYUMExpansion(t *testing.T) {
	repos := `
  - id: public-assets
    type: asset
    path: pkg/tools+debug_1.0~rc^2:archive
    default_pool: public
    asset: {kind: tools}
  - id: apt-main
    type: apt
    path: apt/infra+extras
    default_pool: public
    arches: [amd64]
    os: {family: debian, major: 13, suite: trixie, lifecycle: active}
    apt: {suites: [trixie], components: [non-free-firmware]}
  - id: yum-main
    type: yum
    path: yum/el9/{arch}
    default_pool: public
    arches: [x86_64, aarch64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd}`
	cfg, err := Decode(strings.NewReader(validYAML(repos)))
	if err != nil {
		t.Fatalf("edge-safe repository configuration rejected: %v", err)
	}
	yum := cfg.Repos[2]
	if got, err := yum.PathForArch("x86_64"); err != nil || got != "yum/el9/x86_64" {
		t.Fatalf("safe YUM expansion=%q err=%v", got, err)
	}
}

func TestDecodeFreezesRepositoryTypePathNamespaces(t *testing.T) {
	tests := []struct {
		name      string
		repoBlock string
		want      string
	}{
		{
			name: "apt outside apt namespace",
			repoBlock: `
  - id: apt-main
    type: apt
    path: repositories/apt
    default_pool: public
    arches: [amd64]
    os: {family: debian, major: 13, suite: trixie, lifecycle: active}
    apt: {suites: [trixie], components: [main]}`,
			want: "apt/ namespace",
		},
		{
			name: "yum outside yum namespace",
			repoBlock: `
  - id: yum-main
    type: yum
    path: repositories/yum
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd}`,
			want: "yum/ namespace",
		},
		{
			name: "asset at apt root",
			repoBlock: `
  - id: asset-apt
    type: asset
    path: apt
    default_pool: public
    asset: {kind: data}`,
			want: "reserved apt/ or yum/",
		},
		{
			name: "asset below yum root",
			repoBlock: `
  - id: asset-yum
    type: asset
    path: yum/Packages/a
    default_pool: public
    asset: {kind: data}`,
			want: "reserved apt/ or yum/",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(validYAML(test.repoBlock)))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("namespace violation accepted: %v", err)
			}
		})
	}

	for _, repoBlock := range []string{
		`
  - id: apt-root
    type: apt
    path: apt
    default_pool: public
    arches: [amd64]
    os: {family: debian, major: 13, suite: trixie, lifecycle: active}
    apt: {suites: [trixie], components: [main]}`,
		`
  - id: yum-root
    type: yum
    path: yum
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd}`,
	} {
		if _, err := Decode(strings.NewReader(validYAML(repoBlock))); err != nil {
			t.Fatalf("valid package namespace root rejected: %v", err)
		}
	}
}

func TestDecodeFreezesEL8AndModernCompression(t *testing.T) {
	el8 := `
  - id: el8
    type: yum
    path: yum/el8
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 8, lifecycle: active}
    yum: {compression: zstd}`
	_, err := Decode(strings.NewReader(validYAML(el8)))
	if err == nil || !strings.Contains(err.Error(), "EL8") || !strings.Contains(err.Error(), EL8FrozenSincePigstyVersion) {
		t.Fatalf("wanted EL8 freeze error, got %v", err)
	}

	el9 := strings.Replace(el8, "id: el8", "id: el9", 1)
	el9 = strings.Replace(el9, "path: yum/el8", "path: yum/el9", 1)
	el9 = strings.Replace(el9, "major: 8", "major: 9", 1)
	el9 = strings.Replace(el9, "lifecycle: active", "lifecycle: active", 1)
	if _, err := Decode(strings.NewReader(validYAML(el9))); err != nil {
		t.Fatalf("valid EL9 rejected: %v", err)
	}
}

func TestDecodeAllowsOnlyLegacyFrozenEL7Gzip(t *testing.T) {
	base := `
  - id: el7
    type: yum
    path: yum/el7
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 7, lifecycle: frozen}
    yum: {compression: gzip}`
	if _, err := Decode(strings.NewReader(validYAML(base))); err != nil {
		t.Fatalf("legacy frozen EL7 gzip rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		yaml string
		want string
	}{
		{name: "active EL7", yaml: strings.Replace(base, "lifecycle: frozen", "lifecycle: active", 1), want: "legacy EL7"},
		{name: "EL7 zstd", yaml: strings.Replace(base, "compression: gzip", "compression: zstd", 1), want: "legacy EL7"},
		{name: "EL6", yaml: strings.Replace(base, "major: 7", "major: 6", 1), want: "only legacy frozen EL7"},
		{name: "EL11", yaml: strings.Replace(base, "major: 7", "major: 11", 1), want: "only legacy frozen EL7"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(validYAML(test.yaml))); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid YUM lifecycle accepted or wrong error: %v", err)
			}
		})
	}
}

func TestCanonicalConfigExcludesRuntimePathsAndIsDeterministic(t *testing.T) {
	cfg, err := Decode(strings.NewReader(validYAML("")))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Path = "/private/work/sow.yaml"
	cfg.Root = "/private/work"
	first, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	second, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("canonical configuration is not deterministic")
	}
	if bytes.Contains(first, []byte("/private/work")) {
		t.Fatalf("canonical configuration leaked runtime paths: %s", first)
	}
	if _, err := cfg.CanonicalSHA256(); err != nil {
		t.Fatal(err)
	}
}

func TestYUMPathTemplatePreservesExplicitLegacyLayout(t *testing.T) {
	repoBlock := `
  - id: infra
    type: yum
    path: yum/infra/{arch}
    default_pool: public
    arches: [x86_64, aarch64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd}`
	cfg, err := Decode(strings.NewReader(validYAML(repoBlock)))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cfg.Repos[0].PathForArch("aarch64"); err != nil || got != "yum/infra/aarch64" {
		t.Fatalf("expanded path=%q err=%v", got, err)
	}
	withoutTemplate := strings.Replace(repoBlock, "yum/infra/{arch}", "yum/infra", 1)
	if _, err := Decode(strings.NewReader(validYAML(withoutTemplate))); err == nil || !strings.Contains(err.Error(), "{arch}") {
		t.Fatalf("multiarch path without template accepted: %v", err)
	}
	assetTemplate := strings.Replace(validYAML(""), "path: bin", "path: bin/{arch}", 1)
	if _, err := Decode(strings.NewReader(assetTemplate)); err == nil || !strings.Contains(err.Error(), "only YUM") {
		t.Fatalf("asset path template accepted: %v", err)
	}
}

func TestAPTUpstreamDefaultsFrozenRepoDimensionsAndRequiresTrust(t *testing.T) {
	repoBlock := `
  - id: apt-main
    type: apt
    path: apt/main
    default_pool: public
    arches: [amd64, arm64]
    os: {family: ubuntu, major: 22, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}`
	yaml := strings.Replace(validYAML(repoBlock), "upstreams: []", `upstreams:
  - id: pgdg
    type: apt
    repo: apt-main
    url: https://apt.example.invalid/pub/repos/apt
    keyring: keys/pgdg.asc`, 1)
	cfg, err := Decode(strings.NewReader(yaml))
	if err != nil {
		t.Fatal(err)
	}
	upstream := cfg.Upstreams[0]
	if upstream.Suite != "jammy" || strings.Join(upstream.Components, ",") != "main" || strings.Join(upstream.Arches, ",") != "amd64,arm64" {
		t.Fatalf("upstream defaults = %#v", upstream)
	}
	withoutTrust := strings.Replace(yaml, "    keyring: keys/pgdg.asc\n", "", 1)
	if _, err := Decode(strings.NewReader(withoutTrust)); err == nil || !strings.Contains(err.Error(), "keyring") {
		t.Fatalf("APT upstream without trust accepted: %v", err)
	}
	mismatch := strings.Replace(yaml, "type: apt\n    repo: apt-main", "type: yum\n    repo: apt-main", 1)
	if _, err := Decode(strings.NewReader(mismatch)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("upstream/repo type mismatch accepted: %v", err)
	}
	for name, unsafeURL := range map[string]string{
		"userinfo":       "https://user:secret@apt.example.invalid/pub/repos/apt",
		"query":          "https://apt.example.invalid/pub/repos/apt?token=secret",
		"empty query":    "https://apt.example.invalid/pub/repos/apt?",
		"fragment":       "https://apt.example.invalid/pub/repos/apt#token",
		"empty fragment": "https://apt.example.invalid/pub/repos/apt#",
		"opaque":         "https:apt.example.invalid/pub/repos/apt",
		"encoded path":   "https://apt.example.invalid/pub/%72epos/apt",
	} {
		t.Run("reject "+name, func(t *testing.T) {
			candidate := strings.Replace(yaml, "https://apt.example.invalid/pub/repos/apt", unsafeURL, 1)
			if _, err := Decode(strings.NewReader(candidate)); err == nil || !strings.Contains(err.Error(), "upstreams[0].url") {
				t.Fatalf("unsafe upstream URL %q accepted: %v", unsafeURL, err)
			}
		})
	}
}

func TestCOSRequiresExplicitNeverVersionedBucketConfirmation(t *testing.T) {
	base := strings.Replace(validYAML(""), "targets: {}", `targets:
  cos:
    storage: {kind: cos, endpoint: "https://cos.example.invalid", bucket: repo-1250000000, region: ap-shanghai, credential: env://COS_STORAGE}
    cdn: {kind: edgeone, base_url: "https://repo.example.invalid", beta_base_url: "https://beta.example.invalid", distribution: zone, credential: env://COS_CDN}`, 1)
	if _, err := Decode(strings.NewReader(base)); err == nil || !strings.Contains(err.Error(), "unversioned_bucket_confirmed") {
		t.Fatalf("unconfirmed COS bucket accepted: %v", err)
	}
	confirmed := strings.Replace(base, "credential: env://COS_STORAGE}", "credential: env://COS_STORAGE, unversioned_bucket_confirmed: true}", 1)
	if _, err := Decode(strings.NewReader(confirmed)); err != nil {
		t.Fatalf("confirmed COS target rejected: %v", err)
	}
}

func TestTargetOriginsAndProviderCoordinatesAreNormalizedAndFailClosed(t *testing.T) {
	base := strings.Replace(validYAML(""), "targets: {}", `targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.example.invalid/", bucket: repo-bucket, credential: env://CF_STORAGE}
    cdn: {kind: cloudflare, base_url: "https://repo.example.invalid/", beta_base_url: "https://beta.example.invalid/", zone_id: zone, credential: env://CF_CDN}`, 1)
	cfg, err := Decode(strings.NewReader(base))
	if err != nil {
		t.Fatal(err)
	}
	target := cfg.Targets["cf"]
	if target.Storage.Region != "auto" || strings.HasSuffix(target.Storage.Endpoint, "/") || strings.HasSuffix(target.CDN.BaseURL, "/") {
		t.Fatalf("target defaults not canonical: %#v", target)
	}
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"same beta host", strings.Replace(base, "https://beta.example.invalid/", "https://repo.example.invalid", 1), "distinct beta"},
		{"unsafe bucket", strings.Replace(base, "bucket: repo-bucket", "bucket: Bad_Bucket", 1), "DNS-safe"},
		{"custom port", strings.Replace(base, "https://storage.example.invalid/", "https://storage.example.invalid:8443", 1), "clean"},
		{"wrong r2 region", strings.Replace(base, "credential: env://CF_STORAGE}", "region: us-east-1, credential: env://CF_STORAGE}", 1), "region"},
		{"missing zone", strings.Replace(base, "zone_id: zone, ", "", 1), "zone_id"},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(item.yaml))
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("unsafe target accepted err=%v", err)
			}
		})
	}
}

func TestStorageDeleteModeDefaultsFailClosedAndAcceptsExplicitCheckpointFence(t *testing.T) {
	base := withProjectionTargets(validYAML(""))
	defaults, err := Decode(strings.NewReader(base))
	if err != nil {
		t.Fatal(err)
	}
	for _, targetName := range []string{"cf", "cos"} {
		if got := defaults.Targets[targetName].Storage.DeleteMode; got != StorageDeleteConditional {
			t.Fatalf("target %s delete_mode=%q want=%q", targetName, got, StorageDeleteConditional)
		}
	}

	explicitYAML := strings.Replace(base,
		"bucket: repo-cf, credential:",
		"bucket: repo-cf, delete_mode: checkpoint-fenced, credential:", 1)
	explicit, err := Decode(strings.NewReader(explicitYAML))
	if err != nil {
		t.Fatalf("explicit checkpoint-fenced mode rejected: %v", err)
	}
	if got := explicit.Targets["cf"].Storage.DeleteMode; got != StorageDeleteCheckpointFenced {
		t.Fatalf("explicit delete_mode=%q", got)
	}
	canonical, err := explicit.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonical, []byte("delete_mode: checkpoint-fenced")) {
		t.Fatalf("canonical config omitted explicit delete mode:\n%s", canonical)
	}

	invalidYAML := strings.Replace(base,
		"bucket: repo-cf, credential:",
		"bucket: repo-cf, delete_mode: unsafe-unconditional, credential:", 1)
	if _, err := Decode(strings.NewReader(invalidYAML)); err == nil || !strings.Contains(err.Error(), "storage.delete_mode") {
		t.Fatalf("invalid delete mode accepted or misclassified: %v", err)
	}
}

func TestServingBaseURLLengthIsBoundedBeforePublicationState(t *testing.T) {
	tooLong := "https://" + strings.Repeat("a", MaxServingBaseURLBytes) + ".invalid"
	if err := ValidateServingBaseURL(tooLong, ""); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("overlong serving base URL accepted: %v", err)
	}
}
