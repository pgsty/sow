package config

import (
	"strings"
	"testing"
)

func TestDecodeYUMCompatibilityProjectionsAreCanonicalAndSHA256Bound(t *testing.T) {
	repos := `
  - id: infra-el9
    type: yum
    path: yum/infra/el9/{arch}
    default_pool: public
    arches: [aarch64, x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd}
  - id: infra-el10
    type: yum
    path: yum/infra/el10/{arch}
    default_pool: public
    arches: [aarch64, x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd}
  - id: infra-carrier
    type: yum
    path: yum/infra/{arch}
    active: false
    default_pool: public
    arches: [aarch64, x86_64]
    os: {family: cross-el, major: 0, lifecycle: frozen}
    yum: {compression: gzip, compatibility_carrier: true}`
	commitA, commitB := strings.Repeat("a", 40), strings.Repeat("b", 40)
	block := func(reverse bool, secondCommit string) string {
		first := "  - {id: infra-legacy-aarch64, root: yum/infra/aarch64, mode: frozen-cross-el, carrier: infra-carrier, source: {repo: infra-el9, view: latest, os: cross-el, arch: aarch64, commit: " + commitA + "}}\n"
		second := "  - {id: infra-legacy-x86-64, root: yum/infra/x86_64, mode: frozen-cross-el, carrier: infra-carrier, source: {repo: infra-el10, view: latest, os: cross-el, arch: x86_64, commit: " + secondCommit + "}}\n"
		if reverse {
			first, second = second, first
		}
		return strings.Replace(validYAML(repos), "upstreams: []", "compatibility_projections:\n"+first+second+"upstreams: []", 1)
	}
	left, err := Decode(strings.NewReader(block(false, commitB)))
	if err != nil {
		t.Fatal(err)
	}
	right, err := Decode(strings.NewReader(block(true, commitB)))
	if err != nil {
		t.Fatal(err)
	}
	if len(left.CompatibilityProjections) != 2 || left.CompatibilityProjections[0].ID != "infra-legacy-aarch64" || right.CompatibilityProjections[0].ID != "infra-legacy-aarch64" {
		t.Fatalf("compatibility projections were not canonicalized: left=%+v right=%+v", left.CompatibilityProjections, right.CompatibilityProjections)
	}
	leftSHA, err := left.CanonicalSHA256()
	if err != nil {
		t.Fatal(err)
	}
	rightSHA, err := right.CanonicalSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if leftSHA != rightSHA {
		t.Fatalf("equivalent projection order changed canonical SHA: %s != %s", leftSHA, rightSHA)
	}
	changed, err := Decode(strings.NewReader(block(false, strings.Repeat("c", 40))))
	if err != nil {
		t.Fatal(err)
	}
	changedSHA, err := changed.CanonicalSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if changedSHA == leftSHA {
		t.Fatal("pinned compatibility source commit did not change canonical SHA")
	}
	for _, declaration := range []string{"compatibility_projections: []\n", "compatibility_projections: null\n"} {
		invalid := strings.Replace(validYAML(repos), "upstreams: []", declaration+"upstreams: []", 1)
		if _, err := Decode(strings.NewReader(invalid)); err == nil || !strings.Contains(err.Error(), "non-empty sequence") {
			t.Fatalf("empty compatibility declaration was accepted: %v", err)
		}
	}
}

func TestValidateYUMCompatibilityProjectionsFreezesExplicitLeafOwnership(t *testing.T) {
	repos := []Repo{
		{ID: "infra-el9", Type: "yum", Path: "yum/infra/el9/{arch}", DefaultPool: "public", OS: OSConfig{Family: "el", Major: 9, Lifecycle: "active"}, Arches: []string{"aarch64", "x86_64"}, YUM: &YUMConfig{Compression: "zstd"}},
		{ID: "infra-el10", Type: "yum", Path: "yum/infra/el10/{arch}", DefaultPool: "public", OS: OSConfig{Family: "el", Major: 10, Lifecycle: "active"}, Arches: []string{"aarch64", "x86_64"}, YUM: &YUMConfig{Compression: "zstd"}},
		{ID: "infra-carrier", Type: "yum", Path: "yum/infra/{arch}", Active: configTestBoolPointer(false), DefaultPool: "public", OS: OSConfig{Family: "cross-el", Major: 0, Lifecycle: "frozen"}, Arches: []string{"aarch64", "x86_64"}, YUM: &YUMConfig{Compression: "gzip", CompatibilityCarrier: true}},
	}
	views := map[string]View{"latest": {Access: "public", Repos: []string{"infra-el9", "infra-el10"}}}
	commit := strings.Repeat("a", 40)
	projections := []YUMCompatibilityProjection{
		{ID: "infra-legacy-aarch64", Root: "yum/infra/aarch64", Mode: YUMCompatibilityModeFrozenCrossEL, Carrier: "infra-carrier", Source: YUMCompatibilitySource{Repo: "infra-el9", View: "latest", OS: "cross-el", Arch: "aarch64", Commit: commit}},
		{ID: "infra-legacy-x86-64", Root: "yum/infra/x86_64", Mode: YUMCompatibilityModeFrozenCrossEL, Carrier: "infra-carrier", Source: YUMCompatibilitySource{Repo: "infra-el10", View: "latest", OS: "cross-el", Arch: "x86_64", Commit: commit}},
	}
	if err := ValidateYUMCompatibilityProjections(projections, repos, nil, views); err != nil {
		t.Fatalf("valid explicit compatibility leaves rejected: %v", err)
	}
	got, exists, err := YUMCompatibilityProjectionForSource(projections, "infra-el9", "latest", "el9", "aarch64")
	if err != nil || !exists || got.ID != "infra-legacy-aarch64" {
		t.Fatalf("source lookup mismatch: got=%+v exists=%t err=%v", got, exists, err)
	}
}

func TestValidateYUMCompatibilityProjectionsRejectsAmbiguousOrMutableContracts(t *testing.T) {
	baseRepo := Repo{ID: "infra-el9", Type: "yum", Path: "yum/infra/el9/{arch}", DefaultPool: "public", OS: OSConfig{Family: "el", Major: 9, Lifecycle: "active"}, Arches: []string{"aarch64", "x86_64"}, YUM: &YUMConfig{Compression: "zstd"}}
	carrierRepo := Repo{ID: "infra-carrier", Type: "yum", Path: "yum/infra/{arch}", Active: configTestBoolPointer(false), DefaultPool: "public", OS: OSConfig{Family: "cross-el", Lifecycle: "frozen"}, Arches: []string{"aarch64", "x86_64"}, YUM: &YUMConfig{Compression: "gzip", CompatibilityCarrier: true}}
	withCarrier := func(repos ...Repo) []Repo { return append(repos, carrierRepo) }
	views := map[string]View{
		"latest": {Access: "public", Repos: []string{"infra-el9"}},
		"stable": {Access: "pro", Repos: []string{"infra-el9"}},
	}
	valid := YUMCompatibilityProjection{ID: "infra-legacy-x86-64", Root: "yum/infra/x86_64", Mode: YUMCompatibilityModeFrozenCrossEL, Carrier: "infra-carrier", Source: YUMCompatibilitySource{Repo: "infra-el9", View: "latest", OS: "cross-el", Arch: "x86_64", Commit: strings.Repeat("a", 40)}}
	frozenRepo := replaceRepo(baseRepo, func(value *Repo) { value.OS.Lifecycle = "frozen" })
	if err := ValidateYUMCompatibilityProjections([]YUMCompatibilityProjection{valid}, withCarrier(frozenRepo), nil, views); err != nil {
		t.Fatalf("EOL-frozen policy owner invalidated immutable compatibility history: %v", err)
	}
	sentinel := replaceCompatibility(valid, func(value *YUMCompatibilityProjection) { value.Source.Commit = YUMCompatibilityPinAtFirstFreeze })
	if err := ValidateYUMCompatibilityProjections([]YUMCompatibilityProjection{sentinel}, withCarrier(baseRepo), nil, views); err != nil {
		t.Fatalf("first-freeze sentinel rejected by schema: %v", err)
	}
	tests := []struct {
		name        string
		projections []YUMCompatibilityProjection
		repos       []Repo
		views       map[string]View
		want        string
	}{
		{name: "templated root", projections: []YUMCompatibilityProjection{replaceCompatibility(valid, func(value *YUMCompatibilityProjection) { value.Root = "yum/infra/{arch}" })}, repos: withCarrier(baseRepo), views: views, want: "exact architecture leaf"},
		{name: "canonical overlap", projections: []YUMCompatibilityProjection{replaceCompatibility(valid, func(value *YUMCompatibilityProjection) { value.Root = "yum/infra/el9/x86_64" })}, repos: withCarrier(baseRepo), views: views, want: "carrier leaf"},
		{name: "mutable view", projections: []YUMCompatibilityProjection{replaceCompatibility(valid, func(value *YUMCompatibilityProjection) { value.Source.View = "stable" })}, repos: withCarrier(baseRepo), views: views, want: "must be latest"},
		{name: "fake source os", projections: []YUMCompatibilityProjection{replaceCompatibility(valid, func(value *YUMCompatibilityProjection) { value.Source.OS = "el10" })}, repos: withCarrier(baseRepo), views: views, want: "must be cross-el"},
		{name: "swapped source arch", projections: []YUMCompatibilityProjection{replaceCompatibility(valid, func(value *YUMCompatibilityProjection) { value.Source.Arch = "aarch64" })}, repos: withCarrier(replaceRepo(baseRepo, func(value *Repo) { value.Arches = []string{"x86_64", "aarch64"} })), views: views, want: "must equal source.arch"},
		{name: "gzip source", projections: []YUMCompatibilityProjection{valid}, repos: withCarrier(replaceRepo(baseRepo, func(value *Repo) { value.YUM = &YUMConfig{Compression: "gzip"} })), views: views, want: "EL9/10 zstd"},
		{name: "gated owner", projections: []YUMCompatibilityProjection{valid}, repos: withCarrier(replaceRepo(baseRepo, func(value *Repo) { value.DefaultPool = "gated" })), views: views, want: "default_pool public"},
		{name: "latest excludes owner", projections: []YUMCompatibilityProjection{valid}, repos: withCarrier(baseRepo), views: map[string]View{"latest": {Access: "public", Repos: []string{"other"}}}, want: "included by"},
		{name: "zero commit", projections: []YUMCompatibilityProjection{replaceCompatibility(valid, func(value *YUMCompatibilityProjection) { value.Source.Commit = strings.Repeat("0", 40) })}, repos: withCarrier(baseRepo), views: views, want: "non-zero"},
		{name: "duplicate source", projections: []YUMCompatibilityProjection{valid, replaceCompatibility(valid, func(value *YUMCompatibilityProjection) { value.ID = "other" })}, repos: withCarrier(baseRepo), views: views, want: "same pinned source leaf"},
		{name: "duplicate root", projections: []YUMCompatibilityProjection{valid, replaceCompatibility(valid, func(value *YUMCompatibilityProjection) {
			value.ID = "other"
			value.Source.Commit = strings.Repeat("b", 40)
		})}, repos: withCarrier(baseRepo), views: views, want: "same pinned source leaf"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateYUMCompatibilityProjections(test.projections, test.repos, nil, test.views)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("wanted %q, got %v", test.want, err)
			}
		})
	}
}

func TestYUMCompatibilityCarrierRequiresCompletePublicRawOwnership(t *testing.T) {
	base := nginxCompatibilityCarrierConfigForTest()
	if _, err := Decode(strings.NewReader(base)); err != nil {
		t.Fatalf("valid complete public carrier rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		old  string
		new  string
		want string
	}{
		{name: "gated pool", old: "    active: false\n    default_pool: public", new: "    active: false\n    default_pool: gated", want: "default_pool public"},
		{name: "include filter", old: "    yum: {compression: gzip, compatibility_carrier: true}", new: "    include: ['**/*.rpm']\n    yum: {compression: gzip, compatibility_carrier: true}", want: "without include/exclude"},
		{name: "exclude filter", old: "    yum: {compression: gzip, compatibility_carrier: true}", new: "    exclude: ['operator/**']\n    yum: {compression: gzip, compatibility_carrier: true}", want: "without include/exclude"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(strings.Replace(base, test.old, test.new, 1)))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsafe carrier accepted or misclassified: %v", err)
			}
		})
	}
}

func nginxCompatibilityCarrierConfigForTest() string {
	return `schema: sow/v1
state: {}
gpg: {public_key: keys/repository.asc}
pools: {public: {}, gated: {}}
repos:
  - id: infra-el9
    type: yum
    path: yum/infra/el9/{arch}
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd}
  - id: infra-carrier
    type: yum
    path: yum/infra/{arch}
    active: false
    default_pool: public
    arches: [x86_64]
    os: {family: cross-el, major: 0, lifecycle: frozen}
    yum: {compression: gzip, compatibility_carrier: true}
compatibility_projections:
  - id: infra-legacy-x86-64
    root: yum/infra/x86_64
    mode: frozen-cross-el
    carrier: infra-carrier
    source: {repo: infra-el9, view: latest, os: cross-el, arch: x86_64, commit: pin-at-first-freeze}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`
}

func replaceCompatibility(value YUMCompatibilityProjection, mutate func(*YUMCompatibilityProjection)) YUMCompatibilityProjection {
	mutate(&value)
	return value
}

func replaceRepo(value Repo, mutate func(*Repo)) Repo {
	mutate(&value)
	return value
}

func configTestBoolPointer(value bool) *bool { return &value }
