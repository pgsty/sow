package cli

import (
	"testing"

	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

func TestL3ExplicitAPTSelectorCannotPassOnAssetOnlyIntent(t *testing.T) {
	apt := config.Repo{
		ID: "apt-test", Type: "apt", Path: "apt/test", Arches: []string{"amd64"},
		APT: &config.APTConfig{Suites: []string{"jammy"}, Components: []string{"main"}},
	}
	asset := config.Repo{
		ID: "assets", Type: "asset", Path: "pkg", Arches: []string{"all"},
		Asset: &config.AssetConfig{Kind: "release"},
	}
	cfg := &config.Config{Views: map[string]config.View{"beta": {Access: "public"}}}
	aptRef, _ := state.ViewRef("beta", apt.ID, "jammy", "amd64")
	assetRef, _ := state.ViewRef("beta", asset.ID, "all", "all")
	generation := pub.TargetGeneration{Refs: []pub.RefState{{Name: aptRef.String()}, {Name: assetRef.String()}}}
	values := commonFlags{repos: csvFlag{items: []string{apt.ID}}, arches: csvFlag{items: []string{"amd64"}}}
	assetOnly := []pub.VerifyObject{{URL: "https://beta.example.invalid/pkg/release"}}

	scoped := scopeL3Expectations(cfg, "cf", "beta", "", generation, assetOnly, nil, []config.Repo{apt}, values)
	if len(scoped.positive) != 0 || len(scoped.absent) != 0 || len(scoped.gaps) != 1 || scoped.gaps[0].code != "REMOTE_PLAN_SELECTOR_COVERAGE_MISSING" {
		t.Fatalf("asset-only intent masqueraded as selected APT L3 coverage: %+v", scoped)
	}

	aptExpectation := pub.VerifyObject{URL: "https://beta.example.invalid/apt/test/dists/jammy/main/binary-amd64/Packages.gz"}
	scoped = scopeL3Expectations(cfg, "cf", "beta", "", generation, append(assetOnly, aptExpectation), nil, []config.Repo{apt}, values)
	if len(scoped.gaps) != 0 || len(scoped.positive) != 1 || scoped.positive[0].URL != aptExpectation.URL {
		t.Fatalf("explicit APT scope retained an unrelated asset or lost its own expectation: %+v", scoped)
	}

	sharedRelease := pub.VerifyObject{URL: "https://beta.example.invalid/apt/test/dists/jammy/InRelease"}
	scoped = scopeL3Expectations(cfg, "cf", "beta", "", generation, []pub.VerifyObject{sharedRelease}, nil, []config.Repo{apt}, values)
	if len(scoped.positive) != 1 || len(scoped.gaps) != 1 || scoped.gaps[0].code != "REMOTE_PLAN_SELECTOR_COVERAGE_MISSING" {
		t.Fatalf("suite-wide InRelease incorrectly substituted for exact APT architecture coverage: %+v", scoped)
	}
}

func TestL3ExplicitYUMSelectorRequiresItsExactChannel(t *testing.T) {
	yum := config.Repo{
		ID: "rpm-test", Type: "yum", Path: "yum/test/{arch}", Arches: []string{"x86_64"},
		OS: config.OSConfig{Family: "el", Major: 9, Suite: "el9"}, YUM: &config.YUMConfig{},
	}
	cfg := &config.Config{Views: map[string]config.View{"latest": {Access: "public"}}}
	ref, _ := state.ViewRef("latest", yum.ID, "el9", "x86_64")
	generation := pub.TargetGeneration{Refs: []pub.RefState{{Name: ref.String()}}}
	values := commonFlags{repos: csvFlag{items: []string{yum.ID}}, oses: csvFlag{items: []string{"el9"}}}
	metadata := pub.VerifyObject{URL: "https://repo.example.invalid/_sow/v1/g/00000000000000000042/yum/test/x86_64/repodata/repomd.xml"}

	scoped := scopeL3Expectations(cfg, "cos", "latest", "", generation, []pub.VerifyObject{metadata}, nil, []config.Repo{yum}, values)
	if len(scoped.positive) != 1 || len(scoped.gaps) != 1 || scoped.gaps[0].code != "REMOTE_PLAN_SELECTOR_COVERAGE_MISSING" {
		t.Fatalf("physical YUM bytes incorrectly substituted for an exact logical OS channel: %+v", scoped)
	}

	channel := pub.VerifyObject{URL: "https://repo.example.invalid/_sow/v1/mirrorlist/latest/rpm-test/el9/x86_64.txt"}
	deletedSnapshot := pub.VerifyAbsentObject{URL: "https://repo.example.invalid/pro/v1/basic/_sow/v1/snapshots/el9-20260714/_route.json"}
	scoped = scopeL3Expectations(cfg, "cos", "latest", "", generation, []pub.VerifyObject{metadata, channel}, []pub.VerifyAbsentObject{deletedSnapshot}, []config.Repo{yum}, values)
	if len(scoped.gaps) != 0 || len(scoped.positive) != 2 || len(scoped.absent) != 1 || scoped.absent[0].URL != deletedSnapshot.URL {
		t.Fatalf("exact YUM channel did not close selected L3 coverage: %+v", scoped)
	}
}

func TestL3DefaultChangeSetSemanticsRemainUnfiltered(t *testing.T) {
	positive := []pub.VerifyObject{{URL: "https://repo.example.invalid/one"}, {URL: "https://repo.example.invalid/two"}}
	absent := []pub.VerifyAbsentObject{{URL: "https://repo.example.invalid/old"}}
	scoped := scopeL3Expectations(&config.Config{}, "cf", "latest", "", pub.TargetGeneration{}, positive, absent, nil, commonFlags{})
	if len(scoped.gaps) != 0 || len(scoped.positive) != len(positive) || len(scoped.absent) != len(absent) {
		t.Fatalf("unselected L3 change-set semantics changed: %+v", scoped)
	}
}

func TestL3RootMappedAssetUsesOnlyDeclaredExactKeys(t *testing.T) {
	repo := config.Repo{
		ID: "bootstrap", Type: "asset", Path: "assets/bootstrap", Arches: []string{"all"},
		Asset: &config.AssetConfig{Kind: "bootstrap", PublicPath: ".", RootKeys: []string{"get", "pkg"}},
	}
	cfg := &config.Config{Views: map[string]config.View{"beta": {Access: "public"}}}
	ref, _ := state.ViewRef("beta", repo.ID, "all", "all")
	generation := pub.TargetGeneration{Refs: []pub.RefState{{Name: ref.String()}}}
	values := commonFlags{repos: csvFlag{items: []string{repo.ID}}}
	expectations := []pub.VerifyObject{
		{URL: "https://beta.example.invalid/get"},
		{URL: "https://beta.example.invalid/not-owned"},
	}
	scoped := scopeL3Expectations(cfg, "cf", "beta", "", generation, expectations, nil, []config.Repo{repo}, values)
	if len(scoped.gaps) != 0 || len(scoped.positive) != 1 || scoped.positive[0].URL != expectations[0].URL {
		t.Fatalf("root-mapped asset scope did not retain exactly its declared root key: %+v", scoped)
	}
}

func TestL3PublicRouteNamedProV1IsNotMistakenForCredentialPrefix(t *testing.T) {
	repo := config.Repo{
		ID: "public-pro", Type: "asset", Path: "assets/public-pro", Arches: []string{"all"},
		Asset: &config.AssetConfig{Kind: "release", PublicPath: "pro/v1/public"},
	}
	cfg := &config.Config{Views: map[string]config.View{"beta": {Access: "public"}}}
	ref, _ := state.ViewRef("beta", repo.ID, "all", "all")
	generation := pub.TargetGeneration{Refs: []pub.RefState{{Name: ref.String()}}}
	values := commonFlags{repos: csvFlag{items: []string{repo.ID}}}
	expectation := pub.VerifyObject{URL: "https://beta.example.invalid/pro/v1/public/release.tgz"}
	scoped := scopeL3Expectations(cfg, "cf", "beta", "", generation, []pub.VerifyObject{expectation}, nil, []config.Repo{repo}, values)
	if len(scoped.gaps) != 0 || len(scoped.positive) != 1 {
		t.Fatalf("public asset route was mistaken for a Pro credential prefix: %+v", scoped)
	}
}

func TestL3SnapshotAPTMapsSourceSuiteRefToSnapshotMetadataSuite(t *testing.T) {
	const snapshotID = "jammy-20260714"
	repo := config.Repo{
		ID: "apt-snapshot", Type: "apt", Path: "apt/snapshot", Arches: []string{"amd64"},
		APT: &config.APTConfig{Suites: []string{"jammy"}, Components: []string{"main"}},
	}
	cfg := &config.Config{}
	ref, _ := state.SnapshotRef(snapshotID, repo.ID, "jammy", "amd64")
	generation := pub.TargetGeneration{Refs: []pub.RefState{{Name: ref.String()}}}
	values := commonFlags{repos: csvFlag{items: []string{repo.ID}}, arches: csvFlag{items: []string{"amd64"}}}
	expectation := pub.VerifyObject{URL: "https://repo.example.invalid/pro/v1/basic/_sow/v1/snapshots/" + snapshotID + "/apt/apt/snapshot/dists/" + snapshotID + "/main/binary-amd64/Packages.gz"}
	scoped := scopeL3Expectations(cfg, "cf", "snapshot", snapshotID, generation, []pub.VerifyObject{expectation}, nil, []config.Repo{repo}, values)
	if len(scoped.gaps) != 0 || len(scoped.positive) != 1 {
		t.Fatalf("snapshot APT metadata suite did not close its source-suite ref leaf: %+v", scoped)
	}
}
