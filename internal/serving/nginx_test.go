package serving

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
)

func TestRenderNginxIncludeIsDeterministicAndExact(t *testing.T) {
	cfg := nginxFixtureConfig(t)
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	options := NginxIncludeOptions{
		View: "latest", Root: root,
		RawCompatibilityIDs: []string{"infra-legacy-x86-64"}, ActiveCompatibilityIDs: []string{"infra-legacy-x86-64"},
	}
	first, err := RenderNginxInclude(cfg, cfg.Repos, options)
	if err != nil {
		t.Fatal(err)
	}
	reversed := append([]config.Repo(nil), cfg.Repos...)
	slices.Reverse(reversed)
	second, err := RenderNginxInclude(cfg, reversed, options)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("equivalent repository order changed the Nginx include")
	}
	document := string(first)
	configDir, err := filepath.EvalSymlinks(filepath.Dir(cfg.Path))
	if err != nil {
		t.Fatal(err)
	}
	wanted := []string{
		"location = /keys/repository.asc {",
		"alias \"" + filepath.Join(configDir, "keys", "repository.asc") + "\";",
		"location = /keys/rpm-signers.asc {",
		"alias \"" + filepath.Join(configDir, "keys", "rpm-signers.asc") + "\";",
		"location = /pkg {",
		"alias \"" + filepath.Join(root, "asset", "bootstrap", "pkg") + "\";",
		"location = /_sow/v1/mirrorlist/latest/yum-el9/el9/x86_64.txt {",
		"location = /_sow/v1/mirrorlist/latest/infra-legacy-x86-64/cross-el/x86_64.txt {",
		"location = /_sow/v1/trust/yum-compat/infra-legacy-x86-64/packages.pgp {",
		"location = /_sow/v1/trust/yum-compat/infra-legacy-x86-64/repository.pgp {",
		"alias \"" + filepath.Join(root, "_sow", "v1", "trust", "yum-compat", "infra-legacy-x86-64", "packages.pgp") + "\";",
		"location ^~ /apt/pgsql/trixie/ {",
		"location ^~ /pkg/pig/ {",
		"alias \"" + filepath.Join(root, "asset", "pig") + string(filepath.Separator) + "\";",
		"location ^~ /yum/infra/x86_64/ {",
		"location ^~ /yum/pgsql/el9.x86_64/ {",
		`location ~ "^/_sow/v1/g/([0-9]{20})/yum/pgsql/el9\.x86_64/((?:repodata/(?!\.{1,2}$)[A-Za-z0-9._+~^@-]+|Packages/[a-z0-9_]/[A-Za-z0-9][A-Za-z0-9._+~^-]*\.rpm))$" {`,
		`location ~ "^/_sow/v1/g/([0-9]{20})/yum/infra/x86_64/((?:repodata/(?!\.{1,2}$)[A-Za-z0-9._+~^@-]+|Packages/[a-z0-9_]/[A-Za-z0-9][A-Za-z0-9._+~^-]*\.rpm))$" {`,
		"alias \"" + filepath.Join(root, "_sow", "v1", "g") + "/$1/yum/pgsql/el9.x86_64/$2\";",
		"location / { return 404; }",
	}
	for _, fragment := range wanted {
		if !strings.Contains(document, fragment) {
			t.Fatalf("Nginx include is missing %q:\n%s", fragment, document)
		}
	}
	for _, forbidden := range []string{
		"location ^~ /apt/ {",
		"location ^~ /yum/ {",
		"location ^~ /_sow/ {",
		"try_files $uri",
		"auth_basic ",
		"/(.*)$",
	} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("Nginx include widened or authenticated a public route with %q:\n%s", forbidden, document)
		}
	}
	if got, want := strings.Count(document, "limit_except GET { deny all; }"), strings.Count(document, "\nlocation ")-1; got != want {
		t.Fatalf("method gates=%d route locations=%d\n%s", got, want, document)
	}
	if got, want := strings.Count(document, "disable_symlinks on;"), strings.Count(document, "\nlocation ")-1; got != want {
		t.Fatalf("symlink gates=%d route locations=%d\n%s", got, want, document)
	}
	if got, want := strings.Count(document, "autoindex off;"), strings.Count(document, "\nlocation ")-1; got != want {
		t.Fatalf("autoindex gates=%d route locations=%d\n%s", got, want, document)
	}
}

func TestRenderNginxStableIncludeAuthenticatesEveryOwnedRoute(t *testing.T) {
	cfg := nginxFixtureConfig(t)
	root := filepath.Join(t.TempDir(), "stable")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	auth := filepath.Join(t.TempDir(), "sow.htpasswd")
	if err := os.WriteFile(auth, []byte("verifier:{PLAIN}secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := RenderNginxInclude(cfg, cfg.Repos, NginxIncludeOptions{
		View: "stable", Root: root, BasicAuthUserFile: auth,
	})
	if err != nil {
		t.Fatal(err)
	}
	document := string(body)
	resolvedAuth, err := filepath.EvalSymlinks(auth)
	if err != nil {
		t.Fatal(err)
	}
	owned := strings.Count(document, "\nlocation ") - 1
	if got := strings.Count(document, "auth_basic \"Pigsty Pro repository\";"); got != owned {
		t.Fatalf("auth blocks=%d owned routes=%d\n%s", got, owned, document)
	}
	if got := strings.Count(document, "add_header Cache-Control \"private, no-store\" always;"); got != owned {
		t.Fatalf("no-store blocks=%d owned routes=%d\n%s", got, owned, document)
	}
	for _, wanted := range []string{
		"location ^~ /pro/v1/basic/apt/pgsql/trixie/ {",
		"location ^~ /pro/v1/basic/yum/pgsql/el9.x86_64/ {",
		"location = /pro/v1/basic/_sow/v1/mirrorlist/stable/yum-el9/el9/x86_64.txt {",
		`location ~ "^/pro/v1/basic/_sow/v1/g/([0-9]{20})/yum/pgsql/el9\.x86_64/((?:repodata/(?!\.{1,2}$)[A-Za-z0-9._+~^@-]+|Packages/[a-z0-9_]/[A-Za-z0-9][A-Za-z0-9._+~^-]*\.rpm))$" {`,
		"auth_basic_user_file \"" + resolvedAuth + "\";",
	} {
		if !strings.Contains(document, wanted) {
			t.Fatalf("stable include is missing %q:\n%s", wanted, document)
		}
	}
	if strings.Contains(document, "yum/infra/x86_64") {
		t.Fatalf("latest-only compatibility projection leaked into stable:\n%s", document)
	}
	if strings.Contains(document, "location ^~ /apt/") || strings.Contains(document, "location ^~ /yum/") || strings.Contains(document, "location ^~ /_sow/") {
		t.Fatalf("stable include contains a naked or broad namespace:\n%s", document)
	}
}

func TestRenderNginxIncludeFailsClosedOnModeAndPathMismatch(t *testing.T) {
	cfg := nginxFixtureConfig(t)
	root := t.TempDir()
	repositoryAuth := filepath.Join(cfg.Root, "secret.htpasswd")
	if err := os.WriteFile(repositoryAuth, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	realAuth := filepath.Join(t.TempDir(), "real.htpasswd")
	if err := os.WriteFile(realAuth, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkAuth := filepath.Join(t.TempDir(), "linked.htpasswd")
	if err := os.Symlink(realAuth, symlinkAuth); err != nil {
		t.Fatal(err)
	}
	ancestorBase := t.TempDir()
	if err := os.Symlink(cfg.Root, filepath.Join(ancestorBase, "repository-link")); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		options NginxIncludeOptions
		want    string
	}{
		{name: "relative root", options: NginxIncludeOptions{View: "latest", Root: "relative"}, want: "absolute path"},
		{name: "public auth", options: NginxIncludeOptions{View: "latest", Root: root, BasicAuthUserFile: filepath.Join(t.TempDir(), "auth")}, want: "must not configure Basic Auth"},
		{name: "stable missing auth", options: NginxIncludeOptions{View: "stable", Root: root}, want: "absolute path"},
		{name: "stable auth in repo", options: NginxIncludeOptions{View: "stable", Root: root, BasicAuthUserFile: repositoryAuth}, want: "outside the repository"},
		{name: "stable auth final symlink", options: NginxIncludeOptions{View: "stable", Root: root, BasicAuthUserFile: symlinkAuth}, want: "non-symlink"},
		{name: "stable auth ancestor resolves into repo", options: NginxIncludeOptions{View: "stable", Root: root, BasicAuthUserFile: filepath.Join(ancestorBase, "repository-link", "secret.htpasswd")}, want: "outside the repository"},
		{name: "snapshot", options: NginxIncludeOptions{View: "snapshot-20260715", Root: root}, want: "not a configured mutable view"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := RenderNginxInclude(cfg, cfg.Repos, test.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v want %q", err, test.want)
			}
		})
	}
}

func TestRenderNginxIncludeHonorsViewRepositorySubset(t *testing.T) {
	cfg := nginxFixtureConfig(t)
	beta := cfg.Views["beta"]
	beta.Repos = []string{"apt-trixie"}
	cfg.Views["beta"] = beta
	body, err := RenderNginxInclude(cfg, cfg.Repos, NginxIncludeOptions{View: "beta", Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	document := string(body)
	if !strings.Contains(document, "location ^~ /apt/pgsql/trixie/") {
		t.Fatalf("selected APT route is missing:\n%s", document)
	}
	for _, forbidden := range []string{"yum/pgsql", "yum/infra", "/pkg", "asset/pig"} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("view-excluded repo leaked through %q:\n%s", forbidden, document)
		}
	}
}

func TestRenderNginxCompatibilityRequiresSelectedAffinityOwner(t *testing.T) {
	cfg := nginxFixtureConfig(t)
	var assetOnly []config.Repo
	for _, repo := range cfg.Repos {
		if repo.ID == "bootstrap" {
			assetOnly = append(assetOnly, repo)
		}
	}
	body, err := RenderNginxInclude(cfg, assetOnly, NginxIncludeOptions{View: "latest", Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	document := string(body)
	for _, forbidden := range []string{
		"yum/infra/x86_64",
		"mirrorlist/latest/infra-legacy-x86-64",
		"trust/yum-compat/infra-legacy-x86-64",
		"keys/rpm-signers.asc",
	} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("owner-excluded compatibility route leaked through %q:\n%s", forbidden, document)
		}
	}
	if _, err := RenderNginxInclude(cfg, assetOnly, NginxIncludeOptions{
		View: "latest", Root: t.TempDir(), RawCompatibilityIDs: []string{"infra-legacy-x86-64"},
	}); err == nil || !strings.Contains(err.Error(), "requires selected affinity owner yum-el9") {
		t.Fatalf("explicit compatibility enablement bypassed affinity selection: %v", err)
	}
}

func TestRenderNginxCompatibilityRequiresExplicitValidatedEnablement(t *testing.T) {
	cfg := nginxFixtureConfig(t)
	body, err := RenderNginxInclude(cfg, cfg.Repos, NginxIncludeOptions{View: "latest", Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"yum/infra/x86_64",
		"mirrorlist/latest/infra-legacy-x86-64",
		"trust/yum-compat/infra-legacy-x86-64",
	} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("configured but unproven compatibility route leaked through %q:\n%s", forbidden, body)
		}
	}
	for _, test := range []struct {
		name string
		raw  []string
		live []string
		want string
	}{
		{name: "unknown", raw: []string{"unknown"}, want: "is not configured"},
		{name: "wrong view", raw: []string{"infra-legacy-x86-64"}, want: "belongs to view latest, not beta"},
		{name: "duplicate raw", raw: []string{"infra-legacy-x86-64", "infra-legacy-x86-64"}, want: "enabled more than once"},
		{name: "active without raw", live: []string{"infra-legacy-x86-64"}, want: "lacks a proven raw bridge"},
		{name: "duplicate active", raw: []string{"infra-legacy-x86-64"}, live: []string{"infra-legacy-x86-64", "infra-legacy-x86-64"}, want: "enabled more than once"},
	} {
		t.Run(test.name, func(t *testing.T) {
			view := "latest"
			if test.name == "wrong view" {
				view = "beta"
			}
			_, renderErr := RenderNginxInclude(cfg, cfg.Repos, NginxIncludeOptions{
				View: view, Root: t.TempDir(), RawCompatibilityIDs: test.raw, ActiveCompatibilityIDs: test.live,
			})
			if renderErr == nil || !strings.Contains(renderErr.Error(), test.want) {
				t.Fatalf("err=%v want %q", renderErr, test.want)
			}
		})
	}
}

func TestRenderNginxCompatibilityRawBridgeSurvivesWithoutActiveCutover(t *testing.T) {
	cfg := nginxFixtureConfig(t)
	body, err := RenderNginxInclude(cfg, cfg.Repos, NginxIncludeOptions{
		View: "latest", Root: t.TempDir(), RawCompatibilityIDs: []string{"infra-legacy-x86-64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	document := string(body)
	if !strings.Contains(document, "location ^~ /yum/infra/x86_64/") {
		t.Fatalf("proven pre-cutover raw bridge is missing:\n%s", document)
	}
	for _, forbidden := range []string{
		"mirrorlist/latest/infra-legacy-x86-64",
		"trust/yum-compat/infra-legacy-x86-64",
		`g/([0-9]{20})/yum/infra/x86_64`,
	} {
		if strings.Contains(document, forbidden) {
			t.Fatalf("inactive compatibility closure leaked through %q:\n%s", forbidden, document)
		}
	}
}

func TestRenderNginxIncludeRejectsDuplicateAndOverlappingClaims(t *testing.T) {
	cfg := nginxFixtureConfig(t)
	root := t.TempDir()
	duplicate := append(append([]config.Repo(nil), cfg.Repos...), cfg.Repos[0])
	if _, err := RenderNginxInclude(cfg, duplicate, NginxIncludeOptions{View: "latest", Root: root}); err == nil || !strings.Contains(err.Error(), "selected more than once") {
		t.Fatalf("duplicate repo selection was accepted: %v", err)
	}
	overlap := append([]config.Repo(nil), cfg.Repos...)
	overlap = append(overlap, config.Repo{
		ID: "conflicting-asset", Type: "asset", Path: "asset/conflict", DefaultPool: "public",
		Asset: &config.AssetConfig{Kind: "test", PublicPath: "apt/pgsql/trixie"},
	})
	if _, err := RenderNginxInclude(cfg, overlap, NginxIncludeOptions{View: "latest", Root: root}); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("overlapping exact leaf claim was accepted: %v", err)
	}
}

func TestRenderNginxGenerationAliasKeepsSentinelLikeRootLiteral(t *testing.T) {
	cfg := nginxFixtureConfig(t)
	root := filepath.Join(t.TempDir(), "__SOW_CAPTURE_1__-literal", "__SOW_CAPTURE_2__")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	body, err := RenderNginxInclude(cfg, cfg.Repos, NginxIncludeOptions{View: "latest", Root: root})
	if err != nil {
		t.Fatal(err)
	}
	document := string(body)
	expectedPrefix := `alias "` + nginxEscape(filepath.Join(root, "_sow", "v1", "g")+string(filepath.Separator)) + `$1`
	if !strings.Contains(document, expectedPrefix) {
		t.Fatalf("generation alias rewrote a sentinel-like literal root; missing %q:\n%s", expectedPrefix, document)
	}
	generationRoutes := strings.Count(document, `location ~ "`)
	if got := strings.Count(document, "$1"); got != generationRoutes {
		t.Fatalf("capture-1 variables=%d generation routes=%d; literal root was rewritten:\n%s", got, generationRoutes, document)
	}
	if got := strings.Count(document, "$2"); got != generationRoutes {
		t.Fatalf("capture-2 variables=%d generation routes=%d; literal root was rewritten:\n%s", got, generationRoutes, document)
	}
}

func nginxFixtureConfig(t *testing.T) *config.Config {
	t.Helper()
	configDir := t.TempDir()
	yaml := `schema: sow/v1
state:
  snapshot_materialization_months: 6
  apt_by_hash_retention: 2
  yum_generation_retention: 2
  cas_history_commits: 32
gpg:
  public_key: keys/repository.asc
  private_key: env://SOW_GPG_PRIVATE_KEY
  passphrase: env://SOW_GPG_PASSPHRASE
pools:
  public: {}
  gated: {}
repos:
  - id: bootstrap
    type: asset
    path: asset/bootstrap
    default_pool: public
    include: ["**"]
    asset: {kind: bootstrap, public_path: '.', root_keys: [pkg]}
  - id: pig
    type: asset
    path: asset/pig
    default_pool: public
    include: ["**"]
    asset: {kind: release, public_path: pkg/pig}
  - id: yum-el9
    type: yum
    path: yum/pgsql/el9.x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: keys/rpm-signers.asc}
  - id: infra-carrier
    type: yum
    path: yum/infra/{arch}
    active: false
    default_pool: public
    arches: [x86_64]
    os: {family: cross-el, major: 0, lifecycle: frozen}
    yum: {compression: gzip, compatibility_carrier: true, package_keyring: keys/rpm-signers.asc}
  - id: apt-trixie
    type: apt
    path: apt/pgsql/trixie
    default_pool: public
    arches: [amd64]
    os: {family: debian, major: 13, suite: trixie, lifecycle: active}
    apt: {suites: [trixie], components: [main]}
compatibility_projections:
  - id: infra-legacy-x86-64
    root: yum/infra/x86_64
    mode: frozen-cross-el
    carrier: infra-carrier
    source: {repo: yum-el9, view: latest, os: cross-el, arch: x86_64, commit: pin-at-first-freeze}
upstreams: []
views:
  beta: {access: public, debuginfo: drop, allowed_pools: [public], append_only: false}
  latest: {access: public, debuginfo: drop, allowed_pools: [public], append_only: false}
  stable: {access: pro, debuginfo: keep, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "https://repo.example"}
  beta: {base_url: "https://beta.example"}
  stable: {base_url: "https://repo.example/pro/v1/basic"}
targets: {}
edge:
  pro_prefix: /pro/v1/{token}/
  token_verifier: provider://pigsty-entitlements
`
	cfg, err := config.Decode(strings.NewReader(yaml))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Path = filepath.Join(configDir, "sow.yaml")
	cfg.Root = t.TempDir()
	return cfg
}
