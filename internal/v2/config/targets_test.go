package config

import (
	"strings"
	"testing"
	"time"
)

func targetFixture(prefix string) TargetConfig {
	return TargetConfig{
		Repository: "repo", Provider: "r2", Endpoint: "https://acct.r2.cloudflarestorage.com",
		Region: "auto", Bucket: "sow-repo", Prefix: prefix, Credential: "env://SOW_R2_CREDENTIAL",
		PublicEndpoint: "https://repo.example.test/" + prefix + "/", MaxCacheTTL: "24h0m0s",
		AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
	}
}

func TestTargetBindingsCanonicalIdentityAndSiblingPrefixes(t *testing.T) {
	cfg := Default()
	cfg.Repositories["repo"] = RepositoryConfig{}
	cfg.Targets = map[string]TargetConfig{"alpha": targetFixture("repos/alpha"), "beta": targetFixture("repos/beta")}
	bindings, err := cfg.TargetBindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 2 || bindings[0].Name != "alpha" || bindings[0].StorageIdentity != bindings[1].StorageIdentity || bindings[0].TargetIdentity == bindings[1].TargetIdentity {
		t.Fatalf("unexpected canonical bindings: %#v", bindings)
	}
}

func TestTargetsRejectStoragePrefixOverlap(t *testing.T) {
	for _, tc := range []struct{ name, left, right string }{
		{"exact", "repos/acme", "repos/acme"},
		{"ancestor", "repos", "repos/acme"},
		{"descendant", "repos/acme", "repos"},
		{"empty", "", "repos/acme"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Repositories["repo"] = RepositoryConfig{}
			left, right := targetFixture(tc.left), targetFixture(tc.right)
			right.Region = "us-east-1"
			if tc.left == "" {
				left.PublicEndpoint = "https://repo.example.test/"
			}
			cfg.Targets = map[string]TargetConfig{"left": left, "right": right}
			if _, err := Marshal(cfg); err == nil || !strings.Contains(err.Error(), "overlap") {
				t.Fatalf("expected overlap rejection, got %v", err)
			}
		})
	}
}

func TestTargetsRejectNonCanonicalAndSecretInputs(t *testing.T) {
	base := targetFixture("repos/acme")
	for _, tc := range []struct {
		name string
		edit func(*TargetConfig)
		want string
	}{
		{"endpoint-userinfo", func(v *TargetConfig) { v.Endpoint = "https://key@acct.r2.cloudflarestorage.com" }, "userinfo"},
		{"prefix-leading", func(v *TargetConfig) { v.Prefix = "/repos/acme" }, "prefix"},
		{"prefix-encoded-separator", func(v *TargetConfig) { v.Prefix = "repos%2Facme" }, "percent-encoded"},
		{"inline-secret", func(v *TargetConfig) { v.Credential = "secret-access-key" }, "inline secrets"},
		{"unknown-ttl", func(v *TargetConfig) { v.MaxCacheTTL = "" }, "max_cache_ttl"},
		{"overflowing-ttl", func(v *TargetConfig) { v.MaxCacheTTL = time.Duration(1<<63 - 1).String() }, "max_cache_ttl"},
		{"r2-file-public-endpoint", func(v *TargetConfig) { v.PublicEndpoint = "file:///srv/public/" }, "https or http"},
		{"bucket-grammar", func(v *TargetConfig) { v.Bucket = "bad_bucket" }, "DNS-safe"},
		{"authority", func(v *TargetConfig) { v.ExclusiveWriteAuthority = false }, "exclusive_write_authority"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := base
			tc.edit(&value)
			cfg := Default()
			cfg.Repositories["repo"] = RepositoryConfig{}
			cfg.Targets = map[string]TargetConfig{"prod": value}
			_, err := Marshal(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q rejection, got %v", tc.want, err)
			}
		})
	}
}

func TestTargetsAcceptErgonomicYAMLDefaultsAndStandardDurations(t *testing.T) {
	cfg, err := Parse([]byte(`
schema: sow/v3
repos:
  repo: {}
targets:
  prod:
    repository: repo
    provider: r2
    endpoint: https://ACCT.r2.cloudflarestorage.com/
    region: us-east-1
    bucket: repo.example.com
    prefix: repos/prod
    credential: env://SOW_R2_CREDENTIAL
    public_endpoint: https://REPO.EXAMPLE.COM/repos/prod
    max_cache_ttl: 1h
  local:
    repository: repo
    provider: filesystem
    endpoint: file:///srv/sow/repo/
    prefix: mirror
    public_endpoint: file:///srv/sow/repo/mirror
    max_cache_ttl: "0"
`))
	if err != nil {
		t.Fatalf("Parse ergonomic targets: %v", err)
	}
	prod := cfg.Targets["prod"]
	if prod.Endpoint != "https://acct.r2.cloudflarestorage.com" || prod.PublicEndpoint != "https://repo.example.com/repos/prod/" || prod.MaxCacheTTL != "1h0m0s" || !prod.AuthoritativeWorkspace || !prod.SingleWriter || !prod.ExclusiveWriteAuthority {
		t.Fatalf("normalized prod target = %#v", prod)
	}
	local := cfg.Targets["local"]
	if local.Endpoint != "file:///srv/sow/repo" || local.PublicEndpoint != "file:///srv/sow/repo/mirror/" || local.MaxCacheTTL != "0s" {
		t.Fatalf("normalized local target = %#v", local)
	}

	// Unknown fields (typos or pasted secrets) and explicit null authority flags
	// inside targets must still be rejected by KnownFields / UnmarshalYAML.
	for _, tc := range []struct {
		name, extra string
	}{
		{"unknown typo", "    single_write: false\n"},
		{"pasted secret", "    secret_access_key: leaked\n"},
		{"null authority flag", "    single_writer: null\n"},
		{"r2 path", "    endpoint: https://acct.r2.cloudflarestorage.com/subpath\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := `
schema: sow/v3
repos:
  repo: {}
targets:
  prod:
    repository: repo
    provider: r2
    endpoint: https://acct.r2.cloudflarestorage.com
    bucket: repo
    prefix: repos/prod
    credential: env://SOW_R2_CREDENTIAL
    public_endpoint: https://repo.example.com/repos/prod/
    max_cache_ttl: 1h
` + tc.extra
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatalf("expected Parse rejection for %s", tc.name)
			}
		})
	}
}

func TestTargetMaximumCacheTTLLeavesRoomForGracePadding(t *testing.T) {
	for _, test := range []struct {
		name string
		ttl  time.Duration
		ok   bool
	}{
		{name: "boundary", ttl: maximumPublicationCacheTTL, ok: true},
		{name: "boundary plus one", ttl: maximumPublicationCacheTTL + time.Nanosecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := targetFixture("repos/acme")
			target.MaxCacheTTL = test.ttl.String()
			cfg := Default()
			cfg.Repositories["repo"] = RepositoryConfig{}
			cfg.Targets = map[string]TargetConfig{"prod": target}
			_, err := Marshal(cfg)
			if test.ok && err != nil || !test.ok && err == nil {
				t.Fatalf("ttl=%s ok=%t err=%v", test.ttl, test.ok, err)
			}
		})
	}
}

func TestFilesystemTargetRequiresCanonicalFileEndpoint(t *testing.T) {
	cfg := Default()
	cfg.Repositories["repo"] = RepositoryConfig{}
	cfg.Targets = map[string]TargetConfig{"local": {
		Repository: "repo", Provider: "filesystem", Endpoint: "file:///srv/sow/repo", Prefix: "mirror/repo",
		PublicEndpoint: "file:///srv/sow/repo/mirror/repo/", MaxCacheTTL: "0s",
		AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
	}}
	if _, err := Marshal(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestFilesystemTargetsRejectEffectivePathOverlapAcrossEndpoints(t *testing.T) {
	fixture := func(endpoint, prefix string) TargetConfig {
		return TargetConfig{
			Repository: "repo", Provider: "filesystem", Endpoint: endpoint, Prefix: prefix,
			PublicEndpoint: "file:///srv/public/", MaxCacheTTL: "0s",
			AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
		}
	}
	for _, tc := range []struct {
		name                    string
		leftEndpoint, leftPre   string
		rightEndpoint, rightPre string
	}{
		{name: "nested-endpoints", leftEndpoint: "file:///srv/out", rightEndpoint: "file:///srv/out/sub"},
		{name: "endpoint-prefix-alias", leftEndpoint: "file:///srv/out", leftPre: "sub", rightEndpoint: "file:///srv/out/sub"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Repositories["repo"] = RepositoryConfig{}
			cfg.Targets = map[string]TargetConfig{
				"left": fixture(tc.leftEndpoint, tc.leftPre), "right": fixture(tc.rightEndpoint, tc.rightPre),
			}
			if _, err := Marshal(cfg); err == nil || !strings.Contains(err.Error(), "effective paths") {
				t.Fatalf("expected effective filesystem overlap rejection, got %v", err)
			}
		})
	}
}
