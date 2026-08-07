package config

import (
	"strings"
	"testing"
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
		{"endpoint-case", func(v *TargetConfig) { v.Endpoint = "https://ACCT.r2.cloudflarestorage.com" }, "canonical"},
		{"endpoint-userinfo", func(v *TargetConfig) { v.Endpoint = "https://key@acct.r2.cloudflarestorage.com" }, "userinfo"},
		{"prefix-leading", func(v *TargetConfig) { v.Prefix = "/repos/acme" }, "prefix"},
		{"prefix-encoded-separator", func(v *TargetConfig) { v.Prefix = "repos%2Facme" }, "percent-encoded"},
		{"inline-secret", func(v *TargetConfig) { v.Credential = "secret-access-key" }, "inline secrets"},
		{"unknown-ttl", func(v *TargetConfig) { v.MaxCacheTTL = "" }, "max_cache_ttl"},
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
