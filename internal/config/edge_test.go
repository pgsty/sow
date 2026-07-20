package config

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseTokenVerifierReferenceIsClosedAndCanonical(t *testing.T) {
	tests := []struct {
		value string
		kind  string
		name  string
		ok    bool
	}{
		{"provider://pigsty-entitlements", "provider", "pigsty-entitlements", true},
		{"provider://test.v1", "provider", "test.v1", true},
		{"env://SOW_TOKEN_ENTITLEMENTS", "env", "SOW_TOKEN_ENTITLEMENTS", true},
		{"provider://", "", "", false},
		{"provider://Pigsty", "", "", false},
		{"provider://pigsty/entitlements", "", "", false},
		{"provider://pigsty?tenant=x", "", "", false},
		{"env://lowercase", "", "", false},
		{"https://verifier.example/v1", "", "", false},
		{"literal-secret", "", "", false},
	}
	for _, item := range tests {
		t.Run(item.value, func(t *testing.T) {
			got, err := ParseTokenVerifierReference(item.value)
			if (err == nil) != item.ok {
				t.Fatalf("ParseTokenVerifierReference(%q) err=%v", item.value, err)
			}
			if item.ok && (got.Kind != item.kind || got.Name != item.name) {
				t.Fatalf("reference=%#v", got)
			}
		})
	}
}

func TestEdgeDeploymentMapsProviderToRealVendorBindingsWithoutSecrets(t *testing.T) {
	yaml := strings.Replace(validYAML(""), "targets: {}", `targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.example.invalid", bucket: repo-cf, credential: env://CF_STORAGE}
    cdn: {kind: cloudflare, base_url: "https://repo.example", beta_base_url: "https://beta.example", zone_id: zone-cf, credential: env://CF_CDN}
  cos:
    storage: {kind: cos, endpoint: "https://cos.example.invalid", bucket: repo-cos-1250000000, region: ap-shanghai, credential: env://COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.example", beta_base_url: "https://beta-cn.example", distribution: zone-cos, credential: env://COS_CDN}`, 1)
	cfg, err := Decode(strings.NewReader(yaml))
	if err != nil {
		t.Fatal(err)
	}

	cf, err := cfg.EdgeDeployment("cf")
	if err != nil {
		t.Fatal(err)
	}
	if cf.Runtime != "cloudflare" || !reflect.DeepEqual(cf.ServiceBindings, []string{"ORIGIN", "TOKEN_VERIFIER"}) {
		t.Fatalf("Cloudflare deployment=%#v", cf)
	}
	if len(cf.RequiredSecrets) != 0 || len(cf.RequiredVariables) != 0 {
		t.Fatalf("Cloudflare provider transport should use bindings, got %#v", cf)
	}
	if cf.Variables[EdgeRuntimeTokenVerifierVariable] != "provider://pigsty-entitlements" {
		t.Fatalf("verifier mapping=%q", cf.Variables[EdgeRuntimeTokenVerifierVariable])
	}
	if cf.Variables[EdgeRuntimeOriginModeVariable] != "r2-service" || cf.Variables[EdgeRuntimePublicPrefixesVariable] != `["bin"]` || cf.Variables[EdgeRuntimePublicKeysVariable] != `["keys/test-package-trust.asc"]` {
		t.Fatalf("Cloudflare executable variables=%#v", cf.Variables)
	}

	cos, err := cfg.EdgeDeployment("cos")
	if err != nil {
		t.Fatal(err)
	}
	if cos.Runtime != "edgeone" || !reflect.DeepEqual(cos.RequiredVariables, []string{"SOW_TOKEN_VERIFIER_URL"}) {
		t.Fatalf("EdgeOne deployment=%#v", cos)
	}
	if !reflect.DeepEqual(cos.RequiredSecrets, []string{"SOW_COS_SECRET_ID", "SOW_COS_SECRET_KEY", "SOW_TOKEN_VERIFIER_BEARER"}) {
		t.Fatalf("EdgeOne secrets=%v", cos.RequiredSecrets)
	}
	if cos.Variables[EdgeRuntimeOriginModeVariable] != "cos-sigv4" || cos.Variables["SOW_COS_REGION"] != "ap-shanghai" || cos.Variables["SOW_COS_BUCKET"] != "repo-cos-1250000000" {
		t.Fatalf("EdgeOne executable variables=%#v", cos.Variables)
	}
	encoded, err := json.Marshal(cos)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-value", "token-value", "bearer-value"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("deployment contract leaked secret material: %s", encoded)
		}
	}
}

func TestEdgeDeploymentUsesTargetSpecificPublicAssetProjection(t *testing.T) {
	repos := `
  - {id: bootstrap, type: asset, path: asset/bootstrap, default_pool: public, publish_targets: [cf], asset: {kind: bootstrap, public_path: '.', root_keys: [get, pkg]}}
  - {id: pig, type: asset, path: asset/pig, default_pool: public, publish_targets: [cf], asset: {kind: release, public_path: pkg/pig}}
  - {id: ray-key, type: asset, path: asset/ray-key, default_pool: public, publish_targets: [cos], asset: {kind: bootstrap, public_path: '.', root_keys: [ray]}}
  - {id: images, type: asset, path: asset/images, default_pool: public, publish_targets: [cos], asset: {kind: images, public_path: img}}
  - {id: source, type: asset, path: asset/source, default_pool: public, asset: {kind: source, public_path: src}}`
	cfg, err := Decode(strings.NewReader(withProjectionTargets(validYAML(repos))))
	if err != nil {
		t.Fatal(err)
	}
	cf, err := cfg.EdgeDeployment("cf")
	if err != nil {
		t.Fatal(err)
	}
	if got := cf.Variables[EdgeRuntimePublicPrefixesVariable]; got != `["pkg/pig","src"]` {
		t.Fatalf("Cloudflare public prefixes=%s", got)
	}
	if got := cf.Variables[EdgeRuntimePublicKeysVariable]; got != `["get","keys/test-package-trust.asc","pkg"]` {
		t.Fatalf("Cloudflare public keys=%s", got)
	}
	cos, err := cfg.EdgeDeployment("cos")
	if err != nil {
		t.Fatal(err)
	}
	if got := cos.Variables[EdgeRuntimePublicPrefixesVariable]; got != `["img","src"]` {
		t.Fatalf("EdgeOne public prefixes=%s", got)
	}
	if got := cos.Variables[EdgeRuntimePublicKeysVariable]; got != `["keys/test-package-trust.asc","ray"]` {
		t.Fatalf("EdgeOne public keys=%s", got)
	}
	for _, contract := range []EdgeDeploymentContract{cf, cos} {
		encoded, _ := json.Marshal(contract.Variables)
		for _, physical := range []string{"asset/bootstrap", "asset/pig", "asset/ray-key", "asset/images", "asset/source"} {
			if strings.Contains(string(encoded), physical) {
				t.Fatalf("physical asset path %s leaked into %s edge contract: %s", physical, contract.Target, encoded)
			}
		}
	}
}

func TestEdgeDeploymentExcludesInactiveAndViewOrphanedOrdinaryRepositories(t *testing.T) {
	repos := `
  - {id: kept, type: asset, path: physical/kept, default_pool: public, asset: {kind: release, public_path: allowed/kept}}
  - {id: inactive-asset, type: asset, path: physical/inactive-asset, active: false, default_pool: public, asset: {kind: release, public_path: denied/inactive-asset}}
  - id: inactive-apt
    type: apt
    path: apt/denied/inactive-apt
    active: false
    default_pool: public
    arches: [amd64]
    os: {family: debian, major: 12, lifecycle: frozen}
    apt: {suites: [bookworm], components: [main]}
  - id: inactive-yum
    type: yum
    path: yum/denied/inactive-yum/{arch}
    active: false
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: frozen}
    yum: {compression: zstd, package_keyring: denied/inactive-yum.pgp}
  - {id: active-orphan, type: asset, path: physical/active-orphan, default_pool: public, asset: {kind: release, public_path: denied/active-orphan}}`
	yaml := withProjectionTargets(validYAML(repos))
	yaml = strings.Replace(yaml,
		"  beta: {access: public, allowed_pools: [public], append_only: false}\n  latest: {access: public, allowed_pools: [public], append_only: false}\n  stable: {access: pro, allowed_pools: [public, gated], append_only: true}",
		"  beta: {access: public, allowed_pools: [public], append_only: false, repos: [kept]}\n  latest: {access: public, allowed_pools: [public], append_only: false, repos: [kept]}\n  stable: {access: pro, allowed_pools: [public, gated], append_only: true, repos: [kept]}", 1)
	cfg, err := Decode(strings.NewReader(yaml))
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := cfg.EdgeDeployment("cf")
	if err != nil {
		t.Fatal(err)
	}
	if got := deployment.Variables[EdgeRuntimePublicPrefixesVariable]; got != `["allowed/kept"]` {
		t.Fatalf("ordinary edge prefixes=%s", got)
	}
	compatibility := deployment.Variables[EdgeRuntimeCompatibilityVariable]
	if compatibility != `{"apt_roots":[],"yum_repos":[],"yum_roots":[],"yum_channels":[],"asset_roots":["allowed/kept"],"asset_keys":[],"projections":[],"snapshots":[],"raw":[],"active":[]}` {
		t.Fatalf("ordinary edge compatibility inventory=%s", compatibility)
	}
	encoded, err := json.Marshal(deployment.Variables)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"inactive-asset", "inactive-apt", "inactive-yum", "active-orphan"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("inactive or view-orphaned repository %s leaked into edge contract: %s", forbidden, encoded)
		}
	}
}

func TestValidateEdgeCompatibilityAdmissionJSONRejectsNestedSemanticDrift(t *testing.T) {
	valid := `{"apt_roots":["apt/debian"],"yum_repos":["infra-el9"],"yum_roots":["yum/infra-el9/x86_64"],"yum_channels":[{"view":"latest","repo":"infra-el9","os":"el9","arch":"x86_64","root":"yum/infra-el9/x86_64"}],"asset_roots":["v1"],"asset_keys":["KEYS"],"projections":[{"id":"infra-legacy-x86-64","root":"yum/infra/x86_64","view":"latest","os":"cross-el","arch":"x86_64"}],"snapshots":[{"id":"pigsty-20260717","apt_roots":["apt/snapshot"],"yum_roots":["yum/snapshot/x86_64"],"asset_roots":["v1/snapshot"],"asset_keys":["KEYS.snapshot"]}],"raw":["infra-legacy-x86-64"],"active":["infra-legacy-x86-64"]}`
	if err := ValidateEdgeCompatibilityAdmissionJSON(valid); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]string{
		"opaque projection traversal": strings.Replace(valid, `"root":"yum/infra/x86_64"`, `"root":"yum/../foreign"`, 1),
		"active outside raw":          strings.Replace(valid, `"raw":["infra-legacy-x86-64"]`, `"raw":[]`, 1),
		"unknown channel repo":        strings.Replace(valid, `"repo":"infra-el9"`, `"repo":"foreign"`, 1),
		"unsafe snapshot key":         strings.Replace(valid, `"KEYS.snapshot"`, `"KEYS%2fsnapshot"`, 1),
		"unknown nested field":        strings.Replace(valid, `"arch":"x86_64","root"`, `"arch":"x86_64","foreign":true,"root"`, 1),
		"noncanonical whitespace":     " " + valid,
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateEdgeCompatibilityAdmissionJSON(invalid); err == nil {
				t.Fatal("unsafe or non-canonical nested compatibility admission was accepted")
			}
		})
	}
}

func TestEdgeDeploymentIncludesOnlyTargetOwnedFrozenYUMCompatibilityLeaves(t *testing.T) {
	repos := `
  - id: infra-el9-cf
    type: yum
    path: yum/canonical/el9-cf/{arch}
    default_pool: public
    publish_targets: [cf]
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: keys/cf-rpm.asc}
  - id: infra-el9-cos
    type: yum
    path: yum/canonical/el9-cos/{arch}
    default_pool: public
    publish_targets: [cos]
    arches: [aarch64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: keys/cos-rpm.asc}
  - id: infra-carrier-cf
    type: yum
    path: yum/infra/{arch}
    active: false
    default_pool: public
    publish_targets: [cf]
    arches: [x86_64]
    os: {family: cross-el, major: 0, lifecycle: frozen}
    yum: {compression: gzip, compatibility_carrier: true}
  - id: infra-carrier-cos
    type: yum
    path: yum/infra/{arch}
    active: false
    default_pool: public
    publish_targets: [cos]
    arches: [aarch64]
    os: {family: cross-el, major: 0, lifecycle: frozen}
    yum: {compression: gzip, compatibility_carrier: true}`
	yaml := strings.Replace(validYAML(repos), "upstreams: []", `compatibility_projections:
  - {id: infra-legacy-x86-64, root: yum/infra/x86_64, mode: frozen-cross-el, carrier: infra-carrier-cf, source: {repo: infra-el9-cf, view: latest, os: cross-el, arch: x86_64, commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}}
  - {id: infra-legacy-aarch64, root: yum/infra/aarch64, mode: frozen-cross-el, carrier: infra-carrier-cos, source: {repo: infra-el9-cos, view: latest, os: cross-el, arch: aarch64, commit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}}
upstreams: []`, 1)
	cfg, err := Decode(strings.NewReader(withProjectionTargets(yaml)))
	if err != nil {
		t.Fatal(err)
	}
	unproven, err := cfg.EdgeDeployment("cf")
	if err != nil {
		t.Fatal(err)
	}
	if got := unproven.Variables[EdgeRuntimePublicPrefixesVariable]; strings.Contains(got, "yum/infra/x86_64") {
		t.Fatalf("config-only compatibility raw prefix leaked: %s", got)
	}
	if got := unproven.Variables[EdgeRuntimePublicKeysVariable]; strings.Contains(got, "trust/yum-compat") {
		t.Fatalf("config-only compatibility trust leaked: %s", got)
	}
	if got := unproven.Variables[EdgeRuntimeCompatibilityVariable]; got != `{"apt_roots":[],"yum_repos":["infra-el9-cf"],"yum_roots":["yum/canonical/el9-cf/x86_64"],"yum_channels":[{"view":"beta","repo":"infra-el9-cf","os":"el9","arch":"x86_64","root":"yum/canonical/el9-cf/x86_64"},{"view":"latest","repo":"infra-el9-cf","os":"el9","arch":"x86_64","root":"yum/canonical/el9-cf/x86_64"},{"view":"stable","repo":"infra-el9-cf","os":"el9","arch":"x86_64","root":"yum/canonical/el9-cf/x86_64"}],"asset_roots":[],"asset_keys":[],"projections":[{"id":"infra-legacy-x86-64","root":"yum/infra/x86_64","view":"latest","os":"cross-el","arch":"x86_64"}],"snapshots":[],"raw":[],"active":[]}` {
		t.Fatalf("Cloudflare unproven compatibility admission=%s", got)
	}
	cf, err := cfg.EdgeDeployment("cf", EdgeCompatibilityAdmission{
		RawIDs: []string{"infra-legacy-x86-64"}, ActiveIDs: []string{"infra-legacy-x86-64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := cf.Variables[EdgeRuntimePublicPrefixesVariable]; got != `["yum/canonical/el9-cf/x86_64","yum/infra/x86_64"]` {
		t.Fatalf("Cloudflare compatibility prefixes=%s", got)
	}
	if got := cf.Variables[EdgeRuntimePublicKeysVariable]; got != `["_sow/v1/trust/yum-compat/infra-legacy-x86-64/packages.pgp","_sow/v1/trust/yum-compat/infra-legacy-x86-64/repository.pgp","keys/cf-rpm.asc","keys/test-package-trust.asc"]` {
		t.Fatalf("Cloudflare compatibility trust keys=%s", got)
	}
	cos, err := cfg.EdgeDeployment("cos", EdgeCompatibilityAdmission{
		RawIDs: []string{"infra-legacy-aarch64"}, ActiveIDs: []string{"infra-legacy-aarch64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := cos.Variables[EdgeRuntimePublicPrefixesVariable]; got != `["yum/canonical/el9-cos/aarch64","yum/infra/aarch64"]` {
		t.Fatalf("EdgeOne compatibility prefixes=%s", got)
	}
	if got := cos.Variables[EdgeRuntimePublicKeysVariable]; got != `["_sow/v1/trust/yum-compat/infra-legacy-aarch64/packages.pgp","_sow/v1/trust/yum-compat/infra-legacy-aarch64/repository.pgp","keys/cos-rpm.asc","keys/test-package-trust.asc"]` {
		t.Fatalf("EdgeOne compatibility trust keys=%s", got)
	}
	for _, deployment := range []EdgeDeploymentContract{cf, cos} {
		if strings.Contains(deployment.Variables[EdgeRuntimePublicPrefixesVariable], `"yum"`) {
			t.Fatalf("compatibility allowlist widened to yum/: %s", deployment.Variables[EdgeRuntimePublicPrefixesVariable])
		}
	}
	rawOnly, err := cfg.EdgeDeployment("cf", EdgeCompatibilityAdmission{RawIDs: []string{"infra-legacy-x86-64"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rawOnly.Variables[EdgeRuntimePublicPrefixesVariable], "yum/infra/x86_64") || strings.Contains(rawOnly.Variables[EdgeRuntimePublicKeysVariable], "trust/yum-compat") {
		t.Fatalf("raw-only edge compatibility closure=%v", rawOnly.Variables)
	}
	for _, admission := range []EdgeCompatibilityAdmission{
		{ActiveIDs: []string{"infra-legacy-x86-64"}},
		{RawIDs: []string{"unknown"}},
		{RawIDs: []string{"infra-legacy-aarch64"}},
		{RawIDs: []string{"infra-legacy-x86-64", "infra-legacy-x86-64"}},
	} {
		if _, err := cfg.EdgeDeployment("cf", admission); err == nil {
			t.Fatalf("unsafe edge compatibility admission accepted: %+v", admission)
		}
	}
}

func TestEdgeDeploymentDeduplicatesSharedYUMTrustWithoutWideningExactKeys(t *testing.T) {
	for _, test := range []struct {
		name     string
		yum      string
		wantKeys string
	}{
		{
			name:     "explicit shared bundle",
			yum:      "{compression: zstd, package_keyring: keys/shared-rpm.pgp}",
			wantKeys: `["keys/shared-rpm.pgp","keys/test-package-trust.asc"]`,
		},
		{
			name:     "default repository trust fallback",
			yum:      "{compression: zstd}",
			wantKeys: `["keys/test-package-trust.asc"]`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repos := `
  - id: yum-a
    type: yum
    path: yum/a/{arch}
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: ` + test.yum + `
  - id: yum-b
    type: yum
    path: yum/b/{arch}
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: ` + test.yum
			cfg, err := Decode(strings.NewReader(withProjectionTargets(validYAML(repos))))
			if err != nil {
				t.Fatal(err)
			}
			deployment, err := cfg.EdgeDeployment("cf")
			if err != nil {
				t.Fatal(err)
			}
			if got := deployment.Variables[EdgeRuntimePublicKeysVariable]; got != test.wantKeys {
				t.Fatalf("shared trust exact keys=%s want=%s", got, test.wantKeys)
			}
		})
	}
}

func TestEdgeDeploymentMapsEnvReferenceToNamedSecretOnBothVendors(t *testing.T) {
	yaml := strings.Replace(validYAML(""), "token_verifier: provider://pigsty-entitlements", "token_verifier: env://SOW_TOKEN_ENTITLEMENTS", 1)
	yaml = strings.Replace(yaml, "targets: {}", `targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.example.invalid", bucket: repo-cf, credential: env://CF_STORAGE}
    cdn: {kind: cloudflare, base_url: "https://repo.example", beta_base_url: "https://beta.example", zone_id: zone-cf, credential: env://CF_CDN}
  cos:
    storage: {kind: cos, endpoint: "https://cos.example.invalid", bucket: repo-cos-1250000000, region: ap-shanghai, credential: env://COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.example", beta_base_url: "https://beta-cn.example", distribution: zone-cos, credential: env://COS_CDN}`, 1)
	cfg, err := Decode(strings.NewReader(yaml))
	if err != nil {
		t.Fatal(err)
	}
	cf, err := cfg.EdgeDeployment("cf")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cf.ServiceBindings, []string{"ORIGIN"}) || !reflect.DeepEqual(cf.RequiredSecrets, []string{"SOW_TOKEN_ENTITLEMENTS"}) {
		t.Fatalf("Cloudflare env deployment=%#v", cf)
	}
	cos, err := cfg.EdgeDeployment("cos")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cos.RequiredSecrets, []string{"SOW_COS_SECRET_ID", "SOW_COS_SECRET_KEY", "SOW_TOKEN_ENTITLEMENTS"}) {
		t.Fatalf("EdgeOne env deployment=%#v", cos)
	}
}

func TestEdgeDeploymentRejectsCrossKindBindingNameCollisions(t *testing.T) {
	yaml := strings.Replace(validYAML(""), "targets: {}", `targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.example.invalid", bucket: repo-cf, credential: env://CF_STORAGE}
    cdn: {kind: cloudflare, base_url: "https://repo.example", beta_base_url: "https://beta.example", zone_id: zone-cf, credential: env://CF_CDN}
  cos:
    storage: {kind: cos, endpoint: "https://cos.example.invalid", bucket: repo-cos-1250000000, region: ap-shanghai, credential: env://COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.example", beta_base_url: "https://beta-cn.example", distribution: zone-cos, credential: env://COS_CDN}`, 1)
	cfg, err := Decode(strings.NewReader(yaml))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		target   string
		verifier string
	}{
		{target: "cf", verifier: "env://ORIGIN"},
		{target: "cf", verifier: "env://SOW_PUBLIC_BASE_URL"},
		{target: "cos", verifier: "env://SOW_COS_SECRET_ID"},
	} {
		t.Run(test.target+"-"+test.verifier, func(t *testing.T) {
			cfg.Edge.TokenVerifier = test.verifier
			if _, err := cfg.EdgeDeployment(test.target); err == nil || !strings.Contains(err.Error(), "collides") {
				t.Fatalf("edge deployment accepted cross-kind binding collision verifier=%s err=%v", test.verifier, err)
			}
		})
	}
}

func TestEdgeDeploymentRejectsTokenAndBasicEntitlementAlias(t *testing.T) {
	yaml := strings.Replace(validYAML(""), "token_verifier: provider://pigsty-entitlements", "token_verifier: env://"+EdgeRuntimeBasicEntitlementsVariable, 1)
	yaml = strings.Replace(yaml, "targets: {}", `targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.example.invalid", bucket: repo-cf, credential: env://CF_STORAGE}
    cdn: {kind: cloudflare, base_url: "https://repo.example", beta_base_url: "https://beta.example", zone_id: zone-cf, credential: env://CF_CDN}`, 1)
	if _, err := Decode(strings.NewReader(yaml)); err == nil || !strings.Contains(err.Error(), "Basic entitlement") {
		t.Fatalf("edge deployment accepted token/Basic authority alias err=%v", err)
	}
}

func TestSharedEdgeRuntimeFixtureMatchesGoMapping(t *testing.T) {
	data, err := os.ReadFile("../../edge/testdata/runtime-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Schema           string            `json:"schema"`
		ProPrefix        string            `json:"pro_prefix"`
		TokenVerifier    string            `json:"token_verifier"`
		RuntimeVariables map[string]string `json:"runtime_variables"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != EdgeRuntimeSchema || fixture.ProPrefix != DefaultProPrefix {
		t.Fatalf("fixture contract drift: %#v", fixture)
	}
	if _, err := ParseTokenVerifierReference(fixture.TokenVerifier); err != nil {
		t.Fatalf("fixture verifier reference: %v", err)
	}
	want := map[string]string{
		EdgeRuntimeSchemaVariable:        EdgeRuntimeSchema,
		EdgeRuntimeProPrefixVariable:     DefaultProPrefix,
		EdgeRuntimeTokenVerifierVariable: fixture.TokenVerifier,
		EdgeRuntimeCompatibilityVariable: `{"apt_roots":["apt/infra"],"yum_repos":["infra"],"yum_roots":["yum/infra/x86_64"],"yum_channels":[{"view":"beta","repo":"infra","os":"el9","arch":"x86_64","root":"yum/infra/x86_64"},{"view":"latest","repo":"infra","os":"el9","arch":"x86_64","root":"yum/infra/x86_64"},{"view":"stable","repo":"infra","os":"el9","arch":"x86_64","root":"yum/infra/x86_64"}],"asset_roots":["pkg"],"asset_keys":[],"projections":[],"snapshots":[{"id":"jammy-20260712","apt_roots":["apt/infra"],"yum_roots":["yum/infra/x86_64"],"asset_roots":["pkg"],"asset_keys":[]}],"raw":[],"active":[]}`,
	}
	if !reflect.DeepEqual(fixture.RuntimeVariables, want) {
		t.Fatalf("fixture runtime variables=%v want=%v", fixture.RuntimeVariables, want)
	}
}

func TestDeploymentFixtureIsExactGoContractForBothAdapters(t *testing.T) {
	data, err := os.ReadFile("../../edge/testdata/deployment-contracts.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]EdgeDeploymentContract
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	yaml := strings.Replace(validYAML(""), "targets: {}", `targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.example.invalid", bucket: repo-cf, credential: env://CF_STORAGE}
    cdn: {kind: cloudflare, base_url: "https://repo.example", beta_base_url: "https://beta.example", zone_id: zone-cf, credential: env://CF_CDN}
  cos:
    storage: {kind: cos, endpoint: "https://cos.example.invalid", bucket: repo-cos-1250000000, region: ap-shanghai, credential: env://COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.example", beta_base_url: "https://beta-cn.example", distribution: zone-cos, credential: env://COS_CDN}`, 1)
	cfg, err := Decode(strings.NewReader(yaml))
	if err != nil {
		t.Fatal(err)
	}
	for fixtureName, targetName := range map[string]string{"cloudflare": "cf", "edgeone": "cos"} {
		got, err := cfg.EdgeDeployment(targetName)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, fixture[fixtureName]) {
			gotJSON, _ := json.MarshalIndent(got, "", "  ")
			wantJSON, _ := json.MarshalIndent(fixture[fixtureName], "", "  ")
			t.Fatalf("%s deployment fixture drift\ngot: %s\nwant: %s", fixtureName, gotJSON, wantJSON)
		}
	}
}
