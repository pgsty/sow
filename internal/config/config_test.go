package config

import (
	"os"
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
gpg: {}
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
	if cfg.Edge.ProPrefix != DefaultProPrefix || cfg.State.SnapshotMaterializationMonths != DefaultSnapshotAge {
		t.Fatalf("frozen defaults not applied: %#v %#v", cfg.Edge, cfg.State)
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
	yaml := strings.Replace(validYAML(""), "gpg: {}", "gpg: {passphrase: literal-secret}", 1)
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

	yaml := strings.Replace(validYAML(""), "token_verifier: provider://", "pro_prefix: /other/{token}/\n  token_verifier: provider://", 1)
	_, err = Decode(strings.NewReader(yaml))
	if err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("wanted frozen prefix error, got %v", err)
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
	if err == nil || !strings.Contains(err.Error(), "EL8") {
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
