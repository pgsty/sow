package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzParseCanonicalRoundTrip(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("schema: sow/v2\n"),
		[]byte("schema: sow/v2\narchitectures: [amd64, arm64]\nrepos:\n  repo:\n    dists:\n      el9: {format: rpm}\n"),
		[]byte("schema: sow/v2\nrepos:\n  repo:\n    dists:\n      noble:\n        format: deb\n        limit: 2\n        exclude:\n          - kind: [dbgsym]\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		cfg, err := Parse(data)
		if err != nil {
			return
		}
		canonical, err := Marshal(cfg)
		if err != nil {
			t.Fatalf("marshal parsed config: %v", err)
		}
		reparsed, err := Parse(canonical)
		if err != nil {
			t.Fatalf("parse canonical config: %v\n%s", err, canonical)
		}
		second, err := Marshal(reparsed)
		if err != nil {
			t.Fatalf("remarshal canonical config: %v", err)
		}
		if !bytes.Equal(canonical, second) {
			t.Fatalf("canonical config is not byte-stable:\nfirst:\n%s\nsecond:\n%s", canonical, second)
		}
	})
}

func TestParseNormalizesDefaultsAndAliases(t *testing.T) {
	cfg, err := Parse([]byte(`
schema: sow/v2
architectures: [amd64, arm64]
repos:
  pgsql:
    protected: true
    dists:
      el9:
        format: rpm
      noble:
        format: deb
        architectures: [amd64]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := strings.Join(cfg.Architectures, ","), "x86_64,aarch64"; got != want {
		t.Fatalf("architectures = %q, want %q", got, want)
	}
	repo := cfg.Repositories["pgsql"]
	if !repo.Protected {
		t.Fatal("protected repository was not preserved")
	}
	if repo.Dists["el9"].Architectures != nil {
		t.Fatalf("omitted dist architectures should remain inherited, got %#v", repo.Dists["el9"].Architectures)
	}
	if got, want := strings.Join(repo.Dists["noble"].Architectures, ","), "x86_64"; got != want {
		t.Fatalf("dist architectures = %q, want %q", got, want)
	}
}

func TestParseUsesDefaultArchitectures(t *testing.T) {
	cfg, err := Parse([]byte("schema: sow/v2\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := strings.Join(cfg.Architectures, ","), "x86_64,aarch64"; got != want {
		t.Fatalf("architectures = %q, want %q", got, want)
	}
	if cfg.Repositories == nil {
		t.Fatal("repositories map must be initialized")
	}
}

func TestParseRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"empty", "", "schema"},
		{"wrong schema", "schema: sow/v1\n", "schema"},
		{"unknown root", "schema: sow/v2\nfuture: true\n", "field future"},
		{"duplicate root", "schema: sow/v2\nschema: sow/v2\n", "already defined"},
		{"duplicate nested", "schema: sow/v2\nrepos:\n  pgsql:\n    protected: true\n    protected: false\n", "already defined"},
		{"unknown nested", "schema: sow/v2\nrepos:\n  pgsql:\n    path: elsewhere\n", "field path"},
		{"duplicate canonical architecture", "schema: sow/v2\narchitectures: [x86_64, amd64]\n", "duplicate architecture"},
		{"neutral workspace architecture", "schema: sow/v2\narchitectures: [neutral]\n", "neutral"},
		{"neutral rpm architecture", "schema: sow/v2\narchitectures: [noarch]\n", "noarch"},
		{"unsupported architecture", "schema: sow/v2\narchitectures: [riscv64]\n", "unsupported architecture"},
		{"empty explicit architectures", "schema: sow/v2\narchitectures: []\n", "architectures must not be empty"},
		{"invalid repo name", "schema: sow/v2\nrepos:\n  Bad: {}\n", "repository name"},
		{"reserved repo name", "schema: sow/v2\nrepos:\n  pool: {}\n", "reserved"},
		{"invalid dist name", "schema: sow/v2\nrepos:\n  pgsql:\n    dists:\n      ../el9:\n        format: rpm\n", "dist name"},
		{"reserved dist name", "schema: sow/v2\nrepos:\n  pgsql:\n    dists:\n      dists:\n        format: rpm\n", "reserved"},
		{"missing format", "schema: sow/v2\nrepos:\n  pgsql:\n    dists:\n      el9: {}\n", "format"},
		{"invalid format", "schema: sow/v2\nrepos:\n  pgsql:\n    dists:\n      el9:\n        format: apk\n", "format"},
		{"dist architecture outside workspace", "schema: sow/v2\narchitectures: [x86_64]\nrepos:\n  pgsql:\n    dists:\n      el9:\n        format: rpm\n        architectures: [aarch64]\n", "not allowed by workspace"},
		{"empty dist architectures", "schema: sow/v2\nrepos:\n  pgsql:\n    dists:\n      el9:\n        format: rpm\n        architectures: []\n", "architectures must not be empty"},
		{"negative limit", "schema: sow/v2\nrepos:\n  pgsql:\n    dists:\n      el9:\n        format: rpm\n        limit: -1\n", "limit must be zero or positive"},
		{"empty exclude rule", "schema: sow/v2\nrepos:\n  pgsql:\n    dists:\n      el9:\n        format: rpm\n        exclude: [{}]\n", "exclude rule 0 is empty"},
		{"invalid exclude glob", "schema: sow/v2\nrepos:\n  pgsql:\n    dists:\n      el9:\n        format: rpm\n        exclude:\n          - name: ['[']\n", "invalid glob"},
		{"unknown exclude field", "schema: sow/v2\nrepos:\n  pgsql:\n    dists:\n      el9:\n        format: rpm\n        exclude:\n          - version: ['1.*']\n", "field version"},
		{"signing mode without key", "schema: sow/v2\nrepos:\n  pgsql:\n    signing:\n      rpm:\n        packages:\n          mode: fill\n", "requires key"},
		{"invalid signing mode", "schema: sow/v2\nrepos:\n  pgsql:\n    signing:\n      rpm:\n        packages:\n          mode: sometimes\n          key: env://KEY\n", "mode must be"},
		{"invalid env key reference", "schema: sow/v2\nrepos:\n  pgsql:\n    signing:\n      rpm:\n        metadata:\n          key: env://BAD-NAME\n", "invalid env key reference"},
		{"unsupported key reference", "schema: sow/v2\nrepos:\n  pgsql:\n    signing:\n      deb:\n        metadata:\n          key: vault://secret\n", "unsupported key reference scheme"},
		{"passphrase without key", "schema: sow/v2\nrepos:\n  pgsql:\n    signing:\n      deb:\n        metadata:\n          passphrase: env://PASSPHRASE\n", "passphrase requires key"},
		{"invalid passphrase reference", "schema: sow/v2\nrepos:\n  pgsql:\n    signing:\n      deb:\n        metadata:\n          key: keys/repo.asc\n          passphrase: vault://secret\n", "unsupported passphrase reference scheme"},
		{"agent key explicit passphrase", "schema: sow/v2\nrepos:\n  pgsql:\n    signing:\n      rpm:\n        metadata:\n          key: agent://0123456789abcdef\n          passphrase: env://PASSPHRASE\n", "ambient gpg-agent"},
		{"duplicate trusted key reference", "schema: sow/v2\nrepos:\n  pgsql:\n    signing:\n      rpm:\n        packages:\n          trusted_keys: [keys/a.asc, keys/a.asc]\n", "duplicate rpm trusted key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestParseNormalizesPolicyAndSigning(t *testing.T) {
	cfg, err := Parse([]byte(`
schema: sow/v2
repos:
  pgsql:
    signing:
      rpm:
        packages:
          key: env://SOW_RPM_KEY
          trusted_keys: [keys/pgdg.asc]
        metadata:
          key: agent://0123456789abcdef
      deb:
        metadata:
          key: file://keys/repo.asc
    dists:
      el9:
        format: rpm
        limit: 1
        exclude:
          - kind: [debuginfo, debugsource, llvmjit]
          - name: ['test-*']
            arch: [aarch64]
`))
	if err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repositories["pgsql"]
	if repo.Signing.RPM.Packages.Mode != "fill" {
		t.Fatalf("default signing mode = %q", repo.Signing.RPM.Packages.Mode)
	}
	dist := repo.Dists["el9"]
	if dist.Limit != 1 || len(dist.Exclude) != 2 || len(dist.Exclude[0].Kind) != 3 {
		t.Fatalf("normalized policy = %#v", dist)
	}
}

func TestEffectiveViewExpandsDefaultsAndCanonicalizes(t *testing.T) {
	cfg, err := Parse([]byte(`
schema: sow/v2
repos:
  pgsql:
    dists:
      el9:
        format: rpm
      noble:
        format: deb
        architectures: [arm64]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	view, err := EffectiveView(cfg, ViewOptions{})
	if err != nil {
		t.Fatalf("EffectiveView: %v", err)
	}
	got, err := MarshalEffective(view)
	if err != nil {
		t.Fatalf("MarshalEffective: %v", err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "effective.golden.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("effective YAML mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestMarshalIsCanonicalAndStable(t *testing.T) {
	cfg, err := Parse([]byte(`
repos:
  zed:
    dists:
      noble: {format: deb, architectures: [amd64]}
  alpha: {}
architectures: [arm64, amd64]
schema: sow/v2
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	one, err := Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(one) != string(two) {
		t.Fatal("Marshal is not byte stable")
	}
	if strings.Contains(string(one), "amd64") || !strings.Contains(string(one), "x86_64") {
		t.Fatalf("Marshal did not canonicalize aliases:\n%s", one)
	}
	reparsed, err := Parse(one)
	if err != nil {
		t.Fatalf("canonical output does not parse: %v", err)
	}
	if strings.Join(reparsed.Architectures, ",") != "aarch64,x86_64" {
		t.Fatalf("architecture order changed: %#v", reparsed.Architectures)
	}
}

func TestArchitectureAndNameHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"x86_64":  "x86_64",
		"amd64":   "x86_64",
		"aarch64": "aarch64",
		"arm64":   "aarch64",
	} {
		got, err := CanonicalArchitecture(in)
		if err != nil || got != want {
			t.Errorf("CanonicalArchitecture(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"all", "noarch", "neutral", "riscv64", ""} {
		if _, err := CanonicalArchitecture(in); err == nil {
			t.Errorf("CanonicalArchitecture(%q) unexpectedly succeeded", in)
		}
	}
	for _, valid := range []string{"infra", "el9-beta", "noble.1", "repo_2", "0"} {
		if err := ValidateName(valid); err != nil {
			t.Errorf("ValidateName(%q): %v", valid, err)
		}
	}
	for _, invalid := range []string{"", ".", "..", ".sow", "pool", "dists", "sow.yml", "workspace-ops", "repo-locks", "workspace.lock", "UPPER", "a/b", "-bad"} {
		if err := ValidateName(invalid); err == nil {
			t.Errorf("ValidateName(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestRepositoryDerivedStatePathCollisionsAreRejected(t *testing.T) {
	for _, second := range []string{"foo.db", "foo.db-wal", "foo.db-shm", "foo.db-journal"} {
		t.Run(second, func(t *testing.T) {
			data := []byte("schema: sow/v2\nrepos:\n  foo: {}\n  " + second + ": {}\n")
			if _, err := Parse(data); err == nil || !strings.Contains(err.Error(), "collide") {
				t.Fatalf("Parse collision error=%v", err)
			}
		})
	}
}

func TestEffectiveViewScopeAndStateArchitectureReferences(t *testing.T) {
	cfg, err := Parse([]byte(`
schema: sow/v2
architectures: [x86_64, aarch64]
repos:
  infra:
    dists:
      el9: {format: rpm}
  pgsql:
    dists:
      noble: {format: deb, architectures: [amd64]}
`))
	if err != nil {
		t.Fatal(err)
	}
	view, err := EffectiveView(cfg, ViewOptions{Repository: "pgsql", Dist: "noble"})
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Repositories) != 1 || len(view.Repositories["pgsql"].Dists) != 1 {
		t.Fatalf("scoped view = %#v", view)
	}
	if got := strings.Join(view.Repositories["pgsql"].Dists["noble"].Architectures, ","); got != "x86_64" {
		t.Fatalf("effective architectures = %q", got)
	}

	valid := []StateArchitectureReference{{Repository: "pgsql", Dist: "noble", Architecture: "amd64", Source: "built generation"}}
	if err := ValidateStateArchitectureReferences(cfg, valid); err != nil {
		t.Fatalf("valid state refs: %v", err)
	}
	tests := []struct {
		name string
		refs []StateArchitectureReference
		want string
	}{
		{"removed repo", []StateArchitectureReference{{Repository: "gone", Dist: "noble", Architecture: "x86_64"}}, "removed repository"},
		{"removed dist", []StateArchitectureReference{{Repository: "pgsql", Dist: "gone", Architecture: "x86_64"}}, "removed dist"},
		{"removed architecture", []StateArchitectureReference{{Repository: "pgsql", Dist: "noble", Architecture: "aarch64", Source: "membership"}}, "removed from"},
		{"neutral is not family", []StateArchitectureReference{{Repository: "pgsql", Dist: "noble", Architecture: "neutral"}}, "not a canonical CPU family"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateStateArchitectureReferences(cfg, tt.refs); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestEffectiveViewExposesPolicyAndSigningReferencesOnly(t *testing.T) {
	t.Setenv("SOW_SECRET_KEY", "PRIVATE SECRET MATERIAL")
	cfg, err := Parse([]byte("schema: sow/v2\nrepos:\n  pgsql:\n    signing:\n      rpm:\n        metadata:\n          key: env://SOW_SECRET_KEY\n    dists:\n      el9:\n        format: rpm\n        limit: 1\n        exclude:\n          - kind: [debuginfo]\n"))
	if err != nil {
		t.Fatal(err)
	}
	all, err := EffectiveView(cfg, ViewOptions{Repository: "pgsql"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalEffective(all)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"signing:", "env://SOW_SECRET_KEY", "mode: never", "limit: 1", "exclude:", "debuginfo"} {
		if !strings.Contains(string(data), required) {
			t.Fatalf("effective view omitted %q:\n%s", required, data)
		}
	}
	if strings.Contains(string(data), "PRIVATE SECRET MATERIAL") {
		t.Fatalf("effective view resolved secret material:\n%s", data)
	}
}

func TestLoadAndPublicHelpers(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, ConfigFilename)
	if err := os.WriteFile(filename, []byte("schema: sow/v2\nrepos:\n  pgsql:\n    dists:\n      el9: {format: rpm}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, digest, err := LoadWithSHA(filename)
	if err != nil {
		t.Fatalf("LoadWithSHA: %v", err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("config digest=%q", digest)
	}
	if standalone, err := FileSHA(filename); err != nil || standalone != digest {
		t.Fatalf("FileSHA=%q err=%v", standalone, err)
	}
	if got := strings.Join(RepositoryNames(cfg), ","); got != "pgsql" {
		t.Fatalf("RepositoryNames = %q", got)
	}
	architectures, err := EffectiveArchitectures(cfg, "pgsql", "el9")
	if err != nil {
		t.Fatalf("EffectiveArchitectures: %v", err)
	}
	if got := strings.Join(architectures, ","); got != "x86_64,aarch64" {
		t.Fatalf("EffectiveArchitectures = %q", got)
	}
	link := filepath.Join(root, "linked.yml")
	if err := os.Symlink(filename, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Load symlink error = %v", err)
	}
	if _, err := Load(root); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Load directory error = %v", err)
	}
	oversized := filepath.Join(root, "oversized.yml")
	file, err := os.OpenFile(oversized, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxConfigBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(oversized); err == nil || !strings.Contains(err.Error(), "bounded regular file") {
		t.Fatalf("Load oversized error = %v", err)
	}
}
