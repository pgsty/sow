package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func TestDEBAddBuildsSignedByHashRepositoryFromExternalPackage(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(debTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "apt/test")
	encoded, err := os.ReadFile("../aptrepo/testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64")
	if err != nil {
		t.Fatal(err)
	}
	debBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	debPath := filepath.Join(root, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb")
	if err := os.WriteFile(debPath, debBytes, 0o444); err != nil {
		t.Fatal(err)
	}
	created := time.Unix(1_500_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW CLI APT Test", "", "sow@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: testOpenPGPRSABits})
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	if err := entity.SerializePrivate(&private, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	var public bytes.Buffer
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "signing.key")
	if err := os.WriteFile(keyPath, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(root, "repository-public.pgp")
	if err := os.WriteFile(publicPath, public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err = runAdd(context.Background(), []string{debPath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("deb add: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "inrelease=dists/jammy/InRelease") {
		t.Fatalf("missing APT evidence: %s", stdout.String())
	}

	target := filepath.Join(root, ".sow", "materialized", "beta", "apt", "test")
	pkg, err := aptrepo.InspectPackage(context.Background(), debPath, "main")
	if err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(target, filepath.FromSlash(pkg.PoolPath))
	packageInfo, err := os.Stat(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := repository.ParseDigest(pkg.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	poolInfo, err := os.Stat(filepath.Join(root, ".pool", "sha256", pkg.SHA256[:2], digest.String()))
	if err != nil || !os.SameFile(packageInfo, poolInfo) {
		t.Fatalf("DEB is not a CAS hardlink: %v", err)
	}
	packagesBytes, err := os.ReadFile(filepath.Join(target, "dists", "jammy", "main", "binary-arm64", "Packages"))
	if err != nil {
		t.Fatal(err)
	}
	packages := string(packagesBytes)
	if !strings.Contains(packages, "Package: libpqtypes0\n") || !strings.Contains(packages, "Filename: "+pkg.PoolPath+"\n") || !strings.Contains(packages, "SHA256: "+pkg.SHA256+"\n") {
		t.Fatalf("generated Packages omits package evidence:\n%s", packages)
	}
	byHash, err := filepath.Glob(filepath.Join(target, "dists", "jammy", "main", "binary-arm64", "by-hash", "SHA256", "*"))
	if err != nil || len(byHash) < 3 {
		t.Fatalf("by-hash artifacts=%d err=%v", len(byHash), err)
	}
	for _, artifact := range byHash {
		info, err := os.Lstat(artifact)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("by-hash artifact is not an independent regular file: %s: %v", artifact, err)
		}
	}

	loaded, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(loaded.StatePath())
	ref, _ := state.ViewRef("beta", "deb-test", "jammy", "arm64")
	commit, exists, err := canonical.Ref(ref)
	if err != nil || !exists {
		t.Fatalf("view ref exists=%v err=%v", exists, err)
	}
	signedAt, err := canonical.CommitTime(commit)
	if err != nil {
		t.Fatal(err)
	}
	release, err := os.ReadFile(filepath.Join(target, "dists", "jammy", "Release"))
	if err != nil {
		t.Fatal(err)
	}
	inRelease, err := os.ReadFile(filepath.Join(target, "dists", "jammy", "InRelease"))
	if err != nil {
		t.Fatal(err)
	}
	detached, err := os.ReadFile(filepath.Join(target, "dists", "jammy", "Release.gpg"))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := aptrepo.NewSigner(bytes.NewReader(private.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Verify(release, inRelease, detached, signedAt); err != nil {
		t.Fatalf("verify generated APT signatures: %v", err)
	}
	// Add the same immutable package to a second suite through a narrowed
	// selector. Rebuilding the shared APT root must preserve jammy while adding
	// bookworm; exact reconciliation of only the selected suite would prune it.
	stdout.Reset()
	stderr.Reset()
	err = runAdd(context.Background(), []string{debPath, "--config", configPath, "--repo", "deb-test", "--os", "bookworm", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("bookworm-scoped add: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	for _, suite := range []string{"jammy", "bookworm"} {
		indexed, readErr := os.ReadFile(filepath.Join(target, "dists", suite, "main", "binary-arm64", "Packages"))
		if readErr != nil || !strings.Contains(string(indexed), "Package: libpqtypes0\n") {
			t.Fatalf("scoped add pruned suite %s err=%v Packages=%s", suite, readErr, indexed)
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"verify", "--layer", "L1", "--view", "beta", "--config", configPath, "--repo", "deb-test", "--gpg-public-key-file", publicPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "outcome=passed") {
		t.Fatalf("APT CLI verify code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	err = runAdd(context.Background(), []string{debPath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr)
	if err != nil || !strings.Contains(stdout.String(), "add unchanged format=deb") {
		t.Fatalf("deb replay err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	err = runRemove(context.Background(), []string{pkg.Name, "--config", configPath, "--repo", "deb-test", "--os", "jammy", "--view", "beta", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr)
	if err != nil || !strings.Contains(stdout.String(), "removed view=beta entries=1") {
		t.Fatalf("deb remove err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(packagePath); err != nil {
		t.Fatalf("jammy-scoped remove pruned bookworm shared payload: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".pool", "sha256", pkg.SHA256[:2], digest.String())); err != nil {
		t.Fatalf("DEB removal deleted CAS object: %v", err)
	}
	packagesBytes, err = os.ReadFile(filepath.Join(target, "dists", "jammy", "main", "binary-arm64", "Packages"))
	if err != nil || strings.Contains(string(packagesBytes), "Package: libpqtypes0\n") {
		t.Fatalf("removed DEB remains indexed err=%v Packages=%s", err, packagesBytes)
	}
	bookwormPackages, err := os.ReadFile(filepath.Join(target, "dists", "bookworm", "main", "binary-arm64", "Packages"))
	if err != nil || !strings.Contains(string(bookwormPackages), "Package: libpqtypes0\n") {
		t.Fatalf("jammy-scoped remove pruned bookworm err=%v Packages=%s", err, bookwormPackages)
	}
	stdout.Reset()
	stderr.Reset()
	err = runRemove(context.Background(), []string{pkg.Name, "--config", configPath, "--repo", "deb-test", "--os", "bookworm", "--view", "beta", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr)
	if err != nil || !strings.Contains(stdout.String(), "removed view=beta entries=1") {
		t.Fatalf("bookworm remove err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(packagePath); !os.IsNotExist(err) {
		t.Fatalf("fully unreferenced DEB remains in repository: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	err = runRemove(context.Background(), []string{pkg.Name, "--config", configPath, "--repo", "deb-test", "--os", "bookworm", "--view", "beta", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr)
	if err != nil || !strings.Contains(stdout.String(), "rm unchanged") || !strings.Contains(stdout.String(), "selectors=1") {
		t.Fatalf("deb remove replay err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
}

func TestDEBSuiteInferenceAndAllArchitectureExpansion(t *testing.T) {
	repo := config.Repo{Arches: []string{"amd64", "arm64"}, APT: &config.APTConfig{Suites: []string{"jammy", "bookworm"}}}
	pkg := aptrepo.Package{Version: "1.5.1-9.pgdg22.04+1", SourcePath: "package_all.deb"}
	if got := debSuiteCandidates(repo, pkg, nil); len(got) != 1 || got[0] != "jammy" {
		t.Fatalf("suite inference = %v", got)
	}
	if got := debLeafArches(repo, "all", nil); strings.Join(got, ",") != "amd64,arm64" {
		t.Fatalf("all architecture expansion = %v", got)
	}
	if got := debSuiteCandidates(repo, pkg, []string{"bookworm"}); len(got) != 1 || got[0] != "bookworm" {
		t.Fatalf("explicit suite selection = %v", got)
	}
}

func TestSparseAPTAddAndLifecycleGatesFailClosedBeforeStateMutation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(sparseAPTLifecycleTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile("../aptrepo/testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64")
	if err != nil {
		t.Fatal(err)
	}
	debBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	debPath := filepath.Join(root, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb")
	if err := os.WriteFile(debPath, debBytes, 0o444); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err = runAdd(context.Background(), []string{debPath, "--config", configPath, "--repo", "apt-pgdg", "--os", "bookworm-pgdg", "--component", "18"}, &stdout, &stderr)
	if exitCode(err) != ExitConfig || !strings.Contains(err.Error(), "must match exactly one APT repo/suite") {
		t.Fatalf("stable suite accepted testing-only component: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, ".sow")); !os.IsNotExist(statErr) {
		t.Fatalf("rejected sparse component mutated canonical state: %v", statErr)
	}

	stdout.Reset()
	stderr.Reset()
	err = runAdd(context.Background(), []string{debPath, "--config", configPath, "--repo", "apt-pgdg", "--os", "bookworm-pgdg", "--component", "main"}, &stdout, &stderr)
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "suite bookworm-pgdg is frozen") {
		t.Fatalf("frozen suite accepted DEB add: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, ".sow")); !os.IsNotExist(statErr) {
		t.Fatalf("rejected frozen add mutated canonical state: %v", statErr)
	}

	stdout.Reset()
	stderr.Reset()
	err = runRemove(context.Background(), []string{"libpqtypes0", "--config", configPath, "--repo", "apt-pgdg", "--os", "bookworm-pgdg"}, &stdout, &stderr)
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "suite bookworm-pgdg is frozen") {
		t.Fatalf("frozen suite accepted remove: %v", err)
	}

	factoryCalled := false
	stdout.Reset()
	stderr.Reset()
	err = runSyncWithClientFactory(context.Background(), []string{"--config", configPath, "--upstream", "pgdg-bookworm"}, &stdout, &stderr, func(config.Upstream, []byte) (*http.Client, error) {
		factoryCalled = true
		return nil, errors.New("network factory must not run")
	})
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "suite bookworm-pgdg is frozen") || factoryCalled {
		t.Fatalf("frozen suite sync gate err=%v factory_called=%v", err, factoryCalled)
	}
	if _, statErr := os.Stat(filepath.Join(root, ".sow")); !os.IsNotExist(statErr) {
		t.Fatalf("rejected frozen operations mutated canonical state: %v", statErr)
	}

	if err := os.MkdirAll(filepath.Join(root, "apt", "pgdg"), 0o755); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"init", "--config", configPath, "--repo", "apt-pgdg", "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("initialize frozen promotion fixture code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	loaded, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(loaded.StatePath())
	viewStage := filepath.Join(root, "frozen-beta.tsv")
	file, err := os.OpenFile(viewStage, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	entry := views.Entry{Repo: "apt-pgdg", OS: "bookworm-pgdg", Arch: "arm64", Name: "libpqtypes0", Version: "1", Path: "apt/pgdg/pool/main/l/libpqtypes0.deb", Size: 1, SHA256: strings.Repeat("0", 64), Pool: "public"}
	if err := views.WriteEntry(file, entry); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	canonicalPath, _ := state.ViewPath("beta", entry.Repo, entry.OS, entry.Arch)
	commit, _, err := canonical.InstallPaths(map[string]string{canonicalPath: viewStage}, "seed frozen beta leaf")
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := state.ViewRef("beta", entry.Repo, entry.OS, entry.Arch)
	if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	err = runPromote(context.Background(), []string{"beta", "latest", "--config", configPath, "--repo", "apt-pgdg", "--os", "bookworm-pgdg", "--arch", "arm64"}, &stdout, &stderr)
	if exitCode(err) != ExitConflict || !strings.Contains(err.Error(), "suite bookworm-pgdg is frozen") {
		t.Fatalf("frozen suite accepted promotion: %v", err)
	}
	headAfter, err := canonical.HeadHash()
	if err != nil || headAfter != headBefore {
		t.Fatalf("rejected promotion changed canonical HEAD before=%s after=%s err=%v", headBefore, headAfter, err)
	}
	latestRef, _ := state.ViewRef("latest", entry.Repo, entry.OS, entry.Arch)
	if _, exists, err := canonical.Ref(latestRef); err != nil || exists {
		t.Fatalf("rejected frozen promotion advanced latest exists=%v err=%v", exists, err)
	}
}

func TestSparseAPTMaterializationNeverGeneratesStableTestingComponents(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(sparseAPTMaterializeTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "apt/pgdg")
	encoded, err := os.ReadFile("../aptrepo/testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64")
	if err != nil {
		t.Fatal(err)
	}
	debBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	debPath := filepath.Join(root, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb")
	if err := os.WriteFile(debPath, debBytes, 0o444); err != nil {
		t.Fatal(err)
	}
	created := time.Unix(1_500_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW Sparse APT Test", "", "sow@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: testOpenPGPRSABits})
	if err != nil {
		t.Fatal(err)
	}
	var private, public bytes.Buffer
	if err := entity.SerializePrivate(&private, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "signing.key")
	publicPath := filepath.Join(root, "repository-public.pgp")
	if err := os.WriteFile(keyPath, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, operation := range []struct {
		suite     string
		component string
	}{
		{suite: "bookworm-pgdg", component: "main"},
		{suite: "bookworm-pgdg-testing", component: "18"},
	} {
		var stdout, stderr bytes.Buffer
		err := runAdd(context.Background(), []string{debPath, "--config", configPath, "--repo", "apt-pgdg", "--os", operation.suite, "--component", operation.component, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr)
		if err != nil {
			t.Fatalf("add suite=%s component=%s: %v stdout=%s stderr=%s", operation.suite, operation.component, err, stdout.String(), stderr.String())
		}
	}
	target := filepath.Join(root, ".sow", "materialized", "beta", "apt", "pgdg", "dists")
	stableRelease, err := os.ReadFile(filepath.Join(target, "bookworm-pgdg", "Release"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stableRelease), "Components: main\n") || strings.Contains(string(stableRelease), "Components: main 18") {
		t.Fatalf("stable Release widened components:\n%s", stableRelease)
	}
	if _, err := os.Stat(filepath.Join(target, "bookworm-pgdg", "18")); !os.IsNotExist(err) {
		t.Fatalf("stable suite gained testing component directory: %v", err)
	}
	testingRelease, err := os.ReadFile(filepath.Join(target, "bookworm-pgdg-testing", "Release"))
	if err != nil {
		t.Fatal(err)
	}
	componentLine := ""
	for _, line := range strings.Split(string(testingRelease), "\n") {
		if strings.HasPrefix(line, "Components:") {
			componentLine = strings.Join(strings.Fields(strings.TrimPrefix(line, "Components:")), ",")
			break
		}
	}
	if componentLine != "18,19,main" {
		t.Fatalf("testing Release omitted exact component contract:\n%s", testingRelease)
	}
	if packages, err := os.ReadFile(filepath.Join(target, "bookworm-pgdg-testing", "18", "binary-arm64", "Packages")); err != nil || !strings.Contains(string(packages), "Package: libpqtypes0\n") {
		t.Fatalf("testing component was not materialized err=%v Packages=%s", err, packages)
	}

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"verify", "--layer", "L1", "--view", "beta", "--config", configPath, "--repo", "apt-pgdg", "--gpg-public-key-file", publicPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "outcome=passed") {
		t.Fatalf("sparse APT L1 verify code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

const debTestConfig = `schema: sow/v1
state: {}
gpg:
  public_key: repository-public.pgp
pools:
  public: {}
  gated: {}
repos:
  - id: deb-test
    type: apt
    path: apt/test
    default_pool: public
    arches: [arm64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy, bookworm], components: [main]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`

const sparseAPTLifecycleTestConfig = `schema: sow/v1
state: {}
gpg: {public_key: repository-public.pgp}
pools:
  public: {}
  gated: {}
repos:
  - id: apt-pgdg
    type: apt
    path: apt/pgdg
    default_pool: public
    arches: [arm64]
    os: {family: debian, lifecycle: active}
    apt:
      suites: [bookworm-pgdg, bookworm-pgdg-testing]
      components: [main, "18", "19"]
      suite_components:
        bookworm-pgdg: [main]
        bookworm-pgdg-testing: [main, "18", "19"]
      suite_lifecycle:
        bookworm-pgdg: frozen
        bookworm-pgdg-testing: active
upstreams:
  - id: pgdg-bookworm
    type: apt
    repo: apt-pgdg
    url: https://apt.example.invalid/pgdg/
    suite: bookworm-pgdg
    components: [main]
    arches: [arm64]
    debuginfo: drop
    keyring: keys/pgdg.asc
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`

const sparseAPTMaterializeTestConfig = `schema: sow/v1
state: {}
gpg: {public_key: repository-public.pgp}
pools:
  public: {}
  gated: {}
repos:
  - id: apt-pgdg
    type: apt
    path: apt/pgdg
    default_pool: public
    arches: [arm64]
    os: {family: debian, lifecycle: active}
    apt:
      suites: [bookworm-pgdg, bookworm-pgdg-testing]
      components: [main, "18", "19"]
      suite_components:
        bookworm-pgdg: [main]
        bookworm-pgdg-testing: [main, "18", "19"]
      suite_lifecycle:
        bookworm-pgdg: active
        bookworm-pgdg-testing: active
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
