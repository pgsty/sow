package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestRPMReleaseDistTagNarrowsMultiELRepositoryMatrix(t *testing.T) {
	repos := []config.Repo{
		{ID: "el8", Type: "yum", OS: config.OSConfig{Family: "el", Major: 8}, Arches: []string{"x86_64"}},
		{ID: "el9", Type: "yum", OS: config.OSConfig{Family: "el", Major: 9}, Arches: []string{"x86_64"}},
		{ID: "el10", Type: "yum", OS: config.OSConfig{Family: "el", Major: 10}, Arches: []string{"x86_64"}},
	}
	for release, want := range map[string]string{
		"1.el8": "el8", "2.el9_4": "el9", "3.rhel10.1": "el10",
	} {
		info := yumrepo.PackageInfo{Name: "probe", Release: release, Arch: "x86_64"}
		candidates, err := rpmInputCandidates("probe.rpm", info, repos, nil)
		if err != nil || len(candidates) != 1 || candidates[0].repo.ID != want {
			t.Fatalf("release=%s candidates=%v err=%v", release, candidates, err)
		}
	}
	untagged, err := rpmInputCandidates("probe.rpm", yumrepo.PackageInfo{Name: "probe", Release: "1", Arch: "x86_64"}, repos, nil)
	if err != nil || len(untagged) != 3 {
		t.Fatalf("untagged candidates=%v err=%v", untagged, err)
	}
	if _, _, err := inferRPMELMajor("1.el8.el9"); err == nil {
		t.Fatal("conflicting RPM dist tags were accepted")
	}
}

func TestRPMAddPlanningHonorsReplicateAndSeparateNoarchModes(t *testing.T) {
	packageInfo := yumrepo.PackageInfo{
		Name: "percona-release", Version: "1", Release: "1.el10", Arch: "noarch",
		Location: "Packages/p/percona-release-1-1.el10.noarch.rpm", Size: 1, SHA256: strings.Repeat("a", 64),
	}
	replicate := config.Repo{
		ID: "replicate", Type: "yum", Path: "yum/replicate/{arch}", OS: config.OSConfig{Family: "el", Major: 10},
		Arches: []string{"x86_64", "aarch64"}, DefaultPool: "public", YUM: &config.YUMConfig{NoarchMode: config.YUMNoarchReplicate},
	}
	separate := config.Repo{
		ID: "separate", Type: "yum", Path: "yum/percona/el10.{arch}", OS: config.OSConfig{Family: "el", Major: 10},
		Arches: []string{"x86_64", "aarch64", "noarch"}, DefaultPool: "public", YUM: &config.YUMConfig{NoarchMode: config.YUMNoarchSeparate},
	}

	if got := strings.Join(rpmLeafArches(replicate, "noarch", nil), ","); got != "x86_64,aarch64" {
		t.Fatalf("replicate noarch leaves=%q", got)
	}
	if got := strings.Join(rpmLeafArches(separate, "noarch", nil), ","); got != "noarch" {
		t.Fatalf("separate noarch leaves=%q", got)
	}
	if got := strings.Join(rpmLeafArches(separate, "x86_64", nil), ","); got != "x86_64" {
		t.Fatalf("separate x86_64 leaves=%q", got)
	}
	if got := rpmLeafArches(separate, "noarch", []string{"x86_64"}); len(got) != 0 {
		t.Fatalf("basearch selector widened to separate noarch leaf: %v", got)
	}
	if rpmLeafAcceptsPackageArch(separate, "noarch", "x86_64") || rpmLeafAcceptsPackageArch(separate, "x86_64", "noarch") {
		t.Fatal("separate mode admitted a package into the wrong leaf")
	}

	candidates, err := rpmInputCandidates("percona-release.rpm", packageInfo, []config.Repo{separate}, nil)
	if err != nil || len(candidates) != 1 || strings.Join(candidates[0].arches, ",") != "noarch" {
		t.Fatalf("separate add candidates=%+v err=%v", candidates, err)
	}
	groups, err := planRPMLeafGroups(candidates)
	if err != nil || len(groups) != 1 {
		t.Fatalf("separate add groups=%+v err=%v", groups, err)
	}
	for _, group := range groups {
		if group.leaf.arch != "noarch" || len(group.entries) != 1 || !strings.HasPrefix(group.entries[0].Path, "yum/percona/el10.noarch/") {
			t.Fatalf("separate noarch group=%+v", group)
		}
	}
	if candidates, err := rpmInputCandidates("percona-release.rpm", packageInfo, []config.Repo{separate}, []string{"x86_64"}); err != nil || len(candidates) != 0 {
		t.Fatalf("separate basearch selector candidates=%+v err=%v", candidates, err)
	}
}

func TestRPMAddBuildsSignedZstdRepositoryFromExternalPackage(t *testing.T) {
	root := t.TempDir()
	writeRPMPackageTrustFixture(t, root)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(rpmTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "yum/test/x86_64")
	encoded, err := os.ReadFile("testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	rpmBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := filepath.Join(root, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm")
	if err := os.WriteFile(rpmPath, rpmBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	created := time.Unix(1_500_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW CLI Test", "", "sow@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	if err := entity.SerializePrivate(&private, nil); err != nil {
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
	err = runAdd(context.Background(), []string{rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("rpm add: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "repomd_sha256=") {
		t.Fatalf("missing YUM evidence: %s", stdout.String())
	}
	target := filepath.Join(root, ".sow", "materialized", "beta", "yum", "test", "x86_64")
	repodata := filepath.Join(target, "repodata")
	info, err := yumrepo.InspectPackage(context.Background(), yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(target, filepath.FromSlash(info.Location))
	packageInfo, err := os.Stat(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := repository.ParseDigest(info.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	poolInfo, err := os.Stat(filepath.Join(root, ".pool", "sha256", info.SHA256[:2], digest.String()))
	if err != nil || !os.SameFile(packageInfo, poolInfo) {
		t.Fatalf("RPM is not a CAS hardlink: %v", err)
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(private.Bytes()), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	generation, err := yumrepo.ValidateDirectory(context.Background(), repodata, yumrepo.CompressionZstd, verifier)
	if err != nil || generation.Packages != 1 {
		t.Fatalf("validate generated repo packages=%v err=%v", generation, err)
	}
	if _, err := os.Stat(filepath.Join(repodata, "repomd.xml.asc")); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"verify", "--layer", "L1", "--view", "beta", "--config", configPath, "--repo", "rpm-test", "--gpg-public-key-file", publicPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "outcome=passed") {
		t.Fatalf("YUM CLI verify code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	err = runAdd(context.Background(), []string{rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr)
	if err != nil || !strings.Contains(stdout.String(), "add unchanged format=rpm") {
		t.Fatalf("rpm replay err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	err = runRemove(context.Background(), []string{info.Name, "--config", configPath, "--repo", "rpm-test", "--view", "beta", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr)
	if err != nil || !strings.Contains(stdout.String(), "packages=0") {
		t.Fatalf("rpm remove err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(packagePath); !os.IsNotExist(err) {
		t.Fatalf("removed RPM remains in repository: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".pool", "sha256", info.SHA256[:2], digest.String())); err != nil {
		t.Fatalf("RPM removal deleted CAS object: %v", err)
	}
	verifier, err = yumrepo.NewOpenPGPVerifier(bytes.NewReader(private.Bytes()), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	generation, err = yumrepo.ValidateDirectory(context.Background(), repodata, yumrepo.CompressionZstd, verifier)
	if err != nil || generation.Packages != 0 {
		t.Fatalf("validate empty regenerated repo packages=%v err=%v", generation, err)
	}
	stdout.Reset()
	stderr.Reset()
	err = runRemove(context.Background(), []string{info.Name, "--config", configPath, "--repo", "rpm-test", "--view", "beta", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}, &stdout, &stderr)
	if err != nil || !strings.Contains(stdout.String(), "rm unchanged") || !strings.Contains(stdout.String(), "packages=0") {
		t.Fatalf("rpm remove replay err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}
}

func TestRPMAddRejectsUntrustedPackageBeforeCASOrStateMutation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(rpmTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "yum/test/x86_64")
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	_, privateKeyPath := writeMaterializeSigningKey(t, root)
	wrongTrust, err := os.ReadFile(filepath.Join(root, "repository-public.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-trust.asc"), wrongTrust, 0o644); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, config.StateDirectory))
	before, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", privateKeyPath}, &stdout, &stderr)
	if code != ExitVerification || !strings.Contains(stderr.String(), "verify RPM package signature") {
		t.Fatalf("untrusted add code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	after, err := canonical.HeadHash()
	if err != nil || after != before {
		t.Fatalf("untrusted add mutated canonical state before=%s after=%s err=%v", before, after, err)
	}
	info, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := repository.ParseDigest(info.SHA256)
	if _, err := os.Stat(filepath.Join(root, ".pool", "sha256", info.SHA256[:2], digest.String())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("untrusted RPM entered CAS: %v", err)
	}
}

func TestRPMAddPrivateSnapshotClosesSourcePathSwap(t *testing.T) {
	root := t.TempDir()
	trustPath := writeRPMPackageTrustFixture(t, root)
	source := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	if err := os.Chmod(source, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshotDir, err := os.MkdirTemp("", "sow-add-rpm-snapshot-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(snapshotDir) })
	snapshot, err := snapshotRPMInput(t.Context(), source, snapshotDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), original...)
	tampered[len(tampered)-1] ^= 1
	if err := os.WriteFile(source, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: snapshot, Basename: filepath.Base(source)})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := openpgp.ReadKeyRing(bytes.NewReader(trust))
	if err != nil {
		t.Fatal(err)
	}
	verified, _, err := openVerifiedRPMFile(t.Context(), snapshot, info.Size, keyring, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	object, err := pool.Put(t.Context(), verified)
	if err != nil {
		t.Fatal(err)
	}
	if object.HashString() != info.SHA256 || object.Size != info.Size {
		t.Fatalf("CAS object=%+v snapshot_info=%+v", object, info)
	}
	if _, err := verifyStableRPMFile(t.Context(), source, info.Size, keyring, time.Now().UTC()); !errors.Is(err, yumrepo.ErrRPMPackageSignature) {
		t.Fatalf("same-size swapped source unexpectedly trusted: %v", err)
	}
}

func TestPublicationConfigIdentityBindsRPMPackageTrustBytes(t *testing.T) {
	root := t.TempDir()
	_, _ = writeMaterializeSigningKey(t, root)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(rpmTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	rpmRef, err := state.ViewRef("beta", "rpm-test", "el10", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	refs := []pub.RefState{{Name: rpmRef.String(), Commit: strings.Repeat("a", 40), ManifestSHA256: strings.Repeat("b", 64)}}
	firstSnapshot, err := loadPublicationRPMTrustSnapshot(cfg, refs)
	if err != nil {
		t.Fatal(err)
	}
	first := firstSnapshot.ConfigSHA256
	repositoryKey, err := os.ReadFile(filepath.Join(root, "repository-public.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-trust.asc"), repositoryKey, 0o644); err != nil {
		t.Fatal(err)
	}
	secondSnapshot, err := loadPublicationRPMTrustSnapshot(cfg, refs)
	if err != nil {
		t.Fatal(err)
	}
	second := secondSnapshot.ConfigSHA256
	if first == second {
		t.Fatalf("publication config identity ignored package-keyring rotation: %s", first)
	}
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "snapshot-package.rpm"))
	rpmFile, err := os.Open(rpmPath)
	if err != nil {
		t.Fatal(err)
	}
	_, verifyErr := yumrepo.VerifyEmbeddedRPMSignatures(t.Context(), rpmFile, firstSnapshot.Repos["rpm-test"].Keyring, time.Now().UTC())
	closeErr := rpmFile.Close()
	if verifyErr != nil || closeErr != nil {
		t.Fatalf("immutable trust snapshot changed after keyring replacement: %v", errors.Join(verifyErr, closeErr))
	}
}

func TestPublishRPMTrustDeltaReadsOnlyAddedOrReplacedPackageBytes(t *testing.T) {
	root := t.TempDir()
	trustPath := writeRPMPackageTrustFixture(t, root)
	trust, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := openpgp.ReadKeyRing(bytes.NewReader(trust))
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	packageFile, err := os.Open(rpmPath)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		_ = packageFile.Close()
		t.Fatal(err)
	}
	object, putErr := pool.Put(t.Context(), packageFile)
	closeErr := packageFile.Close()
	if putErr != nil || closeErr != nil {
		t.Fatal(errors.Join(putErr, closeErr))
	}
	old := views.Entry{Repo: "rpm-test", OS: "el10", Arch: "x86_64", Name: "old", Version: "1-1", Path: "Packages/o/old.rpm", Size: 1, SHA256: strings.Repeat("0", 64), Pool: "public"}
	added := views.Entry{Repo: "rpm-test", OS: "el10", Arch: "x86_64", Name: "pgdg-redhat-nonfree-repo", Version: "42.0-20PGDG", Path: "Packages/p/pgdg.rpm", Size: object.Size, SHA256: object.HashString(), Pool: "public"}
	manifest := func(entries ...views.Entry) *bytes.Buffer {
		var body bytes.Buffer
		for _, entry := range entries {
			if err := views.WriteEntry(&body, entry); err != nil {
				t.Fatal(err)
			}
		}
		return &body
	}
	leaf := viewLeaf{repo: config.Repo{ID: "rpm-test", Type: "yum"}, os: "el10", arch: "x86_64"}
	if err := verifyCanonicalRPMViewDelta(t.Context(), manifest(old, added), manifest(old), pool, leaf, keyring, time.Now().UTC(), 2); err != nil {
		t.Fatalf("unchanged missing parent package was re-read: %v", err)
	}
	replaced := old
	replaced.SHA256 = strings.Repeat("1", 64)
	if err := verifyCanonicalRPMViewDelta(t.Context(), manifest(replaced, added), manifest(old), pool, leaf, keyring, time.Now().UTC(), 2); err == nil {
		t.Fatal("replaced parent entry bypassed package verification")
	}
}

func TestPublishRPMTrustUsesOneCASFileDescriptorForDigestAndSignature(t *testing.T) {
	root := t.TempDir()
	trustPath := writeRPMPackageTrustFixture(t, root)
	trust, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := openpgp.ReadKeyRing(bytes.NewReader(trust))
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	rpmBody, err := os.ReadFile(rpmPath)
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(rpmPath)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	object, putErr := pool.Put(t.Context(), input)
	closeErr := input.Close()
	if putErr != nil || closeErr != nil {
		t.Fatal(errors.Join(putErr, closeErr))
	}
	tampered := append([]byte(nil), rpmBody...)
	tampered[len(tampered)-1] ^= 1
	hook := func() error {
		coordinate := pool.ObjectPath(object.SHA256)
		if err := os.Rename(coordinate, coordinate+".replaced"); err != nil {
			return err
		}
		return os.WriteFile(coordinate, tampered, 0o444)
	}
	err = verifyCASRPMObjectWithHook(t.Context(), pool, object, keyring, time.Now().UTC(), hook)
	if err == nil || !strings.Contains(err.Error(), "changed during trust verification") {
		t.Fatalf("CAS path replacement was not detected after same-FD verification: %v", err)
	}
}

const rpmTestConfig = `schema: sow/v1
state: {}
gpg:
  public_key: repository-public.pgp
pools:
  public: {}
  gated: {}
repos:
  - id: rpm-test
    type: yum
    path: yum/test/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
