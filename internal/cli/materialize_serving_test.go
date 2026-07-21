package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

func servingYUMConfig() string {
	block := `serving:
  latest: {base_url: "https://repo.example.invalid"}
  beta: {base_url: "https://beta.example.invalid"}
  stable: {base_url: "https://repo.example.invalid/pro/v1/basic"}
targets: {}
`
	return strings.Replace(snapshotYUMConfig, "targets: {}\n", block, 1)
}

func runServingCLI(t *testing.T, arguments ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Main(arguments, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func setupServingYUMView(t *testing.T) (root, configPath, rpmPath, keyPath string, private []byte) {
	t.Helper()
	root = nginxWorkerTempDir(t)
	configPath = filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(servingYUMConfig()), 0o600); err != nil {
		t.Fatal(err)
	}
	rpmPath = decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	private, keyPath = writeMaterializeSigningKey(t, root)
	if code, stdout, stderr := runServingCLI(t, "add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := runServingCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "rpm-test"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	return root, configPath, rpmPath, keyPath, private
}

func TestRollbackLocalServingMirrorlistBindsExactParentAndPriorState(t *testing.T) {
	manifestBody := "yum/test/el10/x86_64/Packages/p/pkg.rpm\t1\t" + strings.Repeat("a", 64) + "\n"
	identity := serving.Identity{
		View: "latest", Repo: "rpm-test", OS: "el10", Arch: "x86_64", LegacyRoot: "yum/test/el10/x86_64",
		RefCommit: strings.Repeat("1", 40), ConfigSHA256: strings.Repeat("2", 64), RepositoryKeySHA256: strings.Repeat("3", 64),
	}
	parentGeneration, err := serving.DeriveGeneration(identity, strings.NewReader(manifestBody))
	if err != nil {
		t.Fatal(err)
	}
	target, err := serving.NewTargetIdentity("latest", "public", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := serving.NewChannelForTarget(parentGeneration, target, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	wrongURLTarget, err := serving.NewTargetIdentity("latest", "public", "https://wrong.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	wrongURLParent, err := serving.NewChannelForTarget(parentGeneration, wrongURLTarget, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	wrongRootTarget, err := serving.NewTargetIdentity("latest", "other-public", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	wrongTargetParent, err := serving.NewChannelForTarget(parentGeneration, wrongRootTarget, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	identity.RefCommit = strings.Repeat("4", 40)
	childGeneration, err := serving.DeriveGeneration(identity, strings.NewReader(manifestBody))
	if err != nil {
		t.Fatal(err)
	}
	child, err := serving.NewChannelForTarget(childGeneration, target, &parent, 2)
	if err != nil {
		t.Fatal(err)
	}
	installChild := func(t *testing.T, root string) {
		t.Helper()
		if _, err := serving.ReconcileMirrorlist(root, parent); err != nil {
			t.Fatal(err)
		}
		if _, err := serving.ReconcileMirrorlist(root, child); err != nil {
			t.Fatal(err)
		}
	}

	for _, test := range []struct {
		name   string
		parent serving.Channel
	}{
		{name: "different URL", parent: wrongURLParent},
		{name: "different target root", parent: wrongTargetParent},
	} {
		t.Run("reject another valid parent "+test.name+" before mutation", func(t *testing.T) {
			root := t.TempDir()
			installChild(t, root)
			childBody, err := child.MirrorlistBody()
			if err != nil {
				t.Fatal(err)
			}
			if err := rollbackLocalServingMirrorlist(root, &test.parent, child); err == nil || !strings.Contains(err.Error(), "parent") {
				t.Fatalf("rollback accepted a valid but unsealed parent: %v", err)
			}
			observed, exists, err := serving.ReadMirrorlist(root, child.MirrorlistPath)
			if err != nil || !exists || !bytes.Equal(observed, childBody) {
				t.Fatalf("rejected rollback changed child pointer: body=%q exists=%t err=%v", observed, exists, err)
			}
		})
	}

	t.Run("restore exact parent", func(t *testing.T) {
		root := t.TempDir()
		installChild(t, root)
		parentBody, err := parent.MirrorlistBody()
		if err != nil {
			t.Fatal(err)
		}
		if err := rollbackLocalServingMirrorlist(root, &parent, child); err != nil {
			t.Fatal(err)
		}
		observed, exists, err := serving.ReadMirrorlist(root, child.MirrorlistPath)
		if err != nil || !exists || !bytes.Equal(observed, parentBody) {
			t.Fatalf("exact rollback body=%q exists=%t err=%v", observed, exists, err)
		}
	})

	t.Run("restore first-install absence", func(t *testing.T) {
		root := t.TempDir()
		if _, err := serving.ReconcileMirrorlist(root, parent); err != nil {
			t.Fatal(err)
		}
		if err := rollbackLocalServingMirrorlist(root, nil, parent); err != nil {
			t.Fatal(err)
		}
		if _, exists, err := serving.ReadMirrorlist(root, parent.MirrorlistPath); err != nil || exists {
			t.Fatalf("first-install rollback exists=%t err=%v", exists, err)
		}
	})
}

func mirrorGenerationID(t *testing.T, root, relative string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(strings.TrimSpace(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for index := range parts {
		if parts[index] == "g" && index+1 < len(parts) && len(parts[index+1]) == 20 {
			return parts[index+1]
		}
	}
	t.Fatalf("mirrorlist has no generation ID: %s", body)
	return ""
}

func TestMaterializeMutableYUMBuildsCanonicalStrongRoutesAndRetainsOldGeneration(t *testing.T) {
	root, configPath, rpmPath, keyPath, _ := setupServingYUMView(t)
	arguments := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	code, stdout, stderr := runServingCLI(t, arguments...)
	if code != ExitOK || !strings.Contains(stdout, "serving_generations=1") {
		t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	mirrorRelative := "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"
	firstID := mirrorGenerationID(t, root, mirrorRelative)
	firstRoot := filepath.Join(root, "_sow", "v1", "g", firstID, "yum", "test", "x86_64")
	for _, relative := range []string{"repodata/repomd.xml", "repodata/repomd.xml.asc"} {
		if _, err := os.Stat(filepath.Join(firstRoot, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("missing generation %s: %v", relative, err)
		}
	}
	info, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	rawPackage := filepath.Join(root, "yum", "test", "x86_64", filepath.FromSlash(info.Location))
	generationPackage := filepath.Join(firstRoot, filepath.FromSlash(info.Location))
	rawInfo, err := os.Stat(rawPackage)
	if err != nil {
		t.Fatal(err)
	}
	generationInfo, err := os.Stat(generationPackage)
	if err != nil || !os.SameFile(rawInfo, generationInfo) {
		t.Fatalf("generation payload is not the raw/CAS hardlink: %v", err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	channelPath := serving.ChannelStatePath(serving.Channel{TargetID: target.ID, View: "latest", Repo: "rpm-test", OS: "el10", Arch: "x86_64"})
	if reader, err := canonical.OpenPath(channelPath); err != nil {
		t.Fatalf("canonical channel ledger missing: %v", err)
	} else {
		_ = reader.Close()
	}
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runServingCLI(t, arguments...)
	if code != ExitOK || !strings.Contains(stdout, "pointer=unchanged") {
		t.Fatalf("idempotent materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	afterHead, _ := canonical.HeadHash()
	if head != afterHead || mirrorGenerationID(t, root, mirrorRelative) != firstID {
		t.Fatalf("idempotent materialize advanced state head=%s/%s", head, afterHead)
	}

	if code, stdout, stderr := runServingCLI(t, "rm", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, info.Name); code != ExitOK || !strings.Contains(stdout, "removed view=latest entries=1") {
		t.Fatalf("rm code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runServingCLI(t, arguments...)
	if code != ExitOK {
		t.Fatalf("second generation code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	secondID := mirrorGenerationID(t, root, mirrorRelative)
	if secondID == firstID {
		t.Fatal("changed latest view did not advance content-derived generation")
	}
	if _, err := os.Stat(generationPackage); err != nil {
		t.Fatalf("delayed-client generation was removed: %v", err)
	}
	if code, stdout, stderr := runServingCLI(t, "gc", "--config", configPath, "--limit", "0"); code != ExitOK || !strings.Contains(stdout, "missing=0") {
		t.Fatalf("generation GC root code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestMaterializePartialYUMAliasClosesPhysicalOwnerOnce(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	configBody := strings.Replace(servingYUMConfig(),
		"os: {family: el, major: 10, lifecycle: active}",
		"os: {family: el, suite: rocky, major: 10, lifecycle: active}", 1)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	private, keyPath := writeMaterializeSigningKey(t, root)
	if code, stdout, stderr := runServingCLI(t, "add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("add aliases code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := runServingCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "rpm-test"); code != ExitOK {
		t.Fatalf("promote aliases code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	elRef, err := state.ViewRef("latest", "rpm-test", "el10", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	elCommit, exists, err := canonical.Ref(elRef)
	if err != nil || !exists {
		t.Fatalf("latest el10 ref commit=%s exists=%t err=%v", elCommit, exists, err)
	}
	elInfo, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	elPayloadPath := path.Join("yum/test/x86_64", elInfo.Location)
	rockyRPM := filepath.Join("..", "..", "third_party", "cavaliergopher-rpm", "testdata", "centos-release-5-0.0.el5.centos.2.x86_64.rpm")
	rockyInfo, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rockyRPM})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	rockyObject, err := pool.Import(t.Context(), rockyRPM)
	if err != nil || rockyObject.HashString() != rockyInfo.SHA256 || rockyObject.Size != rockyInfo.Size {
		t.Fatalf("import rocky-only RPM object=%+v info=%+v err=%v", rockyObject, rockyInfo, err)
	}
	rockyVersion := rockyInfo.Version + "-" + rockyInfo.Release
	if rockyInfo.Epoch > 0 {
		rockyVersion = fmt.Sprintf("%d:%s", rockyInfo.Epoch, rockyVersion)
	}
	rockyEntry := views.Entry{
		Repo: "rpm-test", OS: "rocky", Arch: "x86_64", Name: rockyInfo.Name, Version: rockyVersion,
		Path: path.Join("yum/test/x86_64", rockyInfo.Location), Size: rockyInfo.Size, SHA256: rockyInfo.SHA256, Pool: "public",
	}
	var rockyBody bytes.Buffer
	if err := views.WriteEntry(&rockyBody, rockyEntry); err != nil {
		t.Fatal(err)
	}
	rockyPayloadPath := rockyEntry.Path
	rockyStage := filepath.Join(root, ".sow", "rocky-alias.tsv")
	if err := os.WriteFile(rockyStage, rockyBody.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	rockyPath, _ := state.ViewPath("latest", "rpm-test", "rocky", "x86_64")
	rockyRef, _ := state.ViewRef("latest", "rpm-test", "rocky", "x86_64")
	if _, changed, err := canonical.Apply(t.Context(), "test-yum-alias", "test: seed rocky logical alias", map[string]string{rockyPath: rockyStage}, []state.RefUpdate{{Name: rockyRef}}, state.ApplyOptions{}); err != nil || !changed {
		t.Fatalf("seed rocky alias changed=%t err=%v", changed, err)
	}
	archivePath := filepath.Join(root, "offline", "rocky-only.tgz")
	args := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--os", "rocky", "--gpg-private-key-file", keyPath, "--tgz", archivePath, "--workers", "4", "--chunk-entries", "2"}
	code, stdout, stderr := runServingCLI(t, args...)
	if code != ExitOK || !strings.Contains(stdout, "aliases=2") {
		t.Fatalf("partial alias materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	rockyMirror := "_sow/v1/mirrorlist/latest/rpm-test/rocky/x86_64.txt"
	elMirror := "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"
	rockyGeneration := mirrorGenerationID(t, root, rockyMirror)
	elGeneration := mirrorGenerationID(t, root, elMirror)
	rockyRepomd, err := os.ReadFile(filepath.Join(root, "_sow", "v1", "g", rockyGeneration, "yum", "test", "x86_64", "repodata", "repomd.xml"))
	if err != nil {
		t.Fatal(err)
	}
	elRepomd, err := os.ReadFile(filepath.Join(root, "_sow", "v1", "g", elGeneration, "yum", "test", "x86_64", "repodata", "repomd.xml"))
	if err != nil || !bytes.Equal(elRepomd, rockyRepomd) {
		t.Fatalf("logical aliases do not retain the same physical repodata bytes: rocky=%s el10=%s err=%v", rockyGeneration, elGeneration, err)
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(private), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	liveGeneration, err := yumrepo.ValidateDirectory(t.Context(), filepath.Join(root, "yum", "test", "x86_64", "repodata"), yumrepo.CompressionZstd, verifier)
	if err != nil || liveGeneration.Packages != 2 {
		t.Fatalf("physical owner did not close both logical payloads: generation=%v err=%v", liveGeneration, err)
	}
	archiveBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{rockyPayloadPath, rockyMirror, "yum/test/x86_64/repodata/repomd.xml"} {
		if !archiveHasPath(t, archiveBytes, wanted) {
			t.Fatalf("partial logical archive omitted %s", wanted)
		}
	}
	for _, forbidden := range []string{elPayloadPath, elMirror} {
		if archiveHasPath(t, archiveBytes, forbidden) {
			t.Fatalf("partial logical archive leaked sibling alias path %s", forbidden)
		}
	}
	extracted := extractMaterializeArchive(t, archiveBytes)
	validated, err := yumrepo.ValidateDirectory(t.Context(), filepath.Join(extracted, "yum", "test", "x86_64", "repodata"), yumrepo.CompressionZstd, verifier)
	if err != nil || validated.Packages != 1 {
		t.Fatalf("partial logical archive repodata packages=%v err=%v", validated, err)
	}
	archiveGeneration := mirrorGenerationID(t, extracted, rockyMirror)
	validatedGeneration, err := yumrepo.ValidateDirectory(t.Context(), filepath.Join(extracted, "_sow", "v1", "g", archiveGeneration, "yum", "test", "x86_64", "repodata"), yumrepo.CompressionZstd, verifier)
	if err != nil || validatedGeneration.Packages != 1 {
		t.Fatalf("partial logical archive generation packages=%v err=%v", validatedGeneration, err)
	}
	if _, err := os.Stat(filepath.Join(extracted, filepath.FromSlash(rockyPayloadPath))); err != nil {
		t.Fatalf("partial logical archive index payload is missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(extracted, filepath.FromSlash(elPayloadPath))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial logical archive retained sibling payload: %v", err)
	}
	ledgers := loadRouteLedgersForTest(t, canonical, root, "latest")
	if len(ledgers) != 1 || ledgers[0].Receipt.Kind != "yum" || len(ledgers[0].Receipt.Refs) != 2 {
		t.Fatalf("partial alias receipt is not one complete physical owner: %+v", ledgers)
	}
	receiptRefs := make(map[string]struct{}, len(ledgers[0].Receipt.Refs))
	for _, ref := range ledgers[0].Receipt.Refs {
		receiptRefs[ref.Name] = struct{}{}
	}
	for _, osName := range []string{"rocky", "el10"} {
		name, err := state.ViewRef("latest", "rpm-test", osName, "x86_64")
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := receiptRefs[name.String()]; !exists {
			t.Fatalf("physical owner receipt omitted alias ref %s: %+v", name, ledgers[0].Receipt.Refs)
		}
	}
	cfg, repos, err := loadAndSelect(commonFlags{configPath: configPath, workers: 1, chunk: 2})
	if err != nil || len(repos) != 1 {
		t.Fatalf("reload grouped YUM fixture repos=%d err=%v", len(repos), err)
	}
	ownerLeaves := selectedLeaves(repos, commonFlags{})
	prepared := preparedPublication{
		view: "latest",
		projections: []publicationProjection{{
			view: "latest", repo: repos[0], os: "el10", arch: "x86_64", sourceRoot: "yum/test/x86_64",
			canonicalRoot: "yum/test/x86_64", remoteRoot: "yum/test/x86_64", legacyRoot: "yum/test/x86_64",
		}},
		yumOwnerLeaves: map[string][]viewLeaf{yumPublicationOwnerKey("rpm-test", "x86_64"): ownerLeaves},
	}
	publicationRefs, err := desiredPublicationRefs(canonical, nil, cfg, repos, prepared, commonFlags{}, nil)
	if err != nil || len(publicationRefs) != 2 {
		t.Fatalf("grouped physical projection refs=%+v err=%v", publicationRefs, err)
	}
	changedChannels := changedYUMProjections(prepared, []string{"yum/test/x86_64/repodata/repomd.xml"})
	if len(changedChannels) != 2 {
		t.Fatalf("grouped physical projection changed channels=%v", changedChannels)
	}
	channels, err := desiredPublicationChannels(nil, prepared, 1, changedChannels, nil)
	if err != nil || len(channels) != 2 {
		t.Fatalf("grouped physical projection channels=%+v err=%v", channels, err)
	}
	if scopes := changedYUMMetadataScopes(prepared, changedChannels); len(scopes) != 1 || scopes[0] != "yum/test/x86_64/repodata" {
		t.Fatalf("grouped physical projection metadata scopes=%v", scopes)
	}
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runServingCLI(t, args...)
	if code != ExitOK || !strings.Contains(stdout, "pointer=unchanged") {
		t.Fatalf("idempotent partial alias materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	replayedArchive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayedArchive, archiveBytes) {
		t.Fatalf("partial logical archive is not deterministic: %s", archiveDifference(t, archiveBytes, replayedArchive))
	}
	if after, err := canonical.HeadHash(); err != nil || after != head {
		t.Fatalf("idempotent partial alias materialize advanced HEAD before=%s after=%s err=%v", head, after, err)
	}
}

func TestMaterializeYUMFailsWhenTrustRotationDropsReachablePackageSigner(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	wrongTrust, err := os.ReadFile(filepath.Join(root, "repository-public.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-trust.asc"), wrongTrust, 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runServingCLI(t, "materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2")
	if code != ExitVerification || !strings.Contains(stderr, "RPM package trust preflight") {
		t.Fatalf("dropped signer materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestMaterializeDedicatedAndStableYUMRoutesAreCompleteAndExplicit(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	missingTarget := "missing-export"
	if code, _, stderr := runServingCLI(t, "materialize", "beta", "--config", configPath, "--repo", "rpm-test", "--target", missingTarget, "--gpg-private-key-file", keyPath); code != ExitConfig || !strings.Contains(stderr, "--serving-base-url is required") {
		t.Fatalf("missing dedicated URL code=%d stderr=%s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, missingTarget)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed preflight mutated target: %v", err)
	}

	archivePath := filepath.Join(root, "offline", "beta.tgz")
	arguments := []string{"materialize", "beta", "--config", configPath, "--repo", "rpm-test", "--target", "export-beta", "--serving-base-url", "https://export.example.invalid", "--gpg-private-key-file", keyPath, "--tgz", archivePath, "--workers", "2", "--chunk-entries", "2"}
	code, stdout, stderr := runServingCLI(t, arguments...)
	if code != ExitOK || !strings.Contains(stdout, "serving_generations=1") {
		t.Fatalf("dedicated materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	exportRoot := filepath.Join(root, "export-beta")
	mirror := "_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt"
	generation := mirrorGenerationID(t, exportRoot, mirror)
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	assertArchiveNames(t, archive,
		mirror,
		"_sow/v1/g/"+generation+"/yum/test/x86_64/repodata/repomd.xml",
		"_sow/v1/g/"+generation+"/yum/test/x86_64/repodata/repomd.xml.asc",
	)
	if code, stdout, stderr = runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("dedicated replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(exportRoot, "_sow", "v1", "g", generation)); err != nil {
		t.Fatalf("dedicated reconcile removed generation: %v", err)
	}

	if code, stdout, stderr := runServingCLI(t, "promote", "beta", "stable", "--config", configPath, "--repo", "rpm-test"); code != ExitOK {
		t.Fatalf("stable promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := runServingCLI(t, "materialize", "stable", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("stable materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	stableRoot := filepath.Join(root, ".sow", "origin", "gated")
	stableMirror := "_sow/v1/mirrorlist/stable/rpm-test/el10/x86_64.txt"
	body, err := os.ReadFile(filepath.Join(stableRoot, filepath.FromSlash(stableMirror)))
	if err != nil || !strings.HasPrefix(string(body), "https://repo.example.invalid/pro/v1/basic/_sow/v1/g/") || strings.Contains(string(body), "@") {
		t.Fatalf("stable Basic mirrorlist body=%q err=%v", body, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", "materialized", "stable")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("obsolete stable materialization root exists: %v", err)
	}
}

func TestLocalServingRecoveryClosesEveryPostGenerationBoundary(t *testing.T) {
	for _, phase := range []localServingPhase{localServingGenerationReady, localServingStateCommitted, localServingPointerFlipped} {
		t.Run(string(phase), func(t *testing.T) {
			root, configPath, _, keyPath, _ := setupServingYUMView(t)
			cfg, repos, err := loadAndSelect(commonFlags{configPath: configPath, workers: 2, chunk: 2})
			if err != nil {
				t.Fatal(err)
			}
			canonical := state.New(cfg.StatePath())
			pool, err := repository.NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			privateKey, passphrase, keySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, selectedLeaves(repos, commonFlags{}), keyPath, "")
			if err != nil {
				t.Fatal(err)
			}
			defer clearSecret(privateKey)
			defer clearSecret(passphrase)
			txDir, err := newTransactionDir(cfg.StatePath(), "serving-fault-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(txDir)
			leaf := selectedLeaves(repos, commonFlags{})[0]
			if _, err := materializeYUMLeaf(t.Context(), cfg, canonical, pool, leaf.repo, leaf, "latest", txDir, commonFlags{workers: 2, chunk: 2}, privateKey, passphrase); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected local serving stop")
			_, err = activateLocalYUMServing(t.Context(), cfg, canonical, pool, materializeCanonicalSource{ID: "latest", Public: true}, root,
				"https://repo.example.invalid", keySHA, txDir, []localYUMServingLeaf{{repo: leaf.repo, os: leaf.os, arch: leaf.arch}},
				commonFlags{workers: 2, chunk: 2}, localServingActivationOptions{AfterPhase: func(current localServingPhase) error {
					if current == phase {
						return injected
					}
					return nil
				}}, io.Discard)
			if !errors.Is(err, injected) {
				t.Fatalf("fault phase=%s err=%v", phase, err)
			}
			if phase == localServingGenerationReady {
				journals, err := listLocalServingJournals(cfg.StatePath())
				if err != nil || len(journals) != 1 {
					t.Fatalf("generation-ready journal=%+v err=%v", journals, err)
				}
				if err := os.RemoveAll(filepath.Join(root, "_sow", "v1", "g", journals[0].Generation.ID)); err != nil {
					t.Fatal(err)
				}
			}
			if phase == localServingStateCommitted {
				if err := os.RemoveAll(filepath.Join(root, "_sow")); err != nil {
					t.Fatal(err)
				}
			}
			if err := prepareLocalServingState(t.Context(), cfg, canonical, false, commonFlags{workers: 2, chunk: 2}, io.Discard); err == nil {
				t.Fatal("incomplete serving transaction was not detected")
			}
			if err := prepareCanonicalStateCore(t.Context(), canonical, true, io.Discard); err != nil {
				t.Fatal(err)
			}
			if err := prepareLocalServingState(t.Context(), cfg, canonical, true, commonFlags{workers: 2, chunk: 2}, io.Discard); err != nil {
				t.Fatalf("recover phase=%s: %v", phase, err)
			}
			if journals, err := listLocalServingJournals(cfg.StatePath()); err != nil || len(journals) != 0 {
				t.Fatalf("journals after recovery=%#v err=%v", journals, err)
			}
			ready, err := localYUMServingReady(cfg, canonical, repos, "latest", keySHA, commonFlags{workers: 2, chunk: 2})
			if phase == localServingGenerationReady {
				if err != nil || ready {
					t.Fatalf("abandoned generation-ready absence ready=%v err=%v", ready, err)
				}
				return
			}
			if err != nil || !ready {
				t.Fatalf("serving closure after recovery ready=%v err=%v", ready, err)
			}
		})
	}
}

func TestLocalServingRecoveryClosesInstallBeforeReadyWindow(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	cfg, repos, err := loadAndSelect(commonFlags{configPath: configPath, workers: 2, chunk: 2})
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, passphrase, keySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, selectedLeaves(repos, commonFlags{}), keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	txDir, err := newTransactionDir(cfg.StatePath(), "serving-install-intent-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	leaf := selectedLeaves(repos, commonFlags{})[0]
	if _, err := materializeYUMLeaf(t.Context(), cfg, canonical, pool, leaf.repo, leaf, "latest", txDir, commonFlags{workers: 2, chunk: 2}, privateKey, passphrase); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("stop after generation install before ready journal")
	_, err = activateLocalYUMServing(t.Context(), cfg, canonical, pool, materializeCanonicalSource{ID: "latest", Public: true}, root,
		"https://repo.example.invalid", keySHA, txDir, []localYUMServingLeaf{{repo: leaf.repo, os: leaf.os, arch: leaf.arch}},
		commonFlags{workers: 2, chunk: 2}, localServingActivationOptions{AfterGenerationInstallBeforeReady: func() error { return injected }}, io.Discard)
	if !errors.Is(err, injected) {
		t.Fatalf("install-before-ready fault err=%v", err)
	}
	journals, err := listLocalServingJournals(cfg.StatePath())
	if err != nil || len(journals) != 1 || journals[0].Phase != localServingInstallIntent {
		t.Fatalf("install intent journal=%+v err=%v", journals, err)
	}
	if _, err := os.Stat(filepath.Join(root, "_sow", "v1", "g", journals[0].Generation.ID)); err != nil {
		t.Fatalf("installed pre-ready generation missing: %v", err)
	}
	if err := prepareLocalServingState(t.Context(), cfg, canonical, true, commonFlags{workers: 2, chunk: 2}, io.Discard); err != nil {
		t.Fatalf("recover install-before-ready: %v", err)
	}
	ready, err := localYUMServingReady(cfg, canonical, repos, "latest", keySHA, commonFlags{workers: 2, chunk: 2})
	if err != nil || !ready {
		t.Fatalf("install-before-ready recovery ready=%v err=%v", ready, err)
	}
}

func TestLocalServingRecoveryAdvancesCommittedSuccessorFromParentPointer(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	arguments := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("first materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	mirror := "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"
	parentID := mirrorGenerationID(t, root, mirror)
	if code, stdout, stderr := runServingCLI(t, "rm", "--view", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "pgdg-redhat-nonfree-repo"); code != ExitOK {
		t.Fatalf("rm code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	cfg, repos, err := loadAndSelect(commonFlags{configPath: configPath, workers: 2, chunk: 2})
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, passphrase, keySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, selectedLeaves(repos, commonFlags{}), keyPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	txDir, err := newTransactionDir(cfg.StatePath(), "serving-parent-recovery-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	leaf := selectedLeaves(repos, commonFlags{})[0]
	if _, err := materializeYUMLeaf(t.Context(), cfg, canonical, pool, leaf.repo, leaf, "latest", txDir, commonFlags{workers: 2, chunk: 2}, privateKey, passphrase); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("stop with committed successor and parent pointer")
	_, err = activateLocalYUMServing(t.Context(), cfg, canonical, pool, materializeCanonicalSource{ID: "latest", Public: true}, root,
		"https://repo.example.invalid", keySHA, txDir, []localYUMServingLeaf{{repo: leaf.repo, os: leaf.os, arch: leaf.arch}},
		commonFlags{workers: 2, chunk: 2}, localServingActivationOptions{AfterPhase: func(phase localServingPhase) error {
			if phase == localServingStateCommitted {
				return injected
			}
			return nil
		}}, io.Discard)
	if !errors.Is(err, injected) || mirrorGenerationID(t, root, mirror) != parentID {
		t.Fatalf("successor fault err=%v pointer=%s parent=%s", err, mirrorGenerationID(t, root, mirror), parentID)
	}
	if err := prepareLocalServingState(t.Context(), cfg, canonical, true, commonFlags{workers: 2, chunk: 2}, io.Discard); err != nil {
		t.Fatalf("recover committed successor: %v", err)
	}
	if successorID := mirrorGenerationID(t, root, mirror); successorID == parentID {
		t.Fatal("recovery did not advance parent pointer to committed successor")
	}
	ready, err := localYUMServingReady(cfg, canonical, repos, "latest", keySHA, commonFlags{workers: 2, chunk: 2})
	if err != nil || !ready {
		t.Fatalf("committed successor recovery ready=%v err=%v", ready, err)
	}
}

func TestMaterializeRecoverMigratesLegacyUnpartitionedServingChannel(t *testing.T) {
	root, configPath, _, keyPath, _ := setupServingYUMView(t)
	arguments := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
		t.Fatalf("initial materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	target, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	partitionedPath := serving.ChannelStatePath(serving.Channel{TargetID: target.ID, View: "latest", Repo: "rpm-test", OS: "el10", Arch: "x86_64"})
	body, exists, err := readOptionalCanonical(canonical, partitionedPath)
	if err != nil || !exists {
		t.Fatalf("read partitioned channel exists=%v err=%v", exists, err)
	}
	channel, err := serving.DecodeChannel(body)
	if err != nil {
		t.Fatal(err)
	}
	channel.TargetID = ""
	channel.TargetRoot = ""
	channel.ParentTargetID = ""
	legacyBody, err := channel.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	stageDir, err := newTransactionDir(filepath.Join(root, ".sow"), "legacy-channel-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stageDir)
	stage := stageLifecycleBytes(t, stageDir, "legacy-channel.json", legacyBody)
	legacyPath := serving.ChannelStatePath(channel)
	if _, _, err := canonical.Apply(t.Context(), "test-legacy-serving", "test: seed legacy serving channel", map[string]string{legacyPath: stage}, nil, state.ApplyOptions{DeletePaths: []string{partitionedPath, serving.TargetStatePath(target)}}); err != nil {
		t.Fatal(err)
	}
	recoverArguments := append(append([]string(nil), arguments...), "--recover")
	if code, stdout, stderr := runServingCLI(t, recoverArguments...); code != ExitOK || !strings.Contains(stdout, "recovered legacy-local-serving-channels=1") {
		t.Fatalf("legacy serving migration code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, exists, err := readOptionalCanonical(canonical, legacyPath); err != nil || exists {
		t.Fatalf("legacy channel remains exists=%v err=%v", exists, err)
	}
	if _, exists, err := readOptionalCanonical(canonical, partitionedPath); err != nil || !exists {
		t.Fatalf("partitioned channel missing exists=%v err=%v", exists, err)
	}
}
