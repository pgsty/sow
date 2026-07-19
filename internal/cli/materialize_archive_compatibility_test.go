package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestLatestWorkingTreeArchiveCarriesFrozenYUMCompatibility(t *testing.T) {
	fixture := newFlatYUMCompatibilityFixture(t)
	workspace := filepath.Clean(filepath.Join(fixture.root, "..", "..", ".."))
	configPath := filepath.Join(workspace, "sow.yaml")
	if err := os.MkdirAll(filepath.Join(workspace, "yum", "infra", "el9", "x86_64"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(nginxCompatibilityConfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	privateKey := filepath.Join(workspace, "legacy-private.key")
	candidate := filepath.Join(t.TempDir(), "candidate")
	runOK := func(args ...string) string {
		t.Helper()
		code, stdout, stderr := runServingCLI(t, args...)
		if code != ExitOK || stderr != "" {
			t.Fatalf("command=%v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
		return stdout
	}

	runOK("init", "--config", configPath, "--workers", "1", "--chunk-entries", "2")
	prepareNginxCompatibilityOrdinaryRoutes(t, fixture, configPath)
	runOK("compatibility", "yum-adopt", "--id", "infra-legacy-x86-64", "--config", configPath, "--workers", "1", "--chunk-entries", "2")
	candidateOutput := runOK("compatibility", "yum-candidate", "--id", "infra-legacy-x86-64", "--output", candidate, "--gpg-private-key-file", privateKey, "--config", configPath, "--workers", "1", "--chunk-entries", "2")
	freezeOutput := runOK("compatibility", "yum-freeze", "--id", "infra-legacy-x86-64", "--candidate", candidate, "--confirm", nginxTestOutputValue(t, candidateOutput, "freeze_confirm"), "--config", configPath, "--workers", "1", "--chunk-entries", "2")
	runOK("compatibility", "yum-cutover", "--id", "infra-legacy-x86-64", "--confirm", nginxTestOutputValue(t, freezeOutput, "cutover_confirm"), "--config", configPath, "--workers", "1", "--chunk-entries", "2")

	canonical := state.New(filepath.Join(workspace, config.StateDirectory))
	frozen, err := loadYUMCompatibilityFrozenStateAt(canonical, plumbing.ZeroHash, "infra-legacy-x86-64")
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(workspace, "offline", "infra-el9-with-frozen-compatibility.tgz")
	arguments := []string{
		"materialize", "latest", "--repo", "infra-el9", "--config", configPath,
		"--gpg-private-key-file", privateKey, "--tgz", archivePath,
		"--workers", "2", "--chunk-entries", "2",
	}
	if output := runOK(arguments...); !strings.Contains(output, "compatibility_generations=1") || !strings.Contains(output, "archive path=") {
		t.Fatalf("materialize did not report compatibility archive closure: %s", output)
	}
	encoded, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	archivePaths := frozenCompatibilityArchivePaths(t, encoded)
	if _, exists := archivePaths[offlineArchivePayloadMarkerPath]; !exists {
		t.Fatalf("archive omitted required payload contract marker %s", offlineArchivePayloadMarkerPath)
	}
	if _, exists := archivePaths["files/route-proof.bin"]; exists {
		t.Fatal("repo-scoped archive leaked the unselected asset payload")
	}
	for name := range archivePaths {
		if strings.HasPrefix(name, "files/") || strings.HasPrefix(name, config.StateDirectory+"/") {
			t.Fatalf("repo-scoped archive leaked unselected or canonical-state path %s", name)
		}
		for _, segment := range strings.Split(name, "/") {
			if name == offlineArchivePayloadMarkerPath {
				continue
			}
			if strings.HasSuffix(segment, ".next") || strings.HasSuffix(segment, ".tmp") || strings.HasPrefix(segment, ".sow-") || strings.HasPrefix(segment, ".materialize-") {
				t.Fatalf("archive retained transaction temporary %s", name)
			}
		}
	}

	extracted := extractMaterializeArchive(t, encoded)
	const compatibilityID = "infra-legacy-x86-64"
	const compatibilityRoot = "yum/infra/x86_64"
	mirrorRelative := serving.MirrorlistPath("latest", compatibilityID, "cross-el", "x86_64")
	generationID := mirrorGenerationID(t, extracted, mirrorRelative)
	wantMirror := "https://repo.example.invalid/" + serving.GenerationPath(generationID, compatibilityRoot) + "\n"
	if body, err := os.ReadFile(filepath.Join(extracted, filepath.FromSlash(mirrorRelative))); err != nil || string(body) != wantMirror {
		t.Fatalf("compatibility mirrorlist body=%q want=%q err=%v", body, wantMirror, err)
	}
	rawRoot := filepath.Join(extracted, filepath.FromSlash(compatibilityRoot))
	generationRoot := filepath.Join(extracted, filepath.FromSlash(serving.GenerationPath(generationID, compatibilityRoot)))

	candidatePath, _ := state.YUMCompatibilityCandidateManifestPath(compatibilityID)
	candidateManifest, err := canonical.OpenPathAt(frozen.Commit, candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	candidateReader := manifest.NewReader(candidateManifest)
	flatAliases := 0
	expectedRaw := make(map[string]struct{})
	expectedStrong := make(map[string]struct{})
	for {
		entry, readErr := candidateReader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = candidateManifest.Close()
			t.Fatal(readErr)
		}
		rawPath := path.Join(compatibilityRoot, entry.Path)
		expectedRaw[rawPath] = struct{}{}
		if _, exists := archivePaths[rawPath]; !exists {
			t.Fatalf("archive raw projection omitted frozen candidate path %s", rawPath)
		}
		generationPath := path.Join(serving.GenerationPath(generationID, compatibilityRoot), entry.Path)
		switch {
		case strings.HasPrefix(entry.Path, "Packages/"), strings.HasPrefix(entry.Path, "repodata/"):
			expectedStrong[generationPath] = struct{}{}
			if _, exists := archivePaths[generationPath]; !exists {
				t.Fatalf("archive strong generation omitted %s", generationPath)
			}
		case path.Base(entry.Path) == entry.Path && strings.HasSuffix(entry.Path, ".rpm"):
			flatAliases++
			if _, exists := archivePaths[generationPath]; exists {
				t.Fatalf("flat compatibility alias leaked into immutable generation %s", generationPath)
			}
		default:
			t.Fatalf("frozen candidate contains an unexpected path class %s", entry.Path)
		}
	}
	if closeErr := candidateManifest.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if flatAliases == 0 || !archiveHasPath(t, encoded, path.Join(compatibilityRoot, fixture.flat)) || archiveHasPath(t, encoded, path.Join(serving.GenerationPath(generationID, compatibilityRoot), fixture.flat)) {
		t.Fatalf("raw/strong flat-alias split is incomplete: flat_aliases=%d", flatAliases)
	}
	rawPrefix := compatibilityRoot + "/"
	strongPrefix := serving.GenerationPath(generationID, compatibilityRoot)
	for name := range archivePaths {
		if strings.HasPrefix(name, rawPrefix) {
			if _, expected := expectedRaw[name]; !expected {
				t.Fatalf("raw compatibility projection contains non-candidate path %s", name)
			}
		}
		if strings.HasPrefix(name, strongPrefix) {
			if _, expected := expectedStrong[name]; !expected {
				t.Fatalf("strong compatibility generation contains non-candidate path %s", name)
			}
		}
	}

	packageTrustRelative := config.YUMCompatibilityPackageTrustRoute(compatibilityID)
	repositoryTrustRelative := config.YUMCompatibilityRepositoryTrustRoute(compatibilityID)
	packageTrust, err := os.ReadFile(filepath.Join(extracted, filepath.FromSlash(packageTrustRelative)))
	if err != nil || digestBytesCLI(packageTrust) != frozen.Receipt.PackageTrustSHA256 {
		t.Fatalf("archived package trust differs from frozen evidence: sha=%s want=%s err=%v", digestBytesCLI(packageTrust), frozen.Receipt.PackageTrustSHA256, err)
	}
	repositoryTrust, err := os.ReadFile(filepath.Join(extracted, filepath.FromSlash(repositoryTrustRelative)))
	if err != nil || digestBytesCLI(repositoryTrust) != frozen.Receipt.RepositoryTrustSHA256 || repositoryTrustAnchorDigest(repositoryTrust) != frozen.Receipt.RepositoryKeySHA256 {
		t.Fatalf("archived repository trust differs from frozen evidence: sha=%s key=%s err=%v", digestBytesCLI(repositoryTrust), repositoryTrustAnchorDigest(repositoryTrust), err)
	}
	packageKeyring, err := yumrepo.ParseRPMPackageKeyring(packageTrust)
	if err != nil {
		t.Fatal(err)
	}
	verifyAt := time.Now().UTC().Add(time.Hour)
	validateGeneration := func(label, root string) {
		t.Helper()
		verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(repositoryTrust), verifyAt)
		if err != nil {
			t.Fatal(err)
		}
		generation, err := yumrepo.ValidateDirectory(t.Context(), filepath.Join(root, "repodata"), yumrepo.CompressionGzip, verifier)
		if err != nil {
			t.Fatalf("%s repodata is not consumable: %v", label, err)
		}
		if generation.Packages != frozen.Receipt.Packages || generation.Packages != 1 {
			t.Fatalf("%s repodata is not the frozen one-package generation: packages=%d frozen=%d", label, generation.Packages, frozen.Receipt.Packages)
		}
	}
	validateGeneration("raw compatibility", rawRoot)
	validateGeneration("strong compatibility", generationRoot)
	checks := make([]verify.Check, 0, 2)
	for _, item := range []struct {
		id   string
		root string
	}{{"archive-compatibility-raw", rawRoot}, {"archive-compatibility-generation", generationRoot}} {
		verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(repositoryTrust), verifyAt)
		if err != nil {
			t.Fatal(err)
		}
		checks = append(checks, verify.YUMCheck{
			CheckID: item.id, Root: item.root, Compression: yumrepo.CompressionGzip,
			Verifier: verifier, PackageKeyring: packageKeyring, VerifyAt: verifyAt,
			Workers: 2, ChunkEntries: 2, TempDir: t.TempDir(),
		})
	}
	report := verify.Run(t.Context(), verify.Request{Layers: []verify.Layer{verify.LayerL1}, Checks: checks, Workers: 2})
	if report.Outcome != verify.OutcomePassed {
		t.Fatalf("frozen compatibility archive is not consumable through raw and strong routes: %+v", report)
	}

	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	runOK(arguments...)
	replayed, err := os.ReadFile(archivePath)
	if err != nil || !bytes.Equal(encoded, replayed) {
		t.Fatalf("frozen compatibility archive replay changed bytes: err=%v", err)
	}
	if after, err := canonical.HeadHash(); err != nil || after != head {
		t.Fatalf("frozen compatibility archive replay advanced canonical HEAD before=%s after=%s err=%v", head, after, err)
	}
}

func frozenCompatibilityArchivePaths(t *testing.T, encoded []byte) map[string]struct{} {
	t.Helper()
	compressed, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	result := make(map[string]struct{})
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return result
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg || header.Name == "" || path.Clean(header.Name) != header.Name || strings.HasPrefix(header.Name, "/") || strings.HasPrefix(header.Name, "../") {
			t.Fatalf("unsafe compatibility archive entry %q type=%d", header.Name, header.Typeflag)
		}
		if _, duplicate := result[header.Name]; duplicate {
			t.Fatalf("duplicate compatibility archive entry %s", header.Name)
		}
		result[header.Name] = struct{}{}
	}
}
