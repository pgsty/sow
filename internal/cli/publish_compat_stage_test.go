package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestStageFrozenCompatibilityPublicationUsesIsolatedExactCandidate(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	initial := filepath.Join(root, "initial")
	if err := os.WriteFile(initial, []byte("source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceCommit, changed, err := canonical.InstallPaths(map[string]string{"initial": initial}, "test: adopted source anchor")
	if err != nil || !changed {
		t.Fatalf("install source changed=%t err=%v", changed, err)
	}

	privatePath, publicPath := writeLegacySigningKey(t, root)
	privateKey, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	active := true
	inactive := false
	projection := config.YUMCompatibilityProjection{
		ID: "infra-legacy-x86-64", Root: "yum/infra/x86_64", Mode: config.YUMCompatibilityModeFrozenCrossEL, Carrier: "infra-legacy-carrier",
		Source: config.YUMCompatibilitySource{Repo: "infra-el9", View: "latest", OS: "cross-el", Arch: "x86_64", Commit: sourceCommit.String()},
	}
	cfg := &config.Config{
		Root: root, Path: filepath.Join(root, "sow.yaml"),
		GPG: config.GPGConfig{PublicKey: filepath.Base(publicPath)},
		Repos: []config.Repo{
			{ID: "infra-el9", Type: "yum", Path: "yum/infra/el9/{arch}", Active: &active, OS: config.OSConfig{Family: "el", Major: 9, Lifecycle: "active"}, Arches: []string{"x86_64"}, YUM: &config.YUMConfig{Compression: "zstd"}},
			{ID: "infra-legacy-carrier", Type: "yum", Path: projection.Root, Active: &inactive, OS: config.OSConfig{Family: "el", Major: 7, Lifecycle: "frozen"}, Arches: []string{"x86_64"}, YUM: &config.YUMConfig{Compression: "gzip", CompatibilityCarrier: true}},
		},
		CompatibilityProjections: []config.YUMCompatibilityProjection{projection},
	}

	candidateRoot := filepath.Join(root, "candidate-root")
	rpmInput := decodeLegacyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "input.rpm"))
	packageInfo, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rpmInput})
	if err != nil {
		t.Fatal(err)
	}
	canonicalPackage := filepath.Join(candidateRoot, filepath.FromSlash(packageInfo.Location))
	if err := copyAllSelectorFile(rpmInput, canonicalPackage, 0o644); err != nil {
		t.Fatal(err)
	}
	flatPackage := filepath.Join(candidateRoot, filepath.Base(packageInfo.Location))
	if err := os.Link(canonicalPackage, flatPackage); err != nil {
		t.Fatal(err)
	}
	packageManifest := filepath.Join(root, "packages.tsv")
	packageStats, err := manifest.Scan(t.Context(), candidateRoot, manifest.Scope{Path: ".", Include: []string{"Packages/**"}}, packageManifest, manifest.ScanOptions{Workers: 2, ChunkEntries: 2, TempDir: t.TempDir()})
	if err != nil || packageStats.Files != 1 {
		t.Fatalf("scan canonical RPM files=%d err=%v", packageStats.Files, err)
	}
	packageSize := packageStats.Bytes
	signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateKey), nil, time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	iterator, packageManifestFile, err := openYUMManifestIterator(packageManifest, candidateRoot)
	if err != nil {
		t.Fatal(err)
	}
	generation, generationErr := yumrepo.Generate(t.Context(), filepath.Join(candidateRoot, "repodata"), yumrepo.Options{
		ELMajor: 0, Frozen: true, Compatibility: true, Compression: yumrepo.CompressionGzip,
		Revision: 1_752_448_000, Signer: signer,
	}, iterator)
	closeErr := packageManifestFile.Close()
	if generationErr != nil || closeErr != nil {
		t.Fatal(errors.Join(generationErr, closeErr))
	}
	candidateFile := filepath.Join(root, "candidate.tsv")
	if _, err := manifest.Scan(t.Context(), candidateRoot, manifest.Scope{Path: "."}, candidateFile, manifest.ScanOptions{Workers: 2, ChunkEntries: 2, TempDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := importYUMCompatibilityManifestObjects(t.Context(), pool, candidateRoot, candidateFile); err != nil {
		t.Fatal(err)
	}
	candidateSHA, candidateGit, candidateSize, err := fileSHA256AndGitBlob(candidateFile)
	if err != nil {
		t.Fatal(err)
	}
	candidateEntries := readCompatibilityTestManifest(t, candidateFile)
	var payloadEntries []manifest.Entry
	for _, entry := range candidateEntries {
		if strings.HasPrefix(entry.Path, "Packages/") || (!strings.Contains(entry.Path, "/") && strings.HasSuffix(entry.Path, ".rpm")) {
			payloadEntries = append(payloadEntries, entry)
		}
	}
	for index := range payloadEntries {
		payloadEntries[index].Path = path.Join(projection.Root, payloadEntries[index].Path)
	}
	sort.Slice(payloadEntries, func(i, j int) bool { return payloadEntries[i].Path < payloadEntries[j].Path })
	payloadFile := filepath.Join(root, "payload.tsv")
	writeCompatibilityTestManifest(t, payloadFile, payloadEntries)
	payloadSHA, payloadGit, payloadSize, err := fileSHA256AndGitBlob(payloadFile)
	if err != nil {
		t.Fatal(err)
	}

	sha1, sha2 := strings.Repeat("1", 64), strings.Repeat("2", 64)
	git1, git2 := strings.Repeat("1", 40), strings.Repeat("2", 40)
	packageTrust := filepath.Join(root, "package-trust.asc")
	packageTrustSHA, packageTrustGit, packageTrustSize, err := fileSHA256AndGitBlob(packageTrust)
	if err != nil {
		t.Fatal(err)
	}
	_, repositoryPackets, err := loadRepositoryPublicTrustAnchor(cfg.Path, cfg.GPG.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	repositoryTrust := filepath.Join(root, "repository-trust.pgp")
	if err := os.WriteFile(repositoryTrust, repositoryPackets, 0o600); err != nil {
		t.Fatal(err)
	}
	repositoryTrustSHA, repositoryTrustGit, repositoryTrustSize, err := fileSHA256AndGitBlob(repositoryTrust)
	if err != nil {
		t.Fatal(err)
	}
	repositoryKeySHA := repositoryTrustAnchorDigest(repositoryPackets)
	sourceRef, _ := state.YUMCompatibilitySourceRef(projection.ID)
	sourceRoot, _ := state.YUMCompatibilitySourcePath(projection.ID)
	witness := yumCompatibilityWitness{
		Schema: yumCompatibilityWitnessSchema, ID: projection.ID, Root: projection.Root, Mode: projection.Mode, Carrier: projection.Carrier,
		SourceRepo: projection.Source.Repo, SourceView: projection.Source.View, SourceOS: projection.Source.OS, SourceArch: projection.Source.Arch,
		SourceRoot: sourceRoot, SourceRef: sourceRef.String(), SourceCommit: sourceCommit.String(),
		SourceManifestSHA: sha1, SourceManifestGit: git1, SourceManifestLen: 1,
		AdoptionSHA: sha2, AdoptionGit: git2, AdoptionLen: 1,
		PayloadManifestSHA: payloadSHA, PayloadManifestGit: payloadGit.String(), PayloadManifestLen: payloadSize,
		PackageTrustSHA: packageTrustSHA, PackageTrustGit: packageTrustGit.String(), PackageTrustLen: packageTrustSize,
		Packages: 1, Bytes: packageSize, FlatAliases: true,
	}
	witnessBody, err := json.Marshal(witness)
	if err != nil {
		t.Fatal(err)
	}
	witnessBody = append(witnessBody, '\n')
	witnessFile := filepath.Join(root, "projection.json")
	if err := os.WriteFile(witnessFile, witnessBody, 0o600); err != nil {
		t.Fatal(err)
	}
	receipt := yumCompatibilityCandidate{
		Schema: yumCompatibilityCandidateSchema, ID: projection.ID, Root: projection.Root, Carrier: projection.Carrier, OwnerRepo: projection.Source.Repo,
		SourceRef: sourceRef.String(), SourceCommit: sourceCommit.String(), SourceManifestSHA256: sha1, SourceManifestGit: git1, SourceManifestSize: 1,
		AdoptionSHA256: sha2, AdoptionGit: git2, AdoptionSize: 1,
		PackageTrustSHA256: packageTrustSHA, PackageTrustGit: packageTrustGit.String(), PackageTrustSize: packageTrustSize,
		RepositoryTrustSHA256: repositoryTrustSHA, RepositoryTrustGit: repositoryTrustGit.String(), RepositoryTrustSize: repositoryTrustSize,
		CandidatePath: "/operator-only/candidate", CandidateManifestSHA256: candidateSHA, CandidateManifestGit: candidateGit.String(), CandidateManifestSize: candidateSize,
		RepomdSHA256: generation.RepomdSHA256, RepositoryKeySHA256: repositoryKeySHA, Packages: 1, Bytes: packageSize,
	}
	receipt.FreezeConfirm, err = yumCompatibilityConfirmation("freeze", receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptBody, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptBody = append(receiptBody, '\n')
	receiptFile := filepath.Join(root, "candidate.json")
	if err := os.WriteFile(receiptFile, receiptBody, 0o600); err != nil {
		t.Fatal(err)
	}
	witnessPath, _ := state.YUMCompatibilityProjectionPath(projection.ID)
	payloadPath, _ := state.YUMCompatibilityManifestPath(projection.ID)
	candidatePath, _ := state.YUMCompatibilityCandidateManifestPath(projection.ID)
	receiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(projection.ID)
	packageTrustPath, _ := state.YUMCompatibilityPackageTrustPath(projection.ID)
	repositoryTrustPath, _ := state.YUMCompatibilityRepositoryTrustPath(projection.ID)
	freezeCommit, changed, err := canonical.InstallPaths(map[string]string{
		witnessPath: witnessFile, payloadPath: payloadFile, candidatePath: candidateFile, receiptPath: receiptFile,
		packageTrustPath: packageTrust, repositoryTrustPath: repositoryTrust,
	}, "test: freeze exact candidate")
	if err != nil || !changed {
		t.Fatalf("install freeze changed=%t err=%v", changed, err)
	}
	freezeRef, _ := state.YUMCompatibilityRef(projection.ID)
	if err := canonical.AdvanceRef(freezeRef, plumbing.ZeroHash, freezeCommit, true); err != nil {
		t.Fatal(err)
	}

	legacyRoot := filepath.Join(root, filepath.FromSlash(projection.Root))
	if err := os.MkdirAll(legacyRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(legacyRoot, "operator-sentinel")
	if err := os.WriteFile(sentinel, []byte("must-not-change\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := stageFrozenYUMCompatibilityPublication(t.Context(), cfg, canonical, pool, projection, t.TempDir(), commonFlags{workers: 2, chunk: 2})
	if err != nil {
		t.Fatal(err)
	}
	if stage.projection.localRoot == "" || stage.projection.sourceRoot != projection.Root || stage.projection.localRoot == projection.Root {
		t.Fatalf("candidate was not isolated: %+v", stage.projection)
	}
	trustRoot := path.Dir(config.YUMCompatibilityPackageTrustRoute(projection.ID))
	if !stage.trustProjection.isYUMCompatibilityTrust() || stage.trustProjection.sourceRoot != trustRoot || stage.trustProjection.remotePathRoot() != trustRoot || stage.trustProjection.localRoot == "" || stage.trustProjection.localRoot == trustRoot {
		t.Fatalf("frozen trust was not isolated at its exact route: %+v", stage.trustProjection)
	}
	for name, wantSHA := range map[string]string{"packages.pgp": packageTrustSHA, "repository.pgp": repositoryTrustSHA} {
		physical := filepath.Join(root, filepath.FromSlash(stage.trustProjection.localRoot), name)
		body, err := os.ReadFile(physical)
		if err != nil || digestBytesCLI(body) != wantSHA {
			t.Fatalf("staged frozen trust %s digest=%s want=%s err=%v", name, digestBytesCLI(body), wantSHA, err)
		}
		digest, err := repository.ParseDigest(wantSHA)
		if err != nil {
			t.Fatal(err)
		}
		stagedInfo, err := os.Stat(physical)
		if err != nil {
			t.Fatal(err)
		}
		casInfo, err := os.Stat(pool.ObjectPath(digest))
		if err != nil || !os.SameFile(stagedInfo, casInfo) {
			t.Fatalf("staged frozen trust %s is not the exact CAS hardlink: %v", name, err)
		}
	}
	actual := filepath.Join(t.TempDir(), "actual.tsv")
	if _, err := manifest.Scan(t.Context(), filepath.Join(root, filepath.FromSlash(stage.projection.localRoot)), manifest.Scope{Path: "."}, actual, manifest.ScanOptions{Workers: 2, ChunkEntries: 2, TempDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := requireManifestFilesEqual(candidateFile, actual); err != nil {
		t.Fatalf("isolated stage differs from exact candidate: %v", err)
	}
	if body, err := os.ReadFile(sentinel); err != nil || string(body) != "must-not-change\n" {
		t.Fatalf("publish staging rewrote hosted compatibility root: body=%q err=%v", body, err)
	}
	if _, err := os.Lstat(filepath.Join(legacyRoot, "repodata")); !os.IsNotExist(err) {
		t.Fatalf("publish staging installed metadata in hosted root: %v", err)
	}
	identity := pub.CompatibilityState{
		ID: projection.ID, FreezeCommit: freezeCommit.String(), RepomdSHA256: generation.RepomdSHA256,
		RepositoryKeySHA256: repositoryKeySHA,
		PackageTrustSHA256:  packageTrustSHA, PackageTrustGit: packageTrustGit.String(), PackageTrustSize: packageTrustSize,
	}
	physicalStage := filepath.Join(root, filepath.FromSlash(stage.projection.localRoot))
	t.Run("reject repository signer identity drift", func(t *testing.T) {
		drift := identity
		drift.RepositoryKeySHA256 = strings.Repeat("f", 64)
		if err := validateFrozenCompatibilityTree(t.Context(), cfg, canonical, drift, physicalStage, t.TempDir(), 2, 2); err == nil {
			t.Fatal("repository signer identity drift was accepted")
		}
	})
	t.Run("reject signed metadata byte drift", func(t *testing.T) {
		clone := filepath.Join(t.TempDir(), "candidate")
		copyCompatibilityTestTree(t, physicalStage, clone)
		repomd := filepath.Join(clone, "repodata", "repomd.xml")
		body, err := os.ReadFile(repomd)
		if err != nil || len(body) == 0 {
			t.Fatal(err)
		}
		body[len(body)-1] ^= 1
		if err := os.WriteFile(repomd, body, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := validateFrozenCompatibilityTree(t.Context(), cfg, canonical, identity, clone, t.TempDir(), 2, 2); err == nil {
			t.Fatal("signed metadata byte drift was accepted")
		}
	})
	t.Run("reject frozen RPM byte drift", func(t *testing.T) {
		clone := filepath.Join(t.TempDir(), "candidate")
		copyCompatibilityTestTree(t, physicalStage, clone)
		rpmPath := filepath.Join(clone, filepath.FromSlash(packageInfo.Location))
		body, err := os.ReadFile(rpmPath)
		if err != nil || len(body) == 0 {
			t.Fatal(err)
		}
		body[len(body)-1] ^= 1
		if err := os.WriteFile(rpmPath, body, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := validateFrozenCompatibilityTree(t.Context(), cfg, canonical, identity, clone, t.TempDir(), 2, 2); err == nil {
			t.Fatal("frozen RPM byte drift was accepted")
		}
	})

	plan := pub.Plan{Objects: []pub.PlannedObject{
		{SourcePath: projection.Root + "/repodata/repomd.xml"},
		{SourcePath: ".sow/generated/mirrorlists/test.txt"},
	}}
	classifier := publicationClassifier{projections: []publicationProjection{stage.projection, stage.trustProjection}}
	if err := localizeIsolatedPublicationSources(&plan, classifier, false); err != nil {
		t.Fatal(err)
	}
	if plan.Objects[0].SourcePath != path.Join(stage.projection.localRoot, "repodata/repomd.xml") || plan.Objects[1].SourcePath != ".sow/generated/mirrorlists/test.txt" {
		t.Fatalf("isolated plan source localization=%+v", plan.Objects)
	}
	remote, class, err := classifier.classify(manifest.Entry{Path: config.YUMCompatibilityRepositoryTrustRoute(projection.ID), Size: repositoryTrustSize})
	if err != nil || remote != config.YUMCompatibilityRepositoryTrustRoute(projection.ID) || class != pub.ObjectImmutable {
		t.Fatalf("frozen repository trust classification remote=%s class=%s err=%v", remote, class, err)
	}
}

func copyCompatibilityTestTree(t *testing.T, source, destination string) {
	t.Helper()
	if err := filepath.WalkDir(source, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		body, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, 0o644)
	}); err != nil {
		t.Fatal(err)
	}
}

func readCompatibilityTestManifest(t *testing.T, filename string) []manifest.Entry {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	var entries []manifest.Entry
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return entries
		}
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
}
