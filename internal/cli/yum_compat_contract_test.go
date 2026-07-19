package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

type yumCompatibilityContractFixture struct {
	root                 string
	canonical            *state.Store
	cfg                  *config.Config
	configBody           []byte
	sourceBody           []byte
	adoptionBody         []byte
	witnessBody          []byte
	manifestBody         []byte
	candidateReceiptBody []byte
	packageTrustBody     []byte
	repositoryTrustBody  []byte
	manifestPath         string
	s0                   plumbing.Hash
	s1                   plumbing.Hash
	anchor               plumbing.Hash
}

func TestYUMCompatibilityContinuityAdmissionDoesNotCreateCanonicalState(t *testing.T) {
	root := t.TempDir()
	cfg, err := decodeRootedYUMCompatibilityConfig(root, "")
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, ".sow", "state")
	if _, err := os.Lstat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected preexisting state: %v", err)
	}
	if err := validateCanonicalYUMCompatibilityContracts(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only compatibility admission created canonical state: %v", err)
	}
}

func TestYUMCompatibilityContinuityAcceptsAdoptionOnlyAndExactSourceRefRebuild(t *testing.T) {
	fixture := newYUMCompatibilityContractFixture(t, "")
	resetYUMCompatibilityFixtureToS1(t, fixture)
	if err := validateCanonicalYUMCompatibilityContracts(fixture.cfg); err != nil {
		t.Fatalf("valid adoption-only S1 rejected: %v", err)
	}
	sourceRef, _ := state.YUMCompatibilitySourceRef(fixture.cfg.CompatibilityProjections[0].ID)
	repository, err := git.PlainOpen(filepath.Join(fixture.root, ".sow", "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.RemoveReference(sourceRef); err != nil {
		t.Fatal(err)
	}
	if err := validateCanonicalYUMCompatibilityContracts(fixture.cfg); err == nil || !strings.Contains(err.Error(), "source ref") {
		t.Fatalf("deleted S1 source ref escaped continuity audit: %v", err)
	}
	if err := fixture.canonical.AdvanceRef(sourceRef, plumbing.ZeroHash, fixture.s1, true); err != nil {
		t.Fatal(err)
	}
	if err := validateCanonicalYUMCompatibilityContracts(fixture.cfg); err != nil {
		t.Fatalf("exact source ref rebuild did not recover adoption continuity: %v", err)
	}
}

func TestYUMCompatibilityContinuityRejectsContentUnboundInitialS2Anchor(t *testing.T) {
	fixture := newYUMCompatibilityContractFixture(t, "")
	var forged yumCompatibilityCandidate
	if err := json.Unmarshal(fixture.candidateReceiptBody, &forged); err != nil {
		t.Fatal(err)
	}
	// Keep every tree/Git identity accepted by the streaming history scanner,
	// but make the receipt claim different package-trust bytes and seal that
	// self-consistent lie with a fresh confirmation.  With the legitimate S2
	// branch made unreachable, this is the initial freeze anchor rather than a
	// descendant drift case.
	forged.PackageTrustSHA256 = strings.Repeat("f", 64)
	forged.FreezeConfirm = ""
	var err error
	forged.FreezeConfirm, err = yumCompatibilityConfirmation("freeze", forged)
	if err != nil {
		t.Fatal(err)
	}
	forgedBody, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	forgedBody = append(forgedBody, '\n')
	id := forged.ID
	witnessPath, _ := state.YUMCompatibilityProjectionPath(id)
	manifestPath, _ := state.YUMCompatibilityManifestPath(id)
	candidateManifestPath, _ := state.YUMCompatibilityCandidateManifestPath(id)
	candidateReceiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(id)
	repositoryTrustPath, _ := state.YUMCompatibilityRepositoryTrustPath(id)
	forgedAnchor := commitAssetProjectionState(t, fixture.root, []plumbing.Hash{fixture.s1}, time.Now().UTC(), "test: forged initial S2 anchor", map[string][]byte{
		"config/sow.yaml": fixture.configBody, witnessPath: fixture.witnessBody, manifestPath: fixture.manifestBody,
		candidateManifestPath: fixture.manifestBody, candidateReceiptPath: forgedBody, repositoryTrustPath: fixture.repositoryTrustBody,
	})
	resetAssetProjectionHead(t, fixture.root, forgedAnchor)
	repository, err := git.PlainOpen(filepath.Join(fixture.root, ".sow", "state"))
	if err != nil {
		t.Fatal(err)
	}
	freezeRef, _ := state.YUMCompatibilityRef(id)
	if err := repository.Storer.SetReference(plumbing.NewHashReference(freezeRef, forgedAnchor)); err != nil {
		t.Fatal(err)
	}
	if err := validateCanonicalYUMCompatibilityContracts(fixture.cfg); err == nil ||
		!strings.Contains(err.Error(), "full content-bound admission") {
		t.Fatalf("content-unbound initial S2 anchor escaped continuity admission: %v", err)
	}
}

func TestYUMCompatibilityContinuityRequiresS3LedgerPrefixAppendOnly(t *testing.T) {
	fixture := newYUMCompatibilityContractFixture(t, "")
	var receipt yumCompatibilityCandidate
	if err := json.Unmarshal(fixture.candidateReceiptBody, &receipt); err != nil {
		t.Fatal(err)
	}
	link := path.Join(".sow", "serving", "compatibility", "yum", receipt.ID, "current")
	candidateTarget := path.Join(".sow", "materialized", "compatibility", receipt.ID, receipt.CandidateManifestSHA256)
	cutover := sealYUMCompatibilityCutoverEvent(t, yumCompatibilityCutoverEvent{
		Schema: yumCompatibilityCutoverEventSchema, Sequence: 1, ID: receipt.ID, Action: "cutover",
		ServingLink: link, FromTarget: receipt.Root, ToTarget: candidateTarget, FreezeCommit: fixture.anchor.String(),
		CandidateManifestSHA256: receipt.CandidateManifestSHA256, PreviousEventSHA256: strings.Repeat("0", 64),
	})
	cutoverLine, err := json.Marshal(cutover)
	if err != nil {
		t.Fatal(err)
	}
	cutoverBody := append(cutoverLine, '\n')
	ledgerPath, _ := state.YUMCompatibilityCutoverPath(receipt.ID)
	s3 := commitAssetProjectionState(t, fixture.root, []plumbing.Hash{fixture.anchor}, time.Now().UTC(), "test: append S3 cutover", map[string][]byte{ledgerPath: cutoverBody})
	if err := validateCanonicalYUMCompatibilityContracts(fixture.cfg); err != nil {
		t.Fatalf("valid S1 -> S2 -> S3 cutover history rejected: %v", err)
	}
	rollback := sealYUMCompatibilityCutoverEvent(t, yumCompatibilityCutoverEvent{
		Schema: yumCompatibilityCutoverEventSchema, Sequence: 2, ID: receipt.ID, Action: "rollback",
		ServingLink: link, FromTarget: candidateTarget, ToTarget: receipt.Root, FreezeCommit: fixture.anchor.String(),
		CandidateManifestSHA256: receipt.CandidateManifestSHA256, PreviousEventSHA256: cutover.EventSHA256,
	})
	rollbackLine, err := json.Marshal(rollback)
	if err != nil {
		t.Fatal(err)
	}
	rollbackBody := append(append(append([]byte(nil), cutoverBody...), rollbackLine...), '\n')
	rolledBack := commitAssetProjectionState(t, fixture.root, []plumbing.Hash{s3}, time.Now().UTC().Add(time.Second), "test: append S3 rollback", map[string][]byte{ledgerPath: rollbackBody})
	if err := validateCanonicalYUMCompatibilityContracts(fixture.cfg); err != nil {
		t.Fatalf("valid append-only rollback history rejected: %v", err)
	}
	commitAssetProjectionState(t, fixture.root, []plumbing.Hash{rolledBack}, time.Now().UTC().Add(2*time.Second), "test: truncate S3 ledger", map[string][]byte{ledgerPath: cutoverBody})
	if err := validateCanonicalYUMCompatibilityContracts(fixture.cfg); err == nil || !strings.Contains(err.Error(), "ledger was truncated") {
		t.Fatalf("S3 ledger truncation escaped Git-edge continuity audit: %v", err)
	}
}

func resetYUMCompatibilityFixtureToS1(t *testing.T, fixture yumCompatibilityContractFixture) {
	t.Helper()
	repository, err := git.PlainOpen(filepath.Join(fixture.root, ".sow", "state"))
	if err != nil {
		t.Fatal(err)
	}
	head, err := repository.Head()
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.SetReference(plumbing.NewHashReference(head.Name(), fixture.s1)); err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := worktree.Reset(&git.ResetOptions{Mode: git.HardReset, Commit: fixture.s1}); err != nil {
		t.Fatal(err)
	}
	freezeRef, _ := state.YUMCompatibilityRef(fixture.cfg.CompatibilityProjections[0].ID)
	if err := repository.Storer.RemoveReference(freezeRef); err != nil {
		t.Fatal(err)
	}
}

func newYUMCompatibilityContractFixture(t *testing.T, manifestPath string) yumCompatibilityContractFixture {
	t.Helper()
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	initial, err := decodeRootedYUMCompatibilityConfig(root, "")
	if err != nil {
		t.Fatal(err)
	}
	initialBody, err := initial.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	initialPath := filepath.Join(root, "initial-sow.yaml")
	viewPath := filepath.Join(root, "latest.tsv")
	carrierPath := filepath.Join(root, "carrier.tsv")
	if err := os.WriteFile(initialPath, initialBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(viewPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	carrierBody := []byte("yum/infra/x86_64/legacy.rpm\t1\t" + strings.Repeat("0", 64) + "\n")
	if err := os.WriteFile(carrierPath, carrierBody, 0o600); err != nil {
		t.Fatal(err)
	}
	canonicalViewPath, _ := state.ViewPath("latest", "infra-el9", "el9", "x86_64")
	carrierCanonical := filepath.ToSlash(filepath.Join("manifests", "infra-carrier.tsv"))
	s0, changed, err := canonical.InstallPaths(map[string]string{
		"config/sow.yaml": initialPath, canonicalViewPath: viewPath, carrierCanonical: carrierPath,
	}, "test: immutable S0 carrier")
	if err != nil || !changed {
		t.Fatalf("install S0 changed=%v err=%v", changed, err)
	}
	viewRef, _ := state.ViewRef("latest", "infra-el9", "el9", "x86_64")
	if err := canonical.AdvanceRef(viewRef, plumbing.ZeroHash, s0, false); err != nil {
		t.Fatal(err)
	}
	carrierRef, _ := state.RepoRef("infra-carrier")
	if err := canonical.AdvanceRef(carrierRef, plumbing.ZeroHash, s0, true); err != nil {
		t.Fatal(err)
	}
	cfg, err := decodeRootedYUMCompatibilityConfig(root, config.YUMCompatibilityPinAtFirstFreeze)
	if err != nil {
		t.Fatal(err)
	}
	configBody, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if manifestPath == "" {
		manifestPath = filepath.Join(root, "compat-manifest.tsv")
		body := []byte("yum/infra/x86_64/pkg.rpm\t1\t" + strings.Repeat("a", 64) + "\n")
		if err := os.WriteFile(manifestPath, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifestSHA, manifestGit, manifestSize, err := fileSHA256AndGitBlob(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	trustPath := writeRPMPackageTrustFixture(t, root)
	trustBody, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	trustSHA, trustGit, trustSize, err := fileSHA256AndGitBlob(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	projection := cfg.CompatibilityProjections[0]
	carrierSHA, carrierGit, carrierSize, err := fileSHA256AndGitBlob(carrierPath)
	if err != nil {
		t.Fatal(err)
	}
	adoption := yumCompatibilityAdoption{
		Schema: yumCompatibilityAdoptionSchema, ID: projection.ID, Root: projection.Root, Carrier: projection.Carrier,
		OwnerRepo: projection.Source.Repo, View: projection.Source.View, OS: projection.Source.OS, Arch: projection.Source.Arch,
		BaselineRef: carrierRef.String(), BaselineCommit: s0.String(), BaselineManifestSHA256: carrierSHA,
		BaselineManifestGit: carrierGit.String(), BaselineManifestSize: carrierSize,
		SourceManifestSHA256: manifestSHA, SourceManifestGit: manifestGit.String(), SourceManifestSize: manifestSize,
		PackageTrustSHA256: trustSHA, PackageTrustGit: trustGit.String(), PackageTrustSize: trustSize,
		Packages: 1, Bytes: 1, LegacyMetadataPolicy: yumCompatibilityMetadataPolicy,
		LegacyRepomdSignature: "not-claimed", CandidateMetadataPolicy: "clean-signed-three-xml-gzip",
	}
	adoptionBody, err := json.Marshal(adoption)
	if err != nil {
		t.Fatal(err)
	}
	adoptionBody = append(adoptionBody, '\n')
	configPath := filepath.Join(root, "adopted-sow.yaml")
	adoptionFile := filepath.Join(root, "adoption.json")
	if err := os.WriteFile(configPath, configBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adoptionFile, adoptionBody, 0o600); err != nil {
		t.Fatal(err)
	}
	sourceCanonical, _ := state.YUMCompatibilitySourcePath(projection.ID)
	adoptionCanonical, _ := state.YUMCompatibilityAdoptionPath(projection.ID)
	trustCanonical, _ := state.YUMCompatibilityPackageTrustPath(projection.ID)
	s1, changed, err := canonical.InstallPaths(map[string]string{
		"config/sow.yaml": configPath, sourceCanonical: manifestPath, adoptionCanonical: adoptionFile, trustCanonical: trustPath,
	}, "test: immutable S1 adoption")
	if err != nil || !changed {
		t.Fatalf("install S1 changed=%v err=%v", changed, err)
	}
	sourceRef, _ := state.YUMCompatibilitySourceRef(projection.ID)
	if err := canonical.AdvanceRef(sourceRef, plumbing.ZeroHash, s1, true); err != nil {
		t.Fatal(err)
	}
	adoptionSHA, adoptionGit, adoptionSize, err := fileSHA256AndGitBlob(adoptionFile)
	if err != nil {
		t.Fatal(err)
	}
	witness := yumCompatibilityWitness{
		Schema: yumCompatibilityWitnessSchema, ID: projection.ID, Root: projection.Root, Mode: projection.Mode, Carrier: projection.Carrier,
		SourceRepo: projection.Source.Repo, SourceView: projection.Source.View, SourceOS: projection.Source.OS, SourceArch: projection.Source.Arch, SourceRoot: sourceCanonical,
		SourceRef: sourceRef.String(), SourceCommit: s1.String(), SourceManifestSHA: manifestSHA,
		SourceManifestGit: manifestGit.String(), SourceManifestLen: manifestSize,
		AdoptionSHA: adoptionSHA, AdoptionGit: adoptionGit.String(), AdoptionLen: adoptionSize,
		PayloadManifestSHA: manifestSHA,
		PayloadManifestGit: manifestGit.String(), PayloadManifestLen: manifestSize,
		PackageTrustSHA: trustSHA, PackageTrustGit: trustGit.String(), PackageTrustLen: trustSize,
		Packages: 1, Bytes: 1, FlatAliases: true,
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
	_, repositoryTrustPath := writeLegacySigningKey(t, root)
	repositoryTrustBody, err := os.ReadFile(repositoryTrustPath)
	if err != nil {
		t.Fatal(err)
	}
	repositoryTrustSHA, repositoryTrustGit, repositoryTrustSize, err := fileSHA256AndGitBlob(repositoryTrustPath)
	if err != nil {
		t.Fatal(err)
	}
	trustPool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		label string
		body  []byte
		sha   string
		size  int64
	}{
		{label: "package", body: trustBody, sha: trustSHA, size: trustSize},
		{label: "repository", body: repositoryTrustBody, sha: repositoryTrustSHA, size: repositoryTrustSize},
	} {
		object, err := trustPool.Put(t.Context(), bytes.NewReader(item.body))
		if err != nil || object.HashString() != item.sha || object.Size != item.size {
			t.Fatalf("import frozen %s trust CAS object=%+v err=%v", item.label, object, err)
		}
	}
	candidate := yumCompatibilityCandidate{
		Schema: yumCompatibilityCandidateSchema, ID: projection.ID, Root: projection.Root, Carrier: projection.Carrier, OwnerRepo: projection.Source.Repo,
		SourceRef: sourceRef.String(), SourceCommit: s1.String(), SourceManifestSHA256: manifestSHA, SourceManifestGit: manifestGit.String(), SourceManifestSize: manifestSize,
		AdoptionSHA256: adoptionSHA, AdoptionGit: adoptionGit.String(), AdoptionSize: adoptionSize,
		PackageTrustSHA256: trustSHA, PackageTrustGit: trustGit.String(), PackageTrustSize: trustSize,
		CandidateManifestSHA256: manifestSHA, CandidateManifestGit: manifestGit.String(), CandidateManifestSize: manifestSize,
		RepomdSHA256: strings.Repeat("9", 64), RepositoryKeySHA256: repositoryTrustAnchorDigest(repositoryTrustBody),
		RepositoryTrustSHA256: repositoryTrustSHA, RepositoryTrustGit: repositoryTrustGit.String(), RepositoryTrustSize: repositoryTrustSize,
		Packages: 1, Bytes: 1,
	}
	candidate.FreezeConfirm, err = yumCompatibilityConfirmation("freeze", candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidateReceiptBody, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidateReceiptBody = append(candidateReceiptBody, '\n')
	candidateReceiptFile := filepath.Join(root, "candidate.json")
	if err := os.WriteFile(candidateReceiptFile, candidateReceiptBody, 0o600); err != nil {
		t.Fatal(err)
	}
	witnessCanonical, _ := state.YUMCompatibilityProjectionPath(projection.ID)
	manifestCanonical, _ := state.YUMCompatibilityManifestPath(projection.ID)
	candidateManifestCanonical, _ := state.YUMCompatibilityCandidateManifestPath(projection.ID)
	candidateReceiptCanonical, _ := state.YUMCompatibilityCandidateReceiptPath(projection.ID)
	repositoryTrustCanonical, _ := state.YUMCompatibilityRepositoryTrustPath(projection.ID)
	anchor, changed, err := canonical.InstallPaths(map[string]string{
		witnessCanonical: witnessFile, manifestCanonical: manifestPath, candidateManifestCanonical: manifestPath,
		candidateReceiptCanonical: candidateReceiptFile, repositoryTrustCanonical: repositoryTrustPath,
	}, "test: freeze compatibility")
	if err != nil || !changed {
		t.Fatalf("install witness changed=%v err=%v", changed, err)
	}
	compatRef, _ := state.YUMCompatibilityRef(projection.ID)
	if err := canonical.AdvanceRef(compatRef, plumbing.ZeroHash, anchor, true); err != nil {
		t.Fatal(err)
	}
	var manifestBody []byte
	if manifestSize <= 1<<20 {
		manifestBody, err = os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
	}
	return yumCompatibilityContractFixture{
		root: root, canonical: canonical, cfg: cfg, configBody: configBody, sourceBody: manifestBody, adoptionBody: adoptionBody,
		witnessBody: witnessBody, manifestBody: manifestBody, candidateReceiptBody: candidateReceiptBody,
		packageTrustBody: trustBody, repositoryTrustBody: repositoryTrustBody, manifestPath: manifestPath,
		s0: s0, s1: s1, anchor: anchor,
	}
}

func decodeRootedYUMCompatibilityConfig(root, commit string) (*config.Config, error) {
	compatibility := ""
	if commit != "" {
		compatibility = `compatibility_projections:
  - {id: infra-legacy-x86-64, root: yum/infra/x86_64, mode: frozen-cross-el, carrier: infra-carrier, source: {repo: infra-el9, view: latest, os: cross-el, arch: x86_64, commit: ` + commit + `}}
`
	}
	body := `schema: sow/v1
state: {}
gpg: {public_key: legacy-public.key}
pools: {public: {}, gated: {}}
repos:
  - id: infra-el9
    type: yum
    path: yum/infra/el9/{arch}
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
  - id: infra-carrier
    type: yum
    path: yum/infra/{arch}
    active: false
    default_pool: public
    arches: [x86_64]
    os: {family: cross-el, major: 0, lifecycle: frozen}
    yum: {compression: gzip, compatibility_carrier: true}
` + compatibility + `upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`
	cfg, err := config.Decode(strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	cfg.Root = root
	cfg.Path = filepath.Join(root, "sow.yaml")
	return cfg, nil
}

func TestYUMCompatibilityContinuityRejectsClockSkewRemovalAndByteIdenticalReintroduction(t *testing.T) {
	fixture := newYUMCompatibilityContractFixture(t, "")
	id := "infra-legacy-x86-64"
	witnessPath, _ := state.YUMCompatibilityProjectionPath(id)
	manifestPath, _ := state.YUMCompatibilityManifestPath(id)
	candidateManifestPath, _ := state.YUMCompatibilityCandidateManifestPath(id)
	candidateReceiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(id)
	repositoryTrustPath, _ := state.YUMCompatibilityRepositoryTrustPath(id)
	now := time.Now().UTC()
	removed := commitAssetProjectionState(t, fixture.root, []plumbing.Hash{fixture.anchor}, now.Add(-4*time.Hour), "test: regress S2 to S1 despite skew", map[string][]byte{"config/sow.yaml": fixture.configBody}, witnessPath, manifestPath, candidateManifestPath, candidateReceiptPath, repositoryTrustPath)
	commitAssetProjectionState(t, fixture.root, []plumbing.Hash{removed}, now.Add(-8*time.Hour), "test: reintroduce exact compatibility bytes despite skew", map[string][]byte{
		"config/sow.yaml": fixture.configBody, witnessPath: fixture.witnessBody, manifestPath: fixture.manifestBody,
		candidateManifestPath: fixture.manifestBody, candidateReceiptPath: fixture.candidateReceiptBody, repositoryTrustPath: fixture.repositoryTrustBody,
	})
	err := validateCanonicalYUMCompatibilityContracts(fixture.cfg)
	if err == nil || !strings.Contains(err.Error(), "regressed at descendant") {
		t.Fatalf("clock-skew removal/reintroduction escaped continuity audit: %v", err)
	}
}

func TestYUMCompatibilityContinuityAuditsOffHEADSOWRefMergeWithClockSkew(t *testing.T) {
	fixture := newYUMCompatibilityContractFixture(t, "")
	id := "infra-legacy-x86-64"
	witnessPath, _ := state.YUMCompatibilityProjectionPath(id)
	manifestPath, _ := state.YUMCompatibilityManifestPath(id)
	candidateManifestPath, _ := state.YUMCompatibilityCandidateManifestPath(id)
	candidateReceiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(id)
	repositoryTrustPath, _ := state.YUMCompatibilityRepositoryTrustPath(id)
	now := time.Now().UTC()
	removed := commitAssetProjectionState(t, fixture.root, []plumbing.Hash{fixture.anchor}, now.Add(8*time.Hour), "test: off-head regress S2 to S1", map[string][]byte{"config/sow.yaml": fixture.configBody}, witnessPath, manifestPath, candidateManifestPath, candidateReceiptPath, repositoryTrustPath)
	merged := commitAssetProjectionState(t, fixture.root, []plumbing.Hash{removed, fixture.anchor}, now.Add(-8*time.Hour), "test: off-head merge reintroduces identical bytes with skew", map[string][]byte{
		"config/sow.yaml": fixture.configBody, witnessPath: fixture.witnessBody, manifestPath: fixture.manifestBody,
		candidateManifestPath: fixture.manifestBody, candidateReceiptPath: fixture.candidateReceiptBody, repositoryTrustPath: fixture.repositoryTrustBody,
	})
	repository, err := git.PlainOpen(filepath.Join(fixture.root, ".sow", "state"))
	if err != nil {
		t.Fatal(err)
	}
	head, err := repository.Head()
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.SetReference(plumbing.NewHashReference(head.Name(), fixture.anchor)); err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := worktree.Reset(&git.ResetOptions{Mode: git.HardReset, Commit: fixture.anchor}); err != nil {
		t.Fatal(err)
	}
	offHEADRef, _ := state.ViewRef("latest", "off-head-compat-audit", "all", "all")
	if err := fixture.canonical.AdvanceRef(offHEADRef, plumbing.ZeroHash, merged, false); err != nil {
		t.Fatal(err)
	}
	err = validateCanonicalYUMCompatibilityContracts(fixture.cfg)
	if err == nil || !strings.Contains(err.Error(), "regressed at descendant") {
		t.Fatalf("off-HEAD SOW-ref merge removal escaped compatibility audit: %v", err)
	}
}

func TestYUMCompatibilityContinuityRejectsConflictingDisconnectedSOWRoot(t *testing.T) {
	fixture := newYUMCompatibilityContractFixture(t, "")
	var driftWitness yumCompatibilityWitness
	if err := json.Unmarshal(fixture.witnessBody, &driftWitness); err != nil {
		t.Fatal(err)
	}
	driftManifest := append([]byte(nil), fixture.manifestBody...)
	driftManifest[len(driftManifest)-2] ^= 1
	driftManifestPath := filepath.Join(fixture.root, "disconnected-manifest.tsv")
	if err := os.WriteFile(driftManifestPath, driftManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	driftSHA, driftGit, driftSize, err := fileSHA256AndGitBlob(driftManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	driftWitness.PayloadManifestSHA = driftSHA
	driftWitness.PayloadManifestGit = driftGit.String()
	driftWitness.PayloadManifestLen = driftSize
	driftWitnessBody, err := json.Marshal(driftWitness)
	if err != nil {
		t.Fatal(err)
	}
	driftWitnessBody = append(driftWitnessBody, '\n')
	var driftCandidate yumCompatibilityCandidate
	if err := json.Unmarshal(fixture.candidateReceiptBody, &driftCandidate); err != nil {
		t.Fatal(err)
	}
	driftCandidate.CandidateManifestSHA256 = driftSHA
	driftCandidate.CandidateManifestGit = driftGit.String()
	driftCandidate.CandidateManifestSize = driftSize
	driftCandidate.FreezeConfirm = ""
	driftCandidate.FreezeConfirm, err = yumCompatibilityConfirmation("freeze", driftCandidate)
	if err != nil {
		t.Fatal(err)
	}
	driftCandidateBody, err := json.Marshal(driftCandidate)
	if err != nil {
		t.Fatal(err)
	}
	driftCandidateBody = append(driftCandidateBody, '\n')
	witnessPath, _ := state.YUMCompatibilityProjectionPath(driftWitness.ID)
	manifestPath, _ := state.YUMCompatibilityManifestPath(driftWitness.ID)
	candidateManifestPath, _ := state.YUMCompatibilityCandidateManifestPath(driftWitness.ID)
	candidateReceiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(driftWitness.ID)
	repositoryTrustPath, _ := state.YUMCompatibilityRepositoryTrustPath(driftWitness.ID)
	disconnected := commitAssetProjectionState(t, fixture.root, []plumbing.Hash{fixture.s1}, time.Now().UTC().Add(-12*time.Hour), "test: disconnected conflicting compatibility owner", map[string][]byte{
		"config/sow.yaml": fixture.configBody, witnessPath: driftWitnessBody, manifestPath: driftManifest,
		candidateManifestPath: driftManifest, candidateReceiptPath: driftCandidateBody, repositoryTrustPath: fixture.repositoryTrustBody,
	})
	repository, err := git.PlainOpen(filepath.Join(fixture.root, ".sow", "state"))
	if err != nil {
		t.Fatal(err)
	}
	head, err := repository.Head()
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.SetReference(plumbing.NewHashReference(head.Name(), fixture.anchor)); err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := worktree.Reset(&git.ResetOptions{Mode: git.HardReset, Commit: fixture.anchor}); err != nil {
		t.Fatal(err)
	}
	offHEADRef, _ := state.SnapshotRef("jammy-20260714", "disconnected-compat-audit", "all", "all")
	if err := fixture.canonical.AdvanceRef(offHEADRef, plumbing.ZeroHash, disconnected, true); err != nil {
		t.Fatal(err)
	}
	err = validateCanonicalYUMCompatibilityContracts(fixture.cfg)
	if err == nil || !strings.Contains(err.Error(), "conflicting disconnected ownership anchors") {
		t.Fatalf("conflicting disconnected compatibility owner escaped audit: %v", err)
	}
}

func TestYUMCompatibilityContinuityRejectsSameSizeManifestTamper(t *testing.T) {
	fixture := newYUMCompatibilityContractFixture(t, "")
	manifestPath, _ := state.YUMCompatibilityManifestPath("infra-legacy-x86-64")
	tampered := append([]byte(nil), fixture.manifestBody...)
	tampered[len(tampered)-2] ^= 1
	commitAssetProjectionState(t, fixture.root, []plumbing.Hash{fixture.anchor}, time.Now().UTC(), "test: same-size compatibility manifest tamper", map[string][]byte{manifestPath: tampered})
	err := validateCanonicalYUMCompatibilityContracts(fixture.cfg)
	if err == nil || !strings.Contains(err.Error(), "tree identity differs") {
		t.Fatalf("same-size manifest tamper escaped blob identity gate: %v", err)
	}
}

func TestYUMCompatibilityContinuityDoesNotInflateLargeManifest(t *testing.T) {
	measure := func(manifestSize int64) uint64 {
		t.Helper()
		large := filepath.Join(t.TempDir(), fmt.Sprintf("compat-manifest-%d.tsv", manifestSize))
		file, err := os.OpenFile(large, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		truncateErr := file.Truncate(manifestSize)
		closeErr := file.Close()
		if truncateErr != nil || closeErr != nil {
			t.Fatalf("create compatibility manifest truncate=%v close=%v", truncateErr, closeErr)
		}
		fixture := newYUMCompatibilityContractFixture(t, large)
		for index := 0; index < 5; index++ {
			marker := filepath.Join(fixture.root, fmt.Sprintf("marker-%d", index))
			if err := os.WriteFile(marker, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, changed, err := fixture.canonical.InstallPaths(map[string]string{fmt.Sprintf("tests/marker-%d", index): marker}, "test: extend compatibility history"); err != nil || !changed {
				t.Fatalf("extend history changed=%v err=%v", changed, err)
			}
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		err = validateCanonicalYUMCompatibilityContracts(fixture.cfg)
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatal(err)
		}
		allocated := after.TotalAlloc - before.TotalAlloc
		t.Logf("compatibility identity audit allocated=%d manifest=%d", allocated, manifestSize)
		return allocated
	}

	const (
		smallManifestSize = int64(8 << 20)
		largeManifestSize = int64(32 << 20)
		maximumGrowth     = uint64(8 << 20)
	)
	smallAllocated := measure(smallManifestSize)
	largeAllocated := measure(largeManifestSize)
	if largeAllocated >= uint64(largeManifestSize) {
		t.Fatalf("ordinary compatibility audit allocated a whole large manifest: allocated=%d manifest=%d", largeAllocated, largeManifestSize)
	}
	if largeAllocated > smallAllocated+maximumGrowth {
		t.Fatalf("ordinary compatibility audit allocation scales with manifest bytes: small=%d large=%d growth=%d limit=%d", smallAllocated, largeAllocated, largeAllocated-smallAllocated, maximumGrowth)
	}
}

func TestYUMCompatibilityManifestRemainsCASRootBeyondBoundedHEADHistory(t *testing.T) {
	payload := []byte("x")
	digestBytes := sha256.Sum256(payload)
	manifestPath := filepath.Join(t.TempDir(), "compatibility.tsv")
	body := []byte("yum/infra/x86_64/pkg.rpm\t1\t" + hex.EncodeToString(digestBytes[:]) + "\n")
	if err := os.WriteFile(manifestPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture := newYUMCompatibilityContractFixture(t, manifestPath)
	pool, err := repository.NewStore(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	object, err := pool.Put(t.Context(), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 4; index++ {
		marker := filepath.Join(fixture.root, fmt.Sprintf("gc-marker-%d", index))
		if err := os.WriteFile(marker, []byte("m"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, changed, err := fixture.canonical.InstallPaths(map[string]string{fmt.Sprintf("tests/gc-marker-%d", index): marker}, "test: advance compatibility beyond bounded history"); err != nil || !changed {
			t.Fatalf("advance compatibility history changed=%v err=%v", changed, err)
		}
	}
	roots, _, err := collectCanonicalRoots(t.Context(), fixture.canonical, pool, 1)
	if err != nil {
		t.Fatal(err)
	}
	if roots.Count(object.SHA256) == 0 {
		t.Fatal("current compatibility witness manifest was omitted from CAS roots")
	}
	orphan, err := pool.Put(t.Context(), strings.NewReader("orphan"))
	if err != nil {
		t.Fatal(err)
	}
	dry, err := pool.GC(t.Context(), roots, repository.GCOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Report.Stats.MissingObjects != 0 || dry.Report.Stats.OrphanObjects != 1 || len(dry.Report.Orphans) != 1 || dry.Report.Orphans[0].SHA256 != orphan.SHA256 {
		t.Fatalf("compatibility CAS partition=%+v", dry.Report)
	}
	if _, err := pool.GC(t.Context(), roots, repository.GCOptions{Apply: true, ConfirmOrphanSetSHA256: dry.Report.OrphanSetSHA256}); err != nil {
		t.Fatal(err)
	}
	if file, err := pool.Open(object.SHA256); err != nil {
		t.Fatalf("GC deleted pinned compatibility object: %v", err)
	} else if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if file, err := pool.Open(orphan.SHA256); !errors.Is(err, os.ErrNotExist) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("GC retained unreferenced control object: %v", err)
	}
}

func TestYUMCompatibilityPrefreezeMakesParallelWorkersReadOnly(t *testing.T) {
	cfg, canonical, pool, projections, privateKey := newYUMCompatibilityPrefreezeFixture(t)
	txDir, err := newTransactionDir(cfg.StatePath(), "test-compat-prefreeze-")
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{workers: 2, chunk: 4096, allowYUMCompatibilityFreeze: true}
	if err := prefreezeYUMCompatibilityProjections(t.Context(), cfg, canonical, pool, []config.YUMCompatibilityProjection{projections[1], projections[0]}, txDir, values, privateKey, nil); err != nil {
		t.Fatal(err)
	}
	frozenHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	errorsByWorker := make([]error, len(projections))
	for index, projection := range projections {
		index, projection := index, projection
		group.Add(1)
		go func() {
			defer group.Done()
			admission, err := admitYUMCompatibilityProjection(cfg, canonical, projection)
			if err != nil {
				errorsByWorker[index] = err
				return
			}
			stage := filepath.Join(txDir, fmt.Sprintf("worker-%d", index))
			if err := os.Mkdir(stage, 0o700); err != nil {
				errorsByWorker[index] = err
				return
			}
			_, aliases, _, witness, packages, bytesTotal, err := buildYUMCompatibilityPayload(canonical, admission, stage)
			if err == nil {
				var trust yumCompatibilityPackageTrust
				trust, err = stageYUMCompatibilityPackageTrust(cfg, canonical, admission, stage)
				if err == nil {
					err = ensureYUMCompatibilityWitness(t.Context(), cfg, canonical, admission, witness, aliases, stage, privateKey, trust, packages, bytesTotal)
				}
			}
			errorsByWorker[index] = err
		}()
	}
	group.Wait()
	for index, err := range errorsByWorker {
		if err != nil {
			t.Fatalf("read-only compatibility worker %d: %v", index, err)
		}
	}
	after, err := canonical.HeadHash()
	if err != nil || after != frozenHead {
		t.Fatalf("parallel workers mutated canonical HEAD before=%s after=%s err=%v", frozenHead, after, err)
	}
}

func TestYUMCompatibilityPrefreezeRecoversAfterOneProjectionAdmissionFailure(t *testing.T) {
	cfg, canonical, pool, projections, privateKey := newYUMCompatibilityPrefreezeFixture(t)
	values := commonFlags{workers: 2, chunk: 4096, allowYUMCompatibilityFreeze: true}
	blockedRoot := filepath.Join(cfg.Root, filepath.FromSlash(projections[1].Root))
	if err := os.MkdirAll(blockedRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blockedRoot, "unexpected.txt"), []byte("must not be deleted"), 0o600); err != nil {
		t.Fatal(err)
	}
	firstTx, err := newTransactionDir(cfg.StatePath(), "test-compat-prefreeze-fail-")
	if err != nil {
		t.Fatal(err)
	}
	if err := prefreezeYUMCompatibilityProjections(t.Context(), cfg, canonical, pool, projections, firstTx, values, privateKey, nil); err == nil {
		t.Fatal("second projection admission fault was accepted")
	}
	firstRef, _ := state.YUMCompatibilityRef(projections[0].ID)
	secondRef, _ := state.YUMCompatibilityRef(projections[1].ID)
	if _, exists, err := canonical.Ref(firstRef); err != nil || !exists {
		t.Fatalf("deterministic first witness was not recoverably committed: exists=%v err=%v", exists, err)
	}
	if _, exists, err := canonical.Ref(secondRef); err != nil || exists {
		t.Fatalf("failed second witness unexpectedly committed: exists=%v err=%v", exists, err)
	}
	if err := os.Remove(filepath.Join(blockedRoot, "unexpected.txt")); err != nil {
		t.Fatal(err)
	}
	secondTx, err := newTransactionDir(cfg.StatePath(), "test-compat-prefreeze-replay-")
	if err != nil {
		t.Fatal(err)
	}
	if err := prefreezeYUMCompatibilityProjections(t.Context(), cfg, canonical, pool, projections, secondTx, values, privateKey, nil); err != nil {
		t.Fatalf("safe replay after admission repair failed: %v", err)
	}
	if _, exists, err := canonical.Ref(secondRef); err != nil || !exists {
		t.Fatalf("replay did not complete second witness: exists=%v err=%v", exists, err)
	}
}

func newYUMCompatibilityPrefreezeFixture(t *testing.T) (*config.Config, *state.Store, *repository.Store, []config.YUMCompatibilityProjection, []byte) {
	t.Helper()
	root := t.TempDir()
	privatePath, _ := writeLegacySigningKey(t, root)
	privateKey, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	rpmInput := decodeLegacyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "compat-source.rpm"))
	packageInfo, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rpmInput})
	if err != nil {
		t.Fatal(err)
	}
	rpmFile, err := os.Open(rpmInput)
	if err != nil {
		t.Fatal(err)
	}
	object, putErr := pool.Put(t.Context(), rpmFile)
	closeErr := rpmFile.Close()
	if putErr != nil || closeErr != nil {
		t.Fatal(errors.Join(putErr, closeErr))
	}
	var objectSHA [sha256.Size]byte
	copy(objectSHA[:], object.SHA256[:])
	writeManifest := func(filename string, entries []manifest.Entry) {
		file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if err := manifest.WriteEntry(file, entry); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	viewFiles := make(map[string]string)
	var carrierEntries []manifest.Entry
	for _, arch := range []string{"aarch64", "x86_64"} {
		name := filepath.Join(root, arch+".tsv")
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		canonicalPath, _ := state.ViewPath("latest", "infra-el9", "el9", arch)
		viewFiles[canonicalPath] = name
		carrierEntries = append(carrierEntries, manifest.Entry{Path: path.Join("yum/infra", arch, packageInfo.Location), Size: object.Size, SHA256: objectSHA})
	}
	carrierManifest := filepath.Join(root, "infra-carrier.tsv")
	writeManifest(carrierManifest, carrierEntries)
	viewFiles[filepath.ToSlash(filepath.Join("manifests", "infra-carrier.tsv"))] = carrierManifest
	initial, err := decodeRootedYUMCompatibilityPrefreezeConfig(root, "")
	if err != nil {
		t.Fatal(err)
	}
	initialBody, err := initial.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "initial-config.yaml")
	if err := os.WriteFile(marker, initialBody, 0o600); err != nil {
		t.Fatal(err)
	}
	viewFiles["config/sow.yaml"] = marker
	s0, changed, err := canonical.InstallPaths(viewFiles, "test: immutable two-arch S0 carrier")
	if err != nil || !changed {
		t.Fatalf("install S0 carrier changed=%v err=%v", changed, err)
	}
	carrierRef, _ := state.RepoRef("infra-carrier")
	if err := canonical.AdvanceRef(carrierRef, plumbing.ZeroHash, s0, true); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"aarch64", "x86_64"} {
		ref, _ := state.ViewRef("latest", "infra-el9", "el9", arch)
		if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, s0, false); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := decodeRootedYUMCompatibilityPrefreezeConfig(root, config.YUMCompatibilityPinAtFirstFreeze)
	if err != nil {
		t.Fatal(err)
	}
	finalBody, err := cfg.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(root, "final-config.yaml")
	if err := os.WriteFile(finalPath, finalBody, 0o600); err != nil {
		t.Fatal(err)
	}
	baselineSHA, baselineGit, baselineSize, err := fileSHA256AndGitBlob(carrierManifest)
	if err != nil {
		t.Fatal(err)
	}
	packageTrust := filepath.Join(root, "package-trust.asc")
	packageTrustSHA, packageTrustGit, packageTrustSize, err := fileSHA256AndGitBlob(packageTrust)
	if err != nil {
		t.Fatal(err)
	}
	s1Paths := map[string]string{"config/sow.yaml": finalPath}
	for _, projection := range cfg.CompatibilityProjections {
		sourceFile := filepath.Join(root, projection.ID+"-source.tsv")
		writeManifest(sourceFile, []manifest.Entry{{Path: packageInfo.Location, Size: object.Size, SHA256: objectSHA}})
		sourceSHA, sourceGit, sourceSize, err := fileSHA256AndGitBlob(sourceFile)
		if err != nil {
			t.Fatal(err)
		}
		adoption := yumCompatibilityAdoption{
			Schema: yumCompatibilityAdoptionSchema, ID: projection.ID, Root: projection.Root, Carrier: projection.Carrier,
			OwnerRepo: projection.Source.Repo, View: projection.Source.View, OS: projection.Source.OS, Arch: projection.Source.Arch,
			BaselineRef: carrierRef.String(), BaselineCommit: s0.String(), BaselineManifestSHA256: baselineSHA,
			BaselineManifestGit: baselineGit.String(), BaselineManifestSize: baselineSize,
			SourceManifestSHA256: sourceSHA, SourceManifestGit: sourceGit.String(), SourceManifestSize: sourceSize,
			PackageTrustSHA256: packageTrustSHA, PackageTrustGit: packageTrustGit.String(), PackageTrustSize: packageTrustSize,
			Packages: 1, Bytes: object.Size, LegacyMetadataPolicy: yumCompatibilityMetadataPolicy,
			LegacyRepomdSignature: "not-claimed", CandidateMetadataPolicy: "clean-signed-three-xml-gzip",
		}
		adoptionBody, err := json.Marshal(adoption)
		if err != nil {
			t.Fatal(err)
		}
		adoptionFile := filepath.Join(root, projection.ID+"-adoption.json")
		if err := os.WriteFile(adoptionFile, append(adoptionBody, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		sourcePath, _ := state.YUMCompatibilitySourcePath(projection.ID)
		adoptionPath, _ := state.YUMCompatibilityAdoptionPath(projection.ID)
		trustPath, _ := state.YUMCompatibilityPackageTrustPath(projection.ID)
		s1Paths[sourcePath], s1Paths[adoptionPath], s1Paths[trustPath] = sourceFile, adoptionFile, packageTrust
	}
	s1, changed, err := canonical.InstallPaths(s1Paths, "test: immutable two-arch S1 adoption")
	if err != nil || !changed {
		t.Fatalf("install S1 adoption changed=%v err=%v", changed, err)
	}
	for _, projection := range cfg.CompatibilityProjections {
		sourceRef, _ := state.YUMCompatibilitySourceRef(projection.ID)
		if err := canonical.AdvanceRef(sourceRef, plumbing.ZeroHash, s1, true); err != nil {
			t.Fatal(err)
		}
	}
	return cfg, canonical, pool, cfg.CompatibilityProjections, privateKey
}

func decodeRootedYUMCompatibilityPrefreezeConfig(root, commit string) (*config.Config, error) {
	compatibility := ""
	if commit != "" {
		compatibility = `compatibility_projections:
  - {id: a-legacy-aarch64, root: yum/infra/aarch64, mode: frozen-cross-el, carrier: infra-carrier, source: {repo: infra-el9, view: latest, os: cross-el, arch: aarch64, commit: ` + commit + `}}
  - {id: b-legacy-x86-64, root: yum/infra/x86_64, mode: frozen-cross-el, carrier: infra-carrier, source: {repo: infra-el9, view: latest, os: cross-el, arch: x86_64, commit: ` + commit + `}}
`
	}
	body := `schema: sow/v1
state: {}
gpg: {public_key: legacy-public.key}
pools: {public: {}, gated: {}}
repos:
  - id: infra-el9
    type: yum
    path: yum/infra/el9/{arch}
    default_pool: public
    arches: [aarch64, x86_64]
    os: {family: el, major: 9, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
  - id: infra-carrier
    type: yum
    path: yum/infra/{arch}
    active: false
    default_pool: public
    arches: [aarch64, x86_64]
    os: {family: cross-el, major: 0, lifecycle: frozen}
    yum: {compression: gzip, compatibility_carrier: true}
` + compatibility + `upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`
	cfg, err := config.Decode(strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	cfg.Root = root
	cfg.Path = filepath.Join(root, "sow.yaml")
	return cfg, nil
}
