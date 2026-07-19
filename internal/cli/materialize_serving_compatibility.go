package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

type localYUMCompatibilityServingResult struct {
	Generations int
	Created     int
	Pointers    int
	TrustFiles  int
}

type frozenYUMCompatibilityServingEvidence struct {
	projection        config.YUMCompatibilityProjection
	freezeCommit      plumbing.Hash
	receipt           yumCompatibilityCandidate
	candidatePath     string
	packageTrust      []byte
	repositoryTrust   []byte
	packageTrustBlob  state.BlobIdentity
	candidateManifest state.BlobIdentity
}

// activateLocalYUMCompatibilityServing installs one immutable local generation
// from the exact S2 candidate. It never regenerates metadata and never signs
// with the current private key. The raw legacy tree is managed separately by
// materialization/cutover; this function owns only the generation, exact trust
// objects, canonical serving ledger and atomic mirrorlist pointer.
func activateLocalYUMCompatibilityServing(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	targetRoot, baseURL, txDir string,
	prepared preparedPublication,
	values commonFlags,
	stdout io.Writer,
) (result localYUMCompatibilityServingResult, resultErr error) {
	if cfg == nil || canonical == nil || pool == nil {
		return result, errors.New("local YUM compatibility serving dependencies are unavailable")
	}
	if prepared.view != "latest" || prepared.snapshotID != "" {
		return result, nil
	}
	projections, err := selectedPreparedYUMCompatibilityProjections(cfg, prepared)
	if err != nil || len(projections) == 0 {
		return result, err
	}
	targetRoot, err = filepath.Abs(targetRoot)
	if err != nil {
		return result, err
	}
	targetIdentity, err := localServingTargetIdentity(cfg, "latest", targetRoot, baseURL)
	if err != nil {
		return result, err
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return result, err
	}
	installOptions := serving.InstallOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}
	targetRelative, err := localServingTargetRelative(cfg, targetRoot)
	if err != nil {
		return result, err
	}

	for index, projection := range projections {
		evidence, err := loadFrozenYUMCompatibilityServingEvidence(cfg, canonical, projection)
		if err != nil {
			return result, err
		}
		unitValues := values
		unitValues.materializeUnit, err = materializationUnitFor(values, "yum-compat", "latest", projection.Source.Repo, projection.Source.OS, projection.Source.Arch, targetRoot)
		if err != nil {
			return result, err
		}
		trustCreated, err := installFrozenYUMCompatibilityTrust(ctx, cfg, canonical, pool, targetRoot, evidence, txDir, values.workers)
		if err != nil {
			return result, fmt.Errorf("install frozen compatibility trust %s: %w", projection.ID, err)
		}
		result.TrustFiles += trustCreated

		identity := serving.Identity{
			View: "latest", Repo: projection.ID, OS: "cross-el", Arch: projection.Source.Arch,
			LegacyRoot: projection.Root, RefCommit: evidence.freezeCommit.String(),
			ConfigSHA256: configSHA, RepositoryKeySHA256: evidence.receipt.RepositoryKeySHA256,
		}
		coordinate := serving.Generation{View: identity.View, Repo: identity.Repo, OS: identity.OS, Arch: identity.Arch}
		current, err := readLocalServingChannel(canonical, coordinate, targetIdentity)
		if err != nil {
			return result, err
		}
		parent := current
		if parent == nil {
			parent, err = findServingTargetMigrationParent(canonical, targetIdentity, coordinate)
			if err != nil {
				return result, err
			}
		}

		canonicalManifest := filepath.Join(txDir, fmt.Sprintf("local-serving-compat-canonical-%06d.tsv", index))
		generation, installed, pointerRestored, replayed, err := replayCurrentLocalYUMServing(
			ctx, canonical, pool, targetRoot, targetIdentity, current, identity,
			cfg.State.YUMGenerationRetention, canonicalManifest, installOptions,
			func(channel serving.Channel) (bool, error) { return serving.RestoreMirrorlist(targetRoot, channel) },
		)
		if err != nil {
			return result, fmt.Errorf("replay frozen compatibility serving %s: %w", projection.ID, err)
		}
		if replayed {
			if err := markMaterializationUnitComplete(unitValues, cfg); err != nil {
				return result, err
			}
			result.Generations++
			if installed.Created {
				result.Created++
			}
			if pointerRestored {
				result.Pointers++
			}
			fmt.Fprintf(stdout, "serving compatibility=%s generation=%s created=%t pointer_restored=%t trust_files=%d\n", projection.ID, generation.ID, installed.Created, pointerRestored, trustCreated)
			continue
		}

		candidate := filepath.Join(txDir, fmt.Sprintf("local-serving-compat-candidate-%06d.tsv", index))
		if err := copyCanonicalPathAt(canonical, evidence.freezeCommit, evidence.candidatePath, candidate, evidence.receipt.CandidateManifestSize); err != nil {
			return result, err
		}
		rooted := filepath.Join(txDir, fmt.Sprintf("local-serving-compat-rooted-%06d.tsv", index))
		if err := buildYUMCompatibilityGenerationManifest(candidate, rooted, projection.Root); err != nil {
			return result, err
		}
		rootedFile, err := os.Open(rooted)
		if err != nil {
			return result, err
		}
		generation, deriveErr := serving.DeriveGeneration(identity, rootedFile)
		closeErr := rootedFile.Close()
		if deriveErr != nil || closeErr != nil {
			return result, errors.Join(deriveErr, closeErr)
		}
		if parent != nil {
			if _, err := ensureLocalServingChannelGenerations(ctx, canonical, pool, targetRoot, *parent, 0, filepath.Join(txDir, fmt.Sprintf("compat-parent-%06d", index)), installOptions, true); err != nil {
				return result, fmt.Errorf("restore compatibility parent retention set: %w", err)
			}
			if _, err := serving.RestoreMirrorlist(targetRoot, *parent); err != nil {
				return result, fmt.Errorf("restore compatibility parent mirrorlist: %w", err)
			}
		}
		desiredWithoutParent, err := serving.NewChannelForTarget(generation, targetIdentity, nil, cfg.State.YUMGenerationRetention)
		if err != nil {
			return result, err
		}
		if err := requireCurrentServingParent(targetRoot, parent, desiredWithoutParent.MirrorlistPath); err != nil {
			return result, err
		}
		var channel serving.Channel
		if parent != nil && parent.TargetID != targetIdentity.ID {
			channel, err = serving.NewChannelForTargetMigration(generation, targetIdentity, parent, cfg.State.YUMGenerationRetention)
		} else {
			channel, err = serving.NewChannelForTarget(generation, targetIdentity, parent, cfg.State.YUMGenerationRetention)
		}
		if err != nil {
			return result, err
		}
		journal := localServingJournal{
			Schema: localServingJournalSchema, Phase: localServingInstallIntent, TargetRoot: targetRelative,
			PackageKeyringSHA256: evidence.receipt.PackageTrustSHA256, Generation: generation, Channel: channel,
		}
		journal.ID = localServingJournalID(journal)
		if err := createLocalServingJournal(cfg.StatePath(), journal); err != nil {
			return result, err
		}
		installed, err = serving.InstallGeneration(ctx, pool, targetRoot, generation, rooted, installOptions)
		if err != nil {
			return result, fmt.Errorf("install frozen compatibility generation %s: %w", generation.ID, err)
		}
		journal.Phase = localServingGenerationReady
		if err := updateLocalServingJournal(cfg.StatePath(), journal); err != nil {
			return result, err
		}
		if _, _, err := persistLocalServingLedger(ctx, canonical, generation, channel, rooted, txDir); err != nil {
			return result, stateMutationError("commit local YUM compatibility serving ledger", err)
		}
		journal.Phase = localServingStateCommitted
		if err := updateLocalServingJournal(cfg.StatePath(), journal); err != nil {
			return result, err
		}
		pointerChanged, err := serving.ReconcileMirrorlist(targetRoot, channel)
		if err != nil {
			return result, fmt.Errorf("flip local compatibility mirrorlist: %w", err)
		}
		journal.Phase = localServingPointerFlipped
		if err := updateLocalServingJournal(cfg.StatePath(), journal); err != nil {
			return result, err
		}
		if err := serving.ValidateInstalledGeneration(ctx, pool, targetRoot, generation, rooted, installOptions); err != nil {
			return result, err
		}
		if err := validateInstalledFrozenYUMCompatibilityTrust(ctx, pool, targetRoot, evidence); err != nil {
			return result, err
		}
		if err := markMaterializationUnitComplete(unitValues, cfg); err != nil {
			return result, err
		}
		if err := removeLocalServingJournal(cfg.StatePath(), journal.ID); err != nil {
			return result, err
		}
		result.Generations++
		if installed.Created {
			result.Created++
		}
		if pointerChanged {
			result.Pointers++
		}
		fmt.Fprintf(stdout, "serving compatibility=%s generation=%s created=%t pointer=%t trust_files=%d\n", projection.ID, generation.ID, installed.Created, pointerChanged, trustCreated)
	}
	return result, nil
}

// buildYUMCompatibilityGenerationManifest deliberately drops S2's root-flat
// RPM aliases. Those aliases remain part of the raw legacy tree, but immutable
// generation URLs are isomorphic across Nginx, Cloudflare and EdgeOne and may
// address only repodata or canonical Packages/<bucket>/<basename>.rpm paths.
func buildYUMCompatibilityGenerationManifest(sourcePath, destination, prefix string) error {
	if prefix == "" || path.Clean(prefix) != prefix || strings.HasPrefix(prefix, "/") || strings.HasPrefix(prefix, "../") {
		return errors.New("compatibility generation prefix is unsafe")
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	destinationFile, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = source.Close()
		return err
	}
	committed := false
	defer func() {
		_ = source.Close()
		_ = destinationFile.Close()
		if !committed {
			_ = os.Remove(destination)
		}
	}()
	reader := manifest.NewReader(source)
	packages, metadata := 0, 0
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
		switch {
		case isCanonicalYUMCompatibilityGenerationPackage(entry.Path):
			packages++
		case isYUMCompatibilityGenerationMetadata(entry.Path):
			metadata++
		case isYUMCompatibilityFlatAlias(entry.Path):
			continue
		default:
			return fmt.Errorf("compatibility generation candidate contains unsupported path %s", entry.Path)
		}
		entry.Path = path.Join(prefix, entry.Path)
		if err := manifest.WriteEntry(destinationFile, entry); err != nil {
			return err
		}
	}
	if packages == 0 || metadata == 0 {
		return fmt.Errorf("compatibility generation requires canonical packages and metadata, got packages=%d metadata=%d", packages, metadata)
	}
	if err := errors.Join(source.Close(), destinationFile.Sync(), destinationFile.Close()); err != nil {
		return err
	}
	committed = true
	return nil
}

func isCanonicalYUMCompatibilityGenerationPackage(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 3 || parts[0] != "Packages" || len(parts[1]) != 1 || !isYUMCompatibilityBucket(parts[1][0]) {
		return false
	}
	basename := parts[2]
	if len(basename) < len("a.rpm") || !strings.HasSuffix(basename, ".rpm") || !isASCIIAlphanumeric(basename[0]) {
		return false
	}
	for index := 1; index < len(basename); index++ {
		if !isASCIIAlphanumeric(basename[index]) && !strings.ContainsRune(".-_+~^", rune(basename[index])) {
			return false
		}
	}
	return true
}

func isYUMCompatibilityGenerationMetadata(value string) bool {
	if !strings.HasPrefix(value, "repodata/") {
		return false
	}
	name := strings.TrimPrefix(value, "repodata/")
	return name != "" && name != "." && name != ".." && path.Base(name) == name
}

func isYUMCompatibilityFlatAlias(value string) bool {
	return path.Base(value) == value && isCanonicalYUMCompatibilityGenerationPackage("Packages/_/"+value)
}

func isYUMCompatibilityBucket(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func isASCIIAlphanumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func selectedPreparedYUMCompatibilityProjections(cfg *config.Config, prepared preparedPublication) ([]config.YUMCompatibilityProjection, error) {
	seen := make(map[string]struct{})
	var result []config.YUMCompatibilityProjection
	for _, item := range prepared.projections {
		if !item.isYUMCompatibility() {
			continue
		}
		if _, duplicate := seen[item.compatibilityID]; duplicate {
			return nil, fmt.Errorf("prepared compatibility projection %s is duplicated", item.compatibilityID)
		}
		projection, exists, err := config.YUMCompatibilityProjectionByID(cfg.CompatibilityProjections, item.compatibilityID)
		if err != nil || !exists {
			return nil, errors.Join(err, fmt.Errorf("prepared compatibility projection %s is unavailable", item.compatibilityID))
		}
		if projection.Root != item.remotePathRoot() || projection.Source.View != "latest" {
			return nil, fmt.Errorf("prepared compatibility projection %s changed immutable route identity", item.compatibilityID)
		}
		seen[item.compatibilityID] = struct{}{}
		result = append(result, projection)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func activeLocalYUMCompatibilityPrepared(cfg *config.Config, canonical *state.Store, prepared preparedPublication) (preparedPublication, error) {
	result := preparedPublication{view: "latest"}
	if cfg == nil || canonical == nil || prepared.view != "latest" {
		return result, nil
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return result, errors.Join(err, errors.New("canonical HEAD is unavailable for local YUM compatibility serving"))
	}
	seen := make(map[string]struct{})
	for _, physical := range prepared.projections {
		if physical.repo.Type != "yum" || physical.compatibilityID != "" {
			continue
		}
		for _, item := range prepared.yumChannelProjections(physical) {
			projection, matched, err := config.YUMCompatibilityProjectionForSource(cfg.CompatibilityProjections, item.repo.ID, "latest", item.os, item.arch)
			if err != nil {
				return result, err
			}
			if !matched {
				continue
			}
			if _, duplicate := seen[projection.ID]; duplicate {
				continue
			}
			active, err := publicationYUMCompatibilityActiveAt(canonical, head, projection.ID)
			if err != nil {
				return result, err
			}
			if !active {
				continue
			}
			seen[projection.ID] = struct{}{}
			result.projections = append(result.projections, publicationProjection{
				view: "latest", repo: item.repo, os: projection.Source.OS, arch: projection.Source.Arch,
				compatibilityID: projection.ID, sourceRoot: projection.Root,
				canonicalRoot: projection.Root, remoteRoot: projection.Root, legacyRoot: projection.Root,
			})
		}
	}
	sort.Slice(result.projections, func(i, j int) bool {
		return result.projections[i].compatibilityID < result.projections[j].compatibilityID
	})
	return result, nil
}

func localYUMCompatibilityTopologyLeaves(prepared preparedPublication) []localYUMServingLeaf {
	var result []localYUMServingLeaf
	for _, projection := range prepared.projections {
		if !projection.isYUMCompatibility() {
			continue
		}
		result = append(result, localYUMServingLeaf{
			repo: config.Repo{ID: projection.compatibilityID}, os: "cross-el", arch: projection.arch,
		})
	}
	return result
}

func loadFrozenYUMCompatibilityServingEvidence(cfg *config.Config, canonical *state.Store, projection config.YUMCompatibilityProjection) (frozenYUMCompatibilityServingEvidence, error) {
	var result frozenYUMCompatibilityServingEvidence
	if cfg == nil || canonical == nil {
		return result, errors.New("frozen compatibility serving evidence dependencies are unavailable")
	}
	freezeRef, err := state.YUMCompatibilityRef(projection.ID)
	if err != nil {
		return result, err
	}
	freezeCommit, exists, err := canonical.Ref(freezeRef)
	if err != nil || !exists || freezeCommit.IsZero() {
		return result, errors.Join(err, fmt.Errorf("compatibility freeze ref %s is missing", freezeRef))
	}
	receiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(projection.ID)
	receiptBody, exists, err := readCanonicalBytesAt(canonical, freezeCommit, receiptPath, maximumYUMCompatibilityWitnessBytes)
	if err != nil || !exists {
		return result, errors.Join(err, fmt.Errorf("compatibility %s frozen candidate receipt is missing", projection.ID))
	}
	receipt, err := decodeYUMCompatibilityCandidate(receiptBody)
	if err != nil {
		return result, err
	}
	confirmation, err := yumCompatibilityConfirmation("freeze", receipt)
	if err != nil || receipt.FreezeConfirm != confirmation || receipt.ID != projection.ID || receipt.Root != projection.Root || receipt.Carrier != projection.Carrier || receipt.OwnerRepo != projection.Source.Repo {
		return result, errors.Join(err, fmt.Errorf("compatibility %s frozen candidate receipt differs from configuration", projection.ID))
	}
	candidatePath, _ := state.YUMCompatibilityCandidateManifestPath(projection.ID)
	candidateBlob, exists, err := canonical.BlobIdentityAt(freezeCommit, candidatePath)
	if err != nil || !exists || candidateBlob.Hash.String() != receipt.CandidateManifestGit || candidateBlob.Size != receipt.CandidateManifestSize {
		return result, errors.Join(err, fmt.Errorf("compatibility %s frozen candidate manifest identity changed", projection.ID))
	}
	candidateSHA, exists, err := hashCanonicalPathOptionalAt(canonical, freezeCommit, candidatePath)
	if err != nil || !exists || candidateSHA != receipt.CandidateManifestSHA256 {
		return result, errors.Join(err, fmt.Errorf("compatibility %s frozen candidate manifest digest changed", projection.ID))
	}
	packagePath, _ := state.YUMCompatibilityPackageTrustPath(projection.ID)
	packageTrust, exists, err := readCanonicalBytesAt(canonical, freezeCommit, packagePath, maxSecretBytes)
	if err != nil || !exists || digestBytesCLI(packageTrust) != receipt.PackageTrustSHA256 || int64(len(packageTrust)) != receipt.PackageTrustSize {
		return result, errors.Join(err, fmt.Errorf("compatibility %s frozen package trust bytes changed", projection.ID))
	}
	packageBlob, exists, err := canonical.BlobIdentityAt(freezeCommit, packagePath)
	if err != nil || !exists || packageBlob.Hash.String() != receipt.PackageTrustGit || packageBlob.Size != receipt.PackageTrustSize {
		return result, errors.Join(err, fmt.Errorf("compatibility %s frozen package trust Git identity changed", projection.ID))
	}
	repositoryPath, _ := state.YUMCompatibilityRepositoryTrustPath(projection.ID)
	repositoryTrust, exists, err := readCanonicalBytesAt(canonical, freezeCommit, repositoryPath, maxSecretBytes)
	if err != nil || !exists || int64(len(repositoryTrust)) != receipt.RepositoryTrustSize || digestBytesCLI(repositoryTrust) != receipt.RepositoryTrustSHA256 || repositoryTrustAnchorDigest(repositoryTrust) != receipt.RepositoryKeySHA256 {
		return result, errors.Join(err, fmt.Errorf("compatibility %s frozen repository trust differs from candidate signer", projection.ID))
	}
	repositoryBlob, exists, err := canonical.BlobIdentityAt(freezeCommit, repositoryPath)
	if err != nil || !exists || repositoryBlob.Hash.String() != receipt.RepositoryTrustGit || repositoryBlob.Size != receipt.RepositoryTrustSize {
		return result, errors.Join(err, fmt.Errorf("compatibility %s frozen repository trust Git identity changed", projection.ID))
	}
	identity := pub.CompatibilityState{
		ID: projection.ID, RouteRoot: projection.Root, FreezeCommit: freezeCommit.String(),
		RepomdSHA256: receipt.RepomdSHA256, RepositoryKeySHA256: receipt.RepositoryKeySHA256,
		PackageTrustSHA256: receipt.PackageTrustSHA256, PackageTrustGit: receipt.PackageTrustGit, PackageTrustSize: receipt.PackageTrustSize,
	}
	candidate, err := canonical.OpenPathAt(freezeCommit, candidatePath)
	if err != nil {
		return result, err
	}
	payloadPath, _ := state.YUMCompatibilityManifestPath(projection.ID)
	payload, err := canonical.OpenPathAt(freezeCommit, payloadPath)
	if err != nil {
		_ = candidate.Close()
		return result, err
	}
	_, _, validateErr := validateHistoricalCompatibilityCandidate(candidate, payload, identity)
	closeErr := errors.Join(candidate.Close(), payload.Close())
	if validateErr != nil || closeErr != nil {
		return result, errors.Join(validateErr, closeErr)
	}
	return frozenYUMCompatibilityServingEvidence{
		projection: projection, freezeCommit: freezeCommit, receipt: receipt, candidatePath: candidatePath,
		packageTrust: packageTrust, repositoryTrust: repositoryTrust, packageTrustBlob: packageBlob, candidateManifest: candidateBlob,
	}, nil
}

func installFrozenYUMCompatibilityTrust(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, targetRoot string, evidence frozenYUMCompatibilityServingEvidence, txDir string, workers int) (int, error) {
	_ = canonical
	targetRelative, err := localServingTargetRelative(cfg, targetRoot)
	if err != nil {
		return 0, err
	}
	stage, err := os.MkdirTemp(txDir, "compat-trust-")
	if err != nil {
		return 0, err
	}
	packageFile := filepath.Join(stage, "packages.pgp")
	repositoryFile := filepath.Join(stage, "repository.pgp")
	if err := writeExclusiveBytes(packageFile, evidence.packageTrust); err != nil {
		return 0, err
	}
	if err := writeExclusiveBytes(repositoryFile, evidence.repositoryTrust); err != nil {
		return 0, err
	}
	packageObject, err := pool.Import(ctx, packageFile)
	if err != nil {
		return 0, err
	}
	repositoryObject, err := pool.Import(ctx, repositoryFile)
	if err != nil {
		return 0, err
	}
	packageRoute := config.YUMCompatibilityPackageTrustRoute(evidence.projection.ID)
	repositoryRoute := config.YUMCompatibilityRepositoryTrustRoute(evidence.projection.ID)
	trustRouteRoot := path.Dir(packageRoute)
	if path.Dir(repositoryRoute) != trustRouteRoot {
		return 0, errors.New("compatibility trust routes do not share one exact directory")
	}
	entries := []manifest.Entry{
		{Path: path.Base(packageRoute), Size: packageObject.Size, SHA256: packageObject.SHA256},
		{Path: path.Base(repositoryRoute), Size: repositoryObject.Size, SHA256: repositoryObject.SHA256},
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	manifestPath := filepath.Join(stage, "trust.tsv")
	file, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		if err := manifest.WriteEntry(file, entry); err != nil {
			_ = file.Close()
			return 0, err
		}
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return 0, err
	}
	source, err := os.Open(manifestPath)
	if err != nil {
		return 0, err
	}
	allowed := map[string]struct{}{entries[0].Path: {}, entries[1].Path: {}}
	trustTargetRelative := filepath.Join(filepath.FromSlash(targetRelative), filepath.FromSlash(trustRouteRoot))
	// Use the repository-relative coordinate so macOS's /var -> /private/var
	// spelling cannot make an otherwise identical root appear to escape the
	// canonical CAS root. Scoping the target to the two-file trust directory
	// also avoids walking unrelated controlled symlinks below .sow.
	stats, materializeErr := pool.MaterializeWithOptions(ctx, source, trustTargetRelative, repository.MaterializeOptions{
		Workers: workers,
		AllowReplacePath: func(relative string) bool {
			_, ok := allowed[relative]
			return ok
		},
	})
	closeErr := source.Close()
	if materializeErr != nil || closeErr != nil {
		return 0, errors.Join(materializeErr, closeErr)
	}
	if err := validateInstalledFrozenYUMCompatibilityTrust(ctx, pool, targetRoot, evidence); err != nil {
		return 0, err
	}
	return int(stats.Linked + stats.Relinked), nil
}

func validateInstalledFrozenYUMCompatibilityTrust(ctx context.Context, pool *repository.Store, targetRoot string, evidence frozenYUMCompatibilityServingEvidence) error {
	return validateInstalledFrozenYUMCompatibilityTrustWithHook(ctx, pool, targetRoot, evidence, nil)
}

func validateInstalledFrozenYUMCompatibilityTrustAtRoot(ctx context.Context, pool *repository.Store, targetRoot *os.Root, evidence frozenYUMCompatibilityServingEvidence) error {
	if ctx == nil || pool == nil || targetRoot == nil {
		return errors.New("bound frozen compatibility trust dependencies are unavailable")
	}
	entries := []struct {
		relative string
		body     []byte
	}{
		{config.YUMCompatibilityPackageTrustRoute(evidence.projection.ID), evidence.packageTrust},
		{config.YUMCompatibilityRepositoryTrustRoute(evidence.projection.ID), evidence.repositoryTrust},
	}
	for _, entry := range entries {
		if err := serving.ValidateHostableFileRoot(targetRoot, entry.relative); err != nil {
			return fmt.Errorf("installed compatibility trust %s is not directly hostable: %w", entry.relative, err)
		}
		object := repository.Object{SHA256: repository.Digest(sha256.Sum256(entry.body)), Size: int64(len(entry.body))}
		casFile, err := pool.OpenVerified(ctx, object)
		if err != nil {
			return fmt.Errorf("open frozen compatibility trust CAS %s: %w", entry.relative, err)
		}
		casInfo, err := casFile.Stat()
		if err != nil || !casInfo.Mode().IsRegular() || casInfo.Size() != object.Size {
			_ = casFile.Close()
			return errors.Join(err, fmt.Errorf("frozen compatibility trust CAS %s has the wrong identity", entry.relative))
		}
		name := filepath.FromSlash(entry.relative)
		info, err := targetRoot.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			_ = casFile.Close()
			return fmt.Errorf("validate installed compatibility trust %s: %w", entry.relative, err)
		}
		routeFile, err := targetRoot.Open(name)
		if err != nil {
			_ = casFile.Close()
			return fmt.Errorf("open installed compatibility trust %s: %w", entry.relative, err)
		}
		opened, openStatErr := routeFile.Stat()
		afterOpen, lstatErr := targetRoot.Lstat(name)
		if openStatErr != nil || lstatErr != nil || !os.SameFile(info, opened) || !os.SameFile(info, afterOpen) || info.Size() != object.Size || !os.SameFile(opened, casInfo) {
			closeErr := errors.Join(routeFile.Close(), casFile.Close())
			return errors.Join(openStatErr, lstatErr, closeErr, fmt.Errorf("installed compatibility trust %s is not the exact CAS hardlink", entry.relative))
		}
		lastInfo, lastErr := targetRoot.Lstat(name)
		lastRoute, lastRouteErr := routeFile.Stat()
		lastCAS, lastCASErr := casFile.Stat()
		reverifyErr := repository.VerifyOpenedObject(ctx, casFile, object)
		closeErr := errors.Join(routeFile.Close(), casFile.Close())
		if lastErr != nil || lastRouteErr != nil || lastCASErr != nil || reverifyErr != nil ||
			!os.SameFile(info, lastInfo) || !os.SameFile(opened, lastRoute) || !os.SameFile(casInfo, lastCAS) || !os.SameFile(lastRoute, lastCAS) || closeErr != nil {
			return errors.Join(lastErr, lastRouteErr, lastCASErr, reverifyErr, closeErr, fmt.Errorf("installed compatibility trust %s changed or differs from the exact verified CAS hardlink", entry.relative))
		}
		if err := serving.ValidateHostableFileRoot(targetRoot, entry.relative); err != nil {
			return fmt.Errorf("installed compatibility trust %s changed hostable permissions: %w", entry.relative, err)
		}
	}
	return nil
}

// validateInstalledFrozenYUMCompatibilityTrustWithHook holds the verified CAS
// file descriptor while opening the public route. It deliberately never
// resolves ObjectPath after verification: replacing both the CAS coordinate
// and route with a same-sized malicious hardlink therefore differs from the
// already-open immutable object and fails closed. The hook is test-only.
func validateInstalledFrozenYUMCompatibilityTrustWithHook(ctx context.Context, pool *repository.Store, targetRoot string, evidence frozenYUMCompatibilityServingEvidence, afterCASOpen func(string) error) error {
	entries := []struct {
		relative string
		body     []byte
	}{
		{config.YUMCompatibilityPackageTrustRoute(evidence.projection.ID), evidence.packageTrust},
		{config.YUMCompatibilityRepositoryTrustRoute(evidence.projection.ID), evidence.repositoryTrust},
	}
	for _, entry := range entries {
		relative, body := entry.relative, entry.body
		if err := serving.ValidateHostableFile(targetRoot, relative); err != nil {
			return fmt.Errorf("installed compatibility trust %s is not directly hostable: %w", relative, err)
		}
		object := repository.Object{SHA256: repository.Digest(sha256.Sum256(body)), Size: int64(len(body))}
		casFile, err := pool.OpenVerified(ctx, object)
		if err != nil {
			return fmt.Errorf("open frozen compatibility trust CAS %s: %w", relative, err)
		}
		casInfo, err := casFile.Stat()
		if err != nil || !casInfo.Mode().IsRegular() || casInfo.Size() != object.Size {
			_ = casFile.Close()
			return errors.Join(err, fmt.Errorf("frozen compatibility trust CAS %s has the wrong identity", relative))
		}
		if afterCASOpen != nil {
			if err := afterCASOpen(relative); err != nil {
				_ = casFile.Close()
				return err
			}
		}
		physical := filepath.Join(targetRoot, filepath.FromSlash(relative))
		info, err := os.Lstat(physical)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			_ = casFile.Close()
			return fmt.Errorf("validate installed compatibility trust %s: %w", relative, err)
		}
		routeFile, err := os.Open(physical)
		if err != nil {
			_ = casFile.Close()
			return fmt.Errorf("open installed compatibility trust %s: %w", relative, err)
		}
		opened, openStatErr := routeFile.Stat()
		if openStatErr != nil || !os.SameFile(info, opened) || info.Size() != object.Size || !os.SameFile(opened, casInfo) {
			closeErr := errors.Join(routeFile.Close(), casFile.Close())
			return errors.Join(openStatErr, closeErr, fmt.Errorf("installed compatibility trust %s is not the exact CAS hardlink", relative))
		}
		lastInfo, lastErr := os.Lstat(physical)
		lastRoute, lastRouteErr := routeFile.Stat()
		lastCAS, lastCASErr := casFile.Stat()
		reverifyErr := repository.VerifyOpenedObject(ctx, casFile, object)
		closeErr := errors.Join(routeFile.Close(), casFile.Close())
		if lastErr != nil || lastRouteErr != nil || lastCASErr != nil || reverifyErr != nil ||
			!os.SameFile(info, lastInfo) || !os.SameFile(opened, lastRoute) || !os.SameFile(casInfo, lastCAS) || !os.SameFile(lastRoute, lastCAS) || closeErr != nil {
			return errors.Join(lastErr, lastRouteErr, lastCASErr, reverifyErr, closeErr, fmt.Errorf("installed compatibility trust %s changed or differs from the exact verified CAS hardlink", relative))
		}
		if err := serving.ValidateHostableFile(targetRoot, relative); err != nil {
			return fmt.Errorf("installed compatibility trust %s changed hostable permissions: %w", relative, err)
		}
	}
	return nil
}
