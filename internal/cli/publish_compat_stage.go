package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
)

type compatibilityPublicationStage struct {
	projection      publicationProjection
	trustProjection publicationProjection
	entries         int64
	bytes           int64
	linked          int64
	relinked        int64
	pruned          int64
	repomd          string
}

func publicationYUMCompatibilityActiveAt(canonical *state.Store, commit plumbing.Hash, id string) (bool, error) {
	ledgerPath, err := state.YUMCompatibilityCutoverPath(id)
	if err != nil {
		return false, err
	}
	body, exists, err := readCanonicalBytesAt(canonical, commit, ledgerPath, maximumYUMCompatibilityLedgerBytes)
	if err != nil || !exists {
		return false, err
	}
	events, err := decodeYUMCompatibilityCutoverLedger(body)
	if err != nil {
		return false, err
	}
	for _, event := range events {
		if event.ID != id {
			return false, fmt.Errorf("YUM compatibility cutover ledger %s contains event for %s", id, event.ID)
		}
	}
	return yumCompatibilityLedgerStage(events) == yumCompatibilityStageS3, nil
}

func bindRolledBackYUMCompatibility(prepared preparedPublication, parent *pub.TargetGeneration) (preparedPublication, error) {
	prepared.compatibilityRollbacks = nil
	if parent == nil || len(prepared.compatibilitySelected) == 0 {
		return prepared, nil
	}
	active := make(map[string]struct{})
	trust := make(map[string]struct{})
	for _, projection := range prepared.projections {
		switch {
		case projection.isYUMCompatibility():
			active[projection.compatibilityID] = struct{}{}
		case projection.isYUMCompatibilityTrust():
			trust[projection.compatibilityID] = struct{}{}
		}
	}
	for id := range active {
		if _, exists := trust[id]; !exists {
			return prepared, fmt.Errorf("active YUM compatibility projection %s has no frozen trust projection", id)
		}
	}
	for id := range trust {
		if _, exists := active[id]; !exists {
			return prepared, fmt.Errorf("YUM compatibility trust projection %s has no active payload projection", id)
		}
	}
	for _, identity := range parent.Compatibility {
		if _, selected := prepared.compatibilitySelected[identity.ID]; !selected {
			continue
		}
		if _, stillActive := active[identity.ID]; stillActive {
			continue
		}
		if prepared.compatibilityRollbacks == nil {
			prepared.compatibilityRollbacks = make(map[string]pub.CompatibilityState)
		}
		prepared.compatibilityRollbacks[identity.ID] = identity
	}
	return prepared, nil
}

func validateDesiredActiveYUMCompatibilityCompleteness(cfg *config.Config, canonical *state.Store, target string, generation pub.TargetGeneration, commit plumbing.Hash) error {
	if cfg == nil || canonical == nil || commit.IsZero() {
		return errors.New("active YUM compatibility completeness dependencies are unavailable")
	}
	desired := make(map[string]struct{}, len(generation.Compatibility))
	for _, identity := range generation.Compatibility {
		desired[identity.ID] = struct{}{}
	}
	for _, projection := range cfg.CompatibilityProjections {
		owner, exists := cfg.RepoByName(projection.Source.Repo)
		if !exists || !owner.PublishesToTarget(target) {
			continue
		}
		active, err := publicationYUMCompatibilityActiveAt(canonical, commit, projection.ID)
		if err != nil {
			return err
		}
		_, published := desired[projection.ID]
		if active != published {
			state := "inactive"
			if active {
				state = "active"
			}
			return fmt.Errorf("YUM compatibility projection %s is %s at S3 but desired target %s presence=%t", projection.ID, state, target, published)
		}
	}
	return nil
}

// stageFrozenYUMCompatibilityPublication materializes the canonical S2
// candidate into a deterministic, non-hosted .sow tree. Publish reads and
// uploads these exact CAS hardlinks; it must never regenerate metadata, sign
// with today's key, activate repodata, or reconcile the legacy served root.
// The deterministic path also makes an interrupted remote transaction
// replayable across processes because persisted plan source_path values do not
// depend on a temporary transaction directory.
func stageFrozenYUMCompatibilityPublication(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, projection config.YUMCompatibilityProjection, txDir string, values commonFlags) (compatibilityPublicationStage, error) {
	var result compatibilityPublicationStage
	if cfg == nil || canonical == nil || pool == nil {
		return result, errors.New("YUM compatibility publication stage dependencies are unavailable")
	}
	owner, exists := cfg.RepoByName(projection.Source.Repo)
	if !exists || owner.Type != "yum" || owner.YUM == nil {
		return result, fmt.Errorf("YUM compatibility projection %s has no YUM owner", projection.ID)
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return result, errors.Join(err, errors.New("canonical HEAD is unavailable for YUM compatibility staging"))
	}
	witnessPath, _ := state.YUMCompatibilityProjectionPath(projection.ID)
	witnessBody, witnessExists, err := readCanonicalBytesAt(canonical, head, witnessPath, maximumYUMCompatibilityWitnessBytes)
	if err != nil || !witnessExists {
		return result, errors.Join(err, fmt.Errorf("YUM compatibility witness %s is missing", projection.ID))
	}
	witness, err := decodeYUMCompatibilityWitness(witnessBody)
	if err != nil || requireYUMCompatibilityWitnessMatchesProjection(witness, projection) != nil {
		return result, errors.Join(err, fmt.Errorf("YUM compatibility witness %s differs from immutable configuration", projection.ID))
	}

	freezeRef, _ := state.YUMCompatibilityRef(projection.ID)
	freezeCommit, freezeExists, err := canonical.Ref(freezeRef)
	if err != nil || !freezeExists || freezeCommit.IsZero() {
		return result, errors.Join(err, fmt.Errorf("YUM compatibility freeze ref %s is missing", freezeRef))
	}
	if ancestor, ancestorErr := canonical.IsAncestor(freezeCommit, head); ancestorErr != nil || !ancestor {
		return result, errors.Join(ancestorErr, fmt.Errorf("YUM compatibility freeze %s is not reachable from HEAD", freezeRef))
	}

	receiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(projection.ID)
	receiptBody, receiptExists, err := readCanonicalBytesAt(canonical, head, receiptPath, maximumYUMCompatibilityWitnessBytes)
	if err != nil || !receiptExists {
		return result, errors.Join(err, fmt.Errorf("YUM compatibility candidate receipt %s is missing", projection.ID))
	}
	receipt, err := decodeYUMCompatibilityCandidate(receiptBody)
	if err != nil {
		return result, err
	}
	confirmation, err := yumCompatibilityConfirmation("freeze", receipt)
	if err != nil || receipt.FreezeConfirm != confirmation {
		return result, errors.Join(err, fmt.Errorf("YUM compatibility candidate %s confirmation is not content-bound", projection.ID))
	}
	if receipt.ID != witness.ID || receipt.Root != witness.Root || receipt.Carrier != witness.Carrier || receipt.OwnerRepo != witness.SourceRepo ||
		receipt.SourceRef != witness.SourceRef || receipt.SourceCommit != witness.SourceCommit ||
		receipt.SourceManifestSHA256 != witness.SourceManifestSHA || receipt.SourceManifestGit != witness.SourceManifestGit || receipt.SourceManifestSize != witness.SourceManifestLen ||
		receipt.AdoptionSHA256 != witness.AdoptionSHA || receipt.AdoptionGit != witness.AdoptionGit || receipt.AdoptionSize != witness.AdoptionLen ||
		receipt.PackageTrustSHA256 != witness.PackageTrustSHA || receipt.PackageTrustGit != witness.PackageTrustGit || receipt.PackageTrustSize != witness.PackageTrustLen ||
		receipt.Packages != witness.Packages || receipt.Bytes != witness.Bytes {
		return result, fmt.Errorf("YUM compatibility candidate %s differs from frozen witness", projection.ID)
	}

	candidatePath, _ := state.YUMCompatibilityCandidateManifestPath(projection.ID)
	candidateBlob, candidateExists, err := canonical.BlobIdentityAt(head, candidatePath)
	if err != nil || !candidateExists || candidateBlob.Hash.String() != receipt.CandidateManifestGit || candidateBlob.Size != receipt.CandidateManifestSize {
		return result, errors.Join(err, fmt.Errorf("YUM compatibility candidate manifest %s Git identity changed", projection.ID))
	}
	candidateSHA, candidateExists, err := hashCanonicalPathOptionalAt(canonical, head, candidatePath)
	if err != nil || !candidateExists || candidateSHA != receipt.CandidateManifestSHA256 {
		return result, errors.Join(err, fmt.Errorf("YUM compatibility candidate manifest %s digest changed", projection.ID))
	}
	receiptBlob, receiptBlobExists, err := canonical.BlobIdentityAt(head, receiptPath)
	if err != nil || !receiptBlobExists || receiptBlob.Size != int64(len(receiptBody)) {
		return result, errors.Join(err, fmt.Errorf("YUM compatibility candidate receipt %s Git identity is unavailable", projection.ID))
	}
	for frozenPath, want := range map[string]state.BlobIdentity{candidatePath: candidateBlob, receiptPath: receiptBlob} {
		frozen, frozenExists, frozenErr := canonical.BlobIdentityAt(freezeCommit, frozenPath)
		if frozenErr != nil || !frozenExists || frozen != want {
			return result, errors.Join(frozenErr, fmt.Errorf("YUM compatibility freeze %s does not preserve %s", freezeRef, frozenPath))
		}
	}

	localCandidate := filepath.Join(txDir, "publish-compat-"+projection.ID+"-candidate.tsv")
	if err := copyCanonicalPathAt(canonical, head, candidatePath, localCandidate, receipt.CandidateManifestSize); err != nil {
		return result, err
	}
	candidate, err := os.Open(localCandidate)
	if err != nil {
		return result, err
	}
	payloadPath, _ := state.YUMCompatibilityManifestPath(projection.ID)
	payload, err := canonical.OpenPathAt(head, payloadPath)
	if err != nil {
		_ = candidate.Close()
		return result, err
	}
	identity := pub.CompatibilityState{
		ID: projection.ID, RouteRoot: projection.Root, FreezeCommit: freezeCommit.String(), RepomdSHA256: receipt.RepomdSHA256,
		RepositoryKeySHA256: receipt.RepositoryKeySHA256,
		PackageTrustSHA256:  witness.PackageTrustSHA, PackageTrustGit: witness.PackageTrustGit, PackageTrustSize: witness.PackageTrustLen,
	}
	entries, bytesTotal, validateErr := validateHistoricalCompatibilityCandidate(candidate, payload, identity)
	closeErr := errors.Join(candidate.Close(), payload.Close())
	if validateErr != nil || closeErr != nil {
		return result, errors.Join(validateErr, closeErr)
	}
	trustStageRoot, err := stageFrozenYUMCompatibilityTrust(ctx, cfg, canonical, pool, projection, freezeCommit, receipt, txDir, values)
	if err != nil {
		return result, err
	}

	stageRoot := filepath.ToSlash(filepath.Join(config.StateDirectory, "materialized", "compatibility", projection.ID, receipt.CandidateManifestSHA256))
	manifestFile, err := os.Open(localCandidate)
	if err != nil {
		return result, err
	}
	materialized, materializeErr := pool.MaterializeWithOptions(ctx, manifestFile, stageRoot, repository.MaterializeOptions{
		Workers: values.workers,
		// This callback is scoped to a digest-named, non-hosted tree. Replacing a
		// tampered path with its already-verified CAS hardlink is deterministic.
		AllowReplacePath: func(string) bool { return true },
	})
	closeErr = manifestFile.Close()
	if materializeErr != nil || closeErr != nil {
		return result, errors.Join(materializeErr, closeErr)
	}
	reconciled, err := pool.ReconcileExact(ctx, localCandidate, stageRoot, values.workers, values.chunk)
	if err != nil {
		return result, err
	}
	if err := validateFrozenCompatibilityTree(ctx, cfg, canonical, identity, filepath.Join(cfg.Root, filepath.FromSlash(stageRoot)), txDir, values.workers, values.chunk); err != nil {
		return result, err
	}
	result = compatibilityPublicationStage{
		projection: publicationProjection{
			view: "latest", repo: owner, os: projection.Source.OS, arch: projection.Source.Arch,
			compatibilityID: projection.ID, sourceRoot: projection.Root, localRoot: stageRoot,
			canonicalRoot: projection.Root, remoteRoot: projection.Root, legacyRoot: projection.Root,
		},
		trustProjection: publicationProjection{
			view: "latest", repo: owner, os: "cross-el", arch: projection.Source.Arch,
			compatibilityID: projection.ID, compatibilityTrust: true,
			sourceRoot: path.Dir(config.YUMCompatibilityPackageTrustRoute(projection.ID)), localRoot: trustStageRoot,
			canonicalRoot: path.Dir(config.YUMCompatibilityPackageTrustRoute(projection.ID)),
			remoteRoot:    path.Dir(config.YUMCompatibilityPackageTrustRoute(projection.ID)),
			legacyRoot:    path.Dir(config.YUMCompatibilityPackageTrustRoute(projection.ID)),
		},
		entries: entries, bytes: bytesTotal, linked: materialized.Linked,
		relinked: materialized.Relinked, pruned: reconciled.RemovedFiles, repomd: receipt.RepomdSHA256,
	}
	return result, nil
}

// stageFrozenYUMCompatibilityTrust closes the S3 publication over both public
// trust anchors recorded by the S2 freeze. The output is a digest-named,
// non-hosted CAS-hardlink tree; the plan localizer maps it to the stable edge
// contract URLs without consulting today's mutable key files.
func stageFrozenYUMCompatibilityTrust(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	projection config.YUMCompatibilityProjection,
	freezeCommit plumbing.Hash,
	receipt yumCompatibilityCandidate,
	txDir string,
	values commonFlags,
) (string, error) {
	packagePath, _ := state.YUMCompatibilityPackageTrustPath(projection.ID)
	repositoryPath, _ := state.YUMCompatibilityRepositoryTrustPath(projection.ID)
	type frozenTrust struct {
		canonicalPath string
		filename      string
		sha256        string
		git           string
		size          int64
	}
	items := []frozenTrust{
		{canonicalPath: packagePath, filename: "packages.pgp", sha256: receipt.PackageTrustSHA256, git: receipt.PackageTrustGit, size: receipt.PackageTrustSize},
		{canonicalPath: repositoryPath, filename: "repository.pgp", sha256: receipt.RepositoryTrustSHA256, git: receipt.RepositoryTrustGit, size: receipt.RepositoryTrustSize},
	}
	stage := filepath.Join(txDir, "publish-compat-"+projection.ID+"-trust")
	if err := os.Mkdir(stage, 0o700); err != nil {
		return "", err
	}
	manifestPath := filepath.Join(stage, "trust.tsv")
	manifestFile, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	manifestClosed := false
	defer func() {
		if !manifestClosed {
			_ = manifestFile.Close()
		}
	}()
	for _, item := range items {
		if item.sha256 == "" || item.git == "" || item.size < 1 {
			return "", fmt.Errorf("YUM compatibility %s frozen %s trust identity is incomplete", projection.ID, item.filename)
		}
		body, exists, err := readCanonicalBytesAt(canonical, freezeCommit, item.canonicalPath, maxSecretBytes)
		if err != nil || !exists || int64(len(body)) != item.size || digestBytesCLI(body) != item.sha256 {
			return "", errors.Join(err, fmt.Errorf("YUM compatibility %s frozen %s trust bytes changed", projection.ID, item.filename))
		}
		blob, exists, err := canonical.BlobIdentityAt(freezeCommit, item.canonicalPath)
		if err != nil || !exists || blob.Hash.String() != item.git || blob.Size != item.size {
			return "", errors.Join(err, fmt.Errorf("YUM compatibility %s frozen %s trust Git identity changed", projection.ID, item.filename))
		}
		physical := filepath.Join(stage, item.filename)
		if err := writeExclusiveBytes(physical, body); err != nil {
			return "", err
		}
		object, err := pool.Import(ctx, physical)
		if err != nil {
			return "", err
		}
		if object.HashString() != item.sha256 || object.Size != item.size {
			return "", fmt.Errorf("YUM compatibility %s frozen %s trust CAS identity changed", projection.ID, item.filename)
		}
		if err := manifest.WriteEntry(manifestFile, manifest.Entry{Path: item.filename, Size: object.Size, SHA256: object.SHA256}); err != nil {
			return "", err
		}
	}
	if err := errors.Join(manifestFile.Sync(), manifestFile.Close()); err != nil {
		return "", err
	}
	manifestClosed = true
	// Keep trust beside, never below, the exact candidate tree. The candidate
	// projection is scanned/reconciled as a closed manifest; nesting trust below
	// it would either make the package plan ingest non-candidate files or let a
	// later exact reconcile silently prune the two trust anchors.
	stageRoot := filepath.ToSlash(filepath.Join(config.StateDirectory, "materialized", "compatibility", projection.ID, "trust", receipt.CandidateManifestSHA256))
	reader, err := os.Open(manifestPath)
	if err != nil {
		return "", err
	}
	_, materializeErr := pool.MaterializeWithOptions(ctx, reader, stageRoot, repository.MaterializeOptions{
		Workers: values.workers, AllowReplacePath: func(string) bool { return true },
	})
	closeErr := reader.Close()
	if materializeErr != nil || closeErr != nil {
		return "", errors.Join(materializeErr, closeErr)
	}
	if _, err := pool.ReconcileExact(ctx, manifestPath, stageRoot, values.workers, values.chunk); err != nil {
		return "", err
	}
	return stageRoot, nil
}
