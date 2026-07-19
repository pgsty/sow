package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

// auditYUMCompatibilityStage validates the state that is legal at the exact
// S0/S1/S2/S3 boundary. In particular, it never requires S3 materialized
// metadata before cutover and never mistakes an intentional rollback for a
// missing active tree. Every adopted stage still replays the raw S0 baseline,
// S1 CAS/RPM trust, and (once frozen) the complete S2 candidate CAS closure.
func auditYUMCompatibilityStage(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, projection config.YUMCompatibilityProjection, txDir string, values commonFlags) (yumCompatibilityStage, error) {
	return auditYUMCompatibilityStageWithBinding(ctx, cfg, canonical, pool, projection, txDir, values, nil)
}

type yumCompatibilityReadBinding struct {
	repositoryRoot *os.Root
	rootIdentity   os.FileInfo
}

func auditYUMCompatibilityStageWithBinding(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, projection config.YUMCompatibilityProjection, txDir string, values commonFlags, binding *yumCompatibilityReadBinding) (yumCompatibilityStage, error) {
	if ctx == nil || cfg == nil || canonical == nil || pool == nil || txDir == "" {
		return "", errors.New("incomplete YUM compatibility stage audit dependencies")
	}
	carrier, carrierExists := cfg.RepoByName(projection.Carrier)
	owner, ownerExists := cfg.RepoByName(projection.Source.Repo)
	if !carrierExists || !ownerExists {
		return "", fmt.Errorf("YUM compatibility projection %s carrier or owner is unavailable", projection.ID)
	}
	workflow := yumCompatibilityWorkflow{cfg: cfg, projection: projection, carrier: carrier, owner: owner}
	if binding != nil {
		if binding.repositoryRoot == nil || binding.rootIdentity == nil {
			return "", errors.New("bound YUM compatibility read root is unavailable")
		}
		workflow.readRoot = binding.repositoryRoot
	}
	sourceRef, _ := state.YUMCompatibilitySourceRef(projection.ID)
	freezeRef, _ := state.YUMCompatibilityRef(projection.ID)
	sourceCommit, sourceExists, err := canonical.Ref(sourceRef)
	if err != nil {
		return "", err
	}
	_, freezeExists, err := canonical.Ref(freezeRef)
	if err != nil {
		return "", err
	}
	if err := requireNoYUMCompatibilityCutoverJournalWithBinding(cfg, projection.ID, binding); err != nil {
		return "", err
	}
	servingLink := filepath.Join(cfg.Root, filepath.FromSlash(path.Join(".sow", "serving", "compatibility", "yum", projection.ID, "current")))
	lstatServing := func() (os.FileInfo, error) {
		if binding == nil {
			return os.Lstat(servingLink)
		}
		relative, err := physicalPathBelowYUMCompatibilityRoot(cfg.Root, servingLink)
		if err != nil {
			return nil, err
		}
		return binding.repositoryRoot.Lstat(relative)
	}

	if !sourceExists {
		if freezeExists {
			return "", errors.New("S2 freeze ref exists without the immutable S1 source ref")
		}
		if _, err := lstatServing(); err == nil {
			return "", errors.New("S0 projection unexpectedly has a controlled serving link")
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		_, _, _, _, _, err := requireYUMCompatibilityCarrierBaselineWithRoot(ctx, cfg, canonical, carrier, filepath.Join(txDir, "yum-compat-stage-s0-"+projection.ID+".tsv"), values, workflow.readRoot)
		return yumCompatibilityStageS0, err
	}

	adoptionStage := filepath.Join(txDir, "yum-compat-stage-s1-"+projection.ID)
	if err := os.Mkdir(adoptionStage, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	adoption, err := validateYUMCompatibilityAdoptedStateWithPool(ctx, workflow, canonical, pool, adoptionStage, values)
	if err != nil {
		return "", fmt.Errorf("replay immutable S0/S1 closure: %w", err)
	}
	if !freezeExists {
		if _, err := lstatServing(); err == nil {
			return "", errors.New("S1 projection unexpectedly has a controlled serving link")
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		return yumCompatibilityStageS1, nil
	}

	frozen, err := loadYUMCompatibilityFrozenStateAt(canonical, plumbing.ZeroHash, projection.ID)
	if err != nil {
		return "", fmt.Errorf("validate immutable S2 freeze: %w", err)
	}
	if frozen.Receipt.SourceCommit != sourceCommit.String() || frozen.Receipt.Packages != adoption.Packages || frozen.Receipt.Bytes != adoption.Bytes {
		return "", errors.New("S2 candidate no longer binds the current immutable S1 adoption")
	}
	if err := auditYUMCompatibilityCandidateCAS(ctx, canonical, pool, frozen, projection.ID); err != nil {
		return "", fmt.Errorf("validate immutable S2 candidate CAS: %w", err)
	}
	cutover, err := loadYUMCompatibilityCutoverStateAt(canonical, plumbing.ZeroHash, projection.ID)
	if err != nil {
		return "", fmt.Errorf("validate S3 cutover ledger: %w", err)
	}
	if cutover.Stage == yumCompatibilityStageS2 {
		if _, err := lstatServing(); err == nil {
			return "", errors.New("S2 pre-cutover projection unexpectedly has a controlled serving link")
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		return yumCompatibilityStageS2, nil
	}
	if len(cutover.Events) == 0 {
		return "", errors.New("S3 stage has no append-only cutover event")
	}
	journal, err := physicalYUMCompatibilityCutoverJournal(cfg, cutover.Last)
	if err != nil {
		return "", err
	}
	if err := auditYUMCompatibilityServingLinkWithBinding(cfg, journal, binding); err != nil {
		return "", err
	}
	if err := auditYUMCompatibilityCandidateTreeWithBinding(ctx, cfg, canonical, pool, frozen, txDir, values, binding); err != nil {
		return "", err
	}
	return cutover.Stage, nil
}

func requireNoYUMCompatibilityCutoverJournal(cfg *config.Config, id string) error {
	return requireNoYUMCompatibilityCutoverJournalWithBinding(cfg, id, nil)
}

func requireNoYUMCompatibilityCutoverJournalWithBinding(cfg *config.Config, id string, binding *yumCompatibilityReadBinding) error {
	name := yumCompatibilityCutoverJournalPath(cfg, id)
	for _, candidate := range []string{name, name + ".next"} {
		var err error
		if binding == nil {
			_, err = os.Lstat(candidate)
		} else {
			relative, relativeErr := physicalPathBelowYUMCompatibilityRoot(cfg.Root, candidate)
			if relativeErr != nil {
				return relativeErr
			}
			_, err = binding.repositoryRoot.Lstat(relative)
		}
		if err == nil {
			return fmt.Errorf("incomplete YUM compatibility cutover journal %s requires explicit recovery", candidate)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func auditYUMCompatibilityCandidateCAS(ctx context.Context, canonical *state.Store, pool *repository.Store, frozen yumCompatibilityFrozenState, id string) error {
	candidatePath, _ := state.YUMCompatibilityCandidateManifestPath(id)
	reader, err := canonical.OpenPathAt(frozen.Commit, candidatePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	stream := manifest.NewReader(reader)
	for {
		entry, nextErr := stream.Next()
		if errors.Is(nextErr, io.EOF) {
			return nil
		}
		if nextErr != nil {
			return nextErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		digest, err := repository.ParseDigest(entry.HashString())
		if err != nil {
			return err
		}
		object := repository.Object{SHA256: digest, Size: entry.Size}
		if err := pool.Verify(ctx, object); err != nil {
			return errors.Join(err, fmt.Errorf("candidate CAS object %s is missing or differs", entry.HashString()))
		}
	}
}

func auditYUMCompatibilityServingLink(cfg *config.Config, journal yumCompatibilityCutoverJournal) error {
	return auditYUMCompatibilityServingLinkWithHook(cfg, journal, nil)
}

func auditYUMCompatibilityServingLinkWithBinding(cfg *config.Config, journal yumCompatibilityCutoverJournal, binding *yumCompatibilityReadBinding) error {
	if binding == nil {
		return auditYUMCompatibilityServingLink(cfg, journal)
	}
	return auditYUMCompatibilityServingLinkAtRoot(cfg, journal, binding.repositoryRoot, binding.rootIdentity, nil)
}

// auditYUMCompatibilityServingLinkWithHook performs a stable, root-bound
// read-side audit. The hook exists only for deterministic replacement-race
// tests and runs after the link was first read from its already-open parent.
func auditYUMCompatibilityServingLinkWithHook(cfg *config.Config, journal yumCompatibilityCutoverJournal, afterFirstRead func() error) error {
	if cfg == nil || cfg.Root == "" {
		return errors.New("configuration root is unavailable")
	}
	repositoryRoot, rootIdentity, err := openBoundYUMCompatibilityRepositoryRoot(cfg.Root)
	if err != nil {
		return err
	}
	defer repositoryRoot.Close()
	return auditYUMCompatibilityServingLinkAtRoot(cfg, journal, repositoryRoot, rootIdentity, afterFirstRead)
}

func auditYUMCompatibilityServingLinkAtRoot(cfg *config.Config, journal yumCompatibilityCutoverJournal, repositoryRoot *os.Root, rootIdentity os.FileInfo, afterFirstRead func() error) error {
	if repositoryRoot == nil || rootIdentity == nil {
		return errors.New("retained compatibility repository root is unavailable")
	}
	servingRelative, err := physicalPathBelowYUMCompatibilityRoot(cfg.Root, journal.ServingLink)
	if err != nil {
		return err
	}
	toRelative, err := physicalPathBelowYUMCompatibilityRoot(cfg.Root, journal.ToTarget)
	if err != nil {
		return err
	}
	targetRoot, targetIdentity, err := openRealYUMCompatibilityDirectory(repositoryRoot, toRelative, false)
	if err != nil {
		return fmt.Errorf("open real compatibility target %s: %w", journal.ToTarget, err)
	}
	_ = targetRoot.Close()
	parentRelative := filepath.Dir(servingRelative)
	parentRoot, parentIdentity, err := openRealYUMCompatibilityDirectory(repositoryRoot, parentRelative, false)
	if err != nil {
		return err
	}
	defer parentRoot.Close()
	base := filepath.Base(servingRelative)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return errors.New("controlled compatibility serving link basename is unsafe")
	}
	firstInfo, err := parentRoot.Lstat(base)
	if err != nil || firstInfo.Mode()&os.ModeSymlink == 0 {
		return errors.Join(err, errors.New("controlled YUM compatibility serving link is absent or not a symlink"))
	}
	firstValue, err := parentRoot.Readlink(base)
	if err != nil {
		return err
	}
	if filepath.IsAbs(firstValue) {
		return errors.New("controlled YUM compatibility serving link has an absolute target")
	}
	resolved := filepath.Clean(filepath.Join(parentRelative, firstValue))
	if resolved != toRelative {
		return fmt.Errorf("controlled YUM compatibility serving link targets %s, want %s", resolved, toRelative)
	}
	if afterFirstRead != nil {
		if err := afterFirstRead(); err != nil {
			return err
		}
	}
	if err := verifyBoundYUMCompatibilityDirectory(repositoryRoot, parentRelative, parentIdentity); err != nil {
		return err
	}
	if err := verifyBoundYUMCompatibilityDirectory(repositoryRoot, toRelative, targetIdentity); err != nil {
		return err
	}
	lastInfo, err := parentRoot.Lstat(base)
	if err != nil || lastInfo.Mode()&os.ModeSymlink == 0 || !os.SameFile(firstInfo, lastInfo) {
		return errors.Join(err, errors.New("controlled YUM compatibility serving link was replaced during admission"))
	}
	lastValue, err := parentRoot.Readlink(base)
	if err != nil || lastValue != firstValue {
		return errors.Join(err, errors.New("controlled YUM compatibility serving link changed during admission"))
	}
	rootAtPath, err := os.Lstat(cfg.Root)
	if err != nil || rootAtPath.Mode()&os.ModeSymlink != 0 || !rootAtPath.IsDir() || !os.SameFile(rootIdentity, rootAtPath) {
		return errors.Join(err, errors.New("repository root was replaced during compatibility admission"))
	}
	return nil
}

func auditYUMCompatibilityCandidateTree(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, frozen yumCompatibilityFrozenState, txDir string, values commonFlags) error {
	return auditYUMCompatibilityCandidateTreeWithBinding(ctx, cfg, canonical, pool, frozen, txDir, values, nil)
}

func auditYUMCompatibilityCandidateTreeWithBinding(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, frozen yumCompatibilityFrozenState, txDir string, values commonFlags, binding *yumCompatibilityReadBinding) (resultErr error) {
	if pool == nil {
		return errors.New("controlled S3 candidate CAS is unavailable")
	}
	_, _, candidateTarget := yumCompatibilityLogicalServingPaths(frozen)
	candidatePath, _ := state.YUMCompatibilityCandidateManifestPath(frozen.Receipt.ID)
	expected := filepath.Join(txDir, "yum-compat-stage-candidate-"+frozen.Receipt.ID+".tsv")
	if err := copyCanonicalPathAt(canonical, frozen.Commit, candidatePath, expected, frozen.Receipt.CandidateManifestSize); err != nil {
		return err
	}
	actual := filepath.Join(txDir, "yum-compat-stage-candidate-actual-"+frozen.Receipt.ID+".tsv")
	options := manifest.ScanOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: txDir}
	ownedBinding := false
	if binding == nil {
		repositoryRoot, rootIdentity, err := openBoundYUMCompatibilityRepositoryRoot(cfg.Root)
		if err != nil {
			return err
		}
		binding = &yumCompatibilityReadBinding{repositoryRoot: repositoryRoot, rootIdentity: rootIdentity}
		ownedBinding = true
		defer func() { resultErr = errors.Join(resultErr, repositoryRoot.Close()) }()
	}
	if err := validateYUMCompatibilityCandidateHostability(cfg, candidateTarget, binding); err != nil {
		return fmt.Errorf("controlled S3 candidate is not directly hostable before inspection: %w", err)
	}
	candidateRoot, candidateIdentity, err := openRealYUMCompatibilityDirectory(binding.repositoryRoot, filepath.FromSlash(candidateTarget), false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, candidateRoot.Close()) }()
	if _, err := manifest.ScanRoot(ctx, candidateRoot, manifest.Scope{Path: "."}, actual, options); err != nil {
		return err
	}
	metadataRoot := filepath.Join(txDir, "yum-compat-stage-repodata-"+frozen.Receipt.ID)
	if err := snapshotBoundYUMCompatibilityRepodata(ctx, candidateRoot, metadataRoot); err != nil {
		return err
	}
	if err := requireManifestFilesEqual(expected, actual); err != nil {
		return fmt.Errorf("controlled S3 candidate differs from immutable S2 manifest: %w", err)
	}
	if err := validateYUMCompatibilityCandidateHardlinks(ctx, pool, candidateRoot, expected); err != nil {
		return fmt.Errorf("controlled S3 candidate is not the immutable CAS hardlink tree: %w", err)
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(frozen.RepositoryTrust), timeNowUTC())
	if err != nil {
		return err
	}
	generation, err := yumrepo.ValidateDirectory(ctx, metadataRoot, yumrepo.CompressionGzip, verifier)
	if err != nil || !yumGenerationMatches(generation, frozen.Receipt.RepomdSHA256, frozen.Receipt.Packages) {
		return errors.Join(err, errors.New("controlled S3 candidate metadata differs from immutable S2 receipt"))
	}
	if err := validateYUMCompatibilityCandidateHostability(cfg, candidateTarget, binding); err != nil {
		return fmt.Errorf("controlled S3 candidate is not directly hostable: %w", err)
	}
	if err := verifyBoundYUMCompatibilityDirectory(binding.repositoryRoot, filepath.FromSlash(candidateTarget), candidateIdentity); err != nil {
		return err
	}
	if ownedBinding {
		if err := verifyYUMCompatibilityRepositoryRootPath(cfg.Root, binding.rootIdentity); err != nil {
			return err
		}
	}
	return nil
}

type yumCompatibilityCandidateHardlinkHook func(relative string) error
type yumCompatibilityCandidateHardlinkHookKey struct{}

// withYUMCompatibilityCandidateHardlinkHook is a deterministic test seam at
// the boundary after both the candidate and canonical CAS descriptors are
// retained and the CAS body passed its first verification. Production callers
// never install it.
func withYUMCompatibilityCandidateHardlinkHook(ctx context.Context, hook yumCompatibilityCandidateHardlinkHook) context.Context {
	return context.WithValue(ctx, yumCompatibilityCandidateHardlinkHookKey{}, hook)
}

func validateYUMCompatibilityCandidateHardlinks(ctx context.Context, pool *repository.Store, candidateRoot *os.Root, manifestPath string) (resultErr error) {
	if ctx == nil || pool == nil || candidateRoot == nil || manifestPath == "" {
		return errors.New("candidate CAS hardlink validation dependencies are unavailable")
	}
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	stream := manifest.NewReader(file)
	for {
		entry, err := stream.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		name := filepath.FromSlash(entry.Path)
		before, err := candidateRoot.Lstat(name)
		if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
			return errors.Join(err, fmt.Errorf("candidate path %s is not a regular CAS hardlink", entry.Path))
		}
		target, err := candidateRoot.Open(name)
		if err != nil {
			return err
		}
		targetInfo, targetStatErr := target.Stat()
		afterOpen, lstatErr := candidateRoot.Lstat(name)
		if targetStatErr != nil || lstatErr != nil || !targetInfo.Mode().IsRegular() ||
			!os.SameFile(before, targetInfo) || !os.SameFile(before, afterOpen) {
			return errors.Join(targetStatErr, lstatErr, target.Close(), fmt.Errorf("candidate path %s changed while opening", entry.Path))
		}
		digest, err := repository.ParseDigest(entry.HashString())
		if err != nil {
			_ = target.Close()
			return err
		}
		identity := repository.Object{SHA256: digest, Size: entry.Size}
		object, err := pool.OpenVerified(ctx, identity)
		if err != nil {
			_ = target.Close()
			return fmt.Errorf("open canonical candidate CAS object for %s: %w", entry.Path, err)
		}
		objectInfo, objectStatErr := object.Stat()
		if objectStatErr != nil || targetInfo.Size() != entry.Size || objectInfo.Size() != entry.Size || !os.SameFile(targetInfo, objectInfo) {
			return errors.Join(objectStatErr, target.Close(), object.Close(), fmt.Errorf("candidate path %s is a byte-identical copy, not the canonical CAS hardlink", entry.Path))
		}
		if hook, ok := ctx.Value(yumCompatibilityCandidateHardlinkHookKey{}).(yumCompatibilityCandidateHardlinkHook); ok && hook != nil {
			if err := hook(entry.Path); err != nil {
				return errors.Join(err, target.Close(), object.Close())
			}
		}

		// First close the identity window, then perform the final descriptor
		// rehash. An in-place same-size rewrite changes both hardlinks and is
		// therefore caught by the retained CAS descriptor rather than inferred
		// from inode/size alone.
		lastTarget, targetErr := target.Stat()
		lastObject, objectErr := object.Stat()
		coordinate, coordinateErr := candidateRoot.Lstat(name)
		if targetErr != nil || objectErr != nil || coordinateErr != nil || coordinate.Mode()&os.ModeSymlink != 0 || !coordinate.Mode().IsRegular() ||
			!os.SameFile(targetInfo, lastTarget) || !os.SameFile(objectInfo, lastObject) || !os.SameFile(targetInfo, coordinate) || !os.SameFile(lastTarget, lastObject) {
			return errors.Join(targetErr, objectErr, coordinateErr, target.Close(), object.Close(), fmt.Errorf("candidate path %s changed before final CAS verification", entry.Path))
		}
		reverifyErr := repository.VerifyOpenedObject(ctx, object, identity)
		finalTarget, finalTargetErr := target.Stat()
		finalObject, finalObjectErr := object.Stat()
		finalCoordinate, finalCoordinateErr := candidateRoot.Lstat(name)
		closeErr := errors.Join(target.Close(), object.Close())
		if reverifyErr != nil || finalTargetErr != nil || finalObjectErr != nil || finalCoordinateErr != nil || closeErr != nil ||
			finalCoordinate.Mode()&os.ModeSymlink != 0 || !finalCoordinate.Mode().IsRegular() ||
			finalTarget.Size() != entry.Size || finalObject.Size() != entry.Size ||
			!os.SameFile(targetInfo, finalTarget) || !os.SameFile(objectInfo, finalObject) ||
			!os.SameFile(targetInfo, finalCoordinate) || !os.SameFile(finalTarget, finalObject) {
			return errors.Join(reverifyErr, finalTargetErr, finalObjectErr, finalCoordinateErr, closeErr, fmt.Errorf("candidate path %s is not the stable canonical CAS hardlink", entry.Path))
		}
	}
}

func validateYUMCompatibilityCandidateHostability(cfg *config.Config, candidateTarget string, binding *yumCompatibilityReadBinding) error {
	if cfg == nil || cfg.Root == "" {
		return errors.New("YUM compatibility candidate hostability configuration is unavailable")
	}
	if binding == nil {
		return serving.ValidateHostableTree(cfg.Root, candidateTarget)
	}
	if binding.repositoryRoot == nil {
		return errors.New("bound YUM compatibility candidate root is unavailable")
	}
	return serving.ValidateHostableTreeRoot(binding.repositoryRoot, candidateTarget)
}

func snapshotBoundYUMCompatibilityRepodata(ctx context.Context, candidateRoot *os.Root, destination string) error {
	if ctx == nil || candidateRoot == nil || destination == "" {
		return errors.New("bound repodata snapshot dependencies are unavailable")
	}
	repodata, identity, err := openRealYUMCompatibilityDirectory(candidateRoot, "repodata", false)
	if err != nil {
		return err
	}
	defer repodata.Close()
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	entries, err := fs.ReadDir(repodata.FS(), ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		before, err := repodata.Lstat(name)
		if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
			return errors.Join(err, fmt.Errorf("bound repodata entry %q is not a regular non-symlink file", name))
		}
		source, err := repodata.Open(name)
		if err != nil {
			return err
		}
		opened, statErr := source.Stat()
		afterOpen, lstatErr := repodata.Lstat(name)
		if statErr != nil || lstatErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, afterOpen) {
			_ = source.Close()
			return errors.Join(statErr, lstatErr, fmt.Errorf("bound repodata entry %q changed while opening", name))
		}
		_, _, captureErr := captureStableOpenedRegular(ctx, source, filepath.Join(destination, name))
		closeErr := source.Close()
		afterCopy, coordinateErr := repodata.Lstat(name)
		if captureErr != nil || closeErr != nil || coordinateErr != nil || !os.SameFile(before, afterCopy) {
			return errors.Join(captureErr, closeErr, coordinateErr, fmt.Errorf("bound repodata entry %q changed while copying", name))
		}
	}
	return verifyBoundYUMCompatibilityDirectory(candidateRoot, "repodata", identity)
}
