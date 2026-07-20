package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

// timeNowUTC is a narrow test seam for calendar-window decisions. Repository
// bytes never use wall-clock time: their timestamps come from canonical Git.
var timeNowUTC = func() time.Time { return time.Now().UTC() }

type materializeCanonicalSource struct {
	ID       string
	Snapshot bool
	Public   bool
	// RefCommits is used by remote restore to materialize a previously
	// published canonical ref vector without moving the current local refs.
	// A nil map preserves the normal current-ref behavior.
	RefCommits map[string]plumbing.Hash
}

type materializeMetadataResult struct {
	APTSuites        int
	YUMRepos         int
	YUMCompatibility int
	APTByHashStages  map[string]string
	APTByHashRemoved int
	// ExactManifests are frozen, target-root-relative metadata manifests
	// captured from private generation output and canonical retention ledgers.
	// They must never be assembled by scanning the live materialized target.
	ExactManifests []string
}

func (source materializeCanonicalSource) leaf(repo, osName, arch string) (plumbing.ReferenceName, string, error) {
	if source.Snapshot {
		ref, err := state.SnapshotRef(source.ID, repo, osName, arch)
		if err != nil {
			return "", "", err
		}
		path, err := state.SnapshotPath(source.ID, repo, osName, arch)
		return ref, path, err
	}
	ref, err := state.ViewRef(source.ID, repo, osName, arch)
	if err != nil {
		return "", "", err
	}
	path, err := state.ViewPath(source.ID, repo, osName, arch)
	return ref, path, err
}

func (source materializeCanonicalSource) resolveLeaf(canonical *state.Store, repo, osName, arch string) (plumbing.ReferenceName, string, plumbing.Hash, error) {
	ref, canonicalPath, err := source.leaf(repo, osName, arch)
	if err != nil {
		return "", "", plumbing.ZeroHash, err
	}
	if source.RefCommits != nil {
		commit, exists := source.RefCommits[ref.String()]
		if !exists || commit.IsZero() {
			return "", "", plumbing.ZeroHash, fmt.Errorf("historical canonical ref %s is missing", ref)
		}
		return ref, canonicalPath, commit, nil
	}
	commit, exists, err := canonical.Ref(ref)
	if err != nil || !exists {
		return "", "", plumbing.ZeroHash, errors.Join(err, fmt.Errorf("canonical ref %s is missing", ref))
	}
	return ref, canonicalPath, commit, nil
}

func defaultMaterializationTarget(refID string, snapshot bool) string {
	if snapshot {
		return filepath.ToSlash(filepath.Join(config.StateDirectory, "materialized", "snapshots", refID))
	}
	if refID == "stable" {
		return filepath.ToSlash(filepath.Join(config.StateDirectory, "origin", "gated"))
	}
	return filepath.ToSlash(filepath.Join(config.StateDirectory, "materialized", refID))
}

func loadMaterializeSigningSecrets(cfg *config.Config, leaves []viewLeaf, privateKeyFile, passphraseFile string) ([]byte, []byte, error) {
	privateKey, passphrase, _, err := loadMaterializeSigningSecretsWithIdentity(cfg, leaves, privateKeyFile, passphraseFile)
	return privateKey, passphrase, err
}

func loadMaterializeSigningSecretsWithIdentity(cfg *config.Config, leaves []viewLeaf, privateKeyFile, passphraseFile string) ([]byte, []byte, string, error) {
	required := false
	for _, leaf := range leaves {
		if leaf.repo.Type == "apt" || leaf.repo.Type == "yum" {
			required = true
			break
		}
	}
	if !required {
		return nil, nil, "", nil
	}
	privateKey, err := resolveSecret(cfg.GPG.PrivateKey, privateKeyFile, false)
	if err != nil {
		return nil, nil, "", fmt.Errorf("resolve repository signing key: %w", err)
	}
	passphrase, err := resolveSecret(cfg.GPG.Passphrase, passphraseFile, true)
	if err != nil {
		clearSecret(privateKey)
		return nil, nil, "", fmt.Errorf("resolve repository signing passphrase: %w", err)
	}
	identity, err := repositorySigningKeyIdentity(cfg, privateKey)
	if err != nil {
		clearSecret(privateKey)
		clearSecret(passphrase)
		return nil, nil, "", fmt.Errorf("repository signing trust preflight failed: %w", err)
	}
	return privateKey, passphrase, identity, nil
}

func materializeRepositoryMetadata(ctx context.Context, cfg *config.Config, canonical *state.Store, leaves []viewLeaf, source materializeCanonicalSource, targetRoot, txDir string, privateKey, passphrase []byte, values commonFlags) (finalResult materializeMetadataResult, resultErr error) {
	values, selectionOwner, err := beginMaterializationSelectionForSource(cfg, canonical, values, selectedMaterializationOperation(values, "materialize"), source, leaves, targetRoot, true, false)
	if err != nil {
		return materializeMetadataResult{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	type metadataTask struct {
		key string
		run func() (materializeMetadataResult, error)
	}
	var tasks []metadataTask
	byRepo := make(map[string][]viewLeaf)
	for _, leaf := range leaves {
		byRepo[leaf.repo.ID] = append(byRepo[leaf.repo.ID], leaf)
	}
	repoIDs := make([]string, 0, len(byRepo))
	for repoID := range byRepo {
		repoIDs = append(repoIDs, repoID)
	}
	sort.Strings(repoIDs)
	for _, repoID := range repoIDs {
		repoLeaves := byRepo[repoID]
		repo := repoLeaves[0].repo
		switch repo.Type {
		case "asset":
			continue
		case "apt":
			repo, repoLeaves := repo, append([]viewLeaf(nil), repoLeaves...)
			tasks = append(tasks, metadataTask{key: "apt/" + repo.ID, run: func() (materializeMetadataResult, error) {
				count, stages, removed, err := materializeAPTMetadata(ctx, cfg, canonical, repo, repoLeaves, source, targetRoot, txDir, privateKey, passphrase, values)
				result := materializeMetadataResult{APTSuites: count, APTByHashStages: stages, APTByHashRemoved: removed}
				if err == nil {
					result.ExactManifests = []string{filepath.Join(txDir, fmt.Sprintf("materialize-apt-%s-metadata.tsv", repo.ID))}
				}
				return result, err
			}})
		case "yum":
			sort.Slice(repoLeaves, func(i, j int) bool {
				if repoLeaves[i].arch != repoLeaves[j].arch {
					return repoLeaves[i].arch < repoLeaves[j].arch
				}
				return repoLeaves[i].os < repoLeaves[j].os
			})
			byArch := make(map[string][]viewLeaf)
			for _, leaf := range repoLeaves {
				byArch[leaf.arch] = append(byArch[leaf.arch], leaf)
			}
			arches := make([]string, 0, len(byArch))
			for arch := range byArch {
				arches = append(arches, arch)
			}
			sort.Strings(arches)
			for _, arch := range arches {
				repo, ownerLeaves := repo, append([]viewLeaf(nil), byArch[arch]...)
				tasks = append(tasks, metadataTask{key: "yum/" + repo.ID + "/" + arch, run: func() (materializeMetadataResult, error) {
					err := materializeYUMMetadataOwner(ctx, cfg, canonical, repo, ownerLeaves, source, targetRoot, txDir, privateKey, passphrase, values, nil)
					result := materializeMetadataResult{YUMRepos: 1}
					if err == nil {
						result.ExactManifests = []string{materializedYUMMetadataManifestPath(txDir, repo.ID, ownerLeaves)}
					}
					return result, err
				}})
			}
		default:
			return materializeMetadataResult{}, fmt.Errorf("unsupported repository type %q", repo.Type)
		}
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].key < tasks[j].key })
	if len(tasks) == 0 {
		return materializeMetadataResult{}, nil
	}
	workers := values.workers
	if workers < 1 {
		workers = 1
	}
	workers = min(workers, len(tasks))
	type outcome struct {
		index  int
		result materializeMetadataResult
		err    error
	}
	jobs := make(chan int)
	outcomes := make(chan outcome, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				result, err := tasks[index].run()
				outcomes <- outcome{index: index, result: result, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range tasks {
			jobs <- index
		}
	}()
	go func() {
		group.Wait()
		close(outcomes)
	}()
	ordered := make([]outcome, len(tasks))
	for item := range outcomes {
		ordered[item.index] = item
	}
	result := materializeMetadataResult{APTByHashStages: make(map[string]string)}
	for index, item := range ordered {
		if item.err != nil {
			return materializeMetadataResult{}, fmt.Errorf("%s: %w", tasks[index].key, item.err)
		}
		result.APTSuites += item.result.APTSuites
		result.YUMRepos += item.result.YUMRepos
		result.YUMCompatibility += item.result.YUMCompatibility
		result.APTByHashRemoved += item.result.APTByHashRemoved
		result.ExactManifests = append(result.ExactManifests, item.result.ExactManifests...)
		if err := mergeAPTByHashStages(result.APTByHashStages, item.result.APTByHashStages); err != nil {
			return materializeMetadataResult{}, err
		}
	}
	if len(result.APTByHashStages) != 0 {
		if _, _, err := persistAPTByHashStages(ctx, canonical, selectedMaterializationOperation(values, "materialize"), result.APTByHashStages); err != nil {
			return materializeMetadataResult{}, err
		}
	}
	return result, nil
}

func materializeAPTMetadata(ctx context.Context, cfg *config.Config, canonical *state.Store, repo config.Repo, leaves []viewLeaf, source materializeCanonicalSource, targetRoot, tempRoot string, privateKey, passphrase []byte, values commonFlags) (int, map[string]string, int, error) {
	signer, err := aptrepo.NewSigner(bytes.NewReader(privateKey), passphrase)
	if err != nil {
		return 0, nil, 0, errors.New("cannot initialize APT signing key")
	}
	stages := make(map[string]string)
	removed := 0
	bySuite := make(map[string][]string)
	for _, leaf := range leaves {
		bySuite[leaf.os] = append(bySuite[leaf.os], leaf.arch)
	}
	suites := make([]string, 0, len(bySuite))
	for suite := range bySuite {
		suites = append(suites, suite)
	}
	sort.Strings(suites)
	archiveRoot := filepath.Join(targetRoot, filepath.FromSlash(repo.Path))
	manageByHash := directMaterializationUsesCanonicalByHashTarget(cfg, source, targetRoot)
	ledgerStageDir := ""
	if manageByHash {
		ledgerStageDir, err = aptByHashStageDir(tempRoot)
		if err != nil {
			return 0, nil, 0, err
		}
	}
	builds := make([]aptrepo.BuildResult, 0, len(suites))
	for _, sourceSuite := range suites {
		components := repo.APT.ComponentsForSuite(sourceSuite)
		suiteValues := values
		suiteValues.materializeUnit, err = materializationUnitFor(values, "apt", source.ID, repo.ID, sourceSuite, "", targetRoot)
		if err != nil {
			return 0, nil, 0, err
		}
		arches := uniqueSorted(bySuite[sourceSuite])
		outputSuite := sourceSuite
		description := "Pigsty software repository"
		if source.Snapshot {
			snapshotSuite, err := views.SnapshotSuite(source.ID)
			if err != nil {
				return 0, nil, 0, err
			}
			if snapshotSuite != sourceSuite {
				return 0, nil, 0, fmt.Errorf("snapshot %s cannot materialize APT source suite %s", source.ID, sourceSuite)
			}
			outputSuite = source.ID
			description = "Pigsty software repository snapshot"
		}
		indexes, publicationTime, cleanup, err := buildAPTMaterializeIndexes(ctx, canonical, repo, source, sourceSuite, arches, archiveRoot, tempRoot, values)
		if err != nil {
			return 0, nil, 0, err
		}
		deterministic, err := newDeterministicMaterializeKey(privateKey, passphrase, publicationTime)
		if err != nil {
			_ = cleanup()
			return 0, nil, 0, err
		}
		build, generateErr := aptrepo.GenerateStreaming(ctx, archiveRoot, aptrepo.RepositoryConfig{
			Origin: "Pigsty", Label: "Pigsty", Suite: outputSuite, Codename: outputSuite,
			Description: description, Components: components,
			Architectures: arches, Date: publicationTime,
		}, indexes, signer, aptrepo.StreamingOptions{
			Workers: values.workers,
			StagedTransform: func(stageRoot string, _ aptrepo.BuildResult) error {
				if err := rewriteDeterministicAPTSignatures(ctx, stageRoot, outputSuite, deterministic); err != nil {
					return fmt.Errorf("install deterministic suite signatures %s: %w", outputSuite, err)
				}
				release, err := os.ReadFile(filepath.Join(stageRoot, "dists", outputSuite, "Release"))
				if err != nil {
					return err
				}
				inRelease, err := os.ReadFile(filepath.Join(stageRoot, "dists", outputSuite, "InRelease"))
				if err != nil {
					return err
				}
				detached, err := os.ReadFile(filepath.Join(stageRoot, "dists", outputSuite, "Release.gpg"))
				if err != nil {
					return err
				}
				return signer.Verify(release, inRelease, detached, publicationTime)
			},
			CommitGuard: func(phase aptrepo.CommitPhase) error {
				boundary := materializeTrustAPTCommitBefore
				if phase == aptrepo.CommitAfterMutation {
					boundary = materializeTrustAPTCommitAfter
				}
				return requireMaterializationRepositoryTrust(suiteValues, cfg, privateKey, boundary)
			},
		})
		cleanupErr := cleanup()
		if generateErr != nil || cleanupErr != nil {
			return 0, nil, 0, fmt.Errorf("generate suite %s: %w", outputSuite, errors.Join(generateErr, cleanupErr))
		}
		if manageByHash {
			stage, err := stageAPTByHashGeneration(ctx, canonical, archiveRoot, "views", source.ID, repo.ID, outputSuite, ledgerStageDir, cfg.State.APTByHashRetention, build.ByHashGeneration)
			if err != nil {
				return 0, nil, 0, err
			}
			if err := mergeAPTByHashStages(stages, map[string]string{stage.CanonicalPath: stage.StagedPath}); err != nil {
				return 0, nil, 0, err
			}
			removed += stage.Removed
		}
		builds = append(builds, build)
	}
	metadataManifest := filepath.Join(tempRoot, fmt.Sprintf("materialize-apt-%s-metadata.tsv", repo.ID))
	if err := writeFrozenAPTMetadataManifest(ctx, archiveRoot, repo.Path, metadataManifest, builds, stages); err != nil {
		return 0, nil, 0, err
	}
	return len(suites), stages, removed, nil
}

func directMaterializationUsesCanonicalByHashTarget(cfg *config.Config, source materializeCanonicalSource, targetRoot string) bool {
	if cfg == nil || source.Snapshot || source.RefCommits != nil {
		return false
	}
	want := defaultMaterializationTarget(source.ID, false)
	if !filepath.IsAbs(want) {
		want = filepath.Join(cfg.Root, filepath.FromSlash(want))
	}
	wantAbs, err := filepath.Abs(filepath.Clean(want))
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(filepath.Clean(targetRoot))
	return err == nil && targetAbs == wantAbs
}

func buildAPTMaterializeIndexes(ctx context.Context, canonical *state.Store, repo config.Repo, source materializeCanonicalSource, suite string, arches []string, archiveRoot, tempRoot string, values commonFlags) ([]aptrepo.StreamingIndex, time.Time, func() error, error) {
	var leaves []aptCanonicalLeaf
	var publicationTime time.Time
	for _, arch := range arches {
		_, canonicalPath, commit, err := source.resolveLeaf(canonical, repo.ID, suite, arch)
		if err != nil {
			return nil, time.Time{}, func() error { return nil }, err
		}
		commitTime, err := canonical.CommitTime(commit)
		if err != nil {
			return nil, time.Time{}, func() error { return nil }, err
		}
		if commitTime.After(publicationTime) {
			publicationTime = commitTime
		}
		leaf := viewLeaf{repo: repo, os: suite, arch: arch}
		if err := validateViewAt(canonical, commit, canonicalPath, leaf, source.Public); err != nil {
			return nil, time.Time{}, func() error { return nil }, err
		}
		leaves = append(leaves, aptCanonicalLeaf{arch: arch, commit: commit, canonicalPath: canonicalPath})
	}
	if publicationTime.IsZero() {
		return nil, time.Time{}, func() error { return nil }, errors.New("APT source has no canonical commit time")
	}
	indexes, cleanup, err := buildAPTStreamingSpools(ctx, canonical, repo, repo.APT.ComponentsForSuite(suite), leaves, archiveRoot, tempRoot, values.workers, values.chunk)
	if err != nil {
		return nil, time.Time{}, func() error { return nil }, err
	}
	return indexes, publicationTime.UTC().Truncate(time.Second), cleanup, nil
}

func materializedYUMMetadataManifestPath(txDir, repoID string, leaves []viewLeaf) string {
	arch, label := "unknown", "all"
	if len(leaves) != 0 {
		arch = leaves[0].arch
		if len(leaves) == 1 {
			label = leaves[0].os
		}
	}
	return filepath.Join(txDir, fmt.Sprintf("materialize-yum-%s-%s-%s-metadata.tsv", repoID, label, arch))
}

// materializeYUMMetadataOwner generates and flips repodata once for the
// complete repo+arch physical owner. Multiple OS coordinates may share that
// root; projecting them together prevents concurrent repodata exchanges and
// makes the raw alias exactly represent the route receipt's full ref vector.
func materializeYUMMetadataOwner(ctx context.Context, cfg *config.Config, canonical *state.Store, repo config.Repo, leaves []viewLeaf, source materializeCanonicalSource, targetRoot, txDir string, privateKey, passphrase []byte, values commonFlags, generationOut **yumrepo.Generation) (resultErr error) {
	if len(leaves) == 0 {
		return errors.New("YUM metadata physical owner has no leaves")
	}
	arch := leaves[0].arch
	for _, leaf := range leaves {
		if leaf.repo.ID != repo.ID || leaf.arch != arch {
			return errors.New("YUM metadata leaves cross a physical repo+arch owner")
		}
	}
	effectiveRoot, err := repo.PathForArch(arch)
	if err != nil {
		return err
	}
	baseLabel := "all"
	if len(leaves) == 1 {
		baseLabel = leaves[0].os
	}
	base := fmt.Sprintf("materialize-yum-%s-%s-%s", repo.ID, baseLabel, arch)
	inputs := make([]views.ProjectionInput, 0, len(leaves))
	readers := make([]io.ReadCloser, 0, len(leaves))
	unitValues := make([]commonFlags, 0, len(leaves))
	unitTargetRoot := values.materializeTarget
	if unitTargetRoot == "" {
		unitTargetRoot = targetRoot
	}
	var anchor plumbing.Hash
	var commitTime time.Time
	defer func() {
		for _, reader := range readers {
			resultErr = errors.Join(resultErr, reader.Close())
		}
	}()
	for _, leaf := range leaves {
		ref, canonicalPath, commit, err := source.resolveLeaf(canonical, repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return err
		}
		if err := validateViewAt(canonical, commit, canonicalPath, leaf, source.Public); err != nil {
			return err
		}
		when, err := canonical.CommitTime(commit)
		if err != nil {
			return err
		}
		if anchor.IsZero() || when.After(commitTime) || when.Equal(commitTime) && commit.String() > anchor.String() {
			anchor, commitTime = commit, when
		}
		reader, err := canonical.OpenPathAt(commit, canonicalPath)
		if err != nil {
			return err
		}
		readers = append(readers, reader)
		inputs = append(inputs, views.ProjectionInput{Label: ref.String(), Reader: reader})
		unit := values
		unit.materializeUnit, err = materializationUnitFor(values, "yum", source.ID, repo.ID, leaf.os, leaf.arch, unitTargetRoot)
		if err != nil {
			return err
		}
		unitValues = append(unitValues, unit)
	}
	commitTime = packageProjectionMaterializationTime(values, commitTime)
	if _, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateKey), passphrase, commitTime); err != nil {
		return errors.New("cannot initialize YUM signing key")
	}
	signer, err := newDeterministicMaterializeKey(privateKey, passphrase, commitTime)
	if err != nil {
		return errors.New("cannot initialize YUM signing key")
	}
	fullManifest := filepath.Join(txDir, base+"-full.tsv")
	full, err := os.OpenFile(fullManifest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, _, projectErr := views.ProjectManifest(inputs, full)
	closeErr := errors.Join(full.Sync(), full.Close())
	for _, reader := range readers {
		closeErr = errors.Join(closeErr, reader.Close())
	}
	readers = nil
	if projectErr != nil || closeErr != nil {
		return errors.Join(projectErr, closeErr)
	}
	relativeManifest := filepath.Join(txDir, base+"-relative.tsv")
	if err := stripManifestPrefix(fullManifest, relativeManifest, effectiveRoot); err != nil {
		return err
	}
	if err := validateYUMPayloadManifest(relativeManifest); err != nil {
		return err
	}
	// A repository whose entire stale primary set was explicitly pruned has an
	// empty payload manifest. The top-level materializer still creates the
	// dedicated target root, but no payload worker exists to create this nested
	// physical repo root. Create and durably bind it before installing the first
	// signed empty repodata generation.
	if err := ensureLocalServingRecoveryTarget(targetRoot, effectiveRoot); err != nil {
		return fmt.Errorf("prepare YUM metadata root: %w", err)
	}
	repoRoot := filepath.Join(targetRoot, filepath.FromSlash(effectiveRoot))
	var packageKeyring openpgp.KeyRing
	for _, unit := range unitValues {
		keyring, err := requireMaterializationYUMTrust(unit, cfg, repo, privateKey, materializeTrustPayloadAfter)
		if err != nil {
			return err
		}
		if packageKeyring == nil {
			packageKeyring = keyring
		}
	}
	verificationTime := packageProjectionMaterializationTime(values, time.Now())
	if err := verifyYUMPackageManifest(ctx, relativeManifest, repoRoot, packageKeyring, verificationTime, values.workers); err != nil {
		return fmt.Errorf("RPM package trust preflight: %w", err)
	}
	iterator, file, err := openYUMManifestIterator(relativeManifest, repoRoot)
	if err != nil {
		return err
	}
	generationDir := filepath.Join(txDir, base+"-generation")
	options := yumrepo.Options{
		ELMajor: repo.OS.Major, Frozen: repo.OS.Lifecycle == "frozen", Compression: yumrepo.Compression(repo.YUM.Compression),
		Revision: commitTime.Unix(), Signer: signer,
	}
	generation, generateErr := yumrepo.Generate(ctx, generationDir, options, iterator)
	closeErr = file.Close()
	if generateErr != nil || closeErr != nil {
		return errors.Join(generateErr, closeErr)
	}
	compression, err := yumrepo.CompressionForOptions(options)
	if err != nil {
		return err
	}
	live := filepath.Join(repoRoot, "repodata")
	staged := filepath.Join(repoRoot, ".sow-repodata-"+anchor.String()[:16])
	if err := installYUMStagedGeneration(ctx, generationDir, staged, compression, signer, generation.RepomdSHA256); err != nil {
		return err
	}
	guard := func(phase yumrepo.ActivationPhase) error {
		boundary := materializeTrustYUMActivationBefore
		if phase == yumrepo.ActivationAfterExchange {
			boundary = materializeTrustYUMActivationAfter
		}
		for _, unit := range unitValues {
			if _, err := requireMaterializationYUMTrust(unit, cfg, repo, privateKey, boundary); err != nil {
				return err
			}
		}
		return nil
	}
	if _, statErr := os.Lstat(live); errors.Is(statErr, os.ErrNotExist) {
		err = yumrepo.ActivateInitialLocalGuarded(ctx, live, staged, compression, signer, generation.RepomdSHA256, guard)
	} else if statErr != nil {
		return statErr
	} else {
		err = yumrepo.ActivateLocalGuarded(ctx, live, staged, compression, signer, generation.RepomdSHA256, yumrepo.NativeDirectoryExchanger{}, guard)
	}
	if err != nil {
		return err
	}
	if err := os.RemoveAll(staged); err != nil {
		return err
	}
	active, err := yumrepo.ValidateDirectory(ctx, live, compression, signer)
	if err != nil || !yumGenerationMatchesExpected(active, generation, -1) {
		return errors.Join(err, errors.New("active YUM generation identity mismatch"))
	}
	if generationOut != nil {
		*generationOut = active
	}
	metadataManifest := materializedYUMMetadataManifestPath(txDir, repo.ID, leaves)
	return writeFrozenYUMMetadataManifest(ctx, live, metadataManifest, path.Join(effectiveRoot, "repodata"), active)
}

// retainMaterializedSnapshot reports whether an immutable snapshot belongs to
// the configured natural-month window. The current month counts as month one.
func retainMaterializedSnapshot(snapshotID string, now time.Time, months int) (bool, error) {
	if months < 1 {
		return false, errors.New("snapshot materialization month count must be positive")
	}
	if err := views.ValidateSnapshotID(snapshotID); err != nil {
		return false, err
	}
	date, err := time.Parse("20060102", snapshotID[len(snapshotID)-8:])
	if err != nil {
		return false, err
	}
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if date.After(today) {
		return false, fmt.Errorf("snapshot ID %s is in the future", snapshotID)
	}
	cutoff := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -(months - 1), 0)
	return !date.Before(cutoff), nil
}

// pruneExpiredSnapshotMaterializations applies FR-22 only to the derived
// cache. It never mutates refs or CAS bytes. keepID protects an explicitly
// requested old snapshot long enough for on-demand service or tgz creation.
func pruneExpiredSnapshotMaterializations(root, keepID string, months int, now time.Time) ([]string, error) {
	base := filepath.Join(root, config.StateDirectory, "materialized", "snapshots")
	entries, err := os.ReadDir(base)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, entry := range entries {
		name := entry.Name()
		if err := views.ValidateSnapshotID(name); err != nil {
			return nil, fmt.Errorf("unsafe snapshot materialization entry %q", name)
		}
		info, err := entry.Info()
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.Join(err, fmt.Errorf("snapshot materialization %s is not a real directory", name))
		}
		retained, err := retainMaterializedSnapshot(name, now, months)
		if err != nil {
			return nil, err
		}
		if retained || name == keepID {
			continue
		}
		path := filepath.Join(base, name)
		if err := validateDerivedMaterializationTree(path); err != nil {
			return nil, err
		}
		if err := os.RemoveAll(path); err != nil {
			return nil, err
		}
		removed = append(removed, name)
	}
	sort.Strings(removed)
	if len(removed) != 0 {
		if err := syncLocalDirectory(base); err != nil {
			return nil, err
		}
	}
	return removed, nil
}

func validateDerivedMaterializationTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("refuse to prune unsafe derived snapshot path %s", path)
		}
		return nil
	})
}
