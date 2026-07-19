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
	"strings"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

type aptMaterializeResult struct {
	Packages                repository.MaterializeStats
	Reconciled              repository.ReconcileStats
	Builds                  map[string]aptrepo.BuildResult
	Ledgers                 map[string]string
	ByHashRemoved           int
	Target                  string
	SelectedPayloadManifest string
	// ExactManifest is the repository-relative expected tree assembled from
	// the frozen payload ref vector and the freshly generated deterministic
	// metadata.  Callers that persist serving admission evidence must use this
	// file rather than scanning the live route after reconciliation.
	ExactManifest string
	SelectedRepo  config.Repo
}

func materializeAPTRepo(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repo config.Repo, viewName, txDir string, values commonFlags, privateKey, passphrase []byte) (result aptMaterializeResult, resultErr error) {
	result = aptMaterializeResult{Builds: make(map[string]aptrepo.BuildResult), Ledgers: make(map[string]string)}
	// APT suites and architectures share one pool and one directly hosted repo
	// root. A command may mutate only selected refs, but exact reconciliation of
	// that root must always project every configured leaf; reconciling a narrowed
	// projection would delete unselected suites and package bytes.
	selectedRepo := repo
	fullRepo, exists := cfg.RepoByName(repo.ID)
	if !exists || fullRepo.Type != "apt" || fullRepo.APT == nil {
		return result, fmt.Errorf("APT repository %s is not present in canonical configuration", repo.ID)
	}
	selectedRepo.Arches = append([]string(nil), fullRepo.Arches...)
	if selectedRepo.APT == nil || len(selectedRepo.APT.Suites) == 0 {
		return result, fmt.Errorf("APT repository %s has no selected suites", repo.ID)
	}
	result.SelectedRepo = selectedRepo
	repo = fullRepo
	transactionLeaves := make([]viewLeaf, 0, len(repo.APT.Suites)*len(repo.Arches))
	for _, suite := range repo.APT.Suites {
		for _, arch := range repo.Arches {
			transactionLeaves = append(transactionLeaves, viewLeaf{repo: repo, os: suite, arch: arch})
		}
	}
	targetRoot := values.materializeTarget
	if targetRoot == "" {
		targetRoot = cfg.Root
	}
	values, selectionOwner, err := beginMaterializationSelectionForSource(cfg, canonical, values, selectedMaterializationOperation(values, "materialize"), materializeCanonicalSource{ID: viewName, Public: cfg.Views[viewName].Access == "public"}, transactionLeaves, targetRoot, true, false, true)
	if err != nil {
		return result, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	signer, err := aptrepo.NewSigner(bytes.NewReader(privateKey), passphrase)
	if err != nil {
		return result, errors.New("cannot initialize APT signing key")
	}
	var inputs []views.ProjectionInput
	var readers []io.ReadCloser
	closeReaders := func() error {
		var closeErr error
		for _, reader := range readers {
			closeErr = errors.Join(closeErr, reader.Close())
		}
		readers = nil
		return closeErr
	}
	defer closeReaders()
	viewConfig := cfg.Views[viewName]
	for _, suite := range repo.APT.Suites {
		for _, arch := range repo.Arches {
			ref, err := state.ViewRef(viewName, repo.ID, suite, arch)
			if err != nil {
				return result, err
			}
			commit, exists, err := canonical.Ref(ref)
			if err != nil {
				return result, err
			}
			if !exists {
				continue
			}
			viewPath, err := state.ViewPath(viewName, repo.ID, suite, arch)
			if err != nil {
				return result, err
			}
			leaf := viewLeaf{repo: repo, os: suite, arch: arch}
			if err := validateViewAt(canonical, commit, viewPath, leaf, viewConfig.Access == "public"); err != nil {
				return result, err
			}
			reader, err := canonical.OpenPathAt(commit, viewPath)
			if err != nil {
				return result, err
			}
			readers = append(readers, reader)
			inputs = append(inputs, views.ProjectionInput{Label: ref.String(), Reader: reader})
		}
	}
	if len(inputs) == 0 {
		return result, fmt.Errorf("APT view %s has no refs for repo %s", viewName, repo.ID)
	}
	fullManifest := filepath.Join(txDir, fmt.Sprintf("apt-%s-%s-full.tsv", repo.ID, viewName))
	full, err := os.OpenFile(fullManifest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return result, err
	}
	_, _, projectErr := views.ProjectManifest(inputs, full)
	closeErr := errors.Join(full.Sync(), full.Close(), closeReaders())
	if projectErr != nil || closeErr != nil {
		return result, errors.Join(projectErr, closeErr)
	}
	result.SelectedPayloadManifest = fullManifest
	if !repoSelectionIsFull(fullRepo, selectedRepo) {
		selectedManifest := filepath.Join(txDir, fmt.Sprintf("apt-%s-%s-selected-payloads.tsv", repo.ID, viewName))
		if err := projectAPTViewPayloadManifest(canonical, cfg.Views[viewName], selectedRepo, viewName, selectedManifest); err != nil {
			return result, err
		}
		result.SelectedPayloadManifest = selectedManifest
	}
	relativeManifest := filepath.Join(txDir, fmt.Sprintf("apt-%s-%s-relative.tsv", repo.ID, viewName))
	if err := stripManifestPrefix(fullManifest, relativeManifest, repo.Path); err != nil {
		return result, err
	}
	if err := validateAPTPayloadManifest(relativeManifest); err != nil {
		return result, err
	}
	target := repo.Path
	switch viewName {
	case "beta":
		target = filepath.ToSlash(filepath.Join(config.StateDirectory, "materialized", "beta", repo.Path))
	case "stable":
		target = filepath.ToSlash(filepath.Join(config.StateDirectory, "origin", "gated", repo.Path))
	}
	result.Target = target
	desired, err := os.Open(relativeManifest)
	if err != nil {
		return result, err
	}
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustPayloadBefore); err != nil {
		desired.Close()
		return result, err
	}
	result.Packages, err = pool.MaterializeWithOptions(ctx, desired, target, repository.MaterializeOptions{Workers: values.workers})
	closeErr = desired.Close()
	if err != nil || closeErr != nil {
		return result, errors.Join(err, closeErr)
	}
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustPayloadAfter); err != nil {
		return result, err
	}
	targetAbs := filepath.Join(cfg.Root, filepath.FromSlash(target))
	ledgerStageDir, err := aptByHashStageDir(txDir)
	if err != nil {
		return result, err
	}
	frozenBuilds := make([]aptrepo.BuildResult, 0, len(repo.APT.Suites))
	for _, suite := range repo.APT.Suites {
		components := repo.APT.ComponentsForSuite(suite)
		indexes, publicationTime, exists, cleanup, err := buildAPTIndexes(ctx, cfg, canonical, repo, viewName, suite, targetAbs, values)
		if err != nil {
			return result, err
		}
		if !exists {
			_ = cleanup()
			continue
		}
		publicationTime = packageProjectionMaterializationTime(values, publicationTime)
		deterministic, err := newDeterministicMaterializeKey(privateKey, passphrase, publicationTime)
		if err != nil {
			_ = cleanup()
			return result, err
		}
		suiteValues := values
		suiteValues.materializeUnit, err = materializationUnitFor(values, "apt", viewName, repo.ID, suite, "", targetRoot)
		if err != nil {
			_ = cleanup()
			return result, err
		}
		build, buildErr := aptrepo.GenerateStreaming(ctx, targetAbs, aptrepo.RepositoryConfig{
			Origin: "Pigsty", Label: "Pigsty", Suite: suite, Codename: suite,
			Description: "Pigsty software repository", Components: components,
			Architectures: repo.Arches, Date: publicationTime,
		}, indexes, signer, aptrepo.StreamingOptions{
			Workers: values.workers,
			StagedTransform: func(stageRoot string, _ aptrepo.BuildResult) error {
				if err := rewriteDeterministicAPTSignatures(ctx, stageRoot, suite, deterministic); err != nil {
					return fmt.Errorf("install deterministic suite signatures %s: %w", suite, err)
				}
				release, err := os.ReadFile(filepath.Join(stageRoot, "dists", suite, "Release"))
				if err != nil {
					return err
				}
				inRelease, err := os.ReadFile(filepath.Join(stageRoot, "dists", suite, "InRelease"))
				if err != nil {
					return err
				}
				detached, err := os.ReadFile(filepath.Join(stageRoot, "dists", suite, "Release.gpg"))
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
		if buildErr != nil || cleanupErr != nil {
			return result, fmt.Errorf("generate APT suite %s: %w", suite, errors.Join(buildErr, cleanupErr))
		}
		ledger, err := stageAPTByHashGeneration(ctx, canonical, targetAbs, "views", viewName, repo.ID, suite, ledgerStageDir, cfg.State.APTByHashRetention, build.ByHashGeneration)
		if err != nil {
			return result, err
		}
		result.Ledgers[ledger.CanonicalPath] = ledger.StagedPath
		result.ByHashRemoved += ledger.Removed
		result.Builds[suite] = build
		frozenBuilds = append(frozenBuilds, build)
	}
	if len(result.Builds) == 0 {
		return result, errors.New("APT view has no buildable suite refs")
	}
	metadataManifest := filepath.Join(txDir, fmt.Sprintf("apt-%s-%s-metadata.tsv", repo.ID, viewName))
	if err := writeFrozenAPTMetadataManifest(ctx, targetAbs, "", metadataManifest, frozenBuilds, result.Ledgers); err != nil {
		return result, err
	}
	exactManifest := filepath.Join(txDir, fmt.Sprintf("apt-%s-%s-exact.tsv", repo.ID, viewName))
	if err := mergeManifestFiles(relativeManifest, metadataManifest, exactManifest); err != nil {
		return result, err
	}
	result.ExactManifest = exactManifest
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustExactReconcileBefore); err != nil {
		return result, err
	}
	result.Reconciled, err = pool.ReconcileExact(ctx, exactManifest, target, values.workers, values.chunk)
	if err != nil {
		return result, err
	}
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustExactReconcileAfter); err != nil {
		return result, err
	}
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustServingPublishBefore); err != nil {
		return result, err
	}
	if err := serving.PublishHostableTree(targetAbs); err != nil {
		return result, fmt.Errorf("publish hostable APT tree: %w", err)
	}
	if err := requireMaterializationRepositoryTrust(values, cfg, privateKey, materializeTrustServingPublishAfter); err != nil {
		return result, err
	}
	return result, nil
}

func projectAPTViewPayloadManifest(canonical *state.Store, viewConfig config.View, repo config.Repo, viewName, destination string) error {
	var inputs []views.ProjectionInput
	var readers []io.ReadCloser
	closeReaders := func() error {
		var result error
		for _, reader := range readers {
			result = errors.Join(result, reader.Close())
		}
		readers = nil
		return result
	}
	defer closeReaders()
	for _, suite := range repo.APT.Suites {
		for _, arch := range repo.Arches {
			ref, err := state.ViewRef(viewName, repo.ID, suite, arch)
			if err != nil {
				return err
			}
			commit, exists, err := canonical.Ref(ref)
			if err != nil {
				return err
			}
			if !exists {
				continue
			}
			viewPath, err := state.ViewPath(viewName, repo.ID, suite, arch)
			if err != nil {
				return err
			}
			leaf := viewLeaf{repo: repo, os: suite, arch: arch}
			if err := validateViewAt(canonical, commit, viewPath, leaf, viewConfig.Access == "public"); err != nil {
				return err
			}
			reader, err := canonical.OpenPathAt(commit, viewPath)
			if err != nil {
				return err
			}
			readers = append(readers, reader)
			inputs = append(inputs, views.ProjectionInput{Label: ref.String(), Reader: reader})
		}
	}
	if len(inputs) == 0 {
		return fmt.Errorf("APT view %s has no selected refs for repo %s", viewName, repo.ID)
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, _, projectErr := views.ProjectManifest(inputs, output)
	return errors.Join(projectErr, output.Sync(), output.Close(), closeReaders())
}

func buildAPTIndexes(ctx context.Context, cfg *config.Config, canonical *state.Store, repo config.Repo, viewName, suite, targetRoot string, values commonFlags) ([]aptrepo.StreamingIndex, time.Time, bool, func() error, error) {
	viewConfig := cfg.Views[viewName]
	var leaves []aptCanonicalLeaf
	var publicationTime time.Time
	var found bool
	for _, arch := range repo.Arches {
		ref, err := state.ViewRef(viewName, repo.ID, suite, arch)
		if err != nil {
			return nil, time.Time{}, false, func() error { return nil }, err
		}
		commit, exists, err := canonical.Ref(ref)
		if err != nil {
			return nil, time.Time{}, false, func() error { return nil }, err
		}
		if !exists {
			continue
		}
		found = true
		commitTime, err := canonical.CommitTime(commit)
		if err != nil {
			return nil, time.Time{}, false, func() error { return nil }, err
		}
		if commitTime.After(publicationTime) {
			publicationTime = commitTime
		}
		viewPath, err := state.ViewPath(viewName, repo.ID, suite, arch)
		if err != nil {
			return nil, time.Time{}, false, func() error { return nil }, err
		}
		leaf := viewLeaf{repo: repo, os: suite, arch: arch}
		if err := validateViewAt(canonical, commit, viewPath, leaf, viewConfig.Access == "public"); err != nil {
			return nil, time.Time{}, false, func() error { return nil }, err
		}
		leaves = append(leaves, aptCanonicalLeaf{arch: arch, commit: commit, canonicalPath: viewPath})
	}
	if !found {
		return nil, time.Time{}, false, func() error { return nil }, nil
	}
	indexes, cleanup, err := buildAPTStreamingSpools(ctx, canonical, repo, repo.APT.ComponentsForSuite(suite), leaves, targetRoot, filepath.Join(cfg.StatePath(), "tmp"), values.workers, values.chunk)
	if err != nil {
		return nil, time.Time{}, false, func() error { return nil }, err
	}
	return indexes, publicationTime.UTC().Truncate(time.Second), true, cleanup, nil
}

func validateAPTPayloadManifest(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := aptComponentFromPoolPath(entry.Path); err != nil || !strings.HasSuffix(entry.Path, ".deb") {
			return fmt.Errorf("APT view contains non-canonical payload path %q", entry.Path)
		}
	}
}

func aptComponentFromPoolPath(value string) (string, error) {
	parts := strings.Split(value, "/")
	if len(parts) < 5 || parts[0] != "pool" || parts[1] == "" || path.Base(value) == value || strings.ContainsAny(value, "%?#\\") {
		return "", errors.New("invalid APT pool path")
	}
	return parts[1], nil
}
