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
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

type yumMaterializeResult struct {
	Packages   repository.MaterializeStats
	Reconciled repository.ReconcileStats
	Generation *yumrepo.Generation
	Target     string
	// PayloadManifest is rooted at the configured physical repository path;
	// ExactManifest is relative to the physical YUM arch root.  Both are
	// expected inputs captured before exact reconciliation, never live scans.
	PayloadManifest string
	ExactManifest   string
}

// materializeYUMOwner rebuilds one physical repo+arch root from the complete
// logical OS alias vector. Suite and family-major refs may intentionally point
// at different, disjoint package manifests while sharing one legacy URL; they
// must therefore be projected, signed, reconciled, and published as one unit.
func materializeYUMOwner(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repo config.Repo, leaves []viewLeaf, viewName, txDir string, values commonFlags, privateKey, passphrase []byte) (result yumMaterializeResult, resultErr error) {
	if cfg == nil || canonical == nil || pool == nil || len(leaves) == 0 {
		return result, errors.New("YUM physical owner dependencies are unavailable")
	}
	leaves = append([]viewLeaf(nil), leaves...)
	sort.Slice(leaves, func(i, j int) bool {
		if leaves[i].arch != leaves[j].arch {
			return leaves[i].arch < leaves[j].arch
		}
		return leaves[i].os < leaves[j].os
	})
	arch := leaves[0].arch
	seen := make(map[string]struct{}, len(leaves))
	for _, leaf := range leaves {
		if leaf.repo.ID != repo.ID || leaf.repo.Type != "yum" || leaf.arch != arch || leaf.os == "" {
			return result, errors.New("YUM physical owner leaves cross a repo+arch boundary")
		}
		key := leaf.os + "\x00" + leaf.arch
		if _, duplicate := seen[key]; duplicate {
			return result, fmt.Errorf("duplicate YUM physical owner leaf %s/%s", leaf.os, leaf.arch)
		}
		seen[key] = struct{}{}
	}
	effectiveRoot, err := repo.PathForArch(arch)
	if err != nil {
		return result, err
	}
	viewConfig, exists := cfg.Views[viewName]
	if !exists {
		return result, fmt.Errorf("view %s is unavailable", viewName)
	}
	targetRoot := values.materializeTarget
	if targetRoot == "" {
		targetRoot = cfg.Root
	}
	source := materializeCanonicalSource{ID: viewName, Public: viewConfig.Access == "public"}
	values, selectionOwner, err := beginMaterializationSelectionForSource(cfg, canonical, values, selectedMaterializationOperation(values, "materialize"), source, leaves, targetRoot, true, false)
	if err != nil {
		return result, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	unitValues := make([]commonFlags, 0, len(leaves))
	for _, leaf := range leaves {
		unit := values
		unit.materializeUnit, err = materializationUnitFor(values, "yum", viewName, repo.ID, leaf.os, leaf.arch, targetRoot)
		if err != nil {
			return result, err
		}
		unitValues = append(unitValues, unit)
	}
	base := fmt.Sprintf("yum-owner-%s-%s", repo.ID, arch)
	fullManifest := filepath.Join(txDir, base+"-full.tsv")
	if _, _, err := projectCanonicalMaterializationLeaves(canonical, source, leaves, fullManifest); err != nil {
		return result, err
	}
	result.PayloadManifest = fullManifest
	relativeManifest := filepath.Join(txDir, base+"-relative.tsv")
	if err := stripManifestPrefix(fullManifest, relativeManifest, effectiveRoot); err != nil {
		return result, err
	}
	if err := validateYUMPayloadManifest(relativeManifest); err != nil {
		return result, err
	}
	target := effectiveRoot
	metadataBaseRoot := cfg.Root
	switch viewName {
	case "beta":
		baseRoot := filepath.ToSlash(filepath.Join(config.StateDirectory, "materialized", "beta"))
		target = filepath.ToSlash(filepath.Join(baseRoot, effectiveRoot))
		metadataBaseRoot = filepath.Join(cfg.Root, filepath.FromSlash(baseRoot))
	case "stable":
		baseRoot := filepath.ToSlash(filepath.Join(config.StateDirectory, "origin", "gated"))
		target = filepath.ToSlash(filepath.Join(baseRoot, effectiveRoot))
		metadataBaseRoot = filepath.Join(cfg.Root, filepath.FromSlash(baseRoot))
	}
	result.Target = target
	var packageKeyring openpgp.KeyRing
	for _, unit := range unitValues {
		keyring, err := requireMaterializationYUMTrust(unit, cfg, repo, privateKey, materializeTrustPayloadBefore)
		if err != nil {
			return result, err
		}
		if packageKeyring == nil {
			packageKeyring = keyring
		}
	}
	desired, err := os.Open(relativeManifest)
	if err != nil {
		return result, err
	}
	result.Packages, err = pool.MaterializeWithOptions(ctx, desired, target, repository.MaterializeOptions{Workers: values.workers})
	closeErr := desired.Close()
	if err != nil || closeErr != nil {
		return result, errors.Join(err, closeErr)
	}
	for _, unit := range unitValues {
		if _, err := requireMaterializationYUMTrust(unit, cfg, repo, privateKey, materializeTrustPayloadAfter); err != nil {
			return result, err
		}
	}
	targetAbs := filepath.Join(cfg.Root, filepath.FromSlash(target))
	verificationTime := packageProjectionMaterializationTime(values, time.Now())
	if err := verifyYUMPackageManifest(ctx, relativeManifest, targetAbs, packageKeyring, verificationTime, values.workers); err != nil {
		return result, fmt.Errorf("RPM package trust preflight: %w", err)
	}
	if err := materializeYUMMetadataOwner(ctx, cfg, canonical, repo, leaves, source, metadataBaseRoot, txDir, privateKey, passphrase, values, &result.Generation); err != nil {
		return result, err
	}
	metadataManifest := materializedYUMMetadataManifestPath(txDir, repo.ID, leaves)
	exactFull := filepath.Join(txDir, base+"-exact-full.tsv")
	if err := mergeManifestFiles(fullManifest, metadataManifest, exactFull); err != nil {
		return result, err
	}
	exactManifest := filepath.Join(txDir, base+"-exact.tsv")
	if err := stripManifestPrefix(exactFull, exactManifest, effectiveRoot); err != nil {
		return result, err
	}
	result.ExactManifest = exactManifest
	for _, unit := range unitValues {
		if _, err := requireMaterializationYUMTrust(unit, cfg, repo, privateKey, materializeTrustExactReconcileBefore); err != nil {
			return result, err
		}
	}
	result.Reconciled, err = pool.ReconcileExact(ctx, exactManifest, target, values.workers, values.chunk)
	if err != nil {
		return result, err
	}
	for _, unit := range unitValues {
		if _, err := requireMaterializationYUMTrust(unit, cfg, repo, privateKey, materializeTrustExactReconcileAfter); err != nil {
			return result, err
		}
	}
	for _, unit := range unitValues {
		if _, err := requireMaterializationYUMTrust(unit, cfg, repo, privateKey, materializeTrustServingPublishBefore); err != nil {
			return result, err
		}
	}
	if err := serving.PublishHostableTree(targetAbs); err != nil {
		return result, fmt.Errorf("publish hostable YUM tree: %w", err)
	}
	for _, unit := range unitValues {
		if _, err := requireMaterializationYUMTrust(unit, cfg, repo, privateKey, materializeTrustServingPublishAfter); err != nil {
			return result, err
		}
	}
	if result.Generation == nil {
		return result, errors.New("YUM physical owner has no active generation identity")
	}
	return result, nil
}

func materializeYUMLeaf(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repo config.Repo, leaf viewLeaf, viewName, txDir string, values commonFlags, privateKey, passphrase []byte) (result yumMaterializeResult, resultErr error) {
	effectiveRoot, err := repo.PathForArch(leaf.arch)
	if err != nil {
		return result, err
	}
	targetRoot := values.materializeTarget
	if targetRoot == "" {
		targetRoot = cfg.Root
	}
	values, selectionOwner, err := beginMaterializationSelectionForSource(cfg, canonical, values, selectedMaterializationOperation(values, "materialize"), materializeCanonicalSource{ID: viewName, Public: cfg.Views[viewName].Access == "public"}, []viewLeaf{leaf}, targetRoot, true, false)
	if err != nil {
		return result, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	values.materializeUnit, err = materializationUnitFor(values, "yum", viewName, repo.ID, leaf.os, leaf.arch, targetRoot)
	if err != nil {
		return result, err
	}
	viewPath, err := state.ViewPath(viewName, repo.ID, leaf.os, leaf.arch)
	if err != nil {
		return result, err
	}
	viewRef, err := state.ViewRef(viewName, repo.ID, leaf.os, leaf.arch)
	if err != nil {
		return result, err
	}
	commit, exists, err := canonical.Ref(viewRef)
	if err != nil || !exists {
		return result, errors.Join(err, fmt.Errorf("view ref %s is missing", viewRef))
	}
	commitTime, err := canonical.CommitTime(commit)
	if err != nil {
		return result, err
	}
	commitTime = packageProjectionMaterializationTime(values, commitTime)
	signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateKey), passphrase, commitTime)
	if err != nil {
		return result, errors.New("cannot initialize YUM signing key")
	}
	reader, err := canonical.OpenPathAt(commit, viewPath)
	if err != nil {
		return result, err
	}
	if _, err := views.ValidateLeaf(reader, repo.ID, leaf.os, leaf.arch, cfg.Views[viewName].Access == "public"); err != nil {
		reader.Close()
		return result, err
	}
	if err := reader.Close(); err != nil {
		return result, err
	}
	reader, err = canonical.OpenPathAt(commit, viewPath)
	if err != nil {
		return result, err
	}
	fullManifest := filepath.Join(txDir, fmt.Sprintf("yum-%s-%s-%s-full.tsv", repo.ID, leaf.os, leaf.arch))
	full, err := os.OpenFile(fullManifest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		reader.Close()
		return result, err
	}
	_, _, projectErr := views.ProjectManifest([]views.ProjectionInput{{Label: viewRef.String(), Reader: reader}}, full)
	closeErr := errors.Join(reader.Close(), full.Sync(), full.Close())
	if projectErr != nil || closeErr != nil {
		return result, errors.Join(projectErr, closeErr)
	}
	result.PayloadManifest = fullManifest
	relativeManifest := filepath.Join(txDir, fmt.Sprintf("yum-%s-%s-%s-relative.tsv", repo.ID, leaf.os, leaf.arch))
	if err := stripManifestPrefix(fullManifest, relativeManifest, effectiveRoot); err != nil {
		return result, err
	}
	if err := validateYUMPayloadManifest(relativeManifest); err != nil {
		return result, err
	}
	target := effectiveRoot
	switch viewName {
	case "beta":
		target = filepath.ToSlash(filepath.Join(config.StateDirectory, "materialized", "beta", effectiveRoot))
	case "stable":
		target = filepath.ToSlash(filepath.Join(config.StateDirectory, "origin", "gated", effectiveRoot))
	}
	result.Target = target
	desired, err := os.Open(relativeManifest)
	if err != nil {
		return result, err
	}
	packageKeyring, err := requireMaterializationYUMTrust(values, cfg, repo, privateKey, materializeTrustPayloadBefore)
	if err != nil {
		desired.Close()
		return result, err
	}
	result.Packages, err = pool.MaterializeWithOptions(ctx, desired, target, repository.MaterializeOptions{Workers: values.workers})
	closeErr = desired.Close()
	if err != nil || closeErr != nil {
		return result, errors.Join(err, closeErr)
	}
	if _, err := requireMaterializationYUMTrust(values, cfg, repo, privateKey, materializeTrustPayloadAfter); err != nil {
		return result, err
	}
	targetAbs := filepath.Join(cfg.Root, filepath.FromSlash(target))
	verificationTime := packageProjectionMaterializationTime(values, time.Now())
	if err := verifyYUMPackageManifest(ctx, relativeManifest, targetAbs, packageKeyring, verificationTime, values.workers); err != nil {
		return result, fmt.Errorf("RPM package trust preflight: %w", err)
	}
	live := filepath.Join(targetAbs, "repodata")
	options := yumrepo.Options{
		ELMajor:     repo.OS.Major,
		Frozen:      repo.OS.Lifecycle == "frozen",
		Compression: yumrepo.Compression(repo.YUM.Compression),
		Revision:    commitTime.Unix(),
		Signer:      signer,
	}
	compression, err := yumrepo.CompressionForOptions(options)
	if err != nil {
		return result, err
	}
	generationDir := filepath.Join(txDir, fmt.Sprintf("yum-%s-%s-%s-generation", repo.ID, leaf.os, leaf.arch))
	iterator, file, err := openYUMManifestIterator(relativeManifest, targetAbs)
	if err != nil {
		return result, err
	}
	result.Generation, err = yumrepo.Generate(ctx, generationDir, options, iterator)
	closeErr = file.Close()
	if err != nil || closeErr != nil {
		return result, errors.Join(err, closeErr)
	}
	staged := filepath.Join(targetAbs, ".sow-repodata-"+commit.String()[:16])
	if err := installYUMStagedGeneration(ctx, generationDir, staged, compression, signer, result.Generation.RepomdSHA256); err != nil {
		return result, err
	}
	activationGuard := func(phase yumrepo.ActivationPhase) error {
		boundary := materializeTrustYUMActivationBefore
		if phase == yumrepo.ActivationAfterExchange {
			boundary = materializeTrustYUMActivationAfter
		}
		_, err := requireMaterializationYUMTrust(values, cfg, repo, privateKey, boundary)
		return err
	}
	if _, statErr := os.Lstat(live); errors.Is(statErr, os.ErrNotExist) {
		if err := yumrepo.ActivateInitialLocalGuarded(ctx, live, staged, compression, signer, result.Generation.RepomdSHA256, activationGuard); err != nil {
			return result, err
		}
	} else if statErr != nil {
		return result, statErr
	} else {
		if err := yumrepo.ActivateLocalGuarded(ctx, live, staged, compression, signer, result.Generation.RepomdSHA256, yumrepo.NativeDirectoryExchanger{}, activationGuard); err != nil {
			return result, err
		}
	}
	if err := os.RemoveAll(staged); err != nil {
		return result, fmt.Errorf("remove inactive YUM repodata generation: %w", err)
	}
	if err := syncLocalDirectory(targetAbs); err != nil {
		return result, err
	}
	active, err := yumrepo.ValidateDirectory(ctx, live, compression, signer)
	if err != nil || !yumGenerationMatchesExpected(active, result.Generation, -1) {
		return result, errors.Join(err, errors.New("active YUM generation identity mismatch"))
	}
	// Activation is identity-idempotent: when repomd is already current it
	// intentionally keeps the previously valid detached signature. Freeze the
	// exact five-file active generation after strict validation so the manifest
	// matches the bytes actually selected by the atomic activation decision.
	metadataManifest := filepath.Join(txDir, fmt.Sprintf("yum-%s-%s-%s-metadata.tsv", repo.ID, leaf.os, leaf.arch))
	if err := writeFrozenYUMMetadataManifest(ctx, live, metadataManifest, "repodata", active); err != nil {
		return result, err
	}
	exactManifest := filepath.Join(txDir, fmt.Sprintf("yum-%s-%s-%s-exact.tsv", repo.ID, leaf.os, leaf.arch))
	if err := mergeManifestFiles(relativeManifest, metadataManifest, exactManifest); err != nil {
		return result, err
	}
	result.ExactManifest = exactManifest
	if _, err := requireMaterializationYUMTrust(values, cfg, repo, privateKey, materializeTrustExactReconcileBefore); err != nil {
		return result, err
	}
	result.Reconciled, err = pool.ReconcileExact(ctx, exactManifest, target, values.workers, values.chunk)
	if err != nil {
		return result, err
	}
	if _, err := requireMaterializationYUMTrust(values, cfg, repo, privateKey, materializeTrustExactReconcileAfter); err != nil {
		return result, err
	}
	if _, err := requireMaterializationYUMTrust(values, cfg, repo, privateKey, materializeTrustServingPublishBefore); err != nil {
		return result, err
	}
	if err := serving.PublishHostableTree(targetAbs); err != nil {
		return result, fmt.Errorf("publish hostable YUM tree: %w", err)
	}
	if _, err := requireMaterializationYUMTrust(values, cfg, repo, privateKey, materializeTrustServingPublishAfter); err != nil {
		return result, err
	}
	return result, nil
}

func verifyYUMPackageManifest(ctx context.Context, manifestPath, root string, keyring openpgp.KeyRing, at time.Time, workers int) error {
	if keyring == nil || at.IsZero() {
		return errors.New("RPM package keyring and verification time are required")
	}
	if workers <= 0 {
		workers = 4
	}
	if workers > 64 {
		workers = 64
	}
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer file.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type packageJob struct {
		path string
		size int64
	}
	jobs := make(chan packageJob, workers*2)
	errCh := make(chan error, 1)
	recordError := func(err error) {
		select {
		case errCh <- err:
			cancel()
		default:
		}
	}
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					continue
				}
				filename := filepath.Join(root, filepath.FromSlash(job.path))
				if _, err := verifyStableRPMFile(ctx, filename, job.size, keyring, at); err != nil {
					recordError(fmt.Errorf("verify %s: %w", job.path, err))
				}
			}
		}()
	}
	reader := manifest.NewReader(file)
readLoop:
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			recordError(err)
			break
		}
		select {
		case jobs <- packageJob{path: entry.Path, size: entry.Size}:
		case <-ctx.Done():
			break readLoop
		}
	}
	close(jobs)
	wait.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return ctx.Err()
	}
}

type yumManifestIterator struct {
	reader *manifest.Reader
	root   string
}

func (iterator *yumManifestIterator) Next(ctx context.Context) (yumrepo.PackageInput, error) {
	if err := ctx.Err(); err != nil {
		return yumrepo.PackageInput{}, err
	}
	entry, err := iterator.reader.Next()
	if err != nil {
		return yumrepo.PackageInput{}, err
	}
	if !strings.HasPrefix(entry.Path, "Packages/") || path.Base(entry.Path) == entry.Path {
		return yumrepo.PackageInput{}, fmt.Errorf("invalid YUM payload path %q", entry.Path)
	}
	return yumrepo.PackageInput{Path: filepath.Join(iterator.root, filepath.FromSlash(entry.Path)), Basename: path.Base(entry.Path)}, nil
}

func openYUMManifestIterator(path, root string) (*yumManifestIterator, *os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return &yumManifestIterator{reader: manifest.NewReader(file), root: root}, file, nil
}

func validateYUMPayloadManifest(filename string) error {
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
		parts := strings.Split(entry.Path, "/")
		if len(parts) != 3 || parts[0] != "Packages" || len(parts[1]) != 1 || path.Base(parts[2]) != parts[2] || !strings.HasSuffix(parts[2], ".rpm") {
			return fmt.Errorf("YUM view contains non-canonical payload path %q", entry.Path)
		}
	}
}

func installYUMStagedGeneration(ctx context.Context, generated, staged string, compression yumrepo.Compression, verifier yumrepo.DetachedVerifier, expected string) error {
	if info, err := os.Lstat(staged); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("YUM staged generation is not a real directory")
		}
		existing, err := yumrepo.ValidateDirectory(ctx, staged, compression, verifier)
		if err != nil || !yumGenerationMatches(existing, expected, -1) {
			return errors.Join(err, errors.New("conflicting YUM staged generation"))
		}
		return os.RemoveAll(generated)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(generated, staged); err != nil {
		return fmt.Errorf("install sibling YUM staged generation: %w", err)
	}
	return syncLocalDirectory(filepath.Dir(staged))
}

// yumGenerationMatches is the single nil-safe boundary for validator results.
// A concrete validator currently never returns (nil, nil), but callers must
// fail closed rather than panic if that contract regresses or is fault-injected.
func yumGenerationMatches(actual *yumrepo.Generation, repomdSHA256 string, packages int64) bool {
	if actual == nil || repomdSHA256 == "" || actual.RepomdSHA256 != repomdSHA256 {
		return false
	}
	return packages < 0 || actual.Packages == packages
}

func yumGenerationMatchesExpected(actual, expected *yumrepo.Generation, packages int64) bool {
	return expected != nil && yumGenerationMatches(actual, expected.RepomdSHA256, packages)
}

func mergeManifestFiles(leftPath, rightPath, destinationPath string) error {
	left, err := os.Open(leftPath)
	if err != nil {
		return err
	}
	right, err := os.Open(rightPath)
	if err != nil {
		left.Close()
		return err
	}
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		left.Close()
		right.Close()
		return err
	}
	leftReader, rightReader := manifest.NewReader(left), manifest.NewReader(right)
	leftEntry, leftErr := leftReader.Next()
	rightEntry, rightErr := rightReader.Next()
	for !errors.Is(leftErr, io.EOF) || !errors.Is(rightErr, io.EOF) {
		if leftErr != nil && !errors.Is(leftErr, io.EOF) || rightErr != nil && !errors.Is(rightErr, io.EOF) {
			return errors.Join(leftErr, rightErr, left.Close(), right.Close(), destination.Close())
		}
		var entry manifest.Entry
		switch {
		case errors.Is(leftErr, io.EOF):
			entry = rightEntry
			rightEntry, rightErr = rightReader.Next()
		case errors.Is(rightErr, io.EOF):
			entry = leftEntry
			leftEntry, leftErr = leftReader.Next()
		case leftEntry.Path < rightEntry.Path:
			entry = leftEntry
			leftEntry, leftErr = leftReader.Next()
		case rightEntry.Path < leftEntry.Path:
			entry = rightEntry
			rightEntry, rightErr = rightReader.Next()
		default:
			return errors.Join(fmt.Errorf("duplicate exact manifest path %q", leftEntry.Path), left.Close(), right.Close(), destination.Close())
		}
		if err := manifest.WriteEntry(destination, entry); err != nil {
			return errors.Join(err, left.Close(), right.Close(), destination.Close())
		}
	}
	return errors.Join(left.Close(), right.Close(), destination.Sync(), destination.Close())
}

func syncLocalDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
