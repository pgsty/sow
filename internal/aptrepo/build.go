package aptrepo

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ulikunitz/xz"
	"golang.org/x/sys/unix"
)

// RepositoryConfig is the immutable configuration used to build one APT
// distribution. Components and Architectures are explicit so empty indexes
// remain publishable and the Release contract does not depend on package
// discovery order.
type RepositoryConfig struct {
	Origin        string
	Label         string
	Suite         string
	Codename      string
	Version       string
	Description   string
	Components    []string
	Architectures []string
	Date          time.Time
	ValidUntil    time.Time
}

// Index assigns packages to one component/architecture Packages index.
// Architecture "all" packages may be present in every configured native
// architecture index; native packages must match the index architecture.
type Index struct {
	Component    string
	Architecture string
	Packages     []Package
}

// Artifact describes one generated repository file relative to the archive
// root. SHA256 is always lowercase hexadecimal.
type Artifact struct {
	Path   string
	Size   int64
	SHA256 string
}

// PoolObject is a verified materialization request for a human-readable pool
// path. Generate never copies package bodies; repository orchestration can
// hardlink or copy these objects before atomically publishing the metadata.
type PoolObject struct {
	SourcePath string
	Path       string
	Size       int64
	SHA256     string
}

// BuildResult is the complete output contract for one distribution build.
type BuildResult struct {
	Artifacts             []Artifact
	PoolObjects           []PoolObject
	ByHashGeneration      ByHashGeneration
	ReleasePath           string
	InReleasePath         string
	DetachedSignaturePath string
	StreamedPackages      int64
	PeakIndexWorkers      int
}

type indexKey struct {
	component    string
	architecture string
}

// Generate builds a complete distribution in a private staging directory,
// verifies every artifact, then commits it to outputDir. Immutable by-hash
// objects are installed first, mutable metadata is replaced atomically one
// file at a time, and InRelease is the final checkpoint flip. On a commit
// error all mutable files and newly installed by-hash objects are rolled back.
func Generate(ctx context.Context, outputDir string, cfg RepositoryConfig, indexes []Index, signer *Signer) (result BuildResult, resultErr error) {
	if ctx == nil {
		return BuildResult{}, errors.New("aptrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return BuildResult{}, err
	}
	validated, err := validateRepositoryConfig(cfg)
	if err != nil {
		return BuildResult{}, err
	}
	if signer == nil {
		return BuildResult{}, errors.New("aptrepo: signing key is required")
	}
	if err := signer.Validate(validated.Date); err != nil {
		return BuildResult{}, err
	}
	if outputDir == "" {
		return BuildResult{}, errors.New("aptrepo: output directory is required")
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return BuildResult{}, fmt.Errorf("aptrepo: create output directory: %w", err)
	}
	if err := validateOutputRoot(outputDir); err != nil {
		return BuildResult{}, err
	}
	unlock, err := acquireOutputLock(ctx, outputDir)
	if err != nil {
		return BuildResult{}, err
	}
	defer propagateOutputUnlock(unlock, &resultErr)
	outputAbs, err := filepath.Abs(outputDir)
	if err != nil {
		return BuildResult{}, fmt.Errorf("aptrepo: resolve output directory: %w", err)
	}
	stageRoot, err := os.MkdirTemp(filepath.Dir(outputAbs), ".sow-apt-stage-")
	if err != nil {
		return BuildResult{}, fmt.Errorf("aptrepo: create staging directory: %w", err)
	}
	defer os.RemoveAll(stageRoot)

	result, err = generateTree(ctx, stageRoot, cfg, indexes, signer)
	if err != nil {
		return BuildResult{}, err
	}
	if err := commitStagedBuild(ctx, stageRoot, outputDir, result); err != nil {
		return BuildResult{}, err
	}
	return result, nil
}

type outputUnlock func() error

func propagateOutputUnlock(unlock outputUnlock, resultErr *error) {
	if unlock == nil || resultErr == nil {
		return
	}
	*resultErr = errors.Join(*resultErr, unlock())
}

func acquireOutputLock(ctx context.Context, outputDir string) (outputUnlock, error) {
	directory, err := os.Open(outputDir)
	if err != nil {
		return nil, fmt.Errorf("aptrepo: open output directory lock: %w", err)
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() error {
				return errors.Join(unix.Flock(int(directory.Fd()), unix.LOCK_UN), directory.Close())
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return nil, errors.Join(fmt.Errorf("aptrepo: lock output directory: %w", err), directory.Close())
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), directory.Close())
		case <-ticker.C:
		}
	}
}

func generateTree(ctx context.Context, outputDir string, cfg RepositoryConfig, indexes []Index, signer *Signer) (BuildResult, error) {
	if err := ctx.Err(); err != nil {
		return BuildResult{}, err
	}
	validated, err := validateRepositoryConfig(cfg)
	if err != nil {
		return BuildResult{}, err
	}
	if signer == nil {
		return BuildResult{}, errors.New("aptrepo: signing key is required")
	}
	if err := signer.Validate(validated.Date); err != nil {
		return BuildResult{}, err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return BuildResult{}, fmt.Errorf("aptrepo: create output directory: %w", err)
	}
	if err := validateOutputRoot(outputDir); err != nil {
		return BuildResult{}, err
	}

	assigned, poolObjects, err := assignIndexes(ctx, validated, indexes)
	if err != nil {
		return BuildResult{}, err
	}

	result := BuildResult{
		PoolObjects:           poolObjects,
		ReleasePath:           path.Join("dists", validated.Suite, "Release"),
		InReleasePath:         path.Join("dists", validated.Suite, "InRelease"),
		DetachedSignaturePath: path.Join("dists", validated.Suite, "Release.gpg"),
	}
	var canonicalIndexes []Artifact
	var byHashPaths []string
	for _, component := range validated.Components {
		for _, architecture := range validated.Architectures {
			if err := ctx.Err(); err != nil {
				return BuildResult{}, err
			}
			key := indexKey{component: component, architecture: architecture}
			base, err := IndexBasePath(validated.Suite, component, architecture)
			if err != nil {
				return BuildResult{}, err
			}
			packagesPath := path.Join(base, "Packages")
			packagesArtifact, err := writeArtifact(ctx, outputDir, packagesPath, func(w io.Writer) error {
				return WritePackages(w, assigned[key])
			})
			if err != nil {
				return BuildResult{}, err
			}

			gzipArtifact, err := writeArtifact(ctx, outputDir, packagesPath+".gz", func(w io.Writer) error {
				zw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
				if err != nil {
					return fmt.Errorf("aptrepo: create gzip writer: %w", err)
				}
				zw.Header.ModTime = time.Time{}
				zw.Header.OS = 255
				if err := copyArtifact(ctx, outputDir, packagesPath, zw); err != nil {
					_ = zw.Close()
					return err
				}
				if err := zw.Close(); err != nil {
					return fmt.Errorf("aptrepo: close gzip index: %w", err)
				}
				return nil
			})
			if err != nil {
				return BuildResult{}, err
			}

			xzArtifact, err := writeArtifact(ctx, outputDir, packagesPath+".xz", func(w io.Writer) error {
				zw, err := xz.NewWriter(w)
				if err != nil {
					return fmt.Errorf("aptrepo: create xz writer: %w", err)
				}
				if err := copyArtifact(ctx, outputDir, packagesPath, zw); err != nil {
					_ = zw.Close()
					return err
				}
				if err := zw.Close(); err != nil {
					return fmt.Errorf("aptrepo: close xz index: %w", err)
				}
				return nil
			})
			if err != nil {
				return BuildResult{}, err
			}

			for _, artifact := range []Artifact{packagesArtifact, gzipArtifact, xzArtifact} {
				byHashPath := path.Join(base, "by-hash", "SHA256", artifact.SHA256)
				byHashArtifact, err := linkByHash(outputDir, artifact, byHashPath)
				if err != nil {
					return BuildResult{}, err
				}
				canonicalIndexes = append(canonicalIndexes, artifact)
				result.Artifacts = append(result.Artifacts, artifact, byHashArtifact)
				byHashPaths = append(byHashPaths, byHashPath)
			}
		}
	}

	return finalizeBuild(ctx, outputDir, validated, result, canonicalIndexes, byHashPaths, signer)
}

func finalizeBuild(ctx context.Context, outputDir string, validated RepositoryConfig, result BuildResult, canonicalIndexes []Artifact, byHashPaths []string, signer *Signer) (BuildResult, error) {
	release := renderRelease(validated, canonicalIndexes)
	releaseArtifact, err := writeArtifact(ctx, outputDir, result.ReleasePath, func(w io.Writer) error {
		_, err := w.Write(release)
		return err
	})
	if err != nil {
		return BuildResult{}, err
	}
	var detached, inRelease bytes.Buffer
	if err := signer.DetachedSign(&detached, bytes.NewReader(release), validated.Date); err != nil {
		return BuildResult{}, err
	}
	if err := signer.ClearSign(&inRelease, bytes.NewReader(release), validated.Date); err != nil {
		return BuildResult{}, err
	}
	if err := signer.Verify(release, inRelease.Bytes(), detached.Bytes(), validated.Date); err != nil {
		return BuildResult{}, err
	}
	detachedArtifact, err := writeArtifact(ctx, outputDir, result.DetachedSignaturePath, func(w io.Writer) error {
		_, err := io.Copy(w, bytes.NewReader(detached.Bytes()))
		return err
	})
	if err != nil {
		return BuildResult{}, err
	}
	// InRelease is the APT checkpoint and is deliberately replaced last.
	inReleaseArtifact, err := writeArtifact(ctx, outputDir, result.InReleasePath, func(w io.Writer) error {
		_, err := io.Copy(w, bytes.NewReader(inRelease.Bytes()))
		return err
	})
	if err != nil {
		return BuildResult{}, err
	}
	result.Artifacts = append(result.Artifacts, releaseArtifact, inReleaseArtifact, detachedArtifact)
	sort.Slice(result.Artifacts, func(i, j int) bool { return result.Artifacts[i].Path < result.Artifacts[j].Path })
	sort.Strings(byHashPaths)
	result.ByHashGeneration = ByHashGeneration{
		ID:          releaseArtifact.SHA256,
		CreatedAt:   validated.Date,
		Paths:       byHashPaths,
		PathsSHA256: sealByHashPaths(byHashPaths),
	}
	return result, nil
}

type mutableBackup struct {
	path    string
	existed bool
}

func commitStagedBuild(ctx context.Context, stageRoot, outputRoot string, result BuildResult) error {
	return commitStagedBuildGuarded(ctx, stageRoot, outputRoot, result, nil)
}

func commitStagedBuildGuarded(ctx context.Context, stageRoot, outputRoot string, result BuildResult, guard func(CommitPhase) error) error {
	for _, artifact := range result.Artifacts {
		if err := ctx.Err(); err != nil {
			return err
		}
		stagePath, err := outputPath(stageRoot, artifact.Path)
		if err != nil {
			return err
		}
		if err := verifyArtifact(stagePath, artifact); err != nil {
			return fmt.Errorf("aptrepo: verify staged artifact %q: %w", artifact.Path, err)
		}
	}

	outputAbs, err := filepath.Abs(outputRoot)
	if err != nil {
		return err
	}
	backupRoot, err := os.MkdirTemp(filepath.Dir(outputAbs), ".sow-apt-backup-")
	if err != nil {
		return fmt.Errorf("aptrepo: create commit backup: %w", err)
	}
	defer os.RemoveAll(backupRoot)

	var immutable, mutable []Artifact
	for _, artifact := range result.Artifacts {
		if strings.Contains(artifact.Path, "/by-hash/SHA256/") {
			immutable = append(immutable, artifact)
		} else {
			mutable = append(mutable, artifact)
		}
	}
	sort.Slice(mutable, func(i, j int) bool {
		return commitOrder(mutable[i].Path, result) < commitOrder(mutable[j].Path, result) ||
			(commitOrder(mutable[i].Path, result) == commitOrder(mutable[j].Path, result) && mutable[i].Path < mutable[j].Path)
	})

	backups := make([]mutableBackup, 0, len(mutable))
	for _, artifact := range mutable {
		backup, err := backupMutableArtifact(outputRoot, backupRoot, artifact.Path)
		if err != nil {
			return err
		}
		backups = append(backups, backup)
	}

	var createdByHash []Artifact
	rollback := func(commitErr error) error {
		var rollbackErrors []error
		for i := len(backups) - 1; i >= 0; i-- {
			if err := restoreMutableArtifact(outputRoot, backupRoot, backups[i]); err != nil {
				rollbackErrors = append(rollbackErrors, err)
			}
		}
		for _, artifact := range createdByHash {
			rootHandle, rootErr := os.OpenRoot(outputRoot)
			if rootErr != nil {
				rollbackErrors = append(rollbackErrors, rootErr)
				continue
			}
			if err := verifyRootArtifact(rootHandle, artifact.Path, artifact); err == nil {
				if err := rootHandle.Remove(filepath.FromSlash(artifact.Path)); err != nil && !errors.Is(err, os.ErrNotExist) {
					rollbackErrors = append(rollbackErrors, fmt.Errorf("aptrepo: roll back by-hash %q: %w", artifact.Path, err))
				}
			}
			_ = rootHandle.Close()
		}
		if len(rollbackErrors) == 0 {
			return commitErr
		}
		return errors.Join(append([]error{commitErr}, rollbackErrors...)...)
	}
	if guard != nil {
		if err := guard(CommitBeforeMutation); err != nil {
			return fmt.Errorf("aptrepo: pre-commit guard: %w", err)
		}
	}

	for _, artifact := range immutable {
		if err := ctx.Err(); err != nil {
			return rollback(err)
		}
		created, err := installImmutableArtifact(ctx, stageRoot, outputRoot, artifact)
		if err != nil {
			return rollback(err)
		}
		if created {
			createdByHash = append(createdByHash, artifact)
		}
	}
	for _, artifact := range mutable {
		if err := ctx.Err(); err != nil {
			return rollback(err)
		}
		stagePath, err := outputPath(stageRoot, artifact.Path)
		if err != nil {
			return rollback(err)
		}
		if err := atomicReplaceFromFile(ctx, stagePath, outputRoot, artifact.Path); err != nil {
			return rollback(err)
		}
		rootHandle, err := os.OpenRoot(outputRoot)
		if err != nil {
			return rollback(err)
		}
		verifyErr := verifyRootArtifact(rootHandle, artifact.Path, artifact)
		_ = rootHandle.Close()
		if verifyErr != nil {
			return rollback(fmt.Errorf("aptrepo: verify committed artifact %q: %w", artifact.Path, verifyErr))
		}
	}
	if guard != nil {
		if err := guard(CommitAfterMutation); err != nil {
			return rollback(fmt.Errorf("aptrepo: post-commit guard: %w", err))
		}
	}
	return nil
}

func resealStagedBuild(stageRoot string, result BuildResult) (BuildResult, error) {
	for index, artifact := range result.Artifacts {
		filename, err := outputPath(stageRoot, artifact.Path)
		if err != nil {
			return BuildResult{}, err
		}
		file, err := os.Open(filename)
		if err != nil {
			return BuildResult{}, fmt.Errorf("aptrepo: open transformed artifact %q: %w", artifact.Path, err)
		}
		digest := sha256.New()
		size, copyErr := io.Copy(digest, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return BuildResult{}, fmt.Errorf("aptrepo: hash transformed artifact %q: %w", artifact.Path, errors.Join(copyErr, closeErr))
		}
		result.Artifacts[index].Size = size
		result.Artifacts[index].SHA256 = hex.EncodeToString(digest.Sum(nil))
	}
	return result, nil
}

func validateStagedSignatureTransform(before, after BuildResult) error {
	if len(before.Artifacts) != len(after.Artifacts) || before.InReleasePath != after.InReleasePath || before.DetachedSignaturePath != after.DetachedSignaturePath || before.ReleasePath != after.ReleasePath {
		return errors.New("aptrepo: staged signature transform changed the build topology")
	}
	for index := range before.Artifacts {
		oldArtifact, newArtifact := before.Artifacts[index], after.Artifacts[index]
		if oldArtifact.Path != newArtifact.Path {
			return errors.New("aptrepo: staged signature transform changed an artifact path")
		}
		if oldArtifact.Path == before.InReleasePath || oldArtifact.Path == before.DetachedSignaturePath {
			continue
		}
		if oldArtifact != newArtifact {
			return fmt.Errorf("aptrepo: staged signature transform changed non-signature artifact %q", oldArtifact.Path)
		}
	}
	return nil
}

func commitOrder(filePath string, result BuildResult) int {
	switch filePath {
	case result.ReleasePath:
		return 10
	case result.DetachedSignaturePath:
		return 20
	case result.InReleasePath:
		return 30
	default:
		return 0
	}
}

func backupMutableArtifact(outputRoot, backupRoot, relative string) (mutableBackup, error) {
	if err := ensureOutputParent(outputRoot, relative, true); err != nil {
		return mutableBackup{}, err
	}
	rootHandle, err := os.OpenRoot(outputRoot)
	if err != nil {
		return mutableBackup{}, err
	}
	defer rootHandle.Close()
	info, err := rootHandle.Lstat(filepath.FromSlash(relative))
	if errors.Is(err, os.ErrNotExist) {
		return mutableBackup{path: relative}, nil
	}
	if err != nil {
		return mutableBackup{}, fmt.Errorf("aptrepo: inspect existing artifact %q: %w", relative, err)
	}
	if !info.Mode().IsRegular() {
		return mutableBackup{}, fmt.Errorf("aptrepo: existing artifact is not a regular file %q", relative)
	}
	if err := ensureOutputParent(backupRoot, relative, true); err != nil {
		return mutableBackup{}, err
	}
	backupPath, err := outputPath(backupRoot, relative)
	if err != nil {
		return mutableBackup{}, err
	}
	source, err := rootHandle.Open(filepath.FromSlash(relative))
	if err != nil {
		return mutableBackup{}, fmt.Errorf("aptrepo: open artifact backup source %q: %w", relative, err)
	}
	if err := copyFileExclusive(source, backupPath, 0o400); err != nil {
		_ = source.Close()
		return mutableBackup{}, fmt.Errorf("aptrepo: back up artifact %q: %w", relative, err)
	}
	if err := source.Close(); err != nil {
		return mutableBackup{}, fmt.Errorf("aptrepo: close artifact backup source %q: %w", relative, err)
	}
	return mutableBackup{path: relative, existed: true}, nil
}

func restoreMutableArtifact(outputRoot, backupRoot string, backup mutableBackup) error {
	if !backup.existed {
		rootHandle, rootErr := os.OpenRoot(outputRoot)
		if rootErr != nil {
			return rootErr
		}
		defer rootHandle.Close()
		if err := rootHandle.Remove(filepath.FromSlash(backup.path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("aptrepo: roll back new artifact %q: %w", backup.path, err)
		}
		return nil
	}
	backupPath, err := outputPath(backupRoot, backup.path)
	if err != nil {
		return err
	}
	if err := atomicReplaceFromFile(context.Background(), backupPath, outputRoot, backup.path); err != nil {
		return fmt.Errorf("aptrepo: restore artifact %q: %w", backup.path, err)
	}
	return nil
}

func installImmutableArtifact(ctx context.Context, stageRoot, outputRoot string, artifact Artifact) (bool, error) {
	if err := validateByHashPath(artifact.Path); err != nil {
		return false, err
	}
	if err := ensureOutputParent(outputRoot, artifact.Path, true); err != nil {
		return false, err
	}
	stagePath, err := outputPath(stageRoot, artifact.Path)
	if err != nil {
		return false, err
	}
	rootHandle, err := os.OpenRoot(outputRoot)
	if err != nil {
		return false, err
	}
	defer rootHandle.Close()
	if info, err := rootHandle.Lstat(filepath.FromSlash(artifact.Path)); err == nil {
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("aptrepo: immutable path is not a regular file %q", artifact.Path)
		}
		if err := verifyRootArtifact(rootHandle, artifact.Path, artifact); err != nil {
			return false, fmt.Errorf("aptrepo: immutable path collision %q: %w", artifact.Path, err)
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("aptrepo: inspect immutable path %q: %w", artifact.Path, err)
	}
	source, err := os.Open(stagePath)
	if err != nil {
		return false, fmt.Errorf("aptrepo: open staged immutable %q: %w", artifact.Path, err)
	}
	destination, err := rootHandle.OpenFile(filepath.FromSlash(artifact.Path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		_ = source.Close()
		if errors.Is(err, os.ErrExist) && verifyRootArtifact(rootHandle, artifact.Path, artifact) == nil {
			return false, nil
		}
		return false, fmt.Errorf("aptrepo: install immutable path %q: %w", artifact.Path, err)
	}
	copyErr := copyWithContext(ctx, destination, source)
	if copyErr == nil {
		copyErr = destination.Sync()
	}
	closeDestinationErr := destination.Close()
	closeSourceErr := source.Close()
	if copyErr != nil || closeDestinationErr != nil || closeSourceErr != nil {
		_ = rootHandle.Remove(filepath.FromSlash(artifact.Path))
		return false, fmt.Errorf("aptrepo: write immutable path %q: %w", artifact.Path, errors.Join(copyErr, closeDestinationErr, closeSourceErr))
	}
	if err := verifyRootArtifact(rootHandle, artifact.Path, artifact); err != nil {
		_ = rootHandle.Remove(filepath.FromSlash(artifact.Path))
		return false, fmt.Errorf("aptrepo: verify immutable path %q: %w", artifact.Path, err)
	}
	if err := syncRootParent(rootHandle, artifact.Path); err != nil {
		_ = rootHandle.Remove(filepath.FromSlash(artifact.Path))
		return false, fmt.Errorf("aptrepo: sync immutable path %q: %w", artifact.Path, err)
	}
	return true, nil
}

func atomicReplaceFromFile(ctx context.Context, sourcePath, outputRoot, relative string) error {
	if err := ensureOutputParent(outputRoot, relative, true); err != nil {
		return err
	}
	rootHandle, err := os.OpenRoot(outputRoot)
	if err != nil {
		return fmt.Errorf("aptrepo: open output root: %w", err)
	}
	defer rootHandle.Close()
	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("aptrepo: open staged artifact %q: %w", relative, err)
	}
	defer source.Close()
	if info, err := source.Stat(); err != nil || !info.Mode().IsRegular() {
		if err != nil {
			return fmt.Errorf("aptrepo: inspect staged artifact %q: %w", relative, err)
		}
		return fmt.Errorf("aptrepo: staged artifact is not a regular file %q", relative)
	}
	for attempt := 0; attempt < 16; attempt++ {
		suffix := make([]byte, 8)
		if _, err := rand.Read(suffix); err != nil {
			return fmt.Errorf("aptrepo: create commit link name: %w", err)
		}
		tmpRelative := path.Join(path.Dir(relative), ".sow-apt-install-"+hex.EncodeToString(suffix))
		tmp, err := rootHandle.OpenFile(filepath.FromSlash(tmpRelative), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return fmt.Errorf("aptrepo: create staged commit file %q: %w", relative, err)
		}
		copyErr := copyWithContext(ctx, tmp, source)
		if copyErr == nil {
			copyErr = tmp.Sync()
		}
		closeErr := tmp.Close()
		if copyErr != nil || closeErr != nil {
			_ = rootHandle.Remove(filepath.FromSlash(tmpRelative))
			return fmt.Errorf("aptrepo: write staged commit file %q: %w", relative, errors.Join(copyErr, closeErr))
		}
		if err := rootHandle.Rename(filepath.FromSlash(tmpRelative), filepath.FromSlash(relative)); err != nil {
			_ = rootHandle.Remove(filepath.FromSlash(tmpRelative))
			return fmt.Errorf("aptrepo: commit artifact %q: %w", relative, err)
		}
		if err := syncRootParent(rootHandle, relative); err != nil {
			return fmt.Errorf("aptrepo: sync committed artifact %q: %w", relative, err)
		}
		return nil
	}
	return fmt.Errorf("aptrepo: exhausted commit link names for %q", relative)
}

func syncRootParent(root *os.Root, relative string) error {
	directory, err := root.Open(filepath.FromSlash(path.Dir(relative)))
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if errors.Is(syncErr, unix.EINVAL) || errors.Is(syncErr, unix.ENOTSUP) {
		syncErr = nil
	}
	return errors.Join(syncErr, closeErr)
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) error {
	_, err := io.CopyBuffer(destination, &contextReader{ctx: ctx, r: source}, make([]byte, 128*1024))
	return err
}

func copyFileExclusive(source io.Reader, destination string, mode os.FileMode) error {
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	copyErr := copyWithContext(context.Background(), f, source)
	if copyErr == nil {
		copyErr = f.Sync()
	}
	closeErr := f.Close()
	return errors.Join(copyErr, closeErr)
}

func verifyRootArtifact(root *os.Root, relative string, expected Artifact) error {
	info, err := root.Lstat(filepath.FromSlash(relative))
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("artifact is not a regular file")
	}
	f, err := root.Open(filepath.FromSlash(relative))
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.CopyBuffer(h, f, make([]byte, 128*1024))
	if err != nil {
		return err
	}
	if size != expected.Size || hex.EncodeToString(h.Sum(nil)) != expected.SHA256 {
		return errors.New("content does not match digest")
	}
	return nil
}

// IndexBasePath returns the canonical archive-root-relative directory for one
// binary Packages index. All arguments are validated before a path is formed.
func IndexBasePath(suite, component, architecture string) (string, error) {
	if err := validateSegment("suite", suite); err != nil {
		return "", err
	}
	if err := validateComponent(component); err != nil {
		return "", err
	}
	if !architecturePattern.MatchString(architecture) {
		return "", fmt.Errorf("aptrepo: unsafe architecture %q", architecture)
	}
	if architecture == "all" {
		return "", errors.New("aptrepo: architecture all cannot be a standalone index")
	}
	return path.Join("dists", suite, component, "binary-"+architecture), nil
}

func validateRepositoryConfig(cfg RepositoryConfig) (RepositoryConfig, error) {
	if err := validateSegment("suite", cfg.Suite); err != nil {
		return RepositoryConfig{}, err
	}
	if err := validateSegment("codename", cfg.Codename); err != nil {
		return RepositoryConfig{}, err
	}
	for _, item := range []struct{ field, value string }{
		{field: "origin", value: cfg.Origin},
		{field: "label", value: cfg.Label},
	} {
		if err := validateReleaseValue(item.field, item.value, true); err != nil {
			return RepositoryConfig{}, err
		}
	}
	for _, item := range []struct{ field, value string }{
		{field: "version", value: cfg.Version},
		{field: "description", value: cfg.Description},
	} {
		if err := validateReleaseValue(item.field, item.value, false); err != nil {
			return RepositoryConfig{}, err
		}
	}
	if cfg.Date.IsZero() {
		return RepositoryConfig{}, errors.New("aptrepo: deterministic Release date is required")
	}
	cfg.Date = cfg.Date.UTC().Truncate(time.Second)
	if !cfg.ValidUntil.IsZero() {
		cfg.ValidUntil = cfg.ValidUntil.UTC().Truncate(time.Second)
		if !cfg.ValidUntil.After(cfg.Date) {
			return RepositoryConfig{}, errors.New("aptrepo: Valid-Until must be after Date")
		}
	}
	if len(cfg.Components) == 0 || len(cfg.Architectures) == 0 {
		return RepositoryConfig{}, errors.New("aptrepo: at least one component and architecture are required")
	}
	cfg.Components = append([]string(nil), cfg.Components...)
	cfg.Architectures = append([]string(nil), cfg.Architectures...)
	for _, component := range cfg.Components {
		if err := validateComponent(component); err != nil {
			return RepositoryConfig{}, err
		}
	}
	for _, architecture := range cfg.Architectures {
		if !architecturePattern.MatchString(architecture) {
			return RepositoryConfig{}, fmt.Errorf("aptrepo: unsafe architecture %q", architecture)
		}
		if architecture == "all" {
			return RepositoryConfig{}, errors.New("aptrepo: architecture all cannot be a standalone index")
		}
	}
	sort.Strings(cfg.Components)
	sort.Strings(cfg.Architectures)
	if hasDuplicate(cfg.Components) || hasDuplicate(cfg.Architectures) {
		return RepositoryConfig{}, errors.New("aptrepo: duplicate component or architecture")
	}
	return cfg, nil
}

func validateReleaseValue(field, value string, required bool) error {
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("aptrepo: %s is required", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("aptrepo: %s has leading or trailing whitespace", field)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("aptrepo: unsafe %s value", field)
		}
	}
	return nil
}

func hasDuplicate(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i] == values[i-1] {
			return true
		}
	}
	return false
}

func assignIndexes(ctx context.Context, cfg RepositoryConfig, indexes []Index) (map[indexKey][]Package, []PoolObject, error) {
	configured := make(map[indexKey]struct{}, len(cfg.Components)*len(cfg.Architectures))
	assigned := make(map[indexKey][]Package, len(cfg.Components)*len(cfg.Architectures))
	for _, component := range cfg.Components {
		for _, architecture := range cfg.Architectures {
			key := indexKey{component: component, architecture: architecture}
			configured[key] = struct{}{}
			assigned[key] = nil
		}
	}
	seenIndexes := make(map[indexKey]struct{}, len(indexes))
	pool := make(map[string]PoolObject)
	for _, index := range indexes {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if err := validateComponent(index.Component); err != nil {
			return nil, nil, err
		}
		if !architecturePattern.MatchString(index.Architecture) || index.Architecture == "all" {
			return nil, nil, fmt.Errorf("aptrepo: unsafe index architecture %q", index.Architecture)
		}
		key := indexKey{component: index.Component, architecture: index.Architecture}
		if _, ok := configured[key]; !ok {
			return nil, nil, fmt.Errorf("aptrepo: index %s/%s is not configured", index.Component, index.Architecture)
		}
		if _, duplicate := seenIndexes[key]; duplicate {
			return nil, nil, fmt.Errorf("aptrepo: duplicate index %s/%s", index.Component, index.Architecture)
		}
		seenIndexes[key] = struct{}{}
		seenPackages := make(map[string]struct{}, len(index.Packages))
		seenIdentities := make(map[string]struct{}, len(index.Packages))
		for _, pkg := range index.Packages {
			if err := validatePackageMetadata(pkg); err != nil {
				return nil, nil, err
			}
			if pkg.Component != index.Component {
				return nil, nil, fmt.Errorf("aptrepo: package component %q does not match index %q", pkg.Component, index.Component)
			}
			if pkg.Architecture != "all" && pkg.Architecture != index.Architecture {
				return nil, nil, fmt.Errorf("aptrepo: package architecture %q does not match index %q", pkg.Architecture, index.Architecture)
			}
			if _, duplicate := seenPackages[pkg.PoolPath]; duplicate {
				return nil, nil, fmt.Errorf("aptrepo: duplicate package %q in index %s/%s", pkg.PoolPath, index.Component, index.Architecture)
			}
			seenPackages[pkg.PoolPath] = struct{}{}
			identity := pkg.Name + "\x00" + pkg.Version + "\x00" + pkg.Architecture
			if _, duplicate := seenIdentities[identity]; duplicate {
				return nil, nil, fmt.Errorf("aptrepo: duplicate package identity %s=%s/%s in index %s/%s", pkg.Name, pkg.Version, pkg.Architecture, index.Component, index.Architecture)
			}
			seenIdentities[identity] = struct{}{}
			object := PoolObject{SourcePath: pkg.SourcePath, Path: pkg.PoolPath, Size: pkg.Size, SHA256: pkg.SHA256}
			if existing, exists := pool[pkg.PoolPath]; exists {
				if existing.Size != object.Size || existing.SHA256 != object.SHA256 {
					return nil, nil, fmt.Errorf("aptrepo: conflicting pool object %q", pkg.PoolPath)
				}
				if object.SourcePath < existing.SourcePath {
					if err := verifyPackageSource(ctx, pkg); err != nil {
						return nil, nil, err
					}
					pool[pkg.PoolPath] = object
				}
			} else {
				if err := verifyPackageSource(ctx, pkg); err != nil {
					return nil, nil, err
				}
				pool[pkg.PoolPath] = object
			}
		}
		assigned[key] = append([]Package(nil), index.Packages...)
	}
	poolObjects := make([]PoolObject, 0, len(pool))
	for _, object := range pool {
		poolObjects = append(poolObjects, object)
	}
	sort.Slice(poolObjects, func(i, j int) bool { return poolObjects[i].Path < poolObjects[j].Path })
	return assigned, poolObjects, nil
}

func verifyPackageSource(ctx context.Context, pkg Package) error {
	digest, size, err := hashPackage(ctx, pkg.SourcePath)
	if err != nil {
		return fmt.Errorf("aptrepo: verify package source %q: %w", pkg.PoolPath, err)
	}
	if size != pkg.Size || digest != pkg.SHA256 {
		return fmt.Errorf("aptrepo: package source changed for %q", pkg.PoolPath)
	}
	return nil
}

func renderRelease(cfg RepositoryConfig, indexes []Artifact) []byte {
	var b strings.Builder
	writeReleaseField := func(name, value string) {
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteByte('\n')
	}
	writeReleaseField("Origin", cfg.Origin)
	writeReleaseField("Label", cfg.Label)
	writeReleaseField("Suite", cfg.Suite)
	writeReleaseField("Codename", cfg.Codename)
	if cfg.Version != "" {
		writeReleaseField("Version", cfg.Version)
	}
	writeReleaseField("Date", releaseTime(cfg.Date))
	if !cfg.ValidUntil.IsZero() {
		writeReleaseField("Valid-Until", releaseTime(cfg.ValidUntil))
	}
	writeReleaseField("Architectures", strings.Join(cfg.Architectures, " "))
	writeReleaseField("Components", strings.Join(cfg.Components, " "))
	if cfg.Description != "" {
		writeReleaseField("Description", cfg.Description)
	}
	writeReleaseField("Acquire-By-Hash", "yes")
	b.WriteString("SHA256:\n")
	sort.Slice(indexes, func(i, j int) bool { return indexes[i].Path < indexes[j].Path })
	prefix := path.Join("dists", cfg.Suite) + "/"
	for _, artifact := range indexes {
		relative := strings.TrimPrefix(artifact.Path, prefix)
		b.WriteByte(' ')
		b.WriteString(artifact.SHA256)
		b.WriteByte(' ')
		b.WriteString(strconv.FormatInt(artifact.Size, 10))
		b.WriteByte(' ')
		b.WriteString(relative)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func releaseTime(value time.Time) string {
	return value.UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700")
}

func writeArtifact(ctx context.Context, root, relative string, write func(io.Writer) error) (Artifact, error) {
	fullPath, err := outputPath(root, relative)
	if err != nil {
		return Artifact{}, err
	}
	if write == nil {
		return Artifact{}, errors.New("aptrepo: nil artifact writer")
	}
	if err := ensureOutputParent(root, relative, true); err != nil {
		return Artifact{}, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(fullPath), ".sow-apt-*")
	if err != nil {
		return Artifact{}, fmt.Errorf("aptrepo: create artifact temp file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o644); err != nil {
		return Artifact{}, fmt.Errorf("aptrepo: set artifact mode: %w", err)
	}
	h := sha256.New()
	counter := &countingWriter{w: io.MultiWriter(tmp, h)}
	if err := write(&contextWriter{ctx: ctx, w: counter}); err != nil {
		return Artifact{}, fmt.Errorf("aptrepo: write artifact %q: %w", relative, err)
	}
	if err := ctx.Err(); err != nil {
		return Artifact{}, err
	}
	if err := tmp.Chmod(0o444); err != nil {
		return Artifact{}, fmt.Errorf("aptrepo: make artifact immutable %q: %w", relative, err)
	}
	if err := tmp.Sync(); err != nil {
		return Artifact{}, fmt.Errorf("aptrepo: sync artifact %q: %w", relative, err)
	}
	if err := tmp.Close(); err != nil {
		return Artifact{}, fmt.Errorf("aptrepo: close artifact %q: %w", relative, err)
	}
	if err := os.Rename(tmpPath, fullPath); err != nil {
		return Artifact{}, fmt.Errorf("aptrepo: replace artifact %q: %w", relative, err)
	}
	committed = true
	return Artifact{Path: relative, Size: counter.n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

func copyArtifact(ctx context.Context, root, relative string, destination io.Writer) error {
	if err := ensureOutputParent(root, relative, false); err != nil {
		return err
	}
	fullPath, err := outputPath(root, relative)
	if err != nil {
		return err
	}
	source, err := os.Open(fullPath)
	if err != nil {
		return fmt.Errorf("aptrepo: open generated index %q: %w", relative, err)
	}
	defer source.Close()
	if info, err := source.Stat(); err != nil || !info.Mode().IsRegular() {
		if err != nil {
			return fmt.Errorf("aptrepo: stat generated index %q: %w", relative, err)
		}
		return fmt.Errorf("aptrepo: generated index is not a regular file %q", relative)
	}
	if _, err := io.CopyBuffer(destination, &contextReader{ctx: ctx, r: source}, make([]byte, 128*1024)); err != nil {
		return fmt.Errorf("aptrepo: compress index %q: %w", relative, err)
	}
	return nil
}

func linkByHash(root string, source Artifact, relative string) (Artifact, error) {
	if err := validateByHashPath(relative); err != nil {
		return Artifact{}, err
	}
	sourcePath, err := outputPath(root, source.Path)
	if err != nil {
		return Artifact{}, err
	}
	destinationPath, err := outputPath(root, relative)
	if err != nil {
		return Artifact{}, err
	}
	if err := ensureOutputParent(root, relative, true); err != nil {
		return Artifact{}, err
	}
	if info, err := os.Lstat(destinationPath); err == nil {
		if !info.Mode().IsRegular() {
			return Artifact{}, fmt.Errorf("aptrepo: immutable by-hash path is not a regular file %q", relative)
		}
		if err := verifyArtifact(destinationPath, source); err != nil {
			return Artifact{}, fmt.Errorf("aptrepo: immutable by-hash collision %q: %w", relative, err)
		}
		return Artifact{Path: relative, Size: source.Size, SHA256: source.SHA256}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Artifact{}, fmt.Errorf("aptrepo: inspect by-hash path %q: %w", relative, err)
	}
	if err := os.Link(sourcePath, destinationPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			if verifyErr := verifyArtifact(destinationPath, source); verifyErr == nil {
				return Artifact{Path: relative, Size: source.Size, SHA256: source.SHA256}, nil
			}
		}
		return Artifact{}, fmt.Errorf("aptrepo: create immutable by-hash path %q: %w", relative, err)
	}
	if err := verifyArtifact(destinationPath, source); err != nil {
		_ = os.Remove(destinationPath)
		return Artifact{}, fmt.Errorf("aptrepo: verify immutable by-hash path %q: %w", relative, err)
	}
	return Artifact{Path: relative, Size: source.Size, SHA256: source.SHA256}, nil
}

func verifyArtifact(filePath string, expected Artifact) error {
	info, err := os.Lstat(filePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("artifact is not a regular file")
	}
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.CopyBuffer(h, f, make([]byte, 128*1024))
	if err != nil {
		return err
	}
	if size != expected.Size || hex.EncodeToString(h.Sum(nil)) != expected.SHA256 {
		return errors.New("content does not match digest")
	}
	return nil
}

func outputPath(root, relative string) (string, error) {
	if err := validateRelativePath(relative); err != nil {
		return "", fmt.Errorf("aptrepo: unsafe artifact path %q", relative)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("aptrepo: resolve output directory: %w", err)
	}
	joined := filepath.Join(rootAbs, filepath.FromSlash(relative))
	contained, err := filepath.Rel(rootAbs, joined)
	if err != nil || contained == ".." || strings.HasPrefix(contained, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("aptrepo: unsafe artifact path %q", relative)
	}
	return joined, nil
}

func validateOutputRoot(root string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("aptrepo: resolve output directory: %w", err)
	}
	info, err := os.Lstat(rootAbs)
	if err != nil {
		return fmt.Errorf("aptrepo: inspect output directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("aptrepo: output directory must be a real directory, not a symlink")
	}
	return nil
}

func ensureOutputParent(root, relative string, create bool) error {
	if _, err := outputPath(root, relative); err != nil {
		return err
	}
	if err := validateOutputRoot(root); err != nil {
		return err
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("aptrepo: open output directory: %w", err)
	}
	defer rootHandle.Close()
	parent := path.Dir(relative)
	if parent == "." {
		return nil
	}
	current := ""
	for _, segment := range strings.Split(parent, "/") {
		current = path.Join(current, segment)
		info, err := rootHandle.Lstat(filepath.FromSlash(current))
		if errors.Is(err, os.ErrNotExist) && create {
			if err := rootHandle.Mkdir(filepath.FromSlash(current), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("aptrepo: create artifact directory: %w", err)
			}
			info, err = rootHandle.Lstat(filepath.FromSlash(current))
		}
		if err != nil {
			return fmt.Errorf("aptrepo: inspect artifact directory: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("aptrepo: unsafe artifact directory %q", current)
		}
	}
	return nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.n += int64(n)
	return n, err
}

type contextWriter struct {
	ctx context.Context
	w   io.Writer
}

func (w *contextWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.w.Write(p)
}
