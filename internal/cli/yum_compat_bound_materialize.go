package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
)

// materializeYUMCompatibilityManifestBound installs one immutable digest-named
// S3 candidate below the persistent repository root. Every file is linked from
// a verified CAS inode into a sibling stage, the exact stage is proven against
// the canonical manifest, and one parent-FD no-replace rename publishes it.
func materializeYUMCompatibilityManifestBound(ctx context.Context, workflow yumCompatibilityWorkflow, desiredManifest, targetRelative, actualManifest string) error {
	if workflow.root == nil || workflow.root.root == nil || !validYUMCompatibilityLogicalPath(filepath.ToSlash(targetRelative)) {
		return errors.New("invalid bound YUM compatibility materialization target")
	}
	targetRelative = filepath.FromSlash(targetRelative)
	parentRelative, base := filepath.Dir(targetRelative), filepath.Base(targetRelative)
	if base == "." || base == ".." || base == "" {
		return errors.New("invalid bound YUM compatibility target basename")
	}
	if err := ensureYUMCompatibilityBoundCASDirectory(workflow.root.root, parentRelative, 0o755); err != nil {
		return err
	}
	if _, err := workflow.root.root.Lstat(targetRelative); err == nil {
		return validateYUMCompatibilityBoundMaterialization(ctx, workflow, targetRelative, desiredManifest, actualManifest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parentRoot, parentIdentity, err := openRealYUMCompatibilityDirectory(workflow.root.root, parentRelative, false)
	if err != nil {
		return err
	}
	defer parentRoot.Close()
	parentFile, err := parentRoot.Open(".")
	if err != nil {
		return err
	}
	defer parentFile.Close()
	nonce, err := randomYUMCompatibilityBoundNonce()
	if err != nil {
		return err
	}
	stageName := ".candidate-" + nonce
	if err := parentRoot.Mkdir(stageName, 0o700); err != nil {
		return err
	}
	keepStage := true
	defer func() {
		if keepStage {
			_ = parentRoot.RemoveAll(stageName)
		}
	}()
	stageRoot, err := parentRoot.OpenRoot(stageName)
	if err != nil {
		return err
	}
	if err := linkYUMCompatibilityManifestFromBoundCAS(ctx, workflow, desiredManifest, stageRoot); err != nil {
		_ = stageRoot.Close()
		return err
	}
	if err := makeYUMCompatibilityBoundTreeHostable(stageRoot, "."); err != nil {
		_ = stageRoot.Close()
		return err
	}
	if err := scanYUMCompatibilityBoundMaterialization(ctx, workflow, stageRoot, actualManifest); err != nil {
		_ = stageRoot.Close()
		return err
	}
	if err := stageRoot.Close(); err != nil {
		return err
	}
	if err := requireManifestFilesEqual(desiredManifest, actualManifest); err != nil {
		return fmt.Errorf("staged bound YUM compatibility materialization differs: %w", err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "admit bound yum-cutover candidate install"); err != nil {
		return err
	}
	if workflow.mutationHook != nil {
		if err := workflow.mutationHook("install yum-cutover candidate"); err != nil {
			return fmt.Errorf("YUM compatibility materialization mutation hook: %w", err)
		}
	}
	if err := renameYUMCompatibilityCandidateNoReplace(parentFile.Fd(), stageName, base); err != nil {
		// A retry or an external no-replace winner is accepted only when the
		// occupied immutable generation is already byte/inode exact.
		if validateErr := validateYUMCompatibilityBoundMaterialization(ctx, workflow, targetRelative, desiredManifest, actualManifest); validateErr != nil {
			return errors.Join(err, validateErr)
		}
		return nil
	}
	keepStage = false
	if err := errors.Join(parentFile.Sync(), verifyBoundYUMCompatibilityDirectory(workflow.root.root, parentRelative, parentIdentity)); err != nil {
		return err
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "finish bound yum-cutover candidate install"); err != nil {
		return err
	}
	return validateYUMCompatibilityBoundMaterialization(ctx, workflow, targetRelative, desiredManifest, actualManifest)
}

func validateYUMCompatibilityBoundMaterialization(ctx context.Context, workflow yumCompatibilityWorkflow, targetRelative, desiredManifest, actualManifest string) error {
	target, _, err := openRealYUMCompatibilityDirectory(workflow.root.root, targetRelative, false)
	if err != nil {
		return err
	}
	defer target.Close()
	if err := scanYUMCompatibilityBoundMaterialization(ctx, workflow, target, actualManifest); err != nil {
		return err
	}
	return requireManifestFilesEqual(desiredManifest, actualManifest)
}

func scanYUMCompatibilityBoundMaterialization(ctx context.Context, workflow yumCompatibilityWorkflow, root *os.Root, destination string) error {
	var entries []manifest.Entry
	if err := collectYUMCompatibilityBoundMaterialization(ctx, workflow, root, ".", &entries); err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := manifest.WriteEntry(file, entry); err != nil {
			_ = file.Close()
			return err
		}
	}
	return errors.Join(file.Sync(), file.Close())
}

func collectYUMCompatibilityBoundMaterialization(ctx context.Context, workflow yumCompatibilityWorkflow, root *os.Root, relative string, entries *[]manifest.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, err := root.Open(relative)
	if err != nil {
		return err
	}
	opened, statErr := directory.Stat()
	children, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	current, lstatErr := root.Lstat(relative)
	if statErr != nil || readErr != nil || closeErr != nil || lstatErr != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(opened, current) {
		return errors.Join(statErr, readErr, closeErr, lstatErr, fmt.Errorf("bound materialization directory %s changed while scanning", relative))
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
	for _, child := range children {
		name := filepath.Join(relative, child.Name())
		info, err := root.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("unsafe bound materialization entry %s", name))
		}
		if info.IsDir() {
			if err := collectYUMCompatibilityBoundMaterialization(ctx, workflow, root, name, entries); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("special bound materialization entry %s is forbidden", name)
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(info, opened) {
			return errors.Join(statErr, file.Close(), fmt.Errorf("bound materialization entry %s changed while opening", name))
		}
		hasher := sha256.New()
		size, copyErr := io.Copy(hasher, file)
		after, restatErr := file.Stat()
		current, lstatErr := root.Lstat(name)
		closeErr := file.Close()
		if copyErr != nil || restatErr != nil || lstatErr != nil || closeErr != nil || size != info.Size() || !os.SameFile(opened, after) || !os.SameFile(opened, current) {
			return errors.Join(copyErr, restatErr, lstatErr, closeErr, fmt.Errorf("bound materialization entry %s changed while hashing", name))
		}
		var digest repository.Digest
		copy(digest[:], hasher.Sum(nil))
		casInfo, err := workflow.root.root.Lstat(yumCompatibilityCASObjectRelative(digest))
		if err != nil || casInfo.Mode()&os.ModeSymlink != 0 || !casInfo.Mode().IsRegular() || !os.SameFile(info, casInfo) {
			return errors.Join(err, fmt.Errorf("bound materialization entry %s is not a hardlink to its CAS object", name))
		}
		logical := filepath.ToSlash(strings.TrimPrefix(name, "."+string(filepath.Separator)))
		entry := manifest.Entry{Path: logical, Size: size, SHA256: [sha256.Size]byte(digest)}
		if err := entry.Validate(); err != nil {
			return err
		}
		*entries = append(*entries, entry)
	}
	return nil
}

func makeYUMCompatibilityBoundTreeHostable(root *os.Root, relative string) error {
	info, err := root.Lstat(relative)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.Join(err, fmt.Errorf("bound hostable directory %s is unsafe", relative))
	}
	directory, err := root.Open(relative)
	if err != nil {
		return err
	}
	opened, statErr := directory.Stat()
	if statErr != nil || !os.SameFile(info, opened) {
		return errors.Join(statErr, directory.Close(), fmt.Errorf("bound hostable directory %s changed while opening", relative))
	}
	if err := directory.Chmod(0o755); err != nil {
		_ = directory.Close()
		return err
	}
	children, readErr := directory.ReadDir(-1)
	if readErr != nil {
		_ = directory.Close()
		return readErr
	}
	for _, child := range children {
		name := filepath.Join(relative, child.Name())
		childInfo, err := root.Lstat(name)
		if err != nil || childInfo.Mode()&os.ModeSymlink != 0 {
			_ = directory.Close()
			return errors.Join(err, fmt.Errorf("unsafe bound hostable entry %s", name))
		}
		if childInfo.IsDir() {
			if err := makeYUMCompatibilityBoundTreeHostable(root, name); err != nil {
				_ = directory.Close()
				return err
			}
		} else if !childInfo.Mode().IsRegular() || childInfo.Mode().Perm() != 0o444 {
			_ = directory.Close()
			return fmt.Errorf("bound hostable file %s is not an immutable CAS hardlink", name)
		}
	}
	return errors.Join(directory.Sync(), directory.Close())
}
