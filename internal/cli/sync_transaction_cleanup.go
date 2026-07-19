package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// cleanupSyncTransactionResidue removes transaction scratch trees abandoned by
// SIGKILL only after the durable operation has converged. It is scoped to the
// validated upstream prefix and refuses symlink or special-file content rather
// than allowing a recovery cleanup to become an unsafe recursive traversal.
func cleanupSyncTransactionResidue(stateDir, upstreamID, currentTxDir string) error {
	if !syncProgressNamePattern.MatchString(upstreamID) {
		return errors.New("invalid upstream identity for sync transaction cleanup")
	}
	parent := filepath.Join(stateDir, "transactions")
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, errors.New("sync transaction parent must be a real directory"))
	}
	prefix := "sync-" + upstreamID + "-"
	current, err := filepath.Abs(filepath.Clean(currentTxDir))
	if err != nil {
		return err
	}
	parentAbs, err := filepath.Abs(filepath.Clean(parent))
	if err != nil {
		return err
	}
	if filepath.Dir(current) != parentAbs || !strings.HasPrefix(filepath.Base(current), prefix) {
		return errors.New("current sync transaction is outside the exact upstream prefix")
	}

	root, err := os.OpenRoot(parentAbs)
	if err != nil {
		return err
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	var candidates []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		info, err := root.Lstat(entry.Name())
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe sync transaction residue %s", entry.Name())
		}
		if err := validateSyncTransactionTree(filepath.Join(parentAbs, entry.Name())); err != nil {
			return fmt.Errorf("unsafe sync transaction residue %s: %w", entry.Name(), err)
		}
		candidates = append(candidates, entry.Name())
	}
	sort.Strings(candidates)
	if !contains(candidates, filepath.Base(current)) {
		return errors.New("current sync transaction disappeared before durable cleanup")
	}
	for _, name := range candidates {
		if err := root.RemoveAll(name); err != nil {
			return fmt.Errorf("remove sync transaction residue %s: %w", name, err)
		}
		if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(err, fmt.Errorf("sync transaction residue %s remains after cleanup", name))
		}
	}
	return syncRootDirectory(root)
}

func validateSyncTransactionTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("path %s is not a real directory or regular file", filepath.Base(path))
		}
		return nil
	})
}
