package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// cleanupStaleRestoreMaterializations removes transaction-local historical
// reconstruction trees left behind by an uncatchable process termination.
// runPublish calls it only while holding the exclusive publish lock, so no
// live restore can own a path below this namespace.
func cleanupStaleRestoreMaterializations(repositoryRoot string) (bool, error) {
	root, err := os.OpenRoot(repositoryRoot)
	if err != nil {
		return false, fmt.Errorf("open repository root: %w", err)
	}
	defer root.Close()

	statePath := ".sow"
	materializedPath := filepath.Join(statePath, "materialized")
	restoresPath := filepath.Join(materializedPath, "restores")
	for _, name := range []string{statePath, materializedPath, restoresPath} {
		info, inspectErr := root.Lstat(name)
		if errors.Is(inspectErr, os.ErrNotExist) {
			return false, nil
		}
		if inspectErr != nil {
			return false, fmt.Errorf("inspect %s: %w", name, inspectErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return false, fmt.Errorf("unsafe restore materialization namespace %s: expected a real directory", name)
		}
	}

	// Root.RemoveAll is confined to repositoryRoot even if an untrusted local
	// process races a directory entry after the checks above.
	if err := root.RemoveAll(restoresPath); err != nil {
		return false, fmt.Errorf("remove %s: %w", restoresPath, err)
	}
	parent, err := root.Open(materializedPath)
	if err != nil {
		return false, fmt.Errorf("open restore materialization parent: %w", err)
	}
	if err := errors.Join(parent.Sync(), parent.Close()); err != nil {
		return false, fmt.Errorf("sync restore materialization cleanup: %w", err)
	}
	return true, nil
}
