package serving

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const servingTempMaxBytes = 1 << 20

var (
	generationStagePattern = regexp.MustCompile(`^\.stage-[0-9]{20}-[0-9a-f]{32}$`)
	mirrorlistTempPattern  = regexp.MustCompile(`^\.mirrorlist-[0-9a-f]{32}$`)
)

// CleanupTransactionTemps removes only SOW-owned, exact-pattern temporary
// coordinates left by an interrupted immutable-generation install or
// mirrorlist flip. It refuses malformed reserved names and special files so a
// recovery request can never become a broad recursive cleanup primitive.
func CleanupTransactionTemps(repositoryRoot, targetRoot string) (int, error) {
	if info, err := os.Lstat(targetRoot); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.Join(err, errors.New("serving target root is not a real directory"))
	}
	confinedRoot, err := validateTargetRoot(repositoryRoot, targetRoot)
	if err != nil {
		return 0, err
	}
	removed, err := cleanupGenerationStages(confinedRoot)
	if err != nil {
		return removed, err
	}
	mirrors, err := cleanupMirrorlistTemps(confinedRoot)
	return removed + mirrors, err
}

func cleanupGenerationStages(root string) (int, error) {
	base, exists, err := existingRealDirectory(root, filepath.Join("_sow", "v1", "g"))
	if err != nil || !exists {
		return 0, err
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".stage-") {
			continue
		}
		if !generationStagePattern.MatchString(entry.Name()) {
			return removed, fmt.Errorf("unsafe generation stage entry %q", entry.Name())
		}
		info, err := os.Lstat(filepath.Join(base, entry.Name()))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return removed, errors.Join(err, fmt.Errorf("generation stage %q is not a real directory", entry.Name()))
		}
		if err := os.RemoveAll(filepath.Join(base, entry.Name())); err != nil {
			return removed, err
		}
		removed++
	}
	if removed != 0 {
		return removed, syncDirectory(base)
	}
	return 0, nil
}

func cleanupMirrorlistTemps(root string) (int, error) {
	base, exists, err := existingRealDirectory(root, filepath.Join("_sow", "v1", "mirrorlist"))
	if err != nil || !exists {
		return 0, err
	}
	removed := 0
	dirty := make(map[string]struct{})
	err = filepath.WalkDir(base, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("mirrorlist tree contains unsafe coordinate %s", current))
		}
		if entry.IsDir() {
			if !info.IsDir() {
				return fmt.Errorf("mirrorlist parent %s is not a real directory", current)
			}
			return nil
		}
		if !strings.HasPrefix(entry.Name(), ".mirrorlist-") {
			return nil
		}
		if !mirrorlistTempPattern.MatchString(entry.Name()) || !info.Mode().IsRegular() || info.Size() > servingTempMaxBytes {
			return fmt.Errorf("unsafe mirrorlist temporary entry %q", entry.Name())
		}
		if err := os.Remove(current); err != nil {
			return err
		}
		dirty[filepath.Dir(current)] = struct{}{}
		removed++
		return nil
	})
	if err != nil {
		return removed, err
	}
	for directory := range dirty {
		if err := syncDirectory(directory); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

func existingRealDirectory(root, relative string) (string, bool, error) {
	handle, err := os.OpenRoot(root)
	if err != nil {
		return "", false, err
	}
	defer handle.Close()
	prefix := ""
	for _, component := range strings.Split(filepath.Clean(relative), string(filepath.Separator)) {
		prefix = filepath.Join(prefix, component)
		info, err := handle.Lstat(prefix)
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", false, errors.Join(err, fmt.Errorf("serving directory %s is not a real directory", prefix))
		}
	}
	return filepath.Join(root, relative), true, nil
}
