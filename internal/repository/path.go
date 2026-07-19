package repository

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func canonicalDirectory(name string) (string, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", fmt.Errorf("resolve directory %q: %w", name, err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("inspect directory %q: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: root %q is a symlink", ErrUnsafePath, name)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: root %q is not a directory", ErrUnsafePath, name)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve directory symlinks %q: %w", name, err)
	}
	return filepath.Clean(real), nil
}

// ensureDirectory creates rel below base one component at a time, rejecting
// symlinks and special files rather than allowing MkdirAll to follow them.
func ensureDirectory(base, rel string, mode fs.FileMode) (string, error) {
	current := base
	if rel == "" || rel == "." {
		return current, nil
	}
	for _, component := range strings.Split(filepath.ToSlash(rel), "/") {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("%w: invalid directory component %q", ErrUnsafePath, component)
		}
		next := filepath.Join(current, filepath.FromSlash(component))
		info, err := os.Lstat(next)
		created := false
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Mkdir(next, mode); err == nil {
				created = true
			} else if !errors.Is(err, fs.ErrExist) {
				return "", fmt.Errorf("create directory %q: %w", next, err)
			}
			info, err = os.Lstat(next)
			if err == nil && created {
				if syncErr := syncDirectory(current); syncErr != nil {
					return "", fmt.Errorf("sync parent after creating directory %q: %w", next, syncErr)
				}
			}
		}
		if err != nil {
			return "", fmt.Errorf("inspect directory %q: %w", next, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("%w: directory component %q is a symlink or non-directory", ErrUnsafePath, next)
		}
		if created && info.Mode().Perm() != mode.Perm() {
			if err := os.Chmod(next, mode.Perm()); err != nil {
				return "", fmt.Errorf("set directory mode %q: %w", next, err)
			}
			if err := syncDirectory(next); err != nil {
				return "", fmt.Errorf("sync directory mode %q: %w", next, err)
			}
		}
		current = next
	}
	return current, nil
}

func inspectDirectory(name string) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: %q is a symlink or non-directory", ErrUnsafePath, name)
	}
	return nil
}

func stableRealDirectory(name string) (os.FileInfo, error) {
	entry, err := os.Lstat(name)
	if err != nil || entry.Mode()&os.ModeSymlink != 0 || !entry.IsDir() {
		return nil, errors.Join(err, fmt.Errorf("%w: %q is absent, symlinked, or not a directory", ErrUnsafePath, name))
	}
	opened, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	bound, statErr := opened.Stat()
	closeErr := opened.Close()
	current, lstatErr := os.Lstat(name)
	if statErr != nil || closeErr != nil || lstatErr != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		!os.SameFile(entry, bound) || !os.SameFile(entry, current) {
		return nil, errors.Join(statErr, closeErr, lstatErr, fmt.Errorf("%w: directory %q changed while opening", ErrUnsafePath, name))
	}
	return entry, nil
}

// openRegular opens a path only when the directory entry and opened file are
// the same regular file. This prevents accepting a symlink or special file.
func openRegular(name string) (*os.File, os.FileInfo, error) {
	entryInfo, err := os.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %q is a symlink or non-regular file", ErrUnsafePath, name)
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(entryInfo, openedInfo) {
		file.Close()
		return nil, nil, fmt.Errorf("%w: %q changed while opening", ErrUnsafePath, name)
	}
	return file, openedInfo, nil
}

func validateMaterializedPath(name string) error {
	if name == "" || strings.ContainsAny(name, "\\\x00\t\r\n") || strings.HasPrefix(name, "/") {
		return fmt.Errorf("%w: invalid root-relative path %q", ErrUnsafePath, name)
	}
	clean := path.Clean(name)
	if clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("%w: non-canonical root-relative path %q", ErrUnsafePath, name)
	}
	first := strings.SplitN(name, "/", 2)[0]
	switch first {
	case ".sow", ".pool", ".git":
		return fmt.Errorf("%w: reserved materialization prefix %q", ErrUnsafePath, first)
	}
	return nil
}

func relativeInside(base, target string) (string, error) {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: %q escapes %q", ErrUnsafePath, target, base)
	}
	return rel, nil
}

func syncDirectory(name string) error {
	dir, err := os.Open(name)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}
