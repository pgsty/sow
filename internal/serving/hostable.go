package serving

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateHostableTree verifies one directly served directory tree. The
// ordinary path API deliberately delegates to the retained-root API so Nginx
// admission has one permission contract in both modes: product-owned serving
// directories are exactly 0755, served files are exactly 0444, and the one
// deliberate .sow corridor is exactly 0711. The serving root itself is owned
// by the operator and is therefore not chmod-policy state.
func ValidateHostableTree(root, relative string) (resultErr error) {
	handle, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, handle.Close()) }()
	return ValidateHostableTreeRoot(handle, relative)
}

// ValidateHostableTreeRoot is the retained-root form of ValidateHostableTree.
// It rejects symlinks and special files and proves that the public subtree
// coordinate still names the opened directory after the walk.
func ValidateHostableTreeRoot(root *os.Root, relative string) (resultErr error) {
	if root == nil {
		return errors.New("hostable serving root is unavailable")
	}
	name, err := cleanHostableRelative(relative)
	if err != nil {
		return err
	}
	if name == "." {
		return errors.New("hostable tree must be below the serving root")
	}
	if err := validateHostableDirectoryParentsRoot(root, name); err != nil {
		return err
	}
	tree, identity, err := openServingDirectoryRoot(root, name)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, tree.Close()) }()
	if err := validateHostableTreeRoot(tree); err != nil {
		return err
	}
	current, currentErr := root.Lstat(name)
	if currentErr != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		current.Mode().Perm() != 0o755 || !os.SameFile(identity, current) {
		return errors.Join(currentErr, fmt.Errorf("hostable tree coordinate %s changed or is not mode 0755", filepath.ToSlash(name)))
	}
	return validateHostableDirectoryParentsRoot(root, name)
}

// ValidateHostableFile verifies one directly served immutable file and every
// product-owned parent below the supplied serving root.
func ValidateHostableFile(root, relative string) (resultErr error) {
	handle, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, handle.Close()) }()
	return ValidateHostableFileRoot(handle, relative)
}

// ValidateHostableFileRoot is the retained-root form of ValidateHostableFile.
func ValidateHostableFileRoot(root *os.Root, relative string) error {
	if root == nil {
		return errors.New("hostable serving root is unavailable")
	}
	name, err := cleanHostableRelative(relative)
	if err != nil {
		return err
	}
	if name == "." {
		return errors.New("hostable file must be below the serving root")
	}
	if err := validateHostableDirectoryParentsRoot(root, filepath.Dir(name)); err != nil {
		return err
	}
	before, err := root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Mode().Perm() != 0o444 {
		return errors.Join(err, fmt.Errorf("hostable file %s is not a regular mode 0444 file", filepath.ToSlash(name)))
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	afterOpen, lstatErr := root.Lstat(name)
	if statErr != nil || lstatErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o444 ||
		!os.SameFile(before, opened) || !os.SameFile(before, afterOpen) {
		return errors.Join(statErr, lstatErr, file.Close(), fmt.Errorf("hostable file %s changed while opening", filepath.ToSlash(name)))
	}
	last, lastErr := file.Stat()
	coordinate, coordinateErr := root.Lstat(name)
	closeErr := file.Close()
	if lastErr != nil || coordinateErr != nil || closeErr != nil || last.Mode().Perm() != 0o444 ||
		!os.SameFile(opened, last) || !os.SameFile(opened, coordinate) {
		return errors.Join(lastErr, coordinateErr, closeErr, fmt.Errorf("hostable file %s changed during validation", filepath.ToSlash(name)))
	}
	return validateHostableDirectoryParentsRoot(root, filepath.Dir(name))
}

func cleanHostableRelative(relative string) (string, error) {
	if err := validateServingRelativePath(relative); err != nil {
		return "", err
	}
	name := filepath.FromSlash(relative)
	if filepath.Clean(name) != name {
		return "", errors.New("unsafe hostable relative path")
	}
	return name, nil
}

// validateHostableDirectoryParentsRoot validates directory itself and each of
// its parents below root. It intentionally excludes root's own mode: root is
// an operator-owned mount/export coordinate, while these descendants are the
// product-owned Nginx data-plane contract.
func validateHostableDirectoryParentsRoot(root *os.Root, directory string) error {
	if root == nil {
		return errors.New("hostable serving root is unavailable")
	}
	directory = filepath.Clean(directory)
	if directory == "." {
		return nil
	}
	prefix := ""
	for _, component := range strings.Split(directory, string(filepath.Separator)) {
		prefix = filepath.Join(prefix, component)
		wanted := os.FileMode(0o755)
		// .sow is the one deliberate corridor exception: execute-only for
		// non-owners prevents directory listing while allowing Nginx to traverse
		// into the product-owned materialized/origin subtrees. This exception is
		// exact and is never inherited by descendants or by a nested .sow.
		if prefix == stateServingCorridorDirectory {
			wanted = 0o711
		}
		info, err := root.Lstat(prefix)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.Join(err, fmt.Errorf("hostable directory %s is not a real directory", filepath.ToSlash(prefix)))
		}
		if info.Mode().Perm() != wanted {
			return fmt.Errorf("hostable directory %s mode=%#o want=%#o", filepath.ToSlash(prefix), info.Mode().Perm(), wanted)
		}
	}
	return nil
}

const stateServingCorridorDirectory = ".sow"
