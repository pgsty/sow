package serving

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateWorkerTraversableAbsoluteDirectory checks every absolute pathname
// component from the filesystem root through path. This is required for an
// Nginx alias: validating only the supplied leaf cannot prove that the worker
// can cross an operator-owned 0700 ancestor. Symlinks in the absolute chain are
// rejected rather than resolved.
func ValidateWorkerTraversableAbsoluteDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("Nginx worker absolute directory must be clean and absolute")
	}
	relative, err := filepath.Rel(string(filepath.Separator), path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.Join(err, errors.New("Nginx worker absolute directory escapes the filesystem root"))
	}
	return ValidateWorkerTraversableDirectory(string(filepath.Separator), filepath.ToSlash(relative))
}

// ValidateWorkerTraversableDirectory verifies that an operator-owned directory
// coordinate can be traversed by an Nginx worker that is neither its owner nor
// in its group. Unlike product-owned serving trees, operator-owned paths do not
// have an exact chmod policy: only the required other-execute bit is admitted.
// The ordinary API deliberately delegates to the retained-root API.
func ValidateWorkerTraversableDirectory(root, relative string) (resultErr error) {
	handle, identity, err := openWorkerHostabilityRoot(root)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, handle.Close()) }()
	if err := ValidateWorkerTraversableDirectoryRoot(handle, relative); err != nil {
		return err
	}
	return verifyWorkerHostabilityRoot(root, handle, identity)
}

// ValidateWorkerTraversableDirectoryRoot is the capability-bound form of
// ValidateWorkerTraversableDirectory. Every component is opened one at a time,
// symlinks are rejected, and all retained parent/child identities are checked
// again before returning.
func ValidateWorkerTraversableDirectoryRoot(root *os.Root, relative string) (resultErr error) {
	chain, err := openWorkerDirectoryChain(root, relative)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, chain.Close()) }()
	return chain.Verify()
}

// ValidateWorkerReadableFile verifies one operator-owned public file from an
// Nginx worker's perspective. It requires other-execute on the supplied root
// and every descendant parent, and other-read on a regular non-symlink file.
// It never repairs permissions or otherwise mutates the operator's path.
func ValidateWorkerReadableFile(root, relative string) (resultErr error) {
	handle, identity, err := openWorkerHostabilityRoot(root)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, handle.Close()) }()
	if err := ValidateWorkerReadableFileRoot(handle, relative); err != nil {
		return err
	}
	return verifyWorkerHostabilityRoot(root, handle, identity)
}

// ValidateWorkerReadableFileRoot is the retained-root form of
// ValidateWorkerReadableFile.
func ValidateWorkerReadableFileRoot(root *os.Root, relative string) (resultErr error) {
	name, err := cleanHostableRelative(relative)
	if err != nil {
		return err
	}
	if name == "." {
		return errors.New("Nginx worker-readable file must be below its admission root")
	}
	chain, err := openWorkerDirectoryChain(root, filepath.Dir(name))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, chain.Close()) }()
	base := filepath.Base(name)
	before, err := chain.Leaf().Lstat(base)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return errors.Join(err, fmt.Errorf("Nginx worker-readable file %s is not a regular non-symlink file", filepath.ToSlash(name)))
	}
	if before.Mode().Perm()&0o004 == 0 {
		return fmt.Errorf("Nginx worker-readable file %s mode=%#o lacks other-read (0004); provide a public file readable by the worker", filepath.ToSlash(name), before.Mode().Perm())
	}
	file, err := chain.Leaf().Open(base)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	afterOpen, lstatErr := chain.Leaf().Lstat(base)
	if statErr != nil || lstatErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o004 == 0 ||
		!os.SameFile(before, opened) || !os.SameFile(before, afterOpen) {
		return errors.Join(statErr, lstatErr, file.Close(), fmt.Errorf("Nginx worker-readable file %s changed while opening", filepath.ToSlash(name)))
	}
	last, lastErr := file.Stat()
	coordinate, coordinateErr := chain.Leaf().Lstat(base)
	closeErr := file.Close()
	if lastErr != nil || coordinateErr != nil || closeErr != nil || last.Mode().Perm()&0o004 == 0 ||
		coordinate.Mode()&os.ModeSymlink != 0 || !coordinate.Mode().IsRegular() || coordinate.Mode().Perm()&0o004 == 0 ||
		!os.SameFile(opened, last) || !os.SameFile(opened, coordinate) {
		return errors.Join(lastErr, coordinateErr, closeErr, fmt.Errorf("Nginx worker-readable file %s changed during admission", filepath.ToSlash(name)))
	}
	return chain.Verify()
}

type workerDirectoryChain struct {
	root         *os.Root
	rootIdentity os.FileInfo
	edges        []workerDirectoryEdge
}

type workerDirectoryEdge struct {
	parent    *os.Root
	component string
	child     *os.Root
	identity  os.FileInfo
}

func openWorkerDirectoryChain(root *os.Root, relative string) (_ *workerDirectoryChain, resultErr error) {
	if root == nil {
		return nil, errors.New("Nginx worker hostability root is unavailable")
	}
	name, err := cleanHostableRelative(relative)
	if err != nil {
		return nil, err
	}
	rootIdentity, err := root.Stat(".")
	if err != nil || !rootIdentity.IsDir() {
		return nil, errors.Join(err, errors.New("Nginx worker hostability root is not a directory"))
	}
	if rootIdentity.Mode().Perm()&0o001 == 0 {
		return nil, fmt.Errorf("Nginx worker hostability root mode=%#o lacks other-execute (0001); make the served/configuration directory traversable by the worker", rootIdentity.Mode().Perm())
	}
	chain := &workerDirectoryChain{root: root, rootIdentity: rootIdentity}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, chain.Close())
		}
	}()
	if name == "." {
		return chain, nil
	}
	current := root
	for _, component := range strings.Split(name, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return nil, errors.New("unsafe Nginx worker directory component")
		}
		before, err := current.Lstat(component)
		if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			return nil, errors.Join(err, fmt.Errorf("Nginx worker directory %s is not a real directory", filepath.ToSlash(name)))
		}
		if before.Mode().Perm()&0o001 == 0 {
			return nil, fmt.Errorf("Nginx worker directory %s mode=%#o lacks other-execute (0001); make every served/configuration parent traversable by the worker", filepath.ToSlash(name), before.Mode().Perm())
		}
		child, err := current.OpenRoot(component)
		if err != nil {
			return nil, err
		}
		opened, statErr := child.Stat(".")
		afterOpen, lstatErr := current.Lstat(component)
		if statErr != nil || lstatErr != nil || opened.Mode().Perm()&0o001 == 0 ||
			!os.SameFile(before, opened) || !os.SameFile(before, afterOpen) {
			_ = child.Close()
			return nil, errors.Join(statErr, lstatErr, fmt.Errorf("Nginx worker directory %s changed while opening", filepath.ToSlash(name)))
		}
		chain.edges = append(chain.edges, workerDirectoryEdge{parent: current, component: component, child: child, identity: opened})
		current = child
	}
	if err := chain.Verify(); err != nil {
		return nil, err
	}
	return chain, nil
}

func (chain *workerDirectoryChain) Leaf() *os.Root {
	if chain == nil || len(chain.edges) == 0 {
		if chain == nil {
			return nil
		}
		return chain.root
	}
	return chain.edges[len(chain.edges)-1].child
}

func (chain *workerDirectoryChain) Verify() error {
	if chain == nil || chain.root == nil || chain.rootIdentity == nil {
		return errors.New("Nginx worker directory chain is unavailable")
	}
	rootInfo, rootErr := chain.root.Stat(".")
	if rootErr != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o001 == 0 || !os.SameFile(chain.rootIdentity, rootInfo) {
		return errors.Join(rootErr, errors.New("Nginx worker hostability root changed or is no longer other-traversable"))
	}
	for _, edge := range chain.edges {
		parentInfo, parentErr := edge.parent.Lstat(edge.component)
		childInfo, childErr := edge.child.Stat(".")
		if parentErr != nil || childErr != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || !childInfo.IsDir() ||
			parentInfo.Mode().Perm()&0o001 == 0 || childInfo.Mode().Perm()&0o001 == 0 ||
			!os.SameFile(edge.identity, parentInfo) || !os.SameFile(edge.identity, childInfo) {
			return errors.Join(parentErr, childErr, fmt.Errorf("Nginx worker directory component %s changed or is no longer other-traversable", edge.component))
		}
	}
	return nil
}

func (chain *workerDirectoryChain) Close() error {
	if chain == nil {
		return nil
	}
	var result error
	for index := len(chain.edges) - 1; index >= 0; index-- {
		if chain.edges[index].child != nil {
			result = errors.Join(result, chain.edges[index].child.Close())
			chain.edges[index].child = nil
		}
	}
	chain.edges = nil
	return result
}

func openWorkerHostabilityRoot(path string) (*os.Root, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, nil, errors.Join(err, errors.New("Nginx worker hostability root must be a real directory"))
	}
	handle, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, err
	}
	opened, statErr := handle.Stat(".")
	afterOpen, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || afterOpen.Mode()&os.ModeSymlink != 0 || !afterOpen.IsDir() ||
		!os.SameFile(before, opened) || !os.SameFile(before, afterOpen) {
		return nil, nil, errors.Join(statErr, lstatErr, handle.Close(), errors.New("Nginx worker hostability root changed while opening"))
	}
	return handle, opened, nil
}

func verifyWorkerHostabilityRoot(path string, root *os.Root, identity os.FileInfo) error {
	through, rootErr := root.Stat(".")
	atPath, pathErr := os.Lstat(path)
	if rootErr != nil || pathErr != nil || atPath.Mode()&os.ModeSymlink != 0 || !atPath.IsDir() ||
		through.Mode().Perm()&0o001 == 0 || atPath.Mode().Perm()&0o001 == 0 ||
		!os.SameFile(identity, through) || !os.SameFile(identity, atPath) {
		return errors.Join(rootErr, pathErr, errors.New("Nginx worker hostability root was replaced or is no longer other-traversable during admission"))
	}
	return nil
}
