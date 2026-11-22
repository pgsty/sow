package signing

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maxSymlinkHops = 40

// ErrUnsafeSourcePath reports that a passfile or key path violates workspace
// symlink boundary rules.
var ErrUnsafeSourcePath = errors.New("external secret path resolves inside workspace")

// ResolveSourcePath resolves a passfile or key-file path under the repository
// symlink policy:
//   - Paths inside root (matched by both canonical path and os.SameFile
//     device/inode so case-insensitive filesystems cannot bypass the boundary)
//     never follow in-workspace symlinks; they are rebased onto canonicalRoot
//     for strict component-by-component O_NOFOLLOW opening.
//   - Paths outside root resolve symlinks hop-by-hop (supporting Kubernetes
//     Secret ..data mounts and /var/run/secrets) while rejecting any
//     intermediate or final hop that touches root or any descendant of root.
func ResolveSourcePath(root, candidate string) (string, error) {
	if candidate == "" {
		return "", ErrUnsafeSourcePath
	}
	absCandidate := candidate
	if !filepath.IsAbs(absCandidate) {
		var err error
		absCandidate, err = filepath.Abs(absCandidate)
		if err != nil {
			return "", err
		}
	}
	absCandidate = filepath.Clean(physicalPath(absCandidate))
	if root == "" {
		resolved, err := filepath.EvalSymlinks(absCandidate)
		if err != nil {
			return "", err
		}
		return filepath.Clean(physicalPath(resolved)), nil
	}

	absRoot := root
	if !filepath.IsAbs(absRoot) {
		var err error
		absRoot, err = filepath.Abs(absRoot)
		if err != nil {
			return "", err
		}
	}
	cleanRoot := filepath.Clean(physicalPath(absRoot))
	canonicalRoot := cleanRoot
	if evalRoot, err := filepath.EvalSymlinks(cleanRoot); err == nil {
		canonicalRoot = filepath.Clean(physicalPath(evalRoot))
	}
	rootInfo, rootStatErr := os.Stat(canonicalRoot)
	rootLstatInfo, rootLstatErr := os.Lstat(cleanRoot)

	var rootPrefixInfos []os.FileInfo
	for prefix := cleanRoot; ; {
		if info, err := os.Lstat(prefix); err == nil {
			rootPrefixInfos = append(rootPrefixInfos, info)
		}
		parent := filepath.Dir(prefix)
		if parent == prefix {
			break
		}
		prefix = parent
	}
	isRootPrefixSymlink := func(info os.FileInfo) bool {
		for _, allowed := range rootPrefixInfos {
			if os.SameFile(info, allowed) {
				return true
			}
		}
		return false
	}
	matchesRootDir := func(p string, info os.FileInfo) bool {
		cleanP := filepath.Clean(physicalPath(p))
		if cleanP == canonicalRoot {
			return true
		}
		if rootStatErr == nil && info != nil && info.IsDir() && os.SameFile(info, rootInfo) {
			return true
		}
		return false
	}
	matchesCallerRoot := func(p string, info os.FileInfo) bool {
		if matchesRootDir(p, info) {
			return true
		}
		if rootLstatErr == nil && info != nil && os.SameFile(info, rootLstatInfo) {
			return true
		}
		return false
	}

	// Step A: Walk absCandidate shallowest-to-deepest to detect paths inside root
	// without traversing arbitrary external symlinks.
	if pathWithinRoot(canonicalRoot, absCandidate) {
		return absCandidate, nil
	}
	if rebased, within := findWorkspaceAnchor(absCandidate, canonicalRoot, matchesCallerRoot, isRootPrefixSymlink); within {
		return rebased, nil
	}
	if pathWithinRoot(cleanRoot, absCandidate) {
		if rel, err := filepath.Rel(cleanRoot, absCandidate); err == nil {
			return filepath.Join(canonicalRoot, rel), nil
		}
	}

	// Step B: External path. Resolve symlinks hop-by-hop with POSIX semantics and
	// reject any intermediate or final step that touches root.
	resolved, err := resolveExternalNoWorkspaceBounce(absCandidate, canonicalRoot, matchesRootDir)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

func findWorkspaceAnchor(absCandidate, canonicalRoot string, matchesCallerRoot func(string, os.FileInfo) bool, isRootPrefixSymlink func(os.FileInfo) bool) (string, bool) {
	parts := splitPathSegments(absCandidate)
	cur := "/"
	if info, err := os.Lstat(cur); err == nil && matchesCallerRoot(cur, info) {
		return filepath.Join(canonicalRoot, strings.Join(parts, "/")), true
	}
	for i, part := range parts {
		next := filepath.Join(cur, part)
		info, err := os.Lstat(next)
		if err != nil {
			return "", false
		}
		if matchesCallerRoot(next, info) {
			if i+1 >= len(parts) {
				return canonicalRoot, true
			}
			return filepath.Join(append([]string{canonicalRoot}, parts[i+1:]...)...), true
		}
		if info.Mode()&os.ModeSymlink != 0 && !isRootPrefixSymlink(info) {
			return "", false
		}
		cur = next
	}
	return "", false
}

func resolveExternalNoWorkspaceBounce(absCandidate, canonicalRoot string, matchesRootDir func(string, os.FileInfo) bool) (string, error) {
	queue := splitPathSegments(absCandidate)
	cur := "/"
	hops := 0
	for len(queue) > 0 {
		part := queue[0]
		queue = queue[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			cur = filepath.Dir(cur)
			if info, err := os.Lstat(cur); err == nil && (matchesRootDir(cur, info) || pathWithinRoot(canonicalRoot, cur)) {
				return "", ErrUnsafeSourcePath
			}
			continue
		}
		next := filepath.Join(cur, part)
		info, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if matchesRootDir(next, info) || pathWithinRoot(canonicalRoot, next) {
			return "", ErrUnsafeSourcePath
		}
		if info.Mode()&os.ModeSymlink != 0 {
			hops++
			if hops > maxSymlinkHops {
				return "", ErrUnsafeSourcePath
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			targetParts := splitPathSegments(target)
			if filepath.IsAbs(target) {
				cur = "/"
			}
			queue = append(targetParts, queue...)
			continue
		}
		cur = next
	}
	finalInfo, err := os.Lstat(cur)
	if err != nil {
		return "", err
	}
	if matchesRootDir(cur, finalInfo) || pathWithinRoot(canonicalRoot, cur) {
		return "", ErrUnsafeSourcePath
	}
	return filepath.Clean(physicalPath(cur)), nil
}

func splitPathSegments(p string) []string {
	raw := strings.Split(p, string(filepath.Separator))
	parts := make([]string, 0, len(raw))
	for _, seg := range raw {
		if seg == "" {
			continue
		}
		parts = append(parts, seg)
	}
	return parts
}

// readSourceFile enforces strict component-by-component O_NOFOLLOW inside a
// workspace root, while allowing symlink resolution (e.g. Kubernetes Secret
// ..data mounts and /var/run/secrets) when the path resides outside the
// workspace root. Resolved targets still undergo full O_NOFOLLOW|O_NONBLOCK
// regular-file and size verification.
func readSourceFile(root, path string) ([]byte, error) {
	badFile := errors.New("passfile is missing, unreadable, unsafe, empty, oversized, or changed during reading")
	resolved, err := ResolveSourcePath(root, path)
	if err != nil {
		return nil, badFile
	}
	return readFile(resolved)
}

func pathWithinRoot(root, candidate string) bool {
	cleanRoot := filepath.Clean(root)
	cleanCandidate := filepath.Clean(candidate)
	rel, err := filepath.Rel(cleanRoot, cleanCandidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// Bind the parent chain as well as the leaf so neither symlinks nor directory
// replacement can redirect a read. O_NONBLOCK prevents a raced FIFO from hanging.
func readFile(path string) ([]byte, error) {
	badFile := errors.New("passfile is missing, unreadable, unsafe, empty, oversized, or changed during reading")
	path = physicalPath(path)
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	fd, err := unix.Open("/", directoryAccess|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, badFile
	}
	fds := []int{fd}
	defer func() {
		for _, opened := range fds {
			_ = unix.Close(opened)
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		fd, err = unix.Openat(fd, part, directoryAccess|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, badFile
		}
		fds = append(fds, fd)
	}
	name := parts[len(parts)-1]
	leaf, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, badFile
	}
	file := os.NewFile(uintptr(leaf), "passfile")
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > MaxBytes {
		return nil, badFile
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	after, statErr := file.Stat()
	var entry, opened unix.Stat_t
	pathErr := unix.Fstatat(fd, name, &entry, unix.AT_SYMLINK_NOFOLLOW)
	openErr := unix.Fstat(leaf, &opened)
	if err != nil || statErr != nil || pathErr != nil || openErr != nil ||
		len(data) != int(before.Size()) || !os.SameFile(before, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) || entry.Dev != opened.Dev || entry.Ino != opened.Ino ||
		entry.Size != opened.Size || uint32(entry.Mode)&unix.S_IFMT != unix.S_IFREG {
		Clear(data)
		return nil, badFile
	}
	for i := 1; i < len(fds); i++ {
		if unix.Fstat(fds[i], &opened) != nil || unix.Fstatat(fds[i-1], parts[i-1], &entry, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			entry.Dev != opened.Dev || entry.Ino != opened.Ino || uint32(entry.Mode)&unix.S_IFMT != unix.S_IFDIR {
			Clear(data)
			return nil, badFile
		}
	}
	return data, nil
}
