package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type DiscoverySource string

const (
	DiscoveryWorkdir     DiscoverySource = "workdir"
	DiscoveryCWD         DiscoverySource = "cwd"
	DiscoveryEnvironment DiscoverySource = "SOW_DIR"
)

type DiscoverOptions struct {
	Workdir string
	CWD     string
	SOWDir  string
}

// Workspace is a discovered configuration boundary. Root, ConfigPath, StartDir
// and CWD are absolute physical paths. StartDir records the winning discovery
// start and is also the implicit Repository/Dist selection origin. CWD remains
// available for resolving ordinary relative command arguments.
type Workspace struct {
	Root       string
	ConfigPath string
	StartDir   string
	CWD        string
	Source     DiscoverySource

	lexicalRoot  string
	lexicalStart string
	rootDevice   uint64
	rootInode    uint64
}

// RootIdentity returns the physical directory identity captured by Discover.
// Callers that retain a Workspace across multiple filesystem operations use
// this identity to reject a pathname that is rebound to another real tree.
func (workspace Workspace) RootIdentity() (device, inode uint64, ok bool) {
	if workspace.rootDevice == 0 || workspace.rootInode == 0 {
		return 0, 0, false
	}
	return workspace.rootDevice, workspace.rootInode, true
}

// Discover searches Workdir, then cwd, then SOW_DIR. Each start searches only
// its own nearest ancestors. It never changes the process working directory.
func Discover(opts DiscoverOptions) (Workspace, error) {
	cwd := opts.CWD
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return Workspace{}, fmt.Errorf("get cwd for workspace discovery: %w", err)
		}
	}
	resolvedCWD, err := absoluteClean(cwd)
	if err != nil {
		return Workspace{}, fmt.Errorf("resolve cwd for workspace discovery: %w", err)
	}
	if realCWD, evalErr := filepath.EvalSymlinks(resolvedCWD); evalErr == nil {
		if realCWD, absErr := absoluteClean(realCWD); absErr == nil {
			resolvedCWD = realCWD
		}
	}
	sowDir := opts.SOWDir
	if sowDir == "" {
		sowDir = os.Getenv("SOW_DIR")
	}
	type candidate struct {
		path   string
		source DiscoverySource
	}
	var candidates []candidate
	if opts.Workdir != "" {
		candidates = append(candidates, candidate{opts.Workdir, DiscoveryWorkdir})
	} else {
		candidates = append(candidates, candidate{cwd, DiscoveryCWD})
	}
	if sowDir != "" {
		candidates = append(candidates, candidate{sowDir, DiscoveryEnvironment})
	}

	seen := make(map[string]struct{})
	var misses []string
	for _, candidate := range candidates {
		start, err := absoluteClean(candidate.path)
		if err != nil {
			misses = append(misses, fmt.Sprintf("%s=%q (%v)", candidate.source, candidate.path, err))
			continue
		}
		if _, ok := seen[start]; ok {
			continue
		}
		seen[start] = struct{}{}
		root, found, err := findWorkspaceRoot(start)
		if err != nil {
			return Workspace{}, fmt.Errorf("discover workspace from %s %q: %w", candidate.source, start, err)
		}
		if !found {
			misses = append(misses, fmt.Sprintf("%s=%q", candidate.source, start))
			continue
		}
		realRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			return Workspace{}, fmt.Errorf("resolve workspace root %q: %w", root, err)
		}
		realRoot, err = absoluteClean(realRoot)
		if err != nil {
			return Workspace{}, fmt.Errorf("resolve workspace root %q: %w", root, err)
		}
		realStart, err := filepath.EvalSymlinks(start)
		if err != nil {
			return Workspace{}, fmt.Errorf("resolve workspace discovery start %q: %w", start, err)
		}
		realStart, err = absoluteClean(realStart)
		if err != nil {
			return Workspace{}, fmt.Errorf("resolve workspace discovery start %q: %w", start, err)
		}
		var rootStat unix.Stat_t
		if err := unix.Lstat(realRoot, &rootStat); err != nil || uint32(rootStat.Mode)&unix.S_IFMT != unix.S_IFDIR {
			return Workspace{}, fmt.Errorf("bind workspace root %q: %w", realRoot, err)
		}
		return Workspace{
			Root: realRoot, ConfigPath: filepath.Join(realRoot, ConfigFilename),
			StartDir: realStart, CWD: resolvedCWD, Source: candidate.source,
			lexicalRoot: root, lexicalStart: start,
			rootDevice: uint64(rootStat.Dev), rootInode: uint64(rootStat.Ino),
		}, nil
	}
	return Workspace{}, fmt.Errorf("workspace not found (searched %s); run sow init or set --workdir/SOW_DIR", strings.Join(misses, ", "))
}

func findWorkspaceRoot(start string) (string, bool, error) {
	info, err := os.Lstat(start)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	if !info.IsDir() {
		return "", false, fmt.Errorf("start is not a directory")
	}
	for dir := start; ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, ConfigFilename)
		info, err := os.Lstat(candidate)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 {
				return "", false, fmt.Errorf("nearest %s %q is a symlink", ConfigFilename, candidate)
			}
			if !info.Mode().IsRegular() {
				return "", false, fmt.Errorf("nearest %s %q is not a regular file", ConfigFilename, candidate)
			}
			return dir, true, nil
		case !os.IsNotExist(err):
			return "", false, err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false, nil
		}
	}
}

type RepositorySelectionSource string

const (
	RepositoryExplicit RepositorySelectionSource = "explicit"
	RepositoryCWD      RepositorySelectionSource = "cwd"
	RepositoryUnique   RepositorySelectionSource = "unique"
)

type SelectRepositoryOptions struct {
	Explicit string
	StartDir string
}

type RepositorySelection struct {
	Name   string
	Path   string
	Source RepositorySelectionSource
}

// SelectRepository applies explicit -> command discovery-start ownership ->
// unique. StartDir is an internal test/caller override; normal managed callers
// use the winning Workspace.StartDir so --workdir affects Workspace,
// Repository, and Dist discovery without changing process cwd. The selector
// never guesses or follows a Repository symlink.
func SelectRepository(ws Workspace, cfg Config, opts SelectRepositoryOptions) (RepositorySelection, error) {
	if opts.Explicit != "" {
		if err := ValidateName(opts.Explicit); err != nil {
			return RepositorySelection{}, fmt.Errorf("select repository %q: %w", opts.Explicit, err)
		}
		if _, ok := cfg.Repositories[opts.Explicit]; !ok {
			return RepositorySelection{}, fmt.Errorf("repository %q is not configured", opts.Explicit)
		}
		path, err := RepositoryPath(ws.Root, opts.Explicit)
		if err != nil {
			return RepositorySelection{}, err
		}
		return RepositorySelection{Name: opts.Explicit, Path: path, Source: RepositoryExplicit}, nil
	}

	start := opts.StartDir
	if start == "" {
		start = ws.lexicalStart
	}
	if start == "" {
		start = ws.StartDir
	}
	if start == "" {
		start, _ = os.Getwd()
	}
	if start != "" {
		name, inside, err := repositoryContainingStart(ws, start, cfg)
		if err != nil {
			return RepositorySelection{}, err
		}
		if inside {
			path, err := RepositoryPath(ws.Root, name)
			if err != nil {
				return RepositorySelection{}, err
			}
			return RepositorySelection{Name: name, Path: path, Source: RepositoryCWD}, nil
		}
	}

	names := sortedRepositoryNames(cfg.Repositories)
	if len(names) == 1 {
		path, err := RepositoryPath(ws.Root, names[0])
		if err != nil {
			return RepositorySelection{}, err
		}
		return RepositorySelection{Name: names[0], Path: path, Source: RepositoryUnique}, nil
	}
	if len(names) == 0 {
		return RepositorySelection{}, errors.New("workspace has no configured repositories")
	}
	return RepositorySelection{}, fmt.Errorf("workspace has multiple repositories (%s); select one with --repo", strings.Join(names, ", "))
}

func repositoryContainingStart(ws Workspace, start string, cfg Config) (string, bool, error) {
	start, err := absoluteClean(start)
	if err != nil {
		return "", false, fmt.Errorf("resolve repository selection start %q: %w", start, err)
	}
	bases := []string{ws.lexicalRoot, ws.Root}
	seen := make(map[string]struct{})
	for _, base := range bases {
		if base == "" {
			continue
		}
		base, err = absoluteClean(base)
		if err != nil {
			continue
		}
		if _, ok := seen[base]; ok {
			continue
		}
		seen[base] = struct{}{}
		rel, err := filepath.Rel(base, start)
		if err != nil || escapes(rel) {
			continue
		}
		if err := validateDirectoryChain(base, rel); err != nil {
			return "", false, fmt.Errorf("repository selection start %q: %w", start, err)
		}
		if rel == "." {
			return "", false, nil
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		name := parts[0]
		if _, configured := cfg.Repositories[name]; configured {
			return name, true, nil
		}
		return "", false, nil
	}
	return "", false, nil
}

// DistContainingCWD reports the configured Dist that physically contains the
// command discovery start within the already selected Repository. It does not apply the
// unique-Dist fallback: callers that can operate at Repository scope use this
// only to preserve an implicit Dist scope. No symlinked directory component is
// accepted.
func DistContainingCWD(ws Workspace, cfg Config, repository string) (string, bool, error) {
	if err := ValidateName(repository); err != nil {
		return "", false, fmt.Errorf("dist cwd repository %q: %w", repository, err)
	}
	repo, ok := cfg.Repositories[repository]
	if !ok {
		return "", false, fmt.Errorf("repository %q is not configured", repository)
	}
	start := ws.lexicalStart
	if start == "" {
		start = ws.StartDir
	}
	if start == "" {
		var err error
		start, err = os.Getwd()
		if err != nil {
			return "", false, fmt.Errorf("get cwd for dist selection: %w", err)
		}
	}
	start, err := absoluteClean(start)
	if err != nil {
		return "", false, fmt.Errorf("resolve dist selection cwd: %w", err)
	}
	physicalRepositoryRoot, err := RepositoryPath(ws.Root, repository)
	if err != nil {
		return "", false, err
	}
	repositoryRoots := []string{physicalRepositoryRoot}
	if ws.lexicalRoot != "" {
		repositoryRoots = append([]string{filepath.Join(ws.lexicalRoot, repository)}, repositoryRoots...)
	}
	seen := make(map[string]struct{})
	for _, repositoryRoot := range repositoryRoots {
		repositoryRoot, err = absoluteClean(repositoryRoot)
		if err != nil {
			continue
		}
		if _, ok := seen[repositoryRoot]; ok {
			continue
		}
		seen[repositoryRoot] = struct{}{}
		rel, err := filepath.Rel(repositoryRoot, start)
		if err != nil || escapes(rel) || rel == "." {
			continue
		}
		if err := validateDirectoryChain(repositoryRoot, rel); err != nil {
			return "", false, fmt.Errorf("dist selection cwd %q: %w", start, err)
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 2 || parts[0] != "dists" {
			return "", false, nil
		}
		name := parts[1]
		if _, configured := repo.Dists[name]; !configured {
			return "", false, nil
		}
		return name, true, nil
	}
	return "", false, nil
}

// RepositoryPath derives the only legal physical Repository path. Missing is
// allowed so repo new/init can use the same derivation; an existing target must
// be a real directory, never a symlink.
func RepositoryPath(workspaceRoot, name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", fmt.Errorf("repository name %q: %w", name, err)
	}
	root, err := absoluteClean(workspaceRoot)
	if err != nil {
		return "", fmt.Errorf("workspace root: %w", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("workspace root %q: %w", root, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", fmt.Errorf("workspace root %q must be a real directory", root)
	}
	target := filepath.Join(root, name)
	rel, err := filepath.Rel(root, target)
	if err != nil || escapes(rel) || rel != name {
		return "", fmt.Errorf("repository path %q escapes workspace root %q", target, root)
	}
	info, err := os.Lstat(target)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		return "", fmt.Errorf("repository path %q is a symlink", target)
	case err == nil && !info.IsDir():
		return "", fmt.Errorf("repository path %q is not a directory", target)
	case err != nil && !os.IsNotExist(err):
		return "", fmt.Errorf("inspect repository path %q: %w", target, err)
	}
	return target, nil
}

func validateDirectoryChain(root, rel string) error {
	if rel == "." {
		return nil
	}
	current := root
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, filepath.FromSlash(part))
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symlink", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("path component %q is not a directory", current)
		}
	}
	return nil
}

func absoluteClean(input string) (string, error) {
	if input == "" {
		return "", errors.New("path is empty")
	}
	abs, err := filepath.Abs(input)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func escapes(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel)
}

// RepositoryNames returns a stable list useful for diagnostics and CLI output.
func RepositoryNames(cfg Config) []string {
	names := sortedRepositoryNames(cfg.Repositories)
	sort.Strings(names)
	return names
}
