package managed

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func ListPackages(ctx context.Context, opts PackageListOptions) (result PackageListResult, resultErr error) {
	result = PackageListResult{Packages: []state.PackageObject{}}
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return result, err
	}
	result.Repository = repoName
	dists, _, err := selectedMutationDists(ws, cfg, repoName, opts.Dists)
	if err != nil {
		return result, err
	}
	result.Dists = dists
	store, repoLock, err := openReadRepository(ctx, ws.Root, repoName)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	result.Packages, err = store.ListPackageObjects(ctx, dists, false)
	if err != nil {
		return result, err
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return result, err
	}
	observedStatus, err := changesSelectedDistsStatus(ctx, ws.Root, repoName, cfg, store, summary, dists)
	if err != nil {
		return result, err
	}
	result.Dirty = observedStatus != "clean"
	return result, nil
}

func ShowPackage(ctx context.Context, opts PackageShowOptions) (result PackageShowResult, resultErr error) {
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return result, err
	}
	result.Repository = repoName
	dists, err := validateOptionalDists(cfg, repoName, opts.Dists)
	if err != nil {
		return result, err
	}
	store, repoLock, err := openReadRepository(ctx, ws.Root, repoName)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	matches, err := resolvePackageReference(ctx, store, opts.Reference, dists, false)
	if err != nil {
		return result, err
	}
	result.Package = matches[0]
	return result, nil
}

func WherePackage(ctx context.Context, opts PackageWhereOptions) (result PackageWhereResult, resultErr error) {
	result = PackageWhereResult{Reference: opts.Reference, Locations: []PackageLocation{}}
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	repositories := config.RepositoryNames(cfg)
	if opts.Repository != "" {
		if _, ok := cfg.Repositories[opts.Repository]; !ok {
			return result, fmt.Errorf("%w: repository %q is not configured", ErrRejected, opts.Repository)
		}
		repositories = []string{opts.Repository}
	}
	type candidate struct {
		repository string
		object     state.PackageObject
	}
	candidates := []candidate{}
	requestedDists := stableUniqueStrings(opts.Dists)
	sort.Strings(requestedDists)
	matchedDists := map[string]bool{}
	for _, repoName := range repositories {
		var dists []string
		if opts.Repository == "" && len(requestedDists) != 0 {
			for _, distName := range requestedDists {
				if _, ok := cfg.Repositories[repoName].Dists[distName]; ok {
					dists = append(dists, distName)
					matchedDists[distName] = true
				}
			}
			if len(dists) == 0 {
				continue
			}
		} else {
			dists, err = validateOptionalDists(cfg, repoName, requestedDists)
			if err != nil {
				return result, err
			}
			if len(dists) == 0 {
				dists = sortedDistConfigNames(cfg.Repositories[repoName])
				if len(dists) == 0 {
					continue
				}
			}
		}
		store, repoLock, err := openReadRepository(ctx, ws.Root, repoName)
		if err != nil {
			return result, err
		}
		matches, matchErr := resolvePackageReference(ctx, store, opts.Reference, dists, false)
		closeErr := store.Close()
		lockErr := repoLock.Close()
		if matchErr == nil {
			for _, object := range matches {
				candidates = append(candidates, candidate{repository: repoName, object: object})
			}
		}
		if closeErr != nil || lockErr != nil {
			return result, fmt.Errorf("%w: close read repository", ErrIntegrity)
		}
		if matchErr != nil && !errors.Is(matchErr, errPackageReferenceNotFound) {
			return result, matchErr
		}
	}
	for _, distName := range requestedDists {
		if opts.Repository == "" && !matchedDists[distName] {
			return result, fmt.Errorf("%w: dist %q is not configured in any repository", ErrRejected, distName)
		}
	}
	if len(candidates) == 0 {
		return result, fmt.Errorf("%w: package reference %q was not found in the selected Workspace scope", ErrRejected, opts.Reference)
	}
	identity := candidates[0].object.Format + "\x00" + candidates[0].object.Coordinate + "\x00" + candidates[0].object.SHA256
	for _, item := range candidates[1:] {
		if item.object.Format+"\x00"+item.object.Coordinate+"\x00"+item.object.SHA256 != identity {
			sort.Slice(candidates, func(i, j int) bool {
				left := candidates[i].repository + "\x00" + candidates[i].object.Format + "\x00" + candidates[i].object.Coordinate + "\x00" + candidates[i].object.SHA256
				right := candidates[j].repository + "\x00" + candidates[j].object.Format + "\x00" + candidates[j].object.Coordinate + "\x00" + candidates[j].object.SHA256
				return left < right
			})
			details := make([]string, 0, len(candidates))
			for _, candidate := range candidates {
				details = append(details, fmt.Sprintf("%s:%s:%s sha256:%s", candidate.repository, candidate.object.Format, candidate.object.Coordinate, candidate.object.SHA256))
			}
			return result, fmt.Errorf("%w: package reference %q is ambiguous across repositories; candidates: %s", ErrRejected, opts.Reference, strings.Join(details, ", "))
		}
	}
	for _, item := range candidates {
		result.Locations = append(result.Locations, PackageLocation{Repository: item.repository, Dists: item.object.Dists, BuiltDists: item.object.BuiltDists, SHA256: item.object.SHA256, Coordinate: item.object.Format + ":" + item.object.Coordinate})
	}
	sort.Slice(result.Locations, func(i, j int) bool { return result.Locations[i].Repository < result.Locations[j].Repository })
	return result, nil
}

func openReadRepository(ctx context.Context, root, repoName string) (*state.Store, *fileLock, error) {
	if err := validateRepositoryLayout(root, repoName); err != nil {
		return nil, nil, err
	}
	lock, err := acquireSharedFileLock(ctx, filepath.Join(root, ".sow", "repo-locks", repoName+".lock"))
	if err != nil {
		return nil, nil, classifyReadLockError("acquire repository read lock", err)
	}
	store, err := openReadOnlyState(filepath.Join(root, ".sow", repoName+".db"))
	if err != nil {
		lock.Close()
		return nil, nil, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	return store, lock, nil
}

func validateOptionalDists(cfg config.Config, repoName string, explicit []string) ([]string, error) {
	names := stableUniqueStrings(explicit)
	sort.Strings(names)
	for _, name := range names {
		if _, ok := cfg.Repositories[repoName].Dists[name]; !ok {
			return nil, fmt.Errorf("%w: dist %q is not configured in repository %q", ErrRejected, name, repoName)
		}
	}
	return names, nil
}
