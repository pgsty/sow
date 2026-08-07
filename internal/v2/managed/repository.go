package managed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func ListRepositories(ctx context.Context, opts WorkspaceOptions) (result []RepositoryInfo, resultErr error) {
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts, true)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	journal, err := inspectWorkspaceJournal(ws.Root)
	if err != nil {
		return nil, err
	}
	if journal != nil {
		if journal.Repository == "" {
			return nil, fmt.Errorf("%w: workspace operation %q is pending recovery", ErrIntegrity, journal.ID)
		}
		if _, present := cfg.Repositories[journal.Repository]; !present {
			return nil, fmt.Errorf("%w: repository operation %q is pending recovery", ErrIntegrity, journal.ID)
		}
	}
	result = make([]RepositoryInfo, 0, len(cfg.Repositories))
	for _, name := range config.RepositoryNames(cfg) {
		info, err := repositoryInfo(ctx, ws.Root, name, cfg)
		if err != nil {
			return nil, err
		}
		result = append(result, info)
	}
	return result, nil
}

func ShowRepository(ctx context.Context, opts RepositoryShowOptions) (result RepositoryInfo, resultErr error) {
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return RepositoryInfo{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	journal, err := inspectWorkspaceJournal(ws.Root)
	if err != nil {
		return RepositoryInfo{}, err
	}
	if journal != nil {
		if journal.Repository == "" {
			return RepositoryInfo{}, fmt.Errorf("%w: workspace operation %q is pending recovery", ErrIntegrity, journal.ID)
		}
		if _, present := cfg.Repositories[journal.Repository]; !present {
			return RepositoryInfo{}, fmt.Errorf("%w: repository operation %q is pending recovery", ErrIntegrity, journal.ID)
		}
	}
	name := opts.Name
	if name != "" && opts.Repository != "" && name != opts.Repository {
		return RepositoryInfo{}, fmt.Errorf("%w: repository name and --repo differ", ErrRejected)
	}
	if name == "" {
		selection, err := config.SelectRepository(ws, cfg, config.SelectRepositoryOptions{Explicit: opts.Repository})
		if err != nil {
			return RepositoryInfo{}, err
		}
		name = selection.Name
	}
	_, ok := cfg.Repositories[name]
	if !ok {
		return RepositoryInfo{}, fmt.Errorf("%w: repository %q is not configured", ErrRejected, name)
	}
	return repositoryInfo(ctx, ws.Root, name, cfg)
}

func repositoryInfo(ctx context.Context, root, name string, cfg config.Config) (result RepositoryInfo, resultErr error) {
	repo := cfg.Repositories[name]
	if _, err := validateReadOnlyStateRoot(root, false); err != nil {
		return RepositoryInfo{}, err
	}
	repoLock, err := acquireSharedFileLock(ctx, filepath.Join(root, ".sow", "repo-locks", name+".lock"))
	if err != nil {
		return RepositoryInfo{}, classifyReadLockError(fmt.Sprintf("acquire repository %q read lock", name), err)
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	path, err := config.RepositoryPath(root, name)
	if err != nil {
		return RepositoryInfo{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	if err := validateLegacyRepositoryPrivateLayout(root, name); err != nil {
		return RepositoryInfo{}, err
	}
	if err := validateRepositoryPublicLayout(root, name); err != nil {
		return RepositoryInfo{}, err
	}
	store, err := openReadOnlyState(filepath.Join(root, ".sow", name+".db"))
	if err != nil {
		return RepositoryInfo{}, fmt.Errorf("%w: repository %q is not initialized: %v", ErrIntegrity, name, err)
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := validateRepositoryLayoutForRead(root, name, store.SchemaVersion()); err != nil {
		return RepositoryInfo{}, err
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return RepositoryInfo{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	effectiveView, err := config.EffectiveView(cfg, config.ViewOptions{Repository: name})
	if err != nil {
		return RepositoryInfo{}, err
	}
	effectiveRepo := effectiveView.Repositories[name]
	status := summary.Status
	dirtyReasons := []string{}
	layout := inspectRepositoryReadLayout(ctx, root, name, store)
	legacyC2, transition := layout.FrozenC2, layout.Transition
	transitionActive := layout.transitionActive()
	if !legacyC2 && layout.IdentityErr != nil {
		status = "error"
		dirtyReasons = append(dirtyReasons, "repository identity is invalid: "+layout.IdentityErr.Error())
	} else if transitionActive {
		if layout.TransitionErr != nil {
			status = "error"
			dirtyReasons = append(dirtyReasons, "transition journal is invalid: "+layout.TransitionErr.Error())
		} else if layout.ControlErr != nil {
			status = "error"
			dirtyReasons = append(dirtyReasons, "transition control is invalid: "+layout.ControlErr.Error())
		} else if transition == nil {
			status = "error"
			dirtyReasons = append(dirtyReasons, "non-terminal Repository or stale transition control has no transition journal")
		} else if _, transitionErr := validateTransitionBinding(ctx, root, name, cfg, store, *transition, time.Now().UTC()); transitionErr != nil {
			status = "error"
			dirtyReasons = append(dirtyReasons, "transition closure is invalid: "+transitionErr.Error())
		} else {
			status = statusAtLeast(status, "recovering")
			dirtyReasons = append(dirtyReasons, fmt.Sprintf("layout transition is %s", transition.Phase))
		}
	}
	if summary.BuiltGeneration > 0 {
		if _, generationErr := store.GetGeneration(ctx, summary.BuiltGeneration); errors.Is(generationErr, state.ErrNotFound) {
			status = statusAtLeast(status, "dirty")
			dirtyReasons = append(dirtyReasons, "current migrated Generation has no physical manifest baseline")
		} else if generationErr != nil {
			return RepositoryInfo{}, fmt.Errorf("%w: read current Generation: %v", ErrIntegrity, generationErr)
		}
	}
	workspaceOperation, err := inspectWorkspaceJournal(root)
	if err != nil {
		return RepositoryInfo{}, err
	}
	if workspaceOperation != nil {
		if workspaceOperation.Repository == "" {
			return RepositoryInfo{}, fmt.Errorf("%w: workspace operation %q is pending recovery", ErrIntegrity, workspaceOperation.ID)
		}
		if workspaceOperation.Repository == name {
			status = "recovering"
			dirtyReasons = append(dirtyReasons, fmt.Sprintf("workspace operation %s is %s", workspaceOperation.ID, workspaceOperation.Phase))
		}
	}
	if summary.DirtyReason != "" {
		dirtyReasons = append(dirtyReasons, summary.DirtyReason)
	}
	pending, err := store.PendingOperations(ctx)
	if err != nil {
		return RepositoryInfo{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	if len(pending) != 0 {
		status = "recovering"
		dirtyReasons = append(dirtyReasons, fmt.Sprintf("operation %s is %s", pending[0].ID, pending[0].State))
	}
	dists, err := store.ListDists(ctx)
	if err != nil {
		return RepositoryInfo{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	stateByName := make(map[string]state.Dist, len(dists))
	for _, dist := range dists {
		stateByName[dist.Name] = dist
		configured, ok := repo.Dists[dist.Name]
		if !ok {
			status = statusAtLeast(status, "error")
			dirtyReasons = append(dirtyReasons, fmt.Sprintf("built dist %s is absent from configuration", dist.Name))
			continue
		}
		if configured.Format != dist.Format {
			status = statusAtLeast(status, "dirty")
			dirtyReasons = append(dirtyReasons, fmt.Sprintf("dist %s format differs from built state", dist.Name))
		}
		effective, effectiveErr := config.EffectiveArchitectures(cfg, name, dist.Name)
		if effectiveErr != nil {
			return RepositoryInfo{}, effectiveErr
		}
		if !sameArchitectureFamilies(effective, dist.Architectures) {
			status = statusAtLeast(status, "dirty")
			dirtyReasons = append(dirtyReasons, fmt.Sprintf("dist %s effective architectures differ from built state", dist.Name))
		}
		effectiveSHA, configDirty, effectiveErr := observedEffectiveDistConfig(ctx, root, cfg, name, dist.Name, dist)
		if effectiveErr != nil {
			return RepositoryInfo{}, effectiveErr
		}
		if configDirty || effectiveSHA != "" && effectiveSHA != dist.EffectiveConfigSHA256 {
			status = statusAtLeast(status, "dirty")
			dirtyReasons = append(dirtyReasons, fmt.Sprintf("dist %s effective configuration differs from built state", dist.Name))
		}
		if !transitionActive {
			if err := validateLiveDistViews(ctx, root, name, dist.Format, dist.Name, dist.Architectures); err != nil {
				status = statusAtLeast(status, "error")
				dirtyReasons = append(dirtyReasons, fmt.Sprintf("dist %s views are invalid: %v", dist.Name, err))
			}
		}
	}
	for distName := range repo.Dists {
		if _, ok := stateByName[distName]; !ok {
			if err := rejectUninitializedDistAdoption(root, name, distName); err != nil {
				return RepositoryInfo{}, err
			}
			status = statusAtLeast(status, "dirty")
			dirtyReasons = append(dirtyReasons, fmt.Sprintf("configured dist %s is not initialized", distName))
		}
	}
	last, err := store.LastTerminalOperation(ctx)
	if err != nil {
		return RepositoryInfo{}, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	var recent *OperationInfo
	if last != nil {
		recent = &OperationInfo{ID: last.ID, Kind: last.Kind, State: last.State, ErrorClass: last.ErrorClass, CreatedAt: last.CreatedAt, UpdatedAt: last.UpdatedAt}
	}
	sort.Strings(dirtyReasons)
	return RepositoryInfo{
		Name: name, Path: path, Protected: repo.Protected, Dists: int64(len(repo.Dists)),
		Generation: summary.BuiltGeneration, DesiredRevision: summary.DesiredRevision, Status: status,
		Packages: summary.PackageCount, Memberships: summary.MembershipCount, DirtyReasons: dirtyReasons,
		RecentOperation: recent, Config: effectiveRepo,
	}, nil
}

func statusAtLeast(current, candidate string) string {
	priority := map[string]int{"clean": 0, "dirty": 1, "recovering": 2, "error": 3}
	if priority[candidate] > priority[current] {
		return candidate
	}
	return current
}

func NewRepository(ctx context.Context, opts RepositoryNewOptions) (result RepositoryInfo, resultErr error) {
	if err := config.ValidateName(opts.Name); err != nil {
		return RepositoryInfo{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	ws, cfg, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return RepositoryInfo{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	lock, err := acquireFileLock(ctx, filepath.Join(ws.Root, ".sow", "workspace.lock"), opts.Timeout, opts.NoWait)
	if err != nil {
		return RepositoryInfo{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	if err := recoverWorkspaceOperation(ctx, ws.Root); err != nil {
		return RepositoryInfo{}, err
	}
	var oldData []byte
	cfg, oldData, _, err = config.LoadWorkspaceDocument(ws)
	if err != nil {
		return RepositoryInfo{}, err
	}
	if _, err := checkConfigAtRoot(ctx, ws.Root, cfg); err != nil {
		return RepositoryInfo{}, err
	}
	if _, exists := cfg.Repositories[opts.Name]; exists {
		// Lifecycle retries are idempotent. A complete fixed-path shell and
		// readable state prove that a prior invocation already converged.
		return repositoryInfo(ctx, ws.Root, opts.Name, cfg)
	}
	if err := rejectRepositoryAdoption(ws.Root, opts.Name); err != nil {
		return RepositoryInfo{}, err
	}
	cfg.Repositories[opts.Name] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
	newData, err := config.Marshal(cfg)
	if err != nil {
		return RepositoryInfo{}, err
	}
	id, err := operationID()
	if err != nil {
		return RepositoryInfo{}, err
	}
	journal := workspaceJournal{Version: workspaceJournalVersion, ID: id, Kind: "repo.new", Repository: opts.Name, OldConfigSHA: bytesSHA(oldData), OldConfig: oldData, NewConfigSHA: bytesSHA(newData), NewConfig: newData, Phase: "planned"}
	if err := persistWorkspaceJournal(ws.Root, journal); err != nil {
		return RepositoryInfo{}, err
	}
	if err := callFault(opts.Fault, "repo.new.journal"); err != nil {
		return RepositoryInfo{}, err
	}
	if err := writeAtomic(ws.ConfigPath, newData, 0o644); err != nil {
		return RepositoryInfo{}, err
	}
	journal.Phase = "applied"
	if err := persistWorkspaceJournal(ws.Root, journal); err != nil {
		return RepositoryInfo{}, err
	}
	if err := callFault(opts.Fault, "repo.new.config"); err != nil {
		return RepositoryInfo{}, err
	}
	if _, err := ensureRepositoryShell(ws.Root, opts.Name); err != nil {
		return RepositoryInfo{}, err
	}
	if err := clearWorkspaceJournal(ws.Root); err != nil {
		return RepositoryInfo{}, err
	}
	return repositoryInfo(ctx, ws.Root, opts.Name, cfg)
}

func rejectRepositoryAdoption(root, name string) error {
	if err := config.ValidateName(name); err != nil {
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	for _, candidate := range []string{
		filepath.Join(root, name),
		filepath.Join(root, ".sow", name),
		filepath.Join(root, ".sow", "repo-locks", name+".lock"),
		filepath.Join(root, ".sow", name+".db"),
		filepath.Join(root, ".sow", name+".db-wal"),
		filepath.Join(root, ".sow", name+".db-shm"),
		filepath.Join(root, ".sow", name+".db-journal"),
	} {
		if _, err := os.Lstat(candidate); err == nil {
			return fmt.Errorf("%w: refusing to adopt pre-existing repository path %q", ErrRejected, candidate)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func sameArchitectureFamilies(configured []string, stored []state.Architecture) bool {
	if len(configured) != len(stored) {
		return false
	}
	set := make(map[string]struct{}, len(configured))
	for _, family := range configured {
		set[family] = struct{}{}
	}
	for _, architecture := range stored {
		if _, ok := set[architecture.Family]; !ok {
			return false
		}
	}
	return true
}

func RemoveRepository(ctx context.Context, opts RepositoryRemoveOptions) error {
	_, err := RemoveRepositoryResult(ctx, opts)
	return err
}

func RemoveRepositoryResult(ctx context.Context, opts RepositoryRemoveOptions) (RemovalResult, error) {
	result := RemovalResult{}
	err := removeRepository(ctx, opts, &result)
	return result, err
}

func removeRepository(ctx context.Context, opts RepositoryRemoveOptions, result *RemovalResult) (resultErr error) {
	started := time.Now()
	if err := config.ValidateName(opts.Name); err != nil {
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	ws, cfg, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	workspaceLock, err := acquireFileLock(ctx, filepath.Join(ws.Root, ".sow", "workspace.lock"), opts.Timeout, opts.NoWait)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	if err := recoverWorkspaceOperation(ctx, ws.Root); err != nil {
		return err
	}
	var oldData []byte
	cfg, oldData, _, err = config.LoadWorkspaceDocument(ws)
	if err != nil {
		return err
	}
	var checkErr error
	if opts.Force {
		_, checkErr = checkConfigAtRootForForcedRemoval(ctx, ws.Root, cfg, opts.Name)
	} else {
		_, checkErr = checkConfigAtRoot(ctx, ws.Root, cfg)
	}
	if checkErr != nil {
		return checkErr
	}
	repo, ok := cfg.Repositories[opts.Name]
	if !ok {
		result.Noop = true
		return nil
	}
	if repo.Protected {
		return fmt.Errorf("%w: repository %q is protected", ErrRejected, opts.Name)
	}
	remaining, err := remainingLockTimeout(opts.Timeout, started)
	if err != nil {
		return err
	}
	repoLock, err := acquireFileLock(ctx, filepath.Join(ws.Root, ".sow", "repo-locks", opts.Name+".lock"), remaining, opts.NoWait)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	if err := validateRepositoryLayout(ws.Root, opts.Name); err != nil {
		return err
	}
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", opts.Name+".db"))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	if err := store.RequireTerminalLayout(ctx); err != nil {
		store.Close()
		return fmt.Errorf("%w: repository removal is forbidden during layout transition: %v", ErrNotReady, err)
	}
	transition, _, transitionErr := loadTransitionJournal(ws.Root, opts.Name)
	control, controlErr := store.LayoutTransitionControl(ctx)
	if transitionErr != nil || controlErr != nil || transition != nil || control != nil {
		store.Close()
		return errors.Join(fmt.Errorf("%w: repository removal requires no transition evidence", ErrNotReady), transitionErr, controlErr)
	}
	if err := recoverDistOperations(ctx, ws.Root, opts.Name, store); err != nil {
		store.Close()
		return err
	}
	if err := requireNoWriteActivePublication(ctx, store); err != nil {
		store.Close()
		return err
	}
	if err := store.Checkpoint(ctx); err != nil {
		store.Close()
		return fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	summary, summaryErr := store.Summary(ctx)
	pending, pendingErr := store.PendingOperations(ctx)
	closeErr := store.Close()
	if err := errors.Join(summaryErr, pendingErr, closeErr); err != nil {
		return fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	if len(pending) != 0 {
		return fmt.Errorf("%w: repository %q has a pending operation", ErrIntegrity, opts.Name)
	}
	if !opts.Force {
		if summary.DistCount != 0 || summary.PackageCount != 0 || summary.MembershipCount != 0 || !directoryEmpty(filepath.Join(ws.Root, opts.Name, "pool")) || !directoryEmpty(filepath.Join(ws.Root, opts.Name, "dists")) {
			return fmt.Errorf("%w: repository %q is not empty; use --force", ErrRejected, opts.Name)
		}
	}
	if err := requireSameDevice(ws.Root, filepath.Join(ws.Root, ".sow", "workspace-ops")); err != nil {
		return err
	}
	delete(cfg.Repositories, opts.Name)
	newData, err := config.Marshal(cfg)
	if err != nil {
		return err
	}
	id, err := operationID()
	if err != nil {
		return err
	}
	journal := workspaceJournal{Version: workspaceJournalVersion, ID: id, Kind: "repo.rm", Repository: opts.Name, OldConfigSHA: bytesSHA(oldData), OldConfig: oldData, NewConfigSHA: bytesSHA(newData), NewConfig: newData, Phase: "planned"}
	if err := persistWorkspaceJournal(ws.Root, journal); err != nil {
		return err
	}
	if err := callFault(opts.Fault, "repo.rm.journal"); err != nil {
		return err
	}
	if err := writeAtomic(ws.ConfigPath, newData, 0o644); err != nil {
		return err
	}
	result.Removed = true
	journal.Phase = "applied"
	if err := persistWorkspaceJournal(ws.Root, journal); err != nil {
		return err
	}
	if err := callFault(opts.Fault, "repo.rm.config"); err != nil {
		return err
	}
	if err := removeRepositoryOwnedPaths(ws.Root, opts.Name, id); err != nil {
		return err
	}
	return clearWorkspaceJournal(ws.Root)
}

func removeRepositoryOwnedPaths(root, name, id string) error {
	if err := config.ValidateName(name); err != nil {
		return fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	recoveryRoot := filepath.Join(root, ".sow", "workspace-ops", "recovery-"+id)
	if info, err := os.Lstat(recoveryRoot); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: invalid repository recovery path", ErrIntegrity)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := durableMkdir(recoveryRoot, 0o700); err != nil {
			return err
		}
	} else {
		return err
	}
	targets := map[string]string{
		filepath.Join(root, name):                               "repository",
		filepath.Join(root, ".sow", name):                       "private",
		filepath.Join(root, ".sow", "repo-locks", name+".lock"): "lock",
		filepath.Join(root, ".sow", name+".db"):                 "state.db",
		filepath.Join(root, ".sow", name+".db-wal"):             "state.db-wal",
		filepath.Join(root, ".sow", name+".db-shm"):             "state.db-shm",
		filepath.Join(root, ".sow", name+".db-journal"):         "state.db-journal",
	}
	ordered := make([]string, 0, len(targets))
	for target := range targets {
		ordered = append(ordered, target)
	}
	sort.Strings(ordered)
	for _, target := range ordered {
		info, err := os.Lstat(target)
		dest := filepath.Join(recoveryRoot, targets[target])
		destInfo, destErr := os.Lstat(dest)
		if err == nil && destErr == nil {
			return fmt.Errorf("%w: repository source and recovery slot both exist", ErrIntegrity)
		}
		if errors.Is(err, os.ErrNotExist) {
			if destErr == nil {
				if destInfo.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("%w: unsafe repository recovery slot", ErrIntegrity)
				}
				continue
			}
			if errors.Is(destErr, os.ErrNotExist) {
				continue
			}
			return destErr
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: refusing to remove symlink %q", ErrRejected, target)
		}
		if errors.Is(destErr, os.ErrNotExist) {
			if err := durableRename(root, target, dest); err != nil {
				return err
			}
		} else if destErr != nil {
			return destErr
		}
	}
	return removeOwnedDirectory(recoveryRoot, filepath.Join(root, ".sow", "workspace-ops"))
}

func directoryEmpty(path string) bool {
	entries, err := listRootedDirectory(path)
	return err == nil && len(entries) == 0
}
