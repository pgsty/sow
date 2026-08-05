package managed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"golang.org/x/sys/unix"
)

func workspace(opts WorkspaceOptions) (config.Workspace, config.Config, *workspaceRootGuard, error) {
	ws, err := config.Discover(config.DiscoverOptions{Workdir: opts.Workdir, CWD: opts.CWD, SOWDir: opts.SOWDir})
	if err != nil {
		return config.Workspace{}, config.Config{}, nil, fmt.Errorf("%w: %v", ErrWorkspaceInput, err)
	}
	guard, err := bindDiscoveredWorkspaceRoot(ws)
	if err != nil {
		return config.Workspace{}, config.Config{}, nil, err
	}
	cfg, err := config.LoadWorkspace(ws)
	if err != nil {
		_ = guard.Close()
		return config.Workspace{}, config.Config{}, nil, fmt.Errorf("%w: %v", ErrWorkspaceInput, err)
	}
	return ws, cfg, guard, nil
}

// readWorkspace acquires the existing Workspace lock in shared mode before it
// loads sow.yml. That keeps every combined config+state read on one lifecycle
// side of a writer's atomic update. A config-only, not-yet-initialized
// Workspace is allowed only when requireState is false.
func readWorkspace(ctx context.Context, opts WorkspaceOptions, requireState bool) (config.Workspace, config.Config, *fileLock, error) {
	ws, err := config.Discover(config.DiscoverOptions{Workdir: opts.Workdir, CWD: opts.CWD, SOWDir: opts.SOWDir})
	if err != nil {
		return config.Workspace{}, config.Config{}, nil, fmt.Errorf("%w: %v", ErrWorkspaceInput, err)
	}
	rootGuard, err := bindDiscoveredWorkspaceRoot(ws)
	if err != nil {
		return config.Workspace{}, config.Config{}, nil, err
	}
	fail := func(result error) (config.Workspace, config.Config, *fileLock, error) {
		return config.Workspace{}, config.Config{}, nil, errors.Join(result, rootGuard.Close())
	}
	preflightConfig, loadErr := config.LoadWorkspace(ws)
	if loadErr != nil {
		return fail(fmt.Errorf("%w: %v", ErrWorkspaceInput, loadErr))
	}
	stateRoot := filepath.Join(ws.Root, ".sow")
	info, err := os.Lstat(stateRoot)
	if errors.Is(err, os.ErrNotExist) && !requireState {
		if _, retryErr := os.Lstat(stateRoot); errors.Is(retryErr, os.ErrNotExist) {
			return ws, preflightConfig, &fileLock{rootGuard: rootGuard}, nil
		} else if retryErr != nil {
			return fail(fmt.Errorf("%w: inspect state root after config read: %v", ErrIntegrity, retryErr))
		}
		// Initialization appeared while the config-only snapshot was read. Fall
		// through and reload sow.yml after acquiring its Workspace lock.
		info, err = os.Lstat(stateRoot)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fail(fmt.Errorf("%w: state root is missing or unsafe", ErrIntegrity))
	}
	lock, err := acquireSharedFileLock(ctx, filepath.Join(stateRoot, "workspace.lock"))
	if err != nil {
		return fail(classifyReadLockError("acquire workspace read lock", err))
	}
	lock.rootGuard = rootGuard
	cfg, err := config.LoadWorkspace(ws)
	if err != nil {
		lock.Close()
		return config.Workspace{}, config.Config{}, nil, fmt.Errorf("%w: %v", ErrWorkspaceInput, err)
	}
	return ws, cfg, lock, nil
}

func loadWorkspaceWithSHA(ws config.Workspace) (config.Config, string, error) {
	cfg, digest, err := config.LoadWorkspaceWithSHA(ws)
	if err != nil {
		return config.Config{}, "", fmt.Errorf("%w: %v", ErrWorkspaceInput, err)
	}
	return cfg, digest, nil
}

func Init(ctx context.Context, opts InitOptions) (result InitResult, resultErr error) {
	if ctx == nil {
		return InitResult{}, errors.New("managed: nil context")
	}
	dir := opts.Dir
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return InitResult{}, err
		}
	}
	root, err := realDirectory(dir, true, 0o755)
	if err != nil {
		return InitResult{}, err
	}
	rootGuard, err := bindCurrentWorkspaceRoot(root)
	if err != nil {
		return InitResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	result = InitResult{Workspace: root, Existing: []string{}}
	started := time.Now()
	configPath := filepath.Join(root, config.ConfigFilename)
	stateRoot := filepath.Join(root, ".sow")
	var existingConfig config.Config
	configExists := false
	if info, statErr := os.Lstat(configPath); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return result, fmt.Errorf("%w: sow.yml is not a regular file", ErrRejected)
		}
		existingConfig, err = config.Load(configPath)
		if err != nil {
			return result, err
		}
		configExists = true
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return result, statErr
	}
	if info, statErr := os.Lstat(stateRoot); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return result, fmt.Errorf("%w: reserved path .sow is not a real directory", ErrRejected)
		}
	} else if errors.Is(statErr, os.ErrNotExist) {
		// Before the first lock inode exists there cannot be a serialized Managed
		// writer. Reject adoption conflicts now so an invalid existing declaration
		// does not acquire a partial .sow layout as a side effect.
		if configExists {
			for _, repoName := range config.RepositoryNames(existingConfig) {
				if err := rejectUninitializedRepositoryAdoption(root, repoName); err != nil {
					return result, err
				}
			}
		}
		if _, err := durableEnsureDir(stateRoot, 0o700); err != nil {
			return result, err
		}
	} else {
		return result, statErr
	}
	initializeStateLayout, err := ensureWorkspaceLock(root)
	if err != nil {
		return result, err
	}
	if initializeStateLayout {
		// Make the state root visibly non-empty before any process can hold the
		// new lock. Thereafter an unlinked lock inode is never recreated.
		if err := ensureStateDirectories(root); err != nil {
			return result, err
		}
	}
	lock, err := acquireFileLock(ctx, filepath.Join(stateRoot, "workspace.lock"), opts.Timeout, opts.NoWait)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	if !initializeStateLayout {
		if err := ensureStateDirectories(root); err != nil {
			return result, err
		}
	}
	if err := recoverWorkspaceOperation(ctx, root); err != nil {
		return result, err
	}

	var cfg config.Config
	var configData []byte
	if _, statErr := os.Lstat(configPath); errors.Is(statErr, os.ErrNotExist) {
		cfg = config.Default()
		data, marshalErr := config.Marshal(cfg)
		if marshalErr != nil {
			return result, marshalErr
		}
		id, idErr := operationID()
		if idErr != nil {
			return result, idErr
		}
		journal := workspaceJournal{Version: workspaceJournalVersion, ID: id, Kind: "workspace.init", NewConfigSHA: bytesSHA(data), NewConfig: data, Phase: "planned"}
		if err := persistWorkspaceJournal(root, journal); err != nil {
			return result, err
		}
		if err := callFault(opts.Fault, "init.journal"); err != nil {
			return result, err
		}
		if err := writeAtomic(configPath, data, 0o644); err != nil {
			return result, err
		}
		result.ConfigCreated = true
		journal.Phase = "applied"
		if err := persistWorkspaceJournal(root, journal); err != nil {
			return result, err
		}
		if err := callFault(opts.Fault, "init.config"); err != nil {
			return result, err
		}
		if err := clearWorkspaceJournal(root); err != nil {
			return result, err
		}
		configData = data
	} else if statErr != nil {
		return result, statErr
	} else {
		// The pre-lock parse is only a mutation-free validity preflight. A queued
		// lifecycle writer may have committed a newer config before Init acquired
		// the Workspace lock, so the locked snapshot is always loaded afresh.
		cfg, configData, _, err = config.LoadDocument(configPath)
		if err != nil {
			return result, err
		}
		result.Existing = append(result.Existing, config.ConfigFilename)
	}
	// Recovery must precede the state-aware preflight: an applied operation may
	// have installed a new view while its SQLite finalization was interrupted.
	// Treating that recoverable intermediate tree as corruption would strand the
	// operation permanently.
	if err := recoverInitializedRepositories(ctx, root, cfg, opts.LockOptions, started); err != nil {
		return result, err
	}
	if _, err := checkConfigAtRoot(ctx, root, cfg); err != nil {
		return result, err
	}

	for _, repoName := range config.RepositoryNames(cfg) {
		complete, err := repositoryShellComplete(root, repoName)
		if err != nil {
			return result, err
		}
		if complete {
			continue
		}
		id, err := operationID()
		if err != nil {
			return result, err
		}
		journal := workspaceJournal{Version: workspaceJournalVersion, ID: id, Kind: "repo.init", Repository: repoName, OldConfigSHA: bytesSHA(configData), OldConfig: configData, NewConfigSHA: bytesSHA(configData), NewConfig: configData, Phase: "planned"}
		if err := persistWorkspaceJournal(root, journal); err != nil {
			return result, err
		}
		if err := callFault(opts.Fault, "init.repo.journal."+repoName); err != nil {
			return result, err
		}
		if _, err := ensureRepositoryShell(root, repoName); err != nil {
			return result, err
		}
		result.RepositoriesInitialized++
		journal.Phase = "applied"
		if err := persistWorkspaceJournal(root, journal); err != nil {
			return result, err
		}
		if err := clearWorkspaceJournal(root); err != nil {
			return result, err
		}
		if err := callFault(opts.Fault, "init.repository."+repoName); err != nil {
			return result, err
		}
	}
	// Release the Workspace lock before taking Workspace -> Repository locks
	// for Dist reconciliation. Each phase reloads the current locked config; a
	// serialized lifecycle command may legitimately commit between phases.
	if err := lock.Close(); err != nil {
		return result, err
	}
	lock = nil
	for _, repoName := range config.RepositoryNames(cfg) {
		remaining, err := remainingLockTimeout(opts.Timeout, started)
		if err != nil {
			return result, err
		}
		created, err := initializeDeclaredDists(ctx, root, repoName, opts.Fault, LockOptions{Timeout: remaining, NoWait: opts.NoWait})
		result.DistsInitialized += created
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

func rejectUninitializedRepositoryAdoption(root, repoName string) error {
	if err := config.ValidateName(repoName); err != nil {
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	dbPath := filepath.Join(root, ".sow", repoName+".db")
	if _, err := os.Lstat(dbPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, candidate := range []string{
		filepath.Join(root, repoName),
		filepath.Join(root, ".sow", repoName),
		filepath.Join(root, ".sow", "repo-locks", repoName+".lock"),
		dbPath + "-wal",
		dbPath + "-shm",
		dbPath + "-journal",
	} {
		if _, err := os.Lstat(candidate); err == nil {
			return fmt.Errorf("%w: refusing to adopt pre-existing uninitialized repository path %q", ErrRejected, candidate)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func recoverInitializedRepositories(ctx context.Context, root string, cfg config.Config, opts LockOptions, started time.Time) error {
	for _, repoName := range config.RepositoryNames(cfg) {
		complete, err := repositoryShellComplete(root, repoName)
		if err != nil {
			return err
		}
		if !complete {
			continue
		}
		remaining, err := remainingLockTimeout(opts.Timeout, started)
		if err != nil {
			return err
		}
		repoLock, err := acquireFileLock(ctx, filepath.Join(root, ".sow", "repo-locks", repoName+".lock"), remaining, opts.NoWait)
		if err != nil {
			return err
		}
		if err := validateRepositoryLayout(root, repoName); err != nil {
			repoLock.Close()
			return err
		}
		store, err := openExistingState(filepath.Join(root, ".sow", repoName+".db"))
		if err != nil {
			repoLock.Close()
			return fmt.Errorf("%w: %v", ErrIntegrity, err)
		}
		recoverErr := recoverDistOperations(ctx, root, repoName, store)
		if recoverErr == nil {
			recoverErr = store.Checkpoint(ctx)
		}
		closeErr := errors.Join(store.Close(), repoLock.Close())
		if err := errors.Join(recoverErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

func CheckConfig(ctx context.Context, opts WorkspaceOptions) (result ConfigCheckResult, resultErr error) {
	if ctx == nil {
		return ConfigCheckResult{}, errors.New("managed: nil context")
	}
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts, false)
	if err != nil {
		return ConfigCheckResult{}, err
	}
	if workspaceLock != nil {
		defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	}
	return checkConfigAtRoot(ctx, ws.Root, cfg)
}

// checkConfigAtRoot is the state-aware, read-only preflight shared by
// `config check` and every Managed lifecycle mutation.  Lifecycle callers run
// it while holding the Workspace lock, after recovering the selected
// Repository, so a hand-edited sow.yml cannot silently invalidate state.
type configInspectionMode struct {
	skipLiveMetadataRepositories map[string]struct{}
	skipLiveMetadataDists        map[distMetadataIdentity]struct{}
	lockedRepositories           map[string]struct{}
	repositories                 map[string]struct{}
	signingFormats               map[string]signingFormatMask
}

type signingFormatMask struct {
	rpm bool
	deb bool
}

type distMetadataIdentity struct {
	repository string
	dist       string
}

func checkConfigAtRoot(ctx context.Context, root string, cfg config.Config) (ConfigCheckResult, error) {
	return checkConfigAtRootMode(ctx, root, cfg, configInspectionMode{})
}

func checkConfigAtRootWithLockedRepositories(ctx context.Context, root string, cfg config.Config, lockedRepositories map[string]struct{}) (ConfigCheckResult, error) {
	return checkConfigAtRootMode(ctx, root, cfg, configInspectionMode{lockedRepositories: lockedRepositories})
}

func checkConfigAtRootForLockedRepository(ctx context.Context, root string, cfg config.Config, repository string, formats signingFormatMask) (ConfigCheckResult, error) {
	return checkConfigAtRootMode(ctx, root, cfg, configInspectionMode{
		lockedRepositories: map[string]struct{}{repository: {}},
		repositories:       map[string]struct{}{repository: {}},
		signingFormats:     map[string]signingFormatMask{repository: formats},
	})
}

func configuredSigningFormats(cfg config.Config, repository string, names []string) signingFormatMask {
	var formats signingFormatMask
	for _, name := range names {
		if cfg.Repositories[repository].Dists[name].Format == "rpm" {
			formats.rpm = true
		} else if cfg.Repositories[repository].Dists[name].Format == "deb" {
			formats.deb = true
		}
	}
	return formats
}

func checkConfigAtRootForForcedRemoval(ctx context.Context, root string, cfg config.Config, repository string) (ConfigCheckResult, error) {
	return checkConfigAtRootMode(ctx, root, cfg, configInspectionMode{skipLiveMetadataRepositories: map[string]struct{}{repository: {}}})
}

func checkConfigAtRootForForcedDistRemovalWithLockedRepositories(ctx context.Context, root string, cfg config.Config, repository, dist string, lockedRepositories map[string]struct{}) (ConfigCheckResult, error) {
	return checkConfigAtRootMode(ctx, root, cfg, configInspectionMode{
		skipLiveMetadataDists: map[distMetadataIdentity]struct{}{{repository: repository, dist: dist}: {}},
		lockedRepositories:    lockedRepositories,
	})
}

func checkConfigAtRootMode(ctx context.Context, root string, cfg config.Config, mode configInspectionMode) (ConfigCheckResult, error) {
	result := ConfigCheckResult{Workspace: root, Repositories: len(cfg.Repositories)}
	readLocks := []*fileLock{}
	defer func() {
		for index := len(readLocks) - 1; index >= 0; index-- {
			_ = readLocks[index].Close()
		}
	}()
	stateRootExists, err := validateReadOnlyStateRoot(root, true)
	if err != nil {
		return ConfigCheckResult{}, err
	}
	stateRepositories := map[string]struct{}{}
	if stateRootExists {
		if err := validateReadOnlyControlPaths(root); err != nil {
			return ConfigCheckResult{}, err
		}
		if err := validateReadOnlyStateEntries(root, cfg); err != nil {
			return ConfigCheckResult{}, err
		}
		if journal, err := inspectWorkspaceJournal(root); err != nil {
			return ConfigCheckResult{}, err
		} else if journal != nil {
			return ConfigCheckResult{}, fmt.Errorf("%w: workspace operation %q is pending recovery", ErrIntegrity, journal.ID)
		}
		for _, repoName := range config.RepositoryNames(cfg) {
			dbPath := filepath.Join(root, ".sow", repoName+".db")
			info, err := os.Lstat(dbPath)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return ConfigCheckResult{}, fmt.Errorf("%w: repository database %q is unsafe", ErrIntegrity, filepath.Base(dbPath))
			}
			stateRepositories[repoName] = struct{}{}
		}
	}
	refs := []config.StateArchitectureReference{}
	for _, repoName := range config.RepositoryNames(cfg) {
		if len(mode.repositories) != 0 {
			if _, selected := mode.repositories[repoName]; !selected {
				continue
			}
		}
		repo := cfg.Repositories[repoName]
		result.Dists += len(repo.Dists)
		formats, scoped := mode.signingFormats[repoName]
		if !scoped {
			formats = signingFormatMask{rpm: true, deb: true}
		}
		if err := validateSigningApplicabilityForFormats(ctx, root, repo.Signing, formats.rpm, formats.deb); err != nil {
			return ConfigCheckResult{}, fmt.Errorf("%w: repository %q signing: %v", ErrRejected, repoName, err)
		}
		_, repositoryInitialized := stateRepositories[repoName]
		repositoryPath, pathErr := config.RepositoryPath(root, repoName)
		if pathErr != nil {
			class := ErrRejected
			if repositoryInitialized {
				class = ErrIntegrity
			}
			return ConfigCheckResult{}, fmt.Errorf("%w: repository %q path: %v", class, repoName, pathErr)
		}
		for _, candidate := range []string{
			repositoryPath,
			filepath.Join(repositoryPath, "pool"),
			filepath.Join(repositoryPath, "dists"),
			filepath.Join(root, ".sow", repoName),
			filepath.Join(root, ".sow", repoName, "stage"),
			filepath.Join(root, ".sow", repoName, "pending"),
			filepath.Join(root, ".sow", repoName, "recovery"),
		} {
			info, statErr := os.Lstat(candidate)
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			if !repositoryInitialized && statErr == nil {
				return ConfigCheckResult{}, fmt.Errorf("%w: refusing to adopt pre-existing uninitialized repository path %q", ErrRejected, candidate)
			}
			if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return ConfigCheckResult{}, fmt.Errorf("%w: configured repository path %q conflicts with an existing object", ErrRejected, candidate)
			}
		}
		dbPath := filepath.Join(root, ".sow", repoName+".db")
		stateDists := map[string]struct{}{}
		if repositoryInitialized {
			if _, alreadyLocked := mode.lockedRepositories[repoName]; !alreadyLocked {
				repoLock, lockErr := acquireSharedFileLock(ctx, filepath.Join(root, ".sow", "repo-locks", repoName+".lock"))
				if lockErr != nil {
					return ConfigCheckResult{}, classifyReadLockError(fmt.Sprintf("acquire repository %q read lock", repoName), lockErr)
				}
				readLocks = append(readLocks, repoLock)
			}
			if err := validateRepositoryLayout(root, repoName); err != nil {
				return ConfigCheckResult{}, err
			}
			store, openErr := openReadOnlyState(dbPath)
			if openErr != nil {
				return ConfigCheckResult{}, fmt.Errorf("%w: repository %q state: %v", ErrIntegrity, repoName, openErr)
			}
			dists, listErr := store.ListDists(ctx)
			architectureRefs, refsErr := store.ArchitectureReferences(ctx)
			pending, pendingErr := store.PendingOperations(ctx)
			closeErr := store.Close()
			if err := errors.Join(listErr, refsErr, pendingErr, closeErr); err != nil {
				return ConfigCheckResult{}, fmt.Errorf("%w: repository %q state: %v", ErrIntegrity, repoName, err)
			}
			if len(pending) != 0 {
				return ConfigCheckResult{}, fmt.Errorf("%w: repository %q has pending operation %q requiring recovery", ErrIntegrity, repoName, pending[0].ID)
			}
			for _, ref := range architectureRefs {
				family, neutral, err := ref.Architecture, false, error(nil)
				if ref.Source == "built generation" {
					if family != "x86_64" && family != "aarch64" {
						err = fmt.Errorf("unknown canonical architecture %q", family)
					}
				} else {
					family, neutral, err = canonicalStateArchitecture(ref.Format, ref.Architecture)
				}
				if err != nil {
					return ConfigCheckResult{}, fmt.Errorf("%w: repository %q dist %q %s: %v", ErrIntegrity, repoName, ref.Dist, ref.Source, err)
				}
				if neutral {
					continue
				}
				refs = append(refs, config.StateArchitectureReference{Repository: repoName, Dist: ref.Dist, Architecture: family, Source: ref.Source})
			}
			stateDists = make(map[string]struct{}, len(dists))
			for _, dist := range dists {
				stateDists[dist.Name] = struct{}{}
				configured, exists := repo.Dists[dist.Name]
				if !exists {
					return ConfigCheckResult{}, fmt.Errorf("%w: state dist %q is absent from repository %q config", ErrRejected, dist.Name, repoName)
				}
				if configured.Format != dist.Format {
					return ConfigCheckResult{}, fmt.Errorf("%w: dist %q format differs between config and state", ErrIntegrity, dist.Name)
				}
				_, skipRepositoryMetadata := mode.skipLiveMetadataRepositories[repoName]
				_, skipDistMetadata := mode.skipLiveMetadataDists[distMetadataIdentity{repository: repoName, dist: dist.Name}]
				var viewErr error
				if skipRepositoryMetadata || skipDistMetadata {
					viewErr = validateLiveDistViewPaths(root, repoName, dist.Format, dist.Name, dist.Architectures)
				} else {
					viewErr = validateLiveDistViews(ctx, root, repoName, dist.Format, dist.Name, dist.Architectures)
				}
				if viewErr != nil {
					return ConfigCheckResult{}, viewErr
				}
			}
		} else {
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				candidate := dbPath + suffix
				if _, err := os.Lstat(candidate); err == nil {
					return ConfigCheckResult{}, fmt.Errorf("%w: refusing to adopt orphan repository database sidecar %q", ErrRejected, candidate)
				} else if !errors.Is(err, os.ErrNotExist) {
					return ConfigCheckResult{}, err
				}
			}
		}
		for distName := range repo.Dists {
			if _, initialized := stateDists[distName]; initialized {
				continue
			}
			if err := rejectUninitializedDistAdoption(root, repoName, distName); err != nil {
				return ConfigCheckResult{}, err
			}
		}
	}
	if err := config.ValidateStateArchitectureReferences(cfg, refs); err != nil {
		return ConfigCheckResult{}, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	return result, nil
}

func canonicalStateArchitecture(format, architecture string) (family string, neutral bool, err error) {
	switch format {
	case "rpm":
		switch architecture {
		case "x86_64", "aarch64":
			return architecture, false, nil
		case "noarch":
			return "", true, nil
		}
	case "deb":
		switch architecture {
		case "amd64":
			return "x86_64", false, nil
		case "arm64":
			return "aarch64", false, nil
		case "all":
			return "", true, nil
		}
	default:
		return "", false, fmt.Errorf("unsupported package format %q", format)
	}
	allowed := "x86_64, aarch64, noarch"
	if format == "deb" {
		allowed = "amd64, arm64, all"
	}
	return "", false, fmt.Errorf("unknown %s package architecture %q; supported %s package architectures are [%s] (canonical families [x86_64, aarch64, neutral]); use a supported package or update only supported architecture families in %s", format, architecture, format, allowed, config.ConfigFilename)
}

func validateReadOnlyControlPaths(root string) error {
	for _, candidate := range []struct {
		path string
		dir  bool
	}{
		{path: filepath.Join(root, ".sow", "workspace-ops"), dir: true},
		{path: filepath.Join(root, ".sow", "repo-locks"), dir: true},
		{path: filepath.Join(root, ".sow", "workspace.lock")},
	} {
		info, err := os.Lstat(candidate.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (candidate.dir && !info.IsDir()) || (!candidate.dir && !info.Mode().IsRegular()) {
			return fmt.Errorf("%w: reserved control path %q is unsafe", ErrIntegrity, candidate.path)
		}
	}
	lockRoot := filepath.Join(root, ".sow", "repo-locks")
	if _, err := os.Lstat(lockRoot); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("%w: inspect repository lock directory: %v", ErrIntegrity, err)
	}
	entries, err := listRootedDirectory(lockRoot)
	if err != nil {
		return fmt.Errorf("%w: inspect repository lock directory safely: %v", ErrIntegrity, err)
	}
	for _, entry := range entries {
		name := entry.Name
		if !strings.HasSuffix(name, ".lock") || config.ValidateName(strings.TrimSuffix(name, ".lock")) != nil {
			return fmt.Errorf("%w: repository lock entry %q is invalid", ErrIntegrity, name)
		}
		if uint32(entry.Stat.Mode)&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("%w: repository lock entry %q is unsafe", ErrIntegrity, name)
		}
	}
	return nil
}

func validateReadOnlyStateEntries(root string, cfg config.Config) error {
	allowed := map[string]struct{}{
		"workspace-ops":  {},
		"repo-locks":     {},
		"workspace.lock": {},
	}
	for repoName := range cfg.Repositories {
		allowed[repoName] = struct{}{}
		for _, suffix := range []string{".db", ".db-wal", ".db-shm", ".db-journal"} {
			allowed[repoName+suffix] = struct{}{}
		}
	}
	entries, err := listRootedDirectory(filepath.Join(root, ".sow"))
	if err != nil {
		return fmt.Errorf("%w: inspect state root entries: %v", ErrIntegrity, err)
	}
	for _, entry := range entries {
		if _, ok := allowed[entry.Name]; !ok {
			return fmt.Errorf("%w: state root contains unowned entry %q", ErrRejected, entry.Name)
		}
	}
	return nil
}

func ShowConfig(ctx context.Context, opts ConfigShowOptions) (result config.EffectiveConfig, resultErr error) {
	if ctx == nil {
		return config.EffectiveConfig{}, errors.New("managed: nil context")
	}
	ws, cfg, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return config.EffectiveConfig{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	// --all is a full-workspace display mode. Selectors are intentionally
	// ignored so callers can promote a scoped invocation without first
	// rewriting it.
	if opts.All {
		return effectiveConfigView(ctx, ws.Root, cfg, config.ViewOptions{})
	}
	repository := opts.Repository
	dists := append([]string(nil), opts.Dists...)
	if opts.Dist != "" {
		dists = append(dists, opts.Dist)
	}
	dists = stableUniqueStrings(dists)
	if repository == "" && (len(cfg.Repositories) != 0 || len(dists) != 0) {
		selection, err := config.SelectRepository(ws, cfg, config.SelectRepositoryOptions{})
		if err != nil {
			return config.EffectiveConfig{}, fmt.Errorf("%w: %v", ErrWorkspaceInput, err)
		}
		repository = selection.Name
	}
	if repository != "" {
		if err := config.ValidateName(repository); err != nil {
			return config.EffectiveConfig{}, fmt.Errorf("%w: %v", ErrRejected, err)
		}
		if _, ok := cfg.Repositories[repository]; !ok {
			return config.EffectiveConfig{}, fmt.Errorf("%w: repository %q is not configured", ErrRejected, repository)
		}
	}
	if len(dists) == 0 && repository != "" {
		dist, inside, err := config.DistContainingCWD(ws, cfg, repository)
		if err != nil {
			return config.EffectiveConfig{}, fmt.Errorf("%w: %v", ErrWorkspaceInput, err)
		}
		if inside {
			dists = []string{dist}
		}
	}
	if len(dists) == 0 {
		return effectiveConfigView(ctx, ws.Root, cfg, config.ViewOptions{Repository: repository})
	}
	if repository == "" {
		return config.EffectiveConfig{}, fmt.Errorf("%w: a repository is required when a dist is selected", ErrWorkspaceInput)
	}
	for _, dist := range dists {
		if err := config.ValidateName(dist); err != nil {
			return config.EffectiveConfig{}, fmt.Errorf("%w: %v", ErrRejected, err)
		}
		if _, ok := cfg.Repositories[repository].Dists[dist]; !ok {
			return config.EffectiveConfig{}, fmt.Errorf("%w: dist %q is not configured in repository %q", ErrRejected, dist, repository)
		}
	}

	// Resolve signing identities once from the same immutable config snapshot,
	// then project the requested Dist set. Besides avoiding repeated agent/GPG
	// work, this guarantees repeatable -d selectors cannot observe different
	// config generations.
	view, err := effectiveConfigView(ctx, ws.Root, cfg, config.ViewOptions{Repository: repository})
	if err != nil {
		return config.EffectiveConfig{}, err
	}
	effectiveRepo := view.Repositories[repository]
	selected := make(map[string]config.EffectiveDist, len(dists))
	for _, dist := range dists {
		selected[dist] = effectiveRepo.Dists[dist]
	}
	effectiveRepo.Dists = selected
	view.Repositories[repository] = effectiveRepo
	return view, nil
}

func ensureWorkspaceLock(root string) (bool, error) {
	stateRoot := filepath.Join(root, ".sow")
	path := filepath.Join(stateRoot, "workspace.lock")
	bootstrapDeadline := time.Now().Add(2 * time.Second)
	for {
		info, err := os.Lstat(path)
		if err == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return false, fmt.Errorf("%w: workspace lock is missing or unsafe", ErrIntegrity)
			}
			entries, readErr := listRootedDirectory(stateRoot)
			if readErr != nil {
				if errors.Is(readErr, errRootedDirectoryChangedDuringEnumeration) && time.Now().Before(bootstrapDeadline) {
					time.Sleep(2 * time.Millisecond)
					continue
				}
				return false, readErr
			}
			return len(entries) == 1 && entries[0].Name == "workspace.lock", nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("%w: workspace lock is missing or unsafe", ErrIntegrity)
		}
		entries, readErr := listRootedDirectory(stateRoot)
		if readErr != nil {
			if errors.Is(readErr, errRootedDirectoryChangedDuringEnumeration) && time.Now().Before(bootstrapDeadline) {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			return false, readErr
		}
		if len(entries) == 0 {
			created, createErr := durableEnsureRegularFile(path, 0o600)
			return created, createErr
		}
		if len(entries) == 1 && entries[0].Name == "workspace.lock" {
			continue
		}
		return false, fmt.Errorf("%w: workspace lock is missing from non-empty state root", ErrIntegrity)
	}
}

func ensureStateDirectories(root string) error {
	stateRoot := filepath.Join(root, ".sow")
	for _, name := range []string{"workspace-ops", "repo-locks"} {
		path := filepath.Join(stateRoot, name)
		if info, err := os.Lstat(path); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: private path %q is not a real directory", ErrRejected, path)
			}
		} else if errors.Is(err, os.ErrNotExist) {
			if _, err := durableEnsureDir(path, 0o700); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return syncDir(stateRoot)
}

func ensureRepositoryShell(root, name string) (bool, error) {
	if err := config.ValidateName(name); err != nil {
		return false, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	repoRoot, err := ownedPath(root, name)
	if err != nil {
		return false, err
	}
	created := false
	if info, statErr := os.Lstat(repoRoot); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("%w: repository path %q is not a real directory", ErrRejected, repoRoot)
		}
	} else if errors.Is(statErr, os.ErrNotExist) {
		if err := durableMkdir(repoRoot, 0o755); err != nil {
			return false, err
		}
		created = true
	} else {
		return false, statErr
	}
	for _, child := range []string{"pool", "dists"} {
		path := filepath.Join(repoRoot, child)
		if info, statErr := os.Lstat(path); statErr == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return false, fmt.Errorf("%w: repository child %q is not a real directory", ErrRejected, path)
			}
		} else if errors.Is(statErr, os.ErrNotExist) {
			if err := durableMkdir(path, 0o755); err != nil {
				return false, err
			}
			created = true
		} else {
			return false, statErr
		}
	}
	private := filepath.Join(root, ".sow", name)
	if info, statErr := os.Lstat(private); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("%w: repository private path is unsafe", ErrRejected)
		}
	} else if errors.Is(statErr, os.ErrNotExist) {
		if err := durableMkdir(private, 0o700); err != nil {
			return false, err
		}
		created = true
	} else {
		return false, statErr
	}
	for _, child := range []string{"stage", "pending", "recovery"} {
		path := filepath.Join(private, child)
		if info, err := os.Lstat(path); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return false, fmt.Errorf("%w: repository private child %q is unsafe", ErrRejected, path)
			}
		} else if errors.Is(err, os.ErrNotExist) {
			if err := durableMkdir(path, 0o700); err != nil {
				return false, err
			}
			created = true
		} else {
			return false, err
		}
	}
	lockPath := filepath.Join(root, ".sow", "repo-locks", name+".lock")
	lockCreated, err := durableEnsureRegularFile(lockPath, 0o600)
	if err != nil {
		return false, err
	}
	created = created || lockCreated
	dbPath := filepath.Join(root, ".sow", name+".db")
	if _, statErr := os.Lstat(dbPath); errors.Is(statErr, os.ErrNotExist) {
		store, err := openState(dbPath)
		if err != nil {
			return false, err
		}
		if err := store.Close(); err != nil {
			return false, err
		}
		if err := syncDir(filepath.Join(root, ".sow")); err != nil {
			return false, err
		}
		created = true
	} else if statErr != nil {
		return false, statErr
	} else {
		store, err := openInitializingState(dbPath)
		if err != nil {
			return false, fmt.Errorf("%w: %v", ErrIntegrity, err)
		}
		if err := store.Close(); err != nil {
			return false, err
		}
	}
	return created, errors.Join(syncDir(repoRoot), syncDir(private), syncDir(filepath.Join(root, ".sow")), syncDir(root))
}

func repositoryShellComplete(root, name string) (bool, error) {
	paths := []struct {
		path string
		dir  bool
	}{
		{filepath.Join(root, name), true},
		{filepath.Join(root, name, "pool"), true},
		{filepath.Join(root, name, "dists"), true},
		{filepath.Join(root, ".sow", name), true},
		{filepath.Join(root, ".sow", name, "stage"), true},
		{filepath.Join(root, ".sow", name, "pending"), true},
		{filepath.Join(root, ".sow", name, "recovery"), true},
		{filepath.Join(root, ".sow", "repo-locks", name+".lock"), false},
		{filepath.Join(root, ".sow", name+".db"), false},
	}
	for _, expected := range paths {
		info, err := os.Lstat(expected.path)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if info.Mode()&os.ModeSymlink != 0 || (expected.dir && !info.IsDir()) || (!expected.dir && !info.Mode().IsRegular()) {
			return false, fmt.Errorf("%w: initialized repository path %q has unsafe type", ErrRejected, expected.path)
		}
	}
	// Completeness here is only the fixed-path precondition for locked recovery.
	// recoverInitializedRepositories immediately opens the database through the
	// authorized writable path, which can reconstruct SQLite's persistent WAL
	// coordination sidecars after a crash. A read-only schema probe here would
	// either mutate -shm coordination marks or strand an otherwise recoverable
	// hot WAL.
	return true, nil
}

func sortedDistConfigNames(repo config.RepositoryConfig) []string {
	names := make([]string, 0, len(repo.Dists))
	for name := range repo.Dists {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
