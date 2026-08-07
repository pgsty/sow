package managed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

// Status is intentionally lock-probing rather than lock-taking and never
// hashes the public repository. It remains observable while another process
// owns the write lock and never performs recovery or a SQLite checkpoint.
func Status(ctx context.Context, opts StatusOptions) (result StatusResult, resultErr error) {
	result = StatusResult{DirtyDists: []string{}, DirtyReasons: []string{}}
	if ctx == nil {
		return result, fmt.Errorf("managed: nil context")
	}
	ws, err := config.Discover(config.DiscoverOptions{Workdir: opts.Workdir, CWD: opts.CWD, SOWDir: opts.SOWDir})
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrWorkspaceInput, err)
	}
	rootGuard, err := bindDiscoveredWorkspaceRoot(ws)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	cfg, _, configSHA, _, err := config.LoadWorkspaceDocumentForMigration(ws)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrWorkspaceInput, err)
	}
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return result, err
	}
	result.Repository = repoName
	selected, err := validateOptionalDists(cfg, repoName, opts.Dists)
	if err != nil {
		return result, err
	}
	scoped := len(selected) != 0
	if !scoped {
		selected = sortedDistConfigNames(cfg.Repositories[repoName])
	}
	database := filepath.Join(ws.Root, ".sow", repoName+".db")
	legacyFence, err := state.ReadOnlyRequiresLifecycleFence(database)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	var compatibilityLock *fileLock
	if legacyFence {
		// A settled legacy database has no persistent WAL coordination files,
		// so the physically read-only SQLite path must use immutable mode. Hold
		// a shared lifecycle lock for that one compatibility case; otherwise a
		// first current writer could checkpoint beneath the immutable reader.
		// Current repositories keep -wal/-shm and remain observable while a
		// writer owns the exclusive lifecycle lock.
		compatibilityLock, err = acquireSharedFileLock(ctx, filepath.Join(ws.Root, ".sow", "repo-locks", repoName+".lock"))
		if err != nil {
			return result, classifyReadLockError("fence legacy repository status read", err)
		}
		defer func() { resultErr = errors.Join(resultErr, compatibilityLock.Close()) }()
	}
	store, err := openReadOnlyState(database)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	initialLocked, initialHolder, probeErr := probeFileLock(filepath.Join(ws.Root, ".sow", "repo-locks", repoName+".lock"))
	if probeErr != nil {
		result.Status = "error"
		result.DirtyReasons = append(result.DirtyReasons, "repository lock evidence is unavailable or unsafe")
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	result.Status = "clean"
	if !scoped || summary.Status == "error" {
		result.Status = summary.Status
	}
	if probeErr != nil {
		result.Status = "error"
	}
	// Status deliberately avoids package and public-tree hashing, but the
	// SQLite semantic relations are a cheap part of readiness.  Keep this
	// observation read-only and report corrupt state as status=error rather
	// than returning a command failure: operators must still be able to inspect
	// a damaged repository while ReadyToCopy remains false.
	if stateErr := store.Check(ctx); stateErr != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		result.Status = "error"
		result.DirtyReasons = append(result.DirtyReasons, "repository state relations are invalid: "+stateErr.Error())
	}
	identity, identityErr := store.RepositoryIdentity(ctx)
	transition, _, transitionErr := loadTransitionJournal(ws.Root, repoName)
	transitionActive := identityErr == nil && identity.LayoutVersion != state.LayoutSinglePayloadV1 || transition != nil || transitionErr != nil
	if identityErr != nil {
		result.Status = "error"
		result.DirtyReasons = append(result.DirtyReasons, "repository identity is invalid: "+identityErr.Error())
	} else if transitionActive {
		if transitionErr != nil {
			result.Status = "error"
			result.DirtyReasons = append(result.DirtyReasons, "transition journal is invalid: "+transitionErr.Error())
		} else if transition == nil {
			result.Status = "error"
			result.DirtyReasons = append(result.DirtyReasons, "non-terminal Repository has no transition journal")
		} else if _, transitionErr := validateTransitionBinding(ctx, ws.Root, repoName, cfg, store, *transition, time.Now().UTC()); transitionErr != nil {
			result.Status = "error"
			result.DirtyReasons = append(result.DirtyReasons, "transition closure is invalid: "+transitionErr.Error())
		} else {
			result.Status = statusAtLeast(result.Status, "recovering")
			result.DirtyReasons = append(result.DirtyReasons, fmt.Sprintf("layout transition is %s", transition.Phase))
		}
	}
	result.DesiredRevision, result.BuiltGeneration = summary.DesiredRevision, summary.BuiltGeneration
	result.RepositoryLocked, result.LockHolder = initialLocked, initialHolder
	for _, issue := range statusPublicShellIssues(ws.Root, repoName) {
		result.Status = "error"
		result.DirtyReasons = append(result.DirtyReasons, issue)
	}
	if summary.DirtyReason != "" && (!scoped || summary.Status == "error") {
		result.DirtyReasons = append(result.DirtyReasons, summary.DirtyReason)
	}
	if summary.BuiltGeneration > 0 {
		if _, generationErr := store.GetGeneration(ctx, summary.BuiltGeneration); errors.Is(generationErr, state.ErrNotFound) {
			result.Status = statusAtLeast(result.Status, "dirty")
			result.DirtyReasons = append(result.DirtyReasons, "current migrated Generation has no physical manifest baseline")
		} else if generationErr != nil {
			return result, fmt.Errorf("%w: read current Generation: %v", ErrIntegrity, generationErr)
		}
	}
	storedDists, err := store.ListDists(ctx)
	if err != nil {
		return result, fmt.Errorf("%w: read Dist state: %v", ErrIntegrity, err)
	}
	for _, dist := range storedDists {
		if _, ok := cfg.Repositories[repoName].Dists[dist.Name]; !ok {
			result.Status = "error"
			result.DirtyDists = append(result.DirtyDists, dist.Name)
			result.DirtyReasons = append(result.DirtyReasons, fmt.Sprintf("built dist %s is absent from configuration", dist.Name))
		}
	}
	for _, distName := range selected {
		dist, err := store.GetDist(ctx, distName)
		if err != nil {
			result.Status = statusAtLeast(result.Status, "error")
			result.DirtyDists = append(result.DirtyDists, distName)
			result.DirtyReasons = append(result.DirtyReasons, fmt.Sprintf("dist %s state is unavailable", distName))
			continue
		}
		desired, desiredErr := store.MembershipDigests(ctx, distName, false)
		built, builtErr := store.MembershipDigests(ctx, distName, true)
		effectiveSHA, configDirty, configErr := observedEffectiveDistConfig(ctx, ws.Root, cfg, repoName, distName, dist)
		if desiredErr != nil || builtErr != nil || configErr != nil {
			result.Status = statusAtLeast(result.Status, "error")
			result.DirtyDists = append(result.DirtyDists, distName)
			result.DirtyReasons = append(result.DirtyReasons, fmt.Sprintf("dist %s projection cannot be read", distName))
			continue
		}
		membershipDirty := !sameStringSet(desired, built)
		effectiveConfigDirty := configDirty || effectiveSHA != "" && effectiveSHA != dist.EffectiveConfigSHA256
		if membershipDirty || effectiveConfigDirty {
			result.Status = statusAtLeast(result.Status, "dirty")
			result.DirtyDists = append(result.DirtyDists, distName)
			if membershipDirty {
				result.DirtyReasons = append(result.DirtyReasons, fmt.Sprintf("dist %s Desired and Built membership sets differ", distName))
			}
			if effectiveConfigDirty {
				result.DirtyReasons = append(result.DirtyReasons, fmt.Sprintf("dist %s effective configuration differs from built state", distName))
			}
		}
	}
	pendingObjects, err := store.ListPackageObjects(ctx, selected, false)
	if err != nil {
		return result, fmt.Errorf("%w: read pending payload summary: %v", ErrIntegrity, err)
	}
	for _, object := range pendingObjects {
		if object.Storage == "pending" {
			result.Pending.Count++
			result.Pending.Bytes += object.Size
		}
	}
	pending, err := store.PendingOperations(ctx)
	if err != nil {
		return result, err
	}
	pending = pendingOperationsForSelectedDists(pending, selected, scoped)
	if len(pending) != 0 {
		result.Status = statusAtLeast(result.Status, "recovering")
		result.Operation = publicOperationInfo(&pending[0])
		result.DirtyReasons = append(result.DirtyReasons, fmt.Sprintf("operation %s is %s", pending[0].ID, pending[0].State))
	}
	last, err := store.LastTerminalOperation(ctx)
	if err != nil {
		return result, err
	}
	result.RecentOperation = publicOperationInfo(last)
	if workspaceOperation, inspectErr := inspectWorkspaceJournal(ws.Root); inspectErr != nil {
		result.Status = "error"
		result.DirtyReasons = append(result.DirtyReasons, "workspace journal evidence is invalid")
	} else if workspaceOperation != nil && (workspaceOperation.Repository == "" || workspaceOperation.Repository == repoName) {
		result.Status = statusAtLeast(result.Status, "recovering")
		result.DirtyReasons = append(result.DirtyReasons, fmt.Sprintf("workspace operation %s is %s", workspaceOperation.ID, workspaceOperation.Phase))
	}
	finalLocked, finalHolder, finalProbeErr := probeFileLock(filepath.Join(ws.Root, ".sow", "repo-locks", repoName+".lock"))
	finalSummary, finalSummaryErr := store.Summary(ctx)
	_, _, finalConfigSHA, _, finalConfigErr := config.LoadWorkspaceDocumentForMigration(ws)
	if finalProbeErr != nil || finalSummaryErr != nil || finalConfigErr != nil {
		result.Status = "error"
		result.RepositoryLocked = true
		result.DirtyReasons = append(result.DirtyReasons, "repository observation could not be closed over a stable snapshot")
	} else if finalLocked || finalSummary != summary || finalConfigSHA != configSHA {
		result.RepositoryLocked = true
		result.DirtyReasons = append(result.DirtyReasons, "repository changed or was locked during status observation")
	}
	if finalHolder != "" {
		result.LockHolder = finalHolder
	}
	if result.RepositoryLocked {
		result.DirtyReasons = append(result.DirtyReasons, "repository write lock is held")
	}
	sort.Strings(result.DirtyDists)
	result.DirtyDists = stableUniqueStrings(result.DirtyDists)
	sort.Strings(result.DirtyReasons)
	result.DirtyReasons = stableUniqueStrings(result.DirtyReasons)
	result.ReadyToCopy = result.Status == "clean" && !result.RepositoryLocked
	return result, nil
}

func pendingOperationsForSelectedDists(operations []state.Operation, selected []string, scoped bool) []state.Operation {
	if !scoped {
		return operations
	}
	wanted := make(map[string]struct{}, len(selected))
	for _, name := range selected {
		wanted[name] = struct{}{}
	}
	result := make([]state.Operation, 0, len(operations))
	for _, operation := range operations {
		touches := true
		switch operation.Kind {
		case "add", "rm", "build":
			var payload struct {
				Dists []string `json:"dists"`
			}
			if json.Unmarshal([]byte(operation.PayloadJSON), &payload) == nil && len(payload.Dists) != 0 {
				touches = intersectsDistSelection(payload.Dists, wanted)
			}
		case "dist.new", "dist.init", "dist.rm":
			var payload struct {
				Name string `json:"name"`
			}
			if json.Unmarshal([]byte(operation.PayloadJSON), &payload) == nil && payload.Name != "" {
				_, touches = wanted[payload.Name]
			}
		}
		if touches {
			result = append(result, operation)
		}
	}
	return result
}

func intersectsDistSelection(names []string, selected map[string]struct{}) bool {
	for _, name := range names {
		if _, ok := selected[name]; ok {
			return true
		}
	}
	return false
}

func statusPublicShellIssues(root, repoName string) []string {
	issues := []string{}
	for _, candidate := range []struct {
		label string
		path  string
	}{
		{label: "repository", path: filepath.Join(root, repoName)},
		{label: "public Pool", path: filepath.Join(root, repoName, "pool")},
		{label: "public Dists", path: filepath.Join(root, repoName, "dists")},
	} {
		entry, statErr := os.Lstat(candidate.path)
		if statErr != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
			issues = append(issues, candidate.label+" directory is missing or unsafe")
		}
	}
	return issues
}

func publicOperationInfo(operation *state.Operation) *OperationInfo {
	if operation == nil {
		return nil
	}
	return &OperationInfo{ID: operation.ID, Kind: operation.Kind, State: operation.State, ErrorClass: operation.ErrorClass, CreatedAt: operation.CreatedAt, UpdatedAt: operation.UpdatedAt}
}
