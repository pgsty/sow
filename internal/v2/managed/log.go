package managed

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

const exportLogPageSize = 256

const logPruneOperationVersion = 1

type logPruneOperationPayload struct {
	Version    int    `json:"version"`
	Repository string `json:"repository"`
	Before     string `json:"before"`
}

func decodeLogPrunePayload(raw, repoName string) (logPruneOperationPayload, time.Time, error) {
	var payload logPruneOperationPayload
	if err := jsonUnmarshalStrict(raw, &payload); err != nil || payload.Version != logPruneOperationVersion || payload.Repository != repoName {
		return payload, time.Time{}, fmt.Errorf("%w: invalid log prune operation payload", ErrIntegrity)
	}
	before, err := time.Parse(time.RFC3339Nano, payload.Before)
	if err != nil || before.IsZero() {
		return payload, time.Time{}, fmt.Errorf("%w: invalid log prune cutoff", ErrIntegrity)
	}
	return payload, before.UTC(), nil
}

func recoverLogPruneOperation(ctx context.Context, repoName string, store *state.Store, operation state.Operation) error {
	_, before, err := decodeLogPrunePayload(operation.PayloadJSON, repoName)
	if err != nil {
		return err
	}
	if operation.State == state.OperationPlanned {
		if err := store.SetOperationState(ctx, operation.ID, state.OperationStaged, ""); err != nil {
			return err
		}
		operation.State = state.OperationStaged
	}
	if operation.State == state.OperationStaged || operation.State == state.OperationRecovering {
		if _, err := store.ApplyPruneOperation(ctx, operation.ID, before); err != nil {
			return err
		}
		operation.State = state.OperationApplied
	}
	if operation.State != state.OperationApplied {
		return fmt.Errorf("%w: log prune operation is pending in %s", ErrIntegrity, operation.State)
	}
	return store.FinishPruneOperation(ctx, operation.ID)
}

func Log(ctx context.Context, opts LogOptions) (result LogResult, resultErr error) {
	result = LogResult{Operations: []state.Operation{}}
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
	dist, err := oneLogDist(cfg, repoName, opts.Dists)
	if err != nil {
		return result, err
	}
	store, repoLock, err := openReadRepository(ctx, ws.Root, repoName)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if opts.Operation != "" {
		detail, err := store.GetOperation(ctx, opts.Operation)
		if err != nil {
			if errors.Is(err, state.ErrNotFound) {
				return result, fmt.Errorf("%w: operation %q was not found", ErrRejected, opts.Operation)
			}
			return result, err
		}
		if dist != "" && !operationTouchesDist(detail.Operation.PayloadJSON, dist) {
			return result, fmt.Errorf("%w: operation %q does not touch Dist %q", ErrRejected, opts.Operation, dist)
		}
		result.Detail = &detail
		return result, nil
	}
	result.Operations, err = store.ListOperations(ctx, 50, dist)
	return result, err
}

func ExportLog(ctx context.Context, opts LogOptions, output io.Writer) (count int, resultErr error) {
	if output == nil {
		return 0, errors.New("managed: nil log export writer")
	}
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return 0, err
	}
	dist, err := oneLogDist(cfg, repoName, opts.Dists)
	if err != nil {
		return 0, err
	}
	store, repoLock, err := openReadRepository(ctx, ws.Root, repoName)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	writer := bufio.NewWriter(output)
	var cursor *state.Operation
	for {
		operations, err := store.ListTerminalOperationPage(ctx, exportLogPageSize, dist, cursor)
		if err != nil {
			return count, err
		}
		for index := range operations {
			detail, err := store.GetOperation(ctx, operations[index].ID)
			if err != nil {
				return count, err
			}
			data, err := json.Marshal(detail)
			if err != nil {
				return count, err
			}
			if _, err := writer.Write(append(data, '\n')); err != nil {
				return count, err
			}
			count++
		}
		if len(operations) < exportLogPageSize {
			break
		}
		last := operations[len(operations)-1]
		cursor = &last
	}
	if err := writer.Flush(); err != nil {
		return count, err
	}
	return count, nil
}

func PruneLog(ctx context.Context, opts LogPruneOptions) (result LogPruneResult, resultErr error) {
	result = LogPruneResult{Before: opts.Before}
	if opts.Before.IsZero() {
		return result, fmt.Errorf("%w: log prune requires an absolute cutoff", ErrRejected)
	}
	ws, _, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	_, _, repoName, workspaceLock, repoLock, err := acquireSelectedRepositoryLocks(ctx, ws, opts.Repository, opts.LockOptions)
	if err != nil {
		return result, err
	}
	result.Repository = repoName
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := recoverDistOperations(ctx, ws.Root, repoName, store); err != nil {
		return result, err
	}
	id, err := operationID()
	if err != nil {
		return result, err
	}
	result.Operation = id
	payload := logPruneOperationPayload{Version: logPruneOperationVersion, Repository: repoName, Before: opts.Before.UTC().Format(time.RFC3339Nano)}
	payloadData, err := json.Marshal(payload)
	if err != nil {
		return result, err
	}
	defer func() {
		if resultErr == nil || isInjectedFault(resultErr) {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), operationFailureFinalizeTimeout)
		defer cancel()
		detail, inspectErr := store.GetOperation(cleanupCtx, id)
		if inspectErr != nil || detail.Operation.State != state.OperationPlanned && detail.Operation.State != state.OperationStaged {
			return
		}
		class, message := safeOperationFailure(resultErr)
		failure := fmt.Sprintf(`{"before":%q,"pruned":0}`, payload.Before)
		resultErr = errors.Join(resultErr, store.FailOperation(cleanupCtx, id, class, message, failure))
	}()
	if err := store.BeginOperation(ctx, state.Operation{ID: id, Kind: "log.prune", State: state.OperationPlanned, PayloadJSON: string(payloadData)}); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "log.prune.planned"); err != nil {
		return result, err
	}
	if err := store.SetOperationState(ctx, id, state.OperationStaged, ""); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "log.prune.staged"); err != nil {
		return result, err
	}
	result.Pruned, err = store.ApplyPruneOperation(ctx, id, opts.Before)
	if err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "log.prune.applied"); err != nil {
		return result, err
	}
	if err := store.FinishPruneOperation(ctx, id); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "log.prune.done"); err != nil {
		return result, err
	}
	return result, nil
}

func oneLogDist(cfg config.Config, repoName string, dists []string) (string, error) {
	_ = cfg
	_ = repoName
	names := stableUniqueStrings(dists)
	for _, name := range names {
		if err := config.ValidateName(name); err != nil {
			return "", fmt.Errorf("%w: invalid historical Dist filter: %v", ErrRejected, err)
		}
	}
	if len(names) > 1 {
		return "", fmt.Errorf("%w: log accepts at most one --dist filter", ErrRejected)
	}
	if len(names) == 1 {
		return names[0], nil
	}
	return "", nil
}

func operationTouchesDist(payloadJSON, dist string) bool {
	var payload struct {
		Dists []string `json:"dists"`
		Name  string   `json:"name"`
	}
	if json.Unmarshal([]byte(payloadJSON), &payload) != nil {
		return false
	}
	return payload.Name == dist || slices.Contains(payload.Dists, dist)
}
