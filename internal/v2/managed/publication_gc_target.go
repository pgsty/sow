package managed

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/pgsty/sow/internal/v2/state"
)

type TargetGCOptions struct {
	WorkspaceOptions
	LockOptions
	Target  string
	Fault   func(string) error
	now     func() time.Time
	backend publicationBackend
}

type TargetGCResult struct {
	Repository        string `json:"repository"`
	Target            string `json:"target"`
	Provider          string `json:"provider"`
	Phase             string `json:"phase"`
	Reports           int    `json:"reports"`
	Candidates        int    `json:"candidates"`
	DeletedObjects    int    `json:"deleted_objects"`
	DeletedBytes      int64  `json:"deleted_bytes"`
	RetainedObjects   int    `json:"retained_objects"`
	PendingGrace      int    `json:"pending_grace"`
	CompletedAttempts int    `json:"completed_attempts"`
	Noop              bool   `json:"noop"`
}

// TargetGC is the only explicit remote-maintenance entry point. Filesystem
// targets use report-bound exact deletion receipts; R2 persists the same exact
// candidate report but never calls DeleteObject and reports every candidate as
// retained.
func TargetGC(ctx context.Context, opts TargetGCOptions) (result TargetGCResult, resultErr error) {
	if ctx == nil || opts.Target == "" {
		return result, fmt.Errorf("%w: target GC requires a context and target", ErrRejected)
	}
	ws, _, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	cfg, _, repoName, workspaceLock, repoLock, err := acquirePublicationLocks(ctx, ws, opts.Target, opts.LockOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close(), repoLock.Close()) }()
	targetConfig, configured := cfg.Targets[opts.Target]
	if !configured || targetConfig.Repository != repoName {
		return result, fmt.Errorf("%w: target %q is not bound to selected repository", ErrRejected, opts.Target)
	}
	result.Repository, result.Target, result.Provider = repoName, opts.Target, targetConfig.Provider
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := store.RequireTerminalLayout(ctx); err != nil {
		return result, fmt.Errorf("%w: target GC is unavailable during layout transition: %v", ErrNotReady, err)
	}
	now := publicationObservedTime(opts.now)
	if err := store.ObserveRepositoryTime(ctx, now); err != nil {
		return result, fmt.Errorf("%w: target GC clock preflight: %v", ErrIntegrity, err)
	}
	if err := recoverDistOperations(ctx, ws.Root, repoName, store); err != nil {
		return result, err
	}
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		return result, err
	}
	binding, err := publicationTargetBinding(cfg, opts.Target, identity.RepositoryID)
	if err != nil {
		return result, err
	}
	if err := store.BindPublicationTarget(ctx, binding); err != nil {
		return result, fmt.Errorf("%w: bind publication target: %v", ErrIntegrity, err)
	}
	if active, activeErr := store.GetActivePublicationAttempt(ctx, binding.TargetIdentity); activeErr == nil {
		return result, fmt.Errorf("%w: target %q has write-active publication attempt %s in phase %s", ErrNotReady, opts.Target, active.AttemptIdentity, active.Phase)
	} else if !errors.Is(activeErr, state.ErrNotFound) {
		return result, activeErr
	}
	if targetConfig.Provider == "filesystem" {
		targetRoot, err := filesystemPublicationRoot(targetConfig)
		if err != nil {
			return result, err
		}
		if err := rejectPublicationSourceTargetOverlap(filepath.Join(ws.Root, repoName), filepath.Join(ws.Root, ".sow"), targetRoot); err != nil {
			return result, err
		}
	}
	backend := opts.backend
	if backend == nil {
		backend, err = newPublicationBackend(targetConfig)
		if err != nil {
			return result, err
		}
	} else if backend.Provider() != targetConfig.Provider {
		return result, fmt.Errorf("%w: publication backend provider differs from target", ErrRejected)
	}
	maintenance, err := store.ListPublicationMaintenance(ctx, binding.TargetIdentity)
	if err != nil {
		return result, err
	}
	if len(maintenance) == 0 {
		result.Phase, result.Noop = "done", true
		return result, nil
	}
	for _, item := range maintenance {
		if item.AttemptPhase == "deletion_verified" || item.AttemptPhase == "retained_reported" {
			report, err := store.GetPublicationCandidateReport(ctx, item.CheckpointIdentity)
			if err != nil {
				return result, err
			}
			if err := store.CompletePublicationAttempt(ctx, item.AttemptIdentity, report.ReportIdentity); err != nil {
				return result, err
			}
			result.CompletedAttempts++
			continue
		}
		if item.AttemptPhase != "grace" || item.GraceState != "grace" {
			return result, fmt.Errorf("%w: unsupported target maintenance state %s/%s", ErrIntegrity, item.AttemptPhase, item.GraceState)
		}
		if now.Before(item.NotBefore) {
			result.PendingGrace++
			continue
		}
		checkpoint, err := store.GetAppliedCheckpoint(ctx, item.CheckpointIdentity)
		if err != nil {
			return result, err
		}
		grace, err := store.GetGraceRecord(ctx, item.CheckpointIdentity)
		if err != nil || grace.GraceIdentity != item.GraceIdentity || grace.NotBefore.After(now) {
			return result, errors.Join(fmt.Errorf("%w: target grace changed during maintenance", ErrIntegrity), err)
		}
		report, reportErr := store.GetPublicationCandidateReport(ctx, item.CheckpointIdentity)
		if errors.Is(reportErr, state.ErrNotFound) {
			if err := verifyTargetMaintenanceInventory(ctx, store, backend, binding.TargetIdentity, nil, false); err != nil {
				return result, err
			}
			candidates, err := store.ExactPublicationCandidates(ctx, item.CheckpointIdentity, now)
			if err != nil {
				return result, err
			}
			mode := "conditional_delete"
			if backend.Provider() == "r2" {
				mode = "report_only"
			}
			report = state.PublicationCandidateReport{
				TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity,
				InventoryIdentity: checkpoint.InventoryIdentity, Mode: mode, Candidates: candidates, CreatedAt: now,
			}
			if err := store.PutPublicationCandidateReport(ctx, &report); err != nil {
				return result, err
			}
			result.Reports++
			if err := callFault(opts.Fault, "target_gc.report"); err != nil {
				return result, err
			}
		} else if reportErr != nil {
			return result, reportErr
		} else if report.TargetIdentity != binding.TargetIdentity || report.CheckpointIdentity != checkpoint.CheckpointIdentity || report.InventoryIdentity != checkpoint.InventoryIdentity || backend.Provider() == "r2" && report.Mode != "report_only" || backend.Provider() == "filesystem" && report.Mode != "conditional_delete" {
			return result, fmt.Errorf("%w: persisted target maintenance report differs from provider checkpoint", ErrIntegrity)
		}
		if err := verifyTargetMaintenanceInventory(ctx, store, backend, binding.TargetIdentity, report.Candidates, true); err != nil {
			return result, err
		}
		result.Candidates += len(report.Candidates)
		if backend.Provider() == "r2" {
			if err := store.MarkPublicationRetainedReported(ctx, item.AttemptIdentity, report.ReportIdentity, now); err != nil {
				return result, err
			}
			if err := callFault(opts.Fault, "target_gc.retained_reported"); err != nil {
				return result, err
			}
			if err := store.CompletePublicationAttempt(ctx, item.AttemptIdentity, report.ReportIdentity); err != nil {
				return result, err
			}
			result.RetainedObjects += len(report.Candidates)
			result.CompletedAttempts++
			continue
		}
		for _, candidate := range report.Candidates {
			if err := backend.DeleteConditional(ctx, candidate); err != nil {
				return result, err
			}
			if err := callFault(opts.Fault, "target_gc.deleted."+candidate.Path); err != nil {
				return result, err
			}
			if err := backend.VerifyPublicAbsent(ctx, candidate.Path); err != nil {
				return result, err
			}
			receipt := state.PublicationDeletionReceipt{
				ReportIdentity: report.ReportIdentity, Path: candidate.Path, Phase: candidate.Phase,
				Size: candidate.Size, SHA256: candidate.SHA256, RemoteIdentity: candidate.RemoteIdentity,
				StorageAbsent: true, PublicAbsent: true, ObservedAt: now,
			}
			if err := store.PutPublicationDeletionReceipt(ctx, &receipt); err != nil {
				return result, err
			}
			if err := callFault(opts.Fault, "target_gc.receipt."+candidate.Path); err != nil {
				return result, err
			}
			result.DeletedObjects++
			result.DeletedBytes += candidate.Size
		}
		if err := store.MarkPublicationDeletionVerified(ctx, item.AttemptIdentity, report.ReportIdentity, now); err != nil {
			return result, err
		}
		if err := callFault(opts.Fault, "target_gc.deletion_verified"); err != nil {
			return result, err
		}
		if err := store.CompletePublicationAttempt(ctx, item.AttemptIdentity, report.ReportIdentity); err != nil {
			return result, err
		}
		result.CompletedAttempts++
	}
	if result.PendingGrace != 0 {
		result.Phase = "pending_grace"
	} else {
		result.Phase = "done"
	}
	result.Noop = result.Reports == 0 && result.CompletedAttempts == 0 && result.DeletedObjects == 0 && result.RetainedObjects == 0
	return result, nil
}

func verifyTargetMaintenanceInventory(ctx context.Context, store *state.Store, backend publicationBackend, targetIdentity string, candidates []state.PublicationCandidate, allowCandidateAbsence bool) error {
	target, err := store.GetPublicationTarget(ctx, targetIdentity)
	if err != nil {
		return err
	}
	if target.Head.CheckpointIdentity == "" {
		return fmt.Errorf("%w: target maintenance has no applied checkpoint", ErrIntegrity)
	}
	if err := verifyPublishedGeneration(ctx, backend, store, target.Head.Generation, target.Head.ManifestSHA256); err != nil {
		return err
	}
	expected, err := store.PublicationLiveInventory(ctx, target.Head.CheckpointIdentity)
	if err != nil {
		return err
	}
	remote, err := backend.List(ctx, nil)
	if err != nil {
		return err
	}
	expectedByPath := make(map[string]state.PublicationInventoryObject, len(expected))
	for _, object := range expected {
		expectedByPath[object.Path] = object
	}
	missingAllowed := make(map[string]state.PublicationCandidate, len(candidates))
	for _, candidate := range candidates {
		missingAllowed[candidate.Path] = candidate
	}
	seen := make(map[string]struct{}, len(remote))
	for _, object := range remote {
		expect, ok := expectedByPath[object.Path]
		if !ok || expect.Size != object.Size || expect.SHA256 != object.SHA256 || expect.RemoteIdentity != object.RemoteIdentity {
			return fmt.Errorf("%w: target maintenance found unknown or changed object %q", ErrIntegrity, object.Path)
		}
		seen[object.Path] = struct{}{}
	}
	for _, expect := range expected {
		if _, ok := seen[expect.Path]; ok {
			continue
		}
		candidate, allowed := missingAllowed[expect.Path]
		if !allowCandidateAbsence || !allowed || candidate.Phase != expect.Phase || candidate.Size != expect.Size || candidate.SHA256 != expect.SHA256 || candidate.RemoteIdentity != expect.RemoteIdentity {
			return fmt.Errorf("%w: target maintenance is missing non-candidate object %q", ErrIntegrity, expect.Path)
		}
	}
	return nil
}
