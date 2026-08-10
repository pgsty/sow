package plain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Create builds flat RPM and/or DEB metadata for one directory. It does not
// discover a workspace, read sow.yml, or create SQLite state.
func Create(ctx context.Context, opts Options) (result Result, resultErr error) {
	opts, err := normalizeOptions(ctx, opts)
	if err != nil {
		return Result{}, err
	}
	root, err := filepath.Abs(opts.Dir)
	if err != nil {
		return Result{}, &Error{Kind: KindRuntime, Op: "resolve directory", Path: opts.Dir, Err: err}
	}
	info, err := os.Lstat(root)
	if err != nil {
		return Result{}, &Error{Kind: KindRuntime, Op: "inspect directory", Path: root, Err: err}
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Result{}, &Error{Kind: KindRejected, Op: "inspect directory", Path: root, Err: errors.New("target is not a real directory")}
	}
	lock, err := acquireDirectoryLock(ctx, root, opts.Timeout, opts.NoWait)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		if err := lock.Close(); err != nil {
			resultErr = errors.Join(resultErr, &Error{Kind: KindRuntime, Op: "unlock", Path: root, Err: err})
		}
	}()
	if err := lock.Validate(); err != nil {
		return Result{}, err
	}
	result.Dir = root
	result.Kept = []string{}
	result.Removed = []string{}
	if err := cleanupStalePlainState(root); err != nil {
		return Result{}, err
	}
	markerPath := filepath.Join(root, "repo_complete")

	if !opts.Pigsty {
		if _, err := os.Lstat(markerPath); err == nil {
			return Result{}, &Error{Kind: KindRejected, Op: "marker gate", Path: markerPath, Err: errors.New("repo_complete exists; use --pigsty or remove it explicitly before rebuilding")}
		} else if !errors.Is(err, os.ErrNotExist) {
			return Result{}, &Error{Kind: KindRuntime, Op: "marker gate", Path: markerPath, Err: err}
		}
	}

	scan, err := scanPackages(ctx, root, opts.Jobs, opts.Pigsty)
	if err != nil {
		return Result{}, err
	}
	if err := lock.Validate(); err != nil {
		return Result{}, err
	}
	if err := inject(opts.Fault, FaultAfterContentScan, "", -1); err != nil {
		return Result{}, err
	}
	staged, scan, err := renderStage(ctx, root, scan, opts)
	if err != nil {
		return Result{}, err
	}
	if err := inject(opts.Fault, FaultBeforeStatValidation, "", -1); err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	if err := verifyStableInputs(ctx, root, scan); err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	if err := lock.Validate(); err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	plan, err := preparePublication(ctx, root, staged, scan, opts)
	if err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	if err := lock.Validate(); err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	if err := publishStage(ctx, root, staged, scan, opts, plan); err != nil {
		return Result{}, err
	}
	populateResult(&result, scan, staged, opts, plan.changed)
	return result, nil
}

func populateResult(result *Result, scan scanResult, staged stagedBuild, opts Options, changed bool) {
	for _, fact := range scan.kept {
		result.Kept = append(result.Kept, fact.base)
		if fact.signed {
			result.Signed = append(result.Signed, fact.base)
		}
		if fact.format == formatRPM {
			result.RPM++
		} else {
			result.DEB++
		}
	}
	for _, fact := range scan.removed {
		result.Removed = append(result.Removed, fact.base)
	}
	result.Marker = opts.Pigsty
	result.Signer = opts.SignWith
	result.MarkerSHA256 = staged.markerSHA
	result.Noop = !changed && len(scan.removed) == 0
}

func verifyStableInputs(ctx context.Context, root string, scan scanResult) error {
	candidates, err := listPackageCandidates(root)
	if err != nil {
		return err
	}
	if len(candidates) != len(scan.all) {
		return &Error{Kind: KindIntegrity, Op: "verify input stats", Path: root, Err: fmt.Errorf("package set changed after inspection: got %d files, want %d", len(candidates), len(scan.all))}
	}
	for index, fact := range scan.all {
		if err := ctx.Err(); err != nil {
			return &Error{Kind: KindRuntime, Op: "verify input stats", Path: root, Err: err}
		}
		candidate := candidates[index]
		if candidate.base != fact.base || candidate.format != fact.format {
			return &Error{Kind: KindIntegrity, Op: "verify input stats", Path: root, Err: errors.New("package set changed after inspection")}
		}
		before, after := fact.sourceInfo, candidate.info
		if before == nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() {
			return &Error{Kind: KindIntegrity, Op: "verify input stats", Path: fact.originalPath, Err: errors.New("package stat changed after inspection")}
		}
	}
	return nil
}
