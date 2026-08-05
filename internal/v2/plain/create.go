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
	markerPath := filepath.Join(root, "repo_complete")

	if journal, err := loadJournal(root); err != nil {
		return Result{}, err
	} else if journal != nil {
		if !journal.Pigsty {
			if _, err := os.Lstat(markerPath); err == nil {
				return Result{}, &Error{Kind: KindRejected, Op: "recover marker gate", Path: markerPath, Err: errors.New("repo_complete appeared while a default create journal is pending; refusing replay")}
			} else if !errors.Is(err, os.ErrNotExist) {
				return Result{}, &Error{Kind: KindRuntime, Op: "recover marker gate", Path: markerPath, Err: err}
			}
		}
		if journal.Pigsty && !opts.Pigsty {
			return Result{}, &Error{Kind: KindRejected, Op: "recover", Path: root, Err: errors.New("an interrupted --pigsty operation exists; rerun create with --pigsty to authorize recovery")}
		}
		if !journal.Pigsty && opts.Pigsty {
			return Result{}, &Error{Kind: KindRejected, Op: "recover", Path: root, Err: errors.New("an interrupted default create operation exists; rerun create without --pigsty before starting compatibility cleanup")}
		}
		if journal.SignWith != opts.SignWith || journal.Overwrite != opts.Overwrite {
			return Result{}, &Error{Kind: KindRejected, Op: "recover", Path: root, Err: errors.New("an interrupted create operation has different --sign-with/--overwrite authorization; rerun with the original signing options")}
		}
		changed, err := executeJournal(ctx, root, journal, nil)
		if err != nil {
			return Result{}, err
		}
		return resultFromJournal(root, *journal, changed), nil
	}

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
	staged, scan, err := renderStage(ctx, root, scan, opts)
	if err != nil {
		return Result{}, err
	}
	if err := verifyStableInputs(ctx, scan); err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	if err := lock.Validate(); err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	journal, err := buildJournal(ctx, root, staged, scan, opts)
	if err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	changesPublicState, err := journalChangesPublicState(ctx, root, journal)
	if err != nil {
		_ = os.RemoveAll(staged.dir)
		_ = os.RemoveAll(filepath.Join(root, journal.Trash))
		return Result{}, err
	}
	if !changesPublicState {
		if err := discardUnpublishedJournal(root, journal); err != nil {
			return Result{}, err
		}
		populateResult(&result, scan, staged, opts, false)
		return result, nil
	}
	if err := persistJournal(root, journal); err != nil {
		// Once the journal rename succeeds it may be the only durable recovery
		// evidence, even when the following parent-directory fsync reports an
		// error. Keep both dependencies in that state so the next create can
		// replay or roll back the visible journal safely.
		if !journalWasInstalled(err) {
			_ = os.RemoveAll(staged.dir)
			_ = os.RemoveAll(filepath.Join(root, journal.Trash))
		}
		return Result{}, err
	}
	if err := lock.Validate(); err != nil {
		return Result{}, err
	}
	if err := inject(opts.Fault, FaultAfterJournal, "", -1); err != nil {
		return Result{}, err
	}
	changed, err := executeJournal(ctx, root, &journal, opts.Fault)
	if err != nil {
		return Result{}, err
	}

	populateResult(&result, scan, staged, opts, changed)
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
	result.Noop = !changed && len(scan.removed) == 0 && !result.Recovered
}

func verifyStableInputs(ctx context.Context, scan scanResult) error {
	for _, fact := range scan.all {
		digest, err := hashFile(ctx, fact.originalPath)
		if err != nil {
			return err
		}
		if digest != fact.originalSHA256 {
			return &Error{Kind: KindIntegrity, Op: "verify input", Path: fact.originalPath, Err: fmt.Errorf("package changed after inspection: got %s, want %s", digest, fact.originalSHA256)}
		}
	}
	return nil
}
