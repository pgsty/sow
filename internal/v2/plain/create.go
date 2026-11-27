package plain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pgsty/sow/internal/v2/signing"
)

// Create builds flat RPM and/or DEB metadata for one directory. It does not
// discover a workspace, read sow.yml, or create SQLite state.
func Create(ctx context.Context, opts Options) (result Result, resultErr error) {
	opts, err := normalizeOptions(ctx, opts)
	if err != nil {
		return Result{}, err
	}
	ctx = signing.WithPassFile(ctx, opts.PassFile)
	root, err := filepath.Abs(opts.Dir)
	if err != nil {
		return Result{}, &Error{Kind: KindRuntime, Op: "resolve directory", Path: opts.Dir, Err: err}
	}
	info, err := os.Stat(root)
	if err != nil {
		return Result{}, &Error{Kind: KindRuntime, Op: "inspect directory", Path: root, Err: err}
	}
	if !info.IsDir() {
		return Result{}, &Error{Kind: KindRejected, Op: "inspect directory", Path: root, Err: errors.New("target is not a directory")}
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return Result{}, &Error{Kind: KindRuntime, Op: "resolve directory", Path: root, Err: err}
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
	if err := rejectManagedWorkspaceAncestors(root, "create", "managed workspaces cannot be rebuilt as flat repositories"); err != nil {
		return Result{}, err
	}
	result.Dir = root
	result.Kept = []string{}
	result.Removed = []string{}
	if err := cleanupStalePlainState(root); err != nil {
		return Result{}, err
	}

	if !opts.Pigsty {
		for _, markerName := range []string{"repo_complete", pruneMarkerName} {
			markerPath := filepath.Join(root, markerName)
			if _, err := os.Lstat(markerPath); err == nil {
				return Result{}, &Error{Kind: KindRejected, Op: "marker gate", Path: markerPath, Err: errors.New("repo_complete exists; use --pigsty or remove it explicitly before rebuilding")}
			} else if !errors.Is(err, os.ErrNotExist) {
				return Result{}, &Error{Kind: KindRuntime, Op: "marker gate", Path: markerPath, Err: err}
			}
		}
	}

	scan, err := scanPackages(ctx, root, opts.Jobs, opts.Pigsty, opts.Strict, false)
	if err != nil {
		return Result{}, err
	}
	preserveRPM, preserveDEB := scan.preserveFormat(formatRPM), scan.preserveFormat(formatDEB)
	if preserveRPM || preserveDEB {
		// A failed format keeps its old index, including any would-be exclusions.
		removed := scan.removed[:0]
		for _, f := range scan.removed {
			if !(preserveRPM && f.format == formatRPM || preserveDEB && f.format == formatDEB) {
				removed = append(removed, f)
			}
		}
		scan.removed = removed
		priorRPMIndex, hasPriorRPMIndex, err := priorFormatIndexPath(root, formatRPM)
		if err != nil {
			return Result{}, &Error{Kind: KindRuntime, Op: "inspect prior rpm index", Path: root, Err: err}
		}
		priorDEBIndex, hasPriorDEBIndex, err := priorFormatIndexPath(root, formatDEB)
		if err != nil {
			return Result{}, &Error{Kind: KindRuntime, Op: "inspect prior deb index", Path: root, Err: err}
		}
		if preserveRPM {
			if hasPriorRPMIndex {
				scan.warnings = append(scan.warnings, "all RPM candidates were skipped; existing RPM metadata preserved")
			} else {
				scan.warnings = append(scan.warnings, "all RPM candidates were skipped")
			}
		}
		if preserveDEB {
			if hasPriorDEBIndex {
				scan.warnings = append(scan.warnings, "all DEB candidates were skipped; existing DEB metadata preserved")
			} else {
				scan.warnings = append(scan.warnings, "all DEB candidates were skipped")
			}
		}
		removeOtherIndex := (!preserveRPM && !scan.hasRPM && hasPriorRPMIndex) || (!preserveDEB && !scan.hasDEB && hasPriorDEBIndex)
		skip := len(scan.kept) == 0 && len(scan.removed) == 0 && !removeOtherIndex
		if opts.Pigsty && !skip {
			preservedFormat := formatDEB
			index, priorIndexExists := priorDEBIndex, hasPriorDEBIndex
			if preserveRPM {
				preservedFormat = formatRPM
				index, priorIndexExists = priorRPMIndex, hasPriorRPMIndex
			}
			var lines []markerLine
			var markerErr error
			if priorIndexExists {
				lines, markerErr = readPriorMarker(root, func(name string) bool {
					return filepath.Ext(name) == "."+string(preservedFormat)
				})
				if errors.Is(markerErr, os.ErrNotExist) {
					markerErr = fmt.Errorf("existing %s cannot be carried forward without repo_complete", index)
				} else if markerErr == nil && len(lines) == 0 {
					markerErr = fmt.Errorf("existing %s has no entries in repo_complete", index)
				}
			}
			if markerErr != nil {
				scan.warnings = append(scan.warnings, "cannot carry forward repo_complete; skipped publication: "+markerErr.Error())
				skip = true
			}
			scan.markerLines = lines
		}
		if skip {
			scan.removed = nil
			populateResult(&result, scan, stagedBuild{}, opts, false)
			result.Marker, err = pruneMarkerExists(filepath.Join(root, "repo_complete"))
			if err == nil && result.Marker {
				result.MarkerSHA256, err = hashFile(ctx, filepath.Join(root, "repo_complete"))
			}
			return result, err
		}
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
	if err := lock.Validate(); err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	plan, err := preparePublication(ctx, root, staged, scan, opts, false)
	if err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	if err := lock.Validate(); err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	// Create replaces a foreign repomd.xml, as createrepo_c does; for example,
	// Pigsty relies on this to retire legacy synthetic module metadata. Report
	// the data types that the rebuilt index no longer carries.
	var prior priorRPMMetadata
	if !preserveRPM && plan.changed {
		prior, err = inspectPriorRPMMetadata(root)
	}
	if err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	if err := validatePackageStats(root, scan, false); err != nil {
		_ = os.RemoveAll(staged.dir)
		return Result{}, err
	}
	if err := publishStage(ctx, root, staged, scan, opts, &plan); err != nil {
		return Result{}, err
	}
	populateResult(&result, scan, staged, opts, plan.changed)
	if plan.rpmPublished {
		result.DroppedMetadata = prior.unsupported
	}
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
	result.Skipped = scan.skipped
	result.Warnings = scan.warnings
	result.Marker = opts.Pigsty
	result.Signer = opts.SignWith
	result.MarkerSHA256 = staged.markerSHA
	result.Noop = !changed && len(scan.removed) == 0
}

func priorFormatIndexPath(root string, format packageFormat) (string, bool, error) {
	candidates := []string{"Packages", "Packages.gz"}
	if format == formatRPM {
		candidates = []string{filepath.Join("repodata", "repomd.xml")}
	}
	for _, rel := range candidates {
		if _, err := os.Lstat(filepath.Join(root, rel)); err == nil {
			return rel, true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", false, err
		}
	}
	return candidates[0], false, nil
}
