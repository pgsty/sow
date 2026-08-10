package plain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const legacyPlainJournal = ".sow-plain-operation.json"

// publicationPlan contains only cheap, preflighted filesystem work. Package
// identity is already captured by the one content pass; publication never
// reopens a retained package merely to prove a durable transaction journal.
type publicationPlan struct {
	changed   bool
	staleRPM  []string
	removeRPM []string
	removeDEB []string
}

func preparePublication(ctx context.Context, root string, staged stagedBuild, scan scanResult, opts Options) (publicationPlan, error) {
	plan := publicationPlan{}
	if err := prepareRPMPublication(ctx, root, staged, &plan); err != nil {
		return publicationPlan{}, err
	}
	if err := prepareDEBPublication(ctx, root, staged, &plan); err != nil {
		return publicationPlan{}, err
	}
	for _, fact := range scan.kept {
		if fact.format == formatRPM && fact.signed && fact.originalSHA256 != fact.sha256 {
			plan.changed = true
		}
	}
	if len(scan.removed) != 0 {
		plan.changed = true
	}
	if opts.Pigsty {
		equal, err := regularFilesEqual(ctx, filepath.Join(staged.dir, "repo_complete"), filepath.Join(root, "repo_complete"))
		if err != nil {
			return publicationPlan{}, err
		}
		plan.changed = plan.changed || !equal
	}
	return plan, nil
}

func prepareRPMPublication(ctx context.Context, root string, staged stagedBuild, plan *publicationPlan) error {
	liveDir := filepath.Join(root, "repodata")
	info, err := os.Lstat(liveDir)
	if errors.Is(err, os.ErrNotExist) {
		if staged.rpmPresent {
			plan.changed = true
		}
		return nil
	}
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "inspect prior rpm index", Path: liveDir, Err: err}
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		if staged.rpmPresent {
			return &Error{Kind: KindIntegrity, Op: "inspect prior rpm index", Path: liveDir, Err: errors.New("repodata is not a real directory")}
		}
		return nil
	}
	liveEntries, err := os.ReadDir(liveDir)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "list prior rpm index", Path: liveDir, Err: err}
	}
	if !staged.rpmPresent {
		for _, entry := range liveEntries {
			if entry.Name() == "repomd.xml" {
				if err := validateGeneratedMetadataFile(filepath.Join(liveDir, entry.Name())); err != nil {
					return err
				}
				plan.removeRPM = append(plan.removeRPM, entry.Name())
			}
		}
		for _, entry := range liveEntries {
			if entry.Name() != "repomd.xml" && isSOWRPMMetadataName(entry.Name()) {
				if err := validateGeneratedMetadataFile(filepath.Join(liveDir, entry.Name())); err != nil {
					return err
				}
				plan.removeRPM = append(plan.removeRPM, entry.Name())
			}
		}
		plan.changed = plan.changed || len(plan.removeRPM) != 0
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(staged.dir, "repodata"))
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "list staged rpm index", Path: staged.dir, Err: err}
	}
	stagedNames := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		stagedNames[entry.Name()] = struct{}{}
		equal, err := regularFilesEqual(ctx, filepath.Join(staged.dir, "repodata", entry.Name()), filepath.Join(liveDir, entry.Name()))
		if err != nil {
			return err
		}
		plan.changed = plan.changed || !equal
	}
	for _, entry := range liveEntries {
		name := entry.Name()
		if name == "repomd.xml" || !isSOWRPMMetadataName(name) {
			continue
		}
		if err := validateGeneratedMetadataFile(filepath.Join(liveDir, name)); err != nil {
			return err
		}
		if _, keep := stagedNames[name]; !keep {
			plan.staleRPM = append(plan.staleRPM, name)
			plan.changed = true
		}
	}
	return nil
}

func validateGeneratedMetadataFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return &Error{Kind: KindIntegrity, Op: "inspect prior generated metadata", Path: path, Err: errors.Join(err, errors.New("path is not a regular file"))}
	}
	return nil
}

func isSOWRPMMetadataName(name string) bool {
	if name == "repomd.xml" {
		return true
	}
	for _, kind := range []string{"primary", "filelists", "other"} {
		suffix := "-" + kind + ".xml.gz"
		if strings.HasSuffix(name, suffix) && validSHA256(strings.TrimSuffix(name, suffix)) {
			return true
		}
	}
	return false
}

func prepareDEBPublication(ctx context.Context, root string, staged stagedBuild, plan *publicationPlan) error {
	packagesPath := filepath.Join(root, "Packages")
	gzipPath := filepath.Join(root, "Packages.gz")
	if staged.debPresent {
		for _, name := range []string{"Packages", "Packages.gz"} {
			equal, err := regularFilesEqual(ctx, filepath.Join(staged.dir, name), filepath.Join(root, name))
			if err != nil {
				return err
			}
			plan.changed = plan.changed || !equal
		}
		return nil
	}
	for _, path := range []string{gzipPath, packagesPath} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "inspect prior deb index", Path: path, Err: errors.Join(err, errors.New("path is not a regular file"))}
		}
		plan.removeDEB = append(plan.removeDEB, filepath.Base(path))
	}
	plan.changed = plan.changed || len(plan.removeDEB) != 0
	return nil
}

func regularFilesEqual(ctx context.Context, source, target string) (bool, error) {
	sourceInfo, err := os.Lstat(source)
	if err != nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Mode()&os.ModeSymlink != 0 {
		return false, &Error{Kind: KindIntegrity, Op: "inspect staged output", Path: source, Err: errors.Join(err, errors.New("source is not a regular file"))}
	}
	targetInfo, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !targetInfo.Mode().IsRegular() || targetInfo.Mode()&os.ModeSymlink != 0 {
		return false, &Error{Kind: KindIntegrity, Op: "inspect live output", Path: target, Err: errors.Join(err, errors.New("target is not a regular file"))}
	}
	if sourceInfo.Size() != targetInfo.Size() {
		return false, nil
	}
	sourceDigest, err := hashFile(ctx, source)
	if err != nil {
		return false, err
	}
	targetDigest, err := hashFile(ctx, target)
	if err != nil {
		return false, err
	}
	return sourceDigest == targetDigest, nil
}

func publishStage(ctx context.Context, root string, staged stagedBuild, scan scanResult, opts Options, plan publicationPlan) (resultErr error) {
	defer func() {
		resultErr = errors.Join(resultErr, os.RemoveAll(staged.dir))
	}()
	if !plan.changed {
		return nil
	}
	if opts.Pigsty {
		marker := filepath.Join(root, "repo_complete")
		if err := removeRegularFile(marker, true); err != nil {
			return err
		}
		if err := syncDir(root); err != nil {
			return &Error{Kind: KindRuntime, Op: "sync marker withdrawal", Path: root, Err: err}
		}
		if err := inject(opts.Fault, FaultAfterMarkerWithdrawn, "", -1); err != nil {
			return err
		}
	}

	sequence := 0
	for _, fact := range scan.kept {
		if fact.format != formatRPM || !fact.signed || fact.originalSHA256 == fact.sha256 {
			continue
		}
		if err := inject(opts.Fault, FaultBeforeRPMPackage, fact.base, sequence); err != nil {
			return err
		}
		if err := installStagedFile(filepath.Join(staged.dir, "packages", fact.base), filepath.Join(root, fact.base)); err != nil {
			return err
		}
		if err := inject(opts.Fault, FaultAfterRPMPackage, fact.base, sequence); err != nil {
			return err
		}
		sequence++
	}

	if staged.rpmPresent {
		liveDir := filepath.Join(root, "repodata")
		if err := ensureRealDirectory(liveDir, 0o755); err != nil {
			return err
		}
		entries, err := os.ReadDir(filepath.Join(staged.dir, "repodata"))
		if err != nil {
			return &Error{Kind: KindRuntime, Op: "list staged rpm index", Path: staged.dir, Err: err}
		}
		var names []string
		for _, entry := range entries {
			if entry.Name() != "repomd.xml" {
				names = append(names, entry.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			if err := installStagedFile(filepath.Join(staged.dir, "repodata", name), filepath.Join(liveDir, name)); err != nil {
				return err
			}
		}
		if err := inject(opts.Fault, FaultBeforeRPMPointer, "", -1); err != nil {
			return err
		}
		if err := installStagedFile(filepath.Join(staged.dir, "repodata", "repomd.xml"), filepath.Join(liveDir, "repomd.xml")); err != nil {
			return err
		}
		if err := inject(opts.Fault, FaultAfterRPMPointer, "", -1); err != nil {
			return err
		}
		for _, name := range plan.staleRPM {
			if err := removeRegularFile(filepath.Join(liveDir, name), false); err != nil {
				return err
			}
		}
		if err := syncDir(liveDir); err != nil {
			return &Error{Kind: KindRuntime, Op: "sync rpm index", Path: liveDir, Err: err}
		}
	} else if len(plan.removeRPM) != 0 {
		for sequence, name := range plan.removeRPM {
			if err := inject(opts.Fault, FaultBeforeRPMRemoval, "", sequence); err != nil {
				return err
			}
			if err := removeRegularFile(filepath.Join(root, "repodata", name), false); err != nil {
				return err
			}
			if err := inject(opts.Fault, FaultAfterRPMRemoval, "", sequence); err != nil {
				return err
			}
		}
		if err := syncDir(filepath.Join(root, "repodata")); err != nil {
			return &Error{Kind: KindRuntime, Op: "sync rpm index removal", Path: filepath.Join(root, "repodata"), Err: err}
		}
		if entries, err := os.ReadDir(filepath.Join(root, "repodata")); err == nil && len(entries) == 0 {
			if err := os.Remove(filepath.Join(root, "repodata")); err != nil {
				return &Error{Kind: KindRuntime, Op: "remove empty rpm index", Path: filepath.Join(root, "repodata"), Err: err}
			}
			if err := syncDir(root); err != nil {
				return &Error{Kind: KindRuntime, Op: "sync rpm index removal", Path: root, Err: err}
			}
		}
	}

	if staged.debPresent {
		for sequence, item := range []struct {
			name          string
			before, after FaultPoint
		}{{"Packages", FaultBeforeDEBPackages, FaultAfterDEBPackages}, {"Packages.gz", FaultBeforeDEBGzip, FaultAfterDEBGzip}} {
			if err := inject(opts.Fault, item.before, "", sequence); err != nil {
				return err
			}
			if err := installStagedFile(filepath.Join(staged.dir, item.name), filepath.Join(root, item.name)); err != nil {
				return err
			}
			if err := inject(opts.Fault, item.after, "", sequence); err != nil {
				return err
			}
		}
	} else if len(plan.removeDEB) != 0 {
		for sequence, name := range plan.removeDEB {
			if err := inject(opts.Fault, FaultBeforeDEBRemoval, "", sequence); err != nil {
				return err
			}
			if err := removeRegularFile(filepath.Join(root, name), false); err != nil {
				return err
			}
			if err := inject(opts.Fault, FaultAfterDEBRemoval, "", sequence); err != nil {
				return err
			}
		}
		if err := syncDir(root); err != nil {
			return &Error{Kind: KindRuntime, Op: "sync deb index removal", Path: root, Err: err}
		}
	}

	if opts.Pigsty {
		for sequence, fact := range scan.removed {
			if err := removeRegularFile(filepath.Join(root, fact.base), false); err != nil {
				return err
			}
			if err := inject(opts.Fault, FaultAfterPackageRename, fact.base, sequence); err != nil {
				return err
			}
		}
		if err := inject(opts.Fault, FaultBeforeMarker, "", -1); err != nil {
			return err
		}
		if err := installStagedFile(filepath.Join(staged.dir, "repo_complete"), filepath.Join(root, "repo_complete")); err != nil {
			return err
		}
		if err := inject(opts.Fault, FaultAfterMarker, "", -1); err != nil {
			return err
		}
	}
	return nil
}

func ensureRealDirectory(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, mode); err != nil {
			return &Error{Kind: KindRuntime, Op: "create output directory", Path: path, Err: err}
		}
		created = true
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return &Error{Kind: KindIntegrity, Op: "inspect output directory", Path: path, Err: errors.Join(err, errors.New("path is not a real directory"))}
	}
	if created {
		if err := syncDir(filepath.Dir(path)); err != nil {
			return &Error{Kind: KindRuntime, Op: "sync output directory creation", Path: filepath.Dir(path), Err: err}
		}
	}
	return nil
}

func installStagedFile(source, target string) error {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return &Error{Kind: KindIntegrity, Op: "install staged output", Path: source, Err: errors.Join(err, errors.New("source is not a regular file"))}
	}
	parent := filepath.Dir(target)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return &Error{Kind: KindIntegrity, Op: "install staged output", Path: parent, Err: errors.Join(err, errors.New("target parent is not a real directory"))}
	}
	if targetInfo, err := os.Lstat(target); err == nil {
		if !targetInfo.Mode().IsRegular() || targetInfo.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "install staged output", Path: target, Err: errors.New("target is not a regular file")}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return &Error{Kind: KindRuntime, Op: "inspect output target", Path: target, Err: err}
	}
	if err := os.Rename(source, target); err != nil {
		return &Error{Kind: KindRuntime, Op: "install staged output", Path: target, Err: err}
	}
	if err := syncDir(parent); err != nil {
		return &Error{Kind: KindRuntime, Op: "sync output directory", Path: parent, Err: err}
	}
	return nil
}

func removeRegularFile(path string, allowAbsent bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && allowAbsent {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return &Error{Kind: KindIntegrity, Op: "remove prior output", Path: path, Err: errors.Join(err, errors.New("path is not a regular file"))}
	}
	if err := os.Remove(path); err != nil {
		return &Error{Kind: KindRuntime, Op: "remove prior output", Path: path, Err: err}
	}
	return nil
}

func cleanupStalePlainState(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "list stale plain state", Path: root, Err: err}
	}
	changed := false
	for _, entry := range entries {
		name := entry.Name()
		owned := name == legacyPlainJournal || strings.HasPrefix(name, ".sow-plain-stage-") || strings.HasPrefix(name, ".sow-plain-recovery-") ||
			strings.HasPrefix(name, ".sow-plain-rpm-proof-") || strings.HasPrefix(name, ".sow-plain-journal-write-")
		if !owned {
			continue
		}
		path := filepath.Join(root, name)
		if err := os.RemoveAll(path); err != nil {
			return &Error{Kind: KindRuntime, Op: "discard stale plain state", Path: path, Err: err}
		}
		changed = true
	}
	if changed {
		if err := syncDir(root); err != nil {
			return &Error{Kind: KindRuntime, Op: "sync stale plain cleanup", Path: root, Err: err}
		}
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func inject(fault func(Fault) error, point FaultPoint, packageName string, sequence int) error {
	if fault == nil || point == "" {
		return nil
	}
	if err := fault(Fault{Point: point, Package: packageName, Sequence: sequence}); err != nil {
		return &Error{Kind: KindRuntime, Op: "fault injection", Err: err}
	}
	return nil
}
