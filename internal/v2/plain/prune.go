package plain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/yumrepo"
)

// An interrupted prune keeps the old completion marker here until its rerun
// finishes. No package backup or operation journal is needed.
const pruneMarkerName = ".sow-prune-repo-complete"

type PruneOptions struct {
	Dir     string
	DryRun  bool
	Protect []string
	Jobs    int
	Timeout time.Duration
	NoWait  bool
	Fault   func(Fault) error
}

type PruneCandidate struct {
	Path   string `json:"path"`
	Latest string `json:"latest"`
}

type PruneResult struct {
	Dir          string           `json:"dir"`
	DryRun       bool             `json:"dry_run"`
	Kept         []string         `json:"kept"`
	Candidates   []PruneCandidate `json:"candidates"`
	Removed      []string         `json:"removed"`
	IndexUpdated bool             `json:"index_updated"`
	Marker       bool             `json:"marker"`
	Noop         bool             `json:"noop"`
}

// Prune keeps the highest EVR for each RPM name/architecture, publishes the
// filtered flat index, then removes superseded files. DryRun performs no writes.
func Prune(ctx context.Context, opts PruneOptions) (result PruneResult, resultErr error) {
	if strings.TrimSpace(opts.Dir) == "" {
		return result, &Error{Kind: KindUsage, Op: "prune", Err: errors.New("directory is required")}
	}
	base, err := normalizeOptions(ctx, Options{Dir: opts.Dir, Jobs: opts.Jobs, Timeout: opts.Timeout, NoWait: opts.NoWait, Fault: opts.Fault})
	if err != nil {
		return result, err
	}
	for _, name := range opts.Protect {
		if name == "" || strings.ContainsAny(name, "/*?[]\\\x00\r\n\t ") {
			return result, &Error{Kind: KindUsage, Op: "protect", Path: name, Err: errors.New("expected an exact RPM package name")}
		}
	}
	root, err := filepath.Abs(opts.Dir)
	if err != nil {
		return result, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return result, &Error{Kind: KindRejected, Op: "prune directory", Path: root, Err: errors.Join(err, errors.New("target is not a real directory"))}
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return result, err
	}
	lock, err := acquireDirectoryLock(ctx, root, base.Timeout, base.NoWait)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	if err := lock.Validate(); err != nil {
		return result, err
	}
	if err := validatePruneDirectory(root); err != nil {
		return result, err
	}
	marker, err := pruneMarkerExists(filepath.Join(root, "repo_complete"))
	if err != nil {
		return result, err
	}
	pendingMarker, err := pruneMarkerExists(filepath.Join(root, pruneMarkerName))
	if err != nil {
		return result, err
	}
	// Pigsty only controls marker rendering/publication here. Prune never
	// applies create --pigsty's Patroni or architecture exclusion rules.
	base.Pigsty = marker || pendingMarker
	scan, err := scanPackages(ctx, root, base.Jobs, false)
	if err != nil {
		return result, err
	}
	scan, candidates, err := selectPrunePackages(scan, opts.Protect)
	if err != nil {
		return result, err
	}
	result = PruneResult{Dir: root, DryRun: opts.DryRun, Kept: []string{}, Candidates: candidates, Removed: []string{}, Marker: base.Pigsty}
	for _, fact := range scan.kept {
		result.Kept = append(result.Kept, fact.base)
	}
	if err := inject(base.Fault, FaultAfterContentScan, "", -1); err != nil {
		return result, err
	}
	if err := verifyPruneReplacements(ctx, scan, candidates); err != nil {
		return result, err
	}
	if err := verifyStableInputs(ctx, root, scan); err != nil {
		return result, err
	}
	if err := validatePruneDirectory(root); err != nil {
		return result, err
	}
	if opts.DryRun {
		return result, lock.Validate()
	}
	if err := cleanupStalePlainState(root); err != nil {
		return result, err
	}
	staged, scan, err := renderStage(ctx, root, scan, base)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(staged.dir)) }()
	if err := inject(base.Fault, FaultBeforeStatValidation, "", -1); err != nil {
		return result, err
	}
	if err := verifyStableInputs(ctx, root, scan); err != nil {
		return result, err
	}
	if err := validatePruneDirectory(root); err != nil {
		return result, err
	}
	plan, err := preparePublication(ctx, root, staged, scan, base)
	if err != nil {
		return result, err
	}
	if err := lock.Validate(); err != nil {
		return result, err
	}
	plan.prune = true
	plan.changed = plan.changed || pendingMarker
	if plan.changed && marker && !pendingMarker {
		if err := os.Rename(filepath.Join(root, "repo_complete"), filepath.Join(root, pruneMarkerName)); err != nil {
			return result, err
		}
		if err := syncDir(root); err != nil {
			return result, err
		}
	}
	err = publishStage(ctx, root, staged, scan, base, &plan)
	result.Removed = append(result.Removed, plan.removed...)
	result.IndexUpdated = plan.rpmPublished
	if err != nil {
		return result, err
	}
	if base.Pigsty {
		if err := removeRegularFile(filepath.Join(root, pruneMarkerName), true); err != nil {
			return result, err
		}
		if err := syncDir(root); err != nil {
			return result, err
		}
	}
	result.Noop = !plan.changed
	return result, nil
}

func validatePruneDirectory(root string) error {
	for dir := root; ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(filepath.Join(dir, ".sow")); err == nil {
			return &Error{Kind: KindRejected, Op: "prune", Path: root, Err: errors.New("managed workspaces cannot be pruned as flat repositories")}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	for _, name := range []string{"repodata/repomd.xml.asc", "Packages", "Packages.gz"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err == nil {
			return &Error{Kind: KindRejected, Op: "prune", Path: filepath.Join(root, name), Err: errors.New("prune supports RPM-only flat repositories without signed repository metadata")}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		if strings.HasSuffix(entry.Name(), ".deb") {
			return &Error{Kind: KindRejected, Op: "prune", Path: path, Err: errors.New("prune supports RPM packages only")}
		}
		if strings.HasSuffix(entry.Name(), ".rpm") {
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() {
				return &Error{Kind: KindRejected, Op: "prune", Path: path, Err: errors.Join(err, errors.New("RPM must be a regular file, not a symlink"))}
			}
		}
	}
	return nil
}

func pruneMarkerExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return false, &Error{Kind: KindRejected, Op: "prune marker", Path: path, Err: errors.Join(err, errors.New("completion marker must be a regular file"))}
	}
	return true, nil
}

func selectPrunePackages(scan scanResult, protect []string) (scanResult, []PruneCandidate, error) {
	protected := make(map[string]bool, len(protect))
	for _, name := range protect {
		protected[name] = true
	}
	groups := make(map[string][]packageFact)
	for _, fact := range scan.all {
		if fact.format != formatRPM {
			return scanResult{}, nil, &Error{Kind: KindRejected, Op: "prune", Path: fact.path, Err: errors.New("prune supports RPM packages only")}
		}
		key := fact.name + "\x00" + fact.arch
		groups[key] = append(groups[key], fact)
	}
	compare := func(a, b packageFact) int {
		return yumrepo.CompareEVR(a.rpm.Epoch, a.rpm.Version, a.rpm.Release, b.rpm.Epoch, b.rpm.Version, b.rpm.Release)
	}
	latest := make(map[string]packageFact, len(groups))
	var keys []string
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := groups[key]
		sort.SliceStable(group, func(i, j int) bool { return compare(group[i], group[j]) > 0 })
		for i := 1; i < len(group); i++ {
			if compare(group[i-1], group[i]) == 0 {
				return scanResult{}, nil, &Error{Kind: KindRejected, Op: "prune version conflict", Path: group[i].base, Err: fmt.Errorf("%s and %s have equal RPM versions", group[i-1].base, group[i].base)}
			}
		}
		latest[key] = group[0]
	}
	result := scanResult{all: scan.all, hasRPM: true}
	candidates := []PruneCandidate{}
	for _, fact := range scan.all {
		newest := latest[fact.name+"\x00"+fact.arch]
		if protected[fact.name] || fact.base == newest.base {
			result.kept = append(result.kept, fact)
			result.index = append(result.index, fact)
		} else {
			result.removed = append(result.removed, fact)
			candidates = append(candidates, PruneCandidate{Path: fact.base, Latest: newest.base})
		}
	}
	return result, candidates, nil
}

func verifyPruneReplacements(ctx context.Context, scan scanResult, candidates []PruneCandidate) error {
	replacements := map[string]bool{}
	for _, candidate := range candidates {
		replacements[candidate.Latest] = true
	}
	for _, fact := range scan.kept {
		if !replacements[fact.base] {
			continue
		}
		file, err := os.Open(fact.path)
		if err != nil {
			return err
		}
		before, err := file.Stat()
		if err == nil && !samePackageStat(fact.sourceInfo, before) {
			err = errors.New("replacement RPM changed before verification")
		}
		if err == nil {
			err = yumrepo.VerifyPackageDigests(ctx, file)
		}
		after, statErr := file.Stat()
		if statErr == nil && !samePackageStat(fact.sourceInfo, after) {
			statErr = errors.New("replacement RPM changed during verification")
		}
		if err = errors.Join(err, statErr, file.Close()); err != nil {
			return &Error{Kind: KindIntegrity, Op: "verify replacement RPM", Path: fact.path, Err: err}
		}
	}
	return nil
}
