package plain

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/yumrepo"
	"golang.org/x/sys/unix"
)

// An interrupted prune keeps the old completion marker here until its rerun
// finishes. No package backup or operation journal is needed.
const pruneMarkerName = ".sow-prune-repo-complete"

type PruneOptions struct {
	Dir     string
	DryRun  bool
	Strict  bool
	Protect []string
	Jobs    int
	// MetadataTimestamp is the RPM index publication time, as for Create.
	MetadataTimestamp int64
	Timeout           time.Duration
	NoWait            bool
	Fault             func(Fault) error
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
	Skipped      []SkippedPackage `json:"skipped,omitempty"`
	Warnings     []string         `json:"warnings,omitempty"`
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
	base, err := normalizeOptions(ctx, Options{Dir: opts.Dir, Jobs: opts.Jobs, Strict: opts.Strict, MetadataTimestamp: opts.MetadataTimestamp, Timeout: opts.Timeout, NoWait: opts.NoWait, Fault: opts.Fault})
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
	info, err := os.Stat(root)
	if err != nil {
		return result, &Error{Kind: KindRuntime, Op: "prune directory", Path: root, Err: err}
	}
	if !info.IsDir() {
		return result, &Error{Kind: KindRejected, Op: "prune directory", Path: root, Err: errors.New("target is not a directory")}
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return result, &Error{Kind: KindRuntime, Op: "prune directory", Path: root, Err: err}
	}
	lock, err := acquireDirectoryLock(ctx, root, base.Timeout, base.NoWait)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	if err := lock.Validate(); err != nil {
		return result, err
	}
	var extraWarnings []string
	if err := validatePruneDirectory(root, opts.DryRun); err != nil {
		return result, err
	}
	if opts.DryRun {
		prior, inspectErr := inspectPriorRPMMetadata(root)
		if inspectErr != nil {
			extraWarnings = append(extraWarnings, fmt.Sprintf("repodata/repomd.xml inspection warning (would block a live prune): %v", inspectErr))
		} else if len(prior.unsupported) > 0 {
			extraWarnings = append(extraWarnings, fmt.Sprintf("repodata/repomd.xml contains unsupported metadata (%s) that would block a live prune unless removed", strings.Join(prior.unsupported, ", ")))
		}
		if _, statErr := os.Lstat(filepath.Join(root, "repodata", "repomd.xml.asc")); statErr == nil {
			extraWarnings = append(extraWarnings, "repodata/repomd.xml.asc exists; live prune refuses signed repodata until the detached signature is removed")
		}
	} else {
		if err := rejectUnsupportedRPMMetadata(root); err != nil {
			return result, err
		}
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
	scan, err := scanPackages(ctx, root, base.Jobs, false, opts.Strict, true)
	if err != nil {
		return result, err
	}
	scan.warnings = append(extraWarnings, scan.warnings...)
	scan, candidates, err := selectPrunePackages(scan, opts.Protect, opts.Strict)
	if err != nil {
		return result, err
	}
	result = PruneResult{
		Dir: root, DryRun: opts.DryRun, Kept: []string{}, Candidates: candidates, Removed: []string{},
		Skipped: scan.skipped, Warnings: scan.warnings, Marker: base.Pigsty,
	}
	for _, fact := range scan.kept {
		result.Kept = append(result.Kept, fact.base)
	}
	if err := inject(base.Fault, FaultAfterContentScan, "", -1); err != nil {
		return result, err
	}
	if scan.preserveFormat(formatRPM) {
		result.Warnings = append(result.Warnings, "all RPM candidates were skipped; existing repository metadata preserved")
		result.Noop, result.Marker = true, marker
		return result, lock.Validate()
	}
	if opts.DryRun {
		result.Noop = len(candidates) == 0 && !pendingMarker
		return result, lock.Validate()
	}
	replacements, err := verifyPruneReplacements(ctx, scan, candidates)
	if err != nil {
		return result, err
	}
	if err := validatePruneDirectory(root, false); err != nil {
		return result, err
	}
	if err := cleanupStalePlainState(root); err != nil {
		return result, err
	}
	if base.Pigsty && len(scan.otherDEBs) > 0 {
		present := make(map[string]bool, len(scan.otherDEBs))
		for _, name := range scan.otherDEBs {
			present[name] = true
		}
		scan.markerLines, err = readPriorMarker(root, func(name string) bool { return present[name] })
		if err != nil {
			return result, err
		}
	}
	staged, scan, err := renderStage(ctx, root, scan, base)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(staged.dir)) }()
	if err := inject(base.Fault, FaultBeforeStatValidation, "", -1); err != nil {
		return result, err
	}
	if err := validatePruneDirectory(root, false); err != nil {
		return result, err
	}
	if err := rejectUnsupportedRPMMetadata(root); err != nil {
		return result, err
	}
	plan, err := preparePublication(ctx, root, staged, scan, base, true)
	if err != nil {
		return result, err
	}
	if err := lock.Validate(); err != nil {
		return result, err
	}
	if err := verifyPruneReplacementIdentities(ctx, replacements); err != nil {
		return result, err
	}
	if err := validatePackageStats(root, scan, true); err != nil {
		return result, err
	}
	plan.prune = true
	plan.pruneReplacements = replacements
	plan.changed = plan.changed || pendingMarker
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

// isManagedWorkspaceRoot identifies an actual SOW managed workspace: a .sow
// directory paired with sow.yml (or sow.yaml). A stray plain file named .sow
// in an ancestor directory is not a managed workspace.
func isManagedWorkspaceRoot(dir string) bool {
	sowInfo, err := os.Stat(filepath.Join(dir, ".sow"))
	if err != nil || !sowInfo.IsDir() {
		return false
	}
	for _, cfgName := range []string{"sow.yml", "sow.yaml"} {
		cfgInfo, cfgErr := os.Stat(filepath.Join(dir, cfgName))
		if cfgErr == nil && cfgInfo.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func rejectManagedWorkspaceAncestors(root, op, message string) error {
	for dir := root; ; dir = filepath.Dir(dir) {
		if isManagedWorkspaceRoot(dir) {
			return &Error{Kind: KindRejected, Op: op, Path: root, Err: errors.New(message)}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	return nil
}

func validatePruneDirectory(root string, dryRun bool) error {
	if err := rejectManagedWorkspaceAncestors(root, "prune", "managed workspaces cannot be pruned as flat repositories"); err != nil {
		return err
	}
	if !dryRun {
		sigPath := filepath.Join(root, "repodata", "repomd.xml.asc")
		if _, err := os.Lstat(sigPath); err == nil {
			return &Error{Kind: KindRejected, Op: "prune", Path: sigPath, Err: errors.New("prune refuses signed repodata/repomd.xml.asc; remove the detached signature before pruning")}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// The prior marker is the evidence for a format whose index we leave in place.
// During an interrupted publication its durable copy is the pending marker.
func readPriorMarker(root string, keep func(string) bool) ([]markerLine, error) {
	path := filepath.Join(root, "repo_complete")
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		path = filepath.Join(root, pruneMarkerName)
		file, err = os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	var lines []markerLine
	seen := map[string]bool{}
	s := bufio.NewScanner(file)
	for s.Scan() {
		digest, name, ok := strings.Cut(s.Text(), "  ")
		if !ok || !validSHA256(digest) || filepath.Base(name) != name || (filepath.Ext(name) != ".rpm" && filepath.Ext(name) != ".deb") || seen[name] {
			return nil, fmt.Errorf("invalid completion marker %s", path)
		}
		seen[name] = true
		if keep(name) {
			lines = append(lines, markerLine{base: name, sha256: digest})
		}
	}
	return lines, s.Err()
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

func selectPrunePackages(scan scanResult, protect []string, strict bool) (scanResult, []PruneCandidate, error) {
	protected := make(map[string]bool, len(protect))
	for _, name := range protect {
		protected[name] = true
	}
	groups := make(map[string][]packageFact)
	present := make(map[string]bool, len(scan.all))
	for _, fact := range scan.all {
		if fact.format != formatRPM {
			continue
		}
		key := fact.name + "\x00" + fact.arch
		groups[key] = append(groups[key], fact)
		present[fact.name] = true
	}
	warnings := append([]string(nil), scan.warnings...)
	skipped := append([]SkippedPackage(nil), scan.skipped...)
	for _, name := range protect {
		if !present[name] {
			if strict {
				return scanResult{}, nil, &Error{Kind: KindUsage, Op: "protect", Path: name, Err: errors.New("no RPM package in the directory has this exact name")}
			}
			warnings = append(warnings, fmt.Sprintf("protected package %q was not found in this directory", name))
		}
	}
	compare := func(a, b packageFact) int {
		return yumrepo.CompareEVR(a.rpm.Epoch, a.rpm.Version, a.rpm.Release, b.rpm.Epoch, b.rpm.Version, b.rpm.Release)
	}
	latest := make(map[string]packageFact, len(groups))
	keepAllGroup := make(map[string]bool)
	var keys []string
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := groups[key]
		sort.SliceStable(group, func(i, j int) bool { return compare(group[i], group[j]) > 0 })
		if protected[group[0].name] {
			// Explicitly protected packages keep every version; equal-version
			// copies need never block pruning.
			keepAllGroup[key] = true
			latest[key] = group[0]
			continue
		}
		conflict := false
		for i := 1; i < len(group); i++ {
			if compare(group[i-1], group[i]) == 0 {
				if group[i-1].sha256 == group[i].sha256 {
					continue
				}
				if strict {
					return scanResult{}, nil, &Error{Kind: KindRejected, Op: "prune version conflict", Path: group[i].base, Err: fmt.Errorf("%s and %s have equal RPM versions", group[i-1].base, group[i].base)}
				}
				conflict = true
				warnings = append(warnings, fmt.Sprintf("skipped pruning %s.%s: %s and %s have equal RPM versions with different content", group[0].name, group[0].arch, group[i-1].base, group[i].base))
				break
			}
		}
		if conflict {
			keepAllGroup[key] = true
		}
		latest[key] = group[0]
	}
	result := scanResult{all: scan.all, hasRPM: len(groups) > 0, skipped: skipped, warnings: warnings, otherDEBs: scan.otherDEBs}
	candidates := []PruneCandidate{}
	indexed := make(map[string]struct{}, len(scan.all))
	for _, fact := range scan.all {
		if fact.format != formatRPM {
			continue
		}
		groupKey := fact.name + "\x00" + fact.arch
		newest := latest[groupKey]
		if protected[fact.name] || keepAllGroup[groupKey] || fact.base == newest.base || (compare(fact, newest) == 0 && fact.sha256 == newest.sha256) {
			result.kept = append(result.kept, fact)
			if _, exists := indexed[fact.coordinate]; !exists {
				indexed[fact.coordinate] = struct{}{}
				result.index = append(result.index, fact)
			}
		} else {
			result.removed = append(result.removed, fact)
			candidates = append(candidates, PruneCandidate{Path: fact.base, Latest: newest.base})
		}
	}
	return result, candidates, nil
}

// pruneReplacement binds a verified replacement RPM to its inode and digest.
// Refreshing identity after a successful SHA-256 re-check avoids repeating full
// file hashing on benign external hardlink / ctime changes.
type pruneReplacement struct {
	path     string
	sha256   string
	identity unix.Stat_t
}

func samePruneCoreIdentity(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mtim == b.Mtim
}

func samePruneIdentity(a, b unix.Stat_t) bool {
	return samePruneCoreIdentity(a, b) && a.Nlink == b.Nlink && a.Ctim == b.Ctim
}

func (replacement *pruneReplacement) verify(ctx context.Context) error {
	var current unix.Stat_t
	err := unix.Stat(replacement.path, &current)
	if err != nil {
		return &Error{Kind: KindIntegrity, Op: "verify replacement RPM", Path: replacement.path, Err: err}
	}
	if samePruneIdentity(replacement.identity, current) {
		return nil
	}
	if !samePruneCoreIdentity(replacement.identity, current) || replacement.sha256 == "" {
		return &Error{Kind: KindIntegrity, Op: "verify replacement RPM", Path: replacement.path, Err: errors.New("replacement RPM changed after verification")}
	}
	file, err := os.OpenFile(replacement.path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return &Error{Kind: KindIntegrity, Op: "verify replacement RPM", Path: replacement.path, Err: err}
	}
	var opened unix.Stat_t
	statErr := unix.Fstat(int(file.Fd()), &opened)
	if statErr == nil && !samePruneCoreIdentity(replacement.identity, opened) {
		statErr = errors.New("replacement RPM changed while reopening")
	}
	hash := sha256.New()
	var copyErr error
	if statErr == nil {
		_, copyErr = io.Copy(hash, &contextReader{ctx: ctx, reader: file})
	}
	if err := errors.Join(statErr, copyErr, file.Close()); err != nil {
		return &Error{Kind: KindIntegrity, Op: "verify replacement RPM", Path: replacement.path, Err: err}
	}
	if hex.EncodeToString(hash.Sum(nil)) != replacement.sha256 {
		return &Error{Kind: KindIntegrity, Op: "verify replacement RPM", Path: replacement.path, Err: errors.New("replacement RPM changed after verification")}
	}
	// Update recorded stat identity so subsequent checks do not re-hash on the
	// same unchanged external hardlink / ctime bump.
	replacement.identity = opened
	return nil
}

func verifyPruneReplacementIdentities(ctx context.Context, replacements map[string]*pruneReplacement) error {
	for _, replacement := range replacements {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := replacement.verify(ctx); err != nil {
			return err
		}
	}
	return nil
}

func verifyPruneReplacements(ctx context.Context, scan scanResult, candidates []PruneCandidate) (map[string]*pruneReplacement, error) {
	needed := map[string]bool{}
	for _, candidate := range candidates {
		needed[candidate.Latest] = true
	}
	replacements := make(map[string]*pruneReplacement, len(needed))
	for _, fact := range scan.kept {
		if !needed[fact.base] {
			continue
		}
		file, err := os.OpenFile(fact.path, os.O_RDONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, &Error{Kind: KindIntegrity, Op: "verify replacement RPM", Path: fact.path, Err: err}
		}
		replacement := &pruneReplacement{path: fact.path, sha256: fact.sha256}
		err = unix.Fstat(int(file.Fd()), &replacement.identity)
		if err == nil && replacement.identity.Mode&unix.S_IFMT != unix.S_IFREG {
			err = errors.New("replacement RPM must be a regular file")
		}
		if err == nil && fact.sourceInfo != nil {
			openedInfo, infoErr := file.Stat()
			if infoErr != nil {
				err = infoErr
			} else if !os.SameFile(fact.sourceInfo, openedInfo) || fact.sourceInfo.Size() != openedInfo.Size() || !fact.sourceInfo.ModTime().Equal(openedInfo.ModTime()) {
				// File metadata changed between scan and verify: require exact
				// SHA-256 equality with the indexed bytes before accepting it.
				hash := sha256.New()
				if _, copyErr := io.Copy(hash, &contextReader{ctx: ctx, reader: file}); copyErr != nil {
					err = copyErr
				} else if hex.EncodeToString(hash.Sum(nil)) != fact.sha256 {
					err = errors.New("replacement RPM changed after scan")
				} else if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
					err = seekErr
				}
			}
		}
		if err == nil {
			err = yumrepo.VerifyPackageDigests(ctx, file)
		}
		if err = errors.Join(err, file.Close()); err != nil {
			return nil, &Error{Kind: KindIntegrity, Op: "verify replacement RPM", Path: fact.path, Err: err}
		}
		replacements[fact.name+"\x00"+fact.arch] = replacement
	}
	return replacements, nil
}
