package plain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/yumrepo"
)

type packageFormat string

const (
	formatRPM packageFormat = "rpm"
	formatDEB packageFormat = "deb"
)

type packageFact struct {
	format         packageFormat
	base           string
	path           string
	originalPath   string
	coordinate     string
	sha256         string
	originalSHA256 string
	name           string
	version        string
	arch           string
	signed         bool
	rpm            yumrepo.PackageInfo
	parsedRPM      *yumrepo.FlatPackage
	deb            aptrepo.Package
	sourceInfo     os.FileInfo
}

type scanResult struct {
	all         []packageFact
	index       []packageFact
	kept        []packageFact
	removed     []packageFact
	skipped     []SkippedPackage
	warnings    []string
	hasRPM      bool
	hasDEB      bool
	duplicates  int
	otherDEBs   []string
	markerLines []markerLine
}

type markerLine struct {
	base   string
	sha256 string
}

type packageCandidate struct {
	base   string
	path   string
	format packageFormat
	info   os.FileInfo
}

func listPackageCandidates(dir string, rpmOnly bool) ([]packageCandidate, []SkippedPackage, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, nil, &Error{Kind: KindRuntime, Op: "scan", Path: dir, Err: err}
	}
	var candidates []packageCandidate
	var skipped []SkippedPackage
	var otherDEBs []string
	for _, entry := range entries {
		base := entry.Name()
		var format packageFormat
		switch {
		case strings.HasSuffix(base, ".rpm"):
			format = formatRPM
		case strings.HasSuffix(base, ".deb"):
			format = formatDEB
		default:
			continue
		}
		fullPath := filepath.Join(dir, base)
		info, err := os.Stat(fullPath)
		if err != nil {
			if rpmOnly && format == formatDEB {
				continue
			}
			skipped = append(skipped, SkippedPackage{Path: base, Reason: fmt.Sprintf("unreadable package: %v", err)})
			continue
		}
		if !info.Mode().IsRegular() {
			if !info.IsDir() && !(rpmOnly && format == formatDEB) {
				skipped = append(skipped, SkippedPackage{Path: base, Reason: "package input is not a regular file"})
			}
			continue
		}
		if rpmOnly && format == formatDEB {
			otherDEBs = append(otherDEBs, base)
			continue
		}
		candidates = append(candidates, packageCandidate{base: base, path: fullPath, format: format, info: info})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].base < candidates[j].base })
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Path < skipped[j].Path })
	sort.Strings(otherDEBs)
	return candidates, skipped, otherDEBs, nil
}

func scanPackages(ctx context.Context, dir string, jobs int, pigsty, strict, rpmOnly bool) (scanResult, error) {
	candidates, brokenLinks, otherDEBs, err := listPackageCandidates(dir, rpmOnly)
	if err != nil {
		return scanResult{}, err
	}
	var warnings []string
	var skipped []SkippedPackage
	for _, item := range brokenLinks {
		if strict {
			return scanResult{}, &Error{Kind: KindRuntime, Op: "stat", Path: filepath.Join(dir, item.Path), Err: errors.New(item.Reason)}
		}
		skipped = append(skipped, item)
		warnings = append(warnings, fmt.Sprintf("skipped %s: %s", item.Path, item.Reason))
	}
	if rpmOnly && len(otherDEBs) > 0 {
		warnings = append(warnings, "directory also contains DEB packages; prune operates on RPM packages only")
	}
	if len(candidates) == 0 {
		if strict && !pigsty {
			return scanResult{}, &Error{Kind: KindRejected, Op: "scan", Path: dir, Err: errors.New("no supported top-level RPM or DEB packages")}
		}
		if !pigsty && len(skipped) == 0 {
			warnings = append(warnings, "no RPM or DEB packages found; nothing to index")
		}
		return scanResult{skipped: skipped, warnings: warnings, otherDEBs: otherDEBs}, nil
	}
	type parsed struct {
		index int
		fact  packageFact
		err   error
	}
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan int)
	results := make(chan parsed, len(candidates))
	workers := jobs
	if workers > len(candidates) {
		workers = len(candidates)
	}
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for i := range work {
				candidate := candidates[i]
				fact, err := inspectPackageFact(workerCtx, candidate.path, candidate.base, candidate.format, candidate.info)
				if err != nil {
					op := "parse deb"
					if candidate.format == formatRPM {
						op = "parse rpm"
					}
					results <- parsed{index: i, err: &Error{Kind: KindOf(err), Op: op, Path: candidate.path, Err: err}}
					continue
				}
				if candidate.format == formatRPM && isSourceRPMArch(fact.arch) {
					results <- parsed{index: i, err: &Error{Kind: KindRejected, Op: "reject source rpm", Path: candidate.path, Err: fmt.Errorf("RPM header architecture %q is not a binary package", fact.arch)}}
					continue
				}
				results <- parsed{index: i, fact: fact}
			}
		}()
	}
	go func() {
		defer close(work)
		for i := range candidates {
			select {
			case work <- i:
			case <-workerCtx.Done():
				return
			}
		}
	}()
	go func() {
		group.Wait()
		close(results)
	}()
	parsedFacts := make([]packageFact, len(candidates))
	parseErrors := make([]error, len(candidates))
	for result := range results {
		if result.err != nil {
			parseErrors[result.index] = result.err
			continue
		}
		parsedFacts[result.index] = result.fact
	}
	if err := ctx.Err(); err != nil {
		return scanResult{}, &Error{Kind: KindRuntime, Op: "scan", Path: dir, Err: err}
	}

	facts := make([]packageFact, 0, len(candidates))
	for i, parseErr := range parseErrors {
		if parseErr != nil {
			if strict || KindOf(parseErr) == KindIntegrity {
				return scanResult{}, parseErr
			}
			reason := parseErr.Error()
			if unwrapped := errors.Unwrap(parseErr); unwrapped != nil {
				reason = unwrapped.Error()
			}
			skipped = append(skipped, SkippedPackage{Path: candidates[i].base, Reason: reason})
			warnings = append(warnings, fmt.Sprintf("skipped %s: %s", candidates[i].base, reason))
			continue
		}
		facts = append(facts, parsedFacts[i])
	}

	unifyDEBCoordinates(facts)
	result := scanResult{all: facts, skipped: skipped, warnings: warnings, otherDEBs: otherDEBs}
	coordinates := make(map[string]packageFact, len(facts))
	for _, fact := range facts {
		if pigsty && shouldRemove(fact) {
			result.removed = append(result.removed, fact)
			continue
		}
		if !rpmOnly {
			if previous, exists := coordinates[fact.coordinate]; exists {
				if previous.sha256 != fact.sha256 {
					if strict {
						return scanResult{}, &Error{Kind: KindRejected, Op: "coordinate conflict", Path: fact.base, Err: fmt.Errorf("%s and %s have the same logical coordinate but different SHA-256", previous.base, fact.base)}
					}
					reason := fmt.Sprintf("conflicts with %s (same logical coordinate, different SHA-256)", previous.base)
					result.skipped = append(result.skipped, SkippedPackage{Path: fact.base, Reason: reason})
					result.warnings = append(result.warnings, fmt.Sprintf("skipped %s: %s", fact.base, reason))
					continue
				}
				result.duplicates++
			} else {
				coordinates[fact.coordinate] = fact
			}
		}
		result.kept = append(result.kept, fact)
	}
	indexed := make(map[string]struct{}, len(result.kept))
	for _, fact := range result.kept {
		if _, exists := indexed[fact.coordinate]; exists {
			continue
		}
		indexed[fact.coordinate] = struct{}{}
		result.index = append(result.index, fact)
		if fact.format == formatRPM {
			result.hasRPM = true
		} else {
			result.hasDEB = true
		}
	}
	return result, nil
}

// Equal Debian versions can have different spellings. Keep scan order (basename)
// for conflict resolution, while grouping equivalent coordinates in O(n log n).
func unifyDEBCoordinates(facts []packageFact) {
	var debs []*packageFact
	for i := range facts {
		if facts[i].format == formatDEB {
			debs = append(debs, &facts[i])
		}
	}
	sort.SliceStable(debs, func(i, j int) bool { return aptrepo.ComparePackageIdentity(debs[i].deb, debs[j].deb) < 0 })
	for i := 1; i < len(debs); i++ {
		if aptrepo.ComparePackageIdentity(debs[i-1].deb, debs[i].deb) == 0 {
			debs[i].coordinate = debs[i-1].coordinate
		}
	}
}

func (s scanResult) preserveFormat(format packageFormat) bool {
	if format == formatRPM && s.hasRPM || format == formatDEB && s.hasDEB {
		return false
	}
	for _, skipped := range s.skipped {
		if filepath.Ext(skipped.Path) == "."+string(format) {
			return true
		}
	}
	return false
}

func validatePackageStats(root string, scan scanResult, rpmOnly bool) error {
	candidates, _, _, err := listPackageCandidates(root, rpmOnly)
	if err != nil {
		return err
	}
	expected := make(map[string]os.FileInfo, len(scan.all)+len(scan.skipped))
	for _, skipped := range scan.skipped {
		expected[skipped.Path] = nil
	}
	for _, fact := range scan.all {
		expected[fact.base] = fact.sourceInfo
	}
	verified := 0
	for _, candidate := range candidates {
		info, known := expected[candidate.base]
		if !known {
			return &Error{Kind: KindIntegrity, Op: "validate package set", Path: candidate.path, Err: errors.New("package appeared after inspection")}
		}
		if info == nil {
			continue
		} // Already reported and excluded from the index.
		if !samePackageStat(info, candidate.info) {
			return &Error{Kind: KindIntegrity, Op: "validate package", Path: candidate.path, Err: errors.New("package stat changed after inspection")}
		}
		verified++
	}
	if verified != len(scan.all) {
		return &Error{Kind: KindIntegrity, Op: "validate package set", Path: root, Err: errors.New("package disappeared after inspection")}
	}
	return nil
}

func (f packageFact) validateStat() error {
	info, err := os.Stat(f.originalPath)
	if err != nil || !samePackageStat(f.sourceInfo, info) {
		return &Error{Kind: KindIntegrity, Op: "validate package", Path: f.originalPath, Err: errors.Join(errors.New("package stat changed after inspection"), err)}
	}
	return nil
}

func inspectPackageFact(ctx context.Context, path, base string, format packageFormat, before os.FileInfo) (_ packageFact, resultErr error) {
	if before == nil {
		var err error
		before, err = os.Stat(path)
		if err != nil {
			return packageFact{}, err
		}
	}
	if !before.Mode().IsRegular() {
		return packageFact{}, errors.New("package input is not a regular file")
	}
	fact := packageFact{format: format, base: base, path: path, originalPath: path, sourceInfo: before}
	defer func() {
		if err := fact.validateStat(); err != nil {
			resultErr = err
		}
	}()
	switch format {
	case formatRPM:
		parsed, pkg, err := yumrepo.InspectFlatPackage(ctx, yumrepo.PackageInput{Path: path, Basename: base})
		if err != nil {
			return packageFact{}, err
		}
		fact.parsedRPM, fact.rpm, fact.name, fact.version, fact.arch, fact.sha256 = parsed, pkg, pkg.Name, pkg.Version, pkg.Arch, pkg.SHA256
		fact.coordinate = fmt.Sprintf("rpm:%s\x00%d\x00%s\x00%s\x00%s", pkg.Name, pkg.Epoch, pkg.Version, pkg.Release, pkg.Arch)
	case formatDEB:
		pkg, err := aptrepo.InspectFlatPackage(ctx, path, "main")
		if err != nil {
			return packageFact{}, err
		}
		fact.deb, fact.name, fact.version, fact.arch, fact.sha256 = pkg, pkg.Name, pkg.Version, pkg.Architecture, pkg.SHA256
		fact.coordinate = fmt.Sprintf("deb:%s\x00%s\x00%s", pkg.Name, pkg.Version, pkg.Architecture)
	default:
		return packageFact{}, fmt.Errorf("unsupported package format %q", format)
	}
	fact.originalSHA256 = fact.sha256
	return fact, nil
}

func samePackageStat(before, after os.FileInfo) bool {
	return before != nil && after != nil &&
		before.Mode().IsRegular() && after.Mode().IsRegular() &&
		os.SameFile(before, after) &&
		before.Size() == after.Size() &&
		before.ModTime().Equal(after.ModTime())
}

func isSourceRPMArch(arch string) bool {
	return arch == "src" || arch == "nosrc"
}

func shouldRemove(fact packageFact) bool {
	switch fact.format {
	case formatRPM:
		return fact.name == "patroni" && fact.version == "3.0.4"
	case formatDEB:
		if fact.arch == "i386" {
			return true
		}
		return fact.name == "patroni" && debianUpstreamVersion(fact.version) == "3.0.4"
	default:
		return false
	}
}

func debianUpstreamVersion(version string) string {
	if colon := strings.IndexByte(version, ':'); colon >= 0 {
		version = version[colon+1:]
	}
	if revision := strings.LastIndexByte(version, '-'); revision >= 0 {
		version = version[:revision]
	}
	return version
}
