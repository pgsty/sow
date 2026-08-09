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
	deb            aptrepo.Package
}

type scanResult struct {
	all        []packageFact
	index      []packageFact
	kept       []packageFact
	removed    []packageFact
	hadRPM     bool
	hadDEB     bool
	duplicates int
}

func scanPackages(ctx context.Context, dir string, jobs int, pigsty bool) (scanResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return scanResult{}, &Error{Kind: KindRuntime, Op: "scan", Path: dir, Err: err}
	}
	type candidate struct {
		base   string
		path   string
		format packageFormat
	}
	var candidates []candidate
	for _, entry := range entries {
		base := entry.Name()
		format := packageFormat("")
		switch {
		case strings.HasSuffix(base, ".rpm"):
			format = formatRPM
		case strings.HasSuffix(base, ".deb"):
			format = formatDEB
		default:
			continue
		}
		path := filepath.Join(dir, base)
		info, err := os.Lstat(path)
		if err != nil {
			return scanResult{}, &Error{Kind: KindRuntime, Op: "lstat", Path: path, Err: err}
		}
		if !info.Mode().IsRegular() {
			continue
		}
		candidates = append(candidates, candidate{base: base, path: path, format: format})
	}
	if len(candidates) == 0 {
		return scanResult{}, &Error{Kind: KindRejected, Op: "scan", Path: dir, Err: errors.New("no supported top-level regular RPM or DEB packages")}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].base < candidates[j].base })

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
				fact, err := inspectPackageFact(workerCtx, candidate.path, candidate.base, candidate.format)
				if err != nil {
					op := "parse deb"
					if candidate.format == formatRPM {
						op = "parse rpm"
					}
					results <- parsed{index: i, err: &Error{Kind: KindRuntime, Op: op, Path: candidate.path, Err: err}}
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
	facts := make([]packageFact, len(candidates))
	parseErrors := make([]error, len(candidates))
	for result := range results {
		if result.err != nil {
			parseErrors[result.index] = result.err
			continue
		}
		facts[result.index] = result.fact
	}
	for _, parseErr := range parseErrors {
		if parseErr != nil {
			return scanResult{}, parseErr
		}
	}
	if err := ctx.Err(); err != nil {
		return scanResult{}, &Error{Kind: KindRuntime, Op: "scan", Path: dir, Err: err}
	}

	result := scanResult{all: facts}
	coordinates := make(map[string]packageFact, len(facts))
	for _, fact := range facts {
		if fact.format == formatRPM {
			result.hadRPM = true
		} else {
			result.hadDEB = true
		}
		if previous, exists := coordinates[fact.coordinate]; exists {
			if previous.sha256 != fact.sha256 {
				return scanResult{}, &Error{Kind: KindRejected, Op: "coordinate conflict", Path: fact.base, Err: fmt.Errorf("%s and %s have the same logical coordinate but different SHA-256", previous.base, fact.base)}
			}
			result.duplicates++
		} else {
			coordinates[fact.coordinate] = fact
		}
		if pigsty && shouldRemove(fact) {
			result.removed = append(result.removed, fact)
		} else {
			result.kept = append(result.kept, fact)
		}
	}
	indexed := make(map[string]struct{}, len(result.kept))
	for _, fact := range result.kept {
		if _, exists := indexed[fact.coordinate]; exists {
			continue
		}
		indexed[fact.coordinate] = struct{}{}
		result.index = append(result.index, fact)
	}
	return result, nil
}

func inspectPackageFact(ctx context.Context, path, base string, format packageFormat) (packageFact, error) {
	fact := packageFact{format: format, base: base, path: path, originalPath: path}
	switch format {
	case formatRPM:
		pkg, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: path, Basename: base})
		if err != nil {
			return packageFact{}, err
		}
		fact.rpm, fact.name, fact.version, fact.arch, fact.sha256 = pkg, pkg.Name, pkg.Version, pkg.Arch, pkg.SHA256
		fact.coordinate = fmt.Sprintf("rpm:%s\x00%d\x00%s\x00%s\x00%s", pkg.Name, pkg.Epoch, pkg.Version, pkg.Release, pkg.Arch)
	case formatDEB:
		pkg, err := aptrepo.InspectPackage(ctx, path, "main")
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
