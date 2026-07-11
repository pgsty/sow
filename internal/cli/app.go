package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/catalog"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/state"
)

const Version = "0.1.0-dev"

func Main(args []string, stdout, stderr io.Writer) int {
	err := Run(context.Background(), args, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "sow: %v\n", err)
	}
	return exitCode(err)
}

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		writeHelp(stdout)
		return nil
	}
	switch args[0] {
	case "help", "-h", "--help":
		writeHelp(stdout)
		return nil
	case "version", "--version":
		fmt.Fprintf(stdout, "sow %s %s/%s %s\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return nil
	case "init":
		return runInit(ctx, args[1:], stdout, stderr)
	case "fsck":
		return runFSCK(ctx, args[1:], stdout, stderr)
	default:
		return withExitCode(ExitUsage, "unknown command %q (run 'sow help')", args[0])
	}
}

func writeHelp(w io.Writer) {
	fmt.Fprintln(w, `sow — Pigsty artifact repository manager

Usage:
  sow <command> [options]

Commands:
  init       adopt configured repository trees into a deterministic Git manifest baseline
  fsck       rescan configured repository trees and report drift from the baseline
  version    print version and target platform
  help       show this help

Implemented commands are listed explicitly; incomplete product commands are not exposed.
Use 'sow <command> --help' for command options.

Exit codes:
  0 success; 1 internal; 2 usage; 3 config; 4 verification drift;
  5 network/auth; 6 conflict; 7 partial multi-target publication`)
}

type commonFlags struct {
	configPath string
	root       string
	repos      csvFlag
	oses       csvFlag
	arches     csvFlag
	workers    int
	chunk      int
	recover    bool
}

func addCommonFlags(fs *flag.FlagSet, values *commonFlags) {
	fs.StringVar(&values.configPath, "config", "sow.yaml", "path to strict schema-v1 configuration")
	fs.StringVar(&values.root, "root", "", "override repository root from config")
	fs.Var(&values.repos, "repo", "select repo name (repeatable or comma-separated)")
	fs.Var(&values.oses, "os", "select configured OS (repeatable or comma-separated)")
	fs.Var(&values.arches, "arch", "select configured architecture (repeatable or comma-separated)")
	fs.IntVar(&values.workers, "workers", runtime.NumCPU(), "bounded hashing worker count")
	fs.IntVar(&values.chunk, "chunk-entries", 4096, "entries per in-memory sorted run")
	fs.BoolVar(&values.recover, "recover", false, "preserve and replace a stale local operation lock")
}

func runInit(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	addCommonFlags(fs, &values)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: sow init [--config sow.yaml] [--root DIR] [--repo NAME] [--os OS] [--arch ARCH] [--workers N] [--recover]")
	}
	if err := fs.Parse(args); err != nil {
		return withExitCode(ExitUsage, "%v", err)
	}
	if fs.NArg() != 0 {
		return withExitCode(ExitUsage, "init accepts no positional arguments")
	}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		return err
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "init", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer func() {
		if releaseErr := lock.Release(); releaseErr != nil {
			fmt.Fprintf(stderr, "warning: release state lock: %v\n", releaseErr)
		}
	}()
	transactionDir, err := newTransactionDir(cfg.StatePath(), "init-")
	if err != nil {
		return withExitCode(ExitInternal, "create init transaction: %v", err)
	}
	defer os.RemoveAll(transactionDir)
	staged := make(map[string]string, len(repos))
	for _, repo := range repos {
		dst := filepath.Join(transactionDir, repo.ID+".tsv")
		stats, err := manifest.Scan(ctx, cfg.Root, manifest.Scope{
			Path: repo.Path, Include: repo.Include, Exclude: repo.Exclude,
		}, dst, manifest.ScanOptions{
			Workers: values.workers, ChunkEntries: values.chunk,
			TempDir: filepath.Join(cfg.StatePath(), "tmp"),
		})
		if err != nil {
			return withExitCode(ExitConflict, "scan repo %s: %v", repo.ID, err)
		}
		staged[repo.ID] = dst
		fmt.Fprintf(stdout, "scanned repo=%s files=%d bytes=%d\n", repo.ID, stats.Files, stats.Bytes)
	}
	store := state.New(cfg.StatePath())
	hash, committed, err := store.Install(staged, "sow init: baseline "+strings.Join(repoNames(repos), ","))
	if err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	if committed {
		fmt.Fprintf(stdout, "baseline committed=%s repos=%d\n", hash.String(), len(repos))
	} else {
		fmt.Fprintf(stdout, "baseline unchanged=%s repos=%d\n", hash.String(), len(repos))
	}
	if err := catalog.Rebuild(cfg.StatePath()); err != nil {
		return withExitCode(ExitInternal, "rebuild SQLite cache from canonical manifests: %v", err)
	}
	entries, err := catalog.Count(cfg.StatePath())
	if err != nil {
		return withExitCode(ExitInternal, "verify rebuilt SQLite cache: %v", err)
	}
	fmt.Fprintf(stdout, "cache rebuilt entries=%d\n", entries)
	return nil
}

func runFSCK(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("fsck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	addCommonFlags(fs, &values)
	limit := fs.Int("limit", 100, "maximum drift entries printed per repo (0 prints none)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: sow fsck [--config sow.yaml] [--root DIR] [--repo NAME] [--os OS] [--arch ARCH] [--limit N] [--recover]")
	}
	if err := fs.Parse(args); err != nil {
		return withExitCode(ExitUsage, "%v", err)
	}
	if fs.NArg() != 0 || *limit < 0 {
		return withExitCode(ExitUsage, "fsck accepts no positional arguments and --limit cannot be negative")
	}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		return err
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "fsck", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer func() {
		if releaseErr := lock.Release(); releaseErr != nil {
			fmt.Fprintf(stderr, "warning: release state lock: %v\n", releaseErr)
		}
	}()
	transactionDir, err := newTransactionDir(cfg.StatePath(), "fsck-")
	if err != nil {
		return withExitCode(ExitInternal, "create fsck transaction: %v", err)
	}
	defer os.RemoveAll(transactionDir)
	store := state.New(cfg.StatePath())
	dirty := false
	for _, repo := range repos {
		currentPath := filepath.Join(transactionDir, repo.ID+".tsv")
		_, err := manifest.Scan(ctx, cfg.Root, manifest.Scope{
			Path: repo.Path, Include: repo.Include, Exclude: repo.Exclude,
		}, currentPath, manifest.ScanOptions{
			Workers: values.workers, ChunkEntries: values.chunk,
			TempDir: filepath.Join(cfg.StatePath(), "tmp"),
		})
		if err != nil {
			return withExitCode(ExitConflict, "scan repo %s: %v", repo.ID, err)
		}
		baseline, err := store.OpenManifest(repo.ID)
		if err != nil {
			return withExitCode(ExitVerification, "%v (run 'sow init' first)", err)
		}
		current, err := os.Open(currentPath)
		if err != nil {
			_ = baseline.Close()
			return withExitCode(ExitInternal, "%v", err)
		}
		printed := 0
		stats, diffErr := manifest.Diff(baseline, current, func(change manifest.Change) error {
			if printed < *limit {
				fmt.Fprintf(stdout, "drift repo=%s kind=%s path=%s\n", repo.ID, change.Kind, change.Path())
				printed++
			}
			return nil
		})
		closeErr := errors.Join(baseline.Close(), current.Close())
		if diffErr != nil || closeErr != nil {
			return withExitCode(ExitInternal, "compare repo %s: %v", repo.ID, errors.Join(diffErr, closeErr))
		}
		fmt.Fprintf(stdout, "fsck repo=%s added=%d removed=%d changed=%d\n", repo.ID, stats.Added, stats.Removed, stats.Changed)
		if !stats.Clean() {
			dirty = true
		}
	}
	if dirty {
		return withExitCode(ExitVerification, "repository drift detected")
	}
	fmt.Fprintf(stdout, "fsck clean repos=%d at=%s\n", len(repos), time.Now().UTC().Format(time.RFC3339))
	return nil
}

func loadAndSelect(values commonFlags) (*config.Config, []config.Repo, error) {
	cfg, err := config.Load(values.configPath, values.root)
	if err != nil {
		return nil, nil, withExitCode(ExitConfig, "%v", err)
	}
	if values.workers < 1 || values.chunk < 1 {
		return nil, nil, withExitCode(ExitUsage, "--workers and --chunk-entries must be positive")
	}
	unknown := difference(values.repos.values(), repoNames(cfg.Repos))
	if len(unknown) > 0 {
		return nil, nil, withExitCode(ExitConfig, "unknown repo selector(s): %s", strings.Join(unknown, ","))
	}
	var selected []config.Repo
	for _, repo := range cfg.Repos {
		if !repo.IsActive() {
			continue
		}
		if !matchesValue(repo.ID, values.repos.values()) || !matchesAnyValue(repo.OSSelectorValues(), values.oses.values()) || !matchesAnyValue(repo.Arches, values.arches.values()) {
			continue
		}
		selected = append(selected, repo)
	}
	if len(selected) == 0 {
		return nil, nil, withExitCode(ExitConfig, "selectors matched no active repositories")
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	return cfg, selected, nil
}

func matchesValue(value string, selected []string) bool {
	if len(selected) == 0 {
		return true
	}
	for _, candidate := range selected {
		if candidate == value {
			return true
		}
	}
	return false
}

func matchesAnyValue(values, selected []string) bool {
	if len(selected) == 0 {
		return true
	}
	for _, value := range values {
		if matchesValue(value, selected) {
			return true
		}
	}
	return false
}

func repoNames(repos []config.Repo) []string {
	names := make([]string, 0, len(repos))
	for _, repo := range repos {
		names = append(names, repo.ID)
	}
	sort.Strings(names)
	return names
}

func difference(selected, available []string) []string {
	set := make(map[string]struct{}, len(available))
	for _, value := range available {
		set[value] = struct{}{}
	}
	var missing []string
	for _, value := range selected {
		if _, exists := set[value]; !exists {
			missing = append(missing, value)
		}
	}
	sort.Strings(missing)
	return missing
}

type csvFlag struct {
	items []string
}

func (f *csvFlag) String() string { return strings.Join(f.items, ",") }

func (f *csvFlag) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return errors.New("selector values cannot be empty")
		}
		if !contains(f.items, item) {
			f.items = append(f.items, item)
		}
	}
	return nil
}

func (f *csvFlag) values() []string { return f.items }

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func newTransactionDir(statePath, prefix string) (string, error) {
	parent := filepath.Join(statePath, "transactions")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(parent, prefix)
}
