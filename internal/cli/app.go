package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/catalog"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

const Version = "0.1.0-dev"

// maxCLIWorkers is a user-visible resource-safety boundary. Remote publish
// workers are per target; with the fixed cf/cos target set, dual-target
// publication can therefore use at most twice this number concurrently.
const maxCLIWorkers = 64

func Main(args []string, stdout, stderr io.Writer) int {
	err := Run(context.Background(), args, stdout, stderr)
	if err != nil {
		if _, writeErr := fmt.Fprintf(stderr, "sow: %v\n", err); writeErr != nil {
			err = errors.Join(err, fmt.Errorf("write CLI diagnostic: %w", writeErr))
		}
	}
	return exitCode(err)
}

// cliWriteRecorder turns ignored fmt/io write results throughout the command
// surface into one sticky error at the process boundary. Commands can keep
// streaming progress without plumbing an output error through every business
// function, while a broken pipe or failed diagnostic sink can never be
// reported as successful completion.
type cliWriteRecorder struct {
	mu     sync.Mutex
	label  string
	writer io.Writer
	err    error
}

func newCLIWriteRecorder(label string, writer io.Writer) *cliWriteRecorder {
	return &cliWriteRecorder{label: label, writer: writer}
}

func (w *cliWriteRecorder) Write(body []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if w.writer == nil {
		w.err = fmt.Errorf("%s writer is nil", w.label)
		return 0, w.err
	}
	written, err := w.writer.Write(body)
	if err == nil && written != len(body) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.err = fmt.Errorf("%s: %w", w.label, err)
		return written, w.err
	}
	return written, nil
}

func (w *cliWriteRecorder) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func propagateCLIWriteErrors(result error, stdout, stderr *cliWriteRecorder) error {
	writeErr := errors.Join(stdout.Err(), stderr.Err())
	if writeErr == nil {
		return result
	}
	wrapped := fmt.Errorf("write CLI output: %w", writeErr)
	if result != nil {
		// Keep an established usage/config/network/etc exit class while retaining
		// the independently observable output failure in the error chain.
		return errors.Join(result, wrapped)
	}
	return &exitError{code: ExitInternal, err: wrapped}
}

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	stdoutRecorder := newCLIWriteRecorder("stdout", stdout)
	stderrRecorder := newCLIWriteRecorder("stderr", stderr)
	stdout = stdoutRecorder
	stderr = stderrRecorder
	defer func() {
		resultErr = propagateCLIWriteErrors(resultErr, stdoutRecorder, stderrRecorder)
	}()
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
	case "add":
		return runAdd(ctx, args[1:], stdout, stderr)
	case "rm":
		return runRemove(ctx, args[1:], stdout, stderr)
	case "sync":
		return runSync(ctx, args[1:], stdout, stderr)
	case "publish":
		return runPublish(ctx, args[1:], stdout, stderr)
	case "gc":
		return runGC(ctx, args[1:], stdout, stderr)
	case "verify":
		return runVerify(ctx, args[1:], stdout, stderr)
	case "promote":
		return runPromote(ctx, args[1:], stdout, stderr)
	case "materialize":
		return runMaterialize(ctx, args[1:], stdout, stderr)
	case "compatibility":
		return runCompatibility(ctx, args[1:], stdout, stderr)
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
  add        adopt DEB, RPM, or asset files into CAS, views, indexes, and a serving tree
  rm         remove selected packages or assets from a mutable view and rebuild indexes
  sync       mirror signed upstream metadata additively and commit provenance receipts
  publish    publish views or forward-restore one recorded target generation
  gc         audit CAS reachability; delete only a separately confirmed orphan set
  verify     execute evidence-backed L1-L4 checks with explicit coverage gates
  promote    promote selected package refs between channel manifests
  materialize build an exact hardlink tree from a view or snapshot ref
  compatibility adopt, build, freeze, cut over, or roll back frozen legacy trees
  version    print version and target platform
  help       show this help

Use 'sow <command> --help' for command options.

Exit codes:
  0 success; 1 internal; 2 usage; 3 config; 4 verification drift;
  5 network/auth; 6 conflict; 7 partial multi-target publication`)
}

// parseFlagSet preserves flag's built-in usage output while treating an
// explicit -h/--help request as successful command completion. ContinueOnError
// otherwise reports flag.ErrHelp to the caller, which would incorrectly turn
// every subcommand help request into exit status 2.
func parseFlagSet(fs *flag.FlagSet, args []string) (help bool, err error) {
	// The standard flag parser stops at the first positional argument. Scan the
	// raw command tail first so `flags positional --help` cannot be interpreted
	// as business input (which is especially dangerous for rm). The conventional
	// `--` delimiter still makes subsequent values literal positionals.
	expectsValue := false
	for _, argument := range args {
		if expectsValue {
			expectsValue = false
			continue
		}
		if argument == "--" {
			break
		}
		if argument == "-h" || argument == "--help" {
			fs.Usage()
			return true, nil
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			continue
		}
		name := strings.TrimPrefix(argument, "-")
		name = strings.TrimPrefix(name, "-")
		if _, _, hasValue := strings.Cut(name, "="); hasValue {
			continue
		}
		registered := fs.Lookup(name)
		if registered == nil {
			continue
		}
		boolean, isBoolean := registered.Value.(interface{ IsBoolFlag() bool })
		expectsValue = !isBoolean || !boolean.IsBoolFlag()
	}
	if parseErr := fs.Parse(args); parseErr != nil {
		if errors.Is(parseErr, flag.ErrHelp) {
			return true, nil
		}
		return false, withExitCode(ExitUsage, "%v", parseErr)
	}
	return false, nil
}

// printSubcommandUsage keeps each command's short synopsis and notes while
// deriving the option list from the FlagSet itself. That makes --help an exact
// view of the parser surface instead of a second, hand-maintained flag list.
func printSubcommandUsage(fs *flag.FlagSet, synopsis string, notes ...string) {
	output := fs.Output()
	fmt.Fprintf(output, "Usage: %s\n", synopsis)
	for _, note := range notes {
		if note != "" {
			fmt.Fprintln(output, note)
		}
	}
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Options:")
	fs.PrintDefaults()
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

	syncInternal         bool
	syncSelectionSHA256  string
	syncUpstreamContract *config.Upstream

	// materializeTrust is an immutable, lock-time snapshot used by every inner
	// live materialization boundary. It is intentionally not a CLI flag.
	materializeTrust *materializationTrustSnapshot
	// materializeUnit binds one worker to the exact durable selected-set unit.
	// It is copied into bounded worker values and never comes from CLI input.
	materializeUnit string
	// materializeCompatibility is nil for ordinary planning. Exact publication
	// recovery fills it from the durable unit vector so current selectors or a
	// newly-added projection cannot widen an interrupted transaction.
	materializeCompatibility map[string]bool
	materializeSource        string
	materializeTarget        string
	materializeOperation     string
	materializeScope         string
	// offlineArchiveAdoption is an internal-only, finalized proof carried from
	// deterministic archive creation into the asset CAS/ref transaction.
	offlineArchiveAdoption *offlineArchiveAdoptionContract
	// allowYUMCompatibilityFreeze is set only by the explicit compatibility
	// candidate/freeze command. Broad materialize or publish commands may replay
	// an existing witness but can never create an irreversible one implicitly.
	allowYUMCompatibilityFreeze bool
	// includeCompatibilityCarriers is set only by sow init and local fsck. It
	// lets the zero-byte baseline and local drift audit bind explicit inactive
	// legacy YUM carriers while every mutating and remote command excludes them
	// from ordinary repo selection.
	includeCompatibilityCarriers bool
	// includeAssetInventoryCarriers lets init and local fsck bind legacy asset
	// source trees that are deliberately not views or publishable repositories.
	// No package/asset mutation or remote command enables this selector class.
	includeAssetInventoryCarriers bool
	// localServingRecoveryTrustHook is a deterministic test-only seam around
	// journal-bound recovery checks. Production leaves it nil.
	localServingRecoveryTrustHook func(localServingRecoveryTrustBoundary)
}

func addCommonFlags(fs *flag.FlagSet, values *commonFlags) {
	fs.StringVar(&values.configPath, "config", "sow.yaml", "path to strict schema-v1 configuration")
	fs.StringVar(&values.root, "root", "", "override repository root from config")
	fs.Var(&values.repos, "repo", "select repo name or configured group (repeatable or comma-separated)")
	fs.Var(&values.oses, "os", "select configured OS (repeatable or comma-separated)")
	fs.Var(&values.arches, "arch", "select configured architecture (repeatable or comma-separated)")
	fs.IntVar(&values.workers, "workers", min(runtime.NumCPU(), maxCLIWorkers), "bounded worker count per operation/remote target (1-64)")
	fs.IntVar(&values.chunk, "chunk-entries", 4096, "entries per in-memory sorted run")
	fs.BoolVar(&values.recover, "recover", false, "preserve and replace a stale local operation lock")
}

func runInit(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	values.includeCompatibilityCarriers = true
	values.includeAssetInventoryCarriers = true
	addCommonFlags(fs, &values)
	adoptContent := fs.Bool("adopt-content", false, "import baseline-proven package/asset bytes into CAS and canonical views without rewriting the serving tree")
	legacyMetadataKeyring := fs.String("legacy-metadata-keyring", "", "verify every selected legacy YUM repomd.xml.asc with this public-only keyring (relative to config or absolute)")
	pruneMissingYUMConfirm := fs.String("adopt-prune-missing-yum-confirm", "", "explicitly omit YUM primary entries whose bodies are absent from M0; requires the exact reported blocker-set SHA-256")
	var adoptionViews csvFlag
	fs.Var(&adoptionViews, "view", "adoption destination: latest or stable (repeatable; default latest)")
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow init [--adopt-content [--view latest[,stable]] [--legacy-metadata-keyring FILE] [--adopt-prune-missing-yum-confirm SHA256]] [--config sow.yaml] [--root DIR] [--repo NAME] [--os OS] [--arch ARCH] [--workers N] [--recover]")
	}
	if help, err := parseFlagSet(fs, args); err != nil || help {
		return err
	}
	if fs.NArg() != 0 {
		return withExitCode(ExitUsage, "init accepts no positional arguments")
	}
	if !*adoptContent && len(adoptionViews.values()) != 0 {
		return withExitCode(ExitUsage, "init --view is valid only with --adopt-content")
	}
	if !*adoptContent && *legacyMetadataKeyring != "" {
		return withExitCode(ExitUsage, "init --legacy-metadata-keyring is valid only with --adopt-content")
	}
	if !*adoptContent && *pruneMissingYUMConfirm != "" {
		return withExitCode(ExitUsage, "init --adopt-prune-missing-yum-confirm is valid only with --adopt-content")
	}
	if *pruneMissingYUMConfirm != "" {
		digest, err := repository.ParseDigest(*pruneMissingYUMConfirm)
		if err != nil || digest.String() != *pruneMissingYUMConfirm {
			return withExitCode(ExitUsage, "init --adopt-prune-missing-yum-confirm must be a lowercase SHA-256")
		}
	}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		return err
	}
	var preparedAdoptionViews []string
	if *adoptContent {
		preparedAdoptionViews, err = validateLegacyAdoptionViews(cfg, adoptionViews.values())
		if err != nil {
			return err
		}
	}
	// Inactive compatibility carriers participate in the zero-byte S0 scan,
	// but their mixed-EL RPM set may only enter CAS through the dedicated
	// compatibility adoption state machine.  Generic legacy adoption would
	// incorrectly relabel those bytes as an ordinary repository leaf.
	adoptionRepos := make([]config.Repo, 0, len(repos))
	for _, repo := range repos {
		if repo.Type == "yum" && repo.YUM != nil && repo.YUM.CompatibilityCarrier {
			continue
		}
		if repo.Type == "asset" && repo.Asset != nil && repo.Asset.InventoryCarrier {
			continue
		}
		adoptionRepos = append(adoptionRepos, repo)
	}
	if *adoptContent && len(adoptionRepos) == 0 {
		return withExitCode(ExitUsage, "--adopt-content cannot adopt an inventory carrier; use the dedicated YUM compatibility workflow or activate a reviewed canonical asset repository after its rebase")
	}
	legacyMetadataTrust, err := prepareLegacyMetadataTrust(cfg, adoptionRepos, *legacyMetadataKeyring)
	if err != nil {
		return err
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "init", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := requireNoMaterializationIntentBeforeCanonicalMutation(cfg); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	store := state.New(cfg.StatePath())
	if err := prepareCanonicalState(ctx, store, values.recover, stdout); err != nil {
		return err
	}
	if err := requireCanonicalConfigBaseline(cfg, store); err != nil {
		return withExitCode(ExitConflict, "canonical config changed while init was waiting for the state lock: %v", err)
	}
	// A successfully initialized repository always has the real CAS directory
	// skeleton required by subsequent read-only Nginx/edge admission. Renderers
	// deliberately use repository.OpenStore and never create it themselves.
	if _, err := repository.NewStore(cfg.Root); err != nil {
		return withExitCode(ExitVerification, "initialize repository CAS: %v", err)
	}
	transactionDir, err := newTransactionDir(cfg.StatePath(), "init-")
	if err != nil {
		return withExitCode(ExitInternal, "create init transaction: %v", err)
	}
	defer os.RemoveAll(transactionDir)
	staged := make(map[string]string, len(repos))
	pinnedInventoryCarriers := make(map[string]bool)
	for _, repo := range repos {
		selectedPath := filepath.Join(transactionDir, repo.ID+".selected.tsv")
		stats, err := scanRepoManifest(ctx, cfg, repo, selectedPath, manifest.ScanOptions{
			Workers: values.workers, ChunkEntries: values.chunk,
			TempDir: filepath.Join(cfg.StatePath(), "tmp"),
		})
		if err != nil {
			return withExitCode(ExitVerification, "scan repo %s: %v", repo.ID, err)
		}
		dst := filepath.Join(transactionDir, repo.ID+".tsv")
		if err := stageRepoManifestUpdate(cfg, store, repo, selectedPath, dst, filepath.Join(cfg.StatePath(), "tmp")); err != nil {
			return withExitCode(ExitInternal, "stage selected baseline for repo %s: %v", repo.ID, err)
		}
		staged[repo.ID] = dst
		original, _ := cfg.RepoByName(repo.ID)
		immutableCarrier := repo.Type == "yum" && repo.YUM != nil && repo.YUM.CompatibilityCarrier ||
			repo.Type == "asset" && repo.Asset != nil && repo.Asset.InventoryCarrier
		if immutableCarrier {
			if !repoSelectionIsFull(original, repo) {
				return withExitCode(ExitUsage, "inventory carrier %s must be initialized as one complete S0 baseline without partial selectors", repo.ID)
			}
			ref, refErr := state.RepoRef(repo.ID)
			if refErr != nil {
				return withExitCode(ExitInternal, "construct compatibility carrier ref: %v", refErr)
			}
			baselineCommit, baselineExists, refErr := store.Ref(ref)
			if refErr != nil {
				return withExitCode(ExitInternal, "read compatibility carrier ref: %v", refErr)
			}
			if baselineExists {
				canonicalPath := filepath.ToSlash(filepath.Join("manifests", repo.ID+".tsv"))
				baseline, openErr := store.OpenPathAt(baselineCommit, canonicalPath)
				if openErr != nil {
					return withExitCode(ExitVerification, "open immutable inventory carrier baseline %s: %v", repo.ID, openErr)
				}
				current, openErr := os.Open(dst)
				if openErr != nil {
					_ = baseline.Close()
					return withExitCode(ExitInternal, "open rescanned inventory carrier %s: %v", repo.ID, openErr)
				}
				diff, diffErr := manifest.Diff(baseline, current, nil)
				closeErr := errors.Join(baseline.Close(), current.Close())
				if diffErr != nil || closeErr != nil || !diff.Clean() {
					return withExitCode(ExitVerification, "inventory carrier %s differs from immutable baseline at %s: added=%d removed=%d changed=%d: %v", repo.ID, baselineCommit, diff.Added, diff.Removed, diff.Changed, errors.Join(diffErr, closeErr))
				}
				pinnedInventoryCarriers[repo.ID] = true
			}
		}
		fmt.Fprintf(stdout, "scanned repo=%s files=%d bytes=%d scope_full=%t\n", repo.ID, stats.Files, stats.Bytes, repoSelectionIsFull(original, repo))
	}
	canonicalPaths := make(map[string]string, len(staged))
	updates := make([]state.RefUpdate, 0, len(repos))
	for _, repo := range repos {
		if pinnedInventoryCarriers[repo.ID] {
			fmt.Fprintf(stdout, "baseline preserved repo=%s immutable_inventory=true\n", repo.ID)
			continue
		}
		canonicalPaths[filepath.ToSlash(filepath.Join("manifests", repo.ID+".tsv"))] = staged[repo.ID]
		ref, err := state.RepoRef(repo.ID)
		if err != nil {
			return withExitCode(ExitInternal, "construct repository ref for %s: %v", repo.ID, err)
		}
		expected, _, err := store.Ref(ref)
		if err != nil {
			return withExitCode(ExitInternal, "read repository ref for %s: %v", repo.ID, err)
		}
		update := state.RefUpdate{Name: ref, Expected: expected}
		if repo.Type == "yum" && repo.YUM != nil && repo.YUM.CompatibilityCarrier ||
			repo.Type == "asset" && repo.Asset != nil && repo.Asset.InventoryCarrier {
			update.Immutable = true
		}
		updates = append(updates, update)
	}
	canonicalConfig, configHash, err := stageCanonicalConfig(cfg, transactionDir)
	if err != nil {
		return withExitCode(ExitInternal, "stage canonical config: %v", err)
	}
	canonicalPaths["config/sow.yaml"] = canonicalConfig
	hash, committed, err := applyCanonicalConfig(ctx, cfg, store, "init", "sow init: baseline "+strings.Join(repoNames(repos), ","), canonicalPaths, updates, state.ApplyOptions{})
	if err != nil {
		return stateMutationError("commit baseline", err)
	}
	if committed {
		fmt.Fprintf(stdout, "baseline committed=%s repos=%d config_sha256=%s\n", hash.String(), len(repos), configHash)
	} else {
		fmt.Fprintf(stdout, "baseline unchanged=%s repos=%d config_sha256=%s\n", hash.String(), len(repos), configHash)
	}
	entries, err := catalog.Count(cfg.StatePath())
	if err != nil {
		return withExitCode(ExitInternal, "verify rebuilt SQLite cache: %v", err)
	}
	fmt.Fprintf(stdout, "cache rebuilt entries=%d\n", entries)
	if *adoptContent {
		result, err := adoptLegacyContent(ctx, cfg, store, adoptionRepos, preparedAdoptionViews, transactionDir, legacyMetadataTrust, *pruneMissingYUMConfirm, values, stdout)
		if err != nil {
			var coded *exitError
			if errors.As(err, &coded) {
				return fmt.Errorf("adopt legacy content: %w", err)
			}
			return withExitCode(ExitVerification, "adopt legacy content: %v", err)
		}
		fmt.Fprintf(stdout, "adopt-content commit=%s changed=%t payloads=%d bytes=%d peak_import_workers=%d leaves=%d receipts=%d pruned_missing_yum=%d cache_entries=%d serving_tree_rewritten=false yum_metadata_signature=%s yum_metadata_keyring_sha256=%s\n",
			result.Commit, result.Changed, result.Payloads, result.Bytes, result.PeakImportWorkers, result.Leaves, result.Receipts, result.PrunedMissingYUM,
			result.CacheEntries, result.YUMMetadataSignature, result.YUMMetadataKeyringSHA256)
	}
	return nil
}

func runFSCK(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("fsck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	addCommonFlags(fs, &values)
	var targetFlags csvFlag
	fs.Var(&targetFlags, "target", "remote target to audit with full ListObjectsV2 (cf or cos; repeatable; omitted for local-only fsck)")
	adoptRemoteFlag := fs.Bool("adopt-remote-inventory", false, "explicitly adopt one stable remote bucket inventory after double-list and byte verification")
	repairPurgeLedgerFlag := fs.Bool("repair-purge-ledger", false, "local-only: restore canonical purge receipts from immutable Git anchors and attest legacy v1 plan bindings")
	limit := fs.Int("limit", 100, "maximum drift entries printed per repo (0 prints none)")
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow fsck [--config sow.yaml] [--root DIR] [--target cf|cos] [--adopt-remote-inventory | --repair-purge-ledger] [--repo NAME] [--os OS] [--arch ARCH] [--limit N] [--recover]")
	}
	if help, err := parseFlagSet(fs, args); err != nil || help {
		return err
	}
	if fs.NArg() != 0 || *limit < 0 {
		return withExitCode(ExitUsage, "fsck accepts no positional arguments and --limit cannot be negative")
	}
	if *adoptRemoteFlag {
		targets := uniqueSorted(targetFlags.values())
		if len(targets) != 1 {
			return withExitCode(ExitUsage, "--adopt-remote-inventory requires exactly one explicit --target cf|cos")
		}
		if len(values.oses.values()) != 0 || len(values.arches.values()) != 0 {
			return withExitCode(ExitUsage, "--adopt-remote-inventory does not accept partial --os/--arch selectors")
		}
	}
	if *repairPurgeLedgerFlag {
		targets := uniqueSorted(targetFlags.values())
		if len(targets) != 1 {
			return withExitCode(ExitUsage, "--repair-purge-ledger requires exactly one explicit --target cf|cos")
		}
		if *adoptRemoteFlag {
			return withExitCode(ExitUsage, "--repair-purge-ledger cannot be combined with --adopt-remote-inventory")
		}
		if len(values.repos.values()) != 0 || len(values.oses.values()) != 0 || len(values.arches.values()) != 0 {
			return withExitCode(ExitUsage, "--repair-purge-ledger does not accept repository, OS, or architecture selectors")
		}
	}
	// Local fsck must continue to audit M0-only asset baselines and raw YUM S0
	// carriers. Remote fsck excludes them because carriers have no serving or
	// target route.
	values.includeCompatibilityCarriers = len(targetFlags.values()) == 0
	values.includeAssetInventoryCarriers = len(targetFlags.values()) == 0
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		return err
	}
	if err := validateVerifyTargets(cfg, targetFlags.values()); err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	if *adoptRemoteFlag {
		targets := uniqueSorted(targetFlags.values())
		if err := validatePublishTargetAffinitySelection(repos, targets, len(values.repos.values()) != 0); err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "fsck", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	projectionAudit := inspectProjectionIntentsForAudit(cfg.StatePath())
	if projectionAudit.pending() {
		projectionAudit.writeFSCKDrift(stdout)
		return withExitCode(ExitVerification, "fsck found %d pending or invalid projection recovery intent(s); run the matching add, rm, or materialize command with --recover", len(projectionAudit.findings))
	}
	if values.recover || *adoptRemoteFlag || *repairPurgeLedgerFlag {
		if err := requireNoMaterializationIntentBeforeCanonicalMutation(cfg); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
	}
	if values.recover {
		preRecoveryStats, err := auditCanonicalGraphBeforeRecovery(cfg, lock)
		if err != nil {
			return withExitCode(ExitVerification, "audit canonical Git state before recovery: %v", err)
		}
		fmt.Fprintf(stdout, "fsck canonical_git_pre_recovery_roots=%d commits=%d blobs=%d blob_bytes=%d drift=0\n",
			preRecoveryStats.Roots, preRecoveryStats.Commits, preRecoveryStats.Blobs, preRecoveryStats.BlobBytes)
	}
	store := state.New(cfg.StatePath())
	if err := prepareCanonicalState(ctx, store, values.recover, stdout); err != nil {
		return err
	}
	if err := requireCanonicalConfigBaseline(cfg, store); err != nil {
		return withExitCode(ExitConflict, "canonical config changed while fsck was waiting for the state lock: %v", err)
	}
	writableStore := store
	canonicalAdmission, canonicalStats, err := openCanonicalFSCKAdmission(cfg, lock, writableStore)
	if err != nil {
		return withExitCode(ExitVerification, "audit canonical Git state: %v", err)
	}
	canonicalMutation := *adoptRemoteFlag || *repairPurgeLedgerFlag
	mutationTopologyGuard := false
	defer func() {
		if canonicalAdmission == nil {
			return
		}
		if mutationTopologyGuard {
			propagateCanonicalFSCKFinalizer(
				func() error { return closeCanonicalFSCKMutationTopology(canonicalAdmission) },
				"canonical Git topology", &resultErr,
			)
			return
		}
		propagateCanonicalFSCKFinalizer(
			func() error { return closeCanonicalFSCKAdmission(canonicalAdmission) },
			"canonical Git audit", &resultErr,
		)
	}()
	fmt.Fprintf(stdout, "fsck canonical_git_roots=%d commits=%d blobs=%d blob_bytes=%d drift=0\n",
		canonicalStats.Roots, canonicalStats.Commits, canonicalStats.Blobs, canonicalStats.BlobBytes)
	legacyPruneStats, err := auditCanonicalLegacyIndexPruneLedgers(canonicalAdmission.canonical)
	if err != nil {
		return withExitCode(ExitVerification, "audit canonical legacy YUM prune provenance: %v", err)
	}
	fmt.Fprintf(stdout, "fsck legacy_prune_ledgers=%d receipts=%d confirmation_sets=%d drift=0\n",
		legacyPruneStats.Ledgers, legacyPruneStats.Receipts, legacyPruneStats.ConfirmationSets)
	if canonicalMutation {
		// A planned canonical mutation must not poison the pre-mutation read
		// snapshot. Finalize it first, retain its topology capabilities across
		// the write, then open a fresh post-mutation audit below.
		if err := finalizeCanonicalFSCKAdmissionForMutation(canonicalAdmission); err != nil {
			return withExitCode(ExitVerification, "finalize pre-mutation canonical Git audit: %v", err)
		}
		mutationTopologyGuard = true
	} else {
		// Every subsequent canonical read in ordinary fsck now comes from the
		// same retained, hash-verifying Git snapshot rather than the mutable
		// checkout pathname.
		store = canonicalAdmission.canonical
	}
	transactionDir, err := newTransactionDir(cfg.StatePath(), "fsck-")
	if err != nil {
		return withExitCode(ExitInternal, "create fsck transaction: %v", err)
	}
	defer os.RemoveAll(transactionDir)
	if *repairPurgeLedgerFlag {
		if err := ensurePurgeLedgerRepairTransactionDir(cfg.StatePath(), transactionDir); err != nil {
			return withExitCode(ExitInternal, "validate purge ledger repair transaction: %v", err)
		}
		target := uniqueSorted(targetFlags.values())[0]
		if err := canonicalAdmission.verifyTopology(); err != nil {
			return withExitCode(ExitVerification, "validate canonical Git topology before purge-ledger repair: %v", err)
		}
		result, err := repairCanonicalPurgeLedger(ctx, store, cfg, target, transactionDir)
		topologyErr := canonicalAdmission.verifyTopology()
		if topologyErr != nil {
			return withExitCode(ExitVerification, "validate canonical Git topology after purge-ledger repair: %v", topologyErr)
		}
		if err != nil {
			if errors.Is(err, errPurgeLedgerRepairMutation) {
				return stateMutationError("repair canonical purge ledger target "+target, err)
			}
			return withExitCode(ExitVerification, "repair canonical purge ledger target %s: %v", target, err)
		}
		if err := catalog.Rebuild(cfg.StatePath()); err != nil {
			return withExitCode(ExitInternal, "rebuild SQLite cache after purge ledger repair: %v", err)
		}
		if err := validateCurrentCanonicalPurgeEvidenceClosure(store, cfg, target); err != nil {
			return withExitCode(ExitVerification, "validate repaired current purge closure target %s: %v", target, err)
		}
		findings, err := inspectCanonicalPurgeLedger(store, cfg, target)
		if err != nil {
			return withExitCode(ExitVerification, "validate repaired purge history target %s: %v", target, err)
		}
		if len(findings) != 0 {
			return withExitCode(ExitVerification, "validate repaired purge history target %s: %s: %s", target, findings[0].Code, findings[0].Message)
		}
		postAdmission, postStats, err := openCanonicalFSCKAdmission(cfg, lock, writableStore)
		if err != nil {
			return withExitCode(ExitVerification, "audit repaired canonical Git state: %v", err)
		}
		if err := closeCanonicalFSCKAdmission(postAdmission); err != nil {
			return withExitCode(ExitVerification, "finalize repaired canonical Git audit: %v", err)
		}
		if err := closeCanonicalFSCKMutationTopology(canonicalAdmission); err != nil {
			canonicalAdmission = nil
			mutationTopologyGuard = false
			return withExitCode(ExitVerification, "finalize repaired canonical Git topology: %v", err)
		}
		canonicalAdmission = nil
		mutationTopologyGuard = false
		fmt.Fprintf(stdout, "fsck canonical_git_post_roots=%d commits=%d blobs=%d blob_bytes=%d drift=0\n",
			postStats.Roots, postStats.Commits, postStats.Blobs, postStats.BlobBytes)
		fmt.Fprintf(stdout, "fsck-repair-purge-ledger target=%s generations=%d receipts_restored=%d legacy_attestations=%d commit=%s changed=%t network_requests=0\n",
			target, result.Generations, result.Receipts, result.Attestations, result.Commit, result.Changed)
		return nil
	}
	dirty := false
	materializedRouteStage := materializedRouteAuditStagePath(transactionDir)
	if err := os.MkdirAll(materializedRouteStage, 0o700); err != nil {
		return withExitCode(ExitInternal, "prepare canonical materialized-route audit: %v", err)
	}
	materializedRouteStats, err := auditCanonicalMaterializedRouteLedgers(store, materializedRouteStage)
	if err != nil {
		return withExitCode(ExitVerification, "audit canonical materialized-route ledgers: %v", err)
	}
	fmt.Fprintf(stdout, "fsck materialized_route_partitions=%d ledgers=%d files=%d drift=0\n",
		materializedRouteStats.Partitions, materializedRouteStats.Ledgers, materializedRouteStats.Files)
	if journal, active, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil {
		return withExitCode(ExitVerification, "inspect materialization recovery journal: %v", err)
	} else if active {
		dirty = true
		fmt.Fprintf(stdout, "drift materialization_operation=%s phase=%s completed_units=%d units=%d recovery_required=true\n", journal.Operation, journal.Phase, len(journal.CompletedUnits), len(journal.Units))
	}
	if intent, active, err := readAssetProjectionIntent(cfg.StatePath()); err != nil {
		return withExitCode(ExitVerification, "inspect pending asset projection intent: %v", err)
	} else if active {
		dirty = true
		fmt.Fprintf(stdout, "drift asset_projection_operation=%s repo=%s view=%s transaction=%s recovery_required=true\n",
			intent.Operation, intent.Repo, intent.View, intent.TransactionID)
	}
	assetProjectionDrift, err := auditCanonicalAssetProjectionRefs(store, cfg, repos, *limit, stdout)
	if err != nil {
		return withExitCode(ExitVerification, "audit canonical asset projection refs: %v", err)
	}
	if assetProjectionDrift != 0 {
		dirty = true
	}
	if len(repos) != 0 {
		fmt.Fprintf(stdout, "fsck canonical_asset_projection_drift=%d\n", assetProjectionDrift)
	}
	for _, repo := range repos {
		currentPath := filepath.Join(transactionDir, repo.ID+".tsv")
		_, err := scanRepoManifest(ctx, cfg, repo, currentPath, manifest.ScanOptions{
			Workers: values.workers, ChunkEntries: values.chunk,
			TempDir: filepath.Join(cfg.StatePath(), "tmp"),
		})
		if err != nil {
			fmt.Fprintf(stdout, "drift repo=%s kind=scan_error path=- error=%q\n", repo.ID, err.Error())
			return withExitCode(ExitVerification, "scan repo %s: %v", repo.ID, err)
		}
		baseline, err := store.OpenManifest(repo.ID)
		if err != nil {
			return withExitCode(ExitVerification, "%v (run 'sow init' first)", err)
		}
		original, _ := cfg.RepoByName(repo.ID)
		if !repoSelectionIsFull(original, repo) {
			filteredPath := filepath.Join(transactionDir, repo.ID+".baseline.selected.tsv")
			filterErr := filteredRepoBaseline(cfg, repo, baseline, filteredPath)
			closeErr := baseline.Close()
			if filterErr != nil || closeErr != nil {
				return withExitCode(ExitInternal, "filter repository baseline %s: %v", repo.ID, errors.Join(filterErr, closeErr))
			}
			baseline, err = os.Open(filteredPath)
			if err != nil {
				return withExitCode(ExitInternal, "open selected repository baseline %s: %v", repo.ID, err)
			}
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
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return withExitCode(ExitConflict, "open CAS for local serving audit: %v", err)
	}
	compatibility, err := selectedLatestYUMCompatibilityForViews(cfg, repos, []string{"latest"}, values)
	if err != nil {
		return withExitCode(ExitVerification, "select YUM compatibility projections: %v", err)
	}
	compatibilityDrift := 0
	if len(compatibility) != 0 {
		for _, projection := range compatibility {
			stage, err := auditYUMCompatibilityStage(ctx, cfg, store, pool, projection, transactionDir, values)
			if err != nil {
				compatibilityDrift++
				dirty = true
				if compatibilityDrift <= *limit {
					fmt.Fprintf(stdout, "drift yum_compatibility=%s stage=%s code=YUM_COMPATIBILITY_STAGE_CLOSURE_INVALID reason=%q\n", projection.ID, stage, err.Error())
				}
			} else {
				fmt.Fprintf(stdout, "fsck yum_compatibility=%s stage=%s clean=true\n", projection.ID, stage)
			}
		}
		fmt.Fprintf(stdout, "fsck yum_compatibility_checks=%d drift=%d\n", len(compatibility), compatibilityDrift)
	}
	servingEntries, err := buildLocalServingAuditEntries(cfg, store, pool, repos, nil, values, transactionDir)
	if err != nil {
		return withExitCode(ExitVerification, "audit canonical local YUM serving lifecycle: %v", err)
	}
	servingDrift := 0
	servingPrinted := 0
	for _, entry := range servingEntries {
		if err := entry.Run(ctx); err != nil {
			servingDrift++
			dirty = true
			if servingPrinted < *limit {
				fmt.Fprintf(stdout, "drift serving=%s code=%s reason=%v\n", entry.Subject, entry.Code, err)
				servingPrinted++
			}
		}
	}
	if len(servingEntries) != 0 {
		fmt.Fprintf(stdout, "fsck serving_checks=%d drift=%d\n", len(servingEntries), servingDrift)
	}
	if *adoptRemoteFlag && dirty {
		return withExitCode(ExitVerification, "local repository drift prevents remote inventory adoption")
	}
	targetNames := targetFlags.values()
	targetNames = uniqueSorted(targetNames)
	for _, target := range targetNames {
		client, err := newPublishTargetClient(cfg, target, "latest", false)
		if err != nil {
			return withExitCode(ExitConfig, "prepare remote fsck target %s: %v", target, err)
		}
		if *adoptRemoteFlag {
			if err := canonicalAdmission.verifyTopology(); err != nil {
				return withExitCode(ExitVerification, "validate canonical Git topology before remote inventory adoption: %v", err)
			}
			result, err := adoptRemoteInventory(ctx, cfg, store, repos, target, client, transactionDir, values.workers, *limit, stdout)
			topologyErr := canonicalAdmission.verifyTopology()
			if topologyErr != nil {
				return withExitCode(ExitVerification, "validate canonical Git topology after remote inventory adoption: %v", topologyErr)
			}
			if err != nil {
				code := ExitVerification
				if !errors.Is(err, errCanonicalRemoteAuditState) && !errors.Is(err, errRemoteAdoptionDrift) && !errors.Is(err, errRemoteObjectChanged) {
					code = ExitNetworkAuth
				}
				return withExitCode(code, "adopt remote inventory target %s: %v", target, redactPublishError(err))
			}
			fmt.Fprintf(stdout, "fsck-adopt target=%s listed=%d local_expected=%d retained_extra=%d streamed_get=%d pages=%d commit=%s changed=%t inventory_coverage=complete\n",
				target, result.Listed, result.LocalExpected, result.RetainedExtra, result.StreamedGET, result.Pages, result.Commit, result.Changed)
			if result.ZeroByteChecksums != 0 {
				dirty = true
			}
			continue
		}
		listedPath := filepath.Join(transactionDir, "remote-"+target+".tsv")
		remoteStats, err := auditFullRemoteInventory(ctx, cfg, store, target, client, listedPath, values.workers, *limit, stdout)
		if err != nil {
			if _, exists, stateErr := readOptionalCanonical(store, remoteStatePath(target, "inventory.tsv")); stateErr == nil && !exists {
				return withExitCode(ExitVerification, "remote fsck target %s has no canonical inventory (run an explicit remote baseline import first)", target)
			}
			if errors.Is(err, errCanonicalRemoteAuditState) {
				return withExitCode(ExitVerification, "remote fsck target %s canonical state is invalid", target)
			}
			if errors.Is(err, errRemoteAdoptionDrift) || errors.Is(err, errRemoteObjectChanged) {
				return withExitCode(ExitVerification, "remote fsck target %s drifted during audit: %v", target, redactPublishError(err))
			}
			return withExitCode(ExitNetworkAuth, "remote fsck target %s incomplete: %v", target, redactPublishError(err))
		}
		fmt.Fprintf(stdout, "fsck target=%s listed=%d expected=%d missing=%d changed=%d orphan=%d unknown=%d zero_byte_checksums=%d pages=%d inventory_coverage=%s\n",
			target, remoteStats.Listed, remoteStats.Expected, remoteStats.Missing, remoteStats.Changed,
			remoteStats.Orphan, remoteStats.Untracked, remoteStats.ZeroByteChecksums, remoteStats.Pages, remoteStats.Coverage)
		if remoteAuditDirty(remoteStats) {
			dirty = true
		}
	}
	if canonicalMutation {
		postAdmission, postStats, err := openCanonicalFSCKAdmission(cfg, lock, writableStore)
		if err != nil {
			return withExitCode(ExitVerification, "audit post-mutation canonical Git state: %v", err)
		}
		if err := closeCanonicalFSCKAdmission(postAdmission); err != nil {
			return withExitCode(ExitVerification, "finalize post-mutation canonical Git audit: %v", err)
		}
		fmt.Fprintf(stdout, "fsck canonical_git_post_roots=%d commits=%d blobs=%d blob_bytes=%d drift=0\n",
			postStats.Roots, postStats.Commits, postStats.Blobs, postStats.BlobBytes)
		if err := closeCanonicalFSCKMutationTopology(canonicalAdmission); err != nil {
			canonicalAdmission = nil
			mutationTopologyGuard = false
			return withExitCode(ExitVerification, "finalize post-mutation canonical Git topology: %v", err)
		}
		canonicalAdmission = nil
		mutationTopologyGuard = false
	}
	if dirty {
		return withExitCode(ExitVerification, "repository or remote drift detected")
	}
	if !canonicalMutation {
		if err := closeCanonicalFSCKAdmission(canonicalAdmission); err != nil {
			canonicalAdmission = nil
			return withExitCode(ExitVerification, "finalize canonical Git audit: %v", err)
		}
		canonicalAdmission = nil
	}
	fmt.Fprintf(stdout, "fsck clean repos=%d targets=%d at=%s\n", len(repos), len(targetNames), time.Now().UTC().Format(time.RFC3339))
	return nil
}

func prepareCanonicalState(ctx context.Context, store *state.Store, recover bool, stdout io.Writer) error {
	if err := prepareCanonicalStateCore(ctx, store, recover, stdout); err != nil {
		return err
	}
	if err := requireNoLocalServingTransactions(store.StateDir()); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireNoLocalServingTopologyRemovals(store.StateDir()); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	return nil
}

func prepareCanonicalStateCore(ctx context.Context, store *state.Store, recover bool, stdout io.Writer) error {
	if err := requireNoPendingYUMCompatibilityCutoverJournals(store.StateDir()); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	return prepareCanonicalStateCoreUnchecked(ctx, store, recover, stdout)
}

// prepareCanonicalStateCoreForYUMCompatibilityRecovery is the sole bypass for
// the ordinary-command cutover-journal gate. A compatibility transition may
// inspect and recover its own durable local journal, but it must still refuse
// to run while another compatibility projection has an unfinished cutover.
func prepareCanonicalStateCoreForYUMCompatibilityRecovery(ctx context.Context, store *state.Store, recover bool, stdout io.Writer, id string) error {
	if err := requireNoPendingYUMCompatibilityCutoverJournalsExcept(store.StateDir(), id); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	return prepareCanonicalStateCoreUnchecked(ctx, store, recover, stdout)
}

func prepareCanonicalStateCoreUnchecked(ctx context.Context, store *state.Store, recover bool, stdout io.Writer) error {
	var recovered int
	if recover {
		results, err := store.Recover(ctx)
		if err != nil {
			return withExitCode(ExitConflict, "recover canonical state: %v", err)
		}
		for _, result := range results {
			fmt.Fprintf(stdout, "recovered transaction=%s operation=%s commit=%s\n", result.ID, result.Operation, result.Commit)
		}
		recovered = len(results)
	} else if err := store.RequireNoIncompleteTransactions(); err != nil {
		return withExitCode(ExitConflict, "%v (retry with --recover)", err)
	}
	pendingProjection, err := pendingCatalogProjectionMutation(store.StateDir())
	if err != nil {
		return withExitCode(ExitConflict, "inspect pending SQLite catalog projection: %v", err)
	}
	if recovered == 0 && !pendingProjection {
		return nil
	}
	head, err := store.HeadHash()
	if err != nil {
		return withExitCode(ExitInternal, "read canonical HEAD after recovery: %v", err)
	}
	if !head.IsZero() {
		// A durable projection marker means the prior process could have stopped
		// at any point between the canonical commit and the cache-directory sync.
		// Do not trust matching metadata alone: rebuild and fsync the disposable
		// projection before removing the marker. Recovery is intentionally the
		// expensive path; ordinary projection-neutral commits still use the exact
		// head-only CAS in applyCanonicalState.
		if err := catalog.RebuildContext(ctx, store.StateDir()); err != nil {
			return withExitCode(ExitInternal, "rebuild SQLite cache after canonical recovery: %v", err)
		}
	}
	if pendingProjection {
		if err := finishCatalogProjectionMutation(store.StateDir()); err != nil {
			return withExitCode(ExitInternal, "complete SQLite catalog projection recovery: %v", err)
		}
	}
	if !head.IsZero() {
		entries, err := catalog.Count(store.StateDir())
		if err != nil {
			return withExitCode(ExitInternal, "verify SQLite cache after canonical recovery: %v", err)
		}
		if recover {
			fmt.Fprintf(stdout, "cache rebuilt after recovery entries=%d\n", entries)
		} else {
			fmt.Fprintf(stdout, "cache rebuilt after pending projection entries=%d\n", entries)
		}
	}
	return nil
}

func stateMutationError(action string, err error) error {
	code := ExitInternal
	if errors.Is(err, state.ErrRecoveryRequired) || errors.Is(err, state.ErrRefConflict) || errors.Is(err, state.ErrImmutableRef) || errors.Is(err, state.ErrFileConflict) {
		code = ExitConflict
	}
	return withExitCode(code, "%s: %v", action, err)
}

func loadAndSelect(values commonFlags) (*config.Config, []config.Repo, error) {
	baseline, err := readCanonicalConfigBaseline(values.configPath, values.root)
	if err != nil {
		return nil, nil, withExitCode(ExitVerification, "%v", err)
	}
	cfg, err := config.Load(values.configPath, values.root)
	if err != nil {
		return nil, nil, withExitCode(ExitConfig, "%v", err)
	}
	setCanonicalConfigBaseline(cfg, baseline)
	if err := validateCanonicalHistoryContracts(cfg); err != nil {
		return nil, nil, withExitCode(ExitConflict, "%v", err)
	}
	if err := validateCanonicalPoolContracts(cfg); err != nil {
		return nil, nil, withExitCode(ExitConflict, "%v", err)
	}
	if err := validateCanonicalYUMCompatibilityContracts(cfg); err != nil {
		return nil, nil, withExitCode(ExitConflict, "%v", err)
	}
	if values.workers < 1 || values.chunk < 1 {
		return nil, nil, withExitCode(ExitUsage, "--workers and --chunk-entries must be positive")
	}
	if values.workers > maxCLIWorkers {
		return nil, nil, withExitCode(ExitUsage, "--workers must not exceed %d", maxCLIWorkers)
	}
	unknown := difference(values.repos.values(), cfg.RepoSelectorNames())
	if len(unknown) > 0 {
		return nil, nil, withExitCode(ExitConfig, "unknown repo selector(s): %s", strings.Join(unknown, ","))
	}
	repoSelectors, err := cfg.ExpandRepoSelectors(values.repos.values())
	if err != nil {
		return nil, nil, withExitCode(ExitConfig, "%v", err)
	}
	// Validate every dimension value, not merely whether at least one value in
	// a comma-separated selector happens to match. Otherwise --arch
	// amd64,typo silently widens to amd64 and hides an operator mistake. Repo
	// selection scopes the vocabulary so values from an unrelated repository do
	// not mask an invalid combination.
	var selectorRepos []config.Repo
	var availableOS, availableArches []string
	for _, repo := range cfg.Repos {
		carrierForInit := values.includeCompatibilityCarriers && repo.Type == "yum" && repo.YUM != nil && repo.YUM.CompatibilityCarrier
		assetInventoryForAudit := values.includeAssetInventoryCarriers && repo.Type == "asset" && repo.Asset != nil && repo.Asset.InventoryCarrier
		if !repo.IsActive() && !carrierForInit && !assetInventoryForAudit || !matchesValue(repo.ID, repoSelectors) {
			continue
		}
		selectorRepos = append(selectorRepos, repo)
		availableOS = append(availableOS, repo.OSSelectorValues()...)
		availableArches = append(availableArches, repo.ArchSelectorValues()...)
	}
	if unknown = difference(values.oses.values(), availableOS); len(unknown) > 0 {
		return nil, nil, withExitCode(ExitConfig, "unknown os selector(s): %s", strings.Join(unknown, ","))
	}
	if unknown = difference(values.arches.values(), availableArches); len(unknown) > 0 {
		return nil, nil, withExitCode(ExitConfig, "unknown arch selector(s): %s", strings.Join(unknown, ","))
	}
	var selected []config.Repo
	for _, repo := range selectorRepos {
		if !matchesValue(repo.ID, repoSelectors) || !matchesAnyValue(repo.OSSelectorValues(), values.oses.values()) || !matchesAnyValue(repo.ArchSelectorValues(), values.arches.values()) {
			continue
		}
		selected = append(selected, narrowRepoSelection(repo, values))
	}
	if len(selected) == 0 {
		return nil, nil, withExitCode(ExitConfig, "selectors matched no active repositories")
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	return cfg, selected, nil
}

type canonicalConfigBaseline struct {
	exists   bool
	identity state.FileIdentity
}

// readCanonicalConfigBaseline snapshots committed canonical state before the
// external YAML is opened. FileIdentityAtHead binds the read to one Git commit
// rather than the mutable worktree used while another writer is committing.
func readCanonicalConfigBaseline(configPath, rootOverride string) (canonicalConfigBaseline, error) {
	_, root, err := config.ResolvePaths(configPath, rootOverride)
	if err != nil {
		return canonicalConfigBaseline{}, err
	}
	identity, exists, err := state.New(filepath.Join(root, config.StateDirectory)).FileIdentityAtHead("config/sow.yaml")
	if err != nil {
		return canonicalConfigBaseline{}, fmt.Errorf("read canonical config baseline from Git HEAD: %w", err)
	}
	return canonicalConfigBaseline{exists: exists, identity: identity}, nil
}

func setCanonicalConfigBaseline(cfg *config.Config, baseline canonicalConfigBaseline) {
	cfg.CanonicalBaselineKnown = true
	cfg.CanonicalBaselineExists = baseline.exists
	cfg.CanonicalBaselineSHA256 = baseline.identity.SHA256
	cfg.CanonicalBaselineSize = baseline.identity.Size
}

// captureCanonicalConfigBaseline remains the narrow helper for callers that
// already own a decoded Config. Command load paths must use the pre-decode
// readCanonicalConfigBaseline helper instead.
func captureCanonicalConfigBaseline(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("cannot capture canonical config baseline from nil config")
	}
	baseline, err := readCanonicalConfigBaseline(cfg.Path, cfg.Root)
	if err != nil {
		return err
	}
	setCanonicalConfigBaseline(cfg, baseline)
	return nil
}

func canonicalConfigFileIdentity(store *state.Store) (string, int64, error) {
	identity, exists, err := store.FileIdentityAtHead("config/sow.yaml")
	if err != nil {
		return "", 0, err
	}
	if !exists {
		return "", 0, os.ErrNotExist
	}
	return identity.SHA256, identity.Size, nil
}

func canonicalConfigApplyOptions(cfg *config.Config, options state.ApplyOptions) (state.ApplyOptions, error) {
	if cfg == nil || !cfg.CanonicalBaselineKnown {
		return options, nil
	}
	desired, err := cfg.Canonical()
	if err != nil {
		return state.ApplyOptions{}, err
	}
	digest := sha256.Sum256(desired)
	expectation := state.FileExpectation{AllowAbsent: !cfg.CanonicalBaselineExists}
	if cfg.CanonicalBaselineExists {
		expectation.Identities = append(expectation.Identities, state.FileIdentity{Size: cfg.CanonicalBaselineSize, SHA256: cfg.CanonicalBaselineSHA256})
	}
	desiredIdentity := state.FileIdentity{Size: int64(len(desired)), SHA256: hex.EncodeToString(digest[:])}
	if len(expectation.Identities) == 0 || expectation.Identities[0] != desiredIdentity {
		expectation.Identities = append(expectation.Identities, desiredIdentity)
	}
	expected := make(map[string]state.FileExpectation, len(options.ExpectedFiles)+1)
	for name, value := range options.ExpectedFiles {
		expected[name] = value
	}
	expected["config/sow.yaml"] = expectation
	options.ExpectedFiles = expected
	return options, nil
}

func requireCanonicalConfigBaseline(cfg *config.Config, store *state.Store) error {
	options, err := canonicalConfigApplyOptions(cfg, state.ApplyOptions{})
	if err != nil {
		return err
	}
	if err := store.RequireExpectedFiles(options.ExpectedFiles); err != nil {
		return err
	}
	// The exact config blob can return to its pre-lock identity after an unsafe
	// historical commit. Re-audit every immutable repository-history contract
	// while the caller holds the canonical lock so matching-HEAD drift cannot
	// cross a mutation boundary.
	if err := validateCanonicalHistoryContracts(cfg); err != nil {
		return err
	}
	_, err = auditCanonicalLegacyIndexPruneLedgers(store)
	return err
}

// validateCanonicalHistoryContracts is the shared read-only admission gate
// for ownership contracts whose evidence spans the reachable Git DAG rather
// than only the current config blob. Callers use it once before external work
// and again under the canonical lock immediately before local mutation.
func validateCanonicalHistoryContracts(cfg *config.Config) error {
	if err := validateCanonicalAssetProjectionContracts(cfg); err != nil {
		return err
	}
	if err := validateCanonicalPackageRepositoryContracts(cfg); err != nil {
		return err
	}
	return validateCanonicalYUMCompatibilityContracts(cfg)
}

func applyCanonicalConfig(ctx context.Context, cfg *config.Config, store *state.Store, operation, message string, staged map[string]string, refs []state.RefUpdate, options state.ApplyOptions) (plumbing.Hash, bool, error) {
	options, err := canonicalConfigApplyOptions(cfg, options)
	if err != nil {
		return plumbing.ZeroHash, false, err
	}
	return applyCanonicalState(ctx, store, operation, message, staged, refs, options)
}

// narrowRepoSelection returns a detached repository value whose leaf
// dimensions contain only the requested selectors. Selecting a repository is
// not sufficient: callers expand Suites and Arches later, so returning the
// original value would silently widen --os/--arch back to the whole repo.
func narrowRepoSelection(repo config.Repo, values commonFlags) config.Repo {
	selected := repo
	selected.Arches = intersectSelected(repo.Arches, values.arches.values())
	if repo.Type == "asset" {
		// Assets have the single frozen all/all leaf. loadAndSelect has already
		// rejected any selector that does not match it.
		selected.Arches = append([]string(nil), repo.Arches...)
	}
	if repo.APT != nil {
		selected.APT = repo.APT.NarrowSuites(intersectSelected(repo.APT.Suites, values.oses.values()))
	}
	if repo.YUM != nil {
		yum := *repo.YUM
		selected.YUM = &yum
	}
	if repo.Asset != nil {
		asset := *repo.Asset
		asset.MutablePaths = append([]string(nil), repo.Asset.MutablePaths...)
		selected.Asset = &asset
	}
	selected.Include = append([]string(nil), repo.Include...)
	selected.Exclude = append([]string(nil), repo.Exclude...)
	return selected
}

func intersectSelected(configured, selected []string) []string {
	if len(selected) == 0 {
		return append([]string(nil), configured...)
	}
	result := make([]string, 0, len(configured))
	for _, value := range configured {
		if matchesValue(value, selected) {
			result = append(result, value)
		}
	}
	return result
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

func stageCanonicalConfig(cfg *config.Config, transactionDir string) (string, string, error) {
	if err := validateCanonicalHistoryContracts(cfg); err != nil {
		return "", "", err
	}
	if err := validateCanonicalPoolContracts(cfg); err != nil {
		return "", "", err
	}
	encoded, err := cfg.Canonical()
	if err != nil {
		return "", "", err
	}
	hash, err := cfg.CanonicalSHA256()
	if err != nil {
		return "", "", err
	}
	path := filepath.Join(transactionDir, "canonical-sow.yaml")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", err
	}
	if _, err := file.Write(encoded); err != nil {
		file.Close()
		return "", "", err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", "", err
	}
	if err := file.Close(); err != nil {
		return "", "", err
	}
	return path, hash, nil
}

// validateCanonicalPoolContracts prevents a repository ID from silently
// reclassifying bytes that may already have been exposed through a public
// view. Pool is historical per-entry security state, not a mutable label. An
// empty repository may change before its first entry; populated repositories
// must use a new ID for an explicit classification migration.
func validateCanonicalPoolContracts(cfg *config.Config) error {
	if cfg == nil || cfg.Root == "" {
		return errors.New("cannot validate repository pool contract without a rooted config")
	}
	canonical := state.New(cfg.StatePath())
	reader, err := canonical.OpenPath("config/sow.yaml")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read prior canonical config for pool classification: %w", err)
	}
	prior, decodeErr := config.Decode(reader)
	closeErr := reader.Close()
	if decodeErr != nil || closeErr != nil {
		return fmt.Errorf("decode prior canonical config for pool classification: %w", errors.Join(decodeErr, closeErr))
	}
	priorPools := make(map[string]string, len(prior.Repos))
	for _, repo := range prior.Repos {
		priorPools[repo.ID] = repo.DefaultPool
	}
	for _, repo := range cfg.Repos {
		if previous, exists := priorPools[repo.ID]; exists && previous == repo.DefaultPool {
			continue
		}
		observed, location, exists, err := historicalRepositoryPool(canonical, repo.ID, repo.DefaultPool)
		if err != nil {
			return fmt.Errorf("audit historical pool classification for repo %s: %w", repo.ID, err)
		}
		if exists {
			return fmt.Errorf("repo %s default_pool is frozen as %s by canonical entry %s; refusing reclassification to %s (use a new repo ID and an explicit migration)", repo.ID, observed, location, repo.DefaultPool)
		}
	}
	return nil
}

func historicalRepositoryPool(canonical *state.Store, repoID, wanted string) (pool, location string, exists bool, err error) {
	history, err := canonical.History()
	if err != nil {
		return "", "", false, err
	}
	found := errors.New("historical repository pool mismatch found")
	for _, commit := range history {
		manifestPath := filepath.ToSlash(filepath.Join("manifests", repoID+".tsv"))
		err := canonical.ForEachFileAt(commit, "manifests/", func(name string) error {
			if name != manifestPath {
				return nil
			}
			reader, err := canonical.OpenPathAt(commit, name)
			if err != nil {
				return err
			}
			manifestReader := manifest.NewReader(reader)
			_, firstErr := manifestReader.Next()
			closeErr := reader.Close()
			if errors.Is(firstErr, io.EOF) {
				return closeErr
			}
			if firstErr != nil || closeErr != nil {
				return errors.Join(firstErr, closeErr)
			}
			historicalPool, err := canonicalRepositoryPoolAt(canonical, commit, repoID)
			if err != nil {
				return err
			}
			if historicalPool != wanted {
				pool, location, exists = historicalPool, commit.String()+":"+name, true
				return found
			}
			return nil
		})
		if errors.Is(err, found) {
			return pool, location, true, nil
		}
		if err != nil {
			return "", "", false, err
		}
		for _, prefix := range []string{"views/", "snapshots/"} {
			err := canonical.ForEachFileAt(commit, prefix, func(name string) error {
				reader, err := canonical.OpenPathAt(commit, name)
				if err != nil {
					return err
				}
				viewReader := views.NewReader(reader)
				for {
					entry, readErr := viewReader.Next()
					if errors.Is(readErr, io.EOF) {
						break
					}
					if readErr != nil {
						_ = reader.Close()
						return readErr
					}
					if entry.Repo == repoID && entry.Pool != wanted {
						pool, location, exists = entry.Pool, commit.String()+":"+name, true
						_ = reader.Close()
						return found
					}
				}
				return reader.Close()
			})
			if errors.Is(err, found) {
				return pool, location, true, nil
			}
			if err != nil {
				return "", "", false, err
			}
		}
	}
	return "", "", false, nil
}

func canonicalRepositoryPoolAt(canonical *state.Store, commit plumbing.Hash, repoID string) (string, error) {
	reader, err := canonical.OpenPathAt(commit, "config/sow.yaml")
	if err != nil {
		return "", fmt.Errorf("open historical config: %w", err)
	}
	cfg, decodeErr := config.Decode(reader)
	closeErr := reader.Close()
	if decodeErr != nil || closeErr != nil {
		return "", errors.Join(decodeErr, closeErr)
	}
	for _, repo := range cfg.Repos {
		if repo.ID == repoID {
			return repo.DefaultPool, nil
		}
	}
	return "", fmt.Errorf("historical manifest repo %s has no canonical config contract", repoID)
}
