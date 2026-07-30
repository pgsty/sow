package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func runGC(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "sow.yaml", "path to strict schema-v1 configuration")
	root := fs.String("root", "", "override repository root from config")
	apply := fs.Bool("apply", false, "delete the exact currently confirmed CAS and serving set")
	confirm := fs.String("confirm", "", "gc_set_sha256 from a current dry run")
	limit := fs.Int("limit", 100, "maximum orphan/missing objects printed (0 prints none)")
	workers := fs.Int("workers", min(runtime.NumCPU(), maxCLIWorkers), "bounded workers for generation-directory validation (1-64)")
	chunk := fs.Int("chunk-entries", 4096, "entries per generation-directory manifest run")
	recover := fs.Bool("recover", false, "recover local state and rebuild the SQLite cache before auditing")
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow gc [--config sow.yaml] [--apply --confirm SHA256] [--limit N] [--workers N] [--chunk-entries N] [--recover]")
	}
	if help, err := parseFlagSet(fs, args); err != nil || help {
		return err
	}
	if fs.NArg() != 0 || *limit < 0 || *workers < 1 || *workers > maxCLIWorkers || *chunk < 1 || (!*apply && *confirm != "") || (*apply && *confirm == "") {
		return withExitCode(ExitUsage, "gc accepts no positional arguments; --apply requires --confirm, and --confirm is invalid without --apply")
	}
	baseline, err := readCanonicalConfigBaseline(*configPath, *root)
	if err != nil {
		return withExitCode(ExitVerification, "%v", err)
	}
	cfg, err := config.Load(*configPath, *root)
	if err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	setCanonicalConfigBaseline(cfg, baseline)
	if err := validateCanonicalHistoryContracts(cfg); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := validateCanonicalPoolContracts(cfg); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := validateCanonicalYUMCompatibilityContracts(cfg); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "gc", *recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := requireNoMaterializationIntentBeforeCanonicalMutation(cfg); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	canonical := state.New(cfg.StatePath())
	if err := prepareCanonicalState(ctx, canonical, *recover, stdout); err != nil {
		return err
	}
	if err := requireCanonicalConfigBaseline(cfg, canonical); err != nil {
		return withExitCode(ExitConflict, "canonical config changed while gc was waiting for the state lock: %v", err)
	}
	// requireCanonicalConfigBaseline re-audits both asset and package reachable
	// history while the lock is held. Keep repository.NewStore below that shared
	// boundary so no CAS scan or delete can run against post-load drift.
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return withExitCode(ExitConflict, "open CAS: %v", err)
	}
	roots, rootFiles, err := collectCanonicalRoots(ctx, canonical, pool, cfg.State.CASHistoryCommits)
	if err != nil {
		return withExitCode(ExitVerification, "collect canonical GC roots: %v", err)
	}
	result, err := pool.GC(ctx, roots, repository.GCOptions{})
	if err != nil {
		code := ExitVerification
		if errors.Is(err, repository.ErrGCProtection) {
			code = ExitConflict
		}
		return withExitCode(code, "CAS GC: %v", err)
	}
	servingPlan, err := collectServingGenerationGCPlan(cfg, canonical, pool)
	if err != nil {
		return withExitCode(ExitVerification, "collect serving generation GC plan: %v", err)
	}
	planSHA256 := combinedGCPlanSHA256(result.Report, servingPlan)
	deletedGenerations := 0
	deletedTombstones := 0
	deletedServingChannels := 0
	deletedServingTargets := 0
	retiredServingLedgers := 0
	var transactionDir string
	if len(servingPlan.Directories) != 0 || len(servingPlan.Protected) != 0 {
		transactionDir, err = newTransactionDir(cfg.StatePath(), "serving-gc-")
		if err != nil {
			return withExitCode(ExitInternal, "create serving GC transaction: %v", err)
		}
		defer os.RemoveAll(transactionDir)
		gcValues := commonFlags{workers: *workers, chunk: *chunk}
		if err := validateServingGenerationGCPlan(ctx, cfg, canonical, pool, servingPlan, gcValues, transactionDir); err != nil {
			return withExitCode(ExitVerification, "serving generation GC preflight: %v", err)
		}
		if err := requireServingGenerationGCPlan(cfg, canonical, pool, servingPlan); err != nil {
			return withExitCode(ExitConflict, "serving generation GC preflight changed: %v", err)
		}
	}
	if *apply {
		if *confirm != planSHA256 {
			return withExitCode(ExitConflict, "GC confirmation differs from current CAS+serving plan: confirm %q, current %q", *confirm, planSHA256)
		}
		if transactionDir == "" {
			transactionDir, err = newTransactionDir(cfg.StatePath(), "serving-gc-")
			if err != nil {
				return withExitCode(ExitInternal, "create serving GC transaction: %v", err)
			}
			defer os.RemoveAll(transactionDir)
		}
		// Rebind the combined plan after potentially expensive directory
		// preflight and before the first destructive action. This closes the
		// window in which an out-of-band CAS or canonical change could otherwise
		// leave directory deletion authorized by a stale combined digest.
		applyRoots, _, rootErr := collectCanonicalRoots(ctx, canonical, pool, cfg.State.CASHistoryCommits)
		if rootErr != nil {
			return withExitCode(ExitVerification, "recollect canonical GC roots before apply: %v", rootErr)
		}
		applyCAS, auditErr := pool.GC(ctx, applyRoots, repository.GCOptions{})
		if auditErr != nil {
			return withExitCode(ExitVerification, "re-audit CAS GC before apply: %v", auditErr)
		}
		applyServingPlan, planErr := collectServingGenerationGCPlan(cfg, canonical, pool)
		if planErr != nil {
			return withExitCode(ExitVerification, "recollect serving generation GC plan before apply: %v", planErr)
		}
		if !sameServingGenerationGCPlan(servingPlan, applyServingPlan) || combinedGCPlanSHA256(applyCAS.Report, applyServingPlan) != *confirm {
			return withExitCode(ExitConflict, "CAS or serving GC set changed after preflight; run a new dry run")
		}
		gcValues := commonFlags{workers: *workers, chunk: *chunk}
		if err := validateServingGenerationGCPlan(ctx, cfg, canonical, pool, applyServingPlan, gcValues, transactionDir); err != nil {
			return withExitCode(ExitVerification, "serving generation GC changed after preflight: %v", err)
		}
		if applyCAS.Report.Stats.MissingObjects != 0 {
			return withExitCode(ExitVerification, "CAS GC has %d missing referenced object(s); refusing serving-directory deletion", applyCAS.Report.Stats.MissingObjects)
		}
		result = applyCAS
		var remainingPlan servingGenerationGCPlan
		deletedGenerations, remainingPlan, err = applyServingGenerationDirectories(ctx, cfg, canonical, pool, servingPlan, gcValues, transactionDir)
		if err != nil {
			code := ExitVerification
			if errors.Is(err, repository.ErrGCProtection) {
				code = ExitConflict
			}
			return withExitCode(code, "serving generation GC: %v", err)
		}
		// Directory removal does not alter canonical reachability, but the CAS
		// set may have drifted out-of-band while large trees were validated.
		// Rebuild roots and re-audit before using the CAS-only confirmation.
		freshRoots, _, rootErr := collectCanonicalRoots(ctx, canonical, pool, cfg.State.CASHistoryCommits)
		if rootErr != nil {
			return withExitCode(ExitVerification, "recollect canonical GC roots: %v", rootErr)
		}
		freshCAS, auditErr := pool.GC(ctx, freshRoots, repository.GCOptions{})
		if auditErr != nil {
			return withExitCode(ExitVerification, "re-audit CAS GC: %v", auditErr)
		}
		if freshCAS.Report.OrphanSetSHA256 != result.Report.OrphanSetSHA256 || freshCAS.Report.Stats.MissingObjects != result.Report.Stats.MissingObjects || freshCAS.Report.Stats.MissingBytes != result.Report.Stats.MissingBytes {
			return withExitCode(ExitConflict, "CAS GC set changed after serving-directory validation; run a new dry run")
		}
		result, err = pool.GC(ctx, freshRoots, repository.GCOptions{Apply: true, ConfirmOrphanSetSHA256: freshCAS.Report.OrphanSetSHA256})
		if err != nil {
			code := ExitVerification
			if errors.Is(err, repository.ErrGCProtection) {
				code = ExitConflict
			}
			return withExitCode(code, "CAS GC: %v", err)
		}
		deletedTombstones, err = removeServingGenerationTombstones(ctx, cfg, canonical, pool, remainingPlan)
		if err != nil {
			code := ExitVerification
			if errors.Is(err, repository.ErrGCProtection) {
				code = ExitConflict
			}
			return withExitCode(code, "serving generation tombstone GC: %v", err)
		}
		deletedServingChannels, deletedServingTargets, retiredServingLedgers, err = applyMissingServingTargets(ctx, cfg, canonical, pool, servingPlan.Targets)
		if err != nil {
			code := ExitVerification
			if errors.Is(err, repository.ErrGCProtection) {
				code = ExitConflict
			}
			return withExitCode(code, "serving target GC: %v", err)
		}
	}
	printed := 0
	for _, object := range result.Report.Missing {
		if printed >= *limit {
			break
		}
		fmt.Fprintf(stdout, "gc missing sha256=%s size=%d\n", object.HashString(), object.Size)
		printed++
	}
	for _, object := range result.Report.Orphans {
		if printed >= *limit {
			break
		}
		fmt.Fprintf(stdout, "gc orphan sha256=%s size=%d\n", object.HashString(), object.Size)
		printed++
	}
	stats := result.Report.Stats
	fmt.Fprintf(stdout, "gc dry_run=%t root_files=%d references=%d reachable=%d orphans=%d missing=%d serving_generations_installed=%d serving_generation_orphans=%d serving_generation_tombstones=%d serving_target_orphans=%d orphan_set_sha256=%s gc_set_sha256=%s deleted=%d deleted_bytes=%d deleted_serving_generations=%d deleted_serving_tombstones=%d deleted_serving_channels=%d deleted_serving_targets=%d retired_serving_ledgers=%d\n",
		result.DryRun, rootFiles, stats.ReferenceEntries, stats.ReachableObjects, stats.OrphanObjects, stats.MissingObjects,
		len(servingPlan.Installed), len(servingPlan.Directories), len(servingPlan.Tombstones), len(servingPlan.Targets), result.Report.OrphanSetSHA256, planSHA256,
		result.DeletedObjects, result.DeletedBytes, deletedGenerations, deletedTombstones, deletedServingChannels, deletedServingTargets, retiredServingLedgers)
	return nil
}

func collectCanonicalRoots(ctx context.Context, canonical *state.Store, pool *repository.Store, historyLimit int) (*repository.ReferenceSet, int64, error) {
	if historyLimit < 1 {
		return nil, 0, errors.New("canonical CAS history retention must be positive")
	}
	history, err := canonical.History()
	if err != nil {
		return nil, 0, err
	}
	if len(history) > historyLimit {
		history = history[:historyLimit]
	}
	roots := &repository.ReferenceSet{}
	var files int64
	for historyIndex, commit := range history {
		if err := ctx.Err(); err != nil {
			return nil, files, err
		}
		paths, err := canonical.ListFilesAt(commit, "")
		if err != nil {
			return nil, files, err
		}
		for _, canonicalPath := range paths {
			var addErr error
			switch {
			case isCurrentYUMCompatibilityManifest(canonicalPath):
				// A compatibility ref pins the source commit, which can age out of
				// the bounded aggregate HEAD history. The witness manifest at HEAD
				// is therefore the permanent CAS preservation root for both the
				// canonical Packages paths and their byte-identical flat aliases.
				// Historical copies do not extend retention; contract validation
				// before GC proves the current witness/ref pair is immutable.
				if historyIndex != 0 {
					continue
				}
				addErr = addLocalServingGenerationRoots(canonical, commit, canonicalPath, roots)
			case strings.HasPrefix(canonicalPath, "views/"), strings.HasPrefix(canonicalPath, "snapshots/"):
				addErr = addViewRoot(canonical, commit, canonicalPath, roots)
			case isRemoteSourceManifest(canonicalPath):
				// A zero-byte remote adoption may baseline legacy serving files
				// before they have a CAS projection. Preserve any source object
				// that is already in CAS, but do not manufacture a missing CAS
				// reference merely because the remote source baseline names it.
				addErr = addAdoptedManifestRoots(canonical, commit, canonicalPath, pool, roots)
			case strings.HasPrefix(canonicalPath, "manifests/") && strings.HasSuffix(canonicalPath, ".tsv"):
				addErr = addAdoptedManifestRoots(canonical, commit, canonicalPath, pool, roots)
			case strings.HasPrefix(canonicalPath, "provenance/deb/") || strings.HasPrefix(canonicalPath, "provenance/rpm/"):
				if strings.HasSuffix(canonicalPath, ".json") {
					addErr = addProvenanceRoot(canonical, commit, canonicalPath, roots)
				}
			case strings.HasPrefix(canonicalPath, "provenance/legacy/") && strings.HasSuffix(canonicalPath, ".jsonl"):
				addErr = addLegacyProvenanceRoots(canonical, commit, canonicalPath, roots)
			case strings.HasPrefix(canonicalPath, "provenance/legacy-pruned/") && strings.HasSuffix(canonicalPath, ".jsonl"):
				addErr = validateLegacyIndexPruneLedger(canonical, commit, canonicalPath)
			case serving.IsGenerationManifestStatePath(canonicalPath):
				// Previous pins in current target channels are the explicit,
				// bounded YUM rollback window. A generation ledger removed from
				// HEAD must not remain a CAS root merely because the Git commit
				// that used to contain it is inside CASHistoryCommits.
				if historyIndex != 0 {
					continue
				}
				addErr = addLocalServingGenerationRoots(canonical, commit, canonicalPath, roots)
			default:
				continue
			}
			if addErr != nil {
				return nil, files, fmt.Errorf("%s at %s: %w", canonicalPath, commit, addErr)
			}
			files++
		}
	}
	// Compatibility state has two immutable preservation roots independent of
	// bounded aggregate HEAD history: yum-source pins S1 source.tsv and yum pins
	// the S2 exact candidate/payload manifests.  Enumerating the refs directly
	// prevents GC from collecting adopted RPMs before freeze or signed metadata
	// after the freeze commit ages out of the configured history window.
	refFiles, err := addYUMCompatibilityRefCASRoots(canonical, roots)
	if err != nil {
		return nil, files, err
	}
	files += refFiles
	return roots, files, nil
}

func addYUMCompatibilityRefCASRoots(canonical *state.Store, roots *repository.ReferenceSet) (int64, error) {
	refs, err := canonical.SOWRefs()
	if err != nil {
		return 0, err
	}
	var files int64
	for _, ref := range refs {
		name := ref.Name.String()
		var canonicalPaths []string
		switch {
		case strings.HasPrefix(name, "refs/sow/compatibility/yum-source/"):
			id := strings.TrimPrefix(name, "refs/sow/compatibility/yum-source/")
			if id == "" || strings.Contains(id, "/") {
				return files, fmt.Errorf("invalid YUM compatibility source ref %s", name)
			}
			sourcePath, pathErr := state.YUMCompatibilitySourcePath(id)
			if pathErr != nil {
				return files, pathErr
			}
			canonicalPaths = []string{sourcePath}
		case strings.HasPrefix(name, "refs/sow/compatibility/yum/"):
			id := strings.TrimPrefix(name, "refs/sow/compatibility/yum/")
			if id == "" || strings.Contains(id, "/") {
				return files, fmt.Errorf("invalid YUM compatibility freeze ref %s", name)
			}
			payloadPath, pathErr := state.YUMCompatibilityManifestPath(id)
			if pathErr != nil {
				return files, pathErr
			}
			candidatePath, pathErr := state.YUMCompatibilityCandidateManifestPath(id)
			if pathErr != nil {
				return files, pathErr
			}
			canonicalPaths = []string{payloadPath, candidatePath}
			receiptPath, pathErr := state.YUMCompatibilityCandidateReceiptPath(id)
			if pathErr != nil {
				return files, pathErr
			}
			frozen, frozenErr := loadYUMCompatibilityFrozenStateAt(canonical, ref.Hash, id)
			if frozenErr != nil {
				return files, fmt.Errorf("validate content-bound frozen YUM compatibility receipt %s at %s: %w", receiptPath, ref.Hash, frozenErr)
			}
			receipt := frozen.Receipt
			packageDigest, parseErr := repository.ParseDigest(receipt.PackageTrustSHA256)
			if parseErr != nil {
				return files, fmt.Errorf("%s package trust: %w", receiptPath, parseErr)
			}
			repositoryDigest, parseErr := repository.ParseDigest(receipt.RepositoryTrustSHA256)
			if parseErr != nil {
				return files, fmt.Errorf("%s repository trust: %w", receiptPath, parseErr)
			}
			if addErr := roots.Add(repository.Object{SHA256: packageDigest, Size: receipt.PackageTrustSize}); addErr != nil {
				return files, fmt.Errorf("%s package trust: %w", receiptPath, addErr)
			}
			if addErr := roots.Add(repository.Object{SHA256: repositoryDigest, Size: receipt.RepositoryTrustSize}); addErr != nil {
				return files, fmt.Errorf("%s repository trust: %w", receiptPath, addErr)
			}
			// The receipt is one canonical preservation-root file which names two
			// independent public trust objects.
			files++
		default:
			continue
		}
		for _, canonicalPath := range canonicalPaths {
			if err := addLocalServingGenerationRoots(canonical, ref.Hash, canonicalPath, roots); err != nil {
				return files, fmt.Errorf("%s at %s: %w", canonicalPath, ref.Hash, err)
			}
			files++
		}
	}
	return files, nil
}

func isCurrentYUMCompatibilityManifest(canonicalPath string) bool {
	parts := strings.Split(canonicalPath, "/")
	return len(parts) == 4 && parts[0] == "compatibility" && parts[1] == "yum" && parts[2] != "" && parts[3] == "manifest.tsv"
}

func addLocalServingGenerationRoots(canonical *state.Store, commit plumbing.Hash, canonicalPath string, roots *repository.ReferenceSet) error {
	reader, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return err
	}
	addErr := roots.AddManifest(reader)
	return errors.Join(addErr, reader.Close())
}

func addLegacyProvenanceRoots(canonical *state.Store, commit plumbing.Hash, canonicalPath string, roots *repository.ReferenceSet) error {
	expectedRepo, err := canonicalProvenanceLedgerRepo(canonicalPath, "provenance/legacy/")
	if err != nil {
		return err
	}
	reader, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	ledger := provenance.NewLegacyAdoptionReader(reader)
	for {
		receipt, err := ledger.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if receipt.Repo != expectedRepo {
			return fmt.Errorf("legacy adoption repo %q differs from canonical ledger repo %q", receipt.Repo, expectedRepo)
		}
		digest, err := repository.ParseDigest(receipt.ArtifactSHA256)
		if err != nil {
			return err
		}
		if err := roots.Add(repository.Object{SHA256: digest, Size: receipt.ArtifactSize}); err != nil {
			return err
		}
	}
}

func validateLegacyIndexPruneLedger(canonical *state.Store, commit plumbing.Hash, canonicalPath string) error {
	expectedRepo, err := canonicalProvenanceLedgerRepo(canonicalPath, "provenance/legacy-pruned/")
	if err != nil {
		return err
	}
	reader, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	ledger := provenance.NewLegacyIndexPruneReader(reader)
	for {
		receipt, err := ledger.Next()
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		if receipt.Repo != expectedRepo {
			return fmt.Errorf("legacy prune repo %q differs from canonical ledger repo %q", receipt.Repo, expectedRepo)
		}
	}
}

func canonicalProvenanceLedgerRepo(canonicalPath, prefix string) (string, error) {
	if !strings.HasPrefix(canonicalPath, prefix) || !strings.HasSuffix(canonicalPath, ".jsonl") {
		return "", fmt.Errorf("canonical provenance ledger path %q has the wrong namespace", canonicalPath)
	}
	repo := strings.TrimSuffix(strings.TrimPrefix(canonicalPath, prefix), ".jsonl")
	if repo == "" || strings.Contains(repo, "/") {
		return "", fmt.Errorf("canonical provenance ledger path %q does not identify one repo", canonicalPath)
	}
	return repo, nil
}

func isRemoteSourceManifest(canonicalPath string) bool {
	parts := strings.Split(canonicalPath, "/")
	return len(parts) == 3 && parts[0] == "remotes" && parts[1] != "" && parts[2] == "content.tsv"
}

func addViewRoot(canonical *state.Store, commit plumbing.Hash, canonicalPath string, roots *repository.ReferenceSet) error {
	reader, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	stream := views.NewReader(reader)
	for {
		entry, err := stream.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		digest, err := repository.ParseDigest(entry.SHA256)
		if err != nil {
			return err
		}
		if err := roots.Add(repository.Object{SHA256: digest, Size: entry.Size}); err != nil {
			return err
		}
	}
}

func addAdoptedManifestRoots(canonical *state.Store, commit plumbing.Hash, canonicalPath string, pool *repository.Store, roots *repository.ReferenceSet) error {
	reader, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	stream := manifest.NewReader(reader)
	for {
		entry, err := stream.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		digest := repository.Digest(entry.SHA256)
		file, err := pool.Open(digest)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || closeErr != nil {
			return errors.Join(statErr, closeErr)
		}
		if info.Size() != entry.Size {
			return fmt.Errorf("adopted CAS object %s has size %d, expected %d", digest, info.Size(), entry.Size)
		}
		if err := roots.Add(repository.Object{SHA256: digest, Size: entry.Size}); err != nil {
			return err
		}
	}
}

func addProvenanceRoot(canonical *state.Store, commit plumbing.Hash, canonicalPath string, roots *repository.ReferenceSet) error {
	reader, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, maxSecretBytes+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(data) > maxSecretBytes {
		return errors.Join(readErr, closeErr, errors.New("provenance receipt exceeds size limit"))
	}
	receipt, err := provenance.Decode(data)
	if err != nil {
		return err
	}
	expectedPath := path.Join("provenance", receipt.Format, receipt.ArtifactSHA256+".json")
	if canonicalPath != expectedPath {
		return fmt.Errorf("canonical provenance path %q differs from receipt identity %q", canonicalPath, expectedPath)
	}
	digest, err := repository.ParseDigest(receipt.ArtifactSHA256)
	if err != nil {
		return err
	}
	return roots.Add(repository.Object{SHA256: digest, Size: receipt.ArtifactSize})
}
