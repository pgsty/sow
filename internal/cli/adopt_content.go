package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/catalog"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/upstream"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
	_ "modernc.org/sqlite"
	debianversion "pault.ag/go/debian/version"
)

type legacyAdoptionResult struct {
	Commit                   plumbing.Hash
	Changed                  bool
	Payloads                 int64
	Bytes                    int64
	PeakImportWorkers        int64
	Leaves                   int
	Receipts                 int64
	CacheEntries             int64
	YUMMetadataSignature     string
	YUMMetadataKeyringSHA256 string
	PrunedMissingYUM         int64
}

// legacyMetadataTrust is an optional one-operation trust snapshot. Legacy
// adoption never infers metadata trust from the new repository signing key:
// an existing tree may be unsigned, or signed by an unrelated historical
// identity. A caller must explicitly supply a public-only keyring to make and
// enforce a metadata-signature claim.
type legacyMetadataTrust struct {
	keyring openpgp.EntityList
	sha256  string
}

// legacyAdoptionAfterPrunePreflightHook is a test-only seam for proving that a
// reviewed missing-body set cannot change between the two index parses. It is
// nil in every production invocation.
var legacyAdoptionAfterPrunePreflightHook func() error

// legacyAdoptionAfterMembershipPreflightHook is a test-only seam for proving
// that every ordinary APT/YUM candidate parsed during preflight must be
// re-observed byte-for-byte during import. It is nil in production.
var legacyAdoptionAfterMembershipPreflightHook func() error

// legacyAdoptionBeforeFinalTreeVerificationHook is a test-only seam. The
// production path performs one final selected-tree rescan at the transaction's
// filesystem observation boundary; tests use this hook to prove observed late
// drift fails before Apply. An uncooperative external writer is excluded by the
// mandatory migration writer-freeze contract; the SOW state lock alone cannot
// lock arbitrary legacy processes.
var legacyAdoptionBeforeFinalTreeVerificationHook func() error

type legacyLeaf struct {
	repo config.Repo
	os   string
	arch string
}

type legacyCandidate struct {
	repo     config.Repo
	format   string
	os       string
	leafArch string
	// logical is the byte-for-byte source path proved by the baseline and the
	// legacy index. canonical is the path committed to the SOW view. They differ
	// only for the approved Pigsty-v1 flat-YUM migration.
	logical           string
	canonical         string
	location          string
	canonicalLocation string
	name              string
	version           string
	packageArch       string
	size              int64
	sha256            string
	pool              string
	debug             bool
	expected          manifest.Entry
	blocker           *legacyAdoptionBlocker
}

type legacyMissingIndexedMode uint8

const (
	legacyMissingIndexedReject legacyMissingIndexedMode = iota
	legacyMissingIndexedRecord
	legacyMissingIndexedSkip
)

const legacyAdoptionBlockerPreviewLimit = 20

// legacyAdoptionBlocker is deliberately line-oriented and complete. Migration
// operators need an exact recovery inventory; reporting only the first missing
// body makes a large legacy tree converge one package per retry and encourages
// unsafe guess/ignore workarounds.
type legacyAdoptionBlocker struct {
	kind    string
	repo    string
	path    string
	name    string
	version string
	arch    string
	size    int64
	sha256  string
}

func writeLegacyAdoptionBlocker(output io.Writer, blocker legacyAdoptionBlocker) {
	fmt.Fprintf(output, "\nlegacy-adoption-blocker kind=%s repo=%s path=%s size=%d sha256=%s",
		blocker.kind, blocker.repo, blocker.path, blocker.size, blocker.sha256)
	if blocker.name != "" {
		fmt.Fprintf(output, " name=%s version=%s arch=%s", blocker.name, blocker.version, blocker.arch)
	}
}

// legacyAdoptionBlockerReport is a bounded in-memory summary of an exact
// disk-backed report. Error rendering must stay O(1) with respect to the
// blocker population: large negative inventories are common precisely when a
// legacy tree is incomplete.
type legacyAdoptionBlockerReport struct {
	Count   int64
	SHA256  string
	Path    string
	Preview []legacyAdoptionBlocker
}

func (r legacyAdoptionBlockerReport) asError(summary string) error {
	var output strings.Builder
	fmt.Fprintf(&output, "%s; exact blocker report count=%d sha256=%s path=%s", summary, r.Count, r.SHA256, r.Path)
	for _, blocker := range r.Preview {
		writeLegacyAdoptionBlocker(&output, blocker)
	}
	if omitted := r.Count - int64(len(r.Preview)); omitted > 0 {
		fmt.Fprintf(&output, "\nlegacy-adoption-blocker omitted=%d see=%s", omitted, r.Path)
	}
	return errors.New(output.String())
}

type legacyImported struct {
	candidate     legacyCandidate
	entry         views.Entry
	format        string
	sourcePath    string
	canonicalPath string
	expected      manifest.Entry
	err           error
}

// adoptLegacyContent runs only after runInit has committed the exact serving
// tree baseline while the init state lock remains held. Every deterministic
// admission rule is checked transaction-wide before package bytes can enter
// CAS. A later I/O interruption may leave only content-addressed, GC-visible
// orphans and never partial refs.
func adoptLegacyContent(ctx context.Context, cfg *config.Config, canonical *state.Store, repos []config.Repo, viewNames []string, txDir string, metadataTrust legacyMetadataTrust, pruneMissingYUMConfirm string, values commonFlags, stdout io.Writer) (legacyAdoptionResult, error) {
	result := legacyAdoptionResult{YUMMetadataSignature: "not-applicable", YUMMetadataKeyringSHA256: "-"}
	if len(repos) == 0 {
		return result, errors.New("legacy adoption matched no repositories")
	}
	viewNames, err := validateLegacyAdoptionViews(cfg, viewNames)
	if err != nil {
		return result, err
	}
	stageDir := filepath.Join(txDir, "adopt-content")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		return result, err
	}
	spool, err := newLegacyAdoptionSpool(filepath.Join(stageDir, "adoption.db"))
	if err != nil {
		return result, err
	}
	defer spool.Close()
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return result, err
	}
	for _, repo := range repos {
		if repo.Type != "yum" {
			continue
		}
		result.YUMMetadataSignature = "not-claimed"
		if metadataTrust.keyring != nil {
			result.YUMMetadataSignature = "verified"
			result.YUMMetadataKeyringSHA256 = metadataTrust.sha256
		}
		break
	}

	baselineCommits := make(map[string]plumbing.Hash, len(repos))
	baselineTimes := make(map[string]time.Time, len(repos))
	leaves := make([]legacyLeaf, 0)
	for _, repo := range repos {
		ref, err := state.RepoRef(repo.ID)
		if err != nil {
			return result, err
		}
		commit, exists, err := canonical.Ref(ref)
		if err != nil || !exists {
			return result, errors.Join(err, fmt.Errorf("repo %s has no baseline ref; run sow init first", repo.ID))
		}
		manifestPath := filepath.ToSlash(filepath.Join("manifests", repo.ID+".tsv"))
		baseline, err := canonical.OpenPathAt(commit, manifestPath)
		if err != nil {
			return result, fmt.Errorf("open baseline for %s: %w", repo.ID, err)
		}
		original, configured := cfg.RepoByName(repo.ID)
		if !configured {
			_ = baseline.Close()
			return result, fmt.Errorf("repo %s disappeared from canonical configuration", repo.ID)
		}
		seedErr := spool.seedBaseline(repo.ID, baseline, func(entry manifest.Entry) bool {
			return legacyAdoptionBaselineSelected(original, repo, entry.Path)
		})
		closeErr := baseline.Close()
		if seedErr != nil || closeErr != nil {
			return result, errors.Join(seedErr, closeErr)
		}
		commitTime, err := canonical.CommitTime(commit)
		if err != nil {
			return result, err
		}
		baselineCommits[repo.ID] = commit
		baselineTimes[repo.ID] = commitTime.UTC()
		leaves = append(leaves, legacyRepoLeaves(repo)...)
	}
	// Confidentiality admission is transaction-wide and must precede every CAS
	// object write. In particular, a public view selected alongside a gated
	// repository must not import objects from an earlier public repository before
	// the gated leaf is rejected.
	if err := preflightLegacyAdoptionViewAdmission(cfg, viewNames, leaves); err != nil {
		return result, err
	}
	// Admission is transaction-wide: reject every non-routable legacy asset
	// path across all selected repositories before any worker can write CAS.
	for _, repo := range repos {
		if repo.Type != "asset" {
			continue
		}
		if err := validateLegacyAssetBaseline(ctx, spool, repo); err != nil {
			return result, fmt.Errorf("adopt repo %s: %w", repo.ID, err)
		}
		if err := validateLegacyAssetTaintBaseline(ctx, canonical, pool, spool, repo); err != nil {
			return result, fmt.Errorf("adopt repo %s archive confidentiality: %w", repo.ID, err)
		}
	}
	// Package admission is transaction-wide and precedes every CAS write. Parse
	// all selected indexes once to prove that every package-shaped baseline
	// path is a member. A late orphan in one repository must not leave imported
	// objects from repositories visited earlier in the same command.
	var membershipErrors []error
	for _, repo := range repos {
		if repo.Type != "apt" && repo.Type != "yum" {
			continue
		}
		original, configured := cfg.RepoByName(repo.ID)
		if !configured {
			membershipErrors = append(membershipErrors, fmt.Errorf("repo %s disappeared from canonical configuration", repo.ID))
			continue
		}
		partialAPT := repo.Type == "apt" && !repoSelectionIsFull(original, repo)
		if partialAPT {
			// APT package bodies live in one repository-global pool. A narrowed
			// suite/arch import must still audit that pool against every configured
			// Packages index; otherwise a body omitted by every leaf can evade all
			// sequential partial invocations forever.
			fullProducer := legacyCandidateProducer(cfg, spool, original, metadataTrust.keyring, legacyMissingIndexedRecord)
			if err := spool.auditIndexed(ctx, repo.ID, fullProducer); err != nil {
				membershipErrors = append(membershipErrors, fmt.Errorf("audit complete APT index membership for repo %s: %w", repo.ID, err))
				continue
			}
		}
		// Missing indexed bodies are persisted in the disk-backed spool even on
		// the default reject path. This keeps a pathological negative inventory
		// out of Go heap while retaining an exact, reviewable report and digest.
		producer := legacyCandidateProducer(cfg, spool, repo, metadataTrust.keyring, legacyMissingIndexedRecord)
		if err := spool.admitIndexed(ctx, repo.ID, producer); err != nil {
			membershipErrors = append(membershipErrors, fmt.Errorf("preflight legacy index membership for repo %s: %w", repo.ID, err))
			continue
		}
		if err := spool.recordEveryUnindexedPackage(repo.ID, repo.Type, partialAPT); err != nil {
			membershipErrors = append(membershipErrors, err)
		}
	}
	if len(membershipErrors) != 0 {
		return result, errors.Join(membershipErrors...)
	}
	unindexedCount, err := spool.blockerCount("body-without-index", false)
	if err != nil {
		return result, err
	}
	missingCount, err := spool.blockerCount("indexed-body-missing", false)
	if err != nil {
		return result, err
	}
	if unindexedCount != 0 || missingCount != 0 && pruneMissingYUMConfirm == "" {
		report, err := spool.writeBlockerReport(cfg.StatePath())
		if err != nil {
			return result, fmt.Errorf("write legacy adoption blocker report: %w", err)
		}
		var summaries []string
		if unindexedCount != 0 {
			summaries = append(summaries, fmt.Sprintf("selected repositories contain %d package(s) that no repository index proves; adoption refuses to guess membership", unindexedCount))
		}
		if missingCount != 0 && pruneMissingYUMConfirm == "" {
			confirmation, err := spool.legacyIndexPruneDigest()
			if err != nil {
				return result, fmt.Errorf("derive missing-indexed YUM blocker confirmation: %w", err)
			}
			summaries = append(summaries, fmt.Sprintf("selected YUM primary metadata references %d package body/bodies absent from the M0 baseline; adoption refuses to invent bytes; missing-indexed YUM blocker confirmation sha256=%s", missingCount, confirmation))
		}
		return result, report.asError(strings.Join(summaries, "; "))
	}
	if pruneMissingYUMConfirm != "" {
		if missingCount == 0 {
			return result, errors.New("--adopt-prune-missing-yum-confirm was supplied but the selected indexes have no missing YUM bodies")
		}
		actual, err := spool.legacyIndexPruneDigest()
		if err != nil {
			return result, fmt.Errorf("derive missing-indexed YUM blocker confirmation: %w", err)
		}
		if actual != pruneMissingYUMConfirm {
			return result, fmt.Errorf("missing-indexed YUM blocker set changed: sha256=%s, confirmation=%s", actual, pruneMissingYUMConfirm)
		}
		fmt.Fprintf(stdout, "adopt-content prune-missing-yum confirmed_sha256=%s entries=%d serving_tree_rewritten=false\n", actual, missingCount)
		if legacyAdoptionAfterPrunePreflightHook != nil {
			if err := legacyAdoptionAfterPrunePreflightHook(); err != nil {
				return result, fmt.Errorf("legacy missing-index prune preflight hook: %w", err)
			}
		}
	}
	if legacyAdoptionAfterMembershipPreflightHook != nil {
		if err := legacyAdoptionAfterMembershipPreflightHook(); err != nil {
			return result, fmt.Errorf("legacy adoption membership preflight hook: %w", err)
		}
	}

	importMissingMode := legacyMissingIndexedReject
	if pruneMissingYUMConfirm != "" {
		importMissingMode = legacyMissingIndexedSkip
	}
	for _, repo := range repos {
		producer := legacyCandidateProducer(cfg, spool, repo, metadataTrust.keyring, importMissingMode)
		reobserve := repo.Type == "apt" || repo.Type == "yum"
		stats, err := importLegacyCandidates(ctx, pool, spool, producer, values.workers, reobserve)
		if err != nil {
			return result, fmt.Errorf("adopt repo %s: %w", repo.ID, err)
		}
		if repo.Type == "apt" || repo.Type == "yum" {
			if err := spool.requireEveryCandidateReobserved(repo.ID); err != nil {
				return result, err
			}
		}
		result.Payloads += stats.Payloads
		result.Bytes += stats.Bytes
		if stats.PeakWorkers > result.PeakImportWorkers {
			result.PeakImportWorkers = stats.PeakWorkers
		}
		frozenSuites, lifecycleLeaves := repoLifecycleCounts(repo)
		metadataSignature := "not-applicable"
		if repo.Type == "apt" {
			metadataSignature = "not-claimed"
		} else if repo.Type == "yum" {
			metadataSignature = result.YUMMetadataSignature
		}
		fmt.Fprintf(stdout, "adopt-content scanned repo=%s type=%s payloads=%d bytes=%d peak_import_workers=%d pool=%s frozen=%t frozen_leaves=%d/%d metadata_signature=%s\n",
			repo.ID, repo.Type, stats.Payloads, stats.Bytes, stats.PeakWorkers, repo.DefaultPool, lifecycleLeaves > 0 && frozenSuites == lifecycleLeaves, frozenSuites, lifecycleLeaves, metadataSignature)
	}
	if pruneMissingYUMConfirm != "" {
		if err := spool.requireEveryPrunedYUMBlockerReobserved(); err != nil {
			return result, err
		}
	}

	staged := make(map[string]string)
	updates := make([]state.RefUpdate, 0, len(leaves)*len(viewNames))
	for _, viewName := range viewNames {
		for _, leaf := range leaves {
			canonicalPath, err := state.ViewPath(viewName, leaf.repo.ID, leaf.os, leaf.arch)
			if err != nil {
				return result, err
			}
			ref, err := state.ViewRef(viewName, leaf.repo.ID, leaf.os, leaf.arch)
			if err != nil {
				return result, err
			}
			expected, exists, err := canonical.Ref(ref)
			if err != nil {
				return result, err
			}
			generated := filepath.Join(stageDir, fmt.Sprintf("generated-%s-%s-%s-%s.tsv", viewName, leaf.repo.ID, leaf.os, leaf.arch))
			if err := spool.writeView(leaf.repo.ID, leaf.os, leaf.arch, generated, cfg.Views[viewName].DebugInfo == "keep"); err != nil {
				return result, err
			}
			stagePath := generated
			if exists {
				existingPath, err := state.ViewPath(viewName, leaf.repo.ID, leaf.os, leaf.arch)
				if err != nil {
					return result, err
				}
				existing, err := canonical.OpenPathAt(expected, existingPath)
				if err != nil {
					return result, err
				}
				generatedReader, openErr := os.Open(generated)
				if openErr != nil {
					existing.Close()
					return result, openErr
				}
				merged, createErr := os.CreateTemp(stageDir, viewName+"-adoption-union-*.tsv")
				if createErr != nil {
					existing.Close()
					generatedReader.Close()
					return result, createErr
				}
				_, promoteErr := views.Promote(existing, generatedReader, merged, views.Selector{}, cfg.Views[viewName].Access == "public")
				closeErr := errors.Join(existing.Close(), generatedReader.Close(), merged.Sync(), merged.Close())
				if promoteErr != nil || closeErr != nil {
					return result, errors.Join(promoteErr, closeErr)
				}
				stagePath = merged.Name()
			}
			check, err := os.Open(stagePath)
			if err != nil {
				return result, err
			}
			var validateEntry func(views.Entry) error
			if leaf.repo.Type == "asset" {
				validateEntry = func(entry views.Entry) error { return validateAssetProjectionPath(leaf.repo, entry.Path) }
			}
			_, validateErr := views.ValidateLeafEntries(check, leaf.repo.ID, leaf.os, leaf.arch, cfg.Views[viewName].Access == "public", validateEntry)
			closeErr := check.Close()
			if validateErr != nil || closeErr != nil {
				return result, errors.Join(validateErr, closeErr)
			}
			staged[canonicalPath] = stagePath
			updates = append(updates, state.RefUpdate{Name: ref, Expected: expected})
			result.Leaves++
		}
	}

	for _, repo := range repos {
		anchorRepo, configured := cfg.RepoByName(repo.ID)
		if !configured {
			return result, fmt.Errorf("repo %s disappeared from canonical configuration", repo.ID)
		}
		ledgerPath := filepath.Join(stageDir, "legacy-"+repo.ID+".jsonl")
		currentLedgerPath := filepath.Join(stageDir, "legacy-current-"+repo.ID+".jsonl")
		canonicalLedger := path.Join("provenance", "legacy", repo.ID+".jsonl")
		_, err := spool.writeLegacyLedger(repo.ID, repo.DefaultPool, baselineCommits[repo.ID], baselineTimes[repo.ID], currentLedgerPath)
		if err != nil {
			return result, err
		}
		existing, exists, err := openOptionalCanonical(canonical, canonicalLedger)
		if err != nil {
			return result, err
		}
		count := int64(0)
		if exists {
			current, openErr := os.Open(currentLedgerPath)
			if openErr != nil {
				_ = existing.Close()
				return result, openErr
			}
			count, err = mergeLegacyAdoptionLedgers(canonical, spool, anchorRepo, baselineCommits[repo.ID], existing, current, ledgerPath)
			closeErr := errors.Join(existing.Close(), current.Close())
			if err != nil || closeErr != nil {
				return result, errors.Join(err, closeErr)
			}
		} else {
			if err := os.Rename(currentLedgerPath, ledgerPath); err != nil {
				return result, err
			}
			count, err = spool.payloadCount(repo.ID)
			if err != nil {
				return result, err
			}
		}
		staged[canonicalLedger] = ledgerPath
		result.Receipts += count
	}
	if pruneMissingYUMConfirm != "" {
		for _, repo := range repos {
			if repo.Type != "yum" {
				continue
			}
			ledgerPath := filepath.Join(stageDir, "legacy-pruned-"+repo.ID+".jsonl")
			canonicalLedger := path.Join("provenance", "legacy-pruned", repo.ID+".jsonl")
			existing, exists, err := openOptionalCanonical(canonical, canonicalLedger)
			if err != nil {
				return result, err
			}
			count := int64(0)
			if exists {
				matches, existingCount, matchErr := spool.matchesLegacyIndexPruneLedger(repo.ID, pruneMissingYUMConfirm, existing)
				closeErr := existing.Close()
				if matchErr != nil || closeErr != nil {
					return result, errors.Join(matchErr, closeErr)
				}
				if !matches {
					return result, fmt.Errorf("legacy missing-index prune ledger for repo %s conflicts with canonical history", repo.ID)
				}
				_, copied, err := stageOptionalCanonicalFile(canonical, canonicalLedger, ledgerPath)
				if err != nil || !copied {
					return result, errors.Join(err, errors.New("legacy missing-index prune ledger disappeared while staging"))
				}
				count = existingCount
			} else {
				count, err = spool.writeLegacyIndexPruneLedger(repo.ID, baselineCommits[repo.ID], baselineTimes[repo.ID], pruneMissingYUMConfirm, ledgerPath)
				if err != nil {
					return result, err
				}
			}
			if count == 0 {
				_ = os.Remove(ledgerPath)
				continue
			}
			staged[canonicalLedger] = ledgerPath
			result.PrunedMissingYUM += count
		}
	}
	if legacyAdoptionBeforeFinalTreeVerificationHook != nil {
		if err := legacyAdoptionBeforeFinalTreeVerificationHook(); err != nil {
			return result, fmt.Errorf("legacy adoption final tree verification hook: %w", err)
		}
	}
	if err := verifyLegacyServingBaselines(ctx, cfg, canonical, repos, baselineCommits, stageDir, values); err != nil {
		return result, err
	}
	canonicalConfig, _, err := stageCanonicalConfig(cfg, stageDir)
	if err != nil {
		return result, err
	}
	staged["config/sow.yaml"] = canonicalConfig
	commit, changed, err := applyCanonicalConfig(ctx, cfg, canonical, "init-adopt-content", "sow init: adopt legacy content into "+strings.Join(viewNames, ","), staged, updates, state.ApplyOptions{})
	if err != nil {
		return result, stateMutationError("commit adopted legacy content", err)
	}
	result.Commit, result.Changed = commit, changed
	result.CacheEntries, err = catalog.Count(cfg.StatePath())
	if err != nil {
		return result, withExitCode(ExitInternal, "verify SQLite cache after legacy adoption: %v", err)
	}
	return result, nil
}

func verifyLegacyServingBaselines(ctx context.Context, cfg *config.Config, canonical *state.Store, repos []config.Repo, baselineCommits map[string]plumbing.Hash, stageDir string, values commonFlags) error {
	// This is the final read-side linearization check after all candidate/body
	// work. Migration requires old writers to remain revoked for the operation;
	// without that external exclusion no portable macOS/Linux directory scanner
	// can make a multi-file tree immutable merely by reading it.
	verificationDir := filepath.Join(stageDir, "final-serving-verification")
	if err := os.Mkdir(verificationDir, 0o700); err != nil {
		return err
	}
	for _, repo := range repos {
		selectedPath := filepath.Join(verificationDir, repo.ID+".selected.tsv")
		if _, err := scanRepoManifest(ctx, cfg, repo, selectedPath, manifest.ScanOptions{
			Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp"),
		}); err != nil {
			return fmt.Errorf("rescan legacy serving tree for repo %s: %w", repo.ID, err)
		}
		currentPath := filepath.Join(verificationDir, repo.ID+".current.tsv")
		if err := stageRepoManifestUpdate(cfg, canonical, repo, selectedPath, currentPath, filepath.Join(cfg.StatePath(), "tmp")); err != nil {
			return fmt.Errorf("reconstruct final legacy serving baseline for repo %s: %w", repo.ID, err)
		}
		manifestPath := filepath.ToSlash(filepath.Join("manifests", repo.ID+".tsv"))
		baseline, err := canonical.OpenPathAt(baselineCommits[repo.ID], manifestPath)
		if err != nil {
			return err
		}
		current, err := os.Open(currentPath)
		if err != nil {
			_ = baseline.Close()
			return err
		}
		diff, diffErr := manifest.Diff(baseline, current, nil)
		closeErr := errors.Join(baseline.Close(), current.Close())
		if diffErr != nil || closeErr != nil {
			return errors.Join(diffErr, closeErr)
		}
		if !diff.Clean() {
			return fmt.Errorf("legacy serving tree changed during adoption for repo %s: added=%d removed=%d changed=%d", repo.ID, diff.Added, diff.Removed, diff.Changed)
		}
	}
	return nil
}

func legacyCandidateProducer(cfg *config.Config, spool *legacyAdoptionSpool, repo config.Repo, metadataKeyring openpgp.EntityList, missingMode legacyMissingIndexedMode) func(context.Context, func(legacyCandidate) error) error {
	return func(ctx context.Context, emit func(legacyCandidate) error) error {
		switch repo.Type {
		case "apt":
			return produceLegacyAPT(ctx, cfg, spool, repo, emit)
		case "yum":
			return produceLegacyYUM(ctx, cfg, spool, repo, metadataKeyring, missingMode, emit)
		case "asset":
			return produceLegacyAssets(ctx, spool, repo, emit)
		default:
			return fmt.Errorf("unsupported legacy repo type %q", repo.Type)
		}
	}
}

func repoLifecycleCounts(repo config.Repo) (frozen, total int) {
	switch repo.Type {
	case "apt":
		if repo.APT == nil {
			return 0, 0
		}
		for _, suite := range repo.APT.Suites {
			total++
			if repo.LifecycleForSuite(suite) == "frozen" {
				frozen++
			}
		}
	case "yum":
		total = 1
		if repo.OS.Lifecycle == "frozen" {
			frozen = 1
		}
	}
	return frozen, total
}

// legacyAdoptionBaselineSelected marks the serving bytes that a narrowed
// adoption is responsible for proving. APT pool bytes are repository-global,
// so a partial suite/arch selection may import only bodies named by its chosen
// Packages indexes; treating every shared pool file as selected would falsely
// reject packages belonging solely to an unselected leaf. Full selections and
// YUM's arch-partitioned roots retain the strict unindexed-body check.
func legacyAdoptionBaselineSelected(original, selected config.Repo, manifestPath string) bool {
	if repoSelectionIsFull(original, selected) {
		return true
	}
	if original.Type == "apt" && (strings.HasSuffix(manifestPath, ".deb") || strings.HasSuffix(manifestPath, ".ddeb")) {
		return false
	}
	return repoSelectionContains(original, selected, manifestPath)
}

func validateLegacyAdoptionViews(cfg *config.Config, selected []string) ([]string, error) {
	if len(selected) == 0 {
		selected = []string{"latest"}
	}
	selected = uniqueSorted(selected)
	for _, name := range selected {
		if name != "latest" && name != "stable" {
			return nil, withExitCode(ExitUsage, "init --adopt-content supports only latest and stable views; got %q", name)
		}
		if _, exists := cfg.Views[name]; !exists {
			return nil, withExitCode(ExitConfig, "adoption view %s is not configured", name)
		}
	}
	return selected, nil
}

func preflightLegacyAdoptionViewAdmission(cfg *config.Config, viewNames []string, leaves []legacyLeaf) error {
	for _, viewName := range viewNames {
		view, exists := cfg.Views[viewName]
		if !exists {
			return fmt.Errorf("adoption view %s is not configured", viewName)
		}
		for _, leaf := range leaves {
			if !viewIncludesRepo(view, leaf.repo.ID) {
				return fmt.Errorf("view %s excludes selected repo %s", viewName, leaf.repo.ID)
			}
			if !contains(view.AllowedPools, leaf.repo.DefaultPool) || view.Access == "public" && leaf.repo.DefaultPool != "public" {
				return fmt.Errorf("confidentiality closure violation: repo %s default_pool %s cannot enter view %s", leaf.repo.ID, leaf.repo.DefaultPool, viewName)
			}
		}
	}
	return nil
}

func prepareLegacyMetadataTrust(cfg *config.Config, repos []config.Repo, keyringPath string) (legacyMetadataTrust, error) {
	var trust legacyMetadataTrust
	if keyringPath == "" {
		return trust, nil
	}
	hasYUM := false
	for _, repo := range repos {
		if repo.Type == "yum" {
			hasYUM = true
			break
		}
	}
	if !hasYUM {
		return trust, withExitCode(ExitUsage, "init --legacy-metadata-keyring requires at least one selected YUM repository")
	}
	keyring, digest, err := loadPublicOnlyKeyring(cfg.Path, keyringPath, "legacy metadata")
	if err != nil {
		return trust, withExitCode(ExitConfig, "load legacy metadata keyring: %v", err)
	}
	trust.keyring = keyring
	trust.sha256 = digest
	return trust, nil
}

func legacyRepoLeaves(repo config.Repo) []legacyLeaf {
	var result []legacyLeaf
	switch repo.Type {
	case "asset":
		result = append(result, legacyLeaf{repo: repo, os: "all", arch: "all"})
	case "apt":
		for _, suite := range repo.APT.Suites {
			for _, arch := range repo.Arches {
				result = append(result, legacyLeaf{repo: repo, os: suite, arch: arch})
			}
		}
	case "yum":
		for _, arch := range repo.Arches {
			result = append(result, legacyLeaf{repo: repo, os: "el" + fmt.Sprint(repo.OS.Major), arch: arch})
		}
	}
	return result
}

func produceLegacyAPT(ctx context.Context, cfg *config.Config, spool *legacyAdoptionSpool, repo config.Repo, emit func(legacyCandidate) error) error {
	root := filepath.Join(cfg.Root, filepath.FromSlash(repo.Path))
	for _, suite := range repo.APT.Suites {
		for _, component := range repo.APT.ComponentsForSuite(suite) {
			for _, arch := range repo.Arches {
				base := filepath.Join(root, "dists", suite, component, "binary-"+arch, "Packages")
				index, err := selectLegacyAPTIndex(base)
				if err != nil {
					return fmt.Errorf("APT repo %s lacks a usable Packages index for %s/%s/%s: %w", repo.ID, suite, component, arch, err)
				}
				err = upstream.ParseLocalAPTIndex(ctx, index, upstream.Limits{}, func(pkg upstream.LocalPackage) error {
					if pkg.Arch != arch && pkg.Arch != "all" {
						return fmt.Errorf("APT package %s architecture %s is indexed by binary-%s", pkg.Name, pkg.Arch, arch)
					}
					if !strings.HasPrefix(pkg.Location, "pool/"+component+"/") {
						return fmt.Errorf("APT package %s location %q crosses component %s", pkg.Name, pkg.Location, component)
					}
					logical, err := legacyLogicalPath(repo.Path, pkg.Location)
					if err != nil {
						return err
					}
					expected, err := spool.baseline(repo.ID, logical)
					if err != nil {
						return fmt.Errorf("APT index references untracked path %s: %w", logical, err)
					}
					if expected.Size != pkg.Size || expected.HashString() != pkg.SHA256 {
						return fmt.Errorf("APT index checksum/size differs from baseline at %s", logical)
					}
					return emit(legacyCandidate{repo: repo, format: "deb", os: suite, leafArch: arch, logical: logical, canonical: logical, location: pkg.Location, canonicalLocation: pkg.Location, name: pkg.Name, version: pkg.Version, packageArch: pkg.Arch, size: pkg.Size, sha256: pkg.SHA256, pool: repo.DefaultPool, debug: pkg.DebugInfo, expected: expected})
				})
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func selectLegacyAPTIndex(base string) (string, error) {
	for _, suffix := range []string{"", ".zst", ".zstd", ".xz", ".gz"} {
		candidate := base + suffix
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("Packages index is a symlink or non-regular file")
		}
		return candidate, nil
	}
	return "", os.ErrNotExist
}

func produceLegacyYUM(ctx context.Context, cfg *config.Config, spool *legacyAdoptionSpool, repo config.Repo, keyring openpgp.EntityList, missingMode legacyMissingIndexedMode, emit func(legacyCandidate) error) error {
	var verifier openpgp.KeyRing
	if len(keyring) != 0 {
		verifier = keyring
	}
	for _, arch := range repo.Arches {
		effectiveRoot, err := repo.PathForArch(arch)
		if err != nil {
			return err
		}
		root := filepath.Join(cfg.Root, filepath.FromSlash(effectiveRoot))
		err = upstream.ParseLocalYUMRepository(ctx, root, upstream.Limits{}, verifier, func(pkg upstream.LocalPackage) error {
			targetArch, err := legacyRPMTargetArch(repo, arch, pkg.Arch)
			if err != nil {
				return fmt.Errorf("YUM package %s architecture %s is indexed by %s", pkg.Name, pkg.Arch, arch)
			}
			canonicalLocation, err := canonicalLegacyYUMLocation(pkg.Name, pkg.Location)
			if err != nil {
				return err
			}
			logical, err := legacyLogicalPath(effectiveRoot, pkg.Location)
			if err != nil {
				return err
			}
			expected, err := spool.baseline(repo.ID, logical)
			if errors.Is(err, sql.ErrNoRows) {
				blocker := legacyAdoptionBlocker{
					kind: "indexed-body-missing", repo: repo.ID, path: logical,
					name: pkg.Name, version: pkg.Version, arch: pkg.Arch,
					size: pkg.Size, sha256: pkg.SHA256,
				}
				switch missingMode {
				case legacyMissingIndexedReject:
					return fmt.Errorf("YUM primary references package body absent from the M0 baseline: repo=%s path=%s", blocker.repo, blocker.path)
				case legacyMissingIndexedRecord:
					return emit(legacyCandidate{repo: repo, blocker: &blocker})
				case legacyMissingIndexedSkip:
					return emit(legacyCandidate{repo: repo, blocker: &blocker})
				default:
					return errors.New("invalid missing-indexed YUM adoption mode")
				}
			}
			if err != nil {
				return fmt.Errorf("YUM primary references untracked path %s: %w", logical, err)
			}
			if expected.Size != pkg.Size || expected.HashString() != pkg.SHA256 {
				return fmt.Errorf("YUM primary checksum/size differs from baseline at %s", logical)
			}
			canonicalRoot, err := repo.PathForArch(targetArch)
			if err != nil {
				return err
			}
			canonical, err := legacyLogicalPath(canonicalRoot, canonicalLocation)
			if err != nil {
				return err
			}
			return emit(legacyCandidate{repo: repo, format: "rpm", os: "el" + fmt.Sprint(repo.OS.Major), leafArch: targetArch, logical: logical, canonical: canonical, location: pkg.Location, canonicalLocation: canonicalLocation, name: pkg.Name, version: pkg.Version, packageArch: pkg.Arch, size: pkg.Size, sha256: pkg.SHA256, pool: repo.DefaultPool, debug: pkg.DebugInfo, expected: expected})
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func canonicalLegacyYUMLocation(name, location string) (string, error) {
	if err := validateLegacyRoutePath(location); err != nil || !strings.HasSuffix(location, ".rpm") {
		return "", fmt.Errorf("YUM package %s has unsafe location %q", name, location)
	}
	basename := path.Base(location)
	want, err := yumrepo.PackageLocation(name, basename)
	if err != nil {
		return "", fmt.Errorf("YUM package %s has unsafe location %q: %w", name, location, err)
	}
	if strings.HasPrefix(location, "Packages/") && location != want {
		return "", fmt.Errorf("YUM package %s has malformed canonical location %q", name, location)
	}
	// The source path is preserved in the legacy receipt. Any normalized,
	// index-proven relative RPM href may migrate to the one frozen SOW layout;
	// transaction-wide admission rejects two distinct bytes that collapse onto
	// the same canonical destination before CAS is touched.
	return want, nil
}

func legacyRPMTargetArch(repo config.Repo, sourceArch, packageArch string) (string, error) {
	// Some legacy binary leaves intentionally carried source RPM entries. Keep
	// their leaf membership during adoption without widening the ordinary
	// add/sync routing contract for new source packages.
	if packageArch == "src" && sourceArch != "noarch" && contains(repo.Arches, sourceArch) {
		return sourceArch, nil
	}
	if repo.YUM != nil && repo.YUM.NoarchMode == config.YUMNoarchSeparate {
		if packageArch == "noarch" && contains(repo.Arches, "noarch") {
			return "noarch", nil
		}
		if sourceArch != "noarch" && packageArch == sourceArch {
			return sourceArch, nil
		}
		return "", errors.New("legacy package architecture does not map to the separate-noarch target")
	}
	if !rpmLeafAcceptsPackageArch(repo, sourceArch, packageArch) {
		return "", errors.New("legacy package architecture does not map to the target leaf")
	}
	return sourceArch, nil
}

func produceLegacyAssets(ctx context.Context, spool *legacyAdoptionSpool, repo config.Repo, emit func(legacyCandidate) error) error {
	// Validate the complete baseline before emitting any work. The importer is
	// concurrent, so per-entry validation in the emitting pass could otherwise
	// import an earlier valid object before a later unsafe URL path is noticed.
	if err := validateLegacyAssetBaseline(ctx, spool, repo); err != nil {
		return err
	}
	return spool.forEachBaseline(ctx, repo.ID, func(expected manifest.Entry) error {
		location := strings.TrimPrefix(expected.Path, strings.TrimSuffix(repo.Path, "/")+"/")
		return emit(legacyCandidate{repo: repo, format: "asset", os: "all", leafArch: "all", logical: expected.Path, canonical: expected.Path, location: location, canonicalLocation: location, name: path.Base(expected.Path), version: expected.HashString()[:16], packageArch: "all", size: expected.Size, sha256: expected.HashString(), pool: repo.DefaultPool, expected: expected})
	})
}

func validateLegacyAssetBaseline(ctx context.Context, spool *legacyAdoptionSpool, repo config.Repo) error {
	return spool.forEachBaseline(ctx, repo.ID, func(expected manifest.Entry) error {
		if err := validateLegacyRoutePath(expected.Path); err != nil {
			return fmt.Errorf("legacy asset path %q is not edge-routable: %w", expected.Path, err)
		}
		if err := validateAssetProjectionPath(repo, expected.Path); err != nil {
			return fmt.Errorf("legacy asset path %q violates its public projection: %w", expected.Path, err)
		}
		return nil
	})
}

// validateLegacyAssetTaintBaseline closes the whole selected asset baseline
// before any concurrent importer can mutate CAS. Digest receipts make
// copy/rename/hardlink aliases equivalent, while the gzip marker carries Pro
// policy across repositories that do not yet have the originating receipt.
func validateLegacyAssetTaintBaseline(ctx context.Context, canonical *state.Store, pool *repository.Store, spool *legacyAdoptionSpool, repo config.Repo) error {
	if canonical == nil || pool == nil {
		return errors.New("legacy asset taint admission is unavailable")
	}
	return spool.forEachBaseline(ctx, repo.ID, func(expected manifest.Entry) error {
		receipt, err := requireOfflineArchiveTaintAdmission(canonical, repo, expected.HashString(), expected.Size)
		if err != nil {
			return fmt.Errorf("legacy asset %q digest taint admission: %w", expected.Path, err)
		}
		physical, err := regularLegacyPath(pool.Root(), expected.Path)
		if err != nil {
			return fmt.Errorf("legacy asset %q physical path: %w", expected.Path, err)
		}
		inspected, err := inspectOfflineArchiveInputContext(ctx, physical)
		if err != nil {
			return fmt.Errorf("legacy asset %q archive inspection: %w", expected.Path, err)
		}
		if inspected.Object.HashString() != expected.HashString() || inspected.Object.Size != expected.Size {
			return fmt.Errorf("legacy asset %s changed from its transaction baseline", expected.Path)
		}
		if err := requireOfflineArchiveMarkerAdmission(inspected.Marker, repo, receipt, nil); err != nil {
			return fmt.Errorf("legacy asset %q marker admission: %w", expected.Path, err)
		}
		return nil
	})
}

type legacyImportStats struct {
	Payloads int64
	Bytes    int64
	// PeakWorkers records workers concurrently executing the complete
	// inspect-and-CAS-import operation. It is observed from the production
	// worker pool rather than inferred from the requested worker count.
	PeakWorkers int64
}

func importLegacyCandidates(ctx context.Context, pool *repository.Store, spool *legacyAdoptionSpool, produce func(context.Context, func(legacyCandidate) error) error, workers int, reobserve bool) (legacyImportStats, error) {
	var stats legacyImportStats
	if workers < 1 {
		workers = 1
	}
	if workers > 64 {
		workers = 64
	}
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan legacyCandidate, workers*2)
	results := make(chan legacyImported, workers*2)
	producerErr := make(chan error, 1)
	// Keep the complete disk-backed result projection in one transaction. CAS
	// inspection remains concurrent, but payload collision checks no longer pay
	// one SQLite autocommit/WAL sync per package. Candidate re-observation runs
	// under the same transaction immediately before body inspection, preserving
	// the fail-before-CAS boundary for a changed second index parse.
	spool.writeMu.Lock()
	tx, err := spool.db.BeginTx(workerCtx, nil)
	if err != nil {
		spool.writeMu.Unlock()
		return stats, err
	}
	var txMu sync.Mutex
	go func() {
		defer close(jobs)
		producerErr <- produce(workerCtx, func(candidate legacyCandidate) error {
			select {
			case jobs <- candidate:
				return nil
			case <-workerCtx.Done():
				return workerCtx.Err()
			}
		})
	}()
	var group sync.WaitGroup
	var activeWorkers atomic.Int64
	var peakWorkers atomic.Int64
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for candidate := range jobs {
				current := activeWorkers.Add(1)
				for observed := peakWorkers.Load(); current > observed; observed = peakWorkers.Load() {
					if peakWorkers.CompareAndSwap(observed, current) {
						break
					}
				}
				var imported legacyImported
				if reobserve {
					txMu.Lock()
					err := markCandidateReobservedTx(tx, candidate)
					txMu.Unlock()
					if err != nil {
						imported = legacyImported{candidate: candidate, err: err}
					} else {
						imported = inspectAndImportLegacy(workerCtx, pool, candidate)
					}
				} else {
					imported = inspectAndImportLegacy(workerCtx, pool, candidate)
				}
				activeWorkers.Add(-1)
				select {
				case results <- imported:
				case <-workerCtx.Done():
					return
				}
				if imported.err != nil {
					cancel()
					return
				}
			}
		}()
	}
	go func() {
		group.Wait()
		close(results)
	}()
	var firstErr error
	for imported := range results {
		if imported.err != nil {
			if firstErr == nil {
				firstErr = imported.err
				cancel()
			}
			continue
		}
		if firstErr != nil {
			continue
		}
		if imported.candidate.blocker != nil {
			if !reobserve {
				firstErr = errors.New("legacy blocker reached a non-package import stream")
				cancel()
			}
			continue
		}
		txMu.Lock()
		added, err := addImportedTx(tx, imported)
		txMu.Unlock()
		if err != nil {
			firstErr = err
			cancel()
			continue
		}
		if added {
			stats.Payloads++
			stats.Bytes += imported.expected.Size
		}
	}
	if err := <-producerErr; err != nil && !errors.Is(err, context.Canceled) && firstErr == nil {
		firstErr = err
	}
	if firstErr != nil {
		_ = tx.Rollback()
		spool.writeMu.Unlock()
		stats.PeakWorkers = peakWorkers.Load()
		return stats, firstErr
	}
	if err := tx.Commit(); err != nil {
		spool.writeMu.Unlock()
		stats.PeakWorkers = peakWorkers.Load()
		return stats, err
	}
	spool.writeMu.Unlock()
	stats.PeakWorkers = peakWorkers.Load()
	return stats, ctx.Err()
}

func inspectAndImportLegacy(ctx context.Context, pool *repository.Store, candidate legacyCandidate) legacyImported {
	result := legacyImported{candidate: candidate}
	if candidate.blocker != nil {
		return result
	}
	canonical := candidate.canonical
	if canonical == "" {
		canonical = candidate.logical
	}
	canonicalLocation := candidate.canonicalLocation
	if canonicalLocation == "" {
		canonicalLocation = candidate.location
	}
	result.format, result.sourcePath, result.canonicalPath, result.expected = candidate.format, candidate.logical, canonical, candidate.expected
	full, err := regularLegacyPath(pool.Root(), candidate.logical)
	if err != nil {
		result.err = err
		return result
	}
	name, version, packageArch, debug := candidate.name, candidate.version, candidate.packageArch, candidate.debug
	switch candidate.format {
	case "deb":
		component, err := aptComponentFromPoolPath(candidate.location)
		if err != nil {
			result.err = err
			return result
		}
		pkg, err := aptrepo.InspectPackage(ctx, full, component)
		if err != nil {
			result.err = err
			return result
		}
		if pkg.Name != candidate.name || !sameLegacyDebianVersion(pkg.Version, candidate.version) || pkg.Architecture != candidate.packageArch || pkg.PoolPath != candidate.location || pkg.Size != candidate.size || pkg.SHA256 != candidate.sha256 || pkg.Architecture != "all" && pkg.Architecture != candidate.leafArch {
			result.err = fmt.Errorf("DEB body identity differs from Packages at %s: index=%s/%s/%s body=%s/%s/%s", candidate.logical, candidate.name, candidate.version, candidate.packageArch, pkg.Name, pkg.Version, pkg.Architecture)
			return result
		}
		name, version, packageArch = pkg.Name, pkg.Version, pkg.Architecture
	case "rpm":
		pkg, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: full, Basename: path.Base(candidate.location)})
		if err != nil {
			result.err = err
			return result
		}
		bodyVersion := pkg.Version + "-" + pkg.Release
		if pkg.Epoch > 0 {
			bodyVersion = fmt.Sprintf("%d:%s", pkg.Epoch, bodyVersion)
		}
		targetArch, targetErr := legacyRPMTargetArch(candidate.repo, candidate.leafArch, pkg.Arch)
		if pkg.Name != candidate.name || bodyVersion != candidate.version || pkg.Arch != candidate.packageArch || pkg.Location != canonicalLocation || pkg.Size != candidate.size || pkg.SHA256 != candidate.sha256 || targetErr != nil || targetArch != candidate.leafArch {
			result.err = fmt.Errorf("RPM body identity differs from primary at %s: index=%s/%s/%s location=%s body=%s/%s/%s location=%s", candidate.logical, candidate.name, candidate.version, candidate.packageArch, canonicalLocation, pkg.Name, bodyVersion, pkg.Arch, pkg.Location)
			return result
		}
		name, version, packageArch, debug = pkg.Name, bodyVersion, pkg.Arch, isDebugRPM(pkg.Name)
	case "asset":
	default:
		result.err = fmt.Errorf("unsupported legacy format %q", candidate.format)
		return result
	}
	digest, err := repository.ParseDigest(candidate.expected.HashString())
	if err != nil {
		result.err = err
		return result
	}
	object, err := pool.ImportExpected(ctx, full, repository.Object{SHA256: digest, Size: candidate.expected.Size})
	if err != nil {
		result.err = err
		return result
	}
	if object.Size != candidate.expected.Size || object.HashString() != candidate.expected.HashString() {
		result.err = fmt.Errorf("legacy source changed after baseline at %s", candidate.logical)
		return result
	}
	_ = packageArch
	result.entry = views.Entry{Repo: candidate.repo.ID, OS: candidate.os, Arch: candidate.leafArch, Name: name, Version: version, Path: canonical, Size: object.Size, SHA256: object.HashString(), Pool: candidate.pool, DebugInfo: debug}
	return result
}

func sameLegacyDebianVersion(left, right string) bool {
	leftVersion, leftErr := debianversion.Parse(left)
	rightVersion, rightErr := debianversion.Parse(right)
	return leftErr == nil && rightErr == nil && debianversion.Compare(leftVersion, rightVersion) == 0
}

func regularLegacyPath(root, logical string) (string, error) {
	if err := validateLegacyRoutePath(logical); err != nil {
		return "", fmt.Errorf("unsafe legacy source path %q", logical)
	}
	full := filepath.Join(root, filepath.FromSlash(logical))
	info, err := os.Lstat(full)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.Join(err, fmt.Errorf("legacy source %s is absent, symlinked, or non-regular", logical))
	}
	return full, nil
}

func legacyLogicalPath(repoRoot, relative string) (string, error) {
	if err := validateLegacyRoutePath(relative); err != nil {
		return "", fmt.Errorf("unsafe indexed package location %q", relative)
	}
	logical := path.Join(repoRoot, relative)
	prefix := strings.TrimSuffix(repoRoot, "/") + "/"
	if !strings.HasPrefix(logical, prefix) {
		return "", fmt.Errorf("indexed package location %q escapes repo %s", relative, repoRoot)
	}
	if err := validateLegacyRoutePath(logical); err != nil {
		return "", fmt.Errorf("indexed package location %q is not edge-routable: %w", relative, err)
	}
	return logical, nil
}

func validateLegacyRoutePath(value string) error {
	if value == "" || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\%?#\x00\t\r\n") || path.Clean(value) != value || value == ".." || strings.HasPrefix(value, "../") {
		return errors.New("must be a normalized relative URL path")
	}
	for _, segment := range strings.Split(value, "/") {
		if err := config.ValidateRouteSegment(segment); err != nil {
			return fmt.Errorf("segment %q: %w", segment, err)
		}
	}
	return nil
}

type legacyAdoptionSpool struct {
	db      *sql.DB
	path    string
	writeMu sync.Mutex
}

const legacyAdoptionBusyTimeoutMS = 5000

func newLegacyAdoptionSpool(filename string) (*legacyAdoptionSpool, error) {
	// busy_timeout is connection-local. Put it in the DSN so database/sql
	// applies it to every lazily opened reader/writer connection, not merely to
	// whichever connection happens to create the schema.
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(filename)}
	query := dsn.Query()
	query.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", legacyAdoptionBusyTimeoutMS))
	dsn.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	if _, err := db.Exec(`
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE baseline(repo TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, selected INTEGER NOT NULL CHECK(selected IN (0,1)), PRIMARY KEY(repo,path)) WITHOUT ROWID;
CREATE TABLE indexed(repo TEXT NOT NULL, path TEXT NOT NULL, canonical_path TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(repo,path)) WITHOUT ROWID;
CREATE INDEX indexed_canonical_path ON indexed(repo,canonical_path);
CREATE TABLE audit_indexed(repo TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(repo,path)) WITHOUT ROWID;
CREATE TABLE admitted(repo TEXT NOT NULL, identity TEXT NOT NULL, kind TEXT NOT NULL, path TEXT NOT NULL, seen INTEGER NOT NULL DEFAULT 0 CHECK(seen IN (0,1)), PRIMARY KEY(repo,identity)) WITHOUT ROWID;
CREATE TABLE blocker(kind TEXT NOT NULL, repo TEXT NOT NULL, path TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, arch TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, seen INTEGER NOT NULL DEFAULT 0 CHECK(seen IN (0,1)), PRIMARY KEY(kind,repo,path)) WITHOUT ROWID;
CREATE TABLE payload(repo TEXT NOT NULL, source_path TEXT NOT NULL, canonical_path TEXT NOT NULL, format TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, pool TEXT NOT NULL, PRIMARY KEY(repo,source_path)) WITHOUT ROWID;
CREATE INDEX payload_canonical_path ON payload(repo,canonical_path);
CREATE TABLE entry(repo TEXT NOT NULL, os TEXT NOT NULL, arch TEXT NOT NULL, path TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, pool TEXT NOT NULL, debug INTEGER NOT NULL, PRIMARY KEY(repo,os,arch,path)) WITHOUT ROWID;
CREATE TABLE anchor(commit_sha TEXT NOT NULL, repo TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(commit_sha,repo,path)) WITHOUT ROWID;
CREATE TABLE anchor_loaded(commit_sha TEXT NOT NULL, repo TEXT NOT NULL, PRIMARY KEY(commit_sha,repo)) WITHOUT ROWID;
`); err != nil {
		db.Close()
		return nil, err
	}
	return &legacyAdoptionSpool{db: db, path: filename}, nil
}

func (s *legacyAdoptionSpool) admitIndexed(ctx context.Context, repo string, produce func(context.Context, func(legacyCandidate) error) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err = produce(ctx, func(candidate legacyCandidate) error {
		return markIndexedTx(tx, repo, candidate)
	}); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *legacyAdoptionSpool) auditIndexed(ctx context.Context, repo string, produce func(context.Context, func(legacyCandidate) error) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err = produce(ctx, func(candidate legacyCandidate) error {
		if candidate.blocker != nil || candidate.repo.ID != repo || candidate.format != "deb" || candidate.logical == "" {
			return errors.New("complete APT membership audit emitted an invalid candidate")
		}
		var size int64
		var digest string
		if err := tx.QueryRow(`SELECT size,sha256 FROM baseline WHERE repo=? AND path=?`, repo, candidate.logical).Scan(&size, &digest); err != nil {
			return fmt.Errorf("APT index references path outside complete baseline %s: %w", candidate.logical, err)
		}
		if size != candidate.expected.Size || digest != candidate.expected.HashString() {
			return fmt.Errorf("APT complete index identity differs from baseline at %s", candidate.logical)
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO audit_indexed(repo,path,size,sha256) VALUES(?,?,?,?)`, repo, candidate.logical, size, digest); err != nil {
			return err
		}
		var recordedSize int64
		var recordedDigest string
		if err := tx.QueryRow(`SELECT size,sha256 FROM audit_indexed WHERE repo=? AND path=?`, repo, candidate.logical).Scan(&recordedSize, &recordedDigest); err != nil {
			return err
		}
		if recordedSize != size || recordedDigest != digest {
			return fmt.Errorf("conflicting complete APT index membership at %s", candidate.logical)
		}
		return nil
	}); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func markIndexedTx(tx *sql.Tx, repo string, candidate legacyCandidate) error {
	if candidate.blocker != nil {
		blocker := *candidate.blocker
		if blocker.kind != "indexed-body-missing" || blocker.repo != repo || blocker.path == "" || blocker.size <= 0 || len(blocker.sha256) != 64 {
			return errors.New("invalid missing-indexed YUM blocker")
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO blocker(kind,repo,path,name,version,arch,size,sha256) VALUES(?,?,?,?,?,?,?,?)`,
			blocker.kind, blocker.repo, blocker.path, blocker.name, blocker.version, blocker.arch, blocker.size, blocker.sha256); err != nil {
			return err
		}
		var name, version, arch, sha string
		var size int64
		if err := tx.QueryRow(`SELECT name,version,arch,size,sha256 FROM blocker WHERE kind=? AND repo=? AND path=?`, blocker.kind, blocker.repo, blocker.path).Scan(&name, &version, &arch, &size, &sha); err != nil {
			return err
		}
		if name != blocker.name || version != blocker.version || arch != blocker.arch || size != blocker.size || sha != blocker.sha256 {
			return fmt.Errorf("conflicting missing-indexed YUM identity at %s", blocker.path)
		}
		return recordAdmittedCandidateTx(tx, repo, candidate)
	}
	var baselineSize int64
	var baselineSHA string
	err := tx.QueryRow(`SELECT size,sha256 FROM baseline WHERE repo=? AND path=?`, repo, candidate.logical).Scan(&baselineSize, &baselineSHA)
	if err != nil {
		return fmt.Errorf("index references path outside baseline %s: %w", candidate.logical, err)
	}
	if baselineSize != candidate.expected.Size || baselineSHA != candidate.expected.HashString() {
		return fmt.Errorf("index candidate identity differs from baseline at %s", candidate.logical)
	}
	var priorSource, priorSHA string
	var priorSize int64
	err = tx.QueryRow(`SELECT path,size,sha256 FROM indexed WHERE repo=? AND canonical_path=? ORDER BY path LIMIT 1`, repo, candidate.canonical).Scan(&priorSource, &priorSize, &priorSHA)
	if err == nil && (priorSize != baselineSize || priorSHA != baselineSHA) {
		return fmt.Errorf("conflicting legacy canonical destination %s from %s and %s", candidate.canonical, priorSource, candidate.logical)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err = tx.Exec(`INSERT OR IGNORE INTO indexed(repo,path,canonical_path,size,sha256) VALUES(?,?,?,?,?)`, repo, candidate.logical, candidate.canonical, baselineSize, baselineSHA); err != nil {
		return err
	}
	var canonicalPath, sha string
	var size int64
	if err = tx.QueryRow(`SELECT canonical_path,size,sha256 FROM indexed WHERE repo=? AND path=?`, repo, candidate.logical).Scan(&canonicalPath, &size, &sha); err != nil {
		return err
	}
	if canonicalPath != candidate.canonical || size != baselineSize || sha != baselineSHA {
		return fmt.Errorf("conflicting index membership for legacy source %s", candidate.logical)
	}
	return recordAdmittedCandidateTx(tx, repo, candidate)
}

func legacyCandidateIdentity(candidate legacyCandidate) (identity, kind, candidatePath string, err error) {
	if candidate.blocker != nil {
		blocker := *candidate.blocker
		body, encodeErr := json.Marshal(struct {
			Kind, Repo, Path, Name, Version, Arch, SHA256 string
			Size                                          int64
		}{blocker.kind, blocker.repo, blocker.path, blocker.name, blocker.version, blocker.arch, blocker.sha256, blocker.size})
		if encodeErr != nil {
			return "", "", "", encodeErr
		}
		digest := sha256.Sum256(body)
		return hex.EncodeToString(digest[:]), blocker.kind, blocker.path, nil
	}
	body, encodeErr := json.Marshal(struct {
		Repo, Format, OS, LeafArch, Logical, Canonical, Location, CanonicalLocation string
		Name, Version, PackageArch, SHA256, Pool, ExpectedSHA256                    string
		Size, ExpectedSize                                                          int64
		Debug                                                                       bool
	}{
		candidate.repo.ID, candidate.format, candidate.os, candidate.leafArch, candidate.logical, candidate.canonical,
		candidate.location, candidate.canonicalLocation, candidate.name, candidate.version, candidate.packageArch,
		candidate.sha256, candidate.pool, candidate.expected.HashString(), candidate.size, candidate.expected.Size, candidate.debug,
	})
	if encodeErr != nil {
		return "", "", "", encodeErr
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), candidate.format, candidate.logical, nil
}

func recordAdmittedCandidateTx(tx *sql.Tx, repo string, candidate legacyCandidate) error {
	identity, kind, candidatePath, err := legacyCandidateIdentity(candidate)
	if err != nil {
		return err
	}
	if repo == "" || candidate.repo.ID != repo {
		return errors.New("legacy candidate repository identity is inconsistent")
	}
	_, err = tx.Exec(`INSERT OR IGNORE INTO admitted(repo,identity,kind,path) VALUES(?,?,?,?)`, repo, identity, kind, candidatePath)
	return err
}

func markCandidateReobservedTx(tx *sql.Tx, candidate legacyCandidate) error {
	identity, kind, candidatePath, err := legacyCandidateIdentity(candidate)
	if err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE admitted SET seen=1 WHERE repo=? AND identity=? AND kind=? AND path=?`, candidate.repo.ID, identity, kind, candidatePath)
	if err != nil {
		return err
	}
	matched, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if matched != 1 {
		return fmt.Errorf("legacy index candidate set changed at repo=%s kind=%s path=%s", candidate.repo.ID, kind, candidatePath)
	}
	if candidate.blocker != nil {
		blocker := *candidate.blocker
		result, err = tx.Exec(`UPDATE blocker SET seen=1 WHERE kind=? AND repo=? AND path=? AND name=? AND version=? AND arch=? AND size=? AND sha256=?`,
			blocker.kind, blocker.repo, blocker.path, blocker.name, blocker.version, blocker.arch, blocker.size, blocker.sha256)
		if err != nil {
			return err
		}
		matched, err = result.RowsAffected()
		if err != nil || matched != 1 {
			return errors.Join(err, fmt.Errorf("confirmed missing-indexed YUM identity changed at %s", blocker.path))
		}
	}
	return nil
}

func (s *legacyAdoptionSpool) requireEveryCandidateReobserved(repo string) error {
	var kind, candidatePath string
	err := s.db.QueryRow(`SELECT kind,path FROM admitted WHERE repo=? AND seen=0 ORDER BY kind,path LIMIT 1`, repo).Scan(&kind, &candidatePath)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("legacy index candidate disappeared during adoption repo=%s kind=%s path=%s", repo, kind, candidatePath)
}

func (s *legacyAdoptionSpool) blockerCount(kind string, unseenOnly bool) (int64, error) {
	query := `SELECT count(*) FROM blocker`
	var arguments []any
	if kind != "" {
		query += ` WHERE kind=?`
		arguments = append(arguments, kind)
		if unseenOnly {
			query += ` AND seen=0`
		}
	} else if unseenOnly {
		query += ` WHERE seen=0`
	}
	var count int64
	err := s.db.QueryRow(query, arguments...).Scan(&count)
	return count, err
}

func (s *legacyAdoptionSpool) streamBlockers(kind string, unseenOnly bool, output io.Writer, previewLimit int) (int64, []legacyAdoptionBlocker, error) {
	query := `SELECT kind,repo,path,name,version,arch,size,sha256 FROM blocker`
	var arguments []any
	if kind != "" {
		query += ` WHERE kind=?`
		arguments = append(arguments, kind)
		if unseenOnly {
			query += ` AND seen=0`
		}
	} else if unseenOnly {
		query += ` WHERE seen=0`
	}
	query += ` ORDER BY repo,path,kind`
	rows, err := s.db.Query(query, arguments...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	preview := make([]legacyAdoptionBlocker, 0, previewLimit)
	var count int64
	for rows.Next() {
		var blocker legacyAdoptionBlocker
		if err := rows.Scan(&blocker.kind, &blocker.repo, &blocker.path, &blocker.name, &blocker.version, &blocker.arch, &blocker.size, &blocker.sha256); err != nil {
			return count, preview, err
		}
		if output != nil {
			if _, err := fmt.Fprintf(output, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
				blocker.kind, blocker.repo, blocker.path, blocker.size, blocker.sha256, blocker.name, blocker.version, blocker.arch); err != nil {
				return count, preview, err
			}
		}
		if len(preview) < previewLimit {
			preview = append(preview, blocker)
		}
		count++
	}
	return count, preview, rows.Err()
}

func (s *legacyAdoptionSpool) writeBlockerReport(stateDir string) (legacyAdoptionBlockerReport, error) {
	var report legacyAdoptionBlockerReport
	hash := sha256.New()
	count, preview, err := s.streamBlockers("", false, hash, legacyAdoptionBlockerPreviewLimit)
	if err != nil {
		return report, err
	}
	if count == 0 {
		return report, errors.New("cannot write an empty legacy adoption blocker report")
	}
	report.Count = count
	report.Preview = preview
	report.SHA256 = hex.EncodeToString(hash.Sum(nil))
	relative := path.Join("reports", "legacy-adoption-blockers-"+report.SHA256+".tsv")
	report.Path = filepath.Join(stateDir, filepath.FromSlash(relative))

	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return legacyAdoptionBlockerReport{}, err
	}
	defer root.Close()
	if err := root.Mkdir("reports", 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return legacyAdoptionBlockerReport{}, err
	}
	info, err := root.Lstat("reports")
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return legacyAdoptionBlockerReport{}, errors.Join(err, errors.New("legacy adoption report directory is symlinked or non-directory"))
	}
	file, err := root.OpenFile(relative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		existing, openErr := root.Open(relative)
		if openErr != nil {
			return legacyAdoptionBlockerReport{}, openErr
		}
		existingHash := sha256.New()
		_, copyErr := io.Copy(existingHash, existing)
		closeErr := existing.Close()
		if copyErr != nil || closeErr != nil || hex.EncodeToString(existingHash.Sum(nil)) != report.SHA256 {
			return legacyAdoptionBlockerReport{}, errors.Join(copyErr, closeErr, errors.New("existing legacy adoption blocker report differs from its digest name"))
		}
		return report, nil
	}
	if err != nil {
		return legacyAdoptionBlockerReport{}, err
	}
	installed := false
	defer func() {
		_ = file.Close()
		if !installed {
			_ = root.Remove(relative)
		}
	}()
	writtenHash := sha256.New()
	writtenCount, _, streamErr := s.streamBlockers("", false, io.MultiWriter(file, writtenHash), 0)
	closeErr := errors.Join(file.Sync(), file.Close())
	if streamErr != nil || closeErr != nil || writtenCount != report.Count || hex.EncodeToString(writtenHash.Sum(nil)) != report.SHA256 {
		return legacyAdoptionBlockerReport{}, errors.Join(streamErr, closeErr, errors.New("legacy adoption blocker set changed while writing its report"))
	}
	reports, err := root.Open("reports")
	if err != nil {
		return legacyAdoptionBlockerReport{}, err
	}
	if err := errors.Join(reports.Sync(), reports.Close()); err != nil {
		return legacyAdoptionBlockerReport{}, err
	}
	installed = true
	return report, nil
}

func (s *legacyAdoptionSpool) legacyIndexPruneDigest() (string, error) {
	rows, err := s.db.Query(`SELECT repo,path,name,version,arch,size,sha256 FROM blocker WHERE kind='indexed-body-missing' ORDER BY repo,path`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	hash := sha256.New()
	var priorRepo, priorPath string
	for rows.Next() {
		var identity provenance.LegacyIndexPruneIdentity
		if err := rows.Scan(&identity.Repo, &identity.Path, &identity.Name, &identity.Version, &identity.Arch, &identity.ArtifactSize, &identity.ArtifactSHA256); err != nil {
			return "", err
		}
		if err := identity.Validate(); err != nil {
			return "", err
		}
		if identity.Repo == priorRepo && identity.Path == priorPath {
			return "", fmt.Errorf("duplicate legacy index prune coordinate %s/%s", identity.Repo, identity.Path)
		}
		fmt.Fprintf(hash, "indexed-body-missing\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			identity.Repo, identity.Path, identity.ArtifactSize, identity.ArtifactSHA256,
			identity.Name, identity.Version, identity.Arch)
		priorRepo, priorPath = identity.Repo, identity.Path
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *legacyAdoptionSpool) markPrunedYUMBlockerReobserved(blocker legacyAdoptionBlocker) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.db.Exec(`UPDATE blocker SET seen=1 WHERE kind=? AND repo=? AND path=? AND name=? AND version=? AND arch=? AND size=? AND sha256=?`,
		blocker.kind, blocker.repo, blocker.path, blocker.name, blocker.version, blocker.arch, blocker.size, blocker.sha256)
	if err != nil {
		return err
	}
	matched, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if matched != 1 {
		return fmt.Errorf("unreviewed missing body repo=%s path=%s size=%d sha256=%s", blocker.repo, blocker.path, blocker.size, blocker.sha256)
	}
	return nil
}

func (s *legacyAdoptionSpool) requireEveryPrunedYUMBlockerReobserved() error {
	count, blockers, err := s.streamBlockers("indexed-body-missing", true, nil, legacyAdoptionBlockerPreviewLimit)
	if err != nil || count == 0 {
		return err
	}
	var output strings.Builder
	fmt.Fprintf(&output, "confirmed missing-indexed YUM set changed during import; %d reviewed blocker(s) were not re-observed", count)
	for _, blocker := range blockers {
		writeLegacyAdoptionBlocker(&output, blocker)
	}
	if count > int64(len(blockers)) {
		fmt.Fprintf(&output, "\nlegacy-adoption-blocker omitted=%d", count-int64(len(blockers)))
	}
	return errors.New(output.String())
}

func (s *legacyAdoptionSpool) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return errors.Join(err, os.Remove(s.path), os.Remove(s.path+"-wal"), os.Remove(s.path+"-shm"))
}

func (s *legacyAdoptionSpool) seedBaseline(repo string, source io.Reader, selectors ...func(manifest.Entry) bool) error {
	if len(selectors) > 1 {
		return errors.New("legacy adoption baseline accepts at most one selector")
	}
	var selected func(manifest.Entry) bool
	if len(selectors) == 1 {
		selected = selectors[0]
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	statement, err := tx.Prepare(`INSERT INTO baseline(repo,path,size,sha256,selected) VALUES(?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	reader := manifest.NewReader(source)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			statement.Close()
			tx.Rollback()
			return err
		}
		isSelected := selected == nil || selected(entry)
		selectedValue := 0
		if isSelected {
			selectedValue = 1
		}
		if _, err := statement.Exec(repo, entry.Path, entry.Size, entry.HashString(), selectedValue); err != nil {
			statement.Close()
			tx.Rollback()
			return err
		}
	}
	if err := statement.Close(); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *legacyAdoptionSpool) baseline(repo, logical string) (manifest.Entry, error) {
	var size int64
	var sha string
	if err := s.db.QueryRow(`SELECT size,sha256 FROM baseline WHERE repo=? AND path=?`, repo, logical).Scan(&size, &sha); err != nil {
		return manifest.Entry{}, err
	}
	decoded, err := hex.DecodeString(sha)
	if err != nil || len(decoded) != 32 {
		return manifest.Entry{}, errors.New("baseline contains invalid SHA256")
	}
	entry := manifest.Entry{Path: logical, Size: size}
	copy(entry.SHA256[:], decoded)
	return entry, nil
}

func (s *legacyAdoptionSpool) forEachBaseline(ctx context.Context, repo string, fn func(manifest.Entry) error) error {
	rows, err := s.db.QueryContext(ctx, `SELECT path,size,sha256 FROM baseline WHERE repo=? AND selected=1 ORDER BY path`, repo)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var pathValue, sha string
		var size int64
		if err := rows.Scan(&pathValue, &size, &sha); err != nil {
			return err
		}
		decoded, err := hex.DecodeString(sha)
		if err != nil || len(decoded) != 32 {
			return errors.New("baseline contains invalid SHA256")
		}
		entry := manifest.Entry{Path: pathValue, Size: size}
		copy(entry.SHA256[:], decoded)
		if err := fn(entry); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *legacyAdoptionSpool) addImported(imported legacyImported) (bool, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	added, err := addImportedTx(tx, imported)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return added, nil
}

func addImportedTx(tx *sql.Tx, imported legacyImported) (bool, error) {
	if tx == nil || imported.candidate.blocker != nil {
		return false, errors.New("invalid legacy imported payload transaction")
	}
	entry := imported.entry
	var conflictingSource string
	var conflictingFormat, conflictingSHA, conflictingPool string
	var conflictingSize int64
	err := tx.QueryRow(`SELECT source_path,format,size,sha256,pool FROM payload WHERE repo=? AND canonical_path=? ORDER BY source_path LIMIT 1`, entry.Repo, imported.canonicalPath).Scan(&conflictingSource, &conflictingFormat, &conflictingSize, &conflictingSHA, &conflictingPool)
	if err == nil && (conflictingFormat != imported.format || conflictingSize != entry.Size || conflictingSHA != entry.SHA256 || conflictingPool != entry.Pool) {
		return false, fmt.Errorf("conflicting legacy canonical destination %s from %s and %s", imported.canonicalPath, conflictingSource, imported.sourcePath)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	result, err := tx.Exec(`INSERT OR IGNORE INTO payload(repo,source_path,canonical_path,format,size,sha256,pool) VALUES(?,?,?,?,?,?,?)`, entry.Repo, imported.sourcePath, imported.canonicalPath, imported.format, entry.Size, entry.SHA256, entry.Pool)
	if err != nil {
		return false, err
	}
	added, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	var canonicalPath, format, sha, pool string
	var size int64
	if err := tx.QueryRow(`SELECT canonical_path,format,size,sha256,pool FROM payload WHERE repo=? AND source_path=?`, entry.Repo, imported.sourcePath).Scan(&canonicalPath, &format, &size, &sha, &pool); err != nil {
		return false, err
	}
	if canonicalPath != imported.canonicalPath || format != imported.format || size != entry.Size || sha != entry.SHA256 || pool != entry.Pool {
		return false, fmt.Errorf("conflicting legacy payload identity at %s", imported.sourcePath)
	}
	debug := 0
	if entry.DebugInfo {
		debug = 1
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO entry(repo,os,arch,path,name,version,size,sha256,pool,debug) VALUES(?,?,?,?,?,?,?,?,?,?)`, entry.Repo, entry.OS, entry.Arch, entry.Path, entry.Name, entry.Version, entry.Size, entry.SHA256, entry.Pool, debug); err != nil {
		return false, err
	}
	var name, version, entrySHA, entryPool string
	var entrySize int64
	var entryDebug int
	if err := tx.QueryRow(`SELECT name,version,size,sha256,pool,debug FROM entry WHERE repo=? AND os=? AND arch=? AND path=?`, entry.Repo, entry.OS, entry.Arch, entry.Path).Scan(&name, &version, &entrySize, &entrySHA, &entryPool, &entryDebug); err != nil {
		return false, err
	}
	if name != entry.Name || version != entry.Version || entrySize != entry.Size || entrySHA != entry.SHA256 || entryPool != entry.Pool || entryDebug != debug {
		return false, fmt.Errorf("conflicting legacy package membership at %s", entry.Path)
	}
	return added != 0, nil
}

func (s *legacyAdoptionSpool) recordEveryUnindexedPackage(repo, repoType string, partialAPT bool) error {
	predicate := `b.path LIKE '%.deb' OR b.path LIKE '%.ddeb'`
	indexTable := "indexed"
	selection := "b.selected=1 AND "
	if partialAPT {
		indexTable = "audit_indexed"
		selection = ""
	}
	if repoType == "yum" {
		predicate = `b.path LIKE '%.rpm'`
	}
	query := `INSERT OR IGNORE INTO blocker(kind,repo,path,name,version,arch,size,sha256)
SELECT 'body-without-index',b.repo,b.path,'','','',b.size,b.sha256
FROM baseline b LEFT JOIN ` + indexTable + ` i ON i.repo=b.repo AND i.path=b.path
WHERE b.repo=? AND ` + selection + `(` + predicate + `) AND i.path IS NULL`
	_, err := s.db.Exec(query, repo)
	return err
}

func (s *legacyAdoptionSpool) writeView(repo, osName, arch, destination string, includeDebug bool) error {
	query := `SELECT name,version,path,size,sha256,pool,debug FROM entry WHERE repo=? AND os=? AND arch=?`
	if !includeDebug {
		query += ` AND debug=0`
	}
	query += ` ORDER BY path`
	rows, err := s.db.Query(query, repo, osName, arch)
	if err != nil {
		return err
	}
	defer rows.Close()
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		file.Close()
		if !committed {
			os.Remove(destination)
		}
	}()
	for rows.Next() {
		entry := views.Entry{Repo: repo, OS: osName, Arch: arch}
		var debug int
		if err := rows.Scan(&entry.Name, &entry.Version, &entry.Path, &entry.Size, &entry.SHA256, &entry.Pool, &debug); err != nil {
			return err
		}
		entry.DebugInfo = debug != 0
		if err := views.WriteEntry(file, entry); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *legacyAdoptionSpool) writeLegacyLedger(repo, pool string, commit plumbing.Hash, adoptedAt time.Time, destination string) (int64, error) {
	rows, err := s.db.Query(`SELECT source_path,canonical_path,format,size,sha256 FROM payload WHERE repo=? ORDER BY source_path`, repo)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		file.Close()
		if !committed {
			os.Remove(destination)
		}
	}()
	var count int64
	for rows.Next() {
		receipt := provenance.LegacyAdoptionReceipt{Schema: provenance.LegacyAdoptionSchema, Repo: repo, Pool: pool, AdoptedAt: adoptedAt, ConfigCommit: commit.String()}
		if err := rows.Scan(&receipt.SourcePath, &receipt.CanonicalPath, &receipt.Format, &receipt.ArtifactSize, &receipt.ArtifactSHA256); err != nil {
			return count, err
		}
		if err := provenance.WriteLegacyAdoption(file, receipt); err != nil {
			return count, err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return count, err
	}
	if err := file.Sync(); err != nil {
		return count, err
	}
	if err := file.Close(); err != nil {
		return count, err
	}
	committed = true
	return count, nil
}

func (s *legacyAdoptionSpool) writeLegacyIndexPruneLedger(repo string, commit plumbing.Hash, recordedAt time.Time, confirmation, destination string) (int64, error) {
	rows, err := s.db.Query(`SELECT path,name,version,arch,size,sha256 FROM blocker WHERE repo=? ORDER BY path`, repo)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		file.Close()
		if !committed {
			os.Remove(destination)
		}
	}()
	var count int64
	for rows.Next() {
		receipt := provenance.LegacyIndexPruneReceipt{
			Schema: provenance.LegacyIndexPruneSchema, Repo: repo, Reason: "indexed-body-missing",
			ConfirmationSHA256: confirmation, RecordedAt: recordedAt, BaselineCommit: commit.String(),
		}
		if err := rows.Scan(&receipt.Path, &receipt.Name, &receipt.Version, &receipt.Arch, &receipt.ArtifactSize, &receipt.ArtifactSHA256); err != nil {
			return count, err
		}
		if err := provenance.WriteLegacyIndexPrune(file, receipt); err != nil {
			return count, err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return count, err
	}
	if err := file.Sync(); err != nil {
		return count, err
	}
	if err := file.Close(); err != nil {
		return count, err
	}
	committed = true
	return count, nil
}

func (s *legacyAdoptionSpool) payloadCount(repo string) (int64, error) {
	var count int64
	err := s.db.QueryRow(`SELECT count(*) FROM payload WHERE repo=?`, repo).Scan(&count)
	return count, err
}

func mergeLegacyAdoptionLedgers(canonical *state.Store, spool *legacyAdoptionSpool, repo config.Repo, currentBaseline plumbing.Hash, existing, current io.Reader, destination string) (count int64, resultErr error) {
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	committed := false
	closed := false
	defer func() {
		if !committed {
			_ = os.Remove(destination)
		}
		if !closed {
			resultErr = errors.Join(resultErr, output.Close())
		}
	}()
	left := provenance.NewLegacyAdoptionReader(existing)
	right := provenance.NewLegacyAdoptionReader(current)
	leftReceipt, leftErr := left.Next()
	rightReceipt, rightErr := right.Next()
	for !errors.Is(leftErr, io.EOF) || !errors.Is(rightErr, io.EOF) {
		if leftErr != nil && !errors.Is(leftErr, io.EOF) || rightErr != nil && !errors.Is(rightErr, io.EOF) {
			return count, errors.Join(leftErr, rightErr)
		}
		var selected provenance.LegacyAdoptionReceipt
		switch {
		case errors.Is(leftErr, io.EOF):
			selected = rightReceipt
			rightReceipt, rightErr = right.Next()
		case errors.Is(rightErr, io.EOF):
			selected = leftReceipt
			leftReceipt, leftErr = left.Next()
		case leftReceipt.SourcePath < rightReceipt.SourcePath:
			selected = leftReceipt
			leftReceipt, leftErr = left.Next()
		case rightReceipt.SourcePath < leftReceipt.SourcePath:
			selected = rightReceipt
			rightReceipt, rightErr = right.Next()
		default:
			if !sameLegacyReceiptArtifact(leftReceipt, rightReceipt) {
				return count, fmt.Errorf("legacy adoption ledger for repo %s conflicts at %s", repo.ID, leftReceipt.SourcePath)
			}
			// Preserve the older valid anchor for an already-adopted byte. A later
			// partial selector may advance the repo baseline without invalidating
			// provenance created from an exact ancestor manifest.
			selected = leftReceipt
			leftReceipt, leftErr = left.Next()
			rightReceipt, rightErr = right.Next()
		}
		if err := spool.validateLegacyReceiptAnchor(canonical, repo, currentBaseline, selected); err != nil {
			return count, err
		}
		if err := provenance.WriteLegacyAdoption(output, selected); err != nil {
			return count, err
		}
		count++
	}
	if err := output.Sync(); err != nil {
		return count, err
	}
	if err := output.Close(); err != nil {
		return count, err
	}
	closed = true
	committed = true
	return count, nil
}

func sameLegacyReceiptArtifact(left, right provenance.LegacyAdoptionReceipt) bool {
	return left.Schema == right.Schema && left.Format == right.Format && left.Repo == right.Repo &&
		left.SourcePath == right.SourcePath && left.CanonicalPath == right.CanonicalPath &&
		left.ArtifactSize == right.ArtifactSize && left.ArtifactSHA256 == right.ArtifactSHA256 && left.Pool == right.Pool
}

func (s *legacyAdoptionSpool) validateLegacyReceiptAnchor(canonical *state.Store, repo config.Repo, currentBaseline plumbing.Hash, receipt provenance.LegacyAdoptionReceipt) error {
	wantFormat := map[string]string{"apt": "deb", "yum": "rpm", "asset": "asset"}[repo.Type]
	if wantFormat == "" || receipt.Repo != repo.ID || receipt.Pool != repo.DefaultPool || receipt.Format != wantFormat {
		return fmt.Errorf("legacy adoption receipt has the wrong repo, pool, or format for %s", repo.ID)
	}
	if err := validateLegacyReceiptCanonicalPath(repo, receipt); err != nil {
		return err
	}
	var currentSize int64
	var currentSHA string
	if err := s.db.QueryRow(`SELECT size,sha256 FROM baseline WHERE repo=? AND path=?`, repo.ID, receipt.SourcePath).Scan(&currentSize, &currentSHA); err != nil {
		return fmt.Errorf("legacy adoption receipt source %s is absent from the current baseline: %w", receipt.SourcePath, err)
	}
	if currentSize != receipt.ArtifactSize || currentSHA != receipt.ArtifactSHA256 {
		return fmt.Errorf("legacy adoption receipt source %s differs from the current baseline", receipt.SourcePath)
	}
	anchor := plumbing.NewHash(receipt.ConfigCommit)
	if anchor.String() != receipt.ConfigCommit {
		return fmt.Errorf("legacy adoption receipt source %s has an invalid baseline commit", receipt.SourcePath)
	}
	ancestor, err := canonical.IsAncestor(anchor, currentBaseline)
	if err != nil || !ancestor {
		return errors.Join(err, fmt.Errorf("legacy adoption receipt source %s is not anchored in the current baseline lineage", receipt.SourcePath))
	}
	commitTime, err := canonical.CommitTime(anchor)
	if err != nil || !commitTime.UTC().Equal(receipt.AdoptedAt) {
		return errors.Join(err, fmt.Errorf("legacy adoption receipt source %s has the wrong baseline timestamp", receipt.SourcePath))
	}
	if err := s.ensureLegacyAnchor(canonical, repo.ID, anchor); err != nil {
		return err
	}
	var anchoredSize int64
	var anchoredSHA string
	if err := s.db.QueryRow(`SELECT size,sha256 FROM anchor WHERE commit_sha=? AND repo=? AND path=?`, anchor.String(), repo.ID, receipt.SourcePath).Scan(&anchoredSize, &anchoredSHA); err != nil {
		return fmt.Errorf("legacy adoption receipt source %s is absent from its claimed baseline: %w", receipt.SourcePath, err)
	}
	if anchoredSize != receipt.ArtifactSize || anchoredSHA != receipt.ArtifactSHA256 {
		return fmt.Errorf("legacy adoption receipt source %s differs from its claimed baseline", receipt.SourcePath)
	}
	return nil
}

func validateLegacyReceiptCanonicalPath(repo config.Repo, receipt provenance.LegacyAdoptionReceipt) error {
	switch repo.Type {
	case "apt", "asset":
		if receipt.CanonicalPath != receipt.SourcePath {
			return fmt.Errorf("legacy adoption receipt source %s has an invalid canonical path %s", receipt.SourcePath, receipt.CanonicalPath)
		}
		return nil
	case "yum":
		if path.Base(receipt.SourcePath) != path.Base(receipt.CanonicalPath) {
			return fmt.Errorf("legacy YUM adoption receipt source %s changes basename at canonical path %s", receipt.SourcePath, receipt.CanonicalPath)
		}
		for _, arch := range repo.Arches {
			root, err := repo.PathForArch(arch)
			if err != nil {
				return err
			}
			relative := strings.TrimPrefix(receipt.CanonicalPath, strings.TrimSuffix(root, "/")+"/")
			parts := strings.Split(relative, "/")
			if len(parts) == 3 && parts[0] == "Packages" && len(parts[1]) == 1 && parts[2] == path.Base(receipt.SourcePath) {
				return nil
			}
		}
		return fmt.Errorf("legacy YUM adoption receipt source %s has a non-canonical package route %s", receipt.SourcePath, receipt.CanonicalPath)
	default:
		return fmt.Errorf("unsupported legacy adoption receipt repo type %q", repo.Type)
	}
}

func (s *legacyAdoptionSpool) ensureLegacyAnchor(canonical *state.Store, repo string, commit plumbing.Hash) error {
	var loaded int
	if err := s.db.QueryRow(`SELECT 1 FROM anchor_loaded WHERE commit_sha=? AND repo=?`, commit.String(), repo).Scan(&loaded); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	manifestPath := filepath.ToSlash(filepath.Join("manifests", repo+".tsv"))
	source, err := canonical.OpenPathAt(commit, manifestPath)
	if err != nil {
		return fmt.Errorf("open claimed legacy adoption baseline %s/%s: %w", commit, repo, err)
	}
	defer source.Close()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.db.QueryRow(`SELECT 1 FROM anchor_loaded WHERE commit_sha=? AND repo=?`, commit.String(), repo).Scan(&loaded); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	insert, err := tx.Prepare(`INSERT INTO anchor(commit_sha,repo,path,size,sha256) VALUES(?,?,?,?,?)`)
	if err != nil {
		return err
	}
	reader := manifest.NewReader(source)
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = insert.Close()
			return readErr
		}
		if _, err := insert.Exec(commit.String(), repo, entry.Path, entry.Size, entry.HashString()); err != nil {
			_ = insert.Close()
			return err
		}
	}
	if err := insert.Close(); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO anchor_loaded(commit_sha,repo) VALUES(?,?)`, commit.String(), repo); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *legacyAdoptionSpool) matchesLegacyIndexPruneLedger(repo, confirmation string, source io.Reader) (bool, int64, error) {
	rows, err := s.db.Query(`SELECT path,name,version,arch,size,sha256 FROM blocker WHERE repo=? ORDER BY path`, repo)
	if err != nil {
		return false, 0, err
	}
	defer rows.Close()
	ledger := provenance.NewLegacyIndexPruneReader(source)
	var count int64
	for {
		rowExists := rows.Next()
		receipt, receiptErr := ledger.Next()
		ledgerExists := !errors.Is(receiptErr, io.EOF)
		if receiptErr != nil && ledgerExists {
			return false, count, receiptErr
		}
		if !rowExists || !ledgerExists {
			if rowErr := rows.Err(); rowErr != nil {
				return false, count, rowErr
			}
			return !rowExists && !ledgerExists, count, nil
		}
		var path, name, version, arch, sha string
		var size int64
		if err := rows.Scan(&path, &name, &version, &arch, &size, &sha); err != nil {
			return false, count, err
		}
		if receipt.Repo != repo || receipt.Path != path || receipt.Name != name || receipt.Version != version || receipt.Arch != arch ||
			receipt.ArtifactSize != size || receipt.ArtifactSHA256 != sha || receipt.Reason != "indexed-body-missing" ||
			receipt.ConfirmationSHA256 != confirmation {
			return false, count, fmt.Errorf("legacy missing-index prune receipt differs at %s: repo=%q/%q name=%q/%q version=%q/%q arch=%q/%q size=%d/%d sha256=%q/%q reason=%q confirmation=%q/%q baseline_commit=%q",
				path, receipt.Repo, repo, receipt.Name, name, receipt.Version, version, receipt.Arch, arch,
				receipt.ArtifactSize, size, receipt.ArtifactSHA256, sha, receipt.Reason,
				receipt.ConfirmationSHA256, confirmation, receipt.BaselineCommit)
		}
		count++
	}
}
