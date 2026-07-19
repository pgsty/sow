package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/syncer"
	"github.com/pgsty/sow/internal/upstream"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

type syncClientFactory func(config.Upstream, []byte) (*http.Client, error)

// syncExecutionHooks are test-only crash boundaries around durable production
// phases. The production entry point always supplies an empty value; recovery
// correctness is additionally exercised with real filesystem obstructions.
type syncExecutionHooks struct {
	AfterProvenanceApply  func(config.Upstream, string) error
	AfterProvenanceCommit func(config.Upstream, string) error
	AfterAPTComponent     func(config.Upstream, string) error
}

type syncJournalRecord struct {
	Kind       string                  `json:"kind"`
	Downloaded *upstream.Downloaded    `json:"downloaded,omitempty"`
	Present    *upstream.ReceiptCommit `json:"present,omitempty"`
}

// syncJournal is the disk-backed handoff between bounded upstream execution
// and repository ingestion. It prevents a replay with tens of thousands of
// present packages from rebuilding an in-memory []Candidate.
type syncJournal struct {
	path   string
	file   *os.File
	encode *json.Encoder
	sealed bool
}

func newSyncJournal(txDir string) (*syncJournal, error) {
	file, err := os.OpenFile(filepath.Join(txDir, "sync-results.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &syncJournal{path: file.Name(), file: file, encode: json.NewEncoder(file)}, nil
}

func (j *syncJournal) PutDownloaded(value upstream.Downloaded) error {
	if j == nil || j.sealed || j.encode == nil {
		return errors.New("sync result journal is not writable")
	}
	if err := value.Candidate.Validate(); err != nil {
		return err
	}
	return j.encode.Encode(syncJournalRecord{Kind: "downloaded", Downloaded: &value})
}

func (j *syncJournal) PutPresent(value upstream.ReceiptCommit) error {
	if j == nil || j.sealed || j.encode == nil {
		return errors.New("sync result journal is not writable")
	}
	if err := value.Candidate.Validate(); err != nil {
		return err
	}
	return j.encode.Encode(syncJournalRecord{Kind: "present", Present: &value})
}

func (j *syncJournal) Seal() error {
	if j == nil {
		return errors.New("sync result journal is unavailable")
	}
	if j.sealed {
		return nil
	}
	if j.file == nil {
		return errors.New("sync result journal is unavailable")
	}
	if err := j.file.Sync(); err != nil {
		_ = j.file.Close()
		return err
	}
	if err := j.file.Close(); err != nil {
		return err
	}
	j.file = nil
	j.encode = nil
	j.sealed = true
	return nil
}

func (j *syncJournal) ForEach(fn func(syncJournalRecord) error) error {
	if j == nil || !j.sealed || fn == nil {
		return errors.New("sync result journal is not sealed")
	}
	file, err := os.Open(j.path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	for {
		var record syncJournalRecord
		if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("decode sync result journal: %w", err)
		}
		switch record.Kind {
		case "downloaded":
			if record.Downloaded == nil || record.Present != nil {
				return errors.New("invalid downloaded sync journal record")
			}
			if err := record.Downloaded.Candidate.Validate(); err != nil {
				return err
			}
		case "present":
			if record.Present == nil || record.Downloaded != nil {
				return errors.New("invalid present sync journal record")
			}
			if err := record.Present.Candidate.Validate(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown sync result journal kind %q", record.Kind)
		}
		if err := fn(record); err != nil {
			return err
		}
	}
	return nil
}

func (j *syncJournal) Close() error {
	if j == nil {
		return nil
	}
	if j.file != nil {
		_ = j.file.Close()
	}
	if err := os.Remove(j.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func runSync(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runSyncWithClientFactory(ctx, args, stdout, stderr, defaultSyncClient)
}

func runSyncWithClientFactory(ctx context.Context, args []string, stdout, stderr io.Writer, clientFactory syncClientFactory) error {
	return runSyncWithClientFactoryAndHooks(ctx, args, stdout, stderr, clientFactory, syncExecutionHooks{})
}

func runSyncWithClientFactoryAndHooks(ctx context.Context, args []string, stdout, stderr io.Writer, clientFactory syncClientFactory, hooks syncExecutionHooks) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	addCommonFlags(fs, &values)
	var upstreamSelectors csvFlag
	fs.Var(&upstreamSelectors, "upstream", "select upstream name (repeatable or comma-separated)")
	privateKeyFile := fs.String("gpg-private-key-file", "", "read the repository OpenPGP private key from a protected file")
	passphraseFile := fs.String("gpg-passphrase-file", "", "read the repository OpenPGP passphrase from a protected file")
	attempts := fs.Int("attempts", 4, "verified package download attempts")
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow sync [--upstream NAME] [--repo NAME] [--os OS] [--arch ARCH] [--config sow.yaml]")
	}
	if help, err := parseFlagSet(fs, args); err != nil || help {
		return err
	}
	if fs.NArg() != 0 || *attempts < 1 {
		return withExitCode(ExitUsage, "sync accepts no positional arguments and --attempts must be positive")
	}
	if clientFactory == nil {
		return withExitCode(ExitInternal, "sync HTTP client factory is unavailable")
	}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		return err
	}
	unknown := difference(upstreamSelectors.values(), upstreamNames(cfg.Upstreams))
	if len(unknown) != 0 {
		return withExitCode(ExitConfig, "unknown upstream selector(s): %s", strings.Join(unknown, ","))
	}
	selectedRepos := make(map[string]config.Repo, len(repos))
	for _, repo := range repos {
		selectedRepos[repo.ID] = repo
	}
	selectedUpstreams := make([]config.Upstream, 0, len(cfg.Upstreams))
	for _, source := range cfg.Upstreams {
		repo, selected := selectedRepos[source.Repo]
		if !selected || !matchesValue(source.ID, upstreamSelectors.values()) {
			continue
		}
		effective, selected := narrowUpstreamSelection(source, repo)
		if !selected {
			continue
		}
		selectedUpstreams = append(selectedUpstreams, effective)
	}
	if len(selectedUpstreams) == 0 {
		return withExitCode(ExitConfig, "selectors matched no configured upstreams")
	}
	sort.Slice(selectedUpstreams, func(i, j int) bool { return selectedUpstreams[i].ID < selectedUpstreams[j].ID })
	for _, source := range selectedUpstreams {
		repo := selectedRepos[source.Repo]
		if repo.LifecycleForSuite(source.Suite) != "frozen" {
			continue
		}
		if repo.Type == "apt" {
			return withExitCode(ExitConflict, "repo %s suite %s is frozen; upstream sync is forbidden", repo.ID, source.Suite)
		}
		return withExitCode(ExitConflict, "repo %s is frozen; upstream sync is forbidden", repo.ID)
	}

	canonical := state.New(cfg.StatePath())
	materializationRecover, err := checkSyncRecovery(ctx, cfg, canonical, values.recover, selectedUpstreams, stdout, stderr)
	if err != nil {
		return err
	}
	values.recover = values.recover || materializationRecover
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return withExitCode(ExitConflict, "open CAS: %v", err)
	}
	for _, source := range selectedUpstreams {
		repo := selectedRepos[source.Repo]
		operationRepo, selected := narrowRepoToUpstream(repo, source)
		if !selected {
			return withExitCode(ExitInternal, "selected upstream %s no longer has a representable repository scope", source.ID)
		}
		if err := syncOneUpstream(ctx, cfg, canonical, pool, operationRepo, source, values, *attempts, *privateKeyFile, *passphraseFile, stdout, stderr, clientFactory, hooks); err != nil {
			return err
		}
	}
	return rebuildCatalogProjection(ctx, cfg, stdout)
}

func syncPackageFormat(upstreamType string) string {
	if upstreamType == "yum" {
		return "RPM"
	}
	return "DEB"
}

// narrowUpstreamSelection intersects the configured source with the already
// narrowed repository value. It prevents discovery and ingestion from
// restoring architectures or APT suites excluded by the CLI selectors.
func narrowUpstreamSelection(source config.Upstream, repo config.Repo) (config.Upstream, bool) {
	effective := source
	effective.Arches = intersectSelected(source.Arches, repo.Arches)
	if len(effective.Arches) == 0 {
		return config.Upstream{}, false
	}
	if source.Type == "apt" {
		if repo.APT == nil || !contains(repo.APT.Suites, source.Suite) {
			return config.Upstream{}, false
		}
	}
	effective.Components = append([]string(nil), source.Components...)
	effective.Allow = append([]string(nil), source.Allow...)
	effective.Deny = append([]string(nil), source.Deny...)
	return effective, true
}

// narrowRepoToUpstream freezes the repository half of one sync operation to
// exactly the dimensions that its already-narrowed upstream can populate.
// Repository selectors may still contain several APT suites or architectures;
// persisting that wider value would make an unrelated dimension part of the
// durable replay contract and let recovery project leaves this upstream never
// selected. For APT, NarrowSuites also freezes that suite's exact component
// and lifecycle maps; recovery cannot widen a stable suite to components that
// exist only in a testing sibling.
func narrowRepoToUpstream(repo config.Repo, source config.Upstream) (config.Repo, bool) {
	if repo.ID != source.Repo || repo.Type != source.Type || len(source.Arches) == 0 {
		return config.Repo{}, false
	}
	effective := repo
	effective.Arches = intersectSelected(repo.Arches, source.Arches)
	if len(effective.Arches) != len(uniqueSorted(source.Arches)) {
		return config.Repo{}, false
	}
	if repo.Type == "apt" {
		if repo.APT == nil || source.Suite == "" || !contains(repo.APT.Suites, source.Suite) {
			return config.Repo{}, false
		}
		effective.APT = repo.APT.NarrowSuites([]string{source.Suite})
	}
	return effective, true
}

func syncOneUpstream(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repo config.Repo, source config.Upstream, values commonFlags, attempts int, privateKeyFile, passphraseFile string, stdout, stderr io.Writer, clientFactory syncClientFactory, hooks syncExecutionHooks) (returnErr error) {
	operation, err := acquireSyncOperation(ctx, cfg.StatePath(), source.ID)
	if err != nil {
		return withExitCode(ExitConflict, "acquire upstream sync operation: %v", err)
	}
	defer propagateSyncOperationClose(operation, source.ID, &returnErr, stderr)
	wantedProgress, err := newSyncProgress(cfg, repo, source)
	if err != nil {
		return withExitCode(ExitInternal, "derive sync progress identity for %s: %v", source.ID, err)
	}
	progress, err := operation.Load()
	if err != nil {
		return withExitCode(ExitVerification, "load durable sync progress for %s: %v", source.ID, err)
	}
	if journal, active, journalErr := readMaterializationSelectionJournal(cfg.StatePath()); journalErr != nil {
		return withExitCode(ExitConflict, "read sync selected-set identity for %s: %v", source.ID, journalErr)
	} else if active {
		upstreamID, selectionSHA256, scopeErr := parseSyncMaterializationScope(journal.OperationScope)
		if scopeErr != nil || upstreamID != source.ID || selectionSHA256 != wantedProgress.SelectionSHA256 || progress == nil || progress.SelectionSHA256 != selectionSHA256 {
			return withExitCode(ExitConflict, "sync selected-set identity does not match durable progress for upstream %s: %v", source.ID, scopeErr)
		}
	}
	defer func() {
		if returnErr != nil && progress != nil &&
			(syncProgressGitPattern.MatchString(progress.ProvenanceCommit) || syncProgressTxPattern.MatchString(progress.ProvenanceTransaction)) &&
			!isSyncPartialCommitError(returnErr) {
			returnErr = syncPartialCommitError(source, progress, returnErr)
		}
	}()
	resuming := progress != nil
	if progress == nil {
		progress = wantedProgress
	} else {
		if err := operation.ValidateReplay(progress); err != nil {
			return withExitCode(ExitVerification, "validate frozen sync replay for %s: %v", source.ID, err)
		}
		if err := reconcileSyncProvenanceTransaction(canonical, source, operation, progress); err != nil {
			return withExitCode(ExitVerification, "reconcile sync provenance transaction for %s: %v", source.ID, err)
		}
		discard := values.recover && progress.ProvenanceCommit == "" && progress.Phase == syncPhasePrepared && progress.ProvenanceTransaction == ""
		if values.recover && progress.ProvenanceCommit == "" && progress.Phase == syncPhaseProvenanceCommitting && progress.ProvenanceTransaction != "" {
			_, exists, err := canonical.Transaction(progress.ProvenanceTransaction)
			if err != nil {
				return withExitCode(ExitVerification, "inspect unstarted sync provenance transaction for %s: %v", source.ID, err)
			}
			discard = !exists
		}
		if discard {
			phase := progress.Phase
			if err := discardUncommittedSyncIntent(operation, progress); err != nil {
				return withExitCode(ExitVerification, "discard uncommitted sync intent for %s: %v", source.ID, err)
			}
			fmt.Fprintf(stdout, "sync recovery upstream=%s discarded_uncommitted_intent=true phase=%s\n", source.ID, phase)
			progress = wantedProgress
			resuming = false
		} else {
			if err := reconcileSyncProgress(progress, wantedProgress, values.recover); err != nil {
				return withExitCode(ExitConflict, "resume durable sync progress for %s: %v", source.ID, err)
			}
			fmt.Fprintf(stdout, "sync recovery upstream=%s phase=%s provenance_commit=%s completed_units=%d\n",
				source.ID, progress.Phase, progress.ProvenanceCommit, len(progress.CompletedUnits))
		}
	}
	if syncProgressGitPattern.MatchString(progress.ProvenanceCommit) {
		txDir, err := newTransactionDir(cfg.StatePath(), "sync-"+source.ID+"-")
		if err != nil {
			return withExitCode(ExitInternal, "create offline sync recovery transaction: %v", err)
		}
		defer os.RemoveAll(txDir)
		missing, err := missingSyncReplayRecords(canonical, repo, source, operation, progress)
		if err != nil {
			return withExitCode(ExitVerification, "compare frozen sync replay with canonical views: %v", err)
		}
		stagedInputs, err := stageSyncReplayInputs(ctx, txDir, pool, operation, missing)
		if err != nil {
			return withExitCode(ExitVerification, "stage frozen sync replay inputs: %v", err)
		}
		ingestContract, err := resolveCanonicalSyncContract(canonical, cfg, repo, source, progress.SelectionSHA256)
		if err != nil {
			return withExitCode(ExitConflict, "canonical %s sync contract changed: %v", syncPackageFormat(source.Type), err)
		}
		if !ingestContract.Exists || ingestContract.Config == nil {
			return withExitCode(ExitConflict, "current canonical sync projection is unavailable")
		}
		if err := ingestSyncChangeSet(ctx, ingestContract.Config, repo, source, values, stagedInputs, privateKeyFile, passphraseFile, stdout, stderr, operation, progress, hooks); err != nil {
			return err
		}
		advanceSyncProgress(progress, syncPhaseProjectionRepair, progress.ProvenanceCommit, "canonical-view-projection", false)
		if err := operation.Write(progress); err != nil {
			return withExitCode(ExitInternal, "persist offline projection repair phase: %v", err)
		}
		if err := repairSyncProjection(ctx, cfg, canonical, pool, repo, source, values, progress.SelectionSHA256, txDir, privateKeyFile, passphraseFile, stdout, stderr); err != nil {
			return err
		}
		if err := cleanupSyncTransactionResidue(cfg.StatePath(), source.ID, txDir); err != nil {
			return withExitCode(ExitVerification, "clean completed offline sync transaction residue: %v", err)
		}
		if err := operation.RemoveReplayDownloads(progress); err != nil {
			return withExitCode(ExitVerification, "clean completed offline sync download copies: %v", err)
		}
		if err := operation.RemoveProgress(); err != nil {
			return withExitCode(ExitInternal, "remove completed sync progress: %v", err)
		}
		if err := operation.RemoveReplay(); err != nil {
			return withExitCode(ExitVerification, "remove completed offline sync replay: %v", err)
		}
		return nil
	}
	keyring, upstreamKeyringSHA256, err := loadPublicOnlyKeyring(cfg.Path, source.Keyring, "upstream")
	if err != nil {
		return withExitCode(ExitConfig, "load upstream %s keyring: %v", source.ID, err)
	}
	var rpmPackageKeyring openpgp.KeyRing
	var rpmPackageKeyringSHA256 string
	if source.Type == "yum" {
		rpmPackageKeyring, rpmPackageKeyringSHA256, err = loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
		if err != nil || rpmPackageKeyring == nil || rpmPackageKeyringSHA256 == "" {
			return withExitCode(ExitConfig, "load repo %s RPM package keyring: %v", repo.ID, errors.Join(err, errors.New("public package trust bundle is required")))
		}
	}
	_, repositoryKeyPackets, err := loadRepositoryPublicTrustAnchor(cfg.Path, cfg.GPG.PublicKey)
	if err != nil {
		return withExitCode(ExitConfig, "revalidate repository signing trust for sync: %v", err)
	}
	currentSelectionSHA256, err := syncSelectionSHA256WithTrust(cfg, repo, source, repositoryTrustAnchorDigest(repositoryKeyPackets), upstreamKeyringSHA256, rpmPackageKeyringSHA256)
	if err != nil {
		return withExitCode(ExitConfig, "revalidate upstream %s trust identities: %v", source.ID, err)
	}
	if currentSelectionSHA256 != progress.SelectionSHA256 {
		return withExitCode(ExitConflict, "upstream %s trust keyring changed after sync preflight", source.ID)
	}
	credential, err := resolveSecret(source.Credential, "", true)
	if err != nil {
		return withExitCode(ExitConfig, "resolve upstream %s credential: %v", source.ID, err)
	}
	defer clearSecret(credential)
	client, err := clientFactory(source, credential)
	if err != nil {
		return withExitCode(ExitConfig, "configure upstream %s HTTP client: %v", source.ID, err)
	}
	workDir := operation.dir
	var discovery *upstream.Discovery
	switch source.Type {
	case "apt":
		if keyring == nil {
			return withExitCode(ExitConfig, "APT upstream %s has no trusted keyring", source.ID)
		}
		discovery, err = upstream.DiscoverAPTStreaming(ctx, upstream.APTSource{
			BaseURL: source.URL, Suite: source.Suite, Components: source.Components,
			Architectures: source.Arches, Keyring: keyring, Client: client, WorkDir: workDir,
		})
	case "yum":
		discovery, err = upstream.DiscoverYUMStreaming(ctx, upstream.YUMSource{
			BaseURL: source.URL, Architectures: source.Arches,
			ExcludeNoarch: repo.YUM.NoarchMode == config.YUMNoarchSeparate && !contains(source.Arches, "noarch"),
			Keyring:       keyring, Client: client, WorkDir: workDir,
		})
	default:
		return withExitCode(ExitConfig, "unsupported upstream type %q", source.Type)
	}
	if err != nil {
		return withExitCode(syncFailureExitCode(err), "discover upstream %s: %v", source.ID, err)
	}
	defer func() {
		if closeErr := discovery.Close(); closeErr != nil {
			fmt.Fprintf(stderr, "warning: close upstream %s candidate spool: %v\n", source.ID, closeErr)
		}
	}()
	txDir, err := newTransactionDir(cfg.StatePath(), "sync-"+source.ID+"-")
	if err != nil {
		return withExitCode(ExitInternal, "create sync transaction: %v", err)
	}
	defer os.RemoveAll(txDir)
	provenanceStore := provenance.NewStore(txDir)
	if err := seedCanonicalProvenance(ctx, canonical, provenanceStore, discovery); err != nil {
		return withExitCode(ExitVerification, "load canonical provenance for %s: %v", source.ID, err)
	}
	journal, err := newSyncJournal(txDir)
	if err != nil {
		return withExitCode(ExitInternal, "create sync result journal: %v", err)
	}
	defer journal.Close()
	executor := upstream.Executor{
		Downloader:  syncer.Downloader{Client: client, Attempts: attempts, RetryDelay: 250 * time.Millisecond},
		DownloadDir: filepath.Join(workDir, "downloads"), Provenance: provenanceStore,
		Workers: values.workers, RPMPackageKeyring: rpmPackageKeyring, RPMPackageKeyringSHA256: rpmPackageKeyringSHA256,
	}
	// source.DebugInfo is validated as the public-view policy (drop). Debug
	// packages are nevertheless retained at ingestion so their verified bytes
	// and provenance can be routed exclusively to stable.
	result, err := executor.RunStreaming(ctx, discovery, syncer.Filter{Allow: source.Allow, Deny: source.Deny, DebugInfo: "keep"}, casInventory{ctx: ctx, pool: pool}, journal)
	if err != nil {
		return withExitCode(syncFailureExitCode(err), "sync upstream %s: %v", source.ID, err)
	}
	if err := journal.Seal(); err != nil {
		return withExitCode(ExitInternal, "seal sync result journal: %v", err)
	}
	missingPresent, err := missingPresentCandidates(canonical, repo, source, journal)
	if err != nil {
		return withExitCode(ExitVerification, "inspect target view for %s: %v", source.ID, err)
	}
	stagedInputs, err := stageSyncInputs(ctx, txDir, pool, repo, source, journal, missingPresent)
	if err != nil {
		return withExitCode(ExitVerification, "stage verified sync inputs for %s: %v", source.ID, err)
	}
	replayRecords, err := buildSyncReplayRecords(repo, source, journal, missingPresent)
	if err != nil {
		return withExitCode(ExitVerification, "build frozen sync replay for %s: %v", source.ID, err)
	}
	expectedReplaySHA, expectedReplayCount := "", int64(0)
	if resuming {
		expectedReplaySHA, expectedReplayCount = progress.ReplaySHA256, progress.ReplayCount
	}
	replaySHA, replayCount, err := operation.WriteReplay(replayRecords, expectedReplaySHA, expectedReplayCount)
	if err != nil {
		return withExitCode(ExitConflict, "seal frozen sync replay for %s: %v", source.ID, err)
	}
	progress.ReplaySHA256, progress.ReplayCount = replaySHA, replayCount
	provenanceInputSHA, err := syncProvenanceInputSHA256(discovery, replaySHA, replayCount)
	if err != nil {
		return withExitCode(ExitVerification, "bind sync provenance input for %s: %v", source.ID, err)
	}
	if resuming && progress.ProvenanceInputSHA256 != provenanceInputSHA {
		return withExitCode(ExitConflict, "upstream evidence differs from prepared durable sync intent for %s", source.ID)
	}
	progress.ProvenanceInputSHA256 = provenanceInputSHA
	if !resuming {
		if err := operation.Write(progress); err != nil {
			return withExitCode(ExitInternal, "persist prepared sync progress for %s: %v", source.ID, err)
		}
	}
	if progress.ProvenanceTransaction == "" {
		progress.ProvenanceTransaction, err = state.NewTransactionID()
		if err != nil {
			return withExitCode(ExitInternal, "allocate provenance transaction for %s: %v", source.ID, err)
		}
	}
	advanceSyncProgress(progress, syncPhaseProvenanceCommitting, "", "", false)
	if err := operation.Write(progress); err != nil {
		return withExitCode(ExitInternal, "persist provenance commit intent for %s: %v", source.ID, err)
	}
	commit, changed, err := commitSyncProvenance(ctx, cfg, canonical, repo, source, discovery, journal, txDir, progress.ProvenanceInputSHA256, progress.SelectionSHA256, progress.ProvenanceTransaction, values.recover, stdout, stderr)
	if err != nil {
		return err
	}
	if hooks.AfterProvenanceApply != nil {
		if err := hooks.AfterProvenanceApply(source, commit); err != nil {
			return syncPartialCommitError(source, progress, err)
		}
	}
	advanceSyncProgress(progress, syncPhaseProvenanceCommitted, commit, "", false)
	if err := operation.Write(progress); err != nil {
		return syncPartialCommitError(source, progress, withExitCode(ExitInternal, "persist provenance phase: %v", err))
	}
	fmt.Fprintf(stdout, "sync upstream=%s format=%s candidates=%d download=%d present=%d filtered=%d provenance_commit=%s provenance_changed=%t\n",
		source.ID, discovery.Format, discovery.CandidateCount(), result.Plan.DownloadCount, result.Plan.Present, result.Plan.Filtered, commit, changed)
	if hooks.AfterProvenanceCommit != nil {
		if err := hooks.AfterProvenanceCommit(source, commit); err != nil {
			return syncPartialCommitError(source, progress, err)
		}
	}
	ingestContract, err := resolveCanonicalSyncContract(canonical, cfg, repo, source, progress.SelectionSHA256)
	if err != nil {
		return syncPartialCommitError(source, progress, withExitCode(ExitConflict, "canonical %s sync contract changed: %v", syncPackageFormat(source.Type), err))
	}
	if !ingestContract.Exists || ingestContract.Config == nil {
		return syncPartialCommitError(source, progress, withExitCode(ExitConflict, "current canonical sync projection is unavailable"))
	}
	if err := ingestSyncChangeSet(ctx, ingestContract.Config, repo, source, values, stagedInputs, privateKeyFile, passphraseFile, stdout, stderr, operation, progress, hooks); err != nil {
		return err
	}
	if resuming {
		advanceSyncProgress(progress, syncPhaseProjectionRepair, commit, "canonical-view-projection", false)
		if err := operation.Write(progress); err != nil {
			return syncPartialCommitError(source, progress, withExitCode(ExitInternal, "persist projection repair phase: %v", err))
		}
		if err := repairSyncProjection(ctx, cfg, canonical, pool, repo, source, values, progress.SelectionSHA256, txDir, privateKeyFile, passphraseFile, stdout, stderr); err != nil {
			return syncPartialCommitError(source, progress, err)
		}
	}
	if err := cleanupSyncTransactionResidue(cfg.StatePath(), source.ID, txDir); err != nil {
		return syncPartialCommitError(source, progress, withExitCode(ExitVerification, "clean completed sync transaction residue: %v", err))
	}
	if err := operation.RemoveReplayDownloads(progress); err != nil {
		return syncPartialCommitError(source, progress, withExitCode(ExitVerification, "clean completed sync download copies: %v", err))
	}
	if err := operation.RemoveProgress(); err != nil {
		return syncPartialCommitError(source, progress, withExitCode(ExitInternal, "remove completed sync progress: %v", err))
	}
	if err := operation.RemoveReplay(); err != nil {
		return withExitCode(ExitVerification, "remove completed sync replay: %v", err)
	}
	return nil
}

// propagateSyncOperationClose makes release of the per-upstream durable
// operation lease part of command success. A command that already failed keeps
// its primary exit class while still reporting a teardown problem.
func propagateSyncOperationClose(operation io.Closer, upstreamID string, resultErr *error, stderr io.Writer) {
	if operation == nil || resultErr == nil {
		return
	}
	closeErr := operation.Close()
	if closeErr == nil {
		return
	}
	if *resultErr != nil {
		if stderr != nil {
			fmt.Fprintf(stderr, "warning: close upstream %s sync operation: %v\n", upstreamID, closeErr)
		}
		return
	}
	*resultErr = withExitCode(ExitInternal, "close upstream %s sync operation: %v", upstreamID, closeErr)
}

func discardUncommittedSyncIntent(operation *syncOperation, progress *syncProgress) error {
	if err := operation.RemoveReplayDownloads(progress); err != nil {
		return err
	}
	if err := operation.RemoveProgress(); err != nil {
		return err
	}
	return operation.RemoveReplay()
}

func syncFailureExitCode(err error) int {
	switch {
	case errors.Is(err, upstream.ErrUnsafeURL):
		return ExitConfig
	case errors.Is(err, upstream.ErrMetadataTooLarge),
		errors.Is(err, upstream.ErrInvalidMetadata),
		errors.Is(err, upstream.ErrSignature),
		errors.Is(err, upstream.ErrConflictingPackage),
		errors.Is(err, upstream.ErrEvidence):
		return ExitVerification
	default:
		return ExitNetworkAuth
	}
}

func upstreamNames(values []config.Upstream) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.ID)
	}
	sort.Strings(result)
	return result
}

func syncMaterializationScope(upstreamID, selectionSHA256 string) string {
	return "upstream=" + upstreamID + ";selection=" + selectionSHA256
}

func parseSyncMaterializationScope(value string) (string, string, error) {
	const prefix = "upstream="
	const separator = ";selection="
	if !strings.HasPrefix(value, prefix) {
		return "", "", errors.New("sync materialization scope has no upstream identity")
	}
	remainder := strings.TrimPrefix(value, prefix)
	index := strings.Index(remainder, separator)
	if index <= 0 || strings.Contains(remainder[index+len(separator):], separator) {
		return "", "", errors.New("sync materialization scope is malformed")
	}
	upstreamID := remainder[:index]
	selectionSHA256 := remainder[index+len(separator):]
	if !syncProgressNamePattern.MatchString(upstreamID) || !syncProgressSHA256Pattern.MatchString(selectionSHA256) {
		return "", "", errors.New("sync materialization scope identity is invalid")
	}
	return upstreamID, selectionSHA256, nil
}

func checkSyncRecovery(ctx context.Context, cfg *config.Config, canonical *state.Store, recover bool, selectedUpstreams []config.Upstream, stdout, stderr io.Writer) (recovered bool, resultErr error) {
	lock, err := state.AcquireLock(cfg.StatePath(), "sync", recover)
	if err != nil {
		return false, withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	// Cleanup and admission are deliberately inside the state lock. A sync
	// selected set is automatically recoverable like its progress ledger, but
	// only by the one upstream identity frozen in the journal scope.
	if err := requireNoForeignMaterializationIntent(cfg, "sync", true); err != nil {
		return false, withExitCode(ExitConflict, "%v", err)
	}
	autoRecover := false
	journal, active, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil {
		return false, withExitCode(ExitConflict, "inspect sync materialization recovery: %v", err)
	}
	if active {
		upstreamID, _, scopeErr := parseSyncMaterializationScope(journal.OperationScope)
		if scopeErr != nil || len(selectedUpstreams) != 1 || selectedUpstreams[0].ID != upstreamID {
			return false, withExitCode(ExitConflict, "incomplete sync materialization requires its one exact upstream %s: %v", upstreamID, scopeErr)
		}
		for _, unit := range journal.Units {
			if unit.Repo != selectedUpstreams[0].Repo {
				return false, withExitCode(ExitConflict, "incomplete sync materialization belongs to repo %s, not selected upstream %s", unit.Repo, selectedUpstreams[0].ID)
			}
		}
		autoRecover = true
		fmt.Fprintf(stdout, "sync recovery upstream=%s materialization_selected_set=true\n", upstreamID)
	}
	if err := prepareCanonicalState(ctx, canonical, recover || autoRecover, stdout); err != nil {
		return false, err
	}
	if err := validateCanonicalHistoryContracts(cfg); err != nil {
		return false, withExitCode(ExitConflict, "repository history contract changed while sync was waiting for the state lock: %v", err)
	}
	return autoRecover, nil
}

type casInventory struct {
	ctx  context.Context
	pool *repository.Store
}

func (inventory casInventory) Has(value string, size int64) (bool, error) {
	digest, err := repository.ParseDigest(value)
	if err != nil {
		return false, err
	}
	file, err := inventory.pool.Open(digest)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || closeErr != nil {
		return false, errors.Join(statErr, closeErr)
	}
	if err := inventory.ctx.Err(); err != nil {
		return false, err
	}
	return info.Size() == size, nil
}

func (inventory casInventory) OpenArtifact(value string, size int64) (io.ReadSeekCloser, error) {
	digest, err := repository.ParseDigest(value)
	if err != nil {
		return nil, err
	}
	file, err := inventory.pool.Open(digest)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("CAS artifact %s has size %d, want %d", value, info.Size(), size)
	}
	if err := inventory.ctx.Err(); err != nil {
		_ = file.Close()
		return nil, err
	}
	coordinate := inventory.pool.ObjectPath(digest)
	current, err := os.Lstat(coordinate)
	if err != nil || !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, current) {
		_ = file.Close()
		return nil, errors.Join(err, fmt.Errorf("CAS artifact %s changed while opening", value))
	}
	return &stableCASArtifact{file: file, coordinate: coordinate, before: info}, nil
}

// stableCASArtifact makes the ArtifactOpener close boundary part of present
// artifact verification. Upstream hashes every format and additionally
// verifies RPM signatures through this descriptor; Close then proves that the
// canonical CAS pathname still names the opened inode and did not change.
type stableCASArtifact struct {
	file       *os.File
	coordinate string
	before     os.FileInfo
}

func (artifact *stableCASArtifact) Read(buffer []byte) (int, error) {
	return artifact.file.Read(buffer)
}

func (artifact *stableCASArtifact) Seek(offset int64, whence int) (int64, error) {
	return artifact.file.Seek(offset, whence)
}

func (artifact *stableCASArtifact) Close() error {
	if artifact == nil || artifact.file == nil || artifact.before == nil {
		return errors.New("CAS artifact handle is not configured")
	}
	after, statErr := artifact.file.Stat()
	current, pathErr := os.Lstat(artifact.coordinate)
	closeErr := artifact.file.Close()
	artifact.file = nil
	if statErr != nil || pathErr != nil || closeErr != nil || !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(artifact.before, after) || !os.SameFile(artifact.before, current) ||
		artifact.before.Size() != after.Size() || !artifact.before.ModTime().Equal(after.ModTime()) {
		return errors.Join(statErr, pathErr, closeErr, errors.New("CAS artifact changed during digest/signature verification"))
	}
	return nil
}

func loadUpstreamKeyring(configPath, relative string) (openpgp.EntityList, error) {
	entities, _, err := loadPublicOnlyKeyring(configPath, relative, "upstream")
	return entities, err
}

// loadPublicOnlyKeyring returns both parsed entities and the digest of the
// exact trust-bundle bytes. The digest is a provenance input; filenames alone
// are not stable trust identities across key rotation.
func loadPublicOnlyKeyring(configPath, relative, subject string) (openpgp.EntityList, string, error) {
	data, digest, err := readStableKeyringBytes(configPath, relative)
	if err != nil || data == nil {
		return nil, "", err
	}
	entities, err := yumrepo.ParsePublicKeyring(data)
	if err != nil {
		return nil, "", err
	}
	if len(entities) == 0 {
		return nil, "", errors.New("keyring contains no usable OpenPGP public keys")
	}
	for _, entity := range entities {
		if entity == nil || entity.PrimaryKey == nil || entity.PrivateKey != nil {
			return nil, "", fmt.Errorf("%s keyring must contain public keys only", subject)
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil {
				return nil, "", fmt.Errorf("%s keyring must contain public keys only", subject)
			}
		}
	}
	return entities, digest, nil
}

// loadRPMPackageKeyring uses the packet-preserving package-trust parser so a
// later signing-subkey binding renewal cannot invalidate historical packages.
func loadRPMPackageKeyring(configPath, relative string) (openpgp.KeyRing, string, error) {
	data, digest, err := readStableKeyringBytes(configPath, relative)
	if err != nil || data == nil {
		return nil, "", err
	}
	keyring, err := yumrepo.ParseRPMPackageKeyring(data)
	if err != nil {
		return nil, "", fmt.Errorf("RPM package keyring contains no usable public OpenPGP trust history: %w", err)
	}
	return keyring, digest, nil
}

func readStableKeyringBytes(configPath, relative string) ([]byte, string, error) {
	if relative == "" {
		return nil, "", nil
	}
	filename := relative
	if !filepath.IsAbs(filename) {
		filename = filepath.Join(filepath.Dir(configPath), filepath.FromSlash(relative))
	}
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, "", errors.New("resolve keyring path")
	}
	before, err := os.Lstat(abs)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maxSecretBytes {
		return nil, "", errors.New("keyring must be a bounded regular non-symlink file")
	}
	file, err := os.Open(abs)
	if err != nil {
		return nil, "", errors.New("open keyring")
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		file.Close()
		return nil, "", errors.New("keyring changed while opening")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > maxSecretBytes {
		return nil, "", errors.New("read keyring")
	}
	after, err := os.Lstat(abs)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, "", errors.New("keyring changed while reading")
	}
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), nil
}

type bearerTransport struct {
	base  http.RoundTripper
	host  string
	token []byte
}

func (transport bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, errors.New("sync HTTP request is nil")
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	if clone.URL.Scheme == "https" && clone.URL.Host == transport.host && len(transport.token) != 0 {
		clone.Header.Set("Authorization", "Bearer "+string(transport.token))
	}
	return transport.base.RoundTrip(clone)
}

func defaultSyncClient(source config.Upstream, credential []byte) (*http.Client, error) {
	parsed, err := url.Parse(source.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("upstream URL is not clean HTTPS")
	}
	base := http.DefaultTransport
	transport := http.RoundTripper(base)
	if len(credential) != 0 {
		transport = bearerTransport{base: base, host: parsed.Host, token: credential}
	}
	return &http.Client{Transport: transport, Timeout: 5 * time.Minute}, nil
}

func seedCanonicalProvenance(ctx context.Context, canonical *state.Store, destination *provenance.Store, discovery *upstream.Discovery) error {
	return discovery.ForEachCandidateContext(ctx, func(candidate syncer.Candidate) error {
		reader, err := canonical.OpenPath(path.Join("provenance", candidate.Format, candidate.SHA256+".json"))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, maxSecretBytes+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || len(data) > maxSecretBytes {
			return errors.Join(readErr, closeErr, errors.New("canonical provenance receipt exceeds limit"))
		}
		receipt, err := provenance.Decode(data)
		if err != nil {
			return err
		}
		if _, _, err := destination.Put(receipt); err != nil {
			return err
		}
		return nil
	})
}

func commitSyncProvenance(ctx context.Context, cfg *config.Config, canonical *state.Store, repo config.Repo, source config.Upstream, discovery *upstream.Discovery, journal *syncJournal, txDir, inputSHA, selectionSHA, transactionID string, recover bool, stdout, stderr io.Writer) (commitSHA string, created bool, resultErr error) {
	staged := make(map[string]string)
	for _, evidence := range discovery.Evidence {
		if !evidence.Verified {
			return "", false, withExitCode(ExitVerification, "upstream %s evidence %s is not verified", source.ID, evidence.Kind)
		}
		canonicalPath := path.Join("provenance", "evidence", "sha256", evidence.SHA256)
		if prior, exists := staged[canonicalPath]; exists && prior != evidence.Path {
			return "", false, withExitCode(ExitVerification, "conflicting evidence coordinate %s", evidence.SHA256)
		}
		staged[canonicalPath] = evidence.Path
	}
	if err := journal.ForEach(func(record syncJournalRecord) error {
		var candidate syncer.Candidate
		newReceipt := false
		if record.Downloaded != nil {
			candidate = record.Downloaded.Candidate
			newReceipt = record.Downloaded.NewReceipt
		} else {
			candidate = record.Present.Candidate
			newReceipt = record.Present.NewReceipt
		}
		if newReceipt {
			staged[path.Join("provenance", candidate.Format, candidate.SHA256+".json")] = filepath.Join(txDir, "provenance", candidate.Format, candidate.SHA256+".json")
		}
		return nil
	}); err != nil {
		return "", false, withExitCode(ExitVerification, "read sync result journal: %v", err)
	}
	canonicalConfig, _, err := stageCanonicalConfig(cfg, txDir)
	if err != nil {
		return "", false, withExitCode(ExitInternal, "stage canonical config: %v", err)
	}
	staged["config/sow.yaml"] = canonicalConfig
	lock, err := state.AcquireLock(cfg.StatePath(), "sync", recover)
	if err != nil {
		return "", false, withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := requireNoMaterializationIntentBeforeCanonicalMutation(cfg); err != nil {
		return "", false, withExitCode(ExitConflict, "%v", err)
	}
	if err := prepareCanonicalState(ctx, canonical, recover, stdout); err != nil {
		return "", false, err
	}
	if err := validateCanonicalHistoryContracts(cfg); err != nil {
		return "", false, withExitCode(ExitConflict, "repository history contract changed while sync provenance was waiting for the state lock: %v", err)
	}
	configExists, err := validateCanonicalSyncContract(canonical, cfg, repo, source, selectionSHA)
	if err != nil {
		return "", false, withExitCode(ExitConflict, "canonical sync contract changed: %v", err)
	}
	options := state.ApplyOptions{TransactionID: transactionID}
	var commit plumbing.Hash
	var changed bool
	if configExists {
		delete(staged, "config/sow.yaml")
		commit, changed, err = applyCanonicalState(ctx, canonical, "sync", syncProvenanceTransactionMessage(source, inputSHA), staged, nil, options)
	} else {
		commit, changed, err = applyCanonicalConfig(ctx, cfg, canonical, "sync", syncProvenanceTransactionMessage(source, inputSHA), staged, nil, options)
	}
	if err != nil {
		return "", false, stateMutationError("commit sync provenance", err)
	}
	return commit.String(), changed, nil
}

func syncProvenanceTransactionMessage(source config.Upstream, inputSHA string) string {
	return "sow sync provenance: " + source.ID + " input=" + inputSHA
}

type canonicalSyncContract struct {
	Exists   bool
	Config   *config.Config
	Repo     config.Repo
	Upstream config.Upstream
}

// validateCanonicalSyncContract permits an interrupted/long-running sync to
// coexist with a later unrelated config commit, while refusing to apply its
// frozen package set under a changed repository, upstream, or beta/stable
// confidentiality contract. It returns false only before the first canonical
// config has been installed.
func validateCanonicalSyncContract(canonical *state.Store, runtimeConfig *config.Config, selectedRepo config.Repo, selectedSource config.Upstream, expectedSHA string) (bool, error) {
	contract, err := resolveCanonicalSyncContract(canonical, runtimeConfig, selectedRepo, selectedSource, expectedSHA)
	return contract.Exists, err
}

// resolveCanonicalSyncContract also returns the current canonical repository
// projection contract. Recovery must use this value, rather than the stale
// invocation YAML, so a removed unrelated suite/architecture cannot be
// resurrected and a newly configured sibling dimension is preserved when a
// shared repository root is reconciled.
func resolveCanonicalSyncContract(canonical *state.Store, runtimeConfig *config.Config, selectedRepo config.Repo, selectedSource config.Upstream, expectedSHA string) (canonicalSyncContract, error) {
	if !syncProgressSHA256Pattern.MatchString(expectedSHA) {
		return canonicalSyncContract{}, errors.New("invalid frozen sync selection identity")
	}
	if runtimeConfig == nil || runtimeConfig.Path == "" || runtimeConfig.Root == "" {
		return canonicalSyncContract{}, errors.New("runtime sync configuration path is unavailable")
	}
	currentSHA, err := syncSelectionSHA256(runtimeConfig, selectedRepo, selectedSource)
	if err != nil {
		return canonicalSyncContract{}, err
	}
	if currentSHA != expectedSHA {
		return canonicalSyncContract{}, errors.New("runtime repository/upstream/view or signing-key contract changed during sync")
	}
	reader, err := canonical.OpenPath("config/sow.yaml")
	if errors.Is(err, os.ErrNotExist) {
		return canonicalSyncContract{}, nil
	}
	if err != nil {
		return canonicalSyncContract{}, err
	}
	canonicalConfig, decodeErr := config.Decode(reader)
	closeErr := reader.Close()
	if decodeErr != nil || closeErr != nil {
		return canonicalSyncContract{}, errors.Join(decodeErr, closeErr)
	}
	canonicalConfig.Path = runtimeConfig.Path
	canonicalConfig.Root = runtimeConfig.Root
	var repo config.Repo
	repoFound := false
	for _, candidate := range canonicalConfig.Repos {
		if candidate.ID == selectedRepo.ID {
			repo, repoFound = candidate, true
			break
		}
	}
	var source config.Upstream
	sourceFound := false
	for _, candidate := range canonicalConfig.Upstreams {
		if candidate.ID == selectedSource.ID {
			source, sourceFound = candidate, true
			break
		}
	}
	if !repoFound || !sourceFound || source.Repo != repo.ID || source.Type != selectedSource.Type {
		return canonicalSyncContract{Exists: true}, errors.New("canonical config no longer contains the frozen repo/upstream pair")
	}
	if repo.Type != selectedRepo.Type || source.ID != selectedSource.ID {
		return canonicalSyncContract{Exists: true}, errors.New("canonical config changed the frozen repo/upstream identity")
	}
	for _, arch := range selectedRepo.Arches {
		if !contains(repo.Arches, arch) {
			return canonicalSyncContract{Exists: true}, fmt.Errorf("canonical sync contract removed repository architecture %s", arch)
		}
	}
	for _, arch := range selectedSource.Arches {
		if !contains(selectedRepo.Arches, arch) || !contains(repo.Arches, arch) || !contains(source.Arches, arch) {
			return canonicalSyncContract{Exists: true}, fmt.Errorf("canonical sync contract removed upstream architecture %s", arch)
		}
	}
	contractRepo := repo
	contractRepo.Arches = append([]string(nil), selectedRepo.Arches...)
	if repo.APT != nil {
		if selectedRepo.APT == nil || selectedSource.Suite == "" || !contains(selectedRepo.APT.Suites, selectedSource.Suite) || !contains(repo.APT.Suites, selectedSource.Suite) {
			return canonicalSyncContract{Exists: true}, errors.New("canonical sync contract removed the selected APT suite")
		}
		for _, suite := range selectedRepo.APT.Suites {
			if !contains(repo.APT.Suites, suite) {
				return canonicalSyncContract{Exists: true}, fmt.Errorf("canonical sync contract removed repository suite %s", suite)
			}
		}
		contractRepo.APT = repo.APT.NarrowSuites(selectedRepo.APT.Suites)
	} else if selectedRepo.APT != nil {
		return canonicalSyncContract{Exists: true}, errors.New("canonical sync contract removed APT repository configuration")
	}
	contractSource := source
	contractSource.Arches = append([]string(nil), selectedSource.Arches...)
	selectionSHA, err := syncSelectionSHA256(canonicalConfig, contractRepo, contractSource)
	if err != nil {
		return canonicalSyncContract{Exists: true}, err
	}
	if selectionSHA != expectedSHA {
		return canonicalSyncContract{Exists: true}, errors.New("canonical repository/upstream/view contract changed during sync")
	}
	return canonicalSyncContract{Exists: true, Config: canonicalConfig, Repo: repo, Upstream: source}, nil
}

func reconcileSyncProvenanceTransaction(canonical *state.Store, source config.Upstream, operation *syncOperation, progress *syncProgress) error {
	if progress == nil || progress.ProvenanceTransaction == "" {
		return nil
	}
	record, exists, err := canonical.Transaction(progress.ProvenanceTransaction)
	if err != nil {
		return err
	}
	if !exists {
		if progress.ProvenanceCommit != "" {
			return errors.New("committed sync progress names a missing provenance transaction")
		}
		return nil
	}
	wantMessage := syncProvenanceTransactionMessage(source, progress.ProvenanceInputSHA256)
	if record.Operation != "sync" || record.Message != wantMessage {
		return errors.New("provenance transaction does not match durable sync input identity")
	}
	switch record.Phase {
	case "complete":
		if record.Commit.IsZero() {
			return errors.New("completed provenance transaction has no commit")
		}
		if progress.ProvenanceCommit != "" && progress.ProvenanceCommit != record.Commit.String() {
			return errors.New("provenance progress commit differs from its local transaction")
		}
		advanceSyncProgress(progress, syncPhaseProvenanceCommitted, record.Commit.String(), "", false)
		return operation.Write(progress)
	case "aborted":
		if progress.ProvenanceCommit != "" {
			return errors.New("aborted provenance transaction conflicts with committed sync progress")
		}
		progress.ProvenanceTransaction = ""
		advanceSyncProgress(progress, syncPhasePrepared, "", "", false)
		return operation.Write(progress)
	default:
		return fmt.Errorf("provenance transaction remains %s after canonical recovery", record.Phase)
	}
}

func missingPresentCandidates(canonical *state.Store, repo config.Repo, source config.Upstream, journal *syncJournal) ([]syncer.Candidate, error) {
	// Only digests are retained. Candidate bodies stay in the disk journal and
	// are read again solely for the actual missing change set.
	type need struct {
		leafArches []string
		view       string
		component  string
		name       string
		version    string
		size       int64
		debugInfo  bool
		required   int
		found      int
	}
	wanted := make(map[string]*need)
	if err := journal.ForEach(func(record syncJournalRecord) error {
		if record.Present != nil {
			candidate := record.Present.Candidate
			leafArches := []string{candidate.Arch}
			if repo.Type == "yum" {
				leafArches = rpmLeafArches(repo, candidate.Arch, source.Arches)
			} else if candidate.Arch == "all" {
				leafArches = append([]string(nil), source.Arches...)
			}
			if len(leafArches) == 0 {
				return fmt.Errorf("present %s package architecture %s has no selected target leaf", candidate.Format, candidate.Arch)
			}
			component := ""
			if candidate.Format == "deb" {
				var err error
				component, err = syncCandidateComponent(candidate, repo, source)
				if err != nil {
					return err
				}
			}
			wanted[candidate.SHA256] = &need{
				leafArches: leafArches, view: packageDestinationView(repo, candidate.DebugInfo),
				component: component, name: candidate.Name, version: candidate.Version,
				size: candidate.Size, debugInfo: candidate.DebugInfo, required: len(leafArches),
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if len(wanted) == 0 {
		return nil, nil
	}
	oses := []string{"el" + fmt.Sprint(repo.OS.Major)}
	if repo.Type == "apt" {
		oses = []string{source.Suite}
	}
viewScan:
	for _, viewName := range []string{"beta", "stable"} {
		for _, osName := range oses {
			for _, arch := range source.Arches {
				if len(wanted) == 0 {
					break viewScan
				}
				ref, err := state.ViewRef(viewName, repo.ID, osName, arch)
				if err != nil {
					return nil, err
				}
				commit, exists, err := canonical.Ref(ref)
				if err != nil {
					return nil, err
				}
				if !exists {
					continue
				}
				viewPath, err := state.ViewPath(viewName, repo.ID, osName, arch)
				if err != nil {
					return nil, err
				}
				reader, err := canonical.OpenPathAt(commit, viewPath)
				if err != nil {
					return nil, err
				}
				viewReader := views.NewReader(reader)
				for {
					entry, readErr := viewReader.Next()
					if errors.Is(readErr, io.EOF) {
						break
					}
					if readErr != nil {
						reader.Close()
						return nil, readErr
					}
					if candidateNeed := wanted[entry.SHA256]; candidateNeed != nil && candidateNeed.view == viewName &&
						contains(candidateNeed.leafArches, arch) &&
						entry.Name == candidateNeed.name && entry.Version == candidateNeed.version && entry.Size == candidateNeed.size &&
						entry.Pool == repo.DefaultPool && entry.DebugInfo == candidateNeed.debugInfo &&
						(repo.Type != "apt" || aptViewEntryComponent(entry.Path, repo, source.Suite) == candidateNeed.component) {
						candidateNeed.found++
						if candidateNeed.found >= candidateNeed.required {
							delete(wanted, entry.SHA256)
						}
					}
				}
				if err := reader.Close(); err != nil {
					return nil, err
				}
			}
		}
	}
	result := make([]syncer.Candidate, 0, len(wanted))
	if err := journal.ForEach(func(record syncJournalRecord) error {
		if record.Present != nil {
			if wanted[record.Present.Candidate.SHA256] != nil {
				result = append(result, record.Present.Candidate)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SHA256 < result[j].SHA256 })
	return result, nil
}

func aptViewEntryComponent(entryPath string, repo config.Repo, suite string) string {
	relative := entryPath
	prefix := strings.TrimSuffix(repo.Path, "/")
	if prefix != "" {
		prefix += "/"
		if !strings.HasPrefix(relative, prefix) {
			return ""
		}
		relative = strings.TrimPrefix(relative, prefix)
	}
	parts := strings.Split(relative, "/")
	if len(parts) >= 3 && parts[0] == "pool" && repo.APT.HasComponent(suite, parts[1]) {
		return parts[1]
	}
	return ""
}

type stagedSyncInputs struct {
	paths       []string
	byComponent map[string][]string
	expected    map[string]repository.Object
}

func verifyExpectedSyncInput(input, sha256 string, size int64, expected map[string]repository.Object) error {
	if expected == nil {
		return nil
	}
	object, exists := expected[input]
	if !exists {
		return fmt.Errorf("sync input %s has no authenticated candidate identity", filepath.Base(input))
	}
	if object.HashString() != sha256 || object.Size != size {
		return fmt.Errorf("sync input %s differs from authenticated candidate %s/%d", filepath.Base(input), object.HashString(), object.Size)
	}
	return nil
}

func stageSyncInputs(ctx context.Context, txDir string, pool *repository.Store, repo config.Repo, source config.Upstream, journal *syncJournal, missing []syncer.Candidate) (stagedSyncInputs, error) {
	result := stagedSyncInputs{
		paths:       make([]string, 0, len(missing)),
		byComponent: make(map[string][]string),
		expected:    make(map[string]repository.Object),
	}
	stage := func(candidate syncer.Candidate, filename string) error {
		digest, err := repository.ParseDigest(candidate.SHA256)
		if err != nil {
			return err
		}
		object := repository.Object{SHA256: digest, Size: candidate.Size}
		basename, err := syncCandidateBasename(candidate)
		if err != nil {
			return err
		}
		dir := filepath.Join(txDir, "inputs", candidate.SHA256[:16])
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		destination := filepath.Join(dir, basename)
		if err := os.Link(filename, destination); err != nil {
			return fmt.Errorf("hardlink verified sync input %s: %w", candidate.SHA256, err)
		}
		result.paths = append(result.paths, destination)
		result.expected[destination] = object
		if candidate.Format == "deb" {
			component, err := syncCandidateComponent(candidate, repo, source)
			if err != nil {
				return err
			}
			result.byComponent[component] = append(result.byComponent[component], destination)
		}
		return nil
	}
	if err := journal.ForEach(func(record syncJournalRecord) error {
		if record.Downloaded == nil {
			return nil
		}
		candidate := record.Downloaded.Candidate
		digest, err := repository.ParseDigest(candidate.SHA256)
		if err != nil {
			return err
		}
		object := repository.Object{SHA256: digest, Size: candidate.Size}
		if _, err := pool.ImportExpected(ctx, record.Downloaded.Path, object); err != nil {
			return fmt.Errorf("bind downloaded artifact %s to authenticated candidate: %w", candidate.SHA256, err)
		}
		return stage(candidate, pool.ObjectPath(digest))
	}); err != nil {
		return stagedSyncInputs{}, err
	}
	for _, candidate := range missing {
		digest, err := repository.ParseDigest(candidate.SHA256)
		if err != nil {
			return stagedSyncInputs{}, err
		}
		object := repository.Object{SHA256: digest, Size: candidate.Size}
		if err := pool.Verify(ctx, object); err != nil {
			return stagedSyncInputs{}, fmt.Errorf("verify present CAS object %s: %w", candidate.SHA256, err)
		}
		if err := stage(candidate, pool.ObjectPath(digest)); err != nil {
			return stagedSyncInputs{}, err
		}
	}
	sort.Strings(result.paths)
	for component := range result.byComponent {
		sort.Strings(result.byComponent[component])
	}
	return result, nil
}

func syncCandidateBasename(candidate syncer.Candidate) (string, error) {
	parsed, err := url.Parse(candidate.URL)
	if err != nil {
		return "", err
	}
	decoded, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil {
		return "", err
	}
	basename := path.Base(decoded)
	wantedSuffix := "." + candidate.Format
	if basename == "." || basename == "/" || strings.ContainsAny(basename, "%?#\\\x00\t\r\n") || !strings.HasSuffix(strings.ToLower(basename), wantedSuffix) {
		return "", fmt.Errorf("upstream candidate has unsafe %s basename", candidate.Format)
	}
	return basename, nil
}

func syncCandidateComponent(candidate syncer.Candidate, repo config.Repo, source config.Upstream) (string, error) {
	parsed, err := url.Parse(candidate.URL)
	if err != nil {
		return "", err
	}
	base, err := url.Parse(source.URL)
	if err != nil {
		return "", err
	}
	decoded, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil {
		return "", err
	}
	basePath, err := url.PathUnescape(base.EscapedPath())
	if err != nil {
		return "", err
	}
	basePath = strings.TrimSuffix(basePath, "/") + "/"
	if parsed.Scheme != base.Scheme || parsed.Host != base.Host || !strings.HasPrefix(decoded, basePath) {
		return "", fmt.Errorf("APT candidate %s is outside upstream base URL", candidate.Name)
	}
	relative := strings.TrimPrefix(decoded, basePath)
	parts := strings.Split(relative, "/")
	if repo.APT == nil {
		return "", fmt.Errorf("cannot infer APT component for %s", candidate.Name)
	}
	sourceComponents := source.Components
	if len(sourceComponents) == 0 {
		// Config validation applies this same suite-exact default. Keep the
		// low-level replay helper equivalent for tests and recovered values built
		// programmatically rather than treating omission as "deny every component".
		sourceComponents = repo.APT.ComponentsForSuite(source.Suite)
	}
	if len(parts) >= 3 && parts[0] == "pool" && repo.APT.HasComponent(source.Suite, parts[1]) && contains(sourceComponents, parts[1]) {
		return parts[1], nil
	}
	return "", fmt.Errorf("cannot infer APT component for %s", candidate.Name)
}
