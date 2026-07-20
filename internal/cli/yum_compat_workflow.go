package cli

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/klauspost/compress/zstd"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

const (
	yumCompatibilityAdoptionSchema  = "sow-yum-compatibility-adoption/v1"
	yumCompatibilityMetadataPolicy  = "legacy-repomd-primary-membership-hint-only"
	yumCompatibilityCandidateSchema = "sow-yum-compatibility-candidate/v1"
	yumCompatibilityJournalSchema   = "sow-yum-compatibility-candidate-journal/v2"
)

type yumCompatibilityAdoption struct {
	Schema                  string `json:"schema"`
	ID                      string `json:"id"`
	Root                    string `json:"root"`
	Carrier                 string `json:"carrier"`
	OwnerRepo               string `json:"owner_repo"`
	View                    string `json:"view"`
	OS                      string `json:"os"`
	Arch                    string `json:"arch"`
	BaselineRef             string `json:"baseline_ref"`
	BaselineCommit          string `json:"baseline_commit"`
	BaselineManifestSHA256  string `json:"baseline_manifest_sha256"`
	BaselineManifestGit     string `json:"baseline_manifest_git_blob"`
	BaselineManifestSize    int64  `json:"baseline_manifest_size"`
	SourceManifestSHA256    string `json:"source_manifest_sha256"`
	SourceManifestGit       string `json:"source_manifest_git_blob"`
	SourceManifestSize      int64  `json:"source_manifest_size"`
	PackageTrustSHA256      string `json:"package_trust_sha256"`
	PackageTrustGit         string `json:"package_trust_git_blob"`
	PackageTrustSize        int64  `json:"package_trust_size"`
	Packages                int64  `json:"packages"`
	Bytes                   int64  `json:"bytes"`
	LegacyMetadataPolicy    string `json:"legacy_metadata_policy"`
	LegacyRepomdSignature   string `json:"legacy_repomd_signature"`
	CandidateMetadataPolicy string `json:"candidate_metadata_policy"`
}

type yumCompatibilityCandidate struct {
	Schema               string `json:"schema"`
	ID                   string `json:"id"`
	Root                 string `json:"root"`
	Carrier              string `json:"carrier"`
	OwnerRepo            string `json:"owner_repo"`
	SourceRef            string `json:"source_ref"`
	SourceCommit         string `json:"source_commit"`
	SourceManifestSHA256 string `json:"source_manifest_sha256"`
	SourceManifestGit    string `json:"source_manifest_git_blob"`
	SourceManifestSize   int64  `json:"source_manifest_size"`
	AdoptionSHA256       string `json:"adoption_sha256"`
	AdoptionGit          string `json:"adoption_git_blob"`
	AdoptionSize         int64  `json:"adoption_size"`
	PackageTrustSHA256   string `json:"package_trust_sha256"`
	PackageTrustGit      string `json:"package_trust_git_blob"`
	PackageTrustSize     int64  `json:"package_trust_size"`
	// CandidatePath is operator-local context only. It must never participate
	// in the canonical receipt or its confirmation because an S2 identity must
	// be portable between machines and restore locations.
	CandidatePath           string `json:"-"`
	CandidateManifestSHA256 string `json:"candidate_manifest_sha256"`
	CandidateManifestGit    string `json:"candidate_manifest_git_blob"`
	CandidateManifestSize   int64  `json:"candidate_manifest_size"`
	RepomdSHA256            string `json:"repomd_sha256"`
	RepositoryKeySHA256     string `json:"repository_key_sha256"`
	RepositoryTrustSHA256   string `json:"repository_trust_sha256"`
	RepositoryTrustGit      string `json:"repository_trust_git_blob"`
	RepositoryTrustSize     int64  `json:"repository_trust_size"`
	Packages                int64  `json:"packages"`
	Bytes                   int64  `json:"bytes"`
	FreezeConfirm           string `json:"freeze_confirm"`
}

type yumCompatibilityCandidateJournal struct {
	Schema          string `json:"schema"`
	ID              string `json:"id"`
	Phase           string `json:"phase"`
	Output          string `json:"output"`
	Stage           string `json:"stage"`
	PendingManifest string `json:"pending_manifest"`
	PendingReceipt  string `json:"pending_receipt"`
	// The candidate journal is local crash state, not a portable canonical
	// receipt.  Persisting the directory identity prevents a later process from
	// accepting a byte-for-byte clone placed at the same pathname after the
	// original parent was renamed away.
	ParentPath   string `json:"parent_path"`
	ParentDevice uint64 `json:"parent_device"`
	ParentInode  uint64 `json:"parent_inode"`
}

type yumCompatibilityCutoverJournal struct {
	Schema      string `json:"schema"`
	ID          string `json:"id"`
	Action      string `json:"action"`
	Phase       string `json:"phase"`
	EventSHA256 string `json:"event_sha256"`
	ServingLink string `json:"serving_link"`
	FromTarget  string `json:"from_target"`
	ToTarget    string `json:"to_target"`
}

const (
	yumCompatibilityCutoverJournalSchema = "sow-yum-compatibility-cutover-journal/v1"
	yumCompatibilityCutoverPrepared      = "prepared"
	yumCompatibilityCutoverCommitted     = "state-committed"
)

const (
	yumCompatibilityCandidateBuilding      = "building"
	yumCompatibilityCandidatePrepared      = "prepared"
	yumCompatibilityCandidateTreeReady     = "tree-ready"
	yumCompatibilityCandidateManifestReady = "manifest-ready"
)

type yumCompatibilityCutoverState struct {
	Stage  yumCompatibilityStage
	Active bool
	Events []yumCompatibilityCutoverEvent
	Last   yumCompatibilityCutoverEvent
}

func runCompatibility(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stdout, `Usage: sow compatibility <verb> [options]

Verbs:
  yum-adopt                  verify the zero-byte carrier baseline and create immutable cross-EL CAS/source state
  yum-candidate              build an isolated clean signed candidate without changing the served legacy root
  yum-freeze                 bind a confirmed candidate into the immutable compatibility witness
  yum-cutover                append S3 authority and atomically flip the controlled local serving link
  yum-rollback               append rollback authority and atomically return the serving link to raw S0
  yum-consumer-preflight     read public endpoints and issue a short-lived Pigsty cutover receipt
  yum-consumer-receipt-check validate that receipt and current local/canonical authority without network access

Workflow mutation verbs do not access cloud storage or CDN resources. The
consumer preflight performs read-only public CDN requests; receipt-check is
network-free.`)
		return nil
	}
	switch args[0] {
	case "yum-adopt":
		return runYUMCompatibilityAdopt(ctx, args[1:], stdout, stderr)
	case "yum-candidate":
		return runYUMCompatibilityCandidate(ctx, args[1:], stdout, stderr)
	case "yum-freeze":
		return runYUMCompatibilityFreeze(ctx, args[1:], stdout, stderr)
	case "yum-cutover":
		return runYUMCompatibilityCutover(ctx, args[1:], stdout, stderr)
	case "yum-rollback":
		return runYUMCompatibilityRollback(ctx, args[1:], stdout, stderr)
	case "yum-consumer-preflight":
		return runYUMConsumerPreflight(ctx, args[1:], stdout, stderr)
	case "yum-consumer-receipt-check":
		return runYUMConsumerReceiptCheck(ctx, args[1:], stdout, stderr)
	default:
		return withExitCode(ExitUsage, "unknown compatibility verb %q", args[0])
	}
}

type yumCompatibilityWorkflow struct {
	cfg        *config.Config
	projection config.YUMCompatibilityProjection
	carrier    config.Repo
	owner      config.Repo
	lock       *state.Lock
	root       *yumCompatibilityRepositoryBinding
	// readRoot is set only by capability-bound read-side admission. It never
	// grants mutation authority; baseline scans remain rooted at this retained
	// repository even if the public pathname is renamed concurrently.
	readRoot *os.Root
	// mutationHook is an unexported deterministic fault-injection seam. It is
	// invoked only inside a bound mutation primitive, after ordinary admission
	// checks and immediately before the primitive writes through an already-open
	// directory capability. Production workflows always leave it nil.
	mutationHook func(string) error
}

type yumCompatibilityRepositoryBinding struct {
	path          string
	root          *os.Root
	file          *os.File
	identity      os.FileInfo
	stateRoot     *os.Root
	stateFile     *os.File
	stateIdentity os.FileInfo
}

func (workflow *yumCompatibilityWorkflow) bindMutationRoots(lock *state.Lock) error {
	if workflow == nil || workflow.cfg == nil || lock == nil {
		return errors.New("YUM compatibility mutation roots are unavailable")
	}
	if err := lock.Validate(); err != nil {
		return err
	}
	root, identity, err := openBoundYUMCompatibilityRepositoryRoot(workflow.cfg.Root)
	if err != nil {
		return err
	}
	file, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return err
	}
	stateInfo, err := root.Lstat(config.StateDirectory)
	if err != nil || stateInfo.Mode()&os.ModeSymlink != 0 || !stateInfo.IsDir() {
		_ = file.Close()
		_ = root.Close()
		return errors.Join(err, errors.New("YUM compatibility state root is absent, symlinked, or not a directory"))
	}
	stateRoot, err := root.OpenRoot(config.StateDirectory)
	if err != nil {
		_ = file.Close()
		_ = root.Close()
		return err
	}
	stateBound, err := stateRoot.Stat(".")
	if err != nil || !os.SameFile(stateInfo, stateBound) {
		_ = stateRoot.Close()
		_ = file.Close()
		_ = root.Close()
		return errors.Join(err, errors.New("YUM compatibility state root changed while binding"))
	}
	stateFile, err := stateRoot.Open(".")
	if err != nil {
		_ = stateRoot.Close()
		_ = file.Close()
		_ = root.Close()
		return err
	}
	workflow.lock = lock
	workflow.root = &yumCompatibilityRepositoryBinding{
		path: workflow.cfg.Root, root: root, file: file, identity: identity,
		stateRoot: stateRoot, stateFile: stateFile, stateIdentity: stateBound,
	}
	if err := workflow.validateMutationRoots(); err != nil {
		_ = workflow.closeMutationRoots()
		return err
	}
	return nil
}

func (workflow yumCompatibilityWorkflow) validateMutationRoots() error {
	if workflow.lock == nil || workflow.root == nil || workflow.root.root == nil || workflow.root.file == nil || workflow.root.identity == nil ||
		workflow.root.stateRoot == nil || workflow.root.stateFile == nil || workflow.root.stateIdentity == nil {
		return errors.New("YUM compatibility mutation root binding is unavailable")
	}
	if err := workflow.lock.Validate(); err != nil {
		return err
	}
	throughRoot, rootErr := workflow.root.root.Stat(".")
	throughFile, fileErr := workflow.root.file.Stat()
	throughStateRoot, stateRootErr := workflow.root.stateRoot.Stat(".")
	throughStateFile, stateFileErr := workflow.root.stateFile.Stat()
	atPath, pathErr := os.Lstat(workflow.root.path)
	stateInfo, stateErr := workflow.root.root.Lstat(config.StateDirectory)
	if rootErr != nil || fileErr != nil || stateRootErr != nil || stateFileErr != nil || pathErr != nil || stateErr != nil ||
		atPath.Mode()&os.ModeSymlink != 0 || !atPath.IsDir() || stateInfo.Mode()&os.ModeSymlink != 0 || !stateInfo.IsDir() ||
		!os.SameFile(workflow.root.identity, throughRoot) || !os.SameFile(workflow.root.identity, throughFile) || !os.SameFile(workflow.root.identity, atPath) ||
		!os.SameFile(workflow.root.stateIdentity, throughStateRoot) || !os.SameFile(workflow.root.stateIdentity, throughStateFile) || !os.SameFile(workflow.root.stateIdentity, stateInfo) {
		return errors.Join(rootErr, fileErr, stateRootErr, stateFileErr, pathErr, stateErr, errors.New("repository or state root was replaced after compatibility lock acquisition"))
	}
	return nil
}

func (workflow *yumCompatibilityWorkflow) closeMutationRoots() error {
	if workflow == nil || workflow.root == nil {
		return nil
	}
	stateFileErr := workflow.root.stateFile.Close()
	stateRootErr := workflow.root.stateRoot.Close()
	fileErr := workflow.root.file.Close()
	rootErr := workflow.root.root.Close()
	workflow.root, workflow.lock = nil, nil
	return errors.Join(stateFileErr, stateRootErr, fileErr, rootErr)
}

// propagateYUMCompatibilityCleanup treats teardown of retained directory
// capabilities and private canonical workspaces as part of command success.
// An existing business failure keeps its exit class while the cleanup failure
// is emitted as an explicit diagnostic, matching state-lock teardown.
func propagateYUMCompatibilityCleanup(subject string, cleanup func() error, resultErr *error, stderr io.Writer) {
	if cleanup == nil || resultErr == nil {
		return
	}
	cleanupErr := cleanup()
	if cleanupErr == nil {
		return
	}
	if *resultErr != nil {
		if stderr != nil {
			fmt.Fprintf(stderr, "warning: %s: %v\n", subject, cleanupErr)
		}
		return
	}
	*resultErr = withExitCode(ExitInternal, "%s: %v", subject, cleanupErr)
}

func requireYUMCompatibilityMutationBoundary(workflow yumCompatibilityWorkflow, operation string) error {
	if err := workflow.validateMutationRoots(); err != nil {
		return fmt.Errorf("%s refused because the bound repository/state root changed: %w", operation, err)
	}
	return nil
}

func loadYUMCompatibilityWorkflow(values commonFlags, id string) (yumCompatibilityWorkflow, error) {
	var result yumCompatibilityWorkflow
	if id == "" {
		return result, withExitCode(ExitUsage, "--id is required")
	}
	baseline, err := readCanonicalConfigBaseline(values.configPath, values.root)
	if err != nil {
		return result, withExitCode(ExitVerification, "%v", err)
	}
	cfg, err := config.Load(values.configPath, values.root)
	if err != nil {
		return result, withExitCode(ExitConfig, "%v", err)
	}
	setCanonicalConfigBaseline(cfg, baseline)
	if err := validateCanonicalHistoryContracts(cfg); err != nil {
		return result, withExitCode(ExitConflict, "%v", err)
	}
	if err := validateCanonicalPoolContracts(cfg); err != nil {
		return result, withExitCode(ExitConflict, "%v", err)
	}
	if err := validateCanonicalYUMCompatibilityContracts(cfg); err != nil {
		return result, withExitCode(ExitConflict, "%v", err)
	}
	if values.workers < 1 || values.workers > maxCLIWorkers || values.chunk < 1 {
		return result, withExitCode(ExitUsage, "--workers must be in 1..%d and --chunk-entries must be positive", maxCLIWorkers)
	}
	projection, exists, err := config.YUMCompatibilityProjectionByID(cfg.CompatibilityProjections, id)
	if err != nil || !exists {
		return result, withExitCode(ExitConfig, "compatibility projection %q is unavailable: %v", id, err)
	}
	carrier, carrierExists := cfg.RepoByName(projection.Carrier)
	owner, ownerExists := cfg.RepoByName(projection.Source.Repo)
	if !carrierExists || !ownerExists {
		return result, withExitCode(ExitConfig, "compatibility projection %s carrier or owner is unavailable", id)
	}
	return yumCompatibilityWorkflow{cfg: cfg, projection: projection, carrier: carrier, owner: owner}, nil
}

func addYUMCompatibilityWorkflowFlags(fs *flag.FlagSet, values *commonFlags, id *string) {
	fs.StringVar(&values.configPath, "config", "sow.yaml", "path to strict schema-v1 configuration")
	fs.StringVar(&values.root, "root", "", "override repository root from config")
	fs.IntVar(&values.workers, "workers", min(runtime.NumCPU(), maxCLIWorkers), "bounded worker count (1-64)")
	fs.IntVar(&values.chunk, "chunk-entries", 4096, "entries per in-memory sorted run")
	fs.BoolVar(&values.recover, "recover", false, "recover an interrupted compatibility transaction")
	fs.StringVar(id, "id", "", "exact compatibility projection ID")
}

func runYUMCompatibilityAdopt(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("compatibility yum-adopt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	id := ""
	addYUMCompatibilityWorkflowFlags(fs, &values, &id)
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow compatibility yum-adopt --id ID [--config sow.yaml] [--root DIR] [--workers N] [--chunk-entries N] [--recover]")
	}
	if help, err := parseFlagSet(fs, args); err != nil || help {
		return err
	}
	if fs.NArg() != 0 || len(values.repos.values()) != 0 || len(values.oses.values()) != 0 || len(values.arches.values()) != 0 {
		return withExitCode(ExitUsage, "yum-adopt accepts --id, not ordinary repo/os/arch selectors")
	}
	workflow, err := loadYUMCompatibilityWorkflow(values, id)
	if err != nil {
		return err
	}
	lock, err := state.AcquireLock(workflow.cfg.StatePath(), "compatibility-yum-adopt", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := workflow.bindMutationRoots(lock); err != nil {
		return withExitCode(ExitConflict, "bind compatibility repository/state roots: %v", err)
	}
	defer propagateYUMCompatibilityCleanup("close compatibility root binding", workflow.closeMutationRoots, &resultErr, stderr)
	if err := requireYUMCompatibilityMutationBoundary(workflow, "start yum-adopt"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireNoPendingYUMCompatibilityCutoverJournalsBound(workflow, ""); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	workspace, err := newYUMCompatibilityCanonicalWorkspace(workflow)
	if err != nil {
		return withExitCode(ExitConflict, "snapshot bound yum-adopt canonical state: %v", err)
	}
	defer propagateYUMCompatibilityCleanup("remove compatibility canonical workspace", workspace.Close, &resultErr, stderr)
	canonical := workspace.Store()
	if err := prepareCanonicalStateCore(ctx, canonical, values.recover, stdout); err != nil {
		return err
	}
	if _, err := workspace.Commit(workflow, "recover yum-adopt canonical state"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "prepare yum-adopt canonical state"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireCanonicalConfigBaseline(workflow.cfg, canonical); err != nil {
		return withExitCode(ExitConflict, "canonical config changed while yum-adopt waited for lock: %v", err)
	}
	txDir, err := workspace.NewTransactionDir("yum-compat-adopt-")
	if err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	defer workspace.RemoveTransaction(txDir)
	if err := requireYUMCompatibilityMutationBoundary(workflow, "create yum-adopt transaction directory"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	commit, changed, adoption, err := adoptYUMCompatibilitySource(ctx, workflow, canonical, txDir, values)
	if err != nil {
		return withExitCode(ExitVerification, "adopt YUM compatibility source: %v", err)
	}
	if err := workspace.RemoveTransaction(txDir); err != nil {
		return withExitCode(ExitInternal, "remove yum-adopt private transaction: %v", err)
	}
	if _, err := workspace.Commit(workflow, "commit yum-adopt canonical state"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	fmt.Fprintf(stdout, "compatibility adopted id=%s commit=%s changed=%t packages=%d bytes=%d source_sha256=%s legacy_metadata=%s served_tree_rewritten=false\n",
		id, commit, changed, adoption.Packages, adoption.Bytes, adoption.SourceManifestSHA256, adoption.LegacyMetadataPolicy)
	return nil
}

func adoptYUMCompatibilitySource(ctx context.Context, workflow yumCompatibilityWorkflow, canonical *state.Store, txDir string, values commonFlags) (resultCommit plumbing.Hash, resultChanged bool, result yumCompatibilityAdoption, resultErr error) {
	if err := requireYUMCompatibilityMutationBoundary(workflow, "enter yum-adopt source transaction"); err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	projection, cfg := workflow.projection, workflow.cfg
	sourceRef, _ := state.YUMCompatibilitySourceRef(projection.ID)
	if existing, exists, err := canonical.Ref(sourceRef); err != nil {
		return plumbing.ZeroHash, false, result, err
	} else if exists {
		record, err := validateYUMCompatibilityAdoptedState(ctx, workflow, canonical, txDir, values)
		return existing, false, record, err
	}
	witnessPath, _ := state.YUMCompatibilityProjectionPath(projection.ID)
	if _, exists, err := readOptionalCanonical(canonical, witnessPath); err != nil || exists {
		return plumbing.ZeroHash, false, result, errors.Join(err, errors.New("compatibility witness exists before adopted source"))
	}
	baselinePath := filepath.Join(txDir, "carrier-baseline.tsv")
	baselineRef, baselineCommit, baselineSHA, baselineGit, baselineSize, err := requireYUMCompatibilityCarrierBaseline(ctx, cfg, canonical, workflow.carrier, baselinePath, values)
	if err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	trustBytes, _, err := readStableKeyringBytes(cfg.Path, workflow.owner.YUM.PackageKeyring)
	if err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	keyring, err := yumrepo.ParseRPMPackageKeyring(trustBytes)
	if err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	legacyRoot := filepath.Join(cfg.Root, filepath.FromSlash(projection.Root))
	if err := validateLegacyYUMCompatibilityRepomd(ctx, legacyRoot); err != nil {
		return plumbing.ZeroHash, false, result, fmt.Errorf("validate complete legacy repomd evidence: %w", err)
	}
	flat := filepath.Join(txDir, "legacy-flat.tsv")
	if _, err := writeSortedLegacyYUMCompatibilityManifest(ctx, legacyRoot, flat, keyring); err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	casWorkspace, err := newYUMCompatibilityCASWorkspace()
	if err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	defer func() { resultErr = errors.Join(resultErr, casWorkspace.Close()) }()
	pool := casWorkspace.Store()
	if err := requireYUMCompatibilityMutationBoundary(workflow, "open yum-adopt CAS"); err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	sourcePath := filepath.Join(txDir, "source.tsv")
	packages, bytesTotal, err := importYUMCompatibilitySource(ctx, pool, legacyRoot, flat, sourcePath, projection.Source.Arch, values.chunk, txDir, keyring)
	if err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	if err := casWorkspace.TrackManifest(sourcePath); err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	if err := casWorkspace.Commit(ctx, workflow, "commit yum-adopt CAS"); err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "import yum-adopt CAS objects"); err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	aliases := filepath.Join(txDir, "aliases.tsv")
	if aliasPackages, aliasBytes, err := writeYUMCompatibilityAliases(sourcePath, aliases); err != nil || aliasPackages != packages || aliasBytes != bytesTotal {
		return plumbing.ZeroHash, false, result, errors.Join(err, errors.New("adopted source alias identity changed"))
	}
	if err := requireManifestFilesEqual(flat, aliases); err != nil {
		return plumbing.ZeroHash, false, result, fmt.Errorf("legacy flat set differs from adopted canonical aliases: %w", err)
	}
	trustPath := filepath.Join(txDir, "package-trust.pgp")
	if err := os.WriteFile(trustPath, trustBytes, 0o600); err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	sourceSHA, sourceGit, sourceSize, err := fileSHA256AndGitBlob(sourcePath)
	if err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	trustSHA, trustGit, trustSize, err := fileSHA256AndGitBlob(trustPath)
	if err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	result = yumCompatibilityAdoption{
		Schema: yumCompatibilityAdoptionSchema, ID: projection.ID, Root: projection.Root, Carrier: projection.Carrier,
		OwnerRepo: projection.Source.Repo, View: projection.Source.View, OS: projection.Source.OS, Arch: projection.Source.Arch,
		BaselineRef: baselineRef.String(), BaselineCommit: baselineCommit.String(), BaselineManifestSHA256: baselineSHA,
		BaselineManifestGit: baselineGit.String(), BaselineManifestSize: baselineSize,
		SourceManifestSHA256: sourceSHA, SourceManifestGit: sourceGit.String(), SourceManifestSize: sourceSize,
		PackageTrustSHA256: trustSHA, PackageTrustGit: trustGit.String(), PackageTrustSize: trustSize,
		Packages: packages, Bytes: bytesTotal, LegacyMetadataPolicy: yumCompatibilityMetadataPolicy,
		LegacyRepomdSignature: "not-claimed", CandidateMetadataPolicy: "clean-signed-three-xml-gzip",
	}
	adoptionBody, err := json.Marshal(result)
	if err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	adoptionBody = append(adoptionBody, '\n')
	adoptionPath := filepath.Join(txDir, "adoption.json")
	if err := os.WriteFile(adoptionPath, adoptionBody, 0o600); err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	// Re-scan immediately before the canonical commit. CAS imports are allowed
	// to leave safe orphans on failure, but a changed served legacy root can
	// never be admitted as a different source than its S0 baseline.
	if _, _, _, _, _, err := requireYUMCompatibilityCarrierBaseline(ctx, cfg, canonical, workflow.carrier, filepath.Join(txDir, "carrier-before-commit.tsv"), values); err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	canonicalSource, _ := state.YUMCompatibilitySourcePath(projection.ID)
	canonicalAdoption, _ := state.YUMCompatibilityAdoptionPath(projection.ID)
	canonicalTrust, _ := state.YUMCompatibilityPackageTrustPath(projection.ID)
	configStage, _, err := stageCanonicalConfig(cfg, txDir)
	if err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "commit yum-adopt canonical state"); err != nil {
		return plumbing.ZeroHash, false, result, err
	}
	commit, changed, err := applyCanonicalConfig(ctx, cfg, canonical, "yum-compatibility-adopt", "sow compatibility yum-adopt: "+projection.ID,
		map[string]string{"config/sow.yaml": configStage, canonicalSource: sourcePath, canonicalAdoption: adoptionPath, canonicalTrust: trustPath},
		[]state.RefUpdate{{Name: sourceRef, Immutable: true}}, state.ApplyOptions{})
	if err != nil {
		return commit, changed, result, err
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "finish yum-adopt canonical commit"); err != nil {
		return commit, changed, result, err
	}
	if _, _, _, _, _, err := requireYUMCompatibilityCarrierBaseline(ctx, cfg, canonical, workflow.carrier, filepath.Join(txDir, "carrier-after-commit.tsv"), values); err != nil {
		return commit, changed, result, err
	}
	if _, err := validateYUMCompatibilityAdoptedState(ctx, workflow, canonical, txDir, values); err != nil {
		return commit, changed, result, err
	}
	return commit, changed, result, nil
}

func requireYUMCompatibilityCarrierBaseline(ctx context.Context, cfg *config.Config, canonical *state.Store, carrier config.Repo, destination string, values commonFlags) (plumbing.ReferenceName, plumbing.Hash, string, plumbing.Hash, int64, error) {
	return requireYUMCompatibilityCarrierBaselineWithRoot(ctx, cfg, canonical, carrier, destination, values, nil)
}

func requireYUMCompatibilityCarrierBaselineWithRoot(ctx context.Context, cfg *config.Config, canonical *state.Store, carrier config.Repo, destination string, values commonFlags, root *os.Root) (plumbing.ReferenceName, plumbing.Hash, string, plumbing.Hash, int64, error) {
	ref, err := state.RepoRef(carrier.ID)
	if err != nil {
		return "", plumbing.ZeroHash, "", plumbing.ZeroHash, 0, err
	}
	commit, exists, err := canonical.Ref(ref)
	if err != nil || !exists {
		return "", plumbing.ZeroHash, "", plumbing.ZeroHash, 0, errors.Join(err, fmt.Errorf("S0 carrier baseline ref %s is missing; run sow init first", ref))
	}
	canonicalPath := filepath.ToSlash(filepath.Join("manifests", carrier.ID+".tsv"))
	blob, exists, err := canonical.BlobIdentityAt(commit, canonicalPath)
	if err != nil || !exists {
		return "", plumbing.ZeroHash, "", plumbing.ZeroHash, 0, errors.Join(err, errors.New("S0 carrier baseline manifest is missing"))
	}
	options := manifest.ScanOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Dir(destination)}
	if root == nil {
		_, err = scanRepoManifest(ctx, cfg, carrier, destination, options)
	} else {
		_, err = scanRepoManifestRoot(ctx, root, cfg, carrier, destination, options)
	}
	if err != nil {
		return "", plumbing.ZeroHash, "", plumbing.ZeroHash, 0, err
	}
	expected, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return "", plumbing.ZeroHash, "", plumbing.ZeroHash, 0, err
	}
	actual, err := os.Open(destination)
	if err != nil {
		expected.Close()
		return "", plumbing.ZeroHash, "", plumbing.ZeroHash, 0, err
	}
	diff, diffErr := manifest.Diff(expected, actual, nil)
	closeErr := errors.Join(expected.Close(), actual.Close())
	if diffErr != nil || closeErr != nil || !diff.Clean() {
		return "", plumbing.ZeroHash, "", plumbing.ZeroHash, 0, errors.Join(diffErr, closeErr, fmt.Errorf("served carrier differs from S0 baseline: added=%d removed=%d changed=%d", diff.Added, diff.Removed, diff.Changed))
	}
	sha, actualGit, size, err := fileSHA256AndGitBlob(destination)
	if err != nil || blob.Hash.IsZero() || blob.Hash != actualGit || blob.Size != size {
		return "", plumbing.ZeroHash, "", plumbing.ZeroHash, 0, errors.Join(err, errors.New("S0 carrier baseline blob identity changed"))
	}
	return ref, commit, sha, blob.Hash, size, nil
}

// validateYUMCompatibilityAdoptedState is the single S1 replay gate.  It
// re-proves the current configuration, pinned raw S0 carrier, immutable
// source/adoption/trust blobs, and every CAS/RPM object rather than treating a
// decodable receipt as evidence that adoption still exists.
func validateYUMCompatibilityAdoptedState(ctx context.Context, workflow yumCompatibilityWorkflow, canonical *state.Store, txDir string, values commonFlags) (yumCompatibilityAdoption, error) {
	return validateYUMCompatibilityAdoptedStateWithPool(ctx, workflow, canonical, nil, txDir, values)
}

func validateYUMCompatibilityAdoptedStateWithPool(ctx context.Context, workflow yumCompatibilityWorkflow, canonical *state.Store, pool *repository.Store, txDir string, values commonFlags) (yumCompatibilityAdoption, error) {
	return validateYUMCompatibilityAdoptedStateWithPoolAndHook(ctx, workflow, canonical, pool, txDir, values, nil)
}

func validateYUMCompatibilityAdoptedStateWithPoolAndHook(ctx context.Context, workflow yumCompatibilityWorkflow, canonical *state.Store, pool *repository.Store, txDir string, values commonFlags, beforeFirstCAS func() error) (result yumCompatibilityAdoption, resultErr error) {
	projection, cfg := workflow.projection, workflow.cfg
	sourceRef, err := state.YUMCompatibilitySourceRef(projection.ID)
	if err != nil {
		return result, err
	}
	sourceCommit, exists, err := canonical.Ref(sourceRef)
	if err != nil || !exists || sourceCommit.IsZero() {
		return result, errors.Join(err, fmt.Errorf("S1 source ref %s is missing", sourceRef))
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return result, errors.Join(err, errors.New("canonical HEAD is unavailable for S1 replay"))
	}
	if reachable, reachErr := canonical.IsAncestor(sourceCommit, head); reachErr != nil || !reachable {
		return result, errors.Join(reachErr, fmt.Errorf("S1 source commit %s is not reachable from canonical HEAD", sourceCommit))
	}
	result, err = loadYUMCompatibilityAdoptionAt(canonical, sourceCommit, projection.ID)
	if err != nil {
		return result, err
	}
	if err := requireYUMCompatibilityAdoptionMatchesProjection(result, projection, workflow.carrier); err != nil {
		return result, err
	}

	// The config committed with S1 is part of the adoption contract.  This
	// catches an orphaned/repaired source ref whose receipt happens to decode
	// under a different current topology.
	configBody, configExists, err := readCanonicalConfigBytesAt(canonical, sourceCommit)
	if err != nil || !configExists {
		return result, errors.Join(err, errors.New("S1 commit has no canonical configuration"))
	}
	committedConfig, err := config.Decode(bytes.NewReader(configBody))
	if err != nil {
		return result, fmt.Errorf("decode S1 canonical config: %w", err)
	}
	committedProjection, exists, err := config.YUMCompatibilityProjectionByID(committedConfig.CompatibilityProjections, projection.ID)
	if err != nil || !exists || committedProjection != projection {
		return result, errors.Join(err, errors.New("current compatibility projection differs from S1 canonical config"))
	}

	baselineRef, _ := state.RepoRef(workflow.carrier.ID)
	baselineCommit, exists, err := canonical.Ref(baselineRef)
	if err != nil || !exists || baselineCommit.String() != result.BaselineCommit {
		return result, errors.Join(err, fmt.Errorf("carrier baseline ref %s moved after S1 adoption", baselineRef))
	}
	actualRef, actualBaseline, actualSHA, actualGit, actualSize, err := requireYUMCompatibilityCarrierBaselineWithRoot(ctx, cfg, canonical, workflow.carrier, filepath.Join(txDir, "carrier-s1-replay.tsv"), values, workflow.readRoot)
	if err != nil {
		return result, err
	}
	if actualRef.String() != result.BaselineRef || actualBaseline.String() != result.BaselineCommit || actualSHA != result.BaselineManifestSHA256 || actualGit.String() != result.BaselineManifestGit || actualSize != result.BaselineManifestSize {
		return result, errors.New("current raw carrier does not match the S0 identity pinned by adoption")
	}

	sourcePath, _ := state.YUMCompatibilitySourcePath(projection.ID)
	trustPath, _ := state.YUMCompatibilityPackageTrustPath(projection.ID)
	sourceBlob, sourceExists, err := canonical.BlobIdentityAt(sourceCommit, sourcePath)
	if err != nil || !sourceExists || sourceBlob.Hash.String() != result.SourceManifestGit || sourceBlob.Size != result.SourceManifestSize {
		return result, errors.Join(err, errors.New("S1 source manifest Git identity/size differs from adoption receipt"))
	}
	trustBlob, trustExists, err := canonical.BlobIdentityAt(sourceCommit, trustPath)
	if err != nil || !trustExists || trustBlob.Hash.String() != result.PackageTrustGit || trustBlob.Size != result.PackageTrustSize {
		return result, errors.Join(err, errors.New("S1 package trust Git identity/size differs from adoption receipt"))
	}
	sourceSHA, err := hashYUMCompatibilityCanonicalPathAt(canonical, sourceCommit, sourcePath)
	if err != nil || sourceSHA != result.SourceManifestSHA256 {
		return result, errors.Join(err, errors.New("S1 source manifest SHA-256 differs from adoption receipt"))
	}
	trustBytes, trustSHA, err := readAndHashYUMCompatibilityCanonicalPathAt(canonical, sourceCommit, trustPath, maxSecretBytes)
	if err != nil || trustSHA != result.PackageTrustSHA256 {
		return result, errors.Join(err, errors.New("S1 package trust SHA-256 differs from adoption receipt"))
	}
	keyring, err := yumrepo.ParseRPMPackageKeyring(trustBytes)
	if err != nil || keyring == nil {
		return result, errors.Join(err, errors.New("S1 package trust contains no usable RPM signer"))
	}
	var casWorkspace *yumCompatibilityCASWorkspace
	if pool == nil {
		casWorkspace, err = newYUMCompatibilityCASWorkspace()
		if err != nil {
			return result, err
		}
		defer func() { resultErr = errors.Join(resultErr, casWorkspace.Close()) }()
		localSource := filepath.Join(txDir, "s1-bound-cas-source.tsv")
		if err := copyCanonicalPathAt(canonical, sourceCommit, sourcePath, localSource, result.SourceManifestSize); err != nil {
			return result, err
		}
		if err := casWorkspace.MirrorManifest(ctx, workflow, localSource); err != nil {
			return result, err
		}
		pool = casWorkspace.Store()
	}
	packages, bytesTotal, err := validateYUMCompatibilitySourceCAS(ctx, canonical, sourceCommit, sourcePath, pool, keyring, projection.Source.Arch, txDir, beforeFirstCAS)
	if err != nil {
		return result, err
	}
	if packages != result.Packages || bytesTotal != result.Bytes {
		return result, fmt.Errorf("S1 source counts differ from receipt: packages=%d/%d bytes=%d/%d", packages, result.Packages, bytesTotal, result.Bytes)
	}
	return result, nil
}

func requireYUMCompatibilityAdoptionMatchesProjection(record yumCompatibilityAdoption, projection config.YUMCompatibilityProjection, carrier config.Repo) error {
	wantRef, err := state.RepoRef(carrier.ID)
	if err != nil {
		return err
	}
	if record.ID != projection.ID || record.Root != projection.Root || record.Carrier != projection.Carrier || record.OwnerRepo != projection.Source.Repo ||
		record.View != projection.Source.View || record.OS != projection.Source.OS || record.Arch != projection.Source.Arch || record.BaselineRef != wantRef.String() {
		return errors.New("S1 adoption id/root/carrier/owner/source/baseline ref differs from current projection")
	}
	return nil
}

func hashYUMCompatibilityCanonicalPathAt(canonical *state.Store, commit plumbing.Hash, canonicalPath string) (string, error) {
	reader, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, reader)
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func readAndHashYUMCompatibilityCanonicalPathAt(canonical *state.Store, commit plumbing.Hash, canonicalPath string, maximum int64) ([]byte, string, error) {
	reader, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return nil, "", err
	}
	hasher := sha256.New()
	body, readErr := io.ReadAll(io.TeeReader(io.LimitReader(reader, maximum+1), hasher))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || int64(len(body)) > maximum {
		return nil, "", errors.Join(readErr, closeErr, errors.New("canonical compatibility file exceeds its bound"))
	}
	return body, hex.EncodeToString(hasher.Sum(nil)), nil
}

// captureStableOpenedRegular snapshots one already-opened regular file into a
// private O_EXCL file while hashing the same descriptor. Callers parse and
// verify only the private snapshot, preventing path replacement between hash,
// RPM parsing and signature verification from changing the admitted bytes.
func captureStableOpenedRegular(ctx context.Context, source *os.File, destination string) (string, int64, error) {
	if ctx == nil || source == nil || destination == "" {
		return "", 0, errors.New("stable file capture dependencies are unavailable")
	}
	before, err := source.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return "", 0, errors.Join(err, errors.New("stable file capture source is not regular"))
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}
	committed := false
	defer func() {
		_ = output.Close()
		if !committed {
			_ = os.Remove(destination)
		}
	}()
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, hasher), &contextBoundReader{ctx: ctx, reader: source})
	after, statErr := source.Stat()
	closeErr := errors.Join(output.Sync(), output.Close())
	if copyErr != nil || statErr != nil || closeErr != nil || written != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || !os.SameFile(before, after) {
		return "", 0, errors.Join(copyErr, statErr, closeErr, errors.New("source changed while capturing stable descriptor"))
	}
	committed = true
	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

type contextBoundReader struct {
	ctx    context.Context
	reader io.Reader
}

func captureStablePath(ctx context.Context, source, destination string) (string, int64, error) {
	before, err := os.Lstat(source)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return "", 0, errors.Join(err, errors.New("stable capture source is not a regular non-symlink file"))
	}
	file, err := os.Open(source)
	if err != nil {
		return "", 0, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return "", 0, errors.Join(err, errors.New("stable capture source changed while opening"))
	}
	sha, size, captureErr := captureStableOpenedRegular(ctx, file, destination)
	closeErr := file.Close()
	after, statErr := os.Lstat(source)
	if captureErr != nil || closeErr != nil || statErr != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !os.SameFile(opened, after) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		_ = os.Remove(destination)
		return "", 0, errors.Join(captureErr, closeErr, statErr, errors.New("stable capture source changed while reading"))
	}
	return sha, size, nil
}

func (reader *contextBoundReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func validateYUMCompatibilitySourceCAS(ctx context.Context, canonical *state.Store, commit plumbing.Hash, sourcePath string, pool *repository.Store, keyring openpgp.KeyRing, projectionArch, txDir string, beforeFirstCAS ...func() error) (int64, int64, error) {
	reader, err := canonical.OpenPathAt(commit, sourcePath)
	if err != nil {
		return 0, 0, err
	}
	defer reader.Close()
	if len(beforeFirstCAS) > 1 {
		return 0, 0, errors.New("multiple S1 CAS replacement hooks are unsupported")
	}
	if len(beforeFirstCAS) == 1 && beforeFirstCAS[0] != nil {
		if err := beforeFirstCAS[0](); err != nil {
			return 0, 0, err
		}
	}
	stream := manifest.NewReader(reader)
	var packages, bytesTotal int64
	for {
		entry, nextErr := stream.Next()
		if errors.Is(nextErr, io.EOF) {
			return packages, bytesTotal, nil
		}
		if nextErr != nil {
			return 0, 0, nextErr
		}
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		digest, err := repository.ParseDigest(entry.HashString())
		if err != nil {
			return 0, 0, err
		}
		objectFile, err := pool.Open(digest)
		if err != nil {
			return 0, 0, err
		}
		captured := filepath.Join(txDir, fmt.Sprintf("cas-rpm-%08d.rpm", packages))
		capturedSHA, capturedSize, captureErr := captureStableOpenedRegular(ctx, objectFile, captured)
		closeErr := objectFile.Close()
		if captureErr != nil || closeErr != nil || capturedSHA != entry.HashString() || capturedSize != entry.Size {
			return 0, 0, errors.Join(captureErr, closeErr, fmt.Errorf("CAS RPM %s changed while capturing one stable descriptor", entry.Path))
		}
		info, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: captured, Basename: path.Base(entry.Path)})
		if err != nil || info.Location != entry.Path || info.SHA256 != entry.HashString() || info.Size != entry.Size || info.Arch != projectionArch && info.Arch != "noarch" {
			return 0, 0, errors.Join(err, fmt.Errorf("CAS RPM %s identity/location/architecture differs from S1 manifest", entry.Path))
		}
		packageFile, err := os.Open(captured)
		if err != nil {
			return 0, 0, err
		}
		_, verifyErr := yumrepo.VerifyEmbeddedRPMSignatures(ctx, packageFile, keyring, timeNowUTC())
		closeErr = packageFile.Close()
		if verifyErr != nil || closeErr != nil {
			return 0, 0, errors.Join(verifyErr, closeErr, fmt.Errorf("CAS RPM %s fails pinned S1 package trust", entry.Path))
		}
		if err := os.Remove(captured); err != nil {
			return 0, 0, err
		}
		packages++
		bytesTotal += entry.Size
	}
}

func importYUMCompatibilitySource(ctx context.Context, pool *repository.Store, legacyRoot, flatManifest, destination, projectionArch string, chunkEntries int, tempRoot string, keyring openpgp.KeyRing) (int64, int64, error) {
	if chunkEntries < 1 {
		return 0, 0, errors.New("compatibility source chunk size must be positive")
	}
	flat, err := os.Open(flatManifest)
	if err != nil {
		return 0, 0, err
	}
	defer flat.Close()
	reader := manifest.NewReader(flat)
	runDir, err := os.MkdirTemp(tempRoot, ".yum-compat-source-runs-")
	if err != nil {
		return 0, 0, err
	}
	defer os.RemoveAll(runDir)
	chunk := make([]manifest.Entry, 0, chunkEntries)
	var runs []string
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		sort.Slice(chunk, func(i, j int) bool { return chunk[i].Path < chunk[j].Path })
		for index := 1; index < len(chunk); index++ {
			if chunk[index-1].Path == chunk[index].Path {
				return fmt.Errorf("adopted RPMs collide at canonical location %s", chunk[index].Path)
			}
		}
		name := filepath.Join(runDir, fmt.Sprintf("%08d.tsv", len(runs)))
		file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		for _, entry := range chunk {
			if err := manifest.WriteEntry(file, entry); err != nil {
				_ = file.Close()
				return err
			}
		}
		if err := errors.Join(file.Sync(), file.Close()); err != nil {
			return err
		}
		runs = append(runs, name)
		chunk = chunk[:0]
		return nil
	}
	var packages, bytesTotal int64
	for {
		entry, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return 0, 0, nextErr
		}
		file := filepath.Join(legacyRoot, filepath.FromSlash(entry.Path))
		captured := filepath.Join(tempRoot, fmt.Sprintf("legacy-rpm-%08d.rpm", packages))
		capturedSHA, capturedSize, err := captureStablePath(ctx, file, captured)
		if err != nil || capturedSHA != entry.HashString() || capturedSize != entry.Size {
			return 0, 0, errors.Join(err, fmt.Errorf("RPM %s changed while capturing one stable descriptor", entry.Path))
		}
		info, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: captured, Basename: filepath.Base(file)})
		if err != nil || info.SHA256 != entry.HashString() || info.Size != entry.Size {
			return 0, 0, errors.Join(err, fmt.Errorf("RPM %s changed after legacy membership/signature verification", entry.Path))
		}
		if info.Arch != projectionArch && info.Arch != "noarch" {
			return 0, 0, fmt.Errorf("RPM %s architecture %s is outside compatibility leaf %s", entry.Path, info.Arch, projectionArch)
		}
		digest, err := repository.ParseDigest(entry.HashString())
		if err != nil {
			return 0, 0, err
		}
		packageFile, err := os.Open(captured)
		if err != nil {
			return 0, 0, err
		}
		_, verifyErr := yumrepo.VerifyEmbeddedRPMSignatures(ctx, packageFile, keyring, timeNowUTC())
		closeErr := packageFile.Close()
		if verifyErr != nil || closeErr != nil {
			return 0, 0, errors.Join(verifyErr, closeErr, fmt.Errorf("captured RPM %s fails pinned S1 package trust", entry.Path))
		}
		if _, err := pool.ImportExpected(ctx, captured, repository.Object{SHA256: digest, Size: entry.Size}); err != nil {
			return 0, 0, err
		}
		if err := os.Remove(captured); err != nil {
			return 0, 0, err
		}
		entry.Path = info.Location
		chunk = append(chunk, entry)
		packages++
		bytesTotal += entry.Size
		if len(chunk) == cap(chunk) {
			if err := flush(); err != nil {
				return 0, 0, err
			}
		}
	}
	if err := flush(); err != nil {
		return 0, 0, err
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, 0, err
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(destination)
		}
	}()
	var cursors yumCompatibilityAliasHeap
	for _, runName := range runs {
		run, err := os.Open(runName)
		if err != nil {
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, 0, err
		}
		reader := manifest.NewReader(run)
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			_ = run.Close()
			continue
		}
		if err != nil {
			_ = run.Close()
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, 0, err
		}
		cursors = append(cursors, &yumCompatibilityAliasCursor{entry: entry, reader: reader, file: run})
	}
	heap.Init(&cursors)
	previous := ""
	for cursors.Len() != 0 {
		cursor := heap.Pop(&cursors).(*yumCompatibilityAliasCursor)
		if cursor.entry.Path <= previous {
			_ = cursor.file.Close()
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, 0, fmt.Errorf("adopted RPMs collide at canonical location %s", cursor.entry.Path)
		}
		if err := manifest.WriteEntry(file, cursor.entry); err != nil {
			_ = cursor.file.Close()
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, 0, err
		}
		previous = cursor.entry.Path
		next, err := cursor.reader.Next()
		if errors.Is(err, io.EOF) {
			_ = cursor.file.Close()
			continue
		}
		if err != nil {
			_ = cursor.file.Close()
			closeYUMCompatibilityAliasCursors(cursors)
			return 0, 0, err
		}
		cursor.entry = next
		heap.Push(&cursors, cursor)
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return 0, 0, err
	}
	committed = true
	return packages, bytesTotal, validateYUMPayloadManifest(destination)
}

func requireManifestFilesEqual(leftPath, rightPath string) error {
	left, err := os.Open(leftPath)
	if err != nil {
		return err
	}
	right, err := os.Open(rightPath)
	if err != nil {
		left.Close()
		return err
	}
	diff, diffErr := manifest.Diff(left, right, nil)
	closeErr := errors.Join(left.Close(), right.Close())
	if diffErr != nil || closeErr != nil || !diff.Clean() {
		return errors.Join(diffErr, closeErr, fmt.Errorf("manifest diff added=%d removed=%d changed=%d", diff.Added, diff.Removed, diff.Changed))
	}
	return nil
}

func loadYUMCompatibilityAdoptionAt(canonical *state.Store, commit plumbing.Hash, id string) (yumCompatibilityAdoption, error) {
	var result yumCompatibilityAdoption
	path, err := state.YUMCompatibilityAdoptionPath(id)
	if err != nil {
		return result, err
	}
	reader, err := canonical.OpenPathAt(commit, path)
	if err != nil {
		return result, err
	}
	body, readErr := io.ReadAll(io.LimitReader(reader, maximumYUMCompatibilityWitnessBytes+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(body) > maximumYUMCompatibilityWitnessBytes {
		return result, errors.Join(readErr, closeErr, errors.New("YUM compatibility adoption receipt is too large"))
	}
	return decodeYUMCompatibilityAdoption(body)
}

func decodeYUMCompatibilityAdoption(body []byte) (yumCompatibilityAdoption, error) {
	var result yumCompatibilityAdoption
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return result, errors.New("YUM compatibility adoption receipt has trailing JSON")
	}
	if result.Schema != yumCompatibilityAdoptionSchema || result.ID == "" || result.Root == "" || result.Carrier == "" || result.OwnerRepo == "" ||
		result.View != "latest" || result.OS != "cross-el" || result.Arch == "" || !plumbing.IsHash(result.BaselineCommit) ||
		result.BaselineCommit == plumbing.ZeroHash.String() || result.BaselineManifestSize < 1 || result.SourceManifestSize < 1 || result.PackageTrustSize < 1 || result.Packages < 1 || result.Bytes < 1 ||
		result.LegacyMetadataPolicy != yumCompatibilityMetadataPolicy || result.LegacyRepomdSignature != "not-claimed" || result.CandidateMetadataPolicy != "clean-signed-three-xml-gzip" {
		return result, errors.New("YUM compatibility adoption receipt is incomplete or unsupported")
	}
	for name, value := range map[string]string{
		"baseline manifest": result.BaselineManifestSHA256, "source manifest": result.SourceManifestSHA256, "package trust": result.PackageTrustSHA256,
	} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size || value != strings.ToLower(value) {
			return result, fmt.Errorf("YUM compatibility adoption %s SHA-256 is invalid", name)
		}
	}
	for name, value := range map[string]string{
		"baseline manifest": result.BaselineManifestGit, "source manifest": result.SourceManifestGit, "package trust": result.PackageTrustGit,
	} {
		if !plumbing.IsHash(value) || value == plumbing.ZeroHash.String() || value != strings.ToLower(value) {
			return result, fmt.Errorf("YUM compatibility adoption %s Git blob is invalid", name)
		}
	}
	return result, nil
}

type legacyYUMCompatibilityRepomd struct {
	XMLName xml.Name                           `xml:"repomd"`
	Data    []legacyYUMCompatibilityRepomdData `xml:"data"`
}

type legacyYUMCompatibilityRepomdData struct {
	Type     string `xml:"type,attr"`
	Checksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	OpenChecksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"open-checksum"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
	Size     *int64 `xml:"size"`
	OpenSize *int64 `xml:"open-size"`
}

const (
	maximumLegacyYUMRepomdBytes      = 4 << 20
	maximumLegacyYUMOpenMetadataSize = int64(8 << 30)
)

// validateLegacyYUMCompatibilityRepomd verifies every record advertised by
// the S0 repomd, including sqlite and modulemd records that are deliberately
// migration-input-only. Requiring both compressed and open SHA-256/size
// identities prevents excluded records from becoming an unaudited byte hole;
// none of those excluded formats is copied to SOW's clean S2 candidate.
func validateLegacyYUMCompatibilityRepomd(ctx context.Context, root string) error {
	if ctx == nil {
		return errors.New("legacy repomd validation requires context")
	}
	repomdPath := filepath.Join(root, "repodata", "repomd.xml")
	body, err := readStableRegularLimited(repomdPath, maximumLegacyYUMRepomdBytes)
	if err != nil {
		return err
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	var document legacyYUMCompatibilityRepomd
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode legacy repomd.xml: %w", err)
	}
	if document.XMLName.Space != "http://linux.duke.edu/metadata/repo" || document.XMLName.Local != "repomd" {
		return errors.New("legacy repomd requires the canonical namespace")
	}
	// This is a frozen S0 migration contract, not a generic repomd parser. The
	// three XML streams are regenerated for S2; sqlite and modulemd remain
	// verified input-only evidence. Accepting any other record would reopen the
	// migration byte boundary and make its preservation policy ambiguous.
	requiredSuffix := map[string]string{
		"primary": ".xml.gz", "filelists": ".xml.gz", "other": ".xml.gz",
		"primary_db": ".sqlite.bz2", "filelists_db": ".sqlite.bz2", "other_db": ".sqlite.bz2",
		"modules": ".yaml.gz",
	}
	if len(document.Data) != len(requiredSuffix) {
		return fmt.Errorf("legacy repomd requires exactly seven frozen records; got %d", len(document.Data))
	}
	types, locations := make(map[string]struct{}, len(document.Data)), make(map[string]struct{}, len(document.Data))
	for _, record := range document.Data {
		if err := ctx.Err(); err != nil {
			return err
		}
		if record.Type == "" || strings.ContainsAny(record.Type, "\x00\t\r\n/") {
			return fmt.Errorf("legacy repomd has unsafe record type %q", record.Type)
		}
		if _, duplicate := types[record.Type]; duplicate {
			return fmt.Errorf("legacy repomd has duplicate record type %q", record.Type)
		}
		suffix, required := requiredSuffix[record.Type]
		if !required {
			return fmt.Errorf("legacy repomd has unsupported frozen record type %q", record.Type)
		}
		types[record.Type] = struct{}{}
		record.Checksum.Value = strings.TrimSpace(record.Checksum.Value)
		record.OpenChecksum.Value = strings.TrimSpace(record.OpenChecksum.Value)
		if record.Checksum.Type != "sha256" || record.OpenChecksum.Type != "sha256" || !validLowerSHA256(record.Checksum.Value) || !validLowerSHA256(record.OpenChecksum.Value) {
			return fmt.Errorf("legacy repomd record %s requires compressed and open SHA-256", record.Type)
		}
		if record.Size == nil || record.OpenSize == nil || *record.Size <= 0 || *record.OpenSize < 0 || *record.OpenSize > maximumLegacyYUMOpenMetadataSize {
			return fmt.Errorf("legacy repomd record %s requires bounded size and open-size", record.Type)
		}
		href := record.Location.Href
		if href == "" || path.Clean(href) != href || !strings.HasPrefix(href, "repodata/") || strings.Contains(href, "\\") || strings.HasPrefix(href, "/") || strings.ContainsAny(href, "\x00\t\r\n") {
			return fmt.Errorf("legacy repomd record %s has unsafe location %q", record.Type, href)
		}
		if !strings.HasSuffix(href, suffix) {
			return fmt.Errorf("legacy repomd record %s location %q must end in %s", record.Type, href, suffix)
		}
		if _, duplicate := locations[href]; duplicate {
			return fmt.Errorf("legacy repomd has duplicate location %q", href)
		}
		locations[href] = struct{}{}
		if err := validateLegacyYUMCompatibilityArtifact(ctx, root, href, *record.Size, record.Checksum.Value, *record.OpenSize, record.OpenChecksum.Value); err != nil {
			return fmt.Errorf("legacy repomd record %s: %w", record.Type, err)
		}
	}
	for kind := range requiredSuffix {
		if _, present := types[kind]; !present {
			return fmt.Errorf("legacy repomd is missing required %s record", kind)
		}
	}
	return nil
}

func legacyYUMCompatibilityRepodataAllowlist(ctx context.Context, root string) (map[string]struct{}, error) {
	if err := validateLegacyYUMCompatibilityRepomd(ctx, root); err != nil {
		return nil, err
	}
	body, err := readStableRegularLimited(filepath.Join(root, "repodata", "repomd.xml"), maximumLegacyYUMRepomdBytes)
	if err != nil {
		return nil, err
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	var document legacyYUMCompatibilityRepomd
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	allowed := map[string]struct{}{"repodata/repomd.xml": {}}
	for _, record := range document.Data {
		if _, duplicate := allowed[record.Location.Href]; duplicate {
			return nil, fmt.Errorf("legacy repomd repeats physical artifact %q", record.Location.Href)
		}
		allowed[record.Location.Href] = struct{}{}
	}
	if len(allowed) != 8 {
		return nil, fmt.Errorf("legacy repodata allowlist has %d entries, want repomd.xml plus seven artifacts", len(allowed))
	}
	return allowed, nil
}

func readStableRegularLimited(filename string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(filename)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum {
		return nil, errors.Join(err, fmt.Errorf("%s is not a bounded regular file", filename))
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errors.Join(err, fmt.Errorf("%s changed while opening", filename))
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	afterOpen, statErr := file.Stat()
	closeErr := file.Close()
	afterPath, lstatErr := os.Lstat(filename)
	if readErr != nil || statErr != nil || closeErr != nil || lstatErr != nil || int64(len(body)) > maximum || int64(len(body)) != opened.Size() || !os.SameFile(opened, afterOpen) || !os.SameFile(opened, afterPath) || afterPath.Mode()&os.ModeSymlink != 0 || afterOpen.Size() != opened.Size() || !afterOpen.ModTime().Equal(opened.ModTime()) {
		return nil, errors.Join(readErr, statErr, closeErr, lstatErr, fmt.Errorf("%s changed while reading", filename))
	}
	return body, nil
}

func validateLegacyYUMCompatibilityArtifact(ctx context.Context, root, href string, compressedSize int64, compressedSHA string, openSize int64, openSHA string) error {
	filename := filepath.Join(root, filepath.FromSlash(href))
	before, err := os.Lstat(filename)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != compressedSize {
		return errors.Join(err, fmt.Errorf("metadata artifact %s is missing or has the wrong compressed size", href))
	}
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return errors.Join(err, fmt.Errorf("metadata artifact %s changed while opening", href))
	}
	compressedHasher := sha256.New()
	written, err := io.Copy(compressedHasher, io.LimitReader(&contextBoundReader{ctx: ctx, reader: file}, compressedSize+1))
	if err != nil || written != compressedSize || hex.EncodeToString(compressedHasher.Sum(nil)) != compressedSHA {
		return errors.Join(err, fmt.Errorf("metadata artifact %s compressed identity differs from repomd", href))
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	reader, closeReader, err := openLegacyYUMMetadata(file, href)
	if err != nil {
		return err
	}
	openHasher := sha256.New()
	openedBytes, readErr := io.Copy(openHasher, io.LimitReader(&contextBoundReader{ctx: ctx, reader: reader}, openSize+1))
	closeReaderErr := closeReader()
	afterOpen, statErr := file.Stat()
	afterPath, lstatErr := os.Lstat(filename)
	if readErr != nil || closeReaderErr != nil || statErr != nil || lstatErr != nil || openedBytes != openSize || hex.EncodeToString(openHasher.Sum(nil)) != openSHA || !os.SameFile(opened, afterOpen) || !os.SameFile(opened, afterPath) || afterPath.Mode()&os.ModeSymlink != 0 || afterOpen.Size() != opened.Size() || !afterOpen.ModTime().Equal(opened.ModTime()) {
		return errors.Join(readErr, closeReaderErr, statErr, lstatErr, fmt.Errorf("metadata artifact %s open identity differs from repomd or changed while reading", href))
	}
	return nil
}

func openLegacyYUMMetadata(file *os.File, href string) (io.Reader, func() error, error) {
	switch {
	case strings.HasSuffix(href, ".gz"):
		reader, err := gzip.NewReader(file)
		if err != nil {
			return nil, nil, err
		}
		return reader, reader.Close, nil
	case strings.HasSuffix(href, ".bz2"):
		return bzip2.NewReader(file), func() error { return nil }, nil
	case strings.HasSuffix(href, ".zst"):
		reader, err := zstd.NewReader(file, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			return nil, nil, err
		}
		return reader, func() error { reader.Close(); return nil }, nil
	default:
		return nil, nil, fmt.Errorf("unsupported legacy metadata compression for %s", href)
	}
}

func resolveYUMCompatibilityCandidatePath(cfg *config.Config, value string) (string, error) {
	if cfg == nil || value == "" || strings.ContainsAny(value, "\x00\t\r\n") {
		return "", errors.New("candidate path is empty or unsafe")
	}
	abs, err := filepath.Abs(filepath.Clean(value))
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", fmt.Errorf("candidate parent must already exist: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.Join(err, errors.New("candidate parent is not a real directory"))
	}
	abs = filepath.Join(parent, filepath.Base(abs))
	root, err := filepath.EvalSymlinks(cfg.Root)
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	if pathsOverlap(abs, root) {
		return "", errors.New("candidate must be outside the hosted repository root")
	}
	if filepath.Base(abs) == "." || filepath.Base(abs) == string(filepath.Separator) {
		return "", errors.New("candidate path must name a dedicated child directory")
	}
	return abs, nil
}

type yumCompatibilityCandidateBinding struct {
	output         string
	parentPath     string
	base           string
	parent         *os.Root
	parentFile     *os.File
	parentIdentity os.FileInfo
	parentDevice   uint64
	parentInode    uint64
	allowed        map[string]struct{}
}

func openYUMCompatibilityCandidateBinding(cfg *config.Config, value string) (*yumCompatibilityCandidateBinding, error) {
	output, err := resolveYUMCompatibilityCandidatePath(cfg, value)
	if err != nil {
		return nil, err
	}
	parentPath := filepath.Dir(output)
	before, err := os.Lstat(parentPath)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(err, errors.New("candidate parent is not a real directory"))
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, err
	}
	bound, err := parent.Stat(".")
	if err != nil || !os.SameFile(before, bound) {
		_ = parent.Close()
		return nil, errors.Join(err, errors.New("candidate parent changed while binding its directory handle"))
	}
	parentDevice, parentInode, supported := yumCompatibilityDirectoryIdentity(bound)
	if !supported || parentInode == 0 {
		_ = parent.Close()
		return nil, errors.New("candidate parent does not expose a durable directory identity on this platform")
	}
	parentFile, err := parent.Open(".")
	if err != nil {
		_ = parent.Close()
		return nil, err
	}
	base := filepath.Base(output)
	binding := &yumCompatibilityCandidateBinding{
		output: output, parentPath: parentPath, base: base, parent: parent, parentFile: parentFile, parentIdentity: bound,
		parentDevice: parentDevice, parentInode: parentInode,
		allowed: make(map[string]struct{}, 8),
	}
	for _, name := range []string{
		base, base + ".sow-stage", base + ".sow-candidate.tsv", base + ".sow-candidate.tsv.pending",
		base + ".sow-candidate.json", base + ".sow-candidate.json.pending",
		base + ".sow-candidate.journal.json", base + ".sow-candidate.journal.json.next",
	} {
		binding.allowed[name] = struct{}{}
	}
	if err := binding.verifyParent(); err != nil {
		_ = binding.Close()
		return nil, err
	}
	return binding, nil
}

func (binding *yumCompatibilityCandidateBinding) Close() error {
	if binding == nil {
		return nil
	}
	var fileErr, rootErr error
	if binding.parentFile != nil {
		fileErr = binding.parentFile.Close()
		binding.parentFile = nil
	}
	if binding.parent != nil {
		rootErr = binding.parent.Close()
		binding.parent = nil
	}
	return errors.Join(fileErr, rootErr)
}

func (binding *yumCompatibilityCandidateBinding) verifyParent() error {
	if binding == nil || binding.parent == nil || binding.parentFile == nil || binding.parentIdentity == nil {
		return errors.New("candidate parent binding is unavailable")
	}
	throughRoot, rootErr := binding.parent.Stat(".")
	throughFile, fileErr := binding.parentFile.Stat()
	atPath, pathErr := os.Lstat(binding.parentPath)
	if rootErr != nil || fileErr != nil || pathErr != nil || atPath.Mode()&os.ModeSymlink != 0 || !atPath.IsDir() ||
		!os.SameFile(binding.parentIdentity, throughRoot) || !os.SameFile(binding.parentIdentity, throughFile) || !os.SameFile(binding.parentIdentity, atPath) {
		return errors.Join(rootErr, fileErr, pathErr, errors.New("candidate parent was replaced after its directory handle was bound"))
	}
	return nil
}

func (binding *yumCompatibilityCandidateBinding) name(absolute string) (string, error) {
	if binding == nil || filepath.Dir(absolute) != binding.parentPath {
		return "", fmt.Errorf("candidate transaction path %s is outside its bound parent", absolute)
	}
	name := filepath.Base(absolute)
	if _, exists := binding.allowed[name]; !exists || filepath.Join(binding.parentPath, name) != absolute {
		return "", fmt.Errorf("candidate transaction basename %q is outside the closed artifact set", name)
	}
	return name, nil
}

func (binding *yumCompatibilityCandidateBinding) lstat(absolute string) (os.FileInfo, error) {
	if err := binding.verifyParent(); err != nil {
		return nil, err
	}
	name, err := binding.name(absolute)
	if err != nil {
		return nil, err
	}
	return binding.parent.Lstat(name)
}

func (binding *yumCompatibilityCandidateBinding) mkdir(absolute string, mode os.FileMode) error {
	if err := binding.verifyParent(); err != nil {
		return err
	}
	name, err := binding.name(absolute)
	if err != nil {
		return err
	}
	if err := binding.parent.Mkdir(name, mode); err != nil {
		return err
	}
	return binding.syncParent()
}

func (binding *yumCompatibilityCandidateBinding) remove(absolute string) error {
	if err := binding.verifyParent(); err != nil {
		return err
	}
	name, err := binding.name(absolute)
	if err != nil {
		return err
	}
	if err := binding.parent.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return binding.syncParent()
}

func (binding *yumCompatibilityCandidateBinding) removeAllDirectory(absolute string) error {
	if err := binding.verifyParent(); err != nil {
		return err
	}
	name, err := binding.name(absolute)
	if err != nil {
		return err
	}
	if err := binding.parent.RemoveAll(name); err != nil {
		return err
	}
	return binding.syncParent()
}

func (binding *yumCompatibilityCandidateBinding) writeExclusive(absolute string, body []byte) error {
	if err := binding.verifyParent(); err != nil {
		return err
	}
	name, err := binding.name(absolute)
	if err != nil {
		return err
	}
	file, err := binding.parent.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(body)
	closeErr := errors.Join(file.Sync(), file.Close())
	if writeErr != nil || closeErr != nil {
		return errors.Join(writeErr, closeErr)
	}
	return binding.syncParent()
}

func (binding *yumCompatibilityCandidateBinding) copyExclusive(absolute, source string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := binding.verifyParent(); err != nil {
		return err
	}
	name, err := binding.name(absolute)
	if err != nil {
		return err
	}
	output, err := binding.parent.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := errors.Join(output.Sync(), output.Close())
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	return binding.syncParent()
}

func (binding *yumCompatibilityCandidateBinding) snapshotExact(absolute, destination string, expectedSize int64) error {
	if expectedSize < 1 {
		return errors.New("candidate artifact snapshot size must be positive")
	}
	if err := binding.verifyParent(); err != nil {
		return err
	}
	name, err := binding.name(absolute)
	if err != nil {
		return err
	}
	before, err := binding.parent.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() != expectedSize {
		return errors.Join(err, fmt.Errorf("candidate artifact %s does not have expected size", absolute))
	}
	input, err := binding.parent.Open(name)
	if err != nil {
		return err
	}
	opened, err := input.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		_ = input.Close()
		return errors.Join(err, fmt.Errorf("candidate artifact %s changed while opening", absolute))
	}
	_, size, captureErr := captureStableOpenedRegular(context.Background(), input, destination)
	closeErr := input.Close()
	after, lstatErr := binding.parent.Lstat(name)
	if captureErr != nil || closeErr != nil || lstatErr != nil || size != expectedSize || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) {
		_ = os.Remove(destination)
		return errors.Join(captureErr, closeErr, lstatErr, fmt.Errorf("candidate artifact %s changed while snapshotting", absolute))
	}
	return binding.verifyParent()
}

func (binding *yumCompatibilityCandidateBinding) readStable(absolute string, maximum int64) ([]byte, error) {
	if err := binding.verifyParent(); err != nil {
		return nil, err
	}
	name, err := binding.name(absolute)
	if err != nil {
		return nil, err
	}
	before, err := binding.parent.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum {
		return nil, errors.Join(err, fmt.Errorf("%s is not a bounded regular candidate artifact", absolute))
	}
	file, err := binding.parent.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errors.Join(err, fmt.Errorf("%s changed while opening", absolute))
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	afterOpen, statErr := file.Stat()
	closeErr := file.Close()
	afterPath, lstatErr := binding.parent.Lstat(name)
	if readErr != nil || statErr != nil || closeErr != nil || lstatErr != nil || int64(len(body)) > maximum || int64(len(body)) != opened.Size() || !os.SameFile(opened, afterOpen) || !os.SameFile(opened, afterPath) || afterPath.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(readErr, statErr, closeErr, lstatErr, fmt.Errorf("%s changed while reading", absolute))
	}
	return body, nil
}

func (binding *yumCompatibilityCandidateBinding) renameNoReplace(source, destination string) error {
	if err := binding.verifyParent(); err != nil {
		return err
	}
	from, err := binding.name(source)
	if err != nil {
		return err
	}
	to, err := binding.name(destination)
	if err != nil {
		return err
	}
	if err := renameYUMCompatibilityCandidateNoReplace(binding.parentFile.Fd(), from, to); err != nil {
		return err
	}
	return binding.syncParent()
}

func (binding *yumCompatibilityCandidateBinding) link(source, destination string) error {
	if err := binding.verifyParent(); err != nil {
		return err
	}
	from, err := binding.name(source)
	if err != nil {
		return err
	}
	to, err := binding.name(destination)
	if err != nil {
		return err
	}
	if err := binding.parent.Link(from, to); err != nil {
		return err
	}
	return binding.syncParent()
}

func (binding *yumCompatibilityCandidateBinding) syncParent() error {
	if err := binding.parentFile.Sync(); err != nil {
		return err
	}
	return binding.verifyParent()
}

func (binding *yumCompatibilityCandidateBinding) openBoundDirectory(absolute string) (*os.Root, os.FileInfo, error) {
	info, err := binding.lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.Join(err, fmt.Errorf("candidate directory %s is not real", absolute))
	}
	name, _ := binding.name(absolute)
	child, err := binding.parent.OpenRoot(name)
	if err != nil {
		return nil, nil, err
	}
	bound, err := child.Stat(".")
	if err != nil || !os.SameFile(info, bound) {
		_ = child.Close()
		return nil, nil, errors.Join(err, fmt.Errorf("candidate directory %s changed while binding", absolute))
	}
	return child, bound, nil
}

func (binding *yumCompatibilityCandidateBinding) verifyBoundDirectory(absolute string, expected os.FileInfo) error {
	info, err := binding.lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || expected == nil || !os.SameFile(expected, info) {
		return errors.Join(err, fmt.Errorf("candidate directory %s was replaced during the transaction", absolute))
	}
	return nil
}

func yumCompatibilityCandidateSidecars(candidate string) (manifestPath, receiptPath string) {
	return candidate + ".sow-candidate.tsv", candidate + ".sow-candidate.json"
}

func yumCompatibilityCandidateJournalPath(candidate string) string {
	return candidate + ".sow-candidate.journal.json"
}

func expectedYUMCompatibilityCandidateJournal(id string, binding *yumCompatibilityCandidateBinding) yumCompatibilityCandidateJournal {
	output := binding.output
	manifestPath, receiptPath := yumCompatibilityCandidateSidecars(output)
	return yumCompatibilityCandidateJournal{
		Schema: yumCompatibilityJournalSchema, ID: id, Phase: yumCompatibilityCandidateBuilding,
		Output: output, Stage: output + ".sow-stage", PendingManifest: manifestPath + ".pending", PendingReceipt: receiptPath + ".pending",
		ParentPath: binding.parentPath, ParentDevice: binding.parentDevice, ParentInode: binding.parentInode,
	}
}

func createYUMCompatibilityCandidateJournal(id string, binding *yumCompatibilityCandidateBinding) (yumCompatibilityCandidateJournal, error) {
	output := binding.output
	journal := expectedYUMCompatibilityCandidateJournal(id, binding)
	manifestPath, receiptPath := yumCompatibilityCandidateSidecars(output)
	for _, name := range []string{output, journal.Stage, manifestPath, receiptPath, journal.PendingManifest, journal.PendingReceipt, yumCompatibilityCandidateJournalPath(output), yumCompatibilityCandidateJournalPath(output) + ".next"} {
		if _, err := binding.lstat(name); err == nil {
			return journal, fmt.Errorf("candidate transaction path %s already exists", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return journal, err
		}
	}
	if err := writeYUMCompatibilityCandidateJournal(binding, journal, true); err != nil {
		return journal, err
	}
	if err := binding.mkdir(journal.Stage, 0o700); err != nil {
		return journal, err
	}
	if err := binding.syncParent(); err != nil {
		return journal, err
	}
	return journal, nil
}

func writeYUMCompatibilityCandidateJournal(binding *yumCompatibilityCandidateBinding, journal yumCompatibilityCandidateJournal, exclusive bool) error {
	body, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	destination := yumCompatibilityCandidateJournalPath(binding.output)
	if exclusive {
		return writeExclusiveAtomicYUMCompatibilityCandidateJournalBytes(binding, destination, body)
	}
	pending := destination + ".next"
	if err := binding.writeExclusive(pending, body); err != nil {
		return err
	}
	if err := binding.parent.Rename(filepath.Base(pending), filepath.Base(destination)); err != nil {
		return err
	}
	return binding.syncParent()
}

func readYUMCompatibilityCandidateJournal(binding *yumCompatibilityCandidateBinding, id string) (yumCompatibilityCandidateJournal, bool, error) {
	return readYUMCompatibilityCandidateJournalAt(binding, yumCompatibilityCandidateJournalPath(binding.output), id)
}

var errPartialYUMCompatibilityCandidateJournalEncoding = errors.New("partial candidate journal encoding")

func readYUMCompatibilityCandidateJournalAt(binding *yumCompatibilityCandidateBinding, filename, id string) (yumCompatibilityCandidateJournal, bool, error) {
	var journal yumCompatibilityCandidateJournal
	body, err := binding.readStable(filename, maximumYUMCompatibilityWitnessBytes)
	if errors.Is(err, os.ErrNotExist) {
		return journal, false, nil
	}
	if err != nil {
		return journal, false, fmt.Errorf("%w: %v", errPartialYUMCompatibilityCandidateJournalEncoding, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return journal, false, fmt.Errorf("%w: %v", errPartialYUMCompatibilityCandidateJournalEncoding, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return journal, false, fmt.Errorf("%w: trailing JSON", errPartialYUMCompatibilityCandidateJournalEncoding)
	}
	want := expectedYUMCompatibilityCandidateJournal(id, binding)
	if journal.Schema != want.Schema || journal.ID != want.ID || journal.Output != want.Output || journal.Stage != want.Stage || journal.PendingManifest != want.PendingManifest || journal.PendingReceipt != want.PendingReceipt ||
		journal.ParentPath != want.ParentPath || journal.ParentDevice != want.ParentDevice || journal.ParentInode != want.ParentInode {
		return journal, false, errors.New("candidate journal path or identity differs from the requested transaction")
	}
	switch journal.Phase {
	case yumCompatibilityCandidateBuilding, yumCompatibilityCandidatePrepared, yumCompatibilityCandidateTreeReady, yumCompatibilityCandidateManifestReady:
	default:
		return journal, false, fmt.Errorf("candidate journal has unsupported phase %q", journal.Phase)
	}
	return journal, true, nil
}

func recoverYUMCompatibilityCandidateJournal(id string, binding *yumCompatibilityCandidateBinding, recover bool) (bool, error) {
	output := binding.output
	base := yumCompatibilityCandidateJournalPath(output)
	if err := reconcileYUMCompatibilityCandidateJournalPair(binding, base, id, recover); err != nil {
		return false, err
	}
	journal, exists, err := readYUMCompatibilityCandidateJournal(binding, id)
	if err != nil || !exists {
		return false, err
	}
	if !recover {
		return false, fmt.Errorf("incomplete candidate transaction exists at %s; rerun with --recover", yumCompatibilityCandidateJournalPath(output))
	}
	if journal.Phase == yumCompatibilityCandidateBuilding {
		if _, err := binding.lstat(output); err == nil {
			return false, errors.New("building candidate journal conflicts with an installed output")
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		for _, name := range []string{journal.Stage, journal.PendingManifest, journal.PendingReceipt, yumCompatibilityCandidateJournalPath(output) + ".next"} {
			if err := removeCandidateRecoveryPath(binding, name, journal.Stage); err != nil {
				return false, err
			}
		}
		if err := binding.remove(yumCompatibilityCandidateJournalPath(output)); err != nil {
			return false, err
		}
		return false, binding.syncParent()
	}
	if err := finalizeYUMCompatibilityCandidateJournal(binding, &journal); err != nil {
		return false, err
	}
	return true, nil
}

func writeExclusiveAtomicYUMCompatibilityJournalBytes(destination string, body []byte) error {
	pending := destination + ".next"
	if err := writeExclusiveBytes(pending, body); err != nil {
		return err
	}
	linked := false
	defer func() {
		if !linked {
			_ = os.Remove(pending)
		}
	}()
	if err := os.Link(pending, destination); err != nil {
		return err
	}
	linked = true
	if err := syncLocalDirectory(filepath.Dir(destination)); err != nil {
		return err
	}
	if err := os.Remove(pending); err != nil {
		return err
	}
	return syncLocalDirectory(filepath.Dir(destination))
}

func writeExclusiveAtomicYUMCompatibilityCandidateJournalBytes(binding *yumCompatibilityCandidateBinding, destination string, body []byte) error {
	pending := destination + ".next"
	if err := binding.writeExclusive(pending, body); err != nil {
		return err
	}
	linked := false
	defer func() {
		if !linked {
			_ = binding.remove(pending)
		}
	}()
	if err := binding.link(pending, destination); err != nil {
		return err
	}
	linked = true
	return binding.remove(pending)
}

func sameYUMCompatibilityCandidateJournalIdentity(left, right yumCompatibilityCandidateJournal) bool {
	left.Phase, right.Phase = "", ""
	return left == right
}

func nextYUMCompatibilityCandidateJournalPhase(current, next string) bool {
	order := map[string]int{
		yumCompatibilityCandidateBuilding: 0, yumCompatibilityCandidatePrepared: 1,
		yumCompatibilityCandidateTreeReady: 2, yumCompatibilityCandidateManifestReady: 3,
	}
	return order[next] == order[current]+1
}

// Candidate phase updates are safe to replay from the older base because all
// filesystem renames are no-overwrite and idempotent. Recovery still decodes
// and identity-checks both files before removing .next, so a partial or
// mismatched update can never be silently accepted as a transaction phase.
func reconcileYUMCompatibilityCandidateJournalPair(binding *yumCompatibilityCandidateBinding, base, id string, recover bool) error {
	next := base + ".next"
	nextInfo, err := binding.lstat(next)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !recover {
		return fmt.Errorf("incomplete candidate journal phase update exists at %s; rerun with --recover", next)
	}
	if !nextInfo.Mode().IsRegular() || nextInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("candidate journal pending update is not a regular file")
	}
	baseInfo, baseErr := binding.lstat(base)
	if errors.Is(baseErr, os.ErrNotExist) {
		nextJournal, nextExists, nextErr := readYUMCompatibilityCandidateJournalAt(binding, next, id)
		if nextErr != nil || !nextExists {
			if nextErr != nil && !errors.Is(nextErr, errPartialYUMCompatibilityCandidateJournalEncoding) {
				return errors.Join(nextErr, errors.New("candidate journal pending update conflicts with the requested transaction"))
			}
			if err := requireNoYUMCompatibilityCandidateArtifacts(id, binding); err != nil {
				return errors.Join(nextErr, err, errors.New("partial candidate journal has no durable base"))
			}
			if err := binding.remove(next); err != nil {
				return err
			}
			return binding.syncParent()
		}
		if nextJournal.Phase != yumCompatibilityCandidateBuilding {
			return errors.New("candidate journal pending update has no durable base")
		}
		if err := requireNoYUMCompatibilityCandidateArtifacts(id, binding); err != nil {
			return err
		}
		if err := binding.remove(next); err != nil {
			return err
		}
		return binding.syncParent()
	}
	if baseErr != nil || !baseInfo.Mode().IsRegular() || baseInfo.Mode()&os.ModeSymlink != 0 {
		return errors.Join(baseErr, errors.New("candidate journal pending update has no safe durable base"))
	}
	baseJournal, baseExists, baseReadErr := readYUMCompatibilityCandidateJournalAt(binding, base, id)
	if baseReadErr != nil || !baseExists {
		return errors.Join(baseReadErr, errors.New("candidate journal durable base is incomplete"))
	}
	nextJournal, nextExists, nextErr := readYUMCompatibilityCandidateJournalAt(binding, next, id)
	if nextErr != nil || !nextExists {
		if nextErr != nil && !errors.Is(nextErr, errPartialYUMCompatibilityCandidateJournalEncoding) {
			return errors.Join(nextErr, errors.New("candidate journal pending update conflicts with the durable transaction"))
		}
		// The durable base and no-overwrite filesystem phases are sufficient to
		// replay safely. Invalid bytes in the uncommitted phase file are never
		// admitted; explicit recovery discards them and resumes from the base.
		if err := binding.remove(next); err != nil {
			return err
		}
		return binding.syncParent()
	}
	sameInitialLink := os.SameFile(baseInfo, nextInfo)
	if !sameYUMCompatibilityCandidateJournalIdentity(baseJournal, nextJournal) ||
		!(sameInitialLink && baseJournal.Phase == nextJournal.Phase && baseJournal.Phase == yumCompatibilityCandidateBuilding) &&
			!nextYUMCompatibilityCandidateJournalPhase(baseJournal.Phase, nextJournal.Phase) {
		return errors.New("candidate journal pending update differs from the exact durable transaction")
	}
	if err := binding.remove(next); err != nil {
		return err
	}
	return binding.syncParent()
}

func requireNoYUMCompatibilityCandidateArtifacts(id string, binding *yumCompatibilityCandidateBinding) error {
	want := expectedYUMCompatibilityCandidateJournal(id, binding)
	manifestPath, receiptPath := yumCompatibilityCandidateSidecars(binding.output)
	for _, name := range []string{binding.output, want.Stage, want.PendingManifest, want.PendingReceipt, manifestPath, receiptPath} {
		if _, err := binding.lstat(name); err == nil {
			return fmt.Errorf("candidate artifact %s exists without a durable journal base", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func removeCandidateRecoveryPath(binding *yumCompatibilityCandidateBinding, name, stage string) error {
	info, err := binding.lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if name == stage {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("candidate recovery stage %s is not a real directory", name)
		}
		return binding.removeAllDirectory(name)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("candidate recovery sidecar %s is not a regular file", name)
	}
	return binding.remove(name)
}

func finalizeYUMCompatibilityCandidateJournal(binding *yumCompatibilityCandidateBinding, journal *yumCompatibilityCandidateJournal) error {
	if journal == nil {
		return errors.New("candidate journal is unavailable")
	}
	if err := reconcileCandidateRename(binding, journal.Stage, journal.Output, true); err != nil {
		return err
	}
	journal.Phase = yumCompatibilityCandidateTreeReady
	if err := writeYUMCompatibilityCandidateJournal(binding, *journal, false); err != nil {
		return err
	}
	manifestPath, receiptPath := yumCompatibilityCandidateSidecars(journal.Output)
	if err := reconcileCandidateRename(binding, journal.PendingManifest, manifestPath, false); err != nil {
		return err
	}
	journal.Phase = yumCompatibilityCandidateManifestReady
	if err := writeYUMCompatibilityCandidateJournal(binding, *journal, false); err != nil {
		return err
	}
	if err := reconcileCandidateRename(binding, journal.PendingReceipt, receiptPath, false); err != nil {
		return err
	}
	return binding.syncParent()
}

func reconcileCandidateRename(binding *yumCompatibilityCandidateBinding, source, destination string, directory bool) error {
	sourceInfo, sourceErr := binding.lstat(source)
	destinationInfo, destinationErr := binding.lstat(destination)
	sourceExists, destinationExists := sourceErr == nil, destinationErr == nil
	if sourceErr != nil && !errors.Is(sourceErr, os.ErrNotExist) {
		return sourceErr
	}
	if destinationErr != nil && !errors.Is(destinationErr, os.ErrNotExist) {
		return destinationErr
	}
	if sourceExists && destinationExists {
		return fmt.Errorf("candidate transaction refuses to overwrite existing %s", destination)
	}
	if !sourceExists && !destinationExists {
		return fmt.Errorf("candidate transaction lost both %s and %s", source, destination)
	}
	validate := func(name string, info os.FileInfo) error {
		if info.Mode()&os.ModeSymlink != 0 || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
			return fmt.Errorf("candidate transaction path %s has an unsafe type", name)
		}
		return nil
	}
	if sourceExists {
		if err := validate(source, sourceInfo); err != nil {
			return err
		}
		if err := binding.renameNoReplace(source, destination); err != nil {
			return err
		}
		return binding.syncParent()
	}
	return validate(destination, destinationInfo)
}

func removeYUMCompatibilityCandidateJournal(binding *yumCompatibilityCandidateBinding) error {
	return binding.remove(yumCompatibilityCandidateJournalPath(binding.output))
}

// yumCompatibilityRepositoryTrustPath is intentionally derived from an
// exported, validated state path rather than reimplementing state segment
// validation in the CLI package.
func yumCompatibilityRepositoryTrustPath(id string) (string, error) {
	return state.YUMCompatibilityRepositoryTrustPath(id)
}

func loadCandidateRepositoryTrust(workflow yumCompatibilityWorkflow, canonical *state.Store, receipt yumCompatibilityCandidate) ([]byte, error) {
	freezeRef, err := state.YUMCompatibilityRef(workflow.projection.ID)
	if err != nil {
		return nil, err
	}
	freezeCommit, frozen, err := canonical.Ref(freezeRef)
	if err != nil {
		return nil, err
	}
	if frozen {
		trustPath, err := yumCompatibilityRepositoryTrustPath(workflow.projection.ID)
		if err != nil {
			return nil, err
		}
		body, exists, err := readCanonicalBytesAt(canonical, freezeCommit, trustPath, maxSecretBytes)
		if err != nil || !exists || int64(len(body)) != receipt.RepositoryTrustSize || digestBytesCLI(body) != receipt.RepositoryTrustSHA256 {
			return nil, errors.Join(err, errors.New("frozen repository trust bytes differ from candidate receipt"))
		}
		blob, exists, err := canonical.BlobIdentityAt(freezeCommit, trustPath)
		if err != nil || !exists || blob.Hash.String() != receipt.RepositoryTrustGit || blob.Size != receipt.RepositoryTrustSize {
			return nil, errors.Join(err, errors.New("frozen repository trust Git identity differs from candidate receipt"))
		}
		return body, nil
	}
	_, packets, err := loadRepositoryPublicTrustAnchor(workflow.cfg.Path, workflow.cfg.GPG.PublicKey)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(packets)
	gitBlob := plumbing.NewHasher(plumbing.BlobObject, int64(len(packets)))
	_, _ = gitBlob.Write(packets)
	if hex.EncodeToString(digest[:]) != receipt.RepositoryTrustSHA256 || gitBlob.Sum().String() != receipt.RepositoryTrustGit || int64(len(packets)) != receipt.RepositoryTrustSize {
		return nil, errors.New("current repository trust bytes differ from candidate receipt")
	}
	return packets, nil
}

// commitYUMCompatibilityTrustCAS makes the two frozen public trust artifacts
// ordinary immutable CAS objects before the S2 ref can make them permanent
// reachability roots. All path-oriented reads stay in the private canonical
// workspace; the final install is delegated to the persistent root capability.
func commitYUMCompatibilityTrustCAS(ctx context.Context, workflow yumCompatibilityWorkflow, receipt yumCompatibilityCandidate, packageTrustPath, repositoryTrustPath, phase string) (resultErr error) {
	if receipt.ID != workflow.projection.ID {
		return errors.New("YUM compatibility trust receipt does not match the bound projection")
	}
	packageDigest, err := repository.ParseDigest(receipt.PackageTrustSHA256)
	if err != nil {
		return err
	}
	repositoryDigest, err := repository.ParseDigest(receipt.RepositoryTrustSHA256)
	if err != nil {
		return err
	}
	workspace, err := newYUMCompatibilityCASWorkspace()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, workspace.Close()) }()
	for _, item := range []struct {
		path   string
		object repository.Object
		label  string
	}{
		{path: packageTrustPath, object: repository.Object{SHA256: packageDigest, Size: receipt.PackageTrustSize}, label: "package trust"},
		{path: repositoryTrustPath, object: repository.Object{SHA256: repositoryDigest, Size: receipt.RepositoryTrustSize}, label: "repository trust"},
	} {
		if err := workspace.ImportLocalObject(ctx, item.path, item.object); err != nil {
			return fmt.Errorf("import frozen %s into private CAS: %w", item.label, err)
		}
	}
	if err := workspace.Commit(ctx, workflow, phase); err != nil {
		return fmt.Errorf("commit frozen trust CAS closure: %w", err)
	}
	return nil
}

// ensureFrozenYUMCompatibilityTrustCAS repairs repositories frozen by an older
// SOW release. The immutable freeze commit is the only byte source; a replay of
// freeze/cutover/rollback can therefore install missing CAS coordinates without
// consulting mutable config or the original operator candidate directory.
func ensureFrozenYUMCompatibilityTrustCAS(ctx context.Context, workflow yumCompatibilityWorkflow, canonical *state.Store, freezeCommit plumbing.Hash, receipt yumCompatibilityCandidate, txDir, phase string) error {
	packageCanonicalPath, err := state.YUMCompatibilityPackageTrustPath(receipt.ID)
	if err != nil {
		return err
	}
	repositoryCanonicalPath, err := state.YUMCompatibilityRepositoryTrustPath(receipt.ID)
	if err != nil {
		return err
	}
	packageTrustPath := filepath.Join(txDir, "frozen-package-trust.pgp")
	repositoryTrustPath := filepath.Join(txDir, "frozen-repository-trust.pgp")
	if err := copyCanonicalPathAt(canonical, freezeCommit, packageCanonicalPath, packageTrustPath, receipt.PackageTrustSize); err != nil {
		return fmt.Errorf("stage frozen package trust from canonical state: %w", err)
	}
	if err := copyCanonicalPathAt(canonical, freezeCommit, repositoryCanonicalPath, repositoryTrustPath, receipt.RepositoryTrustSize); err != nil {
		return fmt.Errorf("stage frozen repository trust from canonical state: %w", err)
	}
	return commitYUMCompatibilityTrustCAS(ctx, workflow, receipt, packageTrustPath, repositoryTrustPath, phase)
}

func buildYUMCompatibilityCandidate(ctx context.Context, workflow yumCompatibilityWorkflow, canonical *state.Store, binding *yumCompatibilityCandidateBinding, txDir string, values commonFlags, adoption yumCompatibilityAdoption, privateKey, passphrase []byte) (result yumCompatibilityCandidate, resultErr error) {
	output := binding.output
	admission, err := admitYUMCompatibilityProjection(workflow.cfg, canonical, workflow.projection)
	if err != nil {
		return result, err
	}
	packagesPath, aliasesPath, payloadPath, _, packages, bytesTotal, err := buildYUMCompatibilityPayload(canonical, admission, txDir)
	if err != nil {
		return result, err
	}
	trust, err := stageYUMCompatibilityPackageTrust(workflow.cfg, canonical, admission, txDir)
	if err != nil {
		return result, err
	}
	if trust.sha256 != adoption.PackageTrustSHA256 || trust.gitBlob.String() != adoption.PackageTrustGit || trust.size != adoption.PackageTrustSize {
		return result, errors.New("candidate package trust differs from S1 adoption")
	}
	commitTime, err := canonical.CommitTime(admission.sourceCommit)
	if err != nil {
		return result, err
	}
	signer, err := newDeterministicMaterializeKey(privateKey, passphrase, commitTime)
	if err != nil {
		return result, errors.New("cannot initialize deterministic compatibility candidate signer")
	}
	_, repositoryPackets, err := loadRepositoryPublicTrustAnchor(workflow.cfg.Path, workflow.cfg.GPG.PublicKey)
	if err != nil {
		return result, err
	}
	repositoryKeySHA := repositoryTrustAnchorDigest(repositoryPackets)
	repositoryTrustStage := filepath.Join(txDir, "candidate-repository-trust.pgp")
	if err := writeExclusiveBytes(repositoryTrustStage, repositoryPackets); err != nil {
		return result, err
	}
	repositoryTrustSHA, repositoryTrustGit, repositoryTrustSize, err := fileSHA256AndGitBlob(repositoryTrustStage)
	if err != nil {
		return result, err
	}
	journal, err := createYUMCompatibilityCandidateJournal(workflow.projection.ID, binding)
	if err != nil {
		return result, err
	}
	privateCAS, err := newYUMCompatibilityCASWorkspace()
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, privateCAS.Close()) }()
	if err := privateCAS.MirrorManifest(ctx, workflow, packagesPath); err != nil {
		return result, fmt.Errorf("mirror candidate packages into private CAS: %w", err)
	}
	if err := privateCAS.MirrorManifest(ctx, workflow, aliasesPath); err != nil {
		return result, fmt.Errorf("mirror candidate aliases into private CAS: %w", err)
	}
	privateCandidate, err := privateCAS.MaterializeManifest(ctx, packagesPath, "candidate-build", values.workers)
	if err != nil {
		return result, err
	}
	if _, err := privateCAS.MaterializeManifest(ctx, aliasesPath, "candidate-build", values.workers); err != nil {
		return result, err
	}
	if err := verifyYUMPackageManifest(ctx, packagesPath, privateCandidate, trust.keyring, timeNowUTC(), values.workers); err != nil {
		return result, fmt.Errorf("candidate RPM trust: %w", err)
	}
	iterator, packageManifest, err := openYUMManifestIterator(packagesPath, privateCandidate)
	if err != nil {
		return result, err
	}
	generation, generationErr := yumrepo.Generate(ctx, filepath.Join(privateCandidate, "repodata"), yumrepo.Options{
		ELMajor: 0, Frozen: true, Compatibility: true, Compression: yumrepo.CompressionGzip,
		Revision: commitTime.Unix(), Signer: signer,
	}, iterator)
	closeErr := packageManifest.Close()
	if generationErr != nil || closeErr != nil {
		return result, errors.Join(generationErr, closeErr)
	}
	validated, err := yumrepo.ValidateDirectory(ctx, filepath.Join(privateCandidate, "repodata"), yumrepo.CompressionGzip, signer)
	if err != nil || !yumGenerationMatchesExpected(validated, generation, packages) {
		return result, errors.Join(err, errors.New("candidate generation identity mismatch"))
	}
	if err := makeYUMCompatibilityCandidateDirectoriesTraversable(privateCandidate); err != nil {
		return result, err
	}
	pendingManifest, pendingReceipt := journal.PendingManifest, journal.PendingReceipt
	manifestStage := filepath.Join(txDir, "candidate-manifest.tsv")
	if _, err := manifest.Scan(ctx, privateCandidate, manifest.Scope{Path: "."}, manifestStage, manifest.ScanOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: txDir}); err != nil {
		return result, err
	}
	if err := importYUMCompatibilityManifestObjects(ctx, privateCAS.Store(), privateCandidate, manifestStage); err != nil {
		return result, fmt.Errorf("private candidate bytes in CAS: %w", err)
	}
	if err := privateCAS.TrackManifest(manifestStage); err != nil {
		return result, err
	}
	if err := privateCAS.Commit(ctx, workflow, "commit staged yum-candidate CAS closure"); err != nil {
		return result, err
	}
	stage := journal.Stage
	boundManifest := filepath.Join(txDir, "candidate-bound-manifest.tsv")
	stageIdentity, err := populateYUMCompatibilityBoundCandidateStage(ctx, workflow, binding, stage, manifestStage, boundManifest)
	if err != nil {
		return result, err
	}
	if err := binding.copyExclusive(pendingManifest, manifestStage); err != nil {
		return result, err
	}
	manifestSHA, manifestGit, manifestSize, err := fileSHA256AndGitBlob(manifestStage)
	if err != nil {
		return result, err
	}
	adoptionPath, _ := state.YUMCompatibilityAdoptionPath(workflow.projection.ID)
	adoptionBlob, exists, err := canonical.BlobIdentityAt(admission.sourceCommit, adoptionPath)
	if err != nil || !exists {
		return result, errors.Join(err, errors.New("S1 adoption receipt blob is missing"))
	}
	adoptionSHA, err := hashYUMCompatibilityCanonicalPathAt(canonical, admission.sourceCommit, adoptionPath)
	if err != nil {
		return result, err
	}
	result = yumCompatibilityCandidate{
		Schema: yumCompatibilityCandidateSchema, ID: workflow.projection.ID, Root: workflow.projection.Root, Carrier: workflow.projection.Carrier, OwnerRepo: workflow.projection.Source.Repo,
		SourceRef: admission.sourceRef.String(), SourceCommit: admission.sourceCommit.String(), SourceManifestSHA256: adoption.SourceManifestSHA256,
		SourceManifestGit: adoption.SourceManifestGit, SourceManifestSize: adoption.SourceManifestSize, AdoptionSHA256: adoptionSHA, AdoptionGit: adoptionBlob.Hash.String(), AdoptionSize: adoptionBlob.Size,
		PackageTrustSHA256: adoption.PackageTrustSHA256, PackageTrustGit: adoption.PackageTrustGit, PackageTrustSize: adoption.PackageTrustSize,
		CandidatePath: output, CandidateManifestSHA256: manifestSHA, CandidateManifestGit: manifestGit.String(), CandidateManifestSize: manifestSize,
		RepomdSHA256: generation.RepomdSHA256, RepositoryKeySHA256: repositoryKeySHA,
		RepositoryTrustSHA256: repositoryTrustSHA, RepositoryTrustGit: repositoryTrustGit.String(), RepositoryTrustSize: repositoryTrustSize,
		Packages: packages, Bytes: bytesTotal,
	}
	result.FreezeConfirm, err = yumCompatibilityConfirmation("freeze", result)
	if err != nil {
		return result, err
	}
	body, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return result, err
	}
	body = append(body, '\n')
	if err := binding.writeExclusive(pendingReceipt, body); err != nil {
		return result, err
	}
	if err := errors.Join(binding.syncParent(), binding.verifyBoundDirectory(stage, stageIdentity)); err != nil {
		return result, err
	}
	journal.Phase = yumCompatibilityCandidatePrepared
	if err := writeYUMCompatibilityCandidateJournal(binding, journal, false); err != nil {
		return result, err
	}
	if err := finalizeYUMCompatibilityCandidateJournal(binding, &journal); err != nil {
		return result, err
	}
	validationDir := filepath.Join(txDir, "candidate-final-validation")
	if err := os.Mkdir(validationDir, 0o700); err != nil {
		return result, err
	}
	validatedReceipt, err := validateYUMCompatibilityCandidate(ctx, workflow, canonical, binding, validationDir, values, adoption)
	if err != nil {
		return result, err
	}
	if err := removeYUMCompatibilityCandidateJournal(binding); err != nil {
		return result, err
	}
	_ = payloadPath // payload equality is independently re-proved by validation.
	return validatedReceipt, nil
}

func populateYUMCompatibilityBoundCandidateStage(ctx context.Context, workflow yumCompatibilityWorkflow, binding *yumCompatibilityCandidateBinding, stage, desiredManifest, actualManifest string) (os.FileInfo, error) {
	stageRoot, stageIdentity, err := binding.openBoundDirectory(stage)
	if err != nil {
		return nil, err
	}
	defer stageRoot.Close()
	if workflow.mutationHook != nil {
		if err := workflow.mutationHook("populate external yum-candidate stage"); err != nil {
			return nil, fmt.Errorf("YUM compatibility candidate stage mutation hook: %w", err)
		}
	}
	if err := linkYUMCompatibilityManifestFromBoundCAS(ctx, workflow, desiredManifest, stageRoot); err != nil {
		return nil, err
	}
	if err := makeYUMCompatibilityBoundTreeHostable(stageRoot, "."); err != nil {
		return nil, err
	}
	if err := scanYUMCompatibilityBoundMaterialization(ctx, workflow, stageRoot, actualManifest); err != nil {
		return nil, err
	}
	if err := requireManifestFilesEqual(desiredManifest, actualManifest); err != nil {
		return nil, fmt.Errorf("bound candidate stage differs from private validated candidate: %w", err)
	}
	if err := binding.verifyBoundDirectory(stage, stageIdentity); err != nil {
		return nil, err
	}
	return stageIdentity, nil
}

func makeYUMCompatibilityCandidateDirectoriesTraversable(root string) error {
	return filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("unsafe candidate entry %s", current))
		}
		if info.IsDir() {
			return os.Chmod(current, 0o755)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("candidate contains special file %s", current)
		}
		return nil
	})
}

func importYUMCompatibilityManifestObjects(ctx context.Context, pool *repository.Store, root, manifestPath string) error {
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	for {
		entry, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			return nil
		}
		if nextErr != nil {
			return nextErr
		}
		digest, err := repository.ParseDigest(entry.HashString())
		if err != nil {
			return err
		}
		if _, err := pool.ImportExpected(ctx, filepath.Join(root, filepath.FromSlash(entry.Path)), repository.Object{SHA256: digest, Size: entry.Size}); err != nil {
			return err
		}
	}
}

func writeYUMCompatibilityCandidatePayloadManifest(candidateManifest, destination string) error {
	source, err := os.Open(candidateManifest)
	if err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = source.Close()
		return err
	}
	reader := manifest.NewReader(source)
	for {
		entry, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			_ = source.Close()
			_ = output.Close()
			return nextErr
		}
		if !strings.HasSuffix(entry.Path, ".rpm") || path.Base(entry.Path) != entry.Path && !strings.HasPrefix(entry.Path, "Packages/") {
			continue
		}
		if err := manifest.WriteEntry(output, entry); err != nil {
			_ = source.Close()
			_ = output.Close()
			return err
		}
	}
	return errors.Join(source.Close(), output.Sync(), output.Close())
}

func validateYUMCompatibilityCandidate(ctx context.Context, workflow yumCompatibilityWorkflow, canonical *state.Store, binding *yumCompatibilityCandidateBinding, txDir string, values commonFlags, adoption yumCompatibilityAdoption) (result yumCompatibilityCandidate, resultErr error) {
	candidate := binding.output
	candidateRoot, candidateIdentity, err := binding.openBoundDirectory(candidate)
	if err != nil {
		return result, err
	}
	defer candidateRoot.Close()
	manifestPath, receiptPath := yumCompatibilityCandidateSidecars(candidate)
	body, err := binding.readStable(receiptPath, maximumYUMCompatibilityWitnessBytes)
	if err != nil {
		return result, errors.Join(err, errors.New("candidate receipt is absent or too large"))
	}
	result, err = decodeYUMCompatibilityCandidate(body)
	if err != nil {
		return result, err
	}
	wantConfirmation, err := yumCompatibilityConfirmation("freeze", result)
	if err != nil || result.FreezeConfirm != wantConfirmation {
		return result, errors.Join(err, errors.New("candidate freeze confirmation is not content-bound"))
	}
	sourceRef, _ := state.YUMCompatibilitySourceRef(workflow.projection.ID)
	result.CandidatePath = candidate
	if result.ID != workflow.projection.ID || result.Root != workflow.projection.Root || result.Carrier != workflow.projection.Carrier || result.OwnerRepo != workflow.projection.Source.Repo ||
		result.SourceRef != sourceRef.String() || result.SourceManifestSHA256 != adoption.SourceManifestSHA256 || result.SourceManifestGit != adoption.SourceManifestGit || result.SourceManifestSize != adoption.SourceManifestSize ||
		result.PackageTrustSHA256 != adoption.PackageTrustSHA256 || result.PackageTrustGit != adoption.PackageTrustGit || result.PackageTrustSize != adoption.PackageTrustSize || result.Packages != adoption.Packages || result.Bytes != adoption.Bytes {
		return result, errors.New("candidate receipt differs from current immutable S1 adoption")
	}
	currentSource, exists, err := canonical.Ref(sourceRef)
	if err != nil || !exists || currentSource.String() != result.SourceCommit {
		return result, errors.Join(err, errors.New("candidate source commit differs from S1 source ref"))
	}
	adoptionPath, _ := state.YUMCompatibilityAdoptionPath(workflow.projection.ID)
	adoptionBlob, exists, err := canonical.BlobIdentityAt(currentSource, adoptionPath)
	if err != nil || !exists || adoptionBlob.Hash.String() != result.AdoptionGit || adoptionBlob.Size != result.AdoptionSize {
		return result, errors.Join(err, errors.New("candidate adoption Git identity differs from S1"))
	}
	adoptionSHA, err := hashYUMCompatibilityCanonicalPathAt(canonical, currentSource, adoptionPath)
	if err != nil || adoptionSHA != result.AdoptionSHA256 {
		return result, errors.Join(err, errors.New("candidate adoption SHA-256 differs from S1"))
	}
	manifestSnapshot := filepath.Join(txDir, "candidate-sidecar-"+workflow.projection.ID+".tsv")
	if err := binding.snapshotExact(manifestPath, manifestSnapshot, result.CandidateManifestSize); err != nil {
		return result, err
	}
	manifestSHA, manifestGit, manifestSize, err := fileSHA256AndGitBlob(manifestSnapshot)
	if err != nil || manifestSHA != result.CandidateManifestSHA256 || manifestGit.String() != result.CandidateManifestGit || manifestSize != result.CandidateManifestSize {
		return result, errors.Join(err, errors.New("candidate sidecar manifest identity differs from receipt"))
	}
	scanned := filepath.Join(txDir, "candidate-actual-"+workflow.projection.ID+".tsv")
	if err := scanYUMCompatibilityBoundMaterialization(ctx, workflow, candidateRoot, scanned); err != nil {
		return result, err
	}
	if err := binding.verifyBoundDirectory(candidate, candidateIdentity); err != nil {
		return result, err
	}
	if err := requireManifestFilesEqual(manifestSnapshot, scanned); err != nil {
		return result, fmt.Errorf("candidate tree differs from exact receipt manifest: %w", err)
	}
	admission, err := admitYUMCompatibilityProjection(workflow.cfg, canonical, workflow.projection)
	if err != nil {
		return result, err
	}
	_, _, expectedPayload, _, packages, bytesTotal, err := buildYUMCompatibilityPayload(canonical, admission, txDir)
	if err != nil {
		return result, err
	}
	actualPayload := filepath.Join(txDir, "candidate-payload-"+workflow.projection.ID+".tsv")
	if err := writeYUMCompatibilityCandidatePayloadManifest(scanned, actualPayload); err != nil {
		return result, err
	}
	if err := binding.verifyBoundDirectory(candidate, candidateIdentity); err != nil {
		return result, err
	}
	if err := requireManifestFilesEqual(expectedPayload, actualPayload); err != nil || packages != result.Packages || bytesTotal != result.Bytes {
		return result, errors.Join(err, errors.New("candidate RPM payload differs from S1"))
	}
	privateCAS, err := newYUMCompatibilityCASWorkspace()
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, privateCAS.Close()) }()
	if err := privateCAS.MirrorManifest(ctx, workflow, manifestSnapshot); err != nil {
		return result, fmt.Errorf("mirror bound candidate into private validation CAS: %w", err)
	}
	privateCandidate, err := privateCAS.MaterializeManifest(ctx, manifestSnapshot, "candidate-validate", values.workers)
	if err != nil {
		return result, err
	}
	packageTrust, err := stageYUMCompatibilityPackageTrust(workflow.cfg, canonical, admission, txDir)
	if err != nil || packageTrust.sha256 != result.PackageTrustSHA256 || packageTrust.size != result.PackageTrustSize {
		return result, errors.Join(err, errors.New("candidate package trust differs during private validation"))
	}
	if err := verifyYUMPackageManifest(ctx, expectedPayload, privateCandidate, packageTrust.keyring, timeNowUTC(), values.workers); err != nil {
		return result, fmt.Errorf("candidate private RPM trust validation: %w", err)
	}
	repositoryPackets, err := loadCandidateRepositoryTrust(workflow, canonical, result)
	if err != nil || repositoryTrustAnchorDigest(repositoryPackets) != result.RepositoryKeySHA256 || digestBytesCLI(repositoryPackets) != result.RepositoryTrustSHA256 {
		return result, errors.Join(err, errors.New("candidate repository signing identity differs from receipt/frozen trust"))
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(repositoryPackets), timeNowUTC())
	if err != nil {
		return result, err
	}
	generation, err := yumrepo.ValidateDirectory(ctx, filepath.Join(privateCandidate, "repodata"), yumrepo.CompressionGzip, verifier)
	if err != nil || !yumGenerationMatches(generation, result.RepomdSHA256, result.Packages) {
		return result, errors.Join(err, errors.New("candidate signed metadata differs from receipt"))
	}
	if err := validateYUMCompatibilityCandidateShape(privateCandidate, expectedPayload, generation); err != nil {
		return result, err
	}
	if err := binding.verifyBoundDirectory(candidate, candidateIdentity); err != nil {
		return result, err
	}
	return result, nil
}

func validateYUMCompatibilityCandidateShape(root, expectedPayload string, generation *yumrepo.Generation) error {
	if generation == nil {
		return errors.New("candidate generation is unavailable")
	}
	allowedFiles := make(map[string]struct{})
	allowedDirectories := map[string]struct{}{".": {}, "Packages": {}, "repodata": {}}
	payload, err := os.Open(expectedPayload)
	if err != nil {
		return err
	}
	reader := manifest.NewReader(payload)
	for {
		entry, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			_ = payload.Close()
			return nextErr
		}
		if !strings.HasSuffix(entry.Path, ".rpm") || entry.Path != path.Clean(entry.Path) ||
			(path.Base(entry.Path) != entry.Path && !strings.HasPrefix(entry.Path, "Packages/")) {
			_ = payload.Close()
			return fmt.Errorf("candidate payload path %q is outside flat aliases and canonical Packages", entry.Path)
		}
		allowedFiles[entry.Path] = struct{}{}
		for parent := path.Dir(entry.Path); parent != "."; parent = path.Dir(parent) {
			allowedDirectories[parent] = struct{}{}
		}
	}
	if err := payload.Close(); err != nil {
		return err
	}
	wantedTypes := map[string]bool{"primary": false, "filelists": false, "other": false}
	for _, artifact := range generation.Artifacts {
		if _, exists := wantedTypes[artifact.Type]; !exists || wantedTypes[artifact.Type] {
			return fmt.Errorf("candidate generation has duplicate or unsupported metadata type %q", artifact.Type)
		}
		if path.Dir(artifact.Path) != "repodata" || !strings.HasSuffix(artifact.Path, "-"+artifact.Type+".xml.gz") || path.Clean(artifact.Path) != artifact.Path {
			return fmt.Errorf("candidate metadata artifact %q violates the frozen XML gzip shape", artifact.Path)
		}
		wantedTypes[artifact.Type] = true
		allowedFiles[artifact.Path] = struct{}{}
	}
	for kind, present := range wantedTypes {
		if !present {
			return fmt.Errorf("candidate generation is missing %s metadata", kind)
		}
	}
	allowedFiles["repodata/repomd.xml"] = struct{}{}
	allowedFiles["repodata/repomd.xml.asc"] = struct{}{}
	seenFiles := make(map[string]struct{}, len(allowedFiles))
	err = filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("candidate contains unsafe entry %s", relative))
		}
		if info.IsDir() {
			if _, allowed := allowedDirectories[relative]; !allowed {
				return fmt.Errorf("candidate contains unexpected directory %s", relative)
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("candidate contains non-regular entry %s", relative)
		}
		if _, allowed := allowedFiles[relative]; !allowed {
			return fmt.Errorf("candidate contains unexpected file %s", relative)
		}
		seenFiles[relative] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seenFiles) != len(allowedFiles) {
		return fmt.Errorf("candidate shape has %d files, want exact %d-file payload and metadata closure", len(seenFiles), len(allowedFiles))
	}
	return nil
}

func decodeYUMCompatibilityCandidate(body []byte) (yumCompatibilityCandidate, error) {
	var result yumCompatibilityCandidate
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return result, errors.New("candidate receipt has trailing JSON")
	}
	if result.Schema != yumCompatibilityCandidateSchema || !validYUMCompatibilityEventID(result.ID) || !validYUMCompatibilityLogicalPath(result.Root) || strings.HasPrefix(result.Root, ".sow/") || result.Carrier == "" || result.OwnerRepo == "" || result.SourceRef == "" ||
		!validNonZeroGitHash(result.SourceCommit) || result.Packages < 1 || result.Bytes < 1 || result.SourceManifestSize < 1 || result.AdoptionSize < 1 || result.PackageTrustSize < 1 || result.CandidateManifestSize < 1 || result.RepositoryTrustSize < 1 || result.FreezeConfirm == "" {
		return result, errors.New("candidate receipt is incomplete or unsupported")
	}
	wantSourceRef, err := state.YUMCompatibilitySourceRef(result.ID)
	if err != nil || result.SourceRef != wantSourceRef.String() {
		return result, errors.Join(err, errors.New("candidate source ref is not the controlled immutable compatibility ref"))
	}
	for name, value := range map[string]string{
		"source manifest": result.SourceManifestSHA256, "adoption": result.AdoptionSHA256, "package trust": result.PackageTrustSHA256,
		"candidate manifest": result.CandidateManifestSHA256, "repomd": result.RepomdSHA256, "repository key": result.RepositoryKeySHA256, "repository trust": result.RepositoryTrustSHA256,
	} {
		if !validLowerSHA256(value) {
			return result, fmt.Errorf("candidate %s SHA-256 is invalid", name)
		}
	}
	for name, value := range map[string]string{"source manifest": result.SourceManifestGit, "adoption": result.AdoptionGit, "package trust": result.PackageTrustGit, "candidate manifest": result.CandidateManifestGit, "repository trust": result.RepositoryTrustGit} {
		if !validNonZeroGitHash(value) {
			return result, fmt.Errorf("candidate %s Git blob is invalid", name)
		}
	}
	return result, nil
}

func validLowerSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validNonZeroGitHash(value string) bool {
	return plumbing.IsHash(value) && value != plumbing.ZeroHash.String() && value == strings.ToLower(value)
}

func yumCompatibilityConfirmation(action string, candidate yumCompatibilityCandidate) (string, error) {
	copy := candidate
	copy.FreezeConfirm = ""
	body, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("sow-yum-compatibility-confirm-v1\x00" + action + "\x00"))
	_, _ = digest.Write(body)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

type yumCompatibilityFrozenState struct {
	Commit              plumbing.Hash
	Receipt             yumCompatibilityCandidate
	ReceiptBody         []byte
	ReceiptBlob         state.BlobIdentity
	CandidateManifest   state.BlobIdentity
	RepositoryTrust     []byte
	RepositoryTrustBlob state.BlobIdentity
	Witness             yumCompatibilityWitness
}

func loadYUMCompatibilityFrozenStateAt(canonical *state.Store, commit plumbing.Hash, id string) (yumCompatibilityFrozenState, error) {
	var result yumCompatibilityFrozenState
	if canonical == nil {
		return result, errors.New("canonical state is unavailable")
	}
	freezeRef, err := state.YUMCompatibilityRef(id)
	if err != nil {
		return result, err
	}
	freezeCommit, exists, err := canonical.Ref(freezeRef)
	if err != nil || !exists || freezeCommit.IsZero() {
		return result, errors.Join(err, fmt.Errorf("S2 freeze ref %s is missing", freezeRef))
	}
	if commit.IsZero() {
		commit, err = canonical.HeadHash()
		if err != nil || commit.IsZero() {
			return result, errors.Join(err, errors.New("canonical HEAD is unavailable"))
		}
	}
	if ancestor, ancestryErr := canonical.IsAncestor(freezeCommit, commit); ancestryErr != nil || !ancestor {
		return result, errors.Join(ancestryErr, fmt.Errorf("S2 freeze %s is not reachable from requested state", freezeCommit))
	}
	receiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(id)
	receiptBody, exists, err := readCanonicalBytesAt(canonical, freezeCommit, receiptPath, maximumYUMCompatibilityWitnessBytes)
	if err != nil || !exists {
		return result, errors.Join(err, errors.New("S2 candidate receipt is missing"))
	}
	receipt, err := decodeYUMCompatibilityCandidate(receiptBody)
	if err != nil || receipt.ID != id {
		return result, errors.Join(err, errors.New("S2 candidate receipt identity is invalid"))
	}
	confirmation, err := yumCompatibilityConfirmation("freeze", receipt)
	if err != nil || receipt.FreezeConfirm != confirmation {
		return result, errors.Join(err, errors.New("S2 candidate receipt confirmation is invalid"))
	}
	receiptBlob, exists, err := canonical.BlobIdentityAt(freezeCommit, receiptPath)
	if err != nil || !exists || receiptBlob.Size != int64(len(receiptBody)) {
		return result, errors.Join(err, errors.New("S2 candidate receipt Git identity is missing"))
	}
	candidatePath, _ := state.YUMCompatibilityCandidateManifestPath(id)
	candidateBlob, exists, err := canonical.BlobIdentityAt(freezeCommit, candidatePath)
	if err != nil || !exists || candidateBlob.Hash.String() != receipt.CandidateManifestGit || candidateBlob.Size != receipt.CandidateManifestSize {
		return result, errors.Join(err, errors.New("S2 candidate manifest Git identity changed"))
	}
	streamingGit, closeStreaming, err := openStreamingYUMCompatibilityGit(canonical)
	if err != nil {
		return result, fmt.Errorf("open streaming S2 object store: %w", err)
	}
	candidateSHA, err := hashYUMCompatibilityHistoryBlob(streamingGit, candidateBlob, make(map[plumbing.Hash]string, 1))
	closeStorageErr := closeStreaming()
	if err != nil || closeStorageErr != nil || candidateSHA != receipt.CandidateManifestSHA256 {
		return result, errors.Join(err, closeStorageErr, errors.New("S2 candidate manifest digest changed"))
	}
	repositoryTrustPath, _ := state.YUMCompatibilityRepositoryTrustPath(id)
	repositoryTrust, exists, err := readCanonicalBytesAt(canonical, freezeCommit, repositoryTrustPath, maxSecretBytes)
	if err != nil || !exists || int64(len(repositoryTrust)) != receipt.RepositoryTrustSize || digestBytesCLI(repositoryTrust) != receipt.RepositoryTrustSHA256 || repositoryTrustAnchorDigest(repositoryTrust) != receipt.RepositoryKeySHA256 {
		return result, errors.Join(err, errors.New("S2 repository trust bytes changed"))
	}
	repositoryTrustBlob, exists, err := canonical.BlobIdentityAt(freezeCommit, repositoryTrustPath)
	if err != nil || !exists || repositoryTrustBlob.Hash.String() != receipt.RepositoryTrustGit || repositoryTrustBlob.Size != receipt.RepositoryTrustSize {
		return result, errors.Join(err, errors.New("S2 repository trust Git identity changed"))
	}
	packageTrustPath, _ := state.YUMCompatibilityPackageTrustPath(id)
	packageTrustBlob, exists, err := canonical.BlobIdentityAt(freezeCommit, packageTrustPath)
	if err != nil || !exists || packageTrustBlob.Hash.String() != receipt.PackageTrustGit || packageTrustBlob.Size != receipt.PackageTrustSize {
		return result, errors.Join(err, errors.New("S2 package trust identity changed"))
	}
	packageTrust, exists, err := readCanonicalBytesAt(canonical, freezeCommit, packageTrustPath, maxSecretBytes)
	if err != nil || !exists || digestBytesCLI(packageTrust) != receipt.PackageTrustSHA256 {
		return result, errors.Join(err, errors.New("S2 package trust bytes changed"))
	}
	witnessPath, _ := state.YUMCompatibilityProjectionPath(id)
	witnessBody, exists, err := readCanonicalBytesAt(canonical, freezeCommit, witnessPath, maximumYUMCompatibilityWitnessBytes)
	if err != nil || !exists {
		return result, errors.Join(err, errors.New("S2 projection witness is missing"))
	}
	witness, err := decodeYUMCompatibilityWitness(witnessBody)
	if err != nil || witness.ID != id || witness.Root != receipt.Root || witness.Carrier != receipt.Carrier || witness.SourceRepo != receipt.OwnerRepo || witness.SourceRef != receipt.SourceRef || witness.SourceCommit != receipt.SourceCommit || witness.SourceManifestSHA != receipt.SourceManifestSHA256 || witness.SourceManifestGit != receipt.SourceManifestGit || witness.SourceManifestLen != receipt.SourceManifestSize || witness.AdoptionSHA != receipt.AdoptionSHA256 || witness.AdoptionGit != receipt.AdoptionGit || witness.AdoptionLen != receipt.AdoptionSize || witness.PackageTrustSHA != receipt.PackageTrustSHA256 || witness.PackageTrustGit != receipt.PackageTrustGit || witness.PackageTrustLen != receipt.PackageTrustSize || witness.Packages != receipt.Packages || witness.Bytes != receipt.Bytes {
		return result, errors.Join(err, errors.New("S2 witness differs from candidate receipt"))
	}
	result = yumCompatibilityFrozenState{
		Commit: freezeCommit, Receipt: receipt, ReceiptBody: receiptBody, ReceiptBlob: receiptBlob,
		CandidateManifest: candidateBlob, RepositoryTrust: repositoryTrust, RepositoryTrustBlob: repositoryTrustBlob, Witness: witness,
	}
	return result, nil
}

// loadYUMCompatibilityCutoverStateAt is the shared S3 admission gate. A zero
// commit means current HEAD; callers restoring history pass an explicit commit.
// The portable ledger is validated against the exact immutable S2 receipt and
// never trusts machine-local crash-journal paths.
func loadYUMCompatibilityCutoverStateAt(canonical *state.Store, commit plumbing.Hash, id string) (yumCompatibilityCutoverState, error) {
	var result yumCompatibilityCutoverState
	if canonical == nil {
		return result, errors.New("canonical state is unavailable")
	}
	if commit.IsZero() {
		var err error
		commit, err = canonical.HeadHash()
		if err != nil || commit.IsZero() {
			return result, errors.Join(err, errors.New("canonical HEAD is unavailable"))
		}
	}
	frozen, err := loadYUMCompatibilityFrozenStateAt(canonical, commit, id)
	if err != nil {
		return result, err
	}
	ledgerPath, _ := state.YUMCompatibilityCutoverPath(id)
	body, exists, err := readCanonicalBytesAt(canonical, commit, ledgerPath, maximumYUMCompatibilityLedgerBytes)
	if err != nil {
		return result, err
	}
	if !exists {
		return yumCompatibilityCutoverState{Stage: yumCompatibilityStageS2}, nil
	}
	events, err := decodeYUMCompatibilityCutoverLedger(body)
	if err != nil {
		return result, err
	}
	for index, event := range events {
		if event.ID != id || event.FreezeCommit != frozen.Commit.String() || event.CandidateManifestSHA256 != frozen.Receipt.CandidateManifestSHA256 {
			return result, fmt.Errorf("cutover event %d differs from immutable S2 identity", index+1)
		}
		if index == 0 && event.FromTarget != frozen.Receipt.Root {
			return result, fmt.Errorf("first cutover event raw target %q differs from projection root %q", event.FromTarget, frozen.Receipt.Root)
		}
	}
	stage := yumCompatibilityLedgerStage(events)
	result = yumCompatibilityCutoverState{Stage: stage, Active: stage == yumCompatibilityStageS3, Events: events, Last: events[len(events)-1]}
	return result, nil
}

func stageYUMCompatibilityFreezeWitness(canonical *state.Store, admission yumCompatibilityAdmission, witnessManifest string, trust yumCompatibilityPackageTrust, packages, bytesTotal int64, txDir string) (string, error) {
	manifestSHA, manifestGit, manifestSize, err := fileSHA256AndGitBlob(witnessManifest)
	if err != nil {
		return "", err
	}
	sourceBlob, exists, err := canonical.BlobIdentityAt(admission.sourceCommit, admission.sourcePath)
	if err != nil || !exists {
		return "", errors.Join(err, errors.New("immutable S1 source manifest is missing"))
	}
	sourceSHA, err := hashYUMCompatibilityCanonicalPathAt(canonical, admission.sourceCommit, admission.sourcePath)
	if err != nil {
		return "", err
	}
	adoptionPath, _ := state.YUMCompatibilityAdoptionPath(admission.projection.ID)
	adoptionBlob, exists, err := canonical.BlobIdentityAt(admission.sourceCommit, adoptionPath)
	if err != nil || !exists {
		return "", errors.Join(err, errors.New("immutable S1 adoption receipt is missing"))
	}
	adoptionSHA, err := hashYUMCompatibilityCanonicalPathAt(canonical, admission.sourceCommit, adoptionPath)
	if err != nil {
		return "", err
	}
	witness := yumCompatibilityWitness{
		Schema: yumCompatibilityWitnessSchema, ID: admission.projection.ID, Root: admission.projection.Root, Mode: admission.projection.Mode, Carrier: admission.projection.Carrier,
		SourceRepo: admission.projection.Source.Repo, SourceView: admission.projection.Source.View, SourceOS: admission.projection.Source.OS, SourceArch: admission.projection.Source.Arch, SourceRoot: admission.sourcePath,
		SourceRef: admission.sourceRef.String(), SourceCommit: admission.sourceCommit.String(), SourceManifestSHA: sourceSHA, SourceManifestGit: sourceBlob.Hash.String(), SourceManifestLen: sourceBlob.Size,
		AdoptionSHA: adoptionSHA, AdoptionGit: adoptionBlob.Hash.String(), AdoptionLen: adoptionBlob.Size,
		PayloadManifestSHA: manifestSHA, PayloadManifestGit: manifestGit.String(), PayloadManifestLen: manifestSize,
		PackageTrustSHA: trust.sha256, PackageTrustGit: trust.gitBlob.String(), PackageTrustLen: trust.size,
		Packages: packages, Bytes: bytesTotal, FlatAliases: true,
	}
	body, err := json.MarshalIndent(witness, "", "  ")
	if err != nil {
		return "", err
	}
	body = append(body, '\n')
	destination := filepath.Join(txDir, "yum-compat-"+admission.projection.ID+"-projection.json")
	if err := writeExclusiveBytes(destination, body); err != nil {
		return "", err
	}
	return destination, nil
}

func yumCompatibilityLogicalServingPaths(frozen yumCompatibilityFrozenState) (servingLink, rawTarget, candidateTarget string) {
	id := frozen.Receipt.ID
	return path.Join(".sow", "serving", "compatibility", "yum", id, "current"), frozen.Receipt.Root,
		path.Join(".sow", "materialized", "compatibility", id, frozen.Receipt.CandidateManifestSHA256)
}

func materializeFrozenYUMCompatibilityCandidate(ctx context.Context, workflow yumCompatibilityWorkflow, canonical *state.Store, frozen yumCompatibilityFrozenState, txDir string, _ commonFlags) error {
	_, _, candidateTarget := yumCompatibilityLogicalServingPaths(frozen)
	candidatePath, _ := state.YUMCompatibilityCandidateManifestPath(workflow.projection.ID)
	localManifest := filepath.Join(txDir, "cutover-candidate.tsv")
	if err := copyCanonicalPathAt(canonical, frozen.Commit, candidatePath, localManifest, frozen.Receipt.CandidateManifestSize); err != nil {
		return err
	}
	actual := filepath.Join(txDir, "cutover-candidate-actual.tsv")
	if err := materializeYUMCompatibilityManifestBound(ctx, workflow, localManifest, candidateTarget, actual); err != nil {
		return fmt.Errorf("materialize controlled S3 candidate through bound root: %w", err)
	}
	snapshot := filepath.Join(txDir, "cutover-candidate-tree")
	if err := copyYUMCompatibilityBoundTreeToLocal(workflow.root.root, filepath.FromSlash(candidateTarget), snapshot); err != nil {
		return err
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(frozen.RepositoryTrust), timeNowUTC())
	if err != nil {
		return err
	}
	generation, err := yumrepo.ValidateDirectory(ctx, filepath.Join(snapshot, "repodata"), yumrepo.CompressionGzip, verifier)
	if err != nil || !yumGenerationMatches(generation, frozen.Receipt.RepomdSHA256, frozen.Receipt.Packages) {
		return errors.Join(err, errors.New("controlled S3 candidate metadata differs from frozen receipt"))
	}
	return nil
}

func buildNextYUMCompatibilityCutoverEvent(frozen yumCompatibilityFrozenState, stateAtHead yumCompatibilityCutoverState, action string) (yumCompatibilityCutoverEvent, error) {
	servingLink, rawTarget, candidateTarget := yumCompatibilityLogicalServingPaths(frozen)
	event := yumCompatibilityCutoverEvent{
		Schema: yumCompatibilityCutoverEventSchema, Sequence: int64(len(stateAtHead.Events) + 1), ID: frozen.Receipt.ID,
		Action: action, ServingLink: servingLink, FreezeCommit: frozen.Commit.String(), CandidateManifestSHA256: frozen.Receipt.CandidateManifestSHA256,
		PreviousEventSHA256: strings.Repeat("0", 64),
	}
	if len(stateAtHead.Events) == 0 {
		if action != "cutover" {
			return event, errors.New("rollback requires a prior cutover event")
		}
		event.FromTarget, event.ToTarget = rawTarget, candidateTarget
	} else {
		previous := stateAtHead.Events[len(stateAtHead.Events)-1]
		if action == previous.Action {
			return event, fmt.Errorf("compatibility state is already %s", action)
		}
		event.FromTarget, event.ToTarget = previous.ToTarget, previous.FromTarget
		event.PreviousEventSHA256 = previous.EventSHA256
	}
	hash, err := buildYUMCompatibilityCutoverEventHash(event)
	if err != nil {
		return event, err
	}
	event.EventSHA256 = hash
	prior := append([]yumCompatibilityCutoverEvent(nil), stateAtHead.Events...)
	if err := validateYUMCompatibilityCutoverEvent(event, prior); err != nil {
		return event, err
	}
	return event, nil
}

func appendYUMCompatibilityCutoverEvent(ctx context.Context, canonical *state.Store, event yumCompatibilityCutoverEvent, txDir string) (plumbing.Hash, error) {
	ledgerPath, err := state.YUMCompatibilityCutoverPath(event.ID)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return plumbing.ZeroHash, errors.Join(err, errors.New("canonical HEAD is unavailable"))
	}
	existing, exists, err := readCanonicalBytesAt(canonical, head, ledgerPath, maximumYUMCompatibilityLedgerBytes)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	if exists {
		prior, err := decodeYUMCompatibilityCutoverLedger(existing)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		if err := validateYUMCompatibilityCutoverEvent(event, prior); err != nil {
			return plumbing.ZeroHash, err
		}
	} else if err := validateYUMCompatibilityCutoverEvent(event, nil); err != nil {
		return plumbing.ZeroHash, err
	}
	line, err := json.Marshal(event)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	body := append(append(append([]byte(nil), existing...), line...), '\n')
	if len(body) > maximumYUMCompatibilityLedgerBytes {
		return plumbing.ZeroHash, errors.New("YUM compatibility cutover ledger exceeds its bound")
	}
	if _, err := decodeYUMCompatibilityCutoverLedger(body); err != nil {
		return plumbing.ZeroHash, err
	}
	stage := filepath.Join(txDir, "cutover.jsonl")
	if err := writeExclusiveBytes(stage, body); err != nil {
		return plumbing.ZeroHash, err
	}
	expectation := state.FileExpectation{AllowAbsent: !exists}
	if exists {
		identity, present, err := canonical.FileIdentityAtHead(ledgerPath)
		if err != nil || !present {
			return plumbing.ZeroHash, errors.Join(err, errors.New("cutover ledger disappeared before append"))
		}
		expectation.Identities = []state.FileIdentity{identity}
	}
	commit, changed, err := applyCanonicalState(ctx, canonical, "yum-compatibility-"+event.Action, "sow compatibility yum-"+event.Action+": "+event.ID,
		map[string]string{ledgerPath: stage}, nil, state.ApplyOptions{ExpectedFiles: map[string]state.FileExpectation{ledgerPath: expectation}})
	if err != nil {
		return commit, err
	}
	if !changed {
		return commit, errors.New("cutover ledger append produced no canonical change")
	}
	return commit, nil
}

func yumCompatibilityCutoverJournalPath(cfg *config.Config, id string) string {
	return filepath.Join(cfg.StatePath(), "yum-compatibility-cutover-"+id+".journal.json")
}

func pendingYUMCompatibilityCutoverJournals(stateDir, exceptID string) ([]string, error) {
	entries, err := os.ReadDir(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	prefix := "yum-compatibility-cutover-"
	allowed := prefix + exceptID + ".journal.json"
	allowedNext := allowed + ".next"
	var pending []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || (!strings.HasSuffix(name, ".journal.json") && !strings.HasSuffix(name, ".journal.json.next")) {
			continue
		}
		if exceptID != "" && (name == allowed || name == allowedNext) {
			continue
		}
		pending = append(pending, filepath.Join(stateDir, name))
	}
	sort.Strings(pending)
	return pending, nil
}

func requireNoPendingYUMCompatibilityCutoverJournals(stateDir string) error {
	return requireNoPendingYUMCompatibilityCutoverJournalsExcept(stateDir, "")
}

func requireNoPendingYUMCompatibilityCutoverJournalsExcept(stateDir, exceptID string) error {
	pending, err := pendingYUMCompatibilityCutoverJournals(stateDir, exceptID)
	if err != nil {
		return fmt.Errorf("inspect pending YUM compatibility cutover journals: %w", err)
	}
	if len(pending) == 0 {
		return nil
	}
	return fmt.Errorf("pending YUM compatibility cutover journal %s blocks ordinary commands; rerun the matching sow compatibility yum-cutover or yum-rollback command with its original --confirm token and --recover", pending[0])
}

func physicalYUMCompatibilityCutoverJournal(cfg *config.Config, event yumCompatibilityCutoverEvent) (yumCompatibilityCutoverJournal, error) {
	var result yumCompatibilityCutoverJournal
	if cfg == nil {
		return result, errors.New("configuration is unavailable")
	}
	for _, logical := range []string{event.ServingLink, event.FromTarget, event.ToTarget} {
		if !validYUMCompatibilityLogicalPath(logical) {
			return result, fmt.Errorf("unsafe compatibility logical path %q", logical)
		}
	}
	result = yumCompatibilityCutoverJournal{
		Schema: yumCompatibilityCutoverJournalSchema, ID: event.ID, Action: event.Action, Phase: yumCompatibilityCutoverPrepared, EventSHA256: event.EventSHA256,
		ServingLink: filepath.Join(cfg.Root, filepath.FromSlash(event.ServingLink)), FromTarget: filepath.Join(cfg.Root, filepath.FromSlash(event.FromTarget)), ToTarget: filepath.Join(cfg.Root, filepath.FromSlash(event.ToTarget)),
	}
	return result, nil
}

func writeYUMCompatibilityCutoverJournal(cfg *config.Config, journal yumCompatibilityCutoverJournal, exclusive bool) error {
	body, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	destination := yumCompatibilityCutoverJournalPath(cfg, journal.ID)
	if exclusive {
		return writeExclusiveAtomicYUMCompatibilityJournalBytes(destination, body)
	}
	pending := destination + ".next"
	if err := writeExclusiveBytes(pending, body); err != nil {
		return err
	}
	if err := os.Rename(pending, destination); err != nil {
		return err
	}
	return syncLocalDirectory(filepath.Dir(destination))
}

var errPartialYUMCompatibilityCutoverJournalEncoding = errors.New("partial cutover journal encoding")

func readYUMCompatibilityCutoverJournalAt(filename, id string) (yumCompatibilityCutoverJournal, bool, error) {
	var result yumCompatibilityCutoverJournal
	body, err := readStableRegularLimited(filename, maximumYUMCompatibilityWitnessBytes)
	if errors.Is(err, os.ErrNotExist) {
		return result, false, nil
	}
	if err != nil {
		return result, false, fmt.Errorf("%w: %v", errPartialYUMCompatibilityCutoverJournalEncoding, err)
	}
	result, err = decodeYUMCompatibilityCutoverJournalBody(body, id)
	return result, true, err
}

func decodeYUMCompatibilityCutoverJournalBody(body []byte, id string) (yumCompatibilityCutoverJournal, error) {
	var result yumCompatibilityCutoverJournal
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, fmt.Errorf("%w: %v", errPartialYUMCompatibilityCutoverJournalEncoding, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return result, fmt.Errorf("%w: trailing JSON", errPartialYUMCompatibilityCutoverJournalEncoding)
	}
	if result.Schema != yumCompatibilityCutoverJournalSchema || result.ID != id || (result.Action != "cutover" && result.Action != "rollback") || (result.Phase != yumCompatibilityCutoverPrepared && result.Phase != yumCompatibilityCutoverCommitted) || !validLowerSHA256(result.EventSHA256) {
		return result, errors.New("cutover crash journal is incomplete")
	}
	for _, value := range []string{result.ServingLink, result.FromTarget, result.ToTarget} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsAny(value, "\x00\t\r\n") {
			return result, errors.New("cutover crash journal physical path is unsafe")
		}
	}
	return result, nil
}

func sameYUMCompatibilityCutoverJournalIdentity(left, right yumCompatibilityCutoverJournal) bool {
	left.Phase, right.Phase = "", ""
	return left == right
}

type yumCompatibilityCutoverJournalPair struct {
	Main       yumCompatibilityCutoverJournal
	MainExists bool
	Next       yumCompatibilityCutoverJournal
	NextExists bool
}

var errPartialYUMCompatibilityCutoverJournalNext = errors.New("partial cutover journal pending phase update")

func readYUMCompatibilityCutoverJournalPair(cfg *config.Config, id string, recover bool) (yumCompatibilityCutoverJournalPair, error) {
	var pair yumCompatibilityCutoverJournalPair
	base := yumCompatibilityCutoverJournalPath(cfg, id)
	nextPath := base + ".next"
	nextInfo, nextStatErr := os.Lstat(nextPath)
	if nextStatErr == nil {
		if !recover {
			return pair, fmt.Errorf("incomplete cutover journal phase update exists at %s; rerun the same compatibility command with --recover", nextPath)
		}
		if !nextInfo.Mode().IsRegular() || nextInfo.Mode()&os.ModeSymlink != 0 {
			return pair, errors.New("cutover journal pending phase update is not a regular file")
		}
	} else if !errors.Is(nextStatErr, os.ErrNotExist) {
		return pair, nextStatErr
	}
	var err error
	pair.Main, pair.MainExists, err = readYUMCompatibilityCutoverJournalAt(base, id)
	if err != nil {
		return pair, err
	}
	pair.Next, pair.NextExists, err = readYUMCompatibilityCutoverJournalAt(nextPath, id)
	if err != nil {
		if errors.Is(err, errPartialYUMCompatibilityCutoverJournalEncoding) {
			return pair, fmt.Errorf("%w: %v", errPartialYUMCompatibilityCutoverJournalNext, err)
		}
		return pair, fmt.Errorf("cutover journal pending phase update conflicts with the durable transaction: %w", err)
	}
	if !pair.NextExists {
		return pair, nil
	}
	if !pair.MainExists {
		return pair, nil
	}
	mainInfo, mainErr := os.Lstat(base)
	nextInfo, nextErr := os.Lstat(nextPath)
	if mainErr != nil || nextErr != nil || !mainInfo.Mode().IsRegular() || mainInfo.Mode()&os.ModeSymlink != 0 || !nextInfo.Mode().IsRegular() || nextInfo.Mode()&os.ModeSymlink != 0 {
		return pair, errors.Join(mainErr, nextErr, errors.New("cutover journal pair is not two safe regular files"))
	}
	if os.SameFile(mainInfo, nextInfo) {
		if pair.Main.Phase != yumCompatibilityCutoverPrepared || pair.Next.Phase != yumCompatibilityCutoverPrepared || !sameYUMCompatibilityCutoverJournalIdentity(pair.Main, pair.Next) {
			return pair, errors.New("atomically installed cutover journal pair is inconsistent")
		}
		if err := os.Remove(nextPath); err != nil {
			return pair, err
		}
		if err := syncLocalDirectory(filepath.Dir(base)); err != nil {
			return pair, err
		}
		pair.Next, pair.NextExists = yumCompatibilityCutoverJournal{}, false
		return pair, nil
	}
	if pair.Main.Phase != yumCompatibilityCutoverPrepared || pair.Next.Phase != yumCompatibilityCutoverCommitted || !sameYUMCompatibilityCutoverJournalIdentity(pair.Main, pair.Next) {
		return pair, errors.New("cutover journal pending phase update differs from the exact prepared event")
	}
	return pair, nil
}

func physicalPathBelowYUMCompatibilityRoot(rootPath, physical string) (string, error) {
	if !filepath.IsAbs(rootPath) || !filepath.IsAbs(physical) {
		return "", errors.New("compatibility root and physical path must be absolute")
	}
	relative, err := filepath.Rel(filepath.Clean(rootPath), filepath.Clean(physical))
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", errors.Join(err, fmt.Errorf("physical compatibility path %s escapes repository root %s", physical, rootPath))
	}
	return filepath.Clean(relative), nil
}

func openBoundYUMCompatibilityRepositoryRoot(rootPath string) (*os.Root, os.FileInfo, error) {
	info, err := os.Lstat(rootPath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.Join(err, fmt.Errorf("repository root %s is not a real directory", rootPath))
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, nil, err
	}
	bound, err := root.Stat(".")
	if err != nil || !os.SameFile(info, bound) {
		_ = root.Close()
		return nil, nil, errors.Join(err, errors.New("repository root changed while it was opened"))
	}
	return root, bound, nil
}

// openRealYUMCompatibilityDirectory walks one component at a time. Each child
// directory is opened and then compared to the lstat identity observed through
// its already-bound parent. A replacement between check and open therefore
// fails, while later replacements cannot redirect operations through the
// returned directory handle.
func openRealYUMCompatibilityDirectory(root *os.Root, relative string, create bool) (*os.Root, os.FileInfo, error) {
	if root == nil || relative == "" || relative == "." || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, nil, errors.New("unsafe root-relative compatibility directory")
	}
	current := root
	owned := false
	closeOwned := func() {
		if owned {
			_ = current.Close()
		}
	}
	for _, segment := range strings.Split(relative, string(filepath.Separator)) {
		if segment == "" || segment == "." || segment == ".." {
			closeOwned()
			return nil, nil, errors.New("unsafe compatibility directory segment")
		}
		info, err := current.Lstat(segment)
		if errors.Is(err, os.ErrNotExist) && create {
			if err := current.Mkdir(segment, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				closeOwned()
				return nil, nil, err
			}
			info, err = current.Lstat(segment)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			closeOwned()
			return nil, nil, errors.Join(err, fmt.Errorf("controlled compatibility directory %s is absent, symlinked, or not a directory", relative))
		}
		next, err := current.OpenRoot(segment)
		if err != nil {
			closeOwned()
			return nil, nil, err
		}
		bound, err := next.Stat(".")
		if err != nil || !os.SameFile(info, bound) {
			_ = next.Close()
			closeOwned()
			return nil, nil, errors.Join(err, fmt.Errorf("controlled compatibility directory %s changed while it was opened", relative))
		}
		if owned {
			_ = current.Close()
		}
		current, owned = next, true
	}
	bound, err := current.Stat(".")
	if err != nil {
		closeOwned()
		return nil, nil, err
	}
	return current, bound, nil
}

func verifyBoundYUMCompatibilityDirectory(root *os.Root, relative string, expected os.FileInfo) error {
	current, actual, err := openRealYUMCompatibilityDirectory(root, relative, false)
	if current != nil {
		_ = current.Close()
	}
	if err != nil || expected == nil || !os.SameFile(expected, actual) {
		return errors.Join(err, fmt.Errorf("controlled compatibility directory %s was replaced during serving-link flip", relative))
	}
	return nil
}

func syncYUMCompatibilityRootDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func reconcileYUMCompatibilityServingLink(cfg *config.Config, journal yumCompatibilityCutoverJournal) error {
	return reconcileYUMCompatibilityServingLinkWithHook(cfg, journal, nil)
}

func reconcileYUMCompatibilityServingLinkWithHook(cfg *config.Config, journal yumCompatibilityCutoverJournal, afterParentOpen func() error) error {
	return reconcileYUMCompatibilityServingLinkWithBinding(cfg, journal, nil, afterParentOpen, nil)
}

func reconcileYUMCompatibilityServingLinkBound(workflow yumCompatibilityWorkflow, journal yumCompatibilityCutoverJournal) error {
	if err := requireYUMCompatibilityMutationBoundary(workflow, "open controlled compatibility serving link"); err != nil {
		return err
	}
	var beforeCommit func() error
	if workflow.mutationHook != nil {
		beforeCommit = func() error { return workflow.mutationHook("flip controlled compatibility serving link") }
	}
	if err := reconcileYUMCompatibilityServingLinkWithBinding(workflow.cfg, journal, workflow.root, nil, beforeCommit); err != nil {
		return err
	}
	return requireYUMCompatibilityMutationBoundary(workflow, "finish controlled compatibility serving-link flip")
}

func verifyRetainedYUMCompatibilityDirectory(repositoryRoot *os.Root, relative string, retained *os.Root, expected os.FileInfo) error {
	if retained == nil || expected == nil {
		return errors.New("retained compatibility target capability is unavailable")
	}
	throughHandle, err := retained.Stat(".")
	if err != nil || !os.SameFile(expected, throughHandle) {
		return errors.Join(err, fmt.Errorf("retained compatibility target %s changed", relative))
	}
	return verifyBoundYUMCompatibilityDirectory(repositoryRoot, relative, expected)
}

func verifyYUMCompatibilityRepositoryRootPath(rootPath string, expected os.FileInfo) error {
	rootAtPath, err := os.Lstat(rootPath)
	if err != nil || rootAtPath.Mode()&os.ModeSymlink != 0 || !rootAtPath.IsDir() || expected == nil || !os.SameFile(expected, rootAtPath) {
		return errors.Join(err, errors.New("repository root was replaced during serving-link flip"))
	}
	return nil
}

func restoreYUMCompatibilityServingLink(parentRoot *os.Root, parentRelative, base, previous string, previousExists bool) error {
	rollback := base + ".rollback"
	if info, err := parentRoot.Lstat(rollback); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return errors.New("controlled compatibility rollback link is not a symlink")
		}
		if err := parentRoot.Remove(rollback); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !previousExists {
		if info, err := parentRoot.Lstat(base); err == nil {
			if info.Mode()&os.ModeSymlink == 0 {
				return errors.New("controlled compatibility serving link changed before rollback")
			}
			if err := parentRoot.Remove(base); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncYUMCompatibilityRootDirectory(parentRoot)
	}
	relativeTarget, err := filepath.Rel(parentRelative, previous)
	if err != nil || filepath.IsAbs(relativeTarget) {
		return errors.Join(err, errors.New("cannot restore controlled compatibility serving target"))
	}
	if err := parentRoot.Symlink(relativeTarget, rollback); err != nil {
		return err
	}
	if err := parentRoot.Rename(rollback, base); err != nil {
		return err
	}
	return syncYUMCompatibilityRootDirectory(parentRoot)
}

func verifyRestoredYUMCompatibilityServingLink(parentRoot *os.Root, parentRelative, base, previous string, previousExists bool) error {
	info, err := parentRoot.Lstat(base)
	if !previousExists {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return errors.New("controlled compatibility serving link still exists after rollback")
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return errors.New("controlled compatibility serving link is not a symlink after rollback")
	}
	value, err := parentRoot.Readlink(base)
	if err != nil {
		return err
	}
	if filepath.IsAbs(value) || filepath.Clean(filepath.Join(parentRelative, value)) != previous {
		return errors.New("controlled compatibility serving link did not return to its prior target")
	}
	return nil
}

func reconcileYUMCompatibilityServingLinkWithBinding(cfg *config.Config, journal yumCompatibilityCutoverJournal, binding *yumCompatibilityRepositoryBinding, afterParentOpen, beforeCommit func() error) error {
	if cfg == nil || cfg.Root == "" {
		return errors.New("configuration root is unavailable")
	}
	servingRelative, err := physicalPathBelowYUMCompatibilityRoot(cfg.Root, journal.ServingLink)
	if err != nil {
		return err
	}
	fromRelative, err := physicalPathBelowYUMCompatibilityRoot(cfg.Root, journal.FromTarget)
	if err != nil {
		return err
	}
	toRelative, err := physicalPathBelowYUMCompatibilityRoot(cfg.Root, journal.ToTarget)
	if err != nil {
		return err
	}
	var repositoryRoot *os.Root
	var rootIdentity os.FileInfo
	closeRepositoryRoot := false
	if binding != nil {
		if binding.path != cfg.Root || binding.root == nil || binding.identity == nil {
			return errors.New("bound compatibility repository root does not match configuration")
		}
		repositoryRoot, rootIdentity = binding.root, binding.identity
	} else {
		repositoryRoot, rootIdentity, err = openBoundYUMCompatibilityRepositoryRoot(cfg.Root)
		if err != nil {
			return err
		}
		closeRepositoryRoot = true
	}
	if closeRepositoryRoot {
		defer repositoryRoot.Close()
	}
	toRoot, toIdentity, err := openRealYUMCompatibilityDirectory(repositoryRoot, toRelative, false)
	if err != nil {
		return fmt.Errorf("open real compatibility target %s: %w", journal.ToTarget, err)
	}
	defer toRoot.Close()
	fromRoot, fromIdentity, fromErr := openRealYUMCompatibilityDirectory(repositoryRoot, fromRelative, false)
	if fromRoot != nil {
		defer fromRoot.Close()
	}
	if fromErr != nil && !errors.Is(fromErr, os.ErrNotExist) {
		return fmt.Errorf("open prior compatibility target %s: %w", journal.FromTarget, fromErr)
	}
	parentRelative := filepath.Dir(servingRelative)
	parentRoot, parentIdentity, err := openRealYUMCompatibilityDirectory(repositoryRoot, parentRelative, true)
	if err != nil {
		return err
	}
	defer parentRoot.Close()
	if afterParentOpen != nil {
		if err := afterParentOpen(); err != nil {
			return err
		}
	}
	verifyBoundNamespace := func() error {
		var fromErr error
		if fromRoot != nil {
			fromErr = verifyRetainedYUMCompatibilityDirectory(repositoryRoot, fromRelative, fromRoot, fromIdentity)
		}
		return errors.Join(
			verifyRetainedYUMCompatibilityDirectory(repositoryRoot, parentRelative, parentRoot, parentIdentity),
			verifyRetainedYUMCompatibilityDirectory(repositoryRoot, toRelative, toRoot, toIdentity),
			fromErr,
			verifyYUMCompatibilityRepositoryRootPath(cfg.Root, rootIdentity),
		)
	}
	if err := verifyBoundNamespace(); err != nil {
		return err
	}
	base := filepath.Base(servingRelative)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return errors.New("controlled compatibility serving link basename is unsafe")
	}
	current := ""
	currentExists := false
	if info, err := parentRoot.Lstat(base); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return errors.New("controlled compatibility serving link is not a symlink")
		}
		value, err := parentRoot.Readlink(base)
		if err != nil {
			return err
		}
		if filepath.IsAbs(value) {
			return errors.New("controlled compatibility serving link has an absolute target")
		}
		current = filepath.Clean(filepath.Join(parentRelative, value))
		if current != toRelative && current != fromRelative {
			return fmt.Errorf("controlled compatibility serving link points to unexpected target %s", current)
		}
		currentExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	changed := false
	rollbackAfterMutation := func(cause error) error {
		if !changed {
			return cause
		}
		rollbackErr := restoreYUMCompatibilityServingLink(parentRoot, parentRelative, base, current, currentExists)
		var fromErr error
		if fromRoot != nil {
			fromErr = verifyRetainedYUMCompatibilityDirectory(repositoryRoot, fromRelative, fromRoot, fromIdentity)
		}
		return errors.Join(
			cause,
			rollbackErr,
			verifyRetainedYUMCompatibilityDirectory(repositoryRoot, parentRelative, parentRoot, parentIdentity),
			fromErr,
			verifyYUMCompatibilityRepositoryRootPath(cfg.Root, rootIdentity),
			verifyRestoredYUMCompatibilityServingLink(parentRoot, parentRelative, base, current, currentExists),
		)
	}
	if current != toRelative {
		if current == fromRelative && fromRoot == nil {
			return errors.New("controlled compatibility prior serving target disappeared before flip")
		}
		if beforeCommit != nil {
			if err := beforeCommit(); err != nil {
				return err
			}
		}
		// Re-prove every retained capability immediately before the first
		// link mutation so a target or parent replacement cannot make the live
		// link serve it. The optional hook only exposes this boundary to tests.
		if err := verifyBoundNamespace(); err != nil {
			return err
		}
		relativeTarget, err := filepath.Rel(parentRelative, toRelative)
		if err != nil {
			return err
		}
		pending := base + ".pending"
		if info, err := parentRoot.Lstat(pending); err == nil {
			if info.Mode()&os.ModeSymlink == 0 {
				return errors.New("controlled compatibility pending link is not a symlink")
			}
			if err := parentRoot.Remove(pending); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := parentRoot.Symlink(relativeTarget, pending); err != nil {
			return err
		}
		if err := parentRoot.Rename(pending, base); err != nil {
			return err
		}
		changed = true
		if err := syncYUMCompatibilityRootDirectory(parentRoot); err != nil {
			return rollbackAfterMutation(err)
		}
	}
	if err := verifyBoundNamespace(); err != nil {
		return rollbackAfterMutation(err)
	}
	return nil
}

func removeYUMCompatibilityCutoverJournal(cfg *config.Config, id string) error {
	filename := yumCompatibilityCutoverJournalPath(cfg, id)
	for _, name := range []string{filename, filename + ".next"} {
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return syncLocalDirectory(filepath.Dir(filename))
}

func removeYUMCompatibilityCutoverNext(cfg *config.Config, id string) error {
	filename := yumCompatibilityCutoverJournalPath(cfg, id) + ".next"
	if err := os.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncLocalDirectory(filepath.Dir(filename))
}

func exactYUMCompatibilityJournalForCanonicalLast(cfg *config.Config, stateAtHead yumCompatibilityCutoverState, journal yumCompatibilityCutoverJournal) (yumCompatibilityCutoverJournal, bool, error) {
	if len(stateAtHead.Events) == 0 {
		return yumCompatibilityCutoverJournal{}, false, nil
	}
	expected, err := physicalYUMCompatibilityCutoverJournal(cfg, stateAtHead.Last)
	if err != nil {
		return expected, false, err
	}
	exact := expected.EventSHA256 == journal.EventSHA256 && expected.ID == journal.ID && expected.Action == journal.Action &&
		expected.ServingLink == journal.ServingLink && expected.FromTarget == journal.FromTarget && expected.ToTarget == journal.ToTarget
	return expected, exact, nil
}

func recoverPartialYUMCompatibilityCutoverNext(cfg *config.Config, canonical *state.Store, id string, pair yumCompatibilityCutoverJournalPair) error {
	stateAtHead, err := loadYUMCompatibilityCutoverStateAt(canonical, plumbing.ZeroHash, id)
	if err != nil {
		return err
	}
	if pair.MainExists {
		expected, exact, err := exactYUMCompatibilityJournalForCanonicalLast(cfg, stateAtHead, pair.Main)
		if err != nil || !exact {
			return errors.Join(err, errors.New("partial cutover journal update has no exact canonical event for its durable base"))
		}
		if err := removeYUMCompatibilityCutoverNext(cfg, id); err != nil {
			return err
		}
		if err := reconcileYUMCompatibilityServingLink(cfg, expected); err != nil {
			return err
		}
		return removeYUMCompatibilityCutoverJournal(cfg, id)
	}
	// No base means the only normal writer point is before the initial link,
	// hence before canonical append. If canonical authority nevertheless exists
	// (for example the base was lost after commit), rebuild solely from the
	// immutable last event and reconcile that authority; never trust partial
	// bytes to choose a target.
	if len(stateAtHead.Events) != 0 {
		expected, err := physicalYUMCompatibilityCutoverJournal(cfg, stateAtHead.Last)
		if err != nil {
			return err
		}
		if err := reconcileYUMCompatibilityServingLink(cfg, expected); err != nil {
			return err
		}
	}
	return removeYUMCompatibilityCutoverJournal(cfg, id)
}

func recoverOrphanYUMCompatibilityCutoverNext(cfg *config.Config, canonical *state.Store, id string, next yumCompatibilityCutoverJournal) error {
	stateAtHead, err := loadYUMCompatibilityCutoverStateAt(canonical, plumbing.ZeroHash, id)
	if err != nil {
		return err
	}
	expected, exact, err := exactYUMCompatibilityJournalForCanonicalLast(cfg, stateAtHead, next)
	if err != nil {
		return err
	}
	if next.Phase == yumCompatibilityCutoverCommitted && !exact {
		return errors.New("orphan committed cutover journal has no exact canonical event")
	}
	if exact {
		if err := reconcileYUMCompatibilityServingLink(cfg, expected); err != nil {
			return err
		}
	}
	return removeYUMCompatibilityCutoverJournal(cfg, id)
}

func recoverYUMCompatibilityCutoverJournal(cfg *config.Config, canonical *state.Store, id string, recover bool) error {
	pair, err := readYUMCompatibilityCutoverJournalPair(cfg, id, recover)
	if errors.Is(err, errPartialYUMCompatibilityCutoverJournalNext) && recover {
		return recoverPartialYUMCompatibilityCutoverNext(cfg, canonical, id, pair)
	}
	if err != nil {
		return err
	}
	if !pair.MainExists && pair.NextExists {
		return recoverOrphanYUMCompatibilityCutoverNext(cfg, canonical, id, pair.Next)
	}
	if !pair.MainExists {
		return nil
	}
	journal := pair.Main
	if !recover {
		return fmt.Errorf("incomplete cutover transaction exists at %s; rerun with --recover", yumCompatibilityCutoverJournalPath(cfg, id))
	}
	stateAtHead, stateErr := loadYUMCompatibilityCutoverStateAt(canonical, plumbing.ZeroHash, id)
	committed := stateErr == nil && len(stateAtHead.Events) != 0 && stateAtHead.Last.EventSHA256 == journal.EventSHA256
	if stateErr != nil {
		return stateErr
	}
	if pair.NextExists && !committed {
		return errors.New("committed cutover journal phase update has no exact canonical event")
	}
	if journal.Phase == yumCompatibilityCutoverCommitted && !committed {
		return errors.New("cutover journal claims a committed event that is absent from canonical state")
	}
	if committed {
		eventJournal, err := physicalYUMCompatibilityCutoverJournal(cfg, stateAtHead.Last)
		if err != nil || eventJournal.ServingLink != journal.ServingLink || eventJournal.FromTarget != journal.FromTarget || eventJournal.ToTarget != journal.ToTarget || eventJournal.Action != journal.Action {
			return errors.Join(err, errors.New("cutover crash journal differs from canonical event"))
		}
		if err := reconcileYUMCompatibilityServingLink(cfg, journal); err != nil {
			return err
		}
	}
	return removeYUMCompatibilityCutoverJournal(cfg, id)
}

func runYUMCompatibilityCandidate(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("compatibility yum-candidate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	id, output := "", ""
	addYUMCompatibilityWorkflowFlags(fs, &values, &id)
	fs.StringVar(&output, "output", "", "new isolated candidate directory outside the hosted repository root")
	privateKeyFile := fs.String("gpg-private-key-file", "", "read the repository OpenPGP private key from a protected file")
	passphraseFile := fs.String("gpg-passphrase-file", "", "read the OpenPGP passphrase from a protected file")
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow compatibility yum-candidate --id ID --output DIR [--gpg-private-key-file FILE] [--gpg-passphrase-file FILE] [--config sow.yaml] [--root DIR] [--workers N] [--chunk-entries N] [--recover]")
	}
	if help, err := parseFlagSet(fs, args); err != nil || help {
		return err
	}
	if fs.NArg() != 0 || output == "" || len(values.repos.values()) != 0 || len(values.oses.values()) != 0 || len(values.arches.values()) != 0 {
		return withExitCode(ExitUsage, "yum-candidate requires --id and --output and does not accept ordinary selectors")
	}
	workflow, err := loadYUMCompatibilityWorkflow(values, id)
	if err != nil {
		return err
	}
	binding, err := openYUMCompatibilityCandidateBinding(workflow.cfg, output)
	if err != nil {
		return withExitCode(ExitUsage, "%v", err)
	}
	defer propagateYUMCompatibilityCleanup("close compatibility candidate binding", binding.Close, &resultErr, stderr)
	output = binding.output
	lock, err := state.AcquireLock(workflow.cfg.StatePath(), "compatibility-yum-candidate", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := workflow.bindMutationRoots(lock); err != nil {
		return withExitCode(ExitConflict, "bind compatibility repository/state roots: %v", err)
	}
	defer propagateYUMCompatibilityCleanup("close compatibility root binding", workflow.closeMutationRoots, &resultErr, stderr)
	if err := requireYUMCompatibilityMutationBoundary(workflow, "start yum-candidate"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireNoPendingYUMCompatibilityCutoverJournalsBound(workflow, ""); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	workspace, err := newYUMCompatibilityCanonicalWorkspace(workflow)
	if err != nil {
		return withExitCode(ExitConflict, "snapshot bound yum-candidate canonical state: %v", err)
	}
	defer propagateYUMCompatibilityCleanup("remove compatibility canonical workspace", workspace.Close, &resultErr, stderr)
	canonical := workspace.Store()
	if err := prepareCanonicalStateCore(ctx, canonical, values.recover, stdout); err != nil {
		return err
	}
	if _, err := workspace.Commit(workflow, "recover yum-candidate canonical state"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "prepare yum-candidate canonical state"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireCanonicalConfigBaseline(workflow.cfg, canonical); err != nil {
		return withExitCode(ExitConflict, "canonical config changed while yum-candidate waited for lock: %v", err)
	}
	txDir, err := workspace.NewTransactionDir("yum-compat-candidate-")
	if err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	defer workspace.RemoveTransaction(txDir)
	if err := requireYUMCompatibilityMutationBoundary(workflow, "create yum-candidate transaction directory"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	adoption, err := validateYUMCompatibilityAdoptedState(ctx, workflow, canonical, txDir, values)
	if err != nil {
		return withExitCode(ExitVerification, "validate S1 adoption: %v", err)
	}
	recoveredCandidate, err := recoverYUMCompatibilityCandidateJournal(id, binding, values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "recover candidate transaction: %v", err)
	}
	if info, statErr := binding.lstat(output); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return withExitCode(ExitConflict, "candidate output exists and is not a real directory")
		}
		receipt, err := validateYUMCompatibilityCandidate(ctx, workflow, canonical, binding, txDir, values, adoption)
		if err != nil {
			return withExitCode(ExitConflict, "existing candidate is not an exact replay: %v", err)
		}
		if recoveredCandidate {
			if err := removeYUMCompatibilityCandidateJournal(binding); err != nil {
				return withExitCode(ExitInternal, "complete recovered candidate journal: %v", err)
			}
		}
		fmt.Fprintf(stdout, "compatibility candidate id=%s path=%s changed=false packages=%d bytes=%d repomd_sha256=%s freeze_confirm=%s served_tree_rewritten=false\n", id, output, receipt.Packages, receipt.Bytes, receipt.RepomdSHA256, receipt.FreezeConfirm)
		return nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return withExitCode(ExitVerification, "inspect candidate output: %v", statErr)
	}
	privateKey, passphrase, _, err := loadPublishSigningSecretsWithIdentity(workflow.cfg, []config.Repo{workflow.owner}, *privateKeyFile, *passphraseFile)
	if err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	receipt, err := buildYUMCompatibilityCandidate(ctx, workflow, canonical, binding, txDir, values, adoption, privateKey, passphrase)
	if err != nil {
		return withExitCode(ExitVerification, "build isolated YUM compatibility candidate: %v", err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "finish yum-candidate build"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	fmt.Fprintf(stdout, "compatibility candidate id=%s path=%s changed=true packages=%d bytes=%d repomd_sha256=%s freeze_confirm=%s served_tree_rewritten=false\n", id, output, receipt.Packages, receipt.Bytes, receipt.RepomdSHA256, receipt.FreezeConfirm)
	return nil
}

func yumCompatibilityFreezeExpectedFiles(witnessPath, payloadPath, packageTrustPath, candidateManifestPath, candidateReceiptPath, repositoryTrustPath string, trust yumCompatibilityPackageTrust) map[string]state.FileExpectation {
	expected := make(map[string]state.FileExpectation, 6)
	for _, canonicalPath := range []string{witnessPath, payloadPath, candidateManifestPath, candidateReceiptPath, repositoryTrustPath} {
		expected[canonicalPath] = state.FileExpectation{AllowAbsent: true}
	}
	// Package trust was installed by S1 adoption. Pin the exact bytes observed
	// by this freeze so an intervening canonical writer cannot be overwritten.
	expected[packageTrustPath] = state.FileExpectation{Identities: []state.FileIdentity{{Size: trust.size, SHA256: trust.sha256}}}
	return expected
}

func runYUMCompatibilityFreeze(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("compatibility yum-freeze", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	id, candidate, confirm := "", "", ""
	addYUMCompatibilityWorkflowFlags(fs, &values, &id)
	fs.StringVar(&candidate, "candidate", "", "exact isolated candidate directory")
	fs.StringVar(&confirm, "confirm", "", "content-bound freeze confirmation printed by yum-candidate")
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow compatibility yum-freeze --id ID --candidate DIR --confirm TOKEN [--config sow.yaml] [--root DIR] [--workers N] [--chunk-entries N] [--recover]")
	}
	if help, err := parseFlagSet(fs, args); err != nil || help {
		return err
	}
	if fs.NArg() != 0 || candidate == "" || confirm == "" || len(values.repos.values()) != 0 || len(values.oses.values()) != 0 || len(values.arches.values()) != 0 {
		return withExitCode(ExitUsage, "yum-freeze requires --id, --candidate, and --confirm and does not accept ordinary selectors")
	}
	workflow, err := loadYUMCompatibilityWorkflow(values, id)
	if err != nil {
		return err
	}
	candidateBinding, err := openYUMCompatibilityCandidateBinding(workflow.cfg, candidate)
	if err != nil {
		return withExitCode(ExitUsage, "%v", err)
	}
	defer propagateYUMCompatibilityCleanup("close compatibility candidate binding", candidateBinding.Close, &resultErr, stderr)
	candidate = candidateBinding.output
	lock, err := state.AcquireLock(workflow.cfg.StatePath(), "compatibility-yum-freeze", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := workflow.bindMutationRoots(lock); err != nil {
		return withExitCode(ExitConflict, "bind compatibility repository/state roots: %v", err)
	}
	defer propagateYUMCompatibilityCleanup("close compatibility root binding", workflow.closeMutationRoots, &resultErr, stderr)
	if err := requireYUMCompatibilityMutationBoundary(workflow, "start yum-freeze"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireNoPendingYUMCompatibilityCutoverJournalsBound(workflow, ""); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	workspace, err := newYUMCompatibilityCanonicalWorkspace(workflow)
	if err != nil {
		return withExitCode(ExitConflict, "snapshot bound yum-freeze canonical state: %v", err)
	}
	defer propagateYUMCompatibilityCleanup("remove compatibility canonical workspace", workspace.Close, &resultErr, stderr)
	canonical := workspace.Store()
	if err := prepareCanonicalStateCore(ctx, canonical, values.recover, stdout); err != nil {
		return err
	}
	if _, err := workspace.Commit(workflow, "recover yum-freeze canonical state"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "prepare yum-freeze canonical state"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireCanonicalConfigBaseline(workflow.cfg, canonical); err != nil {
		return withExitCode(ExitConflict, "canonical config changed while yum-freeze waited for lock: %v", err)
	}
	txDir, err := workspace.NewTransactionDir("yum-compat-freeze-")
	if err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	defer workspace.RemoveTransaction(txDir)
	if err := requireYUMCompatibilityMutationBoundary(workflow, "create yum-freeze transaction directory"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	adoption, err := validateYUMCompatibilityAdoptedState(ctx, workflow, canonical, txDir, values)
	if err != nil {
		return withExitCode(ExitVerification, "validate S1 adoption: %v", err)
	}
	candidateValidationDir := filepath.Join(txDir, "candidate-validation")
	if err := os.Mkdir(candidateValidationDir, 0o700); err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	receipt, err := validateYUMCompatibilityCandidate(ctx, workflow, canonical, candidateBinding, candidateValidationDir, values, adoption)
	if err != nil {
		return withExitCode(ExitVerification, "validate candidate: %v", err)
	}
	if confirm != receipt.FreezeConfirm {
		return withExitCode(ExitConflict, "freeze confirmation does not match candidate content; expected %s", receipt.FreezeConfirm)
	}
	freezeRef, _ := state.YUMCompatibilityRef(id)
	if existing, exists, refErr := canonical.Ref(freezeRef); refErr != nil {
		return withExitCode(ExitVerification, "read S2 freeze ref: %v", refErr)
	} else if exists {
		frozen, err := loadYUMCompatibilityFrozenStateAt(canonical, plumbing.ZeroHash, id)
		left, right := frozen.Receipt, receipt
		left.CandidatePath, right.CandidatePath = "", ""
		if err != nil || frozen.Commit != existing || left != right {
			return withExitCode(ExitConflict, "existing S2 freeze differs from candidate: %v", err)
		}
		if err := ensureFrozenYUMCompatibilityTrustCAS(ctx, workflow, canonical, frozen.Commit, frozen.Receipt, txDir, "repair existing yum-freeze trust CAS"); err != nil {
			return withExitCode(ExitVerification, "repair existing S2 frozen trust CAS closure: %v", err)
		}
		cutoverConfirm, _ := yumCompatibilityConfirmation("cutover", frozen.Receipt)
		fmt.Fprintf(stdout, "compatibility frozen id=%s source_commit=%s freeze_commit=%s candidate=%s packages=%d bytes=%d changed=false cutover_confirm=%s served_tree_rewritten=false\n", id, frozen.Receipt.SourceCommit, frozen.Commit, candidate, frozen.Receipt.Packages, frozen.Receipt.Bytes, cutoverConfirm)
		return nil
	}
	admission, err := admitYUMCompatibilityProjection(workflow.cfg, canonical, workflow.projection)
	if err != nil {
		return withExitCode(ExitVerification, "%v", err)
	}
	freezePayloadDir := filepath.Join(txDir, "freeze-payload")
	if err := os.Mkdir(freezePayloadDir, 0o700); err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	_, aliases, _, witnessManifest, packages, bytesTotal, err := buildYUMCompatibilityPayload(canonical, admission, freezePayloadDir)
	if err != nil {
		return withExitCode(ExitVerification, "%v", err)
	}
	if packages != receipt.Packages || bytesTotal != receipt.Bytes {
		return withExitCode(ExitVerification, "candidate package identity changed after confirmation")
	}
	if admission.frozen {
		return withExitCode(ExitConflict, "compatibility projection has an S2 witness without the immutable freeze ref")
	}
	trust, err := stageYUMCompatibilityPackageTrust(workflow.cfg, canonical, admission, txDir)
	if err != nil {
		return withExitCode(ExitVerification, "%v", err)
	}
	physicalRoot := filepath.Join(workflow.cfg.Root, filepath.FromSlash(workflow.projection.Root))
	if populated, err := directoryHasEntries(physicalRoot); err != nil {
		return withExitCode(ExitVerification, "%v", err)
	} else if populated {
		if err := verifyLegacyYUMCompatibilityRoot(ctx, physicalRoot, aliases, trust.keyring); err != nil {
			return withExitCode(ExitVerification, "legacy raw root differs before S2 freeze: %v", err)
		}
	}
	witnessStage, err := stageYUMCompatibilityFreezeWitness(canonical, admission, witnessManifest, trust, packages, bytesTotal, txDir)
	if err != nil {
		return withExitCode(ExitVerification, "%v", err)
	}
	repositoryTrust, err := loadCandidateRepositoryTrust(workflow, canonical, receipt)
	if err != nil {
		return withExitCode(ExitVerification, "%v", err)
	}
	repositoryTrustStage := filepath.Join(txDir, "repository-trust.pgp")
	if err := writeExclusiveBytes(repositoryTrustStage, repositoryTrust); err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	candidateManifestSource, candidateReceiptSource := yumCompatibilityCandidateSidecars(candidate)
	candidateManifestLocal := filepath.Join(txDir, "candidate-manifest.tsv")
	candidateReceiptLocal := filepath.Join(txDir, "candidate-receipt.json")
	manifestSHA, manifestSize, err := captureStablePath(ctx, candidateManifestSource, candidateManifestLocal)
	if err != nil || manifestSHA != receipt.CandidateManifestSHA256 || manifestSize != receipt.CandidateManifestSize {
		return withExitCode(ExitVerification, "capture confirmed candidate manifest: %v", errors.Join(err, errors.New("candidate manifest identity changed after confirmation")))
	}
	if _, _, err := captureStablePath(ctx, candidateReceiptSource, candidateReceiptLocal); err != nil {
		return withExitCode(ExitVerification, "capture confirmed candidate receipt: %v", err)
	}
	capturedReceiptBody, err := os.ReadFile(candidateReceiptLocal)
	if err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	capturedReceipt, err := decodeYUMCompatibilityCandidate(capturedReceiptBody)
	left, right := capturedReceipt, receipt
	left.CandidatePath, right.CandidatePath = "", ""
	if err != nil || left != right {
		return withExitCode(ExitVerification, "captured candidate receipt changed after confirmation: %v", err)
	}
	witnessPath, _ := state.YUMCompatibilityProjectionPath(id)
	payloadPath, _ := state.YUMCompatibilityManifestPath(id)
	packageTrustPath, _ := state.YUMCompatibilityPackageTrustPath(id)
	candidateManifestPath, _ := state.YUMCompatibilityCandidateManifestPath(id)
	candidateReceiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(id)
	repositoryTrustPath, _ := state.YUMCompatibilityRepositoryTrustPath(id)
	staged := map[string]string{
		witnessPath: witnessStage, payloadPath: witnessManifest, packageTrustPath: trust.path,
		candidateManifestPath: candidateManifestLocal, candidateReceiptPath: candidateReceiptLocal, repositoryTrustPath: repositoryTrustStage,
	}
	if err := commitYUMCompatibilityTrustCAS(ctx, workflow, receipt, trust.path, repositoryTrustStage, "commit yum-freeze trust CAS"); err != nil {
		return withExitCode(ExitVerification, "install S2 frozen trust CAS closure: %v", err)
	}
	expected := yumCompatibilityFreezeExpectedFiles(witnessPath, payloadPath, packageTrustPath, candidateManifestPath, candidateReceiptPath, repositoryTrustPath, trust)
	if err := requireYUMCompatibilityMutationBoundary(workflow, "commit yum-freeze canonical state"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	freezeCommit, changed, err := applyCanonicalState(ctx, canonical, "yum-compatibility-freeze", "sow compatibility yum-freeze: "+id,
		staged, []state.RefUpdate{{Name: freezeRef, Immutable: true}}, state.ApplyOptions{ExpectedFiles: expected})
	if err != nil {
		return stateMutationError("freeze exact YUM compatibility S2 state", err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "finish yum-freeze canonical commit"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if !changed {
		return withExitCode(ExitConflict, "S2 freeze produced no canonical change")
	}
	frozen, err := loadYUMCompatibilityFrozenStateAt(canonical, plumbing.ZeroHash, id)
	if err != nil || frozen.Commit != freezeCommit {
		return withExitCode(ExitInternal, "validate S2 freeze: %v", err)
	}
	freezeCommit, exists, err := canonical.Ref(freezeRef)
	if err != nil || !exists || freezeCommit.IsZero() {
		return withExitCode(ExitInternal, "freeze ref %s was not installed: %v", freezeRef, err)
	}
	if err := workspace.RemoveTransaction(txDir); err != nil {
		return withExitCode(ExitInternal, "remove yum-freeze private transaction: %v", err)
	}
	if _, err := workspace.Commit(workflow, "commit yum-freeze canonical state"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	cutoverConfirm, _ := yumCompatibilityConfirmation("cutover", frozen.Receipt)
	fmt.Fprintf(stdout, "compatibility frozen id=%s source_commit=%s freeze_commit=%s candidate=%s packages=%d bytes=%d changed=true cutover_confirm=%s served_tree_rewritten=false\n", id, admission.sourceCommit, freezeCommit, candidate, packages, bytesTotal, cutoverConfirm)
	return nil
}

func runYUMCompatibilityCutover(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runYUMCompatibilityTransition(ctx, args, stdout, stderr, "cutover")
}

func runYUMCompatibilityRollback(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runYUMCompatibilityTransition(ctx, args, stdout, stderr, "rollback")
}

func runYUMCompatibilityTransition(ctx context.Context, args []string, stdout, stderr io.Writer, action string) (resultErr error) {
	if action != "cutover" && action != "rollback" {
		return withExitCode(ExitInternal, "unsupported YUM compatibility transition %q", action)
	}
	fs := flag.NewFlagSet("compatibility yum-"+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	id, confirm := "", ""
	addYUMCompatibilityWorkflowFlags(fs, &values, &id)
	fs.StringVar(&confirm, "confirm", "", "content-bound "+action+" confirmation printed by the preceding compatibility step")
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow compatibility yum-"+action+" --id ID --confirm TOKEN [--config sow.yaml] [--root DIR] [--workers N] [--chunk-entries N] [--recover]")
	}
	if help, err := parseFlagSet(fs, args); err != nil || help {
		return err
	}
	if fs.NArg() != 0 || id == "" || confirm == "" || len(values.repos.values()) != 0 || len(values.oses.values()) != 0 || len(values.arches.values()) != 0 {
		return withExitCode(ExitUsage, "yum-%s requires --id and --confirm and does not accept ordinary selectors", action)
	}
	workflow, err := loadYUMCompatibilityWorkflow(values, id)
	if err != nil {
		return err
	}
	lock, err := state.AcquireLock(workflow.cfg.StatePath(), "compatibility-yum-"+action, values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := workflow.bindMutationRoots(lock); err != nil {
		return withExitCode(ExitConflict, "bind compatibility repository/state roots: %v", err)
	}
	defer propagateYUMCompatibilityCleanup("close compatibility root binding", workflow.closeMutationRoots, &resultErr, stderr)
	if err := requireYUMCompatibilityMutationBoundary(workflow, "start yum-"+action); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireNoPendingYUMCompatibilityCutoverJournalsBound(workflow, id); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	workspace, err := newYUMCompatibilityCanonicalWorkspace(workflow)
	if err != nil {
		return withExitCode(ExitConflict, "snapshot bound yum-%s canonical state: %v", action, err)
	}
	defer propagateYUMCompatibilityCleanup("remove compatibility canonical workspace", workspace.Close, &resultErr, stderr)
	canonical := workspace.Store()
	if err := prepareCanonicalStateCoreForYUMCompatibilityRecovery(ctx, canonical, values.recover, stdout, id); err != nil {
		return err
	}
	if _, err := workspace.Commit(workflow, "recover yum-"+action+" canonical state"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "prepare yum-"+action+" canonical state"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireCanonicalConfigBaseline(workflow.cfg, canonical); err != nil {
		return withExitCode(ExitConflict, "canonical config changed while yum-%s waited for lock: %v", action, err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "recover yum-"+action+" journal"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := recoverYUMCompatibilityCutoverJournalBound(workflow, canonical, id, values.recover); err != nil {
		return withExitCode(ExitConflict, "recover yum-%s: %v", action, err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "finish yum-"+action+" recovery"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	txDir, err := workspace.NewTransactionDir("yum-compat-" + action + "-")
	if err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	defer workspace.RemoveTransaction(txDir)
	if err := requireYUMCompatibilityMutationBoundary(workflow, "create yum-"+action+" transaction directory"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if _, err := validateYUMCompatibilityAdoptedState(ctx, workflow, canonical, txDir, values); err != nil {
		return withExitCode(ExitVerification, "validate preserved S0/S1 state: %v", err)
	}
	frozen, err := loadYUMCompatibilityFrozenStateAt(canonical, plumbing.ZeroHash, id)
	if err != nil {
		return withExitCode(ExitVerification, "validate S2 freeze: %v", err)
	}
	expectedConfirm, err := yumCompatibilityConfirmation(action, frozen.Receipt)
	if err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	if confirm != expectedConfirm {
		return withExitCode(ExitConflict, "%s confirmation does not match frozen content; expected %s", action, expectedConfirm)
	}
	if err := ensureFrozenYUMCompatibilityTrustCAS(ctx, workflow, canonical, frozen.Commit, frozen.Receipt, txDir, "repair yum-"+action+" trust CAS"); err != nil {
		return withExitCode(ExitVerification, "repair S2 frozen trust CAS closure before yum-%s: %v", action, err)
	}
	stateAtHead, err := loadYUMCompatibilityCutoverStateAt(canonical, plumbing.ZeroHash, id)
	if err != nil {
		return withExitCode(ExitVerification, "validate S3 ledger: %v", err)
	}
	if action == "cutover" {
		if err := requireYUMCompatibilityMutationBoundary(workflow, "materialize yum-cutover candidate"); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
		if err := materializeFrozenYUMCompatibilityCandidate(ctx, workflow, canonical, frozen, txDir, values); err != nil {
			return withExitCode(ExitVerification, "materialize controlled S3 candidate: %v", err)
		}
		if err := requireYUMCompatibilityMutationBoundary(workflow, "finish yum-cutover candidate materialization"); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
		if stateAtHead.Active {
			journal, err := physicalYUMCompatibilityCutoverJournal(workflow.cfg, stateAtHead.Last)
			if err != nil {
				return withExitCode(ExitVerification, "reconcile active S3 serving link: %v", err)
			}
			if err := reconcileYUMCompatibilityServingLinkBound(workflow, journal); err != nil {
				return withExitCode(ExitVerification, "reconcile active S3 serving link: %v", err)
			}
			rollbackConfirm, _ := yumCompatibilityConfirmation("rollback", frozen.Receipt)
			fmt.Fprintf(stdout, "compatibility cutover id=%s freeze_commit=%s event=%s changed=false active=true serving_link=%s rollback_confirm=%s raw_tree_rewritten=false\n", id, frozen.Commit, stateAtHead.Last.EventSHA256, stateAtHead.Last.ServingLink, rollbackConfirm)
			return nil
		}
	} else if !stateAtHead.Active {
		if len(stateAtHead.Events) == 0 {
			return withExitCode(ExitConflict, "compatibility projection %s has never been cut over", id)
		}
		journal, err := physicalYUMCompatibilityCutoverJournal(workflow.cfg, stateAtHead.Last)
		if err != nil {
			return withExitCode(ExitVerification, "%v", err)
		}
		if err := reconcileYUMCompatibilityServingLinkBound(workflow, journal); err != nil {
			return withExitCode(ExitVerification, "reconcile rolled-back raw serving link: %v", err)
		}
		cutoverConfirm, _ := yumCompatibilityConfirmation("cutover", frozen.Receipt)
		fmt.Fprintf(stdout, "compatibility rollback id=%s freeze_commit=%s event=%s changed=false active=false serving_link=%s cutover_confirm=%s raw_tree_rewritten=false\n", id, frozen.Commit, stateAtHead.Last.EventSHA256, stateAtHead.Last.ServingLink, cutoverConfirm)
		return nil
	}
	event, err := buildNextYUMCompatibilityCutoverEvent(frozen, stateAtHead, action)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	journal, err := physicalYUMCompatibilityCutoverJournal(workflow.cfg, event)
	if err != nil {
		return withExitCode(ExitVerification, "%v", err)
	}
	if err := preflightYUMCompatibilityServingTransition(journal, action); err != nil {
		return withExitCode(ExitVerification, "%v", err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "write yum-"+action+" prepared journal"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := writeYUMCompatibilityCutoverJournalBound(workflow, journal, true); err != nil {
		return withExitCode(ExitConflict, "create cutover crash journal: %v", err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "commit yum-"+action+" canonical ledger"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	commit, err := appendYUMCompatibilityCutoverEvent(ctx, canonical, event, txDir)
	if err != nil {
		return stateMutationError("append YUM compatibility "+action+" ledger", err)
	}
	if err := workspace.RemoveTransaction(txDir); err != nil {
		return withExitCode(ExitInternal, "remove yum-%s private transaction: %v", action, err)
	}
	if _, err := workspace.Commit(workflow, "commit yum-"+action+" canonical ledger"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "finish yum-"+action+" canonical ledger"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	journal.Phase = yumCompatibilityCutoverCommitted
	if err := writeYUMCompatibilityCutoverJournalBound(workflow, journal, false); err != nil {
		return withExitCode(ExitInternal, "record committed cutover journal: %v", err)
	}
	if err := reconcileYUMCompatibilityServingLinkBound(workflow, journal); err != nil {
		return withExitCode(ExitConflict, "flip controlled compatibility serving link after canonical commit: %v", err)
	}
	if err := removeYUMCompatibilityCutoverJournalBound(workflow, id); err != nil {
		return withExitCode(ExitInternal, "complete cutover crash journal: %v", err)
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "finish yum-"+action+" transaction"); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	finalState, err := loadYUMCompatibilityCutoverStateAt(canonical, commit, id)
	if err != nil || finalState.Last.EventSHA256 != event.EventSHA256 || finalState.Active != (action == "cutover") {
		return withExitCode(ExitInternal, "validate committed %s state: %v", action, err)
	}
	nextAction := "rollback"
	if action == "rollback" {
		nextAction = "cutover"
	}
	nextConfirm, _ := yumCompatibilityConfirmation(nextAction, frozen.Receipt)
	fmt.Fprintf(stdout, "compatibility %s id=%s freeze_commit=%s commit=%s event=%s changed=true active=%t serving_link=%s %s_confirm=%s raw_tree_rewritten=false\n",
		action, id, frozen.Commit, commit, event.EventSHA256, action == "cutover", event.ServingLink, nextAction, nextConfirm)
	return nil
}

func preflightYUMCompatibilityServingTransition(journal yumCompatibilityCutoverJournal, action string) error {
	toInfo, err := os.Lstat(journal.ToTarget)
	if err != nil || !toInfo.IsDir() || toInfo.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, fmt.Errorf("%s target %s is not a real directory", action, journal.ToTarget))
	}
	if action == "cutover" {
		fromInfo, err := os.Lstat(journal.FromTarget)
		if err != nil || !fromInfo.IsDir() || fromInfo.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("raw S0 target %s is not a real directory", journal.FromTarget))
		}
	}
	return nil
}
