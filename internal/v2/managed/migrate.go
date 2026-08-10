package managed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
	"golang.org/x/sys/unix"
)

const defaultC2MigrationGrace = 30 * 24 * time.Hour
const transitionPlanDomain = "sow/transition-plan/v1"

type RepositoryMigrationOptions struct {
	WorkspaceOptions
	LockOptions
	Repository  string
	Jobs        int
	GracePeriod time.Duration
	// now is an in-package deterministic clock hook used by fault tests.  The
	// production surface never accepts a caller-selected wall clock.
	now   func() time.Time
	Fault func(string) error
}

type RepositoryMigrationResult struct {
	Repository     string             `json:"repository"`
	RepositoryID   string             `json:"repository_id"`
	FromLayout     string             `json:"from_layout"`
	ToLayout       string             `json:"to_layout"`
	Phase          string             `json:"phase"`
	Generation     state.GenerationID `json:"generation"`
	GraceNotBefore *string            `json:"grace_not_before"`
	LegacyAliases  int                `json:"legacy_aliases"`
	Complete       bool               `json:"complete"`
}

func MigrateRepositoryLayout(ctx context.Context, opts RepositoryMigrationOptions) (result RepositoryMigrationResult, resultErr error) {
	if ctx == nil {
		return result, errors.New("managed: nil migration context")
	}
	if opts.Jobs < 1 {
		opts.Jobs = runtime.GOMAXPROCS(0)
	}
	if opts.GracePeriod < 0 || opts.GracePeriod > 0 && opts.GracePeriod < defaultC2MigrationGrace {
		return result, fmt.Errorf("%w: migration grace must be at least 30 days", ErrRejected)
	}
	if opts.GracePeriod == 0 {
		opts.GracePeriod = defaultC2MigrationGrace
	}
	now := time.Now().UTC()
	if opts.now != nil {
		now = opts.now().UTC()
	}
	if now.IsZero() {
		return result, fmt.Errorf("%w: migration clock is unavailable", ErrRejected)
	}
	ws, cfg, _, rootGuard, err := migrationWorkspace(opts.WorkspaceOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	repoName, err := selectMigrationRepository(ws, cfg, opts.Repository)
	if err != nil {
		return result, err
	}
	result.Repository = repoName
	workspaceLock, repoLock, err := acquireLifecycleLocks(ctx, ws.Root, repoName, opts.LockOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close(), repoLock.Close()) }()
	// Reload inside the exclusive Workspace lock.  The pre-lock compatibility
	// parse was discovery only and never authorizes a stale config snapshot.
	var legacyConfig bool
	cfg, _, _, legacyConfig, err = config.LoadWorkspaceDocumentForMigration(ws)
	if err != nil {
		return result, err
	}
	if _, exists := cfg.Repositories[repoName]; !exists {
		return result, fmt.Errorf("%w: repository %q disappeared from configuration", ErrRejected, repoName)
	}
	privateRoot := filepath.Join(ws.Root, ".sow", repoName)
	for _, child := range []string{"retained", "transitions"} {
		if _, err := durableEnsureDir(filepath.Join(privateRoot, child), 0o700); err != nil {
			return result, err
		}
	}
	store, err := openExistingStateForMigration(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return result, fmt.Errorf("%w: migrate repository schema: %v", ErrIntegrity, err)
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		return result, err
	}
	result.RepositoryID, result.FromLayout, result.ToLayout = identity.RepositoryID, state.LayoutC2V1, state.LayoutSinglePayloadV1
	journal, journalIdentity, err := loadTransitionJournal(ws.Root, repoName)
	if err != nil {
		return result, err
	}
	if identity.LayoutVersion == state.LayoutSinglePayloadV1 {
		if journal != nil {
			if _, err := validateTransitionBinding(ctx, ws.Root, repoName, cfg, store, *journal, now); err != nil {
				return result, err
			}
			if journal.Phase == "final_manifest" {
				done := *journal
				done.Phase = "done"
				doneIdentity, doneErr := transitionJournalIdentity(done)
				if doneErr != nil || identity.TransitionReceiptSHA256 == "" || identity.TransitionReceiptSHA256 != doneIdentity {
					return result, fmt.Errorf("%w: terminal layout cannot repair its final_manifest journal: %v", ErrIntegrity, doneErr)
				}
				if err := persistTransitionJournal(ws.Root, repoName, done); err != nil {
					return result, err
				}
				journal, journalIdentity = &done, doneIdentity
			}
			if journal.Phase != "done" || identity.TransitionReceiptSHA256 == "" || identity.TransitionReceiptSHA256 != journalIdentity {
				return result, fmt.Errorf("%w: terminal layout has a mismatched transition journal", ErrIntegrity)
			}
			if err := clearTransitionJournal(ws.Root, repoName); err != nil {
				return result, err
			}
		}
		summary, err := store.Summary(ctx)
		if err != nil {
			return result, err
		}
		result.Phase, result.Generation, result.Complete = "done", summary.BuiltGeneration, true
		return result, nil
	}
	if identity.LayoutVersion == state.LayoutC2V1 {
		if journal != nil {
			return result, fmt.Errorf("%w: abandoned C2 layout still has a transition journal", ErrIntegrity)
		}
		if err := store.BeginLayoutTransition(ctx); err != nil {
			return result, err
		}
		identity.LayoutVersion = state.LayoutC2ToSingleV1
	}
	if identity.LayoutVersion != state.LayoutC2ToSingleV1 {
		return result, fmt.Errorf("%w: unsupported repository layout %q", ErrIntegrity, identity.LayoutVersion)
	}
	if legacyConfig {
		cfg.Schema = config.Schema
		data, err := config.Marshal(cfg)
		if err != nil {
			return result, err
		}
		if err := writeAtomic(ws.ConfigPath, data, 0o644); err != nil {
			return result, err
		}
		if err := callFault(opts.Fault, "migrate.config"); err != nil {
			return result, err
		}
	}
	if journal == nil {
		plannedAt := ceilUTCSecond(now)
		control, controlErr := store.LayoutTransitionControl(ctx)
		if controlErr != nil {
			return result, controlErr
		}
		if control != nil {
			if control.CommitIntentAt != "" {
				return result, fmt.Errorf("%w: committed migration control has no transition journal", ErrIntegrity)
			}
			plannedAt, err = time.Parse(time.RFC3339, control.PlannedAt)
			if err != nil {
				return result, fmt.Errorf("%w: invalid anchored migration planning time", ErrIntegrity)
			}
		}
		journal, err = planC2Transition(ctx, ws.Root, repoName, cfg, store, identity.RepositoryID, plannedAt, opts.Jobs)
		if err != nil {
			return result, err
		}
		planIdentity, err := transitionPlanIdentity(*journal)
		if err != nil {
			return result, err
		}
		if err := store.AnchorLayoutTransitionPlan(ctx, journal.RepositoryID, journal.BaseGeneration, journal.TargetManifestSHA256, planIdentity, plannedAt.Format("2006-01-02T15:04:05Z")); err != nil {
			return result, err
		}
		if err := callFault(opts.Fault, "migrate.plan_anchored"); err != nil {
			return result, err
		}
		if err := persistTransitionJournal(ws.Root, repoName, *journal); err != nil {
			return result, err
		}
		if err := callFault(opts.Fault, "migrate.planned"); err != nil {
			return result, err
		}
	} else if journal.RepositoryID != identity.RepositoryID {
		return result, fmt.Errorf("%w: transition journal belongs to another Repository", ErrIntegrity)
	}
	result.LegacyAliases = len(journal.LegacyAliases)
	for {
		binding, bindingErr := validateTransitionBinding(ctx, ws.Root, repoName, cfg, store, *journal, now)
		if bindingErr != nil {
			return result, bindingErr
		}
		result.Phase, result.GraceNotBefore = journal.Phase, journal.GraceNotBefore
		switch journal.Phase {
		case "planned":
			journal.Phase = "staged"
			if err := persistTransitionJournal(ws.Root, repoName, *journal); err != nil {
				return result, err
			}
			if err := callFault(opts.Fault, "migrate.staged"); err != nil {
				return result, err
			}
		case "staged":
			if _, err := ensureMigrationCommitAnchor(ctx, store, *journal, now, opts.GracePeriod); err != nil {
				return result, err
			}
			if err := callFault(opts.Fault, "migrate.commit_anchored"); err != nil {
				return result, err
			}
			journal.Phase, journal.CommitIntent = "commit_intent", true
			if err := persistTransitionJournal(ws.Root, repoName, *journal); err != nil {
				return result, err
			}
			if err := callFault(opts.Fault, "migrate.commit_intent"); err != nil {
				return result, err
			}
		case "commit_intent", "pointer_rollforward":
			if journal.Phase == "commit_intent" {
				journal.Phase = "pointer_rollforward"
				if err := persistTransitionJournal(ws.Root, repoName, *journal); err != nil {
					return result, err
				}
				if err := callFault(opts.Fault, "migrate.pointer_rollforward"); err != nil {
					return result, err
				}
			}
			if err := rollForwardMigrationPointers(ctx, ws.Root, repoName, cfg, store, journal, now, opts.Fault); err != nil {
				return result, err
			}
			control, err := store.LayoutTransitionControl(ctx)
			if err != nil || control == nil || control.CommitIntentAt == "" || control.NotBefore == "" {
				return result, fmt.Errorf("%w: migration commit anchor is unavailable: %v", ErrIntegrity, err)
			}
			deadlineText := control.NotBefore
			journal.Phase, journal.GraceNotBefore = "grace", &deadlineText
			if err := persistTransitionJournal(ws.Root, repoName, *journal); err != nil {
				return result, err
			}
			if err := callFault(opts.Fault, "migrate.grace"); err != nil {
				return result, err
			}
		case "grace":
			deadline, _ := time.Parse(time.RFC3339, *journal.GraceNotBefore)
			if len(journal.LegacyAliases) != 0 && now.Before(deadline) {
				result.Phase, result.GraceNotBefore = journal.Phase, journal.GraceNotBefore
				return result, fmt.Errorf("%w: C2 aliases remain protected until %s", ErrNotReady, *journal.GraceNotBefore)
			}
			journal.Phase = "alias_delete"
			if err := persistTransitionJournal(ws.Root, repoName, *journal); err != nil {
				return result, err
			}
		case "alias_delete":
			if err := deleteLegacyAliases(ctx, ws.Root, repoName, journal, opts.Fault); err != nil {
				return result, err
			}
			binding, err = validateTransitionBinding(ctx, ws.Root, repoName, cfg, store, *journal, now)
			if err != nil {
				return result, err
			}
			_, digest, err := state.ManifestBytes(binding.target)
			if err != nil || digest != journal.TargetManifestSHA256 {
				return result, fmt.Errorf("%w: terminal migration manifest differs from planned target", ErrIntegrity)
			}
			journal.Phase = "final_manifest"
			if err := persistTransitionJournal(ws.Root, repoName, *journal); err != nil {
				return result, err
			}
			if err := callFault(opts.Fault, "migrate.final_manifest"); err != nil {
				return result, err
			}
		case "final_manifest":
			terminal := binding.target
			done := *journal
			done.Phase = "done"
			receipt, err := transitionJournalIdentity(done)
			if err != nil {
				return result, err
			}
			migrationOperationID, err := operationID()
			if err != nil {
				return result, err
			}
			generation, err := store.CompleteLayoutTransition(ctx, migrationOperationID, journal.BaseGeneration, terminal, receipt)
			result.Generation = generation
			if err != nil {
				return result, err
			}
			// SQLite terminal state and its done-record digest commit first.  A
			// crash here leaves final_manifest on disk, which the terminal-entry
			// repair above can deterministically advance to the exact done bytes.
			if err := callFault(opts.Fault, "migrate.sqlite_committed"); err != nil {
				return result, err
			}
			if err := persistTransitionJournal(ws.Root, repoName, done); err != nil {
				return result, err
			}
			journal = &done
			if err := callFault(opts.Fault, "migrate.committed"); err != nil {
				return result, err
			}
		case "done":
			identity, err := store.RepositoryIdentity(ctx)
			if err != nil {
				return result, err
			}
			receipt, receiptErr := transitionJournalIdentity(*journal)
			if receiptErr != nil {
				return result, receiptErr
			}
			if identity.LayoutVersion == state.LayoutC2ToSingleV1 {
				migrationOperationID, idErr := operationID()
				if idErr != nil {
					return result, idErr
				}
				result.Generation, err = store.CompleteLayoutTransition(ctx, migrationOperationID, journal.BaseGeneration, binding.target, receipt)
				if err != nil {
					return result, err
				}
				identity, err = store.RepositoryIdentity(ctx)
				if err != nil {
					return result, err
				}
			}
			if identity.LayoutVersion != state.LayoutSinglePayloadV1 || identity.TransitionReceiptSHA256 != receipt {
				return result, fmt.Errorf("%w: done transition is not committed in repository state", ErrIntegrity)
			}
			if err := clearTransitionJournal(ws.Root, repoName); err != nil {
				return result, err
			}
			stage := migrationStageRoot(ws.Root, repoName)
			if _, err := os.Lstat(stage); err == nil {
				if err := removeOwnedDirectory(stage, filepath.Join(ws.Root, ".sow", repoName, "stage")); err != nil {
					return result, err
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return result, err
			}
			summary, err := store.Summary(ctx)
			if err != nil {
				return result, err
			}
			result.Phase, result.Generation, result.Complete = "done", summary.BuiltGeneration, true
			return result, nil
		default:
			return result, fmt.Errorf("%w: unsupported transition phase %q", ErrIntegrity, journal.Phase)
		}
	}
}

func transitionJournalIdentity(journal C2ToSingleTransition) (string, error) {
	data, err := canonicalTransitionJournal(journal)
	if err != nil {
		return "", err
	}
	return domainDigest(transitionSchema, data), nil
}

func transitionPlanIdentity(journal C2ToSingleTransition) (string, error) {
	plan := journal
	plan.Phase, plan.CommitIntent, plan.GraceNotBefore = "planned", false, nil
	plan.Pointers = append([]TransitionPointer(nil), journal.Pointers...)
	for index := range plan.Pointers {
		plan.Pointers[index].State = "old"
	}
	plan.LegacyAliases = append([]TransitionLegacyAlias(nil), journal.LegacyAliases...)
	for index := range plan.LegacyAliases {
		plan.LegacyAliases[index].State = "present"
		plan.LegacyAliases[index].ReceiptSHA256 = nil
	}
	data, err := canonicalTransitionJournal(plan)
	if err != nil {
		return "", err
	}
	return domainDigest(transitionPlanDomain, data), nil
}

func ceilUTCSecond(value time.Time) time.Time {
	value = value.UTC()
	if value.Nanosecond() == 0 {
		return value
	}
	return value.Truncate(time.Second).Add(time.Second)
}

func ensureMigrationCommitAnchor(ctx context.Context, store *state.Store, journal C2ToSingleTransition, now time.Time, grace time.Duration) (*state.LayoutTransitionControl, error) {
	planIdentity, err := transitionPlanIdentity(journal)
	if err != nil {
		return nil, err
	}
	control, err := store.LayoutTransitionControl(ctx)
	if err != nil || control == nil {
		return nil, fmt.Errorf("%w: migration plan anchor is unavailable: %v", ErrIntegrity, err)
	}
	if control.PlanIdentitySHA256 != planIdentity || control.RepositoryID != journal.RepositoryID || control.BaseGeneration != journal.BaseGeneration || control.TargetManifestSHA256 != journal.TargetManifestSHA256 {
		return nil, fmt.Errorf("%w: migration plan differs from SQLite control anchor", ErrIntegrity)
	}
	if control.CommitIntentAt != "" {
		return control, nil
	}
	start := ceilUTCSecond(now)
	deadline := ceilUTCSecond(start.Add(grace))
	startText := start.Format("2006-01-02T15:04:05Z")
	deadlineText := deadline.Format("2006-01-02T15:04:05Z")
	if err := store.CommitLayoutTransitionPlan(ctx, planIdentity, startText, deadlineText); err != nil {
		return nil, err
	}
	return store.LayoutTransitionControl(ctx)
}

func MigrateRepository(ctx context.Context, opts RepositoryMigrationOptions) (RepositoryMigrationResult, error) {
	return MigrateRepositoryLayout(ctx, opts)
}

func migrationWorkspace(opts WorkspaceOptions) (config.Workspace, config.Config, bool, *workspaceRootGuard, error) {
	ws, err := config.Discover(config.DiscoverOptions{Workdir: opts.Workdir, CWD: opts.CWD, SOWDir: opts.SOWDir})
	if err != nil {
		return config.Workspace{}, config.Config{}, false, nil, fmt.Errorf("%w: %v", ErrWorkspaceInput, err)
	}
	guard, err := bindDiscoveredWorkspaceRoot(ws)
	if err != nil {
		return config.Workspace{}, config.Config{}, false, nil, err
	}
	cfg, _, _, legacy, err := config.LoadWorkspaceDocumentForMigration(ws)
	if err != nil {
		_ = guard.Close()
		return config.Workspace{}, config.Config{}, false, nil, fmt.Errorf("%w: %v", ErrWorkspaceInput, err)
	}
	return ws, cfg, legacy, guard, nil
}

func selectMigrationRepository(ws config.Workspace, cfg config.Config, explicit string) (string, error) {
	selection, err := config.SelectRepository(ws, cfg, config.SelectRepositoryOptions{Explicit: explicit})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrRejected, err)
	}
	return selection.Name, nil
}

func transitionJournalPath(root, repoName string) string {
	return filepath.Join(root, ".sow", repoName, "transitions", transitionJournalName)
}

func migrationStageRoot(root, repoName string) string {
	return filepath.Join(root, ".sow", repoName, "stage", "c2-to-single-v1")
}

func loadTransitionJournal(root, repoName string) (*C2ToSingleTransition, string, error) {
	transitionRoot := filepath.Join(root, ".sow", repoName, "transitions")
	data, err := readRootedPrivateRegular(transitionRoot, transitionJournalName, maxTransitionBytes, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	journal, identity, err := ParseC2ToSingleTransition(data)
	return &journal, identity, err
}

func persistTransitionJournal(root, repoName string, journal C2ToSingleTransition) error {
	data, err := canonicalTransitionJournal(journal)
	if err != nil {
		return err
	}
	return writeAtomic(transitionJournalPath(root, repoName), data, 0o600)
}

func clearTransitionJournal(root, repoName string) error {
	return removeRootedRegular(filepath.Join(root, ".sow", repoName, "transitions"), transitionJournalName, -1)
}

func planC2Transition(ctx context.Context, root, repoName string, cfg config.Config, store *state.Store, repositoryID string, at time.Time, jobs int) (*C2ToSingleTransition, error) {
	pending, err := store.PendingOperations(ctx)
	if err != nil {
		return nil, err
	}
	if len(pending) != 0 {
		return nil, fmt.Errorf("%w: v0.2 operation %s must be completed or rolled back before layout migration", ErrNotReady, pending[0].ID)
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return nil, err
	}
	physical, err := scanPublicManifestForLayout(ctx, filepath.Join(root, repoName), state.LayoutC2V1)
	if err != nil {
		return nil, err
	}
	base := []state.GenerationFile{}
	if summary.BuiltGeneration > 0 {
		base, err = store.GenerationManifest(ctx, summary.BuiltGeneration)
		if errors.Is(err, state.ErrNotFound) {
			bootstrapHash := sha256.Sum256([]byte("sow/layout-bootstrap/v1\x00" + repositoryID))
			if err := store.BootstrapLegacyGeneration(ctx, hex.EncodeToString(bootstrapHash[:]), summary.BuiltGeneration, physical); err != nil {
				return nil, err
			}
			base = physical
		} else if err != nil {
			return nil, err
		}
	} else if len(physical) != 0 {
		return nil, fmt.Errorf("%w: Generation 0 C2 repository is not empty", ErrIntegrity)
	}
	if !sameGenerationManifest(base, physical) {
		return nil, fmt.Errorf("%w: v0.2 public tree differs from its Built Generation", ErrIntegrity)
	}
	if err := store.ValidateGenerationLedger(ctx); err != nil && summary.BuiltGeneration > 0 {
		return nil, fmt.Errorf("%w: v0.2 Generation ledger is invalid: %v", ErrIntegrity, err)
	}
	if err := validateC2MigrationSource(ctx, root, repoName, store); err != nil {
		return nil, fmt.Errorf("%w: v0.2 full check failed: %v", ErrIntegrity, err)
	}
	stageOwner := filepath.Join(root, ".sow", repoName, "stage")
	stage := migrationStageRoot(root, repoName)
	if _, err := os.Lstat(stage); err == nil {
		if err := removeOwnedDirectory(stage, stageOwner); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := durableMkdir(stage, 0o700); err != nil {
		return nil, err
	}
	next, err := summary.BuiltGeneration.Next()
	if err != nil {
		return nil, err
	}
	rpmDists := map[string]struct{}{}
	metadataSnapshot, err := validateMigrationSignerConfigBinding(ctx, root, repoName, cfg, store, at)
	if err != nil {
		return nil, err
	}
	dists, err := store.ListDists(ctx)
	if err != nil {
		return nil, err
	}
	rpmSourceDigests := make(map[string][]string)
	allRPMSources := make(map[string]ManagedPackageSource)
	for _, dist := range dists {
		if dist.Format != "rpm" {
			continue
		}
		rpmDists[dist.Name] = struct{}{}
		objects, err := store.ListPackageObjects(ctx, []string{dist.Name}, true)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			rpmSourceDigests[dist.Name] = append(rpmSourceDigests[dist.Name], object.SHA256)
			if _, exists := allRPMSources[object.SHA256]; !exists {
				source, err := availableManagedPackageSource(root, repoName, object)
				if err != nil {
					return nil, err
				}
				allRPMSources[object.SHA256] = source
			}
		}
	}
	if err := loadManagedPackageFacts(ctx, allRPMSources, store, jobs); err != nil {
		return nil, err
	}
	for _, dist := range dists {
		if dist.Format != "rpm" {
			continue
		}
		sources := make([]ManagedPackageSource, 0, len(rpmSourceDigests[dist.Name]))
		for _, digest := range rpmSourceDigests[dist.Name] {
			sources = append(sources, allRPMSources[digest])
		}
		if _, err := RenderManagedDist(ctx, stage, ManagedDistSpec{Name: dist.Name, Format: "rpm", Architectures: dist.Architectures, Generation: next, Jobs: jobs, PublishedAt: at, Packages: sources, RPMSigner: metadataSnapshot.RPMSigner}); err != nil {
			return nil, err
		}
	}
	stagedManifest, err := scanPublicManifest(ctx, stage)
	if err != nil {
		return nil, err
	}
	target := []state.GenerationFile{}
	aliases := []TransitionLegacyAlias{}
	for _, file := range base {
		if canonicalLegacyAliasPath(file.Path) {
			aliases = append(aliases, TransitionLegacyAlias{Path: file.Path, Size: TransitionSize(file.Size), SHA256: file.SHA256, State: "present"})
			continue
		}
		parts := strings.Split(file.Path, "/")
		if len(parts) >= 2 && parts[0] == "dists" {
			if _, replace := rpmDists[parts[1]]; replace {
				continue
			}
		}
		target = append(target, file)
	}
	target = append(target, stagedManifest...)
	sort.Slice(target, func(i, j int) bool { return target[i].Path < target[j].Path })
	_, baseDigest, err := state.ManifestBytesForLayout(base, state.LayoutC2V1)
	if err != nil {
		return nil, err
	}
	_, targetDigest, err := state.ManifestBytes(target)
	if err != nil {
		return nil, err
	}
	baseByPath := generationFilesByPath(base)
	stagedByPath := generationFilesByPath(stagedManifest)
	pointers := []TransitionPointer{}
	for _, dist := range dists {
		if dist.Format != "rpm" {
			continue
		}
		for _, architecture := range dist.Architectures {
			viewID := filepath.ToSlash(filepath.Join("dists", dist.Name, architecture.Family))
			for _, pointerSpec := range []struct{ kind, name string }{{"signature_companion", "repomd.xml.asc"}, {"commit_pointer", "repomd.xml"}} {
				pointerPath := viewID + "/repodata/" + pointerSpec.name
				oldFile, oldExists := baseByPath[pointerPath]
				newFile, newExists := stagedByPath[pointerPath]
				if !oldExists && !newExists && pointerSpec.kind == "signature_companion" {
					continue
				}
				if !oldExists || !newExists {
					return nil, fmt.Errorf("%w: migration pointer %q is not a complete old/new pair", ErrIntegrity, pointerPath)
				}
				if oldFile.SHA256 == newFile.SHA256 {
					return nil, fmt.Errorf("%w: migration pointer %q does not change between old and new layouts", ErrIntegrity, pointerPath)
				}
				pointers = append(pointers, TransitionPointer{ViewID: viewID, Kind: pointerSpec.kind, Path: pointerPath, OldSHA256: oldFile.SHA256, NewSHA256: newFile.SHA256, State: "old"})
			}
		}
	}
	sortTransitionPointers(pointers)
	sort.Slice(aliases, func(i, j int) bool { return aliases[i].Path < aliases[j].Path })
	journal := &C2ToSingleTransition{
		Schema: transitionSchema, RepositoryID: repositoryID, FromLayout: state.LayoutC2V1, ToLayout: state.LayoutSinglePayloadV1,
		BaseGeneration: summary.BuiltGeneration, BaseManifestSHA256: baseDigest, TargetManifestSHA256: targetDigest,
		Phase: "planned", CommitIntent: false, Pointers: pointers, LegacyAliases: aliases,
	}
	return journal, nil
}

func validateC2MigrationSource(ctx context.Context, root, repoName string, store *state.Store) error {
	if err := store.Check(ctx); err != nil {
		return err
	}
	repositoryRoot := filepath.Join(root, repoName)
	allObjects, err := store.ListPackageObjects(ctx, nil, false)
	if err != nil {
		return err
	}
	for _, object := range allObjects {
		if object.Storage != "pool" {
			continue
		}
		file := state.GenerationFile{Path: object.PoolPath, Phase: "payload", Size: object.Size, SHA256: object.SHA256}
		if err := verifyRetainedSource(ctx, repositoryRoot, file); err != nil {
			return err
		}
		source, err := availableManagedPackageSource(root, repoName, object)
		if err != nil {
			return err
		}
		opened, err := source.open()
		if err != nil {
			return err
		}
		facts, inspectErr := inspectSnapshotReader(ctx, opened.file, object.Filename)
		closeErr := opened.CloseVerified()
		if inspectErr != nil || closeErr != nil || !sameManagedPackageFacts(object, facts) {
			return fmt.Errorf("package %s facts differ from SQLite: %v", object.SHA256, errors.Join(inspectErr, closeErr))
		}
	}
	dists, err := store.ListDists(ctx)
	if err != nil {
		return err
	}
	for _, dist := range dists {
		builtObjects, err := store.ListPackageObjects(ctx, []string{dist.Name}, true)
		if err != nil {
			return err
		}
		if dist.Format == "deb" {
			verifier, signed, verifierErr := builtAPTMetadataVerifier(ctx, store, dist)
			if verifierErr != nil {
				return verifierErr
			}
			if err := validateManagedAPTSignature(ctx, repositoryRoot, dist.Name, verifier, signed); err != nil {
				return err
			}
			expected := make(map[string]map[string]state.PackageObject, len(dist.Architectures))
			for _, architecture := range dist.Architectures {
				expected[architecture.EcosystemArch] = map[string]state.PackageObject{}
				for _, object := range builtObjects {
					if object.CanonicalArch == "neutral" || object.CanonicalArch == architecture.Family {
						expected[architecture.EcosystemArch][object.SHA256] = object
					}
				}
			}
			generation := dist.BuiltGeneration
			if err := validateManagedAPTIndex(ctx, repositoryRoot, dist.Name, dist.Architectures, expected, &generation); err != nil {
				return err
			}
			continue
		}
		priorObjects, err := store.ListPriorBuiltPackageObjects(ctx, []string{dist.Name})
		if err != nil {
			return err
		}
		aliasObjects := append(append([]state.PackageObject(nil), builtObjects...), priorObjects...)
		verifier, signed, verifierErr := builtRPMMetadataVerifier(ctx, store, dist)
		if verifierErr != nil {
			return verifierErr
		}
		for _, architecture := range dist.Architectures {
			if err := validateC2RPMViewAliases(ctx, repositoryRoot, dist.Name, architecture.Family, aliasObjects); err != nil {
				return err
			}
			repodata := filepath.Join(repositoryRoot, "dists", dist.Name, architecture.Family, "repodata")
			if err := validateRPMMetadataSignature(ctx, repodata, verifier, signed); err != nil {
				return err
			}
			view, err := yumrepo.ParseManagedRPMViewPath(path.Join("dists", dist.Name, architecture.Family))
			if err != nil {
				return err
			}
			expected := []yumrepo.ManagedRPMPackageExpectation{}
			expectedIdentities := []string{}
			for _, object := range builtObjects {
				if object.CanonicalArch != "neutral" && object.CanonicalArch != architecture.Family {
					continue
				}
				pool, err := yumrepo.ParseManagedPoolPath(object.PoolPath)
				if err != nil {
					return err
				}
				expected = append(expected, yumrepo.ManagedRPMPackageExpectation{SHA256: object.SHA256, Size: object.Size, PoolPath: pool})
				expectedIdentities = append(expectedIdentities, object.SHA256)
			}
			var generation *yumrepo.Generation
			if signed {
				generation, err = yumrepo.ValidateLegacyC2RPMViewDirectory(ctx, repodata, yumrepo.CompressionGzip, structuralDetachedVerifier{}, view, expected)
			} else {
				generation, err = yumrepo.ValidateLegacyC2RPMViewUnsignedDirectory(ctx, repodata, yumrepo.CompressionGzip, view, expected)
			}
			sort.Strings(expectedIdentities)
			identityBytes := []byte(strings.Join(expectedIdentities, "\n"))
			if len(expectedIdentities) != 0 {
				identityBytes = append(identityBytes, '\n')
			}
			if err != nil || generation == nil || generation.Packages != int64(len(expected)) || generation.IdentitySHA256 != bytesSHA(identityBytes) {
				return fmt.Errorf("Dist %s/%s legacy C2 rpm-md differs: %v", dist.Name, architecture.Family, err)
			}
		}
	}
	return nil
}

func generationFilesByPath(files []state.GenerationFile) map[string]state.GenerationFile {
	result := make(map[string]state.GenerationFile, len(files))
	for _, file := range files {
		result[file.Path] = file
	}
	return result
}

type transitionBinding struct {
	pointerState map[string]string
	aliasPresent map[string]bool
	target       []state.GenerationFile
	control      *state.LayoutTransitionControl
}

type migrationRPMView struct {
	ViewID string
	Signed bool
}

func expectedMigrationRPMViews(ctx context.Context, store *state.Store) ([]migrationRPMView, error) {
	dists, err := store.ListDists(ctx)
	if err != nil {
		return nil, err
	}
	views := []migrationRPMView{}
	for _, dist := range dists {
		if dist.Format != "rpm" {
			continue
		}
		for _, architecture := range dist.Architectures {
			views = append(views, migrationRPMView{
				ViewID: filepath.ToSlash(filepath.Join("dists", dist.Name, architecture.Family)),
				Signed: dist.MetadataSignerFingerprint != "",
			})
		}
	}
	sort.Slice(views, func(i, j int) bool { return views[i].ViewID < views[j].ViewID })
	return views, nil
}

func validateMigrationRPMViewSet(expectedViews []migrationRPMView, pointers []TransitionPointer) error {
	expected := make(map[string]migrationRPMView, len(expectedViews))
	for _, view := range expectedViews {
		if _, duplicate := expected[view.ViewID]; duplicate {
			return fmt.Errorf("%w: duplicate Built RPM view %q", ErrIntegrity, view.ViewID)
		}
		expected[view.ViewID] = view
	}
	pointerKinds := map[string]map[string]int{}
	for _, pointer := range pointers {
		if pointerKinds[pointer.ViewID] == nil {
			pointerKinds[pointer.ViewID] = map[string]int{}
		}
		pointerKinds[pointer.ViewID][pointer.Kind]++
	}
	missing, unexpected := []string{}, []string{}
	for viewID := range expected {
		if _, exists := pointerKinds[viewID]; !exists {
			missing = append(missing, viewID)
		}
	}
	for viewID := range pointerKinds {
		if _, exists := expected[viewID]; !exists {
			unexpected = append(unexpected, viewID)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	if len(missing) != 0 || len(unexpected) != 0 {
		return fmt.Errorf("%w: transition RPM view topology differs: missing=%v unexpected=%v", ErrIntegrity, missing, unexpected)
	}
	for _, view := range expectedViews {
		kinds := pointerKinds[view.ViewID]
		wantSignatures := 0
		if view.Signed {
			wantSignatures = 1
		}
		if kinds["commit_pointer"] != 1 || kinds["signature_companion"] != wantSignatures || len(kinds) != 1+wantSignatures {
			return fmt.Errorf("%w: transition view %q pointer set differs from Built signing state", ErrIntegrity, view.ViewID)
		}
	}
	return nil
}

// validateTransitionBinding closes every resume over the SQLite identity,
// base ledger, complete staged/new RPM closure, live pointer state, exact C2
// alias inventory, and the physical public tree.  The only tolerated journal
// lag is the two explicitly journaled mutation-before-persist seams in
// pointer_rollforward and alias_delete.
func validateTransitionBinding(ctx context.Context, root, repoName string, cfg config.Config, store *state.Store, journal C2ToSingleTransition, at time.Time) (transitionBinding, error) {
	result := transitionBinding{pointerState: map[string]string{}, aliasPresent: map[string]bool{}}
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		return result, err
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return result, err
	}
	next, nextErr := journal.BaseGeneration.Next()
	if nextErr != nil {
		return result, nextErr
	}
	done := journal
	done.Phase = "done"
	done.CommitIntent = true
	doneIdentity, doneErr := transitionJournalIdentity(done)
	terminalCrash := journal.Phase == "final_manifest" && identity.LayoutVersion == state.LayoutSinglePayloadV1 &&
		summary.BuiltGeneration == next && doneErr == nil && identity.TransitionReceiptSHA256 == doneIdentity
	donePendingSQLite := journal.Phase == "done" && identity.LayoutVersion == state.LayoutC2ToSingleV1 &&
		summary.BuiltGeneration == journal.BaseGeneration && identity.TransitionReceiptSHA256 == "" && doneErr == nil
	if journal.Phase == "done" {
		terminalDone := identity.LayoutVersion == state.LayoutSinglePayloadV1 && summary.BuiltGeneration == next && doneErr == nil && identity.TransitionReceiptSHA256 == doneIdentity
		if !terminalDone && !donePendingSQLite {
			return result, fmt.Errorf("%w: done transition differs from terminal SQLite identity", ErrIntegrity)
		}
	} else if !terminalCrash {
		if identity.LayoutVersion != state.LayoutC2ToSingleV1 || summary.BuiltGeneration != journal.BaseGeneration || identity.TransitionReceiptSHA256 != "" {
			return result, fmt.Errorf("%w: transition phase %s differs from SQLite base/layout", ErrIntegrity, journal.Phase)
		}
	}
	if identity.RepositoryID != journal.RepositoryID {
		return result, fmt.Errorf("%w: transition Repository identity changed", ErrIntegrity)
	}
	base := []state.GenerationFile{}
	if journal.BaseGeneration > 0 {
		base, err = store.GenerationManifest(ctx, journal.BaseGeneration)
		if err != nil {
			return result, err
		}
	}
	_, baseDigest, err := state.ManifestBytesForLayout(base, state.LayoutC2V1)
	if err != nil || baseDigest != journal.BaseManifestSHA256 {
		return result, fmt.Errorf("%w: transition base manifest identity differs: %v", ErrIntegrity, err)
	}
	planIdentity, err := transitionPlanIdentity(journal)
	if err != nil {
		return result, err
	}
	control, err := store.LayoutTransitionControl(ctx)
	if err != nil || control == nil || control.RepositoryID != journal.RepositoryID || control.BaseGeneration != journal.BaseGeneration ||
		control.TargetManifestSHA256 != journal.TargetManifestSHA256 || control.PlanIdentitySHA256 != planIdentity {
		return result, fmt.Errorf("%w: transition journal differs from SQLite control anchor: %v", ErrIntegrity, err)
	}
	result.control = control
	rank := transitionPhaseRank[journal.Phase]
	commitAnchored := control.CommitIntentAt != ""
	if commitAnchored {
		if control.NotBefore == "" || rank < transitionPhaseRank["staged"] ||
			rank >= transitionPhaseRank["grace"] && (journal.GraceNotBefore == nil || *journal.GraceNotBefore != control.NotBefore) {
			return result, fmt.Errorf("%w: transition phase/deadline differs from committed SQLite control", ErrIntegrity)
		}
	} else if rank >= transitionPhaseRank["commit_intent"] {
		return result, fmt.Errorf("%w: transition journal has commit intent without SQLite authority", ErrIntegrity)
	}
	// Before commit, continued authorization is bound to the currently
	// effective config and usable private signer.  After the SQLite commit
	// anchor, recovery is secret-independent and validates only frozen journal
	// bytes plus Built public signer/config evidence.
	if !commitAnchored {
		if _, err := validateMigrationSignerConfigBinding(ctx, root, repoName, cfg, store, at); err != nil {
			return result, err
		}
	}
	expectedViews, err := expectedMigrationRPMViews(ctx, store)
	if err != nil {
		return result, err
	}
	if err := validateMigrationRPMViewSet(expectedViews, journal.Pointers); err != nil {
		return result, err
	}
	repositoryRoot := filepath.Join(root, repoName)
	viewState := map[string]string{}
	for _, pointer := range journal.Pointers {
		digest, digestErr := digestRootedPath(ctx, repositoryRoot, pointer.Path)
		if digestErr != nil {
			return result, fmt.Errorf("%w: transition pointer %q is unavailable: %v", ErrIntegrity, pointer.Path, digestErr)
		}
		actual := ""
		switch digest {
		case pointer.OldSHA256:
			actual = "old"
		case pointer.NewSHA256:
			actual = "new"
		default:
			return result, fmt.Errorf("%w: transition pointer %q is neither old nor new", ErrIntegrity, pointer.Path)
		}
		if previous, exists := viewState[pointer.ViewID]; exists && previous != actual {
			return result, fmt.Errorf("%w: transition view %q has a torn pointer set", ErrIntegrity, pointer.ViewID)
		}
		viewState[pointer.ViewID], result.pointerState[pointer.Path] = actual, actual
	}
	for _, pointer := range journal.Pointers {
		actual := result.pointerState[pointer.Path]
		switch {
		case rank < transitionPhaseRank["pointer_rollforward"]:
			if actual != "old" || pointer.State != "old" {
				return result, fmt.Errorf("%w: pointer changed before pointer_rollforward", ErrIntegrity)
			}
		case journal.Phase == "pointer_rollforward":
			if pointer.State == "new" && actual != "new" {
				return result, fmt.Errorf("%w: journaled new pointer rolled backward", ErrIntegrity)
			}
		case rank >= transitionPhaseRank["grace"]:
			if actual != "new" || pointer.State != "new" {
				return result, fmt.Errorf("%w: phase %s lacks complete new pointer closure", ErrIntegrity, journal.Phase)
			}
		}
	}
	result.aliasPresent, err = inspectLegacyAliasInventory(ctx, repositoryRoot, journal)
	if err != nil {
		return result, err
	}
	for _, alias := range journal.LegacyAliases {
		present := result.aliasPresent[alias.Path]
		switch {
		case rank < transitionPhaseRank["alias_delete"]:
			if !present || alias.State != "present" {
				return result, fmt.Errorf("%w: legacy alias changed before alias_delete", ErrIntegrity)
			}
		case journal.Phase == "alias_delete":
			if alias.State == "deleted" && present {
				return result, fmt.Errorf("%w: deleted alias %q reappeared", ErrIntegrity, alias.Path)
			}
		case rank >= transitionPhaseRank["final_manifest"]:
			if present || alias.State != "deleted" {
				return result, fmt.Errorf("%w: terminal transition retains alias %q", ErrIntegrity, alias.Path)
			}
		}
	}
	target, currentExpected, stageExpected, err := transitionExpectedManifests(ctx, root, repoName, store, journal, base, viewState, result.aliasPresent, next)
	if err != nil {
		return result, err
	}
	_, targetDigest, err := state.ManifestBytes(target)
	if err != nil || targetDigest != journal.TargetManifestSHA256 {
		return result, fmt.Errorf("%w: complete staged target manifest differs: %v", ErrIntegrity, err)
	}
	physical, err := scanPublicManifestForLayout(ctx, repositoryRoot, state.LayoutC2V1)
	if err != nil || !sameGenerationManifest(physical, currentExpected) {
		return result, fmt.Errorf("%w: public transition tree is not the journal-permitted composition: %v", ErrIntegrity, err)
	}
	stage, err := scanPublicManifestForLayout(ctx, migrationStageRoot(root, repoName), state.LayoutC2V1)
	if err != nil || !sameGenerationManifest(stage, stageExpected) {
		return result, fmt.Errorf("%w: migration stage inventory differs from old/new exchange state: %v", ErrIntegrity, err)
	}
	result.target = target
	return result, nil
}

func validateMigrationSignerConfigBinding(ctx context.Context, root, repoName string, cfg config.Config, store *state.Store, at time.Time) (metadataSignerSnapshot, error) {
	dists, err := store.ListDists(ctx)
	if err != nil {
		return metadataSignerSnapshot{}, err
	}
	wantRPM := false
	for _, dist := range dists {
		wantRPM = wantRPM || dist.Format == "rpm"
		observed, dirty, observeErr := observedEffectiveDistConfig(ctx, root, cfg, repoName, dist.Name, dist)
		if observeErr != nil || dirty || observed != dist.EffectiveConfigSHA256 {
			return metadataSignerSnapshot{}, fmt.Errorf("%w: Dist %s configuration differs from Built state: %v", ErrIntegrity, dist.Name, observeErr)
		}
	}
	if !wantRPM {
		return metadataSignerSnapshot{}, nil
	}
	repository := cfg.Repositories[repoName]
	snapshot, err := loadMetadataSignerSnapshotForFormats(ctx, root, repository, at, true, false)
	if err != nil {
		return metadataSignerSnapshot{}, err
	}
	policy, err := loadRPMSigningPolicy(ctx, root, repository.Signing.RPM.Packages)
	if err != nil {
		return metadataSignerSnapshot{}, err
	}
	frozen, err := frozenEffectiveSigningForFormats(repository.Signing, policy, snapshot, true, false)
	if err != nil {
		return metadataSignerSnapshot{}, err
	}
	frozenBytes, err := json.Marshal(frozen)
	if err != nil {
		return metadataSignerSnapshot{}, err
	}
	for _, dist := range dists {
		if dist.Format != "rpm" {
			continue
		}
		if dist.EffectiveSigningJSON != string(frozenBytes) || dist.MetadataSignerFingerprint != snapshot.RPM.Fingerprint || !bytes.Equal(dist.MetadataSignerPublicKey, snapshot.RPM.PublicKey) {
			return metadataSignerSnapshot{}, fmt.Errorf("%w: Dist %s signer/config snapshot differs from Built state", ErrIntegrity, dist.Name)
		}
	}
	return snapshot, nil
}

func inspectLegacyAliasInventory(ctx context.Context, repositoryRoot string, journal C2ToSingleTransition) (map[string]bool, error) {
	present := make(map[string]bool, len(journal.LegacyAliases))
	expected := make(map[string]TransitionLegacyAlias, len(journal.LegacyAliases))
	poolRoots := map[string]struct{}{}
	for _, alias := range journal.LegacyAliases {
		expected[alias.Path] = alias
		parts := strings.Split(alias.Path, "/")
		poolRoots[strings.Join(parts[:4], "/")] = struct{}{}
		opened, err := openRootedRegular(repositoryRoot, alias.Path)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
			present[alias.Path] = false
			continue
		}
		if err != nil {
			return nil, err
		}
		canonicalPath := strings.Join(parts[3:], "/")
		canonical, canonicalErr := openRootedRegular(repositoryRoot, canonicalPath)
		if canonicalErr != nil {
			return nil, errors.Join(canonicalErr, opened.CloseVerified())
		}
		same := os.SameFile(opened.before, canonical.before)
		closeErr := errors.Join(opened.CloseVerified(), canonical.CloseVerified())
		file := state.GenerationFile{Path: alias.Path, Phase: "payload", Size: int64(alias.Size), SHA256: alias.SHA256}
		if !same || closeErr != nil || verifyRetainedSource(ctx, repositoryRoot, file) != nil {
			return nil, fmt.Errorf("%w: legacy alias %q is not its exact canonical Pool hardlink", ErrIntegrity, alias.Path)
		}
		present[alias.Path] = true
	}
	for poolRoot := range poolRoots {
		chain, err := openRootedDirectoryChain(repositoryRoot, poolRoot, false, 0)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := chain.close(true); err != nil {
			return nil, err
		}
		err = walkRootedTree(ctx, filepath.Join(repositoryRoot, filepath.FromSlash(poolRoot)), func(relative string, _ *os.File, _ os.FileInfo) error {
			full := path.Join(poolRoot, relative)
			if _, exists := expected[full]; !exists {
				return fmt.Errorf("%w: legacy alias directory contains foreign file %q", ErrIntegrity, full)
			}
			return nil
		}, nil)
		if err != nil {
			return nil, err
		}
	}
	return present, nil
}

func transitionExpectedManifests(ctx context.Context, root, repoName string, store *state.Store, journal C2ToSingleTransition, base []state.GenerationFile, viewState map[string]string, aliasPresent map[string]bool, next state.GenerationID) ([]state.GenerationFile, []state.GenerationFile, []state.GenerationFile, error) {
	repositoryRoot := filepath.Join(root, repoName)
	stageRoot := migrationStageRoot(root, repoName)
	viewIDs := make([]string, 0, len(viewState))
	for viewID := range viewState {
		viewIDs = append(viewIDs, viewID)
	}
	sort.Strings(viewIDs)
	baseByView := map[string][]state.GenerationFile{}
	preserved := []state.GenerationFile{}
	for _, file := range base {
		if canonicalLegacyAliasPath(file.Path) {
			continue
		}
		matched := false
		for _, viewID := range viewIDs {
			if strings.HasPrefix(file.Path, viewID+"/") {
				baseByView[viewID] = append(baseByView[viewID], file)
				matched = true
				break
			}
		}
		if !matched {
			preserved = append(preserved, file)
		}
	}
	target := append([]state.GenerationFile(nil), preserved...)
	current := append([]state.GenerationFile(nil), preserved...)
	stageExpected := []state.GenerationFile{}
	for _, viewID := range viewIDs {
		newRoot := stageRoot
		if viewState[viewID] == "new" {
			newRoot = repositoryRoot
		}
		if err := validateMigrationRPMView(ctx, repositoryRoot, newRoot, viewID, store, false, uint64(next)); err != nil {
			return nil, nil, nil, err
		}
		newView, err := scanTransitionViewManifest(ctx, newRoot, viewID, state.LayoutSinglePayloadV1)
		if err != nil {
			return nil, nil, nil, err
		}
		target = append(target, newView...)
		if viewState[viewID] == "new" {
			current = append(current, newView...)
			stageExpected = append(stageExpected, baseByView[viewID]...)
		} else {
			if err := validateMigrationRPMView(ctx, repositoryRoot, repositoryRoot, viewID, store, true, uint64(journal.BaseGeneration)); err != nil {
				return nil, nil, nil, err
			}
			current = append(current, baseByView[viewID]...)
			stageExpected = append(stageExpected, newView...)
		}
	}
	for _, alias := range journal.LegacyAliases {
		if aliasPresent[alias.Path] {
			current = append(current, state.GenerationFile{Path: alias.Path, Phase: "payload", Size: int64(alias.Size), SHA256: alias.SHA256})
		}
	}
	for _, files := range [][]state.GenerationFile{target, current, stageExpected} {
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	}
	return target, current, stageExpected, nil
}

func scanTransitionViewManifest(ctx context.Context, contentRoot, viewID, layout string) ([]state.GenerationFile, error) {
	files := []state.GenerationFile{}
	viewRoot := filepath.Join(contentRoot, filepath.FromSlash(viewID), "repodata")
	err := walkRootedTree(ctx, viewRoot, func(relative string, file *os.File, info os.FileInfo) error {
		full := path.Join(viewID, "repodata", filepath.ToSlash(relative))
		phase := publicFilePhaseForLayout(full, layout)
		if phase == "" {
			return fmt.Errorf("%w: transition view contains payload %q", ErrIntegrity, full)
		}
		hash := sha256.New()
		if _, err := ioCopyContext(ctx, hash, file); err != nil {
			return err
		}
		files = append(files, state.GenerationFile{Path: full, Phase: phase, Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))})
		return nil
	}, nil)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, err
}

func validateMigrationRPMView(ctx context.Context, repositoryRoot, contentRoot, viewID string, store *state.Store, legacy bool, expectedRevision uint64) error {
	parts := strings.Split(viewID, "/")
	if len(parts) != 3 {
		return fmt.Errorf("%w: invalid migration RPM view %q", ErrIntegrity, viewID)
	}
	dist, err := store.GetDist(ctx, parts[1])
	if err != nil || dist.Format != "rpm" {
		return fmt.Errorf("%w: migration RPM view %q has no Built Dist", ErrIntegrity, viewID)
	}
	objects, err := store.ListPackageObjects(ctx, []string{dist.Name}, true)
	if err != nil {
		return err
	}
	expected := []yumrepo.ManagedRPMPackageExpectation{}
	identities := []string{}
	for _, object := range objects {
		if object.CanonicalArch != "neutral" && object.CanonicalArch != parts[2] {
			continue
		}
		pool, parseErr := yumrepo.ParseManagedPoolPath(object.PoolPath)
		if parseErr != nil {
			return parseErr
		}
		expected = append(expected, yumrepo.ManagedRPMPackageExpectation{SHA256: object.SHA256, Size: object.Size, PoolPath: pool})
		identities = append(identities, object.SHA256)
	}
	verifier, signed, err := builtRPMMetadataVerifier(ctx, store, dist)
	if err != nil {
		return err
	}
	repodata := filepath.Join(contentRoot, filepath.FromSlash(viewID), "repodata")
	if signed && !legacy {
		signature, signatureErr := readOptionalBoundedRegular(repodata, "repomd.xml.asc", 16<<20)
		if signatureErr != nil {
			return fmt.Errorf("%w: migration RPM view %s lacks its frozen signature: %v", ErrIntegrity, viewID, signatureErr)
		}
		signedAt, signatureErr := yumrepo.DetachedSignatureCreationTime(bytes.NewReader(signature))
		if signatureErr != nil {
			return signatureErr
		}
		verifier, signatureErr = yumrepo.NewOpenPGPVerifier(bytes.NewReader(dist.MetadataSignerPublicKey), signedAt)
		if signatureErr != nil {
			return signatureErr
		}
	}
	if err := validateRPMMetadataSignature(ctx, repodata, verifier, signed); err != nil {
		return err
	}
	view, err := yumrepo.ParseManagedRPMViewPath(viewID)
	if err != nil {
		return err
	}
	var generated *yumrepo.Generation
	if legacy {
		if signed {
			generated, err = yumrepo.ValidateLegacyC2RPMViewDirectory(ctx, repodata, yumrepo.CompressionGzip, structuralDetachedVerifier{}, view, expected)
		} else {
			generated, err = yumrepo.ValidateLegacyC2RPMViewUnsignedDirectory(ctx, repodata, yumrepo.CompressionGzip, view, expected)
		}
	} else {
		baseURL := &url.URL{Scheme: "file", Path: filepath.ToSlash(repositoryRoot) + "/"}
		if signed {
			generated, err = yumrepo.ValidateManagedRPMViewDirectory(ctx, repodata, yumrepo.CompressionGzip, structuralDetachedVerifier{}, baseURL, view, expected)
		} else {
			generated, err = yumrepo.ValidateManagedRPMViewUnsignedDirectory(ctx, repodata, yumrepo.CompressionGzip, baseURL, view, expected)
		}
	}
	sort.Strings(identities)
	identityBytes := []byte(strings.Join(identities, "\n"))
	if len(identities) != 0 {
		identityBytes = append(identityBytes, '\n')
	}
	if err != nil || generated == nil || generated.Revision != expectedRevision || generated.Packages != int64(len(expected)) || generated.IdentitySHA256 != bytesSHA(identityBytes) {
		return fmt.Errorf("%w: migration RPM view %s closure differs: %v", ErrIntegrity, viewID, err)
	}
	return nil
}

func rollForwardMigrationPointers(ctx context.Context, root, repoName string, cfg config.Config, store *state.Store, journal *C2ToSingleTransition, at time.Time, fault func(string) error) error {
	views := []string{}
	seen := map[string]struct{}{}
	for _, pointer := range journal.Pointers {
		if _, exists := seen[pointer.ViewID]; !exists {
			seen[pointer.ViewID] = struct{}{}
			views = append(views, pointer.ViewID)
		}
	}
	for _, view := range views {
		if _, err := validateTransitionBinding(ctx, root, repoName, cfg, store, *journal, at); err != nil {
			return err
		}
		commitIndex := -1
		for index := range journal.Pointers {
			if journal.Pointers[index].ViewID == view && journal.Pointers[index].Kind == "commit_pointer" {
				commitIndex = index
				break
			}
		}
		if commitIndex < 0 {
			return fmt.Errorf("%w: transition view %q has no commit pointer", ErrIntegrity, view)
		}
		commit := journal.Pointers[commitIndex]
		liveDigest, err := digestRootedPath(ctx, filepath.Join(root, repoName), commit.Path)
		if err != nil {
			return err
		}
		if liveDigest == commit.OldSHA256 {
			liveRelative := filepath.Join(repoName, filepath.FromSlash(view), "repodata")
			stagedRelative := filepath.Join(".sow", repoName, "stage", "c2-to-single-v1", filepath.FromSlash(view), "repodata")
			if err := exchangeRootedDirectories(root, liveRelative, stagedRelative); err != nil {
				return fmt.Errorf("managed: roll forward migration view %q: %w", view, err)
			}
			// This seam deliberately precedes journal persistence.  Replay must
			// recognize the new commit-pointer digest and continue forward.
			if err := callFault(fault, "migrate.pointer_exchanged."+view); err != nil {
				return err
			}
		} else if liveDigest != commit.NewSHA256 {
			return fmt.Errorf("%w: migration commit pointer %q is neither old nor new", ErrIntegrity, commit.Path)
		}
		if _, err := validateTransitionBinding(ctx, root, repoName, cfg, store, *journal, at); err != nil {
			return err
		}
		for index := range journal.Pointers {
			pointer := &journal.Pointers[index]
			if pointer.ViewID != view {
				continue
			}
			digest, err := digestRootedPath(ctx, filepath.Join(root, repoName), pointer.Path)
			if err != nil || digest != pointer.NewSHA256 {
				return fmt.Errorf("%w: migrated pointer %q does not match planned new bytes", ErrIntegrity, pointer.Path)
			}
			pointer.State = "new"
		}
		if err := persistTransitionJournal(root, repoName, *journal); err != nil {
			return err
		}
		if err := callFault(fault, "migrate.pointer."+view); err != nil {
			return err
		}
	}
	return nil
}

func digestRootedPath(ctx context.Context, root, relative string) (string, error) {
	opened, err := openRootedRegular(root, filepath.FromSlash(relative))
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := ioCopyContext(ctx, hash, opened.file)
	return hex.EncodeToString(hash.Sum(nil)), errors.Join(copyErr, opened.CloseVerified())
}

func ioCopyContext(ctx context.Context, destination interface{ Write([]byte) (int, error) }, source *os.File) (int64, error) {
	return (&copyCounter{writer: destination}).copy(ctx, source)
}

type copyCounter struct {
	writer interface{ Write([]byte) (int, error) }
}

func (counter *copyCounter) copy(ctx context.Context, source *os.File) (int64, error) {
	buffer := make([]byte, 128*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := counter.writer.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, errors.New("short migration digest write")
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
	}
}

func deleteLegacyAliases(ctx context.Context, root, repoName string, journal *C2ToSingleTransition, fault func(string) error) error {
	repositoryRoot := filepath.Join(root, repoName)
	poolRoots := map[string]struct{}{}
	for index := range journal.LegacyAliases {
		alias := &journal.LegacyAliases[index]
		parts := strings.Split(alias.Path, "/")
		poolRoots[strings.Join(parts[:4], "/")] = struct{}{}
		if alias.State == "deleted" {
			continue
		}
		opened, openErr := openRootedRegular(repositoryRoot, alias.Path)
		present := openErr == nil
		if openErr == nil {
			if err := opened.CloseVerified(); err != nil {
				return err
			}
		} else if !errors.Is(openErr, os.ErrNotExist) && !errors.Is(openErr, unix.ENOENT) {
			return openErr
		}
		if err := removeRootedRegularExact(ctx, repositoryRoot, filepath.FromSlash(alias.Path), int64(alias.Size), alias.SHA256); err != nil {
			return err
		}
		if present {
			// This seam deliberately leaves a deleted alias whose receipt is not
			// yet journaled.  Replay derives the same deterministic receipt from
			// the immutable inventory rather than recreating the alias.
			if err := callFault(fault, "migrate.alias_removed."+alias.Path); err != nil {
				return err
			}
		}
		receipt, receiptErr := CanonicalAliasDeletionReceipt(journal.RepositoryID, alias.Path, int64(alias.Size), alias.SHA256)
		if receiptErr != nil {
			return receiptErr
		}
		alias.State, alias.ReceiptSHA256 = "deleted", &receipt
		if err := persistTransitionJournal(root, repoName, *journal); err != nil {
			return err
		}
		if err := callFault(fault, "migrate.alias."+alias.Path); err != nil {
			return err
		}
	}
	orderedRoots := make([]string, 0, len(poolRoots))
	for relative := range poolRoots {
		orderedRoots = append(orderedRoots, relative)
	}
	sort.Strings(orderedRoots)
	for _, relative := range orderedRoots {
		if err := removeRootedEmptyDirectoryTree(repositoryRoot, relative); err != nil {
			return err
		}
	}
	return nil
}

func AbandonRepositoryMigration(ctx context.Context, opts RepositoryMigrationOptions) (result RepositoryMigrationResult, resultErr error) {
	ws, cfg, _, rootGuard, err := migrationWorkspace(opts.WorkspaceOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	repoName, err := selectMigrationRepository(ws, cfg, opts.Repository)
	if err != nil {
		return result, err
	}
	workspaceLock, repoLock, err := acquireLifecycleLocks(ctx, ws.Root, repoName, opts.LockOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close(), repoLock.Close()) }()
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		return result, err
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return result, err
	}
	journal, _, err := loadTransitionJournal(ws.Root, repoName)
	if err != nil {
		return result, err
	}
	control, controlErr := store.LayoutTransitionControl(ctx)
	if controlErr != nil {
		return result, controlErr
	}
	if journal != nil && journal.CommitIntent || control != nil && control.CommitIntentAt != "" {
		return result, fmt.Errorf("%w: migration can be abandoned only before commit_intent", ErrRejected)
	}
	if identity.LayoutVersion == state.LayoutSinglePayloadV1 {
		return result, fmt.Errorf("%w: terminal Repository has no migration to abandon", ErrRejected)
	}
	if journal != nil && control != nil {
		planIdentity, planErr := transitionPlanIdentity(*journal)
		if planErr != nil || journal.RepositoryID != control.RepositoryID || journal.BaseGeneration != control.BaseGeneration || journal.TargetManifestSHA256 != control.TargetManifestSHA256 || planIdentity != control.PlanIdentitySHA256 {
			return result, fmt.Errorf("%w: journal and migration control differ", ErrIntegrity)
		}
	}
	repositoryID, base := identity.RepositoryID, summary.BuiltGeneration
	if journal != nil {
		repositoryID, base = journal.RepositoryID, journal.BaseGeneration
	} else if control != nil {
		repositoryID, base = control.RepositoryID, control.BaseGeneration
	}
	stage := migrationStageRoot(ws.Root, repoName)
	if _, err := os.Lstat(stage); err == nil {
		if err := removeOwnedDirectory(stage, filepath.Join(ws.Root, ".sow", repoName, "stage")); err != nil {
			return result, err
		}
	}
	if identity.LayoutVersion == state.LayoutC2ToSingleV1 {
		// SQLite authority is rolled back before the filesystem journal is
		// removed.  A crash at this seam leaves a readable C2 Repository plus a
		// stale precommit journal that the next --abort can safely clear.
		if err := store.AbandonLayoutTransition(ctx); err != nil {
			return result, err
		}
		if err := callFault(opts.Fault, "migrate.abort_state"); err != nil {
			return result, err
		}
	} else if identity.LayoutVersion != state.LayoutC2V1 {
		return result, fmt.Errorf("%w: unsupported Repository layout %q", ErrIntegrity, identity.LayoutVersion)
	}
	if journal != nil {
		if err := clearTransitionJournal(ws.Root, repoName); err != nil {
			return result, err
		}
	}
	result = RepositoryMigrationResult{Repository: repoName, RepositoryID: repositoryID, FromLayout: state.LayoutC2V1, ToLayout: state.LayoutSinglePayloadV1, Phase: "abandoned", Generation: base}
	return result, nil
}
