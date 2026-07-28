package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

const (
	localServingRemovalSchema = "sow-local-serving-removal/v1"
	localServingRemovalLimit  = 1 << 20
)

var (
	localServingRemovalNamePattern = regexp.MustCompile(`^[0-9a-f]{32}\.json$`)
)

type localServingRemovalPhase string

const (
	localServingRemovalIntent         localServingRemovalPhase = "removal-intent"
	localServingRemovalStateCommitted localServingRemovalPhase = "state-committed"
	localServingRemovalPointerRemoved localServingRemovalPhase = "pointer-removed"
	localServingRemovalTrustRemoved   localServingRemovalPhase = "trust-removed"
)

type localServingRemovalTrust struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Quarantine string `json:"quarantine"`
}

type localServingRemovalJournal struct {
	Schema     string                     `json:"schema"`
	ID         string                     `json:"id"`
	Phase      localServingRemovalPhase   `json:"phase"`
	TargetRoot string                     `json:"target_root"`
	Channel    serving.Channel            `json:"channel"`
	Trust      []localServingRemovalTrust `json:"trust,omitempty"`
}

type localServingTopologyResult struct {
	ChannelsRemoved int
	PointersRemoved int
	LedgersExpired  int
}

func localServingSelectionIsFull(values commonFlags) bool {
	return len(values.repos.values()) == 0 && len(values.oses.values()) == 0 && len(values.arches.values()) == 0
}

func servingLeafKey(repo, osName, arch string) string {
	return repo + "\x00" + osName + "\x00" + arch
}

func desiredLocalYUMServingLeaves(canonical *state.Store, cfg *config.Config, repos []config.Repo, view string, values commonFlags) ([]localYUMServingLeaf, error) {
	viewConfig, exists := cfg.Views[view]
	if !exists {
		return nil, fmt.Errorf("unknown serving view %q", view)
	}
	var requested []viewLeaf
	for _, leaf := range localServingLeavesFromViewLeaves(selectedLeaves(repos, values)) {
		if !viewIncludesRepo(viewConfig, leaf.repo.ID) {
			continue
		}
		ref, err := state.ViewRef(view, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return nil, err
		}
		_, refExists, err := canonical.Ref(ref)
		if err != nil {
			return nil, err
		}
		if refExists {
			requested = append(requested, viewLeaf(leaf))
		}
	}
	closed, err := materializedRoutePhysicalClosureLeaves(cfg, canonical, materializeCanonicalSource{ID: view, Public: viewConfig.Access == "public"}, requested)
	if err != nil {
		return nil, err
	}
	return localServingLeavesFromViewLeaves(closed), nil
}

func pruneLocalServingLifecycle(ctx context.Context, cfg *config.Config, canonical *state.Store) (int, error) {
	journals, err := listLocalServingJournals(cfg.StatePath())
	if err != nil {
		return 0, err
	}
	expired, err := pruneCanonicalServingGenerationLedgers(ctx, canonical, journals)
	return len(expired), err
}

func reconcileLocalServingTopology(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	targetRoot, view string,
	desiredTarget *serving.TargetIdentity,
	desiredLeaves []localYUMServingLeaf,
	fullAuthority, exactTarget bool,
) (localServingTopologyResult, error) {
	var result localServingTopologyResult
	if !fullAuthority && !exactTarget {
		return result, nil
	}
	targetRelative, err := localServingTargetRelative(cfg, targetRoot)
	if err != nil {
		return result, err
	}
	desired := make(map[string]struct{}, len(desiredLeaves))
	for _, leaf := range desiredLeaves {
		desired[servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)] = struct{}{}
	}
	if len(desired) != 0 && desiredTarget == nil {
		return result, errors.New("desired YUM serving topology requires a target identity")
	}
	if desiredTarget != nil && desiredTarget.Root != targetRelative {
		return result, errors.New("desired YUM serving target differs from the reconciled root")
	}
	channels, _, err := loadCanonicalServingChannelIndex(canonical)
	if err != nil {
		return result, err
	}
	var removals []canonicalServingChannel
	for _, record := range channels {
		channel := record.Channel
		if channel.TargetRoot != targetRelative || (!exactTarget && channel.View != view) {
			continue
		}
		_, leafWanted := desired[servingLeafKey(channel.Repo, channel.OS, channel.Arch)]
		if channel.View == view && leafWanted && desiredTarget != nil && channel.TargetID == desiredTarget.ID {
			continue
		}
		removals = append(removals, record)
	}
	if len(removals) == 0 {
		journals, err := listLocalServingJournals(cfg.StatePath())
		if err != nil {
			return result, err
		}
		expired, err := pruneCanonicalServingGenerationLedgers(ctx, canonical, journals)
		result.LedgersExpired = len(expired)
		if err != nil {
			return result, err
		}
		if exactTarget {
			err = pruneExactLocalServingTargetRegistries(ctx, canonical, targetRelative)
		}
		return result, err
	}

	seenPointers := make(map[string]string)
	for _, record := range removals {
		channel := record.Channel
		if owner, exists := seenPointers[channel.MirrorlistPath]; exists {
			return result, fmt.Errorf("multiple canonical channels %s and %s claim mirrorlist %s", owner, record.Path, channel.MirrorlistPath)
		}
		seenPointers[channel.MirrorlistPath] = record.Path
		body, exists, err := serving.ReadMirrorlist(targetRoot, channel.MirrorlistPath)
		if err != nil {
			return result, err
		}
		if exists {
			wanted, err := channel.MirrorlistBody()
			if err != nil {
				return result, err
			}
			if !bytes.Equal(body, wanted) {
				return result, fmt.Errorf("topology removal mirrorlist %s differs from canonical parent", channel.MirrorlistPath)
			}
		}
	}

	journals := make([]localServingRemovalJournal, 0, len(removals))
	deletePaths := make([]string, 0, len(removals))
	for _, record := range removals {
		trust, err := localServingCompatibilityRemovalTrust(cfg, canonical, record.Channel)
		if err != nil {
			return result, err
		}
		journal := localServingRemovalJournal{
			Schema: localServingRemovalSchema, Phase: localServingRemovalIntent,
			TargetRoot: targetRelative, Channel: record.Channel, Trust: trust,
		}
		journal.ID = localServingRemovalJournalID(journal)
		if err := createLocalServingRemovalJournal(cfg.StatePath(), journal); err != nil {
			return result, err
		}
		journals = append(journals, journal)
		deletePaths = append(deletePaths, record.Path)
	}
	sort.Strings(deletePaths)
	if _, changed, err := applyCanonicalState(ctx, canonical, "materialize-serving-topology", "sow: remove obsolete local YUM serving channels", nil, nil, state.ApplyOptions{DeletePaths: deletePaths}); err != nil {
		return result, err
	} else if !changed {
		return result, errors.New("serving topology selected channels but canonical transaction did not change")
	}
	result.ChannelsRemoved = len(deletePaths)
	var removalPool *repository.Store
	for index := range journals {
		journals[index].Phase = localServingRemovalStateCommitted
		if err := updateLocalServingRemovalJournal(cfg.StatePath(), journals[index]); err != nil {
			return result, err
		}
		removed, err := serving.RemoveMirrorlist(targetRoot, journals[index].Channel)
		if err != nil {
			return result, err
		}
		if removed {
			result.PointersRemoved++
		}
		journals[index].Phase = localServingRemovalPointerRemoved
		if err := updateLocalServingRemovalJournal(cfg.StatePath(), journals[index]); err != nil {
			return result, err
		}
		if len(journals[index].Trust) != 0 {
			if removalPool == nil {
				removalPool, err = repository.OpenStore(cfg.Root)
				if err != nil {
					return result, fmt.Errorf("open CAS for compatibility trust removal: %w", err)
				}
				defer removalPool.Close()
			}
			if _, err := removeLocalServingCompatibilityTrust(ctx, removalPool, targetRoot, journals[index], nil); err != nil {
				return result, err
			}
			journals[index].Phase = localServingRemovalTrustRemoved
			if err := updateLocalServingRemovalJournal(cfg.StatePath(), journals[index]); err != nil {
				return result, err
			}
		}
		if err := removeLocalServingRemovalJournal(cfg.StatePath(), journals[index].ID); err != nil {
			return result, err
		}
	}
	activationJournals, err := listLocalServingJournals(cfg.StatePath())
	if err != nil {
		return result, err
	}
	expired, err := pruneCanonicalServingGenerationLedgers(ctx, canonical, activationJournals)
	result.LedgersExpired = len(expired)
	if err != nil {
		return result, err
	}
	if exactTarget {
		err = pruneExactLocalServingTargetRegistries(ctx, canonical, targetRelative)
	}
	return result, err
}

// pruneExactLocalServingTargetRegistries removes target identities made
// unreachable by an explicit target rewrite. Unlike GC for a manually missing
// root, this path has a positive authority witness: ReconcileExact already
// replaced the existing physical target and topology reconciliation removed
// every channel outside the desired exact set. Keeping an orphan registry here
// would make verify report canonical topology drift for a tree SOW itself
// intentionally replaced.
func pruneExactLocalServingTargetRegistries(ctx context.Context, canonical *state.Store, targetRoot string) error {
	lifecycle, err := loadCanonicalServingLifecycle(canonical)
	if err != nil {
		return err
	}
	claimed := make(map[string]struct{}, len(lifecycle.Channels))
	for _, record := range lifecycle.Channels {
		claimed[record.Channel.TargetID] = struct{}{}
	}
	var deletePaths []string
	for targetID, target := range lifecycle.Targets {
		if target.Root != targetRoot {
			continue
		}
		if _, exists := claimed[targetID]; exists {
			continue
		}
		deletePaths = append(deletePaths, serving.TargetStatePath(target))
	}
	if len(deletePaths) == 0 {
		return nil
	}
	sort.Strings(deletePaths)
	if _, changed, err := applyCanonicalState(ctx, canonical, "materialize-serving-target-exact", "sow: prune replaced local YUM serving targets", nil, nil, state.ApplyOptions{DeletePaths: deletePaths}); err != nil {
		return err
	} else if !changed {
		return errors.New("exact serving topology selected target registries but canonical transaction did not change")
	}
	return nil
}

func localServingTargetRelative(cfg *config.Config, targetRoot string) (string, error) {
	targetAbs, err := filepath.Abs(targetRoot)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(cfg.Root, targetAbs)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("local serving target escapes repository root")
	}
	if relative == "" || relative == "." {
		return ".", nil
	}
	return filepath.ToSlash(relative), nil
}

func prepareLocalServingTopologyRemovals(ctx context.Context, cfg *config.Config, canonical *state.Store, recover bool) error {
	if recover {
		if err := cleanupLocalServingRemovalTemps(cfg.StatePath()); err != nil {
			return err
		}
	}
	journals, err := listLocalServingRemovalJournals(cfg.StatePath())
	if err != nil {
		return err
	}
	if len(journals) != 0 && !recover {
		return errors.New("incomplete local serving topology removal exists; retry materialize or publish with --recover")
	}
	var removalPool *repository.Store
	for _, journal := range journals {
		channelPath := serving.ChannelStatePath(journal.Channel)
		body, exists, err := readOptionalCanonical(canonical, channelPath)
		if err != nil {
			return err
		}
		if exists {
			wanted, err := journal.Channel.Canonical()
			if err != nil || !bytes.Equal(body, wanted) {
				return errors.Join(err, errors.New("canonical topology-removal parent channel changed"))
			}
			if _, changed, err := applyCanonicalState(ctx, canonical, "recover-serving-topology", "sow: recover obsolete local YUM serving channel removal", nil, nil, state.ApplyOptions{DeletePaths: []string{channelPath}}); err != nil {
				return err
			} else if !changed {
				return errors.New("topology recovery selected a channel but canonical transaction did not change")
			}
		}
		journal.Phase = localServingRemovalStateCommitted
		if err := updateLocalServingRemovalJournal(cfg.StatePath(), journal); err != nil {
			return err
		}
		targetRoot := cfg.Root
		if journal.TargetRoot != "." {
			targetRoot = filepath.Join(cfg.Root, filepath.FromSlash(journal.TargetRoot))
		}
		if _, err := serving.RemoveMirrorlist(targetRoot, journal.Channel); err != nil {
			return err
		}
		journal.Phase = localServingRemovalPointerRemoved
		if err := updateLocalServingRemovalJournal(cfg.StatePath(), journal); err != nil {
			return err
		}
		if len(journal.Trust) != 0 {
			if removalPool == nil {
				removalPool, err = repository.OpenStore(cfg.Root)
				if err != nil {
					return fmt.Errorf("open CAS for compatibility trust removal recovery: %w", err)
				}
				defer removalPool.Close()
			}
			if _, err := removeLocalServingCompatibilityTrust(ctx, removalPool, targetRoot, journal, nil); err != nil {
				return err
			}
			journal.Phase = localServingRemovalTrustRemoved
			if err := updateLocalServingRemovalJournal(cfg.StatePath(), journal); err != nil {
				return err
			}
		}
		if err := removeLocalServingRemovalJournal(cfg.StatePath(), journal.ID); err != nil {
			return err
		}
	}
	return nil
}

func cleanupLocalServingRemovalTemps(stateRoot string) error {
	directory, exists, err := localServingRemovalDirectory(stateRoot, false)
	if err != nil || !exists {
		return err
	}
	if err := recoverDerivedStateReplacementTransactions(stateRoot, "serving-removal-journal", true); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !isLocalServingRemovalTemporaryName(entry.Name()) {
			continue
		}
		exact, err := removeExactProjectionResidueBounded(directory, entry.Name(), localServingRemovalLimit)
		if err != nil {
			return errors.Join(err, fmt.Errorf("unsafe local serving removal temporary entry %q", entry.Name()))
		}
		removed = removed || exact
	}
	if removed {
		return syncLocalDirectory(directory)
	}
	return nil
}

func isLocalServingRemovalTemporaryName(name string) bool {
	const canonicalBytes = 32 + len(".json")
	return len(name) > canonicalBytes && localServingRemovalNamePattern.MatchString(name[:canonicalBytes]) &&
		isDerivedStateTemporaryName(name, name[:canonicalBytes])
}

func requireNoLocalServingTopologyRemovals(stateRoot string) error {
	journals, err := listLocalServingRemovalJournals(stateRoot)
	if err != nil {
		return err
	}
	if len(journals) != 0 {
		return errors.New("incomplete local serving topology removal requires materialize or publish --recover")
	}
	return nil
}

func localServingTrustQuarantine(relative, sha string) string {
	return path.Join(path.Dir(relative), "."+path.Base(relative)+".remove-"+sha[:16])
}

func localServingCompatibilityRemovalTrust(cfg *config.Config, canonical *state.Store, channel serving.Channel) ([]localServingRemovalTrust, error) {
	projection, exists, err := config.YUMCompatibilityProjectionByID(cfg.CompatibilityProjections, channel.Repo)
	if err != nil || !exists {
		return nil, err
	}
	if channel.View != "latest" || channel.OS != "cross-el" || channel.Arch != projection.Source.Arch {
		return nil, fmt.Errorf("compatibility channel %s has non-canonical serving coordinates", channel.Repo)
	}
	evidence, err := loadFrozenYUMCompatibilityServingEvidence(cfg, canonical, projection)
	if err != nil {
		return nil, fmt.Errorf("load frozen compatibility trust removal evidence %s: %w", projection.ID, err)
	}
	entries := []localServingRemovalTrust{
		{Path: config.YUMCompatibilityPackageTrustRoute(projection.ID), SHA256: digestBytesCLI(evidence.packageTrust), Size: int64(len(evidence.packageTrust))},
		{Path: config.YUMCompatibilityRepositoryTrustRoute(projection.ID), SHA256: digestBytesCLI(evidence.repositoryTrust), Size: int64(len(evidence.repositoryTrust))},
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for index := range entries {
		entries[index].Quarantine = localServingTrustQuarantine(entries[index].Path, entries[index].SHA256)
	}
	return entries, nil
}

// removeLocalServingCompatibilityTrust removes only the two journal-bound
// public trust hardlinks. Each route is first atomically renamed to its
// deterministic quarantine name, then compared with one already-verified CAS
// descriptor before unlink. A crash at any point is replayable from the same
// journal; raw compatibility bytes, immutable generations and CAS objects are
// outside this closed deletion set. afterRemove is test-only.
func removeLocalServingCompatibilityTrust(ctx context.Context, pool *repository.Store, targetRoot string, journal localServingRemovalJournal, afterRemove func(int) error) (int, error) {
	return removeLocalServingCompatibilityTrustWithHooks(ctx, pool, targetRoot, journal, nil, afterRemove)
}

func removeLocalServingCompatibilityTrustWithHooks(ctx context.Context, pool *repository.Store, targetRoot string, journal localServingRemovalJournal, afterBind func() error, afterRemove func(int) error) (int, error) {
	if len(journal.Trust) == 0 {
		return 0, nil
	}
	if err := journal.validate(); err != nil {
		return 0, err
	}
	realTarget, err := filepath.EvalSymlinks(targetRoot)
	if err != nil {
		return 0, err
	}
	rootInfo, err := os.Lstat(realTarget)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return 0, errors.Join(err, errors.New("compatibility trust removal target is not a real directory"))
	}
	root, err := os.OpenRoot(realTarget)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	boundRootInfo, err := boundLocalServingRemovalDirectoryInfo(root)
	if err != nil || !os.SameFile(rootInfo, boundRootInfo) {
		return 0, errors.Join(err, fmt.Errorf("%w: compatibility trust removal root changed while binding", repository.ErrUnsafePath))
	}
	parentRelative := filepath.Dir(filepath.FromSlash(journal.Trust[0].Path))
	for _, trust := range journal.Trust {
		if filepath.Dir(filepath.FromSlash(trust.Path)) != parentRelative || filepath.Dir(filepath.FromSlash(trust.Quarantine)) != parentRelative {
			return 0, errors.New("compatibility trust removal closure spans multiple parents")
		}
	}
	// Trust deletion is destructive. Reject every initially symlinked parent
	// component and retain the exact real parent capability instead of allowing
	// os.Root.OpenRoot to follow an in-tree symlink.
	parent, parentInfo, err := openRealYUMCompatibilityDirectory(root, parentRelative, false)
	if err != nil {
		return 0, errors.Join(err, fmt.Errorf("%w: compatibility trust removal parent is not a real directory", repository.ErrUnsafePath))
	}
	defer parent.Close()
	type preparedTrust struct {
		evidence localServingRemovalTrust
		file     *os.File
		info     os.FileInfo
	}
	prepared := make([]preparedTrust, 0, len(journal.Trust))
	defer func() {
		for _, item := range prepared {
			_ = item.file.Close()
		}
	}()
	for _, trust := range journal.Trust {
		digest, err := repository.ParseDigest(trust.SHA256)
		if err != nil {
			return 0, err
		}
		casFile, err := pool.OpenVerified(ctx, repository.Object{SHA256: digest, Size: trust.Size})
		if err != nil {
			return 0, fmt.Errorf("verify compatibility trust removal CAS %s: %w", trust.Path, err)
		}
		casInfo, err := casFile.Stat()
		if err != nil {
			_ = casFile.Close()
			return 0, err
		}
		prepared = append(prepared, preparedTrust{evidence: trust, file: casFile, info: casInfo})
	}
	if afterBind != nil {
		if err := afterBind(); err != nil {
			return 0, err
		}
	}
	removed := 0
	for index, item := range prepared {
		trust := item.evidence
		relative := filepath.Base(filepath.FromSlash(trust.Path))
		quarantine := filepath.Base(filepath.FromSlash(trust.Quarantine))
		routeInfo, routeErr := parent.Lstat(relative)
		quarantineInfo, quarantineErr := parent.Lstat(quarantine)
		routeExists := routeErr == nil
		quarantineExists := quarantineErr == nil
		if routeErr != nil && !errors.Is(routeErr, os.ErrNotExist) {
			return removed, routeErr
		}
		if quarantineErr != nil && !errors.Is(quarantineErr, os.ErrNotExist) {
			return removed, quarantineErr
		}
		if routeExists && quarantineExists {
			return removed, fmt.Errorf("compatibility trust route and quarantine both exist for %s", trust.Path)
		}
		if routeExists {
			if routeInfo.Mode()&os.ModeSymlink != 0 || !routeInfo.Mode().IsRegular() || routeInfo.Size() != trust.Size {
				return removed, fmt.Errorf("compatibility trust route %s differs from exact removal evidence", trust.Path)
			}
			if err := parent.Rename(relative, quarantine); err != nil {
				return removed, err
			}
			if err := syncBoundLocalServingRemovalDirectory(parent); err != nil {
				return removed, err
			}
			quarantineInfo, quarantineErr = parent.Lstat(quarantine)
			quarantineExists = quarantineErr == nil
		}
		if !quarantineExists {
			continue
		}
		if quarantineErr != nil || quarantineInfo.Mode()&os.ModeSymlink != 0 || !quarantineInfo.Mode().IsRegular() || quarantineInfo.Size() != trust.Size {
			return removed, errors.Join(quarantineErr, fmt.Errorf("compatibility trust quarantine %s is unsafe", trust.Quarantine))
		}
		quarantineFile, err := parent.Open(quarantine)
		if err != nil {
			return removed, err
		}
		opened, openErr := quarantineFile.Stat()
		closeErr := quarantineFile.Close()
		if openErr != nil || closeErr != nil || !os.SameFile(quarantineInfo, opened) || !os.SameFile(opened, item.info) {
			var restoreErr error
			if _, statErr := parent.Lstat(relative); errors.Is(statErr, os.ErrNotExist) {
				if renameErr := parent.Rename(quarantine, relative); renameErr != nil {
					restoreErr = fmt.Errorf("restore rejected compatibility trust route %s: %w", trust.Path, renameErr)
				} else if syncErr := syncBoundLocalServingRemovalDirectory(parent); syncErr != nil {
					restoreErr = fmt.Errorf("sync restored compatibility trust route %s: %w", trust.Path, syncErr)
				}
			} else if statErr != nil {
				restoreErr = fmt.Errorf("inspect rejected compatibility trust route %s before restore: %w", trust.Path, statErr)
			} else {
				restoreErr = fmt.Errorf("refusing to overwrite replacement compatibility trust route %s during restore", trust.Path)
			}
			return removed, errors.Join(openErr, closeErr, restoreErr, fmt.Errorf("compatibility trust route %s is not the exact verified CAS hardlink", trust.Path))
		}
		if err := parent.Remove(quarantine); err != nil {
			return removed, err
		}
		if err := syncBoundLocalServingRemovalDirectory(parent); err != nil {
			return removed, err
		}
		removed++
		if afterRemove != nil {
			if err := afterRemove(index); err != nil {
				return removed, err
			}
		}
	}
	currentRoot, rootErr := os.Lstat(realTarget)
	currentParent, parentErr := root.OpenRoot(parentRelative)
	var currentParentInfo os.FileInfo
	if parentErr == nil {
		currentParentInfo, parentErr = boundLocalServingRemovalDirectoryInfo(currentParent)
		parentErr = errors.Join(parentErr, currentParent.Close())
	}
	if rootErr != nil || currentRoot.Mode()&os.ModeSymlink != 0 || !currentRoot.IsDir() || !os.SameFile(rootInfo, currentRoot) || parentErr != nil || !os.SameFile(parentInfo, currentParentInfo) {
		return removed, errors.Join(rootErr, parentErr, fmt.Errorf("%w: compatibility trust removal root or exact parent was replaced", repository.ErrUnsafePath))
	}
	return removed, nil
}

func boundLocalServingRemovalDirectoryInfo(root *os.Root) (os.FileInfo, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	info, statErr := directory.Stat()
	closeErr := directory.Close()
	if statErr != nil || closeErr != nil || info == nil || !info.IsDir() {
		return nil, errors.Join(statErr, closeErr, errors.New("bound local serving removal directory is unavailable"))
	}
	return info, nil
}

func syncBoundLocalServingRemovalDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func localServingRemovalJournalID(journal localServingRemovalJournal) string {
	identity := "remove\x00" + journal.Channel.TargetID + "\x00" + journal.TargetRoot + "\x00" + journal.Channel.MirrorlistPath
	for _, trust := range journal.Trust {
		identity += "\x00" + trust.Path + "\x00" + trust.SHA256 + "\x00" + fmt.Sprintf("%d", trust.Size) + "\x00" + trust.Quarantine
	}
	digest := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(digest[:16])
}

func (journal localServingRemovalJournal) validate() error {
	if journal.Schema != localServingRemovalSchema || journal.ID != localServingRemovalJournalID(journal) || len(journal.ID) != 32 {
		return errors.New("invalid local serving removal journal envelope")
	}
	if journal.Phase != localServingRemovalIntent && journal.Phase != localServingRemovalStateCommitted && journal.Phase != localServingRemovalPointerRemoved && journal.Phase != localServingRemovalTrustRemoved {
		return errors.New("invalid local serving removal journal phase")
	}
	if journal.TargetRoot == "" || filepath.IsAbs(journal.TargetRoot) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(journal.TargetRoot))) != journal.TargetRoot || strings.HasPrefix(journal.TargetRoot, "../") || strings.ContainsAny(journal.TargetRoot, "\\\x00\t\r\n") {
		return errors.New("invalid local serving removal target")
	}
	if err := journal.Channel.Validate(); err != nil {
		return err
	}
	if journal.Channel.TargetRoot != journal.TargetRoot || journal.Channel.TargetID == "" {
		return errors.New("local serving removal target differs from channel")
	}
	if len(journal.Trust) != 0 {
		if len(journal.Trust) != 2 || journal.Channel.View != "latest" || journal.Channel.OS != "cross-el" {
			return errors.New("invalid compatibility trust removal closure")
		}
		want := []string{
			config.YUMCompatibilityPackageTrustRoute(journal.Channel.Repo),
			config.YUMCompatibilityRepositoryTrustRoute(journal.Channel.Repo),
		}
		sort.Strings(want)
		for index, trust := range journal.Trust {
			digest, err := repository.ParseDigest(trust.SHA256)
			if err != nil || digest.String() != trust.SHA256 || trust.Size <= 0 || trust.Path != want[index] || trust.Quarantine != localServingTrustQuarantine(trust.Path, trust.SHA256) {
				return errors.Join(err, errors.New("invalid exact compatibility trust removal evidence"))
			}
		}
	}
	return nil
}

func localServingRemovalDirectory(stateRoot string, create bool) (string, bool, error) {
	stateAbs, err := filepath.Abs(stateRoot)
	if err != nil {
		return "", false, err
	}
	info, err := os.Lstat(stateAbs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", false, errors.Join(err, errors.New("state root is not a real directory"))
	}
	root, err := os.OpenRoot(stateAbs)
	if err != nil {
		return "", false, err
	}
	defer root.Close()
	const relative = "serving-removal-journal"
	info, err = root.Lstat(relative)
	if errors.Is(err, os.ErrNotExist) && !create {
		return filepath.Join(stateAbs, relative), false, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(relative, 0o700); err != nil {
			return "", false, err
		}
		info, err = root.Lstat(relative)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", false, errors.Join(err, errors.New("serving removal journal directory is unsafe"))
	}
	return filepath.Join(stateAbs, relative), true, nil
}

func createLocalServingRemovalJournal(stateRoot string, journal localServingRemovalJournal) error {
	directory, _, err := localServingRemovalDirectory(stateRoot, true)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(directory, journal.ID+".json")); err == nil {
		return errors.New("incomplete local serving topology removal already exists; retry with --recover")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return updateLocalServingRemovalJournal(stateRoot, journal)
}

func updateLocalServingRemovalJournal(stateRoot string, journal localServingRemovalJournal) error {
	if err := journal.validate(); err != nil {
		return err
	}
	body, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	result, err := writeDerivedStateFileOutcome(stateRoot, filepath.Join("serving-removal-journal", journal.ID+".json"), body)
	return consumeDerivedStateReplacement(result, err)
}

func listLocalServingRemovalJournals(stateRoot string) ([]localServingRemovalJournal, error) {
	directory, exists, err := localServingRemovalDirectory(stateRoot, false)
	if err != nil || !exists {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var result []localServingRemovalJournal
	for _, entry := range entries {
		if !localServingRemovalNamePattern.MatchString(entry.Name()) {
			return nil, fmt.Errorf("unsafe local serving removal journal entry %q", entry.Name())
		}
		body, err := readBoundedExactRegularFile(directory, entry.Name(), localServingRemovalLimit)
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var journal localServingRemovalJournal
		if err := decoder.Decode(&journal); err != nil {
			return nil, err
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, errors.New("local serving removal journal has trailing JSON")
		}
		if err := journal.validate(); err != nil || entry.Name() != journal.ID+".json" {
			return nil, errors.Join(err, errors.New("invalid local serving removal journal filename"))
		}
		result = append(result, journal)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func removeLocalServingRemovalJournal(stateRoot, id string) error {
	if !localServingRemovalNamePattern.MatchString(id + ".json") {
		return errors.New("invalid local serving removal journal ID")
	}
	directory, exists, err := localServingRemovalDirectory(stateRoot, false)
	if err != nil || !exists {
		return errors.Join(err, errors.New("local serving removal journal directory is missing"))
	}
	filename := filepath.Join(directory, id+".json")
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, errors.New("local serving removal journal is unsafe"))
	}
	if err := os.Remove(filename); err != nil {
		return err
	}
	return syncLocalDirectory(directory)
}
