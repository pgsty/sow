package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

type servingGenerationDirectoryGC struct {
	TargetRoot    string
	TombstonePath string
	ManifestPath  string
	Generation    serving.Generation
}

type servingGenerationTombstoneGC struct {
	Path         string
	ManifestPath string
	Generation   serving.Generation
}

type servingGenerationProtectedGC struct {
	TargetRoot   string
	ManifestPath string
	Generation   serving.Generation
}

type servingMissingTargetGC struct {
	Path         string
	Target       serving.TargetIdentity
	ChannelPaths []string
	RootMissing  bool
}

type servingGenerationGCPlan struct {
	Head        plumbing.Hash
	Installed   []string
	Protected   []servingGenerationProtectedGC
	Directories []servingGenerationDirectoryGC
	Tombstones  []servingGenerationTombstoneGC
	Targets     []servingMissingTargetGC
}

func (plan servingGenerationGCPlan) hasServingCandidates() bool {
	return len(plan.Directories) != 0 || len(plan.Tombstones) != 0 || len(plan.Targets) != 0
}

// collectServingGenerationGCPlan treats canonical retired-generation
// tombstones as the only authority for physical deletion. Every registered or
// in-flight target is enumerated, including targets that currently retain no
// channel, so an old copy cannot escape the confirmation set.
func collectServingGenerationGCPlan(cfg *config.Config, canonical *state.Store, pool *repository.Store) (servingGenerationGCPlan, error) {
	var plan servingGenerationGCPlan
	if cfg == nil || canonical == nil || pool == nil {
		return plan, errors.New("serving generation GC requires config, canonical state, and CAS")
	}
	head, err := canonical.HeadHash()
	if err != nil {
		return plan, err
	}
	plan.Head = head
	lifecycle, err := loadCanonicalServingLifecycle(canonical)
	if err != nil {
		return plan, err
	}
	activationJournals, err := listLocalServingJournals(cfg.StatePath())
	if err != nil {
		return plan, fmt.Errorf("inspect local serving activation journals: %w", err)
	}
	removalJournals, err := listLocalServingRemovalJournals(cfg.StatePath())
	if err != nil {
		return plan, fmt.Errorf("inspect local serving removal journals: %w", err)
	}

	channels := make([]serving.Channel, 0, len(lifecycle.Channels)+len(activationJournals)+len(removalJournals))
	targetRoots := make(map[string]struct{}, len(lifecycle.Targets)+len(activationJournals)+len(removalJournals))
	canonicalChannelsByTarget := make(map[string][]string)
	journalRoots := make(map[string]struct{}, len(activationJournals)+len(removalJournals))
	for _, target := range lifecycle.Targets {
		targetRoots[target.Root] = struct{}{}
	}
	for _, record := range lifecycle.Channels {
		channels = append(channels, record.Channel)
		canonicalChannelsByTarget[record.Channel.TargetID] = append(canonicalChannelsByTarget[record.Channel.TargetID], record.Path)
	}
	journalPins := make([]serving.GenerationCoordinate, 0, len(activationJournals))
	for _, journal := range activationJournals {
		channels = append(channels, journal.Channel)
		targetRoots[journal.TargetRoot] = struct{}{}
		journalRoots[journal.TargetRoot] = struct{}{}
		journalPins = append(journalPins, serving.GenerationCoordinate{
			ID: journal.Generation.ID, View: journal.Generation.View, Repo: journal.Generation.Repo,
			OS: journal.Generation.OS, Arch: journal.Generation.Arch,
		})
	}
	for _, journal := range removalJournals {
		channels = append(channels, journal.Channel)
		targetRoots[journal.TargetRoot] = struct{}{}
		journalRoots[journal.TargetRoot] = struct{}{}
	}
	keepPaths, err := serving.RetainedGenerationKeepSet(channels, journalPins)
	if err != nil {
		return plan, err
	}

	// Resolve every retained pin to a collision-resistant Generation record.
	// A desired activation may not yet be canonical, so its journal supplies
	// the record; all prior pins must still have canonical ledgers.
	evidenceByPath := make(map[string]serving.Generation, len(lifecycle.Generations)+len(activationJournals))
	activeByID := make(map[string]serving.Generation)
	for path, record := range lifecycle.Generations {
		evidenceByPath[path] = record.Generation
		if err := addGenerationByID(activeByID, record.Generation, "active ledgers"); err != nil {
			return plan, err
		}
	}
	for _, journal := range activationJournals {
		path := serving.GenerationManifestStatePath(journal.Generation)
		if existing, exists := evidenceByPath[path]; exists && existing != journal.Generation {
			return plan, fmt.Errorf("activation journal generation differs from canonical ledger %s", path)
		}
		evidenceByPath[path] = journal.Generation
	}
	for _, channel := range channels {
		if err := validateServingChannelPins(channel, evidenceByPath); err != nil {
			return plan, err
		}
	}
	protectedByID := make(map[string]serving.Generation, len(keepPaths))
	for path := range keepPaths {
		generation, exists := evidenceByPath[path]
		if !exists {
			return plan, fmt.Errorf("retained serving generation has no full canonical or journal identity: %s", path)
		}
		if err := addGenerationByID(protectedByID, generation, "retained channels and journals"); err != nil {
			return plan, err
		}
	}

	type retiredRecord struct {
		path       string
		generation serving.Generation
	}
	retiredByID := make(map[string]retiredRecord)
	for path, retired := range lifecycle.Retired {
		generation := retired.Retired.Generation
		if active, exists := activeByID[generation.ID]; exists {
			return plan, fmt.Errorf("projected serving generation ID collision between active %s and retired %s", serving.GenerationStatePath(active), path)
		}
		if protected, exists := protectedByID[generation.ID]; exists && protected != generation {
			return plan, fmt.Errorf("projected serving generation ID collision between retained and retired identities at %s", path)
		}
		if existing, exists := retiredByID[generation.ID]; exists && existing.generation != generation {
			return plan, errors.New("projected serving generation ID collision in retired tombstones")
		}
		retiredByID[generation.ID] = retiredRecord{path: path, generation: generation}
		if _, protected := protectedByID[generation.ID]; !protected {
			plan.Tombstones = append(plan.Tombstones, servingGenerationTombstoneGC{Path: path, ManifestPath: retired.ManifestPath, Generation: generation})
		}
	}
	if len(plan.Tombstones) != 0 && len(targetRoots) == 0 {
		return plan, errors.New("retired serving generations have no target registry for physical absence proof")
	}

	roots := make([]string, 0, len(targetRoots))
	targetsByRoot := make(map[string][]serving.TargetIdentity)
	for _, target := range lifecycle.Targets {
		targetsByRoot[target.Root] = append(targetsByRoot[target.Root], target)
	}
	for root := range targetRoots {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	for _, relative := range roots {
		targetRoot := cfg.Root
		if relative != "." {
			targetRoot = filepath.Join(cfg.Root, filepath.FromSlash(relative))
		}
		ids, targetExists, err := serving.ListInstalledGenerationIDsIfPresent(cfg.Root, targetRoot)
		if err != nil {
			return plan, fmt.Errorf("audit registered serving target %s: %w", relative, err)
		}
		if !targetExists {
			if _, inFlight := journalRoots[relative]; inFlight {
				return plan, fmt.Errorf("in-flight serving target %s is missing; recover the transaction before GC", relative)
			}
			registered := targetsByRoot[relative]
			if len(registered) == 0 {
				return plan, fmt.Errorf("unregistered in-flight serving target %s is missing", relative)
			}
			for _, target := range registered {
				paths := append([]string(nil), canonicalChannelsByTarget[target.ID]...)
				sort.Strings(paths)
				plan.Targets = append(plan.Targets, servingMissingTargetGC{Path: serving.TargetStatePath(target), Target: target, ChannelPaths: paths, RootMissing: true})
			}
			continue
		}
		for _, id := range ids {
			plan.Installed = append(plan.Installed, relative+"\x00"+id)
			if protected, exists := protectedByID[id]; exists {
				plan.Protected = append(plan.Protected, servingGenerationProtectedGC{
					TargetRoot: relative, ManifestPath: serving.GenerationManifestStatePath(protected), Generation: protected,
				})
				continue
			}
			if _, active := activeByID[id]; active {
				continue
			}
			retired, exists := retiredByID[id]
			if !exists {
				return plan, fmt.Errorf("installed generation %s below %s has no active or retired canonical identity", id, relative)
			}
			plan.Directories = append(plan.Directories, servingGenerationDirectoryGC{
				TargetRoot: relative, TombstonePath: retired.path,
				ManifestPath: serving.RetiredGenerationManifestStatePath(retired.generation), Generation: retired.generation,
			})
		}
		// A retained channel pin is a physical availability contract, not only a
		// canonical/CAS root. Record every expected copy even when its directory
		// is absent so validation below fails rather than silently skipping it.
		for _, channel := range channels {
			if channel.TargetRoot != relative {
				continue
			}
			coordinates, err := channel.RetainedGenerationCoordinates()
			if err != nil {
				return plan, err
			}
			for _, coordinate := range coordinates {
				generation := evidenceByPath[serving.GenerationManifestStatePathFor(coordinate.ID, coordinate.View, coordinate.Repo, coordinate.OS, coordinate.Arch)]
				candidate := servingGenerationProtectedGC{TargetRoot: relative, ManifestPath: serving.GenerationManifestStatePath(generation), Generation: generation}
				found := false
				for _, existing := range plan.Protected {
					if existing == candidate {
						found = true
						break
					}
				}
				if !found {
					plan.Protected = append(plan.Protected, candidate)
				}
			}
		}
		hasChannelWitness := false
		for _, target := range targetsByRoot[relative] {
			if len(canonicalChannelsByTarget[target.ID]) != 0 {
				hasChannelWitness = true
				break
			}
		}
		if len(ids) == 0 || hasChannelWitness {
			if _, inFlight := journalRoots[relative]; !inFlight {
				for _, target := range targetsByRoot[relative] {
					if len(canonicalChannelsByTarget[target.ID]) == 0 {
						plan.Targets = append(plan.Targets, servingMissingTargetGC{Path: serving.TargetStatePath(target), Target: target})
					}
				}
			}
		}
	}
	sort.Strings(plan.Installed)
	sort.Slice(plan.Protected, func(i, j int) bool {
		left := plan.Protected[i].TargetRoot + "\x00" + plan.Protected[i].Generation.ID + "\x00" + plan.Protected[i].ManifestPath
		right := plan.Protected[j].TargetRoot + "\x00" + plan.Protected[j].Generation.ID + "\x00" + plan.Protected[j].ManifestPath
		return left < right
	})
	sort.Slice(plan.Directories, func(i, j int) bool {
		left := plan.Directories[i].TargetRoot + "\x00" + plan.Directories[i].Generation.ID + "\x00" + plan.Directories[i].TombstonePath
		right := plan.Directories[j].TargetRoot + "\x00" + plan.Directories[j].Generation.ID + "\x00" + plan.Directories[j].TombstonePath
		return left < right
	})
	sort.Slice(plan.Tombstones, func(i, j int) bool { return plan.Tombstones[i].Path < plan.Tombstones[j].Path })
	sort.Slice(plan.Targets, func(i, j int) bool { return plan.Targets[i].Path < plan.Targets[j].Path })
	return plan, nil
}

func addGenerationByID(index map[string]serving.Generation, generation serving.Generation, source string) error {
	if existing, exists := index[generation.ID]; exists && existing != generation {
		return fmt.Errorf("projected serving generation ID collision in %s", source)
	}
	index[generation.ID] = generation
	return nil
}

func validateServingChannelPins(channel serving.Channel, evidence map[string]serving.Generation) error {
	coordinates, err := channel.RetainedGenerationCoordinates()
	if err != nil {
		return err
	}
	pins, err := channel.RetainedGenerationPins()
	if err != nil {
		return err
	}
	for index, coordinate := range coordinates {
		manifestPath, err := coordinate.ManifestPath()
		if err != nil {
			return err
		}
		generation, exists := evidence[manifestPath]
		if !exists {
			return fmt.Errorf("channel %s retains missing generation identity %s", channel.MirrorlistPath, manifestPath)
		}
		pin, err := serving.PinGeneration(generation)
		if err != nil || pin != pins[index] {
			return errors.Join(err, fmt.Errorf("channel %s retained pin differs from generation %s", channel.MirrorlistPath, manifestPath))
		}
	}
	currentPath := serving.GenerationManifestStatePathFor(channel.Generation, channel.View, channel.Repo, channel.OS, channel.Arch)
	current := evidence[currentPath]
	if current.LegacyRoot != channel.LegacyRoot || current.RefCommit != channel.RefCommit || current.ConfigSHA256 != channel.ConfigSHA256 || current.RepositoryKeySHA256 != channel.RepositoryKeySHA256 {
		return fmt.Errorf("channel %s current identity differs from generation ledger", channel.MirrorlistPath)
	}
	return nil
}

// combinedGCPlanSHA256 preserves the original CAS-only confirmation contract
// when there is no serving cleanup. Once serving candidates exist, a
// domain-separated digest binds the canonical parent, exact CAS orphan set,
// every target directory, and every tombstone (including tombstone-only crash
// recovery candidates).
func combinedGCPlanSHA256(report repository.AuditReport, servingPlan servingGenerationGCPlan) string {
	if !servingPlan.hasServingCandidates() {
		return report.OrphanSetSHA256
	}
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, "sow-gc-plan/v3\n")
	fmt.Fprintf(hasher, "head\t%s\n", servingPlan.Head)
	for _, object := range report.Orphans {
		fmt.Fprintf(hasher, "cas\t%s\t%d\n", object.HashString(), object.Size)
	}
	for _, protected := range servingPlan.Protected {
		fmt.Fprintf(hasher, "protected-generation\t%s\t%s\t%s\n", protected.TargetRoot, protected.ManifestPath, generationIdentitySHA256(protected.Generation))
	}
	for _, directory := range servingPlan.Directories {
		fmt.Fprintf(hasher, "generation\t%s\t%s\t%s\t%s\n", directory.TargetRoot, directory.TombstonePath, directory.ManifestPath, generationIdentitySHA256(directory.Generation))
	}
	for _, tombstone := range servingPlan.Tombstones {
		fmt.Fprintf(hasher, "tombstone\t%s\t%s\t%s\n", tombstone.Path, tombstone.ManifestPath, generationIdentitySHA256(tombstone.Generation))
	}
	for _, target := range servingPlan.Targets {
		fmt.Fprintf(hasher, "retired-target\t%s\t%s\t%s\t%s\t%t\n", target.Path, target.Target.ID, target.Target.Root, target.Target.BaseURL, target.RootMissing)
		for _, channelPath := range target.ChannelPaths {
			fmt.Fprintf(hasher, "retired-target-channel\t%s\t%s\n", target.Target.ID, channelPath)
		}
	}
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func generationIdentitySHA256(generation serving.Generation) string {
	body, err := generation.Canonical()
	if err != nil {
		return "invalid"
	}
	digest := sha256.Sum256(body)
	return fmt.Sprintf("%x", digest[:])
}

func sameServingGenerationGCPlan(left, right servingGenerationGCPlan) bool {
	return left.Head == right.Head && reflect.DeepEqual(left.Installed, right.Installed) &&
		reflect.DeepEqual(left.Protected, right.Protected) && reflect.DeepEqual(left.Directories, right.Directories) && reflect.DeepEqual(left.Tombstones, right.Tombstones) && reflect.DeepEqual(left.Targets, right.Targets)
}

func requireServingGenerationGCPlan(cfg *config.Config, canonical *state.Store, pool *repository.Store, expected servingGenerationGCPlan) error {
	current, err := collectServingGenerationGCPlan(cfg, canonical, pool)
	if err != nil {
		return err
	}
	if !sameServingGenerationGCPlan(current, expected) {
		return fmt.Errorf("%w: serving generation set or canonical parent changed", repository.ErrGCProtection)
	}
	return nil
}

func validateServingGenerationGCPlan(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, plan servingGenerationGCPlan, values commonFlags, tempDir string) error {
	for index, candidate := range plan.Protected {
		manifestPath := filepath.Join(tempDir, fmt.Sprintf("protected-%06d.tsv", index))
		if err := stageCanonicalGCManifest(canonical, candidate.ManifestPath, manifestPath); err != nil {
			return fmt.Errorf("stage retained serving generation %s: %w", candidate.Generation.ID, err)
		}
		targetRoot := servingGCTargetRoot(cfg, candidate.TargetRoot)
		if err := serving.ValidateInstalledGeneration(ctx, pool, targetRoot, candidate.Generation, manifestPath, serving.InstallOptions{
			Workers: values.workers, ChunkEntries: values.chunk, TempDir: tempDir,
		}); err != nil {
			return fmt.Errorf("validate retained serving generation %s below %s: %w", candidate.Generation.ID, candidate.TargetRoot, err)
		}
	}
	for index, candidate := range plan.Directories {
		manifestPath := filepath.Join(tempDir, fmt.Sprintf("retired-%06d.tsv", index))
		if err := stageCanonicalGCManifest(canonical, candidate.ManifestPath, manifestPath); err != nil {
			return fmt.Errorf("stage retired serving generation %s: %w", candidate.Generation.ID, err)
		}
		targetRoot := servingGCTargetRoot(cfg, candidate.TargetRoot)
		if err := serving.ValidateRetiredGenerationRemainder(ctx, pool, targetRoot, candidate.Generation, manifestPath, serving.InstallOptions{
			Workers: values.workers, ChunkEntries: values.chunk, TempDir: tempDir,
		}); err != nil {
			return fmt.Errorf("validate retired serving generation %s below %s: %w", candidate.Generation.ID, candidate.TargetRoot, err)
		}
	}
	return nil
}

func stageCanonicalGCManifest(canonical *state.Store, canonicalPath, destination string) error {
	source, err := canonical.OpenPath(canonicalPath)
	if err != nil {
		return err
	}
	copyErr := manifest.AtomicCopy(destination, source, 0o600)
	return errors.Join(copyErr, source.Close())
}

// applyServingGenerationDirectories removes one confirmed directory at a time
// and re-collects the full installed/candidate set before and after each
// removal. Tombstones remain canonical until CAS GC also succeeds.
func applyServingGenerationDirectories(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, plan servingGenerationGCPlan, values commonFlags, tempDir string) (int, servingGenerationGCPlan, error) {
	remaining := plan
	if err := requireServingGenerationGCPlan(cfg, canonical, pool, remaining); err != nil {
		return 0, remaining, err
	}
	removed := 0
	for len(remaining.Directories) != 0 {
		candidate := remaining.Directories[0]
		expectedManifest := filepath.Join(tempDir, "remove-"+candidate.Generation.ID+".tsv")
		if err := stageCanonicalGCManifest(canonical, candidate.ManifestPath, expectedManifest); err != nil {
			return removed, remaining, fmt.Errorf("stage retired serving generation %s: %w", candidate.Generation.ID, err)
		}
		if err := serving.RemoveRetiredGeneration(ctx, pool, servingGCTargetRoot(cfg, candidate.TargetRoot), candidate.Generation, serving.RemoveGenerationOptions{
			InstallOptions:       serving.InstallOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: tempDir},
			ExpectedManifestPath: expectedManifest,
			BeforeRemove: func() error {
				return requireServingGenerationGCPlan(cfg, canonical, pool, remaining)
			},
		}); err != nil {
			return removed, remaining, fmt.Errorf("remove retired serving generation %s below %s: %w", candidate.Generation.ID, candidate.TargetRoot, err)
		}
		remaining.Directories = append([]servingGenerationDirectoryGC(nil), remaining.Directories[1:]...)
		coordinate := candidate.TargetRoot + "\x00" + candidate.Generation.ID
		remaining.Installed = removeSortedServingCoordinate(remaining.Installed, coordinate)
		removed++
		if err := requireServingGenerationGCPlan(cfg, canonical, pool, remaining); err != nil {
			return removed, remaining, err
		}
	}
	return removed, remaining, nil
}

func removeSortedServingCoordinate(values []string, coordinate string) []string {
	index := sort.SearchStrings(values, coordinate)
	if index >= len(values) || values[index] != coordinate {
		return append([]string(nil), values...)
	}
	result := append([]string(nil), values[:index]...)
	return append(result, values[index+1:]...)
}

func removeServingGenerationTombstones(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, plan servingGenerationGCPlan) (int, error) {
	if len(plan.Directories) != 0 {
		return 0, errors.New("cannot remove serving tombstones while physical generation candidates remain")
	}
	if len(plan.Tombstones) == 0 {
		return 0, requireServingGenerationGCPlan(cfg, canonical, pool, plan)
	}
	if err := requireServingGenerationGCPlan(cfg, canonical, pool, plan); err != nil {
		return 0, err
	}
	stageDir, err := os.MkdirTemp(cfg.StatePath(), "serving-tombstone-gc-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(stageDir)
	deletePaths := make([]string, 0, len(plan.Tombstones)*2)
	restore := make(map[string]string, len(plan.Tombstones)*2)
	for index, tombstone := range plan.Tombstones {
		deletePaths = append(deletePaths, tombstone.Path, tombstone.ManifestPath)
		for offset, canonicalPath := range []string{tombstone.Path, tombstone.ManifestPath} {
			stage := filepath.Join(stageDir, fmt.Sprintf("restore-%06d-%d", index, offset))
			if err := stageCanonicalGCManifest(canonical, canonicalPath, stage); err != nil {
				return 0, err
			}
			restore[canonicalPath] = stage
		}
	}
	if _, changed, err := applyCanonicalState(ctx, canonical, "serving-directory-gc", "sow: remove validated retired YUM generation tombstones", nil, nil, state.ApplyOptions{DeletePaths: deletePaths}); err != nil {
		return 0, err
	} else if !changed {
		return 0, errors.New("serving GC selected tombstones but canonical transaction did not change")
	}
	after, err := collectServingGenerationGCPlan(cfg, canonical, pool)
	if err != nil || len(after.Directories) != 0 || len(after.Tombstones) != 0 {
		if err == nil {
			err = errors.New("serving generation cleanup candidates remain after tombstone commit")
		}
		_, _, restoreErr := applyCanonicalState(ctx, canonical, "serving-directory-gc-recovery", "sow: restore retired YUM deletion witness after post-commit drift", restore, nil, state.ApplyOptions{})
		return 0, errors.Join(err, restoreErr)
	}
	return len(plan.Tombstones), nil
}

// applyMissingServingTargets gives manually removed derived exports a bounded
// canonical convergence path. A confirmed target with channels first drops
// those unavailable channels and retires their now-unpinned ledgers, but keeps
// the registry for one more GC pass so the new tombstones retain an explicit
// physical-absence witness. A confirmed target with no channels can be
// removed after its already-confirmed tombstones were processed.
func applyMissingServingTargets(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, expected []servingMissingTargetGC) (int, int, int, error) {
	if len(expected) == 0 {
		return 0, 0, 0, nil
	}
	fresh, err := collectServingGenerationGCPlan(cfg, canonical, pool)
	if err != nil {
		return 0, 0, 0, err
	}
	freshByPath := make(map[string]servingMissingTargetGC, len(fresh.Targets))
	for _, target := range fresh.Targets {
		freshByPath[target.Path] = target
	}
	channelPaths := make([]string, 0, len(expected))
	targetPaths := make([]string, 0, len(expected))
	channels := 0
	for _, candidate := range expected {
		observed, exists := freshByPath[candidate.Path]
		if !exists || !reflect.DeepEqual(observed, candidate) {
			return 0, 0, 0, fmt.Errorf("%w: retired serving target set changed", repository.ErrGCProtection)
		}
		if len(candidate.ChannelPaths) != 0 {
			channelPaths = append(channelPaths, candidate.ChannelPaths...)
			channels += len(candidate.ChannelPaths)
			continue
		}
		targetPaths = append(targetPaths, candidate.Path)
	}
	sort.Strings(channelPaths)
	sort.Strings(targetPaths)
	journals, err := listLocalServingJournals(cfg.StatePath())
	if err != nil {
		return 0, 0, 0, err
	}
	retired := 0
	if channels != 0 {
		expired, err := pruneCanonicalServingGenerationLedgersWithChannelDeletes(ctx, canonical, journals, channelPaths)
		if err != nil {
			return channels, 0, retired, err
		}
		retired = len(expired)
	}
	// Clean up any active ledger stranded by an older interrupted build before
	// removing its final target absence witness. Newly created tombstones are
	// outside the confirmed plan, so target deletion is deferred to a fresh GC.
	expired, err := pruneCanonicalServingGenerationLedgers(ctx, canonical, journals)
	if err != nil {
		return channels, 0, retired, err
	}
	retired += len(expired)
	if retired != 0 || len(targetPaths) == 0 {
		return channels, 0, retired, nil
	}
	stageDir, err := os.MkdirTemp(cfg.StatePath(), "serving-target-gc-")
	if err != nil {
		return channels, 0, retired, err
	}
	defer os.RemoveAll(stageDir)
	restore := make(map[string]string, len(targetPaths))
	missingByPath := make(map[string]servingMissingTargetGC, len(expected))
	for _, candidate := range expected {
		missingByPath[candidate.Path] = candidate
	}
	for index, canonicalPath := range targetPaths {
		stage := filepath.Join(stageDir, fmt.Sprintf("target-%06d.json", index))
		if err := stageCanonicalGCManifest(canonical, canonicalPath, stage); err != nil {
			return channels, 0, retired, err
		}
		restore[canonicalPath] = stage
	}
	if _, changed, err := applyCanonicalState(ctx, canonical, "serving-target-gc", "sow: retire unavailable local YUM serving targets", nil, nil, state.ApplyOptions{DeletePaths: targetPaths}); err != nil {
		return channels, 0, retired, err
	} else if !changed {
		return channels, 0, retired, errors.New("serving target GC selected canonical paths but transaction did not change")
	}
	for _, canonicalPath := range targetPaths {
		candidate := missingByPath[canonicalPath]
		if !candidate.RootMissing {
			continue
		}
		targetRoot := servingGCTargetRoot(cfg, candidate.Target.Root)
		_, exists, inspectErr := serving.ListInstalledGenerationIDsIfPresent(cfg.Root, targetRoot)
		if inspectErr != nil || exists {
			_, _, restoreErr := applyCanonicalState(ctx, canonical, "serving-target-gc-recovery", "sow: restore serving target registry after post-commit drift", restore, nil, state.ApplyOptions{})
			return channels, 0, retired, errors.Join(inspectErr, restoreErr, errors.New("missing serving target reappeared after registry commit"))
		}
	}
	return channels, len(targetPaths), retired, nil
}

func servingGCTargetRoot(cfg *config.Config, relative string) string {
	if relative == "." {
		return cfg.Root
	}
	return filepath.Join(cfg.Root, filepath.FromSlash(relative))
}
