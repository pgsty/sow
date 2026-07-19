package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

type viewLeaf struct {
	repo config.Repo
	os   string
	arch string
}

type pendingRef struct {
	name      plumbing.ReferenceName
	expected  plumbing.Hash
	immutable bool
}

func runPromote(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("promote", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	addCommonFlags(fs, &values)
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow promote <source-view> <destination-view> [--config sow.yaml] [--repo NAME] [--os OS] [--arch ARCH] [--recover]")
	}
	var positional []string
	flagArgs := args
	if len(args) >= 2 && !strings.HasPrefix(args[0], "-") && !strings.HasPrefix(args[1], "-") {
		positional = append(positional, args[0], args[1])
		flagArgs = args[2:]
	}
	if help, err := parseFlagSet(fs, flagArgs); err != nil || help {
		return err
	}
	positional = append(positional, fs.Args()...)
	if len(positional) != 2 {
		return withExitCode(ExitUsage, "promote requires source and destination views")
	}
	sourceView, destinationView := positional[0], positional[1]
	if sourceView == destinationView {
		return withExitCode(ExitUsage, "source and destination views must differ")
	}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		return err
	}
	sourceConfig, ok := cfg.Views[sourceView]
	if !ok || sourceView == "snapshot" {
		return withExitCode(ExitConfig, "unknown promotable source view %q", sourceView)
	}
	destinationConfig, destinationIsView := cfg.Views[destinationView]
	destinationIsSnapshot := !destinationIsView && views.ValidateSnapshotID(destinationView) == nil
	if (destinationIsView && destinationView == "snapshot") || (!destinationIsView && !destinationIsSnapshot) {
		return withExitCode(ExitConfig, "unknown promotable destination view or snapshot %q", destinationView)
	}
	var snapshotSuite string
	if destinationIsSnapshot {
		if sourceView != "stable" {
			return withExitCode(ExitUsage, "snapshots may only be created from stable")
		}
		snapshotSuite, err = views.SnapshotSuite(destinationView)
		if err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
		destinationConfig = config.View{Access: "pro", AllowedPools: []string{"public", "gated"}, AppendOnly: true}
		expectedSnapshot, err := views.SnapshotID(snapshotSuite, time.Now().UTC())
		if err != nil {
			return withExitCode(ExitInternal, "derive snapshot ID: %v", err)
		}
		if destinationView != expectedSnapshot {
			return withExitCode(ExitConflict, "snapshot ID %s does not match the UTC capture date; expected %s", destinationView, expectedSnapshot)
		}
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "promote", values.recover)
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
		return withExitCode(ExitConflict, "canonical config changed while promote was waiting for the state lock: %v", err)
	}
	transactionDir, err := newTransactionDir(cfg.StatePath(), "promote-")
	if err != nil {
		return withExitCode(ExitInternal, "create promote transaction: %v", err)
	}
	defer os.RemoveAll(transactionDir)

	var staged = make(map[string]string)
	var refs []pendingRef
	var sourceLeaves, matched, entryCount int64
	stageSequence := 0
	promotionLeaves := selectedLeaves(repos, values)
	if destinationIsSnapshot {
		// APT Release/InRelease covers every configured architecture in one
		// suite. --arch is therefore only a transaction trigger for snapshots;
		// the immutable ref set is expanded and checked before anything stages.
		promotionLeaves = suiteClosedSelectedLeaves(cfg, repos, values)
		if err := requireCompleteAPTSnapshotSource(store, sourceView, destinationView, sourceConfig, destinationConfig, snapshotSuite, promotionLeaves); err != nil {
			return err
		}
	}
	for _, leaf := range promotionLeaves {
		if !viewIncludesRepo(sourceConfig, leaf.repo.ID) || !viewIncludesRepo(destinationConfig, leaf.repo.ID) {
			continue
		}
		if destinationIsSnapshot && leaf.os != snapshotSuite {
			continue
		}
		sourceRef, err := state.ViewRef(sourceView, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		sourceHash, exists, err := store.Ref(sourceRef)
		if err != nil {
			return withExitCode(ExitInternal, "read %s: %v", sourceRef, err)
		}
		if !exists {
			continue
		}
		sourceLeaves++
		sourcePath, err := state.ViewPath(sourceView, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		var destinationPath string
		var destinationRef plumbing.ReferenceName
		if destinationIsSnapshot {
			destinationPath, err = state.SnapshotPath(destinationView, leaf.repo.ID, leaf.os, leaf.arch)
			if err == nil {
				destinationRef, err = state.SnapshotRef(destinationView, leaf.repo.ID, leaf.os, leaf.arch)
			}
		} else {
			destinationPath, err = state.ViewPath(destinationView, leaf.repo.ID, leaf.os, leaf.arch)
			if err == nil {
				destinationRef, err = state.ViewRef(destinationView, leaf.repo.ID, leaf.os, leaf.arch)
			}
		}
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		destinationHash, destinationExists, err := store.Ref(destinationRef)
		if err != nil {
			return withExitCode(ExitInternal, "read %s: %v", destinationRef, err)
		}

		// A Pro source may be promoted toward a public destination only when its
		// complete asset leaf also satisfies the public digest-taint closure.
		// Source policy alone is insufficient: a public-pool entry can still be
		// a copied Pro archive remembered by its canonical receipt.
		sourceMustBePublic := sourceConfig.Access == "public" || destinationConfig.Access == "public"
		if err := validateViewAt(store, sourceHash, sourcePath, leaf, sourceMustBePublic); err != nil {
			return withExitCode(ExitVerification, "validate source %s: %v", sourceRef, err)
		}
		if destinationExists {
			if err := validateViewAt(store, destinationHash, destinationPath, leaf, destinationConfig.Access == "public"); err != nil {
				return withExitCode(ExitVerification, "validate destination %s: %v", destinationRef, err)
			}
		}

		destination, err := openViewAt(store, destinationHash, destinationPath, destinationExists)
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		source, err := store.OpenPathAt(sourceHash, sourcePath)
		if err != nil {
			_ = destination.Close()
			return withExitCode(ExitInternal, "%v", err)
		}
		// A staged leaf can be unchanged and therefore never enter staged.  Keep
		// the scratch-file sequence independent from the number of changed paths
		// so the next selected leaf cannot reuse an existing O_EXCL filename.
		stagePath := filepath.Join(transactionDir, fmt.Sprintf("%06d.tsv", stageSequence))
		stageSequence++
		stage, err := os.OpenFile(stagePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = errors.Join(destination.Close(), source.Close())
			return withExitCode(ExitInternal, "create promoted view: %v", err)
		}
		count, promoteErr := views.PromoteWithReplacements(destination, source, stage, views.Selector{
			Repos: []string{leaf.repo.ID}, OSes: []string{leaf.os}, Arches: []string{leaf.arch},
		}, destinationConfig.Access == "public", promotionAssetReplacement(leaf.repo, destinationView, destinationIsSnapshot))
		closeErr := errors.Join(destination.Close(), source.Close(), stage.Sync(), stage.Close())
		if promoteErr != nil || closeErr != nil {
			return withExitCode(ExitVerification, "promote %s/%s/%s: %v", leaf.repo.ID, leaf.os, leaf.arch, errors.Join(promoteErr, closeErr))
		}
		if destinationConfig.Access == "public" {
			stagedLeaf, openErr := os.Open(stagePath)
			if openErr != nil {
				return withExitCode(ExitInternal, "open staged public promotion: %v", openErr)
			}
			validateErr := validateViewEntries(store, stagedLeaf, leaf, true)
			closeErr := stagedLeaf.Close()
			if validateErr != nil || closeErr != nil {
				return withExitCode(ExitVerification, "validate staged public destination %s: %v", destinationRef, errors.Join(validateErr, closeErr))
			}
		}
		changed, err := viewChanged(store, destinationHash, destinationPath, destinationExists, stagePath)
		if err != nil {
			return withExitCode(ExitInternal, "compare promoted view: %v", err)
		}
		if leaf.repo.LifecycleForSuite(leaf.os) == "frozen" && changed {
			if !destinationIsSnapshot {
				if leaf.repo.Type == "apt" {
					return withExitCode(ExitConflict, "repo %s suite %s is frozen; promotion may not add content", leaf.repo.ID, leaf.os)
				}
				return withExitCode(ExitConflict, "repo %s is frozen; promotion may not add content", leaf.repo.ID)
			}
		}
		if destinationIsSnapshot && destinationExists && changed {
			return withExitCode(ExitConflict, "snapshot %s already exists with different content at %s/%s/%s", destinationView, leaf.repo.ID, leaf.os, leaf.arch)
		}
		if changed {
			staged[destinationPath] = stagePath
			refs = append(refs, pendingRef{name: destinationRef, expected: destinationHash, immutable: destinationIsSnapshot})
			matched++
			entryCount += count
		}
		// "转正" into latest also extends the append-only commercial history in
		// the same canonical commit. Stable is a set union, never a later manual
		// copy step that can be forgotten.
		if destinationIsView && destinationView == "latest" {
			stableConfig := cfg.Views["stable"]
			if viewIncludesRepo(stableConfig, leaf.repo.ID) {
				stablePath, stableStage, stableRef, stableExpected, stableCount, stableChanged, stableErr := stageStableUnion(
					store, transactionDir, stagePath, leaf, stableConfig,
				)
				if stableErr != nil {
					return stableErr
				}
				if stableChanged {
					staged[stablePath] = stableStage
					refs = append(refs, pendingRef{name: stableRef, expected: stableExpected})
					matched++
					entryCount += stableCount
				}
			}
		}
	}
	if sourceLeaves == 0 {
		return withExitCode(ExitConfig, "selectors matched no source view refs")
	}
	if matched == 0 {
		fmt.Fprintf(stdout, "promote unchanged source=%s destination=%s leaves=%d\n", sourceView, destinationView, sourceLeaves)
		return rebuildCatalogProjection(ctx, cfg, stdout)
	}
	updates := make([]state.RefUpdate, 0, len(refs))
	for _, update := range refs {
		updates = append(updates, state.RefUpdate{Name: update.name, Expected: update.expected, Immutable: update.immutable})
	}
	canonicalConfig, configHash, err := stageCanonicalConfig(cfg, transactionDir)
	if err != nil {
		return withExitCode(ExitInternal, "stage canonical config: %v", err)
	}
	staged["config/sow.yaml"] = canonicalConfig
	hash, committed, err := applyCanonicalConfig(ctx, cfg, store, "promote", fmt.Sprintf("sow promote: %s -> %s", sourceView, destinationView), staged, updates, state.ApplyOptions{})
	if err != nil {
		return stateMutationError("commit promoted views", err)
	}
	if !committed {
		return withExitCode(ExitInternal, "promoted views changed but no canonical commit was created")
	}
	fmt.Fprintf(stdout, "promoted source=%s destination=%s leaves=%d entries=%d commit=%s config_sha256=%s\n", sourceView, destinationView, matched, entryCount, hash, configHash)
	return rebuildCatalogProjection(ctx, cfg, stdout)
}

func requireCompleteAPTSnapshotSource(store *state.Store, sourceView, snapshotID string, sourceConfig, destinationConfig config.View, snapshotSuite string, leaves []viewLeaf) error {
	type suiteState struct {
		repo               string
		suite              string
		total              int
		present            int
		missing            []string
		destinationPresent int
		destinationMissing []string
	}
	states := make(map[string]*suiteState)
	for _, leaf := range leaves {
		if leaf.repo.Type != "apt" || leaf.os != snapshotSuite || !viewIncludesRepo(sourceConfig, leaf.repo.ID) || !viewIncludesRepo(destinationConfig, leaf.repo.ID) {
			continue
		}
		key := leaf.repo.ID + "\x00" + leaf.os
		current := states[key]
		if current == nil {
			current = &suiteState{repo: leaf.repo.ID, suite: leaf.os}
			states[key] = current
		}
		current.total++
		ref, err := state.ViewRef(sourceView, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		if _, exists, err := store.Ref(ref); err != nil {
			return withExitCode(ExitInternal, "read %s: %v", ref, err)
		} else if exists {
			current.present++
		} else {
			current.missing = append(current.missing, ref.String())
		}
		destinationRef, err := state.SnapshotRef(snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		if _, exists, err := store.Ref(destinationRef); err != nil {
			return withExitCode(ExitInternal, "read %s: %v", destinationRef, err)
		} else if exists {
			current.destinationPresent++
		} else {
			current.destinationMissing = append(current.destinationMissing, destinationRef.String())
		}
	}
	keys := make([]string, 0, len(states))
	for key := range states {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		current := states[key]
		if current.present != 0 && current.present != current.total {
			sort.Strings(current.missing)
			return withExitCode(ExitConflict, "APT snapshot source %s/%s is incomplete: configured sibling ref(s) %s missing", current.repo, current.suite, strings.Join(current.missing, ","))
		}
		if current.destinationPresent != 0 && current.destinationPresent != current.total {
			sort.Strings(current.destinationMissing)
			return withExitCode(ExitConflict, "APT snapshot %s is incomplete for %s/%s: immutable sibling ref(s) %s missing", snapshotID, current.repo, current.suite, strings.Join(current.destinationMissing, ","))
		}
	}
	return nil
}

func stageStableUnion(store *state.Store, transactionDir, latestStage string, leaf viewLeaf, stableConfig config.View) (canonicalPath, stagedPath string, ref plumbing.ReferenceName, expected plumbing.Hash, count int64, changed bool, err error) {
	canonicalPath, err = state.ViewPath("stable", leaf.repo.ID, leaf.os, leaf.arch)
	if err != nil {
		return "", "", "", plumbing.ZeroHash, 0, false, withExitCode(ExitInternal, "%v", err)
	}
	ref, err = state.ViewRef("stable", leaf.repo.ID, leaf.os, leaf.arch)
	if err != nil {
		return "", "", "", plumbing.ZeroHash, 0, false, withExitCode(ExitInternal, "%v", err)
	}
	expected, exists, err := store.Ref(ref)
	if err != nil {
		return "", "", "", plumbing.ZeroHash, 0, false, withExitCode(ExitInternal, "read %s: %v", ref, err)
	}
	if exists {
		if validateErr := validateViewAt(store, expected, canonicalPath, leaf, stableConfig.Access == "public"); validateErr != nil {
			return "", "", "", plumbing.ZeroHash, 0, false, withExitCode(ExitVerification, "validate stable %s: %v", ref, validateErr)
		}
	}
	destination, err := openViewAt(store, expected, canonicalPath, exists)
	if err != nil {
		return "", "", "", plumbing.ZeroHash, 0, false, withExitCode(ExitInternal, "%v", err)
	}
	source, err := os.Open(latestStage)
	if err != nil {
		destination.Close()
		return "", "", "", plumbing.ZeroHash, 0, false, withExitCode(ExitInternal, "open promoted latest leaf: %v", err)
	}
	stage, err := os.CreateTemp(transactionDir, "stable-*.tsv")
	if err != nil {
		_ = errors.Join(destination.Close(), source.Close())
		return "", "", "", plumbing.ZeroHash, 0, false, withExitCode(ExitInternal, "create automatic stable view: %v", err)
	}
	stagedPath = stage.Name()
	count, promoteErr := views.PromoteWithReplacements(destination, source, stage, views.Selector{
		Repos: []string{leaf.repo.ID}, OSes: []string{leaf.os}, Arches: []string{leaf.arch},
	}, stableConfig.Access == "public", promotionAssetReplacement(leaf.repo, "stable", false))
	closeErr := errors.Join(destination.Close(), source.Close(), stage.Sync(), stage.Close())
	if promoteErr != nil || closeErr != nil {
		return "", "", "", plumbing.ZeroHash, 0, false, withExitCode(ExitVerification, "extend stable %s/%s/%s: %v", leaf.repo.ID, leaf.os, leaf.arch, errors.Join(promoteErr, closeErr))
	}
	changed, err = viewChanged(store, expected, canonicalPath, exists, stagedPath)
	if err != nil {
		return "", "", "", plumbing.ZeroHash, 0, false, withExitCode(ExitInternal, "compare automatic stable view: %v", err)
	}
	return canonicalPath, stagedPath, ref, expected, count, changed, nil
}

// promotionAssetReplacement grants only the same repository-relative mutable
// paths accepted by `sow add --replace`. Latest and the current stable pointer
// may advance; immutable snapshot refs keep strict union semantics. Prior Git
// commits and CAS objects remain preservation roots for history and rollback.
func promotionAssetReplacement(repo config.Repo, destinationView string, destinationIsSnapshot bool) func(views.Entry) bool {
	if repo.Type != "asset" || repo.Asset == nil || destinationIsSnapshot || destinationView != "latest" && destinationView != "stable" {
		return nil
	}
	prefix := strings.TrimSuffix(repo.Path, "/") + "/"
	return func(entry views.Entry) bool {
		if entry.Repo != repo.ID || !strings.HasPrefix(entry.Path, prefix) {
			return false
		}
		mutable, err := assetMutablePath(repo, strings.TrimPrefix(entry.Path, prefix))
		return err == nil && mutable
	}
}

func selectedLeaves(repos []config.Repo, values commonFlags) []viewLeaf {
	var leaves []viewLeaf
	for _, repo := range repos {
		oses := repo.OSSelectorValues()
		arches := repo.Arches
		if repo.Type == "apt" && repo.APT != nil {
			oses = append([]string(nil), repo.APT.Suites...)
		}
		if repo.Type == "asset" {
			oses, arches = []string{"all"}, []string{"all"}
		}
		for _, osName := range uniqueSorted(oses) {
			if !matchesValue(osName, values.oses.values()) {
				continue
			}
			for _, arch := range uniqueSorted(arches) {
				if !matchesValue(arch, values.arches.values()) {
					continue
				}
				leaves = append(leaves, viewLeaf{repo: repo, os: osName, arch: arch})
			}
		}
	}
	sort.Slice(leaves, func(i, j int) bool {
		left := strings.Join([]string{leaves[i].repo.ID, leaves[i].os, leaves[i].arch}, "\x00")
		right := strings.Join([]string{leaves[j].repo.ID, leaves[j].os, leaves[j].arch}, "\x00")
		return left < right
	})
	return leaves
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func viewIncludesRepo(view config.View, repo string) bool {
	return len(view.Repos) == 0 || contains(view.Repos, repo)
}

func validateViewAt(store *state.Store, hash plumbing.Hash, path string, leaf viewLeaf, public bool) error {
	reader, err := store.OpenPathAt(hash, path)
	if err != nil {
		return err
	}
	validateErr := validateViewEntries(store, reader, leaf, public)
	return errors.Join(validateErr, reader.Close())
}

func validateViewEntries(store *state.Store, reader io.Reader, leaf viewLeaf, public bool) error {
	if store == nil || reader == nil {
		return errors.New("canonical view validation input is unavailable")
	}
	var validateEntry func(views.Entry) error
	if leaf.repo.Type == "asset" {
		validateEntry = func(entry views.Entry) error {
			if err := validateAssetProjectionPath(leaf.repo, entry.Path); err != nil {
				return err
			}
			if public {
				destination := leaf.repo
				destination.DefaultPool = "public"
				if _, err := requireOfflineArchiveTaintAdmission(store, destination, entry.SHA256, entry.Size); err != nil {
					return fmt.Errorf("public asset %s violates canonical archive taint: %w", entry.Path, err)
				}
			}
			return nil
		}
	}
	_, validateErr := views.ValidateLeafEntries(reader, leaf.repo.ID, leaf.os, leaf.arch, public, validateEntry)
	return validateErr
}

func openViewAt(store *state.Store, hash plumbing.Hash, path string, exists bool) (io.ReadCloser, error) {
	if !exists {
		return io.NopCloser(strings.NewReader("")), nil
	}
	return store.OpenPathAt(hash, path)
}

func viewChanged(store *state.Store, hash plumbing.Hash, path string, exists bool, staged string) (bool, error) {
	if !exists {
		return true, nil
	}
	old, err := store.OpenPathAt(hash, path)
	if err != nil {
		return false, err
	}
	defer old.Close()
	newFile, err := os.Open(staged)
	if err != nil {
		return false, err
	}
	defer newFile.Close()
	equal, err := equalReaders(old, newFile)
	return !equal, err
}

func equalReaders(left, right io.Reader) (bool, error) {
	leftBuffer := make([]byte, 128*1024)
	rightBuffer := make([]byte, 128*1024)
	for {
		leftN, leftErr := io.ReadFull(left, leftBuffer)
		rightN, rightErr := io.ReadFull(right, rightBuffer)
		if leftN != rightN || string(leftBuffer[:leftN]) != string(rightBuffer[:rightN]) {
			return false, nil
		}
		leftDone := errors.Is(leftErr, io.EOF) || errors.Is(leftErr, io.ErrUnexpectedEOF)
		rightDone := errors.Is(rightErr, io.EOF) || errors.Is(rightErr, io.ErrUnexpectedEOF)
		if leftDone || rightDone {
			return leftDone && rightDone, nil
		}
		if leftErr != nil || rightErr != nil {
			return false, errors.Join(leftErr, rightErr)
		}
	}
}
