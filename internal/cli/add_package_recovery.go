package cli

import (
	"errors"
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

// packageAddLeafPlan is the complete canonical mutation planned from inspected
// package bytes. It is deliberately constructed before CAS is opened so an
// existing add recovery fence can prove that every proposed input is already
// part of the frozen canonical refs before Put/Import is allowed to repair a
// missing object.
type packageAddLeafPlan struct {
	repo    config.Repo
	leaf    viewLeaf
	view    string
	entries []views.Entry
}

// packageAddSigningVerificationTime permits an exact positional retry to
// verify the same frozen package/repository signatures after their key has
// expired. The observed ID is rechecked under the state lock before CAS can be
// repaired. Without a matching durable add intent, new work always uses the
// current clock and freezePackageProjectionSigningTime repeats that proof
// under the lock immediately before creating a new intent.
func packageAddSigningVerificationTime(cfg *config.Config, values commonFlags, family string) (time.Time, string, error) {
	current := packageProjectionNow().UTC()
	if values.syncInternal || !values.recover {
		return current, "", nil
	}
	intent, exists, err := readPackageProjectionIntent(cfg.StatePath())
	if err != nil || !exists {
		return current, "", err
	}
	if intent.Operation != "add" || intent.Family != family {
		return time.Time{}, "", fmt.Errorf("durable package add projection family differs from current %s input", family)
	}
	at, err := parsePackageProjectionSigningTime(intent.SigningTime)
	if err != nil {
		return time.Time{}, "", err
	}
	return at, intent.ID, nil
}

// requirePackageAddRecoveryFamilyBeforePrepare is the first half of the add
// mutation fence. It runs immediately after acquiring the state lock, before
// canonical recovery/preparation, and prevents a DEB retry from entering an
// interrupted RPM add (or vice versa). Exact input/ref proof follows after the
// package metadata and trust snapshot have been frozen.
func requirePackageAddRecoveryFamilyBeforePrepare(cfg *config.Config, values commonFlags, family string) error {
	if values.syncInternal {
		return nil
	}
	journal, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists {
		return err
	}
	if err := validatePackageAddRecoveryFamily(journal, values.recover, family); err != nil {
		return err
	}
	return nil
}

// preflightPositionalPackageProjection proves that a positional package retry
// is the exact frozen operation before generic Store recovery can advance a
// ref. The caller has already inspected and signature-verified every input,
// but no candidate object has entered CAS yet.
func preflightPositionalPackageProjection(cfg *config.Config, canonical *state.Store, values commonFlags, family string, privateKey []byte, repositoryKeySHA string, groups map[string]*packageAddLeafPlan) (*packageProjectionIntent, error) {
	if values.syncInternal {
		return nil, nil
	}
	if _, exists, err := readAssetProjectionIntent(cfg.StatePath()); err != nil || exists {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("durable asset projection differs from current package input")
	}
	intent, exists, err := readPackageProjectionIntent(cfg.StatePath())
	if err != nil || !exists {
		return nil, err
	}
	if !values.recover {
		return nil, errors.New("incomplete package add projection requires --recover")
	}
	if intent.Operation != "add" || intent.Family != family {
		return nil, fmt.Errorf("durable package add projection family differs from current %s input", family)
	}
	record, transactionExists, err := canonical.Transaction(intent.TransactionID)
	if err != nil {
		return nil, err
	}
	if err := requirePackageProjectionTransactionCompatible(cfg, intent, record, transactionExists); err != nil {
		return nil, err
	}
	if err := requirePackageProjectionIntentAttestation(cfg, intent); err != nil {
		return nil, err
	}
	mutations, err := requirePackageProjectionConfig(cfg, canonical, intent)
	if err != nil {
		return nil, err
	}
	if _, err := captureAndRequirePackageProjectionTrust(cfg, intent, mutations, privateKey, repositoryKeySHA); err != nil {
		return nil, err
	}
	if err := requirePackageAddEntriesInProjectionStages(cfg, intent, groups); err != nil {
		return nil, err
	}
	return &intent, nil
}

func requirePackageAddEntriesInProjectionStages(cfg *config.Config, intent packageProjectionIntent, groups map[string]*packageAddLeafPlan) error {
	units := make(map[string]packageProjectionIntentUnit, len(intent.Units))
	for _, unit := range intent.Units {
		key := strings.Join([]string{unit.View, unit.Repo, unit.OS, unit.Arch}, "\x00")
		units[key] = unit
	}
	for _, group := range groups {
		if group == nil {
			return errors.New("nil package add recovery group")
		}
		key := strings.Join([]string{group.view, group.repo.ID, group.leaf.os, group.leaf.arch}, "\x00")
		unit, exists := units[key]
		if !exists {
			return fmt.Errorf("package add input leaf %s is absent from frozen ref", key)
		}
		wanted := make(map[string]views.Entry, len(group.entries))
		for _, entry := range group.entries {
			if previous, exists := wanted[entry.Path]; exists && previous != entry {
				return fmt.Errorf("package add recovery proposes conflicting entry %s", entry.Path)
			}
			wanted[entry.Path] = entry
		}
		stage, err := os.Open(filepath.Join(cfg.StatePath(), unit.StageRelative))
		if err != nil {
			return err
		}
		reader := views.NewReader(stage)
		for {
			entry, readErr := reader.Next()
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = stage.Close()
				return readErr
			}
			if expected, exists := wanted[entry.Path]; exists {
				if expected != entry {
					_ = stage.Close()
					return fmt.Errorf("package add recovery input %s differs from frozen ref", entry.Path)
				}
				delete(wanted, entry.Path)
			}
		}
		if err := stage.Close(); err != nil {
			return err
		}
		if len(wanted) != 0 {
			missing := make([]string, 0, len(wanted))
			for name := range wanted {
				missing = append(missing, name)
			}
			sort.Strings(missing)
			return fmt.Errorf("package add input %s is absent from frozen ref", strings.Join(missing, ","))
		}
	}
	return nil
}

// Any exact asset add journal has already been decoded and converged by the
// top-level input-independent recovery path before subtype dispatch. Therefore
// a journal still present when a new asset request owns the add lock is either
// a package/mixed selected set or an invalid envelope and must fail closed
// before canonical preparation or asset CAS import.
func requireNoMaterializationIntentBeforeAssetAdd(cfg *config.Config) error {
	if _, exists, err := readPackageProjectionIntent(cfg.StatePath()); err != nil || exists {
		if err != nil {
			return err
		}
		return errors.New("durable package projection must be recovered before a new asset input")
	}
	_, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists {
		return err
	}
	return errors.New("durable add materialization must be recovered before a new asset input")
}

func validatePackageAddRecoveryFamily(journal materializationSelectionJournal, recover bool, family string) error {
	if family != "apt" && family != "yum" {
		return errors.New("invalid package add recovery family")
	}
	if !recover {
		return errors.New("incomplete package add materialization requires --recover")
	}
	if journal.Operation != "add" || journal.OperationScope != "" || len(journal.Units) == 0 {
		return errors.New("durable materialization intent is not an exact package add")
	}
	for _, unit := range journal.Units {
		if unit.Kind != family || unit.Historical {
			return fmt.Errorf("durable add materialization family differs from current %s input", family)
		}
	}
	return nil
}

// packageAddMaterializationRequests returns the same deterministic request set
// used both by the pre-CAS recovery admission and by the selected-set
// coordinator after a new canonical commit. Normal adds merely build this
// in-memory plan; they do not create a durable journal until canonical state is
// ready to materialize.
func packageAddMaterializationRequests(cfg *config.Config, groups map[string]*packageAddLeafPlan) ([]materializationSelectionRequest, error) {
	byView := make(map[string]map[string]viewLeaf)
	for _, group := range groups {
		if group == nil {
			return nil, errors.New("nil package add leaf plan")
		}
		if _, exists := cfg.Views[group.view]; !exists {
			return nil, fmt.Errorf("package add view %s is not configured", group.view)
		}
		leaves := byView[group.view]
		if leaves == nil {
			leaves = make(map[string]viewLeaf)
			byView[group.view] = leaves
		}
		key := strings.Join([]string{group.leaf.repo.ID, group.leaf.os, group.leaf.arch}, "\x00")
		leaves[key] = group.leaf
	}
	viewNames := make([]string, 0, len(byView))
	for viewName := range byView {
		viewNames = append(viewNames, viewName)
	}
	sort.Strings(viewNames)
	requests := make([]materializationSelectionRequest, 0, len(viewNames))
	for _, viewName := range viewNames {
		leafKeys := make([]string, 0, len(byView[viewName]))
		for key := range byView[viewName] {
			leafKeys = append(leafKeys, key)
		}
		sort.Strings(leafKeys)
		leaves := make([]viewLeaf, 0, len(leafKeys))
		for _, key := range leafKeys {
			leaves = append(leaves, byView[viewName][key])
		}
		requests = append(requests, materializationSelectionRequest{
			Source:          materializeCanonicalSource{ID: viewName, Public: cfg.Views[viewName].Access == "public"},
			Leaves:          leaves,
			TargetRoot:      cfg.Root,
			IncludeMetadata: true,
			ExpandAPT:       true,
		})
	}
	if len(requests) == 0 {
		return nil, errors.New("package add materialization request set is empty")
	}
	return requests, nil
}

// requireExactPackageAddRecoveryBeforeCAS is the second half of the recovery
// fence. The durable unit vector alone identifies leaves, not individual
// package inputs, so both proofs are required: the planned unit IDs must match
// exactly and every SHA/size/path entry proposed by this retry must already be
// present byte-for-byte in the journal's frozen canonical refs.
func requireExactPackageAddRecoveryBeforeCAS(cfg *config.Config, canonical *state.Store, values commonFlags, family string, requests []materializationSelectionRequest, groups map[string]*packageAddLeafPlan) error {
	if values.syncInternal {
		return nil
	}
	journal, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists {
		return err
	}
	if err := validatePackageAddRecoveryFamily(journal, values.recover, family); err != nil {
		return err
	}
	if values.materializeTrust == nil || !materializationSnapshotMatchesJournal(values.materializeTrust, journal) {
		return errors.New("package add recovery frozen trust differs from the durable selected set")
	}
	if err := requireMaterializationJournalCanonicalIdentity(cfg, canonical, journal); err != nil {
		return err
	}
	planned, err := planMaterializationSelectedUnits(cfg, canonical, requests)
	if err != nil {
		return err
	}
	durable := make(map[string]materializationSelectedUnit, len(journal.Units))
	for _, unit := range journal.Units {
		durable[unit.ID] = unit
	}
	if err := requireMaterializationUnitSubset(planned, durable, true); err != nil {
		return err
	}
	if err := requirePackageAddEntriesInFrozenRefs(cfg, canonical, journal, groups); err != nil {
		return err
	}
	// This recovery attempt has now proven its exact frozen scope. Promote an
	// inherited prepared fence before any caller can create a transaction,
	// open/install CAS state, or encounter another pre-materializer failure.
	// Otherwise finishMaterializationSelectedSet could later mistake the old
	// fence for a newly-created empty intent and delete the only recovery record.
	if journal.Phase == materializationSelectionPrepared {
		journal.Phase = materializationSelectionMaterializing
		if err := writeMaterializationSelectionJournal(cfg.StatePath(), journal); err != nil {
			return fmt.Errorf("persist package add recovery start before CAS: %w", err)
		}
	}
	return nil
}

type packageAddFrozenRefProof struct {
	commit   string
	viewPath string
	leaf     viewLeaf
	public   bool
	wanted   map[string]views.Entry
}

func requirePackageAddEntriesInFrozenRefs(cfg *config.Config, canonical *state.Store, journal materializationSelectionJournal, groups map[string]*packageAddLeafPlan) error {
	frozen := make(map[string]string)
	for _, unit := range journal.Units {
		for _, ref := range unit.Refs {
			if previous, exists := frozen[ref.Name]; exists && previous != ref.Commit {
				return errors.New("package add journal assigns one ref to multiple commits")
			}
			frozen[ref.Name] = ref.Commit
		}
	}
	proofs := make(map[string]*packageAddFrozenRefProof)
	for _, group := range groups {
		viewRef, err := state.ViewRef(group.view, group.repo.ID, group.leaf.os, group.leaf.arch)
		if err != nil {
			return err
		}
		commit, exists := frozen[viewRef.String()]
		if !exists {
			return fmt.Errorf("package add input ref %s is absent from the durable selected set", viewRef)
		}
		viewPath, err := state.ViewPath(group.view, group.repo.ID, group.leaf.os, group.leaf.arch)
		if err != nil {
			return err
		}
		proof := proofs[viewRef.String()]
		if proof == nil {
			view, exists := cfg.Views[group.view]
			if !exists {
				return fmt.Errorf("package add view %s is not configured", group.view)
			}
			proof = &packageAddFrozenRefProof{commit: commit, viewPath: viewPath, leaf: group.leaf, public: view.Access == "public", wanted: make(map[string]views.Entry)}
			proofs[viewRef.String()] = proof
		} else if proof.commit != commit || proof.viewPath != viewPath || proof.leaf.repo.ID != group.leaf.repo.ID || proof.leaf.os != group.leaf.os || proof.leaf.arch != group.leaf.arch {
			return fmt.Errorf("package add ref %s has inconsistent recovery coordinates", viewRef)
		}
		for _, entry := range group.entries {
			if err := entry.Validate(); err != nil {
				return fmt.Errorf("invalid planned package add entry %s: %w", entry.Path, err)
			}
			if previous, exists := proof.wanted[entry.Path]; exists && previous != entry {
				return fmt.Errorf("package add recovery proposes conflicting entry %s", entry.Path)
			}
			proof.wanted[entry.Path] = entry
		}
	}
	refNames := make([]string, 0, len(proofs))
	for refName := range proofs {
		refNames = append(refNames, refName)
	}
	sort.Strings(refNames)
	for _, refName := range refNames {
		proof := proofs[refName]
		reader, err := canonical.OpenPathAt(plumbing.NewHash(proof.commit), proof.viewPath)
		if err != nil {
			return fmt.Errorf("open frozen package add ref %s: %w", refName, err)
		}
		viewReader := views.NewReader(reader)
		for {
			entry, readErr := viewReader.Next()
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = reader.Close()
				return fmt.Errorf("read frozen package add ref %s: %w", refName, readErr)
			}
			if entry.Repo != proof.leaf.repo.ID || entry.OS != proof.leaf.os || entry.Arch != proof.leaf.arch {
				_ = reader.Close()
				return fmt.Errorf("frozen package add ref %s contains foreign leaf coordinates", refName)
			}
			if proof.public && entry.Pool != "public" {
				_ = reader.Close()
				return fmt.Errorf("frozen public package add ref %s contains gated content", refName)
			}
			if wanted, exists := proof.wanted[entry.Path]; exists {
				if wanted != entry {
					_ = reader.Close()
					return fmt.Errorf("package add recovery input %s differs from frozen ref %s", entry.Path, refName)
				}
				delete(proof.wanted, entry.Path)
			}
		}
		if err := reader.Close(); err != nil {
			return fmt.Errorf("close frozen package add ref %s: %w", refName, err)
		}
		if len(proof.wanted) != 0 {
			missing := make([]string, 0, len(proof.wanted))
			for path := range proof.wanted {
				missing = append(missing, path)
			}
			sort.Strings(missing)
			return fmt.Errorf("package add recovery input paths [%s] are absent from frozen ref %s", strings.Join(missing, ","), refName)
		}
	}
	return nil
}
