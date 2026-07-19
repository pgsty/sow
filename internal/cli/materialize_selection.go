package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

const (
	materializationSelectionJournalSchema   = "sow-materialization-selection/v1"
	materializationSelectionJournalRelative = "materialization-journal/active.json"
	materializationSelectionJournalMaxBytes = 1 << 20
)

type materializationSelectionPhase string

const (
	materializationSelectionPrepared      materializationSelectionPhase = "prepared"
	materializationSelectionMaterializing materializationSelectionPhase = "materializing"
	materializationSelectionDrifted       materializationSelectionPhase = "trust-drifted"
)

var materializationOperationPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var materializationCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var materializationUnitKindPattern = regexp.MustCompile(`^(apt|yum|yum-compat|asset|serving)$`)
var materializationJournalTempPattern = regexp.MustCompile(`^active\.json\.tmp-[0-9a-f]{16}$`)

type materializationSelectionKeyring struct {
	Repo   string `json:"repo"`
	SHA256 string `json:"sha256"`
}

type materializationSelectionRef struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
}

// materializationSelectedUnit is the smallest directly-hostable trust unit.
// TargetSHA256 deliberately stores only an identity digest: target paths may
// contain operator-specific mount names and must not leak through diagnostics
// or durable recovery records.
type materializationSelectedUnit struct {
	ID           string                        `json:"id"`
	Kind         string                        `json:"kind"`
	Source       string                        `json:"source"`
	Historical   bool                          `json:"historical,omitempty"`
	TargetSHA256 string                        `json:"target_sha256"`
	Repo         string                        `json:"repo"`
	OS           string                        `json:"os"`
	Arch         string                        `json:"arch"`
	Refs         []materializationSelectionRef `json:"refs"`
}

type materializationSelectionJournal struct {
	Schema              string                            `json:"schema"`
	ID                  string                            `json:"id"`
	Operation           string                            `json:"operation"`
	OperationScope      string                            `json:"operation_scope,omitempty"`
	Phase               materializationSelectionPhase     `json:"phase"`
	ConfigSHA256        string                            `json:"config_sha256"`
	ParentConfigSHA256  string                            `json:"parent_config_sha256"`
	ExpectedHead        string                            `json:"expected_head"`
	RepositoryKeySHA256 string                            `json:"repository_key_sha256"`
	YUMKeyrings         []materializationSelectionKeyring `json:"yum_keyrings,omitempty"`
	ArchiveAdoption     *offlineArchiveAdoptionContract   `json:"archive_adoption,omitempty"`
	Units               []materializationSelectedUnit     `json:"units"`
	CompletedUnits      []string                          `json:"completed_units,omitempty"`
}

type materializationSelectionIdentity struct {
	Schema              string                            `json:"schema"`
	Operation           string                            `json:"operation"`
	OperationScope      string                            `json:"operation_scope,omitempty"`
	ConfigSHA256        string                            `json:"config_sha256"`
	ParentConfigSHA256  string                            `json:"parent_config_sha256"`
	ExpectedHead        string                            `json:"expected_head"`
	RepositoryKeySHA256 string                            `json:"repository_key_sha256"`
	YUMKeyrings         []materializationSelectionKeyring `json:"yum_keyrings,omitempty"`
	ArchiveAdoption     *offlineArchiveAdoptionContract   `json:"archive_adoption,omitempty"`
	Units               []materializationSelectedUnit     `json:"units"`
}

type materializationSelectedSet struct {
	journal materializationSelectionJournal
	units   map[string]materializationSelectedUnit
}

type materializationSelectionRequest struct {
	Source          materializeCanonicalSource
	Leaves          []viewLeaf
	TargetRoot      string
	IncludeMetadata bool
	IncludeServing  bool
	// IncludeCompatibility is set only by materialize/publish. Write verbs
	// (add/rm/sync/promote) never turn a compatibility projection into a
	// writable repository or silently add one to their selected set.
	IncludeCompatibility bool
	ExpandAPT            bool
}

// planMaterializationSelectedUnits freezes the exact canonical ref vector
// before the first directly-hostable flip. APT is suite-wide because all
// architectures share one Release/InRelease transaction; YUM and serving are
// leaf-wide. Missing refs are skipped exactly as their materializers skip them.
func planMaterializationSelectedUnits(cfg *config.Config, canonical *state.Store, requests []materializationSelectionRequest) ([]materializationSelectedUnit, error) {
	if cfg == nil || canonical == nil {
		return nil, errors.New("canonical state is unavailable for materialization planning")
	}
	units := make(map[string]materializationSelectedUnit)
	for _, request := range requests {
		targetSHA, err := materializationTargetSHA256(request.TargetRoot)
		if err != nil {
			return nil, err
		}
		byRepo := make(map[string]config.Repo)
		for _, leaf := range request.Leaves {
			if leaf.repo.Type == "apt" || leaf.repo.Type == "yum" || leaf.repo.Type == "asset" {
				byRepo[leaf.repo.ID] = leaf.repo
			}
		}
		repoIDs := make([]string, 0, len(byRepo))
		for repoID := range byRepo {
			repoIDs = append(repoIDs, repoID)
		}
		sort.Strings(repoIDs)
		for _, repoID := range repoIDs {
			repo := byRepo[repoID]
			switch repo.Type {
			case "asset":
				if !request.IncludeMetadata {
					continue
				}
				ref, commit, exists, err := resolveOptionalMaterializationLeaf(canonical, request.Source, repo.ID, "all", "all")
				if err != nil {
					return nil, err
				}
				if !exists {
					continue
				}
				unit, err := newMaterializationSelectedUnit("asset", request.Source.ID, request.Source.RefCommits != nil, targetSHA, repo.ID, "all", "all", []materializationSelectionRef{{Name: ref, Commit: commit}})
				if err != nil {
					return nil, err
				}
				units[unit.ID] = unit
			case "apt":
				if !request.IncludeMetadata || repo.APT == nil {
					continue
				}
				suiteArches := make(map[string][]string)
				if request.ExpandAPT {
					fullRepo := repo
					if configured, exists := cfg.RepoByName(repo.ID); exists && configured.Type == "apt" && configured.APT != nil {
						fullRepo = configured
					}
					for _, suite := range fullRepo.APT.Suites {
						suiteArches[suite] = append([]string(nil), fullRepo.Arches...)
					}
				} else {
					for _, leaf := range request.Leaves {
						if leaf.repo.ID == repo.ID {
							suiteArches[leaf.os] = append(suiteArches[leaf.os], leaf.arch)
						}
					}
				}
				suites := make([]string, 0, len(suiteArches))
				for suite := range suiteArches {
					suites = append(suites, suite)
				}
				sort.Strings(suites)
				for _, suite := range suites {
					var refs []materializationSelectionRef
					for _, arch := range uniqueSorted(suiteArches[suite]) {
						ref, commit, exists, err := resolveOptionalMaterializationLeaf(canonical, request.Source, repo.ID, suite, arch)
						if err != nil {
							return nil, err
						}
						if exists {
							refs = append(refs, materializationSelectionRef{Name: ref, Commit: commit})
						}
					}
					if len(refs) == 0 {
						continue
					}
					unit, err := newMaterializationSelectedUnit("apt", request.Source.ID, request.Source.RefCommits != nil, targetSHA, repo.ID, suite, "", refs)
					if err != nil {
						return nil, err
					}
					units[unit.ID] = unit
				}
			case "yum":
				for _, leaf := range request.Leaves {
					if leaf.repo.ID != repo.ID {
						continue
					}
					ref, commit, exists, err := resolveOptionalMaterializationLeaf(canonical, request.Source, repo.ID, leaf.os, leaf.arch)
					if err != nil {
						return nil, err
					}
					if !exists {
						continue
					}
					refVector := []materializationSelectionRef{{Name: ref, Commit: commit}}
					for _, kind := range []struct {
						name    string
						include bool
					}{{"yum", request.IncludeMetadata}, {"serving", request.IncludeServing}} {
						if !kind.include {
							continue
						}
						unit, err := newMaterializationSelectedUnit(kind.name, request.Source.ID, request.Source.RefCommits != nil, targetSHA, repo.ID, leaf.os, leaf.arch, refVector)
						if err != nil {
							return nil, err
						}
						units[unit.ID] = unit
					}
					if request.IncludeCompatibility && request.Source.ID == "latest" && !request.Source.Snapshot && request.Source.RefCommits == nil {
						projection, matched, err := config.YUMCompatibilityProjectionForSource(cfg.CompatibilityProjections, repo.ID, request.Source.ID, leaf.os, leaf.arch)
						if err != nil {
							return nil, err
						}
						if matched {
							head, err := canonical.HeadHash()
							if err != nil || head.IsZero() {
								return nil, errors.Join(err, errors.New("canonical HEAD is unavailable for compatibility materialization planning"))
							}
							active, err := publicationYUMCompatibilityActiveAt(canonical, head, projection.ID)
							if err != nil {
								return nil, err
							}
							if !active {
								continue
							}
							admission, err := admitYUMCompatibilityProjection(cfg, canonical, projection)
							if err != nil {
								return nil, err
							}
							compatUnit, err := newMaterializationSelectedUnit("yum-compat", request.Source.ID, true, targetSHA, repo.ID, projection.Source.OS, projection.Source.Arch,
								[]materializationSelectionRef{{Name: admission.sourceRef.String(), Commit: admission.sourceCommit.String()}})
							if err != nil {
								return nil, err
							}
							units[compatUnit.ID] = compatUnit
						}
					}
				}
			}
		}
	}
	result := make([]materializationSelectedUnit, 0, len(units))
	for _, unit := range units {
		result = append(result, unit)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func resolveOptionalMaterializationLeaf(canonical *state.Store, source materializeCanonicalSource, repo, osName, arch string) (string, string, bool, error) {
	ref, _, err := source.leaf(repo, osName, arch)
	if err != nil {
		return "", "", false, err
	}
	if source.RefCommits != nil {
		commit, exists := source.RefCommits[ref.String()]
		if !exists || commit.IsZero() {
			return ref.String(), "", false, nil
		}
		return ref.String(), commit.String(), true, nil
	}
	commit, exists, err := canonical.Ref(ref)
	if err != nil || !exists {
		return ref.String(), "", false, err
	}
	return ref.String(), commit.String(), true, nil
}

func beginMaterializationSelectionForSource(cfg *config.Config, canonical *state.Store, values commonFlags, operation string, source materializeCanonicalSource, leaves []viewLeaf, targetRoot string, includeMetadata, includeServing bool, expandAPT ...bool) (commonFlags, bool, error) {
	expand := len(expandAPT) != 0 && expandAPT[0]
	return beginMaterializationSelectionForRequests(cfg, canonical, values, operation, []materializationSelectionRequest{{
		Source: source, Leaves: leaves, TargetRoot: targetRoot, IncludeMetadata: includeMetadata, IncludeServing: includeServing,
		IncludeCompatibility: operation == "materialize" || operation == "publish", ExpandAPT: expand,
	}})
}

func beginMaterializationSelectionForRequests(cfg *config.Config, canonical *state.Store, values commonFlags, operation string, requests []materializationSelectionRequest) (commonFlags, bool, error) {
	if values.materializeTrust == nil {
		return values, false, nil
	}
	values.materializeTrust.selectionMu.Lock()
	if values.materializeTrust.operationScope == "" {
		values.materializeTrust.operationScope = values.materializeScope
	} else if values.materializeTrust.operationScope != values.materializeScope {
		values.materializeTrust.selectionMu.Unlock()
		return values, false, errors.New("materialization operation scope differs from the frozen coordinator")
	}
	values.materializeTrust.selectionMu.Unlock()
	units, err := planMaterializationSelectedUnits(cfg, canonical, requests)
	if err != nil {
		return values, false, err
	}
	owner, err := beginMaterializationSelectedSet(cfg, canonical, values.materializeTrust, operation, values.recover, units)
	if err != nil {
		return values, false, err
	}
	values.materializeOperation = operation
	if len(requests) == 1 {
		values.materializeSource = requests[0].Source.ID
		values.materializeTarget = requests[0].TargetRoot
	}
	return values, owner, nil
}

func selectedMaterializationOperation(values commonFlags, fallback string) string {
	if values.materializeOperation != "" {
		return values.materializeOperation
	}
	return fallback
}

func materializationTargetSHA256(target string) (string, error) {
	return serving.MaterializedRouteTargetSHA256(target)
}

func newMaterializationSelectedUnit(kind, source string, historical bool, targetSHA256, repo, osName, arch string, refs []materializationSelectionRef) (materializationSelectedUnit, error) {
	unit := materializationSelectedUnit{
		Kind: kind, Source: source, Historical: historical, TargetSHA256: targetSHA256,
		Repo: repo, OS: osName, Arch: arch,
		Refs: append([]materializationSelectionRef(nil), refs...),
	}
	sort.Slice(unit.Refs, func(i, j int) bool { return unit.Refs[i].Name < unit.Refs[j].Name })
	body, err := json.Marshal(struct {
		Kind         string                        `json:"kind"`
		Source       string                        `json:"source"`
		Historical   bool                          `json:"historical,omitempty"`
		TargetSHA256 string                        `json:"target_sha256"`
		Repo         string                        `json:"repo"`
		OS           string                        `json:"os"`
		Arch         string                        `json:"arch"`
		Refs         []materializationSelectionRef `json:"refs"`
	}{unit.Kind, unit.Source, unit.Historical, unit.TargetSHA256, unit.Repo, unit.OS, unit.Arch, unit.Refs})
	if err != nil {
		return materializationSelectedUnit{}, err
	}
	digest := sha256.Sum256(body)
	unit.ID = hex.EncodeToString(digest[:])
	if err := unit.validate(); err != nil {
		return materializationSelectedUnit{}, err
	}
	return unit, nil
}

func (unit materializationSelectedUnit) validate() error {
	if !validMaterializationTrustSHA256(unit.ID) || !materializationUnitKindPattern.MatchString(unit.Kind) || !validMaterializationJournalString(unit.Source, 256) ||
		!validMaterializationTrustSHA256(unit.TargetSHA256) || !validMaterializationJournalString(unit.Repo, 256) || !validMaterializationJournalString(unit.OS, 256) ||
		(unit.Arch != "" && !validMaterializationJournalString(unit.Arch, 256)) || len(unit.Refs) == 0 {
		return errors.New("invalid materialization selected unit envelope")
	}
	previous := ""
	for _, ref := range unit.Refs {
		if !strings.HasPrefix(ref.Name, "refs/sow/") || !validMaterializationJournalString(ref.Name, 1024) || !materializationCommitPattern.MatchString(ref.Commit) || ref.Name <= previous {
			return errors.New("invalid or unsorted materialization selected ref")
		}
		previous = ref.Name
	}
	wanted, err := newMaterializationSelectedUnitWithoutValidation(unit)
	if err != nil || wanted.ID != unit.ID {
		return errors.Join(err, errors.New("materialization selected unit ID mismatch"))
	}
	return nil
}

func newMaterializationSelectedUnitWithoutValidation(unit materializationSelectedUnit) (materializationSelectedUnit, error) {
	body, err := json.Marshal(struct {
		Kind         string                        `json:"kind"`
		Source       string                        `json:"source"`
		Historical   bool                          `json:"historical,omitempty"`
		TargetSHA256 string                        `json:"target_sha256"`
		Repo         string                        `json:"repo"`
		OS           string                        `json:"os"`
		Arch         string                        `json:"arch"`
		Refs         []materializationSelectionRef `json:"refs"`
	}{unit.Kind, unit.Source, unit.Historical, unit.TargetSHA256, unit.Repo, unit.OS, unit.Arch, unit.Refs})
	if err != nil {
		return materializationSelectedUnit{}, err
	}
	digest := sha256.Sum256(body)
	unit.ID = hex.EncodeToString(digest[:])
	return unit, nil
}

func validMaterializationJournalString(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\t\r\n")
}

func materializationSelectionJournalID(journal materializationSelectionJournal) (string, error) {
	body, err := json.Marshal(materializationSelectionIdentity{
		Schema: journal.Schema, Operation: journal.Operation, OperationScope: journal.OperationScope, ConfigSHA256: journal.ConfigSHA256, ParentConfigSHA256: journal.ParentConfigSHA256, ExpectedHead: journal.ExpectedHead, RepositoryKeySHA256: journal.RepositoryKeySHA256,
		YUMKeyrings: journal.YUMKeyrings, ArchiveAdoption: journal.ArchiveAdoption, Units: journal.Units,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func (journal materializationSelectionJournal) validate() error {
	if journal.Schema != materializationSelectionJournalSchema || !materializationOperationPattern.MatchString(journal.Operation) || (journal.OperationScope != "" && !validMaterializationJournalString(journal.OperationScope, 256)) || (journal.Operation == "sync" && journal.OperationScope == "") || !validMaterializationTrustSHA256(journal.ConfigSHA256) || !validMaterializationTrustSHA256(journal.ParentConfigSHA256) || !materializationCommitPattern.MatchString(journal.ExpectedHead) || !validMaterializationTrustSHA256(journal.RepositoryKeySHA256) ||
		(journal.Phase != materializationSelectionPrepared && journal.Phase != materializationSelectionMaterializing && journal.Phase != materializationSelectionDrifted) || len(journal.Units) == 0 {
		return errors.New("invalid materialization selection journal envelope")
	}
	if journal.OperationScope == offlineArchiveAdoptionMaterializationScope {
		if journal.Operation != "materialize" || journal.ArchiveAdoption == nil {
			return errors.New("offline archive adoption journal is missing its exact contract")
		}
		if err := journal.ArchiveAdoption.validate(); err != nil {
			return fmt.Errorf("invalid offline archive adoption journal contract: %w", err)
		}
	} else if journal.ArchiveAdoption != nil {
		return errors.New("offline archive adoption contract is attached to another materialization scope")
	}
	previousRepo := ""
	for _, keyring := range journal.YUMKeyrings {
		if !validMaterializationJournalString(keyring.Repo, 256) || !validMaterializationTrustSHA256(keyring.SHA256) || keyring.Repo <= previousRepo {
			return errors.New("invalid or unsorted materialization selection keyrings")
		}
		previousRepo = keyring.Repo
	}
	unitSet := make(map[string]struct{}, len(journal.Units))
	previousUnit := ""
	for _, unit := range journal.Units {
		if err := unit.validate(); err != nil || unit.ID <= previousUnit {
			return errors.Join(err, errors.New("invalid or unsorted materialization selection units"))
		}
		unitSet[unit.ID] = struct{}{}
		previousUnit = unit.ID
	}
	previousCompleted := ""
	for _, id := range journal.CompletedUnits {
		if _, exists := unitSet[id]; !exists || id <= previousCompleted {
			return errors.New("invalid, duplicate, or unsorted completed materialization unit")
		}
		previousCompleted = id
	}
	wanted, err := materializationSelectionJournalID(journal)
	if err != nil || journal.ID != wanted {
		return errors.Join(err, errors.New("materialization selection journal ID mismatch"))
	}
	return nil
}

func newMaterializationSelectionJournal(operation, configSHA256, parentConfigSHA256, expectedHead string, snapshot *materializationTrustSnapshot, units []materializationSelectedUnit) (materializationSelectionJournal, error) {
	if snapshot == nil {
		return materializationSelectionJournal{}, errors.New("materialization trust snapshot is unavailable")
	}
	journal := materializationSelectionJournal{
		Schema: materializationSelectionJournalSchema, Operation: operation, OperationScope: snapshot.operationScope, Phase: materializationSelectionPrepared,
		ConfigSHA256: configSHA256, ParentConfigSHA256: parentConfigSHA256, ExpectedHead: expectedHead, RepositoryKeySHA256: snapshot.repositoryKeySHA256,
		ArchiveAdoption: cloneOfflineArchiveAdoptionContract(snapshot.archiveAdoption), Units: append([]materializationSelectedUnit(nil), units...),
	}
	for repo, trust := range snapshot.yum {
		journal.YUMKeyrings = append(journal.YUMKeyrings, materializationSelectionKeyring{Repo: repo, SHA256: trust.digest})
	}
	sort.Slice(journal.YUMKeyrings, func(i, j int) bool { return journal.YUMKeyrings[i].Repo < journal.YUMKeyrings[j].Repo })
	sort.Slice(journal.Units, func(i, j int) bool { return journal.Units[i].ID < journal.Units[j].ID })
	journal.ID, _ = materializationSelectionJournalID(journal)
	if err := journal.validate(); err != nil {
		return materializationSelectionJournal{}, err
	}
	return journal, nil
}

func beginMaterializationSelectedSet(cfg *config.Config, canonical *state.Store, snapshot *materializationTrustSnapshot, operation string, recover bool, units []materializationSelectedUnit) (bool, error) {
	if snapshot == nil {
		return false, nil
	}
	if len(units) == 0 {
		return false, errors.New("materialization selected set is empty")
	}
	// Nested materializers must prove that every unit they intend to touch was
	// included in the one durable set written before the first visible flip.
	// They may narrow that set, but can never silently expand or replace it.
	snapshot.selectionMu.Lock()
	var active *materializationSelectedSet
	if snapshot.selection != nil {
		copyJournal := snapshot.selection.journal
		copyUnits := make(map[string]materializationSelectedUnit, len(snapshot.selection.units))
		for id, unit := range snapshot.selection.units {
			copyUnits[id] = unit
		}
		active = &materializationSelectedSet{journal: copyJournal, units: copyUnits}
	}
	snapshot.selectionMu.Unlock()
	if active != nil {
		durable, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
		if err != nil || !exists || durable.ID != active.journal.ID {
			return false, errors.Join(err, errors.New("durable materialization selected set differs from the active coordinator"))
		}
		if durable.Operation != operation || !materializationSnapshotMatchesJournal(snapshot, durable) {
			return false, errors.New("nested materialization operation or frozen trust differs from the durable selected set")
		}
		if err := requireMaterializationJournalCanonicalIdentity(cfg, canonical, durable); err != nil {
			return false, err
		}
		if err := requireMaterializationUnitSubset(units, active.units, false); err != nil {
			return false, err
		}
		return false, nil
	}
	if recover {
		if err := cleanupMaterializationSelectionJournalTemps(cfg.StatePath()); err != nil {
			return false, err
		}
	}
	current, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil {
		return false, err
	}
	if exists {
		if current.Operation != operation {
			return false, fmt.Errorf("incomplete materialization operation %s blocks %s", current.Operation, operation)
		}
		if !recover {
			return false, fmt.Errorf("incomplete materialization operation %s requires retry with --recover", operation)
		}
		if !materializationSnapshotMatchesJournal(snapshot, current) {
			return false, errors.New("materialization recovery frozen trust differs from the durable selected set")
		}
		if err := requireMaterializationJournalCanonicalIdentity(cfg, canonical, current); err != nil {
			return false, err
		}
		durableUnits := make(map[string]materializationSelectedUnit, len(current.Units))
		for _, unit := range current.Units {
			durableUnits[unit.ID] = unit
		}
		if err := requireMaterializationUnitSubset(units, durableUnits, true); err != nil {
			return false, err
		}
	} else {
		configSHA256, parentConfigSHA256, expectedHead, err := currentMaterializationCanonicalIdentity(cfg, canonical)
		if err != nil {
			return false, err
		}
		current, err = newMaterializationSelectionJournal(operation, configSHA256, parentConfigSHA256, expectedHead, snapshot, units)
		if err != nil {
			return false, err
		}
		if err := requireMaterializationJournalCanonicalIdentity(cfg, canonical, current); err != nil {
			return false, err
		}
		if err := writeMaterializationSelectionJournal(cfg.StatePath(), current); err != nil {
			return false, err
		}
	}
	unitIndex := make(map[string]materializationSelectedUnit, len(current.Units))
	completed := make(map[string]struct{}, len(current.CompletedUnits))
	for _, unit := range current.Units {
		unitIndex[unit.ID] = unit
	}
	for _, id := range current.CompletedUnits {
		completed[id] = struct{}{}
	}
	snapshot.selectionMu.Lock()
	defer snapshot.selectionMu.Unlock()
	snapshot.selection = &materializationSelectedSet{journal: current, units: unitIndex}
	snapshot.completedUnits = completed
	snapshot.firstDrift = nil
	return true, nil
}

func currentMaterializationCanonicalIdentity(cfg *config.Config, canonical *state.Store) (string, string, string, error) {
	if cfg == nil || canonical == nil {
		return "", "", "", errors.New("materialization configuration or canonical state is unavailable")
	}
	configSHA256, err := cfg.CanonicalSHA256()
	if err != nil || !validMaterializationTrustSHA256(configSHA256) {
		return "", "", "", errors.Join(err, errors.New("materialization config identity is unavailable"))
	}
	parentConfigSHA256, _, err := canonicalConfigFileIdentity(canonical)
	if err != nil || !validMaterializationTrustSHA256(parentConfigSHA256) {
		return "", "", "", errors.Join(err, errors.New("canonical parent config identity is unavailable"))
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return "", "", "", errors.Join(err, errors.New("canonical HEAD identity is unavailable"))
	}
	return configSHA256, parentConfigSHA256, head.String(), nil
}

func materializationSnapshotMatchesJournal(snapshot *materializationTrustSnapshot, journal materializationSelectionJournal) bool {
	if snapshot == nil || snapshot.operationScope != journal.OperationScope || snapshot.repositoryKeySHA256 != journal.RepositoryKeySHA256 || len(snapshot.yum) != len(journal.YUMKeyrings) ||
		!offlineArchiveAdoptionContractEqual(snapshot.archiveAdoption, journal.ArchiveAdoption) {
		return false
	}
	for _, keyring := range journal.YUMKeyrings {
		trust, exists := snapshot.yum[keyring.Repo]
		if !exists || trust.digest != keyring.SHA256 {
			return false
		}
	}
	return true
}

func requireMaterializationUnitSubset(requested []materializationSelectedUnit, durable map[string]materializationSelectedUnit, exact bool) error {
	if len(requested) == 0 || (exact && len(requested) != len(durable)) {
		return errors.New("materialization recovery unit set differs from the durable selected set")
	}
	seen := make(map[string]struct{}, len(requested))
	for _, unit := range requested {
		if err := unit.validate(); err != nil {
			return err
		}
		if _, duplicate := seen[unit.ID]; duplicate {
			return errors.New("duplicate nested materialization unit")
		}
		seen[unit.ID] = struct{}{}
		if _, exists := durable[unit.ID]; !exists {
			return fmt.Errorf("nested materialization unit %s is absent from the durable selected set", unit.ID)
		}
	}
	return nil
}

// ExpectedHead is the stable pre-flip identity. Derived ledger, baseline, and
// local-serving commits may legally advance HEAD while the state lock and
// active fence make this operation the only writer. Recovery therefore accepts
// only an exact HEAD or its descendant, and independently proves that the
// canonical config and every frozen live ref remain unchanged.
func requireMaterializationJournalCanonicalIdentity(cfg *config.Config, canonical *state.Store, journal materializationSelectionJournal) error {
	configSHA256, canonicalConfigSHA256, currentHead, err := currentMaterializationCanonicalIdentity(cfg, canonical)
	if err != nil {
		return err
	}
	if configSHA256 != journal.ConfigSHA256 {
		return errors.New("materialization configuration changed after intent")
	}
	if canonicalConfigSHA256 != journal.ParentConfigSHA256 && canonicalConfigSHA256 != journal.ConfigSHA256 {
		return errors.New("canonical config is neither the frozen parent nor materialization contract")
	}
	if currentHead != journal.ExpectedHead {
		repository, err := git.PlainOpen(filepath.Join(canonical.StateDir(), "state"))
		if err != nil {
			return fmt.Errorf("open canonical repository for materialization ancestry: %w", err)
		}
		expected, err := repository.CommitObject(plumbing.NewHash(journal.ExpectedHead))
		if err != nil {
			return fmt.Errorf("read materialization expected HEAD: %w", err)
		}
		current, err := repository.CommitObject(plumbing.NewHash(currentHead))
		if err != nil {
			return fmt.Errorf("read current canonical HEAD: %w", err)
		}
		descendant, err := expected.IsAncestor(current)
		if err != nil || !descendant {
			return errors.Join(err, errors.New("canonical HEAD no longer descends from the materialization intent"))
		}
	}
	checked := make(map[string]string)
	for _, unit := range journal.Units {
		for _, frozen := range unit.Refs {
			if previous, exists := checked[frozen.Name]; exists {
				if previous != frozen.Commit {
					return errors.New("materialization journal assigns one ref to multiple commits")
				}
				continue
			}
			checked[frozen.Name] = frozen.Commit
			commit := plumbing.NewHash(frozen.Commit)
			if unit.Historical {
				if _, err := canonical.CommitTime(commit); err != nil {
					return fmt.Errorf("historical materialization commit %s disappeared: %w", frozen.Commit, err)
				}
				continue
			}
			current, exists, err := canonical.Ref(plumbing.ReferenceName(frozen.Name))
			if err != nil || !exists || current != commit {
				return errors.Join(err, fmt.Errorf("materialization ref %s changed from frozen commit %s", frozen.Name, frozen.Commit))
			}
		}
	}
	if journal.ArchiveAdoption != nil {
		if err := requireOfflineArchiveAdoptionContract(cfg, canonical, journal.ArchiveAdoption); err != nil {
			return fmt.Errorf("offline archive adoption canonical proof: %w", err)
		}
	}
	return nil
}

func finishMaterializationSelectedSet(cfg *config.Config, snapshot *materializationTrustSnapshot, owner bool, runErr error) error {
	if snapshot == nil || !owner {
		return nil
	}
	snapshot.selectionMu.Lock()
	if snapshot.selection == nil {
		snapshot.selectionMu.Unlock()
		return errors.New("materialization selected-set coordinator disappeared")
	}
	committed := len(snapshot.completedUnits)
	journal := snapshot.selection.journal
	complete := committed == len(journal.Units)
	if runErr != nil {
		if committed != 0 || journal.Phase != materializationSelectionPrepared {
			snapshot.selectionMu.Unlock()
			return nil
		}
		snapshot.selectionMu.Unlock()
		durable, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
		if err != nil || !exists || durable.ID != journal.ID {
			return errors.Join(err, errors.New("cannot prove an empty prepared materialization fence before abort"))
		}
		if durable.Phase != materializationSelectionPrepared || len(durable.CompletedUnits) != 0 {
			return nil
		}
		if err := removeMaterializationSelectionJournal(cfg.StatePath()); err != nil {
			return fmt.Errorf("abort empty materialization selected set: %w", err)
		}
		snapshot.resetMaterializationSelection()
		return nil
	}
	recordedDrift := snapshot.firstDrift
	snapshot.selectionMu.Unlock()
	if identityErr := requireMaterializationJournalCanonicalIdentity(cfg, state.New(cfg.StatePath()), journal); identityErr != nil {
		return fmt.Errorf("materialization selected-set canonical identity barrier failed: %w", identityErr)
	}
	if recordedDrift == nil {
		// Test-only hooks use this exact boundary to prove that a rotation after
		// every unit completed is still caught by the final selected-set barrier.
		// Production snapshots never install a hook.
		snapshot.runHook(materializeTrustSelectedSetFinal)
		recordedDrift = snapshot.rawRequireAll(cfg, materializeTrustSelectedSetFinal)
	}
	if recordedDrift != nil {
		_ = snapshot.persistMaterializationSelectionPhase(cfg, materializationSelectionDrifted)
		return fmt.Errorf("materialization selected-set trust barrier failed; restore the frozen trust and retry the exact operation with --recover: %w", recordedDrift)
	}
	if !complete {
		return errors.New("materialization selected set did not complete every durable unit; retry the exact operation with --recover")
	}
	if err := removeMaterializationSelectionJournal(cfg.StatePath()); err != nil {
		return fmt.Errorf("clear completed materialization selected set: %w", err)
	}
	snapshot.resetMaterializationSelection()
	return nil
}

func (snapshot *materializationTrustSnapshot) resetMaterializationSelection() {
	snapshot.selectionMu.Lock()
	snapshot.selection = nil
	snapshot.completedUnits = nil
	snapshot.firstDrift = nil
	snapshot.selectionMu.Unlock()
}

func (snapshot *materializationTrustSnapshot) persistMaterializationSelectionPhase(cfg *config.Config, phase materializationSelectionPhase) error {
	if snapshot == nil {
		return nil
	}
	snapshot.selectionMu.Lock()
	defer snapshot.selectionMu.Unlock()
	if snapshot.selection == nil {
		return nil
	}
	snapshot.selection.journal.Phase = phase
	snapshot.selection.journal.CompletedUnits = sortedMaterializationUnitIDs(snapshot.completedUnits)
	return writeMaterializationSelectionJournal(cfg.StatePath(), snapshot.selection.journal)
}

func sortedMaterializationUnitIDs(units map[string]struct{}) []string {
	ids := make([]string, 0, len(units))
	for id := range units {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (snapshot *materializationTrustSnapshot) handleMaterializationTrustResult(cfg *config.Config, unit string, boundary materializationTrustBoundary, trustErr error) error {
	if snapshot == nil {
		return trustErr
	}
	snapshot.selectionMu.Lock()
	defer snapshot.selectionMu.Unlock()
	committedBefore := len(snapshot.completedUnits)
	post := materializationTrustBoundaryCommitsUnit(boundary) && unit != ""
	if trustErr != nil && committedBefore == 0 {
		return trustErr
	}
	if trustErr == nil && snapshot.selection != nil && materializationTrustBoundaryStartsMutation(boundary) {
		if unit != "" {
			if _, exists := snapshot.selection.units[unit]; !exists {
				return fmt.Errorf("materialization unit %s is absent from the durable selected set", unit)
			}
		}
		if snapshot.selection.journal.Phase == materializationSelectionPrepared {
			snapshot.selection.journal.Phase = materializationSelectionMaterializing
			if err := writeMaterializationSelectionJournal(cfg.StatePath(), snapshot.selection.journal); err != nil {
				return fmt.Errorf("persist materialization start before mutation: %w", err)
			}
		}
	}
	if post && snapshot.selection != nil {
		if _, exists := snapshot.selection.units[unit]; !exists {
			return fmt.Errorf("materialization unit %s is absent from the durable selected set", unit)
		}
		if snapshot.completedUnits == nil {
			snapshot.completedUnits = make(map[string]struct{})
		}
		snapshot.completedUnits[unit] = struct{}{}
		snapshot.selection.journal.CompletedUnits = sortedMaterializationUnitIDs(snapshot.completedUnits)
		if trustErr != nil {
			snapshot.selection.journal.Phase = materializationSelectionDrifted
		} else {
			snapshot.selection.journal.Phase = materializationSelectionMaterializing
		}
		if err := writeMaterializationSelectionJournal(cfg.StatePath(), snapshot.selection.journal); err != nil {
			if snapshot.firstDrift == nil {
				snapshot.firstDrift = fmt.Errorf("persist completed materialization unit: %w", err)
			}
			// The unit is already live. Continue under the frozen trust so later
			// units converge; the final barrier will retain the prepared fence.
			return nil
		}
	}
	if trustErr != nil {
		if snapshot.firstDrift == nil {
			snapshot.firstDrift = trustErr
		}
		if snapshot.selection != nil {
			snapshot.selection.journal.Phase = materializationSelectionDrifted
			_ = writeMaterializationSelectionJournal(cfg.StatePath(), snapshot.selection.journal)
		}
		// Once one directly-hostable unit has crossed its post-boundary, a
		// trust change cannot safely abort into a mixed selected set. Every
		// remaining unit continues with the frozen key material and the final
		// barrier deliberately fails closed.
		return nil
	}
	return nil
}

func materializationTrustBoundaryCommitsUnit(boundary materializationTrustBoundary) bool {
	switch boundary {
	case materializeTrustAPTCommitAfter, materializeTrustYUMActivationAfter, materializeTrustServingPointerAfter, materializeTrustServingRestoreAfter:
		return true
	default:
		return false
	}
}

func materializationTrustBoundaryStartsMutation(boundary materializationTrustBoundary) bool {
	switch boundary {
	case materializeTrustPayloadBefore, materializeTrustAPTCommitBefore, materializeTrustYUMActivationBefore,
		materializeTrustExactReconcileBefore, materializeTrustServingPublishBefore, materializeTrustServingActivateBefore,
		materializeTrustServingLeafBefore, materializeTrustServingPointerBefore, materializeTrustServingRestoreBefore:
		return true
	default:
		return false
	}
}

func markMaterializationUnitComplete(values commonFlags, cfg *config.Config) error {
	if values.materializeTrust == nil || values.materializeUnit == "" {
		return nil
	}
	return values.materializeTrust.handleMaterializationTrustResult(cfg, values.materializeUnit, materializeTrustServingRestoreAfter, nil)
}

func materializationUnitFor(values commonFlags, kind, source, repo, osName, arch, target string) (string, error) {
	if values.materializeTrust == nil {
		return "", nil
	}
	targetSHA, err := materializationTargetSHA256(target)
	if err != nil {
		return "", err
	}
	values.materializeTrust.selectionMu.Lock()
	defer values.materializeTrust.selectionMu.Unlock()
	if values.materializeTrust.selection == nil {
		return "", nil
	}
	for id, unit := range values.materializeTrust.selection.units {
		if unit.Kind == kind && unit.Source == source && unit.TargetSHA256 == targetSHA && unit.Repo == repo && unit.OS == osName && unit.Arch == arch {
			return id, nil
		}
	}
	return "", fmt.Errorf("materialization %s unit %s/%s/%s/%s is absent from the durable selected set", kind, source, repo, osName, arch)
}

func requireNoForeignMaterializationIntent(cfg *config.Config, operation string, recover bool) error {
	if cfg == nil || !materializationOperationPattern.MatchString(operation) {
		return errors.New("invalid materialization operation fence request")
	}
	if recover {
		if err := cleanupMaterializationSelectionJournalTemps(cfg.StatePath()); err != nil {
			return err
		}
	}
	if err := cleanupAssetProjectionIntentResidue(cfg.StatePath(), recover); err != nil {
		return err
	}
	if err := cleanupPackageProjectionIntentResidue(cfg.StatePath(), recover); err != nil {
		return err
	}
	if err := cleanupOfflineArchiveProjectionResidue(cfg.StatePath(), recover); err != nil {
		return err
	}
	projection, projectionExists, err := readAssetProjectionIntent(cfg.StatePath())
	if err != nil {
		return err
	}
	if projectionExists {
		if projection.Operation != operation {
			return fmt.Errorf("pending asset projection %s blocks %s", projection.Operation, operation)
		}
		if !recover {
			return fmt.Errorf("pending asset projection %s requires retry with --recover", operation)
		}
	}
	packageProjection, packageProjectionExists, err := readPackageProjectionIntent(cfg.StatePath())
	if err != nil {
		return err
	}
	if packageProjectionExists && projectionExists {
		return errors.New("simultaneous pending asset and package projections require manual inspection")
	}
	if packageProjectionExists {
		if packageProjection.Operation != operation {
			return fmt.Errorf("pending package projection %s blocks %s", packageProjection.Operation, operation)
		}
		if !recover {
			return fmt.Errorf("pending package projection %s requires retry with --recover", operation)
		}
	}
	archiveProjection, archiveProjectionExists, err := readOfflineArchiveProjectionIntent(cfg.StatePath())
	if err != nil {
		return err
	}
	if packageProjectionExists && archiveProjectionExists {
		return errors.New("simultaneous pending package and offline archive projections require manual inspection")
	}
	exactArchiveAssetPair := false
	if projectionExists && archiveProjectionExists {
		exactArchiveAssetPair = projection.Operation == "materialize" && projection.OperationScope == offlineArchiveAdoptionMaterializationScope &&
			archiveProjection.ArchiveAdoption != nil && offlineArchiveAdoptionContractEqual(projection.ArchiveAdoption, archiveProjection.ArchiveAdoption)
		if !exactArchiveAssetPair {
			return errors.New("simultaneous pending asset and offline archive projections do not share one exact adoption contract")
		}
	}
	activeProjectionIntents := 0
	if projectionExists {
		activeProjectionIntents++
	}
	if packageProjectionExists {
		activeProjectionIntents++
	}
	if archiveProjectionExists {
		activeProjectionIntents++
	}
	if activeProjectionIntents > 1 && !exactArchiveAssetPair {
		return errors.New("simultaneous pending asset, package, or offline archive projections require manual inspection")
	}
	if archiveProjectionExists {
		if operation != "materialize" {
			return fmt.Errorf("pending offline archive projection %s blocks %s", archiveProjection.TransactionID, operation)
		}
		if !recover {
			return errors.New("pending offline archive projection requires materialize --recover")
		}
	}
	journal, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists {
		return err
	}
	if journal.Operation != operation {
		return fmt.Errorf("incomplete materialization operation %s blocks %s", journal.Operation, operation)
	}
	if !recover {
		return fmt.Errorf("incomplete materialization operation %s requires retry with --recover", operation)
	}
	if archiveProjectionExists {
		if archiveProjection.ArchiveAdoption == nil || journal.OperationScope != offlineArchiveAdoptionMaterializationScope ||
			!offlineArchiveAdoptionContractEqual(journal.ArchiveAdoption, archiveProjection.ArchiveAdoption) {
			return errors.New("offline archive projection and selected-set journal do not share one exact adoption contract")
		}
	}
	if projectionExists && (projection.ArchiveAdoption != nil || journal.ArchiveAdoption != nil) &&
		!offlineArchiveAdoptionContractEqual(projection.ArchiveAdoption, journal.ArchiveAdoption) {
		return errors.New("asset projection and selected-set journal do not share one exact adoption contract")
	}
	return nil
}

// Same-operation --recover is only a preliminary admission at lock time. Any
// command that would create a new canonical business commit before exact
// selected-set begin must call this stricter guard immediately before Apply.
func requireNoMaterializationIntentBeforeCanonicalMutation(cfg *config.Config) error {
	if _, exists, err := readAssetProjectionIntent(cfg.StatePath()); err != nil || exists {
		if err != nil {
			return err
		}
		return errors.New("durable materialization intent: asset projection must be recovered before a new canonical mutation")
	}
	if _, exists, err := readPackageProjectionIntent(cfg.StatePath()); err != nil || exists {
		if err != nil {
			return err
		}
		return errors.New("durable materialization intent: package projection must be recovered before a new canonical mutation")
	}
	if _, exists, err := readOfflineArchiveProjectionIntent(cfg.StatePath()); err != nil || exists {
		if err != nil {
			return err
		}
		return errors.New("durable materialization intent: offline archive projection must be recovered before a new canonical mutation")
	}
	_, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists {
		return err
	}
	return errors.New("durable materialization intent must be recovered before a new canonical mutation")
}

// An offline archive adoption is the sole canonical-mutation exception: its
// outer archive intent deliberately remains live while the exact asset bridge
// is created. Every other durable bridge must still be absent.
func requireOfflineArchiveAdoptionOwnerBeforeCanonicalMutation(cfg *config.Config, contract *offlineArchiveAdoptionContract) error {
	if cfg == nil || contract == nil {
		return errors.New("offline archive adoption canonical mutation owner is unavailable")
	}
	if _, exists, err := readAssetProjectionIntent(cfg.StatePath()); err != nil || exists {
		if err != nil {
			return err
		}
		return errors.New("durable materialization intent: asset projection must be recovered before offline archive adoption")
	}
	if _, exists, err := readPackageProjectionIntent(cfg.StatePath()); err != nil || exists {
		if err != nil {
			return err
		}
		return errors.New("durable materialization intent: package projection blocks offline archive adoption")
	}
	intent, exists, err := readOfflineArchiveProjectionIntent(cfg.StatePath())
	if err != nil || !exists || intent.ArchiveAdoption == nil || !offlineArchiveAdoptionContractEqual(intent.ArchiveAdoption, contract) {
		return errors.Join(err, errors.New("offline archive adoption canonical mutation lacks its exact durable archive owner"))
	}
	if _, exists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || exists {
		if err != nil {
			return err
		}
		return errors.New("durable selected-set journal must be recovered before offline archive adoption canonical mutation")
	}
	return nil
}

func writeMaterializationSelectionJournal(stateRoot string, journal materializationSelectionJournal) error {
	if err := journal.validate(); err != nil {
		return err
	}
	// Create and fsync the dedicated directory explicitly. The generic atomic
	// writer fsyncs the leaf directory after rename, but cannot know that a new
	// directory entry itself must first be made durable in the .sow parent.
	if _, _, err := materializationSelectionJournalDirectory(stateRoot, true); err != nil {
		return err
	}
	body, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	if len(body) > materializationSelectionJournalMaxBytes {
		return errors.New("materialization selection journal exceeds its size limit")
	}
	return writeDerivedStateFile(stateRoot, filepath.FromSlash(materializationSelectionJournalRelative), body)
}

func readMaterializationSelectionJournal(stateRoot string) (materializationSelectionJournal, bool, error) {
	var journal materializationSelectionJournal
	directory, exists, err := materializationSelectionJournalDirectory(stateRoot, false)
	if err != nil || !exists {
		return journal, false, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return journal, false, err
	}
	active := false
	for _, entry := range entries {
		if entry.Name() == "active.json" {
			active = true
			continue
		}
		if materializationJournalTempPattern.MatchString(entry.Name()) {
			return journal, false, errors.New("interrupted materialization journal write requires --recover")
		}
		return journal, false, fmt.Errorf("unsafe materialization journal entry %q", entry.Name())
	}
	if !active {
		return journal, false, nil
	}
	activeInfo, err := os.Lstat(filepath.Join(directory, "active.json"))
	if err != nil || !activeInfo.Mode().IsRegular() || activeInfo.Mode()&os.ModeSymlink != 0 || activeInfo.Mode().Perm()&0o077 != 0 {
		return journal, false, errors.Join(err, errors.New("materialization selection journal is not a private exact regular file"))
	}
	body, err := readBoundedExactRegularFile(directory, "active.json", materializationSelectionJournalMaxBytes)
	if err != nil {
		return journal, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return journal, false, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return journal, false, errors.New("materialization selection journal has trailing JSON")
	}
	if err := journal.validate(); err != nil {
		return journal, false, err
	}
	return journal, true, nil
}

func removeMaterializationSelectionJournal(stateRoot string) error {
	directory, exists, err := materializationSelectionJournalDirectory(stateRoot, false)
	if err != nil || !exists {
		return errors.Join(err, errors.New("materialization journal directory is missing"))
	}
	filename := filepath.Join(directory, "active.json")
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.Join(err, errors.New("materialization journal is not an exact regular file"))
	}
	if err := os.Remove(filename); err != nil {
		return err
	}
	return syncLocalDirectory(directory)
}

func cleanupMaterializationSelectionJournalTemps(stateRoot string) error {
	directory, exists, err := materializationSelectionJournalDirectory(stateRoot, false)
	if err != nil || !exists {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !materializationJournalTempPattern.MatchString(entry.Name()) {
			continue
		}
		info, err := os.Lstat(filepath.Join(directory, entry.Name()))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > materializationSelectionJournalMaxBytes {
			return errors.Join(err, fmt.Errorf("unsafe materialization journal temporary %q", entry.Name()))
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return syncLocalDirectory(directory)
	}
	return nil
}

func materializationSelectionJournalDirectory(stateRoot string, create bool) (string, bool, error) {
	stateAbs, err := filepath.Abs(stateRoot)
	if err != nil {
		return "", false, err
	}
	stateInfo, err := os.Lstat(stateAbs)
	if errors.Is(err, os.ErrNotExist) && !create {
		return filepath.Join(stateAbs, "materialization-journal"), false, nil
	}
	if err != nil || !stateInfo.IsDir() || stateInfo.Mode()&os.ModeSymlink != 0 {
		return "", false, errors.Join(err, errors.New("state root is not a real directory"))
	}
	root, err := os.OpenRoot(stateAbs)
	if err != nil {
		return "", false, err
	}
	defer root.Close()
	const relative = "materialization-journal"
	info, err := root.Lstat(relative)
	created := false
	if errors.Is(err, os.ErrNotExist) && !create {
		return filepath.Join(stateAbs, relative), false, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(relative, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", false, err
		}
		created = true
		info, err = root.Lstat(relative)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", false, errors.Join(err, errors.New("materialization journal parent is not a real directory"))
	}
	if created {
		// Persist the directory entry itself before a fence can be relied on.
		// writeDerivedStateFile subsequently fsyncs the leaf directory after
		// installing active.json; both levels are required for crash durability.
		stateDirectory, syncErr := os.Open(stateAbs)
		if syncErr != nil {
			return "", false, syncErr
		}
		if syncErr = errors.Join(stateDirectory.Sync(), stateDirectory.Close()); syncErr != nil {
			return "", false, syncErr
		}
	}
	return filepath.Join(stateAbs, relative), true, nil
}
