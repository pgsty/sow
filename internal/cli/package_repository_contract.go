package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

// validateCanonicalPackageRepositoryContracts freezes the physical package
// repository contract after any canonical manifest, view, snapshot, or local
// YUM generation has owned bytes. The audit is deliberately local/read-only
// and walks aggregate HEAD plus every refs/sow/* preservation root. Git graph
// ancestry, rather than author/committer time, defines continuity.
func validateCanonicalPackageRepositoryContracts(cfg *config.Config) error {
	if cfg == nil || cfg.Root == "" {
		return errors.New("cannot validate package repository contract without a rooted config")
	}
	graph, err := loadReachablePackageRepositoryHistory(state.New(cfg.StatePath()))
	if err != nil {
		return fmt.Errorf("audit historical package repository ownership: %w", err)
	}
	if graph == nil || len(graph.order) == 0 {
		return nil
	}

	owners := make(map[string][]packageRepositoryOwner)
	roots := make(map[string]packageRepositoryOwner)
	for _, commit := range graph.order {
		committed, err := graph.configAt(commit)
		if err != nil {
			return fmt.Errorf("decode historical package repository config at %s: %w", commit, err)
		}
		packages := packageRepositoriesByID(committed)
		repoIDs := sortedPackageEvidenceIDs(graph.evidence[commit])
		for _, repoID := range repoIDs {
			repo, exists := packages[repoID]
			if !exists {
				return fmt.Errorf("package repository ownership evidence %s names repo %s without an APT/YUM config", graph.evidence[commit][repoID], repoID)
			}
			if !repo.IsActive() && !isYUMCompatibilityCarrier(repo) {
				return fmt.Errorf("package repository %s is populated at %s and therefore may not set active=false", repoID, graph.evidence[commit][repoID])
			}
			owner := packageRepositoryOwner{commit: commit, repo: detachHistoricalRepository(repo), location: graph.evidence[commit][repoID]}
			owners[repoID] = retainPackageRepositoryImmutableContract(owners[repoID], owner)
			root := canonicalPackageRepositoryRoot(repo.Path)
			if prior, exists := roots[root]; exists && prior.repo.ID != repo.ID {
				return fmt.Errorf("package repository root %s has populated ownership by both %s at %s and %s at %s; an explicit physical migration is required", root, prior.repo.ID, prior.location, repo.ID, owner.location)
			}
			roots[root] = owner
		}
	}

	currentByID := repositoriesByID(cfg)
	currentPackages := packageRepositoriesByID(cfg)
	for root, owner := range roots {
		for _, candidate := range cfg.Repos {
			if candidate.ID != owner.repo.ID && canonicalPackageRepositoryRoot(candidate.Path) == root {
				return fmt.Errorf("package repository root %s historically owned by %s at %s cannot be reused by repo %s; an explicit physical migration is required", root, owner.repo.ID, owner.location, candidate.ID)
			}
		}
	}

	repoIDs := make([]string, 0, len(owners))
	for repoID := range owners {
		repoIDs = append(repoIDs, repoID)
	}
	sort.Strings(repoIDs)
	for _, repoID := range repoIDs {
		records := owners[repoID]
		baseline := records[0]
		for _, record := range records[1:] {
			if field := packageRepositoryImmutableDifference(baseline.repo, record.repo); field != "" {
				return fmt.Errorf("historical package repository %s %s contract differs between %s and %s; an explicit physical migration is required", repoID, field, baseline.location, record.location)
			}
		}
	}
	lineages, err := auditPackageRepositoryLineages(graph, repoIDs, owners)
	if err != nil {
		return fmt.Errorf("audit package repository lineage: %w", err)
	}
	for _, repoID := range repoIDs {
		baseline := owners[repoID][0]
		lineage := lineages[repoID]
		findings := lineage.findings
		if len(findings) != 0 {
			sort.Slice(findings, func(i, j int) bool {
				if findings[i].priority == findings[j].priority {
					return findings[i].message < findings[j].message
				}
				return findings[i].priority < findings[j].priority
			})
			return errors.New(findings[0].message)
		}

		current, exists := currentByID[repoID]
		if !exists {
			return fmt.Errorf("populated package repository %s cannot be removed from current config; ownership is frozen at %s", repoID, baseline.location)
		}
		if field := packageRepositoryImmutableDifference(baseline.repo, current); field != "" {
			return fmt.Errorf("package repository %s %s contract is frozen by %s; an explicit physical migration is required", repoID, field, baseline.location)
		}
		if !current.IsActive() && !isYUMCompatibilityCarrier(current) {
			return fmt.Errorf("package repository %s is populated at %s and therefore may not set active=false", repoID, baseline.location)
		}
		if field := packageRepositoryLifecycleDifference(baseline.repo, current); field != "" {
			return fmt.Errorf("package repository %s %s may only transition active to frozen; ownership is frozen at %s", repoID, field, baseline.location)
		}
		if field := lineage.lifecycle.rejectCurrent(current); field != "" {
			return fmt.Errorf("package repository %s %s was frozen in reachable canonical history and cannot be reactivated", repoID, field)
		}
		if _, packageTyped := currentPackages[repoID]; !packageTyped {
			return fmt.Errorf("package repository %s type is frozen at %s", repoID, baseline.location)
		}
	}
	return nil
}

func hasPackageRepositoryImmutableContract(records []packageRepositoryOwner, candidate config.Repo) bool {
	for _, record := range records {
		if packageRepositoryImmutableDifference(record.repo, candidate) == "" {
			return true
		}
	}
	return false
}

func retainPackageRepositoryImmutableContract(records []packageRepositoryOwner, candidate packageRepositoryOwner) []packageRepositoryOwner {
	if hasPackageRepositoryImmutableContract(records, candidate.repo) || len(records) >= 2 {
		return records
	}
	return append(records, candidate)
}

func isYUMCompatibilityCarrier(repo config.Repo) bool {
	return repo.Type == "yum" && repo.YUM != nil && repo.YUM.CompatibilityCarrier
}

type packageRepositoryOwner struct {
	commit   plumbing.Hash
	repo     config.Repo
	location string
}

type packageRepositoryFinding struct {
	priority int
	message  string
}

type packageRepositoryLifecycleState struct {
	osFrozen    bool
	suiteFrozen map[string]bool
}

func (s packageRepositoryLifecycleState) copy() packageRepositoryLifecycleState {
	result := packageRepositoryLifecycleState{osFrozen: s.osFrozen}
	if len(s.suiteFrozen) != 0 {
		result.suiteFrozen = make(map[string]bool, len(s.suiteFrozen))
		for suite, frozen := range s.suiteFrozen {
			result.suiteFrozen[suite] = frozen
		}
	}
	return result
}

func (s *packageRepositoryLifecycleState) merge(other packageRepositoryLifecycleState) {
	s.osFrozen = s.osFrozen || other.osFrozen
	if len(other.suiteFrozen) == 0 {
		return
	}
	if s.suiteFrozen == nil {
		s.suiteFrozen = make(map[string]bool, len(other.suiteFrozen))
	}
	for suite, frozen := range other.suiteFrozen {
		s.suiteFrozen[suite] = s.suiteFrozen[suite] || frozen
	}
}

func (s *packageRepositoryLifecycleState) observe(repo config.Repo) {
	if repo.OS.Lifecycle == "frozen" {
		s.osFrozen = true
	}
	if repo.Type != "apt" || repo.APT == nil {
		return
	}
	if s.suiteFrozen == nil {
		s.suiteFrozen = make(map[string]bool, len(repo.APT.Suites))
	}
	for _, suite := range repo.APT.Suites {
		if repo.LifecycleForSuite(suite) == "frozen" {
			s.suiteFrozen[suite] = true
		}
	}
}

func (s packageRepositoryLifecycleState) rejectCurrent(repo config.Repo) string {
	if s.osFrozen && repo.OS.Lifecycle != "frozen" {
		return "os.lifecycle"
	}
	if repo.Type == "apt" && repo.APT != nil {
		for _, suite := range repo.APT.Suites {
			if s.suiteFrozen[suite] && repo.LifecycleForSuite(suite) != "frozen" {
				return "apt.suite_lifecycle[" + suite + "]"
			}
		}
	}
	return ""
}

type packageRepositoryLineageState struct {
	owned     bool
	removed   bool
	lifecycle packageRepositoryLifecycleState
}

type packageRepositoryLineageAudit struct {
	findings  []packageRepositoryFinding
	lifecycle packageRepositoryLifecycleState
}

func (a *packageRepositoryLineageAudit) addFinding(candidate packageRepositoryFinding) {
	if a == nil {
		return
	}
	if len(a.findings) == 0 || candidate.priority < a.findings[0].priority ||
		(candidate.priority == a.findings[0].priority && candidate.message < a.findings[0].message) {
		a.findings = []packageRepositoryFinding{candidate}
	}
}

// auditPackageRepositoryLineages propagates every populated repository through
// the Git DAG in one parents-first config pass. Frontier states are released
// after their last child consumes them, so a linear history retains one commit
// state rather than commit×repo history. Most importantly, each config blob is
// decoded at most once in this phase regardless of repository count.
func auditPackageRepositoryLineages(graph *packageRepositoryHistory, repoIDs []string, owners map[string][]packageRepositoryOwner) (map[string]*packageRepositoryLineageAudit, error) {
	results := make(map[string]*packageRepositoryLineageAudit, len(repoIDs))
	for _, repoID := range repoIDs {
		results[repoID] = &packageRepositoryLineageAudit{}
	}
	remainingChildren := make(map[plumbing.Hash]int, len(graph.order))
	for _, hash := range graph.order {
		for _, parent := range graph.commits[hash].ParentHashes {
			remainingChildren[parent]++
		}
	}
	states := make(map[plumbing.Hash][]packageRepositoryLineageState)
	for _, hash := range graph.order {
		commit := graph.commits[hash]
		committed, err := graph.configAt(hash)
		if err != nil {
			return nil, fmt.Errorf("decode config/sow.yaml at %s: %w", hash, err)
		}
		committedByID := repositoriesByID(committed)
		rootOwners := make(map[string][]string)
		for _, repo := range committed.Repos {
			root := canonicalPackageRepositoryRoot(repo.Path)
			rootOwners[root] = append(rootOwners[root], repo.ID)
		}
		currentStates := make([]packageRepositoryLineageState, len(repoIDs))
		for index, repoID := range repoIDs {
			owner := owners[repoID][0]
			var lineage packageRepositoryLineageState
			for _, parent := range commit.ParentHashes {
				parentStates := states[parent]
				if len(parentStates) != len(repoIDs) {
					return nil, fmt.Errorf("canonical parent %s lineage state is unavailable at child %s", parent, hash)
				}
				prior := parentStates[index]
				lineage.owned = lineage.owned || prior.owned
				lineage.removed = lineage.removed || prior.removed
				lineage.lifecycle.merge(prior.lifecycle)
			}
			if _, establishes := graph.evidence[hash][repoID]; establishes {
				lineage.owned = true
			}
			if lineage.owned {
				location := hash.String() + ":config/sow.yaml"
				root := canonicalPackageRepositoryRoot(owner.repo.Path)
				for _, otherID := range rootOwners[root] {
					if otherID == repoID {
						continue
					}
					results[repoID].addFinding(packageRepositoryFinding{priority: 0, message: fmt.Sprintf("package repository root %s owned by %s at %s was reused by repo %s at %s", root, repoID, owner.location, otherID, location)})
				}
				candidate, exists := committedByID[repoID]
				if !exists {
					lineage.removed = true
					results[repoID].addFinding(packageRepositoryFinding{priority: 30, message: fmt.Sprintf("populated package repository %s owned at %s was removed at %s", repoID, owner.location, location)})
				} else {
					if lineage.removed {
						results[repoID].addFinding(packageRepositoryFinding{priority: 10, message: fmt.Sprintf("populated package repository %s owned at %s was removed and later reintroduced at %s", repoID, owner.location, location)})
					}
					if field := packageRepositoryImmutableDifference(owner.repo, candidate); field != "" {
						results[repoID].addFinding(packageRepositoryFinding{priority: 20, message: fmt.Sprintf("historical package repository %s %s contract owned at %s changed at %s", repoID, field, owner.location, location)})
					}
					if !candidate.IsActive() && !isYUMCompatibilityCarrier(candidate) {
						results[repoID].addFinding(packageRepositoryFinding{priority: 20, message: fmt.Sprintf("populated package repository %s was deactivated at %s", repoID, location)})
					}
					if candidate.Type == owner.repo.Type {
						if field := lineage.lifecycle.rejectCurrent(candidate); field != "" {
							results[repoID].addFinding(packageRepositoryFinding{priority: 15, message: fmt.Sprintf("historical package repository %s %s changed from frozen back to active at %s", repoID, field, location)})
						}
						if field := packageRepositoryLifecycleDifference(owner.repo, candidate); field != "" {
							results[repoID].addFinding(packageRepositoryFinding{priority: 15, message: fmt.Sprintf("historical package repository %s %s violates the active-to-frozen lifecycle contract at %s", repoID, field, location)})
						}
						lineage.lifecycle.observe(candidate)
					}
				}
				results[repoID].lifecycle.merge(lineage.lifecycle)
			}
			currentStates[index] = lineage
		}
		if remainingChildren[hash] != 0 {
			states[hash] = currentStates
		}
		for _, parent := range commit.ParentHashes {
			remainingChildren[parent]--
			if remainingChildren[parent] == 0 {
				delete(states, parent)
			}
		}
	}
	return results, nil
}

func packageRepositoriesByID(cfg *config.Config) map[string]config.Repo {
	result := make(map[string]config.Repo)
	if cfg == nil {
		return result
	}
	for _, repo := range cfg.Repos {
		if repo.Type == "apt" || repo.Type == "yum" {
			result[repo.ID] = repo
		}
	}
	return result
}

func repositoriesByID(cfg *config.Config) map[string]config.Repo {
	result := make(map[string]config.Repo)
	if cfg == nil {
		return result
	}
	for _, repo := range cfg.Repos {
		result[repo.ID] = repo
	}
	return result
}

func packageRepositoryImmutableDifference(owned, candidate config.Repo) string {
	if owned.ID != candidate.ID {
		return "id"
	}
	if owned.Type != candidate.Type {
		return "type"
	}
	if owned.Type != "apt" && owned.Type != "yum" {
		return "type"
	}
	if canonicalPackageRepositoryRoot(owned.Path) != canonicalPackageRepositoryRoot(candidate.Path) {
		return "path"
	}
	if owned.DefaultPool != candidate.DefaultPool {
		return "default_pool"
	}
	if !samePackageRepositoryStringSet(owned.Include, candidate.Include) {
		return "include"
	}
	if !samePackageRepositoryStringSet(owned.Exclude, candidate.Exclude) {
		return "exclude"
	}
	if owned.OS.Family != candidate.OS.Family {
		return "os.family"
	}
	if owned.OS.Major != candidate.OS.Major {
		return "os.major"
	}
	if owned.OS.Suite != candidate.OS.Suite {
		return "os.suite"
	}
	if owned.PublishesToTarget("cf") != candidate.PublishesToTarget("cf") || owned.PublishesToTarget("cos") != candidate.PublishesToTarget("cos") {
		return "publish_targets"
	}
	if !samePackageRepositoryStringSet(owned.Arches, candidate.Arches) {
		return "arches"
	}
	switch owned.Type {
	case "apt":
		if owned.APT == nil || candidate.APT == nil {
			return "apt"
		}
		if !samePackageRepositoryStringSet(owned.APT.Suites, candidate.APT.Suites) {
			return "apt.suites"
		}
		for _, suite := range owned.APT.Suites {
			if !samePackageRepositoryStringSet(owned.APT.ComponentsForSuite(suite), candidate.APT.ComponentsForSuite(suite)) {
				return "apt.suite_components[" + suite + "]"
			}
		}
	case "yum":
		if owned.YUM == nil || candidate.YUM == nil {
			return "yum"
		}
		if owned.YUM.Compression != candidate.YUM.Compression {
			return "yum.compression"
		}
		if owned.YUM.NoarchMode != candidate.YUM.NoarchMode {
			return "yum.noarch_mode"
		}
		if owned.YUM.CompatibilityCarrier != candidate.YUM.CompatibilityCarrier {
			return "yum.compatibility_carrier"
		}
		// package_keyring is intentionally excluded. Rotation is admitted here;
		// the package-trust snapshot and publication saga gates bind each use.
	}
	return ""
}

func packageRepositoryLifecycleDifference(owned, candidate config.Repo) string {
	if !packageLifecycleMayAdvance(owned.OS.Lifecycle, candidate.OS.Lifecycle) {
		return "os.lifecycle"
	}
	if owned.Type == "apt" && owned.APT != nil && candidate.APT != nil {
		for _, suite := range owned.APT.Suites {
			if !packageLifecycleMayAdvance(owned.LifecycleForSuite(suite), candidate.LifecycleForSuite(suite)) {
				return "apt.suite_lifecycle[" + suite + "]"
			}
		}
	}
	return ""
}

func packageLifecycleMayAdvance(owned, candidate string) bool {
	return owned == candidate || (owned == "active" && candidate == "frozen")
}

func samePackageRepositoryStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	values := make(map[string]int, len(left))
	for _, value := range left {
		values[value]++
	}
	for _, value := range right {
		if values[value] == 0 {
			return false
		}
		values[value]--
	}
	return true
}

func canonicalPackageRepositoryRoot(value string) string {
	return path.Clean(filepath.ToSlash(value))
}

func sortedPackageEvidenceIDs(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

type packageRepositoryHistory struct {
	repository       *git.Repository
	commits          map[plumbing.Hash]*object.Commit
	order            []plumbing.Hash
	configIdentities map[plumbing.Hash]state.BlobIdentity
	configCache      *historicalConfigCache
	evidence         map[plumbing.Hash]map[string]string
}

func (g *packageRepositoryHistory) configAt(hash plumbing.Hash) (*config.Config, error) {
	if g == nil || g.repository == nil || g.configCache == nil {
		return nil, errors.New("package repository history config index is unavailable")
	}
	identity, exists := g.configIdentities[hash]
	if !exists {
		return nil, fmt.Errorf("reachable canonical commit %s is missing a config blob identity", hash)
	}
	committed, err := g.configCache.get(identity, func() ([]byte, error) {
		return readHistoricalConfigBlob(g.repository, identity)
	})
	if err != nil {
		return nil, fmt.Errorf("blob %s: %w", identity.Hash, err)
	}
	return committed, nil
}

func loadReachablePackageRepositoryHistory(canonical *state.Store) (*packageRepositoryHistory, error) {
	if canonical == nil || canonical.StateDir() == "" {
		return nil, errors.New("canonical state path is unavailable")
	}
	repositoryPath := filepath.Join(canonical.StateDir(), "state")
	repository, err := git.PlainOpen(repositoryPath)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		if _, metadataErr := os.Lstat(filepath.Join(repositoryPath, ".git")); errors.Is(metadataErr, os.ErrNotExist) {
			return nil, nil
		} else if metadataErr != nil {
			return nil, metadataErr
		}
		return nil, fmt.Errorf("open canonical Git metadata: %w", err)
	}
	if err != nil {
		return nil, err
	}
	graph := &packageRepositoryHistory{
		repository:       repository,
		commits:          make(map[plumbing.Hash]*object.Commit),
		configIdentities: make(map[plumbing.Hash]state.BlobIdentity),
		configCache:      newHistoricalConfigCache(),
		evidence:         make(map[plumbing.Hash]map[string]string),
	}
	roots, err := packageRepositoryHistoryRoots(repository)
	if err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		return graph, nil
	}
	visiting := make(map[plumbing.Hash]bool)
	visited := make(map[plumbing.Hash]bool)
	var visit func(plumbing.Hash) error
	visit = func(hash plumbing.Hash) error {
		if visited[hash] {
			return nil
		}
		if visiting[hash] {
			return fmt.Errorf("canonical commit graph contains a parent cycle at %s", hash)
		}
		visiting[hash] = true
		commit, err := repository.CommitObject(hash)
		if err != nil {
			return fmt.Errorf("open reachable canonical commit %s: %w", hash, err)
		}
		parents := append([]plumbing.Hash(nil), commit.ParentHashes...)
		sort.Slice(parents, func(i, j int) bool { return parents[i].String() < parents[j].String() })
		for _, parent := range parents {
			if err := visit(parent); err != nil {
				return err
			}
		}
		delete(visiting, hash)
		visited[hash] = true
		graph.commits[hash] = commit
		graph.order = append(graph.order, hash)
		return nil
	}
	for _, root := range roots {
		if err := visit(root); err != nil {
			return nil, err
		}
	}
	for _, hash := range graph.order {
		identity, exists, err := graph.blobIdentityAt(hash, "config/sow.yaml", config.MaxConfigBytes)
		if err != nil {
			return nil, fmt.Errorf("read config/sow.yaml at %s: %w", hash, err)
		}
		if !exists {
			return nil, fmt.Errorf("reachable canonical commit %s is missing config/sow.yaml; refusing to bypass package repository ownership", hash)
		}
		graph.configIdentities[hash] = identity
		committed, err := graph.configAt(hash)
		if err != nil {
			return nil, fmt.Errorf("decode config/sow.yaml at %s: %w", hash, err)
		}
		evidence, err := graph.ownershipEvidenceAt(hash, committed)
		if err != nil {
			return nil, err
		}
		graph.evidence[hash] = evidence
	}
	return graph, nil
}

func packageRepositoryHistoryRoots(repository *git.Repository) ([]plumbing.Hash, error) {
	roots := make(map[plumbing.Hash]struct{})
	head, err := repository.Head()
	if err == nil {
		if head.Hash().IsZero() {
			return nil, errors.New("canonical HEAD resolves to the zero commit")
		}
		roots[head.Hash()] = struct{}{}
	} else if !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return nil, err
	}
	iterator, err := repository.References()
	if err != nil {
		return nil, err
	}
	defer iterator.Close()
	err = iterator.ForEach(func(reference *plumbing.Reference) error {
		if reference.Type() != plumbing.HashReference || !strings.HasPrefix(reference.Name().String(), "refs/sow/") {
			return nil
		}
		if reference.Hash().IsZero() {
			return fmt.Errorf("SOW ref %s resolves to the zero commit", reference.Name())
		}
		if _, err := repository.CommitObject(reference.Hash()); err != nil {
			return fmt.Errorf("SOW ref %s has invalid commit %s: %w", reference.Name(), reference.Hash(), err)
		}
		roots[reference.Hash()] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	result := make([]plumbing.Hash, 0, len(roots))
	for root := range roots {
		result = append(result, root)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result, nil
}

func (g *packageRepositoryHistory) treeAt(hash plumbing.Hash) (*object.Tree, error) {
	commit := g.commits[hash]
	if commit == nil {
		return nil, fmt.Errorf("commit %s is outside reachable package history", hash)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}
	return tree, nil
}

func (g *packageRepositoryHistory) blobIdentityAt(hash plumbing.Hash, relative string, maximum int64) (state.BlobIdentity, bool, error) {
	tree, err := g.treeAt(hash)
	if err != nil {
		return state.BlobIdentity{}, false, err
	}
	entry, err := tree.FindEntry(relative)
	if errors.Is(err, object.ErrEntryNotFound) || errors.Is(err, object.ErrDirectoryNotFound) {
		return state.BlobIdentity{}, false, nil
	}
	if err != nil {
		return state.BlobIdentity{}, false, err
	}
	if !isPackageRepositoryHistoryBlob(entry.Mode) {
		return state.BlobIdentity{}, false, fmt.Errorf("canonical state path %s is not a regular file (mode %s)", relative, entry.Mode)
	}
	size, err := g.repository.Storer.EncodedObjectSize(entry.Hash)
	if err != nil {
		return state.BlobIdentity{}, false, err
	}
	if size > maximum {
		return state.BlobIdentity{}, false, fmt.Errorf("canonical state path %s is %d bytes (maximum %d)", relative, size, maximum)
	}
	return state.BlobIdentity{Hash: entry.Hash, Size: size}, true, nil
}

func (g *packageRepositoryHistory) ownershipEvidenceAt(hash plumbing.Hash, committed *config.Config) (map[string]string, error) {
	packages := packageRepositoriesByID(committed)
	evidence := make(map[string]string)
	tree, err := g.treeAt(hash)
	if err != nil {
		return nil, err
	}
	walker := object.NewTreeWalker(tree, true, nil)
	defer walker.Close()
	for {
		name, entry, err := walker.Next()
		if errors.Is(err, io.EOF) {
			return evidence, nil
		}
		if err != nil {
			return nil, err
		}
		repoID, candidate := packageRepositoryEvidenceRepo(name)
		if !candidate {
			continue
		}
		repo, configured := packages[repoID]
		if !configured {
			continue
		}
		if strings.HasPrefix(name, "serving/yum/") && repo.Type != "yum" {
			continue
		}
		if !isPackageRepositoryHistoryBlob(entry.Mode) {
			return nil, fmt.Errorf("canonical package ownership path %s at %s is not a regular file (mode %s)", name, hash, entry.Mode)
		}
		size, err := g.repository.Storer.EncodedObjectSize(entry.Hash)
		if err != nil {
			return nil, fmt.Errorf("read package ownership blob %s at %s: %w", name, hash, err)
		}
		if size != 0 {
			if _, exists := evidence[repoID]; !exists {
				evidence[repoID] = hash.String() + ":" + name
			}
		}
	}
}

func packageRepositoryEvidenceRepo(name string) (string, bool) {
	if path.Clean(name) != name {
		return "", false
	}
	parts := strings.Split(name, "/")
	if len(parts) == 2 && parts[0] == "manifests" && strings.HasSuffix(parts[1], ".tsv") {
		return strings.TrimSuffix(parts[1], ".tsv"), true
	}
	if len(parts) == 5 && (parts[0] == "views" || parts[0] == "snapshots") && strings.HasSuffix(parts[4], ".tsv") {
		return parts[2], true
	}
	if serving.IsGenerationManifestStatePath(name) || serving.IsRetiredGenerationManifestStatePath(name) {
		return parts[5], true
	}
	return "", false
}

func isPackageRepositoryHistoryBlob(mode filemode.FileMode) bool {
	switch mode {
	case filemode.Regular, filemode.Deprecated, filemode.Executable:
		return true
	default:
		return false
	}
}
