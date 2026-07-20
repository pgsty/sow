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
	"github.com/pgsty/sow/internal/state"
)

// validateCanonicalAssetProjectionContracts freezes routing fields once a
// repository ID has ever owned bytes. Physical source paths are the remote
// diff identity, so changing public_path/root_keys/mutable classification for
// unchanged bytes cannot be represented as an ordinary incremental publish.
// Empty repositories remain freely editable before their first entry.
func validateCanonicalAssetProjectionContracts(cfg *config.Config) error {
	if cfg == nil || cfg.Root == "" {
		return errors.New("cannot validate asset projection contract without a rooted config")
	}
	canonical := state.New(cfg.StatePath())
	reader, err := canonical.OpenPath("config/sow.yaml")
	if errors.Is(err, os.ErrNotExist) {
		head, headErr := canonicalAssetProjectionHead(canonical)
		if headErr != nil {
			return fmt.Errorf("read canonical HEAD for asset projection: %w", headErr)
		}
		if !head.IsZero() {
			return fmt.Errorf("canonical HEAD %s is missing config/sow.yaml; refusing to bypass historical asset projection contracts", head)
		}
		repositoryPath := filepath.Join(canonical.StateDir(), "state")
		if _, metadataErr := os.Lstat(filepath.Join(repositoryPath, ".git")); errors.Is(metadataErr, os.ErrNotExist) {
			return nil
		} else if metadataErr != nil {
			return fmt.Errorf("inspect canonical Git metadata for asset projection: %w", metadataErr)
		}
		gitHistory, openErr := openHistoricalAssetProjectionGit(canonical)
		if openErr != nil {
			return openErr
		}
		reachable, historyErr := gitHistory.reachableCanonicalCommits()
		if historyErr != nil {
			return fmt.Errorf("inspect canonical preservation history for asset projection: %w", historyErr)
		}
		if len(reachable) != 0 {
			return errors.New("canonical preservation history is missing config/sow.yaml; refusing to bypass historical asset projection contracts")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read prior canonical config for asset projection: %w", err)
	}
	prior, decodeErr := config.Decode(reader)
	closeErr := reader.Close()
	if decodeErr != nil || closeErr != nil {
		return fmt.Errorf("decode prior canonical config for asset projection: %w", errors.Join(decodeErr, closeErr))
	}
	// The current HEAD is not sufficient evidence. A pre-contract SOW version,
	// imported state repository, or manual Git repair may have changed a
	// populated projection and later returned to the same topology. Such a
	// history would make an apparently unchanged HEAD unsafe. Audit immutable
	// local blob identities across history on every load; this performs no
	// remote I/O and never inflates manifest payloads.
	historical, err := historicalAssetProjectionOwners(canonical)
	if err != nil {
		return fmt.Errorf("audit historical asset projection ownership: %w", err)
	}
	for repoID, records := range historical.byID {
		for index := 1; index < len(records); index++ {
			if !sameAssetProjectionContract(records[0].repo, records[index].repo) {
				return fmt.Errorf("canonical history contains incompatible populated asset contracts for repo %s at %s and %s; requires an explicit full re-projection migration", repoID, records[0].location, records[index].location)
			}
		}
	}
	priorRepos := assetReposByID(prior)
	currentRepos := assetReposByID(cfg)

	for _, repo := range cfg.Repos {
		if repo.Type != "asset" {
			continue
		}
		if _, existedAtHead := priorRepos[repo.ID]; !existedAtHead {
			if records := historical.byID[repo.ID]; len(records) != 0 {
				return fmt.Errorf("repo %s cannot be reintroduced after leaving canonical config; populated asset ownership at %s requires an explicit full re-projection migration", repo.ID, records[0].location)
			}
		}
		for _, record := range historical.byPhysicalRoot[repo.Path] {
			if record.repo.ID != repo.ID {
				return fmt.Errorf("repo %s cannot reuse physical asset root %s historically owned by populated repo %s at %s; requires an explicit full re-projection migration", repo.ID, repo.Path, record.repo.ID, record.location)
			}
		}
		for _, record := range historical.byID[repo.ID] {
			if !sameAssetProjectionContract(record.repo, repo) {
				return fmt.Errorf("repo %s asset active/path/include/exclude/public_path/kind/root_keys/mutable_paths contract is frozen by canonical content %s; requires an explicit full re-projection migration", repo.ID, record.location)
			}
		}
	}
	for repoID, records := range historical.byID {
		if _, exists := currentRepos[repoID]; !exists {
			return fmt.Errorf("populated asset repo %s cannot be removed from canonical config; ownership frozen at %s requires an explicit full re-projection migration", repoID, records[0].location)
		}
	}
	if len(historical.continuity) != 0 {
		return fmt.Errorf("canonical asset projection history is not continuous: %s; requires an explicit full re-projection migration", historical.continuity[0])
	}
	return nil
}

func assetReposByID(cfg *config.Config) map[string]config.Repo {
	result := make(map[string]config.Repo)
	if cfg == nil {
		return result
	}
	for _, repo := range cfg.Repos {
		if repo.Type == "asset" {
			result[repo.ID] = repo
		}
	}
	return result
}

func sameAssetProjectionContract(left, right config.Repo) bool {
	if left.Type != right.Type {
		return left.Type != "asset" && right.Type != "asset"
	}
	if left.Type != "asset" {
		return true
	}
	if left.Asset == nil || right.Asset == nil {
		return left.Asset == nil && right.Asset == nil
	}
	return left.Path == right.Path && left.AssetPublicRoot() == right.AssetPublicRoot() &&
		left.IsActive() == right.IsActive() && sameStringSet(left.Include, right.Include) &&
		sameStringSet(left.Exclude, right.Exclude) && left.Asset.Kind == right.Asset.Kind &&
		left.Asset.InventoryCarrier == right.Asset.InventoryCarrier &&
		sameStringSet(left.Asset.RootKeys, right.Asset.RootKeys) && sameStringSet(left.Asset.MutablePaths, right.Asset.MutablePaths)
}

// canonicalAssetProjectionHead distinguishes a genuinely unborn canonical
// repository from a non-zero HEAD whose config was deleted. It is deliberately
// read-only: state.HeadHash initializes a missing repository, which a config
// admission check must not do.
func canonicalAssetProjectionHead(canonical *state.Store) (plumbing.Hash, error) {
	if canonical == nil || canonical.StateDir() == "" {
		return plumbing.ZeroHash, errors.New("canonical state path is unavailable")
	}
	repositoryPath := filepath.Join(canonical.StateDir(), "state")
	repository, err := git.PlainOpen(repositoryPath)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		if _, metadataErr := os.Lstat(filepath.Join(repositoryPath, ".git")); errors.Is(metadataErr, os.ErrNotExist) {
			return plumbing.ZeroHash, nil
		} else if metadataErr != nil {
			return plumbing.ZeroHash, metadataErr
		}
		return plumbing.ZeroHash, fmt.Errorf("open canonical Git metadata: %w", err)
	}
	if err != nil {
		return plumbing.ZeroHash, err
	}
	head, err := repository.Head()
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return plumbing.ZeroHash, nil
	}
	if err != nil {
		return plumbing.ZeroHash, err
	}
	if head.Hash().IsZero() {
		return plumbing.ZeroHash, errors.New("canonical HEAD resolved to the zero commit")
	}
	return head.Hash(), nil
}

type historicalAssetProjectionRecord struct {
	repo     config.Repo
	location string
}

type historicalAssetProjectionRegistry struct {
	byID           map[string][]historicalAssetProjectionRecord
	byPhysicalRoot map[string][]historicalAssetProjectionRecord
	continuity     []string
	configCache    historicalConfigCacheStats
}

type historicalAssetProjectionConfigIndex struct {
	gitHistory *historicalAssetProjectionGit
	identities map[plumbing.Hash]state.BlobIdentity
	cache      *historicalConfigCache
}

func (i *historicalAssetProjectionConfigIndex) configAt(commit plumbing.Hash) (*config.Config, bool, error) {
	if i == nil || i.gitHistory == nil || i.cache == nil {
		return nil, false, errors.New("historical asset config index is unavailable")
	}
	identity, exists := i.identities[commit]
	if !exists {
		return nil, false, nil
	}
	committed, err := i.cache.get(identity, func() ([]byte, error) {
		return readHistoricalConfigBlob(i.gitHistory.repository, identity)
	})
	if err != nil {
		return nil, false, fmt.Errorf("decode canonical config at %s from blob %s: %w", commit, identity.Hash, err)
	}
	return committed, true, nil
}

func historicalAssetProjectionOwners(canonical *state.Store) (historicalAssetProjectionRegistry, error) {
	result := historicalAssetProjectionRegistry{
		byID:           make(map[string][]historicalAssetProjectionRecord),
		byPhysicalRoot: make(map[string][]historicalAssetProjectionRecord),
	}
	gitHistory, err := openHistoricalAssetProjectionGit(canonical)
	if err != nil {
		return result, err
	}
	history, err := gitHistory.reachableCanonicalCommits()
	if err != nil {
		return result, err
	}
	configs := &historicalAssetProjectionConfigIndex{
		gitHistory: gitHistory,
		identities: make(map[plumbing.Hash]state.BlobIdentity, len(history)),
		cache:      newHistoricalConfigCache(),
	}
	ancestry := &historicalAssetProjectionAncestry{
		gitHistory: gitHistory,
		cache:      make(map[historicalAssetProjectionAncestryKey]bool),
	}
	var anchors []historicalAssetProjectionAnchor
	for _, commit := range history {
		configIdentity, exists, err := gitHistory.blobIdentityAt(commit, "config/sow.yaml")
		if err != nil {
			return result, err
		}
		if !exists {
			continue
		}
		configs.identities[commit] = configIdentity
		committed, stillExists, err := configs.configAt(commit)
		if err != nil {
			return result, err
		}
		if !stillExists {
			return result, fmt.Errorf("config blob %s disappeared at commit %s", configIdentity.Hash, commit)
		}
		evidence, err := assetOwnershipEvidenceAt(gitHistory, commit, committed)
		if err != nil {
			return result, err
		}
		assets := assetReposByID(committed)
		for repoID, location := range evidence {
			repo := detachHistoricalRepository(assets[repoID])
			record := historicalAssetProjectionRecord{repo: repo, location: location}
			records, retained := retainHistoricalAssetProjectionContract(result.byID[repo.ID], record)
			result.byID[repo.ID] = records
			if retained {
				result.byPhysicalRoot[repo.Path] = append(result.byPhysicalRoot[repo.Path], record)
			}
			if len(records) == 2 && !sameAssetProjectionContract(records[0].repo, records[1].repo) {
				anchors = removeHistoricalAssetProjectionAnchors(anchors, repo.ID)
				continue
			}
			for _, stored := range records {
				if sameAssetProjectionContract(stored.repo, repo) {
					repo = stored.repo
					break
				}
			}
			anchors, err = retainHistoricalAssetProjectionAnchor(anchors, historicalAssetProjectionAnchor{
				commit: commit, repo: repo, location: location,
			}, ancestry)
			if err != nil {
				return result, err
			}
		}
	}
	sort.Slice(anchors, func(i, j int) bool {
		if anchors[i].repo.ID == anchors[j].repo.ID {
			return anchors[i].commit.String() < anchors[j].commit.String()
		}
		return anchors[i].repo.ID < anchors[j].repo.ID
	})
	result.continuity, err = auditHistoricalAssetProjectionContinuity(history, configs, anchors, ancestry)
	if err != nil {
		return result, err
	}
	result.configCache = configs.cache.snapshot()
	return result, nil
}

func hasHistoricalAssetProjectionContract(records []historicalAssetProjectionRecord, candidate config.Repo) bool {
	for _, record := range records {
		if sameAssetProjectionContract(record.repo, candidate) {
			return true
		}
	}
	return false
}

func retainHistoricalAssetProjectionContract(records []historicalAssetProjectionRecord, candidate historicalAssetProjectionRecord) ([]historicalAssetProjectionRecord, bool) {
	if hasHistoricalAssetProjectionContract(records, candidate.repo) || len(records) >= 2 {
		return records, false
	}
	return append(records, candidate), true
}

func removeHistoricalAssetProjectionAnchors(anchors []historicalAssetProjectionAnchor, repoID string) []historicalAssetProjectionAnchor {
	retained := make([]historicalAssetProjectionAnchor, 0, len(anchors))
	for _, anchor := range anchors {
		if anchor.repo.ID != repoID {
			retained = append(retained, anchor)
		}
	}
	return retained
}

// assetOwnershipEvidenceAt treats a non-empty repository manifest, view leaf,
// or snapshot leaf as populated ownership. A retained immutable snapshot may
// outlive the current working manifest, and imported canonical state may begin
// with a view, so manifest-only history is not sufficient to freeze routing.
// Blob sizes and canonical path ownership are enough; package entries are not
// inflated on the ordinary command path.
func assetOwnershipEvidenceAt(gitHistory *historicalAssetProjectionGit, commit plumbing.Hash, committed *config.Config) (map[string]string, error) {
	assets := assetReposByID(committed)
	evidence := make(map[string]string)
	for repoID := range assets {
		manifestPath := filepath.ToSlash(filepath.Join("manifests", repoID+".tsv"))
		identity, exists, err := gitHistory.blobIdentityAt(commit, manifestPath)
		if err != nil {
			return nil, fmt.Errorf("inspect historical asset manifest %s at %s: %w", manifestPath, commit, err)
		}
		if exists && identity.Size != 0 {
			evidence[repoID] = commit.String() + ":" + manifestPath
		}
	}
	if len(evidence) == len(assets) {
		return evidence, nil
	}
	for _, prefix := range []string{"views/", "snapshots/"} {
		err := gitHistory.forEachFileAt(commit, prefix, func(name string, identity state.BlobIdentity) error {
			parts := strings.Split(name, "/")
			if len(parts) != 5 || !strings.HasSuffix(parts[4], ".tsv") {
				return nil
			}
			repoID := parts[2]
			if _, configured := assets[repoID]; !configured {
				return nil
			}
			if _, populated := evidence[repoID]; populated {
				return nil
			}
			if identity.Size != 0 {
				evidence[repoID] = commit.String() + ":" + name
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("inspect historical asset %s at %s: %w", strings.TrimSuffix(prefix, "/"), commit, err)
		}
	}
	return evidence, nil
}

// historicalAssetProjectionGit reads only commit/tree metadata and encoded
// object sizes. object.Tree.File/GetBlob can materialize a large blob in the
// filesystem backend; tree entries plus EncodedObjectSize preserve missing
// object detection without inflating manifest/view/snapshot payloads. The
// repository path is explicit rather than discovered from the process CWD and
// addresses the canonical worktree repository directly.
type historicalAssetProjectionGit struct {
	repository *git.Repository
}

func openHistoricalAssetProjectionGit(canonical *state.Store) (*historicalAssetProjectionGit, error) {
	if canonical == nil || canonical.StateDir() == "" {
		return nil, errors.New("cannot inspect asset projection history without canonical state")
	}
	repository, err := canonical.OpenRepository()
	if err != nil {
		return nil, fmt.Errorf("open canonical Git metadata for asset projection: %w", err)
	}
	return &historicalAssetProjectionGit{repository: repository}, nil
}

// reachableCanonicalCommits returns the union of aggregate HEAD ancestry and
// every direct refs/sow/* preservation root. Imported snapshots and retained
// refs can intentionally point at sibling commits that are no longer on HEAD;
// ignoring those branches would let their populated ownership be reassigned.
// This walks commit metadata only and never initializes or mutates the state
// repository.
func (g *historicalAssetProjectionGit) reachableCanonicalCommits() ([]plumbing.Hash, error) {
	if g == nil || g.repository == nil {
		return nil, errors.New("canonical Git metadata reader is unavailable")
	}
	roots := make(map[plumbing.Hash]struct{})
	head, err := g.repository.Head()
	if err == nil {
		if head.Hash().IsZero() {
			return nil, errors.New("canonical HEAD resolved to the zero commit")
		}
		roots[head.Hash()] = struct{}{}
	} else if !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return nil, fmt.Errorf("read canonical HEAD: %w", err)
	}
	iterator, err := g.repository.References()
	if err != nil {
		return nil, fmt.Errorf("enumerate canonical refs: %w", err)
	}
	defer iterator.Close()
	err = iterator.ForEach(func(reference *plumbing.Reference) error {
		if reference.Type() != plumbing.HashReference || !strings.HasPrefix(reference.Name().String(), "refs/sow/") {
			return nil
		}
		if err := reference.Name().Validate(); err != nil {
			return fmt.Errorf("invalid canonical preservation ref %q: %w", reference.Name(), err)
		}
		if reference.Hash().IsZero() {
			return fmt.Errorf("canonical preservation ref %s resolves to the zero commit", reference.Name())
		}
		roots[reference.Hash()] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	stack := make([]plumbing.Hash, 0, len(roots))
	for root := range roots {
		stack = append(stack, root)
	}
	seen := make(map[plumbing.Hash]struct{})
	commits := make([]plumbing.Hash, 0, len(stack))
	for len(stack) != 0 {
		last := len(stack) - 1
		hash := stack[last]
		stack = stack[:last]
		if _, exists := seen[hash]; exists {
			continue
		}
		commit, err := g.repository.CommitObject(hash)
		if err != nil {
			return nil, fmt.Errorf("open reachable canonical commit %s: %w", hash, err)
		}
		seen[hash] = struct{}{}
		commits = append(commits, hash)
		stack = append(stack, commit.ParentHashes...)
	}
	sort.Slice(commits, func(i, j int) bool { return commits[i].String() < commits[j].String() })
	return commits, nil
}

func (g *historicalAssetProjectionGit) treeAt(commit plumbing.Hash) (*object.Tree, error) {
	commitObject, err := g.repository.CommitObject(commit)
	if err != nil {
		return nil, err
	}
	tree, err := commitObject.Tree()
	if err != nil {
		return nil, err
	}
	return tree, nil
}

func (g *historicalAssetProjectionGit) blobIdentityAt(commit plumbing.Hash, relative string) (state.BlobIdentity, bool, error) {
	if err := validateHistoricalAssetProjectionStatePath(relative); err != nil {
		return state.BlobIdentity{}, false, err
	}
	tree, err := g.treeAt(commit)
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
	if !isHistoricalAssetProjectionBlobMode(entry.Mode) {
		return state.BlobIdentity{}, false, fmt.Errorf("canonical state path %s at %s is not a regular file (mode %s)", relative, commit, entry.Mode)
	}
	size, err := g.repository.Storer.EncodedObjectSize(entry.Hash)
	if err != nil {
		return state.BlobIdentity{}, false, err
	}
	return state.BlobIdentity{Hash: entry.Hash, Size: size}, true, nil
}

func (g *historicalAssetProjectionGit) forEachFileAt(commit plumbing.Hash, prefix string, fn func(string, state.BlobIdentity) error) error {
	if fn == nil {
		return errors.New("historical asset projection callback is nil")
	}
	tree, err := g.treeAt(commit)
	if err != nil {
		return err
	}
	walker := object.NewTreeWalker(tree, true, nil)
	defer walker.Close()
	for {
		name, entry, err := walker.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if entry.Mode == filemode.Dir || entry.Mode == filemode.Submodule {
			continue
		}
		if !isHistoricalAssetProjectionBlobMode(entry.Mode) {
			return fmt.Errorf("canonical state path %s at %s is not a regular file (mode %s)", name, commit, entry.Mode)
		}
		if err := validateHistoricalAssetProjectionStatePath(name); err != nil {
			return err
		}
		size, err := g.repository.Storer.EncodedObjectSize(entry.Hash)
		if err != nil {
			return err
		}
		if err := fn(name, state.BlobIdentity{Hash: entry.Hash, Size: size}); err != nil {
			return err
		}
	}
}

func isHistoricalAssetProjectionBlobMode(mode filemode.FileMode) bool {
	switch mode {
	case filemode.Regular, filemode.Deprecated, filemode.Executable:
		return true
	default:
		return false
	}
}

func validateHistoricalAssetProjectionStatePath(value string) error {
	if value == "" || filepath.IsAbs(value) || strings.ContainsAny(value, "\\\x00\t\r\n") {
		return errors.New("historical canonical state path must be a safe relative POSIX path")
	}
	clean := path.Clean(value)
	if clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return errors.New("historical canonical state path must remain inside the state tree")
	}
	for _, segment := range strings.Split(clean, "/") {
		if segment == ".git" {
			return errors.New("historical canonical state path may not address Git metadata")
		}
	}
	return nil
}

type historicalAssetProjectionAnchor struct {
	commit   plumbing.Hash
	repo     config.Repo
	location string
}

type historicalAssetProjectionAncestryKey struct {
	ancestor   plumbing.Hash
	descendant plumbing.Hash
}

type historicalAssetProjectionAncestry struct {
	gitHistory *historicalAssetProjectionGit
	cache      map[historicalAssetProjectionAncestryKey]bool
}

func (a *historicalAssetProjectionAncestry) isAncestor(ancestor, descendant plumbing.Hash) (bool, error) {
	if ancestor == descendant {
		return true, nil
	}
	key := historicalAssetProjectionAncestryKey{ancestor: ancestor, descendant: descendant}
	if result, exists := a.cache[key]; exists {
		return result, nil
	}
	if ancestor.IsZero() || descendant.IsZero() || a.gitHistory == nil || a.gitHistory.repository == nil {
		return false, errors.New("canonical ancestry requires non-zero commits and a Git metadata reader")
	}
	ancestorCommit, err := a.gitHistory.repository.CommitObject(ancestor)
	if err != nil {
		return false, fmt.Errorf("open canonical ancestor %s: %w", ancestor, err)
	}
	descendantCommit, err := a.gitHistory.repository.CommitObject(descendant)
	if err != nil {
		return false, fmt.Errorf("open canonical descendant %s: %w", descendant, err)
	}
	result, err := ancestorCommit.IsAncestor(descendantCommit)
	if err != nil {
		return false, fmt.Errorf("check canonical ancestry %s -> %s: %w", ancestor, descendant, err)
	}
	a.cache[key] = result
	return result, nil
}

type historicalAssetProjectionRemoval struct {
	owner    historicalAssetProjectionAnchor
	commit   plumbing.Hash
	location string
}

// auditHistoricalAssetProjectionContinuity catches legacy histories that
// changed a populated contract while its manifest happened to be empty,
// removed and later reintroduced the same ID, or reused its physical root.
// The commit loop is deliberately outermost: every immutable config is decoded
// at most once in this phase, even when many ownership anchors exist. Compact
// commit hashes retain presence for the later reintroduction check; decoded
// config pointers never escape an iteration.
func auditHistoricalAssetProjectionContinuity(history []plumbing.Hash, configs *historicalAssetProjectionConfigIndex, anchors []historicalAssetProjectionAnchor, ancestry *historicalAssetProjectionAncestry) ([]string, error) {
	commits := append([]plumbing.Hash(nil), history...)
	sort.Slice(commits, func(i, j int) bool { return commits[i].String() < commits[j].String() })
	findings := make(map[string]string)
	removals := make(map[string]historicalAssetProjectionRemoval)
	presentByRepo := make(map[string][]plumbing.Hash)
	anchoredRepoIDs := make(map[string]struct{}, len(anchors))
	for _, anchor := range anchors {
		anchoredRepoIDs[anchor.repo.ID] = struct{}{}
	}
	for _, commit := range commits {
		location := commit.String() + ":config/sow.yaml"
		committed, configExists, err := configs.configAt(commit)
		if err != nil {
			return nil, err
		}
		present := make(map[string]config.Repo)
		roots := make(map[string][]string)
		if configExists {
			present = assetReposByID(committed)
			for repoID, repo := range present {
				if _, anchored := anchoredRepoIDs[repoID]; anchored {
					presentByRepo[repoID] = append(presentByRepo[repoID], commit)
				}
				roots[repo.Path] = append(roots[repo.Path], repoID)
			}
		}
		for _, owner := range anchors {
			descendant, err := ancestry.isAncestor(owner.commit, commit)
			if err != nil {
				return nil, fmt.Errorf("check historical asset ownership ancestry %s -> %s: %w", owner.commit, commit, err)
			}
			if !descendant || commit == owner.commit {
				continue
			}
			if !configExists {
				key := "config-missing\x00" + owner.repo.ID + "\x00" + commit.String()
				findings[key] = fmt.Sprintf("populated asset repo %s owned at %s lost canonical config at %s", owner.repo.ID, owner.location, location)
				continue
			}
			repo, exists := present[owner.repo.ID]
			if !exists {
				key := "removed\x00" + owner.repo.ID + "\x00" + commit.String()
				removals[key] = historicalAssetProjectionRemoval{owner: owner, commit: commit, location: location}
			} else if !sameAssetProjectionContract(owner.repo, repo) {
				key := "contract\x00" + owner.repo.ID + "\x00" + commit.String()
				findings[key] = fmt.Sprintf("populated asset repo %s contract owned at %s changed at %s", owner.repo.ID, owner.location, location)
			}
			for _, candidateID := range roots[owner.repo.Path] {
				if candidateID == owner.repo.ID {
					continue
				}
				key := "root\x00" + owner.repo.ID + "\x00" + candidateID + "\x00" + commit.String()
				findings[key] = fmt.Sprintf("populated asset root %s owned by repo %s at %s was later reused by repo %s at %s", owner.repo.Path, owner.repo.ID, owner.location, candidateID, location)
			}
		}
	}
	for key, removal := range removals {
		reintroducedAt, reintroduced, err := historicalAssetProjectionReintroduction(removal.commit, presentByRepo[removal.owner.repo.ID], ancestry)
		if err != nil {
			return nil, err
		}
		if reintroduced {
			findings[key] = fmt.Sprintf("populated asset repo %s owned at %s was removed at %s and later reintroduced at %s", removal.owner.repo.ID, removal.owner.location, removal.location, reintroducedAt.String()+":config/sow.yaml")
		} else {
			findings[key] = fmt.Sprintf("populated asset repo %s owned at %s was removed at %s", removal.owner.repo.ID, removal.owner.location, removal.location)
		}
	}
	result := make([]string, 0, len(findings))
	for _, finding := range findings {
		result = append(result, finding)
	}
	sort.Strings(result)
	return result, nil
}

// retainHistoricalAssetProjectionAnchor incrementally keeps only the oldest
// populated owner on each ancestry branch for one unchanged detached contract.
func retainHistoricalAssetProjectionAnchor(anchors []historicalAssetProjectionAnchor, candidate historicalAssetProjectionAnchor, ancestry *historicalAssetProjectionAncestry) ([]historicalAssetProjectionAnchor, error) {
	for index := 0; index < len(anchors); {
		existing := anchors[index]
		if existing.repo.ID != candidate.repo.ID || !sameAssetProjectionContract(existing.repo, candidate.repo) {
			index++
			continue
		}
		existingAncestor, err := ancestry.isAncestor(existing.commit, candidate.commit)
		if err != nil {
			return nil, fmt.Errorf("compare historical asset ownership anchors %s -> %s: %w", existing.commit, candidate.commit, err)
		}
		if existingAncestor {
			return anchors, nil
		}
		candidateAncestor, err := ancestry.isAncestor(candidate.commit, existing.commit)
		if err != nil {
			return nil, fmt.Errorf("compare historical asset ownership anchors %s -> %s: %w", candidate.commit, existing.commit, err)
		}
		if candidateAncestor {
			anchors = append(anchors[:index], anchors[index+1:]...)
			continue
		}
		index++
	}
	return append(anchors, candidate), nil
}

func historicalAssetProjectionReintroduction(removed plumbing.Hash, presentCommits []plumbing.Hash, ancestry *historicalAssetProjectionAncestry) (plumbing.Hash, bool, error) {
	for _, commit := range presentCommits {
		if commit == removed {
			continue
		}
		descendant, err := ancestry.isAncestor(removed, commit)
		if err != nil {
			return plumbing.ZeroHash, false, fmt.Errorf("check historical asset reintroduction ancestry %s -> %s: %w", removed, commit, err)
		}
		if descendant {
			return commit, true, nil
		}
	}
	return plumbing.ZeroHash, false, nil
}
