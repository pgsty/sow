package cli

import (
	"bytes"
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
	decodedConfigs := make(map[string]*config.Config)
	configsAtCommit := make(map[string]*config.Config, len(history))
	evidenceAtCommit := make(map[string]map[string]string, len(history))
	seen := make(map[string]struct{})
	for _, commit := range history {
		configIdentity, exists, err := gitHistory.blobIdentityAt(commit, "config/sow.yaml")
		if err != nil {
			return result, err
		}
		if !exists {
			continue
		}
		cacheKey := configIdentity.Hash.String()
		committed := decodedConfigs[cacheKey]
		if committed == nil {
			body, exists, err := readCanonicalBytesAt(canonical, commit, "config/sow.yaml", 16<<20)
			if err != nil {
				return result, err
			}
			if !exists {
				return result, fmt.Errorf("config blob %s disappeared at commit %s", cacheKey, commit)
			}
			committed, err = config.Decode(bytes.NewReader(body))
			if err != nil {
				return result, fmt.Errorf("decode canonical config at %s: %w", commit, err)
			}
			decodedConfigs[cacheKey] = committed
		}
		configsAtCommit[commit.String()] = committed
		evidence, err := assetOwnershipEvidenceAt(gitHistory, commit, committed)
		if err != nil {
			return result, err
		}
		evidenceAtCommit[commit.String()] = evidence
		assets := assetReposByID(committed)
		for repoID, location := range evidence {
			repo := assets[repoID]
			contractKey := repo.ID + "\x00" + configIdentity.Hash.String()
			if _, duplicate := seen[contractKey]; duplicate {
				continue
			}
			seen[contractKey] = struct{}{}
			record := historicalAssetProjectionRecord{repo: repo, location: location}
			result.byID[repo.ID] = append(result.byID[repo.ID], record)
			result.byPhysicalRoot[repo.Path] = append(result.byPhysicalRoot[repo.Path], record)
		}
	}
	result.continuity, err = auditHistoricalAssetProjectionContinuity(gitHistory, history, configsAtCommit, evidenceAtCommit)
	if err != nil {
		return result, err
	}
	return result, nil
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
	trees      map[plumbing.Hash]*object.Tree
}

func openHistoricalAssetProjectionGit(canonical *state.Store) (*historicalAssetProjectionGit, error) {
	if canonical == nil || canonical.StateDir() == "" {
		return nil, errors.New("cannot inspect asset projection history without canonical state")
	}
	repository, err := canonical.OpenRepository()
	if err != nil {
		return nil, fmt.Errorf("open canonical Git metadata for asset projection: %w", err)
	}
	return &historicalAssetProjectionGit{repository: repository, trees: make(map[plumbing.Hash]*object.Tree)}, nil
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
	if tree := g.trees[commit]; tree != nil {
		return tree, nil
	}
	commitObject, err := g.repository.CommitObject(commit)
	if err != nil {
		return nil, err
	}
	tree, err := commitObject.Tree()
	if err != nil {
		return nil, err
	}
	g.trees[commit] = tree
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

// auditHistoricalAssetProjectionContinuity catches legacy histories that
// changed a populated contract while its manifest happened to be empty,
// removed and later reintroduced the same ID, or reused its physical root.
// The reachable union has no meaningful slice order in the presence of clock
// skew, merges, or off-HEAD preservation refs. Every transition is therefore
// judged by Git ancestry instead of slice position. Blob identities remain the
// only ownership evidence; manifest/view/snapshot payloads are never inflated.
func auditHistoricalAssetProjectionContinuity(gitHistory *historicalAssetProjectionGit, history []plumbing.Hash, configsAtCommit map[string]*config.Config, evidenceAtCommit map[string]map[string]string) ([]string, error) {
	commits := append([]plumbing.Hash(nil), history...)
	sort.Slice(commits, func(i, j int) bool { return commits[i].String() < commits[j].String() })
	ancestry := &historicalAssetProjectionAncestry{
		gitHistory: gitHistory,
		cache:      make(map[historicalAssetProjectionAncestryKey]bool),
	}
	anchors, err := minimalHistoricalAssetProjectionAnchors(commits, configsAtCommit, evidenceAtCommit, ancestry)
	if err != nil {
		return nil, err
	}
	findings := make(map[string]string)
	for _, owner := range anchors {
		for _, commit := range commits {
			descendant, err := ancestry.isAncestor(owner.commit, commit)
			if err != nil {
				return nil, fmt.Errorf("check historical asset ownership ancestry %s -> %s: %w", owner.commit, commit, err)
			}
			if !descendant || commit == owner.commit {
				continue
			}
			location := commit.String() + ":config/sow.yaml"
			committed := configsAtCommit[commit.String()]
			if committed == nil {
				key := "config-missing\x00" + owner.repo.ID + "\x00" + commit.String()
				findings[key] = fmt.Sprintf("populated asset repo %s owned at %s lost canonical config at %s", owner.repo.ID, owner.location, location)
				continue
			}
			present := assetReposByID(committed)
			repo, exists := present[owner.repo.ID]
			if !exists {
				key := "removed\x00" + owner.repo.ID + "\x00" + commit.String()
				reintroducedAt, reintroduced, err := historicalAssetProjectionReintroduction(commit, owner.repo.ID, commits, configsAtCommit, ancestry)
				if err != nil {
					return nil, err
				}
				if reintroduced {
					findings[key] = fmt.Sprintf("populated asset repo %s owned at %s was removed at %s and later reintroduced at %s", owner.repo.ID, owner.location, location, reintroducedAt.String()+":config/sow.yaml")
				} else {
					findings[key] = fmt.Sprintf("populated asset repo %s owned at %s was removed at %s", owner.repo.ID, owner.location, location)
				}
			} else if !sameAssetProjectionContract(owner.repo, repo) {
				key := "contract\x00" + owner.repo.ID + "\x00" + commit.String()
				findings[key] = fmt.Sprintf("populated asset repo %s contract owned at %s changed at %s", owner.repo.ID, owner.location, location)
			}
			for _, candidate := range committed.Repos {
				if candidate.Type != "asset" || candidate.ID == owner.repo.ID || candidate.Path != owner.repo.Path {
					continue
				}
				key := "root\x00" + owner.repo.ID + "\x00" + candidate.ID + "\x00" + commit.String()
				findings[key] = fmt.Sprintf("populated asset root %s owned by repo %s at %s was later reused by repo %s at %s", owner.repo.Path, owner.repo.ID, owner.location, candidate.ID, location)
			}
		}
	}
	result := make([]string, 0, len(findings))
	for _, finding := range findings {
		result = append(result, finding)
	}
	sort.Strings(result)
	return result, nil
}

// minimalHistoricalAssetProjectionAnchors retains the oldest populated
// ownership commit on each ancestry branch for an unchanged contract. A
// linear history therefore needs one descendant sweep rather than one per
// commit, while incomparable merge parents remain independently audited.
func minimalHistoricalAssetProjectionAnchors(commits []plumbing.Hash, configsAtCommit map[string]*config.Config, evidenceAtCommit map[string]map[string]string, ancestry *historicalAssetProjectionAncestry) ([]historicalAssetProjectionAnchor, error) {
	var candidates []historicalAssetProjectionAnchor
	for _, commit := range commits {
		committed := configsAtCommit[commit.String()]
		if committed == nil {
			continue
		}
		assets := assetReposByID(committed)
		repoIDs := make([]string, 0, len(evidenceAtCommit[commit.String()]))
		for repoID := range evidenceAtCommit[commit.String()] {
			repoIDs = append(repoIDs, repoID)
		}
		sort.Strings(repoIDs)
		for _, repoID := range repoIDs {
			repo, exists := assets[repoID]
			if !exists {
				return nil, fmt.Errorf("historical asset ownership evidence for unconfigured repo %s at %s", repoID, commit)
			}
			candidates = append(candidates, historicalAssetProjectionAnchor{
				commit: commit, repo: repo, location: evidenceAtCommit[commit.String()][repoID],
			})
		}
	}
	var anchors []historicalAssetProjectionAnchor
	for _, candidate := range candidates {
		redundant := false
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
				redundant = true
				break
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
		if !redundant {
			anchors = append(anchors, candidate)
		}
	}
	sort.Slice(anchors, func(i, j int) bool {
		if anchors[i].repo.ID == anchors[j].repo.ID {
			return anchors[i].commit.String() < anchors[j].commit.String()
		}
		return anchors[i].repo.ID < anchors[j].repo.ID
	})
	return anchors, nil
}

func historicalAssetProjectionReintroduction(removed plumbing.Hash, repoID string, commits []plumbing.Hash, configsAtCommit map[string]*config.Config, ancestry *historicalAssetProjectionAncestry) (plumbing.Hash, bool, error) {
	for _, commit := range commits {
		if commit == removed {
			continue
		}
		committed := configsAtCommit[commit.String()]
		if committed == nil {
			continue
		}
		if _, present := assetReposByID(committed)[repoID]; !present {
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
