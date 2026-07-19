package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/catalog"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/state"
)

// refreshWorkingTreeBaselines records the exact configured serving trees only
// after their materialization has completed. All selected repository scans are
// staged before the recoverable canonical transaction starts, so a scan error
// cannot advance a subset of repository refs. SQLite remains a derived cache
// and is rebuilt only after the canonical commit and ref vector are complete.
func refreshWorkingTreeBaselines(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	repos []config.Repo,
	txDir string,
	values commonFlags,
	operation string,
	applyOptions state.ApplyOptions,
	stdout io.Writer,
) (commit string, changed bool, err error) {
	if len(repos) == 0 {
		return "", false, fmt.Errorf("refresh working tree baseline: no repositories selected")
	}
	repos = append([]config.Repo(nil), repos...)
	sort.Slice(repos, func(i, j int) bool { return repos[i].ID < repos[j].ID })
	for index := 1; index < len(repos); index++ {
		if repos[index-1].ID == repos[index].ID {
			return "", false, fmt.Errorf("refresh working tree baseline: duplicate repository %s", repos[index].ID)
		}
	}
	stageDir := filepath.Join(txDir, "working-tree-baseline")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		return "", false, fmt.Errorf("create working tree baseline stage: %w", err)
	}

	staged := make(map[string]string, len(repos)+1)
	updates := make([]state.RefUpdate, 0, len(repos))
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return "", false, fmt.Errorf("read working tree baseline HEAD: %w", err)
	}
	for _, repo := range repos {
		selectedPath := filepath.Join(stageDir, "working-tree-"+repo.ID+".selected.tsv")
		stats, scanErr := scanRepoManifest(ctx, cfg, repo, selectedPath, manifest.ScanOptions{
			Workers: values.workers, ChunkEntries: values.chunk,
			TempDir: filepath.Join(cfg.StatePath(), "tmp"),
		})
		if scanErr != nil {
			return "", false, fmt.Errorf("scan materialized repo %s: %w", repo.ID, scanErr)
		}
		path := filepath.Join(stageDir, "working-tree-"+repo.ID+".tsv")
		if stageErr := stageRepoManifestUpdate(cfg, canonical, repo, selectedPath, path, filepath.Join(cfg.StatePath(), "tmp")); stageErr != nil {
			return "", false, fmt.Errorf("stage selected working tree baseline %s: %w", repo.ID, stageErr)
		}
		canonicalPath := filepath.ToSlash(filepath.Join("manifests", repo.ID+".tsv"))
		ref, refErr := state.RepoRef(repo.ID)
		if refErr != nil {
			return "", false, refErr
		}
		expected, exists, refErr := canonical.Ref(ref)
		if refErr != nil {
			return "", false, fmt.Errorf("read repository ref %s: %w", ref, refErr)
		}
		unchanged := false
		if exists {
			unchanged, refErr = workingTreeManifestMatchesCommits(canonical, path, canonicalPath, head, expected)
			if refErr != nil {
				return "", false, fmt.Errorf("compare working tree baseline %s: %w", repo.ID, refErr)
			}
		}
		if unchanged {
			fmt.Fprintf(stdout, "working tree scanned repo=%s files=%d bytes=%d unchanged=true\n", repo.ID, stats.Files, stats.Bytes)
			continue
		}
		staged[canonicalPath] = path
		updates = append(updates, state.RefUpdate{Name: ref, Expected: expected})
		fmt.Fprintf(stdout, "working tree scanned repo=%s files=%d bytes=%d\n", repo.ID, stats.Files, stats.Bytes)
	}
	canonicalConfig, _, err := stageCanonicalConfig(cfg, stageDir)
	if err != nil {
		return "", false, fmt.Errorf("stage canonical config: %w", err)
	}
	staged["config/sow.yaml"] = canonicalConfig

	hash, changed, err := applyCanonicalConfig(ctx, cfg, canonical, operation, "sow: refresh latest working tree", staged, updates, applyOptions)
	if err != nil {
		return hash.String(), changed, err
	}
	if err := catalog.Rebuild(cfg.StatePath()); err != nil {
		return hash.String(), changed, fmt.Errorf("rebuild SQLite cache from working manifests: %w", err)
	}
	entries, err := catalog.Count(cfg.StatePath())
	if err != nil {
		return hash.String(), changed, fmt.Errorf("verify rebuilt SQLite cache: %w", err)
	}
	fmt.Fprintf(stdout, "working tree committed=%s repos=%d changed=%t cache_entries=%d\n", hash, len(repos), changed, entries)
	return hash.String(), changed, nil
}

// workingTreeManifestMatchesCommits prevents a content-stable repository ref
// from chasing unrelated canonical commits such as route-receipt updates. The
// current HEAD and the semantic repo ref must both carry the exact staged Git
// blob before the scan can be omitted; any divergence is repaired through the
// normal atomic manifest/ref transaction.
func workingTreeManifestMatchesCommits(canonical *state.Store, staged, canonicalPath string, commits ...plumbing.Hash) (bool, error) {
	if canonical == nil || len(commits) == 0 {
		return false, nil
	}
	_, gitBlob, size, err := fileSHA256AndGitBlob(staged)
	if err != nil {
		return false, err
	}
	for _, commit := range commits {
		if commit.IsZero() {
			return false, nil
		}
		identity, exists, err := canonical.BlobIdentityAt(commit, canonicalPath)
		if err != nil {
			return false, err
		}
		if !exists || identity.Hash != gitBlob || identity.Size != size {
			return false, nil
		}
	}
	return true, nil
}

func preparedWorkingTreeRepos(prepared preparedPublication) ([]config.Repo, error) {
	if prepared.view != "latest" {
		return nil, fmt.Errorf("view %s is not the legacy latest working tree", prepared.view)
	}
	byID := make(map[string]config.Repo)
	for _, projection := range prepared.projections {
		if projection.sourceRoot != projection.legacyRoot {
			return nil, fmt.Errorf("latest projection %s source %s differs from legacy root %s", projection.repo.ID, projection.sourceRoot, projection.legacyRoot)
		}
		repo := projection.repo
		if projection.physicalRepo.ID != "" {
			repo = projection.physicalRepo
		}
		byID[repo.ID] = repo
	}
	repos := make([]config.Repo, 0, len(byID))
	for _, repo := range byID {
		repos = append(repos, repo)
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].ID < repos[j].ID })
	return repos, nil
}

func workingTreeReposFromLeaves(leaves map[string]viewLeaf) []config.Repo {
	byID := make(map[string]config.Repo)
	for _, leaf := range leaves {
		byID[leaf.repo.ID] = leaf.repo
	}
	repos := make([]config.Repo, 0, len(byID))
	for _, repo := range byID {
		repos = append(repos, repo)
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].ID < repos[j].ID })
	return repos
}
