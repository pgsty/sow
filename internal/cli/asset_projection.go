package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/state"
)

// validateAssetProjectionPath proves that one canonical, physical asset path
// can be projected into the repository's public namespace without widening a
// root-mapped repository into an unbounded public prefix. A public_path of "."
// owns only the finite exact object keys declared by root_keys; it does not own
// directories below those keys.
func validateAssetProjectionPath(repo config.Repo, logical string) error {
	if repo.Type != "asset" || repo.Asset == nil {
		return fmt.Errorf("repository %s is not an asset repository", repo.ID)
	}
	prefix := strings.TrimSuffix(repo.Path, "/") + "/"
	if !strings.HasPrefix(logical, prefix) {
		return fmt.Errorf("asset path %q is outside physical repository root %q", logical, repo.Path)
	}
	relative := strings.TrimPrefix(logical, prefix)
	if err := validateAssetRelativeRoute(relative); err != nil {
		return fmt.Errorf("asset path %q has no safe repository-relative key: %w", logical, err)
	}
	if repo.AssetPublicRoot() != "." {
		return nil
	}
	if strings.Contains(relative, "/") {
		return fmt.Errorf("root-mapped asset path %q must be one exact key declared by asset.root_keys", relative)
	}
	for _, key := range repo.Asset.RootKeys {
		if relative == key {
			return nil
		}
	}
	return fmt.Errorf("root-mapped asset path %q is not declared by asset.root_keys", relative)
}

// validateAssetRelativeRoute is the single admission rule for asset keys,
// whether they arrive through add, legacy adoption, init/fsck scans, or a
// generated offline archive. Every accepted key must be representable as one
// clean edge URL without decoding aliases or crossing an internal shadow
// point.
func validateAssetRelativeRoute(relative string) error {
	if relative == "" || strings.HasPrefix(relative, "/") ||
		strings.ContainsAny(relative, "%?#\\\x00\t\r\n") ||
		path.Clean(relative) != relative || relative == ".." || strings.HasPrefix(relative, "../") {
		return fmt.Errorf("unsafe asset destination %q", relative)
	}
	for _, segment := range strings.Split(relative, "/") {
		if segment == ".sow" || segment == ".pool" || segment == ".git" {
			return fmt.Errorf("asset destination %q crosses a reserved shadow point", relative)
		}
		if err := config.ValidateRouteSegment(segment); err != nil {
			return fmt.Errorf("unsafe asset destination %q: segment %q is not edge-routable: %w", relative, segment, err)
		}
	}
	return nil
}

// validateAssetProjectionManifest streams a physical manifest and applies the
// same admission rule used before CAS import. This closes adoption, init, fsck,
// and working-tree refresh paths that start from bytes already on disk.
func validateAssetProjectionManifest(repo config.Repo, filename string) error {
	if repo.Type != "asset" || repo.Asset == nil {
		return nil
	}
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read asset projection manifest: %w", err)
		}
		if err := validateAssetProjectionPath(repo, entry.Path); err != nil {
			return err
		}
	}
}

// auditCanonicalAssetProjectionRefs makes fsck cover canonical views and
// snapshots, not only the physical repository baseline. A forged view cannot
// become self-consistent merely by placing matching bytes in a materialized
// tree.
func auditCanonicalAssetProjectionRefs(canonical *state.Store, cfg *config.Config, repos []config.Repo, limit int, stdout io.Writer) (int, error) {
	selected := make(map[string]config.Repo)
	for _, repo := range repos {
		if repo.Type == "asset" {
			selected[repo.ID] = repo
		}
	}
	if len(selected) == 0 {
		return 0, nil
	}
	refs, err := canonical.SOWRefs()
	if err != nil {
		return 0, err
	}
	drift, printed := 0, 0
	for _, record := range refs {
		parts := strings.Split(record.Name.String(), "/")
		if len(parts) < 3 || parts[0] != "refs" || parts[1] != "sow" || (parts[2] != "views" && parts[2] != "snapshots") {
			continue
		}
		if len(parts) != 7 {
			return drift, fmt.Errorf("invalid canonical asset ref shape %s", record.Name)
		}
		repo, selectedRepo := selected[parts[4]]
		if !selectedRepo {
			continue
		}
		leaf := viewLeaf{repo: repo, os: parts[5], arch: parts[6]}
		var canonicalPath string
		if parts[2] == "views" {
			canonicalPath, err = state.ViewPath(parts[3], repo.ID, leaf.os, leaf.arch)
		} else {
			canonicalPath, err = state.SnapshotPath(parts[3], repo.ID, leaf.os, leaf.arch)
		}
		if err != nil {
			return drift, err
		}
		public := false
		if parts[2] == "views" {
			public = cfg.Views[parts[3]].Access == "public"
		}
		if err := validateViewAt(canonical, record.Hash, canonicalPath, leaf, public); err != nil {
			drift++
			if printed < limit {
				fmt.Fprintf(stdout, "drift repo=%s kind=canonical_asset_projection ref=%s error=%q\n", repo.ID, record.Name, err.Error())
				printed++
			}
		}
	}
	return drift, nil
}
