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

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
)

type latestRemoteProjectionRoot struct {
	physical string
	repo     config.Repo
	index    int
}

// projectLatestSourceManifest converts the canonical physical content.tsv
// namespace into the legacy latest object-key namespace. APT and YUM are
// identity mappings; asset.public_path may project a private physical root to
// a different public prefix or to a finite exact root key. Per-repo sorted
// runs keep memory O(number of repos), and the final merge catches collisions.
func projectLatestSourceManifest(repos []config.Repo, sourcePath, destinationPath, stageDir string) error {
	if len(repos) == 0 {
		return errors.New("project remote manifest: no target-owned repositories")
	}
	runDir := filepath.Join(stageDir, "."+filepath.Base(destinationPath)+".projection")
	if err := os.Mkdir(runDir, 0o700); err != nil {
		return err
	}
	roots := make([]latestRemoteProjectionRoot, 0, len(repos))
	for repoIndex, repo := range repos {
		expanded, err := repo.ExpandedPaths()
		if err != nil {
			return err
		}
		for _, physical := range expanded {
			roots = append(roots, latestRemoteProjectionRoot{physical: physical, repo: repo, index: repoIndex})
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].physical < roots[j].physical })
	for index := 1; index < len(roots); index++ {
		left, right := roots[index-1].physical, roots[index].physical
		if left == right || strings.HasPrefix(right, strings.TrimSuffix(left, "/")+"/") {
			return fmt.Errorf("project remote manifest: physical roots %q and %q overlap", left, right)
		}
	}
	rootByPath := make(map[string]latestRemoteProjectionRoot, len(roots))
	for _, root := range roots {
		rootByPath[root.physical] = root
	}

	source, err := openRegularManifest(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	type spool struct {
		path string
		file *os.File
	}
	spools := make([]spool, len(repos))
	closeSpools := func() error {
		var result error
		for index := range spools {
			if spools[index].file != nil {
				result = errors.Join(result, spools[index].file.Sync(), spools[index].file.Close())
				spools[index].file = nil
			}
		}
		return result
	}
	fail := func(err error) error { return errors.Join(err, closeSpools()) }

	reader := manifest.NewReader(source)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fail(err)
		}
		var root latestRemoteProjectionRoot
		matched := false
		for ancestor := path.Dir(entry.Path); ancestor != "." && ancestor != "/"; ancestor = path.Dir(ancestor) {
			if candidate, exists := rootByPath[ancestor]; exists {
				root, matched = candidate, true
				break
			}
		}
		if !matched {
			return fail(fmt.Errorf("source manifest path %q is outside target-owned repositories", entry.Path))
		}
		prefix := strings.TrimSuffix(root.physical, "/") + "/"
		if !strings.HasPrefix(entry.Path, prefix) {
			return fail(fmt.Errorf("source manifest path %q is outside target-owned repositories", entry.Path))
		}
		if root.repo.Type == "asset" {
			if err := validateAssetProjectionPath(root.repo, entry.Path); err != nil {
				return fail(err)
			}
			relative := strings.TrimPrefix(entry.Path, prefix)
			entry.Path = path.Join(root.repo.AssetPublicRoot(), relative)
		}
		if spools[root.index].file == nil {
			filename := filepath.Join(runDir, fmt.Sprintf("remote-projection-%06d.tsv", root.index))
			file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return fail(err)
			}
			spools[root.index] = spool{path: filename, file: file}
		}
		if err := manifest.WriteEntry(spools[root.index].file, entry); err != nil {
			return fail(err)
		}
	}
	if err := closeSpools(); err != nil {
		return err
	}
	inputs := make([]string, 0, len(spools))
	for _, spool := range spools {
		if spool.path != "" {
			inputs = append(inputs, spool.path)
		}
	}
	return mergePublicationManifests(inputs, destinationPath, runDir)
}
