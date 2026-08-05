package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

type EmptyDistSpec struct {
	Name          string
	Format        string
	Architectures []string
	Generation    int64
}

type RenderedDist struct {
	Path       string `json:"path"`
	TreeSHA256 string `json:"tree_sha256"`
	Files      int    `json:"files"`
}

// RenderEmptyDist writes a complete empty P1 Dist into a private repository
// staging root. It never replaces an existing Dist; publication is owned by
// the managed operation journal.
func RenderEmptyDist(ctx context.Context, repositoryStage string, spec EmptyDistSpec) (RenderedDist, error) {
	if ctx == nil {
		return RenderedDist{}, errors.New("managed: nil context")
	}
	if spec.Name == "" || strings.ContainsAny(spec.Name, `/\\`) || spec.Name == "." || spec.Name == ".." {
		return RenderedDist{}, fmt.Errorf("managed: unsafe dist name %q", spec.Name)
	}
	if spec.Format != "rpm" && spec.Format != "deb" {
		return RenderedDist{}, fmt.Errorf("managed: unsupported dist format %q", spec.Format)
	}
	if spec.Generation < 1 {
		return RenderedDist{}, errors.New("managed: empty dist generation must be at least 1")
	}
	architectures, err := validateFamilies(spec.Architectures)
	if err != nil {
		return RenderedDist{}, err
	}
	root, err := filepath.Abs(repositoryStage)
	if err != nil {
		return RenderedDist{}, fmt.Errorf("managed: resolve repository stage: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return RenderedDist{}, fmt.Errorf("managed: repository stage is not a real directory: %w", err)
	}
	dists := filepath.Join(root, "dists")
	if err := durableMkdir(dists, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return RenderedDist{}, fmt.Errorf("managed: create staged dists: %w", err)
	}
	if info, err := os.Lstat(dists); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return RenderedDist{}, errors.New("managed: staged dists path is not a real directory")
	}
	if spec.Format == "deb" {
		projected := make([]state.Architecture, 0, len(architectures))
		for _, family := range architectures {
			ecosystem := "amd64"
			if family == "aarch64" {
				ecosystem = "arm64"
			}
			projected = append(projected, state.Architecture{Family: family, EcosystemArch: ecosystem})
		}
		return RenderManagedDist(ctx, root, ManagedDistSpec{
			Name: spec.Name, Format: spec.Format, Architectures: projected,
			Generation: spec.Generation, Jobs: 1,
		})
	}
	distRoot := filepath.Join(dists, spec.Name)
	if _, err := os.Lstat(distRoot); err == nil {
		return RenderedDist{}, fmt.Errorf("managed: staged dist already exists: %s", distRoot)
	} else if !errors.Is(err, os.ErrNotExist) {
		return RenderedDist{}, fmt.Errorf("managed: inspect staged dist: %w", err)
	}

	switch spec.Format {
	case "rpm":
		if err := durableMkdir(distRoot, 0o755); err != nil {
			return RenderedDist{}, fmt.Errorf("managed: create staged RPM dist: %w", err)
		}
		for _, family := range architectures {
			dest := filepath.Join(distRoot, family, "repodata")
			if _, err := yumrepo.GenerateFlatUnsigned(ctx, dest, spec.Generation, &yumrepo.SliceIterator{}); err != nil {
				return RenderedDist{}, fmt.Errorf("managed: render empty RPM view %s: %w", family, err)
			}
			if _, err := yumrepo.ValidateFlatUnsignedDirectory(ctx, dest, yumrepo.CompressionGzip); err != nil {
				return RenderedDist{}, fmt.Errorf("managed: validate empty RPM view %s: %w", family, err)
			}
		}
	}
	if err := syncTree(distRoot); err != nil {
		return RenderedDist{}, err
	}
	if err := errors.Join(syncDir(dists), syncDir(root)); err != nil {
		return RenderedDist{}, err
	}
	digest, files, err := digestTree(ctx, distRoot)
	if err != nil {
		return RenderedDist{}, err
	}
	return RenderedDist{Path: distRoot, TreeSHA256: digest, Files: files}, nil
}

func validateFamilies(input []string) ([]string, error) {
	if len(input) == 0 {
		return nil, errors.New("managed: at least one canonical architecture is required")
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(input))
	for _, family := range input {
		if family != "x86_64" && family != "aarch64" {
			return nil, fmt.Errorf("managed: unsupported canonical architecture %q", family)
		}
		if _, ok := seen[family]; ok {
			return nil, fmt.Errorf("managed: duplicate canonical architecture %q", family)
		}
		seen[family] = struct{}{}
		out = append(out, family)
	}
	return out, nil
}

func syncTree(root string) error {
	err := walkRootedTree(context.Background(), root,
		func(_ string, file *os.File, _ os.FileInfo) error { return file.Sync() },
		func(_ string, directory *os.File, _ os.FileInfo) error { return directory.Sync() },
	)
	if err != nil {
		return fmt.Errorf("managed: sync staged dist files: %w", err)
	}
	return nil
}

func digestTree(ctx context.Context, root string) (string, int, error) {
	type item struct{ relative, digest string }
	var items []item
	err := walkRootedTree(ctx, root, func(relative string, file *os.File, _ os.FileInfo) error {
		hash := sha256.New()
		if _, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: file}); err != nil {
			return err
		}
		items = append(items, item{relative: relative, digest: hex.EncodeToString(hash.Sum(nil))})
		return nil
	}, nil)
	if err != nil {
		return "", 0, fmt.Errorf("managed: digest staged dist: %w", err)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].relative < items[j].relative })
	tree := sha256.New()
	for _, item := range items {
		fmt.Fprintf(tree, "%s  %s\n", item.digest, item.relative)
	}
	return hex.EncodeToString(tree.Sum(nil)), len(items), nil
}
