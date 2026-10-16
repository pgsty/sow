package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
)

type RenderedDist struct {
	Path       string `json:"path"`
	TreeSHA256 string `json:"tree_sha256"`
	Files      int    `json:"files"`
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
		digest, err := hashRegularDescriptor(ctx, file)
		if err != nil {
			return fmt.Errorf("digest regular content %q: %w", relative, err)
		}
		items = append(items, item{relative: relative, digest: digest})
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
