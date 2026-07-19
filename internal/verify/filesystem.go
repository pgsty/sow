package verify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pgsty/sow/internal/manifest"
)

// FilesystemCheck proves that a directly hostable tree exactly matches its
// canonical manifest. Scanning hashes real bytes, rejects symlinks and special
// files, and uses external sorted runs through manifest.Scan.
type FilesystemCheck struct {
	CheckID      string
	Root         string
	Scope        manifest.Scope
	Expected     Stream
	Workers      int
	ChunkEntries int
	TempDir      string
}

func (c FilesystemCheck) ID() string   { return c.CheckID }
func (c FilesystemCheck) Layer() Layer { return LayerL1 }

func (c FilesystemCheck) Verify(ctx context.Context, recorder *Recorder) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.Expected == nil {
		return errors.New("filesystem check requires a canonical manifest stream")
	}
	if err := realDirectory(c.Root); err != nil {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "FS_ROOT_UNSAFE", Subject: c.CheckID, Message: "repository root is absent, symlinked, or not a directory"})
		return nil
	}
	tempRoot, removeTemp, err := verificationTemp(c.TempDir, "sow-verify-fs-")
	if err != nil {
		return fmt.Errorf("create filesystem verification temp directory: %w", err)
	}
	if removeTemp {
		defer os.RemoveAll(tempRoot)
	}
	if scratchVisibleToScope(c.Root, c.Scope.Path, tempRoot) {
		return errors.New("filesystem verification scratch directory is inside the scanned scope")
	}
	scopePath := filepath.Join(c.Root, filepath.FromSlash(c.Scope.Path))
	allowRootShadows := c.Scope.Path == "" || c.Scope.Path == "."
	if err := auditTreeShape(ctx, scopePath, allowRootShadows); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "FS_TREE_UNSAFE", Subject: c.CheckID, Message: "repository tree contains a symlink, special file, or nested shadow point"})
		return nil
	}
	actualPath := filepath.Join(tempRoot, "actual.tsv")
	_, err = manifest.Scan(ctx, c.Root, c.Scope, actualPath, manifest.ScanOptions{
		Workers: c.Workers, ChunkEntries: c.ChunkEntries, TempDir: tempRoot,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "FS_SCAN_FAILED", Subject: c.CheckID, Message: "repository tree could not be safely scanned"})
		return nil
	}
	comparison := ManifestComparisonCheck{
		CheckID: c.CheckID + "/manifest", AtLayer: LayerL1, Subject: c.CheckID,
		Desired: c.Expected, Actual: FileStream(actualPath), CodePrefix: "FS",
	}
	return comparison.Verify(ctx, recorder)
}

func scratchVisibleToScope(root, scope, scratch string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return true
	}
	scopeAbs := filepath.Join(rootAbs, filepath.FromSlash(scope))
	scratchAbs, err := filepath.Abs(scratch)
	if err != nil {
		return true
	}
	relScope, err := filepath.Rel(scopeAbs, scratchAbs)
	if err != nil || relScope == ".." || strings.HasPrefix(relScope, ".."+string(filepath.Separator)) {
		return false
	}
	relRoot, err := filepath.Rel(rootAbs, scratchAbs)
	if err != nil {
		return true
	}
	for _, component := range strings.Split(filepath.ToSlash(relRoot), "/") {
		if component == ".sow" || component == ".pool" || component == ".git" {
			return false
		}
	}
	return true
}

func realDirectory(name string) error {
	if name == "" {
		return errors.New("empty directory")
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("not a real directory")
	}
	return nil
}
