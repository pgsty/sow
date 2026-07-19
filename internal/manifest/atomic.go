package manifest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func AtomicCopy(dst string, src io.Reader, mode os.FileMode) error {
	return atomicCopyWithDirectorySync(dst, src, mode, syncManifestDirectory)
}

func atomicCopyWithDirectorySync(dst string, src io.Reader, mode os.FileMode, syncDirectory func(string) error) error {
	if syncDirectory == nil {
		return errors.New("manifest directory sync is unavailable")
	}
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create manifest directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".sow-manifest-*")
	if err != nil {
		return fmt.Errorf("create temporary manifest: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := io.Copy(tmp, src); err != nil {
		return fmt.Errorf("write temporary manifest: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temporary manifest: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary manifest: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("replace manifest: %w", err)
	}
	committed = true
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync manifest directory: %w", err)
	}
	return nil
}

func syncManifestDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(handle.Sync(), handle.Close())
}
