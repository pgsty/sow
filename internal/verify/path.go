package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func safeRelative(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\%?#\x00\t\r\n") {
		return false
	}
	clean := path.Clean(value)
	if clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".sow" || segment == ".pool" || segment == ".git" {
			return false
		}
	}
	return true
}

func safeSegment(value string) bool {
	return value != "" && !strings.ContainsAny(value, "/\\%?#\x00\t\r\n") && value != "." && value != ".."
}

func auditTreeShape(ctx context.Context, base string, allowRootShadows bool) error {
	if err := realDirectory(base); err != nil {
		return err
	}
	return filepath.WalkDir(base, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(base, current)
		if err != nil || relative == "." {
			return err
		}
		name := entry.Name()
		reserved := name == ".sow" || name == ".pool" || name == ".git"
		if reserved {
			if allowRootShadows && !strings.ContainsRune(filepath.ToSlash(relative), '/') && entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
				return filepath.SkipDir
			}
			return errors.New("nested or non-directory shadow point is forbidden")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("tree contains a symlink")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("tree contains a special file")
		}
		return nil
	})
}

func openRegularBelow(root, relative string, maxSize int64) (*os.File, os.FileInfo, error) {
	if err := realDirectory(root); err != nil {
		return nil, nil, err
	}
	if !safeRelative(relative) {
		return nil, nil, fmt.Errorf("unsafe relative path %q", relative)
	}
	current := filepath.Clean(root)
	parts := strings.Split(relative, "/")
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, filepath.FromSlash(part))
		info, err := os.Lstat(current)
		if err != nil {
			return nil, nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, nil, errors.New("path traverses a symlink or non-directory")
		}
	}
	filename := filepath.Join(current, filepath.FromSlash(parts[len(parts)-1]))
	entryInfo, err := os.Lstat(filename)
	if err != nil {
		return nil, nil, err
	}
	if entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.Mode().IsRegular() || entryInfo.Size() < 0 || maxSize >= 0 && entryInfo.Size() > maxSize {
		return nil, nil, errors.New("path is not an allowed regular file")
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(entryInfo, opened) {
		_ = f.Close()
		return nil, nil, errors.New("file changed while opening")
	}
	return f, opened, nil
}

func readRegularBelow(root, relative string, maxSize int64) ([]byte, error) {
	f, info, err := openRegularBelow(root, relative, maxSize)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, errors.New("file size changed while reading")
	}
	return data, nil
}

func hashRegularBelow(ctx context.Context, root, relative string, maxSize int64) (string, int64, error) {
	f, before, err := openRegularBelow(root, relative, maxSize)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	hasher := sha256.New()
	written, err := io.CopyBuffer(hasher, &contextReader{ctx: ctx, reader: f}, make([]byte, 256*1024))
	if err != nil {
		return "", 0, err
	}
	after, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if written != before.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", 0, errors.New("file changed while hashing")
	}
	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
