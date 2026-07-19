package publish

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Source interface {
	Open(path string) (io.ReadCloser, error)
}

type DirectorySource struct {
	Root string
}

func (s DirectorySource) Open(name string) (io.ReadCloser, error) {
	if err := validateRemoteKey(name); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(s.Root)
	if err != nil {
		return nil, fmt.Errorf("open publish root: %w", err)
	}
	defer root.Close()
	localName := filepath.FromSlash(name)
	parts := strings.Split(localName, string(filepath.Separator))
	prefix := ""
	var info os.FileInfo
	for _, part := range parts {
		prefix = filepath.Join(prefix, part)
		info, err = root.Lstat(prefix)
		if err != nil {
			return nil, fmt.Errorf("inspect publish source %s: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("publish source %s contains a symbolic link", name)
		}
	}
	if info == nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("publish source %s is not a regular file", name)
	}
	file, err := root.Open(localName)
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("publish source %s changed while opening", name)
	}
	return file, nil
}
