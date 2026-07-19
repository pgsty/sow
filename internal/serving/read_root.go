package serving

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// ReadMirrorlistRoot reads an immutable pointer through a retained serving
// root. It has the same absence semantics as ReadMirrorlist and additionally
// requires the public coordinate to remain the opened regular file.
func ReadMirrorlistRoot(root *os.Root, relative string) ([]byte, bool, error) {
	if root == nil {
		return nil, false, errors.New("bound mirrorlist root is unavailable")
	}
	if err := validateServingRelativePath(relative); err != nil {
		return nil, false, err
	}
	name := filepath.FromSlash(relative)
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > mirrorlistMaxBytes {
		return nil, false, errors.Join(err, errors.New("mirrorlist coordinate is not a regular non-symlink file"))
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, false, err
	}
	opened, statErr := file.Stat()
	afterOpen, lstatErr := root.Lstat(name)
	if statErr != nil || lstatErr != nil || !os.SameFile(info, opened) || !os.SameFile(info, afterOpen) {
		return nil, false, errors.Join(statErr, lstatErr, file.Close(), errors.New("mirrorlist coordinate changed while opening"))
	}
	body, readErr := io.ReadAll(io.LimitReader(file, mirrorlistMaxBytes+1))
	afterRead, restatErr := file.Stat()
	coordinate, coordinateErr := root.Lstat(name)
	closeErr := file.Close()
	if readErr != nil || restatErr != nil || coordinateErr != nil || closeErr != nil || len(body) > mirrorlistMaxBytes ||
		int64(len(body)) != opened.Size() || opened.Size() != afterRead.Size() || !opened.ModTime().Equal(afterRead.ModTime()) ||
		!os.SameFile(opened, afterRead) || !os.SameFile(opened, coordinate) {
		return nil, false, errors.Join(readErr, restatErr, coordinateErr, closeErr, errors.New("mirrorlist exceeded its limit or changed while reading"))
	}
	return body, true, nil
}
