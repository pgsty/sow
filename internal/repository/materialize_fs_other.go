//go:build !darwin && !linux

package repository

import (
	"errors"
	"os"
	"path/filepath"
)

var errMaterializePlatformUnsupported = errors.New("atomic descriptor-bound materialization requires Linux or macOS")

func openMaterializeDirectory(path string) (*os.File, error) { return os.Open(path) }

func openMaterializeDirectoryAt(parent *os.File, name string) (*os.File, error) {
	return os.Open(filepath.Join(parent.Name(), name))
}

func openMaterializeEntryAt(parent *os.File, name string) (*os.File, error) {
	return os.Open(filepath.Join(parent.Name(), name))
}

func createMaterializeFileAt(parent *os.File, name string, mode os.FileMode) (*os.File, error) {
	return nil, errMaterializePlatformUnsupported
}

func mkdirMaterializeAt(parent *os.File, name string, mode os.FileMode) error {
	return os.Mkdir(filepath.Join(parent.Name(), name), mode)
}

func linkMaterializeFileAt(source *os.File, parent *os.File, name string) error {
	return errMaterializePlatformUnsupported
}

func unlinkMaterializeAt(parent *os.File, name string) error {
	return os.Remove(filepath.Join(parent.Name(), name))
}

func lstatMaterializeAt(parent *os.File, name string) (materializeFileIdentity, error) {
	info, err := os.Lstat(filepath.Join(parent.Name(), name))
	if err != nil {
		return materializeFileIdentity{}, err
	}
	return materializeFileIdentity{inode: uint64(info.ModTime().UnixNano()) ^ uint64(info.Size())}, nil
}

func fstatMaterialize(file *os.File) (materializeFileIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return materializeFileIdentity{}, err
	}
	return materializeFileIdentity{inode: uint64(info.ModTime().UnixNano()) ^ uint64(info.Size())}, nil
}

func renameMaterializeNoReplaceAt(parent *os.File, oldName, newName string) error {
	return errMaterializePlatformUnsupported
}

func exchangeMaterializeAt(parent *os.File, first, second string) error {
	return errMaterializePlatformUnsupported
}
