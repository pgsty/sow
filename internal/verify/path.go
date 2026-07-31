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

type verificationRootBinding struct {
	path     string
	root     *os.Root
	identity os.FileInfo
}

type verificationSubrootBinding struct {
	parent   *verificationRootBinding
	path     string
	root     *os.Root
	identity os.FileInfo
}

func bindVerificationRoot(name string) (*verificationRootBinding, error) {
	if name == "" {
		return nil, errors.New("empty directory")
	}
	absolute, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	before, err := os.Lstat(absolute)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, errors.Join(err, errors.New("not a real directory"))
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, err
	}
	opened, openErr := root.Stat(".")
	current, pathErr := os.Lstat(absolute)
	if openErr != nil || pathErr != nil || !opened.IsDir() ||
		current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		!os.SameFile(before, opened) || !os.SameFile(before, current) {
		_ = root.Close()
		return nil, errors.Join(openErr, pathErr, errors.New("directory changed while binding"))
	}
	return &verificationRootBinding{path: absolute, root: root, identity: opened}, nil
}

func (binding *verificationRootBinding) Check() error {
	if binding == nil || binding.root == nil {
		return errors.New("verification root is unavailable")
	}
	opened, openErr := binding.root.Stat(".")
	current, pathErr := os.Lstat(binding.path)
	if openErr != nil || pathErr != nil || !opened.IsDir() ||
		current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		!os.SameFile(binding.identity, opened) || !os.SameFile(binding.identity, current) {
		return errors.Join(openErr, pathErr, errors.New("verification root identity changed"))
	}
	return nil
}

func (binding *verificationRootBinding) Close() error {
	if binding == nil || binding.root == nil {
		return nil
	}
	err := binding.root.Close()
	binding.root = nil
	return err
}

func bindVerificationSubroot(parent *verificationRootBinding, relative string) (*verificationSubrootBinding, error) {
	if parent == nil || parent.root == nil || !safeRelative(relative) {
		return nil, errors.New("verification subroot coordinate is unsafe")
	}
	if err := parent.Check(); err != nil {
		return nil, err
	}
	name := filepath.FromSlash(relative)
	before, err := parent.root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, errors.Join(err, errors.New("verification subroot is absent, symlinked, or not a directory"))
	}
	root, err := parent.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, openErr := root.Stat(".")
	current, pathErr := parent.root.Lstat(name)
	if openErr != nil || pathErr != nil || !opened.IsDir() ||
		current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		!os.SameFile(before, opened) || !os.SameFile(before, current) {
		_ = root.Close()
		return nil, errors.Join(openErr, pathErr, errors.New("verification subroot changed while binding"))
	}
	return &verificationSubrootBinding{parent: parent, path: name, root: root, identity: opened}, nil
}

func (binding *verificationSubrootBinding) Check() error {
	if binding == nil || binding.parent == nil || binding.root == nil {
		return errors.New("verification subroot is unavailable")
	}
	if err := binding.parent.Check(); err != nil {
		return err
	}
	opened, openErr := binding.root.Stat(".")
	current, pathErr := binding.parent.root.Lstat(binding.path)
	if openErr != nil || pathErr != nil || !opened.IsDir() ||
		current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		!os.SameFile(binding.identity, opened) || !os.SameFile(binding.identity, current) {
		return errors.Join(openErr, pathErr, errors.New("verification subroot identity changed"))
	}
	return nil
}

func (binding *verificationSubrootBinding) Close() error {
	if binding == nil || binding.root == nil {
		return nil
	}
	checkErr := binding.Check()
	closeErr := binding.root.Close()
	binding.root = nil
	return errors.Join(checkErr, closeErr)
}

type verificationRegularFile struct {
	root     *verificationSubrootBinding
	name     string
	file     *os.File
	identity os.FileInfo
	closed   bool
}

func openVerificationRegularFile(root *verificationSubrootBinding, name string, exactSize int64) (*verificationRegularFile, error) {
	if root == nil || root.root == nil || !safeSegment(name) || exactSize < 0 {
		return nil, errors.New("verification regular-file request is unsafe")
	}
	if err := root.Check(); err != nil {
		return nil, err
	}
	before, err := root.root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != exactSize {
		return nil, errors.Join(err, errors.New("verification artifact is not the expected regular file"))
	}
	file, err := root.root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, openErr := file.Stat()
	current, pathErr := root.root.Lstat(name)
	if openErr != nil || pathErr != nil || !opened.Mode().IsRegular() ||
		current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(before, current) {
		_ = file.Close()
		return nil, errors.Join(openErr, pathErr, errors.New("verification artifact changed while opening"))
	}
	return &verificationRegularFile{root: root, name: name, file: file, identity: opened}, nil
}

func (file *verificationRegularFile) Check() error {
	if file == nil || file.root == nil || file.file == nil || file.closed {
		return errors.New("verification regular file is unavailable")
	}
	if err := file.root.Check(); err != nil {
		return err
	}
	opened, openErr := file.file.Stat()
	current, pathErr := file.root.root.Lstat(file.name)
	if openErr != nil || pathErr != nil || !opened.Mode().IsRegular() ||
		current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(file.identity, opened) || !os.SameFile(file.identity, current) ||
		opened.Size() != file.identity.Size() || current.Size() != file.identity.Size() ||
		opened.Mode() != file.identity.Mode() || current.Mode() != file.identity.Mode() ||
		!opened.ModTime().Equal(file.identity.ModTime()) || !current.ModTime().Equal(file.identity.ModTime()) {
		return errors.Join(openErr, pathErr, errors.New("verification artifact changed while reading"))
	}
	return nil
}

func (file *verificationRegularFile) Close() error {
	if file == nil || file.closed {
		return nil
	}
	checkErr := file.Check()
	file.closed = true
	closeErr := file.file.Close()
	file.file = nil
	return errors.Join(checkErr, closeErr)
}

type optionalTreeParent struct {
	path     string
	identity os.FileInfo
}

type optionalTreeAbsenceWitness struct {
	root    *verificationRootBinding
	path    string
	parents []optionalTreeParent
}

// bindOptionalTreeAbsence distinguishes one absent payload leaf from a
// missing/replaced repository root or parent. The returned witness retains the
// root capability and every parent inode for all later stream boundaries.
func bindOptionalTreeAbsence(root *verificationRootBinding, scopePath string) (*optionalTreeAbsenceWitness, bool, error) {
	if root == nil || root.root == nil {
		return nil, false, errors.New("optional tree root is unavailable")
	}
	if scopePath == "" {
		scopePath = "."
	}
	if strings.ContainsAny(scopePath, "\\\x00\t\r\n") || path.IsAbs(scopePath) ||
		path.Clean(scopePath) != scopePath || scopePath == ".." || strings.HasPrefix(scopePath, "../") {
		return nil, false, errors.New("optional tree scope is unsafe")
	}
	if err := root.Check(); err != nil {
		return nil, false, err
	}
	if scopePath == "." {
		return nil, true, nil
	}
	parts := strings.Split(scopePath, "/")
	witness := &optionalTreeAbsenceWitness{root: root, path: scopePath}
	for index := 1; index < len(parts); index++ {
		parentPath := strings.Join(parts[:index], "/")
		info, err := root.root.Lstat(filepath.FromSlash(parentPath))
		if err != nil {
			return nil, false, fmt.Errorf("inspect optional tree parent %s: %w", parentPath, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, false, fmt.Errorf("optional tree parent %s is not a real directory", parentPath)
		}
		witness.parents = append(witness.parents, optionalTreeParent{path: parentPath, identity: info})
	}
	info, err := root.root.Lstat(filepath.FromSlash(scopePath))
	if errors.Is(err, fs.ErrNotExist) {
		if err := witness.Check(); err != nil {
			return nil, false, err
		}
		return witness, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect optional tree %s: %w", scopePath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, false, errors.New("optional tree is not a real directory")
	}
	return nil, true, nil
}

func (witness *optionalTreeAbsenceWitness) Check() error {
	if witness == nil || witness.root == nil {
		return errors.New("optional tree absence witness is unavailable")
	}
	if err := witness.root.Check(); err != nil {
		return err
	}
	for _, parent := range witness.parents {
		info, err := witness.root.root.Lstat(filepath.FromSlash(parent.path))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !os.SameFile(parent.identity, info) {
			return errors.Join(err, fmt.Errorf("optional tree parent %s changed", parent.path))
		}
	}
	_, err := witness.root.root.Lstat(filepath.FromSlash(witness.path))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect optional tree %s: %w", witness.path, err)
	}
	return fmt.Errorf("optional tree %s appeared during verification", witness.path)
}

// absentTreeStream binds an empty manifest to a root-capability absence
// witness. Open, every read, and close all recheck root/parent identity and the
// missing leaf, so replacement cannot be accepted as an empty repository.
func absentTreeStream(witness *optionalTreeAbsenceWitness) Stream {
	return func() (io.ReadCloser, error) {
		reader := &absentTreeReader{witness: witness}
		if err := reader.requireAbsent(); err != nil {
			return nil, err
		}
		return reader, nil
	}
}

type absentTreeReader struct {
	witness *optionalTreeAbsenceWitness
	closed  bool
}

func (r *absentTreeReader) Read([]byte) (int, error) {
	if r.closed {
		return 0, os.ErrClosed
	}
	if err := r.requireAbsent(); err != nil {
		return 0, err
	}
	return 0, io.EOF
}

func (r *absentTreeReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.requireAbsent()
}

func (r *absentTreeReader) requireAbsent() error {
	if r.witness == nil {
		return errors.New("optional tree absence witness is unavailable")
	}
	return r.witness.Check()
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
