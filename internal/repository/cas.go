package repository

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

const copyBufferSize = 256 * 1024

var copyBufferPool = sync.Pool{New: func() any {
	buffer := make([]byte, copyBufferSize)
	return &buffer
}}

func acquireCopyBuffer() *[]byte {
	return copyBufferPool.Get().(*[]byte)
}

func releaseCopyBuffer(buffer *[]byte) {
	if buffer == nil || len(*buffer) != copyBufferSize {
		return
	}
	copyBufferPool.Put(buffer)
}

// Store owns the immutable SHA-256 pool below one repository root.
type Store struct {
	root     string
	poolRoot string
	tempRoot string
	readOnly bool

	// OpenStore retains this descriptor chain for the complete lifetime of a
	// read-only Store. Public path strings remain diagnostics only: no admitted
	// object is opened through them again.
	readRootParent *os.File
	readRootName   string
	readRoot       *os.File
	readPoolParent *os.File
	readPool       *os.File

	closeOnce sync.Once
	closeErr  error

	readOnlyTestHook readOnlyStoreTestHook
}

// NewStore opens (and, when necessary, creates) .pool/sha256 below an existing
// repository root. Existing symlinked pool components are rejected.
func NewStore(root string) (*Store, error) {
	realRoot, err := canonicalDirectory(root)
	if err != nil {
		return nil, err
	}
	poolRoot, err := ensureDirectory(realRoot, filepath.Join(".pool", "sha256"), 0o755)
	if err != nil {
		return nil, err
	}
	tempRoot, err := ensureDirectory(poolRoot, ".tmp", 0o700)
	if err != nil {
		return nil, err
	}
	return &Store{root: realRoot, poolRoot: poolRoot, tempRoot: tempRoot}, nil
}

// OpenStore opens an already-existing CAS without creating .pool, sha256,
// .tmp, shards, or any other path. It is intended for render-only admission
// and audits. Root/.pool/sha256 directory descriptors are retained for every
// read, while their public coordinates are checked only for continuity. The
// caller must Close the returned Store.
func OpenStore(root string) (*Store, error) {
	return openReadOnlyStore(root)
}

// Root returns the configured repository coordinate. For OpenStore this is a
// diagnostic value only; retained descriptors, not this string, are authority.
func (s *Store) Root() string { return s.root }

// PoolRoot returns the configured CAS coordinate. Read-only operations never
// reopen this path after OpenStore admission.
func (s *Store) PoolRoot() string { return s.poolRoot }

// ObjectPath returns the configured canonical coordinate for diagnostics and
// write-side callers. A read-only Store never uses this pathname as authority;
// its object access remains rooted at the descriptors retained by OpenStore.
func (s *Store) ObjectPath(digest Digest) string {
	hash := digest.String()
	return filepath.Join(s.poolRoot, hash[:2], hash)
}

func (s *Store) ensurePoolBase() error {
	if s.readOnly {
		return s.verifyReadOnlyPoolBase()
	}
	pool, err := ensureDirectory(s.root, filepath.Join(".pool", "sha256"), 0o755)
	if err != nil {
		return err
	}
	if pool != s.poolRoot {
		return fmt.Errorf("%w: pool root changed from %q to %q", ErrUnsafePath, s.poolRoot, pool)
	}
	temp, err := ensureDirectory(s.poolRoot, ".tmp", 0o700)
	if err != nil {
		return err
	}
	if temp != s.tempRoot {
		return fmt.Errorf("%w: pool temporary root changed", ErrUnsafePath)
	}
	return nil
}

func (s *Store) ensureShard(digest Digest) (string, error) {
	if s.readOnly {
		return "", fmt.Errorf("%w: read-only CAS cannot create shard %s", ErrUnsafePath, digest.String()[:2])
	}
	if err := s.ensurePoolBase(); err != nil {
		return "", err
	}
	return ensureDirectory(s.poolRoot, digest.String()[:2], 0o755)
}

type stagedObject struct {
	object Object
	path   string
}

// Put streams r into an immutable CAS object. It never exposes a partial object
// and never overwrites an occupied coordinate.
func (s *Store) Put(ctx context.Context, r io.Reader) (Object, error) {
	if s.readOnly {
		return Object{}, fmt.Errorf("%w: read-only CAS cannot store objects", ErrUnsafePath)
	}
	staged, err := s.stage(ctx, r)
	if err != nil {
		return Object{}, err
	}
	return s.install(ctx, staged)
}

// Import streams one existing regular file into the CAS. Symlinks and special
// files are rejected, and a source that changes during import is not installed.
func (s *Store) Import(ctx context.Context, source string) (Object, error) {
	if s.readOnly {
		return Object{}, fmt.Errorf("%w: read-only CAS cannot import objects", ErrUnsafePath)
	}
	staged, err := s.stageImport(ctx, source)
	if err != nil {
		return Object{}, err
	}
	return s.install(ctx, staged)
}

// ImportExpected imports source only when its stable bytes match expected.
// The comparison happens before installation, so a post-verification download
// replacement cannot introduce an unrelated orphan object into the CAS.
func (s *Store) ImportExpected(ctx context.Context, source string, expected Object) (Object, error) {
	if s.readOnly {
		return Object{}, fmt.Errorf("%w: read-only CAS cannot import objects", ErrUnsafePath)
	}
	if err := expected.validate(); err != nil {
		return Object{}, err
	}
	// Idempotent imports must still prove both sides, but need not create and
	// fsync a throwaway staging file when the immutable CAS coordinate already
	// contains the expected object. Verify the occupied coordinate first, then
	// hash one stable source inode over its complete read lifetime.
	destination := s.ObjectPath(expected.SHA256)
	if _, err := os.Lstat(destination); err == nil {
		if err := s.Verify(ctx, expected); err != nil {
			return Object{}, err
		}
		if err := verifyExpectedImportSource(ctx, source, expected); err != nil {
			return Object{}, err
		}
		return expected, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Object{}, fmt.Errorf("inspect expected CAS coordinate %s: %w", expected.HashString(), err)
	}
	staged, err := s.stageImport(ctx, source)
	if err != nil {
		return Object{}, err
	}
	defer os.Remove(staged.path)
	if staged.object != expected {
		return Object{}, fmt.Errorf("%w: import source %q is %s/%d, expected %s/%d",
			ErrObjectCorrupt, source, staged.object.HashString(), staged.object.Size, expected.HashString(), expected.Size)
	}
	return s.install(ctx, staged)
}

func verifyExpectedImportSource(ctx context.Context, source string, expected Object) error {
	file, before, err := openRegular(source)
	if err != nil {
		return fmt.Errorf("open import source %q: %w", source, err)
	}
	if before.Size() != expected.Size {
		return errors.Join(file.Close(), fmt.Errorf("%w: import source %q size is %d, expected %d", ErrObjectCorrupt, source, before.Size(), expected.Size))
	}
	hasher := sha256.New()
	buffer := acquireCopyBuffer()
	written, readErr := io.CopyBuffer(hasher, contextReader{ctx: ctx, reader: file}, *buffer)
	releaseCopyBuffer(buffer)
	after, statErr := file.Stat()
	closeErr := file.Close()
	current, pathErr := os.Lstat(source)
	if readErr != nil || statErr != nil || closeErr != nil || pathErr != nil {
		return errors.Join(readErr, statErr, closeErr, pathErr, fmt.Errorf("verify import source %q", source))
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(before, after) || !os.SameFile(before, current) ||
		before.Size() != after.Size() || before.Size() != current.Size() || written != expected.Size ||
		!before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(current.ModTime()) {
		return fmt.Errorf("import source %q changed while reading", source)
	}
	actual := hasher.Sum(nil)
	var digest Digest
	copy(digest[:], actual)
	if digest != expected.SHA256 {
		return fmt.Errorf("%w: import source %q has SHA256 %x, expected %s", ErrObjectCorrupt, source, actual, expected.HashString())
	}
	return nil
}

func (s *Store) stageImport(ctx context.Context, source string) (stagedObject, error) {
	file, before, err := openRegular(source)
	if err != nil {
		return stagedObject{}, fmt.Errorf("open import source %q: %w", source, err)
	}
	staged, stageErr := s.stage(ctx, file)
	after, statErr := file.Stat()
	closeErr := file.Close()
	if stageErr != nil {
		return stagedObject{}, stageErr
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(staged.path)
		}
	}()
	if statErr != nil {
		return stagedObject{}, fmt.Errorf("restat import source %q: %w", source, statErr)
	}
	if closeErr != nil {
		return stagedObject{}, fmt.Errorf("close import source %q: %w", source, closeErr)
	}
	current, err := os.Lstat(source)
	if err != nil {
		return stagedObject{}, fmt.Errorf("reinspect import source %q: %w", source, err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(before, after) || !os.SameFile(before, current) ||
		before.Size() != after.Size() || before.Size() != staged.object.Size ||
		!before.ModTime().Equal(after.ModTime()) {
		return stagedObject{}, fmt.Errorf("import source %q changed while reading", source)
	}
	keep = true
	return staged, nil
}

func (s *Store) stage(ctx context.Context, reader io.Reader) (stagedObject, error) {
	if reader == nil {
		return stagedObject{}, errors.New("nil CAS input reader")
	}
	if s.readOnly {
		return stagedObject{}, fmt.Errorf("%w: read-only CAS cannot stage objects", ErrUnsafePath)
	}
	if err := s.ensurePoolBase(); err != nil {
		return stagedObject{}, err
	}
	temp, err := os.CreateTemp(s.tempRoot, "put-")
	if err != nil {
		return stagedObject{}, fmt.Errorf("create CAS staging file: %w", err)
	}
	name := temp.Name()
	keep := false
	defer func() {
		if !keep {
			temp.Close()
			os.Remove(name)
		}
	}()

	hasher := sha256.New()
	buffer := acquireCopyBuffer()
	defer releaseCopyBuffer(buffer)
	written, err := io.CopyBuffer(io.MultiWriter(temp, hasher), contextReader{ctx: ctx, reader: reader}, *buffer)
	if err != nil {
		return stagedObject{}, fmt.Errorf("stream CAS input: %w", err)
	}
	if err := temp.Chmod(0o444); err != nil {
		return stagedObject{}, fmt.Errorf("make CAS staging object immutable: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return stagedObject{}, fmt.Errorf("sync CAS staging object: %w", err)
	}
	if err := temp.Close(); err != nil {
		return stagedObject{}, fmt.Errorf("close CAS staging object: %w", err)
	}
	var digest Digest
	copy(digest[:], hasher.Sum(nil))
	keep = true
	return stagedObject{object: Object{SHA256: digest, Size: written}, path: name}, nil
}

func (s *Store) install(ctx context.Context, staged stagedObject) (Object, error) {
	defer os.Remove(staged.path)
	if err := staged.object.validate(); err != nil {
		return Object{}, err
	}
	shard, err := s.ensureShard(staged.object.SHA256)
	if err != nil {
		return Object{}, err
	}
	destination := s.ObjectPath(staged.object.SHA256)
	if err := os.Link(staged.path, destination); err == nil {
		if err := syncDirectory(shard); err != nil {
			return Object{}, fmt.Errorf("sync CAS shard: %w", err)
		}
		return staged.object, nil
	} else if !errors.Is(err, fs.ErrExist) {
		return Object{}, fmt.Errorf("atomically install CAS object %s: %w", staged.object.HashString(), err)
	}

	if err := compareExistingObject(ctx, destination, staged.path, staged.object); err != nil {
		return Object{}, err
	}
	return staged.object, nil
}

func compareExistingObject(ctx context.Context, existing, staged string, object Object) error {
	left, leftInfo, err := openRegular(existing)
	if err != nil {
		return fmt.Errorf("%w: inspect existing coordinate %s: %v", ErrObjectConflict, object.HashString(), err)
	}
	defer left.Close()
	right, rightInfo, err := openRegular(staged)
	if err != nil {
		return fmt.Errorf("inspect staged CAS object: %w", err)
	}
	defer right.Close()
	if leftInfo.Size() != object.Size || rightInfo.Size() != object.Size {
		return fmt.Errorf("%w: coordinate %s has size %d, incoming size %d", ErrObjectConflict, object.HashString(), leftInfo.Size(), object.Size)
	}
	equal, err := equalFiles(ctx, left, right)
	if err != nil {
		return fmt.Errorf("compare occupied CAS coordinate %s: %w", object.HashString(), err)
	}
	if !equal {
		return fmt.Errorf("%w: coordinate %s contains different bytes", ErrObjectConflict, object.HashString())
	}
	return nil
}

// Open opens an immutable object after rejecting symlinks and special files.
// The caller must close the returned file.
func (s *Store) Open(digest Digest) (*os.File, error) {
	if s.readOnly {
		return s.openReadOnlyObject(digest)
	}
	if err := s.ensurePoolBase(); err != nil {
		return nil, err
	}
	shard := filepath.Join(s.poolRoot, digest.String()[:2])
	shardIdentity, err := stableRealDirectory(shard)
	if err != nil {
		return nil, fmt.Errorf("inspect CAS shard: %w", err)
	}
	file, _, err := openRegular(s.ObjectPath(digest))
	if err != nil {
		return nil, fmt.Errorf("open CAS object %s: %w", digest, err)
	}
	if current, err := stableRealDirectory(shard); err != nil || !os.SameFile(shardIdentity, current) {
		_ = file.Close()
		return nil, errors.Join(err, fmt.Errorf("%w: CAS shard changed while opening object", ErrUnsafePath))
	}
	return file, nil
}

// OpenVerified opens object once, verifies size and SHA-256 on that retained
// descriptor, rewinds it, and returns the same descriptor to the caller. This
// is the read-side primitive for checks that must compare a CAS inode with a
// separately opened hardlink without resolving the digest coordinate again.
func (s *Store) OpenVerified(ctx context.Context, object Object) (*os.File, error) {
	if err := object.validate(); err != nil {
		return nil, err
	}
	file, err := s.Open(object.SHA256)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*os.File, error) {
		return nil, errors.Join(err, file.Close())
	}
	if err := verifyOpenedObject(ctx, file, object); err != nil {
		return fail(err)
	}
	return file, nil
}

// VerifyOpenedObject re-verifies one already-retained regular-file descriptor
// against its immutable CAS identity and rewinds it. Callers use this after
// comparing a public hardlink with an OpenVerified descriptor so an in-place,
// same-size rewrite between the first digest pass and the inode comparison is
// still detected without resolving either pathname again. Ownership of file
// remains with the caller.
func VerifyOpenedObject(ctx context.Context, file *os.File, object Object) error {
	if err := object.validate(); err != nil {
		return err
	}
	return verifyOpenedObject(ctx, file, object)
}

// verifyOpenedObject verifies and rewinds one already-retained regular-file
// descriptor. It intentionally has no pathname input.
func verifyOpenedObject(ctx context.Context, file *os.File, object Object) error {
	if file == nil {
		return fmt.Errorf("%w: nil retained descriptor for %s", ErrObjectCorrupt, object.HashString())
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat CAS object %s: %w", object.HashString(), err)
	}
	if info.Size() != object.Size {
		return fmt.Errorf("%w: object %s size is %d, expected %d", ErrObjectCorrupt, object.HashString(), info.Size(), object.Size)
	}
	hasher := sha256.New()
	buffer := acquireCopyBuffer()
	defer releaseCopyBuffer(buffer)
	written, err := io.CopyBuffer(hasher, contextReader{ctx: ctx, reader: file}, *buffer)
	if err != nil {
		return fmt.Errorf("verify CAS object %s: %w", object.HashString(), err)
	}
	if written != object.Size {
		return fmt.Errorf("%w: object %s changed size while reading", ErrObjectCorrupt, object.HashString())
	}
	var actual Digest
	copy(actual[:], hasher.Sum(nil))
	if actual != object.SHA256 {
		return fmt.Errorf("%w: object %s hashes to %s", ErrObjectCorrupt, object.HashString(), actual)
	}
	last, err := file.Stat()
	if err != nil || last.Size() != object.Size || !os.SameFile(info, last) {
		return errors.Join(err, fmt.Errorf("%w: object %s changed while verifying", ErrObjectCorrupt, object.HashString()))
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind verified CAS object %s: %w", object.HashString(), err)
	}
	return nil
}

// Verify streams and verifies both the size and SHA-256 of object.
func (s *Store) Verify(ctx context.Context, object Object) error {
	file, err := s.OpenVerified(ctx, object)
	if err != nil {
		return err
	}
	return file.Close()
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(buffer []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
	}
	n, err := r.reader.Read(buffer)
	if err == nil {
		select {
		case <-r.ctx.Done():
			return n, r.ctx.Err()
		default:
		}
	}
	return n, err
}

func equalFiles(ctx context.Context, left, right *os.File) (bool, error) {
	leftBufferRef := acquireCopyBuffer()
	rightBufferRef := acquireCopyBuffer()
	defer releaseCopyBuffer(leftBufferRef)
	defer releaseCopyBuffer(rightBufferRef)
	leftBuffer := *leftBufferRef
	rightBuffer := *rightBufferRef
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}
		leftN, leftErr := io.ReadFull(left, leftBuffer)
		rightN, rightErr := io.ReadFull(right, rightBuffer)
		if leftN != rightN {
			return false, nil
		}
		for i := 0; i < leftN; i++ {
			if leftBuffer[i] != rightBuffer[i] {
				return false, nil
			}
		}
		leftDone := errors.Is(leftErr, io.EOF) || errors.Is(leftErr, io.ErrUnexpectedEOF)
		rightDone := errors.Is(rightErr, io.EOF) || errors.Is(rightErr, io.ErrUnexpectedEOF)
		if leftDone || rightDone {
			return leftDone && rightDone, nil
		}
		if leftErr != nil {
			return false, leftErr
		}
		if rightErr != nil {
			return false, rightErr
		}
	}
}
