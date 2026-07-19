package state

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path"
	"sort"
	"sync"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/objfile"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/storage"
)

// noObjectCache is intentional for capability-bound canonical readers.
// go-git's filesystem storage keys its object cache by the requested pathname
// hash. A cached MemoryObject would therefore hide an in-place loose-object
// mutation from the read session's final integrity pass.
type noObjectCache struct{}

func (noObjectCache) Put(plumbing.EncodedObject) {}
func (noObjectCache) Get(plumbing.Hash) (plumbing.EncodedObject, bool) {
	return nil, false
}
func (noObjectCache) Clear() {}

type verifiedObjectIdentity struct {
	hash   plumbing.Hash
	typeOf plumbing.ObjectType
	size   int64
}

// verifiedObjectStorer binds the bytes returned for an object request to the
// request's Git identity. The filesystem name or pack index is only a lookup
// hint: type, declared size, exact payload length, and Git payload hash are all
// checked by streaming the object before it is handed to go-git decoders.
//
// Every successful lookup is retained for a final session-bound recheck. The
// embedded storage remains the authority for refs/config/index; boundRootFS
// keeps all mutation methods read-only.
type verifiedObjectStorer struct {
	storage.Storer
	loose billy.Filesystem

	mu       sync.Mutex
	accessed map[verifiedObjectIdentity]struct{}
	packIdx  map[string][sha256.Size]byte
	poisoned error
}

func newVerifiedObjectStorer(base storage.Storer, loose billy.Filesystem) *verifiedObjectStorer {
	return &verifiedObjectStorer{Storer: base, loose: loose, accessed: make(map[verifiedObjectIdentity]struct{})}
}

func (s *verifiedObjectStorer) EncodedObject(requested plumbing.ObjectType, hash plumbing.Hash) (plumbing.EncodedObject, error) {
	looseIdentity, looseFound, err := verifyLooseGitObject(s.loose, requested, hash)
	if err != nil {
		s.poison(err)
		return nil, err
	}
	object, err := s.Storer.EncodedObject(requested, hash)
	if err != nil {
		if looseFound {
			err = fmt.Errorf("%w: loose object %s changed while being opened: %v", ErrGitObjectIntegrity, hash, err)
			s.poison(err)
		} else if !errors.Is(err, plumbing.ErrObjectNotFound) {
			err = fmt.Errorf("%w: open canonical Git object %s: %v", ErrGitObjectIntegrity, hash, err)
			s.poison(err)
		}
		return nil, err
	}
	identity, err := verifyGitObject(object, requested, hash)
	if err != nil {
		s.poison(err)
		return nil, err
	}
	if looseFound && looseIdentity != identity {
		err := fmt.Errorf("%w: loose object %s changed while being opened", ErrGitObjectIntegrity, hash)
		s.poison(err)
		return nil, err
	}
	if !looseFound {
		if err := s.bindPackIndexSet(); err != nil {
			s.poison(err)
			return nil, err
		}
	}
	s.mu.Lock()
	s.accessed[identity] = struct{}{}
	s.mu.Unlock()
	return &verifiedEncodedObject{object: object, identity: identity, owner: s}, nil
}

// IterEncodedObjects cannot bind a loose object's computed payload hash back
// to the directory entry used by go-git's iterator. Canonical read sessions do
// not need full object enumeration, so fail closed instead of offering a path
// that lacks the request identity required for verification.
func (s *verifiedObjectStorer) IterEncodedObjects(plumbing.ObjectType) (storer.EncodedObjectIter, error) {
	return nil, fmt.Errorf("%w: unbound Git object enumeration is disabled", ErrGitObjectIntegrity)
}

func (s *verifiedObjectStorer) HasEncodedObject(hash plumbing.Hash) error {
	_, err := s.EncodedObject(plumbing.AnyObject, hash)
	return err
}

func (s *verifiedObjectStorer) EncodedObjectSize(hash plumbing.Hash) (int64, error) {
	object, err := s.EncodedObject(plumbing.AnyObject, hash)
	if err != nil {
		return 0, err
	}
	return object.Size(), nil
}

// Module would return an unwrapped storage.Storer and therefore create a
// direct object-read bypass. Canonical SOW state has no Git submodules.
func (s *verifiedObjectStorer) Module(string) (storage.Storer, error) {
	return nil, fmt.Errorf("%w: canonical Git submodule storage is disabled", ErrGitObjectIntegrity)
}

func (s *verifiedObjectStorer) poison(err error) {
	if err == nil {
		return
	}
	if !errors.Is(err, ErrGitObjectIntegrity) {
		err = fmt.Errorf("%w: %v", ErrGitObjectIntegrity, err)
	}
	s.mu.Lock()
	if s.poisoned == nil {
		s.poisoned = err
	}
	s.mu.Unlock()
}

// VerifyAccessedObjects reopens every object used by this read session through
// the uncached capability-bound storage. This catches same-inode changes made
// after an earlier phase while HEAD and the direct-ref vector remain stable.
func (s *verifiedObjectStorer) VerifyAccessedObjects() error {
	for {
		s.mu.Lock()
		poisoned := s.poisoned
		objects := make([]verifiedObjectIdentity, 0, len(s.accessed))
		for identity := range s.accessed {
			objects = append(objects, identity)
		}
		s.mu.Unlock()
		if poisoned != nil {
			return poisoned
		}
		if err := s.verifyPackIndexSet(); err != nil {
			return s.reject(err)
		}
		sort.Slice(objects, func(i, j int) bool {
			if objects[i].hash != objects[j].hash {
				return objects[i].hash.String() < objects[j].hash.String()
			}
			if objects[i].typeOf != objects[j].typeOf {
				return objects[i].typeOf < objects[j].typeOf
			}
			return objects[i].size < objects[j].size
		})
		for _, expected := range objects {
			looseIdentity, looseFound, err := verifyLooseGitObject(s.loose, expected.typeOf, expected.hash)
			if err != nil {
				return s.reject(err)
			}
			if looseFound && looseIdentity != expected {
				return s.reject(fmt.Errorf("%w: canonical loose Git object %s type or size changed", ErrGitObjectIntegrity, expected.hash))
			}
			object, err := s.Storer.EncodedObject(expected.typeOf, expected.hash)
			if err != nil {
				return s.reject(fmt.Errorf("%w: reopen canonical Git object %s: %v", ErrGitObjectIntegrity, expected.hash, err))
			}
			actual, err := verifyGitObject(object, expected.typeOf, expected.hash)
			if err != nil {
				return s.reject(err)
			}
			if actual != expected {
				return s.reject(fmt.Errorf("%w: canonical Git object %s type or size changed", ErrGitObjectIntegrity, expected.hash))
			}
		}
		if err := s.verifyPackIndexSet(); err != nil {
			return s.reject(err)
		}
		s.mu.Lock()
		poisoned = s.poisoned
		stable := len(s.accessed) == len(objects)
		s.mu.Unlock()
		if poisoned != nil {
			return poisoned
		}
		if stable {
			return nil
		}
	}
}

// bindPackIndexSet fingerprints the packed-object lookup namespace once a
// session actually consumes a packed object. Object payloads are still
// validated individually; streaming the comparatively small .idx files makes
// a same-path index rewrite visible even though go-git caches decoded indexes.
func (s *verifiedObjectStorer) bindPackIndexSet() error {
	current, err := hashPackIndexSet(s.loose)
	if err != nil {
		return err
	}
	if len(current) == 0 {
		return fmt.Errorf("%w: packed object resolved without a bound pack index", ErrGitObjectIntegrity)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.packIdx == nil {
		s.packIdx = current
		return nil
	}
	if !samePackIndexSet(s.packIdx, current) {
		return fmt.Errorf("%w: packed-object index namespace changed", ErrGitObjectIntegrity)
	}
	return nil
}

func (s *verifiedObjectStorer) verifyPackIndexSet() error {
	s.mu.Lock()
	expected := clonePackIndexSet(s.packIdx)
	s.mu.Unlock()
	if expected == nil {
		return nil
	}
	current, err := hashPackIndexSet(s.loose)
	if err != nil {
		return err
	}
	if !samePackIndexSet(expected, current) {
		return fmt.Errorf("%w: packed-object index namespace changed", ErrGitObjectIntegrity)
	}
	return nil
}

func hashPackIndexSet(filesystem billy.Filesystem) (map[string][sha256.Size]byte, error) {
	entries, err := filesystem.ReadDir("objects/pack")
	if errors.Is(err, fs.ErrNotExist) {
		return map[string][sha256.Size]byte{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: enumerate packed-object indexes: %v", ErrGitObjectIntegrity, err)
	}
	digests := make(map[string][sha256.Size]byte)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || path.Ext(name) != ".idx" {
			continue
		}
		file, err := filesystem.Open(path.Join("objects/pack", name))
		if err != nil {
			return nil, fmt.Errorf("%w: open packed-object index %s: %v", ErrGitObjectIntegrity, name, err)
		}
		hasher := sha256.New()
		_, readErr := io.Copy(hasher, file)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return nil, fmt.Errorf("%w: hash packed-object index %s: %v", ErrGitObjectIntegrity, name, errors.Join(readErr, closeErr))
		}
		var digest [sha256.Size]byte
		copy(digest[:], hasher.Sum(nil))
		digests[name] = digest
	}
	return digests, nil
}

func clonePackIndexSet(source map[string][sha256.Size]byte) map[string][sha256.Size]byte {
	if source == nil {
		return nil
	}
	result := make(map[string][sha256.Size]byte, len(source))
	for name, digest := range source {
		result[name] = digest
	}
	return result
}

func samePackIndexSet(left, right map[string][sha256.Size]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for name, digest := range left {
		if right[name] != digest {
			return false
		}
	}
	return true
}

func (s *verifiedObjectStorer) reject(err error) error {
	s.poison(err)
	return err
}

// verifyLooseGitObject reads the raw loose header as well as the payload. This
// is needed because go-git's small-object MemoryObject rewrites Size() to the
// bytes copied, which otherwise erases a forged declared-size mismatch before
// the validating storer can observe it.
func verifyLooseGitObject(filesystem billy.Filesystem, requested plumbing.ObjectType, hash plumbing.Hash) (verifiedObjectIdentity, bool, error) {
	if filesystem == nil {
		return verifiedObjectIdentity{}, false, fmt.Errorf("%w: bound loose-object filesystem is unavailable", ErrGitObjectIntegrity)
	}
	encoded := hash.String()
	file, err := filesystem.Open(path.Join("objects", encoded[:2], encoded[2:]))
	if errors.Is(err, fs.ErrNotExist) {
		return verifiedObjectIdentity{}, false, nil
	}
	if err != nil {
		return verifiedObjectIdentity{}, true, fmt.Errorf("%w: open loose object %s: %v", ErrGitObjectIntegrity, hash, err)
	}
	reader, err := objfile.NewReader(file)
	if err != nil {
		return verifiedObjectIdentity{}, true, fmt.Errorf("%w: decode loose object %s: %v", ErrGitObjectIntegrity, hash, errors.Join(err, file.Close()))
	}
	typeOf, size, headerErr := reader.Header()
	if headerErr != nil {
		return verifiedObjectIdentity{}, true, fmt.Errorf("%w: read loose object %s header: %v", ErrGitObjectIntegrity, hash, errors.Join(headerErr, reader.Close(), file.Close()))
	}
	identity, verifyErr := verifyGitPayload(reader, requested, hash, typeOf, size)
	closeErr := errors.Join(reader.Close(), file.Close())
	if verifyErr != nil || closeErr != nil {
		return verifiedObjectIdentity{}, true, fmt.Errorf("%w: verify loose object %s: %v", ErrGitObjectIntegrity, hash, errors.Join(verifyErr, closeErr))
	}
	return identity, true, nil
}

func verifyGitObject(object plumbing.EncodedObject, requested plumbing.ObjectType, hash plumbing.Hash) (verifiedObjectIdentity, error) {
	if object == nil {
		return verifiedObjectIdentity{}, fmt.Errorf("%w: object %s lookup returned nil", ErrGitObjectIntegrity, hash)
	}
	reader, err := object.Reader()
	if err != nil {
		return verifiedObjectIdentity{}, fmt.Errorf("%w: open object %s payload: %v", ErrGitObjectIntegrity, hash, err)
	}
	identity, verifyErr := verifyGitPayload(reader, requested, hash, object.Type(), object.Size())
	closeErr := reader.Close()
	if verifyErr != nil || closeErr != nil {
		return verifiedObjectIdentity{}, fmt.Errorf("%w: read object %s payload: %v", ErrGitObjectIntegrity, hash, errors.Join(verifyErr, closeErr))
	}
	return identity, nil
}

func verifyGitPayload(reader io.Reader, requested plumbing.ObjectType, hash plumbing.Hash, typeOf plumbing.ObjectType, size int64) (verifiedObjectIdentity, error) {
	if !typeOf.Valid() || typeOf.IsDelta() {
		return verifiedObjectIdentity{}, fmt.Errorf("%w: object %s has invalid decoded type %s", ErrGitObjectIntegrity, hash, typeOf)
	}
	if requested != plumbing.AnyObject && requested != typeOf {
		return verifiedObjectIdentity{}, fmt.Errorf("%w: object %s type=%s want=%s", ErrGitObjectIntegrity, hash, typeOf, requested)
	}
	if size < 0 || size == math.MaxInt64 {
		return verifiedObjectIdentity{}, fmt.Errorf("%w: object %s has invalid size %d", ErrGitObjectIntegrity, hash, size)
	}
	hasher := plumbing.NewHasher(typeOf, size)
	written, copyErr := io.Copy(&hasher, io.LimitReader(reader, size+1))
	if copyErr != nil {
		return verifiedObjectIdentity{}, fmt.Errorf("%w: read object %s payload: %v", ErrGitObjectIntegrity, hash, copyErr)
	}
	if written != size {
		return verifiedObjectIdentity{}, fmt.Errorf("%w: object %s payload length=%d want=%d", ErrGitObjectIntegrity, hash, written, size)
	}
	if actual := hasher.Sum(); actual != hash {
		return verifiedObjectIdentity{}, fmt.Errorf("%w: object %s payload hashes to %s", ErrGitObjectIntegrity, hash, actual)
	}
	return verifiedObjectIdentity{hash: hash, typeOf: typeOf, size: size}, nil
}

// verifiedEncodedObject protects the second read performed by go-git object
// decoders. Small loose objects are already immutable MemoryObjects here, but
// large loose objects are lazy and reopen their path in Reader. Hashing that
// stream closes the validation-to-use window without buffering the blob.
type verifiedEncodedObject struct {
	object   plumbing.EncodedObject
	identity verifiedObjectIdentity
	owner    *verifiedObjectStorer
}

func (o *verifiedEncodedObject) Hash() plumbing.Hash         { return o.identity.hash }
func (o *verifiedEncodedObject) Type() plumbing.ObjectType   { return o.identity.typeOf }
func (o *verifiedEncodedObject) Size() int64                 { return o.identity.size }
func (o *verifiedEncodedObject) SetType(plumbing.ObjectType) {}
func (o *verifiedEncodedObject) SetSize(int64)               {}
func (o *verifiedEncodedObject) Writer() (io.WriteCloser, error) {
	return nil, fs.ErrPermission
}

func (o *verifiedEncodedObject) Reader() (io.ReadCloser, error) {
	reader, err := o.object.Reader()
	if err != nil {
		err = fmt.Errorf("%w: reopen object %s payload: %v", ErrGitObjectIntegrity, o.identity.hash, err)
		o.owner.poison(err)
		return nil, err
	}
	return &verifiedObjectReader{
		reader: reader, identity: o.identity,
		hasher: plumbing.NewHasher(o.identity.typeOf, o.identity.size), owner: o.owner,
	}, nil
}

type verifiedObjectReader struct {
	reader   io.ReadCloser
	identity verifiedObjectIdentity
	hasher   plumbing.Hasher
	owner    *verifiedObjectStorer
	read     int64
	done     bool
	result   error
	closed   bool
}

func (r *verifiedObjectReader) Read(buffer []byte) (int, error) {
	if r.done {
		if r.result != nil {
			return 0, r.result
		}
		return 0, io.EOF
	}
	n, readErr := r.reader.Read(buffer)
	if n > 0 {
		_, _ = r.hasher.Write(buffer[:n])
		r.read += int64(n)
		if r.read > r.identity.size {
			return n, r.fail(fmt.Errorf("%w: object %s payload exceeded size %d", ErrGitObjectIntegrity, r.identity.hash, r.identity.size))
		}
	}
	if readErr == nil {
		return n, nil
	}
	if !errors.Is(readErr, io.EOF) {
		return n, r.fail(fmt.Errorf("%w: read object %s payload: %v", ErrGitObjectIntegrity, r.identity.hash, readErr))
	}
	if r.read != r.identity.size {
		return n, r.fail(fmt.Errorf("%w: object %s payload length=%d want=%d", ErrGitObjectIntegrity, r.identity.hash, r.read, r.identity.size))
	}
	if actual := r.hasher.Sum(); actual != r.identity.hash {
		return n, r.fail(fmt.Errorf("%w: object %s payload hashes to %s", ErrGitObjectIntegrity, r.identity.hash, actual))
	}
	r.done = true
	return n, io.EOF
}

func (r *verifiedObjectReader) fail(err error) error {
	if !r.done {
		r.done = true
		r.result = err
		r.owner.poison(err)
	}
	return r.result
}

func (r *verifiedObjectReader) Close() error {
	if r.closed {
		return r.result
	}
	var drainErr error
	if !r.done {
		_, drainErr = io.Copy(io.Discard, r)
	}
	closeErr := r.reader.Close()
	if closeErr != nil {
		closeErr = fmt.Errorf("%w: close object %s payload: %w", ErrGitObjectIntegrity, r.identity.hash, closeErr)
		r.owner.poison(closeErr)
		r.result = errors.Join(r.result, closeErr)
		r.done = true
	}
	r.closed = true
	return errors.Join(r.result, drainErr)
}
