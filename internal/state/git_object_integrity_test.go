package state

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/storage"
)

const largeCanonicalBlobSize = (1 << 20) + 257

type boundObjectFixture struct {
	root       string
	dotGitPath string
	head       plumbing.Hash
	tree       plumbing.Hash
	blob       plumbing.Hash
	repository *git.Repository
	store      *Store
}

func newBoundObjectFixture(t *testing.T, payload []byte) boundObjectFixture {
	return newBoundObjectFixtureWithPacking(t, payload, false)
}

func newBoundObjectFixtureWithPacking(t *testing.T, payload []byte, pack bool) boundObjectFixture {
	t.Helper()
	root := t.TempDir()
	stage := filepath.Join(root, "value.bin")
	if err := os.WriteFile(stage, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	writable := New(filepath.Join(root, ".sow"))
	head, changed, err := writable.InstallPaths(map[string]string{"proof/value.bin": stage}, "object integrity fixture")
	if err != nil || !changed || head.IsZero() {
		t.Fatalf("install object fixture changed=%t head=%s err=%v", changed, head, err)
	}
	plain, err := writable.OpenRepository()
	if err != nil {
		t.Fatal(err)
	}
	commit, err := plain.CommitObject(head)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := commit.Tree()
	if err != nil {
		t.Fatal(err)
	}
	file, err := tree.File("proof/value.bin")
	if err != nil {
		t.Fatal(err)
	}
	dotGitPath := filepath.Join(root, ".sow", "state", ".git")
	if pack {
		packRepositoryObjects(t, plain, dotGitPath)
	}
	dotGit, err := os.OpenRoot(dotGitPath)
	if err != nil {
		t.Fatal(err)
	}
	repository, closeRepository, err := OpenBoundRepository(dotGit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeRepository(); err != nil {
			t.Errorf("close bound repository: %v", err)
		}
	})
	bound, err := NewReadOnlyRepository(filepath.Join(root, ".sow"), repository)
	if err != nil {
		t.Fatal(err)
	}
	return boundObjectFixture{
		root: root, dotGitPath: dotGitPath, head: head, tree: commit.TreeHash,
		blob: file.Hash, repository: repository, store: bound,
	}
}

func packRepositoryObjects(t *testing.T, repository *git.Repository, dotGitPath string) {
	t.Helper()
	iterator, err := repository.Storer.IterEncodedObjects(plumbing.AnyObject)
	if err != nil {
		t.Fatal(err)
	}
	var hashes []plumbing.Hash
	err = iterator.ForEach(func(object plumbing.EncodedObject) error {
		hashes = append(hashes, object.Hash())
		return nil
	})
	iterator.Close()
	if err != nil {
		t.Fatal(err)
	}
	packWriter, ok := repository.Storer.(storer.PackfileWriter)
	if !ok {
		t.Fatal("writable fixture storer has no packfile writer")
	}
	writer, err := packWriter.PackfileWriter()
	if err != nil {
		t.Fatal(err)
	}
	packHash, encodeErr := packfile.NewEncoder(writer, repository.Storer, false).Encode(hashes, 0)
	closeErr := writer.Close()
	if encodeErr != nil || closeErr != nil {
		t.Fatalf("pack fixture objects: %v", errors.Join(encodeErr, closeErr))
	}
	for _, hash := range hashes {
		if err := os.Remove(looseObjectPath(dotGitPath, hash)); err != nil {
			t.Fatalf("remove packed loose object %s: %v", hash, err)
		}
	}
	for _, extension := range []string{"pack", "idx"} {
		name := filepath.Join(dotGitPath, "objects", "pack", "pack-"+packHash.String()+"."+extension)
		if info, err := os.Stat(name); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("packed fixture %s missing: %v", extension, err)
		}
	}
}

func looseObjectPath(dotGit string, hash plumbing.Hash) string {
	encoded := hash.String()
	return filepath.Join(dotGit, "objects", encoded[:2], encoded[2:])
}

func readLooseObjectPayload(t *testing.T, dotGit string, hash plumbing.Hash) (plumbing.ObjectType, []byte) {
	t.Helper()
	file, err := os.Open(looseObjectPath(dotGit, hash))
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := zlib.NewReader(file)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(decompressed)
	closeErr := errors.Join(decompressed.Close(), file.Close())
	if readErr != nil || closeErr != nil {
		t.Fatalf("read loose object: %v", errors.Join(readErr, closeErr))
	}
	separator := bytes.IndexByte(body, 0)
	if separator < 0 {
		t.Fatal("loose object has no header separator")
	}
	fields := bytes.Fields(body[:separator])
	if len(fields) != 2 {
		t.Fatalf("invalid loose object header %q", body[:separator])
	}
	objectType, err := plumbing.ParseObjectType(string(fields[0]))
	if err != nil {
		t.Fatal(err)
	}
	size, err := strconv.Atoi(string(fields[1]))
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte(nil), body[separator+1:]...)
	if len(payload) != size {
		t.Fatalf("loose object size=%d payload=%d", size, len(payload))
	}
	return objectType, payload
}

func overwriteLooseObjectPayload(t *testing.T, dotGit string, hash plumbing.Hash, objectType plumbing.ObjectType, payload []byte) {
	overwriteLooseObject(t, dotGit, hash, objectType, len(payload), payload)
}

func overwriteLooseObject(t *testing.T, dotGit string, hash plumbing.Hash, objectType plumbing.ObjectType, declaredSize int, payload []byte) {
	t.Helper()
	name := looseObjectPath(dotGit, hash)
	before, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	compressed := zlib.NewWriter(file)
	_, headerErr := fmt.Fprintf(compressed, "%s %d%c", objectType, declaredSize, byte(0))
	_, payloadErr := compressed.Write(payload)
	closeErr := errors.Join(compressed.Close(), file.Close())
	if err := errors.Join(headerErr, payloadErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, before.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("loose object overwrite replaced the inode instead of mutating it in place")
	}
}

func mutateSameSize(payload []byte) []byte {
	mutated := append([]byte(nil), payload...)
	if len(mutated) == 0 {
		return []byte{'x'}
	}
	mutated[len(mutated)-1] ^= 0x01
	return mutated
}

func mutateRegularFileInPlace(t *testing.T, name string) {
	t.Helper()
	before, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() < 8 {
		t.Fatalf("fixture file %s is unexpectedly short", name)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	offset := before.Size() / 2
	var value [1]byte
	_, readErr := file.ReadAt(value[:], offset)
	value[0] ^= 0x01
	_, writeErr := file.WriteAt(value[:], offset)
	closeErr := file.Close()
	if err := errors.Join(readErr, writeErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, before.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() {
		t.Fatal("test mutation replaced or resized the packed fixture")
	}
}

func TestUpstreamGoGitStorageDoesNotBindLoosePayloadToRequestedHash(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("raw go-git proof\n"))
	objectType, original := readLooseObjectPayload(t, fixture.dotGitPath, fixture.head)
	overwriteLooseObjectPayload(t, fixture.dotGitPath, fixture.head, objectType, mutateSameSize(original))

	// go-git v5.19.1 decodes the loose payload found at the requested hash
	// pathname, but does not compare the payload's computed object ID with that
	// pathname. This direct, unwrapped reader documents the dependency behavior
	// that OpenBoundRepository must harden.
	raw, err := git.PlainOpen(filepath.Join(fixture.root, ".sow", "state"))
	if err != nil {
		t.Fatal(err)
	}
	commit, err := raw.CommitObject(fixture.head)
	if err != nil {
		t.Fatalf("raw go-git unexpectedly rejected the mismatched loose commit: %v", err)
	}
	if commit.Hash == fixture.head {
		t.Fatalf("raw go-git returned requested hash %s instead of mismatched payload hash", fixture.head)
	}
}

func TestBoundRepositoryRejectsHashMismatchedLooseObjects(t *testing.T) {
	tests := []struct {
		name         string
		selectObject func(boundObjectFixture) (plumbing.Hash, func() error)
		mutate       func([]byte) []byte
	}{
		{
			name: "commit",
			selectObject: func(f boundObjectFixture) (plumbing.Hash, func() error) {
				return f.head, func() error { _, err := f.repository.CommitObject(f.head); return err }
			},
			mutate: mutateSameSize,
		},
		{
			name: "tree",
			selectObject: func(f boundObjectFixture) (plumbing.Hash, func() error) {
				return f.tree, func() error { _, err := f.repository.TreeObject(f.tree); return err }
			},
			mutate: mutateSameSize,
		},
		{
			name: "blob",
			selectObject: func(f boundObjectFixture) (plumbing.Hash, func() error) {
				return f.blob, func() error { _, err := f.repository.BlobObject(f.blob); return err }
			},
			mutate: mutateSameSize,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBoundObjectFixture(t, []byte("strict loose object proof\n"))
			hash, read := test.selectObject(fixture)
			objectType, original := readLooseObjectPayload(t, fixture.dotGitPath, hash)
			overwriteLooseObjectPayload(t, fixture.dotGitPath, hash, objectType, test.mutate(original))
			if err := read(); !errors.Is(err, ErrGitObjectIntegrity) {
				t.Fatalf("hash-mismatched %s error=%v, want ErrGitObjectIntegrity", test.name, err)
			}
		})
	}
}

func TestBoundRepositoryRejectsSameSizeLargeBlobMutation(t *testing.T) {
	payload := bytes.Repeat([]byte("large canonical payload\n"), largeCanonicalBlobSize/len("large canonical payload\n")+1)
	payload = payload[:largeCanonicalBlobSize]
	fixture := newBoundObjectFixture(t, payload)
	objectType, original := readLooseObjectPayload(t, fixture.dotGitPath, fixture.blob)
	mutated := mutateSameSize(original)
	if len(mutated) != len(original) {
		t.Fatal("test mutation changed large blob size")
	}
	overwriteLooseObjectPayload(t, fixture.dotGitPath, fixture.blob, objectType, mutated)
	if _, err := fixture.repository.BlobObject(fixture.blob); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("same-size large blob mutation error=%v, want ErrGitObjectIntegrity", err)
	}
}

func TestBoundRepositoryBindsLooseHeaderTypeAndSize(t *testing.T) {
	tests := []struct {
		name         string
		objectType   plumbing.ObjectType
		declaredSize func([]byte) int
	}{
		{name: "wrong type", objectType: plumbing.TreeObject, declaredSize: func(payload []byte) int { return len(payload) }},
		{name: "short declared size", objectType: plumbing.BlobObject, declaredSize: func(payload []byte) int { return len(payload) - 1 }},
		{name: "long declared size", objectType: plumbing.BlobObject, declaredSize: func(payload []byte) int { return len(payload) + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBoundObjectFixture(t, []byte("strict loose header proof\n"))
			_, original := readLooseObjectPayload(t, fixture.dotGitPath, fixture.blob)
			overwriteLooseObject(t, fixture.dotGitPath, fixture.blob, test.objectType, test.declaredSize(original), original)
			if _, err := fixture.repository.BlobObject(fixture.blob); !errors.Is(err, ErrGitObjectIntegrity) {
				t.Fatalf("loose header mismatch error=%v, want ErrGitObjectIntegrity", err)
			}
		})
	}
}

func TestLargeLazyObjectReaderPoisonsSessionAcrossRestore(t *testing.T) {
	payload := bytes.Repeat([]byte("lazy large canonical payload\n"), largeCanonicalBlobSize/len("lazy large canonical payload\n")+1)
	payload = payload[:largeCanonicalBlobSize]
	fixture := newBoundObjectFixture(t, payload)
	blob, err := fixture.repository.BlobObject(fixture.blob)
	if err != nil {
		t.Fatal(err)
	}
	objectType, original := readLooseObjectPayload(t, fixture.dotGitPath, fixture.blob)
	overwriteLooseObjectPayload(t, fixture.dotGitPath, fixture.blob, objectType, mutateSameSize(original))
	reader, err := blob.Reader()
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, reader)
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("lazy large reader mutation error=%v, want ErrGitObjectIntegrity", err)
	}
	overwriteLooseObjectPayload(t, fixture.dotGitPath, fixture.blob, objectType, original)
	if err := fixture.store.VerifyReadSnapshot(); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("restored lazy mutation error=%v, want persistent ErrGitObjectIntegrity", err)
	}
}

type closeErrorReader struct {
	*bytes.Reader
	err error
}

func (r *closeErrorReader) Close() error { return r.err }

type spoofIntegrityStorer struct{ storage.Storer }

func (*spoofIntegrityStorer) VerifyAccessedObjects() error { return nil }

func TestVerifiedObjectReaderPoisonsOnCloseErrorAfterEOF(t *testing.T) {
	payload := []byte("close failure payload\n")
	hash := plumbing.ComputeHash(plumbing.BlobObject, payload)
	closeFailure := errors.New("injected object close failure")
	owner := &verifiedObjectStorer{accessed: make(map[verifiedObjectIdentity]struct{})}
	reader := &verifiedObjectReader{
		reader:   &closeErrorReader{Reader: bytes.NewReader(payload), err: closeFailure},
		identity: verifiedObjectIdentity{hash: hash, typeOf: plumbing.BlobObject, size: int64(len(payload))},
		hasher:   plumbing.NewHasher(plumbing.BlobObject, int64(len(payload))), owner: owner,
	}
	if body, err := io.ReadAll(reader); err != nil || !bytes.Equal(body, payload) {
		t.Fatalf("read fake object body=%q err=%v", body, err)
	}
	if err := reader.Close(); !errors.Is(err, ErrGitObjectIntegrity) || !errors.Is(err, closeFailure) {
		t.Fatalf("close error=%v, want integrity and injected errors", err)
	}
	owner.mu.Lock()
	poisoned := owner.poisoned
	owner.mu.Unlock()
	if !errors.Is(poisoned, ErrGitObjectIntegrity) || !errors.Is(poisoned, closeFailure) {
		t.Fatalf("session poison=%v, want integrity and injected errors", poisoned)
	}
}

func TestVerifiedStorerClosesObjectReadBypasses(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("direct storer bypass proof\n"))
	if _, ok := fixture.repository.Storer.(storer.DeltaObjectStorer); ok {
		t.Fatal("verified storer exposes unverified DeltaObject")
	}
	if _, ok := fixture.repository.Storer.(storer.LooseObjectStorer); ok {
		t.Fatal("verified storer exposes unverified loose-object methods")
	}
	if _, ok := fixture.repository.Storer.(storer.PackedObjectStorer); ok {
		t.Fatal("verified storer exposes unverified packed-object methods")
	}
	if _, ok := fixture.repository.Storer.(storer.PackfileWriter); ok {
		t.Fatal("verified storer exposes a packfile writer")
	}
	if _, ok := fixture.repository.Storer.(storer.Transactioner); ok {
		t.Fatal("verified storer exposes an object transaction")
	}
	if _, err := fixture.repository.Storer.IterEncodedObjects(plumbing.BlobObject); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("object iterator error=%v, want ErrGitObjectIntegrity", err)
	}
	if _, err := fixture.repository.Storer.Module("forbidden"); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("submodule storer error=%v, want ErrGitObjectIntegrity", err)
	}

	newObject := fixture.repository.Storer.NewEncodedObject()
	payload := []byte("forbidden write through storer\n")
	newObject.SetType(plumbing.BlobObject)
	newObject.SetSize(int64(len(payload)))
	writer, err := newObject.Writer()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	newHash := newObject.Hash()
	if _, err := os.Stat(looseObjectPath(fixture.dotGitPath, newHash)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new object unexpectedly exists before write attempt: %v", err)
	}
	if _, err := fixture.repository.Storer.SetEncodedObject(newObject); err == nil {
		t.Fatal("verified storer unexpectedly allowed SetEncodedObject")
	}
	if _, err := os.Stat(looseObjectPath(fixture.dotGitPath, newHash)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed write left an object behind: %v", err)
	}
	if err := fixture.repository.Storer.AddAlternate("forbidden"); err == nil {
		t.Fatal("verified storer unexpectedly allowed AddAlternate")
	}
	if _, err := os.Stat(filepath.Join(fixture.dotGitPath, "objects", "info", "alternates")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed alternate write left state behind: %v", err)
	}

	objectType, original := readLooseObjectPayload(t, fixture.dotGitPath, fixture.blob)
	overwriteLooseObjectPayload(t, fixture.dotGitPath, fixture.blob, objectType, mutateSameSize(original))
	if err := fixture.repository.Storer.HasEncodedObject(fixture.blob); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("HasEncodedObject error=%v, want ErrGitObjectIntegrity", err)
	}
	if _, err := fixture.repository.Storer.EncodedObjectSize(fixture.blob); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("EncodedObjectSize error=%v, want ErrGitObjectIntegrity", err)
	}
}

func TestPackedRepositoryTamperingFailsFinalRevalidation(t *testing.T) {
	for _, extension := range []string{"pack", "idx"} {
		t.Run(extension, func(t *testing.T) {
			fixture := newBoundObjectFixtureWithPacking(t, []byte("packed canonical proof\n"), true)
			reader, err := fixture.store.OpenPathAt(fixture.head, "proof/value.bin")
			if err != nil {
				t.Fatal(err)
			}
			if body, err := io.ReadAll(reader); err != nil || string(body) != "packed canonical proof\n" {
				t.Fatalf("read packed canonical body=%q err=%v", body, err)
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			if err := fixture.store.VerifyReadSnapshot(); err != nil {
				t.Fatalf("verify unchanged packed fixture: %v", err)
			}
			matches, err := filepath.Glob(filepath.Join(fixture.dotGitPath, "objects", "pack", "pack-*."+extension))
			if err != nil || len(matches) != 1 {
				t.Fatalf("find packed fixture %s: matches=%v err=%v", extension, matches, err)
			}
			mutateRegularFileInPlace(t, matches[0])
			if err := fixture.store.VerifyReadSnapshot(); !errors.Is(err, ErrGitObjectIntegrity) {
				t.Fatalf("same-path %s mutation error=%v, want ErrGitObjectIntegrity", extension, err)
			}
		})
	}
}

func TestBoundRepositoryRejectsEscapingAlternates(t *testing.T) {
	payload := []byte("alternate object must stay unreachable\n")
	for _, alternate := range []func(boundObjectFixture) string{
		func(f boundObjectFixture) string { return filepath.Join(f.dotGitPath, "objects") },
		func(boundObjectFixture) string { return "../../../../outside/objects" },
	} {
		t.Run("escape", func(t *testing.T) {
			target := newBoundObjectFixture(t, payload)
			fixture := newBoundObjectFixture(t, payload)
			if err := os.Remove(looseObjectPath(fixture.dotGitPath, fixture.blob)); err != nil {
				t.Fatal(err)
			}
			infoDir := filepath.Join(fixture.dotGitPath, "objects", "info")
			if err := os.MkdirAll(infoDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(infoDir, "alternates"), []byte(alternate(target)+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.repository.BlobObject(fixture.blob); err == nil {
				t.Fatal("bound repository followed an alternate outside its retained .git root")
			}
		})
	}
}

func TestReadOnlyRepositoryRejectsIntegrityVerifierSpoof(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("concrete integrity verifier proof\n"))
	fixture.repository.Storer = &spoofIntegrityStorer{Storer: fixture.repository.Storer}
	if _, err := NewReadOnlyRepository(filepath.Join(fixture.root, ".sow"), fixture.repository); err == nil {
		t.Fatal("read-only repository accepted a non-canonical verifier implementation")
	}
}

func TestReadSnapshotRevalidatesAccessedObjects(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("phase one canonical bytes\n"))
	reader, err := fixture.store.OpenPathAt(fixture.head, "proof/value.bin")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || string(body) != "phase one canonical bytes\n" {
		t.Fatalf("read canonical phase body=%q err=%v", body, errors.Join(readErr, closeErr))
	}
	if err := fixture.store.VerifyReadSnapshot(); err != nil {
		t.Fatalf("unchanged canonical object failed verification: %v", err)
	}
	objectType, original := readLooseObjectPayload(t, fixture.dotGitPath, fixture.blob)
	overwriteLooseObjectPayload(t, fixture.dotGitPath, fixture.blob, objectType, mutateSameSize(original))
	if err := fixture.store.VerifyReadSnapshot(); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("phase-between object mutation error=%v, want ErrGitObjectIntegrity", err)
	}
	overwriteLooseObjectPayload(t, fixture.dotGitPath, fixture.blob, objectType, original)
	if err := fixture.store.VerifyReadSnapshot(); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("restored phase-between mutation error=%v, want persistent ErrGitObjectIntegrity", err)
	}
}

func TestReadSnapshotRemembersTransientObjectIntegrityFailure(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("canonical bytes restored later\n"))
	reader, err := fixture.store.OpenPathAt(fixture.head, "proof/value.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	objectType, original := readLooseObjectPayload(t, fixture.dotGitPath, fixture.blob)
	overwriteLooseObjectPayload(t, fixture.dotGitPath, fixture.blob, objectType, mutateSameSize(original))
	if _, err := fixture.store.OpenPathAt(fixture.head, "proof/value.bin"); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("transient object mutation error=%v, want ErrGitObjectIntegrity", err)
	}
	overwriteLooseObjectPayload(t, fixture.dotGitPath, fixture.blob, objectType, original)
	if err := fixture.store.VerifyReadSnapshot(); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("restored transient mutation error=%v, want persistent ErrGitObjectIntegrity", err)
	}
}

func TestBoundRepositoryReadsAndRevalidatesLargeCanonicalBlob(t *testing.T) {
	payload := bytes.Repeat([]byte("verified large canonical payload\n"), largeCanonicalBlobSize/len("verified large canonical payload\n")+1)
	payload = payload[:largeCanonicalBlobSize]
	fixture := newBoundObjectFixture(t, payload)
	reader, err := fixture.store.OpenPathAt(fixture.head, "proof/value.bin")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("large canonical body differs: got=%d want=%d", len(body), len(payload))
	}
	if err := fixture.store.VerifyReadSnapshot(); err != nil {
		t.Fatalf("revalidate large canonical blob: %v", err)
	}
}
