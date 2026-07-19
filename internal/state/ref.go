package state

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

var (
	ErrRefConflict  = errors.New("canonical ref changed concurrently")
	ErrImmutableRef = errors.New("immutable ref already names different state")
)

func RepoRef(repo string) (plumbing.ReferenceName, error) {
	return buildRef("repos", repo)
}

func ViewRef(view, repo, osName, arch string) (plumbing.ReferenceName, error) {
	return buildRef("views", view, repo, osName, arch)
}

func SnapshotRef(snapshot, repo, osName, arch string) (plumbing.ReferenceName, error) {
	return buildRef("snapshots", snapshot, repo, osName, arch)
}

func RemoteRef(target, view, repo, osName, arch string) (plumbing.ReferenceName, error) {
	return buildRef("remotes", target, view, repo, osName, arch)
}

func ViewPath(view, repo, osName, arch string) (string, error) {
	return buildPath("views", view, repo, osName, arch+".tsv")
}

func SnapshotPath(snapshot, repo, osName, arch string) (string, error) {
	return buildPath("snapshots", snapshot, repo, osName, arch+".tsv")
}

// YUMCompatibilityRef pins the immutable S2 freeze commit of one cross-EL
// compatibility projection. The separate yum-source ref pins S1; this ref
// must name the later commit containing the witness and exact signed candidate.
func YUMCompatibilityRef(id string) (plumbing.ReferenceName, error) {
	return buildRef("compatibility", "yum", id)
}

// YUMCompatibilitySourceRef pins the one-time cross-EL legacy adoption
// commit. It is deliberately not a view ref: the adopted byte set may contain
// packages for several EL releases and must never be relabelled as an active
// per-EL repository merely to satisfy a compatibility URL.
func YUMCompatibilitySourceRef(id string) (plumbing.ReferenceName, error) {
	return buildRef("compatibility", "yum-source", id)
}

// YUMCompatibilitySourcePath is the immutable canonical Packages manifest
// created by explicit legacy adoption. Entries are relative
// Packages/<bucket>/<rpm> paths backed by CAS objects.
func YUMCompatibilitySourcePath(id string) (string, error) {
	return buildPath("compatibility", "yum", id, "source.tsv")
}

func YUMCompatibilityAdoptionPath(id string) (string, error) {
	return buildPath("compatibility", "yum", id, "adoption.json")
}

func YUMCompatibilityCutoverPath(id string) (string, error) {
	return buildPath("compatibility", "yum", id, "cutover.jsonl")
}

// YUMCompatibilityCandidateManifestPath stores the exact S2 clean candidate
// tree manifest, including signed primary/filelists/other metadata bytes.
func YUMCompatibilityCandidateManifestPath(id string) (string, error) {
	return buildPath("compatibility", "yum", id, "candidate.tsv")
}

// YUMCompatibilityCandidateReceiptPath binds the exact candidate manifest to
// the S1 source, package trust, repomd identity and repository signer.
func YUMCompatibilityCandidateReceiptPath(id string) (string, error) {
	return buildPath("compatibility", "yum", id, "candidate.json")
}

// YUMCompatibilityRepositoryTrustPath stores the packet-preserving public
// repository signing key used by the exact S2 metadata candidate. It is
// independent of both the mutable config key path and the RPM package trust.
func YUMCompatibilityRepositoryTrustPath(id string) (string, error) {
	return buildPath("compatibility", "yum", id, "repository-trust.pgp")
}

func YUMCompatibilityProjectionPath(id string) (string, error) {
	return buildPath("compatibility", "yum", id, "projection.json")
}

func YUMCompatibilityManifestPath(id string) (string, error) {
	return buildPath("compatibility", "yum", id, "manifest.tsv")
}

// YUMCompatibilityPackageTrustPath stores the public-only packet-preserving
// RPM signer history used by the immutable projection. It deliberately lives
// beside the witness rather than following the mutable source repo keyring.
func YUMCompatibilityPackageTrustPath(id string) (string, error) {
	return buildPath("compatibility", "yum", id, "package-trust.pgp")
}

// APTByHashLedgerPath names the canonical retention ledger for one APT suite.
// Namespace is deliberately frozen to views or snapshots so hosted mutable
// views and immutable snapshot materializations can never share retention
// history accidentally.
func APTByHashLedgerPath(namespace, name, repo, suite string) (string, error) {
	if namespace != "views" && namespace != "snapshots" {
		return "", fmt.Errorf("invalid APT by-hash ledger namespace %q", namespace)
	}
	return buildPath("retention", "apt-by-hash", namespace, name, repo, suite+".json")
}

func buildRef(parts ...string) (plumbing.ReferenceName, error) {
	for _, part := range parts {
		if err := validateStateSegment(part); err != nil {
			return "", err
		}
	}
	name := plumbing.ReferenceName("refs/sow/" + strings.Join(parts, "/"))
	if err := name.Validate(); err != nil {
		return "", fmt.Errorf("invalid Git reference %q: %w", name, err)
	}
	return name, nil
}

func buildPath(parts ...string) (string, error) {
	for _, part := range parts {
		if err := validateStateSegment(part); err != nil {
			return "", err
		}
	}
	value := strings.Join(parts, "/")
	if err := validateStatePath(value); err != nil {
		return "", err
	}
	return value, nil
}

// OpenPath opens one canonical file from the current aggregate checkout.
func (s *Store) OpenPath(relative string) (*os.File, error) {
	if err := validateStatePath(relative); err != nil {
		return nil, err
	}
	if s != nil && s.readRepository != nil {
		if s.readHead.IsZero() {
			return nil, fmt.Errorf("open canonical state %s: %w", relative, os.ErrNotExist)
		}
		reader, err := s.OpenPathAt(s.readHead, relative)
		if errors.Is(err, object.ErrFileNotFound) || err != nil && strings.Contains(err.Error(), object.ErrFileNotFound.Error()) {
			return nil, fmt.Errorf("open canonical state %s: %w", relative, os.ErrNotExist)
		}
		if err != nil {
			return nil, err
		}
		temporary, err := os.CreateTemp("", "sow-canonical-read-")
		if err != nil {
			_ = reader.Close()
			return nil, err
		}
		name := temporary.Name()
		if err := os.Remove(name); err != nil {
			_ = reader.Close()
			_ = temporary.Close()
			_ = os.Remove(name)
			return nil, fmt.Errorf("unlink private canonical reader: %w", err)
		}
		_, copyErr := io.Copy(temporary, reader)
		closeErr := reader.Close()
		_, seekErr := temporary.Seek(0, io.SeekStart)
		if copyErr != nil || closeErr != nil || seekErr != nil {
			_ = temporary.Close()
			return nil, errors.Join(copyErr, closeErr, seekErr)
		}
		return temporary, nil
	}
	file, err := os.Open(filepath.Join(s.workDir, filepath.FromSlash(relative)))
	if err != nil {
		return nil, fmt.Errorf("open canonical state %s: %w", relative, err)
	}
	return file, nil
}

// OpenPathAt opens one canonical file exactly as recorded by commit. This is
// used for ref algebra so a newer aggregate checkout can never silently change
// the meaning of an older view or snapshot ref.
func (s *Store) OpenPathAt(commit plumbing.Hash, relative string) (io.ReadCloser, error) {
	if commit.IsZero() {
		return nil, errors.New("cannot open canonical state at the zero hash")
	}
	if err := validateStatePath(relative); err != nil {
		return nil, err
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return nil, err
	}
	object, err := repository.CommitObject(commit)
	if err != nil {
		return nil, fmt.Errorf("open canonical commit %s: %w", commit, err)
	}
	tree, err := object.Tree()
	if err != nil {
		return nil, fmt.Errorf("open canonical tree %s: %w", commit, err)
	}
	file, err := tree.File(relative)
	if err != nil {
		return nil, fmt.Errorf("open canonical state %s at %s: %w", relative, commit, err)
	}
	reader, err := file.Reader()
	if err != nil {
		return nil, fmt.Errorf("read canonical state %s at %s: %w", relative, commit, err)
	}
	return reader, nil
}

func (s *Store) CommitTime(hash plumbing.Hash) (time.Time, error) {
	if hash.IsZero() {
		return time.Time{}, errors.New("cannot inspect the zero commit")
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return time.Time{}, err
	}
	commit, err := repository.CommitObject(hash)
	if err != nil {
		return time.Time{}, err
	}
	return commit.Author.When.UTC(), nil
}

// Ref returns a canonical ref hash. A missing ref is reported with exists=false.
func (s *Store) Ref(name plumbing.ReferenceName) (hash plumbing.Hash, exists bool, err error) {
	if err := validateSOWRef(name); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if s != nil && s.readRepository != nil {
		hash, exists := s.readRefs[name]
		return hash, exists, nil
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return plumbing.ZeroHash, false, err
	}
	reference, err := repository.Reference(name, true)
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return plumbing.ZeroHash, false, nil
	}
	if err != nil {
		return plumbing.ZeroHash, false, err
	}
	return reference.Hash(), true, nil
}

// AdvanceRef compare-and-sets one canonical SOW ref. If immutable is true, an
// existing different value can never be rewritten. Repeating the same value is
// always idempotent. Stable view content is append-only but its ref is advanced
// by CAS after the view algebra proves the prior entries remain present;
// immutable=true is reserved for snapshots and other frozen preservation roots.
func (s *Store) AdvanceRef(name plumbing.ReferenceName, expected, next plumbing.Hash, immutable bool) error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	if err := validateSOWRef(name); err != nil {
		return err
	}
	if next.IsZero() {
		return errors.New("cannot advance a canonical ref to the zero hash")
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return err
	}
	if _, err := repository.CommitObject(next); err != nil {
		return fmt.Errorf("canonical ref target %s is not a local commit: %w", next, err)
	}
	current, err := repository.Reference(name, false)
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		if !expected.IsZero() {
			return fmt.Errorf("%w: %s is missing, expected %s", ErrRefConflict, name, expected)
		}
		if err := repository.Storer.CheckAndSetReference(plumbing.NewHashReference(name, next), nil); err != nil {
			return fmt.Errorf("%w: create %s: %v", ErrRefConflict, name, err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if current.Hash() == next {
		return nil
	}
	if immutable {
		return fmt.Errorf("%w: %s is %s, attempted %s", ErrImmutableRef, name, current.Hash(), next)
	}
	if expected.IsZero() || current.Hash() != expected {
		return fmt.Errorf("%w: %s is %s, expected %s", ErrRefConflict, name, current.Hash(), expected)
	}
	if err := repository.Storer.CheckAndSetReference(plumbing.NewHashReference(name, next), current); err != nil {
		return fmt.Errorf("%w: update %s: %v", ErrRefConflict, name, err)
	}
	return nil
}

// DeleteRef compare-and-deletes one mutable canonical SOW ref. Missing is an
// idempotent success so a committed transaction can recover after the delete
// reached Git but before its journal phase was persisted.
func (s *Store) DeleteRef(name plumbing.ReferenceName, expected plumbing.Hash) error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	if err := validateSOWRef(name); err != nil {
		return err
	}
	if expected.IsZero() {
		return errors.New("cannot delete a canonical ref without an expected hash")
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return err
	}
	current, err := repository.Reference(name, false)
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Hash() != expected {
		return fmt.Errorf("%w: %s is %s, expected %s before deletion", ErrRefConflict, name, current.Hash(), expected)
	}
	if err := repository.Storer.RemoveReference(name); err != nil {
		return fmt.Errorf("%w: delete %s: %v", ErrRefConflict, name, err)
	}
	return nil
}

func validateSOWRef(name plumbing.ReferenceName) error {
	if err := name.Validate(); err != nil {
		return err
	}
	if !strings.HasPrefix(name.String(), "refs/sow/") {
		return fmt.Errorf("ref %q is outside refs/sow", name)
	}
	return nil
}
