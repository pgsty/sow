package state

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type RefRecord struct {
	Name plumbing.ReferenceName
	Hash plumbing.Hash
}

// BlobIdentity is the immutable Git blob identity of one canonical state
// file. Callers that audit long histories can compare large publication plans
// without repeatedly inflating and hashing unchanged blobs.
type BlobIdentity struct {
	Hash plumbing.Hash
	Size int64
}

// SOWRefs returns only direct refs in the frozen SOW namespace. Symbolic HEAD
// and unrelated Git refs can never become preservation roots accidentally.
func (s *Store) SOWRefs() ([]RefRecord, error) {
	if s != nil && s.readRepository != nil {
		result := make([]RefRecord, 0, len(s.readRefs))
		for name, hash := range s.readRefs {
			if !strings.HasPrefix(name.String(), "refs/sow/") {
				continue
			}
			if err := validateSOWRef(name); err != nil {
				return nil, err
			}
			if _, err := s.readRepository.CommitObject(hash); err != nil {
				return nil, fmt.Errorf("SOW ref %s has invalid commit %s: %w", name, hash, err)
			}
			result = append(result, RefRecord{Name: name, Hash: hash})
		}
		sort.Slice(result, func(i, j int) bool { return result[i].Name.String() < result[j].Name.String() })
		return result, nil
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return nil, err
	}
	iterator, err := repository.References()
	if err != nil {
		return nil, err
	}
	defer iterator.Close()
	var result []RefRecord
	err = iterator.ForEach(func(reference *plumbing.Reference) error {
		if reference.Type() != plumbing.HashReference || !strings.HasPrefix(reference.Name().String(), "refs/sow/") {
			return nil
		}
		if err := validateSOWRef(reference.Name()); err != nil {
			return err
		}
		if _, err := repository.CommitObject(reference.Hash()); err != nil {
			return fmt.Errorf("SOW ref %s has invalid commit %s: %w", reference.Name(), reference.Hash(), err)
		}
		result = append(result, RefRecord{Name: reference.Name(), Hash: reference.Hash()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name.String() < result[j].Name.String() })
	return result, nil
}

// History returns the aggregate HEAD ancestry from newest to oldest. State
// mutations are linear, but a seen set makes the API safe if an imported state
// repository contains merge commits.
func (s *Store) History() ([]plumbing.Hash, error) {
	repository, err := s.ensureRepository()
	if err != nil {
		return nil, err
	}
	var head plumbing.Hash
	if s != nil && s.readRepository != nil {
		head = s.readHead
		if head.IsZero() {
			return nil, nil
		}
	} else {
		reference, err := repository.Head()
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		head = reference.Hash()
	}
	iterator, err := repository.Log(&git.LogOptions{From: head, Order: git.LogOrderCommitterTime})
	if err != nil {
		return nil, err
	}
	defer iterator.Close()
	seen := make(map[plumbing.Hash]struct{})
	var result []plumbing.Hash
	err = iterator.ForEach(func(commit *object.Commit) error {
		if _, exists := seen[commit.Hash]; exists {
			return nil
		}
		seen[commit.Hash] = struct{}{}
		result = append(result, commit.Hash)
		return nil
	})
	return result, err
}

// ReachableCommits returns every unique commit reachable from HEAD or any
// direct Git ref. Unlike History, it includes off-HEAD preservation branches;
// policy audits use it to prevent a merge or manually retained SOW ref from
// hiding canonical evidence. The result is sorted by object ID so callers do
// not accidentally assign meaning to committer timestamps.
func (s *Store) ReachableCommits() ([]plumbing.Hash, error) {
	repository, err := s.ensureRepository()
	if err != nil {
		return nil, err
	}
	var head plumbing.Hash
	var refs map[plumbing.ReferenceName]plumbing.Hash
	if s != nil && s.readRepository != nil {
		head = s.readHead
		refs = s.readRefs
	} else {
		head, refs, err = snapshotRepositoryState(repository)
		if err != nil {
			return nil, err
		}
	}
	rootSet := make(map[plumbing.Hash]struct{}, len(refs)+1)
	if !head.IsZero() {
		rootSet[head] = struct{}{}
	}
	for _, hash := range refs {
		if hash.IsZero() {
			return nil, errors.New("canonical direct ref names the zero object")
		}
		rootSet[hash] = struct{}{}
	}
	pending := make([]plumbing.Hash, 0, len(rootSet))
	for hash := range rootSet {
		pending = append(pending, hash)
	}
	seen := make(map[plumbing.Hash]struct{})
	for len(pending) != 0 {
		hash := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if _, exists := seen[hash]; exists {
			continue
		}
		commit, err := repository.CommitObject(hash)
		if err != nil {
			return nil, fmt.Errorf("canonical preservation root/history object %s is not a valid commit: %w", hash, err)
		}
		seen[hash] = struct{}{}
		pending = append(pending, commit.ParentHashes...)
	}
	result := make([]plumbing.Hash, 0, len(seen))
	for hash := range seen {
		result = append(result, hash)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result, nil
}

// IsAncestor reports whether ancestor is equal to or a graph ancestor of
// descendant in the canonical repository. History position is insufficient
// for this decision when an imported repository contains merge commits: a
// sibling can appear earlier in a log without being publication provenance.
func (s *Store) IsAncestor(ancestor, descendant plumbing.Hash) (bool, error) {
	if ancestor.IsZero() || descendant.IsZero() {
		return false, errors.New("canonical ancestry requires non-zero commits")
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return false, err
	}
	ancestorCommit, err := repository.CommitObject(ancestor)
	if err != nil {
		return false, fmt.Errorf("open canonical ancestor %s: %w", ancestor, err)
	}
	descendantCommit, err := repository.CommitObject(descendant)
	if err != nil {
		return false, fmt.Errorf("open canonical descendant %s: %w", descendant, err)
	}
	if ancestor == descendant {
		return true, nil
	}
	result, err := ancestorCommit.IsAncestor(descendantCommit)
	if err != nil {
		return false, fmt.Errorf("check canonical ancestry %s -> %s: %w", ancestor, descendant, err)
	}
	return result, nil
}

// BlobIdentityAt returns the immutable blob identity of one canonical path at
// an exact commit. A missing path is reported through exists=false rather than
// as an error so callers can distinguish pre-feature history from corruption.
func (s *Store) BlobIdentityAt(commit plumbing.Hash, relative string) (identity BlobIdentity, exists bool, resultErr error) {
	if commit.IsZero() {
		return identity, false, errors.New("cannot inspect a canonical file at the zero hash")
	}
	if err := validateStatePath(relative); err != nil {
		return identity, false, err
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return identity, false, err
	}
	commitObject, err := repository.CommitObject(commit)
	if err != nil {
		return identity, false, err
	}
	tree, err := commitObject.Tree()
	if err != nil {
		return identity, false, err
	}
	file, err := tree.File(relative)
	if errors.Is(err, object.ErrFileNotFound) {
		return identity, false, nil
	}
	if err != nil {
		return identity, false, err
	}
	return BlobIdentity{Hash: file.Blob.Hash, Size: file.Blob.Size}, true, nil
}

// ListFilesAt lists regular Git blobs at a canonical commit. Prefix is a
// normalized directory prefix such as "views/"; an empty prefix lists all.
func (s *Store) ListFilesAt(commit plumbing.Hash, prefix string) ([]string, error) {
	var result []string
	if err := s.ForEachFileAt(commit, prefix, func(name string) error {
		result = append(result, name)
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(result)
	return result, nil
}

// ForEachFileAt streams regular Git blob names from one canonical commit.
// Unlike ListFilesAt it does not retain a repository-sized path slice, making
// it suitable for rebuilds of large provenance ledgers.
func (s *Store) ForEachFileAt(commit plumbing.Hash, prefix string, fn func(string) error) error {
	if commit.IsZero() {
		return errors.New("cannot list canonical files at the zero hash")
	}
	if fn == nil {
		return errors.New("canonical file callback is nil")
	}
	if prefix != "" {
		if strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "\\\x00\t\r\n") || !strings.HasSuffix(prefix, "/") {
			return errors.New("canonical file prefix must be a safe directory prefix")
		}
		if err := validateStatePath(strings.TrimSuffix(prefix, "/")); err != nil {
			return err
		}
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return err
	}
	commitObject, err := repository.CommitObject(commit)
	if err != nil {
		return err
	}
	tree, err := commitObject.Tree()
	if err != nil {
		return err
	}
	err = tree.Files().ForEach(func(file *object.File) error {
		if prefix == "" || strings.HasPrefix(file.Name, prefix) {
			if err := validateStatePath(file.Name); err != nil {
				return err
			}
			return fn(file.Name)
		}
		return nil
	})
	return err
}
