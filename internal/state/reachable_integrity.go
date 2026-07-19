package state

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// ReachableIntegrityStats reports the unique canonical objects whose payloads
// were consumed by AuditReachableObjects. Tree objects are decoded while
// walking each commit; Commits and Blobs count the explicit graph vertices and
// file bodies visited by this audit.
type ReachableIntegrityStats struct {
	Roots     int
	Commits   int
	Blobs     int
	BlobBytes int64
}

// AuditReachableObjects consumes every commit history and regular file body
// reachable from HEAD or any direct canonical Git ref. It is deliberately
// available only on a capability-bound read Store: ordinary go-git storage
// treats an object filename or pack-index entry as a lookup hint and does not
// provide the content-to-object-ID guarantee required by a full fsck.
//
// Canonical SOW refs name commits, not tag/blob/tree objects. Rejecting a
// non-commit direct ref prevents an otherwise unused object type from becoming
// an unaudited preservation root. Every file is also required to use the
// normal non-executable Git mode used by canonical state transactions.
func (s *Store) AuditReachableObjects() (ReachableIntegrityStats, error) {
	var stats ReachableIntegrityStats
	if s == nil || s.readRepository == nil {
		return stats, errors.New("canonical reachability audit requires a capability-bound read store")
	}

	rootSet := make(map[plumbing.Hash]struct{}, len(s.readRefs)+1)
	if !s.readHead.IsZero() {
		rootSet[s.readHead] = struct{}{}
	}
	for name, hash := range s.readRefs {
		if hash.IsZero() {
			return stats, fmt.Errorf("canonical direct ref %s names the zero object", name)
		}
		rootSet[hash] = struct{}{}
	}
	roots := make([]plumbing.Hash, 0, len(rootSet))
	for hash := range rootSet {
		roots = append(roots, hash)
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].String() < roots[j].String() })
	stats.Roots = len(roots)
	if stats.Roots == 0 {
		return stats, errors.New("canonical Git repository has no HEAD or direct preservation ref")
	}

	seenCommits := make(map[plumbing.Hash]struct{})
	seenTrees := make(map[plumbing.Hash]struct{})
	seenBlobs := make(map[plumbing.Hash]struct{})
	pending := append([]plumbing.Hash(nil), roots...)
	for len(pending) != 0 {
		hash := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if _, seen := seenCommits[hash]; seen {
			continue
		}
		commit, err := s.readRepository.CommitObject(hash)
		if err != nil {
			return stats, fmt.Errorf("canonical preservation root/history object %s is not a valid commit: %w", hash, err)
		}
		seenCommits[hash] = struct{}{}
		stats.Commits++

		var rootTree *object.Tree
		if _, seen := seenTrees[commit.TreeHash]; !seen {
			tree, err := commit.Tree()
			if err != nil {
				return stats, fmt.Errorf("open canonical tree for commit %s: %w", hash, err)
			}
			seenTrees[commit.TreeHash] = struct{}{}
			rootTree = tree
		}
		// object.Tree.Files uses go-git's TreeWalker, which deliberately turns a
		// missing child tree into io.EOF and skips gitlink entries. Canonical fsck
		// needs the opposite contract: every named tree must resolve and every
		// entry must be either a real directory or one regular canonical blob.
		type treeWork struct {
			tree   *object.Tree
			prefix string
		}
		pendingTrees := make([]treeWork, 0, 1)
		if rootTree != nil {
			pendingTrees = append(pendingTrees, treeWork{tree: rootTree})
		}
		for len(pendingTrees) != 0 {
			current := pendingTrees[len(pendingTrees)-1]
			pendingTrees = pendingTrees[:len(pendingTrees)-1]
			if err := validateCanonicalTreeEntries(current.tree.Entries); err != nil {
				return stats, fmt.Errorf("commit %s contains a non-canonical tree at %q: %w", hash, current.prefix, err)
			}
			for _, entry := range current.tree.Entries {
				name := entry.Name
				if current.prefix != "" {
					name = current.prefix + "/" + entry.Name
				}
				if err := validateStatePath(name); err != nil {
					return stats, fmt.Errorf("commit %s contains unsafe canonical path %q: %w", hash, name, err)
				}
				switch entry.Mode {
				case filemode.Dir:
					if _, seen := seenTrees[entry.Hash]; seen {
						continue
					}
					subtree, err := s.readRepository.TreeObject(entry.Hash)
					if err != nil {
						return stats, fmt.Errorf("open canonical subtree %s for %s at %s: %w", entry.Hash, name, hash, err)
					}
					seenTrees[entry.Hash] = struct{}{}
					pendingTrees = append(pendingTrees, treeWork{tree: subtree, prefix: name})
				case filemode.Regular:
					if _, seen := seenBlobs[entry.Hash]; seen {
						continue
					}
					blob, err := s.readRepository.BlobObject(entry.Hash)
					if err != nil {
						return stats, fmt.Errorf("open canonical blob %s for %s at %s: %w", entry.Hash, name, hash, err)
					}
					reader, err := blob.Reader()
					if err != nil {
						return stats, fmt.Errorf("open canonical blob %s for %s at %s: %w", entry.Hash, name, hash, err)
					}
					n, copyErr := io.Copy(io.Discard, reader)
					closeErr := reader.Close()
					if copyErr != nil || closeErr != nil || n != blob.Size {
						return stats, errors.Join(copyErr, closeErr, fmt.Errorf("consume canonical blob %s for %s at %s: read=%d declared=%d", entry.Hash, name, hash, n, blob.Size))
					}
					seenBlobs[entry.Hash] = struct{}{}
					stats.Blobs++
					stats.BlobBytes += n
				default:
					return stats, fmt.Errorf("commit %s canonical path %s has unsupported Git mode %s", hash, name, entry.Mode)
				}
			}
		}
		for _, parent := range commit.ParentHashes {
			if parent.IsZero() {
				return stats, fmt.Errorf("canonical commit %s contains a zero parent", hash)
			}
			if _, seen := seenCommits[parent]; !seen {
				pending = append(pending, parent)
			}
		}
	}
	return stats, nil
}

// validateCanonicalTreeEntries rejects tree encodings that go-git can decode
// but a checkout cannot represent unambiguously. In particular, go-git marks
// out-of-order trees internally without rejecting them, and a raw tree may
// contain duplicate names or slash-bearing pseudo-paths.
func validateCanonicalTreeEntries(entries []object.TreeEntry) error {
	seen := make(map[string]struct{}, len(entries))
	previousSortName := ""
	for index, entry := range entries {
		if err := validateStateSegment(entry.Name); err != nil {
			return fmt.Errorf("unsafe tree entry name %q: %w", entry.Name, err)
		}
		if err := validateStatePath(entry.Name); err != nil {
			return fmt.Errorf("unsafe tree entry name %q: %w", entry.Name, err)
		}
		if entry.Hash.IsZero() {
			return fmt.Errorf("tree entry %q names the zero object", entry.Name)
		}
		if _, duplicate := seen[entry.Name]; duplicate {
			return fmt.Errorf("tree contains duplicate entry name %q", entry.Name)
		}
		seen[entry.Name] = struct{}{}
		sortName := entry.Name
		if entry.Mode == filemode.Dir {
			sortName += "/"
		}
		if index != 0 && previousSortName >= sortName {
			return fmt.Errorf("tree entries %q and %q are not in strict canonical order", previousSortName, sortName)
		}
		previousSortName = sortName
	}
	return nil
}
