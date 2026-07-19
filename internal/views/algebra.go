package views

import (
	"errors"
	"fmt"
	"io"
)

func ValidateConfidentiality(r io.Reader, public bool) (int64, error) {
	reader := NewReader(r)
	var count int64
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		if public && entry.Pool != "public" {
			return count, fmt.Errorf("confidentiality closure violation: public view references gated path %s", entry.Path)
		}
		if public && entry.DebugInfo {
			return count, fmt.Errorf("public view references debuginfo path %s", entry.Path)
		}
		count++
	}
}

// ValidateLeaf proves that every entry belongs to the expected ref leaf and,
// for a public leaf, that its complete metadata closure references only public
// objects. There is no force or skip mode for either invariant.
func ValidateLeaf(r io.Reader, repo, osName, arch string, public bool) (int64, error) {
	return ValidateLeafEntries(r, repo, osName, arch, public, nil)
}

// ValidateLeafEntries applies the leaf/confidentiality invariants and an
// optional product-specific admission check in one streaming pass. The
// callback is invoked only after the entry is proven to belong to the leaf and
// to satisfy the public closure.
func ValidateLeafEntries(r io.Reader, repo, osName, arch string, public bool, validate func(Entry) error) (int64, error) {
	reader := NewReader(r)
	var count int64
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		if entry.Repo != repo || entry.OS != osName || entry.Arch != arch {
			return count, fmt.Errorf("view leaf %s/%s/%s contains entry for %s/%s/%s", repo, osName, arch, entry.Repo, entry.OS, entry.Arch)
		}
		if public && entry.Pool != "public" {
			return count, fmt.Errorf("confidentiality closure violation: public view references gated path %s", entry.Path)
		}
		if public && entry.DebugInfo {
			return count, fmt.Errorf("public view references debuginfo path %s", entry.Path)
		}
		if validate != nil {
			if err := validate(entry); err != nil {
				return count, err
			}
		}
		count++
	}
}

// Promote writes the union of destination and selected source entries. Both inputs
// must be canonical sorted streams. Public destinations always enforce the
// confidentiality closure; there is deliberately no skip/force parameter.
func Promote(destination, source io.Reader, out io.Writer, selector Selector, public bool) (int64, error) {
	return PromoteWithReplacements(destination, source, out, selector, public, nil)
}

// PromoteWithReplacements is the streaming union used when a caller has an
// explicit, path-scoped authority to advance a mutable pointer. A nil predicate
// preserves Promote's strict set-union semantics. The caller owns the policy;
// this layer still enforces canonical ordering and the public closure.
func PromoteWithReplacements(destination, source io.Reader, out io.Writer, selector Selector, public bool, replacementAllowed func(Entry) bool) (int64, error) {
	destReader := NewReader(destination)
	sourceReader := NewReader(source)
	dest, destErr := destReader.Next()
	src, sourceErr := nextSelected(sourceReader, selector)
	var written int64
	for !errors.Is(destErr, io.EOF) || !errors.Is(sourceErr, io.EOF) {
		if destErr != nil && !errors.Is(destErr, io.EOF) {
			return written, destErr
		}
		if sourceErr != nil && !errors.Is(sourceErr, io.EOF) {
			return written, sourceErr
		}
		var entry Entry
		switch {
		case errors.Is(destErr, io.EOF):
			entry = src
			src, sourceErr = nextSelected(sourceReader, selector)
		case errors.Is(sourceErr, io.EOF):
			entry = dest
			dest, destErr = destReader.Next()
		case dest.Key() < src.Key():
			entry = dest
			dest, destErr = destReader.Next()
		case src.Key() < dest.Key():
			entry = src
			src, sourceErr = nextSelected(sourceReader, selector)
		default:
			if dest != src {
				if replacementAllowed == nil || !replacementAllowed(src) {
					return written, fmt.Errorf("view conflict at %s: same identity has different content", dest.Path)
				}
				entry = src
			} else {
				entry = dest
			}
			dest, destErr = destReader.Next()
			src, sourceErr = nextSelected(sourceReader, selector)
		}
		if public && entry.Pool != "public" {
			return written, fmt.Errorf("confidentiality closure violation: public view references gated path %s", entry.Path)
		}
		if public && entry.DebugInfo {
			return written, fmt.Errorf("public view references debuginfo path %s", entry.Path)
		}
		if err := WriteEntry(out, entry); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

func Remove(in io.Reader, out io.Writer, selector Selector, appendOnly bool) (removed int64, err error) {
	if appendOnly {
		return 0, errors.New("cannot remove from append-only stable or snapshot view")
	}
	reader := NewReader(in)
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			return removed, nil
		}
		if readErr != nil {
			return removed, readErr
		}
		if selector.Match(entry) {
			removed++
			continue
		}
		if err := WriteEntry(out, entry); err != nil {
			return removed, err
		}
	}
}

func nextSelected(reader *Reader, selector Selector) (Entry, error) {
	for {
		entry, err := reader.Next()
		if err != nil {
			return Entry{}, err
		}
		if selector.Match(entry) {
			return entry, nil
		}
	}
}
