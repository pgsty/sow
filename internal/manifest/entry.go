package manifest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
)

type Entry struct {
	Path   string
	Size   int64
	SHA256 [sha256.Size]byte
}

func (e Entry) HashString() string { return hex.EncodeToString(e.SHA256[:]) }

func (e Entry) Validate() error {
	if e.Path == "" || strings.ContainsAny(e.Path, "\t\r\n\\") || strings.HasPrefix(e.Path, "/") {
		return fmt.Errorf("unsafe manifest path %q", e.Path)
	}
	clean := path.Clean(e.Path)
	if clean != e.Path || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("non-canonical manifest path %q", e.Path)
	}
	if e.Size < 0 {
		return fmt.Errorf("negative size for %q", e.Path)
	}
	return nil
}

func WriteEntry(w io.Writer, e Entry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%s\t%d\t%s\n", e.Path, e.Size, e.HashString())
	return err
}

type Reader struct {
	scanner *bufio.Scanner
	line    int
	last    string
}

func NewReader(r io.Reader) *Reader {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	return &Reader{scanner: scanner}
}

func (r *Reader) Next() (Entry, error) {
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return Entry{}, err
		}
		return Entry{}, io.EOF
	}
	r.line++
	line := r.scanner.Text()
	parts := strings.Split(line, "\t")
	if len(parts) != 3 {
		return Entry{}, fmt.Errorf("manifest line %d: want 3 tab-separated fields", r.line)
	}
	size, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return Entry{}, fmt.Errorf("manifest line %d: invalid size: %w", r.line, err)
	}
	digest, err := hex.DecodeString(parts[2])
	if err != nil || len(digest) != sha256.Size {
		return Entry{}, fmt.Errorf("manifest line %d: invalid sha256", r.line)
	}
	var hash [sha256.Size]byte
	copy(hash[:], digest)
	entry := Entry{Path: parts[0], Size: size, SHA256: hash}
	if err := entry.Validate(); err != nil {
		return Entry{}, fmt.Errorf("manifest line %d: %w", r.line, err)
	}
	if r.last != "" && entry.Path <= r.last {
		return Entry{}, fmt.Errorf("manifest line %d: paths are not strictly sorted (%q after %q)", r.line, entry.Path, r.last)
	}
	r.last = entry.Path
	return entry, nil
}

type ChangeKind string

const (
	Added   ChangeKind = "added"
	Removed ChangeKind = "removed"
	Changed ChangeKind = "changed"
)

type Change struct {
	Kind ChangeKind
	Old  *Entry
	New  *Entry
}

func (c Change) Path() string {
	if c.New != nil {
		return c.New.Path
	}
	return c.Old.Path
}

type DiffStats struct {
	Added   int64
	Removed int64
	Changed int64
}

func (s DiffStats) Clean() bool { return s.Added == 0 && s.Removed == 0 && s.Changed == 0 }

func Diff(oldReader, newReader io.Reader, emit func(Change) error) (DiffStats, error) {
	oldManifest := NewReader(oldReader)
	newManifest := NewReader(newReader)
	oldEntry, oldErr := oldManifest.Next()
	newEntry, newErr := newManifest.Next()
	var stats DiffStats
	for !errors.Is(oldErr, io.EOF) || !errors.Is(newErr, io.EOF) {
		if oldErr != nil && !errors.Is(oldErr, io.EOF) {
			return stats, oldErr
		}
		if newErr != nil && !errors.Is(newErr, io.EOF) {
			return stats, newErr
		}
		switch {
		case errors.Is(oldErr, io.EOF):
			copyNew := newEntry
			stats.Added++
			if emit != nil {
				if err := emit(Change{Kind: Added, New: &copyNew}); err != nil {
					return stats, err
				}
			}
			newEntry, newErr = newManifest.Next()
		case errors.Is(newErr, io.EOF):
			copyOld := oldEntry
			stats.Removed++
			if emit != nil {
				if err := emit(Change{Kind: Removed, Old: &copyOld}); err != nil {
					return stats, err
				}
			}
			oldEntry, oldErr = oldManifest.Next()
		case oldEntry.Path < newEntry.Path:
			copyOld := oldEntry
			stats.Removed++
			if emit != nil {
				if err := emit(Change{Kind: Removed, Old: &copyOld}); err != nil {
					return stats, err
				}
			}
			oldEntry, oldErr = oldManifest.Next()
		case newEntry.Path < oldEntry.Path:
			copyNew := newEntry
			stats.Added++
			if emit != nil {
				if err := emit(Change{Kind: Added, New: &copyNew}); err != nil {
					return stats, err
				}
			}
			newEntry, newErr = newManifest.Next()
		default:
			if oldEntry.Size != newEntry.Size || oldEntry.SHA256 != newEntry.SHA256 {
				copyOld, copyNew := oldEntry, newEntry
				stats.Changed++
				if emit != nil {
					if err := emit(Change{Kind: Changed, Old: &copyOld, New: &copyNew}); err != nil {
						return stats, err
					}
				}
			}
			oldEntry, oldErr = oldManifest.Next()
			newEntry, newErr = newManifest.Next()
		}
	}
	return stats, nil
}
