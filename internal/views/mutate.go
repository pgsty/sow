package views

import (
	"errors"
	"fmt"
	"io"
	"sort"
)

type Mutation struct {
	Upserts                    []Entry
	RemovePaths                []string
	AllowReplace               bool
	AppendOnly                 bool
	AppendOnlyReplacementPaths []string
	Public                     bool
}

type MutationStats struct {
	Added     int64
	Replaced  int64
	Removed   int64
	Unchanged int64
}

func (s MutationStats) Changed() bool { return s.Added+s.Replaced+s.Removed != 0 }

// Mutate applies a bounded command change set to a canonical streaming view.
// The existing view is never retained in memory. Public closure and append-only
// behavior are structural parameters; callers cannot force past either gate.
func Mutate(existing io.Reader, out io.Writer, mutation Mutation) (MutationStats, error) {
	var stats MutationStats
	if existing == nil || out == nil {
		return stats, errors.New("nil view mutation stream")
	}
	if mutation.AppendOnly && len(mutation.RemovePaths) != 0 {
		return stats, errors.New("append-only view cannot remove paths")
	}
	appendOnlyReplacements := make(map[string]struct{}, len(mutation.AppendOnlyReplacementPaths))
	for _, replacementPath := range mutation.AppendOnlyReplacementPaths {
		if replacementPath == "" {
			return stats, errors.New("empty append-only replacement path")
		}
		if _, duplicate := appendOnlyReplacements[replacementPath]; duplicate {
			return stats, fmt.Errorf("duplicate append-only replacement path %q", replacementPath)
		}
		appendOnlyReplacements[replacementPath] = struct{}{}
	}
	if mutation.AppendOnly && mutation.AllowReplace && len(appendOnlyReplacements) == 0 {
		return stats, errors.New("append-only view cannot replace paths without an explicit replacement scope")
	}
	upserts := append([]Entry(nil), mutation.Upserts...)
	sort.Slice(upserts, func(i, j int) bool { return upserts[i].Path < upserts[j].Path })
	for index, entry := range upserts {
		if err := entry.Validate(); err != nil {
			return stats, err
		}
		if mutation.Public && entry.Pool != "public" {
			return stats, fmt.Errorf("confidentiality closure violation: public view references gated path %s", entry.Path)
		}
		if mutation.Public && entry.DebugInfo {
			return stats, fmt.Errorf("public view references debuginfo path %s", entry.Path)
		}
		if index > 0 && upserts[index-1].Path == entry.Path {
			return stats, fmt.Errorf("duplicate mutation path %q", entry.Path)
		}
	}
	removals := make(map[string]struct{}, len(mutation.RemovePaths))
	for _, path := range mutation.RemovePaths {
		if path == "" {
			return stats, errors.New("empty removal path")
		}
		if _, exists := removals[path]; exists {
			return stats, fmt.Errorf("duplicate removal path %q", path)
		}
		removals[path] = struct{}{}
	}
	reader := NewReader(existing)
	current, currentErr := reader.Next()
	upsertIndex := 0
	for !errors.Is(currentErr, io.EOF) || upsertIndex < len(upserts) {
		if currentErr != nil && !errors.Is(currentErr, io.EOF) {
			return stats, currentErr
		}
		if !errors.Is(currentErr, io.EOF) && mutation.Public && current.Pool != "public" {
			return stats, fmt.Errorf("confidentiality closure violation: public view references gated path %s", current.Path)
		}
		if !errors.Is(currentErr, io.EOF) && mutation.Public && current.DebugInfo {
			return stats, fmt.Errorf("public view references debuginfo path %s", current.Path)
		}
		switch {
		case errors.Is(currentErr, io.EOF):
			entry := upserts[upsertIndex]
			if _, remove := removals[entry.Path]; !remove {
				if err := WriteEntry(out, entry); err != nil {
					return stats, err
				}
				stats.Added++
			}
			upsertIndex++
		case upsertIndex >= len(upserts) || current.Path < upserts[upsertIndex].Path:
			if _, remove := removals[current.Path]; remove {
				if mutation.AppendOnly {
					return stats, errors.New("append-only view cannot remove paths")
				}
				stats.Removed++
			} else {
				if err := WriteEntry(out, current); err != nil {
					return stats, err
				}
				stats.Unchanged++
			}
			current, currentErr = reader.Next()
		case upserts[upsertIndex].Path < current.Path:
			entry := upserts[upsertIndex]
			if _, remove := removals[entry.Path]; !remove {
				if err := WriteEntry(out, entry); err != nil {
					return stats, err
				}
				stats.Added++
			}
			upsertIndex++
		default:
			entry := upserts[upsertIndex]
			if _, remove := removals[current.Path]; remove {
				if mutation.AppendOnly {
					return stats, errors.New("append-only view cannot remove paths")
				}
				stats.Removed++
			} else if entry == current {
				if err := WriteEntry(out, current); err != nil {
					return stats, err
				}
				stats.Unchanged++
			} else if !mutation.AllowReplace {
				return stats, fmt.Errorf("view path conflict %q: existing content differs", current.Path)
			} else {
				if mutation.AppendOnly {
					if _, permitted := appendOnlyReplacements[current.Path]; !permitted {
						return stats, fmt.Errorf("append-only view cannot replace path %q outside its explicit replacement scope", current.Path)
					}
				}
				if err := WriteEntry(out, entry); err != nil {
					return stats, err
				}
				stats.Replaced++
			}
			current, currentErr = reader.Next()
			upsertIndex++
		}
	}
	return stats, nil
}
