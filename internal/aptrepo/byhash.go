package aptrepo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ByHashGeneration struct {
	Sequence    uint64    `json:"sequence,omitempty"`
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	Paths       []string  `json:"paths"`
	PathsSHA256 string    `json:"paths_sha256"`
}

type CleanupPlan struct {
	RetainedGenerationIDs []string
	Keep                  []string
	Remove                []string
	PlanSHA256            string
}

// PlanByHashCleanup retains the live Release generation plus the newest
// complete generations up to N, and returns exact immutable by-hash files no
// retained Release references. liveGenerationID is mandatory whenever any
// generation exists, so clock skew can never collect the published Release.
func PlanByHashCleanup(generations []ByHashGeneration, retain int, liveGenerationID string) (CleanupPlan, error) {
	if retain < 1 {
		return CleanupPlan{}, errors.New("aptrepo: by-hash retention must be positive")
	}
	ordered := append([]ByHashGeneration(nil), generations...)
	seenIDs := make(map[string]struct{}, len(ordered))
	seenCreationTimes := make(map[string]struct{}, len(ordered))
	seenSequences := make(map[uint64]struct{}, len(ordered))
	sequenced := false
	for i := range ordered {
		sequenced = sequenced || ordered[i].Sequence != 0
	}
	for i := range ordered {
		if !isLowerHex(ordered[i].ID, 64) {
			return CleanupPlan{}, fmt.Errorf("aptrepo: invalid by-hash generation ID %q", ordered[i].ID)
		}
		if _, exists := seenIDs[ordered[i].ID]; exists {
			return CleanupPlan{}, fmt.Errorf("aptrepo: duplicate by-hash generation ID %q", ordered[i].ID)
		}
		seenIDs[ordered[i].ID] = struct{}{}
		if ordered[i].CreatedAt.IsZero() {
			return CleanupPlan{}, fmt.Errorf("aptrepo: by-hash generation %q has no creation time", ordered[i].ID)
		}
		if sequenced {
			if ordered[i].Sequence == 0 {
				return CleanupPlan{}, fmt.Errorf("aptrepo: by-hash generation %q has no sequence", ordered[i].ID)
			}
			if _, duplicate := seenSequences[ordered[i].Sequence]; duplicate {
				return CleanupPlan{}, fmt.Errorf("aptrepo: duplicate by-hash generation sequence %d", ordered[i].Sequence)
			}
			seenSequences[ordered[i].Sequence] = struct{}{}
		} else {
			created := ordered[i].CreatedAt.UTC().Format(time.RFC3339Nano)
			if _, duplicate := seenCreationTimes[created]; duplicate {
				return CleanupPlan{}, fmt.Errorf("aptrepo: by-hash generations have ambiguous creation time %s", ordered[i].CreatedAt.UTC().Format(time.RFC3339Nano))
			}
			seenCreationTimes[created] = struct{}{}
		}
		if len(ordered[i].Paths) == 0 {
			return CleanupPlan{}, fmt.Errorf("aptrepo: by-hash generation %q has no paths", ordered[i].ID)
		}
		paths := append([]string(nil), ordered[i].Paths...)
		sort.Strings(paths)
		if hasDuplicate(paths) {
			return CleanupPlan{}, fmt.Errorf("aptrepo: duplicate path in by-hash generation %q", ordered[i].ID)
		}
		for _, value := range paths {
			if err := validateByHashPath(value); err != nil {
				return CleanupPlan{}, err
			}
		}
		if !isLowerHex(ordered[i].PathsSHA256, 64) || sealByHashPaths(paths) != ordered[i].PathsSHA256 {
			return CleanupPlan{}, fmt.Errorf("aptrepo: by-hash generation %q path-set checksum mismatch", ordered[i].ID)
		}
		pathCounts := make(map[string]int)
		for _, value := range paths {
			parts := strings.Split(value, "/")
			pathCounts[strings.Join(parts[:4], "/")]++
		}
		for base, count := range pathCounts {
			if count != 3 {
				return CleanupPlan{}, fmt.Errorf("aptrepo: incomplete by-hash generation %q for %s: got %d index variants, want 3", ordered[i].ID, base, count)
			}
		}
		ordered[i].Paths = paths
	}

	sort.Slice(ordered, func(i, j int) bool {
		if sequenced && ordered[i].Sequence != ordered[j].Sequence {
			return ordered[i].Sequence > ordered[j].Sequence
		}
		if !ordered[i].CreatedAt.Equal(ordered[j].CreatedAt) {
			return ordered[i].CreatedAt.After(ordered[j].CreatedAt)
		}
		return ordered[i].ID > ordered[j].ID
	})
	if retain > len(ordered) {
		retain = len(ordered)
	}
	if len(ordered) == 0 {
		if liveGenerationID != "" {
			return CleanupPlan{}, errors.New("aptrepo: live by-hash generation does not exist")
		}
		plan := CleanupPlan{}
		plan.PlanSHA256 = sealCleanupPlan(plan)
		return plan, nil
	}
	if !isLowerHex(liveGenerationID, 64) {
		return CleanupPlan{}, errors.New("aptrepo: live by-hash generation ID is required")
	}
	if _, exists := seenIDs[liveGenerationID]; !exists {
		return CleanupPlan{}, fmt.Errorf("aptrepo: live by-hash generation %q does not exist", liveGenerationID)
	}

	keepSet := make(map[string]struct{})
	retainedIDs := map[string]struct{}{liveGenerationID: {}}
	for _, generation := range ordered {
		if len(retainedIDs) >= retain {
			break
		}
		retainedIDs[generation.ID] = struct{}{}
	}
	plan := CleanupPlan{}
	for _, generation := range ordered {
		if _, retained := retainedIDs[generation.ID]; retained {
			plan.RetainedGenerationIDs = append(plan.RetainedGenerationIDs, generation.ID)
			for _, value := range generation.Paths {
				keepSet[value] = struct{}{}
			}
		}
	}
	removeSet := make(map[string]struct{})
	for _, generation := range ordered {
		if _, retained := retainedIDs[generation.ID]; !retained {
			for _, value := range generation.Paths {
				if _, kept := keepSet[value]; !kept {
					removeSet[value] = struct{}{}
				}
			}
		}
	}
	for value := range keepSet {
		plan.Keep = append(plan.Keep, value)
	}
	for value := range removeSet {
		plan.Remove = append(plan.Remove, value)
	}
	sort.Strings(plan.Keep)
	sort.Strings(plan.Remove)
	plan.PlanSHA256 = sealCleanupPlan(plan)
	return plan, nil
}

func sealByHashPaths(paths []string) string {
	h := sha256.New()
	for _, value := range paths {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ApplyByHashCleanup removes only the exact immutable files selected by a
// validated CleanupPlan. It intentionally leaves directories in place and
// refuses symlinks, directories, canonical indexes and paths also marked Keep.
func ApplyByHashCleanup(ctx context.Context, root string, plan CleanupPlan) (resultErr error) {
	if ctx == nil {
		return errors.New("aptrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !isLowerHex(plan.PlanSHA256, 64) || plan.PlanSHA256 != sealCleanupPlan(plan) {
		return errors.New("aptrepo: unsealed or corrupted by-hash cleanup plan")
	}
	if err := validateOutputRoot(root); err != nil {
		return err
	}
	unlock, err := acquireOutputLock(ctx, root)
	if err != nil {
		return err
	}
	defer propagateOutputUnlock(unlock, &resultErr)
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("aptrepo: open cleanup root: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, rootHandle.Close()) }()
	keep := make(map[string]struct{}, len(plan.Keep))
	for _, value := range plan.Keep {
		if err := validateByHashPath(value); err != nil {
			return err
		}
		keep[value] = struct{}{}
	}
	keepPaths := append([]string(nil), plan.Keep...)
	sort.Strings(keepPaths)
	if hasDuplicate(keepPaths) {
		return errors.New("aptrepo: duplicate retained by-hash path")
	}
	// Preflight every retained generation before deleting anything. A missing,
	// replaced, or corrupt live object turns cleanup into a fail-closed error.
	for _, value := range keepPaths {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := ensureOutputParent(root, value, false); err != nil {
			return fmt.Errorf("aptrepo: inspect retained by-hash path %q: %w", value, err)
		}
		info, err := rootHandle.Lstat(filepath.FromSlash(value))
		if err != nil {
			return fmt.Errorf("aptrepo: inspect retained by-hash path %q: %w", value, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("aptrepo: retained by-hash path is not regular %q", value)
		}
		file, err := rootHandle.Open(filepath.FromSlash(value))
		if err != nil {
			return fmt.Errorf("aptrepo: open retained by-hash path %q: %w", value, err)
		}
		actual, written, hashErr := hashReader(ctx, file)
		closeErr := file.Close()
		if hashErr != nil || closeErr != nil {
			return fmt.Errorf("aptrepo: hash retained by-hash path %q: %w", value, errors.Join(hashErr, closeErr))
		}
		if written != info.Size() || actual != path.Base(value) {
			return fmt.Errorf("aptrepo: retained by-hash path checksum mismatch %q", value)
		}
	}
	remove := append([]string(nil), plan.Remove...)
	sort.Strings(remove)
	if hasDuplicate(remove) {
		return errors.New("aptrepo: duplicate by-hash removal path")
	}
	for _, value := range remove {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateByHashPath(value); err != nil {
			return err
		}
		if _, retained := keep[value]; retained {
			return fmt.Errorf("aptrepo: by-hash path is both retained and removed %q", value)
		}
		if _, err := outputPath(root, value); err != nil {
			return err
		}
		if err := ensureOutputParent(root, value, false); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		info, err := rootHandle.Lstat(filepath.FromSlash(value))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("aptrepo: inspect by-hash cleanup path %q: %w", value, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("aptrepo: refuse non-regular by-hash cleanup path %q", value)
		}
		if err := rootHandle.Remove(filepath.FromSlash(value)); err != nil {
			return fmt.Errorf("aptrepo: remove by-hash path %q: %w", value, err)
		}
		if err := syncRootParent(rootHandle, value); err != nil {
			return fmt.Errorf("aptrepo: sync by-hash cleanup path %q: %w", value, err)
		}
	}
	return nil
}

func sealCleanupPlan(plan CleanupPlan) string {
	h := sha256.New()
	for _, group := range []struct {
		name   string
		values []string
	}{
		{name: "retained", values: plan.RetainedGenerationIDs},
		{name: "keep", values: plan.Keep},
		{name: "remove", values: plan.Remove},
	} {
		_, _ = h.Write([]byte(group.name + "\n"))
		for _, value := range group.values {
			_, _ = h.Write([]byte(value))
			_, _ = h.Write([]byte{'\n'})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func validateByHashPath(value string) error {
	if err := validateRelativePath(value); err != nil {
		return fmt.Errorf("aptrepo: unsafe by-hash cleanup path %q", value)
	}
	parts := strings.Split(value, "/")
	if len(parts) != 7 || parts[0] != "dists" || parts[4] != "by-hash" || parts[5] != "SHA256" || !isLowerHex(parts[6], 64) {
		return fmt.Errorf("aptrepo: non by-hash cleanup path %q", value)
	}
	if validateSegment("suite", parts[1]) != nil || validateComponent(parts[2]) != nil || !strings.HasPrefix(parts[3], "binary-") || !architecturePattern.MatchString(strings.TrimPrefix(parts[3], "binary-")) {
		return fmt.Errorf("aptrepo: non binary-index by-hash path %q", value)
	}
	return nil
}

func validateRelativePath(value string) error {
	if value == "" || path.IsAbs(value) || path.Clean(value) != value || strings.ContainsAny(value, "\\\x00\r\n\t") {
		return errors.New("unsafe relative path")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("unsafe relative path")
		}
	}
	return nil
}

func isLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
