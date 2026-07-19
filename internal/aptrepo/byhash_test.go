package aptrepo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestPlanAndApplyByHashCleanupRetainsCompleteGenerations(t *testing.T) {
	now := time.Date(2026, 7, 12, 5, 0, 0, 0, time.UTC)
	shared := testByHashContentPath("shared")
	sharedSecond := testByHashContentPath("shared-second")
	oldOnly := testByHashContentPath("old-only")
	middleOnly := testByHashContentPath("middle-only")
	newOnly := testByHashContentPath("new-only")
	generations := []ByHashGeneration{
		testByHashGeneration(strings.Repeat("1", 64), now.Add(-2*time.Hour), []string{oldOnly, shared, sharedSecond}),
		testByHashGeneration(strings.Repeat("2", 64), now.Add(-time.Hour), []string{middleOnly, shared, sharedSecond}),
		testByHashGeneration(strings.Repeat("3", 64), now, []string{newOnly, shared, sharedSecond}),
	}
	plan, err := PlanByHashCleanup(generations, 2, strings.Repeat("3", 64))
	if err != nil {
		t.Fatalf("PlanByHashCleanup: %v", err)
	}
	if !reflect.DeepEqual(plan.RetainedGenerationIDs, []string{strings.Repeat("3", 64), strings.Repeat("2", 64)}) {
		t.Fatalf("retained generations = %v", plan.RetainedGenerationIDs)
	}
	if !reflect.DeepEqual(plan.Remove, []string{oldOnly}) {
		t.Fatalf("Remove = %v, want only %s", plan.Remove, oldOnly)
	}
	root := t.TempDir()
	contents := map[string]string{shared: "shared", sharedSecond: "shared-second", oldOnly: "old-only", middleOnly: "middle-only", newOnly: "new-only"}
	for filePath, content := range contents {
		fullPath := filepath.Join(root, filepath.FromSlash(filePath))
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := ApplyByHashCleanup(context.Background(), root, plan); err != nil {
		t.Fatalf("ApplyByHashCleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(oldOnly))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old-only path still exists: %v", err)
	}
	for _, filePath := range []string{shared, sharedSecond, middleOnly, newOnly} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(filePath))); err != nil {
			t.Fatalf("retained path %s missing: %v", filePath, err)
		}
	}
}

func TestByHashCleanupRejectsUnsafeOrCanonicalPaths(t *testing.T) {
	validID := strings.Repeat("1", 64)
	now := time.Date(2026, 7, 12, 5, 30, 0, 0, time.UTC)
	unsafe := []string{
		"../../Release",
		"dists/beta/Release",
		"dists/beta/main/binary-amd64/by-hash/SHA256/not-a-digest",
		"dists/beta/main/source/by-hash/SHA256/" + strings.Repeat("a", 64),
	}
	for _, filePath := range unsafe {
		_, err := PlanByHashCleanup([]ByHashGeneration{testByHashGeneration(validID, now, []string{filePath})}, 1, validID)
		if err == nil {
			t.Errorf("PlanByHashCleanup accepted %q", filePath)
		}
	}
	if _, err := PlanByHashCleanup(nil, 0, ""); err == nil {
		t.Fatal("PlanByHashCleanup accepted zero retention")
	}

	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlink := testByHashPath("e")
	fullSymlink := filepath.Join(root, filepath.FromSlash(symlink))
	if err := os.MkdirAll(filepath.Dir(fullSymlink), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, fullSymlink); err != nil {
		t.Fatal(err)
	}
	if err := ApplyByHashCleanup(context.Background(), root, testCleanupPlan([]string{symlink})); err == nil {
		t.Fatal("ApplyByHashCleanup accepted a symlink")
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "keep" {
		t.Fatalf("outside symlink target changed: data=%q err=%v", data, err)
	}
	ancestorRoot := t.TempDir()
	ancestorOutside := t.TempDir()
	ancestorTarget := filepath.Join(ancestorOutside, "beta/main/binary-amd64/by-hash/SHA256", strings.Repeat("a", 64))
	if err := os.MkdirAll(filepath.Dir(ancestorTarget), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ancestorTarget, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ancestorOutside, filepath.Join(ancestorRoot, "dists")); err != nil {
		t.Fatal(err)
	}
	ancestorPath := testByHashPath("a")
	if err := ApplyByHashCleanup(context.Background(), ancestorRoot, testCleanupPlan([]string{ancestorPath})); err == nil {
		t.Fatal("ApplyByHashCleanup followed an ancestor symlink")
	}
	if data, err := os.ReadFile(ancestorTarget); err != nil || string(data) != "outside" {
		t.Fatalf("ancestor symlink target changed: data=%q err=%v", data, err)
	}
	missing := testByHashPath("f")
	if err := ApplyByHashCleanup(context.Background(), t.TempDir(), testCleanupPlan([]string{missing})); err != nil {
		t.Fatalf("cleanup of already-missing directory is not idempotent: %v", err)
	}
}

func TestByHashCleanupRejectsIncompleteOrAmbiguousGenerations(t *testing.T) {
	now := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)
	complete := []string{testByHashPath("a"), testByHashPath("b"), testByHashPath("c")}
	if _, err := PlanByHashCleanup([]ByHashGeneration{testByHashGeneration(strings.Repeat("1", 64), now, complete[:2])}, 1, strings.Repeat("1", 64)); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete generation error = %v", err)
	}
	truncated := testByHashGeneration(strings.Repeat("1", 64), now, complete)
	truncated.Paths = truncated.Paths[:2]
	if _, err := PlanByHashCleanup([]ByHashGeneration{truncated}, 1, truncated.ID); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("truncated generation error = %v", err)
	}
	_, err := PlanByHashCleanup([]ByHashGeneration{
		testByHashGeneration(strings.Repeat("1", 64), now, complete),
		testByHashGeneration(strings.Repeat("2", 64), now, complete),
	}, 1, strings.Repeat("2", 64))
	if err == nil || !strings.Contains(err.Error(), "ambiguous creation time") {
		t.Fatalf("same-time generation error = %v", err)
	}
	duplicate := testByHashGeneration(strings.Repeat("3", 64), now.Add(time.Hour), complete)
	duplicate.Paths = append(duplicate.Paths, duplicate.Paths[len(duplicate.Paths)-1])
	if _, err := PlanByHashCleanup([]ByHashGeneration{duplicate}, 1, duplicate.ID); err == nil || !strings.Contains(err.Error(), "duplicate path") {
		t.Fatalf("duplicate generation path error = %v", err)
	}
}

func TestByHashCleanupAlwaysPinsLiveGeneration(t *testing.T) {
	now := time.Date(2026, 7, 12, 8, 0, 0, 0, time.UTC)
	oldLiveID := strings.Repeat("1", 64)
	newerID := strings.Repeat("2", 64)
	oldPaths := []string{testByHashPath("a"), testByHashPath("b"), testByHashPath("c")}
	newPaths := []string{testByHashPath("d"), testByHashPath("e"), testByHashPath("f")}
	plan, err := PlanByHashCleanup([]ByHashGeneration{
		testByHashGeneration(oldLiveID, now.Add(-time.Hour), oldPaths),
		testByHashGeneration(newerID, now, newPaths),
	}, 1, oldLiveID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.RetainedGenerationIDs, []string{oldLiveID}) || !reflect.DeepEqual(plan.Remove, newPaths) {
		t.Fatalf("live pin plan = %+v", plan)
	}
}

func TestByHashCleanupFailsClosedWhenRetainedGenerationIsMissing(t *testing.T) {
	root := t.TempDir()
	remove := testByHashPath("a")
	keep := testByHashPath("b")
	fullRemove := filepath.Join(root, filepath.FromSlash(remove))
	if err := os.MkdirAll(filepath.Dir(fullRemove), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullRemove, []byte("must survive"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan := CleanupPlan{Keep: []string{keep}, Remove: []string{remove}}
	plan.PlanSHA256 = sealCleanupPlan(plan)
	if err := ApplyByHashCleanup(context.Background(), root, plan); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("missing retained path error = %v", err)
	}
	if data, err := os.ReadFile(fullRemove); err != nil || string(data) != "must survive" {
		t.Fatalf("cleanup was not fail-closed: data=%q err=%v", data, err)
	}
}

func TestByHashCleanupHonorsLockCancellationAndNilContext(t *testing.T) {
	root := t.TempDir()
	plan := testCleanupPlan([]string{testByHashPath("a")})
	//lint:ignore SA1012 This test intentionally exercises public nil-context rejection.
	if err := ApplyByHashCleanup(nil, root, plan); err == nil || !strings.Contains(err.Error(), "nil context") {
		t.Fatalf("nil-context cleanup error = %v", err)
	}
	unlock, err := acquireOutputLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unlock(); err != nil {
			t.Errorf("release output lock: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := ApplyByHashCleanup(ctx, root, plan); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended cleanup error = %v", err)
	}
}

func testByHashPath(hexDigit string) string {
	return "dists/beta/main/binary-amd64/by-hash/SHA256/" + strings.Repeat(hexDigit, 64)
}

func testByHashContentPath(content string) string {
	digest := sha256.Sum256([]byte(content))
	return "dists/beta/main/binary-amd64/by-hash/SHA256/" + hex.EncodeToString(digest[:])
}

func testByHashGeneration(id string, createdAt time.Time, paths []string) ByHashGeneration {
	paths = append([]string(nil), paths...)
	sort.Strings(paths)
	return ByHashGeneration{ID: id, CreatedAt: createdAt, Paths: paths, PathsSHA256: sealByHashPaths(paths)}
}

func testCleanupPlan(remove []string) CleanupPlan {
	plan := CleanupPlan{Remove: remove}
	plan.PlanSHA256 = sealCleanupPlan(plan)
	return plan
}
