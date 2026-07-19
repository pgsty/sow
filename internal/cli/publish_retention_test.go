package cli

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/state"
)

func TestRemoteSnapshotRetentionRequiresCompleteInventoryAndNeverDeletesSharedObjects(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	originalNow := timeNowUTC
	timeNowUTC = func() time.Time { return now }
	defer func() { timeNowUTC = originalNow }()

	oldManifest := writeRetentionManifest(t, []string{
		".sow/materialized/snapshots/jammy-20260131/yum/repo/Packages/old.rpm",
		".sow/materialized/snapshots/jammy-20260712/yum/repo/Packages/current.rpm",
	})
	inventory := writeRetentionManifest(t, []string{
		".sow/gated/generations/00000000000000000007/yum/repo/repodata/repomd.xml",
		".sow/gated/snapshots/jammy-20260131/yum/repo/Packages/old.rpm",
		".sow/gated/yum/repo/Packages/shared.rpm",
		".sow/snapshots/jammy-20260131.json",
		".sow/snapshots/jammy-20260712.json",
	})
	coverage := filepath.Join(t.TempDir(), "coverage")
	if err := os.WriteFile(coverage, []byte(remoteInventoryComplete), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), ".sow")
	canonical := state.New(statePath)
	inventoryStage := stageRetentionFile(t, statePath, "inventory.tsv", inventory)
	coverageStage := stageRetentionFile(t, statePath, "coverage", coverage)
	if _, _, err := canonical.Apply(context.Background(), "test", "install complete inventory", map[string]string{
		remoteStatePath("cf", "inventory.tsv"):      inventoryStage,
		remoteStatePath("cf", "inventory.coverage"): coverageStage,
	}, nil, state.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	baseline := filepath.Join(t.TempDir(), "retained.tsv")
	plan, err := planRemoteSnapshotRetention(canonical, "cf", oldManifest, baseline, "", 6)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plan.expired["jammy-20260131"]; !ok || len(plan.expired) != 1 {
		t.Fatalf("expired set=%v", plan.expired)
	}
	if len(plan.deletes) != 2 || plan.deletes[0].RemoteKey != ".sow/gated/snapshots/jammy-20260131/yum/repo/Packages/old.rpm" || plan.deletes[1].RemoteKey != ".sow/snapshots/jammy-20260131.json" {
		t.Fatalf("unsafe or incomplete delete plan: %#v", plan.deletes)
	}
	if plan.deletes[1].CDNPath != "pro/v1/basic/_sow/v1/snapshots/jammy-20260131/_route.json" {
		t.Fatalf("route deletion lacks exact purge path: %#v", plan.deletes[1])
	}
	body, err := os.ReadFile(plan.baseline)
	if err != nil || strings.Contains(string(body), "jammy-20260131") || !strings.Contains(string(body), "jammy-20260712") {
		t.Fatalf("retained content baseline=%s err=%v", body, err)
	}

	partialCoverage := filepath.Join(t.TempDir(), "partial")
	if err := os.WriteFile(partialCoverage, []byte(remoteInventoryPartial), 0o600); err != nil {
		t.Fatal(err)
	}
	partialStatePath := filepath.Join(t.TempDir(), ".sow")
	partial := state.New(partialStatePath)
	partialInventoryStage := stageRetentionFile(t, partialStatePath, "inventory.tsv", inventory)
	partialCoverageStage := stageRetentionFile(t, partialStatePath, "coverage", partialCoverage)
	if _, _, err := partial.Apply(context.Background(), "test", "install partial inventory", map[string]string{
		remoteStatePath("cf", "inventory.tsv"):      partialInventoryStage,
		remoteStatePath("cf", "inventory.coverage"): partialCoverageStage,
	}, nil, state.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	blocked, err := planRemoteSnapshotRetention(partial, "cf", oldManifest, filepath.Join(t.TempDir(), "must-not-exist.tsv"), "", 6)
	if err != nil || blocked.baseline != oldManifest || len(blocked.deletes) != 0 || len(blocked.expired) != 0 {
		t.Fatalf("partial inventory enabled deletion: %#v err=%v", blocked, err)
	}
}

func TestRemoteSnapshotRetentionRejectsFutureSnapshot(t *testing.T) {
	originalNow := timeNowUTC
	timeNowUTC = func() time.Time { return time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC) }
	defer func() { timeNowUTC = originalNow }()
	old := writeRetentionManifest(t, []string{".sow/materialized/snapshots/jammy-20260713/yum/repo/Packages/future.rpm"})
	inventory := writeRetentionManifest(t, []string{".sow/snapshots/jammy-20260713.json"})
	coverage := filepath.Join(t.TempDir(), "coverage")
	_ = os.WriteFile(coverage, []byte(remoteInventoryComplete), 0o600)
	statePath := filepath.Join(t.TempDir(), ".sow")
	canonical := state.New(statePath)
	inventoryStage := stageRetentionFile(t, statePath, "inventory.tsv", inventory)
	coverageStage := stageRetentionFile(t, statePath, "coverage", coverage)
	if _, _, err := canonical.Apply(context.Background(), "test", "future inventory", map[string]string{
		remoteStatePath("cf", "inventory.tsv"): inventoryStage, remoteStatePath("cf", "inventory.coverage"): coverageStage,
	}, nil, state.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := planRemoteSnapshotRetention(canonical, "cf", old, filepath.Join(t.TempDir(), "out.tsv"), "", 6); err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("future snapshot was accepted: %v", err)
	}
}

func stageRetentionFile(t *testing.T, statePath, name, source string) string {
	t.Helper()
	directory := filepath.Join(statePath, "test-stage")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, name)
	body, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return destination
}

func writeRetentionManifest(t *testing.T, paths []string) string {
	t.Helper()
	sort.Strings(paths)
	filename := filepath.Join(t.TempDir(), "manifest.tsv")
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range paths {
		digest := sha256.Sum256([]byte(name))
		if err := manifest.WriteEntry(file, manifest.Entry{Path: name, Size: int64(len(name)), SHA256: digest}); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return filename
}
