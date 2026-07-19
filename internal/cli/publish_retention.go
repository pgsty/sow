package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

type snapshotRetentionPlan struct {
	baseline string
	expired  map[string]struct{}
	deletes  []pub.PlannedDelete
}

// planRemoteSnapshotRetention derives deletions exclusively from the
// canonical, separately audited remote inventory. Partial coverage disables
// pruning entirely: SOW never guesses from a List-free publish baseline.
func planRemoteSnapshotRetention(canonical *state.Store, target, oldManifest, destination, keepID string, months int) (snapshotRetentionPlan, error) {
	result := snapshotRetentionPlan{baseline: oldManifest, expired: make(map[string]struct{})}
	coverage, exists, err := readOptionalCanonical(canonical, remoteStatePath(target, "inventory.coverage"))
	if err != nil {
		return result, err
	}
	if !exists || string(coverage) != remoteInventoryComplete {
		return result, nil
	}

	ids, err := snapshotIDsInSourceManifest(oldManifest)
	if err != nil {
		return result, err
	}
	inventory, inventoryExists, err := openOptionalCanonical(canonical, remoteStatePath(target, "inventory.tsv"))
	if err != nil {
		return result, err
	}
	if inventory != nil {
		defer inventory.Close()
	}
	if !inventoryExists {
		return result, fmt.Errorf("complete target %s inventory coverage has no inventory", target)
	}
	reader := manifest.NewReader(inventory)
	var inventoryEntries []manifest.Entry
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return result, readErr
		}
		if snapshotID, owned := remoteSnapshotOwnedKey(entry.Path); owned {
			ids[snapshotID] = struct{}{}
			inventoryEntries = append(inventoryEntries, entry)
		}
	}
	for snapshotID := range ids {
		retained, err := retainMaterializedSnapshot(snapshotID, timeNowUTC(), months)
		if err != nil {
			return result, err
		}
		if !retained && snapshotID != keepID {
			result.expired[snapshotID] = struct{}{}
		}
	}
	if len(result.expired) == 0 {
		return result, nil
	}
	var scopes []string
	for snapshotID := range result.expired {
		scopes = append(scopes, path.Join(".sow/materialized/snapshots", snapshotID))
	}
	sort.Strings(scopes)
	if err := DropManifestScopes(oldManifest, destination, scopes); err != nil {
		return result, err
	}
	result.baseline = destination
	for _, entry := range inventoryEntries {
		snapshotID, owned := remoteSnapshotOwnedKey(entry.Path)
		if !owned {
			continue
		}
		if _, expired := result.expired[snapshotID]; !expired {
			continue
		}
		deletion := pub.PlannedDelete{
			Class: pub.DeleteSnapshotOwned, SourcePath: entry.Path, RemoteKey: entry.Path,
			Size: entry.Size, SHA256: entry.HashString(),
		}
		if entry.Path == path.Join(".sow/snapshots", snapshotID+".json") {
			deletion.CDNPath = path.Join("pro/v1/basic/_sow/v1/snapshots", snapshotID, "_route.json")
		}
		result.deletes = append(result.deletes, deletion)
	}
	sort.Slice(result.deletes, func(i, j int) bool { return result.deletes[i].RemoteKey < result.deletes[j].RemoteKey })
	return result, nil
}

func snapshotIDsInSourceManifest(filename string) (map[string]struct{}, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := make(map[string]struct{})
	reader := manifest.NewReader(file)
	const prefix = ".sow/materialized/snapshots/"
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(entry.Path, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(entry.Path, prefix)
		id, _, found := strings.Cut(remainder, "/")
		if !found || views.ValidateSnapshotID(id) != nil {
			return nil, fmt.Errorf("unsafe snapshot source path %s in target manifest", entry.Path)
		}
		result[id] = struct{}{}
	}
}

func remoteSnapshotOwnedKey(key string) (string, bool) {
	if strings.HasPrefix(key, ".sow/snapshots/") && strings.HasSuffix(key, ".json") {
		id := strings.TrimSuffix(strings.TrimPrefix(key, ".sow/snapshots/"), ".json")
		return id, views.ValidateSnapshotID(id) == nil
	}
	const prefix = ".sow/gated/snapshots/"
	if strings.HasPrefix(key, prefix) {
		id, tail, found := strings.Cut(strings.TrimPrefix(key, prefix), "/")
		return id, found && tail != "" && views.ValidateSnapshotID(id) == nil
	}
	return "", false
}
