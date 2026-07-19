package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

const (
	remoteInventoryComplete = "complete\n"
	remoteInventoryPartial  = "partial\n"
)

// stageRemoteInventory accumulates the actual remote-key closure without
// changing content.tsv, which remains the source-path baseline used to compute
// O(change-set) publication plans. Memory is proportional to this plan only;
// the parent inventory is merged as a sorted stream.
func stageRemoteInventory(canonical *state.Store, publication targetPublication, generationBody, checkpointBody []byte, destination string) (string, error) {
	updates := make(map[string]manifest.Entry, len(publication.request.Plan.Objects)+3)
	for _, object := range publication.request.Plan.Objects {
		entry, err := remoteInventoryEntry(object.RemoteKey, object.Size, object.SHA256)
		if err != nil {
			return "", fmt.Errorf("inventory planned object %s: %w", object.RemoteKey, err)
		}
		if _, duplicate := updates[entry.Path]; duplicate {
			return "", fmt.Errorf("duplicate inventory key %s", entry.Path)
		}
		updates[entry.Path] = entry
	}
	generationKey, err := pub.GenerationKey(publication.request.Generation.Generation)
	if err != nil {
		return "", err
	}
	for _, control := range []struct {
		key  string
		body []byte
	}{{pub.CheckpointKey, checkpointBody}, {generationKey, generationBody}} {
		entry, err := remoteInventoryEntry(control.key, int64(len(control.body)), digestBytesCLI(control.body))
		if err != nil {
			return "", err
		}
		updates[entry.Path] = entry
	}
	if publication.target == string(pub.TargetTencent) {
		lock := pub.GenerationLock{
			Schema: pub.GenerationLockSchema, Target: pub.TargetTencent,
			Generation: publication.request.Generation.Generation, ParentGeneration: publication.request.Generation.ParentGeneration,
			ParentCheckpointSHA256: publication.request.Expected.CheckpointSHA256,
			GenerationSHA256:       digestBytesCLI(generationBody), TransactionID: publication.request.TransactionID,
			IntentView:     publication.request.Generation.IntentView,
			IntentSnapshot: publication.request.Generation.IntentSnapshot,
			UpdatedAt:      publication.request.UpdatedAt.UTC().Format(time.RFC3339Nano),
		}
		body, err := lock.Canonical()
		if err != nil {
			return "", fmt.Errorf("reconstruct COS generation lock: %w", err)
		}
		key, _ := pub.GenerationLockKey(publication.request.Generation.Generation)
		entry, err := remoteInventoryEntry(key, int64(len(body)), digestBytesCLI(body))
		if err != nil {
			return "", err
		}
		updates[entry.Path] = entry
	}

	parent, parentExists, err := openOptionalCanonical(canonical, remoteStatePath(publication.target, "inventory.tsv"))
	if err != nil {
		return "", err
	}
	if parent != nil {
		defer parent.Close()
	}
	// Publish is forbidden from listing the bucket, so it cannot prove that an
	// existing bucket was empty even for generation 1. Coverage starts partial
	// and can become complete only through a separate explicit full-list import.
	coverage := remoteInventoryPartial
	if parentExists {
		body, exists, err := readOptionalCanonical(canonical, remoteStatePath(publication.target, "inventory.coverage"))
		if err != nil {
			return "", err
		}
		if !exists || string(body) != remoteInventoryComplete && string(body) != remoteInventoryPartial {
			coverage = remoteInventoryPartial
		} else {
			coverage = string(body)
		}
	}
	deletes := make(map[string]struct{}, len(publication.request.Plan.Deletes))
	for _, deletion := range publication.request.Plan.Deletes {
		deletes[deletion.RemoteKey] = struct{}{}
	}
	if err := writeMergedRemoteInventoryApplying(parent, updates, deletes, destination); err != nil {
		return "", err
	}
	return coverage, nil
}

func openOptionalCanonical(canonical *state.Store, path string) (io.ReadCloser, bool, error) {
	reader, err := canonical.OpenPath(path)
	if errors.Is(err, os.ErrNotExist) || err != nil && os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		// go-git wraps missing paths without preserving os.ErrNotExist.
		if _, exists, readErr := readOptionalCanonical(canonical, path); readErr == nil && !exists {
			return nil, false, nil
		}
		return nil, false, err
	}
	return reader, true, nil
}

func remoteInventoryEntry(key string, size int64, sha string) (manifest.Entry, error) {
	digest, err := hex.DecodeString(sha)
	if err != nil || len(digest) != 32 {
		return manifest.Entry{}, errors.New("invalid sha256")
	}
	entry := manifest.Entry{Path: key, Size: size}
	copy(entry.SHA256[:], digest)
	if err := entry.Validate(); err != nil {
		return manifest.Entry{}, err
	}
	return entry, nil
}

func writeMergedRemoteInventory(parent io.Reader, updates map[string]manifest.Entry, destination string) error {
	return writeMergedRemoteInventoryApplying(parent, updates, nil, destination)
}

func writeMergedRemoteInventoryApplying(parent io.Reader, updates map[string]manifest.Entry, deletes map[string]struct{}, destination string) error {
	keys := make([]string, 0, len(updates))
	for key := range updates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return writeExclusiveManifest(destination, func(output io.Writer) error {
		var reader *manifest.Reader
		if parent != nil {
			reader = manifest.NewReader(parent)
		}
		index := 0
		var old manifest.Entry
		oldErr := io.EOF
		if reader != nil {
			old, oldErr = reader.Next()
		}
		for !errors.Is(oldErr, io.EOF) || index < len(keys) {
			if oldErr != nil && !errors.Is(oldErr, io.EOF) {
				return fmt.Errorf("read parent remote inventory: %w", oldErr)
			}
			if oldErr == nil {
				if _, removed := deletes[old.Path]; removed {
					old, oldErr = reader.Next()
					continue
				}
			}
			var next manifest.Entry
			switch {
			case errors.Is(oldErr, io.EOF):
				next = updates[keys[index]]
				index++
			case index == len(keys) || old.Path < keys[index]:
				next = old
				old, oldErr = reader.Next()
			case keys[index] < old.Path:
				next = updates[keys[index]]
				index++
			default:
				next = updates[keys[index]]
				index++
				old, oldErr = reader.Next()
			}
			if err := manifest.WriteEntry(output, next); err != nil {
				return err
			}
		}
		return nil
	})
}

func stageInventoryCoverage(directory, coverage string) (string, error) {
	if coverage != remoteInventoryComplete && coverage != remoteInventoryPartial {
		return "", errors.New("invalid remote inventory coverage")
	}
	path := filepath.Join(directory, "inventory.coverage")
	if err := writeExclusiveBytes(path, []byte(coverage)); err != nil {
		return "", err
	}
	return path, nil
}
